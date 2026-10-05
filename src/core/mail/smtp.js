/**
 * mail/smtp.js — Sesion SMTP de diagnostico.
 *
 * MODULO NUEVO. Lo que hacia legacy/Validate config SMTP/validate-smtp.js era
 * abrir un socket TLS, escribir EHLO y AUTH LOGIN a ojo, con la sesion colgada
 * si el servidor no contestaba. Aqui la conversacion es guionizada y cada paso
 * deja una etapa con su respuesta y su duracion, que es lo que convierte una
 * prueba en un informe.
 *
 * Que NO hace, a proposito:
 *   - No acepta credenciales si no se las pasan: las del `.env` las aplicaba
 *     quien ejecutaba, aqui las escribe quien pide la prueba.
 *   - No envia correo salvo que se lo pidan. Autenticar contra un servidor y
 *     colarse en la bandeja de otra persona son cosas muy distintas, y la
 *     segunda no debe pasar por defecto.
 *   - No registra lo que envia. Las credenciales viajan en base64 dentro del
 *     tunel, pero la telemetria se guarda en la base de datos y en el PDF: lo
 *     unico que se anota es el nombre del mecanismo, nunca su carga util.
 *
 * @module core/mail/smtp
 */

'use strict';

const tlsModulo = require('../net/tls');
const lineasBase = require('./lineas');
const { NetlabError, CODES } = require('../errors');

/** Formas de cifrado que sabe abrir. */
const SEGURIDADES = ['tls', 'starttls', 'ninguno'];

/** Mecanismos que se saben enviar, en orden de preferencia. */
const MECANISMOS = ['PLAIN', 'LOGIN'];

/**
 * Quita el codigo de respuesta a cada linea de un EHLO.
 *
 * "250-PIPELINING" -> "PIPELINING". La ultima linea de un bloque llega con
 * espacio ("250 PIPELINING") y tambien hay que quitarlo.
 *
 * @param {string[]} lineas
 * @returns {string[]}
 */
function limpiarCapacidades(lineas) {
  return lineas
    .map((l) => l.replace(/^\d{3}[ -]/, '').trim())
    .filter(Boolean);
}

/**
 * Mecanismos de autenticacion anunciados en las capacidades.
 *
 * Se aceptan las dos formas de la RFC 4954: `AUTH LOGIN PLAIN` y
 * `AUTH=LOGIN PLAIN`. Hay servidores que usan la segunda porque el guion de la
 * primera choca con alguno de sus valores.
 *
 * @param {string[]} capacidades
 * @returns {string[]}
 */
function extraerMecanismos(capacidades) {
  const salida = new Set();
  for (const capacidad of capacidades) {
    const coincidencia = capacidad.match(/^AUTH\s*=?\s*(.+)$/i);
    if (!coincidencia) continue;
    for (const mecanismo of coincidencia[1].trim().split(/\s+/)) {
      if (mecanismo) salida.add(mecanismo.toUpperCase());
    }
  }
  return [...salida];
}

/**
 * Decide con que mecanismo se intenta la autenticacion.
 *
 * PLAIN va primero porque manda usuario y contrasena en un solo viaje y solo es
 * aceptable sobre TLS; si el servidor esta en claro, el modulo lo avisa y la
 * eleccion cae a LOGIN, que al menos viaja en dos pasos.
 *
 * @param {string[]} soportados Mecanismos anunciados.
 * @param {boolean} cifrado Si la sesion va cifrada.
 * @returns {string|null}
 */
function elegirMecanismo(soportados, cifrado) {
  const permitidos = new Set(MECANISMOS);
  const utiles = soportados.filter((m) => permitidos.has(m));
  const preference = cifrado ? ['PLAIN', 'LOGIN'] : ['LOGIN'];
  return preference.find((m) => utiles.includes(m)) || null;
}

/**
 * Monta el mensaje de la prueba de envio.
 *
 * @param {object} opciones
 * @returns {string}
 */
function componerMensaje({ remitente, destinatario, asunto, texto }) {
  const cabeceras = [
    `From: <${remitente}>`,
    `To: <${destinatario}>`,
    `Subject: ${asunto || 'Prueba de salida SMTP (netlab)'}`,
    `Date: ${new Date().toUTCString()}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit'
  ].join('\r\n');

  const cuerpo = [
    texto || 'Mensaje enviado por el validador SMTP de netlab.',
    '',
    'Si has recibido este correo, el servidor acepta el envio desde esa cuenta.'
  ].join('\n');

  // El punto inicial de una linea significaba el fin de los datos. Con un punto
  // de mas, el servidor lo quita y entrega la linea intacta.
  const escapado = cuerpo.replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');

  return `${cabeceras}\r\n\r\n${escapado}`;
}

/**
 * Ejecuta una prueba SMTP completa.
 *
 * @param {object} opciones
 * @param {string} opciones.host
 * @param {number} opciones.puerto
 * @param {'tls'|'starttls'|'ninguno'} [opciones.seguridad='starttls']
 * @param {string} [opciones.usuario]
 * @param {string} [opciones.contrasena]
 * @param {number} [opciones.timeout=10000]
 * @param {boolean} [opciones.verificar=false] Exigir certificado valido.
 * @param {string} [opciones.nombreRemitente='netlab.local'] Nombre del EHLO.
 * @param {object} [opciones.enviar] Datos del envio real; si no se da, no se envia.
 * @param {(texto: string) => string} [opciones.redactar]
 * @param {object} [deps] Modulos de red, sustituibles en las pruebas.
 * @param {object} [deps.tls] Suplanta a core/net/tls.
 * @param {object} [deps.lineas] Suplanta a core/mail/lineas.
 * @returns {Promise<object>} Informe de la sesion.
 */
async function probar(opciones, deps = {}) {
  const moduloTls = deps.tls || tlsModulo;
  const modLineas = deps.lineas || lineasBase;
  const {
    host,
    puerto,
    seguridad = 'starttls',
    usuario,
    contrasena,
    timeout = 10000,
    verificar = false,
    nombreRemitente = 'netlab.local',
    enviar = null,
    redactar = (texto) => texto
  } = opciones;

  if (!host) {
    throw new NetlabError(CODES.ENTRADA_VACIA, 'Falta el servidor SMTP.', {
      remediation: 'Escribe el nombre del servidor, por ejemplo smtp.ejemplo.com.'
    });
  }
  if (!Number.isFinite(Number(puerto)) || Number(puerto) < 1 || Number(puerto) > 65535) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `El puerto «${puerto}» no es valido.`, {
      remediation: 'Usa un puerto entre 1 y 65535: 465 para TLS directo, 587 para STARTTLS, 25 en claro.'
    });
  }
  if (!SEGURIDADES.includes(seguridad)) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `La forma de cifrado «${seguridad}» no existe.`, {
      remediation: `Valores posibles: ${SEGURIDADES.join(', ')}.`
    });
  }

  const inicio = Date.now();
  const etapas = [];
  const informe = {
    host,
    puerto: Number(puerto),
    seguridadPedida: seguridad,
    seguridadEfectiva: null,
    banner: null,
    etapas,
    tls: null,
    certificado: null,
    capacidades: [],
    respuestasEhlo: [],
    starttls: null,
    auth: {
      soportados: [],
      mecanismo: null,
      enviado: false,
      codigo: null,
      mensaje: null,
      ok: false
    },
    envio: null,
    duracionMs: 0,
    error: null
  };

  const clienteOpciones = { timeout, redactar };
  let cliente = null;

  /** Anota una etapa con su duracion. */
  const anotar = async (paso, accion) => {
    const t0 = Date.now();
    const respuesta = await accion();
    etapas.push({
      paso,
      codigo: respuesta.codigo ?? null,
      respuesta: respuesta.texto,
      ms: Date.now() - t0,
      error: respuesta.error ? respuesta.error.message : null
    });
    // El primer fallo es el que explica el resto: si el EHLO se queda sin
    // respuesta, lo de despues ya no significa nada y el informe tiene que
    // decirlo en vez de mostrar etapas limpias.
    if (respuesta.error && !informe.error) informe.error = respuesta.error;
    return respuesta;
  };

  try {
    if (seguridad === 'tls') {
      const conexion = await moduloTls.conectar({ host, port: Number(puerto), verificar, timeout });
      cliente = modLineas.crearCliente(conexion.socket, clienteOpciones);
      informe.certificado = conexion.certificado;
      informe.tls = resumenTls(conexion.socket, conexion.certificado);
      informe.seguridadEfectiva = 'tls';
    } else {
      const socket = await modLineas.conectarTcp({ host, puerto: Number(puerto), timeout });
      cliente = modLineas.crearCliente(socket, clienteOpciones);
      informe.seguridadEfectiva = 'ninguno';
    }

    const saludo = await anotar('Saludo inicial', () => cliente.leer('saludo'));
    // Si el saludo llego con error, su texto es el mensaje del fallo, no lo que
    // dijo el servidor. Ponerlo como banner haria que el informe pareciera una
    // sesion que no contesto.
    if (!saludo.error) informe.banner = saludo.texto;

    if (seguridad === 'starttls') {
      const primerEhlo = await anotar('EHLO antes de cifrar', () =>
        cliente.enviar(`EHLO ${nombreRemitente}`, 'EHLO')
      );
      const previos = limpiarCapacidades(primerEhlo.lineas);
      const anuncia = previos.some((c) => /^STARTTLS\b/i.test(c));

      if (!anuncia) {
        // Se sigue en claro para poder contar el resto de la prueba, pero el
        // hallazgo se emite igualmente: la sesion quedo sin cifrar.
        informe.starttls = { anunciado: false, aplicado: false, motivo: 'El servidor no anuncia STARTTLS.' };
        informe.seguridadEfectiva = 'ninguno';
      } else {
        try {
          const respuestaStarttls = await anotar('STARTTLS', () => cliente.enviar('STARTTLS', 'STARTTLS'));
          if (respuestaStarttls.codigo !== 220) {
            informe.starttls = {
              anunciado: true,
              aplicado: false,
              motivo: `El servidor respondió ${respuestaStarttls.codigo ?? '—'} a STARTTLS en vez de 220.`
            };
            informe.seguridadEfectiva = 'ninguno';
          } else {
            const subida = await modLineas.subirStartTls(cliente.socket, {
              verificar,
              servername: moduloTls.esIp(host) ? undefined : host,
              timeout
            });
            cliente = modLineas.crearCliente(subida.socket, clienteOpciones);
            informe.certificado = subida.certificado;
            informe.tls = resumenTls(subida.socket, subida.certificado);
            informe.starttls = { anunciado: true, aplicado: true, motivo: null };
            informe.seguridadEfectiva = 'starttls';
          }
        } catch (error) {
          informe.starttls = { anunciado: true, aplicado: false, motivo: error.message };
          informe.seguridadEfectiva = 'ninguno';
          informe.error = error;
        }
}
    }

    // EHLO definitivo: el de antes de STARTTLS no vale, porque las capacidades
    // se anuncian distintas una vez el canal esta cifrado.
    const ehlo = await anotar('EHLO', () => cliente.enviar(`EHLO ${nombreRemitente}`, 'EHLO'));
    informe.respuestasEhlo = ehlo.lineas;
    informe.capacidades = limpiarCapacidades(ehlo.lineas);
    informe.auth.soportados = extraerMecanismos(informe.capacidades);

    const cifrado = informe.seguridadEfectiva !== 'ninguno';
    informe.auth.mecanismo = elegirMecanismo(informe.auth.soportados, cifrado);

    if (!usuario) {
      informe.auth.mensaje = 'No se indicó usuario, así que no se intentó autenticar.';
    } else if (!informe.auth.mecanismo) {
      informe.auth.mensaje = informe.auth.soportados.length
        ? `El servidor anuncia ${informe.auth.soportados.join(', ')} y ninguno se puede usar aquí.`
        : 'El servidor no anuncia ningún mecanismo de autenticación.';
    } else {
      await autenticar(cliente, informe, { usuario, contrasena, timeout, redactar }, anotar);
    }

    if (enviar && informe.auth.ok) {
      informe.envio = await enviarMensaje(cliente, enviar, anotar);
    } else if (enviar) {
      informe.envio = {
        ok: false,
        motivo: 'No se intentó el envío porque la autenticación no salió bien.',
        etapas: []
      };
    }

    await anotar('QUIT', () => cliente.enviar('QUIT', 'QUIT'));
  } catch (error) {
    informe.error = error instanceof NetlabError ? error : new NetlabError(CODES.INTERNO, error.message);
  } finally {
    cliente?.destruir();
    informe.duracionMs = Date.now() - inicio;
  }

  return informe;
}

/**
 * Intenta la autenticacion con el mecanismo elegido.
 *
 * @param {object} cliente
 * @param {object} informe Se completa en el sitio.
 * @param {object} credenciales
 * @param {(paso: string, accion: Function) => Promise<object>} anotar
 */
async function autenticar(cliente, informe, { usuario, contrasena, timeout, redactar }, anotar) {
  const mecanismo = informe.auth.mecanismo;
  informe.auth.enviado = true;

  const base = { timeout, redactar };
  let respuesta;

  if (mecanismo === 'PLAIN') {
    const carga = Buffer.from(`\u0000${usuario}\u0000${contrasena ?? ''}`, 'utf8').toString('base64');
    respuesta = await anotar('AUTH PLAIN', () => cliente.enviar(`AUTH PLAIN ${carga}`, 'AUTH PLAIN'));
  } else {
    const paso1 = await anotar('AUTH LOGIN', () => cliente.enviar('AUTH LOGIN', 'AUTH LOGIN'));
    if (paso1.codigo !== 334) {
      respuesta = paso1;
    } else {
      const paso2 = await anotar('AUTH LOGIN (usuario)', () =>
        cliente.enviar(Buffer.from(usuario, 'utf8').toString('base64'), 'AUTH LOGIN usuario')
      );
      if (paso2.codigo !== 334) {
        respuesta = paso2;
      } else {
        respuesta = await anotar('AUTH LOGIN (contraseña)', () =>
          cliente.enviar(Buffer.from(contrasena ?? '', 'utf8').toString('base64'), 'AUTH LOGIN contraseña')
        );
      }
    }
  }

  informe.auth.codigo = respuesta.codigo ?? null;
  informe.auth.mensaje = respuesta.texto;
  informe.auth.ok = Number.isInteger(respuesta.codigo) && respuesta.codigo >= 200 && respuesta.codigo < 300;
  if (respuesta.error) informe.error = respuesta.error;
}

/**
 * Envia un mensaje de prueba: MAIL FROM, RCPT TO, DATA.
 *
 * @param {object} cliente
 * @param {object} datos { remitente, destinatario, asunto, texto }
 * @param {(paso: string, accion: Function) => Promise<object>} anotar
 * @returns {Promise<object>}
 */
async function enviarMensaje(cliente, datos, anotar) {
  const etapas = [];
  const registrar = async (paso, accion) => {
    const respuesta = await anotar(paso, accion);
    etapas.push({ paso, codigo: respuesta.codigo ?? null, respuesta: respuesta.texto });
    return respuesta;
  };

  const remitente = `<${datos.remitente}>`;
  const destinatario = `<${datos.destinatario}>`;

  const mail = await registrar('MAIL FROM', () => cliente.enviar(`MAIL FROM:${remitente}`, 'MAIL FROM'));
  if (mail.codigo !== 250) {
    return { ok: false, motivo: `El servidor rechazó el remitente con ${mail.codigo ?? '—'}.`, etapas };
  }

  const rcpt = await registrar('RCPT TO', () => cliente.enviar(`RCPT TO:${destinatario}`, 'RCPT TO'));
  if (rcpt.codigo !== 250 && rcpt.codigo !== 251) {
    return { ok: false, motivo: `El servidor rechazó el destinatario con ${rcpt.codigo ?? '—'}.`, etapas };
  }

  const data = await registrar('DATA', () => cliente.enviar('DATA', 'DATA'));
  if (data.codigo !== 354) {
    return { ok: false, motivo: `El servidor no aceptó DATA (${data.codigo ?? '—'}).`, etapas };
  }

  const cuerpo = `${componerMensaje(datos)}\r\n.\r\n`;
  const respuesta = await registrar('Mensaje', async () => {
    cliente.escribirCrudo(cuerpo);
    return cliente.leer('mensaje');
  });

  return {
    ok: respuesta.codigo === 250,
    motivo: respuesta.codigo === 250 ? null : `El servidor rechazó el mensaje con ${respuesta.codigo ?? '—'}.`,
    etapas,
    remitente: datos.remitente,
    destinatario: datos.destinatario
  };
}

/** Resumen de la negociacion TLS para el informe. */
function resumenTls(socket, certificado) {
  return {
    protocolo: socket?.getProtocol?.() || null,
    cifrado: socket?.getCipher?.()?.name || null,
    autoridadCertificadora: socket?.authorized === true,
    motivoRechazo: socket?.authorizationError || null,
    certificado
  };
}

module.exports = {
  probar,
  limpiarCapacidades,
  extraerMecanismos,
  elegirMecanismo,
  componerMensaje,
  SEGURIDADES,
  MECANISMOS
};