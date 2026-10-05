/**
 * mail/imap.js — Sesion IMAP de diagnostico.
 *
 * MODULO NUEVO. El script antiguo probaba IMAP con el mismo socket que SMTP y
 * una expresion que buscaba 'a1 OK' en el texto entero:
 *
 *   Validate config SMTP/validate-smtp.js:46
 *
 * Eso funciona hasta que el servidor contesta a otra cosa en la misma linea, o
 * devuelve la respuesta partida en dos trozos de TCP, y entonces el script se
 * queda esperando datos que nunca llegan. Aqui cada comando espera su respuesta
 * etiquetada (`a2 OK`, `a2 NO`) y todos tienen plazo.
 *
 * El saludo IMAP es distinto del de SMTP: son lineas sin codigo numerico, y
 * pueden decir `* PREAUTH`, que significa que la sesion ya esta autenticada por
 * fuera —Kerberos o IP de confianza— y no hace falta LOGIN.
 *
 * @module core/mail/imap
 */

'use strict';

const tlsModulo = require('../net/tls');
const { crearCliente } = require('./lineas');
const { NetlabError, CODES } = require('../errors');

/**
 * Codigo de una respuesta IMAP etiquetada: `a2 OK` vale 0, `a2 NO` vale 1.
 *
 * `codigoEtiquetado` devuelve null cuando la linea no lleva la etiqueta que se
 * pedia, que es la senal de que el servidor se ha salido del guion.
 *
 * @param {string} linea
 * @param {string} etiqueta
 * @returns {number|null}
 */
function codigoEtiquetado(linea, etiqueta) {
  const coincidencia = String(linea).match(new RegExp(`^${etiqueta}\\s+(OK|NO|BAD|PREAUTH)`, 'i'));
  if (!coincidencia) return null;
  return coincidencia[1].toUpperCase() === 'NO' || coincidencia[1].toUpperCase() === 'BAD' ? 1 : 0;
}

/**
 * Lista de capacidades de la respuesta a CAPABILITY.
 *
 * La respuesta llega en varias lineas `* CAPABILITY ...` y termina con
 * `a1 OK`. Las lineas intermedias son las que interesan; la de confirmacion se
 * descarta porque solo lleva la palabra clave.
 *
 * @param {string[]} lineas
 * @returns {string[]}
 */
function extraerCapacidades(lineas) {
  const capacidades = new Set();
  for (const linea of lineas) {
    const coincidencia = linea.match(/^\*\s+CAPABILITY\s+(.*)$/i);
    if (!coincidencia) continue;
    for (const capacidad of coincidencia[1].trim().split(/\s+/)) {
      if (capacidad) capacidades.add(capacidad.toUpperCase());
    }
  }
  return [...capacidades];
}

/**
 * Ejecuta una prueba IMAP completa.
 *
 * @param {object} opciones
 * @param {string} opciones.host
 * @param {number} opciones.puerto
 * @param {string} [opciones.usuario]
 * @param {string} [opciones.contrasena]
 * @param {number} [opciones.timeout=10000]
 * @param {boolean} [opciones.verificar=false]
 * @param {(texto: string) => string} [opciones.redactar]
 * @param {object} [deps] Modulos de red, sustituibles en las pruebas.
 * @param {object} [deps.tls] Suplanta a core/net/tls.
 * @returns {Promise<object>} Informe de la sesion.
 */
async function probar(opciones, deps = {}) {
  const moduloTls = deps.tls || tlsModulo;
  const {
    host,
    puerto,
    usuario,
    contrasena,
    timeout = 10000,
    verificar = false,
    redactar = (texto) => texto
  } = opciones;

  if (!host) {
    throw new NetlabError(CODES.ENTRADA_VACIA, 'Falta el servidor IMAP.', {
      remediation: 'Escribe el nombre del servidor de entrada, por ejemplo imap.ejemplo.com.'
    });
  }
  if (!Number.isFinite(Number(puerto)) || Number(puerto) < 1 || Number(puerto) > 65535) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `El puerto IMAP «${puerto}» no es valido.`, {
      remediation: 'Usa 993 para IMAP sobre TLS.'
    });
  }

  const inicio = Date.now();
  const etapas = [];
  const informe = {
    host,
    puerto: Number(puerto),
    banner: null,
    preautenticado: false,
    etapas,
    tls: null,
    certificado: null,
    capacidades: [],
    auth: { usuario: usuario || null, intentado: false, codigo: null, mensaje: null, ok: false },
    duracionMs: 0,
    error: null
  };

  let cliente = null;

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
    // El primer fallo es el que explica el resto del recorrido.
    if (respuesta.error && !informe.error) informe.error = respuesta.error;
    return respuesta;
  };

  try {
    const conexion = await moduloTls.conectar({ host, port: Number(puerto), verificar, timeout });
    cliente = crearCliente(conexion.socket, { timeout, redactar });
    informe.certificado = conexion.certificado;
    informe.tls = {
      protocolo: conexion.socket?.getProtocol?.() || null,
      cifrado: conexion.socket?.getCipher?.()?.name || null,
      autoridadCertificadora: conexion.socket?.authorized === true,
      motivoRechazo: conexion.socket?.authorizationError || null,
      certificado: conexion.certificado
    };

    const saludo = await anotar('Saludo del servidor', () => cliente.leer('saludo'));
    informe.banner = saludo.texto;
    informe.preautenticado = /^\s*\*\s+PREAUTH/i.test(saludo.lineas[0] || '');

    const capacidades = await anotar('CAPABILITY', () => cliente.enviar('a1 CAPABILITY', 'CAPABILITY'));
    informe.capacidades = extraerCapacidades(capacidades.lineas);

    if (informe.preautenticado) {
      informe.auth.ok = true;
      informe.auth.codigo = 0;
      informe.auth.mensaje = 'El servidor da la sesion por ya autenticada (PREAUTH), asi que no hace falta LOGIN.';
    } else if (!usuario) {
      informe.auth.mensaje = 'No se indico usuario, asi que no se intento entrar.';
    } else {
      informe.auth.intentado = true;
      // La contrasena viaja en el comando, no en la respuesta, asi que no hay
      // nada que redaccionar despues: lo que se guarda es la etapa «LOGIN».
      const entrada = await anotar('LOGIN', async () => {
        cliente.escribirCrudo(`a2 LOGIN "${escapar(usuario)}" "${escapar(contrasena ?? '')}"\r\n`);
        return cliente.leer('LOGIN');
      });

      const cierre = entrada.lineas[entrada.lineas.length - 1] || '';
      informe.auth.codigo = codigoEtiquetado(cierre, 'a2');
      informe.auth.mensaje = entrada.texto;
      informe.auth.ok = informe.auth.codigo === 0;
      if (informe.auth.codigo === null) {
        informe.auth.mensaje = `El servidor no contesto a LOGIN con la etiqueta esperada. Contestó: ${entrada.texto}`;
      }
      if (entrada.error) informe.error = entrada.error;
    }

    await anotar('LOGOUT', () => cliente.enviar('a3 LOGOUT', 'LOGOUT'));
  } catch (error) {
    informe.error = error instanceof NetlabError ? error : new NetlabError(CODES.INTERNO, error.message);
  } finally {
    cliente?.destruir();
    informe.duracionMs = Date.now() - inicio;
  }

  return informe;
}

/** Cierra barras y comillas para no romper el comando IMAP. */
function escapar(valor) {
  return String(valor).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

module.exports = { probar, codigoEtiquetado, extraerCapacidades, escapar };