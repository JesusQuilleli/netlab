/**
 * mail-checker — puntúa la configuración de correo de un dominio o de un correo
 * enviado, siguiendo el enfoque de mail-tester.
 *
 * DOS MODOS, UNA HERRAMIENTA
 *   1. Dominio: consulta MX, SPF, DKIM, DMARC, PTR, listas negras y las
 *      extensiones de transporte (MTA-STS, TLS-RPT, BIMI) por DNS.
 *   2. Mensaje: analiza la fuente (.eml) de un correo ya enviado: qué dijeron
 *      los receptores de SPF/DKIM/DMARC, la reputación de la IP emisora y el
 *      contenido. No verifica la firma DKIM en criptográfico ni descarga
 *      enlaces: se apoya en `Authentication-Results`, y el informe lo dice.
 *
 * La puntuación es sobre 10 y cada comprobación aporta puntos, igual que
 * mail-tester. El estado global (pass/warn/fail) sale de los hallazgos.
 *
 * @module tools/mail-checker
 */

'use strict';

const {
  createResult,
  addSection,
  addSummary,
  addFinding,
  addLog,
  failWith,
  finalize,
  SECCION_KINDS: K,
  SEVERIDADES
} = require('../core/result');
const { NetlabError, CODES } = require('../core/errors');
const { redactDeep } = require('../core/redact');
const dnsNet = require('../core/net/dns');
const dnsbl = require('../core/net/dnsbl');
const { normalizarDominio, normalizarTimeout } = require('../core/dominio');
const { nombreDkim } = require('../core/mail/comun');
const spfMod = require('../core/mail/spf');
const dmarcMod = require('../core/mail/dmarc');
const dkimMod = require('../core/mail/dkim');
const transporteMod = require('../core/mail/transporte');
const mensajeMod = require('../core/mail/mensaje');
const contenidoMod = require('../core/mail/contenido');
const puntuacion = require('../core/mail/puntuacion');

const ID = 'mail-checker';

/** Pesos del modo dominio. Suman 10. */
const PESOS_DOMINIO = {
  resolucion: 0.5,
  mx: 1.0,
  spf: 1.5,
  dkim: 1.5,
  dmarc: 1.5,
  ptr: 1.0,
  listas: 1.5,
  mtaSts: 0.5,
  tlsRpt: 0.5,
  bimi: 0.5
};

/** Pesos del modo mensaje. Suman 10. */
const PESOS_MENSAJE = {
  spf: 1.5,
  dkim: 1.5,
  dmarc: 1.0,
  ptr: 1.0,
  listas: 2.0,
  formato: 0.5,
  unsubscribe: 0.5
};

/** Campos del formulario, que consume la web. */
const CAMPOS = [
  {
    name: 'dominio',
    label: 'Dominio',
    type: 'text',
    requiredUnless: 'analizarMensaje',
    placeholder: 'ejemplo.com',
    help: 'El dominio del que se revisa el correo. Se limpia solo si pegas una URL entera.'
  },
  {
    name: 'analizarMensaje',
    label: 'Analizar un correo enviado (.eml) en vez de un dominio',
    type: 'checkbox',
    required: false,
    default: false,
    help: 'Actívalo para puntuar un mensaje concreto: sube su código fuente o pégalo. Sustituye al diagnóstico por DNS del dominio.'
  },
  {
    name: 'mensajeArchivo',
    label: 'Archivo del correo (.eml)',
    type: 'file',
    accept: '.eml,.txt,message/rfc822',
    required: false,
    maxBytes: 1024 * 1024,
    shownWhen: 'analizarMensaje',
    help: 'El código fuente del correo. En Gmail es "Mostrar original" y en Outlook "Ver código de origen". Se lee en memoria y no se guarda.'
  },
  {
    name: 'mensajePegado',
    label: 'O pega aquí el código fuente',
    type: 'text',
    required: false,
    shownWhen: 'analizarMensaje',
    help: 'Alternativa al archivo. Cabeceras y cuerpo, tal cual.'
  },
  {
    name: 'selectores',
    label: 'Selectores DKIM',
    type: 'text',
    required: false,
    placeholder: 'default, google, s1',
    help: 'Opcional. Si lo dejas vacío se prueban los selectores habituales. Escribe los tuyos separados por comas para añadirlos.'
  },
  {
    name: 'extensiones',
    label: 'Comprobar MTA-STS, TLS-RPT y BIMI',
    type: 'checkbox',
    required: false,
    default: true,
    help: 'Solo consultas DNS. Comprueba las tres extensiones de seguridad de transporte y marca.'
  },
  {
    name: 'listasNegras',
    label: 'Comprobar listas negras',
    type: 'checkbox',
    required: false,
    default: true,
    help: 'Consulta las listas negras habituales para los servidores de correo del dominio (o para la IP que envió el mensaje).'
  },
  {
    name: 'timeout',
    label: 'Tiempo de espera por consulta',
    type: 'number',
    required: false,
    default: 5000,
    min: 500,
    max: 30000,
    unit: 'ms',
    help: 'Por consulta DNS.'
  }
];

/* ------------------------------------------------------------------ *
 * Entrada de la herramienta
 * ------------------------------------------------------------------ */

/**
 * @param {object} params
 * @param {object} [ctx]
 * @returns {Promise<object>} Result
 */
async function ejecutar(params = {}, ctx = {}) {
  const inicio = new Date();
  const log = ctx.log || null;
  const dns = ctx.dns || dnsNet;
  const blacklists = ctx.dnsbl || dnsbl;
  const timeout = normalizarTimeout(params.timeout);

  const result = createResult({
    tool: ID,
    toolTitle: 'Comprobador de correo',
    target: params.analizarMensaje ? 'correo enviado' : String(params.dominio ?? '').trim(),
    params: paramsSeguros(params)
  });

  try {
    if (params.analizarMensaje) {
      await modoMensaje(result, recogerMensaje(params), { dns, blacklists, timeout, log });
    } else {
      await modoDominio(result, params, { dns, blacklists, timeout, log });
    }
    return finalize(result, inicio);
  } catch (error) {
    addLog(result, { level: 'error', channel: 'error', message: error.message });
    log?.error?.(`mail-checker falló: ${error.message}`);
    return failWith(finalize(result, inicio), error instanceof NetlabError ? error : new NetlabError(CODES.INTERNO, error.message));
  }
}

/** Recorta de `params` el cuerpo del correo: no debe ir al historial ni al PDF. */
function paramsSeguros(params) {
  const copia = { ...params };
  if (copia.mensajeArchivo) copia.mensajeArchivo = `(correo adjunto, ${Buffer.byteLength(String(params.mensajeArchivo), 'utf8')} bytes)`;
  if (copia.mensajePegado) copia.mensajePegado = `(correo pegado, ${String(params.mensajePegado).length} caracteres)`;
  return redactDeep(copia);
}

/** Obtiene y parsea el mensaje de cualquiera de las dos entradas. */
function recogerMensaje(params) {
  const fuente = params.mensajeArchivo || params.mensajePegado;
  if (!fuente || !String(fuente).trim()) {
    throw new NetlabError(CODES.PARAM_INVALIDO, 'No hay ningún correo que analizar.', {
      remediation: 'Sube el archivo .eml o pega el código fuente del correo.'
    });
  }
  const mensaje = mensajeMod.parsear(String(fuente));
  if (!mensaje.cabeceras || Object.keys(mensaje.cabeceras).length === 0) {
    throw new NetlabError(CODES.PARAM_INVALIDO, 'El texto no parece un correo: no tiene cabeceras.', {
      remediation: 'Pega el código fuente completo, empezando por las cabeceras (From, Received, Subject...).'
    });
  }
  return mensaje;
}

/* ------------------------------------------------------------------ *
 * Utilidades DNS
 * ------------------------------------------------------------------ */

/** Ejecuta un lote de consultas y devuelve los resultados en el mismo orden. */
async function consultarMuchas(dns, consultas, timeout) {
  if (typeof dns.consultarLote === 'function') {
    return dns.consultarLote(consultas, { concurrencia: 8, dns: { timeout, reintentos: 1 } });
  }
  return Promise.all(consultas.map(async (c) => ({ ...c, ...(await dns.consultar(c.nombre, c.tipo, { timeout, reintentos: 1 })) })));
}

/** Índice por `clave` para recuperar cada respuesta sin depender del orden. */
function indexar(respuestas) {
  const mapa = new Map();
  for (const r of respuestas) mapa.set(r.clave, r);
  return mapa;
}

/** Lista de IPs de un registro A/AAAA. */
function ipsDe(registro) {
  return registro?.ok ? registro.valores.map((v) => String(v)) : [];
}

/* ------------------------------------------------------------------ *
 * Modo dominio
 * ------------------------------------------------------------------ */

async function modoDominio(result, params, entorno) {
  const { dns, blacklists, timeout, log } = entorno;

  if (!String(params.dominio ?? '').trim()) {
    throw new NetlabError(CODES.ENTRADA_VACIA, 'No se indicó ningún dominio.', {
      remediation: 'Escribe el dominio que quieres revisar, por ejemplo ejemplo.com.'
    });
  }

  const dominio = normalizarDominio(params.dominio);
  result.target = String(params.dominio).trim();
  log?.info?.(`Comprobando el correo de ${dominio}`);

  const extensiones = params.extensiones !== false;
  const conListas = params.listasNegras !== false;
  const selectores = elegirSelectores(params.selectores);

  // --- primer lote: todo lo del dominio base y los nombres de servicio -------
  const consultas = [
    { clave: 'mx', nombre: dominio, tipo: 'MX' },
    { clave: 'a', nombre: dominio, tipo: 'A' },
    { clave: 'aaaa', nombre: dominio, tipo: 'AAAA' },
    { clave: 'txt', nombre: dominio, tipo: 'TXT' },
    { clave: 'dmarc', nombre: `_dmarc.${dominio}`, tipo: 'TXT' }
  ];
  if (extensiones) {
    consultas.push({ clave: 'mtaSts', nombre: `_mta-sts.${dominio}`, tipo: 'TXT' });
    consultas.push({ clave: 'tlsRpt', nombre: `_smtp._tls.${dominio}`, tipo: 'TXT' });
    consultas.push({ clave: 'bimi', nombre: `default._bimi.${dominio}`, tipo: 'TXT' });
  }
  for (const selector of selectores) {
    consultas.push({ clave: `dkim:${selector}`, nombre: nombreDkim(selector, dominio), tipo: 'TXT' });
  }

  const respuestas = indexar(await consultarMuchas(dns, consultas, timeout));
  const r = (clave) => respuestas.get(clave) || { ok: false, valores: [] };

  // --- ¿existe el dominio? --------------------------------------------------
  const registrosA = ipsDe(r('a'));
  const registrosAAAA = ipsDe(r('aaaa'));
  const txtDominio = r('txt');
  const mxRegistro = r('mx');
  const existe = registrosA.length > 0 || registrosAAAA.length > 0 || mxRegistro.ok || txtDominio.ok || r('dmarc').ok;

  if (!existe) {
    throw new NetlabError(CODES.DNS_SIN_REGISTROS, `El dominio "${dominio}" no existe (NXDOMAIN).`, {
      remediation: 'Revisa que esté bien escrito. Un dominio sin registros no puede recibir ni autenticar correo.'
    });
  }

  // --- MX y servidores ------------------------------------------------------
  const mx = parsearMx(mxRegistro);
  const servidores = await resolverServidores(dns, mx, registrosA, registrosAAAA, timeout);
  await marcarListasNegras(blacklists, servidores, { conListas, timeout });

  // --- SPF, DKIM, DMARC y transporte ---------------------------------------
  const spf = spfMod.parsear(registrosTxtDe(txtDominio));
  const dkim = evaluarSelectores(respuestas, selectores, dominio);
  const dmarc = dmarcMod.parsear(registrosTxtDe(r('dmarc')));
  const transporte = extensiones
    ? transporteMod.parsear({ mtaSts: registrosTxtDe(r('mtaSts')), tlsRpt: registrosTxtDe(r('tlsRpt')), bimi: registrosTxtDe(r('bimi')) })
    : null;

  // --- comprobaciones -------------------------------------------------------
  const checks = [
    checkResolucion(existe, dominio),
    checkMx(mx, servidores),
    checkSpf(spf),
    checkDkim(dkim, dominio),
    checkDmarc(dmarc),
    checkPtr(servidores),
    checkListas(servidores, conListas),
    ...(extensiones ? [checkMtaSts(transporte.mtaSts), checkTlsRpt(transporte.tlsRpt), checkBimi(transporte.bimi)] : [])
  ];

  pintarInforme(result, {
    modo: 'Dominio',
    objetivo: dominio,
    checks,
    registros: filasRegistros([
      [`${dominio}`, 'MX', resumenMx(mx), mx.estado],
      [`${dominio}`, 'TXT (SPF)', spf.valor || '—', spf.presente ? 'ok' : 'warn'],
      [`_dmarc.${dominio}`, 'TXT (DMARC)', dmarc.valor || '—', dmarc.presente ? 'ok' : 'warn'],
      ...filasDkim(result.sections, dkim.registros, dominio)
    ]),
    seccionesExtra: (result_) => {
      seccionMx(result_, servidores, conListas);
      seccionSpf(result_, spf);
      seccionDkim(result_, dkim, dominio);
      seccionDmarc(result_, dmarc);
      if (transporte) seccionTransporte(result_, transporte);
    }
  });
}

/** Selectores a probar: los del usuario más los habituales. */
function elegirSelectores(bruto) {
  const propios = String(bruto ?? '')
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const todos = [...new Set([...propios, ...dkimMod.SELECTORES_COMUNES])];
  return todos.slice(0, 40);
}

/** Normaliza y ordena los MX. Detecta el "null MX" (RFC 7505). */
function parsearMx(registro) {
  if (!registro?.ok || !registro.valores.length) {
    return { presentes: [], estados: [], estado: 'sin-mx' };
  }
  const hosts = registro.valores
    .map((v) => ({ exchange: String(v.exchange || '').replace(/\.$/, ''), priority: Number(v.priority) || 0 }))
    .sort((a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange));
  const nulo = hosts.length === 1 && (hosts[0].exchange === '' || hosts[0].exchange === '.');
  return { presentes: nulo ? [] : hosts, estados: [], estado: nulo ? 'null-mx' : 'ok', nulo };
}

/** Resuelve A/AAAA y PTR de cada MX. */
async function resolverServidores(dns, mx, registrosA, registrosAAAA, timeout) {
  if (mx.nulo) return [];
  if (!mx.presentes.length) {
    // MX implícito: sin MX, el correo se entrega al A/AAAA del dominio.
    if (registrosA.length || registrosAAAA.length) {
      return [{ host: '(implícito: el propio dominio)', prioridad: null, direcciones: [...registrosA, ...registrosAAAA], ptr: [], implicito: true }];
    }
    return [];
  }

  const consultas = [];
  for (const host of mx.presentes) {
    consultas.push({ clave: `A:${host.exchange}`, nombre: host.exchange, tipo: 'A' });
    consultas.push({ clave: `AAAA:${host.exchange}`, nombre: host.exchange, tipo: 'AAAA' });
  }
  const respuestas = indexar(await consultarMuchas(dns, consultas, timeout));

  const servidores = [];
  for (const host of mx.presentes) {
    const direcciones = [...ipsDe(respuestas.get(`A:${host.exchange}`)), ...ipsDe(respuestas.get(`AAAA:${host.exchange}`))];
    const ptr = [];
    for (const ip of direcciones.slice(0, 3)) {
      const nombres = await dns.resolverPTR(ip);
      ptr.push({ ip, nombres: nombres || [] });
    }
    servidores.push({ host: host.exchange, prioridad: host.priority, direcciones, ptr, implicito: false });
  }
  return servidores;
}

/** Consulta listas negras para las IPs de los servidores. */
async function marcarListasNegras(blacklists, servidores, { conListas, timeout }) {
  if (!conListas) return;
  for (const servidor of servidores) {
    servidor.listas = [];
    for (const ip of servidor.direcciones.slice(0, 2)) {
      try {
        const { resultados, resumen } = await blacklists.consultar(ip, { timeout, concurrencia: 4 });
        servidor.listas.push({ ip, resultados, resumen });
      } catch (error) {
        servidor.listas.push({ ip, resultados: [], resumen: { listadas: 0, sinDatos: 1 }, error: error.message });
      }
    }
  }
}

/* ------------------------------------------------------------------ *
 * Modo mensaje
 * ------------------------------------------------------------------ */

async function modoMensaje(result, mensaje, entorno) {
  const { dns, blacklists, timeout, log } = entorno;

  const dominio = mensaje.fromDominio || mensaje.returnPathDominio || primerDominioDkim(mensaje);
  result.target = dominio || mensaje.ipEmisor || 'correo enviado';
  log?.info?.(`Analizando un correo de ${mensaje.from || 'remitente desconocido'}`);

  // --- DNS del dominio remitente y del IP emisor ---------------------------
  const consultas = [];
  if (dominio) {
    consultas.push({ clave: 'txt', nombre: dominio, tipo: 'TXT' });
    consultas.push({ clave: 'dmarc', nombre: `_dmarc.${dominio}`, tipo: 'TXT' });
  }
  const respuestas = indexar(consultas.length ? await consultarMuchas(dns, consultas, timeout) : []);
  const r = (clave) => respuestas.get(clave) || { ok: false, valores: [] };

  const spfDominio = spfMod.parsear(registrosTxtDe(r('txt')));
  const dmarcDominio = dmarcMod.parsear(registrosTxtDe(r('dmarc')));

  let ptr = [];
  if (mensaje.ipEmisor) ptr = (await dns.resolverPTR(mensaje.ipEmisor)) || [];

  let listas = null;
  if (mensaje.ipEmisor && result.params.listasNegras !== false) {
    try {
      listas = await blacklists.consultar(mensaje.ipEmisor, { timeout, concurrencia: 4 });
    } catch (error) {
      listas = { resultados: [], resumen: { listadas: 0, sinDatos: 1 }, error: error.message };
    }
  }

  const contenido = contenidoMod.evaluar(mensaje);

  const checks = [
    checkSpfMensaje(mensaje, spfDominio, dominio),
    checkDkimMensaje(mensaje, dominio),
    checkDmarcMensaje(mensaje, dmarcDominio, dominio),
    checkPtrMensaje(mensaje, ptr),
    checkListasMensaje(listas),
    checkFormato(mensaje),
    checkUnsubscribe(mensaje),
    ...contenido.checks
  ];

  pintarInforme(result, {
    modo: 'Mensaje',
    objetivo: mensaje.ipEmisor || dominio || 'correo',
    checks,
    registros: filasRegistros([
      ['From', 'cabecera', mensaje.from || '—', mensaje.from ? 'ok' : 'error'],
      ['Return-Path', 'cabecera', mensaje.returnPath || '—', mensaje.returnPath ? 'ok' : 'warn'],
      ['Subject', 'cabecera', mensaje.asunto || '—', 'neutral'],
      ['Message-ID', 'cabecera', mensaje.messageId || '—', mensaje.messageId ? 'ok' : 'warn'],
      ['Date', 'cabecera', mensaje.fecha || '—', mensaje.fecha ? 'ok' : 'warn'],
      ['IP emisora', 'red', mensaje.ipEmisor || '—', mensaje.ipEmisor ? 'ok' : 'warn'],
      ['PTR', 'DNS', ptr.length ? ptr.join(', ') : '—', ptr.length ? 'ok' : 'warn']
    ]),
    seccionesExtra: (result_) => {
      seccionCabeceras(result_, mensaje);
      seccionAutenticacion(result_, mensaje, spfDominio, dmarcDominio, dominio);
      seccionContenido(result_, contenido);
      if (mensaje.ipEmisor) seccionIp(result_, mensaje, ptr, listas);
      if (dominio) seccionDmarc(result_, dmarcDominio);
    }
  });
}

/* ------------------------------------------------------------------ *
 * Comprobaciones — dominio
 * ------------------------------------------------------------------ */

function checkResolucion(existe, dominio) {
  return puntuacion.check({
    id: 'resolucion',
    categoria: 'DNS',
    titulo: 'El dominio existe y publica registros',
    peso: PESOS_DOMINIO.resolucion,
    estado: existe ? 'ok' : 'error',
    detalle: existe ? `${dominio} resuelve.` : `${dominio} no publica ningún registro.`,
    recomendacion: existe ? null : 'Revisa el nombre: sin registros no hay correo que comprobar.'
  });
}

function checkMx(mx, servidores) {
  if (mx.estado === 'null-mx') {
    return puntuacion.check({
      id: 'mx', categoria: 'MX', titulo: 'Servidores de correo (MX)', peso: PESOS_DOMINIO.mx, estado: 'warn',
      detalle: 'Publica un "null MX": declara explícitamente que el dominio NO recibe correo (RFC 7505).',
      recomendacion: 'Si el dominio debe recibir correo, publica uno o más MX. Si es solo emisor, esto es correcto.'
    });
  }
  if (!servidores.length) {
    return puntuacion.check({
      id: 'mx', categoria: 'MX', titulo: 'Servidores de correo (MX)', peso: PESOS_DOMINIO.mx, estado: 'error',
      detalle: 'No hay MX y el dominio tampoco resuelve por A/AAAA: nadie puede entregar correo en este dominio.',
      recomendacion: 'Publica los MX de tu proveedor de correo (por ejemplo Google Workspace o Microsoft 365).'
    });
  }
  const sinResolver = servidores.filter((s) => !s.direcciones.length);
  if (sinResolver.length) {
    return puntuacion.check({
      id: 'mx', categoria: 'MX', titulo: 'Servidores de correo (MX)', peso: PESOS_DOMINIO.mx, estado: 'error',
      detalle: `Sin dirección: ${sinResolver.map((s) => s.host).join(', ')}. Un MX que no resuelve hace que el correo rebote.`,
      recomendacion: 'Corrige o elimina los MX que no resuelven.'
    });
  }
  const implicito = servidores.some((s) => s.implicito);
  return puntuacion.check({
    id: 'mx', categoria: 'MX', titulo: 'Servidores de correo (MX)', peso: PESOS_DOMINIO.mx, estado: implicito ? 'warn' : 'ok',
    detalle: implicito
      ? 'No hay MX. El correo se entregará a la dirección A/AAAA del dominio (MX implícito, RFC 5321), que no siempre está permitido.'
      : `${servidores.length} MX y todos resuelven.`,
    recomendacion: implicito ? 'Publica un MX explícito en vez de depender del A/AAAA.' : null
  });
}

function checkSpf(spf) {
  if (!spf.presente) {
    return puntuacion.check({
      id: 'spf', categoria: 'SPF', titulo: 'SPF', peso: PESOS_DOMINIO.spf, estado: 'warn',
      detalle: 'No hay registro SPF. Cualquiera puede enviar en tu nombre y el receptor no tiene cómo saberlo.',
      recomendacion: 'Publica un TXT que empiece por "v=spf1" autorizando solo a tus servidores y terminando en "-all".'
    });
  }
  if (spf.errores.length) {
    return puntuacion.check({
      id: 'spf', categoria: 'SPF', titulo: 'SPF', peso: PESOS_DOMINIO.spf, estado: 'error',
      detalle: spf.errores.join(' '),
      recomendacion: 'Corrige el registro: debe haber uno solo, con sintaxis válida y sin "+all".'
    });
  }
  if (spf.avisos.length) {
    return puntuacion.check({
      id: 'spf', categoria: 'SPF', titulo: 'SPF', peso: PESOS_DOMINIO.spf, estado: 'warn',
      detalle: `${spf.lookups} consultas DNS. ${spf.avisos.join(' ')}`,
      recomendacion: 'Revisa las advertencias para endurecer el SPF.'
    });
  }
  return puntuacion.check({
    id: 'spf', categoria: 'SPF', titulo: 'SPF', peso: PESOS_DOMINIO.spf, estado: 'ok',
    detalle: `Registro único y válido (${spf.lookups} consultas DNS).`,
    recomendacion: null
  });
}

function checkDkim(dkim, dominio) {
  if (!dkim.encontrado) {
    return puntuacion.check({
      id: 'dkim', categoria: 'DKIM', titulo: 'DKIM', peso: PESOS_DOMINIO.dkim, estado: 'warn',
      detalle: `No se encontró clave en ningún selector probado bajo "${dominio}". Puede que uses un selector poco común.`,
      recomendacion: 'Publica el TXT del selector que usa tu proveedor, o escribe el selector en el campo "Selectores DKIM".'
    });
  }
  const elegido = dkim.registros.find((d) => d.encontrado && d.valido) || dkim.registros.find((d) => d.encontrado);
  if (!elegido) return null;
  if (elegido.revocada) {
    return puntuacion.check({
      id: 'dkim', categoria: 'DKIM', titulo: 'DKIM', peso: PESOS_DOMINIO.dkim, estado: 'error',
      detalle: `El selector "${elegido.selector}" está publicado pero con la clave "p=" vacía: la clave está revocada.`,
      recomendacion: 'Publica la clave pública nueva de ese selector, o borra el registro si ya no se usa.'
    });
  }
  if (!elegido.valido) {
    return puntuacion.check({
      id: 'dkim', categoria: 'DKIM', titulo: 'DKIM', peso: PESOS_DOMINIO.dkim, estado: 'error',
      detalle: `Selector "${elegido.selector}": ${elegido.errores.join(' ')}`,
      recomendacion: 'Corrige la clave pública del selector.'
    });
  }
  const estado = elegido.avisos.length ? 'warn' : 'ok';
  return puntuacion.check({
    id: 'dkim', categoria: 'DKIM', titulo: 'DKIM', peso: PESOS_DOMINIO.dkim, estado,
    detalle: `Selector "${elegido.selector}": ${elegido.tipoClave}${elegido.bits ? ` de ${elegido.bits} bits` : ''}${elegido.avisos.length ? `. ${elegido.avisos.join(' ')}` : ''}.`,
    recomendacion: elegido.avisos.length ? 'Revisa las advertencias del selector.' : null
  });
}

function checkDmarc(dmarc) {
  if (!dmarc.presente) {
    return puntuacion.check({
      id: 'dmarc', categoria: 'DMARC', titulo: 'DMARC', peso: PESOS_DOMINIO.dmarc, estado: 'warn',
      detalle: 'No hay DMARC. Sin él, SPF y DKIM no se alinean con la cabecera "From" y el suplantador no recibe castigo.',
      recomendacion: 'Publica "v=DMARC1; p=quarantine; rua=mailto:dmarc@tudominio" en "_dmarc". Empieza por p=none si quieres observar.'
    });
  }
  if (dmarc.errores.length) {
    return puntuacion.check({
      id: 'dmarc', categoria: 'DMARC', titulo: 'DMARC', peso: PESOS_DOMINIO.dmarc, estado: 'error',
      detalle: dmarc.errores.join(' '),
      recomendacion: 'Corrige el registro: "v=DMARC1" primero y una "p=" válida.'
    });
  }
  if (dmarc.politica === 'none') {
    return puntuacion.check({
      id: 'dmarc', categoria: 'DMARC', titulo: 'DMARC', peso: PESOS_DOMINIO.dmarc, estado: 'warn',
      detalle: 'DMARC con "p=none": solo observa. Los correos suplantados llegan igualmente.',
      recomendacion: 'Cuando tengas claro quién envía en tu nombre, sube a "p=quarantine" y luego a "p=reject".'
    });
  }
  const estado = dmarc.avisos.length ? 'warn' : 'ok';
  return puntuacion.check({
    id: 'dmarc', categoria: 'DMARC', titulo: 'DMARC', peso: PESOS_DOMINIO.dmarc, estado,
    detalle: `Política "p=${dmarc.politica}"${dmarc.pct !== 100 ? ` aplicada al ${dmarc.pct} %` : ''}${dmarc.avisos.length ? `. ${dmarc.avisos.join(' ')}` : ''}.`,
    recomendacion: dmarc.avisos.length ? 'Revisa las advertencias del DMARC.' : null
  });
}

function checkPtr(servidores) {
  const conIp = servidores.filter((s) => s.direcciones.length && !s.implicito);
  // Sin MX con dirección no hay PTR que mirar; el problema ya lo cuenta la
  // comprobación de MX. Excluirla aquí evita penalizar dos veces lo mismo y
  // que un dominio que solo emite correo (o que publica un null MX) salga mal.
  if (!conIp.length) return null;
  const sinPtr = conIp.filter((s) => !s.ptr.some((p) => p.nombres.length));
  const estado = sinPtr.length ? 'warn' : 'ok';
  return puntuacion.check({
    id: 'ptr', categoria: 'PTR', titulo: 'Resolución inversa (PTR) de los MX', peso: PESOS_DOMINIO.ptr, estado,
    detalle: sinPtr.length
      ? `Sin PTR: ${sinPtr.map((s) => s.host).join(', ')}. Un servidor de correo sin PTR pierde entregabilidad.`
      : `Todos los MX (${conIp.length}) tienen PTR.`,
    recomendacion: sinPtr.length ? 'Configura el PTR de la IP para que apunte al nombre del servidor.' : null
  });
}

function checkListas(servidores, conListas) {
  // Si el usuario la desactiva, no cuenta ni a favor ni en contra: sacarla del
  // máximo es lo honesto, porque no se ha comprobado nada.
  if (!conListas) return null;
  const conListasDatos = servidores.flatMap((s) => s.listas || []);
  if (!conListasDatos.length) {
    return puntuacion.check({ id: 'listas', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_DOMINIO.listas, estado: 'warn', detalle: 'No hay direcciones que consultar.', recomendacion: null });
  }
  const listadas = conListasDatos.filter((l) => l.resumen.listadas > 0);
  if (listadas.length) {
    return puntuacion.check({
      id: 'listas', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_DOMINIO.listas, estado: 'error',
      detalle: `Listadas: ${listadas.map((l) => `${l.ip} en ${l.resumen.zonasListadas.join(', ')}`).join('; ')}.`,
      recomendacion: 'Pide la retirada en cada lista y corrige la causa (equipo comprometido, spam saliente...).'
    });
  }
  // Los "sin datos" por falta de registro en Spamhaus NO bajan la nota.
  //
  // Esta herramienta puntua la configuracion de correo de un dominio, y casi
  // todas las consultas salen desde una IP de servidor que no esta registrada en
  // Spamhaus. Si eso contara como "las listas fallaron", ninguna configuracion
  // llegaria nunca al 10 en la practica, y el 10 dejaria de significar algo.
  //
  // El dato sigue estando ahi y se dice en el texto: no es que se esconda el
  // hecho de que no se ha podido mirar, es que no es un defecto del dominio.
  const sinAcceso = conListasDatos.reduce((s, l) => s + (l.resumen.sinDatosSinAcceso || 0), 0);
  const sinDatos = conListasDatos.reduce((s, l) => s + l.resumen.sinDatos, 0) - sinAcceso;
  const estado = sinDatos ? 'warn' : 'ok';

  const sinRespuesta = sinDatos ? `; ${sinDatos} sin respuesta de las listas.` : '';
  const sinPermiso =
    sinAcceso > 0
      ? ` Sin comprobar en ${sinAcceso} zonas de Spamhaus: no dan datos a resolvedores sin registrar.`
      : '';

  return puntuacion.check({
    id: 'listas', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_DOMINIO.listas, estado,
    detalle:
      `${conListasDatos.length} IP consultadas y ninguna listada` +
      `${sinRespuesta || '.'}${sinPermiso}`,
    recomendacion: sinDatos ? 'Algunas listas no respondieron; el resultado no es concluyente.' : null
  });
}

function checkMtaSts(m) {
  if (!m.presente) {
    return puntuacion.check({ id: 'mta-sts', categoria: 'Transporte', titulo: 'MTA-STS', peso: PESOS_DOMINIO.mtaSts, estado: 'warn', detalle: 'Sin MTA-STS: tus correos pueden ser degradados de TLS a texto plano en el trayecto.', recomendacion: 'Publica "_mta-sts.tudominio" con "v=STSv1; id=..." y sirve la política en https://mta-sts.tudominio/.well-known/mta-sts.txt.' });
  }
  const estado = m.errores.length ? 'error' : m.avisos.length ? 'warn' : 'ok';
  return puntuacion.check({ id: 'mta-sts', categoria: 'Transporte', titulo: 'MTA-STS', peso: PESOS_DOMINIO.mtaSts, estado, detalle: m.errores.join(' ') || m.avisos.join(' ') || `Publicado (id=${m.id}).`, recomendacion: estado === 'ok' ? null : 'Revisa el registro MTA-STS.' });
}

function checkTlsRpt(t) {
  if (!t.presente) {
    return puntuacion.check({ id: 'tls-rpt', categoria: 'Transporte', titulo: 'TLS-RPT', peso: PESOS_DOMINIO.tlsRpt, estado: 'warn', detalle: 'Sin TLS-RPT: no recibirás informes de fallos de TLS.', recomendacion: 'Publica "_smtp._tls.tudominio" con "v=TLSRPTv1; rua=mailto:..." para recibir avisos.' });
  }
  const estado = t.errores.length ? 'error' : t.avisos.length ? 'warn' : 'ok';
  return puntuacion.check({ id: 'tls-rpt', categoria: 'Transporte', titulo: 'TLS-RPT', peso: PESOS_DOMINIO.tlsRpt, estado, detalle: t.errores.join(' ') || t.avisos.join(' ') || `Informes a ${t.rua.join(', ')}.`, recomendacion: estado === 'ok' ? null : 'Revisa el registro TLS-RPT.' });
}

function checkBimi(b) {
  if (!b.presente) {
    return puntuacion.check({ id: 'bimi', categoria: 'Transporte', titulo: 'BIMI', peso: PESOS_DOMINIO.bimi, estado: 'warn', detalle: 'Sin BIMI: tu logotipo no aparecerá en clientes compatibles. Es opcional.', recomendacion: 'Publica "default._bimi.tudominio" con "v=BIMI1; l=https://.../logo.svg; a=https://.../vmc.pem".' });
  }
  const estado = b.errores.length ? 'error' : b.avisos.length ? 'warn' : 'ok';
  return puntuacion.check({ id: 'bimi', categoria: 'Transporte', titulo: 'BIMI', peso: PESOS_DOMINIO.bimi, estado, detalle: b.errores.join(' ') || b.avisos.join(' ') || 'Registro BIMI completo.', recomendacion: estado === 'ok' ? null : 'Revisa el registro BIMI.' });
}

/* ------------------------------------------------------------------ *
 * Comprobaciones — mensaje
 * ------------------------------------------------------------------ */

function checkSpfMensaje(mensaje, spfDominio, dominio) {
  const spf = mensaje.spf;
  const resultado = spf?.resultado || null;
  const alineado = dominio && spfDominio.presente;
  if (resultado === 'pass') {
    return puntuacion.check({ id: 'spf-msg', categoria: 'SPF', titulo: 'SPF del remitente', peso: PESOS_MENSAJE.spf, estado: 'ok', detalle: `El receptor validó SPF (pass)${alineado ? ' y el dominio publica SPF' : ''}.`, recomendacion: null });
  }
  if (!resultado) {
    return puntuacion.check({ id: 'spf-msg', categoria: 'SPF', titulo: 'SPF del remitente', peso: PESOS_MENSAJE.spf, estado: 'warn', detalle: 'El mensaje no trae el resultado de SPF en "Authentication-Results" ni "Received-SPF".', recomendacion: 'Asegúrate de enviar desde un servidor autorizado por el SPF del dominio.' });
  }
  if (['softfail', 'neutral', 'none'].includes(resultado)) {
    return puntuacion.check({ id: 'spf-msg', categoria: 'SPF', titulo: 'SPF del remitente', peso: PESOS_MENSAJE.spf, estado: 'warn', detalle: `SPF = ${resultado}: el remitente no está claramente autorizado.`, recomendacion: 'Añade la IP del servidor emisor al SPF del dominio.' });
  }
  return puntuacion.check({ id: 'spf-msg', categoria: 'SPF', titulo: 'SPF del remitente', peso: PESOS_MENSAJE.spf, estado: 'error', detalle: `SPF = ${resultado}: el remitente no está autorizado.`, recomendacion: 'Revisa el SPF: probablemente no incluye este servidor de envío.' });
}

function checkDkimMensaje(mensaje, dominio) {
  const firmas = mensaje.dkimFirmas;
  const resultados = mensaje.dkim || [];
  const pase = resultados.find((d) => d.resultado === 'pass');
  if (pase) {
    return puntuacion.check({ id: 'dkim-msg', categoria: 'DKIM', titulo: 'Firma DKIM', peso: PESOS_MENSAJE.dkim, estado: 'ok', detalle: `DKIM validado (d=${pase.dominio || dominio || '?'}).`, recomendacion: null });
  }
  if (resultados.some((d) => d.resultado === 'fail')) {
    return puntuacion.check({ id: 'dkim-msg', categoria: 'DKIM', titulo: 'Firma DKIM', peso: PESOS_MENSAJE.dkim, estado: 'error', detalle: 'DKIM = fail: la firma no valida. La clave pública y la privada no cuadran.', recomendacion: 'Comprueba que el selector publicado corresponde a la clave con la que firmas.' });
  }
  if (!firmas.length) {
    return puntuacion.check({ id: 'dkim-msg', categoria: 'DKIM', titulo: 'Firma DKIM', peso: PESOS_MENSAJE.dkim, estado: 'warn', detalle: 'El mensaje no lleva cabecera "DKIM-Signature".', recomendacion: 'Configura la firma DKIM en el servidor de envío.' });
  }
  return puntuacion.check({ id: 'dkim-msg', categoria: 'DKIM', titulo: 'Firma DKIM', peso: PESOS_MENSAJE.dkim, estado: 'warn', detalle: `Lleva ${firmas.length} firma(s) DKIM pero el receptor no reportó el resultado.`, recomendacion: 'Revisa que la clave pública del selector esté publicada.' });
}

function checkDmarcMensaje(mensaje, dmarcDominio, dominio) {
  const resultado = mensaje.dmarc?.resultado || null;
  if (resultado === 'pass') {
    return puntuacion.check({ id: 'dmarc-msg', categoria: 'DMARC', titulo: 'DMARC del remitente', peso: PESOS_MENSAJE.dmarc, estado: 'ok', detalle: 'DMARC validado (pass).', recomendacion: null });
  }
  if (resultado && ['fail', 'reject', 'quarantine'].includes(resultado)) {
    return puntuacion.check({ id: 'dmarc-msg', categoria: 'DMARC', titulo: 'DMARC del remitente', peso: PESOS_MENSAJE.dmarc, estado: 'error', detalle: `DMARC = ${resultado}.`, recomendacion: 'Asegura que SPF o DKIM alinean con el dominio del remitente.' });
  }
  if (!dmarcDominio.presente) {
    return puntuacion.check({ id: 'dmarc-msg', categoria: 'DMARC', titulo: 'DMARC del remitente', peso: PESOS_MENSAJE.dmarc, estado: 'warn', detalle: `${dominio || 'El dominio del remitente'} no publica DMARC.`, recomendacion: 'Publica DMARC en "_dmarc" del dominio.' });
  }
  return puntuacion.check({ id: 'dmarc-msg', categoria: 'DMARC', titulo: 'DMARC del remitente', peso: PESOS_MENSAJE.dmarc, estado: 'warn', detalle: 'El mensaje no reporta un resultado DMARC.', recomendacion: 'Revisa la configuración de DMARC del dominio.' });
}

function checkPtrMensaje(mensaje, ptr) {
  if (!mensaje.ipEmisor) {
    return puntuacion.check({ id: 'ptr-msg', categoria: 'PTR', titulo: 'Resolución inversa (PTR)', peso: PESOS_MENSAJE.ptr, estado: 'warn', detalle: 'No se pudo extraer la IP emisora del mensaje.', recomendacion: 'Revisa que el .eml incluya las cabeceras "Received".' });
  }
  return puntuacion.check({
    id: 'ptr-msg', categoria: 'PTR', titulo: 'Resolución inversa (PTR)', peso: PESOS_MENSAJE.ptr,
    estado: ptr.length ? 'ok' : 'warn',
    detalle: ptr.length ? `${mensaje.ipEmisor} → ${ptr.join(', ')}.` : `${mensaje.ipEmisor} no tiene PTR.`,
    recomendacion: ptr.length ? null : 'Configura el PTR de la IP del servidor de envío.'
  });
}

function checkListasMensaje(listas) {
  if (!listas) {
    return puntuacion.check({ id: 'listas-msg', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_MENSAJE.listas, estado: 'warn', detalle: 'No se pudo comprobar (sin IP emisora o desactivado).', recomendacion: null });
  }
  if (listas.resumen.listadas > 0) {
    return puntuacion.check({ id: 'listas-msg', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_MENSAJE.listas, estado: 'error', detalle: `La IP emisora está en: ${listas.resumen.zonasListadas.join(', ')}.`, recomendacion: 'Es la causa más grave de spam: pide la retirada y corrige el origen.' });
  }
  // Mismo criterio que en modo dominio: lo que no se ha podido mirar por falta de
  // registro en Spamhaus se dice, pero no hace bajar la puntuacion del mensaje.
  const sinAcceso = listas.resumen.sinDatosSinAcceso || 0;
  const sinDatos = listas.resumen.sinDatos - sinAcceso;
  return puntuacion.check({
    id: 'listas-msg', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_MENSAJE.listas,
    estado: sinDatos ? 'warn' : 'ok',
    detalle: sinDatos
      ? `${sinDatos} listas sin respuesta.`
      : `La IP emisora no está en ninguna lista` +
        (sinAcceso ? `. Sin comprobar en ${sinAcceso} zonas de Spamhaus: no dan datos a resolvedores sin registrar.` : '.'),
    recomendacion: null
  });
}

function checkFormato(mensaje) {
  const faltan = [];
  if (!mensaje.messageId) faltan.push('Message-ID');
  if (!mensaje.fecha) faltan.push('Date');
  if (!mensaje.from) faltan.push('From');
  if (!mensaje.mimeVersion) faltan.push('MIME-Version');
  const estado = faltan.length ? 'warn' : 'ok';
  return puntuacion.check({
    id: 'formato', categoria: 'Formato', titulo: 'Cabeceras del mensaje', peso: PESOS_MENSAJE.formato, estado,
    detalle: faltan.length ? `Faltan cabeceras: ${faltan.join(', ')}.` : 'From, Date, Message-ID y MIME-Version presentes.',
    recomendacion: faltan.length ? 'Deja que el cliente de correo genere esas cabeceras; no las borres al construir el mensaje.' : null
  });
}

function checkUnsubscribe(mensaje) {
  const valor = mensaje.listUnsubscribe;
  if (!valor) {
    return puntuacion.check({ id: 'unsubscribe', categoria: 'Formato', titulo: 'Cabecera List-Unsubscribe', peso: PESOS_MENSAJE.unsubscribe, estado: 'warn', detalle: 'No hay "List-Unsubscribe". En correo masivo es casi obligatorio y su ausencia penaliza.', recomendacion: 'Añade "List-Unsubscribe: <mailto:...>" y, mejor, "List-Unsubscribe-Post: List-Unsubscribe=One-Click".' });
  }
  const oneClick = mensaje.listUnsubscribePost && /one-click/i.test(mensaje.listUnsubscribePost);
  return puntuacion.check({
    id: 'unsubscribe', categoria: 'Formato', titulo: 'Cabecera List-Unsubscribe', peso: PESOS_MENSAJE.unsubscribe,
    estado: oneClick ? 'ok' : 'warn',
    detalle: oneClick ? 'Presente con baja en un clic.' : 'Presente, pero sin "List-Unsubscribe-Post: One-Click".',
    recomendacion: oneClick ? null : 'Añade "List-Unsubscribe-Post: List-Unsubscribe=One-Click" para la baja en un clic.'
  });
}

/* ------------------------------------------------------------------ *
 * Comprobaciones auxiliares
 * ------------------------------------------------------------------ */

/** Evalúa los selectores DKIM ya consultados. */
function evaluarSelectores(respuestas, selectores, dominio) {
  const registros = selectores.map((selector) => {
    const r = respuestas.get(`dkim:${selector}`);
    const parseado = dkimMod.parsear(registrosTxtDe(r), { selector, dominio });
    return parseado;
  });
  const encontrado = registros.some((d) => d.encontrado);
  return { registros, encontrado, selectores };
}

function primerDominioDkim(mensaje) {
  return mensaje.dkimFirmas.find((f) => f.dominio)?.dominio || mensaje.dkim.find((d) => d.dominio)?.dominio || null;
}

/* ------------------------------------------------------------------ *
 * Presentación
 * ------------------------------------------------------------------ */

function pintarInforme(result, datos) {
  const evaluado = puntuacion.evaluar(datos.checks);

  addSummary(result, 'Puntuación', puntuacion.formatear(evaluado.nota), evaluado.tone);
  addSummary(result, 'Puntos', `${evaluado.obtenidos} de ${evaluado.max}`, evaluado.tone);
  addSummary(result, 'Comprobaciones', `${evaluado.checks.length - evaluado.fallos.length} de ${evaluado.checks.length} correctas`, evaluado.fallos.length ? 'warn' : 'ok');
  addSummary(result, 'Modo', datos.modo);
  addSummary(result, datos.modo === 'Dominio' ? 'Dominio' : 'IP remitente', datos.objetivo);

  addSection(result, {
    id: 'puntuacion',
    title: 'Puntuación',
    description: 'Cada comprobación reparte puntos. Una advertencia vale la mitad; un fallo, nada.',
    kind: K.BARRA,
    value: Math.round(evaluado.nota * 10),
    tone: evaluado.tone
  });

  addSection(result, {
    id: 'comprobaciones',
    title: 'Comprobaciones',
    description: 'Lo que se ha revisado y cuánto pesa, de mayor a menor problema.',
    kind: K.TABLA,
    columns: ['Comprobación', 'Categoría', 'Resultado', 'Puntos', 'Detalle'],
    anchoColumnas: [26, 12, 11, 9, 42],
    rows: [...evaluado.checks]
      .sort((a, b) => pesoProblema(b) - pesoProblema(a))
      .map((c) => [
        c.titulo,
        c.categoria,
        { valor: etiquetaEstado(c.estado), tone: c.estado === 'ok' ? 'ok' : c.estado === 'warn' ? 'warn' : 'bad' },
        `${puntosDe(c)}/${c.peso}`,
        c.detalle || '—'
      ])
  });

  if (datos.registros && datos.registros.length) {
    addSection(result, {
      id: 'registros',
      title: 'Registros y valores encontrados',
      description: 'Los valores crudos que se han consultado, sin interpretar.',
      kind: K.TABLA,
      columns: ['Nombre', 'Tipo', 'Valor', 'Estado'],
      anchoColumnas: [26, 14, 48, 12],
      rows: datos.registros
    });
  }

  if (typeof datos.seccionesExtra === 'function') datos.seccionesExtra(result);

  for (const c of evaluado.fallos) {
    addFinding(result, {
      severity: c.estado === 'error' ? SEVERIDADES.ERROR : SEVERIDADES.WARN,
      title: c.titulo,
      detail: c.detalle,
      recommendation: c.recomendacion
    });
  }
}

function seccionMx(result, servidores, conListas) {
  if (!servidores.length) return;
  addSection(result, {
    id: 'mx',
    title: 'Servidores de correo (MX)',
    kind: K.TABLA,
    columns: ['Prioridad', 'Host', 'Direcciones', 'PTR', ...(conListas ? ['Listas negras'] : []), 'Estado'],
    anchoColumnas: conListas ? [10, 26, 24, 18, 12, 10] : [12, 32, 30, 16, 10],
    rows: servidores.map((s) => {
      const listada = (s.listas || []).filter((l) => l.resumen.listadas > 0);
      const sinResolver = !s.direcciones.length;
      return [
        s.prioridad ?? '—',
        s.host,
        s.direcciones.length ? s.direcciones.join(', ') : 'no resuelve',
        s.ptr?.map((p) => p.nombres.join(', ') || 'sin PTR').join('; ') || '—',
        ...(conListas ? [{ valor: listada.length ? 'listada' : 'limpia', tone: listada.length ? 'bad' : 'ok' }] : []),
        { valor: sinResolver ? 'Falla' : s.implicito ? 'Implícito' : 'OK', tone: sinResolver ? 'bad' : s.implicito ? 'warn' : 'ok' }
      ];
    })
  });
}

function seccionSpf(result, spf) {
  if (!spf.presente) return;
  addSection(result, {
    id: 'spf',
    title: 'SPF',
    kind: K.PARES,
    items: [
      ['Registro', spf.valor],
      ['Consultas DNS', `${spf.lookups} de ${spf.limiteLookups}`, spf.excedeLimite ? 'bad' : spf.lookups >= spf.limiteLookups ? 'warn' : 'ok'],
      ['Política por defecto', spf.calificacionAll || (spf.redirect ? `redirect=${spf.redirect}` : 'sin "all"'), spf.calificacionAll === 'pass' ? 'bad' : spf.calificacionAll === 'ok' ? 'ok' : 'neutral'],
      ['Include', spf.includes.length ? spf.includes.join(', ') : '—'],
      ['Mecanismos', spf.mecanismos.map((m) => m.termino).join(' ')]
    ]
  });
}

function seccionDkim(result, dkim, dominio) {
  if (!dominio) return;
  addSection(result, {
    id: 'dkim',
    title: 'DKIM',
    description: 'Se prueban los selectores indicados y los habituales. Un selector válido basta para firmar.',
    kind: K.TABLA,
    columns: ['Selector', 'Nombre', 'Encontrado', 'Tipo', 'Bits', 'Estado'],
    anchoColumnas: [16, 34, 12, 10, 8, 20],
    rows: dkim.registros
      .filter((d) => d.encontrado)
      .map((d) => [
        d.selector,
        nombreDkim(d.selector, dominio),
        'Sí',
        d.tipoClave || '—',
        d.bits ?? '—',
        { valor: d.revocada ? 'Revocada' : d.valido ? (d.avisos.length ? 'Con avisos' : 'Válida') : 'Inválida', tone: d.revocada || !d.valido ? 'bad' : d.avisos.length ? 'warn' : 'ok' }
      ])
      .concat(
        dkim.registros.every((d) => !d.encontrado)
          ? [['—', `*.${'_domainkey'}.${dominio}`, 'No', '—', '—', { valor: 'Sin clave', tone: 'warn' }]]
          : []
      )
  });
}

function seccionDmarc(result, dmarc) {
  if (!dmarc.presente) return;
  addSection(result, {
    id: 'dmarc',
    title: 'DMARC',
    kind: K.PARES,
    items: [
      ['Registro', dmarc.valor],
      ['Política', dmarc.politica || '—', dmarc.politica === 'none' ? 'warn' : dmarc.politica ? 'ok' : 'bad'],
      ['Subdominios', dmarc.politicaSubdominios || 'hereda'],
      ['Porcentaje', `${dmarc.pct} %`, dmarc.pct < 100 ? 'warn' : 'ok'],
      ['Informes agregados (rua)', dmarc.rua.length ? dmarc.rua.join(', ') : '—'],
      ['Alineación SPF / DKIM', `${dmarc.aspf || 'r'} / ${dmarc.adkim || 'r'}`]
    ]
  });
}

function seccionTransporte(result, transporte) {
  addSection(result, {
    id: 'transporte',
    title: 'Extensiones de transporte',
    kind: K.TABLA,
    columns: ['Extensión', 'Nombre', 'Estado', 'Valor'],
    anchoColumnas: [16, 30, 14, 40],
    rows: [
      filaTransporte('MTA-STS', '_mta-sts', transporte.mtaSts),
      filaTransporte('TLS-RPT', '_smtp._tls', transporte.tlsRpt),
      filaTransporte('BIMI', 'default._bimi', transporte.bimi)
    ]
  });
}

function filaTransporte(nombre, prefijo, dato) {
  if (!dato.presente) return [nombre, prefijo, { valor: 'No publicado', tone: 'warn' }, '—'];
  const estado = dato.errores.length ? 'bad' : dato.avisos.length ? 'warn' : 'ok';
  return [nombre, prefijo, { valor: dato.errores.length ? 'Inválido' : dato.avisos.length ? 'Con avisos' : 'OK', tone: estado }, dato.valor];
}

function seccionCabeceras(result, mensaje) {
  addSection(result, {
    id: 'cabeceras',
    title: 'Cabeceras del mensaje',
    kind: K.PARES,
    items: [
      ['From', mensaje.from || '—'],
      ['Return-Path', mensaje.returnPath || '—'],
      ['Reply-To', mensaje.replyTo || '—'],
      ['Asunto', mensaje.asunto || '—'],
      ['Fecha', mensaje.fecha || '—'],
      ['Message-ID', mensaje.messageId || '—'],
      ['IP emisora', mensaje.ipEmisor || '—'],
      ['Saltos (Received)', String(mensaje.recibidas.length)],
      ['Adjuntos', String(mensaje.adjuntos)]
    ]
  });
}

function seccionAutenticacion(result, mensaje, spfDominio, dmarcDominio, dominio) {
  const filas = [
    ['SPF', mensaje.spf?.resultado || 'sin dato', mensaje.spf?.fuente || '—', spfDominio.presente ? 'dominio con SPF' : 'sin SPF en el dominio'],
    ['DKIM', mensaje.dkim.length ? mensaje.dkim.map((d) => d.resultado).join(', ') : 'sin dato', mensaje.dkimFirmas.map((f) => f.selector || '—').join(', ') || 'sin firma', mensaje.dkimFirmas.map((f) => f.dominio || '—').join(', ') || '—'],
    ['DMARC', mensaje.dmarc?.resultado || 'sin dato', mensaje.dmarc?.dominio || dominio || '—', dmarcDominio.presente ? 'dominio con DMARC' : 'sin DMARC en el dominio']
  ];
  addSection(result, {
    id: 'autenticacion',
    title: 'Resultado de autenticación',
    description: 'Lo que dejó escrito el receptor en "Authentication-Results" / "Received-SPF".',
    kind: K.TABLA,
    columns: ['Método', 'Resultado', 'Dominio / selector', 'Contexto'],
    anchoColumnas: [14, 20, 34, 32],
    rows: filas
  });
}

function seccionContenido(result, contenido) {
  addSection(result, {
    id: 'contenido',
    title: 'Contenido del mensaje',
    description: 'Aproximación a SpamAssassin: no es el motor real, es un orientador.',
    kind: K.TABLA,
    columns: ['Aspecto', 'Resultado', 'Detalle'],
    anchoColumnas: [28, 14, 58],
    rows: contenido.checks.map((c) => [c.titulo, { valor: etiquetaEstado(c.estado), tone: c.estado === 'ok' ? 'ok' : c.estado === 'warn' ? 'warn' : 'bad' }, c.detalle || '—'])
  });
}

function seccionIp(result, mensaje, ptr, listas) {
  addSection(result, {
    id: 'ip',
    title: 'IP emisora',
    kind: K.PARES,
    items: [
      ['Dirección', mensaje.ipEmisor || '—'],
      ['PTR', ptr.length ? ptr.join(', ') : 'sin PTR', ptr.length ? 'ok' : 'warn'],
      ['Listas negras', listas ? (listas.resumen.listadas > 0 ? `listada en ${listas.resumen.zonasListadas.join(', ')}` : 'limpia') : 'sin comprobar', listas && listas.resumen.listadas > 0 ? 'bad' : 'ok'],
      ['Saltos hasta el receptor', String(mensaje.recibidas.length)]
    ]
  });
}

/* ------------------------------------------------------------------ *
 * Helpers de presentación
 * ------------------------------------------------------------------ */

function registrosTxtDe(registro) {
  if (!registro?.ok) return [];
  return registro.valores.map((v) => (Array.isArray(v) ? v.join('') : String(v))).map((t) => t.trim()).filter(Boolean);
}

function resumenMx(mx) {
  if (mx.estado === 'null-mx') return 'null MX (no recibe correo)';
  if (!mx.presentes.length) return '—';
  return mx.presentes.map((h) => `${h.priority} ${h.exchange}`).join(', ');
}

function filasRegistros(filas) {
  return filas.map(([nombre, tipo, valor, estado]) => [
    nombre,
    tipo,
    valor || '—',
    typeof estado === 'string' ? { valor: etiquetaEstado(estado), tone: tonoDe(estado) } : estado || '—'
  ]);
}

function filasDkim(_secciones, registros, dominio) {
  return registros
    .filter((d) => d.encontrado)
    .slice(0, 5)
    .map((d) => [nombreDkim(d.selector, dominio), 'TXT (DKIM)', d.valor, d.revocada || !d.valido ? 'error' : d.avisos.length ? 'warn' : 'ok']);
}

function tonoDe(estado) {
  if (estado === 'ok' || estado === 'pass') return 'ok';
  if (estado === 'error' || estado === 'fail') return 'bad';
  if (estado === 'warn') return 'warn';
  return 'neutral';
}

function etiquetaEstado(estado) {
  return estado === 'ok' ? 'OK' : estado === 'warn' ? 'Revisar' : estado === 'error' ? 'Falla' : '—';
}

function puntosDe(c) {
  const factor = c.estado === 'ok' ? 1 : c.estado === 'warn' ? 0.5 : 0;
  return Math.round(c.peso * factor * 100) / 100;
}

function pesoProblema(c) {
  return c.estado === 'error' ? 2 : c.estado === 'warn' ? 1 : 0;
}

module.exports = {
  id: ID,
  titulo: 'Comprobador de correo',
  descripcion:
    'Puntúa de 0 a 10 la configuración de correo de un dominio (MX, SPF, DKIM, DMARC, PTR, listas negras y transporte) o de un correo enviado (.eml), al estilo de mail-tester.',
  icon: '📧',
  sinRed: false,
  campos: CAMPOS,
  ejecutar,
  _internas: {
    PESOS_DOMINIO,
    PESOS_MENSAJE,
    elegirSelectores,
    parsearMx,
    paramsSeguros,
    recogerMensaje,
    registrosTxtDe,
    CAMPOS
  }
};
