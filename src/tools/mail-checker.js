/**
 * mail-checker — puntúa la configuración de correo de un dominio o de un correo
 * enviado, siguiendo el enfoque de mail-tester.
 *
 * DOS MODOS, UNA HERRAMIENTA
 *   1. Dominio: consulta MX, SPF, DKIM, DMARC, PTR, listas negras y las
 *      extensiones de transporte (MTA-STS, TLS-RPT, BIMI) por DNS.
 *   2. Mensaje: analiza la fuente (.eml) de un correo ya enviado. Evalúa SPF
 *      contra la IP real, verifica la firma DKIM en criptográfico y comprueba
 *      la alineación de DMARC con `core/mail/verificar`; cuando no se puede
 *      (sin IP, sin clave publicada, firma sin "b="), se apoya en lo que dejó
 *      escrito el receptor en `Authentication-Results` y el informe dice de
 *      dónde sale cada veredicto. También mira la reputación de la IP emisora,
 *      la coherencia HELO/PTR y el contenido.
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
const webMod = require('../core/net/web');
const { normalizarDominio, normalizarTimeout } = require('../core/dominio');
const { nombreDkim } = require('../core/mail/comun');
const spfMod = require('../core/mail/spf');
const dmarcMod = require('../core/mail/dmarc');
const dkimMod = require('../core/mail/dkim');
const transporteMod = require('../core/mail/transporte');
const mensajeMod = require('../core/mail/mensaje');
const contenidoMod = require('../core/mail/contenido');
const puntuacion = require('../core/mail/puntuacion');
const verificarMod = require('../core/mail/verificar');

const ID = 'mail-checker';

/**
 * Pesos del modo dominio. Los principales suman 10; DANE solo entra cuando el
 * dominio publica TLSA, y al reescalar sobre el máximo no cambia la nota del
 * que no lo publica.
 */
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
  bimi: 0.5,
  dane: 0.5
};

/** Pesos del modo mensaje. Los principales suman 7.5; con el contenido, 9.5. */
const PESOS_MENSAJE = {
  spf: 1.5,
  dkim: 1.5,
  dmarc: 1.0,
  ptr: 1.0,
  listas: 2.0,
  formato: 0.5,
  unsubscribe: 0
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
  const pedirWeb = ctx.web?.pedir || webMod.pedir;
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
      await modoDominio(result, params, { dns, blacklists, pedirWeb, fetchImpl: ctx.fetchImpl, timeout, log });
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
  const { dns, blacklists, pedirWeb, fetchImpl, timeout, log } = entorno;

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
  const spfListas = await consultarIpSpf(blacklists, spf, { conListas, timeout });
  const dbl = await consultarDbl(blacklists, dominio, conListas, timeout);
  const transporte = extensiones
    ? transporteMod.parsear({ mtaSts: registrosTxtDe(r('mtaSts')), tlsRpt: registrosTxtDe(r('tlsRpt')), bimi: registrosTxtDe(r('bimi')) })
    : null;
  const politica = extensiones
    ? await consultarPoliticaMtaSts(dominio, transporte?.mtaSts, { pedir: pedirWeb, fetchImpl, timeout, log })
    : null;
  const dane = await consultarDane(dns, servidores, timeout);

  // --- comprobaciones -------------------------------------------------------
  const checks = [
    checkResolucion(existe, dominio),
    checkMx(mx, servidores),
    checkSpf(spf),
    checkDkim(dkim, dominio),
    checkDmarc(dmarc),
    checkPtr(servidores),
    checkListas(servidores, conListas, spfListas, dbl),
    ...(extensiones ? [checkMtaSts(transporte.mtaSts, politica), checkTlsRpt(transporte.tlsRpt), checkBimi(transporte.bimi)] : []),
    checkDane(dane)
  ];

  pintarInforme(result, {
    modo: 'Dominio',
    objetivo: dominio,
    checks,
    registros: filasRegistros([
      [`${dominio}`, 'MX', resumenMx(mx), mx.estado],
      [`${dominio}`, 'TXT (SPF)', spf.valor || '—', spf.presente ? 'ok' : 'warn'],
      [`_dmarc.${dominio}`, 'TXT (DMARC)', dmarc.valor || '—', dmarc.presente ? 'ok' : 'warn'],
      ...filasDkim(result.sections, dkim.registros, dominio),
      ...filasTlsa(dane),
      ...filasDbl(dbl)
    ]),
    seccionesExtra: (result_) => {
      seccionMx(result_, servidores, conListas);
      seccionSpf(result_, spf);
      seccionSpfIp(result_, spfListas);
      seccionDkim(result_, dkim, dominio);
      seccionDmarc(result_, dmarc);
      if (transporte) seccionTransporte(result_, transporte);
      if (politica) seccionPoliticaMtaSts(result_, politica);
      seccionDane(result_, dane);
    }
  });
}

/**
 * Descarga y valida la politica MTA-STS (RFC 8461) cuando el dominio publica el
 * registro `_mta-sts`. Sin registro no hay politica que aplicar: no se pide.
 *
 * Nunca lanza. Un fallo de red se convierte en un estado "inaccesible" para que
 * el informe lo diga sin hundir la comprobacion.
 *
 * @param {string} dominio
 * @param {object|null} registroMtaSts Resultado de `parsear` para `_mta-sts`.
 * @param {object} opciones `pedir` (ha de respetar el contrato de `web.pedir`),
 *   `fetchImpl`, `timeout`, `log`.
 * @returns {Promise<object|null>}
 */
async function consultarPoliticaMtaSts(dominio, registroMtaSts, { pedir, fetchImpl, timeout, log } = {}) {
  if (!registroMtaSts?.presente) return null;
  const url = `https://mta-sts.${dominio}/.well-known/mta-sts.txt`;
  try {
    const respuesta = await pedir(new URL(url), { metodo: 'GET', timeoutMs: timeout, fetchImpl });
    const texto = String(respuesta.cuerpo?.texto || '');
    if (respuesta.estado !== 200 || !texto.trim()) {
      return {
        estado: 'no-servida',
        url,
        status: respuesta.estado,
        policy: null,
        errores: [`La política no se sirve en ${url} (HTTP ${respuesta.estado}).`],
        avisos: []
      };
    }
    const policy = transporteMod.parsearPoliticaMtaSts(texto);
    return { estado: policy.valido ? 'ok' : 'invalida', url, status: respuesta.estado, policy, errores: policy.errores, avisos: policy.avisos };
  } catch (error) {
    log?.warn?.(`MTA-STS: no se pudo descargar la política de ${dominio}: ${error.message}`);
    return {
      estado: 'inaccesible',
      url,
      status: null,
      policy: null,
      errores: [`No se pudo descargar la política de ${url}: ${error.message}`],
      avisos: []
    };
  }
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
      const nombres = (await dns.resolverPTR(ip)) || [];
      ptr.push({ ip, nombres, coherente: await verificarFcrdns(dns, ip, nombres, timeout) });
    }
    servidores.push({ host: host.exchange, prioridad: host.priority, direcciones, ptr, implicito: false });
  }
  return servidores;
}

/**
 * Comprueba el FCrDNS de una inversa: el nombre que devuelve el PTR debe
 * resolver otra vez a la misma IP. Devuelve true/false, o null si no hay PTR.
 */
async function verificarFcrdns(dns, ip, nombres, timeout) {
  const nombresPrueba = (nombres || []).slice(0, 2);
  if (!nombresPrueba.length) return null;
  for (const nombre of nombresPrueba) {
    const a = await dns.consultar(nombre, 'A', { timeout, reintentos: 1 });
    if (ipsDe(a).some((v) => v === ip)) return true;
    const aaaa = await dns.consultar(nombre, 'AAAA', { timeout, reintentos: 1 });
    if (ipsDe(aaaa).some((v) => v === ip)) return true;
  }
  return false;
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

/**
 * Consulta listas negras para las IPs que el SPF declara como autorizadas.
 * Si una de ellas está en una lista, un receptor puede marcar el correo del
 * dominio como spam aunque la configuracion de registros sea impecable.
 */
async function consultarIpSpf(blacklists, spf, { conListas, timeout }) {
  if (!conListas || !spf?.presente) return [];
  const ips = [];
  for (const m of spf.mecanismos || []) {
    if ((m.nombre === 'ip4' || m.nombre === 'ip6') && m.valor) {
      const base = m.valor.split('/')[0];
      if (!ips.includes(base)) ips.push(base);
    }
  }
  const salida = [];
  for (const ip of ips) {
    try {
      const { resultados, resumen } = await blacklists.consultar(ip, { timeout, concurrencia: 4 });
      salida.push({ ip, origen: 'SPF', resultados, resumen });
    } catch (error) {
      salida.push({ ip, origen: 'SPF', resultados: [], resumen: { listadas: 0, sinDatos: 1 }, error: error.message });
    }
  }
  return salida;
}

/**
 * Consulta los TLSA (DANE) de los servidores de correo del dominio.
 *
 * Solo los MX reales (los que tienen dirección y no son el destino implícito
 * del propio dominio): el TLSA se cuelga del servidor, no del domino. Se
 * limitan a los primeros para no consultar sin fin.
 *
 * @param {object} dns
 * @param {object[]} servidores
 * @param {number} timeout
 * @returns {Promise<{hosts: Array<{host: string, registros: object[], estado: string}>, consultado: boolean}>}
 */
async function consultarDane(dns, servidores, timeout) {
  const hosts = (servidores || [])
    .filter((s) => s.direcciones.length && !s.implicito)
    .slice(0, 4)
    .map((s) => s.host);
  if (!hosts.length) return { hosts: [], consultado: false };

  const consultas = hosts.map((host) => ({ clave: `tlsa:${host}`, nombre: `_25._tcp.${host}`, tipo: 'TLSA' }));
  const respuestas = indexar(await consultarMuchas(dns, consultas, timeout));

  return {
    consultado: true,
    hosts: hosts.map((host) => {
      const registro = respuestas.get(`tlsa:${host}`) || { ok: false, valores: [] };
      const registros = (registro.ok ? registro.valores : []).map(normalizarTlsa).filter(Boolean);
      const estado = registros.length
        ? registros.some((t) => t.usage === 2 || t.usage === 3)
          ? 'dane'
          : registros.some((t) => t.usage === 0 || t.usage === 1)
            ? 'pkix'
            : 'dudoso'
        : 'sin-tlsa';
      return { host, registros, estado };
    })
  };
}

/** Pone un TLSA ya decodificado en la forma estable que usan las secciones. */
function normalizarTlsa(dato) {
  if (!dato || typeof dato !== 'object') return null;
  return {
    usage: Number(dato.usage) || 0,
    selector: Number(dato.selector) || 0,
    matchingType: Number(dato.matchingType) || 0,
    certificate: String(dato.certificate || '')
  };
}

/* ------------------------------------------------------------------ *
 * Modo mensaje
 * ------------------------------------------------------------------ */

async function modoMensaje(result, mensaje, entorno) {
  const { dns, blacklists, timeout, log } = entorno;

  const dominio = mensaje.fromDominio || mensaje.returnPathDominio || primerDominioDkim(mensaje);
  result.target = dominio || mensaje.ipEmisor || 'correo enviado';
  log?.info?.(`Analizando un correo de ${mensaje.from || 'remitente desconocido'}`);

  const helo = heloDe(mensaje);
  const conListas = result.params.listasNegras !== false;

  // --- DNS del dominio remitente ------------------------------------------
  const consultas = [];
  if (dominio) {
    consultas.push({ clave: 'txt', nombre: dominio, tipo: 'TXT' });
    consultas.push({ clave: 'dmarc', nombre: `_dmarc.${dominio}`, tipo: 'TXT' });
  }
  const respuestas = indexar(consultas.length ? await consultarMuchas(dns, consultas, timeout) : []);
  const r = (clave) => respuestas.get(clave) || { ok: false, valores: [] };

  const txtSpf = registrosTxtDe(r('txt'));
  const txtDmarc = registrosTxtDe(r('dmarc'));
  const spfDominio = spfMod.parsear(txtSpf);
  const dmarcDominio = dmarcMod.parsear(txtDmarc);

  // --- Verificación propia: SPF, DKIM y DMARC ------------------------------
  const verificacion = await verificarMensaje(mensaje, { dns, timeout, dominio, helo, txtSpf, txtDmarc });

  let ptr = [];
  if (mensaje.ipEmisor) ptr = (await dns.resolverPTR(mensaje.ipEmisor)) || [];

  let listas = null;
  if (mensaje.ipEmisor && conListas) {
    try {
      listas = await blacklists.consultar(mensaje.ipEmisor, { timeout, concurrencia: 4 });
    } catch (error) {
      listas = { resultados: [], resumen: { listadas: 0, sinDatos: 1 }, error: error.message };
    }
  }

  const contenido = contenidoMod.evaluar(mensaje);
  const dbl = await consultarDbl(blacklists, dominio, conListas, timeout);

  const checks = [
    checkSpfMensaje(mensaje, spfDominio, dominio, verificacion.spf),
    checkDkimMensaje(mensaje, dominio, verificacion.dkim),
    checkDmarcMensaje(mensaje, dmarcDominio, dominio, verificacion.dmarc),
    checkPtrMensaje(mensaje, ptr, helo),
    ...(conListas ? [checkListasMensaje(listas, dbl)] : []),
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
      ['HELO', 'red', helo || '—', helo ? 'ok' : 'neutral'],
      ['PTR', 'DNS', ptr.length ? ptr.join(', ') : '—', ptr.length ? 'ok' : 'warn']
    ]),
    seccionesExtra: (result_) => {
      seccionCabeceras(result_, mensaje);
      seccionAutenticacion(result_, mensaje, spfDominio, dmarcDominio, dominio, verificacion);
      seccionVerificacion(result_, verificacion, dominio);
      seccionContenido(result_, contenido);
      if (mensaje.ipEmisor) seccionIp(result_, mensaje, ptr, listas, helo, dbl);
      if (dominio) seccionDmarc(result_, dmarcDominio);
    }
  });
}

/**
 * Evalúa SPF, DKIM y DMARC con `core/mail/verificar` y devuelve los veredictos.
 *
 * Si no hay remitente que comprobar (el mensaje no trae ni From ni Return-Path)
 * no se consulta nada: el informe lo dice con un "no-evaluable" en lugar de
 * inventar un fallo. Los TXT ya consultados por el modo mensaje se reutilizan
 * para no repetir la consulta.
 */
async function verificarMensaje(mensaje, { dns, timeout, dominio, helo, txtSpf, txtDmarc }) {
  const salida = { spf: null, dkim: [], dmarc: null };
  if (!dominio) return salida;

  const opciones = { timeout, dnsModulo: dns };

  if (mensaje.ipEmisor) {
    salida.spf = await verificarMod.verificarSpf(dominio, mensaje.ipEmisor, helo, { ...opciones, txt: txtSpf });
  }

  for (const firma of (mensaje.dkimFirmas || []).slice(0, 3)) {
    if (!firma.selector || !firma.dominio) continue;
    salida.dkim.push(await verificarMod.verificarDkim(mensaje, firma.selector, firma.dominio, opciones));
  }

  const mejorDkim = salida.dkim.find((d) => d.ok) || salida.dkim.find((d) => d.estado === 'error') || salida.dkim[0] || null;
  salida.dmarc = await verificarMod.verificarDmarc(mensaje, salida.spf, mejorDkim, dominio, { ...opciones, txt: txtDmarc });

  return salida;
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
  const incoherente = conIp.flatMap((s) => (s.ptr || []).filter((p) => p.nombres.length && p.coherente === false));
  const estado = sinPtr.length || incoherente.length ? 'warn' : 'ok';
  const detalleIncoherente = incoherente.length
    ? ` FCrDNS: ${incoherente.map((p) => `${p.ip} → ${p.nombres.join(', ')}, pero ese nombre no resuelve a la IP`).join('; ')}.`
    : '';
  return puntuacion.check({
    id: 'ptr', categoria: 'PTR', titulo: 'Resolución inversa (PTR) de los MX', peso: PESOS_DOMINIO.ptr, estado,
    detalle: sinPtr.length
      ? `Sin PTR: ${sinPtr.map((s) => s.host).join(', ')}. Un servidor de correo sin PTR pierde entregabilidad.${detalleIncoherente}`
      : incoherente.length
        ? detalleIncoherente.trim()
        : `Todos los MX (${conIp.length}) tienen PTR y resuelve de vuelta a la misma IP (FCrDNS).`,
    recomendacion: sinPtr.length ? 'Configura el PTR de la IP para que apunte al nombre del servidor.' : incoherente.length ? 'Haz que el nombre del PTR resuelva a la IP del servidor (FCrDNS correcto).' : null
  });
}

function checkListas(servidores, conListas, spfListas, dbl) {
  // Si el usuario la desactiva, no cuenta ni a favor ni en contra: sacarla del
  // máximo es lo honesto, porque no se ha comprobado nada.
  if (!conListas) return null;
  const conListasDatos = [...servidores.flatMap((s) => s.listas || []), ...(spfListas || [])];
  if (!conListasDatos.length && !dbl) {
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
  // El dominio en la lista de dominios de Spamhaus (DBL) es un fallo aparte:
  // las IP pueden estar limpias y que el dominio basto para marcar el correo.
  if (dbl && dbl.estado === dnsbl.ESTADOS.LISTADA) {
    return puntuacion.check({
      id: 'listas', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_DOMINIO.listas, estado: 'error',
      detalle: `El dominio ${dbl.dominio} aparece en la lista de dominios de Spamhaus (DBL): los receptores desconfian de su correo aunque las IP esten limpias.`,
      recomendacion: 'Revisa que se envia desde ese dominio y pide la baja en DBL.'
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
  const notaDbl =
    dbl && dbl.estado === dnsbl.ESTADOS.LIMPIA
      ? ` El dominio ${dbl.dominio} no aparece en Spamhaus DBL.`
      : dbl && dbl.estado === dnsbl.ESTADOS.SIN_DATOS
        ? ` Spamhaus DBL no respondio para ${dbl.dominio}: la reputacion del dominio no se pudo confirmar.`
        : '';

  return puntuacion.check({
    id: 'listas', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_DOMINIO.listas, estado,
    detalle:
      `${conListasDatos.length} IP consultadas y ninguna listada` +
      `${sinRespuesta || '.'}${sinPermiso}${notaDbl}`,
    recomendacion: sinDatos ? 'Algunas listas no respondieron; el resultado no es concluyente.' : null
  });
}

function checkMtaSts(m, politica) {
  if (!m.presente) {
    return puntuacion.check({ id: 'mta-sts', categoria: 'Transporte', titulo: 'MTA-STS', peso: PESOS_DOMINIO.mtaSts, estado: 'warn', detalle: 'Sin MTA-STS: tus correos pueden ser degradados de TLS a texto plano en el trayecto.', recomendacion: 'Publica "_mta-sts.tudominio" con "v=STSv1; id=..." y sirve la política en https://mta-sts.tudominio/.well-known/mta-sts.txt.' });
  }
  if (m.errores.length) {
    return puntuacion.check({ id: 'mta-sts', categoria: 'Transporte', titulo: 'MTA-STS', peso: PESOS_DOMINIO.mtaSts, estado: 'error', detalle: m.errores.join(' '), recomendacion: 'Revisa el registro MTA-STS.' });
  }
  if (!politica) {
    const estado = m.avisos.length ? 'warn' : 'ok';
    return puntuacion.check({ id: 'mta-sts', categoria: 'Transporte', titulo: 'MTA-STS', peso: PESOS_DOMINIO.mtaSts, estado, detalle: m.avisos.join(' ') || `Publicado (id=${m.id}).`, recomendacion: estado === 'ok' ? null : 'Revisa el registro MTA-STS.' });
  }

  // La política descargada manda sobre lo que dice el registro DNS.
  if (politica.estado === 'invalida') {
    return puntuacion.check({ id: 'mta-sts', categoria: 'Transporte', titulo: 'MTA-STS', peso: PESOS_DOMINIO.mtaSts, estado: 'error', detalle: `La política servida en ${politica.url} no es válida: ${politica.errores.join(' ')}`, recomendacion: 'Corrige el texto de la política y vuelve a ejecutar.' });
  }
  if (politica.estado === 'no-servida' || politica.estado === 'inaccesible') {
    return puntuacion.check({ id: 'mta-sts', categoria: 'Transporte', titulo: 'MTA-STS', peso: PESOS_DOMINIO.mtaSts, estado: 'warn', detalle: `El registro existe pero la política no se puede leer en ${politica.url}: ${politica.errores.join(' ')}`, recomendacion: 'Sirve la política en esa URL con HTTP 200: sin ella los receptores no aplican nada.' });
  }
  const texto = politica.policy;
  if (texto.mode === 'testing') {
    return puntuacion.check({ id: 'mta-sts', categoria: 'Transporte', titulo: 'MTA-STS', peso: PESOS_DOMINIO.mtaSts, estado: 'warn', detalle: 'Política MTA-STS descargada y válida, pero en modo "testing": solo observa, no obliga a TLS.', recomendacion: 'Cuando los informes estén limpios, cambia a "mode: enforce".' });
  }
  if (texto.mode === 'none') {
    return puntuacion.check({ id: 'mta-sts', categoria: 'Transporte', titulo: 'MTA-STS', peso: PESOS_DOMINIO.mtaSts, estado: 'warn', detalle: 'Política MTA-STS descargada y válida, pero en modo "none": desactiva la protección.', recomendacion: 'Usa "mode: enforce" para que los receptores exijan TLS.' });
  }
  const avisos = [...(m.avisos || []), ...(politica.avisos || [])];
  const estado = avisos.length ? 'warn' : 'ok';
  const maxAge = texto.maxAge !== null && texto.maxAge !== undefined ? `, max_age ${texto.maxAge} s` : '';
  return puntuacion.check({
    id: 'mta-sts', categoria: 'Transporte', titulo: 'MTA-STS', peso: PESOS_DOMINIO.mtaSts, estado,
    detalle: avisos.length ? avisos.join(' ') : `Política servida y válida (mode enforce${maxAge}).`,
    recomendacion: avisos.length ? 'Revisa las advertencias de la política.' : null
  });
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

/** Nombre legible de cada uso de un TLSA. */
const NOMBRES_USO_TLSA = { 0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE' };

function usoTlsa(usage) {
  return NOMBRES_USO_TLSA[usage] || `uso ${usage}`;
}

/**
 * DANE solo puntúa cuando el dominio publica al menos un TLSA: no es obligatorio,
 * y un dominio sin TLSA no debe salir castigado por no usar una protección
 * opcional (ni el máximo ni la nota cambian). Cuando sí se publica, lo publicado
 * se juzga: usos DANE (2/3) bien, solo PKIX (0/1) avisa, valores fuera de rango fallan.
 */
function checkDane(dane) {
  const conDatos = (dane?.hosts || []).filter((h) => h.registros.length);
  if (!conDatos.length) return null;

  const conDane = conDatos.filter((h) => h.estado === 'dane');
  const soloPkix = conDatos.filter((h) => h.estado === 'pkix');
  const dudoso = conDatos.filter((h) => h.estado === 'dudoso');
  const base = { id: 'dane', categoria: 'DANE', titulo: 'DANE (TLSA) en los MX', peso: PESOS_DOMINIO.dane };

  if (dudoso.length) {
    return puntuacion.check({
      ...base,
      estado: 'error',
      detalle: `TLSA con valores fuera de rango en: ${dudoso.map((h) => h.host).join(', ')}. Un uso fuera de 0-3 no lo aplica ningún receptor.`,
      recomendacion: 'Corrige los TLSA para que usen los usos 3 (DANE-EE) o 2 (DANE-TA).'
    });
  }
  if (!conDane.length) {
    return puntuacion.check({
      ...base,
      estado: 'warn',
      detalle: `Solo se publican TLSA de tipo PKIX (usos 0/1) en: ${soloPkix.map((h) => h.host).join(', ')}. Los usos 0/1 no son DANE: no fijan el certificado por cadena ni por anclaje.`,
      recomendacion: 'Para DANE en SMTP usa el uso 3 (certificado exacto) o el 2 (ancla), con el hash SHA-256.'
    });
  }
  if (soloPkix.length) {
    return puntuacion.check({
      ...base,
      estado: 'warn',
      detalle: `DANE en ${conDane.map((h) => h.host).join(', ')}, pero ${soloPkix.map((h) => h.host).join(', ')} solo publica TLSA PKIX (usos 0/1), que no son DANE.`,
      recomendacion: 'Añade usos 3 o 2 en los TLSA que los tengan como 0/1.'
    });
  }
  return puntuacion.check({
    ...base,
    estado: 'ok',
    detalle: `DANE publicado: ${conDane.map((h) => `${h.host} (${h.registros.map((t) => usoTlsa(t.usage)).join(', ')})`).join('; ')}.`,
    recomendacion: null
  });
}

/* ------------------------------------------------------------------ *
 * Comprobaciones — mensaje
 * ------------------------------------------------------------------ */

/** Frase común cuando el mensaje no trae remitente del que colgar una comprobación. */
const SIN_REMITENTE =
  'No hay remitente que comprobar: el mensaje no trae "From" ni "Return-Path". ¿El .eml está completo?';

function checkSpfMensaje(mensaje, spfDominio, dominio, verificacion) {
  const base = { id: 'spf-msg', categoria: 'SPF', titulo: 'SPF del remitente', peso: PESOS_MENSAJE.spf };

  if (!dominio) {
    return puntuacion.check({
      ...base,
      estado: 'no-evaluable',
      detalle: SIN_REMITENTE,
      recomendacion: 'Pega el correo entero, empezando por las cabeceras (From, Received, Return-Path).'
    });
  }

  // 1) La evaluación propia del registro SPF contra la IP real, si concluyó.
  if (verificacion?.estado === 'ok' || verificacion?.estado === 'error') {
    return puntuacion.check({
      ...base,
      estado: verificacion.estado,
      detalle: `${verificacion.detalle} Evaluado aquí sobre ${dominio} con la IP ${mensaje.ipEmisor}.`,
      recomendacion: verificacion.estado === 'ok' ? null : 'Revisa el SPF: probablemente no incluye este servidor de envío.'
    });
  }

  // 2) Lo que dejó escrito el receptor, que sigue mandando si aquí no concluimos.
  const informe = mensaje.spf?.resultado || null;
  const fuente = mensaje.spf?.fuente ? ` (${mensaje.spf.fuente})` : '';
  if (informe === 'pass') {
    return puntuacion.check({
      ...base,
      estado: 'ok',
      detalle: `El receptor validó SPF: pass${fuente}.${verificacion ? ` Aquí no se pudo concluir: ${verificacion.detalle}` : ''}`,
      recomendacion: null
    });
  }
  if (informe === 'fail') {
    return puntuacion.check({
      ...base,
      estado: 'error',
      detalle: `SPF = fail${fuente}: el remitente no está autorizado.`,
      recomendacion: 'Revisa el SPF: probablemente no incluye este servidor de envío.'
    });
  }
  if (['softfail', 'neutral', 'none'].includes(informe)) {
    return puntuacion.check({
      ...base,
      estado: 'warn',
      detalle: `SPF = ${informe}${fuente}: el remitente no está claramente autorizado.`,
      recomendacion: 'Añade la IP del servidor emisor al SPF del dominio.'
    });
  }

  // 3) Sin ningún veredicto: que se note el motivo.
  if (verificacion?.estado === 'warn') {
    return puntuacion.check({ ...base, estado: 'warn', detalle: verificacion.detalle, recomendacion: 'Publica un SPF que autorice solo a tus servidores y termine en "-all".' });
  }
  if (spfDominio.presente) {
    return puntuacion.check({
      ...base,
      estado: 'warn',
      detalle: 'El dominio publica SPF, pero el mensaje no trae resultado del receptor y no hay IP con la que evaluarlo.',
      recomendacion: 'Comprueba que la cabecera "Received" del .eml expone la IP pública del emisor.'
    });
  }
  return puntuacion.check({
    ...base,
    estado: 'warn',
    detalle: 'El mensaje no trae resultado de SPF y el dominio no publica registro SPF.',
    recomendacion: 'Publica un TXT que empiece por "v=spf1" autorizando solo a tus servidores y terminando en "-all".'
  });
}

function checkDkimMensaje(mensaje, dominio, verificaciones) {
  const base = { id: 'dkim-msg', categoria: 'DKIM', titulo: 'Firma DKIM', peso: PESOS_MENSAJE.dkim };
  const propias = verificaciones || [];

  if (!dominio) {
    return puntuacion.check({
      ...base,
      estado: 'no-evaluable',
      detalle: SIN_REMITENTE,
      recomendacion: 'Pega el correo entero, empezando por las cabeceras (From, Received, DKIM-Signature).'
    });
  }

  // 1) Verificación criptográfica propia: es la que manda cuando sale adelante.
  const valida = propias.find((v) => v.estado === 'ok');
  if (valida) return puntuacion.check({ ...base, estado: 'ok', detalle: valida.detalle, recomendacion: null });
  const rota = propias.find((v) => v.estado === 'error');
  if (rota) return puntuacion.check({ ...base, estado: 'error', detalle: rota.detalle, recomendacion: 'Comprueba que el selector publicado corresponde a la clave con la que firmas.' });

  // 2) Lo que validó el receptor.
  const pase = (mensaje.dkim || []).find((d) => d.resultado === 'pass');
  if (pase) {
    return puntuacion.check({
      ...base,
      estado: 'ok',
      detalle: `El receptor validó la firma DKIM (pass, d=${pase.dominio || dominio}).${propias[0] ? ` Aquí no se pudo concluir: ${propias[0].detalle}` : ''}`,
      recomendacion: null
    });
  }
  if ((mensaje.dkim || []).some((d) => d.resultado === 'fail')) {
    return puntuacion.check({
      ...base,
      estado: 'error',
      detalle: 'DKIM = fail: la firma no valida. La clave pública y la privada no cuadran.',
      recomendacion: 'Comprueba que el selector publicado corresponde a la clave con la que firmas.'
    });
  }

  // 3) Sin veredicto de nadie.
  if (!mensaje.dkimFirmas.length) {
    return puntuacion.check({
      ...base,
      estado: 'warn',
      detalle: 'El mensaje no lleva cabecera "DKIM-Signature".',
      recomendacion: 'Configura la firma DKIM en el servidor de envío.'
    });
  }
  if (propias[0]) {
    return puntuacion.check({ ...base, estado: 'warn', detalle: propias[0].detalle, recomendacion: 'Revisa que la clave pública del selector esté publicada y que la firma incluya la etiqueta "b=".' });
  }
  return puntuacion.check({
    ...base,
    estado: 'warn',
    detalle: `Lleva ${mensaje.dkimFirmas.length} firma(s) DKIM pero ni el receptor ni esta herramienta pudieron validarla.`,
    recomendacion: 'Revisa que la clave pública del selector esté publicada.'
  });
}

function checkDmarcMensaje(mensaje, dmarcDominio, dominio, verificacion) {
  const base = { id: 'dmarc-msg', categoria: 'DMARC', titulo: 'DMARC del remitente', peso: PESOS_MENSAJE.dmarc };

  if (!dominio) {
    return puntuacion.check({
      ...base,
      estado: 'no-evaluable',
      detalle: SIN_REMITENTE,
      recomendacion: 'Pega el correo entero, empezando por las cabeceras (From, Return-Path).'
    });
  }

  if (verificacion?.estado === 'ok') {
    return puntuacion.check({ ...base, estado: 'ok', detalle: `${verificacion.detalle} Alineación comprobada aquí contra "_dmarc.${dominio}".`, recomendacion: null });
  }
  if (verificacion?.estado === 'error') {
    return puntuacion.check({ ...base, estado: 'error', detalle: verificacion.detalle, recomendacion: 'Asegura que SPF o DKIM alinean con el dominio del remitente (header From).' });
  }

  const informe = mensaje.dmarc?.resultado || null;
  if (informe === 'pass') {
    return puntuacion.check({ ...base, estado: 'ok', detalle: `El receptor validó DMARC: pass${mensaje.dmarc?.dominio ? ` (header.from=${mensaje.dmarc.dominio})` : ''}.`, recomendacion: null });
  }
  if (informe && ['fail', 'reject', 'quarantine'].includes(informe)) {
    return puntuacion.check({ ...base, estado: 'error', detalle: `DMARC = ${informe}.`, recomendacion: 'Asegura que SPF o DKIM alinean con el dominio del remitente.' });
  }
  if (!dmarcDominio.presente) {
    return puntuacion.check({ ...base, estado: 'warn', detalle: `${dominio} no publica DMARC.`, recomendacion: 'Publica DMARC en "_dmarc" del dominio.' });
  }
  if (verificacion?.estado === 'warn') {
    return puntuacion.check({ ...base, estado: 'warn', detalle: verificacion.detalle, recomendacion: 'Revisa la configuración de DMARC del dominio.' });
  }
  return puntuacion.check({ ...base, estado: 'warn', detalle: 'El mensaje no reporta un resultado DMARC y aquí no se pudo concluir la alineación.', recomendacion: 'Revisa la configuración de DMARC del dominio.' });
}

function checkPtrMensaje(mensaje, ptr, helo) {
  const base = { id: 'ptr-msg', categoria: 'PTR', titulo: 'Resolución inversa (PTR)', peso: PESOS_MENSAJE.ptr };

  if (!mensaje.ipEmisor) {
    return puntuacion.check({
      ...base,
      estado: 'no-evaluable',
      detalle: 'No se pudo extraer la IP emisora del mensaje: sin IP no hay reputación que comprobar.',
      recomendacion: 'Revisa que el .eml incluya las cabeceras "Received".'
    });
  }
  if (!ptr.length) {
    const privada = mensajeMod.esPrivada(mensaje.ipEmisor);
    return puntuacion.check({
      ...base,
      estado: 'warn',
      detalle: privada
        ? `${mensaje.ipEmisor} es una IP privada y no tiene PTR: la cabecera "Received" no expone la IP pública del emisor, así que la reputación no se puede mirar.`
        : `${mensaje.ipEmisor} no tiene PTR.`,
      recomendacion: privada
        ? 'Exporta el correo desde el cliente con las cabeceras completas, o comprueba la IP pública del servidor de envío.'
        : 'Configura el PTR de la IP del servidor de envío.'
    });
  }
  const nombres = ptr.map((n) => n.toLowerCase().replace(/\.$/, ''));
  const heloLimpio = helo ? helo.toLowerCase().replace(/\.$/, '') : null;
  if (heloLimpio && !nombres.includes(heloLimpio)) {
    return puntuacion.check({
      ...base,
      estado: 'warn',
      detalle: `${mensaje.ipEmisor} → ${ptr.join(', ')}, pero el servidor se presentó como "${helo}" (HELO): la inversa y el HELO no coinciden.`,
      recomendacion: 'El HELO/EHLO debe ser el mismo nombre que resuelve la IP del servidor de envío.'
    });
  }
  return puntuacion.check({
    ...base,
    estado: 'ok',
    detalle: `${mensaje.ipEmisor} → ${ptr.join(', ')}${helo ? `, coherente con el HELO (${helo})` : ''}.`,
    recomendacion: null
  });
}

/** HELO/EHLO del servidor que entregó el mensaje: el "from" de la primera Received. */
function heloDe(mensaje) {
  for (const recibida of mensaje.recibidas || []) {
    const m = String(recibida).match(/^from\s+([^ \t(]+)/i);
    if (m) return m[1].replace(/[.,;]$/, '');
  }
  return null;
}

function checkListasMensaje(listas, dbl) {
  if (dbl && dbl.estado === dnsbl.ESTADOS.LISTADA) {
    return puntuacion.check({
      id: 'listas-msg', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_MENSAJE.listas, estado: 'error',
      detalle: `El dominio del remitente (${dbl.dominio}) está en Spamhaus DBL: la IP puede estar limpia y que el dominio baste para marcar el correo.`,
      recomendacion: 'Revisa el historial del dominio y pide la baja en DBL.'
    });
  }
  if (!listas) {
    return puntuacion.check({ id: 'listas-msg', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_MENSAJE.listas, estado: 'no-evaluable', detalle: 'Sin IP emisora no hay reputación que comprobar.', recomendacion: null });
  }
  if (listas.resumen.listadas > 0) {
    return puntuacion.check({ id: 'listas-msg', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_MENSAJE.listas, estado: 'error', detalle: `La IP emisora está en: ${listas.resumen.zonasListadas.join(', ')}.`, recomendacion: 'Es la causa más grave de spam: pide la retirada y corrige el origen.' });
  }
  // Mismo criterio que en modo dominio: lo que no se ha podido mirar por falta de
  // registro en Spamhaus se dice, pero no hace bajar la puntuacion del mensaje.
  const sinAcceso = listas.resumen.sinDatosSinAcceso || 0;
  const sinDatos = listas.resumen.sinDatos - sinAcceso;
  const notaDbl =
    dbl && dbl.estado === dnsbl.ESTADOS.LIMPIA
      ? ` El dominio del remitente (${dbl.dominio}) no aparece en DBL.`
      : dbl && dbl.estado === dnsbl.ESTADOS.SIN_DATOS
        ? ` No se pudo confirmar DBL para ${dbl.dominio}: Spamhaus no respondió.`
        : '';
  return puntuacion.check({
    id: 'listas-msg', categoria: 'Reputación', titulo: 'Listas negras', peso: PESOS_MENSAJE.listas,
    estado: sinDatos ? 'warn' : 'ok',
    detalle: sinDatos
      ? `${sinDatos} listas sin respuesta.${notaDbl}`
      : `La IP emisora no está en ninguna lista` +
        (sinAcceso ? `. Sin comprobar en ${sinAcceso} zonas de Spamhaus: no dan datos a resolvedores sin registrar.` : '.') +
        notaDbl,
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
    return puntuacion.check({ id: 'unsubscribe', categoria: 'Formato', titulo: 'Cabecera List-Unsubscribe', peso: PESOS_MENSAJE.unsubscribe, estado: 'warn', detalle: 'No hay "List-Unsubscribe". Es un aviso (no resta puntos), pero el correo masivo debería llevarla.', recomendacion: 'Añade "List-Unsubscribe: <mailto:...>" y, mejor, "List-Unsubscribe-Post: List-Unsubscribe=One-Click".' });
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
  const evaluables = evaluado.checks.filter((c) => c.estado !== 'no-evaluable');
  const sinComprobar = evaluado.checks.length - evaluables.length;
  addSummary(
    result,
    'Comprobaciones',
    `${evaluables.length - evaluado.fallos.length} de ${evaluables.length} correctas${sinComprobar ? `, ${sinComprobar} sin comprobar` : ''}`,
    evaluado.fallos.length ? 'warn' : 'ok'
  );
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

  seccionDesglose(result, evaluado);

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
        { valor: etiquetaEstado(c.estado), tone: tonoDe(c.estado) },
        c.estado === 'no-evaluable' ? '—' : `${puntosDe(c)}/${c.peso}`,
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

function seccionSpfIp(result, spfListas) {
  if (!spfListas || !spfListas.length) return;
  addSection(result, {
    id: 'spf-ip',
    title: 'IPs autorizadas por el SPF',
    description: 'Las direcciones que el SPF declara como remitentes legítimos también se consultan en listas negras: aunque los registros sean perfectos, una IP autorizada listada sigue hundiendo el correo.',
    kind: K.TABLA,
    columns: ['IP', 'Origen', 'Listas negras'],
    anchoColumnas: [20, 10, 70],
    rows: spfListas.map((l) => [
      l.ip,
      l.origen,
      l.resumen.listadas > 0
        ? { valor: `listada en ${l.resumen.zonasListadas.join(', ')}`, tone: 'bad' }
        : { valor: 'limpia', tone: 'ok' }
    ])
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

function seccionPoliticaMtaSts(result, politica) {
  const items = [
    ['URL', politica.url],
    ['Estado', etiquetaPolitica(politica), tonoPolitica(politica)]
  ];
  if (politica.policy) {
    const p = politica.policy;
    items.push(['Versión', p.version || '—']);
    items.push(['Modo', p.mode ?? '—', p.mode === 'enforce' ? 'ok' : p.mode ? 'warn' : 'neutral']);
    items.push(['Servidores (mx)', p.mx.length ? p.mx.join(', ') : '—']);
    items.push(['max_age', p.maxAge !== null && p.maxAge !== undefined ? `${p.maxAge} s` : '—']);
  }
  if (politica.errores.length) items.push(['Errores', politica.errores.join(' ')]);
  if (politica.avisos.length) items.push(['Avisos', politica.avisos.join(' ')]);
  addSection(result, {
    id: 'politica-mta-sts',
    title: 'Política MTA-STS',
    description: 'El texto que se sirve en el bien conocido de MTA-STS (RFC 8461). Un registro sin política aplicable no obliga a los receptores a nada.',
    kind: K.PARES,
    items
  });
}

function etiquetaPolitica(p) {
  if (p.estado === 'ok') return 'Válida';
  if (p.estado === 'invalida') return 'Inválida';
  if (p.estado === 'no-servida') return p.status ? `No servida (HTTP ${p.status})` : 'No servida';
  return 'Inaccesible';
}

function tonoPolitica(p) {
  return p.estado === 'ok' ? 'ok' : 'bad';
}

function seccionDane(result, dane) {
  if (!dane?.consultado || !dane.hosts.length) return;
  addSection(result, {
    id: 'dane',
    title: 'DANE (TLSA) en los servidores de correo',
    description: 'Los TLSA de "port 25" que publica cada MX. Sin publicar, los receptores no tienen con qué fijar el certificado de tu servidor.',
    kind: K.TABLA,
    columns: ['Servidor', 'Registros TLSA', 'Uso', 'Estado'],
    anchoColumnas: [28, 13, 32, 15],
    rows: dane.hosts.map((h) => [
      h.host,
      String(h.registros.length),
      h.registros.length ? h.registros.map((t) => `${usoTlsa(t.usage)} ${t.selector}/${t.matchingType}`).join(', ') : '—',
      { valor: etiquetaDane(h.estado), tone: tonoDane(h.estado) }
    ])
  });
}

function etiquetaDane(estado) {
  if (estado === 'dane') return 'DANE activo';
  if (estado === 'pkix') return 'Solo PKIX';
  if (estado === 'dudoso') return 'Valores inválidos';
  return 'Sin TLSA';
}

function tonoDane(estado) {
  if (estado === 'dane') return 'ok';
  if (estado === 'pkix' || estado === 'dudoso') return 'bad';
  return 'warn';
}

/** Filas de "Registros y valores" para los TLSA encontrados. */
function filasTlsa(dane) {
  if (!dane?.consultado) return [];
  const filas = [];
  for (const h of dane.hosts) {
    for (const t of h.registros.slice(0, 2)) {
      filas.push([`_25._tcp.${h.host}`, 'TLSA', `${usoTlsa(t.usage)} ${t.selector} ${t.matchingType} ${t.certificate.slice(0, 24)}…`, h.estado]);
    }
  }
  return filas;
}

/**
 * Desglose de la nota por categoria: de un vistazo se ve de dónde se pierden
 * los puntos, sin tener que recorrer la tabla de comprobaciones.
 */
function seccionDesglose(result, evaluado) {
  const porCategoria = new Map();
  for (const c of evaluado.checks) {
    if (c.estado === 'no-evaluable') continue;
    const categoria = c.categoria || 'Otras';
    const grupo = porCategoria.get(categoria) || { max: 0, obtenidos: 0 };
    const factor = c.estado === 'ok' ? 1 : c.estado === 'warn' ? 0.5 : 0;
    grupo.max += c.peso;
    grupo.obtenidos += c.peso * factor;
    porCategoria.set(categoria, grupo);
  }

  addSection(result, {
    id: 'desglose',
    title: 'Desglose por categoría',
    description: 'Dónde se ganan y se pierden los puntos, agrupado por categoría. Un aviso vale la mitad; un fallo, nada.',
    kind: K.TABLA,
    columns: ['Categoría', 'Puntos', 'Máximo', 'Estado'],
    anchoColumnas: [22, 10, 10, 12],
    rows: [...porCategoria.entries()]
      .map(([categoria, g]) => ({ categoria, ...g }))
      .sort((a, b) => b.max - b.obtenidos - (a.max - a.obtenidos) || b.max - a.max)
      .map((g) => {
        const perdido = g.max - g.obtenidos;
        return [
          g.categoria,
          puntuacion.redondear(g.obtenidos, 2),
          puntuacion.redondear(g.max, 2),
          { valor: perdido === 0 ? 'OK' : perdido >= g.max / 2 ? 'Falla' : 'Revisar', tone: perdido === 0 ? 'ok' : perdido >= g.max / 2 ? 'bad' : 'warn' }
        ];
      })
  });
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

function seccionAutenticacion(result, mensaje, spfDominio, dmarcDominio, dominio, verificacion) {
  const spfPropio = verificacion?.spf || null;
  const dkimPropios = verificacion?.dkim || [];
  const dmarcPropio = verificacion?.dmarc || null;

  const filas = [
    [
      'SPF',
      mensaje.spf?.resultado || 'sin dato',
      etiquetaPropia(spfPropio),
      `${mensaje.spf?.fuente || '—'} · ${spfDominio.presente ? 'dominio con SPF' : 'sin SPF en el dominio'}`
    ],
    [
      'DKIM',
      mensaje.dkim.length ? mensaje.dkim.map((d) => d.resultado).join(', ') : 'sin dato',
      etiquetaPropia(dkimPropios),
      `${mensaje.dkimFirmas.map((f) => f.selector || '—').join(', ') || 'sin firma'} · ${mensaje.dkimFirmas.map((f) => f.dominio || '—').join(', ') || '—'}`
    ],
    [
      'DMARC',
      mensaje.dmarc?.resultado || 'sin dato',
      etiquetaPropia(dmarcPropio),
      `${mensaje.dmarc?.dominio || dominio || '—'} · ${dmarcDominio.presente ? 'dominio con DMARC' : 'sin DMARC en el dominio'}`
    ]
  ];
  addSection(result, {
    id: 'autenticacion',
    title: 'Resultado de autenticación',
    description: 'Dos fuentes: lo que dejó escrito el receptor ("Authentication-Results" / "Received-SPF") y lo que comprobó esta herramienta aquí mismo.',
    kind: K.TABLA,
    columns: ['Método', 'Informe del receptor', 'Verificado aquí', 'Contexto'],
    anchoColumnas: [12, 20, 18, 44],
    rows: filas
  });
}

/** Etiqueta corta del veredicto propio para la tabla de autenticación. */
function etiquetaPropia(verificaciones) {
  const lista = Array.isArray(verificaciones) ? verificaciones : [verificaciones];
  const items = lista.filter(Boolean);
  if (!items.length) return { valor: 'sin evaluar', tone: 'neutral' };
  if (items.some((v) => v.estado === 'ok')) return { valor: 'pass', tone: 'ok' };
  if (items.some((v) => v.estado === 'error')) return { valor: 'no valida', tone: 'bad' };
  if (items.some((v) => v.estado === 'warn')) return { valor: 'advertencia', tone: 'warn' };
  return { valor: 'sin comprobar', tone: 'neutral' };
}

/** La evidencia de la verificación propia, para que el informe se pueda auditar. */
function seccionVerificacion(result, verificacion) {
  if (!verificacion) return;
  const items = [];

  if (verificacion.spf) {
    const v = verificacion.spf;
    items.push(['SPF', v.detalle, tonoDe(v.estado)]);
    const evaluacion = (v.evidencia?.pasos || []).find((p) => p.fase === 'evaluacion');
    if (evaluacion?.razon) items.push(['SPF: por qué', `${evaluacion.mecanismo || 'all'} → ${evaluacion.razon}`]);
    if (v.avisos?.length) items.push(['SPF: avisos', v.avisos.join(' ')]);
  }

  for (const v of verificacion.dkim || []) {
    const clave = (v.evidencia?.pasos || []).find((p) => p.fase === 'clave');
    items.push([
      `DKIM (${v.evidencia?.selector || '?'} @ ${v.evidencia?.dominio || '?'})`,
      `${v.detalle}${clave?.tipo ? ` · ${clave.tipo}` : ''}`,
      tonoDe(v.estado)
    ]);
  }

  const pasoDmarc = (verificacion.dmarc?.evidencia?.pasos || []).find((p) => p.fase === 'dmarc');
  if (pasoDmarc) {
    items.push([
      'DMARC: alineación',
      `SPF ${pasoDmarc.spfPass ? 'pass' : 'no pasa'}${pasoDmarc.spfAlineado ? ', alineado' : ', sin alinear'} · DKIM ${
        pasoDmarc.dkimPass ? 'pass' : 'no pasa'
      }${pasoDmarc.dkimAlineado ? ', alineado' : ', sin alinear'} · política p=${pasoDmarc.politica}`
    ]);
  }

  if (!items.length) return;
  addSection(result, {
    id: 'verificacion',
    title: 'Verificación propia',
    description: 'Lo que comprobó esta herramienta por su cuenta (SPF evaluado contra la IP, firma DKIM y alineación DMARC), sin fiarse solo de lo que dice el receptor.',
    kind: K.PARES,
    items
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
    rows: contenido.checks.map((c) => [c.titulo, { valor: etiquetaEstado(c.estado), tone: tonoDe(c.estado) }, c.detalle || '—'])
  });
}

function seccionIp(result, mensaje, ptr, listas, helo, dbl) {
  addSection(result, {
    id: 'ip',
    title: 'IP emisora',
    kind: K.PARES,
    items: [
      ['Dirección', mensaje.ipEmisor || '—'],
      ['HELO del emisor', helo || 'sin HELO'],
      ['PTR', ptr.length ? ptr.join(', ') : 'sin PTR', ptr.length ? 'ok' : 'warn'],
      ['Listas negras', listas ? (listas.resumen.listadas > 0 ? `listada en ${listas.resumen.zonasListadas.join(', ')}` : 'limpia') : 'sin comprobar', listas && listas.resumen.listadas > 0 ? 'bad' : 'ok'],
      ...(dbl
        ? [['Reputación del dominio (DBL)', textoDbl(dbl), tonoDbl(dbl)]]
        : []),
      ['Saltos hasta el receptor', String(mensaje.recibidas.length)]
    ]
  });
}

/* ------------------------------------------------------------------ *
 * Helpers de presentación
 * ------------------------------------------------------------------ */

/**
 * Consulta la reputación del dominio en Spamhaus DBL si el módulo de listas la
 * soporta. Un doble de pruebas que solo implemente `consultar` no tiene DBL: se
 * devuelve `null` y la comprobación no dice nada del dominio, igual que si la
 * opción estuviera apagada.
 */
async function consultarDbl(blacklists, dominio, conListas, timeout) {
  if (!conListas || !dominio || typeof blacklists.consultarDominio !== 'function') return null;
  try {
    return await blacklists.consultarDominio(dominio, { timeout });
  } catch (error) {
    return { estado: dnsbl.ESTADOS.SIN_DATOS, dominio, consultado: null, codigo: null, error: error.message, avisos: [] };
  }
}

/** Texto legible del estado DBL de un dominio. */
function textoDbl(dbl) {
  if (!dbl) return 'sin comprobar';
  if (dbl.estado === dnsbl.ESTADOS.LISTADA) return `listado en Spamhaus DBL (${dbl.dominio})`;
  if (dbl.estado === dnsbl.ESTADOS.LIMPIA) return `no listado en Spamhaus DBL (${dbl.dominio})`;
  return `sin respuesta de Spamhaus DBL (${dbl.dominio})`;
}

function tonoDbl(dbl) {
  if (!dbl) return 'neutral';
  if (dbl.estado === dnsbl.ESTADOS.LISTADA) return 'bad';
  if (dbl.estado === dnsbl.ESTADOS.LIMPIA) return 'ok';
  return 'warn';
}

/** Filas de "Registros y valores" para el estado DBL, cuando hay datos. */
function filasDbl(dbl) {
  if (!dbl) return [];
  return [[`${dbl.dominio}`, 'DBL', textoDbl(dbl), tonoDbl(dbl)]];
}

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
  if (estado === 'ok') return 'OK';
  if (estado === 'warn') return 'Revisar';
  if (estado === 'error') return 'Falla';
  if (estado === 'no-evaluable') return 'Sin comprobar';
  return '—';
}

function puntosDe(c) {
  if (c.estado === 'no-evaluable') return '—';
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
    consultarDane,
    consultarPoliticaMtaSts,
    normalizarTlsa,
    filasTlsa,
    CAMPOS
  }
};
