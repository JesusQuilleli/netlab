/**
 * net/dns.js — Consultas DNS con timeout, reintentos y concurrencia limitada.
 *
 * MODULO QUE CORRIGE UN CUELGUE REAL. En legacy/Check DNS/dns_validator_js.js
 * las consultas se hacian directamente con `dns.Resolver().resolveTxt()`,
 * que NO tiene timeout propio: si un servidor no responde, el script se
 * queda esperando indefinidamente. En un servidor eso es un proceso zombi.
 *
 * Aqui cada consulta tiene plazo maximo, reintenta con espera creciente, y
 * todas las consultas de una herramienta pasan por un semaforo de concurrencia
 * para no saturar la VPS.
 *
 * @module core/net/dns
 */

'use strict';

const dns = require('node:dns').promises;
const dgram = require('node:dgram');
const net = require('node:net');
const dnsPacket = require('dns-packet');
const { NetlabError, CODES, wrap } = require('../errors');

/** Resolvers publicos por defecto: se consulta fuera de la cache local. */
const RESOLVERS_PUBLICOS = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];

/** Puerta DNS para las consultas crudas. */
const PORT_DNS = 53;

/**
 * Tamano de respuesta UDP que pedimos por EDNS. Con 512 bytes, un dominio
 * firmado con DNSSEC responde truncado casi siempre y obliga a TCP.
 */
const MAX_UDP_PAYLOAD = 1200;

/**
 * Tipos de registro DNSSEC.
 *
 * Node no sabe resolverlos: `Resolver.resolve()` lanza `ERR_INVALID_ARG_VALUE`
 * para DNSKEY y DS, y `resolveAny` los ignora. Se consultan con un paquete DNS
 * crudo (UDP con EDNS y bit DO, con caida a TCP si llega truncado).
 */
const TIPOS_DNSSEC = ['DNSKEY', 'DS', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM'];

/**
 * Crea un resolver apuntando a servidores especificos, evitando la cache local.
 *
 * @param {string[]} [servers]
 * @returns {import('node:dns').Resolver}
 */
function crearResolver(servers = RESOLVERS_PUBLICOS) {
  const resolver = new dns.Resolver({ timeout: 3000, tries: 2 });
  resolver.setServers(servers);
  return resolver;
}

/**
 * Ejecuta una operacion con plazo maximo. Lanza TIMEOUT si no termina a tiempo.
 *
 * @template T
 * @param {Promise<T>} promesa
 * @param {number} ms Plazo en milisegundos.
 * @param {string} contexto Texto para el mensaje de error.
 * @returns {Promise<T>}
 */
function conTimeout(promesa, ms, contexto) {
  let temporizador;
  const plazo = new Promise((_resolve, reject) => {
    temporizador = setTimeout(() => {
      reject(
        new NetlabError(CODES.TIMEOUT, `Tiempo agotado (${ms} ms) ${contexto}.`, {
          remediation: 'El servidor DNS no respondió a tiempo. Puede ser un problema de red o de resolución.'
        })
      );
    }, ms);
  });

  return Promise.race([promesa, plazo]).finally(() => clearTimeout(temporizador));
}

/**
 * Reintenta una operacion con espera creciente.
 *
 * Lanza el error CRUDO del resolvedor, sin envolver. Quien llama es quien sabe
 * que frase usar para describir la consulta, y ademas necesita el codigo
 * original (`ENOTFOUND`, `ENODATA`, `ESERVFAIL`) para decidir si un nombre no
 * existe o simplemente no tiene registros de ese tipo. Envolver aqui perdia
 * esa informacion y producia mensajes como "al la consulta DNS".
 *
 * @template T
 * @param {() => Promise<T>} operacion
 * @param {object} [options]
 * @param {number} [options.reintentos=2]
 * @param {number} [options.esperaInicial=250]
 * @returns {Promise<T>}
 * @throws {Error} El ultimo error, tal cual lo dio el resolvedor.
 */
async function conReintento(operacion, options = {}) {
  const { reintentos = 2, esperaInicial = 250 } = options;
  let ultimoError;

  for (let intento = 0; intento <= reintentos; intento++) {
    try {
      return await operacion();
    } catch (error) {
      ultimoError = error;
      // No tiene sentido reintentar un NXDOMAIN ni un error de parametro.
      if (!esReintentable(error) || intento === reintentos) break;
      await new Promise((r) => setTimeout(r, esperaInicial * 2 ** intento));
    }
  }

  throw ultimoError;
}

/** Decide si un error de DNS merece otro intento. */
function esReintentable(error) {
  // NXDOMAIN / ENODATA son respuestas definitivas, no fallos transitorios.
  const definitivos = ['ENOTFOUND', 'ENODATA', 'ENODOMAIN', 'ESERVFAIL', 'EREFUSED'];
  return !definitivos.includes(error?.code);
}

/**
 * Semaforo simple para limitar cuantas consultas DNS salen a la vez.
 *
 * @param {number} limite Máximo de operaciones simultaneas.
 * @returns {<T>(fn: () => Promise<T>) => Promise<T>}
 */
function limitarConcurrencia(limite) {
  const pendientes = [];
  let activas = 0;

  return function ejecutar(fn) {
    return new Promise((resolve, reject) => {
      const correr = async () => {
        // Ojo al nombre: se declara `activas` y se usa `activos` en el mismo
        // bloque. En modo estricto eso es un ReferenceError, y en laxo se
        // crea una variable global suelta. Nadie lo notaba porque
        // `consultarLote`, que es quien usa este semaforo, no lo cubria        // ninguna prueba.
        activas++;
        try {
          resolve(await fn());
        } catch (error) {
          reject(error);
        } finally {
          activas--;
          const siguiente = pendientes.shift();
          if (siguiente) siguiente();
        }
      };

      if (activas < limite) correr();
      else pendientes.push(correr);
    });
  };
}

/**
 * Consulta un registro DNS con todas las protecciones aplicadas.
 *
 * @param {string} nombre Nombre a consultar.
 * @param {string} tipo Tipo ('TXT', 'MX', 'A'...).
 * @param {object} [options]
 * @param {string[]} [options.servers]
 * @param {number} [options.timeout=5000]
 * @param {number} [options.reintentos=2]
 * @returns {Promise<{ok: boolean, valores: any[], ttl: number|null, error: string|null, codigo: string|null}>}
 *   Nunca lanza: los errores de red van en el campo `error` para que la
 *   herramienta pueda reportarlos por registro en vez de abortar todo.
 */
async function consultar(nombre, tipo, options = {}) {
  const { servers = RESOLVERS_PUBLICOS, timeout = 5000, reintentos = 2 } = options;

  const resolver = crearResolver(servers);

  const METODOS = {
    TXT: 'resolveTxt',
    MX: 'resolveMx',
    A: 'resolve4',
    AAAA: 'resolve6',
    CNAME: 'resolveCname',
    NS: 'resolveNs',
    SRV: 'resolveSrv',
    CAA: 'resolveCaa',
    SOA: 'resolveSoa',
    PTR: 'resolvePtr'
  };

  // Node solo expone el TTL en los registros de direccion: `resolve4` y
  // `resolve6` lo devuelven como `[{address, ttl}]` cuando se pide con
  // `{ttl: true}`. Comprobado contra la resolucion real: `resolveCname`,
  // `resolveNs`, `resolveMx`, `resolveTxt`, `resolveCaa` y `resolveSoa`
  // ignoran esa opcion y devuelven el valor pelado, sin TTL. Para esos tipos se
  // devuelve null, que es preferible a un TTL inventado: leer un TTL
  // erroneo en un informe de diagnostico cuesta mas que no mostrarlo.
  const CON_TTL = new Set(['A', 'AAAA']);

  const tipoNormalizado = String(tipo).toUpperCase();

  // DNSKEY, DS, RRSIG... no los resuelve Node: se hablan por la red con un
  // paquete crudo. Mismo contrato, para que `consultarLote` los trate igual.
  if (TIPOS_DNSSEC.includes(tipoNormalizado)) {
    return consultarDnssec(nombre, tipoNormalizado, { servers, timeout, reintentos });
  }

  const metodo = METODOS[tipoNormalizado];
  if (!metodo) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `Tipo de registro no soportado: ${tipo}.`, {
      remediation: `Tipos disponibles: ${Object.keys(METODOS).join(', ')}.`
    });
  }

  try {
    const bruto = await conReintento(
      () => conTimeout(
        CON_TTL.has(tipoNormalizado) ? resolver[metodo](nombre, { ttl: true }) : resolver[metodo](nombre),
        timeout,
        `consultando ${tipo} de ${nombre}`
      ),
      { reintentos }
    );

    const { valores, ttl } = normalizar(tipoNormalizado, bruto);
    return { ok: true, valores, ttl, error: null, codigo: null, codigoDns: null };
  } catch (error) {
    const envuelto = wrap(error, { contexto: `consultar ${tipo} de ${nombre}` });
    return {
      ok: false,
      valores: [],
      ttl: null,
      error: envuelto.message,
      codigo: envuelto.code || error?.code || null,
      // El codigo crudo del resolvedor es lo que permite a la herramienta
      // distinguir NXDOMAIN de NODATA de SERVFAIL. `codigo` es el codigo
      // interno de netlab, que agrupa varios fallos bajo el mismo nombre y no
      // sirve para decidir si un dominio existe.
      codigoDns: error?.code || null
    };
  }
}

/**
 * Deja los valores de un registro en una forma estable para los renderizadores
 * y extrae el TTL cuando Node lo provides.
 *
 * Con `{ttl: true}`, los registros de direccion llegan como `[{address, ttl}]`
 * en vez de como cadenas sueltas, asi que hay que aplanarlos. Los demas tipos
 * se dejan como los entrega el resolvedor.
 *
 * @param {string} tipo Tipo normalizado.
 * @param {any} bruto Lo que devuelve el metodo del resolvedor.
 * @returns {{valores: any[], ttl: number|null}}
 */
function normalizar(tipo, bruto) {
  if (tipo === 'SOA' && bruto && !Array.isArray(bruto)) return { valores: [bruto], ttl: null };

  const registros = Array.isArray(bruto) ? bruto : bruto ? [bruto] : [];

  if (!registros.length) return { valores: [], ttl: null };

  // Solo los registros de direccion traen `ttl` como numero.
  const ttls = registros.map((r) => (r && typeof r === 'object' ? r.ttl : null)).filter((t) => typeof t === 'number');
  const ttl = ttls.length ? Math.min(...ttls) : null;

  if (ttls.length) return { valores: registros.map((r) => r.address ?? r), ttl };

  if (tipo === 'CNAME' || tipo === 'NS') return { valores: registros.map(String), ttl };
  return { valores: registros, ttl };
}

/**
 * Key Tag de una DNSKEY, segun el Apendice B del RFC 4034.
 *
 * Se calcula sobre la RDATA completa del registro (flags + protocolo +
 * algoritmo + public key) en grupos de dos octetos. Pantallazo de la version
 * de referencia, que es la unica con la que hay que coincidir de forma exacta:
 *
 *     for (ac = 0, i = 0; i < keysize; ++i)
 *             ac += (i & 1) ? key[i] : key[i] << 8;
 *     ac += (ac >> 16) & 0xFFFF;
 *     return ac & 0xFFFF;
 *
 * Comprobado contra el vector que trae el propio RFC (`dskey.example.com`,
 * key id 60485) y contra el DS publicado de cloudflare.com (keyTag 2371).
 *
 * @param {{flags: number, algorithm: number, key: Buffer}} dnskey
 * @returns {number}
 */
function keyTagDeDnsKey({ flags, algorithm, key }) {
  const rdata = Buffer.alloc(4 + key.length);
  rdata.writeUInt16BE(flags, 0);
  rdata[2] = 3; // El protocolo DNSSEC siempre es 3.
  rdata[3] = algorithm;
  key.copy(rdata, 4);

  let ac = 0;
  for (let i = 0; i < rdata.length; i++) ac += i % 2 ? rdata[i] : rdata[i] << 8;
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

/** Manda un paquete DNS por UDP y resuelve con el primer mensaje que llega. */
function consultarUdp(paquete, servidor) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    socket.once('error', (error) => {
      socket.close();
      reject(error);
    });
    socket.once('message', (mensaje) => {
      socket.close();
      resolve(mensaje);
    });
    socket.send(paquete, PORT_DNS, servidor);
  });
}

/** Manda un paquete DNS por TCP (prefijo de longitud) y devuelve la respuesta. */
function consultarTcp(paquete, servidor) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PORT_DNS, servidor);
    const tropiezos = [];
    let recibido = 0;

    socket.once('error', (error) => {
      socket.destroy();
      reject(error);
    });

    socket.on('data', (trozo) => {
      tropiezos.push(trozo);
      recibido += trozo.length;
      if (recibido < 2) return;
      const cabecera = Buffer.concat(tropiezos);
      const longitud = cabecera.readUInt16BE(0);
      if (recibido >= longitud + 2) {
        socket.destroy();
        resolve(cabecera.slice(2, longitud + 2));
      }
    });

    const marco = Buffer.alloc(paquete.length + 2);
    marco.writeUInt16BE(paquete.length, 0);
    paquete.copy(marco, 2);
    socket.write(marco);
  });
}

/** RCODEs del DNS que tienen traduccion al codigo que usa la herramienta. */
const RCODE_CODIGO = {
  NXDOMAIN: 'ENOTFOUND',
  SERVFAIL: 'ESERVFAIL',
  REFUSED: 'EREFUSED',
  NOTAUTH: 'ENOTAUTH',
  NOTIMP: 'ENOTIMP',
  FORMERR: 'EFORMERR'
};

/** RCODEs que son respuesta definitiva y no merecen probar otro resolver. */
const RCODE_DEFINITIVO = new Set(['ENOTFOUND', 'ESERVFAIL']);

/** Serial RRSIG (segundos desde la epoca) a una fecha corta. */
function serialAFecha(serial) {
  if (typeof serial !== 'number' || serial < 1000000000 || serial > 2000000000) return null;
  return new Date(serial * 1000).toISOString().slice(0, 10);
}

/** NSEC3PARAM no tiene decodificador en dns-packet: llega crudo. Se parsea. */
function decodificarNsec3Param(crudo) {
  if (!Buffer.isBuffer(crudo) || crudo.length < 5) return { algoritmo: null, iteraciones: null, salt: null };
  const algoritmo = crudo.readUInt8(0);
  const flags = crudo.readUInt8(1);
  const iteraciones = crudo.readUInt16BE(2);
  const largoSalt = crudo.readUInt8(4);
  const salt = crudo.slice(5, 5 + largoSalt);
  return { algorithm: algoritmo, flags, iterations: iteraciones, salt };
}

/** Deja cada tipo DNSSEC en una forma estable para los formateadores. */
function enriquecerDnssec(tipo, dato) {
  switch (tipo) {
    case 'DNSKEY':
      return { flags: dato.flags, algorithm: dato.algorithm, key: dato.key, keyTag: keyTagDeDnsKey(dato) };
    case 'DS':
      return { ...dato, digestHex: dato.digest.toString('hex') };
    case 'RRSIG':
      return { ...dato, expira: serialAFecha(dato.expiration) };
    case 'NSEC3':
      return {
        ...dato,
        saltHex: dato.salt.length ? dato.salt.toString('hex') : '-',
        hashHex: dato.nextDomain.toString('hex').slice(0, 32)
      };
    case 'NSEC3PARAM':
      return {
        ...decodificarNsec3Param(dato),
        saltHex: dato?.salt?.length ? dato.salt.toString('hex') : '-'
      };
    default:
      return dato;
  }
}

/** Extrae los valores del tipo pedido y el TTL minimo de una respuesta cruda. */
function normalizarDnssec(tipo, decodificado) {
  const delTipo = (decodificado.answers || []).filter((a) => String(a.type).toUpperCase() === tipo && a.data != null);
  const valores = delTipo.map((a) => enriquecerDnssec(tipo, a.data));
  let ttl = delTipo.length ? Math.min(...delTipo.map((a) => a.ttl)) : null;

  // Sin registros (NODATA), el TTL que importa es el negativo del SOA de la
  // autoridad: dice cuanto se cachea la ausencia.
  if (ttl === null) {
    const soa = (decodificado.authorities || []).find((a) => a.type === 'SOA');
    if (soa) ttl = Math.min(soa.ttl, soa.data?.minttl ?? soa.ttl);
  }

  return { valores, ttl };
}

/** Convierte una respuesta cruda descodificada en el contrato de `consultar`. */
function interpretarDnssec(decodificado, tipo) {
  const ad = decodificado.flag_ad === true;
  const rcode = decodificado.rcode || 'NOERROR';

  if (rcode === 'NOERROR') {
    const { valores, ttl } = normalizarDnssec(tipo, decodificado);
    return { ok: true, valores, ttl, error: null, codigo: null, codigoDns: null, ad };
  }

  return {
    ok: false,
    valores: [],
    ttl: null,
    error: `El servidor de nombres devolvió ${rcode}`,
    codigo: 'RED',
    codigoDns: RCODE_CODIGO[rcode] || null,
    ad
  };
}

/**
 * Consulta un registro DNSSEC hablando DNS por la red de forma directa.
 *
 * Node no expone los tipos DNSSEC (ver TIPOS_DNSSEC), asi que aqui se arma el
 * paquete, se manda por UDP con EDNS y el bit DO (para que el resolver incluya
 * las firmas) y, si la respuesta llega truncada, se repite por TCP. Se proban
 * los resolvers en orden; NXDOMAIN y SERVFAIL son respuestas definitivas y
 * cortan, los fallos de red pasan al siguiente resolver.
 *
 * @param {string} nombre Nombre a consultar.
 * @param {string} tipo Tipo DNSSEC ('DNSKEY', 'DS', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM').
 * @param {object} [options]
 * @param {string[]} [options.servers]
 * @param {number} [options.timeout=5000]
 * @returns {Promise<{ok: boolean, valores: any[], ttl: number|null, error: string|null, codigo: string|null, codigoDns: string|null, ad: boolean}>}
 *   Nunca lanza. `ad` es el bit AD del resolver: true si ha validado la cadena.
 */
async function consultarDnssec(nombre, tipo, options = {}) {
  const { servers = RESOLVERS_PUBLICOS, timeout = 5000 } = options;
  const tipoNormalizado = String(tipo).toUpperCase();
  if (!TIPOS_DNSSEC.includes(tipoNormalizado)) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `Tipo de registro DNSSEC no soportado: ${tipo}.`, {
      remediation: `Tipos disponibles: ${TIPOS_DNSSEC.join(', ')}.`
    });
  }

  const paquete = dnsPacket.encode({
    type: 'query',
    id: (Math.random() * 0xffff) | 0,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ name: nombre, type: tipoNormalizado }],
    additionals: [{ type: 'OPT', name: '.', udpPayloadSize: MAX_UDP_PAYLOAD, flags: dnsPacket.DNSSEC_OK }]
  });

  let ultimoError = null;

  for (const servidor of servers) {
    try {
      const contexto = `consultando ${tipoNormalizado} de ${nombre}`;
      const udp = await conTimeout(consultarUdp(paquete, servidor), timeout, contexto);
      let decodificado = dnsPacket.decode(udp);

      if (decodificado.flags & dnsPacket.TRUNCATED_RESPONSE) {
        const tcp = await conTimeout(consultarTcp(paquete, servidor), timeout, `${contexto} por TCP`);
        decodificado = dnsPacket.decode(tcp);
      }

      const resultado = interpretarDnssec(decodificado, tipoNormalizado);
      if (!resultado.ok && RCODE_DEFINITIVO.has(resultado.codigoDns)) return resultado;
      return resultado;
    } catch (error) {
      ultimoError = error;
    }
  }

  return {
    ok: false,
    valores: [],
    ttl: null,
    error: `No se pudo consultar ${tipoNormalizado} de ${nombre}: ${ultimoError?.message || 'sin respuesta'}`,
    codigo: 'RED',
    codigoDns: ultimoError?.code === 'TIMEOUT' ? 'ETIMEDOUT' : ultimoError?.code || null,
    ad: false
  };
}

/**
 * Consulta el TTL real de un nombre.
 *
 * Usa el resolvedor por defecto del sistema con `resolveAny` para leer la
 * cabecera TTL, que no exponen los metodos por tipo.
 *
 * @param {string} nombre
 * @param {object} [options]
 * @returns {Promise<number|null>}
 */
async function consultarTTL(nombre, options = {}) {
  const { timeout = 3000 } = options;
  try {
    const registros = await conTimeout(dns.resolveAny(nombre), timeout, `leyendo el TTL de ${nombre}`);
    const t = registros.find((r) => typeof r.ttl === 'number');
    return t ? t.ttl : null;
  } catch {
    return null;
  }
}

/**
 * Resolucion inversa (PTR) de una direccion IP.
 *
 * @param {string} ip
 * @returns {Promise<string[]>} Nombres encontrados; vacio si no hay PTR.
 */
async function resolverPTR(ip) {
  try {
    return await dns.reverse(ip);
  } catch {
    return [];
  }
}

/**
 * Consulta muchos registros a la vez, limitando la concurrencia.
 *
 * @param {Array<{nombre: string, tipo: string}>} consultas
 * @param {object} [options]
 * @param {number} [options.concurrencia=6]
 * @param {object} [options.dns] Opciones pasadas a `consultar`.
 * @returns {Promise<Array<{nombre, tipo, ...}>>}
 */
async function consultarLote(consultas, options = {}) {
  const { concurrencia = 6, dns: dnsOptions = {} } = options;
  const ejecutar = limitarConcurrencia(concurrencia);

  return Promise.all(
    consultas.map((c) =>
      ejecutar(async () => {
        const r = await consultar(c.nombre, c.tipo, dnsOptions);
        return { ...c, ...r };
      })
    )
  );
}

module.exports = {
  consultar,
  consultarLote,
  consultarDnssec,
  consultarTTL,
  resolverPTR,
  crearResolver,
  limitarConcurrencia,
  conTimeout,
  conReintento,
  keyTagDeDnsKey,
  TIPOS_DNSSEC,
  RESOLVERS_PUBLICOS
};