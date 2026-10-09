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
const crypto = require('node:crypto');
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
 * Tipos de servicio (SVCB y HTTPS, RFC 9460).
 *
 * Node tampoco los resuelve, y `dns-packet` no trae decodificador, asi que se
 * piden con el paquete crudo y la RDATA se interpreta aqui. Un registro HTTPS
 * es lo que publica ALPN (h2, h3), puerto y pistas de direccion para un sitio:
 * justo lo que hace falta para saber si un dominio ofrece HTTP/3.
 */
const TIPOS_SERVICIO = ['HTTPS', 'SVCB'];

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

  // HTTPS y SVCB tampoco: paquete crudo con la RDATA decodificada aqui.
  if (TIPOS_SERVICIO.includes(tipoNormalizado)) {
    return consultarServicio(nombre, tipoNormalizado, { servers, timeout });
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

/** Hash de cada tipo de digest de DS (RFC 4034 apartado 5.1.3). */
const HASH_DS = { 1: 'sha1', 2: 'sha256', 4: 'sha384' };

/**
 * Pasa un nombre a su forma canonica de DNS (RFC 4034 apartado 6.2): etiquetas
 * en minusculas, cada una precedida por su longitud, terminado en la raiz.
 *
 * @param {string} nombre
 * @returns {Buffer}
 */
function nombreAWire(nombre) {
  const etiquetas = String(nombre).replace(/\.$/, '').toLowerCase().split('.').filter(Boolean);
  const partes = [];
  for (const etiqueta of etiquetas) {
    const bytes = Buffer.from(etiqueta, 'ascii');
    partes.push(Buffer.from([bytes.length]), bytes);
  }
  partes.push(Buffer.from([0]));
  return Buffer.concat(partes);
}

/**
 * Calcula el digest de un DS a partir de una DNSKEY y el nombre de la zona.
 *
 * El digest cubre, en este orden: el nombre en forma canonica y la RDATA de la
 * DNSKEY (flags, protocolo, algoritmo y clave). Compararlo con el digest que
 * publica la zona padre es lo unico que demuestra que el DS y la clave encajan
 * de verdad; que el keyTag coincida no basta.
 *
 * @param {{flags:number, algorithm:number, key:Buffer}} dnskey
 * @param {string} nombre Nombre de la zona (propietario de la DNSKEY).
 * @param {number} digestType Tipo de digest del DS (1, 2 o 4).
 * @returns {string|null} Digest en hexadecimal, o null si el tipo no se soporta.
 */
function calcularDigestoDs(dnskey, nombre, digestType) {
  const hash = HASH_DS[digestType];
  if (!hash || !dnskey || !Buffer.isBuffer(dnskey.key)) return null;

  const rdata = Buffer.alloc(4 + dnskey.key.length);
  rdata.writeUInt16BE(dnskey.flags, 0);
  rdata[2] = 3;
  rdata[3] = dnskey.algorithm;
  dnskey.key.copy(rdata, 4);

  return crypto.createHash(hash).update(Buffer.concat([nombreAWire(nombre), rdata])).digest('hex');
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

/** Numero de tipo wire de cada registro de servicio. */
const NUMERO_TIPO_SERVICIO = { SVCB: 64, HTTPS: 65 };

/** Nombre de cada clave de parametro SVCB. */
const CLAVES_SVCB = {
  0: 'mandatory',
  1: 'alpn',
  2: 'no-default-alpn',
  3: 'port',
  4: 'ipv4hint',
  5: 'ech',
  6: 'ipv6hint',
  7: 'dohpath'
};

/** Formatea 16 octetos como una direccion IPv6. */
function formatearIPv6(buffer) {
  const grupos = [];
  for (let i = 0; i < 16; i += 2) grupos.push(buffer.readUInt16BE(i).toString(16));
  // Compacta la run mas larga de ceros con "::".
  let mejorInicio = -1;
  let mejorLargo = 0;
  let inicio = -1;
  for (let i = 0; i <= grupos.length; i++) {
    if (i < grupos.length && grupos[i] === '0') {
      if (inicio < 0) inicio = i;
    } else if (inicio >= 0) {
      const largo = i - inicio;
      if (largo > mejorLargo) {
        mejorLargo = largo;
        mejorInicio = inicio;
      }
      inicio = -1;
    }
  }
  if (mejorLargo < 2) return grupos.join(':');
  const izq = grupos.slice(0, mejorInicio).join(':');
  const der = grupos.slice(mejorInicio + mejorLargo).join(':');
  return `${izq}::${der}`;
}

/** Decodifica el valor de una clave de parametro SVCB segun su tipo. */
function decodificarParamSvcb(clave, valor) {
  if (clave === 1) {
    // alpn: lista de cadenas con prefijo de longitud.
    const alpn = [];
    let i = 0;
    while (i < valor.length) {
      const largo = valor[i];
      i += 1;
      alpn.push(valor.slice(i, i + largo).toString('ascii'));
      i += largo;
    }
    return alpn;
  }
  if (clave === 2) return true;
  if (clave === 3) return valor.length >= 2 ? valor.readUInt16BE(0) : null;
  if (clave === 4) {
    const ips = [];
    for (let i = 0; i + 4 <= valor.length; i += 4) ips.push(`${valor[i]}.${valor[i + 1]}.${valor[i + 2]}.${valor[i + 3]}`);
    return ips;
  }
  if (clave === 5) return `${valor.length} bytes (ECH)`;
  if (clave === 6) {
    const ips = [];
    for (let i = 0; i + 16 <= valor.length; i += 16) ips.push(formatearIPv6(valor.slice(i, i + 16)));
    return ips;
  }
  if (clave === 0) {
    const claves = [];
    for (let i = 0; i + 2 <= valor.length; i += 2) {
      const n = valor.readUInt16BE(i);
      claves.push(CLAVES_SVCB[n] || String(n));
    }
    return claves;
  }
  return valor.toString('utf8');
}

/**
 * Decodifica la RDATA de un registro SVCB/HTTPS (RFC 9460).
 *
 * @param {Buffer} rdata
 * @returns {{prioridad:number, destino:string, params:Array<{key,nombre,valor}>}|null}
 */
function decodificarSvcbRdata(rdata) {
  if (!Buffer.isBuffer(rdata) || rdata.length < 3) return null;

  const prioridad = rdata.readUInt16BE(0);
  let offset = 2;

  // El nombre destino no lleva compresion: RFC 9460 la prohibe aqui.
  const etiquetas = [];
  while (offset < rdata.length && rdata[offset] !== 0) {
    const largo = rdata[offset];
    offset += 1;
    if (offset + largo > rdata.length) break;
    etiquetas.push(rdata.slice(offset, offset + largo).toString('ascii'));
    offset += largo;
  }
  offset += 1; // consume el octeto raiz

  const params = [];
  while (offset + 4 <= rdata.length) {
    const clave = rdata.readUInt16BE(offset);
    offset += 2;
    const largo = rdata.readUInt16BE(offset);
    offset += 2;
    const valor = rdata.slice(offset, offset + largo);
    offset += largo;
    params.push({ key: clave, nombre: CLAVES_SVCB[clave] || `key${clave}`, valor: decodificarParamSvcb(clave, valor) });
  }

  return { prioridad, destino: etiquetas.join('.') || '.', params };
}

/**
 * Consulta un registro HTTPS o SVCB hablando DNS por la red de forma directa.
 *
 * Mismo contrato que `consultar`, para que `consultarLote` lo trate igual.
 *
 * @param {string} nombre
 * @param {string} tipo 'HTTPS' o 'SVCB'.
 * @param {object} [options]
 * @returns {Promise<{ok:boolean, valores:any[], ttl:number|null, error:string|null, codigo:string|null, codigoDns:string|null, ad:boolean}>}
 */
async function consultarServicio(nombre, tipo, options = {}) {
  const { servers = RESOLVERS_PUBLICOS, timeout = 5000 } = options;
  const tipoNormalizado = String(tipo).toUpperCase();
  if (!TIPOS_SERVICIO.includes(tipoNormalizado)) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `Tipo de servicio no soportado: ${tipo}.`, {
      remediation: `Tipos disponibles: ${TIPOS_SERVICIO.join(', ')}.`
    });
  }

  const numero = NUMERO_TIPO_SERVICIO[tipoNormalizado];
  const etiquetaTipo = `UNKNOWN_${numero}`;
  const paquete = dnsPacket.encode({
    type: 'query',
    id: (Math.random() * 0xffff) | 0,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ name: nombre, type: etiquetaTipo }],
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

      const ad = decodificado.flag_ad === true;
      const rcode = decodificado.rcode || 'NOERROR';
      if (rcode !== 'NOERROR') {
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

      const delTipo = (decodificado.answers || []).filter(
        (a) => String(a.type) === etiquetaTipo && a.data != null
      );
      const valores = delTipo.map((a) => decodificarSvcbRdata(a.data)).filter(Boolean);
      const ttls = delTipo.map((a) => a.ttl).filter((t) => typeof t === 'number');
      let ttl = ttls.length ? Math.min(...ttls) : null;
      if (ttl === null) {
        const soa = (decodificado.authorities || []).find((a) => a.type === 'SOA');
        if (soa) ttl = Math.min(soa.ttl, soa.data?.minttl ?? soa.ttl);
      }

      return { ok: true, valores, ttl, error: null, codigo: null, codigoDns: null, ad };
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
  consultarServicio,
  consultarTTL,
  resolverPTR,
  crearResolver,
  limitarConcurrencia,
  conTimeout,
  conReintento,
  keyTagDeDnsKey,
  calcularDigestoDs,
  nombreAWire,
  decodificarSvcbRdata,
  TIPOS_DNSSEC,
  TIPOS_SERVICIO,
  RESOLVERS_PUBLICOS
};