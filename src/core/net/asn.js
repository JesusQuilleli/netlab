/**
 * net/asn.js — Que sistema autonomo anuncia una direccion IP (Team Cymru).
 *
 * QUIEN ANUNCIA UNA IP. La IP la registra un bloque (eso lo dice RDAP, y da el
 * titular y el contacto de abuso), pero quien la ANUNCIA por BGP es otra cosa:
 * un "sistema autonomo" (ASN) que puede ser el mismo registrante o un tercero
 * que le da servicio de red. Saberlo responde a preguntas que RDAP no toca:
 * "esta IP es de Google o de un cliente alojado en Google", "en que pais se
 * anuncia aunque el bloque se registro en otro".
 *
 * LA FUENTE. Team Cymru publica el mapeo IP -> ASN por DNS y gratis, sin clave
 * ni registro:
 *
 *   - `<IP al reves>.origin.asn.cymru.com` (IPv4) y
 *     `<IP al reves>.origin6.asn.cymru.com` (IPv6): un TXT como
 *     `15169 | 8.8.8.0/24 | US | arin | 2023-12-28` (ASN | prefijo | pais |
 *     registro | fecha de asignacion).
 *   - `AS<n>.asn.cymru.com` TXT: el nombre del ASN,
 *     `15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US`.
 *
 * La familia IPv6 usa `origin6` porque las dos zonas son distintas y la de IPv4
 * nunca contesta a una IPv6. Pegar las dos cosas daria un "no anunciada"
 * silencioso.
 *
 * TRES ESTADOS, MAS O MENOS LOS DE SIEMPRE:
 *
 *   - `encontrado`: hay un ASN de verdad y los datos se leyeron.
 *   - `no-anunciada`: la IP no la anuncia nadie (AS0, o NXDOMAIN en su zona).
 *     Es la respuesta normal para rangos reservados, TEST-NET y direcciones
 *     internas; no es un fallo.
 *   - `sin-datos`: no se pudo preguntar (red caida, zona sin respuesta). No es
 *     "no anunciada": es un hueco del informe, y quien lo lea tiene que poder
 *     distinguirlo.
 *
 * @module core/net/asn
 */

'use strict';

const ipaddr = require('./ipaddr');
const dnsNet = require('./dns');
const { NetlabError, CODES } = require('../errors');

/** Zona origen por familia (bits de la direccion). */
const ZONA_ORIGEN = {
  32: 'origin.asn.cymru.com',
  128: 'origin6.asn.cymru.com'
};

/** Zona de registro: de un numero de ASN da su nombre. */
const ZONA_REGISTRO = 'asn.cymru.com';

/** Team Cymru responde AS0 para lo que no anuncia nadie. */
const ASN_NO_ANUNCIADO = '0';

const NO_ANUNCIADA = 'no-anunciada';
const ENCONTRADO = 'encontrado';
const SIN_DATOS = 'sin-datos';

/**
 * Nombre DNS de la consulta origen para una IP.
 *
 * @param {string} ip
 * @returns {string|null} p. ej. `203.0.113.10` -> `10.113.0.203.origin.asn.cymru.com`.
 */
function nombreDeOrigen(ip) {
  const bits = ipaddr.bitsDe(ip);
  const invertido = ipaddr.nombreInvertido(ip);
  if (!bits || !invertido) return null;

  // Quitar `.in-addr.arpa` / `.ip6.arpa`: la zona de Team Cymru es una zona mas,
  // no cuelga de la zona inversa. Ese sufijo es lo que se pide para un PTR.
  const base = invertido.replace(/\.(?:in-addr|ip6)\.arpa$/, '');
  return `${base}.${ZONA_ORIGEN[bits]}`;
}

/** Nombre DNS del registro de un numero de ASN (`15169` -> `AS15169.asn.cymru.com`). */
function nombreDeAsn(asn) {
  return `AS${String(asn).replace(/^as/i, '')}.${ZONA_REGISTRO}`;
}

/**
 * Interpreta una respuesta de `origin*.asn.cymru.com`.
 *
 * Formato real comprobado: `15169 | 8.8.8.0/24 | US | arin | 2023-12-28`.
 * La cabecera antigua de Team Cymru documenta mas columnas, pero el servicio
 * actual solo devuelve estas cinco, y leer campos que ya no vienen daria un
 * informe con huecos.
 *
 * @param {string|string[]} texto El TXT, tal cual lo devuelve el resolver.
 * @returns {{asn: string|null, prefijo: string|null, pais: string|null, registro: string|null, asignado: string|null}}
 */
function interpretarOrigen(texto) {
  const partes = String(Array.isArray(texto) ? texto.join('') : texto)
    .split('|')
    .map((p) => p.trim())
    .filter(Boolean);

  return {
    asn: partes[0] || null,
    prefijo: partes[1] || null,
    pais: partes[2] || null,
    registro: partes[3] || null,
    asignado: partes[4] || null
  };
}

/**
 * Interpreta una respuesta de `asn.cymru.com`.
 *
 * Formato: `15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US`. Se guarda
 * el nombre entero y de la parte tras la raya no se hacen cortes: "GOOGLE -
 * Google LLC, US" es el texto oficial y cortarlo delegaria en una heuristica.
 *
 * @param {string|string[]} texto
 * @returns {{asn: string|null, pais: string|null, registro: string|null, asignado: string|null, nombre: string|null}}
 */
function interpretarRegistro(texto) {
  const partes = String(Array.isArray(texto) ? texto.join('') : texto)
    .split('|')
    .map((p) => p.trim())
    .filter(Boolean);

  return {
    asn: partes[0] || null,
    pais: partes[1] || null,
    registro: partes[2] || null,
    asignado: partes[3] || null,
    nombre: partes[4] || null
  };
}

/**
 * Consulta un TXT y lo reduce a `{textos, error}` sin romper el flujo.
 *
 * Un TXT de DNS llega como lista de cadenas (Node corta una cadena larga en
 * fragmentos de 255 bytes). Unir los fragmentos devuelve el texto entero, que es
 * lo que la respuesta de Team Cymru necesita para parsearse.
 *
 * @param {object} dns Modulo DNS inyectable (`dns.consultar(nombre, tipo, opts)`).
 * @param {string} nombre
 * @param {number} timeout
 * @returns {Promise<{textos: string[], error: string|null, codigoDns: string|null}>}
 */
async function consultarTxt(dns, nombre, timeout) {
  const r = await dns.consultar(nombre, 'TXT', { timeout });
  if (!r.ok) {
    return { textos: [], error: r.error || r.codigoDns || 'sin respuesta', codigoDns: r.codigoDns || null };
  }
  return { textos: r.valores.map((v) => (Array.isArray(v) ? v.join('') : String(v))), error: null, codigoDns: null };
}

/**
 * Codigos del resolver que significan "ese nombre no existe": la IP no la
 * anuncia ningun sistema autonomo, que es una respuesta valida, no un fallo.
 */
const AUSENTES = new Set(['ENOTFOUND', 'ENODATA', 'ENODOMAIN']);

/**
 * Consulta el sistema autonomo que anuncia una IP.
 *
 * Se hacen dos consultas DNS, ambas contra Team Cymru: la de origen, que es la
 * que decide, y la de registro solo para el nombre del ASN. La segunda es
 * complementaria: si falla, la consulta sigue siendo utilizable con el numero,
 * y el informe dice que el nombre no se pudo conseguir en vez de tirar el dato.
 *
 * @param {string} ip
 * @param {object} [opciones]
 * @param {object} [opciones.dns] Modulo DNS inyectable (para las pruebas).
 * @param {number} [opciones.timeout=6000]
 * @returns {Promise<object>} Estado `encontrado`, `no-anunciada` o `sin-datos`.
 *   Nunca lanza por motivos de red; solo lanza si `ip` no es una direccion.
 */
async function consultar(ip, opciones = {}) {
  const { dns = dnsNet, timeout = 6000 } = opciones;

  const bits = ipaddr.bitsDe(ip);
  if (!bits) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${ip}" no es una direccion IP.`, {
      remediation: 'Escribe una IPv4 (203.0.113.10) o una IPv6 (2001:db8::1).'
    });
  }

  const origen = nombreDeOrigen(ip);
  let respuesta;
  try {
    respuesta = await consultarTxt(dns, origen, timeout);
  } catch (error) {
    return { ip, estado: SIN_DATOS, asns: [], error: `No se pudo consultar el ASN de ${ip}: ${error.message}` };
  }

  if (respuesta.error) {
    // NXDOMAIN y amigos no son un fallo: son como dice Team Cymru que no
    // anuncia nadie esa IP (rangos reservados, TEST-NET, direcciones internas).
    if (AUSENTES.has(respuesta.codigoDns)) {
      return {
        ip,
        estado: NO_ANUNCIADA,
        asns: [],
        asn: null,
        prefijo: null,
        pais: null,
        registro: null,
        asignado: null,
        nombre: null,
        avisos: []
      };
    }
    return { ip, estado: SIN_DATOS, asns: [], error: `No se pudo consultar el ASN de ${ip}: ${respuesta.error}` };
  }

  // Un prefijo lo pueden anunciar varios ASN; Team Cymru devuelve entonces un
  // TXT por cada uno. Los AS0 se descartan: dicen "nadie", no aportan un numero.
  const asns = [];
  for (const texto of respuesta.textos) {
    const datos = interpretarOrigen(texto);
    if (!datos.asn || datos.asn === ASN_NO_ANUNCIADO) continue;
    asns.push(datos);
  }

  if (!asns.length) {
    return {
      ip,
      estado: NO_ANUNCIADA,
      asns: [],
      asn: null,
      prefijo: null,
      pais: null,
      registro: null,
      asignado: null,
      nombre: null,
      avisos: []
    };
  }

  const principal = asns[0];

  // El nombre del ASN es el dato accesorio: vale la pena tenerlo, y no vale la
  // pena tumbar la consulta si esta zona no contesta.
  let nombre = null;
  let avisos = [];
  try {
    const registro = await consultarTxt(dns, nombreDeAsn(principal.asn), timeout);
    if (!registro.error && registro.textos.length) {
      nombre = interpretarRegistro(registro.textos[0]).nombre;
    } else {
      avisos.push(`La zona de registro no contesto (${registro.error}); el nombre del ASN no se pudo conseguir.`);
    }
  } catch (error) {
    avisos.push(`La zona de registro no contesto (${error.message}); el nombre del ASN no se pudo conseguir.`);
  }

  return {
    ip,
    estado: ENCONTRADO,
    asns: asns.map((a) => a.asn),
    asn: principal.asn,
    prefijo: principal.prefijo,
    pais: principal.pais,
    registro: principal.registro,
    asignado: principal.asignado,
    nombre,
    avisos
  };
}

module.exports = {
  consultar,
  nombreDeOrigen,
  nombreDeAsn,
  interpretarOrigen,
  interpretarRegistro,
  ZONA_ORIGEN,
  ZONA_REGISTRO,
  ESTADOS: { NO_ANUNCIADA, ENCONTRADO, SIN_DATOS }
};