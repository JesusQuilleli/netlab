/**
 * net/ipaddr.js — Direcciones IP como numeros, sin perpetrar la familia.
 *
 * MODULO PEQUENO PERO IMPRESCINDIBLE. Lo necesitan dos cosas distintas:
 *
 * 1. RDAP tiene que decidir que servidor de registro usar para una IP, y eso se
 *    hace con el prefijo mas largo que contiene la direccion. Como el
 *    bootstrap de IANA mezcla bloques IPv4 e IPv6, hace falta comparar
 *    direcciones de las dos familias, y `core/net/cidr.js` solo sabe hacer
 *    aritmetica IPv4 (`ipToInt` trabaja con enteros de 32 bits).
 *
 * 2. Una lista negra se consulta con el nombre al reves. En IPv4 es ordenar los
 *    octetos, y en IPv6 es escribir 32 nibbles al reves. Es un detalle facil de
 *    equivocar y silenciosamente disastrous: una consulta mal formada da
 *    "no listada" y parece que todo esta bien.
 *
 * Aqui todo se hace con `BigInt`, que da el mismo treatment a las 32 y a las
 * 128 bits. Es mas lento que los enteros de 32 bits, pero sobre una IP suelta no
 * se nota, y evita mantener dos implementaciones del mismo calculo.
 *
 * @module core/net/ipaddr
 */

'use strict';

const net = require('node:net');

/**
 * Numero de bits de una direccion, o `null` si no es una IP.
 *
 * @param {string} ip
 * @returns {number|null} 32, 128 o `null`.
 */
function bitsDe(ip) {
  if (net.isIPv4(ip)) return 32;
  if (net.isIPv6(ip)) return 128;
  return null;
}

/**
 * Separa el identificador de zona de una IPv6 con interfaz (`fe80::1%eth0`).
 *
 * @param {string} ip
 * @returns {string}
 */
function sinZona(ip) {
  return String(ip).split('%')[0];
}

/**
 * Rellena una IPv6 a 32 digitos hexadecimales, resolviendo la compresion `::`.
 *
 * @param {string} ip IPv6, con o sin zona y con o sin IPv4 al final.
 * @returns {string|null} 32 digitos en hexadecimal, o `null` si no es valida.
 */
function expandirIPv6(ip) {
  const original = sinZona(ip);
  if (!net.isIPv6(original)) return null;

  let texto = original;
  let colaV4 = null;

  // Una IPv6 puede acabar en IPv4 (`::ffff:192.0.2.1`). Esa parte ocupa dos
  // grupos de 16 bits y hay que contarla como tal antes de rellenar los ceros.
  const ultimoDosPuntos = texto.lastIndexOf(':');
  const posibleV4 = texto.slice(ultimoDosPuntos + 1);
  if (posibleV4.includes('.')) {
    if (!net.isIPv4(posibleV4)) return null;
    colaV4 = posibleV4
      .split('.')
      .map((n) => Number(n).toString(16).padStart(2, '0'))
      .join('');
    // Se corta ANTES de los dos puntos, no despues. Dejar el `:` final produce
    // un grupo vacio mas, que se cuenta como un grupo mas y desplaza toda la
    // direccion: `::ffff:192.0.2.1` salia como `::ffff:0:c000:201`.
    texto = texto.slice(0, ultimoDosPuntos);
  }

  const partes = texto.split(':');
  const izquierda = [];
  const derecha = [];
  let i = 0;
  while (i < partes.length && partes[i] !== '') {
    izquierda.push(partes[i]);
    i++;
  }
  if (partes[i] === '') {
    i++;
    while (i < partes.length) {
      derecha.push(partes[i]);
      i++;
    }
  }

  const gruposV4 = colaV4 ? 2 : 0;
  const ceros = 8 - izquierda.length - derecha.length - gruposV4;
  // Un `::` solo cuenta como relleno si estaba ahi. Sin el, un numero de grupos
  // equivocado significa que la entrada no era una IPv6.
  if (ceros < 0) return null;
  if (ceros === 0 && !texto.includes('::')) {
    if (izquierda.length + derecha.length + gruposV4 !== 8) return null;
  }

  const grupos = [...izquierda, ...new Array(ceros).fill('0'), ...derecha];
  // La cola IPv4 son cuatro bytes, o sea DOS grupos de 16 bits. Cortar por la
  // mitad de la cadena (2 y 4) los parte mal y desplaza todos los grupos.
  if (colaV4) grupos.push(colaV4.slice(0, 4), colaV4.slice(4, 8));

  return grupos.map((g) => {
    const limpio = g.replace(/^0+/, '') || '0';
    return limpio.padStart(4, '0').slice(-4);
  }).join('');
}

/**
 * Direccion como cadena de bytes, en orden de red.
 *
 * @param {string} ip
 * @returns {number[]|null} 4 bytes en IPv4, 16 en IPv6, `null` si no es IP.
 */
function aBytes(ip) {
  if (net.isIPv4(ip)) return sinZona(ip).split('.').map(Number);

  const hex = expandirIPv6(ip);
  if (!hex) return null;

  const bytes = [];
  for (let i = 0; i < 32; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
  return bytes;
}

/**
 * Direccion en hexadecimal, rellenada a 32 digitos en IPv6.
 *
 * @param {string} ip
 * @returns {string|null}
 */
function aHex(ip) {
  const bytes = aBytes(ip);
  if (!bytes) return null;
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Direccion como entero, para comparar prefijos.
 *
 * @param {string} ip
 * @returns {bigint|null}
 */
function aEntero(ip) {
  const hex = aHex(ip);
  return hex === null ? null : BigInt(`0x${hex}`);
}

/**
 * Indica si un prefijo CIDR contiene una direccion.
 *
 * @param {string} prefijo p. ej. `1.0.0.0/8` o `2001:db8::/32`.
 * @param {string} ip
 * @returns {boolean}
 */
function contiene(prefijo, ip) {
  const [base, largo] = String(prefijo).split('/');
  const bitsBase = bitsDe(base);
  const bitsIp = bitsDe(ip);
  if (bitsBase === null || bitsIp === null || bitsBase !== bitsIp) return false;

  const n = Number(largo);
  if (!Number.isInteger(n) || n < 0 || n > bitsBase) return false;

  const a = aEntero(base);
  const b = aEntero(ip);
  // BigInt >> Number lanza TypeError: los dos lados tienen que ser BigInt.
  const desplazamiento = BigInt(bitsBase - n);

  // Con prefijo 0 los dos desplazan 32 o 128 bits y ambos quedan a cero: todo
  // el mundo esta dentro, que es justo lo que significa /0.
  return (a >> desplazamiento) === (b >> desplazamiento);
}

/**
 * De una lista de prefijos, el mas especifico que contiene la direccion.
 *
 * Es la regla que exige el bootstrap de RDAP: si una IP cae en `0.0.0.0/0` y en
 * `1.0.0.0/8`, gana el /8. Quedarse con el primero de la lista daria el
 * servidor equivocado y un error muy dificil de entender.
 *
 * @param {string} ip
 * @param {string[]} prefijos
 * @returns {string|null} El prefijo ganador, o `null` si ninguno la contiene.
 */
function prefijoMasLargo(ip, prefijos) {
  let mejor = null;
  let mejorLongitud = -1;

  for (const prefijo of prefijos || []) {
    if (!contiene(prefijo, ip)) continue;
    const longitud = Number(String(prefijo).split('/')[1]);
    if (longitud > mejorLongitud) {
      mejorLongitud = longitud;
      mejor = prefijo;
    }
  }

  return mejor;
}

/**
 * Nombre de la zona inversa que usa una lista negra.
 *
 * IPv4 son los octetos al reves con `in-addr.arpa`. IPv6 son los 32 nibbles al
 * reves con `ip6.arpa`, no los bytes: escribir los bytes al reves produce una
 * zona que existe pero nunca devuelve lo que se le pregunta.
 *
 * @param {string} ip
 * @returns {string|null}
 */
function nombreInvertido(ip) {
  if (net.isIPv4(ip)) {
    return `${sinZona(ip).split('.').reverse().join('.')}.in-addr.arpa`;
  }

  const hex = expandirIPv6(ip);
  if (!hex) return null;
  return `${hex.split('').reverse().join('.')}.ip6.arpa`;
}

/**
 * Version "bonita" de una IPv6, con la compresion puesta donde mas se acorta.
 *
 * @param {string} ip
 * @returns {string|null}
 */
function comprimirIPv6(ip) {
  const hex = expandirIPv6(ip);
  if (!hex) return sinZona(ip);

  const grupos = [];
  for (let i = 0; i < 32; i += 4) grupos.push(hex.slice(i, i + 4));

  // Buscar la racha de ceros mas larga; a igualdad de longitud, la primera.
  let mejorInicio = -1;
  let mejorLargo = 0;
  let inicio = -1;
  for (let i = 0; i <= grupos.length; i++) {
    if (grupos[i] === '0000') {
      if (inicio === -1) inicio = i;
    } else if (inicio !== -1) {
      if (i - inicio > mejorLargo) {
        mejorLargo = i - inicio;
        mejorInicio = inicio;
      }
      inicio = -1;
    }
  }
  if (mejorLargo < 2) return grupos.map(acortar).join(':');

  const izquierda = grupos.slice(0, mejorInicio).map(acortar).join(':');
  const derecha = grupos.slice(mejorInicio + mejorLargo).map(acortar).join(':');
  return `${izquierda}::${derecha}`;
}

/** `0db8` -> `db8`. Cada grupo se escribe sin ceros a la izquierda (RFC 5952). */
function acortar(grupo) {
  return (grupo.replace(/^0+/, '') || '0');
}

/**
 * Octetos de una IPv4 como texto, sin ceros a la izquierda.
 *
 * `node:dns` devuelve el PTR ya normalizado, pero algunas fuentes y zonas
 * antiguas lo entregan como `010.001.000.001`. `net.isIPv4` rechaza esa forma
 * a proposito (es ambigua: en octal valia otra cosa), asi que aqui se comprueba
 * octeto a octeto en vez de delegar.
 *
 * @param {string} ip
 * @returns {string|null} p. ej. `10.1.0.1`, o `null` si no son cuatro octetos.
 */
function normalizarIPv4(ip) {
  const partes = sinZona(ip).split('.');
  if (partes.length !== 4) return null;

  const octetos = partes.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  if (octetos.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;

  return octetos.join('.');
}

module.exports = {
  bitsDe,
  sinZona,
  expandirIPv6,
  aBytes,
  aHex,
  aEntero,
  contiene,
  prefijoMasLargo,
  nombreInvertido,
  comprimirIPv6,
  normalizarIPv4
};
