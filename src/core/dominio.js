/**
 * dominio.js — Normalización de nombres de host, direcciones IP y tiempos de
 * espera, compartida por las herramientas.
 *
 * MODULO DE CONVENCION. Estas tres funciones vivían dentro de `dns-checker` y
 * `mail-checker` las necesita iguales: si cada herramienta limpiara la entrada
 * a su manera, pegar `https://ejemplo.com/ruta` en una daría un informe correcto
 * y en la otra un "no parece un dominio". Un único módulo evita esa divergencia.
 *
 * @module core/dominio
 */

'use strict';

const net = require('node:net');
const { NetlabError, CODES } = require('./errors');

/**
 * Limpia lo que la gente pega en el campo de dominio.
 *
 * Quita el esquema (`https://`), las credenciales (`usuario:clave@`), la ruta,
 * la query, el fragmento, el puerto y el punto raíz. Todo eso se quita antes de
 * consultar, porque pasar `https://ejemplo.com/` al resolvedor no devuelve
 * NXDOMAIN: devuelve un error confuso que hace perder tiempo.
 *
 * @param {string} bruto
 * @returns {string}
 * @throws {NetlabError} Si no queda un nombre válido.
 */
function normalizarDominio(bruto) {
  let texto = String(bruto ?? '').trim().toLowerCase();
  if (!texto) {
    throw new NetlabError(CODES.ENTRADA_VACIA, 'No se indicó ningún dominio.', {
      remediation: 'Escribe el dominio que quieres comprobar, por ejemplo ejemplo.com.'
    });
  }

  texto = texto
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '') // esquema
    .replace(/^[^/@]*@/, '') // usuario:pass@
    .split(/[/?#]/)[0] // ruta, query y fragmento
    .replace(/:\d+$/, '') // puerto
    .replace(/\.$/, ''); // punto raíz

  // Una etiqueta por si sola (`servidor01`) también es un nombre de DNS válido,
  // y en una red interna es justo lo que se comprueba. No se exige un punto.
  // El guion bajo sí se admite, y hace falta: los nombres de servicio que usan
  // SRV y los de DMARC (`_sip._tcp.ejemplo.com`, `_dmarc.ejemplo.com`) empiezan
  // por guion bajo.
  //
  // Lo que no se admite son espacios, barras o caracteres raros: eso no es un
  // nombre de host y mandarlo al resolvedor solo produce un error confuso.
  if (!/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$/.test(texto)) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${String(bruto).trim()}" no parece un nombre de dominio.`, {
      remediation:
        'Escribe solo el nombre, por ejemplo ejemplo.com o servidor01. Puedes pegarlo con https:// delante y se limpia solo.'
    });
  }

  if (texto.length > 253) {
    throw new NetlabError(CODES.PARAM_INVALIDO, 'El nombre de dominio es demasiado largo.', {
      remediation: 'El límite son 253 caracteres.'
    });
  }

  return texto;
}

/**
 * Valida una dirección IP.
 *
 * La comprobación se delega en `net.isIP` en vez de fiarse de una expresión
 * regular. Una regex del estilo `/^[0-9a-f:]+$/` acepta `2001:db8::1::2`, que
 * lleva dos grupos comprimidos seguidos y por tanto no es una IPv6 válida.
 *
 * @param {string} bruto
 * @returns {string|null} `null` si viene vacío.
 * @throws {NetlabError} Si no es una dirección válida.
 */
function normalizarIp(bruto) {
  const texto = String(bruto ?? '').trim();
  if (!texto) return null;

  // `http://[2001:db8::1]/x` deja la dirección entre corchetes, que es la forma
  // RFC 3986 para direcciones IPv6 dentro de una URL.
  const candidate = texto.replace(/^\[/, '').replace(/\]$/, '');

  if (net.isIP(candidate)) return candidate;

  throw new NetlabError(CODES.PARAM_INVALIDO, `"${texto}" no es una dirección IP válida.`, {
    remediation: 'Escribe solo la dirección, por ejemplo 8.8.8.8 o 2001:db8::1.'
  });
}

/**
 * Acota un tiempo de espera a un rango razonable.
 *
 * @param {*} bruto
 * @param {object} [opciones]
 * @param {number} [opciones.defecto=5000]
 * @param {number} [opciones.min=500]
 * @param {number} [opciones.max=30000]
 * @returns {number}
 */
function normalizarTimeout(bruto, { defecto = 5000, min = 500, max = 30000 } = {}) {
  const n = Number(bruto);
  if (!Number.isFinite(n) || n <= 0) return defecto;
  return Math.max(min, Math.min(max, Math.round(n)));
}

module.exports = { normalizarDominio, normalizarIp, normalizarTimeout };
