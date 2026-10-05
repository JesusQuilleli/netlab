/**
 * mail/comun.js — Utilidades compartidas por los analizadores de correo.
 *
 * El resolvedor de Node entrega cada registro TXT como un ARRAY de trozos: el
 * mismo registro partido en cadenas de 255 bytes. Unir esos trozos con un
 * separador produce un valor distinto al publicado, y entonces SPF deja de
 * cuadrar y DKIM aparece como "sin clave". Aquí se unen sin separador, que es
 * lo que dice el RFC.
 *
 * @module core/mail/comun
 */

'use strict';

/**
 * Aplana un valor TXT a una sola cadena.
 *
 * @param {string|string[]} valor
 * @returns {string}
 */
function aplanarTxt(valor) {
  if (Array.isArray(valor)) return valor.map((v) => String(v ?? '')).join('');
  return String(valor ?? '');
}

/**
 * Extrae los registros TXT legibles de un resultado de `core/net/dns`.
 *
 * @param {object} resultado `{ ok, valores }`
 * @returns {string[]} Registros, sin los vacíos.
 */
function registrosTxt(resultado) {
  if (!resultado?.ok || !Array.isArray(resultado.valores)) return [];
  return resultado.valores.map(aplanarTxt).map((t) => t.trim()).filter(Boolean);
}

/**
 * Filtra los registros que empiezan por un prefijo conocido (sin distinguir
 * mayúsculas), que es como se reconoce cada tipo de registro de correo.
 *
 * @param {string[]} textos
 * @param {string} prefijo p. ej. 'v=spf1', 'v=DMARC1', 'v=DKIM1'
 * @returns {string[]}
 */
function conPrefijo(textos, prefijo) {
  const p = String(prefijo).toLowerCase();
  return (textos || []).filter((t) => String(t).trim().toLowerCase().startsWith(p));
}

/**
 * Parte un registro de tipo `v=DKIM1; k=rsa; p=...` en sus etiquetas.
 *
 * @param {string} registro
 * @returns {Record<string, string>} Claves en minúsculas.
 */
function etiquetas(registro) {
  const salida = {};
  for (const parte of String(registro ?? '').split(';')) {
    const corte = parte.indexOf('=');
    if (corte < 0) continue;
    const clave = parte.slice(0, corte).trim().toLowerCase();
    const valor = parte.slice(corte + 1).trim();
    if (clave) salida[clave] = valor;
  }
  return salida;
}

/**
 * Nombre del registro DKIM de un selector bajo un dominio.
 *
 * @param {string} selector
 * @param {string} dominio
 * @returns {string}
 */
function nombreDkim(selector, dominio) {
  return `${selector}._domainkey.${dominio}`;
}

/** Recorta un valor largo para no reventar una celda de tabla. */
function recortar(texto, limite = 120) {
  const t = String(texto ?? '');
  return t.length <= limite ? t : `${t.slice(0, limite - 1)}…`;
}

module.exports = { aplanarTxt, registrosTxt, conPrefijo, etiquetas, nombreDkim, recortar };
