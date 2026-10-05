/**
 * mail/transporte.js — Registros de seguridad de transporte del correo.
 *
 * Tres extensiones que no autentican al remitente pero protegen el trayecto:
 *
 *   - MTA-STS (`_mta-sts`): obliga a los receptores que lo soportan a usar TLS
 *     con tu dominio y a validar el certificado. Frustra el "stripping" de TLS.
 *   - TLS-RPT (`_smtp._tls`): pide informes de fallos de TLS.
 *   - BIMI (`default._bimi`): asocia un logotipo verificado a los correos.
 *
 * No hay aquí ninguna descarga de la política MTA-STS ni del logotipo: el
 * análisis se queda en lo que publica el DNS, y el informe lo dice.
 *
 * @module core/mail/transporte
 */

'use strict';

const { conPrefijo, etiquetas } = require('./comun');

/**
 * Interpreta los tres registros de transporte.
 *
 * @param {object} entradas
 * @param {string[]} [entradas.mtaSts] TXT de `_mta-sts.<dominio>`
 * @param {string[]} [entradas.tlsRpt] TXT de `_smtp._tls.<dominio>`
 * @param {string[]} [entradas.bimi] TXT de `default._bimi.<dominio>`
 * @returns {{mtaSts: object, tlsRpt: object, bimi: object}}
 */
function parsear(entradas = {}) {
  return {
    mtaSts: leerMtaSts(entradas.mtaSts || []),
    tlsRpt: leerTlsRpt(entradas.tlsRpt || []),
    bimi: leerBimi(entradas.bimi || [])
  };
}

function leerMtaSts(textos) {
  const encontrados = conPrefijo(textos, 'v=STSv1');
  if (!encontrados.length) return { presente: false, valido: false, valor: null, id: null, errores: [], avisos: [] };

  const valor = encontrados[0];
  const tag = etiquetas(valor);
  const errores = [];
  const avisos = [];
  if (!tag.id) errores.push('Falta la etiqueta "id=", que es obligatoria en MTA-STS.');
  else if (!/^\d+$/.test(tag.id)) avisos.push(`El "id=${tag.id}" no es numérico; suele ser la marca de tiempo del último cambio.`);
  if (encontrados.length > 1) avisos.push('Hay más de un TXT de MTA-STS en el mismo nombre.');

  return { presente: true, valido: errores.length === 0, valor, id: tag.id || null, errores, avisos };
}

function leerTlsRpt(textos) {
  const encontrados = conPrefijo(textos, 'v=TLSRPTv1');
  if (!encontrados.length) return { presente: false, valido: false, valor: null, rua: [], errores: [], avisos: [] };

  const valor = encontrados[0];
  const tag = etiquetas(valor);
  const avisos = [];
  const rua = separarCorreos(tag.rua);
  if (!rua.length) avisos.push('Falta "rua=": sin dirección de informe, el registro no envía nada.');

  return { presente: true, valido: rua.length > 0, valor, rua, errores: [], avisos };
}

function leerBimi(textos) {
  const encontrados = conPrefijo(textos, 'v=BIMI1');
  if (!encontrados.length) return { presente: false, valido: false, valor: null, logo: null, autoridad: null, errores: [], avisos: [] };

  const valor = encontrados[0];
  const tag = etiquetas(valor);
  const errores = [];
  const avisos = [];

  // `l=` puede ser una URL https o vacío (indica "autenticación en curso").
  const logo = tag.l === undefined ? undefined : tag.l;
  if (logo === undefined) errores.push('Falta la etiqueta "l=" con la URL del logotipo.');
  else if (logo && !/^https:\/\//i.test(logo)) errores.push('La URL del logotipo ("l=") debe empezar por https://.');
  if (!logo) avisos.push('"l=" está vacío: el dominio está declarando BIMI pero sin logotipo todavía.');
  if (!tag.a) avisos.push('Sin "a=" (VMC). BIMI sin autoridad verificada lo ignoran Gmail y otros grandes.');

  return { presente: true, valido: errores.length === 0, valor, logo: logo ?? null, autoridad: tag.a || null, errores, avisos };
}

function separarCorreos(bruto) {
  if (!bruto) return [];
  return String(bruto)
    .split(',')
    .map((d) => d.trim().replace(/^mailto:/i, ''))
    .filter(Boolean);
}

module.exports = { parsear };
