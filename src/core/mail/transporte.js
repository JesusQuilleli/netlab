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

/**
 * Interpreta el texto de una politica MTA-STS (RFC 8461) servida en
 * https://mta-sts.<dominio>/.well-known/mta-sts.txt.
 *
 * Es puro: no descarga nada, el que llama hace el pedido y pasa aqui el texto.
 *
 * @param {string} [texto]
 * @returns {{presente: boolean, valido: boolean, version: string|null, mode: string|null, mx: string[], maxAge: number|null, errores: string[], avisos: string[]}}
 */
function parsearPoliticaMtaSts(texto) {
  const vacio = { presente: false, valido: false, version: null, mode: null, mx: [], maxAge: null, errores: [], avisos: [] };
  if (!texto || !String(texto).trim()) {
    vacio.errores.push('La política está vacía (o no se pudo leer).');
    return vacio;
  }

  const campos = {};
  for (const linea of String(texto).split(/\r?\n/)) {
    const limpia = linea.replace(/#.*$/, '').trim();
    if (!limpia) continue;
    const m = limpia.match(/^([a-z0-9_]+)\s*[:=]\s*(.*)$/i);
    if (!m) continue;
    const clave = m[1].trim().toLowerCase();
    const valor = m[2].trim();
    if (!campos[clave]) campos[clave] = [];
    campos[clave].push(valor);
  }

  const errores = [];
  const avisos = [];

  // Solo comentarios o líneas sin campos: es como si no hubiera política.
  if (!Object.keys(campos).length) {
    errores.push('No se encontró ningún campo de política en el texto servido.');
    return { presente: false, valido: false, version: null, mode: null, mx: [], maxAge: null, errores, avisos };
  }

  const version = campos.version ? campos.version[0] : null;
  if (!version) errores.push('Falta "version". Debe ser "STSv1".');
  else if (version !== 'STSv1') errores.push(`"${version}" no es una versión de política MTA-STS válida (debe ser STSv1).`);
  if (campos.version && campos.version.length > 1) avisos.push('Hay más de una línea "version".');

  const mode = campos.mode ? campos.mode[0] : null;
  if (!mode) errores.push('Falta "mode". Debe ser enforce, testing o none.');
  else if (!['enforce', 'testing', 'none'].includes(mode)) errores.push(`"mode: ${mode}" no es válido (enforce, testing o none).`);

  const mx = campos.mx || [];
  if (!mx.length) errores.push('Falta "mx": la política debe listar al menos un servidor.');
  for (const host of mx) {
    if (!host || host === '*' || /\s/.test(host)) {
      errores.push(`"mx: ${host}" no es un nombre de servidor válido.`);
    }
  }

  const baremo = Number.parseFloat(campos.max_age ? campos.max_age[0] : '');
  let maxAge = null;
  if (campos.max_age && !Number.isFinite(baremo)) errores.push(`"max_age" no es un número: "${campos.max_age[0]}".`);
  else if (campos.max_age) {
    maxAge = baremo < 0 ? 0 : Math.round(baremo);
    if (maxAge > 31557600) errores.push(`"max_age" (${maxAge}) supera el máximo de un año (31557600 s).`);
  } else {
    avisos.push('Falta "max_age"; por defecto el receptor usa 86400 s (1 día).');
  }

  return { presente: true, valido: errores.length === 0, version, mode, mx, maxAge, errores, avisos };
}

module.exports = { parsear, parsearPoliticaMtaSts };
