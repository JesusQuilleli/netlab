/**
 * mail/dmarc.js — Lectura y valoración de un registro DMARC.
 *
 * DMARC se publica en `_dmarc.<dominio>` y empieza por `v=DMARC1`. La etiqueta
 * `p=` es obligatoria y es la que decide qué hacer cuando SPF y DKIM fallan:
 * `none` solo observa, `quarantine` manda a spam y `reject` rechaza. Publicar
 * DMARC con `p=none` y no pasar nunca a `quarantine`/`reject` deja el dominio
 * sin protección real, por mucho que el registro exista.
 *
 * @module core/mail/dmarc
 */

'use strict';

const { conPrefijo, etiquetas } = require('./comun');

const POLITICAS = new Set(['none', 'quarantine', 'reject']);
const ALINEACIONES = new Set(['r', 's']);
const CONOCIDAS = new Set(['v', 'p', 'sp', 'np', 'pct', 'rua', 'ruf', 'fo', 'adkim', 'aspf', 'rf', 'ri']);

/**
 * Interpreta los registros TXT de `_dmarc.<dominio>`.
 *
 * @param {string[]} textos
 * @returns {object}
 */
function parsear(textos) {
  const encontrados = conPrefijo(textos, 'v=DMARC1');
  const todos = (textos || []).length;

  const base = {
    presente: false,
    multiple: false,
    valor: null,
    valido: false,
    politica: null,
    politicaSubdominios: null,
    pct: null,
    rua: [],
    ruf: [],
    fo: null,
    adkim: null,
    aspf: null,
    etiquetas: {},
    errores: [],
    avisos: []
  };

  if (!encontrados.length) {
    if (todos > 0) {
      base.avisos.push('El nombre "_dmarc" tiene TXT, pero ninguno empieza por "v=DMARC1". No es un registro DMARC válido.');
    }
    return base;
  }

  if (encontrados.length > 1) {
    return {
      ...base,
      presente: true,
      multiple: true,
      valor: encontrados[0],
      errores: [`Hay ${encontrados.length} registros DMARC. Solo puede haber uno; con varios, el receptor descarta la política.`]
    };
  }

  const valor = encontrados[0];
  const tag = etiquetas(valor);
  const errores = [];
  const avisos = [];

  if (!/^v=DMARC1\s*;/i.test(valor)) {
    errores.push('El registro no empieza por "v=DMARC1;". La versión debe ir en primer lugar.');
  }

  // `p` es obligatoria.
  const politica = tag.p ? tag.p.toLowerCase() : null;
  if (!politica) {
    errores.push('Falta la etiqueta "p=", que es obligatoria en DMARC.');
  } else if (!POLITICAS.has(politica)) {
    errores.push(`La política "p=${tag.p}" no es válida. Solo se admite none, quarantine o reject.`);
  }

  const sp = tag.sp ? tag.sp.toLowerCase() : null;
  if (sp && !POLITICAS.has(sp)) errores.push(`La política de subdominios "sp=${tag.sp}" no es válida.`);

  const pct = tag.pct !== undefined ? Number.parseInt(tag.pct, 10) : 100;
  if (tag.pct !== undefined && (!Number.isInteger(pct) || pct < 0 || pct > 100)) {
    errores.push(`"pct=${tag.pct}" no es un porcentaje entre 0 y 100.`);
  }

  const adkim = tag.adkim ? tag.adkim.toLowerCase() : null;
  const aspf = tag.aspf ? tag.aspf.toLowerCase() : null;
  if (adkim && !ALINEACIONES.has(adkim)) errores.push(`"adkim=${tag.adkim}" solo admite "r" (relajada) o "s" (estricta).`);
  if (aspf && !ALINEACIONES.has(aspf)) errores.push(`"aspf=${tag.aspf}" solo admite "r" (relajada) o "s" (estricta).`);

  // Etiquetas que no existen: suelen ser erratas que invalidan el registro.
  for (const clave of Object.keys(tag)) {
    if (!CONOCIDAS.has(clave)) avisos.push(`La etiqueta "${clave}" no es un campo DMARC conocido.`);
  }

  const rua = separarCorreos(tag.rua);
  const ruf = separarCorreos(tag.ruf);

  if (politica === 'none') {
    avisos.push(
      'La política es "p=none": DMARC solo observa y no pide ninguna acción. Los correos que suplantan el dominio llegan igualmente a la bandeja.'
    );
  }
  if (politica && politica !== 'none' && !rua.length) {
    avisos.push('No hay "rua=" (informes agregados). Sin ellos no verás quién envía en tu nombre ni cuándo falla la autenticación.');
  }
  if (pct < 100 && politica && politica !== 'none') {
    avisos.push(`"pct=${pct}" aplica la política solo a ese porcentaje de mensajes: el resto no se filtra.`);
  }
  if (adkim === 's') {
    avisos.push('"adkim=s" exige alineación ESTRICTA de DKIM: el dominio del "d=" debe ser idéntico al del remitente, sin subdominios.');
  }
  if (aspf === 's') {
    avisos.push('"aspf=s" exige alineación ESTRICTA de SPF: el dominio del "Return-Path" debe ser idéntico, sin subdominios.');
  }

  return {
    presente: true,
    multiple: false,
    valor,
    valido: errores.length === 0,
    politica,
    politicaSubdominios: sp,
    pct: Number.isInteger(pct) ? pct : null,
    rua,
    ruf,
    fo: tag.fo || null,
    adkim,
    aspf,
    etiquetas: tag,
    errores,
    avisos
  };
}

/** Separa una lista `mailto:a@x,mailto:b@y` en direcciones legibles. */
function separarCorreos(bruto) {
  if (!bruto) return [];
  return String(bruto)
    .split(',')
    .map((d) => d.trim().replace(/^mailto:/i, ''))
    .filter(Boolean);
}

module.exports = { parsear, POLITICAS, ALINEACIONES };
