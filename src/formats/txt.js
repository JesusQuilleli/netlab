/**
 * txt.js — Reporte en texto plano.
 *
 * MODULO DE SALIDA. Sustituye a la concatenacion manual de cadenas que hacia
 * cada script legacy con su propio formato. En legacy/Check IP Abuse/checked/check-ip.js,
 * por ejemplo, el reporte se armaba con plantillas sueltas y lineas en blanco
 * para cuadrarlo a ojo. Aqui la estructura sale del `Result`.
 *
 * @module formats/txt
 */

'use strict';

const { human, duration } = require('../core/time');
const { STATUS_META } = require('../core/result');

/** Ancho de linea del reporte. Coincide con la cabecera. */
const ANCHO = 100;

/** Ancho minimo de una columna antes de empezar a recortar contenido. */
const MIN_COLUMNA = 6;

const LINEA = '='.repeat(ANCHO);
const LINEA_FINA = '-'.repeat(ANCHO);

/**
 * Renderiza un Result a texto plano.
 *
 * @param {object} result
 * @param {object} [options]
 * @returns {string}
 */
function render(result, options = {}) {
  const { pie = 'Generado automaticamente por netlab' } = options;
  const s = [];
  const meta = STATUS_META[result.status] || STATUS_META.error;

  s.push(LINEA);
  s.push(result.toolTitle.toUpperCase());
  s.push(LINEA);
  // El titular va el primero y en su propia linea porque es lo primero que se
  // lee al abrir el fichero. Sin el, el que abre un .txt ve "COMPROBADOR DE
  // WEB" y tiene que bajar hasta "Estado" para enterarse del resultado.
  if (result.headline) {
    s.push(result.headline);
    s.push(LINEA);
  }
  s.push(`Estado     : ${meta.label}`);
  s.push(`Objetivo   : ${result.target || 'n/d'}`);
  s.push(`Fecha      : ${human(result.startedAt)}`);
  s.push(`Duración   : ${duration(result.durationMs)}`);
  s.push('');

  if (result.summary?.length) {
    s.push(regla('RESUMEN'));
    for (const item of result.summary) {
      s.push(...envolver(`${String(item.label).padEnd(18)}: ${item.value}`, ANCHO));
    }
    s.push('');
  }

  if (result.error) {
    s.push(regla('ERROR'));
    s.push(`[${result.error.code}] ${result.error.message}`);
    if (result.error.remediation) s.push(...envolver(`Sugerencia: ${result.error.remediation}`, ANCHO));
    s.push('');
  }

  for (const seccionDef of result.sections || []) {
    s.push(LINEA_FINA);
    s.push(seccionDef.title.toUpperCase());
    if (seccionDef.description) s.push(...envolver(seccionDef.description, ANCHO));
    s.push(LINEA_FINA);

    switch (seccionDef.kind) {
      case 'table':
        s.push(...tablaTexto(seccionDef));
        break;
      case 'kv':
        // El ancho de la columna de claves se mide sobre el bloque entero, no
        // con un valor fijo: si no, una clave larga como "Ocupación de la red
        // padre" se come el espacio y deja el valor pegado al dos puntos.
        {
          const claves = (seccionDef.items || []).map(([k]) => String(k).length);
          const anchoClave = Math.min(34, Math.max(20, ...claves));
          for (const [k, v] of seccionDef.items || []) {
            const valor = typeof v === 'object' ? v.valor : v;
            s.push(...fichaTexto(String(k), valor, anchoClave));
          }
        }
        break;
      case 'code':
        s.push(String(seccionDef.value ?? ''));
        break;
      case 'list':
        for (const item of seccionDef.items || []) s.push(`- ${item}`);
        break;
      case 'meter':
        s.push(barraTexto(seccionDef.value, 40));
        break;
      case 'text':
      default:
        if (seccionDef.value) s.push(String(seccionDef.value));
        break;
    }
    s.push('');
  }

  if (result.findings?.length) {
    s.push(regla('HALLAZGOS'));
    for (const h of result.findings) {
      const icono = h.severity === 'error' ? '[X]' : h.severity === 'warn' ? '[!]' : '[i]';
      s.push(`${icono} ${h.title}`);
      if (h.detail) s.push(...envolver(h.detail, ANCHO - 3, '   '));
      if (h.recommendation) s.push(...envolver('-> ' + h.recommendation, ANCHO - 3, '   '));
      s.push('');
    }
  }

  s.push(LINEA_FINA);
  s.push(...envolver(pie, ANCHO));

  return s.join('\n');
}

/**
 * Linea de titulo de bloque, siempre con el ancho exacto del reporte.
 *
 * @param {string} titulo
 * @returns {string}
 */
function regla(titulo) {
  const prefijo = `--- ${titulo} `;
  return prefijo + '-'.repeat(Math.max(3, ANCHO - prefijo.length));
}

/**
 * Escribe una ficha `clave: valor` conservando la columna del valor.
 *
 * No se puede usar `envolver()` aqui porque esa funcion parte por espacios y
 * colapsaria el relleno que alinea la columna de valores. El ancho de la clave
 * se fija por el llamante, y un valor que no cabe pasa de linea con sangria
 * para que siga leyendose debajo de si mismo.
 *
 * @param {string} clave
 * @param {string|number} valor
 * @param {number} [anchoClave]
 * @returns {string[]}
 */
function fichaTexto(clave, valor, anchoClave = 20) {
  // +2 y no +1: la clave mas larga del bloque llega justa a `anchoClave`, y sin
  // ese caracter extra el valor acabaria pegado a los dos puntos.
  const etiqueta = `${clave}:`.padEnd(anchoClave + 2);
  const disponible = ANCHO - etiqueta.length;
  const partes = envolver(String(valor ?? ''), Math.max(20, disponible));
  if (!partes.length) return [etiqueta.trimEnd()];
  return [etiqueta + partes[0], ...partes.slice(1).map((p) => ' '.repeat(etiqueta.length) + p)];
}

/**
 * Parte un texto largo en lineas del ancho pedido, con sangria de continuacion.
 *
 * Los reportes de texto se leen en una terminal: una linea de 134 caracteres se
 * parte sola y deja el texto ilisible. Los hallazgos son los textos mas largos
 * (el detalle y la recomendación se escriben enteros), asi que son los que mas
 * necesitan esto.
 *
 * @param {string} texto Texto a partir.
 * @param {number} [ancho] Ancho total de la linea, sangria incluida.
 * @param {string} [sangria] Prefijo de cada linea.
 * @param {number} [continuacion] Sangria extra solo para las lineas de
 *   continuacion. En una ficha `clave: valor` se pasa el ancho de la clave,
 *   para que el valor siga en su columna y no underneath del margen.
 * @returns {string[]}
 */
function envolver(texto, ancho = ANCHO, sangria = '', continuacion = 0) {
  const palabras = String(texto ?? '').split(/\s+/).filter(Boolean);
  if (!palabras.length) return [];

  const sangriaContinuacion = sangria + ' '.repeat(Math.max(0, continuacion));
  const anchoUtil = Math.max(8, ancho - sangria.length);
  const lineas = [];
  let actual = '';

  for (const palabra of palabras) {
    // Un token mas ancho que la linea no se puede partir por palabras: la
    // mascara binaria de un /8 son 104 caracteres sin un solo espacio. Si no
    // se corta a la fuerza, desborda y arruina el ancho de todo el reporte.
    let resto = palabra;
    while (resto.length > anchoUtil) {
      if (actual) {
        lineas.push(sangria + actual);
        actual = '';
      }
      lineas.push(sangria + resto.slice(0, anchoUtil));
      resto = resto.slice(anchoUtil);
    }
    if (!resto) continue;

    if (!actual) {
      actual = resto;
    } else if (actual.length + 1 + resto.length <= anchoUtil) {
      actual += ` ${resto}`;
    } else {
      lineas.push((lineas.length ? sangriaContinuacion : sangria) + actual);
      actual = resto;
    }
  }
  if (actual) lineas.push((lineas.length ? sangriaContinuacion : sangria) + actual);
  return lineas;
}

/**
 * Alinea una tabla de columnas dentro del ancho disponible.
 *
 * Una tabla de ocho columnas (un reparto VLSM, por ejemplo) puede sumar 105
 * caracteres: mas de lo que cabe en una terminal y mas de lo que cabe en el
 * ancho de la cabecera del TXT, que son 72. Antes de recortar cada columna por
 * separado, que es lo que hacia la version previa y producia lineas ilegibles,
 * aqui primero se mide el ancho natural de cada columna y se reparte el ancho
 * disponible proporcionalmente: las columnas anchas se estrechan y las
 * estrechas se conservan.
 *
 * @param {object} seccionDef
 * @returns {string[]} Lineas de la tabla.
 */
function tablaTexto(seccionDef, anchoDisponible = ANCHO) {
  const filas = seccionDef.rows || [];
  if (!filas.length) return ['(sin resultados)'];

  const norm = filas.map((f) => (Array.isArray(f) ? f : [f]).map((c) => (typeof c === 'object' && c !== null ? String(c.valor ?? '') : String(c ?? ''))));
  const nCols = Math.max(seccionDef.columns?.length || 0, ...norm.map((r) => r.length));

  // Ancho natural de cada columna, con un minimo legible.
  const naturales = [];
  for (let i = 0; i < nCols; i++) {
    naturales[i] = Math.max(
      String(seccionDef.columns?.[i] ?? '').length,
      ...norm.map((r) => (r[i] || '').length),
      MIN_COLUMNA
    );
  }

  const separacion = (nCols - 1) * 2;
  const presupuesto = anchoDisponible - separacion;
  const anchos = repartir(naturales, presupuesto);

  const out = [];
  if (seccionDef.columns?.length) {
    out.push(seccionDef.columns.map((c, i) => cortar(String(c), anchos[i]).padEnd(anchos[i])).join('  ').trimEnd());
    out.push(anchos.map((a) => '-'.repeat(a)).join('  '));
  }
  for (const fila of norm) {
    out.push(fila.map((c, i) => cortar(c, anchos[i]).padEnd(anchos[i])).join('  ').trimEnd());
  }
  return out;
}

/**
 * Reparte `presupuesto` caracteres entre columnas, en proporcion a su ancho
 * natural, respetando un minimo por columna.
 *
 * @param {number[]} naturales
 * @param {number} presupuesto
 * @returns {number[]}
 */
function repartir(naturales, presupuesto) {
  const suma = naturales.reduce((a, b) => a + b, 0);
  if (suma <= presupuesto) return naturales.slice();

  const anchos = naturales.map((n) => Math.max(MIN_COLUMNA, Math.floor((n / suma) * presupuesto)));

  // El redondeo puede dejar el total unos caracteres por encima o por debajo.
  // Se ajusta de una en una sobre la columna mas ancha, que es la que mejor
  //Tolera unos caracteres de mas.
  let diferencia = presupuesto - anchos.reduce((a, b) => a + b, 0);
  let i = anchos.indexOf(Math.max(...anchos));
  while (diferencia !== 0) {
    if (diferencia > 0) {
      anchos[i]++;
      diferencia--;
    } else if (anchos[i] > MIN_COLUMNA) {
      anchos[i]--;
      diferencia++;
    }
    i = (i + 1) % anchos.length;
  }
  return anchos;
}

/** Recorta un valor largo con una tilde al final, para marcar el recorte. */
function cortar(texto, ancho) {
  const t = String(texto);
  if (ancho <= 1) return t.slice(0, Math.max(0, ancho));
  return t.length > ancho ? `${t.slice(0, ancho - 1)}~` : t;
}

/** Barra de progreso en caracteres. */
function barraTexto(valor, ancho = 40) {
  const v = Math.max(0, Math.min(100, Number(valor) || 0));
  const llenos = Math.round((v / 100) * ancho);
  return `[${'#'.repeat(llenos)}${'.'.repeat(ancho - llenos)}] ${v}%`;
}

module.exports = { render };