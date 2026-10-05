/**
 * formats/index.js — Despachador unico de formatos.
 *
 * MODULO DE ENTRADA DE LA CAPA DE SALIDA. La CLI, la API y la web NO llaman a
 * txt/md/html/pdf directamente: llaman a `render(result, formato)`. Asi hay un
 * solo sitio donde se decide que formatos existen y como se llaman, y anadir
 * uno nuevo (por ejemplo CSV) no obliga a tocar la CLI ni la API.
 *
 * El nombre del archivo se deriva aqui tambien, para que los cuatro usos
 * descarguen siempre con el mismo criterio.
 *
 * @module formats
 */

'use strict';

const path = require('node:path');
const fs = require('node:fs/promises');

const txt = require('./txt');
const md = require('./md');
const html = require('./html');
const pdf = require('./pdf');
const json = require('./json');
const { buildReportName, reportPath } = require('../core/filenames');

/** Formatos soportados y su funcion de renderizado. */
const RENDERIZADORES = {
  txt: { render: txt.render, mime: 'text/plain; charset=utf-8', ext: 'txt' },
  md: { render: md.render, mime: 'text/markdown; charset=utf-8', ext: 'md' },
  html: { render: html.render, mime: 'text/html; charset=utf-8', ext: 'html' },
  json: { render: json.render, mime: 'application/json; charset=utf-8', ext: 'json' },
  pdf: { render: pdf.render, mime: 'application/pdf', ext: 'pdf' }
};

/**
 * Renderiza un Result en el formato pedido.
 *
 * @param {object} result
 * @param {string} formato 'txt'|'md'|'html'|'json'|'pdf'
 * @param {object} [options]
 * @returns {Promise<Buffer|string>} PDF devuelve Buffer; el resto, string.
 * @throws {Error} Si el formato no existe.
 */
async function render(result, formato = 'json', options = {}) {
  const r = RENDERIZADORES[String(formato).toLowerCase()];
  if (!r) {
    throw new Error(`Formato desconocido: "${formato}". Disponibles: ${Object.keys(RENDERIZADORES).join(', ')}`);
  }
  const salida = await r.render(result, options);
  return Buffer.isBuffer(salida) ? salida : Buffer.from(String(salida), 'utf8');
}

/**
 * Devuelve el tipo MIME de un formato.
 *
 * @param {string} formato
 * @returns {string}
 */
function mime(formato) {
  const r = RENDERIZADORES[String(formato).toLowerCase()];
  return r ? r.mime : 'application/octet-stream';
}

/** Lista de formatos soportados. */
function soportados() {
  return Object.entries(RENDERIZADORES).map(([nombre, r]) => ({ nombre, mime: r.mime }));
}

/**
 * Renderiza y guarda el reporte en disco, en la carpeta de su herramienta.
 *
 * El nombre lo construye `core/filenames`, que ya resuelve el defecto que
 * tenian los scripts de legacy: dos ejecuciones en el mismo segundo
 * sobrescribian el informe anterior porque el nombre solo llevaba fecha y hora
 * hasta el segundo. Aqui se anade ademas un hash corto del contenido, asi que
 * el nombre es unico aunque el contenido sea identico.
 *
 * @param {object} result
 * @param {string} formato
 * @param {object} [options]
 * @param {string} [options.dir] Carpeta base. Por defecto, data/.
 * @returns {Promise<{file: string, filename: string, bytes: number, mime: string}>}
 */
async function guardar(result, formato, options = {}) {
  const baseDir = options.dir || path.join(process.cwd(), 'data');
  const ext = RENDERIZADORES[formato].ext;

  const contenido = await render(result, formato, options);
  const filename = buildReportName({ tool: result.tool, target: result.target, ext, content: result });
  const destino = reportPath({ baseDir, tool: result.tool, fileName: filename });

  await fs.mkdir(path.dirname(destino), { recursive: true });
  await fs.writeFile(destino, contenido);

  return { file: destino, filename, bytes: contenido.length, mime: mime(formato) };
}

module.exports = { render, mime, soportados, guardar, RENDERIZADORES };