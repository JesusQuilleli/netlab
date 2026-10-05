/**
 * result.js — El contrato comun de todas las herramientas.
 *
 * MODULO CENTRAL DEL PROYECTO. Este esquema es lo que permite centralizar las
 * herramientas en una sola web sin reescribir nada dos veces.
 *
 * La idea: cada herramienta es una funcion pura que devuelve un `Result` en
 * JSON puro. De ahi se generan los cinco formatos de salida (txt, md, html,
 * json, pdf) con los mismos renderizadores. La CLI y la web llaman a la misma
 * funcion, asi que no puede haber divergencia entre lo que ves en pantalla y
 * lo que descargas.
 *
 * Formato del objeto:
 *
 * {
 *   schema:     version del esquema (para migraciones futuras)
 *   tool:       'dns-checker' | 'ip-audit' | 'ip-abuse' | 'smtp-validator' | 'subnet-analyzer'
 *   status:     'pass' | 'warn' | 'fail' | 'error'   (ver ESTADOS)
 *   headline:   titular del veredicto, o null si la herramienta no lo aporta
 *   target:     que se analizo (dominio, IP, mascara...)
 *   params:     entrada completa, ya saneada
 *   summary:    [{ label, value, tone }]     tarjetas de la cabecera
 *   sections:   [{ id, title, kind, ... }]   cuerpo del reporte
 *   findings:   [{ severity, title, detail, recommendation }]
 *   logs:       [{ ts, level, channel, message }]
 *   startedAt:  ISO
 *   durationMs: numero
 * }
 *
 * @module core/result
 */

'use strict';

const { stamp } = require('./time');

/**
 * Version del esquema. Subirla obliga a revisar los renderizadores.
 *
 * 2 - Se anade `headline`. Es opcional, asi que un Result en v1 sigue
 *     renderizando bien: los renderizadores caen al titulo generico cuando no
 *     hay titular. Esa es justamente la razon de que sea opcional y no un
 *     campo obligatorio con texto por defecto.
 */
const SCHEMA_VERSION = 2;

/**
 * Estados posibles de una ejecucion.
 *
 * pass  -> todo correcto
 * warn  -> correcto con observaciones que conviene revisar
 * fail  -> se detectaron problemas reales
 * error -> la ejecucion no pudo completarse
 */
const ESTADOS = {
  PASS: 'pass',
  WARN: 'warn',
  FAIL: 'fail',
  ERROR: 'error'
};

/** Severidad de un hallazgo. */
const SEVERIDADES = {
  INFO: 'info',
  WARN: 'warn',
  ERROR: 'error'
};

/** Formatos de seccion que saben pintar los renderizadores. */
const SECCION_KINDS = {
  TABLA: 'table',
  PARES: 'kv',
  CODIGO: 'code',
  TEXTO: 'text',
  LISTA: 'list',
  BARRA: 'meter'
};

/**
 * Crea un Result vacio, con todos los campos del esquema presentes.
 *
 * Se usa como punto de partida dentro de cada herramienta para que nunca
 * falte un campo aunque la ejecucion falle a mitad.
 *
 * @param {object} init
 * @param {string} init.tool Identificador de la herramienta.
 * @param {string} [init.target]
 * @param {object} [init.params]
 * @returns {object} Result mutable.
 */
function createResult(init) {
  return {
    schema: SCHEMA_VERSION,
    tool: init.tool,
    toolTitle: init.toolTitle || init.tool,
    status: ESTADOS.PASS,
    headline: init.headline || null,
    target: init.target || '',
    params: init.params || {},
    summary: [],
    sections: [],
    findings: [],
    logs: [],
    startedAt: new Date().toISOString(),
    durationMs: 0,
    error: null
  };
}

/**
 * Fija el titular del veredicto.
 *
 * QUE ES ESTO Y POR QUE EXISTE. La cabecera de todos los informes pone hoy
 * "NombreDeLaHerramienta · Correcto", que describe la herramienta pero no dice
 * nada del resultado. Para una herramienta que responde a "esta web esta o no
 * esta", eso esconde justo lo que el usuario vino a ver: no le interesa que
 * ejecuto el comprobador, le interesa si la web responde.
 *
 * El titular deja hueco el sitio del sujeto, que es donde la web mete el
 * objetivo, y pone el veredicto en su lugar:
 *
 *     example.com esta operativa
 *
 * Es opcional a proposito. Una herramienta que no lo rellene sigue mostrando
 * su titulo generico, y por eso anadir este campo no obliga a tocar las otras
 * siete herramientas ni a migrar nada guardado.
 *
 * @param {object} result Result en construccion.
 * @param {string} texto Frase corta. Sin punto final.
 * @returns {object} El mismo Result.
 */
function setHeadline(result, texto) {
  const limpio = String(texto ?? '').trim().replace(/\.+$/, '');
  result.headline = limpio || null;
  return result;
}

/**
 * Anade una seccion. Devuelve el mismo Result para poder encadenar.
 *
 * @param {object} result Result en construccion.
 * @param {object} section { id, title, kind, description, columns, rows, items, value }
 * @returns {object} El mismo Result.
 */
function addSection(result, section) {
  if (!section || !section.kind) throw new Error('La seccion necesita un "kind"');
  result.sections.push({
    id: section.id || null,
    title: section.title || '',
    description: section.description || null,
    kind: section.kind,
    columns: section.columns || null,
    rows: section.rows || null,
    // Pesos relativos de las columnas de una tabla. El PDF los usa para
    // repartir el ancho; el resto de formatos los ignoran. Es opcional, pero
    // sin el una tabla de ocho columnas se estrecha por igual y las celdas
    // largas acaban en tres lineas de diez caracteres.
    anchoColumnas: section.anchoColumnas || null,
    items: section.items || null,
    value: section.value ?? null,
    tone: section.tone || null
  });
  return result;
}

/**
 * Anade una tarjeta a la cabecera del reporte.
 *
 * @param {object} result Result en construccion.
 * @param {string} label Etiqueta corta.
 * @param {string|number} value Valor.
 * @param {string} [tone] 'ok' | 'warn' | 'bad' | 'neutral'
 * @returns {object} El mismo Result.
 */
function addSummary(result, label, value, tone = 'neutral') {
  result.summary.push({ label, value: String(value), tone });
  return result;
}

/**
 * Anade un hallazgo. Los hallazgos son la parte accionable del reporte:
 * no describen el estado, dicen que hacer.
 *
 * @param {object} result Result en construccion.
 * @param {object} finding { severity, title, detail, recommendation }
 * @returns {object} El mismo Result.
 */
function addFinding(result, finding) {
  result.findings.push({
    severity: finding.severity || SEVERIDADES.INFO,
    title: finding.title || '',
    detail: finding.detail || null,
    recommendation: finding.recommendation || null
  });
  return result;
}

/**
 * Anade una entrada de telemetria.
 *
 * @param {object} result Result en construccion.
 * @param {object} entry { level, channel, message, ts }
 * @returns {object} El mismo Result.
 */
function addLog(result, entry) {
  result.logs.push({
    ts: entry.ts || new Date().toISOString(),
    level: entry.level || 'info',
    channel: entry.channel || null,
    message: entry.message || ''
  });
  return result;
}

/**
 * Fija el estado global a partir de los hallazgos, si no se fijó a mano.
 *
 * Regla: si hay algun hallazgo de severidad `error`, el estado es `fail`. Si
 * solo hay `warn`, es `warn`. Si no hay hallazgos, `pass`.
 *
 * @param {object} result Result en construccion.
 * @returns {object} El mismo Result.
 */
function deriveStatus(result) {
  if (result.status === ESTADOS.ERROR) return result;
  if (result.findings.some((f) => f.severity === SEVERIDADES.ERROR)) {
    result.status = ESTADOS.FAIL;
  } else if (result.findings.some((f) => f.severity === SEVERIDADES.WARN)) {
    result.status = ESTADOS.WARN;
  }
  return result;
}

/**
 * Marca la ejecucion como fallida y compacta el Result a un error legible.
 *
 * @param {object} result Result en construccion.
 * @param {Error} error Excepcion.
 * @returns {object} El mismo Result, listo para renderizar.
 */
function failWith(result, error) {
  result.status = ESTADOS.ERROR;
  result.error = {
    code: error?.code || 'INTERNO',
    message: error?.message || String(error),
    remediation: error?.remediation || null
  };
  return result;
}

/** Traduce el estado a un emoji y a un texto en espanol. */
const STATUS_META = {
  pass: { label: 'CORRECTO', emoji: 'OK', tone: 'ok' },
  warn: { label: 'CON OBSERVACIONES', emoji: '!', tone: 'warn' },
  fail: { label: 'CON FALLOS', emoji: 'X', tone: 'bad' },
  error: { label: 'ERROR', emoji: 'X', tone: 'bad' }
};

/**
 * Cierra el Result: calcula la duracion y fija el estado.
 *
 * @param {object} result Result en construccion.
 * @param {Date} startedAt Momento en que empezo la herramienta.
 * @returns {object} Result completo.
 */
function finalize(result, startedAt = new Date()) {
  result.durationMs = Date.now() - startedAt.getTime();
  deriveStatus(result);
  return result;
}

module.exports = {
  SCHEMA_VERSION,
  ESTADOS,
  SEVERIDADES,
  SECCION_KINDS,
  STATUS_META,
  createResult,
  setHeadline,
  addSection,
  addSummary,
  addFinding,
  addLog,
  deriveStatus,
  failWith,
  finalize,
  stamp
};