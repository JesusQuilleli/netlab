/**
 * mail/puntuacion.js — Motor de puntuación estilo mail-tester.
 *
 * Cada comprobación vale unos puntos. Un "ok" los suma enteros, un "warn" la
 * mitad (es una pega, no un fallo) y un "error" no suma nada. La nota final se
 * reescala a 10 sobre el máximo posible, de modo que un dominio al que no se le
 * puede comprobar algo (por ejemplo, sin DKIM publicado) no salga penalizado dos
 * veces: solo por lo que de verdad falta.
 *
 * @module core/mail/puntuacion
 */

'use strict';

/** Fracción de los puntos que aporta cada estado. */
const FACTOR = { ok: 1, warn: 0.5, error: 0, 'no-evaluable': 0 };

/** Nota a partir de la cual el resultado se considera bueno o mejorable. */
const UMBRAL_OK = 9;
const UMBRAL_WARN = 6;

const TONOS = { OK: 'ok', WARN: 'warn', BAD: 'bad' };

/**
 * Crea una comprobación.
 *
 * @param {object} datos
 * @param {string} datos.id
 * @param {string} datos.categoria
 * @param {string} datos.titulo
 * @param {number} datos.peso
 * @param {'ok'|'warn'|'error'} datos.estado
 * @param {string} [datos.detalle]
 * @param {string} [datos.recomendacion]
 * @returns {object}
 */
function check(datos) {
  return {
    id: datos.id,
    categoria: datos.categoria,
    titulo: datos.titulo,
    peso: Number(datos.peso) || 0,
    estado: FACTOR[datos.estado] === undefined ? 'warn' : datos.estado,
    detalle: datos.detalle || null,
    recomendacion: datos.recomendacion || null
  };
}

/**
 * Evalúa una lista de comprobaciones.
 *
 * @param {object[]} checks
 * @returns {{checks: object[], max: number, obtenidos: number, nota: number, tone: string, fallos: object[]}}
 */
function evaluar(checks) {
  const lista = (checks || []).filter(Boolean);
  const evaluables = lista.filter((c) => c.estado !== 'no-evaluable');
  const max = evaluables.reduce((s, c) => s + c.peso, 0);
  const obtenidos = evaluables.reduce((s, c) => s + c.peso * FACTOR[c.estado], 0);
  const nota = max > 0 ? redondear((obtenidos / max) * 10, 1) : 0;

  return {
    checks: lista,
    max: redondear(max, 2),
    obtenidos: redondear(obtenidos, 2),
    nota,
    tone: nota >= UMBRAL_OK ? TONOS.OK : nota >= UMBRAL_WARN ? TONOS.WARN : TONOS.BAD,
    fallos: lista.filter((c) => c.estado !== 'ok' && c.estado !== 'no-evaluable')
  };
}

/** Redondea a `decimales` cifras. */
function redondear(n, decimales) {
  const factor = 10 ** decimales;
  return Math.round(n * factor) / factor;
}

/**
 * Formatea la nota para la cabecera: `8.5 / 10`.
 *
 * @param {number} nota
 * @returns {string}
 */
function formatear(nota) {
  return `${Number(nota).toFixed(1)} / 10`;
}

module.exports = { evaluar, check, formatear, redondear, FACTOR, UMBRAL_OK, UMBRAL_WARN, TONOS };
