/**
 * time.js — Formateo de fecha y hora en espanol.
 *
 * MODULO DE CONVENcion. En legacy/ habia DOS copias de la misma funcion
 * formateadora (Check IP Abuse/abuse/check-abuse.js y
 * Check IP Abuse/checked/check-ip.js) que ademas mezclaban `toLocaleDateString`
 * con `getHours()`, produciendo fechas incoherentes entre reportes.
 *
 * Aqui hay una sola implementacion. Toda fecha que salga de netlab pasa por aqui.
 *
 * @module core/time
 */

'use strict';

const LOCALE = 'es-ES';

/** Zona horaria usada para los reportes. */
const TZ = process.env.REPORT_TZ || undefined;

/**
 * Marca de tiempo compacta y segura para nombres de archivo.
 * Formato: 2026-09-30T14-28-15-227Z
 * Los dos puntos y los puntos se sustituyen por guiones porque no son validos
 * en Windows.
 *
 * @param {Date} [date] Momento a formatear. Por defecto, ahora.
 * @returns {string}
 */
function stamp(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-');
}

/**
 * Fecha y hora legibles en espanol: 30/09/2026, 14:28:15
 *
 * @param {Date|string|number} [value]
 * @returns {string} Cadena vacia si la fecha no es valida.
 */
function human(value = new Date()) {
  const date = toDate(value);
  if (!date) return '';
  return date.toLocaleString(LOCALE, { timeZone: TZ, hour12: false });
}

/**
 * Solo la fecha: 30/09/2026
 *
 * @param {Date|string|number} [value]
 * @returns {string}
 */
function dateOnly(value = new Date()) {
  const date = toDate(value);
  if (!date) return '';
  return date.toLocaleDateString(LOCALE, { timeZone: TZ });
}

/**
 * Solo la hora: 14:28:15
 *
 * @param {Date|string|number} [value]
 * @returns {string}
 */
function timeOnly(value = new Date()) {
  const date = toDate(value);
  if (!date) return '';
  return date.toLocaleTimeString(LOCALE, { timeZone: TZ, hour12: false });
}

/**
 * Duracion legible a partir de milisegundos.
 * Ejemplos: 240 ms · 1.24 s · 2 m 05 s · 1 h 03 m
 *
 * @param {number} ms Milisegundos.
 * @returns {string}
 */
function duration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return 'n/d';
  if (ms < 1000) return `${Math.round(ms)} ms`;

  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(2)} s`;

  const minutes = Math.floor(seconds / 60);
  const restSeconds = Math.round(seconds % 60);
  if (minutes < 60) return `${minutes} m ${String(restSeconds).padStart(2, '0')} s`;

  const hours = Math.floor(minutes / 60);
  return `${hours} h ${String(minutes % 60).padStart(2, '0')} m`;
}

/**
 * Fecha relativa: "hace 3 h", "hace 2 dias". Para el historial.
 *
 * @param {Date|string|number} value
 * @returns {string}
 */
function relative(value) {
  const date = toDate(value);
  if (!date) return '';

  const diff = Date.now() - date.getTime();
  const future = diff < 0;
  const abs = Math.abs(diff);

  const units = [
    ['year', 365 * 24 * 3600e3],
    ['month', 30 * 24 * 3600e3],
    ['day', 24 * 3600e3],
    ['hour', 3600e3],
    ['minute', 60e3]
  ];

  const rtf = new Intl.RelativeTimeFormat(LOCALE, { numeric: 'auto' });
  for (const [unit, ms] of units) {
    if (abs >= ms) return rtf.format(future ? 1 : -1, unit);
  }
  return 'ahora';
}

/**
 * Convierte cualquier entrada a Date, o null si no es una fecha valida.
 *
 * @param {Date|string|number} value
 * @returns {Date|null}
 */
function toDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === 'number') {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  if (typeof value === 'string') {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

module.exports = { stamp, human, dateOnly, timeOnly, duration, relative, toDate, LOCALE };