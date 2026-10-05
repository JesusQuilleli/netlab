/**
 * logger.js — Telemetría con redacción integrada.
 *
 * MODULO DE SEGURIDAD. Ningun modulo deberia escribir directamente en la
 * consola: todo pasa por aqui. El logger aplica el redactor antes de imprimir,
 * de modo que un secreto no puede llegar a un log aunque el modulo que lo
 * maneja tenga un descuido.
 *
 * Un logger produce lineas para `result.logs` (que van al reporte) y, si el
 * nivel lo permite, tambien las escribe en consola.
 *
 * @module core/logger
 */

'use strict';

const { createRedactor } = require('./redact');
const { timeOnly } = require('./time');

/** Niveles, de mas a menos severo. */
const LEVELS = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100
};

/**
 * Crea un logger ligado a un Result.
 *
 * @param {object} options
 * @param {object} [options.result] Result al que anadir entradas.
 * @param {string} [options.channel] Etiqueta del modulo emisor ('dns', 'smtp'...).
 * @param {string[]} [options.secrets] Secretos literales a enmascarar.
 * @param {string} [options.level='info'] Umbral de salida a consola.
 * @param {boolean} [options.console=true] Escribir tambien en consola.
 * @returns {object} Logger con metodos `debug`/`info`/`warn`/`error`/`child`.
 */
function createLogger(options = {}) {
  const { result, channel = null, secrets = [], level = 'info', console: toConsole = true } = options;

  const redact = createRedactor({ secrets });
  const umbral = LEVELS[level] ?? LEVELS.info;
  const prefix = channel ? `[${channel}]` : '';

  /**
   * Registra una linea.
   *
   * @param {string} levelUno
   * @param {...unknown} parts Mensaje. Se concatena con espacios.
   * @returns {void}
   */
  function log(levelUno, ...parts) {
    const mensaje = redact(parts.map(format).join(' '));

    if (result) {
      result.logs.push({
        ts: new Date().toISOString(),
        level: levelUno,
        channel,
        message: mensaje
      });
    }

    if (toConsole && (LEVELS[levelUno] ?? LEVELS.info) >= umbral) {
      const linea = `${timeOnly()} ${prefix} ${marcador(levelUno)} ${mensaje}`;
      if (levelUno === 'error') console.error(linea);
      else if (levelUno === 'warn') console.warn(linea);
      else console.log(linea);
    }
  }

  return {
    debug: (...p) => log('debug', ...p),
    info: (...p) => log('info', ...p),
    warn: (...p) => log('warn', ...p),
    error: (...p) => log('error', ...p),
    redact,
    /** Sub-logger con otro canal, que escribe en el mismo Result. */
    child: (subChannel, opts = {}) =>
      createLogger({ ...options, channel: subChannel, ...opts })
  };
}

/**
 * Convierte cualquier valor a texto legible para un log.
 * Los objetos se serializan como JSON compacto, sin saltos de linea: un log
 * de una sola linea es mucho mas legible en el PDF.
 *
 * @param {unknown} value
 * @returns {string}
 */
function format(value) {
  if (typeof value === 'string') return value;
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (value instanceof Error) return `${value.name}: ${value.message}`;
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

/** Prefijo visible por nivel. Sin emojis: el PDF usa fuentes sin soporte Unicode. */
function marcador(levelUno) {
  return { debug: '··', info: '..', warn: '!!', error: 'XX' }[levelUno] || '..';
}

/**
 * Logger que solo escribe en consola, para uso puntual (arranque de servidor).
 *
 * @param {string} [channel]
 * @returns {object}
 */
function consoleLogger(channel = null) {
  return createLogger({ channel, console: true, level: 'info' });
}

module.exports = { createLogger, consoleLogger, LEVELS };