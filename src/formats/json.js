/**
 * json.js — Serializacion canonica del Result.
 *
 * MODULO DE SALIDA. Es el formato que alimenta al historial en SQLite y al
 * reenvio de la API, asi que tiene una exigencia que los otros no: ser
 * REPRODUCIBLE. Mismo Result debe dar exactamente los mismos bytes, porque si
 * no, los hashes que se usan para deduplicar entradas del historial cambian
 * sin motivo y las comparaciones "este informe no cambio" dejan de funcionar.
 *
 * De ahi las dos diferencias con un JSON.stringify normal:
 *   - claves ordenadas en profundidad
 *   - `undefined` eliminado en lugar de aparecer como null
 *
 * @module formats/json
 */

'use strict';

/**
 * Serializa un Result a JSON canonico.
 *
 * @param {object} result
 * @param {object} [options]
 * @param {boolean} [options.pretty=true] Sangrar para lectura humana.
 * @param {number} [options.spaces=2]
 * @returns {string}
 */
function render(result, options = {}) {
  const { pretty = true, spaces = 2 } = options;
  return JSON.stringify(normalizar(result), null, pretty ? spaces : 0);
}

/**
 * Copia el objeto ordenando claves y eliminando `undefined`.
 *
 * @param {*} valor
 * @returns {*}
 */
function normalizar(valor) {
  if (Array.isArray(valor)) return valor.map(normalizar);

  if (valor && typeof valor === 'object' && !(valor instanceof Date)) {
    // Object.keys no incluye los simbolos, y en este proyecto no se usan.
    const salida = {};
    for (const clave of Object.keys(valor).sort()) {
      if (valor[clave] === undefined) continue;
      salida[clave] = normalizar(valor[clave]);
    }
    return salida;
  }

  return valor === undefined ? null : valor;
}

/**
 * Campos que cambian en cada ejecucion aunque el resultado sea el mismo.
 *
 * `startedAt` y `durationMs` son el reloj, no el resultado. Si entraran en la
 * huella, dos comprobaciones identicas del mismo dominio darian siempre
 * huellas distintas y la deduplicacion del historial no encontraria nunca nada
 * que deduplicar: se llenaria de copias identicas.
 */
const CAMPOS_VOLATILES = ['startedAt', 'durationMs'];

/** Campos de reloj dentro de cada entrada de `result.logs`. */
const CAMPOS_VOLATILES_LOG = ['ts'];

/**
 * Copia el Result quitando el reloj, en todos los sitios donde aparece.
 *
 * El reloj no esta solo arriba. Cada entrada de `logs` lleva su propio `ts`, y
 * quitar unicamente `startedAt` y `durationMs` dejaba la marca de tiempo metida
 * en medio del historial: dos comprobaciones identicas separadas por un segundo
 * dandose en el mismo milisegundo (casi siempre) y distinta cuando no (de vez
 * en cuando). Dos comprobaciones iguales de un dominio registros a distinta
 * hora nunca se deduplicarian, que es justo lo que esta funcion existe para
 * evitar.
 *
 * @param {object} result
 * @returns {object} Copia sin los campos de reloj.
 */
function sinReloj(result) {
  const copia = {};

  for (const [clave, valor] of Object.entries(result)) {
    if (CAMPOS_VOLATILES.includes(clave)) continue;

    if (clave === 'logs' && Array.isArray(valor)) {
      copia.logs = valor.map((entrada) => {
        if (!entrada || typeof entrada !== 'object') return entrada;
        const entradaSinReloj = {};
        for (const [k, v] of Object.entries(entrada)) {
          if (CAMPOS_VOLATILES_LOG.includes(k)) continue;
          entradaSinReloj[k] = v;
        }
        return entradaSinReloj;
      });
      continue;
    }

    copia[clave] = valor;
  }

  return copia;
}

/**
 * Calcula un hash estable de un Result, para deduplicar el historial.
 *
 * Misma entrada, misma huella. Para eso se excluyen los campos de reloj, pero
 * no se toca nada mas: si cambian los hallazgos, las secciones o el objetivo,
 * la huella cambia, que es justo lo que se quiere detectar.
 *
 * @param {object} result
 * @returns {string} SHA-256 en hexadecimal.
 */
function huella(result) {
  return require('node:crypto')
    .createHash('sha256')
    .update(render(sinReloj(result), { pretty: false }))
    .digest('hex');
}

module.exports = { render, normalizar, huella, CAMPOS_VOLATILES, CAMPOS_VOLATILES_LOG };