/**
 * net/ping.js — Comprobacion de alcance ICMP.
 *
 * MODULO QUE CORRIGE UN DEFECTO REAL. legacy/Check IP Abuse/checked/check-ip.js
 * decidia el resultado del ping parseando texto de la salida:
 *
 *     const { stdout } = await execAsync(cmd);
 *     return stdout.includes('bytes=') || stdout.includes('ttl=');
 *
 * Eso falla por dos motivos: el texto cambia segun el idioma del sistema
 * operativo (un Windows en espanol no escribe exactamente lo mismo que uno en
 * ingles) y no distingue "el host respondio" de "hubo un error de red" que
 * tambien genera salida.
 *
 * La forma correcta es el codigo de salida: ping devuelve 0 si hubo respuesta y
 * distinto de 0 si no. Aqui se usa eso, y el texto queda solo como evidencia.
 *
 * @module core/net/ping
 */

'use strict';

const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);

/**
 * Hace un ping y devuelve si hubo respuesta.
 *
 * @param {string} ip Direccion a comprobar.
 * @param {object} [options]
 * @param {number} [options.timeout=2000] Plazo en milisegundos.
 * @param {number} [options.intentos=1]
 * @returns {Promise<{activo: boolean, rttMs: number|null, error: string|null, salida: string}>}
 */
async function ping(ip, options = {}) {
  const { timeout = 2000, intentos = 1 } = options;

  const esWindows = process.platform === 'win32';
  // En Windows el plazo de -w es en milisegundos; en Linux/macOS, -W es en
  // segundos. Es la unica parte del comando que cambia entre plataformas.
  const args = esWindows
    ? ['-n', String(intentos), '-w', String(timeout), ip]
    : ['-c', String(intentos), '-W', String(Math.ceil(timeout / 1000)), ip];

  try {
    const { stdout, stderr } = await execFileAsync('ping', args, {
      timeout: timeout + 800, // margen para que el proceso termine de cerrarse
      windowsHide: true
    });

    return {
      activo: true,
      rttMs: extraerRTT(stdout),
      error: null,
      salida: limpiar(stdout || stderr)
    };
  } catch (error) {
    // execFile rechaza cuando el codigo de salida no es 0: eso significa que
    // no hubo respuesta, que es un resultado valido y no un fallo del script.
    const salida = limpiar(error.stdout || error.stderr || '');
    return {
      activo: false,
      rttMs: null,
      error: salida || 'Sin respuesta',
      salida
    };
  }
}

/**
 * Extrae el tiempo de ida y vuelta de la salida de ping, si aparece.
 *
 * @param {string} salida
 * @returns {number|null} Milisegundos, o null si no se pudo leer.
 */
function extraerRTT(salida) {
  // Formatos habituales: "tiempo=1ms", "time=1ms", "time<1ms", " Tiempo: 12 ms"
  const patrones = [/\btime[io]?=<?\s*([\d.]+)\s*ms/i, /\btiempo\s*=?\s*([\d.]+)\s*ms/i];
  for (const p of patrones) {
    const m = salida.match(p);
    if (m) return Number(m[1]);
  }
  return null;
}

/**
 * Colapsa la salida a una sola linea: los logs van al PDF y tienen que caber.
 *
 * @param {string} texto
 * @returns {string}
 */
function limpiar(texto) {
  return String(texto)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .join(' | ')
    .slice(0, 500);
}

module.exports = { ping, extraerRTT };