/**
 * password.js — Hash y verificación de contraseñas con scrypt.
 *
 * MODULO DE SEGURIDAD. Sin dependencias circulares.
 *
 * @module server/password
 */

'use strict';

const crypto = require('node:crypto');

/** Coste de scrypt. Alto a proposito: es una contrasena, no una cookie. */
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

/**
 * Deriva un hash de contrasena con scrypt y sal aleatoria.
 *
 * El formato lleva los parametros dentro, para que subir `N` mas adelante no
 * invalide los hashes viejos: al verificar se leen de ahi, no de las constantes
 * de este archivo.
 *
 * @param {string} password
 * @returns {string} `scrypt$N$r$p$saltB64$hashB64`
 */
function hashPassword(password) {
  if (!password) throw new Error('La contraseña no puede estar vacía.');
  const sal = crypto.randomBytes(16);
  const derivada = crypto.scryptSync(password, sal, SCRYPT.keylen, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    maxmem: 64 * 1024 * 1024
  });
  return [
    'scrypt',
    SCRYPT.N,
    SCRYPT.r,
    SCRYPT.p,
    sal.toString('base64'),
    derivada.toString('base64')
  ].join('$');
}

/**
 * Compara dos cadenas en tiempo constante.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function igual(a, b) {
  const bufA = Buffer.from(String(a), 'utf8');
  const bufB = Buffer.from(String(b), 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Comprueba una contrasena contra un hash, o contra texto plano.
 *
 * El texto plano se acepta SOLO si `AUTH_PASSWORD_HASH` esta vacio, y solo
 * porque esta en `.env.example` como forma de probar. Si hay hash, el texto
 * plano no vale: asi nadie puede colarse por la puerta de atrás de la
 * prueba y quedarse asi.
 *
 * @param {string} password
 * @param {string} almacenado Hash `scrypt$...` o, en pruebas, texto plano.
 * @returns {boolean}
 */
function verificarPassword(password, almacenado) {
  if (!password || !almacenado) return false;

  if (!almacenado.startsWith('scrypt$')) {
    return igual(password, almacenado);
  }

  const partes = almacenado.split('$');
  if (partes.length !== 6) return false;

  const [, nStr, rStr, pStr, salB64, hashB64] = partes;
  const N = Number(nStr);
  const r = Number(rStr);
  const p = Number(pStr);
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  if (N < 2 || r < 1 || p < 1) return false;
  // scrypt con N grande reserva mas de 32 MB por defecto: sin esto, un hash con
  // N enorme en la config haria fallar el proceso al arrancar.
  if (N > 1024 * 1024 || r > 32 || p > 16) return false;

  let derivada;
  try {
    derivada = crypto.scryptSync(password, Buffer.from(salB64, 'base64'), Buffer.from(hashB64, 'base64').length, {
      N,
      r,
      p,
      maxmem: 256 * 1024 * 1024
    });
  } catch {
    return false;
  }

  return crypto.timingSafeEqual(derivada, Buffer.from(hashB64, 'base64'));
}

module.exports = { hashPassword, verificarPassword, igual };