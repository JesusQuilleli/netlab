/**
 * hash-password.js — Genera el hash de la contraseña de la web.
 *
 * Uso:  npm run hash-password -- "mi-contrasena"
 *
 * La salida se pega en `AUTH_PASSWORD_HASH` dentro del `.env`. La contraseña en
 * claro no se guarda en ningun sitio: de este proceso sale solo el hash.
 *
 * El modulo de autenticacion decide como comprobar la contraseña, asi que este
 * script no reimplementa nada: llama a la misma funcion que el servidor usa al
 * entrar. Si aqui se usara otro algoritmo, un hash generado por este script
 * podria no servir para entrar, que es la peor forma de fallar.
 *
 * @module cli/hash-password
 */

'use strict';

const { hashPassword } = require('../server/auth');

/**
 * Genera un hash.
 *
 * @param {string} password
 * @returns {string}
 */
function generar(password) {
  const limpia = String(password ?? '');
  if (!limpia) {
    console.error('\n  Falta la contraseña.\n  Uso: npm run hash-password -- "mi-contrasena"\n');
    process.exit(1);
  }
  if (limpia.length < 8) {
    console.warn('\n  AVISO: menos de 8 caracteres. Es corta, pero si es la tuya, adelante.\n');
  }
  return hashPassword(limpia);
}

if (require.main === module) {
  const password = process.argv.slice(2).join(' ');
  console.log('\n  Pega esta línea en tu .env:\n');
  console.log(`  AUTH_PASSWORD_HASH=${generar(password)}\n`);
}

module.exports = { generar };
