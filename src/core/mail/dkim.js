/**
 * mail/dkim.js — Lectura y valoración de un registro DKIM.
 *
 * DKIM se publica en `<selector>._domainkey.<dominio>`. El selector lo elige
 * quien firma y es arbitrario, así que no hay forma de adivinarlo: se prueban
 * los habituales y se admite que el usuario escriba los suyos.
 *
 * La clave pública viaja en la etiqueta `p=` en base64. Si está VACÍA, la clave
 * está REVOCADA: cualquier firma con ese selector se considera inválida. Y el
 * tamaño importa: una clave RSA de 512 o 1024 bits se puede factorizar y ya no
 * se considera segura, así que se descodifica el DER SPKI con `node:crypto` para
 * leer el tamaño real en vez de fiarse de que `k=rsa` baste.
 *
 * @module core/mail/dkim
 */

'use strict';

const crypto = require('node:crypto');
const { conPrefijo, etiquetas } = require('./comun');

/** Selectores que se prueban cuando el usuario no escribe ninguno. */
const SELECTORES_COMUNES = [
  'default',
  'google',
  'selector1',
  'selector2',
  's1',
  's2',
  'k1',
  'k2',
  'dkim',
  'mail',
  'smtp',
  'mandrill',
  'mailchimp',
  'sendgrid',
  'amazonses',
  'zoho',
  'protonmail',
  'pm',
  'fm1',
  'fm2',
  'fm3',
  'news',
  'mailjet',
  'sparkpost',
  'postmark',
  'kl',
  'cm',
  'mte1',
  'mte2',
  'key1',
  'key2'
];

/** Tamaño mínimo de clave RSA que se considera aceptable hoy. */
const BITS_MINIMOS = 1024;
const BITS_RECOMENDADOS = 2048;

/**
 * Interpreta los TXT de un nombre `<selector>._domainkey`.
 *
 * @param {string[]} textos
 * @param {object} [opciones]
 * @param {string} [opciones.selector]
 * @param {string} [opciones.dominio]
 * @returns {object}
 */
function parsear(textos, opciones = {}) {
  const { selector = null, dominio = null } = opciones;
  const encontrados = conPrefijo(textos, 'v=DKIM1').length
    ? conPrefijo(textos, 'v=DKIM1')
    : // Hay quien omite `v=DKIM1`. Se acepta cualquier TXT del nombre que
      // traiga una `p=`, que es la parte imprescindible.
      (textos || []).filter((t) => /(?:^|;|\s)p=/i.test(t));

  const base = {
    selector,
    dominio,
    encontrado: false,
    valor: null,
    valido: false,
    revocada: false,
    clavePresente: false,
    tipoClave: null,
    bits: null,
    flags: [],
    prueba: false,
    estricto: false,
    errores: [],
    avisos: []
  };

  if (!encontrados.length) return base;

  const valor = encontrados[0];
  const tag = etiquetas(valor);
  const errores = [];
  const avisos = [];

  const version = tag.v ? tag.v.toUpperCase() : null;
  if (version && version !== 'DKIM1') {
    errores.push(`La versión "v=${tag.v}" no es DKIM1.`);
  }

  const tipoClave = (tag.k || 'rsa').toLowerCase();
  if (!['rsa', 'ed25519'].includes(tipoClave)) {
    avisos.push(`El tipo de clave "k=${tag.k}" no es habitual (se espera rsa o ed25519).`);
  }

  const p = (tag.p || '').replace(/\s+/g, '');
  const clavePresente = Boolean(p);
  if (!clavePresente) {
    return {
      ...base,
      encontrado: true,
      valor,
      revocada: true,
      clavePresente: false,
      tipoClave,
      errores: ['La clave "p=" está VACÍA: el selector está revocado y toda firma con él se considera inválida.'],
      avisos
    };
  }

  let bits = null;
  if (tipoClave === 'ed25519') {
    // La clave ed25519 son 32 bytes crudos; no es DER y `createPublicKey` no la
    // acepta con formato spki. Se informa del tamaño fijo.
    bits = /^[A-Za-z0-9+/=]+$/.test(p) ? 256 : null;
  } else {
    try {
      const clave = crypto.createPublicKey({ key: Buffer.from(p, 'base64'), format: 'der', type: 'spki' });
      bits = clave.asymmetricKeyDetails?.modulusLength ?? null;
    } catch {
      errores.push('La clave "p=" no se puede descodificar como una clave pública válida (¿está truncada al partir el TXT?).');
    }
  }

  const flags = String(tag.t || '').split(':').map((f) => f.trim().toLowerCase()).filter(Boolean);
  if (flags.includes('y')) avisos.push('La bandera "t=y" marca el selector en pruebas: los receptores no deben tratar la firma como definitiva.');
  if (flags.includes('s')) avisos.push('La bandera "t=s" prohíbe usar el selector en subdominios del dominio del "d=".');

  if (bits !== null && tipoClave === 'rsa') {
    if (bits < BITS_MINIMOS) {
      errores.push(`La clave RSA es de ${bits} bits, por debajo del mínimo aceptable (${BITS_MINIMOS}). Es factorizable y no protege nada.`);
    } else if (bits < BITS_RECOMENDADOS) {
      avisos.push(`La clave RSA es de ${bits} bits. Funciona, pero se recomienda girarla a ${BITS_RECOMENDADOS}.`);
    }
  }

  return {
    selector,
    dominio,
    encontrado: true,
    valor,
    valido: errores.length === 0,
    revocada: false,
    clavePresente,
    tipoClave,
    bits,
    flags,
    prueba: flags.includes('y'),
    estricto: flags.includes('s'),
    hash: tag.h || null,
    servicio: tag.s || null,
    errores,
    avisos
  };
}

module.exports = { parsear, SELECTORES_COMUNES, BITS_MINIMOS, BITS_RECOMENDADOS };
