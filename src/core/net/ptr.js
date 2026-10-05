/**
 * net/ptr.js — Resolucion inversa de direcciones IP.
 *
 * MODULO PEQUEÑO PERO NECESARIO. legacy/Check IP Abuse/checked/check-ip.js:77-84
 * resolvia el PTR dentro de su propio archivo, y el parser BIND de
 * legacy/Check DNS/dns_validator_js.js ignoraba los registros PTR que
 * aparecian en el archivo de zona (soloextraia TXT y MX, lineas 84 y 108).
 *
 * Aqui vive la consulta por defecto de PTR, reutilizable por varias
 * herramientas.
 *
 * @module core/net/ptr
 */

'use strict';

const dns = require('node:dns').promises;
const { wrap } = require('../errors');

/**
 * Resuelve el nombre PTR de una direccion IP.
 *
 * @param {string} ip
 * @returns {Promise<{nombres: string[], configurado: boolean, error: string|null}>}
 */
async function resolver(ip) {
  try {
    const nombres = await dns.reverse(ip);
    return {
      nombres: nombres.filter(Boolean),
      configurado: nombres.length > 0,
      error: null
    };
  } catch (error) {
    return {
      nombres: [],
      configurado: false,
      error: wrap(error).message
    };
  }
}

/**
 * Devuelve una interpretacion en lenguaje llano del resultado PTR.
 *
 * @param {{nombres: string[], configurado: boolean, error: string|null}} resultado
 * @returns {{estado: string, descripcion: string, severidad: string, recomendacion: string|null}}
 */
function interpretar(resultado) {
  if (resultado.configurado) {
    return {
      estado: 'Configurado',
      descripcion: `Resuelve a ${resultado.nombres.join(', ')}.`,
      severidad: 'info',
      recomendacion:
        'Comprueba que el nombre sea el que esperas: un PTR inesperado en una IP de correo es una señal clásica de suplantación.'
    };
  }

  return {
    estado: 'Sin PTR',
    descripcion: resultado.error
      ? `No se pudo resolver: ${resultado.error}`
      : 'La direccion no tiene registro PTR publicado.',
    severidad: 'warn',
    recomendacion:
      'Sin PTR, algunos sistemas rechazan o clasifican como spam tu correo saliente. Publica uno en la zona inversa si esta IP envia correo.'
  };
}

module.exports = { resolver, interpretar };