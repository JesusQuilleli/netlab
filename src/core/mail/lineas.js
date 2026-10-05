/**
 * mail/lineas.js — Cliente de protocolo por lineas para SMTP e IMAP.
 *
 * MODULO NUEVO. SMTP e IMAP son los dos protocolos de correo que se prueban
 * leyendo una respuesta por cada comando, y los dos tienen el mismo problema:
 * una conexion sin plazo se queda colgada para siempre si el servidor acepta el
 * socket y luego no contesta. legacy/Validate config SMTP/validate-smtp.js:36
 * abria el socket sin ningun temporizador, asi que un servidor a medio
 * configurar dejaba el script colgado sin decir nada.
 *
 * Por eso vive aqui y no duplicado en cada modulo: una sola implementacion de
 * "leer una respuesta completa" y "subir a TLS en medio de la conversacion", que
 * es la parte que hay que acertar.
 *
 * Que aporta:
 *   - `conectarTcp` / `subirStartTls`: el socket, con plazo.
 *   - `crearCliente`: `leer()` y `enviar()` sobre lineas, con plazo por comando.
 *   - Toda la salida pasa por un redactor antes de devolverla, para que una
 *     credencial que el servidor llegue a devolver no llegue al informe.
 *
 * @module core/mail/lineas
 */

'use strict';

const net = require('node:net');
const tls = require('node:tls');
const { NetlabError, CODES, wrap } = require('../errors');

/** Respuesta multi-linea: "250-continua" y la que cierra es "250 fin". */
const RE_MULTILINEA = /^(\d{3})[- ]/;

/** Ultima linea de un bloque: su codigo cierra la respuesta. */
function cierraBloque(linea) {
  return RE_MULTILINEA.test(linea) && linea[3] === ' ';
}

/** Ultima linea no vacia de un buffer, o null si aun no hay nada. */
function ultimaLinea(buffer) {
  const lineas = buffer.split(/\r?\n/);
  for (let i = lineas.length - 1; i >= 0; i--) {
    if (lineas[i].trim()) return lineas[i];
  }
  return null;
}

/**
 * Indica si el buffer ya contiene una respuesta completa.
 *
 * SMTP cierra con una linea de la forma "250 texto"; mientras solo haya
 * "250-texto" hay mas por venir. Los datos iniciales del servidor (banner SMTP,
 * saludo IMAP) llegan sin codigo, asi que se aceptan si hay al menos una linea
 * terminada en CRLF.
 *
 * @param {string} buffer
 * @returns {boolean}
 */
function respuestaCompleta(buffer) {
  // Sin salto de linea final, la ultima linea todavia esta en camino. Sin esta
  // comprobacion, un "250 hola" partido entre dos trozos de TCP se tomaba por
  // respuesta entera —el cuarto caracter es un espacio— y el resto de la linea
  // se comia la lectura siguiente, que ya venia con el principio de la respuesta
  // que falta.
  if (!/\n$/.test(buffer)) return false;
  const linea = ultimaLinea(buffer);
  if (!linea) return false;
  if (RE_MULTILINEA.test(linea)) return cierraBloque(linea);
  return true;
}

/**
 * Convierte un bloque de respuesta en algo utilizable.
 *
 * @param {string} bruto
 * @param {(texto: string) => string} redactar
 * @returns {{codigo: number|null, lineas: string[], texto: string, multilinea: boolean}}
 */
function interpretar(bruto, redactar) {
  const lineas = bruto
    .split(/\r?\n/)
    .map((l) => l.replace(/\r$/, ''))
    .filter((l) => l.trim() !== '');
  const ultima = lineas[lineas.length - 1] || '';
  const coincidencia = ultima.match(/^(\d{3})/);
  return {
    codigo: coincidencia ? Number(coincidencia[1]) : null,
    lineas: lineas.map((l) => redactar(l)),
    texto: redactar(lineas.join('\n')),
    multilinea: lineas.length > 1
  };
}

/**
 * Abre un socket TCP con plazo.
 *
 * @param {object} opciones
 * @param {string} opciones.host
 * @param {number} opciones.puerto
 * @param {number} [opciones.timeout=10000]
 * @returns {Promise<import('node:net').Socket>}
 */
function conectarTcp({ host, puerto, timeout = 10000 }) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let terminado = false;

    const acabar = (fn) => {
      if (terminado) return;
      terminado = true;
      fn();
    };

    socket.setTimeout(timeout);
    socket.once('connect', () =>
      acabar(() => {
        socket.setTimeout(0);
        resolve(socket);
      })
    );
    socket.once('timeout', () =>
      acabar(() => {
        socket.destroy();
        reject(
          new NetlabError(CODES.TIMEOUT, `No se pudo abrir la conexión con ${host}:${puerto}.`, {
            remediation: 'El puerto no respondió dentro del plazo. Puede estar cerrado o filtrado.'
          })
        );
      })
    );
    socket.once('error', (error) =>
      acabar(() => {
        socket.destroy();
        reject(wrap(error, { contexto: `conectar con ${host}:${puerto}` }));
      })
    );

    socket.connect(puerto, host);
  });
}

/**
 * Sube un socket ya abierto a TLS, sin cerrar la sesión de protocolo.
 *
 * Es lo que hace STARTTLS: el servidor acepta primero en claro y solo cifra
 * después de recibir el comando, con la misma conexión.
 *
 * @param {import('node:net').Socket} socket
 * @param {object} opciones
 * @param {boolean} [opciones.verificar=false]
 * @param {string} [opciones.servername]
 * @param {number} [opciones.timeout=10000]
 * @returns {Promise<{socket: import('node:tls').TLSSocket, certificado: object|null}>}
 */
function subirStartTls(socket, opciones = {}) {
  const { verificar = false, servername, timeout = 10000 } = opciones;

  return new Promise((resolve, reject) => {
    // El cliente anterior leyó de este socket; sus oyentes se marchan porque el
    // TLSSocket pasa a ser el que consume los datos.
    socket.removeAllListeners('data');
    socket.removeAllListeners('error');
    socket.removeAllListeners('timeout');

    const seguro = tls.connect(
      {
        socket,
        servername,
        rejectUnauthorized: verificar,
        timeout
      },
      () => {
        seguro.removeAllListeners('timeout');
        resolve({ socket: seguro, certificado: require('../net/tls').inspeccionar(seguro) });
      }
    );

    seguro.once('timeout', () => {
      seguro.destroy();
      reject(
        new NetlabError(CODES.TIMEOUT, 'El cifrado TLS tras STARTTLS no se completó dentro del plazo.', {
          remediation: 'El servidor anunció STARTTLS pero no completó el cifrado. Suele ser un servidor mal configurado o un proxy TLS que corta.'
        })
      );
    });

    seguro.once('error', (error) => {
      seguro.destroy();
      reject(wrap(error, { contexto: 'subir a TLS con STARTTLS' }));
    });
  });
}

/**
 * Cliente de lineas sobre un socket ya conectado.
 *
 * @param {import('node:net').Socket|import('node:tls').TLSSocket} socket
 * @param {object} [opciones]
 * @param {number} [opciones.timeout=10000] Plazo por comando.
 * @param {(texto: string) => string} [opciones.redactar]
 * @returns {{leer: Function, enviar: Function, escribir: Function, destruir: Function, socket: object}}
 */
function crearCliente(socket, opciones = {}) {
  const { timeout = 10000, redactar = (texto) => texto } = opciones;

  let buffer = '';
  let pendiente = null;

  socket.setEncoding('utf8');
  socket.on('data', (trozo) => {
    buffer += trozo;
    if (!pendiente || !respuestaCompleta(buffer)) return;

    const bruto = buffer;
    buffer = '';
    const { resolver, temporizador } = pendiente;
    pendiente = null;
    clearTimeout(temporizador);
    resolver(interpretar(bruto, redactar));
  });

  socket.once('error', (error) => {
    if (!pendiente) return;
    const { resolver, temporizador, etiqueta } = pendiente;
    pendiente = null;
    clearTimeout(temporizador);
    // El error se entrega como respuesta: el informe tiene que poder contar que
    // fallo el comando, no recibir una excepcion suelta a mitad del recorrido.
    resolver({
      codigo: null,
      lineas: [],
      texto: redactar(wrap(error, { contexto: etiqueta }).message),
      multilinea: false,
      error: wrap(error, { contexto: etiqueta })
    });
  });

  /** Espera la respuesta que falta. */
  function leer(etiqueta = 'leer') {
    if (pendiente) {
      return Promise.reject(
        new NetlabError(CODES.INTERNO, 'Se pidió una segunda respuesta antes de terminar la primera.', {
          remediation: 'Es un fallo de la prueba, no del servidor.'
        })
      );
    }
    if (buffer && respuestaCompleta(buffer)) {
      const bruto = buffer;
      buffer = '';
      return Promise.resolve(interpretar(bruto, redactar));
    }
    return new Promise((resolver) => {
      const temporizador = setTimeout(() => {
        pendiente = null;
        buffer = '';
        resolver({
          codigo: null,
          lineas: [],
          texto: redactar(`Sin respuesta a «${etiqueta}» dentro de ${timeout} ms.`),
          multilinea: false,
          error: new NetlabError(CODES.TIMEOUT, `Sin respuesta a «${etiqueta}» dentro de ${timeout} ms.`, {
            remediation: 'El servidor acepta la conexión pero no contesta a este comando. Revisa si hay un proxy o un antivirus cortando la sesión.'
          })
        });
      }, timeout);
      pendiente = { resolver, temporizador, etiqueta };
    });
  }

  /** Escribe un comando y espera su respuesta. */
  function enviar(linea, etiqueta = linea.split(' ')[0]) {
    try {
      socket.write(`${linea}\r\n`);
    } catch (error) {
      return Promise.resolve({
        codigo: null,
        lineas: [],
        texto: redactar(wrap(error, { contexto: etiqueta }).message),
        multilinea: false,
        error: wrap(error, { contexto: etiqueta })
      });
    }
    return leer(etiqueta);
  }

  /** Escribe sin esperar respuesta. */
  function escribir(linea) {
    socket.write(`${linea}\r\n`);
  }

  /** Escribe una carga util sin terminador de linea (cuerpo de DATA, base64). */
  function escribirCrudo(texto) {
    socket.write(texto);
  }

  /** Cierra el socket. */
  function destruir() {
    try {
      socket.destroy();
    } catch {
      /* ya estaba cerrado */
    }
  }

  return { leer, enviar, escribir, escribirCrudo, destruir, socket };
}

module.exports = { conectarTcp, subirStartTls, crearCliente, respuestaCompleta, interpretar };