/**
 * net/tls.js — Conexiones TLS e inspeccion de certificados.
 *
 * MODULO NUEVO. Ninguno de los scripts de legacy/ miraba el certificado TLS.
 * Todos usaban `rejectUnauthorized: false` sin explicar por que:
 *
 *   Validate config SMTP/validate-smtp.js:36,74
 *
 * Eso desactiva la verificacion entera: el script funciona tanto contra un
 * certificado valido como contra uno autofirmado o del host equivocado, y el
 * reporte no dice nada. Para diagnosticar un servidor de correo es justo el
 * dato que mas falta.
 *
 * Aqui se separa el proposito de la conexion:
 *   - `conectar({verificar:false})` para hablar con un servidor mal configurado
 *     (se avisa en el reporte en vez de fallar).
 *   - `conectar({verificar:true})` para exigir un certificado valido.
 * Y en ambos casos se devuelve la ficha del certificado.
 *
 * @module core/net/tls
 */

'use strict';

const tls = require('node:tls');
const { NetlabError, CODES, wrap } = require('../errors');

/** Indica si un host es una direccion IP literal. */
function esIp(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || String(host || '').includes(':');
}

/**
 * Abre una conexion TLS con plazo maximo y ficha del certificado.
 *
 * @param {object} options
 * @param {string} options.host
 * @param {number} options.port
 * @param {boolean} [options.verificar=false] Exigir certificado valido.
 * @param {number} [options.timeout=10000]
 * @param {string} [options.servername] Nombre para SNI, si distinto del host.
 * @returns {Promise<{socket, certificado, avisos}>}
 * @throws {NetlabError} Si no se puede establecer la conexion.
 */
function conectar(options) {
  const { host, port, verificar = false, timeout = 10000, servername } = options;

  return new Promise((resolve, reject) => {
    const avisos = [];

    if (!verificar) {
      avisos.push({
        severity: 'warn',
        title: 'Verificacion del certificado desactivada',
detail:
          'La conexión se estableció sin comprobar el certificado. Eso permite que una tercera parte se haga pasar por el servidor.',
        recommendation:
          'El informe incluye la ficha del certificado para que puedas juzgar si es el esperado. Activa la verificación si el certificado es válido.'
      });
    }

    const socket = tls.connect({
      host,
      port,
      // Nombre en SNI. Para IP literales sin SNI, algunos servidores cortan.
      servername: servername || (esIp(host) ? undefined : host),
      rejectUnauthorized: verificar,
      timeout
    });

    let terminado = false;
    const acabar = (fn) => {
      if (terminado) return;
      terminado = true;
      fn();
    };

    socket.once('secureConnect', () => {
      acabar(() =>
        resolve({
          socket,
          certificado: inspeccionar(socket),
          avisos
        })
      );
    });

    socket.once('timeout', () => {
      acabar(() => {
        socket.destroy();
        reject(
          new NetlabError(CODES.TIMEOUT, `Tiempo agotado al conectar con ${host}:${port}.`, {
            remediation: 'El puerto no responde TLS dentro del plazo. Puede estar cerrado o filtrado.'
          })
        );
      });
    });

    socket.once('error', (error) => {
      acabar(() => {
        socket.destroy();
        reject(wrap(error, { contexto: `conectar por TLS con ${host}:${port}` }));
      });
    });
  });
}

/**
 * Extrae la ficha legible del certificado TLS de un socket establecido.
 *
 * @param {import('node:tls').TLSSocket} socket
 * @returns {object|null}
 */
function inspeccionar(socket) {
  const cert = socket?.getPeerCertificate?.(true);
  if (!cert || !cert.subject) return null;

  const validoHasta = cert.valid_to ? new Date(cert.valid_to) : null;
  const diasRestantes = validoHasta ? Math.floor((validoHasta.getTime() - Date.now()) / 86400e3) : null;

  const errores = cert.subjectaltname
    ? String(cert.subjectaltname)
        .split(',')
        .map((s) => s.trim())
    : [];

  return {
    sujeto: cert.subject.CN || cert.subject.O || '(sin CN)',
    emisor: cert.issuer?.CN || cert.issuer?.O || '(desconocido)',
    organizacion: cert.issuer?.O || null,
    validoDesde: cert.valid_from || null,
    validoHasta: cert.valid_to || null,
    diasRestantes,
    caducaPronto: diasRestantes !== null && diasRestantes <= 15,
    autoFirmado: cert.issuer?.CN === cert.subject?.CN,
    protocolo: socket.getProtocol ? socket.getProtocol() : null,
    cifrado: socket.getCipher ? socket.getCipher()?.name : null,
    nombresAlternativos: errores.filter((n) => n.startsWith('DNS:')),
    autorizacionBasadaEnExtensiones: socket.getPeerCertificate
      ? Boolean(socket.getPeerCertificate(true)?.raw)
      : null,
    autoridadCertificadora: (socket.authorized ?? null) === true,
    motivoRechazo: socket.authorizationError || null
  };
}

/**
 * Traduce una ficha de certificado en hallazgos accionables.
 *
 * @param {object|null} cert
 * @returns {Array<{severity, title, detail, recommendation}>}
 */
function auditarCertificado(cert) {
  const f = [];
  if (!cert) return f;

  if (cert.autoFirmado) {
    f.push({
      severity: 'error',
      title: 'Certificado autofirmado',
      detail: `El emisor (${cert.emisor}) coincide con el sujeto (${cert.sujeto}). Nadie mas lo puede validar.`,
      recommendation: 'Emite el certificado con una autoridad de certificacion reconocida e instala la cadena completa en el servidor.'
    });
  }

  if (cert.diasRestantes !== null && cert.diasRestantes < 0) {
    f.push({
      severity: 'error',
      title: 'Certificado expirado',
      detail: `Caducó el ${cert.validoHasta} (hace ${Math.abs(cert.diasRestantes)} días).`,
      recommendation: 'Renueva el certificado. Mientras este expirado, los clientes que verifican rechazan la conexion.'
    });
  } else if (cert.diasRestantes !== null && cert.diasRestantes <= 15) {
    f.push({
      severity: 'warn',
      title: 'Certificado a punto de caducar',
      detail: `Caduca el ${cert.validoHasta}, dentro de ${cert.diasRestantes} días.`,
      recommendation: 'Renueva antes de la fecha de caducidad, no el día de la caducidad.'
    });
  }

  // `autoridadCertificadora` sale de la propia conexion: con
  // `rejectUnauthorized:false` el socket se abre y el certificado se lee igual,
  // asi que es la unica forma de decir "esto no lo ha validado nadie". Se avisa
  // aqui y no en el que lo llama porque es una propiedad del certificado, no
  // del servicio que se este mirando.
  if (cert.autoridadCertificadora === false) {
    f.push({
      severity: 'error',
      title: 'El certificado no esta validado por una autoridad de certificacion',
      detail: cert.motivoRechazo
        ? `El cliente lo rechazo por: ${cert.motivoRechazo}. La conexion se abrio igualmente porque la verificacion estaba desactivada.`
        : 'La conexion se abrio sin comprobar el certificado, y no hay ninguna autoridad que lo respalde.',
      recommendation:
        'Quien visite el sitio con el navegador vera un aviso de seguridad. Revisa la cadena del certificado y los nombres alternativos.'
    });
  }

  if (!cert.nombresAlternativos.length) {
    f.push({
      severity: 'warn',
      title: 'El certificado no declara nombres alternativos',
      detail: 'No tiene campo SAN, que es lo que exigen los clientes modernos para validar el host.',
      recommendation: 'Emite el certificado incluyendo el nombre (SAN) con el que te conectas.'
    });
  }

  const protocolo = (cert.protocolo || '').toUpperCase();
  if (protocolo && !['TLSV1.2', 'TLSV1.3'].includes(protocolo)) {
    f.push({
      severity: 'warn',
      title: `Protocolo obsoleto: ${cert.protocolo}`,
      detail: 'Se negoció una versión antigua de TLS.',
      recommendation: 'Configura el servidor para aceptar solo TLS 1.2 y 1.3.'
    });
  }

  return f;
}

module.exports = { conectar, inspeccionar, auditarCertificado, esIp };