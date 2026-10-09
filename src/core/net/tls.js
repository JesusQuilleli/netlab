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
 * Sobre la calificacion (`calcularNota`): reproduce a grandes rasgos el
 * criterio de SSL Labs, pero es una funcion PURA y sin red, para poder probarla
 * con casos fijos. Distingue entre "el servidor no lo soporta" y "este cliente
 * no puede comprobarlo" (OpenSSL moderno ya no ofrece TLS 1.0/1.1 ni cifrados
 * como RC4 o 3DES): nunca se da por bueno lo que no se ha podido medir.
 *
 * @module core/net/tls
 */

'use strict';

const tls = require('node:tls');
const { X509Certificate } = require('node:crypto');
const { NetlabError, CODES, wrap } = require('../errors');

/** Version del protocolo TLS a orden numerico, para comparar. */
const RANGO_PROTOCOLO = {
  'TLSv1': 1,
  'TLSv1.1': 1.1,
  'TLSv1.2': 1.2,
  'TLSv1.3': 1.3
};

/** Bits por curva de nombre (para sacar el tamano de una clave EC). */
const BITS_CURVA = {
  'prime256v1': 256,
  secp256r1: 256,
  secp384r1: 384,
  secp521r1: 521,
  secp224r1: 224,
  'secp256k1': 256
};

/** Firma con un algoritmo de resumen roto u obsoleto. */
const FIRMA_DEBIL = /sha-?1|md5/i;

/** Familias de cifrado que hoy se consideran inseguras. */
const CIFRADO_DEBIL = /(RC4|DES-CBC3|_3DES_|3DES|(^|[^A-Z])DES([^0-9A-Z]|$)|NULL|EXPORT|_anon_|ADH|AECDH|MD5)/i;

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
 * @param {boolean} [options.requestOCSP=false] Pedir stapling OCSP al servidor.
 * @param {string} [options.minVersion] Version TLS minima para forzar el sondeo.
 * @param {string} [options.maxVersion] Version TLS maxima para forzar el sondeo.
 * @returns {Promise<{socket, certificado, avisos, ocsp}>}
 * @throws {NetlabError} Si no se puede establecer la conexion.
 */
function conectar(options) {
  const {
    host,
    port,
    verificar = false,
    timeout = 10000,
    servername,
    requestOCSP = false,
    minVersion,
    maxVersion
  } = options;

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

    const opciones = {
      host,
      port,
      // Nombre en SNI. Para IP literales sin SNI, algunos servidores cortan.
      servername: servername || (esIp(host) ? undefined : host),
      rejectUnauthorized: verificar,
      timeout
    };
    if (minVersion) opciones.minVersion = minVersion;
    if (maxVersion) opciones.maxVersion = maxVersion;

    let socket;
    try {
      socket = tls.connect(opciones);
    } catch (error) {
      reject(wrap(error, { contexto: `configurar conexión TLS con ${host}:${port}` }));
      return;
    }

    // El stapling llega como evento durante el handshake: hay que engancharse
    // ANTES de que el socket termine de conectar.
    let respuestaOcsp = null;
    if (requestOCSP) {
      socket.on('ocsp', (respuesta) => {
        if (respuesta && respuesta.length) respuestaOcsp = respuesta;
      });
    }

    let terminado = false;
    const acabar = (fn) => {
      if (terminado) return;
      terminado = true;
      fn();
    };

    socket.once('secureConnect', () => {
      const finalizar = () =>
        acabar(() =>
          resolve({
            socket,
            certificado: inspeccionar(socket, { ocsp: respuestaOcsp }),
            avisos,
            ocsp: respuestaOcsp
          })
        );

      // Con stapling, la respuesta viaja con el handshake pero puede llegar un
      // pelo despues de `secureConnect`. Se le da un margen corto y acotado.
      if (requestOCSP && !respuestaOcsp) {
        let esperado = 0;
        const reloj = setInterval(() => {
          esperado += 60;
          if (respuestaOcsp || esperado >= 300) {
            clearInterval(reloj);
            finalizar();
          }
        }, 60);
        reloj.unref?.();
        return;
      }
      finalizar();
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
 * Tamaño en bits de una clave publica, a partir de sus detalles.
 *
 * @param {import('node:crypto').KeyObject} clave
 * @returns {number|null}
 */
function bitsDeClave(clave) {
  const detalles = clave?.asymmetricKeyDetails || {};
  if (typeof detalles.modulusLength === 'number') return detalles.modulusLength;
  if (detalles.namedCurve) return BITS_CURVA[detalles.namedCurve] || null;
  return null;
}

/**
 * Recorre la cadena que envia el servidor (hoja → ... → raiz).
 *
 * `getPeerCertificate(true)` expone cada eslabon en `issuerCertificate`, y el
 * ultimo se apunta a si mismo: el recorrido corta ahi o cuando repite huella.
 *
 * @param {import('node:tls').TLSSocket} socket
 * @returns {Array<{nivel, sujeto, emisor, validoHasta, huella, autoFirmado}>}
 */
function cadenaDe(socket) {
  if (!socket?.getPeerCertificate) return [];
  let actual = socket.getPeerCertificate(true);
  const salida = [];
  const vistos = new Set();
  for (let nivel = 0; actual && actual.subject && nivel < 10; nivel += 1) {
    const huella = actual.fingerprint256 || actual.fingerprint || `${actual.subject.CN}-${nivel}`;
    if (vistos.has(huella)) break;
    vistos.add(huella);
    salida.push({
      nivel,
      sujeto: actual.subject.CN || actual.subject.O || '(sin CN)',
      emisor: actual.issuer?.CN || actual.issuer?.O || '(desconocido)',
      validoHasta: actual.valid_to || null,
      huella,
      autoFirmado: actual.issuer?.CN === actual.subject?.CN && actual.issuer?.O === actual.subject?.O
    });
    const siguiente = actual.issuerCertificate;
    if (!siguiente || siguiente === actual) break;
    actual = siguiente;
  }
  return salida;
}

/**
 * Extrae la ficha legible del certificado TLS de un socket establecido.
 *
 * @param {import('node:tls').TLSSocket} socket
 * @param {object} [extras] Datos que no viven en el socket (p. ej. stapling).
 * @returns {object|null}
 */
function inspeccionar(socket, extras = {}) {
  const cert = socket?.getPeerCertificate?.(true);
  if (!cert || !cert.subject) return null;

  const validoHasta = cert.valid_to ? new Date(cert.valid_to) : null;
  const diasRestantes = validoHasta ? Math.floor((validoHasta.getTime() - Date.now()) / 86400e3) : null;

  const nombresAlternativos = cert.subjectaltname
    ? String(cert.subjectaltname)
        .split(',')
        .map((s) => s.trim())
    : [];

  let x509 = null;
  try {
    if (cert.raw) x509 = new X509Certificate(cert.raw);
  } catch {
    x509 = null;
  }

  const tipoClave = x509?.publicKey?.asymmetricKeyType || null;
  const tamanoClave = x509 ? bitsDeClave(x509.publicKey) : null;

  return {
    sujeto: cert.subject.CN || cert.subject.O || '(sin CN)',
    emisor: cert.issuer?.CN || cert.issuer?.O || '(desconocido)',
    organizacion: cert.issuer?.O || null,
    validoDesde: cert.valid_from || null,
    validoHasta: cert.valid_to || null,
    diasRestantes,
    caducaPronto: diasRestantes !== null && diasRestantes <= 15,
    autoFirmado:
      cert.issuer?.CN === cert.subject?.CN && cert.issuer?.O === cert.subject?.O,
    huella256: x509?.fingerprint256 || cert.fingerprint256 || null,
    serial: x509?.serialNumber || cert.serialNumber || null,
    algoritmoFirma: x509?.signatureAlgorithm || null,
    tipoClave,
    tamanoClave,
    protocolo: socket.getProtocol ? socket.getProtocol() : null,
    cifrado: socket.getCipher ? socket.getCipher()?.name : null,
    nombresAlternativos: nombresAlternativos.filter((n) => n.startsWith('DNS:')),
    cadena: cadenaDe(socket),
    autoridadCertificadora: (socket.authorized ?? null) === true,
    motivoRechazo: socket.authorizationError || null,
    ocspStapled: extras.ocsp ? true : null
  };
}

/**
 * ¿El nombre del cifrado negociado pertenece a una familia insegura?
 *
 * @param {string} nombre
 * @returns {boolean}
 */
function esCifradoDebil(nombre) {
  return CIFRADO_DEBIL.test(String(nombre || ''));
}

/**
 * ¿El cifrado negociado ofrece secreto hacia adelante (forward secrecy)?
 *
 * TLS 1.3 siempre lo da; en 1.2 depende del intercambio de claves (ECDHE/DHE).
 * Un cifrado con intercambio de clave RSA no lo ofrece.
 *
 * @param {string} nombre
 * @param {string} [protocolo]
 * @returns {boolean}
 */
function tieneForwardSecrecy(nombre, protocolo) {
  if (RANGO_PROTOCOLO[protocolo] >= 1.3) return true;
  return /(ECDHE|DHE)/i.test(String(nombre || ''));
}

/**
 * Sondea, version por version, culaes acepta el servidor.
 *
 * No todas se pueden medir: OpenSSL moderno ya no ofrece TLS 1.0/1.1, asi que un
 * fallo de esas versiones puede ser del cliente, no del servidor. Esos casos se
 * marcan como `null` (no comprobable) en vez de `false`.
 *
 * @param {object} options
 * @param {string} options.host
 * @param {number} options.port
 * @param {string} [options.servername]
 * @param {number} [options.timeout=8000]
 * @returns {Promise<object>} Mapa { 'TLSv1.3': bool|null, ... } y detalle.
 */
async function sondearProtocolos(options) {
  const { host, port, servername, timeout = 8000 } = options;
  const versiones = ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1'];
  const soporte = {};

  await Promise.all(
    versiones.map(
      (version) =>
        new Promise((resolve) => {
          let socket;
          const terminar = (valor) => {
            try {
              socket?.destroy?.();
            } catch {
              /* da igual: el socket no decide el resultado */
            }
            soporte[version] = valor;
            resolve();
          };

          try {
            socket = tls.connect({
              host,
              port,
              servername: servername || (esIp(host) ? undefined : host),
              rejectUnauthorized: false,
              minVersion: version,
              maxVersion: version,
              timeout
            });
          } catch {
            // El cliente ni siquiera puede ofrecer esta version.
            terminar(null);
            return;
          }

          socket.once('secureConnect', () => terminar(true));
          socket.once('timeout', () => terminar(false));
          socket.once('error', (error) => {
            const mensaje = String(error?.message || '');
            // "El cliente no puede ofrecerla" no es lo mismo que "el servidor la rechaza".
            const limitacionCliente =
              /no protocols available|unsupported protocol|ERR_SSL_NO_PROTOCOLS|wrong ssl version/i.test(mensaje);
            terminar(limitacionCliente ? null : false);
          });
        })
    )
  );

  return soporte;
}

/**
 * Califica la conexion de A a F, al estilo de SSL Labs.
 *
 * Funcion pura: no toca la red. Cada deduccion se devuelve con su motivo para
 * que el informe pueda explicar la nota en vez de soltarla sin justificar.
 *
 * @param {object} entrada
 * @param {string} [entrada.protocoloNegociado]
 * @param {object} [entrada.protocolos] Mapa version → bool|null.
 * @param {object|null} [entrada.certificado]
 * @param {boolean} [entrada.cifradoDebil] El cifrado negociado es inseguro.
 * @param {boolean} [entrada.forwardSecrecy]
 * @param {boolean|null} [entrada.ocspStapled]
 * @param {{presente:boolean}|null} [entrada.hsts]
 * @returns {{letra, puntos, deducciones:Array, caps:Array, resumen}}
 */
function calcularNota(entrada = {}) {
  const {
    protocoloNegociado,
    protocolos = {},
    certificado,
    cifradoDebil = false,
    forwardSecrecy = true,
    ocspStapled = null,
    hsts = null
  } = entrada;

  let puntos = 100;
  const deducciones = [];
  const caps = [];

  const restar = (cantidad, titulo, razon) => {
    puntos -= cantidad;
    deducciones.push({ puntos: cantidad, titulo, razon });
  };
  const topar = (letra, titulo, razon) => {
    caps.push({ letra, titulo, razon });
  };

  if (!certificado) {
    topar('F', 'Sin certificado', 'No se pudo leer el certificado del servidor.');
  } else {
    if (certificado.diasRestantes !== null && certificado.diasRestantes < 0) {
      topar('F', 'Certificado expirado', `Caduco el ${certificado.validoHasta}.`);
    } else if (certificado.diasRestantes !== null && certificado.diasRestantes <= 15) {
      restar(10, 'Certificado a punto de caducar', `Quedan ${certificado.diasRestantes} días.`);
    }
    if (certificado.autoFirmado) {
      topar('F', 'Certificado autofirmado', 'El emisor coincide con el sujeto.');
    }
    if (certificado.autoridadCertificadora === false) {
      topar('F', 'Cadena no confiable', 'Ninguna autoridad de certificación lo respalda.');
    }
    if (!certificado.nombresAlternativos?.length) {
      restar(10, 'Sin nombres alternativos (SAN)', 'El certificado no declara el host.');
    }
    if (certificado.tipoClave === 'rsa' && certificado.tamanoClave && certificado.tamanoClave < 2048) {
      topar('C', 'Clave RSA corta', `Solo ${certificado.tamanoClave} bits; el mínimo recomendado es 2048.`);
    }
    if (certificado.tamanoClave && certificado.tipoClave === 'ec' && certificado.tamanoClave < 256) {
      restar(20, 'Curva elíptica débil', `La curva de ${certificado.tamanoClave} bits no es recomendable.`);
    }
    if (certificado.algoritmoFirma && FIRMA_DEBIL.test(certificado.algoritmoFirma)) {
      restar(20, 'Firma con algoritmo roto', `Firmado con ${certificado.algoritmoFirma}.`);
    }
  }

  const rangoNegociado = RANGO_PROTOCOLO[protocoloNegociado];
  if (rangoNegociado && rangoNegociado < 1.2) {
    topar('F', `Protocolo obsoleto: ${protocoloNegociado}`, 'Por debajo de TLS 1.2 no se considera seguro.');
  }

  if (cifradoDebil) {
    topar('F', 'Cifrado inseguro negociado', 'Se negoció una familia de cifrado rota (RC4/3DES/DES/NULL).');
  }

  if (protocolos['TLSv1.3'] === false) {
    restar(10, 'Sin TLS 1.3', 'El servidor no ofrece la versión más moderna.');
  }
  const ofreceObsoleto = protocolos['TLSv1.1'] === true || protocolos['TLSv1'] === true;
  if (ofreceObsoleto) {
    restar(20, 'Acepta protocolos obsoletos', 'Todavía admite TLS 1.0 o 1.1.');
  }

  if (forwardSecrecy === false) {
    restar(10, 'Sin secreto hacia adelante', 'El cifrado no usa ECDHE/DHE.');
  }
  if (ocspStapled === false) {
    restar(5, 'Sin stapling OCSP', 'No adjunta la prueba de revocación del certificado.');
  }
  if (hsts && hsts.presente === false) {
    restar(5, 'Sin HSTS', 'El sitio no fuerza HTTPS en visitas posteriores.');
  }

  if (puntos < 0) puntos = 0;
  let letra = puntos >= 90 ? 'A' : puntos >= 80 ? 'B' : puntos >= 70 ? 'C' : puntos >= 60 ? 'D' : 'F';

  // Los topes mandan: una sola condicion critica hunde la nota aunque los
  // puntos cuadren, que es como se comporta una auditoria de verdad.
  const orden = { A: 4, B: 3, C: 2, D: 1, F: 0 };
  for (const cap of caps) {
    if (orden[cap.letra] < orden[letra]) letra = cap.letra;
  }

  const resumen =
    letra === 'A'
      ? 'Configuración TLS sólida.'
      : caps.length
        ? `Problemas graves: ${caps.map((c) => c.titulo).join(', ')}.`
        : `Se puede mejorar: ${deducciones.map((d) => d.titulo).join(', ')}.`;

  return { letra, puntos, deducciones, caps, resumen };
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

  if (cert.tipoClave === 'rsa' && cert.tamanoClave && cert.tamanoClave < 2048) {
    f.push({
      severity: 'error',
      title: 'Clave RSA demasiado corta',
      detail: `El certificado usa una clave de ${cert.tamanoClave} bits.`,
      recommendation: 'Emite un certificado nuevo con una clave de al menos 2048 bits (mejor 3072 o 4096).'
    });
  }

  if (cert.algoritmoFirma && FIRMA_DEBIL.test(cert.algoritmoFirma)) {
    f.push({
      severity: 'error',
      title: 'Firma del certificado con algoritmo roto',
      detail: `Está firmado con ${cert.algoritmoFirma}, que ya no se considera seguro.`,
      recommendation: 'Reemite el certificado con una firma SHA-256 o superior.'
    });
  }

  if (cert.ocspStapled === false) {
    f.push({
      severity: 'info',
      title: 'Sin stapling OCSP',
      detail: 'El servidor no adjunta la respuesta OCSP del certificado.',
      recommendation: 'Activa el stapling OCSP: ahorra una consulta al cliente y algo de latencia.'
    });
  }

  if (Array.isArray(cert.cadena) && cert.cadena.length === 1 && !cert.autoFirmado) {
    f.push({
      severity: 'warn',
      title: 'El servidor no envía la cadena intermedia',
      detail: 'Solo se recibió el certificado hoja. Algunos clientes tendrán que buscar el intermedio por su cuenta.',
      recommendation: 'Configura el servidor para enviar el certificado intermedio junto con el hoja.'
    });
  }

  return f;
}

module.exports = {
  conectar,
  inspeccionar,
  auditarCertificado,
  esIp,
  esCifradoDebil,
  tieneForwardSecrecy,
  sondearProtocolos,
  calcularNota,
  cadenaDe,
  bitsDeClave
};
