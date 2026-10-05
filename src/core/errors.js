/**
 * errors.js — Errores de dominio con codigo estable.
 *
 * MODULO DE CONTRATO. La web necesita distinguir "el usuario escribio mal la
 * IP" de "AbuseIPDB no respondio" para mostrar mensajes distintos. Un `Error`
 * normal no transporta esa informacion: el mensaje es texto libre y no se puede
 * consultar de forma fiable.
 *
 * Cada error lleva un `code`, una severidad y, opcionalmente, una
 * `remediation` que la interfaz muestra al usuario.
 *
 * @module core/errors
 */

'use strict';

/** Codigos de error del dominio. Valores estables: la UI compara contra ellos. */
const CODES = {
  PARAM_INVALIDO: 'PARAM_INVALIDO',
  ENTRADA_VACIA: 'ENTRADA_VACIA',
  DNS_SIN_REGISTROS: 'DNS_SIN_REGISTROS',
  TIMEOUT: 'TIMEOUT',
  RED: 'RED',
  CREDENCIAL_AUSENTE: 'CREDENCIAL_AUSENTE',
  CREDENCIAL_INVALIDA: 'CREDENCIAL_INVALIDA',
  API_EXTERNA: 'API_EXTERNA',
  API_CUOTA: 'API_CUOTA',
  SMTP_RECHAZADO: 'SMTP_RECHAZADO',
  TLS_INVALIDO: 'TLS_INVALIDO',
  FICHERO_NO_ENCONTRADO: 'FICHERO_NO_ENCONTRADO',
  INTERNO: 'INTERNO'
};

/**
 * Error de dominio.
 *
 * @class NetlabError
 * @extends Error
 */
class NetlabError extends Error {
  /**
   * @param {string} code Uno de {@link CODES}.
   * @param {string} message Mensaje para la persona usuaria, en espanol.
   * @param {object} [options]
   * @param {string} [options.remediation] Que hacer para resolverlo.
   * @param {Error} [options.cause] Error original, para la traza.
   * @param {object} [options.details] Datos extra para la interfaz.
   */
  constructor(code, message, options = {}) {
    super(message, { cause: options.cause });
    this.name = 'NetlabError';
    this.code = code;
    this.remediation = options.remediation || null;
    this.details = options.details || null;
    this.expose = true;
  }

  /** Serializacion segura para enviar al navegador. */
  toJSON() {
    return {
      code: this.code,
      message: this.message,
      remediation: this.remediation,
      details: this.details
    };
  }
}

/**
 * Convierte cualquier excepcion en un NetlabError.
 *
 * Traduce los errores nativos de Node (`ECONNREFUSED`, `ETIMEDOUT`,
 * `ENOTFOUND`...) a codigos del dominio, para que la UI pueda reaccionar sin
 * conocer los codigos de error del sistema operativo.
 *
 * @param {Error} error Excepcion original.
 * @param {object} [options]
 * @param {string} [options.contexto] Que se estaba haciendo, para el mensaje.
 * @returns {NetlabError}
 */
function wrap(error, options = {}) {
  if (error instanceof NetlabError) return error;

  const contexto = options.contexto ? ` al ${options.contexto}` : '';
  const codigo = error?.code;
  const mensaje = error?.message || String(error);

  switch (codigo) {
    case 'ETIMEDOUT':
    case 'ESOCKETTIMEDOUT':
      return new NetlabError(CODES.TIMEOUT, `Se agotó el tiempo de espera${contexto}.`, {
        cause: error,
        remediation: 'El host no respondió dentro del plazo. Puede estar apagado, filtrando el puerto o con una latencia muy alta.',
        details: { errno: codigo }
      });

    case 'ECONNREFUSED':
      return new NetlabError(CODES.RED, `Conexión rechazada${contexto}.`, {
        cause: error,
        remediation: 'El puerto está cerrado o filtrado. Un firewall descarta las conexiones.',
        details: { errno: codigo }
      });

    // En DNS, ENOTFOUND y EAI_AGAIN no son lo mismo que un nombre mal
    // escrito. ENOTFOUND es NXDOMAIN: el nombre no existe en la zona. Es el
    // unico caso en el que el dominio esta realmente mal, y conviene que el
    // mensaje lo diga sin ambiguedad.
    case 'ENOTFOUND':
      return new NetlabError(CODES.DNS_SIN_REGISTROS, `El nombre no existe${contexto} (NXDOMAIN).`, {
        cause: error,
        remediation: 'El nombre no esta en la zona. Revisa que este bien escrito y que los servidores autoritativos lo publiquen.',
        details: { errno: codigo }
      });

    case 'ENODATA':
      return new NetlabError(CODES.DNS_SIN_REGISTROS, `El nombre existe pero no tiene registros${contexto} (NODATA).`, {
        cause: error,
        remediation: 'Es normal: el nombre resuelve, pero no hay registros de ese tipo. Si esperabas datos, el registro falta o esta en otro nombre.',
        details: { errno: codigo }
      });

    case 'ESERVFAIL':
      return new NetlabError(CODES.RED, `El servidor de nombres no pudo completar la consulta${contexto} (SERVFAIL).`, {
        cause: error,
        remediation: 'El servidor autoritativo devolvio un error al resolver. Suele ser una zona mal cargada, un CNAME que no existe o un problema de DNSSEC.',
        details: { errno: codigo }
      });

    case 'EREFUSED':
      return new NetlabError(CODES.RED, `El servidor de nombres rechazo la consulta${contexto} (REFUSED).`, {
        cause: error,
        remediation: 'El servidor autoritativo se niega a responder por esa zona. Puede ser una Politica de zona restrictiva o un servidor mal configurado.',
        details: { errno: codigo }
      });

    case 'EAI_AGAIN':
      return new NetlabError(CODES.RED, `El servidor de nombres no respondio a tiempo${contexto} (EAI_AGAIN).`, {
        cause: error,
        remediation: 'Reintenta. Si se repite, el servidor de nombres esta saturado o inalcanzable desde aqui.',
        details: { errno: codigo }
      });

    case 'ECONNRESET':
      return new NetlabError(CODES.RED, `La conexión se cerró inesperadamente${contexto}.`, {
        cause: error,
        remediation: 'El servidor cerró el socket a mitad de la conversación.',
        details: { errno: codigo }
      });

    case 'CERT_HAS_EXPIRED':
      return new NetlabError(CODES.TLS_INVALIDO, 'El certificado TLS ha expirado.', {
        cause: error,
        remediation: 'Renueva el certificado del servidor.',
        details: { errno: codigo }
      });

    case 'DEPTH_ZERO_SELF_SIGNED_CERT':
    case 'SELF_SIGNED_CERT_IN_CHAIN':
      return new NetlabError(CODES.TLS_INVALIDO, 'El certificado TLS es autofirmado.', {
        cause: error,
        remediation: 'Instala una cadena de confianza valida o usa el certificado emitido por tu CA.',
        details: { errno: codigo }
      });

    case 'ERR_TLS_CERT_ALTNAME_INVALID':
      return new NetlabError(CODES.TLS_INVALIDO, 'El nombre del host no coincide con el certificado.', {
        cause: error,
        remediation: 'Emite un certificado que incluya el nombre (SAN) que estas usando para conectarte.',
        details: { errno: codigo }
      });

    default:
      return new NetlabError(CODES.INTERNO, mensaje, { cause: error, details: { errno: codigo || null } });
  }
}

module.exports = { NetlabError, CODES, wrap };