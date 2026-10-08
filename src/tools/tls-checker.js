/**
 * tls-checker - Inspeccion de certificados TLS/SSL.
 *
 * Herramienta que conecta a un host:puerto por TLS, extrae la ficha del
 * certificado y la audita generando hallazgos accionables.
 *
 * @module tools/tls-checker
 */

'use strict';

const {
  createResult,
  addSection,
  addSummary,
  addFinding,
  addLog,
  finalize,
  SEVERIDADES,
  SECCION_KINDS: K
} = require('../core/result');
const { NetlabError, CODES } = require('../core/errors');
const { normalizarTimeout } = require('../core/dominio');
const { conectar, inspeccionar, auditarCertificado, esIp } = require('../core/net/tls');

const ID = 'tls-checker';
const TITLE = 'Verificador SSL/TLS';

const CAMPOS = [
  {
    name: 'host',
    label: 'Host o IP',
    type: 'text',
    required: true,
    placeholder: 'ejemplo.com',
    help: 'Nombre de host o direccion IP del servidor a verificar.'
  },
  {
    name: 'puerto',
    label: 'Puerto',
    type: 'number',
    required: false,
    default: 443,
    min: 1,
    max: 65535,
    help: 'Puerto TLS. 443 HTTPS, 465 SMTPS, 993 IMAPS, 995 POP3S, etc.'
  },
  {
    name: 'verificarCertificado',
    label: 'Exigir certificado valido (rejectUnauthorized)',
    type: 'checkbox',
    required: false,
    default: true,
    help: 'Si se desactiva, la conexion se abrira incluso con certificado invalido, y se auditaran los fallos. Util para diagnosticar servidores mal configurados.'
  },
  {
    name: 'timeout',
    label: 'Tiempo de espera',
    type: 'number',
    required: false,
    default: 10000,
    min: 500,
    max: 30000,
    unit: 'ms',
    help: 'Plazo maximo para establecer la conexion TLS y recibir el certificado.'
  }
];

async function ejecutar(params = {}, ctx = {}) {
  const inicio = new Date();
  const log = ctx.log || null;
  const timeout = normalizarTimeout(params.timeout, { defecto: 10000 });
  const host = String(params.host ?? '').trim();
  const puerto = Number(params.puerto ?? 443);
  const verificar = params.verificarCertificado === true;

  if (!host) {
    throw new NetlabError(CODES.PARAM_INVALIDO, 'El host es obligatorio.');
  }

  const result = createResult({
    tool: ID,
    toolTitle: TITLE,
    target: `${host}:${puerto}`,
    params: { ...params, contrasena: undefined }
  });

  try {
    const { certificado, avisos } = await conectar({
      host,
      port: puerto,
      verificar,
      timeout,
      servername: esIp(host) ? undefined : host
    });

    if (avisos?.length) {
      for (const aviso of avisos) {
        addLog(result, aviso.detail, aviso.severity);
      }
    }

    if (!certificado) {
      addFinding(result, {
        severity: 'error',
        title: 'No se pudo obtener el certificado',
        detail: 'La conexion TLS se establecio pero no se recibio certificado del peer.',
        recommendation: 'Verifica que el puerto hable TLS y no otro protocolo.'
      });
    } else {
      const secCert = addSection(result, K.TABLA, 'Ficha del Certificado', [
        { label: 'Sujeto (CN)', value: certificado.sujeto },
        { label: 'Emisor', value: certificado.emisor },
        { label: 'Organizacion (CA)', value: certificado.organizacion || '(no declarada)' },
        { label: 'Valido desde', value: certificado.validoDesde || 'desconocido' },
        { label: 'Valido hasta', value: certificado.validoHasta || 'desconocido' },
        { label: 'Dias restantes', value: certificado.diasRestantes !== null ? String(certificado.diasRestantes) : 'desconocido' },
        { label: 'Autofirmado', value: certificado.autoFirmado ? 'Si' : 'No' },
        { label: 'Protocolo', value: certificado.protocolo || 'desconocido' },
        { label: 'Cipher Suite', value: certificado.cifrado || 'desconocido' },
        { label: 'Nombres alternativos (SAN)', value: certificado.nombresAlternativos?.length ? certificado.nombresAlternativos.join(', ') : '(ninguno)' },
        { label: 'Validado por CA', value: certificado.autoridadCertificadora === true ? 'Si' : (certificado.autoridadCertificadora === false ? 'No' : 'desconocido') },
        { label: 'Motivo rechazo', value: certificado.motivoRechazo || '(ninguno)' }
      ]);

      if (certificado.nombresAlternativos?.length) {
        addSection(result, K.LISTA, 'Nombres Alternativos (SAN)', certificado.nombresAlternativos.map(n => ({ value: n })));
      }

      const hallazgos = auditarCertificado(certificado);
      for (const h of hallazgos) {
        addFinding(result, h);
      }

      addSummary(result, 'Estado del certificado', hallazgos.some(h => h.severity === 'error') ? 'Con errores' : (hallazgos.some(h => h.severity === 'warn') ? 'Con advertencias' : 'Valido'), hallazgos.some(h => h.severity === 'error') ? 'error' : (hallazgos.some(h => h.severity === 'warn') ? 'warn' : 'ok'));
    }

    if (avisos?.length) {
      addSection(result, K.NOTA, 'Avisos de la conexion', avisos.map(a => ({ value: `${a.title}: ${a.detail}` })));
    }

  } catch (error) {
    const wrapped = error instanceof NetlabError ? error : new NetlabError(CODES.RED, `No se pudo conectar por TLS a ${host}:${puerto}`, { remediation: 'Verifica host, puerto y conectividad de red.' }, error);
    addFinding(result, {
      severity: 'error',
      title: 'Error de conexion TLS',
      detail: wrapped.message,
      recommendation: wrapped.remediation
    });
  }

  return finalize(result);
}

module.exports = {
  id: ID,
  titulo: TITLE,
  descripcion: 'Inspecciona el certificado TLS/SSL de un host:puerto, valida la cadena de confianza, verifica expiracion, SANs, protocolo y cipher suite. Opcionalmente permite desactivar la verificacion para diagnosticar certificados invalidos.',
  icon: '🔒',
  sinRed: false,
  campos: CAMPOS,
  ejecutar
};