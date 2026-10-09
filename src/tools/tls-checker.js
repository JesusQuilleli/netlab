/**
 * tls-checker - Inspeccion de certificados TLS/SSL.
 *
 * Conecta a un host:puerto por TLS, extrae la ficha del certificado, sondea los
 * protocolos que acepta, mira si adjunta la prueba OCSP, comprueba HSTS, consulta
 * los registros de transparencia (CT) y califica la configuracion de A a F.
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
  SECCION_KINDS: K
} = require('../core/result');
const { NetlabError, CODES } = require('../core/errors');
const { normalizarTimeout } = require('../core/dominio');
const tlsNet = require('../core/net/tls');
const web = require('../core/net/web');

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
    label: 'Exigir certificado valido',
    type: 'checkbox',
    required: false,
    default: true,
    help: 'Si el certificado no es valido, la conexion se reintenta sin exigirlo para poder leerlo y explicar por que falla.'
  },
  {
    name: 'comprobarProtocolos',
    label: 'Probar versiones de TLS',
    type: 'checkbox',
    required: false,
    default: true,
    help: 'Abre una conexion por version (1.3, 1.2, 1.1, 1.0) para ver cuales acepta el servidor. Tarda unos segundos mas.'
  },
  {
    name: 'comprobarStapling',
    label: 'Comprobar stapling OCSP',
    type: 'checkbox',
    required: false,
    default: true,
    help: 'Pide al servidor la prueba de revocacion del certificado. Si no la adjunta, se anota en el informe.'
  },
  {
    name: 'comprobarHSTS',
    label: 'Comprobar HSTS',
    type: 'checkbox',
    required: false,
    default: true,
    help: 'Hace una peticion HTTPS para leer la cabecera Strict-Transport-Security. Solo aplica al puerto 443.'
  },
  {
    name: 'consultarCT',
    label: 'Consultar transparencia (crt.sh)',
    type: 'checkbox',
    required: false,
    default: false,
    help: 'Consulta los registros de transparencia de certificados en crt.sh. Requiere salida a Internet y puede tardar.'
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

/** Color de la tarjeta segun la nota. */
function tonoDeNota(letra) {
  if (letra === 'A' || letra === 'B') return 'ok';
  if (letra === 'C' || letra === 'D') return 'warn';
  return 'bad';
}

/**
 * Conexion con ficha del certificado. Primero exige validez; si falla, reintenta
 * sin exigirla para poder LEER el certificado y explicar por que no valia.
 *
 * @returns {Promise<{certificado, avisos, ocsp, verificado, motivoRechazo}>}
 */
async function conectarConFicha(opciones) {
  const { host, puerto, verificar, timeout, requestOCSP } = opciones;

  if (verificar) {
    try {
      const { socket, certificado, avisos, ocsp } = await tlsNet.conectar({
        host,
        port: puerto,
        verificar: true,
        timeout,
        requestOCSP,
        servername: tlsNet.esIp(host) ? undefined : host
      });
      socket.destroy?.();
      return { certificado, avisos, ocsp, verificado: true, motivoRechazo: null };
    } catch (error) {
      if (!(error instanceof NetlabError)) throw error;
      // Cae al reintento sin verificacion: hay algo que contar.
      const motivo = error.message;
      const reintento = await tlsNet.conectar({
        host,
        port: puerto,
        verificar: false,
        timeout,
        requestOCSP,
        servername: tlsNet.esIp(host) ? undefined : host
      });
      reintento.socket.destroy?.();
      return {
        certificado: reintento.certificado,
        avisos: reintento.avisos,
        ocsp: reintento.ocsp,
        verificado: false,
        motivoRechazo: motivo
      };
    }
  }

  const { socket, certificado, avisos, ocsp } = await tlsNet.conectar({
    host,
    port: puerto,
    verificar: false,
    timeout,
    requestOCSP,
    servername: tlsNet.esIp(host) ? undefined : host
  });
  socket.destroy?.();
  return { certificado, avisos, ocsp, verificado: false, motivoRechazo: certificado?.motivoRechazo || null };
}

/**
 * Lee la cabecera HSTS con una peticion HTTPS.
 *
 * @returns {Promise<{presente, valor, error}|null>}
 */
async function comprobarHsts(host, puerto, timeout) {
  try {
    const url = new URL(`https://${tlsNet.esIp(host) ? `[${host}]` : host}${puerto === 443 ? '' : `:${puerto}`}/`);
    const respuesta = await web.pedir(url, {
      metodo: 'HEAD',
      timeoutMs: Math.min(timeout, 8000),
      permitirPrivadas: true
    });
    const valor = respuesta.cabeceras?.['strict-transport-security'] || null;
    return { presente: Boolean(valor), valor: valor || null, error: null };
  } catch (error) {
    return { presente: null, valor: null, error: error.message };
  }
}

/**
 * Consulta crt.sh para ver si el certificado actual esta en los registros CT.
 *
 * @returns {Promise<object|null>} Resumen o null si no se pudo consultar.
 */
async function consultarCT(dominio, serial, timeout) {
  const controlador = new AbortController();
  const reloj = setTimeout(() => controlador.abort(), Math.min(timeout, 15000));
  try {
    const respuesta = await fetch(`https://crt.sh/?q=${encodeURIComponent(dominio)}&output=json`, {
      signal: controlador.signal,
      headers: { 'User-Agent': web.USER_AGENT }
    });
    if (!respuesta.ok) return { error: `crt.sh respondió ${respuesta.status}` };
    const entradas = await respuesta.json();
    if (!Array.isArray(entradas)) return { error: 'crt.sh devolvió un formato inesperado' };

    const serialBuscado = String(serial || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
    let encontrado = false;
    let emitido = null;
    let caduca = null;
    for (const entrada of entradas) {
      const s = String(entrada.serial_number || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
      if (serialBuscado && s && s === serialBuscado) {
        encontrado = true;
        emitido = entrada.not_before || emitido;
        caduca = entrada.not_after || caduca;
      }
    }
    return { total: entradas.length, encontrado, emitido, caduca, error: null };
  } catch (error) {
    return { error: error.name === 'AbortError' ? 'crt.sh no respondió a tiempo' : error.message };
  } finally {
    clearTimeout(reloj);
  }
}

async function ejecutar(params = {}, ctx = {}) {
  const log = ctx.log || null;
  const timeout = normalizarTimeout(params.timeout, { defecto: 10000 });
  const host = String(params.host ?? '').trim();
  const puerto = Number(params.puerto ?? 443);
  const verificar = params.verificarCertificado !== false;
  const probarProtocolos = params.comprobarProtocolos !== false;
  const comprobarStapling = params.comprobarStapling !== false;
  const revisarHsts = params.comprobarHSTS !== false;
  const revisarCT = params.consultarCT === true;

  if (!host) {
    throw new NetlabError(CODES.PARAM_INVALIDO, 'El host es obligatorio.');
  }

  const result = createResult({
    tool: ID,
    toolTitle: TITLE,
    target: `${host}:${puerto}`,
    params: { ...params }
  });

  try {
    const { certificado, avisos, ocsp, verificado, motivoRechazo } = await conectarConFicha({
      host,
      puerto,
      verificar,
      timeout,
      requestOCSP: comprobarStapling
    });

    for (const aviso of avisos || []) {
      addLog(result, aviso.detail, aviso.severity);
    }

    if (!certificado) {
      addFinding(result, {
        severity: 'error',
        title: 'No se pudo obtener el certificado',
        detail: 'La conexión TLS se estableció pero no se recibió certificado del peer.',
        recommendation: 'Verifica que el puerto hable TLS y no otro protocolo.'
      });
      return finalize(result);
    }

    addSummary(result, 'Verificación', verificado ? 'Certificado válido' : 'No válido', verificado ? 'ok' : 'bad');
    addSummary(result, 'Protocolo', certificado.protocolo || 'desconocido', 'neutral');

    // Ficha del certificado.
    addSection(result, {
      title: 'Ficha del certificado',
      kind: K.PARES,
      items: [
        { label: 'Sujeto (CN)', value: certificado.sujeto },
        { label: 'Emisor', value: certificado.emisor },
        { label: 'Organizacion (CA)', value: certificado.organizacion || '(no declarada)' },
        { label: 'Valido desde', value: certificado.validoDesde || 'desconocido' },
        { label: 'Valido hasta', value: certificado.validoHasta || 'desconocido' },
        {
          label: 'Dias restantes',
          value: certificado.diasRestantes !== null ? String(certificado.diasRestantes) : 'desconocido',
          tone: certificado.diasRestantes !== null && certificado.diasRestantes < 0 ? 'bad' : certificado.caducaPronto ? 'warn' : 'ok'
        },
        { label: 'Autofirmado', value: certificado.autoFirmado ? 'Si' : 'No', tone: certificado.autoFirmado ? 'bad' : 'ok' },
        { label: 'Algoritmo de firma', value: certificado.algoritmoFirma || 'desconocido' },
        {
          label: 'Clave publica',
          value:
            certificado.tipoClave
              ? `${String(certificado.tipoClave).toUpperCase()}${certificado.tamanoClave ? ` de ${certificado.tamanoClave} bits` : ''}`
              : 'desconocido'
        },
        { label: 'Cipher Suite', value: certificado.cifrado || 'desconocido' },
        { label: 'Serie', value: certificado.serial || 'desconocido' },
        { label: 'Huella SHA-256', value: certificado.huella256 || 'desconocida' },
        { label: 'Validado por CA', value: certificado.autoridadCertificadora === true ? 'Si' : 'No', tone: certificado.autoridadCertificadora === true ? 'ok' : 'bad' },
        { label: 'Motivo rechazo', value: certificado.motivoRechazo || motivoRechazo || '(ninguno)' }
      ]
    });

    // Cadena.
    if (Array.isArray(certificado.cadena) && certificado.cadena.length) {
      addSection(result, {
        title: 'Cadena de certificados',
        description: 'Eslabones que envía el servidor, de la hoja a la raíz. Si falta el intermedio, algunos clientes no podrán validar la cadena.',
        kind: K.TABLA,
        columns: ['Nivel', 'Sujeto (CN)', 'Emisor', 'Valido hasta', 'Autofirmado'],
        rows: certificado.cadena.map((c) => [
          String(c.nivel),
          c.sujeto,
          c.emisor,
          c.validoHasta || 'desconocido',
          c.autoFirmado ? 'Si' : 'No'
        ])
      });
    }

    if (certificado.nombresAlternativos?.length) {
      addSection(result, {
        title: 'Nombres alternativos (SAN)',
        kind: K.LISTA,
        items: certificado.nombresAlternativos.map((n) => ({ value: n.replace(/^DNS:/, '') }))
      });
    }

    // Protocolos.
    let protocolos = {};
    if (probarProtocolos) {
      protocolos = await tlsNet.sondearProtocolos({
        host,
        port: puerto,
        timeout: Math.min(timeout, 8000)
      });
    }

    // Stapling.
    const stapled = comprobarStapling ? Boolean(ocsp) : null;

    // HSTS.
    let hsts = null;
    if (revisarHsts && puerto === 443) {
      hsts = await comprobarHsts(host, puerto, timeout);
    }

    // Nota.
    const nota = tlsNet.calcularNota({
      protocoloNegociado: certificado.protocolo,
      protocolos,
      certificado,
      cifradoDebil: tlsNet.esCifradoDebil(certificado.cifrado),
      forwardSecrecy: tlsNet.tieneForwardSecrecy(certificado.cifrado, certificado.protocolo),
      ocspStapled: stapled,
      hsts
    });

    addSummary(result, 'Nota TLS', nota.letra, tonoDeNota(nota.letra));

    if (probarProtocolos) {
      addSection(result, {
        title: 'Versiones de TLS aceptadas',
        description: 'Cada versión se prueba con una conexión aparte. "No comprobable" significa que este cliente no puede ofrecer esa versión (OpenSSL moderno ya no ofrece TLS 1.0/1.1), no que el servidor la rechace.',
        kind: K.TABLA,
        columns: ['Version', 'Aceptada', 'Lectura'],
        rows: ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1'].map((v) => {
          const valor = protocolos[v];
          const etiqueta = valor === true ? 'Si' : valor === false ? 'No' : 'No comprobable';
          return [v, etiqueta, valor === true ? 'El servidor la ofrece' : valor === false ? 'El servidor la rechaza' : 'Fuera del alcance de este cliente'];
        })
      });
    }

    addSection(result, {
      title: 'Cifrado y revocación',
      kind: K.PARES,
      items: [
        { label: 'Cipher negociado', value: certificado.cifrado || 'desconocido', tone: tlsNet.esCifradoDebil(certificado.cifrado) ? 'bad' : 'ok' },
        { label: 'Secreto hacia adelante', value: tlsNet.tieneForwardSecrecy(certificado.cifrado, certificado.protocolo) ? 'Si' : 'No', tone: tlsNet.tieneForwardSecrecy(certificado.cifrado, certificado.protocolo) ? 'ok' : 'warn' },
        {
          label: 'Stapling OCSP',
          value: stapled === null ? '(no comprobado)' : stapled ? 'Si' : 'No',
          tone: stapled === false ? 'warn' : stapled === true ? 'ok' : 'neutral'
        },
        ...(hsts && hsts.presente !== null
          ? [
              { label: 'HSTS', value: hsts.presente ? hsts.valor : 'No enviado', tone: hsts.presente ? 'ok' : 'warn' }
            ]
          : []),
        ...(hsts && hsts.error ? [{ label: 'HSTS (error)', value: hsts.error, tone: 'neutral' }] : [])
      ]
    });

    // Deducciones de la nota.
    if (nota.caps.length || nota.deducciones.length) {
      const filas = [
        ...nota.caps.map((c) => ['Crítico', c.titulo, c.razon]),
        ...nota.deducciones.map((d) => [`-${d.puntos}`, d.titulo, d.razon])
      ];
      addSection(result, {
        title: `Por qué la nota es ${nota.letra} (${nota.puntos}/100)`,
        kind: K.TABLA,
        columns: ['Impacto', 'Motivo', 'Detalle'],
        rows: filas
      });
    } else {
      addSection(result, {
        title: `Nota ${nota.letra} (${nota.puntos}/100)`,
        kind: K.TEXTO,
        value: nota.resumen
      });
    }

    // Transparencia de certificados.
    if (revisarCT) {
      const dominio = (certificado.nombresAlternativos?.[0] || host).replace(/^DNS:/, '').replace(/^\*\./, '');
      const ct = await consultarCT(dominio, certificado.serial, timeout);
      if (ct && !ct.error) {
        addSection(result, {
          title: 'Transparencia de certificados (CT)',
          description: `Consulta a crt.sh sobre ${dominio}. Un certificado activo que no aparece en los registros CT puede indicar un problema de emisión.`,
          kind: K.PARES,
          items: [
            { label: 'Certificados emitidos para el dominio', value: String(ct.total) },
            { label: 'El certificado actual aparece en CT', value: ct.encontrado ? 'Si' : 'No', tone: ct.encontrado ? 'ok' : 'bad' },
            ...(ct.encontrado && ct.emitido ? [{ label: 'Emitido', value: ct.emitido }] : []),
            ...(ct.encontrado && ct.caduca ? [{ label: 'Caduca', value: ct.caduca }] : [])
          ]
        });
      } else {
        addLog(result, { level: 'warn', channel: 'ct', message: `No se pudo consultar crt.sh: ${ct?.error || 'sin respuesta'}` });
      }
    }

    // Hallazgos.
    for (const h of tlsNet.auditarCertificado(certificado)) {
      addFinding(result, h);
    }
  } catch (error) {
    const wrapped =
      error instanceof NetlabError
        ? error
        : new NetlabError(
            CODES.RED,
            `No se pudo conectar por TLS a ${host}:${puerto}`,
            { remediation: 'Verifica host, puerto y conectividad de red.' },
            error
          );
    addFinding(result, {
      severity: 'error',
      title: 'Error de conexión TLS',
      detail: wrapped.message,
      recommendation: wrapped.remediation
    });
  }

  return finalize(result);
}

module.exports = {
  id: ID,
  titulo: TITLE,
  descripcion:
    'Inspecciona el certificado TLS/SSL de un host:puerto: cadena de confianza, expiración, SANs, versiones de TLS aceptadas, cifrado, stapling OCSP, HSTS y transparencia de certificados. Califica la configuración de A a F explicando cada punto perdido.',
  icon: '🔒',
  sinRed: false,
  campos: CAMPOS,
  ejecutar
};
