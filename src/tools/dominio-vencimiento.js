/**
 * dominio-vencimiento - Consulta caducidad y datos de un dominio (RDAP + WHOIS fallback).
 *
 * Usa RDAP como fuente principal (estructurado, estandar) y WHOIS como
 * fallback para TLDs sin RDAP publico o cuando RDAP falla.
 *
 * @module tools/dominio-vencimiento
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
const { normalizarTimeout, normalizarDominio } = require('../core/dominio');
const { consultarDominio } = require('../core/net/rdap');

const ID = 'dominio-vencimiento';
const TITLE = 'Expiracion y Datos de Dominio';

const CAMPOS = [
  {
    name: 'dominio',
    label: 'Dominio',
    type: 'text',
    required: true,
    placeholder: 'ejemplo.com',
    help: 'Dominio a consultar. Se limpia automaticamente (quita https://, rutas, etc.).'
  },
  {
    name: 'timeout',
    label: 'Tiempo de espera',
    type: 'number',
    required: false,
    default: 12000,
    min: 1000,
    max: 30000,
    unit: 'ms',
    help: 'Plazo maximo por consulta (RDAP y WHOIS).'
  }
];

let whoisModulo = null;
function cargarWhois() {
  if (whoisModulo !== null) return whoisModulo;
  try {
    whoisModulo = require('whois');
    return whoisModulo;
  } catch {
    whoisModulo = false;
    return null;
  }
}

function consultarWhois(dominio, timeoutMs) {
  const whois = cargarWhois();
  if (!whois) return Promise.resolve({ disponible: false, raw: null, error: 'Modulo whois no instalado' });

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ disponible: false, raw: null, error: 'Timeout WHOIS' });
    }, timeoutMs);

    whois.lookup(dominio, (err, data) => {
      clearTimeout(timer);
      if (err) {
        resolve({ disponible: false, raw: null, error: err.message });
      } else {
        resolve({ disponible: true, raw: data, error: null });
      }
    });
  });
}

function parsearWhois(raw, dominio) {
  if (!raw) return null;

  const lineas = raw.split('\n').map(l => l.trim()).filter(Boolean);
  const resultado = {
    dominio,
    fuente: 'whois',
    registrador: null,
    creacion: null,
    expiracion: null,
    actualizacion: null,
    estados: [],
    nameservers: [],
    titular: null,
    email: null,
    raw: raw.slice(0, 5000)
  };

  const patrones = {
    registrador: [/registrar:\s*(.+)/i, /sponsoring registrar:\s*(.+)/i, /registrar name:\s*(.+)/i],
    creacion: [/creation date:\s*(.+)/i, /created:\s*(.+)/i, /registered:\s*(.+)/i, /registration date:\s*(.+)/i],
    expiracion: [/expir(?:y|ation) date:\s*(.+)/i, /registry expiry date:\s*(.+)/i, /expires:\s*(.+)/i],
    actualizacion: [/updated date:\s*(.+)/i, /last updated:\s*(.+)/i, /modified:\s*(.+)/i],
    estado: [/status:\s*(.+)/i, /domain status:\s*(.+)/i],
    nameserver: [/name server:\s*(.+)/i, /nserver:\s*(.+)/i, /nameserver:\s*(.+)/i],
    titular: [/registrant:\s*(.+)/i, /owner:\s*(.+)/i],
    email: [/email:\s*(.+)/i, /registrant email:\s*(.+)/i]
  };

  for (const linea of lineas) {
    const lower = linea.toLowerCase();
    for (const [campo, regexs] of Object.entries(patrones)) {
      for (const regex of regexs) {
        const match = linea.match(regex);
        if (match) {
          const valor = match[1].trim();
          if (campo === 'estado' || campo === 'nameserver') {
            if (!resultado[campo]) resultado[campo] = [];
            resultado[campo].push(valor);
          } else if (!resultado[campo]) {
            resultado[campo] = valor;
          }
          break;
        }
      }
    }
  }

  return resultado;
}

function formatearFecha(fechaStr) {
  if (!fechaStr) return null;
  const fecha = new Date(fechaStr);
  if (isNaN(fecha.getTime())) return fechaStr;
  return fecha.toISOString().split('T')[0];
}

function diasHasta(fechaStr) {
  if (!fechaStr) return null;
  const fecha = new Date(fechaStr);
  if (isNaN(fecha.getTime())) return null;
  const diff = fecha.getTime() - Date.now();
  return Math.floor(diff / 86400000);
}

function combinarResultados(rdap, whois, dominio) {
  const combinado = {
    dominio,
    fuente: rdap?.disponible ? 'rdap' : (whois?.disponible ? 'whois' : 'none'),
    consultable: rdap?.consultable === true || whois?.disponible === true,
    registrador: rdap?.registrador || whois?.registrador || null,
    creacion: rdap?.registro ? formatearFecha(rdap.registro) : (whois?.creacion ? formatearFecha(whois.creacion) : null),
    expiracion: rdap?.caducidad ? formatearFecha(rdap.caducidad) : (whois?.expiracion ? formatearFecha(whois.expiracion) : null),
    actualizacion: rdap?.ultimoCambio ? formatearFecha(rdap.ultimoCambio) : (whois?.actualizacion ? formatearFecha(whois.actualizacion) : null),
    estados: rdap?.estados ? rdap.estados.split(', ').map(s => s.trim()) : (whois?.estados || []),
    nameservers: rdap?.nombreservers || whois?.nameservers || [],
    titular: rdap?.titular || whois?.titular || null,
    email: rdap?.nota || whois?.email || null,
    caducidad: rdap?.caducidad ? formatearFecha(rdap.caducidad) : (whois?.expiracion ? formatearFecha(whois.expiracion) : null),
    diasRestantes: null
  };

  combinado.diasRestantes = diasHasta(combinado.expiracion);
  return combinado;
}

async function ejecutar(params = {}, ctx = {}) {
  const inicio = new Date();
  const log = ctx.log || null;
  const timeout = normalizarTimeout(params.timeout, { defecto: 12000 });

  let dominio;
  try {
    dominio = normalizarDominio(params.dominio);
  } catch (e) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `Dominio invalido: ${e.message}`);
  }

  const result = createResult({
    tool: ID,
    toolTitle: TITLE,
    target: dominio,
    params: { dominio, timeout }
  });

  addLog(result, `Consultando ${dominio} via RDAP...`, 'info');

  // 1. Consultar RDAP (primario)
  let rdapData = null;
  try {
    rdapData = await consultarDominio(dominio, { timeoutMs: timeout });
    if (rdapData?.disponible) {
      addLog(result, 'RDAP: datos obtenidos', 'ok');
    } else if (rdapData?.consultable === false) {
      addLog(result, `RDAP: no disponible para este TLD (${rdapData.motivo})`, 'warn');
    } else {
      addLog(result, `RDAP: ${rdapData.motivo || 'sin datos'}`, 'warn');
    }
  } catch (e) {
    addLog(result, `RDAP: error - ${e.message}`, 'warn');
    rdapData = { disponible: false, consultable: false, error: e.message };
  }

  // 2. WHOIS fallback (siempre intentar para maximo detalle)
  addLog(result, `Consultando ${dominio} via WHOIS...`, 'info');
  let whoisData = null;
  try {
    whoisData = await consultarWhois(dominio, timeout);
    if (whoisData?.disponible) {
      addLog(result, 'WHOIS: datos obtenidos', 'ok');
    } else {
      addLog(result, `WHOIS: ${whoisData?.error || 'sin datos'}`, 'warn');
    }
  } catch (e) {
    addLog(result, `WHOIS: error - ${e.message}`, 'warn');
  }

  // 3. Combinar resultados (RDAP prioritario, WHOIS rellena huecos)
  const datos = combinarResultados(rdapData, whoisData, dominio);

  // Seccion: Datos principales
  const filasPrincipales = [
    ['Dominio', datos.dominio],
    ['Fuente principal', datos.fuente.toUpperCase()],
    ['Consultable', datos.consultable ? 'Si' : 'No'],
    ['Registrador', datos.registrador || 'desconocido'],
    ['Fecha de creacion', datos.creacion || 'desconocida'],
    ['Fecha de expiracion', datos.expiracion || 'desconocida'],
    ['Ultima actualizacion', datos.actualizacion || 'desconocida'],
    ['Dias hasta expiracion', datos.diasRestantes !== null ? `${datos.diasRestantes} dias` : 'desconocido'],
    ['Nameservers', datos.nameservers?.length ? datos.nameservers.join(', ') : 'desconocidos'],
    ['Titular', datos.titular || 'privado/desconocido']
  ];

addSection(result, {
      id: 'datos-principales',
      title: 'Datos del Dominio',
      kind: K.TABLA,
      columns: ['Campo', 'Valor'],
      rows: filasPrincipales
    });

  // Alertas por expiracion
  if (datos.diasRestantes !== null) {
    if (datos.diasRestantes < 0) {
      addFinding(result, {
        severity: 'error',
        title: 'Dominio EXPIRADO',
        detail: `Expiro hace ${Math.abs(datos.diasRestantes)} dias (${datos.expiracion}).`,
        recommendation: 'Renueva inmediatamente en tu registrador para evitar perder el dominio.'
      });
    } else if (datos.diasRestantes <= 15) {
      addFinding(result, {
        severity: 'warn',
        title: 'Dominio por expirar',
        detail: `Quedan ${datos.diasRestantes} dias (expira ${datos.expiracion}).`,
        recommendation: 'Renueva cuanto antes. No esperes al ultimo dia.'
      });
    } else if (datos.diasRestantes <= 60) {
      addFinding(result, {
        severity: 'info',
        title: 'Dominio expira en menos de 60 dias',
        detail: `Quedan ${datos.diasRestantes} dias (expira ${datos.expiracion}).`,
        recommendation: 'Planifica la renovacion con antelacion.'
      });
    } else {
      addFinding(result, {
        severity: 'ok',
        title: 'Dominio vigente',
        detail: `Expira en ${datos.diasRestantes} dias (${datos.expiracion}).`,
        recommendation: null
      });
    }
  }

  // Estados del dominio
  if (datos.estados?.length) {
    addSection(result, {
      id: 'estados',
      title: 'Estados del Dominio',
      kind: K.LISTA,
      items: datos.estados.map(e => ({ value: e }))
    });
  }

  // Nameservers
  if (datos.nameservers?.length) {
    addSection(result, {
      id: 'nameservers',
      title: 'Nameservers',
      kind: K.LISTA,
      items: datos.nameservers.map(ns => ({ value: ns }))
    });
  }

  // Resumen
  const estado = datos.diasRestantes !== null
    ? (datos.diasRestantes < 0 ? 'expirado' : (datos.diasRestantes <= 15 ? 'critico' : (datos.diasRestantes <= 60 ? 'proximo' : 'ok')))
    : 'desconocido';

  addSummary(result, 'Estado de caducidad', estado.charAt(0).toUpperCase() + estado.slice(1), estado === 'expirado' ? 'error' : (estado === 'critico' ? 'warn' : (estado === 'proximo' ? 'info' : 'ok')));

  // Fuentes usadas
  const fuentes = [];
  if (rdapData?.disponible) fuentes.push('RDAP');
  if (whoisData?.disponible) fuentes.push('WHOIS');
  if (fuentes.length) {
    addLog(result, `Fuentes: ${fuentes.join(' + ')}`, 'info');
  }

  return finalize(result);
}

module.exports = {
  id: ID,
  titulo: TITLE,
  descripcion: 'Consulta la fecha de expiracion, registrador, estados y nameservers de un dominio usando RDAP (principal) y WHOIS (fallback). Detecta dominios expirados, por expirar y muestra dias restantes.',
  icon: '📅',
  sinRed: false,
  campos: CAMPOS,
  ejecutar
};