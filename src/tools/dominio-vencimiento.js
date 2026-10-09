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
const dnsNet = require('../core/net/dns');

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
        // El parser se aplica aqui: sin esto, `combinarResultados` recibia el
        // texto crudo y todos los campos whois salian vacios en el informe.
        resolve({ disponible: true, ...parsearWhois(data, dominio), raw: data, error: null });
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
    registradorId: null,
    creacion: null,
    expiracion: null,
    actualizacion: null,
    estados: [],
    nameservers: [],
    titular: null,
    org: null,
    email: null,
    raw: raw.slice(0, 5000)
  };

  const patrones = {
    registrador: [/registrar:\s*(.+)/i, /sponsoring registrar:\s*(.+)/i, /registrar name:\s*(.+)/i],
    registradorId: [/registrar iana id:\s*(.+)/i, /iana registrar id:\s*(.+)/i, /registrar id:\s*(.+)/i],
    creacion: [/creation date:\s*(.+)/i, /registered:\s*(.+)/i, /registration date:\s*(.+)/i, /created:\s*(.+)/i],
    expiracion: [/expir(?:y|ation) date:\s*(.+)/i, /registry expiry date:\s*(.+)/i, /expire:\s*(.+)/i, /expires:\s*(.+)/i],
    actualizacion: [/updated date:\s*(.+)/i, /last updated:\s*(.+)/i, /changed:\s*(.+)/i, /modified:\s*(.+)/i],
    estados: [/status:\s*(.+)/i, /domain status:\s*(.+)/i],
    nameservers: [/name server:\s*(.+)/i, /nserver:\s*(.+)/i, /nameserver:\s*(.+)/i],
    // La organizacion se guarda aparte y manda sobre el `registrant:`: en
    // NIC.VE (y en otros registros) el registrant es un codigo de contacto
    // (CON000073989) y el nombre real esta en el bloque `org:`.
    org: [/^org:\s*(.+)/i, /registrant organization:\s*(.+)/i],
    titular: [/registrant(?: name)?:\s*(.+)/i, /owner:\s*(.+)/i],
    email: [/registrant email:\s*(.+)/i, /email:\s*(.+)/i]
  };

  for (const linea of lineas) {
    for (const [campo, regexs] of Object.entries(patrones)) {
      for (const regex of regexs) {
        const match = linea.match(regex);
        if (match) {
          let valor = match[1].trim();
          if (campo === 'estados') {
            valor = limpiarEstadoWhois(valor);
            if (valor && !resultado.estados.includes(valor)) resultado.estados.push(valor);
          } else if (campo === 'nameservers') {
            const ns = valor.replace(/\.$/, '').toLowerCase();
            if (ns && !resultado.nameservers.includes(ns)) resultado.nameservers.push(ns);
          } else if (!resultado[campo]) {
            resultado[campo] = valor;
          }
          break;
        }
      }
    }
  }

  // La organizacion real gana al codigo de contacto del registrant.
  if (resultado.org) resultado.titular = resultado.org;

  return resultado;
}

/**
 * Los WHOIS devuelven los estados EPP pegados a la URL de ICANN y en
 * camelCase: `clientTransferProhibited https://icann.org/epp#clientTransferProhibited`.
 * En el informe eso es ilegible y repetido; se pasa a `client transfer
 * prohibited` y se descarta la URL.
 */
function limpiarEstadoWhois(valor) {
  const base = String(valor).trim().split(/\s+/)[0] || '';
  if (!base || /^https?:/i.test(base)) return null;
  return base.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase();
}

function formatearFecha(fechaStr) {
  if (!fechaStr) return null;
  let texto = String(fechaStr).trim();

  // Formato de NIC.VE y de otros registros: DD.MM.YYYY [HH:MM:SS]. JavaScript
  // no lo interpreta de forma fiable (a veces lo toma como MM.DD), asi que se
  // convierte a ISO antes de pasarlo por Date. Se anade Z: sin zona horaria,
  // Date lo trata como hora local y el dia puede correrse un dia al pasar a
  // UTC segun el TZ del servidor.
  const ve = texto.match(/^(\d{2})\.(\d{2})\.(\d{4})(?:\s+(\d{1,2}:\d{2}:\d{2}))?$/);
  if (ve) texto = `${ve[3]}-${ve[2]}-${ve[1]}T${ve[4] || '00:00:00'}Z`;

  const fecha = new Date(texto);
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
  // RDAP devuelve los estados como texto pegado ("a, b, c") y WHOIS como
  // lista; se unen y deduplican para que la tabla salga completa venga de
  // donde venga.
  const estadosRdap = rdap?.estados
    ? String(rdap.estados).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    : [];
  const estadosWhois = Array.isArray(whois?.estados) ? whois.estados : [];
  const estados = [...new Set([...estadosRdap, ...estadosWhois])];

  const nsRdap = Array.isArray(rdap?.nombreservers)
    ? rdap.nombreservers.map((n) => String(n).replace(/\.$/, '').toLowerCase()).filter(Boolean)
    : [];
  const nsWhois = Array.isArray(whois?.nameservers) ? whois.nameservers : [];
  const nameservers = [...new Set([...nsRdap, ...nsWhois])];

  const combinado = {
    dominio,
    fuente: rdap?.disponible ? 'rdap' : (whois?.disponible ? 'whois' : 'none'),
    consultable: rdap?.consultable === true || whois?.disponible === true,
    registrador: rdap?.registrador || whois?.registrador || null,
    registradorId: rdap?.registradorId || whois?.registradorId || null,
    creacion: rdap?.registro ? formatearFecha(rdap.registro) : (whois?.creacion ? formatearFecha(whois.creacion) : null),
    expiracion: rdap?.caducidad ? formatearFecha(rdap.caducidad) : (whois?.expiracion ? formatearFecha(whois.expiracion) : null),
    actualizacion: rdap?.ultimoCambio ? formatearFecha(rdap.ultimoCambio) : (whois?.actualizacion ? formatearFecha(whois.actualizacion) : null),
    estados,
    nameservers,
    titular: rdap?.titular || whois?.titular || null,
    email: whois?.email || null,
    nota: rdap?.nota || null,
    caducidad: rdap?.caducidad ? formatearFecha(rdap.caducidad) : (whois?.expiracion ? formatearFecha(whois.expiracion) : null),
    diasRestantes: null
  };

  combinado.diasRestantes = diasHasta(combinado.expiracion);
  return combinado;
}

/* ------------------------------------------------------------------ *
 * DNSSEC
 * ------------------------------------------------------------------ */

/** Nombre de los algoritmos de firma (RFC 4034 y posteriores). */
const ALGORITMOS_DNSSEC = {
  5: 'RSASHA1',
  7: 'RSASHA1-NSEC3-SHA1',
  8: 'RSASHA256',
  10: 'RSASHA512',
  13: 'ECDSAP256SHA256',
  14: 'ECDSAP384SHA384',
  15: 'ED25519',
  16: 'ED448'
};

function nombrarAlgoritmo(algorithm) {
  return ALGORITMOS_DNSSEC[algorithm] || `algoritmo ${algorithm}`;
}

/**
 * Consulta DNSKEY y DS del dominio.
 *
 * No lanza: un fallo de red deja `{dnskey: null, ds: null}` y el informe dice
 * que no se ha podido comprobar, que no es lo mismo que decir que no está
 * firmado. La consulta entra por `ctx.dns` para que las pruebas no salgan a la
 * red y el resto de consultas del módulo pueda reutilizar el mismo inyector.
 */
async function consultarDnssec(result, dominio, timeout, ctx) {
  const dns = ctx?.dns || dnsNet;
  try {
    const [dnskey, ds] = await Promise.all([
      dns.consultar(dominio, 'DNSKEY', { timeout }),
      dns.consultar(dominio, 'DS', { timeout })
    ]);
    addLog(result, `DNSSEC: DNSKEY ${dnskey?.ok ? dnskey.valores.length + ' claves' : 'sin dato'} · DS ${ds?.ok ? ds.valores.length + ' registro(s)' : 'sin dato'}`, 'info');
    return { dnskey, ds };
  } catch (e) {
    addLog(result, `DNSSEC: no se pudo consultar (${e.message})`, 'warn');
    return { dnskey: null, ds: null };
  }
}

/**
 * Decide, en un solo sitio, cuál es la verdad de la cadena DNSSEC.
 *
 * Pintar la tabla y escribir los hallazgos con dos lógicas distintas es la
 * forma más rápida de que un informe diga "verificada" arriba y "rota" abajo.
 * `verificacion` es la única fuente de verdad para las dos cosas.
 *
 * @returns {{verificacion: string, tenidoDatos: boolean}}
 */
function verificarDnssec({ dominio, dnskey, ds }) {
  const firmado = Boolean(dnskey?.ok && dnskey.valores.length);
  const dsConDatos = Boolean(ds?.ok && ds.valores.length);

  if (!firmado) {
    if (dsConDatos) return { verificacion: 'ds-sin-claves', tenidoDatos: true };
    if (dnskey?.ok) return { verificacion: 'sin-firma', tenidoDatos: true };
    return { verificacion: 'sin-datos', tenidoDatos: false };
  }

  if (!dsConDatos) return { verificacion: 'firmado-sin-ds', tenidoDatos: true };

  const tags = new Set(dnskey.valores.map((v) => v.keyTag));
  const coinciden = ds.valores.filter((d) => tags.has(d.keyTag));
  if (!coinciden.length) return { verificacion: 'ds-sin-clave', tenidoDatos: true };

  const rotos = coinciden.filter((d) => {
    const clave = dnskey.valores.find((v) => v.keyTag === d.keyTag);
    const calculado = dnsNet.calcularDigestoDs(clave, dominio, d.digestType);
    return calculado !== null && calculado !== d.digestHex;
  });
  if (rotos.length) return { verificacion: 'digest-roto', tenidoDatos: true };

  return { verificacion: 'valido', tenidoDatos: true };
}

/** La fila de estado y el tono, para la tabla y para la tarjeta. */
function estadoVisibleDnssec(v) {
  switch (v.verificacion) {
    case 'valido': return ['Firmado y verificado', 'ok'];
    case 'sin-firma': return ['Sin DNSSEC', 'neutral'];
    case 'firmado-sin-ds': return ['Firmado sin DS', 'warn'];
    case 'ds-sin-claves': return ['DS sin claves publicadas', 'bad'];
    case 'ds-sin-clave': return ['DS sin clave coincidente', 'bad'];
    case 'digest-roto': return ['DS que no verifica', 'bad'];
    default: return ['No se pudo comprobar', 'neutral'];
  }
}

function pintarDnssec(result, args) {
  const v = verificarDnssec(args);
  const { dnskey, ds } = args;
  const firmado = Boolean(dnskey?.ok && dnskey.valores.length);
  const dsConDatos = Boolean(ds?.ok && ds.valores.length);
  const [estado, tono] = estadoVisibleDnssec(v);
  const algoritmos = firmado
    ? [...new Set(dnskey.valores.map((k) => nombrarAlgoritmo(k.algorithm)))].join(', ')
    : null;

  addSection(result, {
    id: 'dnssec',
    title: 'DNSSEC',
    description: 'Si el dominio está firmado, la zona padre publica un DS que apunta a su clave de firma. Que la cadena cierre significa que un validador no puede dejar que otra persona firme respuestas en su lugar.',
    kind: K.TABLA,
    columns: ['Dato', 'Valor'],
    rows: [
      ['Estado', { valor: estado, tone: tono }],
      ['Claves DNSKEY', firmado ? `${dnskey.valores.length} clave(s) — ${algoritmos}` : 'Sin firmar'],
      ['KSK publicadas', firmado ? dnskey.valores.filter((k) => (k.flags & 0x0001) !== 0).length : '—'],
      ['DS en la zona padre', dsConDatos ? ds.valores.map((d) => `keyTag ${d.keyTag}`).join(', ') : 'Ninguno'],
      ['Verificación del DS', v.verificacion === 'valido' ? 'Coincide con la clave publicada' : v.verificacion === 'digest-roto' ? 'No coincide con la clave publicada' : v.verificacion === 'sin-datos' ? 'No consultable' : '—']
    ]
  });
}

function revisarDnssec(result, args) {
  const v = verificarDnssec(args);
  const { dominio } = args;

  switch (v.verificacion) {
    case 'valido':
      addFinding(result, {
        severity: 'ok',
        title: 'DNSSEC vigente y verificado',
        detail: `El DS de la zona padre coincide con el digest recalculado sobre la clave publicada de ${dominio}. La cadena de confianza cierra.`,
        recommendation: 'Nada que corregir. Al rotar claves, publica el nuevo DS antes de retirar la clave antigua.'
      });
      break;
    case 'sin-firma':
      addFinding(result, {
        severity: 'info',
        title: 'El dominio no está firmado con DNSSEC',
        detail: 'No hay registros DNSKEY. Sin firma no hay cadena que validar: cada respuesta viaja sin garantía de que la enviara la zona real.',
        recommendation: 'Firmar es opcional y siempre exige publicar el DS en la zona padre. Si no necesitas DNSSEC, no es un fallo.'
      });
      break;
    case 'firmado-sin-ds':
      addFinding(result, {
        severity: 'warn',
        title: 'El dominio está firmado pero la zona padre no publica su DS',
        detail: `${dominio} publica DNSKEY pero no hay ningún registro DS en la zona de arriba. Un validador estricto no puede enlazar con la raíz de confianza.`,
        recommendation: 'Publica el DS con el keyTag y el algoritmo de la KSK en el registrador. Es el paso que conecta la zona con la de arriba.'
      });
      break;
    case 'ds-sin-claves':
      addFinding(result, {
        severity: 'error',
        title: 'La zona padre tiene DS pero el dominio no publica las claves',
        detail: `Hay ${args.ds.valores.length} registro(s) DS apuntando a claves que ${dominio} no publica. Un validador busca la clave, no la encuentra y la resolución acaba en SERVFAIL.`,
        recommendation: 'Publica la DNSKEY correspondiente o retira el DS de la zona padre si la clave ya no debe existir.'
      });
      break;
    case 'ds-sin-clave':
      addFinding(result, {
        severity: 'error',
        title: 'El DS no corresponde con ninguna clave publicada',
        detail: `El DS anuncia ${args.ds.valores.map((d) => `keyTag ${d.keyTag}`).join(', ')} pero ${dominio} publica ${args.dnskey.valores.map((k) => `keyTag ${k.keyTag}`).join(', ')}.`,
        recommendation: 'Actualiza el DS a la KSK actual, o publica en la zona la clave que el DS promete. Ambos han de convivir durante la transición.'
      });
      break;
    case 'digest-roto':
      addFinding(result, {
        severity: 'error',
        title: 'El DS no coincide con el contenido de la clave',
        detail: 'El keyTag encaja pero el digest del DS no se corresponde con el recalculado sobre la DNSKEY publicada. El validador rechaza la cadena y el dominio puede fallar al resolver.',
        recommendation: 'Vuelve a generar el DS a partir de la KSK actual. Suele pasar al dejar un DS viejo o de otra clave que comparte keyTag.'
      });
      break;
    default:
      addFinding(result, {
        severity: 'info',
        title: 'No se pudo comprobar el estado DNSSEC',
        detail: 'Las consultas de DNSKEY y DS no devolvieron datos utilizables.',
        recommendation: 'No significa que al dominio le falte algo. Revisa la conectividad y repite.'
      });
  }
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
    ['Registrador', datos.registrador ? (datos.registradorId ? `${datos.registrador} (IANA ${datos.registradorId})` : datos.registrador) : 'desconocido'],
    ['Fecha de creacion', datos.creacion || 'desconocida'],
    ['Fecha de expiracion', datos.expiracion || 'desconocida'],
    ['Ultima actualizacion', datos.actualizacion || 'desconocida'],
    ['Dias hasta expiracion', datos.diasRestantes !== null ? `${datos.diasRestantes} dias` : 'desconocido'],
    ['Nameservers', datos.nameservers?.length ? datos.nameservers.join(', ') : 'desconocidos'],
    ['Titular', datos.titular || 'privado/desconocido'],
    ['Email de contacto', datos.email || 'no publicado'],
    ['Nota del registro', datos.nota || 'ninguna']
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

  // Estados del dominio: la tabla se pinta siempre, aunque venga vacia, para
  // que el informe tenga la misma estructura sea cual sea la fuente.
  addSection(result, {
    id: 'estados',
    title: 'Estados del Dominio',
    kind: K.LISTA,
    items: datos.estados?.length
      ? datos.estados.map((e) => ({ value: e }))
      : [{ value: 'El registro no publico estados para este dominio.' }]
  });

  // Nameservers: igual que arriba, siempre presente.
  addSection(result, {
    id: 'nameservers',
    title: 'Nameservers',
    kind: K.LISTA,
    items: datos.nameservers?.length
      ? datos.nameservers.map((ns) => ({ value: ns }))
      : [{ value: 'El registro no publico nameservers para este dominio.' }]
  });

  // DNSSEC: la firma es un dato del dominio, no de la caducidad, pero importa
  // al renovar: un dominio con DNSSEC roto deja de resolver semanas antes de
  // que caduque. Por eso cierra el informe de este módulo.
  const dnssec = await consultarDnssec(result, dominio, timeout, ctx);
  pintarDnssec(result, { dominio, ...dnssec });
  revisarDnssec(result, { dominio, ...dnssec });

  // Si RDAP no cubrio el TLD y WHOIS si, se vuelca la respuesta cruda: es la
  // unica forma de ver el dato completo (y de diagnosticar un parseo fallido).
  if (!rdapData?.disponible && whoisData?.disponible && whoisData.raw) {
    addSection(result, {
      id: 'whois-raw',
      title: 'Respuesta WHOIS completa',
      description: 'El registro no tiene RDAP para este TLD; estos son los datos crudos que devolvio el servidor WHOIS.',
      kind: K.CODIGO,
      value: whoisData.raw.slice(0, 8000)
    });
  }

  // Si ninguna fuente contesto, se avisa con la causa concreta. El caso mas
  // comun en un VPS es que el puerto 43 saliente este bloqueado por el
  // proveedor: sin eso, WHOIS no contesta nunca.
  if (!rdapData?.disponible && !whoisData?.disponible) {
    addFinding(result, {
      severity: 'warn',
      title: 'Ninguna fuente respondio',
      detail: `RDAP: ${rdapData?.motivo || rdapData?.error || 'sin datos'}. WHOIS: ${whoisData?.error || 'sin datos'}.`,
      recommendation: 'Si el servidor sale de un VPS, comprueba que el puerto 43 saliente no este bloqueado por el proveedor: es la causa mas comun de que WHOIS no conteste.'
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
  descripcion: 'Consulta la fecha de expiracion, registrador, estados y nameservers de un dominio usando RDAP (principal) y WHOIS (fallback). Detecta dominios expirados, por expirar y muestra dias restantes, ademas del estado DNSSEC (DS/DNSKEY).',
  icon: '📅',
  sinRed: false,
  campos: CAMPOS,
  ejecutar,
  // Exportados para las pruebas.
  parsearWhois,
  combinarResultados,
  verificarDnssec,
  pintarDnssec,
  revisarDnssec,
  consultarDnssec
};