/**
 * tools/dominio-reputacion.js — Reputacion de un dominio en Spamhaus DBL.
 *
 * DE DONDE SALE. La consulta a DBL (dbl.spamhaus.org) ya existia dentro del
 * "Comprobador de correo" (`mail-checker` consulta `consultarDominio` del modulo
 * `core/net/dnsbl` y la mete en la nota de las listas negras). Aqui se aísla
 * como herramienta propia: el mismo motor, sin el resto del informe de correo,
 * para cuando solo se quiere saber si un dominio esta en la lista.
 *
 * LO QUE ESTA HECHO DISTINTO, Y POR QUE:
 *
 * 1. Un subdominio se comprueba tambien de su dominio raiz. DBL marca el
 *    registro sobre el dominio de dos etiquetas, de modo que `<sub>.<dominio>`
 *    puede salir "limpio" porque la marca esta en `<dominio>`. La consulta sube
 *    hasta el padre y el veredicto habla del nivel que realmente esta listado.
 *
 * 2. "Sin datos" jamas se presenta como "limpio". Spamhaus solo da datos a
 *    resolvedores registrados; desde un servidor habitual, un NXDOMAIN es
 *    indistinguible entre "no listado" y "no me dejan mirar". Si se detecta que
 *    no hay acceso, el informe lo dice tal cual en vez de dar un "todo limpio".
 *
 * 3. La gravedad se decide sola: listada es un fallo, limpia es informacion y
 *    no comprobable es una advertencia. El veredicto sale del estado que
 *    `consultarDominio` ya ha decidido, sin volver a inventar el criterio.
 *
 * @module tools/dominio-reputacion
 */

'use strict';

const {
  createResult, addSection, addSummary, addFinding, addLog,
  finalize, failWith, SEVERIDADES, SECCION_KINDS: K
} = require('../core/result');
const dnsbl = require('../core/net/dnsbl');
const { NetlabError, CODES } = require('../core/errors');
const { normalizarDominio, normalizarTimeout } = require('../core/dominio');

const ID = 'dominio-reputacion';

/** Nombre con el que se ve la lista, para que el informe no hable de siglas. */
const LISTA = 'Spamhaus DBL';

/** Campos del formulario. */
const CAMPOS = [
  {
    name: 'dominio',
    label: 'Dominio',
    type: 'text',
    required: true,
    placeholder: 'ejemplo.com',
    help: 'Haz la comprobacion sobre el dominio, no sobre una URL: se limpia solo si pegas una. Si es una subdominio, se comprueba también el dominio del que cuelga.'
  },
  {
    name: 'accesoSpamhaus',
    label: 'Confirmar que Spamhaus responde a este resolvedor',
    type: 'checkbox',
    required: false,
    default: true,
    help: 'Spamhaus solo da datos a direcciones registradas. Con esto marcado, un "limpio" que no puede confirmarse sale como "sin datos", no como un limpio falso.'
  },
  {
    name: 'timeout',
    label: 'Tiempo de espera',
    type: 'number',
    required: false,
    default: 8000,
    min: 1000,
    max: 30000,
    unit: 'ms',
    help: 'Por consulta DNS. Solo tiene efecto real sobre la comprobacion de acceso; la de la lista es instantanea.'
  }
];

/**
 * Punto de entrada de la herramienta.
 *
 * @param {object} params Entrada del formulario.
 * @param {object} [ctx] Contexto. `ctx.dbl` permite inyectar la consulta en las
 *   pruebas y `ctx.dns` se pasa al modulo DNS en las de integracion.
 * @returns {Promise<object>} Result completo, listo para renderizar.
 */
async function ejecutar(params = {}, ctx = {}) {
  const inicio = new Date();
  const log = ctx.log || null;

  const result = createResult({
    tool: ID,
    toolTitle: 'Reputacion de Dominio',
    target: String(params?.dominio ?? '').trim(),
    params
  });

  try {
    // La limpieza de entrada va dentro del try a proposito: un dominio invalido
    // no debe tumbar la llamada, sino devolver un Result con error, igual que el
    // resto de errores de la herramienta.
    const dominio = normalizarDominio(params.dominio);
    result.target = dominio;

    const timeout = normalizarTimeout(params.timeout, { defecto: 8000, min: 1000, max: 30000 });
    const accesoSpamhaus = params.accesoSpamhaus !== false;

    addLog(result, {
      level: 'info',
      channel: 'entrada',
      message: `${dominio} contra ${LISTA}, acceso Spamhaus ${accesoSpamhaus ? 'comprobado' : 'omitido'}`
    });

    const consultar = ctx.dbl || ((d, opciones) => dnsbl.consultarDominio(d, opciones));
    const r = await consultar(dominio, { dns: ctx.dns, timeout, accesoSpamhaus });

    addLog(result, {
      level: 'info',
      channel: 'dns',
      message: `${dominio}: ${etiquetaEstado(r.estado)} (consultado ${r.consultado || 'nada'})`
    });

    pintar(result, r);
    revisar(result, r);

    return finalize(result, inicio);
  } catch (error) {
    addLog(result, { level: 'error', channel: 'error', message: error.message });
    log?.error?.(`dominio-reputacion fallo: ${error.message}`);
    return failWith(finalize(result, inicio), error instanceof NetlabError ? error : new NetlabError(CODES.INTERNO, error.message));
  }
}

/** Traduce el estado del modulo a texto legible. */
function etiquetaEstado(estado) {
  if (estado === dnsbl.ESTADOS.LISTADA) return 'Listado';
  if (estado === dnsbl.ESTADOS.LIMPIA) return 'Limpio';
  return 'Sin datos';
}

/** Tonos del resumen y de la seccion segun el estado. */
function tonoEstado(estado) {
  if (estado === dnsbl.ESTADOS.LISTADA) return 'bad';
  if (estado === dnsbl.ESTADOS.LIMPIA) return 'ok';
  return 'warn';
}

/** Campos de la seccion: lo que hace falta para interpretar el veredicto. */
function pintar(result, r) {
  addSummary(result, 'Estado', etiquetaEstado(r.estado), tonoEstado(r.estado));
  addSummary(result, 'Lista', LISTA);

  const consulta = r.consultado ? `${r.consultado}.${dnsbl.ZONA_DBL}` : '—';

  addSection(result, {
    title: 'Reputacion de dominio',
    kind: K.PARES,
    items: [
      ['Estado', etiquetaEstado(r.estado), tonoEstado(r.estado)],
      ['Lista consultada', LISTA],
      ['Dominio escrito', r.dominio || '—'],
      // La consulta sube del subdominio al dominio de dos etiquetas; saber qué
      // nombre se pregunto distingue "el padre esta listado" de "el subdominio".
      ['Consultado en', consulta],
      ['Codigo de la lista', r.codigo || '—'],
      ['Aviso de la lista', r.avisos?.length ? r.avisos.join(' ') : 'Sin avisos']
    ]
  });
}

/**
 * Convierte el estado de `consultarDominio` en hallazgos.
 *
 * La regla es no marcar como limpio lo que no se ha podido comprobar: el "sin
 * datos" suele salir de un resolvedor sin registrar en Spamhaus, y leerlo como
 * un "no esta listado" es el error mas caro de esta consulta.
 */
function revisar(result, r) {
  if (r.estado === dnsbl.ESTADOS.LISTADA) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: `${r.dominio} esta en la lista de dominios de Spamhaus (DBL)`,
      detail:
        `El registro ${r.dominio}` +
        `${r.consultado && r.consultado !== r.dominio ? ` esta listado por la marca en ${r.consultado}` : ' esta listado'}` +
        `${r.codigo ? ` (codigo ${r.codigo})` : ''}. Los receptores de correo desconfian de este dominio aunque sus IP esten limpias.`,
      recommendation: 'Revisa desde donde se envia correo en ese dominio y solicita la baja en DBL; mientras siga listado, el correo saldra mal.'
    });
    return;
  }

  if (r.estado === dnsbl.ESTADOS.LIMPIA) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `${r.dominio} no aparece en Spamhaus DBL`,
      detail: r.consultado
        ? `Se consulto ${r.consultado} y la lista no devuelve ningun registro.`
        : 'La lista no devuelve ningun registro para el dominio.',
      recommendation: 'DBL cubre dominios de spam de correo, no todo el abuso: un limpiado aqui no es un certificado absoluto.'
    });
    return;
  }

  addFinding(result, {
    severity: SEVERIDADES.WARN,
    title: `No se pudo comprobar la reputacion de ${r.dominio}`,
    detail: r.error || 'Spamhaus DBL no respondio.',
    recommendation: [
      'Si el motivo es el acceso, registra tu resolvedor en Spamhaus para que sus listas devuelvan datos.',
      'Un "sin datos" NO es un "limpio": reintenta desde un resolvedor con acceso antes de dar el dominio por bueno.'
    ].join(' ')
  });
}

module.exports = {
  id: ID,
  titulo: 'Reputacion de Dominio',
  descripcion: 'Consulta Spamhaus DBL para saber si un dominio esta en la lista de envio de correo no deseado, subiendo tambien a su dominio raiz.',
  sinRed: false,
  icon: '🌐',
  campos: CAMPOS,
  ejecutar,
  _internas: { etiquetaEstado, tonoEstado }
};