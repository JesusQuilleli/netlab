/**
 * net/spamhaus.js — Blocklists via DNS Query (lo que antes se llamaba DQS).
 *
 * QUE ES Y QUE NO ES. Esto NO es una forma de arreglar el acceso gratuitamente.
 * Es una consulta mas a las zonas de Spamhaus, pero a las zonas de pago, que
 * contestan a cualquiera con una clave. Sin clave, el resultado es el mismo
 * "no me contesta" de siempre.
 *
 * POR QUE HACE FALTA. Las zonas publicas (`zen.spamhaus.org` y compañía) solo
 * dan datos a un resolvedor que Spamhaus tenga registrado. Al resto, incluido
 * cualquier servidor normal, le devuelven NXDOMAIN o un codigo de diagnostico.
 * Y NXDOMAIN es exactamente lo que devuelve una IP que no esta listada, asi que
 * desde un servidor las zonas publicas no distinguen "no listada" de "no te he
 * dado datos". Una clave de DQS quita ese problema: las zonas de DQS responden a
 * cualquier resolvedor porque el acesso va en el NOMBRE de la zona.
 *
 * EL TRUCO: LA CLAVE VA EN EL NOMBRE. No hay ninguna cabecera, ni token, ni
 * login. La zona se construye poniendo la clave delante:
 *
 *     <clave>.zen.dq.spamhaus.net
 *
 * Ojo al `.net`. Las zonas de DQS son `.net` y las publicas `.org`. Poner
 * `zen.spamhaus.org` con una clave delante no funciona, y `dq.spamhaus.org`
 * sin clave tampoco. Documentacion: la pagina "Migration from Spamhaus Legacy
 * Public Mirrors to Blocklists via DNS Query".
 *
 * EL CODIGO DE RESPUESTA DICE QUE LISTA ES. Cuando la IP esta listada, el
 * ultimo octeto no es un 1 cualquiera: identifica la sublista. `127.0.0.2` es
 * SBL, `127.0.0.4` es XBL, `127.0.0.10` es PBL. Es el mismo dato que devuelve
 * la API por HTTPS, en un octeto.
 *
 * BCL NO ESTA AQUI. Y esta es la parte que conviene tener clara, porque es la
 * que hace que este modulo no sirva para lo que parece. La Botnet Controller
 * List, la de IPs que controlan bots, NO forma parte del pack gratuito ni del
 * comercial por DNS Query: solo existe en las espejos publicas, o sea, solo
 * para resolvedores registrados. La lista de datos del alta gratuita incluye
 * AuthBL, XBL, ZEN, DROP, DBL, SBL, PBL y ZRD, y no incluye BCL. Y en la API
 * por HTTPS los recursos son SBL, XBL, PBL, SBL-XBL, ZEN, AUTHBL, ZRD y DBL,
 * tampoco BCL.
 *
 * Lo de botnet C&C que si ofrece el pack gratuito es para DOMINIOS (el 2006 de
 * DBL), no para IPs. Son dos cosas distintas: un dominio que es un C2 y una IP
 * que aloja el C2.
 *
 * Asi que para el caso de la IP que Hastarted esto, la clave gratuita NO sirve.
 * La unica fuente para BCL por IP es el espejo publico desde un resolvedor
 * registrado, o la pagina de consulta de Spamhaus. `tools/ip-audit` lo dice
 * asi, en vez de dar un "no listada" que nadie ha comprobado.
 *
 * DONDE SE PIDE LA CLAVE GRATUITA:
 *   https://portal.spamhaus.com/auth/account-setup?ps=free_dqs_product
 *
 * @module core/net/spamhaus
 */

'use strict';

const dnsNet = require('./dns');
const ipaddr = require('./ipaddr');
// `octetosInvertidos` vive en dnsbl porque las zonas de lista negra y las de DQS
// se montan exactamente igual, y duplicarlo seria acabar divergiendo.
const { octetosInvertidos } = require('./dnsbl');
const { NetlabError, CODES } = require('../errors');

/**
 * La clave que no existe. Es lo que devuelve una consulta sin clave puesta, y
 * es un valor que jamas sera una clave real: son 26 caracteres que no son ni
 * letras ni digitos, y una clave de DQS son 26 caracteres alfabeticos.
 */
const SIN_ACCESO = '127.255.255.254';

const LISTADA = 'listada';
const NO_LISTADA = 'no-listada';
const DESCONOCIDO = 'desconocido';

const ESTADOS = { LISTADA, NO_LISTADA, DESCONOCIDO };

/**
 * Zonas a las que da acceso una clave gratuita.
 *
 * `bcl` NO esta, a proposito. Ver el comentario de cabecera: no existe en DQS.
 * Si algun dia la anaden, se anade aqui y no hay que tocar nada mas.
 */
const LISTAS_DQS = [
  {
    clave: 'zen',
    etiqueta: 'ZEN',
    ip: true,
    quitarUltimoOcteto: true,
    queMide: 'Correo no deseado y actividad sospechosa, junto con SBL y XBL.'
  },
  {
    clave: 'sbl',
    etiqueta: 'SBL',
    ip: true,
    quitarUltimoOcteto: true,
    queMide: 'Direcciones que Spamhaus considera maliciosas a proposito, no por un susto pasajero.'
  },
  {
    clave: 'xbl',
    etiqueta: 'XBL',
    ip: true,
    quitarUltimoOcteto: false,
    queMide: 'Equipos comprometidos: mandan correo o malware porque estan infectados.'
  },
  {
    clave: 'sbl-xbl',
    etiqueta: 'SBL + XBL',
    ip: true,
    quitarUltimoOcteto: true,
    queMide: 'SBL y XBL en una sola consulta.'
  },
  {
    clave: 'pbl',
    etiqueta: 'PBL',
    ip: true,
    quitarUltimoOcteto: false,
    queMide: 'Direcciones que no deberian enviar correo: rangos residenciales, dinamicos, proxies.'
  },
  {
    clave: 'authbl',
    etiqueta: 'AuthBL',
    ip: true,
    quitarUltimoOcteto: false,
    queMide: 'Equipos que usan credenciales robadas o atacan por fuerza bruta.'
  }
];

/**
 * Que sublista es cada codigo de respuesta.
 *
 * El codigo completo es el ultimo octeto de un 127.0.0.x. Las tres primeras
 * cifras no se usan: el rango 127.0.0.x es el de "listada" y el 127.255.255.x el
 * de "no he podido/contestar". Aqui solo se guardan los ultimos digitos, que es
 * lo que distingue una sublista de otra.
 *
 * Faltan los codigos de ZRD, que solo son de dominio y no se consultan aqui.
 */
const SUBLISTAS = {
  2: { zona: 'sbl', nombre: 'SBL', motivo: 'Direccion en la Spamhaus Blocklist.' },
  3: { zona: 'sbl', nombre: 'CSS', motivo: 'Direccion en CSS, un subconjunto de SBL.' },
  4: { zona: 'xbl', nombre: 'XBL', motivo: 'Equipo comprometido: infectado y mandando correo o malware.' },
  9: { zona: 'sbl', nombre: 'DROP', motivo: 'Redes que ya ni se miran: hay que cortar todo el trafico.' },
  10: { zona: 'pbl', nombre: 'PBL', motivo: 'Esta direccion no deberia enviar correo a terceros.' },
  11: { zona: 'pbl', nombre: 'PBL', motivo: 'Esta direccion no deberia enviar correo a terceros.' },
  20: { zona: 'authbl', nombre: 'AuthBL', motivo: 'Credenciales robadas o ataque por fuerza bruta.' }
};

/**
 * Un codigo de diagnostico: la zona existia pero no va a contestar.
 *
 * 127.255.255.x es la manera que tiene Spamhaus de decir "no" sin dar datos. Se
 * descifra asi: los dos ultimos digitos son el numero de error, y 254 y 255
 * significan "no te he dicho nada". Un 127.255.255.252 es un error de
 * configuracion por el lado de quien pregunta, osea la zona montada mal.
 */
function esDiagnostico(ip) {
  return /^127\.255\.255\./.test(ip);
}

/**
 * Traduce la IP que devuelve la zona a un veredicto.
 *
 * @param {string} ip Valor del registro A, o '' si el nombre no existe.
 * @returns {{estado: string, codigo: string|null, sublista: object|null, motivo: string|null, advertencia: string|null}}
 */
function interpretarRespuesta(ip) {
  // Nombre inexistente = la IP no esta en esa lista. Es la respuesta normal de
  // "no listada" y no es un error.
  if (!ip) return { estado: NO_LISTADA, codigo: null, sublista: null, motivo: null, advertencia: null };

  if (esDiagnostico(ip)) {
    const numero = Number(ip.split('.').pop());

    if (ip === SIN_ACCESO) {
      return {
        estado: DESCONOCIDO,
        codigo: ip,
        sublista: null,
        motivo: null,
        advertencia: 'Spamhaus no da datos a esta consulta. Con las zonas publicas es normal si el resolvedor no esta registrado.'
      };
    }

    return {
      estado: DESCONOCIDO,
      codigo: ip,
      sublista: null,
      motivo: null,
      advertencia: `Spamhaus ha contestado con su codigo de error ${numero}, que significa "no te he dado datos" y no "no listada".`
    };
  }

  // 127.0.0.x = listada, y el ultimo digito dice en que sublista.
  const sub = SUBLISTAS[Number(ip.split('.').pop())] || null;

  return {
    estado: LISTADA,
    codigo: ip,
    sublista: sub,
    motivo: sub ? sub.motivo : null,
    // Un codigo de listada que no aparece en la tabla no es un problema, pero
    // conviene decirlo: podria ser una sublista nueva que este modulo no conoce.
    advertencia: sub ? null : `Listada con el codigo ${ip}, que no corresponde a ninguna sublista que se conozca. Puede ser una sublista nueva.`
  };
}

/**
 * Sustituye la clave por un marcador.
 *
 * La clave viaja DENTRO del nombre de la zona, asi que cualquier error de DNS
 * la lleva en su mensaje. Y ese mensaje acaba en el informe, que se puede
 * exportar a PDF o Markdown y enviar a alguien. Una credencial que se cuela en
 * un informe compartido es una credencial quemada, y el informe es
 * precisamente el documento que mas circulacion tiene.
 *
 * @param {string} texto
 * @param {string} clave
 * @returns {string}
 */
function enmascararClave(texto, clave) {
  if (!texto || !clave) return texto;

  // Se ocultan todos los digitos menos los dos ultimos: sirven para distinguir
  // una clave de otra sin permitir reutilizarla, que es lo que se puede hacer
  // con los ultimos cuatro.
  const cola = clave.slice(-2);
  const mascara = `${'*'.repeat(Math.max(clave.length - 2, 0))}${cola}`;

  return String(texto).split(clave).join(mascara);
}

/**
 * Monta el nombre que hay que consultar en DQS.
 *
 * @param {string} ip Direccion IPv4 o IPv6.
 * @param {string} lista Zona ('zen', 'sbl'...).
 * @param {string} clave Clave de DQS.
 * @returns {string}
 */
function nombreConsulta(ip, lista, clave) {
  const def = listaDQS(lista);
  const octetos = octetosDeConsulta(ip, def.quitarUltimoOcteto);
  return `${clave}.${octetos}.${lista}.dq.spamhaus.net`;
}

/** Quita el sufijo de dominio inverso que `octetosInvertidos` deja puesto. */
function octetosDeConsulta(ip, quitarUltimoOcteto) {
  const octetos = octetosInvertidos(ip);
  if (!octetos) return null;

  if (quitarUltimoOcteto) return octetos.split('.').slice(1).join('.');
  return octetos;
}

/** Ficha de una zona, o error si el nombre no existe. */
function listaDQS(clave) {
  const encontrada = LISTAS_DQS.find((l) => l.clave === clave);
  if (encontrada) return encontrada;

  throw new NetlabError(
    CODES.PARAM_INVALIDO,
    `La zona "${clave}" no existe en DQS.`,
    {
      remediation:
        `Zonas disponibles: ${LISTAS_DQS.map((l) => l.clave).join(', ')}. ` +
        'BCL no esta entre ellas: la lista de IPs que controlan bots solo existe en los espejos publicos, ' +
        'para resolvedores registrados. Ver la cabecera de este modulo.'
    }
  );
}

/**
 * Consulta una zona de DQS para una IP.
 *
 * @param {string} ip Direccion a comprobar.
 * @param {object} [opciones]
 * @param {string} [opciones.clave] Clave de DQS.
 * @param {string} [opciones.lista='zen'] Zona.
 * @param {Function} [opciones.consultarDns] Inyectable para pruebas.
 * @returns {Promise<object>}
 * @throws {NetlabError} Si falta la clave, o la IP o la zona no valen.
 */
async function consultar(ip, opciones = {}) {
  const { clave, lista = 'zen', consultarDns = dnsNet.consultar } = opciones;

  // Validar antes de la clave: un nombre de zona malo es un error de quien
  // escribe la llamada, y reportarlo como "falta la clave" manda al sitio
  // equivocado a buscar una clave que ya tiene.
  const def = listaDQS(lista);

  if (!ipaddr.bitsDe(ip)) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${ip}" no es una direccion IP valida.`, {
      remediation: 'Pasa una direccion IPv4 o IPv6 valida.'
    });
  }

  if (!clave) {
    throw new NetlabError(
      CODES.CREDENCIAL_AUSENTE,
      'No hay clave de DQS, asi que no se ha consultado nada.',
      {
        remediation:
          'Registra una cuenta gratuita en https://portal.spamhaus.com/auth/account-setup?ps=free_dqs_product ' +
          'y pon la clave en SPAMHAUS_DQS_KEY. Sin ella, las zonas publicas de Spamhaus siguen sin contestar, ' +
          'que es el problema que esto viene a resolver.'
      }
    );
  }

  const nombre = nombreConsulta(ip, lista, clave);
  const r = await consultarDns(nombre, 'A');

  // A partir de aqui, el nombre no sale de este modulo en claro: la clave va
  // dentro y todo lo que se reporte acaba en un informe que se comparte.
  const nombreLegible = enmascararClave(nombre, clave);
  const error = r.error ? enmascararClave(r.error, clave) : null;

  if (!r.ok) {
    // NXDOMAIN o NODATA con clave puesta es una respuesta de verdad: la IP no
    // esta en esa lista. Cualquier otra cosa NO es un veredicto, y aquí es donde
    // se gana o se pierde el informe entero.
    if (r.codigoDns === 'ENOTFOUND' || r.codigoDns === 'ENODATA') {
      return envolver(ip, lista, def, interpretarRespuesta(''), nombreLegible);
    }

    // Un timeout, un SERVFAIL, un corte de red: no se sabe nada. Traducir esto a
    // "no listada" produce un informe limpio con la zona caida, que es el fallo
    // silencioso mas caro que puede tener esta herramienta.
    return envolver(ip, lista, def, lecturaDeError(r), nombreLegible, error);
  }

  const ipRespuesta = (r.valores || [])[0] || '';
  return envolver(ip, lista, def, interpretarRespuesta(ipRespuesta), nombreLegible, null, ipRespuesta);
}

/** Lectura para "no se ha podido consultar", que no es lo mismo que "no listada". */
function lecturaDeError(r) {
  return {
    estado: DESCONOCIDO,
    codigo: null,
    sublista: null,
    motivo: null,
    advertencia: 'La zona no ha contestado, asi que no se sabe si la IP esta en ella.'
  };
}

/** Junta la lectura de la zona con los datos de la ficha, que es lo que van a leer. */
function envolver(ip, lista, def, lectura, nombre, error = null, ipRespuesta = null) {
  const advertencias = [];
  if (lectura.advertencia) advertencias.push(lectura.advertencia);
  if (error) advertencias.push(`La consulta a ${nombre} fallo: ${error}`);

  // Solo se dice "retirada" si estaba listada ahora mismo. Si el resultado es
  // desconocido, la recomendacion de pedir la retirada no tiene sentido.
  if (lectura.estado === LISTADA) {
    advertencias.push('Quitar un listado no es automatico: hay que pedirlo y esperar a que lo revisen.');
  }

  return {
    ip,
    lista,
    listaNombre: def.etiqueta,
    queMide: def.queMide,
    estado: lectura.estado,
    codigo: lectura.codigo,
    ipRespuesta,
    sublista: lectura.sublista ? lectura.sublista.nombre : null,
    motivo: lectura.motivo,
    consultadoEn: new Date().toISOString(),
    advertencias
  };
}

/**
 * Consulta varias zonas y nunca aborta por culpa de una.
 *
 * @param {string} ip
 * @param {object} [opciones] Igual que `consultar`, mas:
 * @param {string[]} [opciones.listas=['zen']] Zonas a consultar.
 * @returns {Promise<{ip: string, resultados: object[], errores: object[], algunoListada: boolean, algunoDesconocido: boolean}>}
 * @throws {NetlabError} Solo si falta la clave o no hay ninguna zona valida.
 */
async function consultarVarias(ip, opciones = {}) {
  const { clave, listas = ['zen'], consultarDns = dnsNet.consultar } = opciones;

  if (!clave) {
    // Se comprueba aqui y no en cada `consultar` para poder devolver una
    // estructura y no una excepcion a mitad de un informe.
    throw new NetlabError(CODES.CREDENCIAL_AUSENTE, 'No hay clave de DQS.', {
      remediation:
        'Registra una cuenta gratuita en https://portal.spamhaus.com/auth/account-setup?ps=free_dqs_product ' +
        'y pon la clave en SPAMHAUS_DQS_KEY.'
    });
  }

  const resultados = [];
  const errores = [];

  for (const lista of listas) {
    try {
      resultados.push(await consultar(ip, { ...opciones, clave, lista, consultarDns }));
    } catch (error) {
      // Una zona que falla no puede borrar el resultado de las otras. Si ZEN da
      // un "no listada" y SBL se cae, el informe tiene que seguir diciendo que
      // ZEN contesto, no pasar a "no se ha podido comprobar".
      errores.push({
        lista,
        mensaje: error.message,
        codigo: error.code || null
      });
    }
  }

  return {
    ip,
    resultados,
    errores,
    algunoListada: resultados.some((r) => r.estado === LISTADA),
    algunoDesconocido: resultados.some((r) => r.estado === DESCONOCIDO)
  };
}

module.exports = {
  ESTADOS,
  LISTADA,
  NO_LISTADA,
  DESCONOCIDO,
  LISTAS_DQS,
  SUBLISTAS,
  SIN_ACCESO,
  consultar,
  consultarVarias,
  esDiagnostico,
  interpretarRespuesta,
  listaDQS,
  enmascararClave,
  nombreConsulta
};