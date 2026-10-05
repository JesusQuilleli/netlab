/**
 * net/rdap.js — Quien registro una direccion IP.
 *
 * RDAP es el sustituto de WHOIS: los cinco registros regionales publican una
 * API JSON en vez de un texto que hay que raspar con expresiones regulares. Es
 * parte de la politica de bootstrapping de IANA, asi que no depende de ninguna
 * empresa y no necesita clave ni registro.
 *
 * LO QUE HACE ESTE MODULO, Y POR QUE:
 *
 * 1. Descarga el bootstrap oficial de IANA y busca el PREFIJO MAS LARGO que
 *    contiene la IP. El bootstrap lista bloques de mayor a menor detalle, pero
 *    la regla correcta no es "el primero que encaja": si una IP cae en
 *    `0.0.0.0/0` y en `1.0.0.0/8`, tiene que ganar el /8. Con un /0 equivocado
 *    se consulta al registro equivocado y vuelve un 404 que parece "esta IP no
 *    existe", que es una conclusion falsa.
 *
 * 2. Una IP puede no estar registrada. No todas las subredes de un /
 *    autonomo tienen fila en la base del registro. Eso se devuelve como
 *    `disponible: false` con su motivo, no como un error: es una respuesta
 *    valida, y el que pide el dato necesita distinguir "nadie lo ha registrado"
 *    de "no se ha podido preguntar".
 *
 * 3. Del JSON solo se saca lo que ayuda a decidir: quien es el titular, el
 *    ASN, el rango, el contacto de abuso y las fechas. No se vuelca el objeto
 *    entero, porque en un informe eso es ruido y ademas arrastra contactos que
 *    no hacen falta.
 *
 * PRIVACIDAD. Se guarda el correo de contacto para abuso, que es justo el dato
 * para el que existe esta herramienta: cuando una IP roba tu marca, hay que
 * saber a quien escribir. El resto de contactos (administrativo, tecnico) no se
 * copian.
 *
 * @module core/net/rdap
 */

'use strict';

const ipaddr = require('./ipaddr');
const { getJSON } = require('./http');
const { NetlabError, CODES } = require('../errors');

/**
 * Bootstrap oficial de IANA: a quien preguntar por cada bloque.
 *
 * Las claves son '4' y '6' para direcciones y 'dns' para nombres de dominio.
 * Se indexa por texto y no por numero a proposito: son familias distintas con
 * forma distinta, no tres valores de la misma cosa.
 */
const BOOTSTRAP = {
  4: 'https://data.iana.org/rdap/ipv4.json',
  6: 'https://data.iana.org/rdap/ipv6.json',
  dns: 'https://data.iana.org/rdap/dns.json'
};

/**
 * Cache en memoria del bootstrap, por familia.
 *
 * El archivo pesa poco y cambia cuando IANA anade un registro, no cada hora.
 * Una peticion por proceso es suficiente, y evita descargar lo mismo por cada
 * IP de un informe con varias direcciones.
 *
 * @type {Map<string|number, Array>}
 */
const cacheBootstrap = new Map();

/**
 * Descarga el bootstrap de IANA y lo deja en cache.
 *
 * @param {'4'|'6'|'dns'} familia
 * @param {object} [opciones]
 * @param {Function} [opciones.fetchImpl]
 * @param {number} [opciones.timeoutMs]
 * @returns {Promise<Array>} Los pares `[[prefijos], [urls]]` del bootstrap.
 */
async function cargarBootstrap(familia, opciones = {}) {
  const { fetchImpl, timeoutMs = 15000 } = opciones;
  if (!fetchImpl && cacheBootstrap.has(familia)) return cacheBootstrap.get(familia);

  const url = BOOTSTRAP[familia];
  const cuerpo = await getJSON({
    url,
    fetchImpl,
    timeoutMs,
    intentos: 2,
    servicio: 'el registro de IANA'
  });

  if (!Array.isArray(cuerpo.services) || !cuerpo.services.length) {
    throw new NetlabError(CODES.API_EXTERNA, 'El bootstrap de IANA no trae la lista de servicios RDAP.', {
      remediation: `Comprueba que ${url} siga existiendo; si ha cambiado de sitio, actualiza BOOTSTRAP en src/core/net/rdap.js.`
    });
  }

  if (!fetchImpl) cacheBootstrap.set(familia, cuerpo.services);
  return cuerpo.services;
}

/**
 * Aplana el bootstrap a una lista de `[{prefijo, urls}]`.
 *
 * @param {Array} services
 * @returns {Array<{prefijo: string, urls: string[]}>}
 */
function aEntradas(services) {
  const entradas = [];
  for (const servicio of services) {
    if (!Array.isArray(servicio) || !Array.isArray(servicio[0]) || !Array.isArray(servicio[1])) continue;
    for (const prefijo of servicio[0]) {
      entradas.push({ prefijo: String(prefijo), urls: servicio[1].map(String) });
    }
  }
  return entradas;
}

/**
 * Elige el servidor RDAP que corresponde a una IP.
 *
 * @param {string} ip
 * @param {Array} services Bootstrap de IANA.
 * @returns {{prefijo: string, urls: string[]}|null}
 */
function servidorPara(ip, services) {
  let mejor = null;

  for (const entrada of aEntradas(services)) {
    if (!ipaddr.contiene(entrada.prefijo, ip)) continue;
    const longitud = Number(entrada.prefijo.split('/')[1]);
    const mejorLongitud = mejor ? Number(mejor.prefijo.split('/')[1]) : -1;
    if (longitud > mejorLongitud) mejor = entrada;
  }

  return mejor;
}

/**
 * Monta la URL de consulta a partir de la base que publica el registro.
 *
 * Las bases del bootstrap terminan en `/` y no en `/ip`, pero no todas: hay que
 * unir sin duplicar la barra.
 *
 * @param {string} base
 * @param {string} ip
 * @returns {string}
 */
function urlDeConsulta(base, ip) {
  return `${base.replace(/\/+$/, '')}/ip/${encodeURIComponent(ip)}`;
}

/**
 * Extrae los campos de una vCard de RDAP, que es un array alterno.
 *
 * vcardArray: `["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "X"]]]`
 * El segundo elemento de cada entrada es un objeto con parametros (como `pref`
 * o `group`); el valor es la posicion siguiente y el tipo va despues.
 *
 * @param {any} vcardArray
 * @returns {{nombre: string|null, correo: string|null}}
 */
function deVCard(vcardArray) {
  const salida = { nombre: null, correo: null, url: null };
  if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) return salida;

  for (const entrada of vcardArray[1]) {
    if (!Array.isArray(entrada)) continue;
    const [propiedad, , tipo, valor] = entrada;
    if (typeof valor !== 'string' || !valor) continue;

    if (propiedad === 'fn' && !salida.nombre) salida.nombre = valor;
    if (propiedad === 'email' && !salida.correo) {
      salida.correo = valor.startsWith('mailto:') ? valor.slice(7) : valor;
    }
    if (tipo === 'uri' && propiedad === 'url' && !salida.url) {
      salida.url = valor;
    }
  }

  return salida;
}

/**
 * Busca en las entidades de un RDAP las que tienen un papel concreto.
 *
 * @param {any} entidades
 * @param {string} rol p. ej. `abuse`, `registrant`, `administrative`.
 * @returns {{nombre: string|null, correo: string|null, url: string|null}[]}
 */
/**
 * Todas las entidades de un objeto RDAP, incluidas las anidadas.
 *
 * ARIN anida la organizacion dentro del objeto del bloque: en `8.8.8.0/24` el
 * `inetnum` solo trae `registrant`, y la entidad de abused (`ABUSE5250-ARIN`)
 * esta un nivel mas abajo. Mirando solo el nivel superior, casi todo el
 * espacio IPv4 de ARIN aparecia sin contacto de abuso, que es precisamente el
 * dato para el que se consulta un registro.
 */
function todasLasEntidades(entidades) {
  const salida = [];
  for (const entidad of Array.isArray(entidades) ? entidades : []) {
    if (!entidad || typeof entidad !== 'object') continue;
    salida.push(entidad);
    if (Array.isArray(entidad.entities)) {
      for (const anidada of entidad.entities) {
        if (anidada && typeof anidada === 'object') salida.push(anidada);
      }
    }
  }
  return salida;
}

function entidadesConRol(entidades, rol) {
  const encontradas = [];

  for (const entidad of todasLasEntidades(entidades)) {
    const roles = Array.isArray(entidad.roles) ? entidad.roles : [];
    if (!roles.includes(rol)) continue;

    const tarjeta = deVCard(entidad.vcardArray);
    encontradas.push({
      nombre: tarjeta.nombre || entidad.handle || null,
      correo: tarjeta.correo,
      url: tarjeta.url || null
    });
  }

  return encontradas;
}

/** Busca una fecha de evento por su nombre, aunque venga con otro formato. */
function fechaDeEvento(eventos, accion) {
  if (!Array.isArray(eventos)) return null;

  const objetivo = accion.toLowerCase();
  for (const evento of eventos) {
    const accionEvento = String(evento?.eventAction || '').toLowerCase().trim();
    // IANA escribe "last changed"; APNIC y RIPE pueden poner "last changed".
    // Comparar solo con startsWith evita depender de la palabra entera.
    if (accionEvento === objetivo || accionEvento.startsWith(objetivo)) {
      return evento?.eventDate || null;
    }
  }

  return null;
}

/** Une los textos de un bloque `remarks`. */
function textoDeRemarks(remarks) {
  if (!Array.isArray(remarks)) return null;
  const lineas = [];
  for (const bloque of remarks) {
    if (!Array.isArray(bloque?.description)) continue;
    lineas.push(...bloque.description.filter((d) => typeof d === 'string'));
  }
  const texto = lineas.join(' ').trim();
  return texto || null;
}

/**
 * Traduce la respuesta de RDAP a una forma plana y estable.
 *
 * Hay dos formas de respuesta legitimas y no son la misma:
 *
 * - `inetnum` / `ipnetwork`: un bloque asignado, con `startAddress` y
 *   `endAddress`. Es el caso normal.
 * - `entity`: una organizacion a la que se ha asignado el bloque. Algunos
 *   registros devuelven esto cuando no tienen desglosado el rango. Sigue siendo
 *   informacion valida sobre la IP, y por eso no se descarta.
 *
 * @param {object} datos Respuesta `application/rdap+json`.
 * @param {object} contexto `{ip, prefijo, servidor}`.
 * @returns {object} Informacion normalizada de la IP.
 */
function normalizar(datos, contexto) {
  const esBloque = datos.startAddress && datos.endAddress;
  const entidades = datos.entities;

  const abuso = entidadesConRol(entidades, 'abuse')[0] || null;
  const titular = entidadesConRol(entidades, 'registrant')[0] || null;

  // El nombre del objeto es lo mas util que hay: en un inetnum es la
  // organizacion a la que pertenece el bloque.
  const nombre = datos.name || titular?.nombre || (esBloque ? null : datos.handle) || null;

  const cidr = Array.isArray(datos.cidr0_cidrs) ? datos.cidr0_cidrs.find((c) => c && (c.v4prefix || c.v6prefix)) : null;

  return {
    ip: contexto.ip,
    disponible: true,
    servidor: contexto.servidor,
    prefijoRegistro: contexto.prefijo,

    tipoObjeto: datos.objectClassName || (esBloque ? 'inetnum' : 'entity'),
    handle: datos.handle || null,
    nombre,
    tipo: datos.type || null,
    pais: datos.country || null,

    // Sin rango no se afirma nada sobre el ambito. Decir "1.0.0.0/8" sin
    // saberlo seria inventar el dato que se vino a buscar.
    inicio: datos.startAddress || cidr?.v4prefix || cidr?.v6prefix || null,
    fin: datos.endAddress || null,
    prefijoCidr: cidr ? `${cidr.v4prefix || cidr.v6prefix}/${cidr.length}` : null,

    titular: titular?.nombre || null,
    // El correo del titular no se copia: es dato personal y el informe no lo
    // usa. Para reclamar por una IP hace falta el contacto de abuso, que es
    // un cargo publicado precisamente para eso.
    contactoAbuso: abuso ? { nombre: abuso.nombre, correo: abuso.correo } : null,

    registro: fechaDeEvento(datos.events, 'registration'),
    ultimoCambio: fechaDeEvento(datos.events, 'last changed'),
    caducidad: fechaDeEvento(datos.events, 'expiration'),

    estado: Array.isArray(datos.status) && datos.status.length ? datos.status.join(', ') : null,
    nota: textoDeRemarks(datos.remarks),
    enlace: Array.isArray(datos.links)
      ? datos.links.find((l) => l?.rel === 'self')?.href || null
      : null
  };
}

/**
 * Consulta el registro de una direccion IP.
 *
 * @param {string} ip
 * @param {object} [opciones]
 * @param {Function} [opciones.fetchImpl] Doble de `fetch` para las pruebas.
 * @param {Array} [opciones.bootstrap] Services de IANA ya descargados.
 * @param {number} [opciones.timeoutMs]
 * @returns {Promise<object>} `{disponible: false, ...}` si nadie la tiene
 *   registrada, o los datos normalizados del registro.
 */
async function consultar(ip, opciones = {}) {
  const { fetchImpl, timeoutMs = 12000, bootstrap } = opciones;

  const bits = ipaddr.bitsDe(ip);
  if (!bits) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${ip}" no es una direccion IP.`, {
      remediation: 'Escribe una IPv4 (203.0.113.10) o una IPv6 (2001:db8::1).'
    });
  }

// OJO: `bits` son 32 o 128, y el bootstrap esta indexado por familia (4 o 6).
// Pasar los bits aqui directo devolvia `undefined` y el modulo fallaba siempre
// que no se le inyectara el bootstrap a mano, es decir, siempre en produccion.
const familia = bits === 32 ? 4 : 6;
const services = bootstrap || (await cargarBootstrap(familia, { fetchImpl, timeoutMs }));
const entrada = servidorPara(ip, services);

  if (!entrada || !entrada.urls.length) {
    return {
      ip,
      disponible: false,
      motivo: 'El registro de IANA no publica ningun servidor RDAP para este bloque.',
      prefijo: null,
      servidor: null
    };
  }

  // Los registros dan a veces varios servidores; se prueban en orden y se pasa
  // al siguiente si uno falla. El primero que conteste es el bueno.
  let ultimoError = null;
  let todos404 = true;

  for (const base of entrada.urls) {
    const url = urlDeConsulta(base, ip);
    try {
      const cuerpo = await getJSON({
        url,
        fetchImpl,
        timeoutMs,
        intentos: 2,
        servicio: 'el registro de la IP'
      });

      return normalizar(cuerpo, { ip, prefijo: entrada.prefijo, servidor: base });
    } catch (error) {
      ultimoError = error;

      // Un 404 del registro es una respuesta definitiva para ESE servidor:
      // otro de la lista puede tenerla. Un 500 o un timeout tambien: se
      // prueban los demas y, si todos fallan, se reporta el ultimo.
      if (es404(error)) continue;
      todos404 = false;
    }
  }

  // Todos los servidores del bloque respondieron "no la tengo". Eso es una
  // respuesta, no un fallo: la IP no aparece en ningun registro publico, y el
  // informe lo dice como tal en vez de matarlo.
  if (todos404) {
    return {
      ip,
      disponible: false,
      motivo: 'Ningun registro publico tiene asignada esta direccion.',
      prefijo: entrada.prefijo,
      servidor: null
    };
  }

  // Aqui si hubo errores de verdad, asi que no se sabe. Un fallo de red no se
  // puede convertir en "no esta registrada": serian dos mentiras distintas.
  throw new NetlabError(
    ultimoError?.code || CODES.API_EXTERNA,
    `Ningun servidor RDAP del registro respondio para ${ip}.`,
    { remediation: 'Puede ser un fallo temporal del registro. Vuelve a intentarlo en unos minutos.', cause: ultimoError }
  );
}

/* ------------------------------------------------------------------ *
 * Dominios
 *
 * El bootstrap de nombres tiene OTRA FORMA que el de direcciones, y por eso no
 * se reutilizan `servidorPara` ni `aEntradas`:
 *
 *   - Para IPs, `services` trae `[["1.0.0.0/8", "1.1.0.0/16"], [urls]]` y hay
 *     que ganar el prefijo MAS LARGO que contiene la IP.
 *   - Para dominios trae `[["com", "net"], [urls]]`: una lista de sufijos en el
 *     primer elemento, no un prefijo. Si se pasara por `aEntradas`, el
 *     "prefijo" seria la cadena "com,net" y `ipaddr.contiene` reventaria.
 *
 * Tampoco hay prefijo mas largo que ganar: el TLD se busca tal cual.
 * ------------------------------------------------------------------ */

/**
 * Aplana el bootstrap de nombres a una lista de `[{tlds, urls}]`.
 *
 * @param {Array} [services] Lista `services` del bootstrap de IANA. Si falta o
 *   no es una lista, se devuelve vacío en lugar de reventar: quien llama
 *   esperando "no hay servidor para este TLD" y quien llama con un dato
 *   corrupto reciben la misma respuesta, que es la que sirve de verdad.
 * @returns {Array<{tlds: string[], urls: string[]}>}
 */
function entradasDeDominio(services) {
  const entradas = [];
  if (!Array.isArray(services)) return entradas;
  for (const servicio of services) {
    if (!Array.isArray(servicio) || !Array.isArray(servicio[0]) || !Array.isArray(servicio[1])) continue;
    const tlds = servicio[0].map((t) => String(t).toLowerCase().replace(/^\./, ''));
    if (!tlds.length) continue;
    entradas.push({ tlds, urls: servicio[1].map(String) });
  }
  return entradas;
}

/**
 * Elige el servidor RDAP que corresponde a un TLD.
 *
 * @param {string} tld
 * @param {Array} [services] Lista `services` del bootstrap. Sin ella no se sabe
 *   nada, y se devuelve `null`: el bootstrap se descarga, así que esta función
 *   no puede descargarlo por su cuenta sin volverse asíncrona.
 * @returns {{prefijo: string, urls: string[]}|null}
 */
function servidorParaTld(tld, services) {
  const objetivo = String(tld || '').toLowerCase().replace(/^\./, '');
  if (!objetivo) return null;
  for (const entrada of entradasDeDominio(services)) {
    if (entrada.tlds.includes(objetivo)) return { prefijo: objetivo, urls: entrada.urls };
  }
  return null;
}

/** Monta la URL de consulta de un dominio. */
function urlDeDominio(base, dominio) {
  return `${base.replace(/\/+$/, '')}/domain/${encodeURIComponent(dominio)}`;
}

/**
 * Traduce la respuesta de RDAP de un dominio a una forma plana y estable.
 *
 * Lo que interesa de un dominio es mucho mas limitado que lo de una IP: cuando
 * caduca, quien lo tiene y por que nombres responde. No se copia el objeto
 * entero, y en particular no se copian los contactos administrativo ni tecnico
 * que trae la vCard: son datos personales de los titulares y el informe no los
 * usa. El nombre del registrador si, porque es informacion publica del
 * registro y explica por ejemplo un bloqueo por DNSSEC.
 *
 * @param {object} datos Respuesta `application/rdap+json`.
 * @param {object} contexto `{dominio, tld, servidor}`.
 * @returns {object}
 */
function normalizarDominioRdap(datos, contexto) {
  const entidades = datos.entities;
  const registro = entidadesConRol(entidades, 'registrar')[0] || null;
  const titular = entidadesConRol(entidades, 'registrant')[0] || null;

  const dns =
    Array.isArray(datos.nameservers) ? datos.nameservers.map((n) => n?.ldhName || n?.unicodeName).filter(Boolean) : [];

  // Los estados de RDAP no son texto libre: hay un vocabulario cerrado (RFC 7483)
  // y casi todos los que existen son lo NORMAL en un dominio serio, no un
  // fallo. Casi todos los dominios del mundo tienen "client transfer
  // prohibited" para que nadie se los lleve por error, asi que avisar de eso
  // seria llenar el informe de ruido.
  const estados = Array.isArray(datos.status) ? datos.status.map((s) => String(s).toLowerCase()) : [];

  // Los dos unicos estados que impiden usar el dominio sin que este caducado.
  const retenciones = estados.filter((e) => e === 'client hold' || e === 'server hold');

  return {
    dominio: contexto.dominio,
    disponible: true,
    consultable: true,
    servidor: contexto.servidor,
    tld: contexto.tld,

    nombre: datos.ldhName || datos.unicodeName || contexto.dominio,
    handle: datos.handle || null,
    registrador: registro?.nombre || null,
    estados: estados.length ? estados.join(', ') : null,
    retenciones,
    pais: datos.country || null,
    titular: titular?.nombre || null,
    nombreservers: dns,

    registro: fechaDeEvento(datos.events, 'registration'),
    ultimoCambio: fechaDeEvento(datos.events, 'last changed'),
    caducidad: fechaDeEvento(datos.events, 'expiration'),

    nota: textoDeRemarks(datos.remarks),
    enlace: Array.isArray(datos.links) ? datos.links.find((l) => l?.rel === 'self')?.href || null : null
  };
}

/**
 * Consulta el registro de un dominio.
 *
 * La razon de existir es la caducidad: un nombre puede resolver perfectamente y
 * llevar meses sin pagarse, y el unico sitio que lo dice con certeza es el
 * registro.
 *
 * NO TODOS LOS TLD TIENEN RDAP PUBLICO. El bootstrap de IANA cubre la gran
 * mayoria, pero si el TLD no esta en la lista se devuelve `disponible: false`
 * con `consultable: false`, que es una respuesta valida: significa "este
 * registro no se puede consultar", NO "el dominio no existe". Confundir esas
 * dos cosas haria que el informe afirmara que un dominio esta vacio cuando en
 * realidad no lo ha preguntado nadie.
 *
 * @param {string} dominio Solo el nombre, sin esquema ni ruta.
 * @param {object} [opciones]
 * @param {Function} [opciones.fetchImpl] Doble de `fetch` para las pruebas.
 * @param {Array} [opciones.bootstrap] Services de IANA ya descargados.
 * @param {number} [opciones.timeoutMs]
 * @returns {Promise<object>}
 */
async function consultarDominio(dominio, opciones = {}) {
  const { fetchImpl, timeoutMs = 12000, bootstrap } = opciones;

  const nombre = String(dominio || '')
    .trim()
    .toLowerCase()
    .replace(/^\.+|\.+$/g, '');
  if (!nombre || !nombre.includes('.')) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${dominio}" no es un nombre de dominio.`, {
      remediation: 'Escribe un dominio con su TLD, por ejemplo ejemplo.com. Sin el TLD no hay registro que consultar.'
    });
  }

  const tld = nombre.slice(nombre.lastIndexOf('.') + 1);
  const services = bootstrap || (await cargarBootstrap('dns', { fetchImpl, timeoutMs }));
  const entrada = servidorParaTld(tld, services);

  if (!entrada || !entrada.urls.length) {
    return {
      dominio: nombre,
      disponible: false,
      consultable: false,
      motivo: `El TLD ".${tld}" no tiene un servidor RDAP publico, asi que no se puede comprobar la caducidad.`,
      tld,
      retenciones: [],
      nombreservers: []
    };
  }

  let ultimoError = null;
  let todos404 = true;

  for (const base of entrada.urls) {
    const url = urlDeDominio(base, nombre);
    try {
      const cuerpo = await getJSON({
        url,
        fetchImpl,
        timeoutMs,
        intentos: 2,
        servicio: 'el registro del dominio'
      });
      return normalizarDominioRdap(cuerpo, { dominio: nombre, tld, servidor: base });
    } catch (error) {
      ultimoError = error;

      // Un 404 de ESTE servidor es definitivo para el, pero puede que otro de
      // la lista lo tenga. Un fallo de red o un 500 tambien: se prueban los
      // demas y, si todos fallan, se reporta el ultimo.
      if (es404(error)) continue;
      todos404 = false;
    }
  }

  // Misma distincion que en el caso de las IPs, y por el mismo motivo: "todos
  // dijeron que no lo tienen" y "no se pudo preguntar" son dos mentiras
  // distintas. Un fallo de red nunca puede convertirse en "no esta registrado".
  if (todos404) {
    return {
      dominio: nombre,
      disponible: false,
      consultable: true,
      motivo: 'Ningun registro publico tiene asignado este dominio.',
      tld,
      retenciones: [],
      nombreservers: []
    };
  }

  throw new NetlabError(
    ultimoError?.code || CODES.API_EXTERNA,
    `Ningun servidor RDAP del registro respondio para ${nombre}.`,
    { remediation: 'Puede ser un fallo temporal del registro. Vuelve a intentarlo en unos minutos.', cause: ultimoError }
  );
}

/**
 * ¿Este error es un 404 del registro?
 *
 * Mira el estado HTTP que anotó `core/net/http`, y no solo el mensaje. Un 404
 * puede venir como `API_EXTERNA` o como `INTERNO` según quién haya escrito
 * el mensaje, y comprobar solo uno de los dos hacía que el paso al siguiente
 * servidor no llegara a ocurrir: el informe acababa diciendo que nadie
 * responde cuando solo había fallado el primero de dos.
 */
function es404(error) {
  if (error?.details?.httpStatus === 404) return true;
  return /404|no encontrado/i.test(error?.message || '');
}

/** Vacia la cache del bootstrap. Existe para las pruebas. */
function limpiarCache() {
  cacheBootstrap.clear();
}

module.exports = {
  consultar,
  consultarDominio,
  normalizar,
  normalizarDominioRdap,
  servidorPara,
  servidorParaTld,
  urlDeConsulta,
  urlDeDominio,
  entradasDeDominio,
  cargarBootstrap,
  limpiarCache,
  BOOTSTRAP,
  deVCard
};
