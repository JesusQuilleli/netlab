/**
 * net/dns.js — Consultas DNS con timeout, reintentos y concurrencia limitada.
 *
 * MODULO QUE CORRIGE UN CUELGUE REAL. En legacy/Check DNS/dns_validator_js.js
 * las consultas se hacian directamente con `dns.Resolver().resolveTxt()`,
 * que NO tiene timeout propio: si un servidor no responde, el script se
 * queda esperando indefinidamente. En un servidor eso es un proceso zombi.
 *
 * Aqui cada consulta tiene plazo maximo, reintenta con espera creciente, y
 * todas las consultas de una herramienta pasan por un semaforo de concurrencia
 * para no saturar la VPS.
 *
 * @module core/net/dns
 */

'use strict';

const dns = require('node:dns').promises;
const { NetlabError, CODES, wrap } = require('../errors');

/** Resolvers publicos por defecto: se consulta fuera de la cache local. */
const RESOLVERS_PUBLICOS = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];

/**
 * Crea un resolver apuntando a servidores especificos, evitando la cache local.
 *
 * @param {string[]} [servers]
 * @returns {import('node:dns').Resolver}
 */
function crearResolver(servers = RESOLVERS_PUBLICOS) {
  const resolver = new dns.Resolver({ timeout: 3000, tries: 2 });
  resolver.setServers(servers);
  return resolver;
}

/**
 * Ejecuta una operacion con plazo maximo. Lanza TIMEOUT si no termina a tiempo.
 *
 * @template T
 * @param {Promise<T>} promesa
 * @param {number} ms Plazo en milisegundos.
 * @param {string} contexto Texto para el mensaje de error.
 * @returns {Promise<T>}
 */
function conTimeout(promesa, ms, contexto) {
  let temporizador;
  const plazo = new Promise((_resolve, reject) => {
    temporizador = setTimeout(() => {
      reject(
        new NetlabError(CODES.TIMEOUT, `Tiempo agotado (${ms} ms) ${contexto}.`, {
          remediation: 'El servidor DNS no respondió a tiempo. Puede ser un problema de red o de resolución.'
        })
      );
    }, ms);
  });

  return Promise.race([promesa, plazo]).finally(() => clearTimeout(temporizador));
}

/**
 * Reintenta una operacion con espera creciente.
 *
 * Lanza el error CRUDO del resolvedor, sin envolver. Quien llama es quien sabe
 * que frase usar para describir la consulta, y ademas necesita el codigo
 * original (`ENOTFOUND`, `ENODATA`, `ESERVFAIL`) para decidir si un nombre no
 * existe o simplemente no tiene registros de ese tipo. Envolver aqui perdia
 * esa informacion y producia mensajes como "al la consulta DNS".
 *
 * @template T
 * @param {() => Promise<T>} operacion
 * @param {object} [options]
 * @param {number} [options.reintentos=2]
 * @param {number} [options.esperaInicial=250]
 * @returns {Promise<T>}
 * @throws {Error} El ultimo error, tal cual lo dio el resolvedor.
 */
async function conReintento(operacion, options = {}) {
  const { reintentos = 2, esperaInicial = 250 } = options;
  let ultimoError;

  for (let intento = 0; intento <= reintentos; intento++) {
    try {
      return await operacion();
    } catch (error) {
      ultimoError = error;
      // No tiene sentido reintentar un NXDOMAIN ni un error de parametro.
      if (!esReintentable(error) || intento === reintentos) break;
      await new Promise((r) => setTimeout(r, esperaInicial * 2 ** intento));
    }
  }

  throw ultimoError;
}

/** Decide si un error de DNS merece otro intento. */
function esReintentable(error) {
  // NXDOMAIN / ENODATA son respuestas definitivas, no fallos transitorios.
  const definitivos = ['ENOTFOUND', 'ENODATA', 'ENODOMAIN', 'ESERVFAIL', 'EREFUSED'];
  return !definitivos.includes(error?.code);
}

/**
 * Semaforo simple para limitar cuantas consultas DNS salen a la vez.
 *
 * @param {number} limite Máximo de operaciones simultaneas.
 * @returns {<T>(fn: () => Promise<T>) => Promise<T>}
 */
function limitarConcurrencia(limite) {
  const pendientes = [];
  let activas = 0;

  return function ejecutar(fn) {
    return new Promise((resolve, reject) => {
      const correr = async () => {
        // Ojo al nombre: se declara `activas` y se usa `activos` en el mismo
        // bloque. En modo estricto eso es un ReferenceError, y en laxo se
        // crea una variable global suelta. Nadie lo notaba porque
        // `consultarLote`, que es quien usa este semaforo, no lo cubria        // ninguna prueba.
        activas++;
        try {
          resolve(await fn());
        } catch (error) {
          reject(error);
        } finally {
          activas--;
          const siguiente = pendientes.shift();
          if (siguiente) siguiente();
        }
      };

      if (activas < limite) correr();
      else pendientes.push(correr);
    });
  };
}

/**
 * Consulta un registro DNS con todas las protecciones aplicadas.
 *
 * @param {string} nombre Nombre a consultar.
 * @param {string} tipo Tipo ('TXT', 'MX', 'A'...).
 * @param {object} [options]
 * @param {string[]} [options.servers]
 * @param {number} [options.timeout=5000]
 * @param {number} [options.reintentos=2]
 * @returns {Promise<{ok: boolean, valores: any[], ttl: number|null, error: string|null, codigo: string|null}>}
 *   Nunca lanza: los errores de red van en el campo `error` para que la
 *   herramienta pueda reportarlos por registro en vez de abortar todo.
 */
async function consultar(nombre, tipo, options = {}) {
  const { servers = RESOLVERS_PUBLICOS, timeout = 5000, reintentos = 2 } = options;

  const resolver = crearResolver(servers);

  const METODOS = {
    TXT: 'resolveTxt',
    MX: 'resolveMx',
    A: 'resolve4',
    AAAA: 'resolve6',
    CNAME: 'resolveCname',
    NS: 'resolveNs',
    SRV: 'resolveSrv',
    CAA: 'resolveCaa',
    SOA: 'resolveSoa',
    PTR: 'resolvePtr'
  };

  // Node solo expone el TTL en los registros de direccion: `resolve4` y
  // `resolve6` lo devuelven como `[{address, ttl}]` cuando se pide con
  // `{ttl: true}`. Comprobado contra la resolucion real: `resolveCname`,
  // `resolveNs`, `resolveMx`, `resolveTxt`, `resolveCaa` y `resolveSoa`
  // ignoran esa opcion y devuelven el valor pelado, sin TTL. Para esos tipos se
  // devuelve null, que es preferible a un TTL inventado: leer un TTL
  // erroneo en un informe de diagnostico cuesta mas que no mostrarlo.
  const CON_TTL = new Set(['A', 'AAAA']);

  const metodo = METODOS[String(tipo).toUpperCase()];
  if (!metodo) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `Tipo de registro no soportado: ${tipo}.`, {
      remediation: `Tipos disponibles: ${Object.keys(METODOS).join(', ')}.`
    });
  }

  const tipoNormalizado = String(tipo).toUpperCase();

  try {
    const bruto = await conReintento(
      () => conTimeout(
        CON_TTL.has(tipoNormalizado) ? resolver[metodo](nombre, { ttl: true }) : resolver[metodo](nombre),
        timeout,
        `consultando ${tipo} de ${nombre}`
      ),
      { reintentos }
    );

    const { valores, ttl } = normalizar(tipoNormalizado, bruto);
    return { ok: true, valores, ttl, error: null, codigo: null, codigoDns: null };
  } catch (error) {
    const envuelto = wrap(error, { contexto: `consultar ${tipo} de ${nombre}` });
    return {
      ok: false,
      valores: [],
      ttl: null,
      error: envuelto.message,
      codigo: envuelto.code || error?.code || null,
      // El codigo crudo del resolvedor es lo que permite a la herramienta
      // distinguir NXDOMAIN de NODATA de SERVFAIL. `codigo` es el codigo
      // interno de netlab, que agrupa varios fallos bajo el mismo nombre y no
      // sirve para decidir si un dominio existe.
      codigoDns: error?.code || null
    };
  }
}

/**
 * Deja los valores de un registro en una forma estable para los renderizadores
 * y extrae el TTL cuando Node lo provides.
 *
 * Con `{ttl: true}`, los registros de direccion llegan como `[{address, ttl}]`
 * en vez de como cadenas sueltas, asi que hay que aplanarlos. Los demas tipos
 * se dejan como los entrega el resolvedor.
 *
 * @param {string} tipo Tipo normalizado.
 * @param {any} bruto Lo que devuelve el metodo del resolvedor.
 * @returns {{valores: any[], ttl: number|null}}
 */
function normalizar(tipo, bruto) {
  if (tipo === 'SOA' && bruto && !Array.isArray(bruto)) return { valores: [bruto], ttl: null };

  const registros = Array.isArray(bruto) ? bruto : bruto ? [bruto] : [];

  if (!registros.length) return { valores: [], ttl: null };

  // Solo los registros de direccion traen `ttl` como numero.
  const ttls = registros.map((r) => (r && typeof r === 'object' ? r.ttl : null)).filter((t) => typeof t === 'number');
  const ttl = ttls.length ? Math.min(...ttls) : null;

  if (ttls.length) return { valores: registros.map((r) => r.address ?? r), ttl };

  if (tipo === 'CNAME' || tipo === 'NS') return { valores: registros.map(String), ttl };
  return { valores: registros, ttl };
}

/**
 * Consulta el TTL real de un nombre.
 *
 * Usa el resolvedor por defecto del sistema con `resolveAny` para leer la
 * cabecera TTL, que no exponen los metodos por tipo.
 *
 * @param {string} nombre
 * @param {object} [options]
 * @returns {Promise<number|null>}
 */
async function consultarTTL(nombre, options = {}) {
  const { timeout = 3000 } = options;
  try {
    const registros = await conTimeout(dns.resolveAny(nombre), timeout, `leyendo el TTL de ${nombre}`);
    const t = registros.find((r) => typeof r.ttl === 'number');
    return t ? t.ttl : null;
  } catch {
    return null;
  }
}

/**
 * Resolucion inversa (PTR) de una direccion IP.
 *
 * @param {string} ip
 * @returns {Promise<string[]>} Nombres encontrados; vacio si no hay PTR.
 */
async function resolverPTR(ip) {
  try {
    return await dns.reverse(ip);
  } catch {
    return [];
  }
}

/**
 * Consulta muchos registros a la vez, limitando la concurrencia.
 *
 * @param {Array<{nombre: string, tipo: string}>} consultas
 * @param {object} [options]
 * @param {number} [options.concurrencia=6]
 * @param {object} [options.dns] Opciones pasadas a `consultar`.
 * @returns {Promise<Array<{nombre, tipo, ...}>>}
 */
async function consultarLote(consultas, options = {}) {
  const { concurrencia = 6, dns: dnsOptions = {} } = options;
  const ejecutar = limitarConcurrencia(concurrencia);

  return Promise.all(
    consultas.map((c) =>
      ejecutar(async () => {
        const r = await consultar(c.nombre, c.tipo, dnsOptions);
        return { ...c, ...r };
      })
    )
  );
}

module.exports = {
  consultar,
  consultarLote,
  consultarTTL,
  resolverPTR,
  crearResolver,
  limitarConcurrencia,
  conTimeout,
  conReintento,
  RESOLVERS_PUBLICOS
};