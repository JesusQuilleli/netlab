/**
 * mail/spf.js — Lectura y valoración de un registro SPF.
 *
 * SPF se publica en UN SOLO registro TXT que empieza por `v=spf1`. Tener dos es
 * un error de configuración, no una suma: el receptor no sabe cuál aplicar y el
 * resultado es un `permerror`. Publicar uno que no empiece por `v=spf1`, o
 * gastar más de diez consultas DNS para evaluarlo, es igual de inútil: el
 * receptor abandona y SPF no protege nada.
 *
 * El contador de consultas es ESTÁTICO: se cuentan los mecanismos que disparan
 * una consulta (`include`, `a`, `mx`, `ptr`, `exists` y el modificador
 * `redirect`). No se sigue la recursión de un `include` hacia otro dominio, que
 * exigiría resolver DNS durante el análisis. Es la misma cifra que comprueban
 * la mayoría de herramientas de SPF, y se dice en el informe.
 *
 * @module core/mail/spf
 */

'use strict';

const { conPrefijo } = require('./comun');

/** Mecanismos que disparan una consulta DNS al evaluar el SPF. */
const CON_CONSULTA = new Set(['include', 'a', 'mx', 'ptr', 'exists']);

/** Mecanismos que no son consulta. */
const SIN_CONSULTA = new Set(['ip4', 'ip6', 'all']);

/** Calificadores válidos y su significado. */
const CALIFICADORES = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

/**
 * Interpreta los registros TXT de un dominio como SPF.
 *
 * @param {string[]} textos Registros TXT del dominio.
 * @param {object} [opciones]
 * @param {number} [opciones.limiteLookups=10]
 * @returns {object}
 */
function parsear(textos, opciones = {}) {
  const { limiteLookups = 10 } = opciones;
  const encontrados = conPrefijo(textos, 'v=spf1');

  const base = {
    presente: false,
    multiple: false,
    valor: null,
    valido: false,
    all: null,
    allCalificador: null,
    redirect: null,
    includes: [],
    mecanismos: [],
    lookups: 0,
    limiteLookups,
    excedeLimite: false,
    errores: [],
    avisos: []
  };

  if (!encontrados.length) return base;

  if (encontrados.length > 1) {
    return {
      ...base,
      presente: true,
      multiple: true,
      valor: encontrados[0],
      errores: [
        `Hay ${encontrados.length} registros SPF publicados. Solo puede haber uno: con varios, el receptor devuelve "permerror" y SPF no protege nada.`
      ],
      avisos: ['Fusiona todos los "include:" y mecanismos en un único registro.']
    };
  }

  const valor = encontrados[0];
  const terminos = valor.split(/\s+/).filter(Boolean);
  const mecanismos = [];
  const includes = [];
  const errores = [];
  const avisos = [];
  let lookups = 0;
  let redirect = null;
  let all = null;
  let allCalificador = null;
  let despuesDeAll = false;

  terminos.forEach((termino, indice) => {
    if (indice === 0) {
      if (!/^v=spf1$/i.test(termino)) {
        errores.push(`El registro no empieza por "v=spf1" sino por "${termino}".`);
      }
      return;
    }

    if (/^(redirect|exp)=/i.test(termino)) {
      const corte = termino.indexOf('=');
      const clave = termino.slice(0, corte).toLowerCase();
      const dato = termino.slice(corte + 1);
      if (clave === 'redirect') {
        redirect = dato;
        lookups++;
        mecanismos.push({ termino, nombre: 'redirect', valor: dato, calificador: null, consulta: true });
      } else {
        mecanismos.push({ termino, nombre: 'exp', valor: dato, calificador: null, consulta: false });
      }
      return;
    }

    const calificador = '+-~?'.includes(termino[0]) ? termino[0] : '+';
    const cuerpo = '+-~?'.includes(termino[0]) ? termino.slice(1) : termino;

    const corteDosPuntos = cuerpo.indexOf(':');
    const corteBarra = cuerpo.indexOf('/');
    let fin = cuerpo.length;
    if (corteDosPuntos >= 0) fin = Math.min(fin, corteDosPuntos);
    if (corteBarra >= 0) fin = Math.min(fin, corteBarra);

    const nombre = cuerpo.slice(0, fin).toLowerCase();
    const valorMecanismo = corteDosPuntos >= 0 ? cuerpo.slice(corteDosPuntos + 1) : '';

    if (nombre === 'all') {
      all = termino;
      allCalificador = calificador;
      despuesDeAll = true;
      mecanismos.push({ termino, nombre, valor: null, calificador, consulta: false });
      return;
    }

    if (despuesDeAll) {
      avisos.push(`"${termino}" aparece después de "all" y nunca se evalúa.`);
    }

    if (SIN_CONSULTA.has(nombre)) {
      mecanismos.push({ termino, nombre, valor: valorMecanismo || null, calificador, consulta: false });
      return;
    }

    if (CON_CONSULTA.has(nombre)) {
      lookups++;
      if (nombre === 'include') includes.push(valorMecanismo);
      mecanismos.push({ termino, nombre, valor: valorMecanismo || null, calificador, consulta: true });
      return;
    }

    // Cualquier otra cosa no es un mecanismo de SPF.
    errores.push(`"${termino}" no es un mecanismo o modificador de SPF reconocido.`);
    mecanismos.push({ termino, nombre, valor: valorMecanismo || null, calificador, consulta: false, desconocido: true });
  });

  const calificacionAll = allCalificador ? CALIFICADORES[allCalificador] : null;
  const excedeLimite = lookups > limiteLookups;

  if (!all && !redirect) {
    avisos.push(
      'No hay un "all" ni un "redirect" al final. Sin una política por defecto, un remitente no autorizado puede colarse como "neutral".'
    );
  }

  if (calificacionAll === 'pass') {
    errores.push('El "all" es "+all": autoriza a CUALQUIER servidor del mundo a enviar en tu nombre. Es la peor configuración posible.');
  } else if (calificacionAll === 'neutral') {
    avisos.push('El "?all" es neutral: no afirma nada de los remitentes no autorizados. Mejor "~all" o "-all".');
  }

  if (excedeLimite) {
    errores.push(
      `El registro suma ${lookups} consultas DNS y el límite es ${limiteLookups}. Un receptor puede devolver "permerror" y no evaluar SPF.`
    );
  } else if (lookups === limiteLookups) {
    avisos.push(`Está justo en el límite de ${limiteLookups} consultas DNS: cualquier cambio lo supera.`);
  }

  if (mecanismos.some((m) => m.nombre === 'ptr')) {
    avisos.push('El mecanismo "ptr" está desaconsejado por el RFC 7208: es lento y poco fiable.');
  }

  return {
    presente: true,
    multiple: false,
    valor,
    valido: errores.length === 0,
    all,
    allCalificador,
    calificacionAll,
    redirect,
    includes,
    mecanismos,
    lookups,
    limiteLookups,
    excedeLimite,
    errores,
    avisos
  };
}

module.exports = { parsear, CON_CONSULTA, SIN_CONSULTA, CALIFICADORES };
