/**
 * mail/verificar.js — Verificación criptográfica real de SPF, DKIM y DMARC.
 *
 * A diferencia de los parsers (spf.js, dkim.js, dmarc.js) que solo leen lo que
 * dice el mensaje o el DNS, AQUI se VALIDA:
 *   - SPF: evaluar el registro contra IP + HELO reales (algoritmo RFC 7208)
 *   - DKIM: descargar clave pública, canonizar relaxed/simple, crypto.verify(bh, b)
 *   - DMARC: alinear header.from vs d= vs Return-Path, política p=, aspf/adkim
 *
 * Cada función devuelve un objeto con: { ok, estado, detalle, evidencia, avisos, errores }
 * que el mail-checker usa para construir checks con puntuación real.
 *
 * Los `estado` de cada veredicto son: 'ok' | 'warn' | 'error' | 'no-evaluable'.
 * "Sin registro" (ENODATA/ENOTFOUND/ENODOMAIN) es un WAR de configuración, no
 * una rotura de la red; un fallo de red de verdad es 'no-evaluable'.
 *
 * @module core/mail/verificar
 */

'use strict';

const crypto = require('node:crypto');
const dns = require('../net/dns');
const { parsear: parsearSpf } = require('./spf');
const { parsear: parsearDkim } = require('./dkim');
const { parsear: parsearDmarc } = require('./dmarc');
const { etiquetas, registrosTxt, nombreDkim } = require('./comun');

/** ¿Es un cese de DNS que significa "no está publicado" y no un problema de red? */
function esSinRegistro(error) {
  if (!error) return false;
  const codigo = (error.codigo || error.codigoDns || error.type || '').toString();
  return ['ENODATA', 'ENOTFOUND', 'ENODOMAIN', 'NODATA', 'NONAME'].includes(codigo);
}

/** Aplica el mapa "códigos DNS → estados" acordado con el mail-checker. */
function estadoDeRed(error) {
  return esSinRegistro(error) ? 'warn' : 'no-evaluable';
}

/**
 * Evalúa SPF contra IP y HELO reales (RFC 7208 simplificado).
 *
 * @param {string} dominio Dominio del remitente (from o return-path)
 * @param {string} ip IP del emisor
 * @param {string} helo HELO del servidor que entregó
 * @param {object} [opciones]
 * @param {string[]} [opciones.txt] TXT ya consultados por el llamador, para no repetir DNS.
 * @returns {Promise<object>}
 */
async function verificarSpf(dominio, ip, helo, opciones = {}) {
  const { timeout = 5000, dnsModulo = dns } = opciones;
  const avisos = [];
  const errores = [];
  const evidencia = { dominio, ip, helo, pasos: [] };

  let lista = opciones.txt;
  if (!Array.isArray(lista)) {
    const txt = await dnsModulo.consultar(dominio, 'TXT', { timeout, reintentos: 1 });
    if (!txt.ok) {
      const estado = estadoDeRed(txt);
      return {
        ok: false,
        estado,
        detalle: estado === 'warn' ? 'El dominio no publica SPF' : `No se pudo consultar el TXT de ${dominio}`,
        evidencia,
        avisos: estado === 'warn' ? ['Sin registro SPF'] : [],
        errores: estado === 'warn' ? [] : [txt.error || 'DNS falló']
      };
    }
    lista = registrosTxt(txt);
  }

  const spf = parsearSpf(lista);
  if (!spf.presente) {
    avisos.push('El dominio no publica SPF');
    return { ok: false, estado: 'warn', detalle: 'Sin registro SPF: cualquiera puede enviar en nombre del dominio', evidencia, avisos, errores };
  }
  if (spf.multiple) {
    errores.push('Múltiples registros SPF (permerror)');
    return { ok: false, estado: 'error', detalle: 'Varios registros SPF publicados', evidencia, avisos, errores };
  }
  if (!spf.valido) {
    errores.push(...spf.errores);
    return { ok: false, estado: 'error', detalle: spf.errores.join('; '), evidencia, avisos, errores };
  }

  const resultado = await evaluarMecanismosSpf(spf, ip, helo, dominio, dnsModulo, timeout, evidencia);
  evidencia.pasos.push({ fase: 'evaluacion', ...resultado });

  if (resultado.resultado === 'pass') {
    return { ok: true, estado: 'ok', detalle: 'SPF validado: la IP está autorizada', evidencia, avisos: [...avisos, ...spf.avisos], errores: [] };
  }
  if (resultado.resultado === 'fail') {
    return { ok: false, estado: 'error', detalle: 'SPF falla: la IP no está autorizada', evidencia, avisos: [...avisos, ...spf.avisos], errores: ['IP no autorizada por SPF'] };
  }
  if (resultado.resultado === 'softfail') {
    return { ok: false, estado: 'warn', detalle: 'SPF softfail: la IP no está claramente autorizada', evidencia, avisos: [...avisos, ...spf.avisos, 'Softfail (~all): tratado como advertencia'], errores: [] };
  }
  if (resultado.resultado === 'neutral') {
    return { ok: false, estado: 'warn', detalle: 'SPF neutral: no afirma nada', evidencia, avisos: [...avisos, ...spf.avisos, 'Neutral (?all): no se puede confirmar'], errores: [] };
  }
  if (resultado.resultado === 'permerror') {
    return { ok: false, estado: 'error', detalle: 'SPF permerror: malformado al evaluar', evidencia, avisos: [...avisos, ...spf.avisos], errores: [resultado.razon] };
  }
  // none, temperror
  if (resultado.resultado === 'temperror') {
    return { ok: false, estado: 'no-evaluable', detalle: 'SPF temperror: falló una consulta DNS durante la evaluación', evidencia, avisos, errores: [resultado.razon] };
  }
  return { ok: false, estado: 'warn', detalle: `SPF ${resultado.resultado}: no se pudo confirmar autorización`, evidencia, avisos: [...avisos, ...spf.avisos], errores: [] };
}

/**
 * Evalúa los mecanismos de un SPF ya parseado contra IP y HELO.
 * Implementación simplificada: include (recursivo 1 nivel), a, mx, ip4, ip6, all.
 */
async function evaluarMecanismosSpf(spf, ip, helo, dominioOrigen, dnsModulo, timeout, evidencia) {
  const esIp6 = ip.includes(':');

  for (const m of spf.mecanismos) {
    if (m.consulta === false) {
      if (m.nombre === 'ip4' && !esIp6) {
        if (ipEnCidr(ip, m.valor)) return { resultado: 'pass', mecanismo: m.termino, razon: `IP coincide con ${m.valor}` };
      }
      if (m.nombre === 'ip6' && esIp6) {
        if (ipEnCidr(ip, m.valor)) return { resultado: 'pass', mecanismo: m.termino, razon: `IP coincide con ${m.valor}` };
      }
      if (m.nombre === 'all') {
        const calif = m.calificador || '+';
        return { resultado: calificadorAResultado(calif), mecanismo: m.termino, razon: 'all' };
      }
      continue;
    }

    if (m.nombre === 'include') {
      const sub = await evaluarInclude(m.valor, ip, dnsModulo, timeout);
      if (['pass', 'fail', 'softfail'].includes(sub.resultado)) {
        return { resultado: sub.resultado, mecanismo: m.termino, razon: `include:${m.valor} => ${sub.resultado}` };
      }
      if (sub.resultado === 'temperror') {
        return { resultado: 'temperror', mecanismo: m.termino, razon: `include:${m.valor} => DNS intermitente` };
      }
      // neutral/permerror => sigue al siguiente mecanismo
    }
    if (m.nombre === 'a') {
      const host = m.valor || dominioOrigen;
      const a = await dnsModulo.consultar(host, 'A', { timeout, reintentos: 1 });
      if (a.ok && a.valores.some((v) => v === ip)) return { resultado: 'pass', mecanismo: m.termino, razon: `A de ${host} coincide` };
      if (esIp6) {
        const aaaa = await dnsModulo.consultar(host, 'AAAA', { timeout, reintentos: 1 });
        if (aaaa.ok && aaaa.valores.some((v) => v === ip)) return { resultado: 'pass', mecanismo: m.termino, razon: `AAAA de ${host} coincide` };
      }
    }
    if (m.nombre === 'mx') {
      const host = m.valor || dominioOrigen;
      const mx = await dnsModulo.consultar(host, 'MX', { timeout, reintentos: 1 });
      if (mx.ok && mx.valores.length) {
        for (const mxHost of mx.valores.map((v) => String(v.exchange || '').replace(/\.$/, ''))) {
          const a = await dnsModulo.consultar(mxHost, 'A', { timeout, reintentos: 1 });
          if (a.ok && a.valores.some((v) => v === ip)) return { resultado: 'pass', mecanismo: m.termino, razon: `MX ${mxHost} resuelve a la IP` };
          if (esIp6) {
            const aaaa = await dnsModulo.consultar(mxHost, 'AAAA', { timeout, reintentos: 1 });
            if (aaaa.ok && aaaa.valores.some((v) => v === ip)) return { resultado: 'pass', mecanismo: m.termino, razon: `MX ${mxHost} AAAA coincide` };
          }
        }
      }
    }
    // ptr, exists, redirect: se tratan como neutral (no disparan coincidencia).
  }
  const allMec = spf.mecanismos.find((m) => m.nombre === 'all');
  const calif = allMec?.calificador || '+';
  return { resultado: calificadorAResultado(calif), mecanismo: allMec?.termino || 'all (implícito)', razon: 'ningún mecanismo previo pasó' };
}

async function evaluarInclude(dominioInclude, ip, dnsModulo, timeout) {
  const txt = await dnsModulo.consultar(dominioInclude, 'TXT', { timeout, reintentos: 1 });
  if (!txt.ok) return { resultado: 'temperror', razon: `DNS falló para include:${dominioInclude}` };
  const spf = parsearSpf(registrosTxt(txt));
  if (!spf.presente || !spf.valido) return { resultado: 'permerror', razon: `include:${dominioInclude} inválido` };
  const esIp6 = ip.includes(':');
  for (const m of spf.mecanismos) {
    if (m.nombre === 'ip4' && !esIp6 && ipEnCidr(ip, m.valor)) return { resultado: 'pass', razon: `include:${dominioInclude} ip4 coincide` };
    if (m.nombre === 'ip6' && esIp6 && ipEnCidr(ip, m.valor)) return { resultado: 'pass', razon: `include:${dominioInclude} ip6 coincide` };
    if (m.nombre === 'a') {
      const host = m.valor || dominioInclude;
      const a = await dnsModulo.consultar(host, 'A', { timeout, reintentos: 1 });
      if (a.ok && a.valores.some((v) => v === ip)) return { resultado: 'pass', razon: `include:${dominioInclude} A coincide` };
    }
    if (m.nombre === 'mx') {
      const host = m.valor || dominioInclude;
      const mx = await dnsModulo.consultar(host, 'MX', { timeout, reintentos: 1 });
      if (mx.ok) {
        for (const mxHost of mx.valores.map((v) => String(v.exchange || '').replace(/\.$/, ''))) {
          const a = await dnsModulo.consultar(mxHost, 'A', { timeout, reintentos: 1 });
          if (a.ok && a.valores.some((v) => v === ip)) return { resultado: 'pass', razon: `include:${dominioInclude} MX coincide` };
        }
      }
    }
    if (m.nombre === 'all') {
      return { resultado: calificadorAResultado(m.calificador || '+') };
    }
  }
  const allMec = spf.mecanismos.find((x) => x.nombre === 'all');
  return { resultado: calificadorAResultado(allMec?.calificador || '+') };
}

function ipEnCidr(ip, cidr) {
  if (!cidr) return false;
  const [base, bits] = cidr.split('/');
  if (!bits) return ip === base;
  if (ip.includes(':') || base.includes(':')) return ipAEntero(ip) === ipAEntero(base); // simplificación IPv6: solo coincidencia exacta
  const ipBits = ipAEntero(ip);
  const baseBits = ipAEntero(base);
  const mask = (0xffffffff << (32 - parseInt(bits, 10))) >>> 0;
  return (ipBits & mask) === (baseBits & mask);
}

function ipAEntero(ip) {
  if (ip.includes(':')) {
    // IPv6 → 128 bits; aquí solo se usa para comparar igualdad exacta.
    const completo = ip.split('::')[0].split(':');
    return BigInt('0x' + completo.map((h) => h.padStart(4, '0')).join('') || '0');
  }
  return ip.split('.').reduce((a, b) => (a << 8) + parseInt(b, 10), 0) >>> 0;
}

function calificadorAResultado(c) {
  if (c === '+') return 'pass';
  if (c === '-') return 'fail';
  if (c === '~') return 'softfail';
  if (c === '?') return 'neutral';
  return 'neutral';
}

/* ------------------------------------------------------------------ *
 * Canonización DKIM (RFC 6376 §3.4)
 * ------------------------------------------------------------------ */

/**
 * Canoniza el cuerpo para calcular `bh`. El .eml ya viene normalizado a \n por
 * el parser; se devuelve el resultado con saltos \r\n como manda el RFC.
 *
 * @param {string} cuerpo
 * @param {'simple'|'relaxed'} [metodo='simple']
 * @returns {string}
 */
function canonizarCuerpo(cuerpo, metodo = 'simple') {
  let t = String(cuerpo ?? '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  if (metodo === 'relaxed') {
    t = t
      .split('\n')
      .map((l) => l.replace(/[ \t]+/g, ' ').replace(/^[ \t]+|[ \t]+$/g, ''))
      .join('\n');
  }
  // simple y relaxed quitan las líneas vacías finales; si no queda nada, el
  // cuerpo es vacío (bh de la cadena vacía).
  const lineas = t.split('\n');
  while (lineas.length && lineas[lineas.length - 1] === '') lineas.pop();
  if (!lineas.length) return '';
  return lineas.join('\r\n') + '\r\n';
}

/**
 * Canoniza las cabeceras del mensaje según la lista `h=` de la firma.
 *
 * La implementación trabaja sobre las cabeceras ya plegadas y agrupadas por el
 * parser (mensaje.cabeceras). En relaxed se reconstruye fielmente (el RFC
 * normaliza minúsculas y espacios, así que plegado y mayúsculas no importan).
 * En simple se usa el nombre en minúsculas que guarda el parser: suficiente
 * para verificar firmas propias y un buen aproximado para las ajenas.
 *
 * @param {object} mensaje Resultado de mensaje.parsear()
 * @param {string[]} lista Nombres de cabecera del `h=` de la firma
 * @param {'simple'|'relaxed'} [metodo='simple']
 * @returns {string}
 */
function canonizarCabeceras(mensaje, lista, metodo = 'simple') {
  const salida = [];
  const canonSolaLinea = (clave, valor) => {
    let linea = `${clave}:${valor}`;
    if (clave === 'dkim-signature') {
      // La propia DKIM-Signature se incluye sin su valor `b=` (RFC 6376 §3.7.2.2);
      // el `;` que Exim deja tras el valor también se descarta al reconstruir.
      linea = linea.replace(/\bb\s*=[^;]*;?/, 'b=');
    }
    if (metodo === 'relaxed') {
      // RFC 6376 §3.4.2: sin espacio tras los dos puntos, secuencias de WSP
      // colapsadas a un espacio y sin WSP final.
      linea = linea.replace(/^([^:]+):[ \t]*/, '$1:');
      linea = linea.replace(/[ \t]+/g, ' ').trim();
    }
    return linea;
  };
  for (const nombre of lista) {
    const clave = String(nombre).trim().toLowerCase();
    const valores = mensaje.cabeceras?.[clave] || [];
    if (!valores.length) continue; // cabecera ausente: el signatario la trata como vacía
    salida.push(canonSolaLinea(clave, valores[valores.length - 1]));
  }
  // RFC 6376 §3.7: al verificar, la propia DKIM-Signature se añade al final del
  // hash aunque el signatario no la haya incluido en `h=` (Exim/OpenDKIM no la
  // listan). Solo se añade si no figura ya entre las cabeceras firmadas.
  const enLista = lista.map((n) => String(n).trim().toLowerCase()).includes('dkim-signature');
  if (!enLista) {
    const valores = mensaje.cabeceras?.['dkim-signature'] || [];
    if (valores.length) salida.push(canonSolaLinea('dkim-signature', valores[valores.length - 1]));
  }
  return salida.join('\r\n') + (salida.length ? '\r\n' : '');
}

/** Algoritmo de hash de una firma a partir de su `a=`. */
function hashDeAlgoritmo(algoritmo) {
  if (!algoritmo) return 'sha256';
  if (/sha1/i.test(algoritmo)) return 'sha1';
  return 'sha256';
}

/* ------------------------------------------------------------------ *
 * Verificación DKIM
 * ------------------------------------------------------------------ */

/**
 * Verifica DKIM criptográficamente: descarga clave pública, canoniza, verifica bh y b.
 *
 * @param {object} mensaje Resultado de mensaje.parsear()
 * @param {string} selector Selector DKIM a verificar (el que firmó)
 * @param {string} dominio Dominio d= de la firma
 * @param {object} [opciones]
 * @returns {Promise<object>}
 */
async function verificarDkim(mensaje, selector, dominio, opciones = {}) {
  const { timeout = 5000, dnsModulo = dns } = opciones;
  const avisos = [];
  const errores = [];
  const evidencia = { selector, dominio, pasos: [] };

  const firma = mensaje.dkimFirmas?.find((f) => f.selector === selector && f.dominio === dominio);
  if (!firma) {
    return { ok: false, estado: 'error', detalle: `No hay firma DKIM con selector "${selector}" y dominio "${dominio}"`, evidencia, avisos, errores: ['Firma no encontrada en el mensaje'] };
  }

  const nombre = nombreDkim(selector, dominio);
  const txt = await dnsModulo.consultar(nombre, 'TXT', { timeout, reintentos: 1 });
  if (!txt.ok) {
    const estado = estadoDeRed(txt);
    return {
      ok: false,
      estado,
      detalle: estado === 'warn' ? `${nombre} no publica clave DKIM` : `No se pudo consultar la clave DKIM en ${nombre}`,
      evidencia,
      avisos: estado === 'warn' ? ['Selector sin clave publicada'] : [],
      errores: estado === 'warn' ? [] : [txt.error || 'DNS falló']
    };
  }

  const parseado = parsearDkim(registrosTxt(txt), { selector, dominio });
  if (!parseado.encontrado) {
    return { ok: false, estado: 'error', detalle: `No hay clave DKIM válida en ${nombre}`, evidencia, avisos, errores: ['Clave no encontrada'] };
  }
  if (parseado.revocada) {
    return { ok: false, estado: 'error', detalle: 'Clave DKIM revocada (p= vacía)', evidencia, avisos, errores: ['p= vacía: clave revocada'] };
  }
  if (!parseado.valido) {
    return { ok: false, estado: 'error', detalle: `Clave DKIM inválida: ${parseado.errores.join('; ')}`, evidencia, avisos, errores: parseado.errores };
  }

  const tags = firma.etiquetas || {};
  const b = tags.b ? tags.b.replace(/[\s\r\n]+$/, '') : '';
  const bh = firma.cuerpoHash ? firma.cuerpoHash.replace(/[\s]+$/, '') : '';

  if (!b || !bh) {
    avisos.push('La firma no trae "b=" y/o "bh=": no hay verificación criptográfica posible');
    return { ok: false, estado: 'no-evaluable', detalle: 'La firma DKIM no trae "b=" (o "bh="): no hay firma que verificar', evidencia, avisos, errores: [] };
  }

  const c = (tags.c || 'simple/simple').split('/');
  const metodoCuerpo = (c[1] || 'simple') === 'relaxed' ? 'relaxed' : 'simple';
  const metodoCabeceras = (c[0] || 'simple') === 'relaxed' ? 'relaxed' : 'simple';
  const hash = hashDeAlgoritmo(firma.algoritmo || tags.a);
  const lista = firma.encabezados || [];

  // 1) bh es un hash del cuerpo; si no cuadra, la firma cubre otro cuerpo.
  const cuerpoCanon = canonizarCuerpo(mensaje.cuerpo, metodoCuerpo);
  const bhCalculado = crypto.createHash(hash).update(cuerpoCanon).digest();
  const bhFirma = Buffer.from(bh, 'base64');
  if (!bhFirma.length || bhCalculado.length !== bhFirma.length || !bhCalculado.equals(bhFirma)) {
    errores.push('El hash del cuerpo (bh) no coincide con el del mensaje');
    return { ok: false, estado: 'error', detalle: 'El cuerpo del mensaje fue modificado: el "bh=" de la firma no cuadra', evidencia, avisos, errores };
  }

  // 2) b es la firma de las cabeceras con la clave pública publicada.
  let clavePublica;
  try {
    const tag = etiquetas(parseado.valor);
    const p = (tag.p || '').replace(/\s+/g, '');
    clavePublica = crypto.createPublicKey({ key: Buffer.from(p, 'base64'), format: 'der', type: 'spki' });
  } catch (e) {
    errores.push(`Clave pública ilegible: ${e.message}`);
    return { ok: false, estado: 'error', detalle: 'La clave "p=" del selector no se puede usar', evidencia, avisos, errores };
  }

  const detalleClave = parseado.tipoClave === 'ed25519' ? 'Ed25519' : `RSA ${parseado.bits || '?'} bits`;
  evidencia.pasos.push({ fase: 'clave', tipo: detalleClave, bits: parseado.bits || null });

  if (parseado.tipoClave === 'ed25519' || !parseado.valor) {
    // Ed25519 en DKIM viaja cruda (32 bytes), no como SPKI: se informa de la
    // clave pero no se implementa la verificación ed25519.
    avisos.push('Firma ed25519: se reconoce la clave pero la verificación de esta herramienta es solo RSA');
    return { ok: true, estado: 'warn', detalle: `Clave ${detalleClave} presente, pero ed25519 no se verifica aquí`, evidencia, avisos, errores };
  }

  const cabecerasCanon = canonizarCabeceras(mensaje, lista, metodoCabeceras);
  let valida;
  try {
    valida = crypto.verify(hash, cabecerasCanon, clavePublica, Buffer.from(b, 'base64'));
  } catch (e) {
    errores.push(`crypto.verify falló: ${e.message}`);
    return { ok: false, estado: 'error', detalle: `No se pudo verificar la firma: ${e.message}`, evidencia, avisos, errores };
  }

  if (!valida) {
    errores.push('La firma de las cabeceras (b) no valida con la clave pública');
    return { ok: false, estado: 'error', detalle: 'La firma DKIM no valida: el mensaje fue alterado o la clave del selector no es la correcta', evidencia, avisos, errores };
  }

  evidencia.pasos.push({ fase: 'verificacion', metodoCabeceras, metodoCuerpo, hash, cabeceras: lista.length });
  return {
    ok: true,
    estado: 'ok',
    detalle: `Firma DKIM válida (${detalleClave}, c=${c.join('/')})`,
    evidencia,
    avisos: [...avisos, ...parseado.avisos].filter(Boolean),
    errores: []
  };
}

/* ------------------------------------------------------------------ *
 * Verificación DMARC
 * ------------------------------------------------------------------ */

/**
 * Verifica DMARC: alineación SPF/DKIM con header.from, política, pct, subdominios.
 *
 * @param {object} mensaje Resultado de mensaje.parsear()
 * @param {object} spfResultado Resultado de verificarSpf()
 * @param {object} dkimResultado Resultado de verificarDkim()
 * @param {string} dominioFrom Dominio de header From
 * @param {object} [opciones]
 * @param {string[]} [opciones.txt] TXT de _dmarc ya consultados por el llamador.
 * @returns {Promise<object>}
 */
async function verificarDmarc(mensaje, spfResultado, dkimResultado, dominioFrom, opciones = {}) {
  const { timeout = 5000, dnsModulo = dns } = opciones;
  const avisos = [];
  const errores = [];
  const evidencia = { dominio: dominioFrom, pasos: [] };

  let lista = opciones.txt;
  if (!Array.isArray(lista)) {
    let txt = await dnsModulo.consultar(`_dmarc.${dominioFrom}`, 'TXT', { timeout, reintentos: 1 });
    evidencia.heredadoDe = null;
    if (!txt.ok) {
      const partes = dominioFrom.split('.');
      if (partes.length > 2) {
        const padre = partes.slice(-2).join('.');
        const txtPadre = await dnsModulo.consultar(`_dmarc.${padre}`, 'TXT', { timeout, reintentos: 1 });
        if (txtPadre.ok) {
          txt = txtPadre;
          evidencia.heredadoDe = padre;
        }
      }
    }
    if (!txt.ok) {
      const estado = estadoDeRed(txt);
      avisos.push(estado === 'warn' ? 'El dominio no publica DMARC' : 'DNS de DMARC no disponible');
      return {
        ok: false,
        estado,
        detalle: estado === 'warn' ? 'Sin DMARC: no hay política que cumpla' : 'No se pudo consultar el registro DMARC',
        evidencia,
        avisos,
        errores: estado === 'warn' ? [] : [txt.error || 'DNS falló']
      };
    }
    lista = registrosTxt(txt);
  }

  const dmarcParseado = parsearDmarc(lista);
  if (!dmarcParseado.presente || !dmarcParseado.politica) {
    avisos.push('El dominio no publica DMARC');
    return { ok: false, estado: 'warn', detalle: 'Sin DMARC: SPF y DKIM no se alinean con From', evidencia, avisos, errores: [] };
  }
  if (!dmarcParseado.valido) {
    errores.push(...dmarcParseado.errores);
    return { ok: false, estado: 'error', detalle: `DMARC inválido: ${dmarcParseado.errores.join('; ')}`, evidencia, avisos: [...avisos, ...dmarcParseado.avisos], errores };
  }

  const aspf = dmarcParseado.aspf || 'r';
  const returnPathDominio = mensaje.returnPathDominio;
  const spfAlineado = aspf === 's'
    ? returnPathDominio === dominioFrom
    : (returnPathDominio?.endsWith(`.${dominioFrom}`) || returnPathDominio === dominioFrom);

  const adkim = dmarcParseado.adkim || 'r';
  const dkimDominio = dkimResultado?.evidencia?.dominio || null;
  const dkimAlineado = dkimResultado?.ok && dkimDominio
    ? (adkim === 's'
        ? dkimDominio === dominioFrom
        : (dkimDominio?.endsWith(`.${dominioFrom}`) || dkimDominio === dominioFrom))
    : Boolean(dkimResultado?.ok && (mensaje.dkim || []).some((d) => d.resultado === 'pass' && d.dominio === dominioFrom));

  const spfPass = spfResultado?.ok === true;
  const dkimPass = dkimResultado?.ok === true;

  let resultadoDmarc = 'fail';
  if ((spfPass && spfAlineado) || (dkimPass && dkimAlineado)) resultadoDmarc = 'pass';

  const politica = dmarcParseado.politica || 'none';
  let accion = 'none';
  if (resultadoDmarc === 'fail' && politica === 'reject') accion = 'reject';
  else if (resultadoDmarc === 'fail' && politica === 'quarantine') accion = 'quarantine';

  const pct = dmarcParseado.pct ?? 100;
  if (pct < 100 && accion !== 'none') avisos.push(`pct=${pct}: la política solo se aplica al ${pct}% de mensajes`);

  evidencia.pasos.push({
    fase: 'dmarc',
    politica,
    aspf,
    adkim,
    spfPass,
    spfAlineado,
    dkimPass,
    dkimAlineado,
    resultado: resultadoDmarc,
    accion,
    pct
  });

  const estado = resultadoDmarc === 'pass' ? 'ok' : 'error';
  return {
    ok: resultadoDmarc === 'pass',
    estado,
    detalle: `DMARC ${resultadoDmarc} (política ${politica}, acción ${accion})`,
    evidencia,
    avisos: [...avisos, ...dmarcParseado.avisos].filter(Boolean),
    errores: resultadoDmarc === 'fail' ? ['Ni SPF ni DKIM alinean con el "From"'] : []
  };
}

module.exports = {
  verificarSpf,
  verificarDkim,
  verificarDmarc,
  evaluarMecanismosSpf,
  evaluarInclude,
  canonizarCuerpo,
  canonizarCabeceras,
  ipEnCidr,
  ipAEntero,
  calificadorAResultado,
  esSinRegistro,
  estadoDeRed
};