/**
 * mail/mensaje.js — Lee un correo en formato fuente (.eml) y lo deja en piezas.
 *
 * Es el equivalente a lo que hace mail-tester cuando recibe tu correo: mirar las
 * cabeceras que dejaron los servidores por el camino, ver qué dijeron del SPF,
 * del DKIM y del DMARC, y separar el cuerpo para poder juzgar el contenido.
 *
 * El parser es deliberadamente tolerante: un .eml exportado a mano trae líneas
 * plegadas, cabeceras repetidas y cuerpos MIME anidados. Se pliegan las
 * continuaciones (las que empiezan por espacio o tabulador) porque sin eso un
 * `Authentication-Results` partido en tres líneas se lee como tres cabeceras
 * sin sentido.
 *
 * @module core/mail/mensaje
 */

'use strict';

const net = require('node:net');

/**
 * Parsea un mensaje completo.
 *
 * @param {string} texto Fuente del correo (.eml).
 * @returns {object}
 */
function parsear(texto) {
  const bruto = String(texto ?? '').replace(/\r\n/g, '\n');
  const corte = bruto.indexOf('\n\n');
  const cabeceraTexto = corte >= 0 ? bruto.slice(0, corte) : bruto;
  const cuerpo = corte >= 0 ? bruto.slice(corte + 2) : '';

  const cabeceras = parsearCabeceras(cabeceraTexto);
  const valor = (nombre) => (cabeceras[String(nombre).toLowerCase()] || [])[0] ?? null;
  const todas = (nombre) => cabeceras[String(nombre).toLowerCase()] || [];

  const recibidas = parsearRecibidas(todas('received'));
  const ipEmisor = ipDeRecibidas(recibidas);

  const auth = parsearAuthResults(todas('authentication-results'));
  const recibidoSpf = parsearRecibidoSpf(valor('received-spf'), ipEmisor);

  const contentType = valor('content-type') || 'text/plain; charset="utf-8"';
  const partes = parsearCuerpo(cuerpo, contentType, valor('content-transfer-encoding'));

  const mensaje = {
    cabeceras,
    recibidas,
    ipEmisor,
    auth,
    recibidoSpf,
    spf: auth.spf || recibidoSpf.spf || null,
    dkim: auth.dkim,
    dmarc: auth.dmarc,
    dkimFirmas: todas('dkim-signature').map(parsearFirma),
    from: valor('from'),
    fromDominio: dominioDe(valor('from')),
    returnPath: valor('return-path'),
    returnPathDominio: dominioDe(valor('return-path')),
    replyTo: valor('reply-to'),
    asunto: valor('subject'),
    messageId: valor('message-id'),
    fecha: valor('date'),
    mimeVersion: valor('mime-version'),
    listUnsubscribe: valor('list-unsubscribe'),
    listUnsubscribePost: valor('list-unsubscribe-post'),
    precedencia: valor('precedence'),
    cuerpo,
    texto: partes.texto.trim(),
    html: partes.html.trim(),
    adjuntos: partes.adjuntos,
    recibidasPlegadas: recibidas.length,
    avisos: [],
    errores: []
  };

  if (!mensaje.from) mensaje.avisos.push('El mensaje no tiene cabecera "From".');
  if (!mensaje.messageId) mensaje.avisos.push('El mensaje no tiene "Message-ID". Muchos filtros lo penalizan.');
  if (!mensaje.fecha) mensaje.avisos.push('El mensaje no tiene "Date".');

  return mensaje;
}

/** Pliega las cabeceras y las agrupa por nombre en minúsculas. */
function parsearCabeceras(texto) {
  const cabeceras = {};
  let actual = null;

  for (const linea of String(texto).split('\n')) {
    if (/^[ \t]/.test(linea) && actual) {
      // Continuación: se une con un espacio, según el RFC 5322.
      cabeceras[actual][cabeceras[actual].length - 1] += ` ${linea.trim()}`;
      continue;
    }
    const corte = linea.indexOf(':');
    if (corte <= 0) continue;
    actual = linea.slice(0, corte).trim().toLowerCase();
    const contenido = linea.slice(corte + 1).trim();
    (cabeceras[actual] ||= []).push(contenido);
  }

  return cabeceras;
}

/** Cada cabecera Received, ya plegada. */
function parsearRecibidas(valores) {
  return valores.map((v) => String(v).trim());
}

/**
 * Saca la IP de origen del mensaje.
 *
 * Se recorren las Received de ARRIBA a ABAJO. La primera es la que añadió el
 * receptor final, y su cláusula "from" describe el servidor que le entregó el
 * correo: esa es la IP que hay que comprobar contra SPF y las listas negras.
 * Se prefiere una IP pública sobre una privada, porque las Received internas
 * solo hablan de la red de quien envía.
 *
 * @param {string[]} recibidas
 * @returns {string|null}
 */
function ipDeRecibidas(recibidas) {
  const candidatas = [];
  for (const r of recibidas) {
    for (const m of r.matchAll(/\[([0-9a-fA-F:.]+)\]/g)) {
      if (net.isIP(m[1])) candidatas.push(m[1]);
    }
  }
  return candidatas.find((ip) => !esPrivada(ip)) || candidatas[0] || null;
}

/** ¿Es una dirección de red interna que no sirve para reputación? */
function esPrivada(ip) {
  if (net.isIP(ip) === 6) return /^(::1|fe80:|fc|fd)/i.test(ip);
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || a === 0;
}

/**
 * Lee `Authentication-Results` y extrae el veredicto de SPF, DKIM y DMARC.
 *
 * @param {string[]} valores
 * @returns {{spf: object|null, dkim: object[], dmarc: object|null}}
 */
function parsearAuthResults(valores) {
  const salida = { spf: null, dkim: [], dmarc: null };

  for (const valor of valores) {
    const texto = String(valor);

    const spf = texto.match(/\bspf\s*=\s*([a-z]+)/i);
    if (spf && !salida.spf) salida.spf = { resultado: spf[1].toLowerCase(), fuente: 'Authentication-Results' };

    const dmarc = texto.match(/\bdmarc\s*=\s*([a-z]+)/i);
    if (dmarc && !salida.dmarc) {
      const dominio = texto.match(/\bheader\.from\s*=\s*([^\s;()]+)/i);
      salida.dmarc = { resultado: dmarc[1].toLowerCase(), dominio: dominio ? dominio[1].toLowerCase() : null };
    }

    for (const dkim of texto.matchAll(/\bdkim\s*=\s*([a-z]+)([^;]*)/gi)) {
      const dominio = dkim[2].match(/\bheader\.d\s*=\s*([^\s;()]+)/i);
      salida.dkim.push({
        resultado: dkim[1].toLowerCase(),
        dominio: dominio ? dominio[1].toLowerCase() : null
      });
    }
  }

  return salida;
}

/**
 * Lee `Received-SPF`, que añaden algunos receptores como SpamAssassin.
 *
 * @param {string|null} valor
 * @param {string|null} ipEmisor
 * @returns {{spf: object|null}}
 */
function parsearRecibidoSpf(valor, ipEmisor) {
  if (!valor) return { spf: null };
  const resultado = String(valor).match(/^\s*([a-z]+)/i);
  const cliente = String(valor).match(/\bclient-ip\s*=\s*([0-9a-fA-F:.]+)/i);
  return {
    spf: resultado
      ? { resultado: resultado[1].toLowerCase(), fuente: 'Received-SPF', ip: cliente ? cliente[1] : ipEmisor || null }
      : null
  };
}

/** Descompone una cabecera `DKIM-Signature` en sus etiquetas útiles. */
function parsearFirma(valor) {
  const tag = {};
  for (const parte of String(valor).split(';')) {
    const corte = parte.indexOf('=');
    if (corte < 0) continue;
    const clave = parte.slice(0, corte).trim().toLowerCase();
    if (clave) tag[clave] = parte.slice(corte + 1).trim();
  }
  return {
    dominio: tag.d ? tag.d.toLowerCase() : null,
    selector: tag.s || null,
    algoritmo: tag.a || null,
    encabezados: tag.h ? tag.h.split(':').map((h) => h.trim()) : [],
    cuerpoHash: tag.bh || null
  };
}

/** Dominio de una dirección o de un valor tipo `Nombre <a@b.com>`. */
function dominioDe(valor) {
  if (!valor) return null;
  const m = String(valor).match(/@([A-Za-z0-9.-]+)/);
  return m ? m[1].replace(/[>,;].*$/, '').toLowerCase().replace(/\.$/, '') : null;
}

/* ------------------------------------------------------------------ *
 * Cuerpo MIME
 * ------------------------------------------------------------------ */

/** Separa el cuerpo en texto y HTML recorriendo las partes MIME. */
function parsearCuerpo(cuerpo, contentType, transferEncoding) {
  const texto = [];
  const html = [];
  let adjuntos = 0;

  const visitar = (contenido, tipo, transfer) => {
    const ct = String(tipo || 'text/plain').toLowerCase();

    if (ct.startsWith('multipart/')) {
      const boundary = extraerBoundary(tipo);
      if (!boundary) {
        texto.push(contenido);
        return;
      }
      for (const parte of partirPorBoundary(contenido, boundary)) {
        const { cabeceras, cuerpo: subCuerpo } = separarParte(parte);
        const subTipo = cabeceras['content-type'] || 'text/plain';
        const disposicion = (cabeceras['content-disposition'] || '').toLowerCase();
        if (disposicion.includes('attachment')) {
          adjuntos++;
          continue;
        }
        visitar(subCuerpo, subTipo, cabeceras['content-transfer-encoding']);
      }
      return;
    }

    const decodificado = decodificar(contenido, transfer || '8bit');
    if (ct.startsWith('text/html')) html.push(decodificado);
    else if (ct.startsWith('text/plain')) texto.push(decodificado);
    else adjuntos++;
  };

  visitar(cuerpo, contentType, transferEncoding);
  return { texto: texto.join('\n'), html: html.join('\n'), adjuntos };
}

/** Extrae `boundary=` del Content-Type. */
function extraerBoundary(contentType) {
  const m =
    String(contentType || '').match(/boundary\s*=\s*"([^"]+)"/i) ||
    String(contentType || '').match(/boundary\s*=\s*([^;\s]+)/i);
  return m ? m[1] : null;
}

/** Divide un cuerpo multipart por su frontera. */
function partirPorBoundary(cuerpo, boundary) {
  const partes = [];
  const texto = String(cuerpo);
  const marca = `--${boundary}`;
  let indice = texto.indexOf(marca);
  if (indice < 0) return partes;

  while (indice >= 0) {
    const inicio = texto.indexOf('\n', indice) + 1;
    const siguiente = texto.indexOf(marca, inicio);
    if (siguiente < 0) break;
    const contenido = texto.slice(inicio, siguiente).replace(/\n$/, '');
    if (contenido.trim()) partes.push(contenido);
    indice = siguiente;
  }

  return partes;
}

/** Separa la cabecera de una parte MIME de su cuerpo. */
function separarParte(parte) {
  const texto = String(parte).replace(/^\n+/, '');
  const corte = texto.indexOf('\n\n');
  if (corte < 0) return { cabeceras: {}, cuerpo: texto };
  const cabeceraTexto = texto.slice(0, corte);
  const cabeceras = {};
  let actual = null;
  for (const linea of cabeceraTexto.split('\n')) {
    if (/^[ \t]/.test(linea) && actual) {
      cabeceras[actual] += ` ${linea.trim()}`;
      continue;
    }
    const c = linea.indexOf(':');
    if (c <= 0) continue;
    actual = linea.slice(0, c).trim().toLowerCase();
    cabeceras[actual] = linea.slice(c + 1).trim();
  }
  return { cabeceras, cuerpo: texto.slice(corte + 2) };
}

/** Decodifica quoted-printable, que es lo que usan casi todos los cuerpos. */
function decodificar(texto, encoding) {
  if (String(encoding).toLowerCase() !== 'quoted-printable') return String(texto);
  return String(texto)
    .replace(/=\n/g, '')
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
}

module.exports = { parsear, parsearCabeceras, parsearAuthResults, ipDeRecibidas, dominioDe, esPrivada };
