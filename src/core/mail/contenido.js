/**
 * mail/contenido.js — Heurísticas de contenido, al estilo de SpamAssassin.
 *
 * mail-tester pasa el mensaje por SpamAssassin y resume su puntuación. Aquí no
 * hay motor de reglas: es una aproximación con las señales que más peso tienen
 * en la práctica (texto frente a HTML, proporción de enlaces, acortadores,
 * palabras de spam, gritos en el asunto). Es un orientador, no un veredicto, y
 * el informe lo dice.
 *
 * Cada comprobación pesa una fracción del bloque de contenido. Los pesos suman
 * 2.0 puntos sobre los 10 totales, que es lo que mail-tester dedica al contenido.
 *
 * @module core/mail/contenido
 */

'use strict';

/** Palabras que los filtros de spam suelen castigar. */
const PALABRAS_SPAM = [
  'gana dinero',
  'gane dinero',
  'dinero gratis',
  'gratis',
  'free money',
  'make money',
  'work from home',
  'trabaja desde casa',
  'oferta única',
  'limited time',
  'haga clic aquí',
  'click here',
  'compre ahora',
  'buy now',
  'sin costo',
  'no cost',
  'riesgo cero',
  'risk free',
  'garantizado',
  'guaranteed',
  'urgente',
  'urgent',
  'actúe ahora',
  'act now',
  'préstamo',
  'viagra',
  'casino',
  'lottery',
  'lotería',
  'premio',
  'winner',
  'ganador',
  '100% gratis',
  '100% free'
];

/** Acortadores que suelen disparar los filtros. */
const ACORTADORES = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at'];

/**
 * Evalúa el contenido de un mensaje ya parseado.
 *
 * @param {object} mensaje Resultado de `core/mail/mensaje.parsear`.
 * @returns {{checks: object[], max: number}}
 */
function evaluar(mensaje) {
  const texto = textoPlano(mensaje);
  const html = String(mensaje.html || '');
  const palabras = contarPalabras(texto);
  const enlaces = extraerEnlaces(html, texto);
  const asunto = String(mensaje.asunto || '');

  const checks = [];

  checks.push(contenidoSinTexto(mensaje, texto, palabras));
  checks.push(proporcionEnlaces(enlaces, palabras));
  checks.push(imagenesSinTexto(html, palabras));
  checks.push(acortadores(enlaces));
  checks.push(palabrasSpam(texto, asunto));
  checks.push(mayusculasAsunto(asunto));
  checks.push(exclamaciones(asunto));
  checks.push(enlacesConIp(enlaces));

  return { checks, max: checks.reduce((s, c) => s + c.peso, 0) };
}

/** Texto sobre el que aplicar las heurísticas: el visible. */
function textoPlano(mensaje) {
  if (mensaje.texto) return mensaje.texto;
  // Sin parte de texto, se aproxima el HTML quitando etiquetas y entidades
  // básicas. No es un renderizador, solo sirve para contar palabras.
  return String(mensaje.html || '')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

function contarPalabras(texto) {
  return String(texto || '').split(/\s+/).filter((p) => /[a-z0-9áéíóúñ]/i.test(p)).length;
}

/** Enlaces del HTML (href) y enlaces sueltos en el texto. */
function extraerEnlaces(html, texto) {
  const encontrados = [];
  for (const m of String(html).matchAll(/href\s*=\s*["']([^"']+)["']/gi)) encontrados.push(m[1]);
  for (const m of String(texto).matchAll(/https?:\/\/[^\s<>"')]+/gi)) encontrados.push(m[0]);
  return [...new Set(encontrados)];
}

function contarImagenes(html) {
  return (String(html).match(/<img\b/gi) || []).length;
}

function contenidoSinTexto(mensaje, texto, palabras) {
  const peso = 0.5;
  const soloHtml = !mensaje.texto && Boolean(mensaje.html);
  if (palabras === 0 && (mensaje.html || mensaje.texto)) {
    return check('contenido-vacio', 'El mensaje no tiene texto legible', peso, 'error', 'El cuerpo no aporta ni una palabra de texto. Un correo solo con imágenes puntúa muy mal en los filtros.', 'Añade una versión en texto de lo que quieres decir. Debe ser información útil, no una disculpa.');
  }
  if (mensaje.html && !mensaje.texto) {
    return check('sin-alternativa-texto', 'HTML sin versión en texto', peso, 'warn', `El mensaje viaja solo en HTML. Incluye una parte "text/plain": es lo que esperan los filtros y los clientes que no muestran imágenes (${palabras} palabras en el HTML).`, 'Añade una parte text/plain con el mismo contenido (multipart/alternative).');
  }
  return check('contenido-vacio', 'Contenido con texto alternativo', peso, 'ok', soloHtml ? 'Tiene HTML y texto.' : `${palabras} palabras en el cuerpo.`, null);
}

function proporcionEnlaces(enlaces, palabras) {
  const peso = 0.3;
  const ratio = palabras ? enlaces.length / palabras : enlaces.length;
  if (enlaces.length >= 4 && ratio > 0.08) {
    return check('exceso-enlaces', 'Demasiados enlaces para tan poco texto', peso, 'warn', `${enlaces.length} enlaces en ${palabras} palabras. Una proporción alta de enlaces es una de las señales clásicas de spam.`, 'Reduce los enlaces o aumenta el texto real del mensaje.');
  }
  return check('exceso-enlaces', 'Proporción de enlaces razonable', peso, 'ok', `${enlaces.length} enlaces.`, null);
}

function imagenesSinTexto(html, palabras) {
  const peso = 0.2;
  const imagenes = contarImagenes(html);
  if (imagenes > 0 && palabras < imagenes * 5) {
    return check('solo-imagenes', 'El mensaje depende de las imágenes', peso, 'warn', `${imagenes} imágenes frente a ${palabras} palabras. Un correo que solo se entiende viendo las imágenes se marca como spam.`, 'Escribe el mensaje principal como texto y deja las imágenes para apoyar.');
  }
  return check('solo-imagenes', 'Relación imagen/texto correcta', peso, 'ok', `${imagenes} imágenes.`, null);
}

function acortadores(enlaces) {
  const peso = 0.3;
  const malos = enlaces.filter((url) => {
    try {
      const host = new URL(url).hostname.toLowerCase();
      return ACORTADORES.some((a) => host === a || host.endsWith(`.${a}`));
    } catch {
      return false;
    }
  });
  if (malos.length) {
    return check('acortadores', 'Enlaces acortados', peso, 'error', `Hay ${malos.length} enlace(s) con acortadores (${[...new Set(malos.map((u) => hostDe(u)))].join(', ')}). Ocultan el destino y los filtros los castigan.`, 'Usa la URL real de tu dominio en lugar del acortador.');
  }
  return check('acortadores', 'Sin acortadores', peso, 'ok', 'Ningún enlace usa acortadores.', null);
}

function palabrasSpam(texto, asunto) {
  const peso = 0.3;
  const heno = `${asunto} ${texto}`.toLowerCase();
  const encontradas = PALABRAS_SPAM.filter((p) => heno.includes(p));
  if (encontradas.length >= 2) {
    return check('palabras-spam', 'Palabras que los filtros castigan', peso, 'warn', `Aparecen expresiones típicas de spam: ${encontradas.slice(0, 5).join(', ')}.`, 'Reescribe el mensaje con un lenguaje neutro e informativo.');
  }
  if (encontradas.length === 1) {
    return check('palabras-spam', 'Una expresión de riesgo', peso, 'warn', `Aparece "${encontradas[0]}", que muchos filtros vigilan.`, 'Sustitúyela por una formulación más sobria.');
  }
  return check('palabras-spam', 'Sin palabras de spam', peso, 'ok', 'No se detectaron expresiones típicas de spam.', null);
}

function mayusculasAsunto(asunto) {
  const peso = 0.2;
  const letras = asunto.replace(/[^A-Za-zÁÉÍÓÚÑ]/g, '');
  if (letras.length >= 6) {
    const mayusculas = (asunto.match(/[A-ZÁÉÍÓÚÑ]/g) || []).length;
    if (mayusculas / letras.length > 0.5) {
      return check('asunto-gritado', 'El asunto está en mayúsculas', peso, 'warn', `El ${Math.round((mayusculas / letras.length) * 100)} % del asunto está en mayúsculas. Escribir a gritos reduce la entrega.`, 'Escribe el asunto en minúsculas con mayúscula inicial.');
    }
  }
  return check('asunto-gritado', 'Asunto con formato normal', peso, 'ok', 'El asunto no abusa de las mayúsculas.', null);
}

function exclamaciones(asunto) {
  const peso = 0.1;
  const excesivas = /!{2,}|\?!|!{1,}\s*!/.test(asunto);
  if (excesivas) {
    return check('exclamaciones', 'Signos de exclamación repetidos en el asunto', peso, 'warn', `El asunto es "${asunto}".`, 'Usa un asunto descriptivo, sin signos de exclamación encadenados.');
  }
  return check('exclamaciones', 'Asunto sin exclamaciones excesivas', peso, 'ok', 'Sin signos de exclamación repetidos.', null);
}

function enlacesConIp(enlaces) {
  const peso = 0.1;
  const conIp = enlaces.filter((url) => {
    try {
      const host = new URL(url).hostname;
      return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    } catch {
      return false;
    }
  });
  if (conIp.length) {
    return check('enlaces-ip', 'Enlaces que apuntan a una IP', peso, 'warn', `Hay ${conIp.length} enlace(s) a una dirección IP en vez de a un dominio.`, 'Usa un nombre de dominio con certificado válido.');
  }
  return check('enlaces-ip', 'Enlaces con dominio', peso, 'ok', 'Ningún enlace apunta directamente a una IP.', null);
}

function hostDe(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function check(id, titulo, peso, estado, detalle, recomendacion) {
  return { id, categoria: 'contenido', titulo, peso, estado, detalle, recomendacion };
}

module.exports = { evaluar, PALABRAS_SPAM, ACORTADORES, textoPlano };
