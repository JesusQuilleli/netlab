/**
 * pdf/theme.js — Tokens de diseno y saneo de caracteres.
 *
 * MODULO QUE UNIFICA Y ARREGLA. En legacy/ habia CUATRO generadores de PDF,
 * cada uno con su propia paleta, sus propias coordenadas magicas y su forma de
 * partir paginas:
 *
 *   Check IP Abuse/abuse/check-abuse.js    -- paleta #1E293B/#EF4444
 *   Check IP Abuse/checked/check-ip.js     -- paleta #0F172A/#22C55E
 *   Validate config SMTP/validate-smtp.js  -- paleta #0B1E36/#27AE60, marca HOSTINGSSI
 *   Validate config SMTP/validate-smtp-2.js-- paleta #0F172A/#10B981
 *
 * Ademas, dos de ellos dibujaban emojis con las fuentes estandar de pdfkit:
 *
 *   validate-smtp-2.js:49  -> doc.font('Courier').text('✅ Conexión...')
 *   check-abuse.js:138     -> doc.text('✓ IP Limpia...')
 *
 * Las fuentes estandar de PDF (WinAnsi) NO incluyen esos caracteres, asi que
 * salian corruptos o en blanco. Este modulo define una paleta unica y una
 * funcion que sustitui los caracteres no representables por su equivalente
 * ASCII, para que el PDF salga limpio sin cambiar el texto del informe en los
 * demas formatos.
 *
 * @module formats/pdf/theme
 */

'use strict';

/** Paleta unica de netlab. inspiration: slate + acento esmeralda. */
const COLORES = {
  fondoCabecera: '#0F172A',
  fondoCabecera2: '#1E293B',
  textoClaro: '#F8FAFC',
  textoMedio: '#64748B',
  textoSuave: '#94A3B8',
  texto: '#0F172A',
  borde: '#CBD5E1',
  bordeSuave: '#E2E8F0',
  ok: '#10B981',
  okSuave: '#D1FAE5',
  warn: '#F59E0B',
  warnSuave: '#FEF3C7',
  bad: '#EF4444',
  badSuave: '#FEE2E2',
  neutro: '#64748B',
  neutroSuave: '#E2E8F0',
  consolaFondo: '#0F172A',
  consolaTexto: '#34D399',
  consolaError: '#F87171'
};

/** Tipografia. Las fuentes estandar no necesitan incrustar ficheros. */
const TIPOGRAFIA = {
  fuenteTitulo: 'Helvetica-Bold',
  fuenteTexto: 'Helvetica',
  fuenteMono: 'Courier'
};

/** Medidas de pagina (A4 en puntos: 595 x 842). */
const PAGINA = {
  ancho: 595.28,
  alto: 841.89,
  margen: 50,
  get anchoUtil() {
    return this.ancho - this.margen * 2;
  }
};

/**
 * Traduce un tono ('ok'|'warn'|'bad'|'neutral') al par de color correspondiente.
 *
 * @param {string} tone
 * @returns {{principal: string, suave: string}}
 */
function color(tone) {
  switch (tone) {
    case 'ok':
      return { principal: COLORES.ok, suave: COLORES.okSuave };
    case 'warn':
      return { principal: COLORES.warn, suave: COLORES.warnSuave };
    case 'bad':
      return { principal: COLORES.bad, suave: COLORES.badSuave };
    default:
      return { principal: COLORES.neutro, suave: COLORES.neutroSuave };
  }
}

/**
 * Sustituye los caracteres que las fuentes estandar de PDF no pueden dibujar.
 *
 * WinAnsi (la codificacion de las fuentes Type1 estandar) no incluye emojis ni
 * simbolos Unicode de usage general. Cuando pdfkit encuentra uno, lo dibuja
 * como un caracter vacio o como un cuadrado, y en el peor caso rompe el
 * calculo de altura de linea. Esta funcion los cambia por equivalentes ASCII
 * para que el PDF salga legible sin tocar el contenido real del informe.
 *
 * @param {string} texto
 * @returns {string}
 */
function sanear(texto) {
  if (typeof texto !== 'string') return texto;
  return texto
    .replace(/✅|✔|☑/g, '[OK]')
    .replace(/❌|✘|☒/g, '[X]')
    .replace(/✓|✔️?/g, '[OK]')
    .replace(/✗|✘/g, '[X]')
    .replace(/⚠️?|⛔/g, '[!]')
    .replace(/ℹ️?/g, '[i]')
    .replace(/🔴|🟥/g, '[!]')
    .replace(/🟠|🟧/g, '[!]')
    .replace(/🟡|🟨/g, '[?]')
    .replace(/🟢|🟩/g, '[OK]')
    .replace(/[🔵⚫⚪🔘🔴⚪]/gu, '[ ]')
    .replace(/[→➔➡]/g, '->')
    .replace(/[←⇐]/g, '<-')
    .replace(/[…]/g, '...')
    .replace(/[–—]/g, '-')
    .replace(/['']/g, "'")
    .replace(/[""„]/g, '"')
    .replace(/…/g, '...')
    .replace(/[^\x00-\xFF]/g, (c) => (c === 'ñ' || c === 'Ñ' ? c : '.'));
}

/**
 * Traduce un estado a la etiqueta y al color del badge.
 *
 * @param {string} status 'pass'|'warn'|'fail'|'error'
 * @returns {{etiqueta: string, tone: string}}
 */
function estadoBadge(status) {
  switch (status) {
    case 'pass':
      return { etiqueta: 'CORRECTO', tone: 'ok' };
    case 'warn':
      return { etiqueta: 'CON OBSERVACIONES', tone: 'warn' };
    case 'fail':
      return { etiqueta: 'CON FALLOS', tone: 'bad' };
    default:
      return { etiqueta: 'ERROR', tone: 'bad' };
  }
}

module.exports = { COLORES, TIPOGRAFIA, PAGINA, color, sanear, estadoBadge };