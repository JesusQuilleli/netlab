'use strict';

// Reparador de doble codificacion UTF-8.
//
// Cuando un fichero pasa por `Get-Content -Raw` (que en PowerShell 5.1 usa la
// pagina de codigos local) y se vuelve a escribir como UTF-8, cada caracter no
// ASCII se convierte en su mojibake: un em dash (—) pasa a "â€”". Si el
// proceso se repite, la pila de codificaciones crece y hay que deshacerla en
// pasos hasta que el texto cuadre.
//
// Que no haya ruido no basta para darlo por bueno: un fichero puede estar doble
// codificado y no contener ni una sola tilde. Lo que delata el fallo es el
// "â€”", y eso es lo que se busca.
//
// Uso: node scripts/arreglar-codificacion.js FICHERO...

const fs = require('fs');

/**
 * Secuencias que solo pueden ser mojibake.
 *
 * "Ã" y "â€" son las dos huellas que deja el UTF-8 releido como cp1252. Un
 * fichero que las contenga esta danado, porque en un fuente UTF-8 bien escrito
 * no aparecen nunca.
 */
const ROTA = /Ã.|â€./;

/**
 * Tabla inversa de cp1252: caracter -> byte.
 *
 * No se puede usar `charCodeAt & 0xff`: eso es latin1, y en cp1252 varios
 * caracteres ocupan posiciones distintas (el euro, por ejemplo, esta en 0x80 y
 * en latin1 ese hueco no existe). Con la tabla mal puesta, "â€”" se desharia
 * a "â?" y el fichero pasaria de danado a medio danado.
 *
 * El rango 0x80-0x9F es el que mas falla: en cp1252 no son caracteres de
 * control sino imprimibles (€ ‚ ƒ " " – — ™), asi que hay que ponerlos a mano.
 */
const INVERSA = (() => {
  const tabla = new Map();

  for (let byte = 0x00; byte <= 0xff; byte += 1) {
    // De 0x00 a 0x7F, cp1252 y latin1 coinciden, y son ASCII.
    if (byte <= 0x7f) tabla.set(String.fromCharCode(byte), byte);
  }

  // El resto del rango imprimible de latin1 (0xA0-0xFF) tambien coincide.
  for (let byte = 0xa0; byte <= 0xff; byte += 1) {
    tabla.set(String.fromCharCode(byte), byte);
  }

  // Y estos, que en cp1252 NO son los caracteres de control de latin1.
  const ESPECIALES = {
    '\u20ac': 0x80, '\u201a': 0x82, '\u0192': 0x83, '\u201e': 0x84, '\u2026': 0x85,
    '\u2020': 0x86, '\u2021': 0x87, '\u02c6': 0x88, '\u2030': 0x89, '\u0160': 0x8a,
    '\u2039': 0x8b, '\u0152': 0x8c, '\u017d': 0x8e, '\u2018': 0x91, '\u2019': 0x92,
    '\u201c': 0x93, '\u201d': 0x94, '\u2022': 0x95, '\u2013': 0x96, '\u2014': 0x97,
    '\u02dc': 0x98, '\u2122': 0x99, '\u0161': 0x9a, '\u203a': 0x9b, '\u0153': 0x9c,
    '\u017e': 0x9e, '\u0178': 0x9f
  };

  for (const [caracter, byte] of Object.entries(ESPECIALES)) tabla.set(caracter, byte);

  // Los huecos que quedan en 0x80-0x9F no tienen caracter imprimible en cp1252,
  // pero si aparecen en el mojibake como el caracter de control equivalente. El
  // 0x9D es el caso real: al leerlo como cp1252 sale U+009D, y sin esta linea el
  // fichero se declara irreparable aunque se pueda deshacer entero.
  for (let byte = 0x80; byte <= 0x9f; byte += 1) {
    if (!tabla.has(String.fromCharCode(byte))) tabla.set(String.fromCharCode(byte), byte);
  }

  return tabla;
})();

function byteDeCp1252(caracter) {
  const encontrado = INVERSA.get(caracter);
  return encontrado === undefined ? null : encontrado;
}

/** Vuelve a codificar un texto como cp1252, byte a byte. */
function aCp1252Bytes(texto) {
  const bytes = [];
  for (const caracter of texto) {
    const byte = byteDeCp1252(caracter);
    if (byte === null) return null;
    bytes.push(byte);
  }
  return Buffer.from(bytes);
}

/**
 * Deshace una capa de doble codificacion.
 *
 * @param {string} texto Texto con mojibake.
 * @returns {string|null} El texto original, o `null` si no se puede deshacer.
 */
function deshacerCapa(texto) {
  const bytes = aCp1252Bytes(texto);
  if (!bytes) return null;
  return bytes.toString('utf8');
}

/**
 * Repara hasta que no queden restos.
 *
 * @param {Buffer} original
 * @returns {{texto: string, capas: number}|null} `null` si no habia nada que hacer.
 */
function reparar(original) {
  let texto = original.toString('utf8');
  let capas = 0;

  while (ROTA.test(texto)) {
    const siguiente = deshacerCapa(texto);
    if (siguiente === null || siguiente === texto) break;
    texto = siguiente;
    capas += 1;
  }

  return ROTA.test(texto) ? null : { texto, capas };
}

let tocados = 0;

for (const fichero of process.argv.slice(2)) {
  const original = fs.readFileSync(fichero);
  const resultado = reparar(original);

  if (!resultado) {
    console.log(`SIN REPARAR: ${fichero} (sigue roto tras varias capas)`);
    continue;
  }

  if (resultado.capas === 0) {
    console.log(`sin cambios: ${fichero}`);
    continue;
  }

  fs.writeFileSync(fichero, resultado.texto, 'utf8');
  tocados += 1;
  console.log(`reparado:    ${fichero} (${resultado.capas} capa${resultado.capas === 1 ? '' : 's'})`);
}

if (tocados === 0) console.log('No habia nada que reparar.');