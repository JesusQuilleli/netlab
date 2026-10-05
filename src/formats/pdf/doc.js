/**
 * pdf/doc.js — Piezas reutilizables del PDF.
 *
 * MODULO QUE ARREGLA LA PAGINACION. En legacy/Check IP Abuse/checked/check-ip.js
 * y legacy/Check IP Abuse/abuse/check-abuse.js la pagina se partia asi:
 *
 *     if (doc.y > 700) { doc.addPage(); ... }
 *
 * Es un numero magico que no tiene relacion con el alto real de la pagina
 * (842) ni con el margen inferior. Con contenido un poco mas largo el pie de
 * pagina se encima con el ultimo registro; con contenido corto se parte antes
 * de tiempo. Aqui la paginacion la decide el propio documento: cada bloque
 * mide cuanto ocupa y pide salto si no cabe.
 *
 * @module formats/pdf/doc
 */

'use strict';

const { COLORES, TIPOGRAFIA, PAGINA, color, sanear, estadoBadge } = require('./theme');

/** Alto reservado al pie de pagina. */
const ESPACIO_PIE = 40;

/**
 * Limite inferior real del area de contenido.
 *
 * ESTE VALOR TIENE QUE COINCIDIR con el margen inferior que declara el
 * documento (PAGINA.margen), porque es el limite que usa internamente el motor
 * de texto de pdfkit: si aqui se permite escribir mas abajo del que pdfkit
 * considera "en pagina", el motor anade una hoja nueva por su cuenta y el
 * resultado son paginas en blanco intercaladas al final del informe.
 *
 * En una version previa de este modulo el limite era PAGINA.alto - ESPACIO_PIE
 * (801) y el margen era 50 (limite real 791). Con contenido largo, el motor
 * saltaba de pagina por su cuenta y ademas arrastraba el cursor hacia atras,
 * encadenando seis paginas vacias al final. No uses ESPACIO_PIE aqui.
 */
const LIMITE_INFERIOR = PAGINA.alto - PAGINA.margen;

/** Crea un documento PDF con la configuracion estandar de netlab. */
function crear() {
  const PDFDocument = require('pdfkit');
  return new PDFDocument({
    size: 'A4',
    margins: { top: PAGINA.margen, bottom: PAGINA.margen, left: PAGINA.margen, right: PAGINA.margen },
    info: {
      Title: 'Informe netlab',
      Author: 'netlab',
      Subject: 'Informe de diagnostico',
      Creator: 'netlab'
    },
    autoFirstPage: false,
    bufferPages: true
  });
}

/** Añade una hoja nueva con la cabecera de continuacion si no es la primera. */
function nuevaPagina(doc, titulo, primera = false) {
  doc.addPage();
  if (primera) {
    cabecera(doc, titulo);
    return;
  }
  continuationHeader(doc, titulo);
}

/**
 * Cabecera principal de la primera pagina.
 *
 * `veredicto` es el titular de la herramienta. Si viene, la banda se reparte
 * entre el nombre de la herramienta, pequeno arriba, y el titular grande
 * debajo, porque en un informe de una pagina el titular es lo que se lee
 * primero. Sin titular se mantiene la disposicion de siempre.
 */
function cabecera(doc, titulo, veredicto) {
  const { margen, ancho } = PAGINA;
  doc.rect(0, 0, ancho, 96).fill(COLORES.fondoCabecera);

  if (veredicto) {
    doc
      .fillColor(COLORES.textoSuave)
      .font(TIPOGRAFIA.fuenteTexto)
      .fontSize(9)
      .text(sanear(titulo).toUpperCase(), margen, 20, { width: ancho - margen * 2, align: 'left' });

    doc
      .fillColor(COLORES.textoClaro)
      .font(TIPOGRAFIA.fuenteTitulo)
      .fontSize(19)
      .text(sanear(veredicto), margen, 36, { width: ancho - margen * 2, align: 'left' });
  } else {
    doc
      .fillColor(COLORES.textoClaro)
      .font(TIPOGRAFIA.fuenteTitulo)
      .fontSize(20)
      .text(sanear(titulo), margen, 34, { width: ancho - margen * 2, align: 'left' });
  }

  doc
    .fillColor(COLORES.textoSuave)
    .font(TIPOGRAFIA.fuenteTexto)
    .fontSize(9)
    .text('Informe generado automaticamente por netlab', margen, veredicto ? 68 : 62, {
      width: ancho - margen * 2
    });

  doc.y = 96 + 24;
}

/** Cabecera ligera de las paginas siguientes. */
function continuationHeader(doc, titulo) {
  const { margen, ancho } = PAGINA;
  doc.rect(0, 0, ancho, 34).fill(COLORES.fondoCabecera2);
  doc
    .fillColor(COLORES.textoClaro)
    .font(TIPOGRAFIA.fuenteTitulo)
    .fontSize(10)
    .text(sanear(titulo), margen, 11, { width: ancho - margen * 2 });
  doc.y = 34 + 20;
}

/** Badde de estado: rectangulo de color con el veredicto. */
function badge(doc, status, etiquetaExtra) {
  const { margen, anchoUtil } = PAGINA;
  const { etiqueta, tone } = estadoBadge(status);
  const { principal } = color(tone);
  const texto = etiquetaExtra ? `${etiqueta} - ${sanear(etiquetaExtra)}` : etiqueta;

  doc.roundedRect(margen, doc.y, anchoUtil, 34, 5).fill(principal);
  doc
    .fillColor('#FFFFFF')
    .font(TIPOGRAFIA.fuenteTitulo)
    .fontSize(13)
    .text(sanear(texto), margen, doc.y + 10, { width: anchoUtil, align: 'center' });
  doc.y += 34 + 18;
}

/**
 * Fila de datos etiqueta/valor, para el bloque de detalles.
 *
 * `y` se lee DESPUES de pedir espacio. Si se leiera antes y la fila no
 * cabiera, el salto de pagina dejaria `y` apuntando a la posicion antigua de
 * la pagina anterior, y el cursor volveria atras en cada fila siguiente,
 * encadenando una pagina en blanco por fila.
 */
function filaKV(doc, etiqueta, valor, tone = null) {
  const { margen, ancho } = PAGINA;
  const xValor = margen + 180;
  const anchoEtiqueta = 170;
  const anchoValor = ancho - margen * 2 - 180;
  const textoEtiqueta = sanear(etiqueta);
  const textoValor = sanear(valor);

  // Un valor largo (una política DMARC, una cadena SPF) ocupa varias lineas.
  // Se mide de verdad y se avanza el cursor por ese alto: con un salto fijo
  // de 13 la fila siguiente se dibujaba encima de la segunda linea del valor.
  doc.font(TIPOGRAFIA.fuenteTexto).fontSize(9);
  const altoEtiqueta = doc.heightOfString(textoEtiqueta, { width: anchoEtiqueta, lineBreak: false });
  doc.font(TIPOGRAFIA.fuenteTitulo).fontSize(9.5);
  const altoValor = doc.heightOfString(textoValor, { width: anchoValor, lineBreak: false });
  const alto = Math.max(13, altoEtiqueta, altoValor) + 2;

  asegurarEspacio(doc, alto);
  const y = doc.y;

  doc.fillColor(COLORES.textoMedio).font(TIPOGRAFIA.fuenteTexto).fontSize(9);
  doc.text(textoEtiqueta, margen, y, { width: anchoEtiqueta, lineBreak: false });

  doc
    .fillColor(tone ? color(tone).principal : COLORES.texto)
    .font(TIPOGRAFIA.fuenteTitulo)
    .fontSize(9.5)
    .text(textoValor, xValor, y, { width: anchoValor, lineBreak: false });

  doc.y = y + alto;
}

/** Titulo de seccion con linea horizontal. */
function seccion(doc, titulo, descripcion) {
  asegurarEspacio(doc, 60);
  const { margen, anchoUtil } = PAGINA;

  doc.moveDown(0.8);
  doc
    .fillColor(COLORES.texto)
    .font(TIPOGRAFIA.fuenteTitulo)
    .fontSize(13)
    .text(sanear(titulo), margen, doc.y, { width: anchoUtil });

  if (descripcion) {
    doc
      .fillColor(COLORES.textoMedio)
      .font(TIPOGRAFIA.fuenteTexto)
      .fontSize(8.5)
      .text(sanear(descripcion), margen, doc.y + 2, { width: anchoUtil });
  }

  const yLinea = doc.y + 5;
  doc.moveTo(margen, yLinea).lineTo(margen + anchoUtil, yLinea).lineWidth(0.8).strokeColor(COLORES.borde).stroke();
  doc.y = yLinea + 10;
}

/**
 * Ajusta el tamano de una celda o titulo para que ninguna palabra quede
 * partida por la mitad. pdfkit corta las palabras que no caben en el ancho
 * disponible; midiendo la palabra mas larga se reduce la fuente lo justo para
 * que entre y el texto se reparta por lineas solo en los espacios.
 */
function tamanoParaCaber(doc, texto, anchoDisponible, base) {
  doc.fontSize(base);
  const palabras = String(texto).split(/\s+/).filter(Boolean);
  let anchoMax = 0;
  for (const palabra of palabras) {
    anchoMax = Math.max(anchoMax, doc.widthOfString(palabra));
  }
  if (anchoMax <= anchoDisponible || anchoMax <= 0) return base;
  // Suelo de 7.5: por debajo el texto deja de leerse y un valor sin espacios
  // (una clave DKIM completa) encogia la fila hasta lo ilegible. A partir de
  // ahi es preferible que la celda recorte con puntos suspensivos.
  return Math.max(7.5, Math.floor(((base * anchoDisponible) / anchoMax) * 10) / 10);
}

/**
 * Alto real de la franja de cabecera. Se mide con la fuente del PDF porque
 * titulos como "Hosts asignados" ocupan dos lineas en columnas estrechas; con
 * un alto fijo la cabecera se solapaba con la primera fila.
 */
function altoCabecera(doc, columnas, anchos) {
  let alto = 12;
  columnas.forEach((col, i) => {
    const titulo = sanear(String(col));
    const disponible = anchos[i] - 8;
    doc.font(TIPOGRAFIA.fuenteTitulo);
    const size = tamanoParaCaber(doc, titulo, disponible, 8.5);
    doc.fontSize(size);
    alto = Math.max(alto, doc.heightOfString(titulo, { width: disponible }));
  });
  return Math.min(alto + 10, 46);
}

/** Dibuja la franja de cabecera de una tabla en la posicion indicada. */
function dibujarCabecera(doc, columnas, anchos, x, y, alto) {
  doc.rect(x, y, PAGINA.anchoUtil, alto).fill(COLORES.fondoCabecera2);
  let cx = x + 5;
  columnas.forEach((col, i) => {
    const titulo = sanear(String(col));
    const disponible = anchos[i] - 8;
    doc.font(TIPOGRAFIA.fuenteTitulo);
    const size = tamanoParaCaber(doc, titulo, disponible, 8.5);
    doc.fontSize(size).fillColor(COLORES.textoClaro);
    doc.text(titulo, cx, y + 6, { width: disponible });
    cx += anchos[i];
  });
}

/**
 * Tabla de datos con encabezado sombreado y filas alternas.
 *
 * @param {object} doc Documento PDF.
 * @param {object} seccionDef { title, columns, rows }
 */
function tabla(doc, seccionDef) {
  const { margen, anchoUtil } = PAGINA;
  const columnas = seccionDef.columns || [];
  const filas = seccionDef.rows || [];

  if (!columnas.length) return;

  const anchos = calcularAnchos(columnas, seccionDef.anchoColumnas, anchoUtil);
  const x = margen;
  const cabH = altoCabecera(doc, columnas, anchos);

  // Encabezado
  asegurarEspacio(doc, cabH + 12);
  const yHead = doc.y;
  dibujarCabecera(doc, columnas, anchos, x, yHead, cabH);
  doc.y = yHead + cabH + 4;

  // Filas
  filas.forEach((fila, indice) => {
    const celdas = normalizarFila(fila, columnas.length);
    const altoFila = calcularAltoFila(doc, celdas, anchos);

    if (doc.y + altoFila > LIMITE_INFERIOR) {
      nuevaPagina(doc, seccionDef.title || 'Detalle');
      const yNuevo = doc.y;
      dibujarCabecera(doc, columnas, anchos, margen, yNuevo, cabH);
      doc.y = yNuevo + cabH + 4;
    }

    const yFila = doc.y;
    if (indice % 2 === 1) {
      doc.rect(x, yFila - 3, anchoUtil, altoFila + 4).fill(COLORES.neutroSuave);
    }

    let fx = x + 5;
    celdas.forEach((celda, i) => {
      const celdaObj = typeof celda === 'object' && celda !== null ? celda : { valor: celda };
      const valor = sanear(String(celdaObj.valor ?? ''));
      const disponible = anchos[i] - 8;
      const base = celdaObj.tamano || 8.5;
      const fuente = celdaObj.negrita === false ? TIPOGRAFIA.fuenteTexto : TIPOGRAFIA.fuenteTitulo;
      doc.font(fuente);
      const size = tamanoParaCaber(doc, valor, disponible, base);
      doc.fontSize(size);
      doc.fillColor(celdaObj.tone ? color(celdaObj.tone).principal : COLORES.texto);
      doc.text(valor, fx, yFila, { width: disponible, height: Math.max(11, altoFila - 1), ellipsis: true });
      fx += anchos[i];
    });

    doc.moveTo(x, yFila + altoFila).lineTo(x + anchoUtil, yFila + altoFila).lineWidth(0.3).strokeColor(COLORES.bordeSuave).stroke();
    doc.y = yFila + altoFila + 5;
  });

  doc.y += 4;
}

/** Bloque de codigo o telemetria, con fondo oscuro. */
function bloqueCodigo(doc, texto, titulo) {
  const { margen, ancho } = PAGINA;
  const lineas = String(texto).split('\n').slice(0, 400); // tope de seguridad
  const alto = lineas.length * 11 + 20;

  asegurarEspacio(doc, Math.min(alto, 200));
  if (doc.y + alto > LIMITE_INFERIOR) nuevaPagina(doc, titulo || 'Telemetria');

  const y = doc.y;
  doc.roundedRect(margen, y, ancho, alto, 4).fill(COLORES.consolaFondo);

  doc.font(TIPOGRAFIA.fuenteMono).fontSize(7.5);
  let ly = y + 9;
  for (const linea of lineas) {
    // Colorea los errores de la telemetria en rojo.
    doc
      .fillColor(/error|fail|❌|\[X\]|✗/i.test(linea) ? COLORES.consolaError : COLORES.consolaTexto)
      .text(sanear(linea).slice(0, 120), margen + 12, ly, { width: ancho - margen * 2 - 24, ellipsis: true });
    ly += 11;
  }

  doc.y = y + alto + 10;
}

/** Lista de hallazgos con icono por severidad. */
function hallazgos(doc, lista) {
  if (!lista.length) return;

  seccion(doc, 'Hallazgos', 'Observaciones detectadas por el analisis');

  for (const h of lista) {
    const { principal } = color(h.severity === 'error' ? 'bad' : h.severity === 'warn' ? 'warn' : 'ok');
    const icono = h.severity === 'error' ? '[X]' : h.severity === 'warn' ? '[!]' : '[i]';

    asegurarEspacio(doc, 40);
    const y = doc.y;
    const { margen, ancho } = PAGINA;

    doc.fillColor(principal).font(TIPOGRAFIA.fuenteTitulo).fontSize(9);
    doc.text(sanear(icono), margen, y, { width: 24 });
    doc.fillColor(COLORES.texto).font(TIPOGRAFIA.fuenteTitulo).fontSize(9.5);
    doc.text(sanear(h.title), margen + 24, y, { width: ancho - margen * 2 - 24 });

    let yCur = doc.y;
    if (h.detail) {
      doc.fillColor(COLORES.textoMedio).font(TIPOGRAFIA.fuenteTexto).fontSize(8.5);
      doc.text(sanear(h.detail), margen + 24, yCur + 1, { width: ancho - margen * 2 - 24 });
      yCur = doc.y;
    }
    if (h.recommendation) {
      doc.fillColor(principal).font(TIPOGRAFIA.fuenteTexto).fontSize(8.5);
      doc.text(sanear('-> ' + h.recommendation), margen + 24, yCur + 2, { width: ancho - margen * 2 - 24 });
    }
    doc.y += 8;
  }
  doc.y += 4;
}

/** Lista simple de elementos con vinetas. */
function lista(doc, elementos) {
  for (const item of elementos) {
    asegurarEspacio(doc, 20);
    const { margen, ancho } = PAGINA;
    doc.fillColor(COLORES.textoSuave).font(TIPOGRAFIA.fuenteTexto).fontSize(9);
    doc.text('-', margen, doc.y, { width: 14 });
    doc.fillColor(COLORES.texto).text(sanear(String(item)), margen + 14, doc.y, { width: ancho - margen * 2 - 14 });
    doc.y += 3;
  }
}

/**
 * Garantiza que quede espacio para `alto` antes de escribir.
 * Si no cabe, salta de pagina.
 *
 * @param {object} doc
 * @param {number} alto Espacio que hace falta a partir de la posicion actual.
 */
function asegurarEspacio(doc, alto) {
  if (doc.y + alto > LIMITE_INFERIOR) {
    nuevaPagina(doc, doc.__tituloActual || 'Detalle');
  }
}

/** Recorda el titulo para las cabeceras de continuacion. */
function fijarTitulo(doc, titulo) {
  doc.__tituloActual = titulo;
}

/**
 * Escribe pie y numeracion en todas las paginas.
 * Se llama una sola vez, al final, porque pdfkit difiere la escritura.
 *
 * El pie va dentro del margen inferior, es decir por debajo de la ultima linea
 * que pdfkit considera "en pagina". Si se escribe ahi tal cual, su motor de
 * salto de linea entiende que no cabe y crea una pagina nueva para cada linea
 * del pie, dejando paginas en blanco al final del informe. Por eso se pone a
 * cero el margen inferior de esa pagina antes de escribir y se restaura
 * despues.
 *
 * @param {object} doc
 * @param {string} pie Texto del pie.
 */
function pieConNumeracion(doc, pie) {
  const rango = doc.bufferedPageRange();
  const y = PAGINA.alto - 28;

  for (let i = rango.start; i < rango.start + rango.count; i++) {
    doc.switchToPage(i);

    const margenInferior = doc.page.margins.bottom;
    doc.page.margins.bottom = 0;

    doc
      .fillColor(COLORES.textoSuave)
      .font(TIPOGRAFIA.fuenteTexto)
      .fontSize(7.5)
      .text(sanear(pie), PAGINA.margen, y, { width: PAGINA.anchoUtil - 60, align: 'left', lineBreak: false })
      .text(`${i - rango.start + 1} / ${rango.count}`, PAGINA.ancho - PAGINA.margen - 50, y, {
        width: 50,
        align: 'right',
        lineBreak: false
      });

    doc.page.margins.bottom = margenInferior;
  }
}

/** Reparte el ancho disponible entre las columnas. */
function calcularAnchos(columnas, anchosRelativos, anchoTotal) {
  if (anchosRelativos?.length === columnas.length) {
    const suma = anchosRelativos.reduce((a, b) => a + b, 0);
    return anchosRelativos.map((r) => (r / suma) * anchoTotal);
  }
  const iguales = Math.floor(anchoTotal / columnas.length);
  return columnas.map(() => iguales);
}

/** Convierte una fila en un array de celdas de la longitud correcta. */
function normalizarFila(fila, n) {
  const celdas = Array.isArray(fila) ? fila : [fila];
  while (celdas.length < n) celdas.push('');
  return celdas.slice(0, n);
}

/**
 * Alto real de una fila. Se mide con `heightOfString` en vez de estimar por
 * numero de caracteres, porque la estimacion no coincide con el corte real de
 * pdfkit y las filas se solapaban entre si cuando una celda ocupaba mas lineas
 * de las previstas.
 */
function calcularAltoFila(doc, celdas, anchos) {
  let altoTexto = 0;
  celdas.forEach((celda, i) => {
    const celdaObj = typeof celda === 'object' && celda !== null ? celda : { valor: celda };
    const valor = sanear(String(celdaObj.valor ?? ''));
    const disponible = anchos[i] - 8;
    const base = celdaObj.tamano || 8.5;
    const fuente = celdaObj.negrita === false ? TIPOGRAFIA.fuenteTexto : TIPOGRAFIA.fuenteTitulo;
    doc.font(fuente);
    const size = tamanoParaCaber(doc, valor, disponible, base);
    doc.fontSize(size);
    altoTexto = Math.max(altoTexto, doc.heightOfString(valor, { width: disponible }));
  });
  return Math.min(Math.max(11, altoTexto + 2), 120);
}

module.exports = {
  crear,
  nuevaPagina,
  cabecera,
  continuationHeader,
  badge,
  filaKV,
  seccion,
  tabla,
  bloqueCodigo,
  hallazgos,
  lista,
  asegurarEspacio,
  fijarTitulo,
  pieConNumeracion,
  ESPACIO_PIE
};