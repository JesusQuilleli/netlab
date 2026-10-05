/**
 * pdf/index.js — Convierte un Result en un PDF.
 *
 * MODULO DE SALIDA. Recibe el mismo objeto `Result` que producen las
 * herramientas y lo pinta con las piezas de `doc.js` y la paleta de `theme.js`.
 * No sabe nada de DNS, SMTP ni puertos: por eso los cuatro reportes salen
 * identicos en estructura aunque las herramientas sean distintas.
 *
 * @module formats/pdf
 */

'use strict';

const doc = require('./doc');
const { human, duration } = require('../../core/time');
const { SECCION_KINDS, STATUS_META } = require('../../core/result');
const { COLORES, TIPOGRAFIA, PAGINA, color, sanear } = require('./theme');

/**
 * Genera el PDF de un Result.
 *
 * @param {object} result Result produced por una herramienta.
 * @param {object} [options]
 * @param {string} [options.pie] Texto del pie de pagina.
 * @param {string} [options.marca] Nombre que aparece arriba.
 * @returns {Promise<Buffer>} PDF completo.
 */
function render(result, options = {}) {
  const { pie = 'Documento generado automaticamente por netlab', marca = 'netlab' } = options;

  return new Promise((resolve, reject) => {
    const pdf = doc.crear();
    const trozos = [];

    pdf.on('data', (t) => trozos.push(t));
    pdf.on('end', () => resolve(Buffer.concat(trozos)));
    pdf.on('error', reject);

    doc.fijarTitulo(pdf, result.toolTitle);
    pdf.addPage();
    doc.cabecera(pdf, result.toolTitle, result.headline);

    // Cabecera de marca y objetivo
    const { margen, ancho } = PAGINA;
    pdf
      .fillColor(COLORES.textoMedio)
      .font(TIPOGRAFIA.fuenteTexto)
      .fontSize(9)
      .text(`${marca}  ·  Objetivo: ${result.target || 'n/d'}  ·  ${human(result.startedAt)}`, margen, pdf.y, {
        width: ancho
      });
    pdf.y += 14;

    // Badge de estado
    doc.badge(pdf, result.status);

    // Tarjetas de resumen
    if (result.summary?.length) {
      doc.seccion(pdf, 'Resumen');
      for (const s of result.summary) {
        doc.filaKV(pdf, s.label, s.value, s.tone === 'neutral' ? null : s.tone);
      }
      pdf.y += 6;
    }

    // Error
    if (result.error) {
      doc.seccion(pdf, 'Error de ejecucion');
      doc.bloqueCodigo(pdf, `${result.error.code}: ${result.error.message}`, 'Error');
      if (result.error.remediation) {
        pdf
          .fillColor(COLORES.textoMedio)
          .font(TIPOGRAFIA.fuenteTexto)
          .fontSize(9)
          .text(sanear(result.error.remediation), margen, pdf.y + 4, { width: ancho });
        pdf.y += 8;
      }
    }

    // Secciones del cuerpo
    for (const seccionDef of result.sections || []) {
      pintarSeccion(pdf, seccionDef);
    }

    // Hallazgos
    doc.hallazgos(pdf, result.findings || []);

    // Telemetria
    if (result.logs?.length) {
      const texto = result.logs
        .map((l) => `[${new Date(l.ts).toLocaleTimeString('es-ES', { hour12: false })}] ${l.level.toUpperCase().padEnd(5)} ${l.message}`)
        .join('\n');
      doc.seccion(pdf, 'Telemetría de ejecución');
      doc.bloqueCodigo(pdf, texto, 'Telemetría');
    }

    // Metadatos al final
    doc.seccion(pdf, 'Metadatos');
    doc.filaKV(pdf, 'Herramienta', result.tool);
    doc.filaKV(pdf, 'Inicio', human(result.startedAt));
    doc.filaKV(pdf, 'Duración', duration(result.durationMs));
    doc.filaKV(pdf, 'Esquema', `v${result.schema}`);

    doc.pieConNumeracion(pdf, pie);
    pdf.end();
  });
}

/** Despacha una seccion al renderizador que le corresponde. */
function pintarSeccion(pdf, seccionDef) {
  const K = SECCION_KINDS;

  switch (seccionDef.kind) {
    case K.TABLA:
      doc.seccion(pdf, seccionDef.title, seccionDef.description);
      doc.tabla(pdf, seccionDef);
      break;

    case K.PARES:
      doc.seccion(pdf, seccionDef.title, seccionDef.description);
      for (const [k, v] of seccionDef.items || []) {
        doc.filaKV(pdf, k, typeof v === 'object' ? v.valor : v, typeof v === 'object' ? v.tone : null);
      }
      pdf.y += 6;
      break;

    case K.CODIGO:
      doc.seccion(pdf, seccionDef.title, seccionDef.description);
      doc.bloqueCodigo(pdf, seccionDef.value ?? '', seccionDef.title);
      break;

    case K.LISTA:
      doc.seccion(pdf, seccionDef.title, seccionDef.description);
      doc.lista(pdf, seccionDef.items || []);
      pdf.y += 6;
      break;

    case K.BARRA:
      doc.seccion(pdf, seccionDef.title, seccionDef.description);
      pintarBarra(pdf, seccionDef);
      break;

    case K.TEXTO:
    default:
      doc.seccion(pdf, seccionDef.title, seccionDef.description);
      if (seccionDef.value) {
        pdf
          .fillColor(COLORES.texto)
          .font(TIPOGRAFIA.fuenteTexto)
          .fontSize(9)
          .text(sanear(String(seccionDef.value)), PAGINA.margen, pdf.y, { width: PAGINA.anchoUtil });
        pdf.y += 8;
      }
      break;
  }
}

/** Barra de progreso para porcentajes (puntuacion de riesgo). */
function pintarBarra(pdf, seccionDef) {
  const { margen, anchoUtil } = PAGINA;
  const valor = Math.max(0, Math.min(100, Number(seccionDef.value) || 0));
  const tone = seccionDef.tone || (valor >= 70 ? 'bad' : valor >= 30 ? 'warn' : 'ok');

  const y = pdf.y + 4;
  pdf.roundedRect(margen, y, anchoUtil, 16, 8).fill(color(tone).suave);
  pdf.roundedRect(margen, y, (anchoUtil * valor) / 100, 16, 8).fill(color(tone).principal);
  pdf
    .fillColor(valor >= 50 ? '#FFFFFF' : COLORES.texto)
    .font(TIPOGRAFIA.fuenteTitulo)
    .fontSize(9)
    .text(`${valor}%`, margen, y + 4, { width: anchoUtil, align: 'center' });

  pdf.y = y + 26;
}

module.exports = { render, STATUS_META };