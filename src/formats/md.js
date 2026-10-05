/**
 * md.js — Reporte en Markdown.
 *
 * MODULO DE SALIDA. Markdown es el formato que mas seParece a lo que ya
 * generaba legacy/Validate config SMTP/validate-smtp.js, que imprimia el
 * reporte en la consola con caracteres de tabla. Sirve para pegar el informe
 * en un ticket o en un chat sin perder el formato.
 *
 * @module formats/md
 */

'use strict';

const { human, duration } = require('../core/time');
const { STATUS_META } = require('../core/result');

/**
 * Renderiza un Result a Markdown.
 *
 * @param {object} result
 * @param {object} [options]
 * @returns {string}
 */
function render(result, options = {}) {
  const { pie = 'Generado automaticamente por netlab' } = options;
  const meta = STATUS_META[result.status] || STATUS_META.error;
  const out = [];

  out.push(`# ${result.toolTitle}`);
  out.push('');
  if (result.headline) out.push(`## ${result.headline}`, '');
  out.push(`> **${meta.label}** · Objetivo: \`${result.target || 'n/d'}\` · ${human(result.startedAt)} · ${duration(result.durationMs)}`);
  out.push('');

  if (result.summary?.length) {
    out.push('| Concepto | Valor |');
    out.push('| --- | --- |');
    for (const item of result.summary) {
      out.push(`| ${item.label} | ${escaparCelda(item.value)} |`);
    }
    out.push('');
  }

  if (result.error) {
    out.push('## Error');
    out.push('');
    out.push(`**\`${result.error.code}\`** ${result.error.message}`);
    if (result.error.remediation) out.push('', `> ${result.error.remediation}`);
    out.push('');
  }

  for (const seccionDef of result.sections || []) {
    out.push(`## ${seccionDef.title}`);
    if (seccionDef.description) out.push('', `*${seccionDef.description}*`);
    out.push('');

    switch (seccionDef.kind) {
      case 'table': {
        const columnas = seccionDef.columns || [];
        const filas = seccionDef.rows || [];
        if (columnas.length) {
          out.push(`| ${columnas.join(' | ')} |`);
          out.push(`| ${columnas.map(() => '---').join(' | ')} |`);
          for (const fila of filas) {
            const celdas = (Array.isArray(fila) ? fila : [fila]).map((c) => escaparCelda(celdaTexto(c)));
            out.push(`| ${celdas.join(' | ')} |`);
          }
        } else {
          out.push('_(sin resultados)_');
        }
        out.push('');
        break;
      }

      case 'kv': {
        out.push('| Campo | Valor |');
        out.push('| --- | --- |');
        for (const [k, v] of seccionDef.items || []) {
          const valor = typeof v === 'object' ? v.valor : v;
          out.push(`| ${k} | ${escaparCelda(valor)} |`);
        }
        out.push('');
        break;
      }

      case 'code':
        out.push('```');
        out.push(String(seccionDef.value ?? ''));
        out.push('```');
        out.push('');
        break;

      case 'list':
        for (const item of seccionDef.items || []) out.push(`- ${item}`);
        out.push('');
        break;

      case 'meter':
        out.push('```');
        out.push(barraTexto(seccionDef.value));
        out.push('```');
        out.push('');
        break;

      case 'text':
      default:
        if (seccionDef.value) out.push(String(seccionDef.value), '');
        break;
    }
  }

  if (result.findings?.length) {
    out.push('## Hallazgos');
    out.push('');
    for (const h of result.findings) {
      const icono = h.severity === 'error' ? '🔴' : h.severity === 'warn' ? '🟡' : '🔵';
      out.push(`### ${icono} ${h.title}`);
      if (h.detail) out.push('', h.detail);
      if (h.recommendation) out.push('', `**Qué hacer:** ${h.recommendation}`);
      out.push('');
    }
  }

  out.push('---');
  out.push(`_${pie}_`);

  return out.join('\n');
}

/** Extrae el texto de una celda que puede traer objeto. */
function celdaTexto(celda) {
  if (celda && typeof celda === 'object') return celda.valor ?? '';
  return celda ?? '';
}

/** Escapa los pipes que romperian la tabla de Markdown. */
function escaparCelda(valor) {
  return String(valor ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/** Barra de progreso legible. */
function barraTexto(valor, ancho = 30) {
  const v = Math.max(0, Math.min(100, Number(valor) || 0));
  const llenos = Math.round((v / 100) * ancho);
  return `[${'█'.repeat(llenos)}${'░'.repeat(ancho - llenos)}] ${v}%`;
}

module.exports = { render };