/**
 * html.js — Reporte en HTML autonomo.
 *
 * MODULO DE SALIDA. Es el formato que consume la vista de detalle de la web y
 * el que se abre con "Guardar como" desde el navegador. Se genera con el mismo
 * `Result` que el PDF para que la pantalla y lo descargado no puedan divergir.
 *
 * El CSS va incrustado a proposito: el archivo tiene que abrirse sin servidor,
 * copiarse a un correo o guardarse como evidencia y seguir viéndose igual.
 *
 * @module formats/html
 */

'use strict';

const { human, duration } = require('../core/time');
const { STATUS_META } = require('../core/result');
const { redact } = require('../core/redact');

/**
 * Renderiza un Result a HTML.
 *
 * @param {object} result
 * @param {object} [options]
 * @param {boolean} [options.standalone=true] Envolver en documento completo.
 * @param {string} [options.pie]
 * @returns {string}
 */
function render(result, options = {}) {
  const { standalone = true, pie = 'Generado automaticamente por netlab' } = options;
  const meta = STATUS_META[result.status] || STATUS_META.error;

  const body = [
    `<header class="cabecera">`,
    `  <h1>${e(result.toolTitle)}</h1>`,
    result.headline ? `  <p class="veredicto">${e(result.headline)}</p>` : '',
    `  <p class="sub">${e(meta.label)} · <code>${e(result.target || 'n/d')}</code> · ${e(human(result.startedAt))}</p>`,
    `  <span class="badge badge-${e(meta.tone)}">${e(meta.label)}</span>`,
    `</header>`,
    resumen(result),
    error(result),
    ...(result.sections || []).map(seccion),
    hallazgos(result),
    `<footer class="pie">${e(pie)} · ${e(duration(result.durationMs))}</footer>`
  ]
    .filter(Boolean)
    .join('\n');

  if (!standalone) return body;

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${e(result.headline || result.toolTitle)} — ${e(result.target || 'informe')}</title>
<style>${CSS}</style>
</head>
<body>
<main class="hoja">
${body}
</main>
</body>
</html>`;
}

/** Bloque de resumen. */
function resumen(result) {
  if (!result.summary?.length) return '';
  return `<section class="tarjetas">
${result.summary.map((s) => `  <div class="tarjeta t-${e(s.tone)}"><span class="lbl">${e(s.label)}</span><span class="val">${e(s.value)}</span></div>`).join('\n')}
</section>`;
}

/** Bloque de error. */
function error(result) {
  if (!result.error) return '';
  return `<section class="error">
  <h2>Error de ejecucion</h2>
  <p><code>${e(result.error.code)}</code> ${e(result.error.message)}</p>
  ${result.error.remediation ? `<p class="remediacion">${e(result.error.remediation)}</p>` : ''}
</section>`;
}

/** Un bloque del cuerpo. */
function seccion(s) {
  const cab = `<h2>${e(s.title)}</h2>${s.description ? `<p class="desc">${e(s.description)}</p>` : ''}`;

  switch (s.kind) {
    case 'table': {
      if (!s.columns?.length) return `<section>${cab}<p class="vacio">Sin resultados.</p></section>`;
      const filas = (s.rows || [])
        .map((fila) => {
          const celdas = (Array.isArray(fila) ? fila : [fila]).map((c) => celdaHtml(c));
          return `    <tr>${celdas.map((c) => `      <td>${c}</td>`).join('')}</tr>`;
        })
        .join('\n');
      return `<section>${cab}
  <table>
    <thead><tr>${s.columns.map((c) => `<th>${e(c)}</th>`).join('')}</tr></thead>
    <tbody>
${filas}
    </tbody>
  </table>
</section>`;
    }

    case 'kv': {
      const items = (s.items || [])
        .map(([k, v]) => {
          const obj = typeof v === 'object' && v !== null ? v : { valor: v };
          return `    <div class="kv ${obj.tone ? `t-${e(obj.tone)}` : ''}"><dt>${e(k)}</dt><dd>${e(obj.valor ?? '')}</dd></div>`;
        })
        .join('\n');
      return `<section>${cab}
  <dl class="kv-grid">
${items}
  </dl>
</section>`;
    }

    case 'code':
      return `<section>${cab}
  <pre><code>${e(s.value ?? '')}</code></pre>
</section>`;

    case 'list':
      return `<section>${cab}
  <ul>${(s.items || []).map((i) => `<li>${e(i)}</li>`).join('')}</ul>
</section>`;

    case 'meter':
      return `<section>${cab}
  <div class="meter t-${e(s.tone || tonoPorValor(s.value))}"><div class="barra" style="width:${clamp(s.value)}%"></div><span>${clamp(s.value)}%</span></div>
</section>`;

    case 'text':
    default:
      return s.value ? `<section>${cab}<p>${e(String(s.value)).replace(/\n/g, '<br>')}</p></section>` : `<section>${cab}</section>`;
  }
}

/** Lista de hallazgos. */
function hallazgos(result) {
  if (!result.findings?.length) return '';
  const items = result.findings
    .map(
      (h) => `    <li class="h ${e(h.severity)}">
      <h3>${e(h.title)}</h3>
      ${h.detail ? `<p>${e(h.detail)}</p>` : ''}
      ${h.recommendation ? `<p class="rec"><strong>Que hacer:</strong> ${e(h.recommendation)}</p>` : ''}
    </li>`
    )
    .join('\n');
  return `<section>
  <h2>Hallazgos</h2>
  <ol class="hallazgos">
${items}
  </ol>
</section>`;
}

/** Pinta una celda que puede ser texto u objeto con tono. */
function celdaHtml(c) {
  if (c && typeof c === 'object') {
    const clase = c.tone ? ` class="t-${e(c.tone)}"` : '';
    return `<td${clase}>${e(c.valor ?? '')}</td>`;
  }
  return `<td>${e(c ?? '')}</td>`;
}

/** Escapa HTML. Se aplica redact para que ningun secreto llegue al reporte. */
function e(valor) {
  return escapeHtml(redact(String(valor ?? '')));
}

/** Escapa los cinco caracteres especiales de HTML. */
function escapeHtml(texto) {
  return String(texto)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Acota un porcentaje a 0-100. */
function clamp(valor) {
  return Math.max(0, Math.min(100, Math.round(Number(valor) || 0)));
}

/** Elige tono por defecto de una barra segun su valor. */
function tonoPorValor(valor) {
  const v = clamp(valor);
  return v >= 70 ? 'bad' : v >= 30 ? 'warn' : 'ok';
}

/** CSS incrustado. Sin dependencias ni fuentes externas. */
const CSS = `
:root{--ok:#10b981;--ok-bg:#d1fae5;--warn:#f59e0b;--warn-bg:#fef3c7;--bad:#ef4444;--bad-bg:#fee2e2;
--neu:#64748b;--neu-bg:#e2e8f0;--ink:#0f172a;--mid:#475569;--line:#e2e8f0;--paper:#ffffff;--bg:#f8fafc}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.hoja{max-width:900px;margin:0 auto;padding:32px 24px 64px}
.cabecera h1{margin:0 0 4px;font-size:26px;letter-spacing:-.02em}
.cabecera .veredicto{margin:0 0 6px;font-size:21px;font-weight:650;letter-spacing:-.01em}
.cabecera .sub{margin:0 0 12px;color:var(--mid);font-size:14px}
.cabecera code{background:var(--neu-bg);padding:1px 6px;border-radius:4px;font-size:13px}
.badge{display:inline-block;padding:5px 14px;border-radius:999px;font-size:13px;font-weight:600;color:#fff}
.badge-ok{background:var(--ok)}.badge-warn{background:var(--warn)}.badge-bad{background:var(--bad)}
section{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin:16px 0}
section h2{margin:0 0 4px;font-size:17px}
section .desc{margin:0 0 14px;color:var(--mid);font-size:13.5px}
section .vacio{color:var(--mid);font-style:italic}
.tarjetas{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:16px 0}
.tarjeta{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:14px 16px;display:flex;flex-direction:column;gap:4px}
.tarjeta .lbl{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mid)}
.tarjeta .val{font-size:19px;font-weight:600}
.t-ok{color:var(--ok)}.t-warn{color:var(--warn)}.t-bad{color:var(--bad)}.t-neutral{color:var(--mid)}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;padding:8px 10px;background:#1e293b;color:#f8fafc;font-weight:600;font-size:12.5px}
th:first-child{border-radius:6px 0 0 6px}th:last-child{border-radius:0 6px 6px 0}
td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:nth-child(even){background:#f8fafc}
tbody tr:last-child td{border-bottom:none}
.kv-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:2px 20px;margin:0}
.kv{display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-bottom:1px solid var(--line)}
.kv dt{color:var(--mid);font-size:13.5px}
.kv dd{margin:0;font-weight:600;font-size:13.5px;text-align:right;word-break:break-word}
pre{background:#0f172a;color:#34d399;padding:14px 16px;border-radius:8px;overflow-x:auto;
font:12.5px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
ul,ol.hallazgos{margin:0;padding-left:20px}
ul li{margin:3px 0}
ol.hallazgos{list-style:none;padding-left:0}
ol.hallazgos li{border-left:3px solid var(--neu);padding:8px 0 8px 14px;margin:10px 0}
ol.hallazgos li.error{border-color:var(--bad)}
ol.hallazgos li.warn{border-color:var(--warn)}
ol.hallazgos li.info{border-color:var(--neu)}
ol.hallazgos h3{margin:0 0 4px;font-size:14.5px}
ol.hallazgos p{margin:3px 0;font-size:13.5px;color:var(--mid)}
ol.hallazgos .rec{color:var(--ink)}
ol.hallazgos .rec strong{color:var(--mid);font-weight:600}
section.error{border-color:var(--bad);background:#fff5f5}
section.error h2{color:var(--bad)}
.remediacion{color:var(--mid);font-size:13.5px}
.meter{position:relative;height:26px;background:var(--neu-bg);border-radius:13px;overflow:hidden;min-width:220px}
.meter .barra{height:100%;background:var(--neu);border-radius:13px}
.meter.t-ok .barra{background:var(--ok)}.meter.t-warn .barra{background:var(--warn)}.meter.t-bad .barra{background:var(--bad)}
.meter span{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
font-size:12.5px;font-weight:700;color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.35)}
.pie{margin-top:28px;padding-top:14px;border-top:1px solid var(--line);color:var(--mid);font-size:12.5px;text-align:center}
@media print{body{background:#fff}.hoja{max-width:none;padding:0}section{break-inside:avoid}}
`;

module.exports = { render, escapeHtml };