/**
 * html.js �?" Reporte en HTML autonomo.
 *
 * MODULO DE SALIDA. Es el formato que consume la vista de detalle de la web y
 * el que se abre con "Guardar como" desde el navegador. Se genera con el mismo
 * `Result` que el PDF para que la pantalla y lo descargado no puedan divergir.
 *
 * El CSS va incrustado a proposito: el archivo tiene que abrirse sin servidor,
 * copiarse a un correo o guardarse como evidencia y seguir viendose igual.
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
 * @param {boolean} [options.shared=false] Modo informe compartido (adds nav, branding, download buttons)
 * @param {string} [options.shareUrl] URL del informe compartido
 * @param {string} [options.shareExpira] Fecha expiracion del enlace
 * @param {string} [options.shareAutor] Autor del informe
 * @returns {string}
 */
function render(result, options = {}) {
  const {
    standalone = true,
    pie = 'Generado automaticamente por netlab',
    shared = false,
    shareUrl,
    shareExpira,
    shareAutor
  } = options;
  const meta = STATUS_META[result.status] || STATUS_META.error;

  const sharedHeader = shared ? renderSharedHeader(shareUrl, shareExpira, shareAutor) : '';

  const body = [
    `<header class="cabecera${shared ? ' shared' : ''}">`,
    sharedHeader,
    `  <h1>${e(result.toolTitle)}</h1>`,
    result.headline ? `  <p class="veredicto">${e(result.headline)}</p>` : '',
    `  <p class="sub">${e(meta.label)} �� <code>${e(result.target || 'n/d')}</code> �� ${e(human(result.startedAt))}</p>`,
    `  <span class="badge badge-${e(meta.tone)}">${e(meta.label)}</span>`,
    `</header>`,
    shared ? renderSharedActions(shareUrl) : '',
    resumen(result),
    error(result),
    ...(result.sections || []).map(seccion),
    hallazgos(result),
    `<footer class="pie">${e(pie)} �� ${e(duration(result.durationMs))}</footer>`
  ]
    .filter(Boolean)
    .join('\n');

  if (!standalone) return body;

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${e(result.headline || result.toolTitle)} �?" ${e(result.target || 'informe')}</title>
<style>${CSS}</style>
</head>
<body>
${shared ? '<div class="shared-layout"><nav class="sidebar" id="sidebar" aria-label="Navegacion del informe"></nav>' : ''}
<main class="hoja${shared ? ' with-sidebar' : ''}" id="main-content">
${body}
</main>
${shared ? '</div>' : ''}
${shared ? renderSidebarScript() : ''}
</body>
</html>`;
}

function renderSharedHeader(shareUrl, shareExpira, shareAutor) {
  return `
  <div class="shared-badge">
    <svg class="netlab-logo" viewBox="0 0 32 32" fill="none" aria-hidden="true"><rect width="32" height="32" rx="6" fill="currentColor"/><path d="M8 12h16M8 16h12M8 20h8" stroke="white" stroke-width="2.5" stroke-linecap="round"/></svg>
    <span>Informe Compartido</span>
  </div>
  <div class="shared-meta">
    ${shareUrl ? `<a class="share-link" href="${e(shareUrl)}" target="_blank" rel="noopener">${e(shareUrl)}</a>` : ''}
    ${shareExpira ? `<span class="expira">Expira: ${e(shareExpira)}</span>` : ''}
    ${shareAutor ? `<span class="autor">Compartido por: ${e(shareAutor)}</span>` : ''}
  </div>`;
}

function renderSharedActions(shareUrl) {
  return `
<div class="shared-actions" role="group" aria-label="Acciones del informe">
  <button class="btn btn-primary" onclick="downloadFormat('pdf')" aria-label="Descargar PDF">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
    <span>PDF</span>
  </button>
  <button class="btn btn-secondary" onclick="downloadFormat('json')" aria-label="Descargar JSON">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
    <span>JSON</span>
  </button>
  <button class="btn btn-secondary" onclick="downloadFormat('txt')" aria-label="Descargar TXT">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
    <span>TXT</span>
  </button>
  <button class="btn btn-secondary" onclick="copyShareUrl()" aria-label="Copiar enlace">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    <span>Copiar enlace</span>
  </button>
  <a class="btn btn-link" href="/" target="_blank" rel="noopener" aria-label="Volver a netlab">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
    <span>Volver a netlab</span>
  </a>
</div>`;
}

function renderSidebarScript() {
  return `
<script>
(function() {
  const sidebar = document.getElementById('sidebar');
  const main = document.getElementById('main-content');
  if (!sidebar || !main) return;

  const headings = main.querySelectorAll('section h2');
  if (!headings.length) return;

  const toc = document.createElement('ol');
  toc.className = 'toc';
  headings.forEach((h, i) => {
    const id = 'section-' + i;
    h.id = id;
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = '#' + id;
    a.textContent = h.textContent;
    a.addEventListener('click', (e) => {
      e.preventDefault();
      const target = document.getElementById(id);
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    li.appendChild(a);
    toc.appendChild(li);
  });
  sidebar.appendChild(toc);

  // Highlight active section on scroll
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        document.querySelectorAll('.toc a').forEach(a => a.classList.remove('active'));
        const active = document.querySelector('.toc a[href="#' + entry.target.id + '"]');
        if (active) active.classList.add('active');
      }
    });
  }, { rootMargin: '-20% 0px -70% 0px' });
  headings.forEach(h => observer.observe(h));
})();

function downloadFormat(fmt) {
  const currentUrl = window.location.href;
  const base = currentUrl.split('/r/')[0];
  const token = currentUrl.split('/r/')[1];
  if (!token) return alert('No se pudo determinar el token del informe');
  window.open(base + '/api/run/' + token + '/' + fmt, '_blank');
}

function copyShareUrl() {
  navigator.clipboard.writeText(window.location.href).then(() => {
    const btn = event.target.closest('button');
    const original = btn.innerHTML;
    btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg><span>Copiado!</span>';
    btn.classList.add('copied');
    setTimeout(() => { btn.innerHTML = original; btn.classList.remove('copied'); }, 2000);
  });
}
</script>`;
}

function renderSharedHeader(shareUrl, shareExpira, shareAutor) {
  return `
  <div class="shared-badge">
    <svg class="netlab-logo" viewBox="0 0 32 32" fill="none" aria-hidden="true"><rect width="32" height="32" rx="6" fill="currentColor"/><path d="M8 12h16M8 16h12M8 20h8" stroke="white" stroke-width="2.5" stroke-linecap="round"/></svg>
    <span>Informe Compartido</span>
  </div>
  <div class="shared-meta">
    ${shareUrl ? `<a class="share-link" href="${e(shareUrl)}" target="_blank" rel="noopener">${e(shareUrl)}</a>` : ''}
    ${shareExpira ? `<span class="expira">Expira: ${e(shareExpira)}</span>` : ''}
    ${shareAutor ? `<span class="autor">Compartido por: ${e(shareAutor)}</span>` : ''}
  </div>`;
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
--neu:#64748b;--neu-bg:#e2e8f0;--ink:#0f172a;--mid:#475569;--line:#e2e8f0;--paper:#ffffff;--bg:#f8fafc;
--primary:#2563eb;--primary-hover:#1d4ed8;--primary-bg:#dbeafe;--secondary:#64748b;--secondary-hover:#475569}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.hoja{max-width:900px;margin:0 auto;padding:32px 24px 64px}
.cabecera{display:flex;flex-direction:column;gap:10px;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--line)}
.cabecera h1{margin:0;font-size:28px;letter-spacing:-.02em;color:var(--ink)}
.cabecera .veredicto{margin:0;font-size:22px;font-weight:650;letter-spacing:-.01em}
.cabecera .sub{margin:0;color:var(--mid);font-size:14.5px}
.cabecera code{background:var(--neu-bg);padding:2px 8px;border-radius:6px;font-size:13px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:6px 16px;border-radius:999px;font-size:13px;font-weight:600;color:#fff}
.badge-ok{background:var(--ok)}.badge-warn{background:var(--warn)}.badge-bad{background:var(--bad)}

/* Shared header */
.cabecera.shared{flex-direction:row;flex-wrap:wrap;align-items:center;justify-content:space-between;padding:20px;background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);border-radius:16px 16px 0 0;border:none;color:white;margin:-24px -24px 24px}
.cabecera.shared h1{color:white}
.cabecera.shared .sub{color:rgba(255,255,255,0.8)}
.cabecera.shared .veredicto{color:white}
.cabecera.shared code{background:rgba(255,255,255,0.15);color:white}
.cabecera.shared .badge{background:rgba(255,255,255,0.2);color:white;border:1px solid rgba(255,255,255,0.3)}

.shared-badge{display:inline-flex;align-items:center;gap:10px;padding:8px 16px;background:rgba(255,255,255,0.15);border-radius:999px;border:1px solid rgba(255,255,255,0.2);backdrop-filter:blur(8px)}
.netlab-logo{width:28px;height:28px;color:#2563eb;flex-shrink:0}
.shared-badge span{font-weight:600;font-size:14px;color:white}
.shared-meta{display:flex;flex-wrap:wrap;align-items:center;gap:16px;font-size:13px;color:rgba(255,255,255,0.8)}
.share-link{color:#93c5fd;text-decoration:none;word-break:break-all;max-width:300px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.share-link:hover{color:#bfdbfe;text-decoration:underline}
.expira{background:rgba(245,158,11,0.2);color:#fde68a;padding:4px 12px;border-radius:999px;font-size:12px;font-weight:500}
.autor{color:rgba(255,255,255,0.7);font-size:13px}

.shared-actions{display:flex;flex-wrap:wrap;gap:10px;margin:20px 0;padding:16px;background:var(--paper);border:1px solid var(--line);border-radius:12px}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 18px;border-radius:10px;font-size:13.5px;font-weight:600;cursor:pointer;border:none;transition:all 0.15s ease;text-decoration:none}
.btn:focus-visible{outline:2px solid var(--primary);outline-offset:2px}
.btn-primary{background:var(--primary);color:white;border:none}
.btn-primary:hover{background:var(--primary-hover)}
.btn-secondary{background:var(--neu-bg);color:var(--ink);border:1px solid var(--line)}
.btn-secondary:hover{background:var(--neu);color:var(--ink)}
.btn-link{color:var(--primary);background:transparent;border:none;padding:10px 8px}
.btn-link:hover{text-decoration:underline}
.btn svg{flex-shrink:0}
.btn.copied{background:#10b981;color:white}

.shared-layout{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
.sidebar{position:sticky;top:0;height:100vh;padding:24px 16px;overflow-y:auto;background:var(--paper);border-right:1px solid var(--line)}
.toc{list-style:none;padding:0;margin:0}
.toc li{margin:0}
.toc a{display:block;padding:8px 12px;border-radius:8px;font-size:13.5px;color:var(--mid);text-decoration:none;transition:all 0.1s}
.toc a:hover{background:var(--neu-bg);color:var(--ink)}
.toc a.active{background:var(--primary-bg);color:var(--primary);font-weight:600}
.hoja.with-sidebar{max-width:none;margin:0;padding:0}
@media (max-width: 1024px){
  .shared-layout{grid-template-columns:1fr}
  .sidebar{position:fixed;left:0;top:0;bottom:0;width:280px;z-index:50;transform:translateX(-100%);transition:transform 0.2s ease;box-shadow:4px 0 20px rgba(0,0,0,0.1)}
  .sidebar.open{transform:translateX(0)}
  .sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.3);z-index:40}
  .sidebar-overlay.visible{display:block}
}

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

.shared-actions{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0;padding:16px;background:var(--paper);border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 2px rgba(15,23,42,.03)}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 18px;border-radius:10px;font-size:13.5px;font-weight:600;cursor:pointer;border:none;transition:all 0.15s ease;text-decoration:none;line-height:1.1}
.btn:focus-visible{outline:2px solid var(--primary);outline-offset:2px}
.btn-primary{background:var(--primary);color:white;border:none}
.btn-primary:hover{background:var(--primary-hover)}
.btn-secondary{background:var(--neu-bg);color:var(--ink);border:1px solid var(--line)}
.btn-secondary:hover{background:#e7ecf5}
.btn-link{color:var(--primary);background:transparent;border:none;padding:10px 8px}
.btn-link:hover{text-decoration:underline}
.btn svg{flex-shrink:0}
.btn.copied{background:var(--ok);color:white}

.shared-layout{display:flex;gap:24px;max-width:1200px;margin:0 auto;padding:24px 20px 40px;align-items:flex-start}
.sidebar{width:240px;flex-shrink:0;position:sticky;top:24px;background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:18px 16px;max-height:calc(100vh - 48px);overflow:auto;box-shadow:0 1px 2px rgba(15,23,42,.03)}
.sidebar h3{margin:0 0 12px;font-size:12.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--mid);font-weight:700}
.toc{margin:0;padding-left:0;list-style:none}
.toc li{margin:0}
.toc a{display:block;padding:8px 10px;border-radius:8px;color:var(--mid);text-decoration:none;font-size:13.5px;line-height:1.25;transition:all 0.12s ease;border-left:2px solid transparent}
.toc a:hover{background:var(--bg);color:var(--ink)}
.toc a.active{background:var(--primary-bg);color:var(--primary);border-left-color:var(--primary);font-weight:600}
.toc a:focus-visible{outline:2px solid var(--primary);outline-offset:2px}
.hoja.with-sidebar{flex:1;min-width:0;margin:0;box-shadow:0 1px 2px rgba(15,23,42,.03)}

.cabecera.shared{display:flex;flex-direction:column;gap:14px;background:linear-gradient(180deg,#0f172a 0%,#1e293b 100%);color:#f8fafc;padding:20px 24px;border-radius:12px;border:1px solid rgba(255,255,255,.08);box-shadow:0 1px 2px rgba(15,23,42,.08)}
.cabecera.shared h1{color:#f8fafc;margin:6px 0 2px;font-size:26px;letter-spacing:-.01em}
.cabecera.shared .sub{color:rgba(248,250,252,.85);margin:0}
.cabecera.shared .veredicto{color:#f8fafc}
.cabecera.shared .badge{align-self:flex-start;background:rgba(255,255,255,.15);color:#f8fafc;border:1px solid rgba(255,255,255,.25);backdrop-filter:saturate(140%) blur(4px)}
.cabecera.shared code{background:rgba(15,23,42,.45);color:#f8fafc;border-color:rgba(255,255,255,.25)}
.shared-badge{display:flex;align-items:center;gap:10px;align-self:flex-start;padding:6px 10px;border-radius:999px;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.25);backdrop-filter:saturate(140%) blur(4px)}
.shared-badge span{font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-weight:700}
.netlab-logo{width:20px;height:20px;color:#f8fafc}
.shared-meta{display:flex;flex-wrap:wrap;align-items:center;gap:10px 14px;font-size:13.5px;color:rgba(248,250,252,.9)}
.shared-meta .share-link{color:#f8fafc;text-decoration:none;padding:6px 10px;border-radius:999px;background:rgba(15,23,42,.45);border:1px solid rgba(255,255,255,.2);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.shared-meta .share-link:hover{text-decoration:underline;background:rgba(15,23,42,.55)}
.shared-meta .expira,.shared-meta .autor{opacity:.95;padding:4px 8px;border-radius:999px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.18)}

@media (max-width: 980px){
  .shared-layout{flex-direction:column;padding:16px 12px 32px}
  .sidebar{position:static;width:100%;max-height:none}
  .hoja.with-sidebar{margin:0}
  .shared-meta .share-link{max-width:240px}
}

@media print{
  body{background:#fff}
  .hoja,.hoja.with-sidebar{max-width:none;padding:0;margin:0}
  section{break-inside:avoid}
  .shared-actions,.sidebar,.shared-badge,.shared-meta{display:none}
  .cabecera.shared{border-radius:0;background:#0f172a !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
`;

module.exports = { render, escapeHtml };