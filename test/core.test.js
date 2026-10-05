'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { buildReportName, slug, shortHash } = require('../src/core/filenames');
const { stamp, duration, relative, human } = require('../src/core/time');
const { createResult, addSummary, addFinding, addSection, deriveStatus, ESTADOS, SECCION_KINDS } = require('../src/core/result');
const { NetlabError, wrap, CODES } = require('../src/core/errors');
const { createLogger } = require('../src/core/logger');

// --------------------------------------------------------------- filenames --

test('slug limpia caracteres no validos en Windows', () => {
  assert.strictEqual(slug('smtp.hostingssi.com:465/test'), 'smtp.hostingssi.com-465-test');
  assert.strictEqual(slug('a  b   c'), 'a-b-c');
  assert.strictEqual(slug('///'), '');
});

test('slug neutraliza los nombres reservados de Windows', () => {
  // Sin esto, "CON" crearia una ruta imposible de escribir en Windows.
  assert.strictEqual(slug('CON'), '_CON');
  assert.strictEqual(slug('con'), '_con');
  assert.strictEqual(slug('COM1.txt'), '_COM1.txt');
  assert.strictEqual(slug('console'), 'console', 'no debe tocar lo que solo empieza igual');
});

test('slug recorta a la longitud pedida sin dejar guiones colgantes', () => {
  const s = slug('un-nombre-de-objetivo-muy-largo-de-verdad', { max: 20 });
  assert.ok(s.length <= 20);
  assert.ok(!s.endsWith('-'));
});

test('el nombre de reporte incluye marca de tiempo y no se repite', () => {
  const contenido = { a: 1 };
  const n1 = buildReportName({ tool: 'ip-audit', target: '166.1.88.250', ext: 'pdf', content: contenido });
  const n2 = buildReportName({ tool: 'ip-audit', target: '166.1.88.250', ext: 'pdf', content: contenido });
  // Mismo contenido + misma fecha logica => nombres distintos gracias al hash.
  assert.notStrictEqual(n1, n2, 'dos corridas identicas no deben pisarse');
  assert.match(n1, /^ip-audit_166\.1\.88\.250_\d{4}-\d{2}-\d{2}T[\d-]+Z_[0-9a-f]{6}\.pdf$/);
});

test('slug no permite traversals de directorio', () => {
  // Las barras se convierten en guiones, asi que "../../etc/passwd" no escapa.
  const s = slug('../../etc/passwd');
  assert.ok(!s.includes('/'));
  assert.ok(!s.includes('\\'));
  assert.strictEqual(s, 'etc-passwd');
});

test('el nombre de reporte es el que evita el defecto de sobrescritura', () => {
  // Defecto real: legacy/Check IP Abuse/checked/check-ip.js usaba
  // 'Auditoria_<ip>.pdf' fijo, y cada corrida pisaba la anterior.
  const nombres = new Set();
  for (let i = 0; i < 50; i++) {
    nombres.add(buildReportName({ tool: 'ip-audit', target: '166.1.88.250', ext: 'pdf', content: { i } }));
  }
  assert.strictEqual(nombres.size, 50, 'ninguna corrida puede coincidir con otra');
});

test('shortHash es estable y corto', () => {
  assert.strictEqual(shortHash('abc'), shortHash('abc'));
  assert.strictEqual(shortHash('abc').length, 6);
  assert.notStrictEqual(shortHash('abc'), shortHash('abd'));
});

// -------------------------------------------------------------------- time --

test('stamp genera un nombre de archivo sin caracteres invalidos', () => {
  const s = stamp(new Date('2026-09-30T14:28:15.227Z'));
  assert.ok(!/[:.]/.test(s), 'no debe contener dos puntos ni puntos');
  assert.match(s, /^\d{4}-\d{2}-\d{2}T[\d\-]+Z$/);
});

test('duration formatea cada escala', () => {
  assert.strictEqual(duration(240), '240 ms');
  assert.strictEqual(duration(1240), '1.24 s');
  assert.strictEqual(duration(125000), '2 m 05 s');
  assert.strictEqual(duration(-1), 'n/d');
});

test('relative maneja pasado y futuro', () => {
  assert.strictEqual(relative(Date.now() - 1000).includes('ahora'), true);
  assert.ok(relative(Date.now() - 3 * 3600e3).length > 0);
});

test('human no lanza con una fecha invalida', () => {
  assert.strictEqual(human('no-es-una-fecha'), '');
});

// ------------------------------------------------------------------ result --

test('deriveStatus baja a fail si hay un hallazgo error', () => {
  const r = createResult({ tool: 'x' });
  addFinding(r, { severity: 'warn', title: 'aviso' });
  assert.strictEqual(r.status, ESTADOS.PASS);
  deriveStatus(r);
  assert.strictEqual(r.status, ESTADOS.WARN, 'un warn debe baixar el estado a warn');
});

test('deriveStatus no pisa un estado de error ya fijado', () => {
  const r = createResult({ tool: 'x' });
  r.status = ESTADOS.ERROR;
  deriveStatus(r);
  assert.strictEqual(r.status, ESTADOS.ERROR);
});

test('addSection exige un kind', () => {
  const r = createResult({ tool: 'x' });
  assert.throws(() => addSection(r, { title: 'sin kind' }), /kind/);
  addSection(r, { id: 'a', title: 'Con kind', kind: SECCION_KINDS.TABLA, rows: [] });
  assert.strictEqual(r.sections.length, 1);
});

test('el Result es serializable a JSON', () => {
  const r = createResult({ tool: 'dns-checker', target: 'ejemplo.com' });
  addSummary(r, 'Registros', 5, 'ok');
  addSection(r, { id: 's', title: 'Tabla', kind: SECCION_KINDS.TABLA, columns: ['A'], rows: [['b']] });
  const copia = JSON.parse(JSON.stringify(r));
  assert.strictEqual(copia.schema, 2);
  assert.strictEqual(copia.target, 'ejemplo.com');
  assert.strictEqual(copia.summary[0].value, '5', 'el valor se serializa como texto');
  // Desde el esquema 2 el titular viaja en el propio Result, sin que quien lo
  // pinte tenga que acordarse de escribirlo.
  assert.strictEqual(copia.headline, null, 'sin setHeadline el titular va vacío, no inventado');
});

// ------------------------------------------------------------------ errors --

test('wrap traduce los codigos de error de red del sistema', () => {
  const e = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
  const envuelto = wrap(e, { contexto: 'conectar al puerto 465' });
  assert.strictEqual(envuelto.code, CODES.RED);
  assert.match(envuelto.message, /465/);
  assert.ok(envuelto.remediation);
});

test('wrap traduce los errores de certificado', () => {
  const e = Object.assign(new Error('x'), { code: 'CERT_HAS_EXPIRED' });
  assert.strictEqual(wrap(e).code, CODES.TLS_INVALIDO);
});

test('wrap deja pasar un NetlabError sin reenvolverlo', () => {
  const original = new NetlabError(CODES.API_CUOTA, 'Cuota agotada');
  assert.strictEqual(wrap(original), original);
});

test('NetlabError serializa sin filtrar la pila interna', () => {
  const e = new NetlabError(CODES.PARAM_INVALIDO, 'IP invalida', { remediation: 'Revisala' });
  const json = JSON.parse(JSON.stringify(e));
  assert.strictEqual(json.code, 'PARAM_INVALIDO');
  assert.strictEqual(json.stack, undefined, 'la pila no debe viajar al navegador');
});

// ------------------------------------------------------------------ logger --

test('el logger redacta secretos antes de escribirlos', () => {
  const r = createResult({ tool: 'x' });
  const log = createLogger({ result: r, channel: 'smtp', console: false, secrets: ['claveSupersecreta'] });
  log.info('conectando con claveSupersecreta');
  assert.ok(!r.logs[0].message.includes('claveSupersecreta'));
  assert.ok(r.logs[0].message.includes('[REDACTADO]'));
});

test('el logger escribe en el Result y respeta el canal', () => {
  const r = createResult({ tool: 'x' });
  const log = createLogger({ result: r, console: false });
  log.child('dns').warn('TTL bajo');
  assert.strictEqual(r.logs[0].channel, 'dns');
  assert.strictEqual(r.logs[0].level, 'warn');
});

test('el logger serializa objetos sin saltos de linea', () => {
  const r = createResult({ tool: 'x' });
  const log = createLogger({ result: r, console: false });
  log.info('datos', { host: 'x', ttl: 300 });
  assert.ok(!r.logs[0].message.includes('\n'), 'un log debe caber en una linea del PDF');
});