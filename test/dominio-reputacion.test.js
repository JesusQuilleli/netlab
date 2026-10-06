'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const herramienta = require('../src/tools/dominio-reputacion');
const { ESTADOS } = require('../src/core/result');
const { CODES } = require('../src/core/errors');

/** Respuesta de `consultarDominio` con valores por defecto razonables. */
function resultado(extra = {}) {
  return {
    estado: 'limpio',
    dominio: 'ejemplo.com',
    consultado: 'ejemplo.com',
    codigo: null,
    error: null,
    avisos: [],
    ...extra
  };
}

/** Doble de la consulta: sirve el mismo objeto (o el que diga la funcion). */
function doble(objeto) {
  return async (dominio, opciones) => {
    const d = typeof objeto === 'function' ? objeto(dominio, opciones) : objeto;
    if (d instanceof Error) throw d;
    return { ...resultado(), ...d, dominio: d.dominio ?? dominio };
  };
}

/** Ejecuta con la consulta inyectada, saltandose la red. */
function ejecutar(params, ctx = {}) {
  return herramienta.ejecutar(params, ctx);
}

/** Busca un hallazgo cuyo titulo encaje con el patron. */
function hallazgo(result, patron) {
  return result.findings.find((f) => patron.test(f.title));
}

/** Busca una seccion por titulo. */
function seccion(result, titulo) {
  return result.sections.find((s) => s.title === titulo);
}

test('sin dominio lo dice y dice como arreglarlo', async () => {
  let llamadas = 0;
  const r = await ejecutar(
    {},
    { dbl: doble(async () => { llamadas++; }) }
  );

  assert.equal(r.status, ESTADOS.ERROR);
  assert.equal(r.error.code, CODES.ENTRADA_VACIA);
  assert.match(r.error.remediation, /escribe el dominio/i);
  assert.equal(llamadas, 0, 'no se llega a consultar nada');
});

test('un dominio invalido no se consulta', async () => {
  const r = await ejecutar({ dominio: 'esto no es un dominio' }, { dbl: doble({ estado: 'listada' }) });

  assert.equal(r.status, ESTADOS.ERROR);
  assert.equal(r.error.code, CODES.PARAM_INVALIDO);
  assert.ok(r.findings.length === 0);
});

test('un dominio limpio pasa y dice que no esta listado', async () => {
  const r = await ejecutar({ dominio: 'ejemplo.com' }, { dbl: doble({ estado: 'limpio' }) });

  assert.equal(r.status, ESTADOS.PASS);
  assert.equal(r.summary.find((s) => s.label === 'Estado').value, 'Limpio');
  const h = hallazgo(r, /no aparece en Spamhaus DBL/);
  assert.equal(h.severity, 'info');
  assert.equal(seccion(r, 'Reputacion de dominio').items.find(([k]) => k === 'Codigo de la lista')[1], '—');
});

test('un dominio listado es un fallo, con su codigo', async () => {
  const r = await ejecutar({ dominio: 'spam.example.com' }, { dbl: doble({ estado: 'listada', codigo: '127.0.1.2' }) });

  assert.equal(r.status, ESTADOS.FAIL);
  assert.equal(r.summary.find((s) => s.label === 'Estado').value, 'Listado');

  const h = hallazgo(r, /esta en la lista de dominios/);
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /spam\.example\.com/);
  assert.match(h.detail, /127\.0\.1\.2/);

  const items = seccion(r, 'Reputacion de dominio').items;
  assert.equal(items.find(([k]) => k === 'Codigo de la lista')[1], '127.0.1.2');
});

test('un subdominio limpio no esconde que el raiz esta listado', async () => {
  const r = await ejecutar(
    { dominio: 'boletin.ejemplo.com' },
    { dbl: doble({ estado: 'listada', dominio: 'boletin.ejemplo.com', consultado: 'ejemplo.com', codigo: '127.0.1.4' }) }
  );

  assert.equal(r.status, ESTADOS.FAIL);
  const h = hallazgo(r, /esta en la lista de dominios/);
  assert.match(h.detail, /la marca en ejemplo\.com/, 'el hallazgo dice donde esta realmente la marca');

  const items = seccion(r, 'Reputacion de dominio').items;
  assert.equal(items.find(([k]) => k === 'Consultado en')[1], 'ejemplo.com.dbl.spamhaus.org');
});

test('un "sin datos" es advertencia y no se presenta como limpio', async () => {
  const r = await ejecutar(
    { dominio: 'ejemplo.com' },
    { dbl: doble({ estado: 'sin-datos', error: 'Spamhaus no respondio desde este resolvedor.' }) }
  );

  assert.equal(r.status, ESTADOS.WARN);
  assert.equal(r.summary.find((s) => s.label === 'Estado').value, 'Sin datos');
  const h = hallazgo(r, /No se pudo comprobar la reputacion/);
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /no respondio desde este resolvedor/);
  assert.match(h.recommendation, /NO es un "limpio"/);
});

test('el aviso de acceso viaja a la seccion', async () => {
  const aviso = 'Spamhaus solo devuelve datos a quien consulta desde una direccion registrada.';
  const r = await ejecutar(
    { dominio: 'ejemplo.com' },
    { dbl: doble({ estado: 'sin-datos', error: aviso, avisos: [aviso] }) }
  );

  const items = seccion(r, 'Reputacion de dominio').items;
  assert.equal(items.find(([k]) => k === 'Aviso de la lista')[1], aviso);
});

test('el dominio se limpia como en las demas herramientas', async () => {
  let recibido = null;
  const r = await ejecutar(
    { dominio: 'https://Ejemplo.com:443/ruta' },
    { dbl: doble(async (d) => { recibido = d; return { estado: 'limpio' }; }) }
  );

  assert.equal(r.target, 'ejemplo.com');
  assert.equal(recibido, 'ejemplo.com');
  assert.equal(r.status, ESTADOS.PASS);
});

test('el timeout se acota y el acceso Spamhaus va marcado por defecto', async () => {
  let opciones = null;
  await ejecutar(
    { dominio: 'ejemplo.com', timeout: '999999999' },
    { dbl: doble(async (d, o) => { opciones = o; return { estado: 'limpio' }; }) }
  );

  assert.equal(opciones.timeout, 30000, 'se acota a lo maximo');
  assert.equal(opciones.accesoSpamhaus, true, 'por defecto se comprueba');
});

test('desactivar el acceso Spamhaus se lo cuenta a la consulta', async () => {
  let opciones = null;
  await ejecutar(
    { dominio: 'ejemplo.com', accesoSpamhaus: false },
    { dbl: doble(async (d, o) => { opciones = o; return { estado: 'limpio' }; }) }
  );

  assert.equal(opciones.accesoSpamhaus, false);
});

test('una consulta que falla no acaba en un "todo limpio"', async () => {
  const r = await ejecutar(
    { dominio: 'ejemplo.com' },
    { dbl: doble(new Error('red caida')) }
  );

  assert.equal(r.status, ESTADOS.ERROR);
  assert.match(r.error.message, /red caida/);
});

test('declara los campos que necesita el formulario', () => {
  assert.equal(herramienta.id, 'dominio-reputacion');
  assert.equal(herramienta.sinRed, false);
  const dominio = herramienta.campos.find((c) => c.name === 'dominio');
  assert.ok(dominio, 'el campo dominio existe');
  assert.equal(dominio.required, true);
});

test('el catalogo lo ofrece como herramienta', () => {
  const { herramientas } = require('../src/server/herramientas').cargar();
  const h = herramientas.find((x) => x.id === 'dominio-reputacion');
  assert.ok(h, 'debe estar registrada');
  assert.equal(h.titulo, 'Reputacion de Dominio');
  assert.equal(h.ejecutar, undefined, 'el catalogo no ensena la funcion');
});