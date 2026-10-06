'use strict';

/**
 * test/mail-core.test.js — Pruebas de los analizadores de correo.
 *
 * Son funciones puras: reciben texto ya resuelto y devuelven una interpretación.
 * No tocan la red, así que aquí no se inyecta ningún doble y se puede comprobar
 * cada rama (registros múltiples, claves revocadas, cabeceras plegadas...) sin
 * depender de que un dominio real los publique hoy.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const spf = require('../src/core/mail/spf');
const dmarc = require('../src/core/mail/dmarc');
const dkim = require('../src/core/mail/dkim');
const transporte = require('../src/core/mail/transporte');
const mensaje = require('../src/core/mail/mensaje');
const contenido = require('../src/core/mail/contenido');
const puntuacion = require('../src/core/mail/puntuacion');

/* ------------------------------------------------------------------ *
 * Utilidades
 * ------------------------------------------------------------------ */

/** Clave pública RSA en base64, como la publica un selector DKIM. */
function claveRsa(bits = 2048) {
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: bits });
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
}

function leerFixture(nombre) {
  return fs.readFileSync(path.join(__dirname, 'fixtures', nombre), 'utf8');
}

function check(result, id) {
  const encontrado = result.checks.find((c) => c.id === id);
  assert.ok(encontrado, `no existe la comprobación "${id}". Hay: ${result.checks.map((c) => c.id).join(', ')}`);
  return encontrado;
}

/* ------------------------------------------------------------------ *
 * SPF
 * ------------------------------------------------------------------ */

test('SPF: un registro correcto se lee entero', () => {
  const r = spf.parsear(['v=spf1 include:_spf.ejemplo.com ~all']);
  assert.equal(r.presente, true);
  assert.equal(r.multiple, false);
  assert.equal(r.valido, true);
  assert.deepEqual(r.includes, ['_spf.ejemplo.com']);
  assert.equal(r.lookups, 1);
  assert.equal(r.calificacionAll, 'softfail');
  assert.deepEqual(r.avisos, []);
});

test('SPF: sin registro no se inventa nada', () => {
  const r = spf.parsear([]);
  assert.equal(r.presente, false);
  assert.equal(r.lookups, 0);
});

test('SPF: dos registros son un error, no una suma', () => {
  const r = spf.parsear(['v=spf1 -all', 'v=spf1 include:otro.com -all']);
  assert.equal(r.multiple, true);
  assert.equal(r.valido, false);
  assert.ok(r.errores.some((e) => /Solo puede haber uno/.test(e)));
});

test('SPF: "+all" autoriza a todo el mundo', () => {
  const r = spf.parsear(['v=spf1 +all']);
  assert.equal(r.calificacionAll, 'pass');
  assert.ok(r.errores.some((e) => /CUALQUIER servidor/.test(e)));
});

test('SPF: "?all" avisa pero no invalida', () => {
  const r = spf.parsear(['v=spf1 ?all']);
  assert.equal(r.valido, true);
  assert.ok(r.avisos.some((a) => /neutral/.test(a)));
});

test('SPF: contar las consultas y pasarse del límite es un error', () => {
  const diez = `v=spf1 ${Array.from({ length: 10 }, (_, i) => `include:s${i}.ejemplo.com`).join(' ')} -all`;
  const once = `v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:s${i}.ejemplo.com`).join(' ')} -all`;

  const justo = spf.parsear([diez]);
  assert.equal(justo.lookups, 10);
  assert.equal(justo.excedeLimite, false);
  assert.ok(justo.avisos.some((a) => /justo en el límite/.test(a)));

  const excedido = spf.parsear([once]);
  assert.equal(excedido.lookups, 11);
  assert.equal(excedido.excedeLimite, true);
  assert.equal(excedido.valido, false);
  assert.ok(excedido.errores.some((e) => /suma 11 consultas/.test(e)));
});

test('SPF: avisa de que no hay política por defecto', () => {
  const r = spf.parsear(['v=spf1 include:_spf.ejemplo.com']);
  assert.ok(r.avisos.some((a) => /No hay un "all"/.test(a)));
});

test('SPF: un "redirect" sirve de política por defecto', () => {
  const r = spf.parsear(['v=spf1 redirect=_spf.ejemplo.com']);
  assert.equal(r.redirect, '_spf.ejemplo.com');
  assert.equal(r.lookups, 1);
  assert.ok(!r.avisos.some((a) => /No hay un "all"/.test(a)));
});

test('SPF: lo que va después de "all" nunca se evalúa', () => {
  const r = spf.parsear(['v=spf1 -all include:tarde.ejemplo.com']);
  assert.ok(r.avisos.some((a) => /después de "all"/.test(a)));
});

test('SPF: el mecanismo "ptr" está desaconsejado', () => {
  const r = spf.parsear(['v=spf1 ptr -all']);
  assert.ok(r.avisos.some((a) => /"ptr"/.test(a)));
});

test('SPF: un mecanismo inventado es un error de sintaxis', () => {
  const r = spf.parsear(['v=spf1 inventado:algo -all']);
  assert.equal(r.valido, false);
  assert.ok(r.errores.some((e) => /no es un mecanismo/.test(e)));
});

/* ------------------------------------------------------------------ *
 * DMARC
 * ------------------------------------------------------------------ */

test('DMARC: un registro con política fuerte es válido', () => {
  const r = dmarc.parsear(['v=DMARC1; p=reject; rua=mailto:dmarc@ejemplo.com']);
  assert.equal(r.presente, true);
  assert.equal(r.valido, true);
  assert.equal(r.politica, 'reject');
  assert.equal(r.pct, 100);
  assert.deepEqual(r.rua, ['dmarc@ejemplo.com']);
  assert.deepEqual(r.avisos, []);
});

test('DMARC: "p=none" solo observa', () => {
  const r = dmarc.parsear(['v=DMARC1; p=none']);
  assert.equal(r.valido, true);
  assert.ok(r.avisos.some((a) => /solo observa/.test(a)));
});

test('DMARC: la "p" es obligatoria', () => {
  const r = dmarc.parsear(['v=DMARC1; rua=mailto:a@ejemplo.com']);
  assert.equal(r.valido, false);
  assert.ok(r.errores.some((e) => /Falta la etiqueta "p="/.test(e)));
});

test('DMARC: una política inventada no vale', () => {
  const r = dmarc.parsear(['v=DMARC1; p=bloquear']);
  assert.equal(r.valido, false);
  assert.ok(r.errores.some((e) => /no es válida/.test(e)));
});

test('DMARC: varios registros invalidan la política', () => {
  const r = dmarc.parsear(['v=DMARC1; p=reject', 'v=DMARC1; p=none']);
  assert.equal(r.multiple, true);
  assert.equal(r.valido, false);
});

test('DMARC: un "pct" fuera de rango es error y una etiqueta rara es aviso', () => {
  const fuera = dmarc.parsear(['v=DMARC1; p=reject; pct=150']);
  assert.ok(fuera.errores.some((e) => /no es un porcentaje/.test(e)));

  const rara = dmarc.parsear(['v=DMARC1; p=reject; rua=mailto:a@ejemplo.com; foo=bar']);
  assert.ok(rara.avisos.some((a) => /"foo" no es un campo/.test(a)));
});

test('DMARC: un TXT en _dmarc que no es DMARC se explica', () => {
  const r = dmarc.parsear(['v=spf1 -all']);
  assert.equal(r.presente, false);
  assert.ok(r.avisos.some((a) => /no empieza por "v=DMARC1"/.test(a)));
});

/* ------------------------------------------------------------------ *
 * DKIM
 * ------------------------------------------------------------------ */

test('DKIM: una clave de 2048 bits es válida', () => {
  const r = dkim.parsear([`v=DKIM1; k=rsa; p=${claveRsa(2048)}`], { selector: 'default', dominio: 'ejemplo.com' });
  assert.equal(r.encontrado, true);
  assert.equal(r.valido, true);
  assert.equal(r.bits, 2048);
  assert.equal(r.tipoClave, 'rsa');
  assert.deepEqual(r.avisos, []);
});

test('DKIM: una clave de 1024 bits funciona pero se avisa', () => {
  const r = dkim.parsear([`v=DKIM1; k=rsa; p=${claveRsa(1024)}`], { selector: 's1', dominio: 'ejemplo.com' });
  assert.equal(r.valido, true);
  assert.equal(r.bits, 1024);
  assert.ok(r.avisos.some((a) => /1024 bits/.test(a)));
});

test('DKIM: "p=" vacía significa clave revocada', () => {
  const r = dkim.parsear(['v=DKIM1; k=rsa; p='], { selector: 'default', dominio: 'ejemplo.com' });
  assert.equal(r.encontrado, true);
  assert.equal(r.revocada, true);
  assert.equal(r.valido, false);
  assert.ok(r.errores.some((e) => /REVOCADA|VACÍA/.test(e)));
});

test('DKIM: sin "v=DKIM1" pero con "p=" se acepta igual', () => {
  const r = dkim.parsear([`k=rsa; p=${claveRsa(2048)}`], { selector: 'default', dominio: 'ejemplo.com' });
  assert.equal(r.encontrado, true);
  assert.equal(r.bits, 2048);
});

test('DKIM: una clave que no se puede descodificar es un error', () => {
  const r = dkim.parsear(['v=DKIM1; k=rsa; p=esto-no-es-base64-valido!!!'], { selector: 'default', dominio: 'ejemplo.com' });
  assert.equal(r.encontrado, true);
  assert.equal(r.valido, false);
  assert.ok(r.errores.some((e) => /no se puede descodificar/.test(e)));
});

test('DKIM: sin ninguna clave no se marca como encontrado', () => {
  const r = dkim.parsear([], { selector: 'default', dominio: 'ejemplo.com' });
  assert.equal(r.encontrado, false);
  assert.equal(r.valor, null);
});

/* ------------------------------------------------------------------ *
 * Transporte
 * ------------------------------------------------------------------ */

test('transporte: MTA-STS, TLS-RPT y BIMI bien publicados', () => {
  const r = transporte.parsear({
    mtaSts: ['v=STSv1; id=20260101'],
    tlsRpt: ['v=TLSRPTv1; rua=mailto:informes@ejemplo.com'],
    bimi: ['v=BIMI1; l=https://ejemplo.com/logo.svg; a=https://ejemplo.com/vmc.pem']
  });
  assert.equal(r.mtaSts.presente, true);
  assert.equal(r.mtaSts.id, '20260101');
  assert.equal(r.mtaSts.valido, true);
  assert.deepEqual(r.tlsRpt.rua, ['informes@ejemplo.com']);
  assert.equal(r.bimi.valido, true);
});

test('transporte: MTA-STS sin "id" es un error', () => {
  const r = transporte.parsear({ mtaSts: ['v=STSv1'] });
  assert.equal(r.mtaSts.valido, false);
  assert.ok(r.mtaSts.errores.some((e) => /"id="/.test(e)));
});

test('transporte: TLS-RPT sin "rua" no sirve de nada', () => {
  const r = transporte.parsear({ tlsRpt: ['v=TLSRPTv1'] });
  assert.equal(r.tlsRpt.presente, true);
  assert.equal(r.tlsRpt.valido, false);
  assert.ok(r.tlsRpt.avisos.some((a) => /"rua="/.test(a)));
});

test('transporte: BIMI con logo http avisa y sin VMC también', () => {
  const r = transporte.parsear({ bimi: ['v=BIMI1; l=http://ejemplo.com/logo.svg'] });
  assert.ok(r.bimi.errores.some((e) => /https:\/\//.test(e)));
  assert.ok(r.bimi.avisos.some((a) => /"a="/.test(a)));
});

/* ------------------------------------------------------------------ *
 * Mensaje
 * ------------------------------------------------------------------ */

test('mensaje: un .eml completo se descompone en piezas', () => {
  const m = mensaje.parsear(leerFixture('correo-sano.eml'));

  assert.equal(m.fromDominio, 'ejemplo.com');
  assert.equal(m.ipEmisor, '93.184.216.34');
  assert.equal(m.spf.resultado, 'pass');
  assert.equal(m.spf.fuente, 'Authentication-Results');
  assert.equal(m.dkim.length, 1);
  assert.equal(m.dkim[0].resultado, 'pass');
  assert.equal(m.dkim[0].dominio, 'ejemplo.com');
  assert.equal(m.dmarc.resultado, 'pass');
  assert.equal(m.dkimFirmas.length, 1);
  assert.equal(m.dkimFirmas[0].selector, 'default');
  assert.equal(m.listUnsubscribePost, 'List-Unsubscribe=One-Click');
  assert.match(m.texto, /pedido numero 42/);
  assert.match(m.html, /<p>/);
  assert.equal(m.adjuntos, 0);
  assert.equal(m.recibidas.length, 1);
});

test('mensaje: las cabeceras plegadas se leen como una sola', () => {
  const m = mensaje.parsear(leerFixture('correo-sano.eml'));
  // El Authentication-Results viene partido en tres líneas con tabulador.
  assert.match(m.auth.spf.resultado, /pass/);
  assert.match(m.dkim[0].dominio, /ejemplo\.com/);
});

test('mensaje: un HTML sin autenticación no cuela datos', () => {
  const m = mensaje.parsear(leerFixture('correo-spam.eml'));
  assert.equal(m.fromDominio, 'oferta.com');
  assert.equal(m.ipEmisor, '10.0.0.5');
  assert.equal(m.spf, null);
  assert.deepEqual(m.dkim, []);
  assert.equal(m.dmarc, null);
  assert.equal(m.dkimFirmas.length, 0);
  assert.match(m.html, /bit\.ly/);
});

test('mensaje: sin cabeceras avisa, no revienta', () => {
  const m = mensaje.parsear('solo texto suelto sin cabeceras');
  assert.deepEqual(m.cabeceras, {});
  assert.equal(m.from, null);
});

test('mensaje: el quoted-printable se descodifica', () => {
  const eml = [
    'From: a@ejemplo.com',
    'Content-Type: text/plain; charset="utf-8"',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'Hola=2C mundo=20entero'
  ].join('\n');
  const m = mensaje.parsear(eml);
  assert.equal(m.texto, 'Hola, mundo entero');
});

/* ------------------------------------------------------------------ *
 * Contenido
 * ------------------------------------------------------------------ */

test('contenido: un mensaje sobrio no dispara avisos', () => {
  const m = mensaje.parsear(leerFixture('correo-sano.eml'));
  const r = contenido.evaluar(m);
  const malos = r.checks.filter((c) => c.estado !== 'ok');
  assert.deepEqual(malos, [], `no debería haber avisos: ${malos.map((c) => c.id).join(', ')}`);
  assert.equal(r.max, 2.0);
});

test('contenido: un correo tramposo acumula señales', () => {
  const m = mensaje.parsear(leerFixture('correo-spam.eml'));
  const r = contenido.evaluar(m);
  assert.equal(check(r, 'acortadores').estado, 'error');
  assert.equal(check(r, 'enlaces-ip').estado, 'warn');
  assert.equal(check(r, 'palabras-spam').estado, 'warn');
  assert.equal(check(r, 'asunto-gritado').estado, 'warn');
  assert.equal(check(r, 'exclamaciones').estado, 'warn');
  assert.equal(check(r, 'exceso-enlaces').estado, 'warn');
  assert.equal(check(r, 'sin-alternativa-texto').estado, 'warn', 'HTML sin alternativa de texto');
});

test('contenido: un cuerpo sin una sola palabra es un error', () => {
  const m = mensaje.parsear('From: a@ejemplo.com\nSubject: x\nContent-Type: text/plain\n\n... !!! ###');
  const r = contenido.evaluar(m);
  assert.equal(check(r, 'contenido-vacio').estado, 'error');
});

test('contenido: sin texto ni html se marca como no-evaluable', () => {
  const m = mensaje.parsear('From: a@ejemplo.com\nSubject: test\n\n');
  const r = contenido.evaluar(m);
  assert.equal(check(r, 'contenido-vacio').estado, 'no-evaluable');
  assert.ok(check(r, 'contenido-vacio').detalle.includes('parseo'));
});

/* ------------------------------------------------------------------ *
 * Puntuación
 * ------------------------------------------------------------------ */

test('puntuación: un "ok" suma entero y un "warn" la mitad', () => {
  const r = puntuacion.evaluar([
    puntuacion.check({ id: 'a', categoria: 'x', titulo: 'A', peso: 1, estado: 'ok' }),
    puntuacion.check({ id: 'b', categoria: 'x', titulo: 'B', peso: 1, estado: 'warn' }),
    puntuacion.check({ id: 'c', categoria: 'x', titulo: 'C', peso: 2, estado: 'error' })
  ]);
  assert.equal(r.max, 4);
  assert.equal(r.obtenidos, 1.5);
  assert.equal(r.nota, 3.8, '1.5/4 * 10 = 3.75, redondeado a 3.8');
  assert.equal(r.tone, 'bad');
  assert.equal(r.fallos.length, 2, 'el warn y el error cuentan como fallos');
});

test('puntuación: sin comprobaciones la nota es cero, no NaN', () => {
  const r = puntuacion.evaluar([]);
  assert.equal(r.nota, 0);
  assert.equal(r.max, 0);
});

test('puntuación: los umbrales marcan el tono', () => {
  assert.equal(puntuacion.evaluar([{ peso: 1, estado: 'ok' }]).tone, 'ok');
  assert.equal(puntuacion.evaluar([{ peso: 3, estado: 'ok' }, { peso: 3, estado: 'warn' }]).tone, 'warn');
  assert.equal(puntuacion.evaluar([{ peso: 1, estado: 'error' }]).tone, 'bad');
});

test('puntuación: un estado desconocido se trata como advertencia', () => {
  const c = puntuacion.check({ id: 'a', categoria: 'x', titulo: 'A', peso: 1, estado: 'neutral' });
  assert.equal(c.estado, 'warn');
});

test('puntuación: formatea la nota con un decimal', () => {
  assert.equal(puntuacion.formatear(9), '9.0 / 10');
  assert.equal(puntuacion.formatear(8.55), '8.6 / 10');
});

test('puntuación: estado "no-evaluable" no cuenta en max ni en fallos', () => {
  const r = puntuacion.evaluar([
    puntuacion.check({ id: 'a', categoria: 'x', titulo: 'A', peso: 1, estado: 'ok' }),
    puntuacion.check({ id: 'b', categoria: 'x', titulo: 'B', peso: 1, estado: 'no-evaluable' }),
    puntuacion.check({ id: 'c', categoria: 'x', titulo: 'C', peso: 1, estado: 'error' })
  ]);
  assert.equal(r.max, 2, 'solo ok y error cuentan en max');
  assert.equal(r.obtenidos, 1, 'solo ok suma puntos');
  assert.equal(r.nota, 5.0, '1/2 * 10 = 5.0');
  assert.equal(r.fallos.length, 1, 'no-evaluable no cuenta como fallo');
});

/* ------------------------------------------------------------------ *
 * Mensaje: base64
 * ------------------------------------------------------------------ */

test('mensaje: el body base64 se decodifica', () => {
  const base64 = Buffer.from('Hola mundo base64', 'utf8').toString('base64');
  const eml = [
    'From: a@ejemplo.com',
    'Subject: test',
    'Content-Type: text/plain; charset="utf-8"',
    'Content-Transfer-Encoding: base64',
    '',
    base64
  ].join('\n');
  const m = mensaje.parsear(eml);
  assert.equal(m.texto, 'Hola mundo base64');
});

test('mensaje: base64 roto cae a texto plano sin romper', () => {
  const eml = [
    'From: a@ejemplo.com',
    'Subject: test',
    'Content-Type: text/plain; charset="utf-8"',
    'Content-Transfer-Encoding: base64',
    '',
    'esto no es base64 valido!!!'
  ].join('\n');
  const m = mensaje.parsear(eml);
  // Al fallar la decodificación, devuelve el texto original
  assert.ok(m.texto.includes('esto no es base64'));
});
