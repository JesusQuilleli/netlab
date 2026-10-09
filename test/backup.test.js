'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const { Backup, siguienteDisparo, nombreDeArchivo } = require('../src/server/backup');

/** Crea una base de mentira con una tabla y una fila, y devuelve { ruta, directorio }. */
function crearBase() {
  const directorio = fs.mkdtempSync(path.join(os.tmpdir(), 'netlab-backup-'));
  const ruta = path.join(directorio, 'netlab.db');
  const db = new DatabaseSync(ruta);
  db.exec('CREATE TABLE t (a INTEGER)');
  db.prepare('INSERT INTO t VALUES (?)').run(42);
  db.close();
  return { ruta, directorio };
}

test('el nombre de archivo es ordenable y legible', () => {
  // Constructor con componentes locales a proposito: el nombre usa la fecha
  // local del servidor, no la UTC.
  const f = nombreDeArchivo(new Date(2026, 9, 9, 3, 4, 5));
  assert.match(f, /^netlab-\d{8}-\d{6}\.sqlite$/);
  assert.match(f, /20261009-030405/);
});

test('siguienteDisparo cae en la hora pedida, hoy o manana', () => {
  // A las 01:00 la hora de las 03:00 es hoy (misma fecha local).
  const hoy = siguienteDisparo(new Date('2026-10-09T01:00:00'), 3);
  assert.equal(hoy.getDate(), 9);
  assert.equal(hoy.getHours(), 3);
  assert.equal(hoy.getMinutes(), 0);

  // A las 04:00 ya paso: cae manana, no dentro de 23 horas a las 03 de pasado.
  const manana = siguienteDisparo(new Date('2026-10-09T04:00:00'), 3);
  assert.equal(manana.getDate(), 10);
  assert.equal(manana.getHours(), 3);

  // Una hora imposible se acota, no revienta.
  assert.equal(siguienteDisparo(new Date('2026-10-09T00:30:00'), 99).getHours(), 23);
});

test('hacer() produce una copia que se abre y conserva los datos', () => {
  const { ruta, directorio } = crearBase();
  const b = new Backup({ ruta, directorio });

  const copia = b.hacer();

  assert.ok(fs.existsSync(copia.ruta), 'el fichero existe');
  assert.equal(copia.nombre, path.basename(copia.ruta));

  // La copia es una base de verdad, no texto.
  const leida = new DatabaseSync(copia.ruta, { readOnly: true });
  const n = leida.prepare('SELECT COUNT(*) AS n FROM t').get().n;
  leida.close();
  assert.equal(n, 1, 'los datos sobreviven a la copia');

  fs.rmSync(directorio, { recursive: true, force: true });
});

test('hacer() dos veces seguidas no revienta por el nombre repetido', () => {
  const { ruta, directorio } = crearBase();
  const b = new Backup({ ruta, directorio });

  const primera = b.hacer();
  // Dos copias en el mismo segundo podrian coincidir en nombre: no es un error,
  // es una copia que ya esta hecha.
  const segunda = b.hacer();
  assert.ok(segunda.ruta, 'devuelve algo util');
  assert.equal(b.listar().length, 1, 'solo queda la copia');

  fs.rmSync(directorio, { recursive: true, force: true });
});

test('la retencion borra las copias mas viejas', () => {
  const { ruta, directorio } = crearBase();
  const b = new Backup({ ruta, directorio, retencion: 2 });

  // Tres copias antiguas de mentira. Empty files bastan: listar no las abre.
  fs.writeFileSync(path.join(directorio, 'netlab-2020-01-01.sqlite'), '');
  fs.writeFileSync(path.join(directorio, 'netlab-2020-01-02.sqlite'), '');
  fs.writeFileSync(path.join(directorio, 'netlab-2020-01-03.sqlite'), '');

  b.hacer();

  const quedan = b.listar();
  assert.equal(quedan.length, 2, 'se conservan solo las dos mas recientes');
  assert.equal(quedan[0].nombre.startsWith('netlab-202'), true, 'la copia de hoy es la mas reciente');
  assert.equal(quedan.some((x) => x.nombre.includes('2020-01-03')), true, 'se guarda la mas nueva de las falsas');

  fs.rmSync(directorio, { recursive: true, force: true });
});

test('restaurar de una copia deja la base igual', () => {
  const { ruta, directorio } = crearBase();
  const b = new Backup({ ruta, directorio });
  const copia = b.hacer();

  // Se "pierde" la base y se levanta desde la copia, que es el caso de uso.
  fs.unlinkSync(ruta);
  fs.copyFileSync(copia.ruta, ruta);

  const db = new DatabaseSync(ruta, { readOnly: true });
  const n = db.prepare('SELECT COUNT(*) AS n FROM t').get().n;
  db.close();
  assert.equal(n, 1, 'la restauracion devuelve los datos');

  fs.rmSync(directorio, { recursive: true, force: true });
});

test('sin base no hay nada que respaldar, y se dice que escribir', async () => {
  const directorio = fs.mkdtempSync(path.join(os.tmpdir(), 'netlab-backup-'));
  const b = new Backup({ ruta: path.join(directorio, 'no-existe.db'), directorio });

  assert.throws(() => b.hacer(), (e) => {
    assert.equal(e.code, 'FICHERO_NO_ENCONTRADO');
    assert.ok(e.remediation);
    return true;
  });

  fs.rmSync(directorio, { recursive: true, force: true });
});

test('programar() hace una copia al arrancar y se puede detener', () => {
  const { ruta, directorio } = crearBase();
  const b = new Backup({ ruta, directorio });
  const avisos = [];
  b.avisar = (e) => avisos.push(e);

  b.programar();
  assert.equal(b.listar().length, 1, 'la copia de arranque queda hecha');
  b.detener();

  // Sin base no hay nada que respaldar: no es un fallo, no se avisa y el
  // temporizador se arma igual (el servidor nuevo no escupe un ERROR al arrancar).
  const b2 = new Backup({ ruta: path.join(directorio, 'sin-base.db'), directorio, hora: 3 });
  b2.avisar = (e) => avisos.push(e);
  b2.programar();
  assert.equal(avisos.length, 0, 'una base que aun no existe no es un fallo');
  b2.detener();

  fs.rmSync(directorio, { recursive: true, force: true });
});

test('listar() ordena de mas nueva a mas vieja', () => {
  const { ruta, directorio } = crearBase();
  fs.writeFileSync(path.join(directorio, 'netlab-00000000-000000.sqlite'), ' ');

  const b = new Backup({ ruta, directorio });
  b.hacer();

  const orden = b.listar().map((x) => x.nombre);
  assert.ok(orden[0].startsWith('netlab-202'), 'la copia real es la primera');
  assert.ok(orden[orden.length - 1].startsWith('netlab-00000000'), 'la falsa antigua, la ultima');

  fs.rmSync(directorio, { recursive: true, force: true });
});