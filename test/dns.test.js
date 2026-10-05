'use strict';

/**
 * test/dns.test.js — Pruebas del módulo DNS del núcleo.
 *
 * Lo que se prueba aquí es la maquinaria: el semáforo de concurrencia, el
 * envoltorio de tiempo y el de reintentos. Ninguna de estas pruebas sale a la
 * red, salvo las marcadas como `saltarSinRed`, que se desactivan solas si no
 * hay salida para no hacer la suite inestable en un portátil sin WiFi.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');

const dns = require('../src/core/net/dns');

function esperar(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function haySalida() {
  try {
    await dns.consultar('ejemplo.com', 'A', { timeout: 2000, reintentos: 0 });
    return true;
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ *
 * Semáforo de concurrencia
 * ------------------------------------------------------------------ */

test('limitarConcurrencia nunca lanza mas de las permitidas', async () => {
  // Este es el test que faltaba y por el que el bug de `activos` sobrevivió
  // meses: `consultarLote` es el único que usa el semáforo y ningún test lo
  // llamaba con carga suficiente como para activar la rama del `finally`.
  const correr = dns.limitarConcurrencia(3);
  let vivas = 0;
  let maximoVivas = 0;

  const tareas = Array.from({ length: 25 }, (_, i) =>
    correr(async () => {
      vivas++;
      maximoVivas = Math.max(maximoVivas, vivas);
      await esperar(15);
      vivas--;
      return i;
    })
  );

  const salida = await Promise.all(tareas);

  assert.deepEqual(salida, Array.from({ length: 25 }, (_, i) => i), 'el orden y los valores se respetan');
  assert.equal(vivas, 0, 'no queda ninguna tarea en vuelo');
  assert.ok(maximoVivas <= 3, `se llegaron a lanzar ${maximoVivas} a la vez y el limite era 3`);
  assert.ok(maximoVivas > 1, 'el limite debe dejar pasar varias a la vez, si no no sirve de nada');
});

test('limitarConcurrencia entrega todos los resultados', async () => {
  for (const limite of [1, 2, 7]) {
    const correr = dns.limitarConcurrencia(limite);
    const salida = await Promise.all(Array.from({ length: 12 }, (_, i) => correr(async () => i * 2)));
    assert.deepEqual(salida, Array.from({ length: 12 }, (_, i) => i * 2), `con limite ${limite}`);
  }
});

test('un fallo en una tarea no tumba a las de al lado', async () => {
  const correr = dns.limitarConcurrencia(2);
  const resultados = await Promise.allSettled([
    correr(async () => { throw new Error('primera revienta'); }),
    correr(async () => 'segunda sobrevive'),
    correr(async () => 'tercera sobrevive')
  ]);

  assert.equal(resultados[0].status, 'rejected');
  assert.equal(resultados[0].reason.message, 'primera revienta');
  assert.equal(resultados[1].value, 'segunda sobrevive');
  assert.equal(resultados[2].value, 'tercera sobrevive');
});

test('el semáforo sigue admitting tareas tras un fallo', async () => {
  // Si el `finally` soltara la plaza antes de restar, el contador se quedaría
  // colgado y a partir de la enésima tarea nadie volvería a ejecutarse nunca.
  const correr = dns.limitarConcurrencia(1);
  await assert.rejects(correr(async () => { throw new Error('boom'); }));
  assert.equal(await correr(async () => 'sigue vivo'), 'sigue vivo');
});

test('un limite de uno serializa en orden', async () => {
  const correr = dns.limitarConcurrencia(1);
  const orden = [];
  await Promise.all(
    [300, 10, 100, 1].map((ms, i) =>
      correr(async () => {
        await esperar(ms);
        orden.push(i);
      })
    )
  );
  assert.deepEqual(orden, [0, 1, 2, 3], 'con una sola plaza se respeta el orden de entrada');
});

/* ------------------------------------------------------------------ *
 * consultarLote
 * ------------------------------------------------------------------ */

test('consultarLote devuelve un resultado por consulta, en orden', async (t) => {
  if (!(await haySalida())) return t.skip('sin salida a Internet');
  const consultas = [
    { nombre: 'ejemplo.com', tipo: 'A' },
    { nombre: 'este-no-existe-jamas-abc.com', tipo: 'A' },
    { nombre: 'ejemplo.com', tipo: 'AAAA' }
  ];

  const lote = await dns.consultarLote(consultas, { concurrencia: 3, dns: { timeout: 3000, reintentos: 0 } });

  assert.equal(lote.length, consultas.length, 'mismo numero de entradas que de salidas');
  lote.forEach((r, i) => {
    assert.equal(r.nombre, consultas[i].nombre, 'cada fila conserva su consulta');
    assert.equal(r.tipo, consultas[i].tipo);
    assert.equal(typeof r.ok, 'boolean');
  });
  assert.ok(lote.some((r) => r.ok), 'al menos una deberia resolver');
  assert.ok(lote.some((r) => !r.ok), 'y al menos una deberia fallar');
});

test('consultarLote con lista vacia no rompe', async () => {
  assert.deepEqual(await dns.consultarLote([], { concurrencia: 4, dns: { timeout: 500, reintentos: 0 } }), []);
});

/* ------------------------------------------------------------------ *
 * Envoltorios de error y tiempo
 * ------------------------------------------------------------------ */

test('conTimeout corta la espera y da un error reconocible', async () => {
  await assert.rejects(
    dns.conTimeout(new Promise(() => {}), 120, 'la consulta'),
    (e) => {
      assert.equal(e.code, 'TIMEOUT');
      assert.match(e.message, /la consulta/);
      assert.ok(e.remediation, 'debe decir que hacer');
      return true;
    }
  );
});

test('conTimeout deja pasar lo que llega a tiempo', async () => {
  assert.equal(await dns.conTimeout(esperar(10).then(() => 'a tiempo'), 500, 'x'), 'a tiempo');
});

test('conTimeout limpia el temporizador si la promesa gana', async () => {
  // Si el `clearTimeout` desapareciera, cada consulta dejaría un temporizador
  // vivo y el proceso no terminaría de salir solo.
  assert.equal(await dns.conTimeout(Promise.resolve('ya'), 60_000, 'x'), 'ya');
});

test('conReintento reintenta y acaba dando el error', async () => {
  let intentos = 0;
  await assert.rejects(
    dns.conReintento(
      async () => { intentos++; throw new Error('siempre falla'); },
      { reintentos: 3, esperaInicial: 5 }
    ),
    /siempre falla/
  );
  assert.equal(intentos, 4, 'el intento inicial mas tres reintentos');
});

test('conReintento se detiene en cuanto funciona', async () => {
  let intentos = 0;
  const salida = await dns.conReintento(
    async () => {
      intentos++;
      if (intentos < 3) throw new Error('aun no');
      return 'va bien';
    },
    { reintentos: 5, esperaInicial: 5 }
  );
  assert.equal(salida, 'va bien');
  assert.equal(intentos, 3, 'no debe seguir reintentando despues del exito');
});

test('conReintento no insiste con un NXDOMAIN', async () => {
  // NXDOMAIN es una respuesta definitiva: el nombre no existe. Reintentar tres
  // veces solo retrasa el informe, y ademas un nombre inexistente con un TTL de
  // cache corto puede dar NXDOMAIN y luego A, que es justo lo que confunde.
  let intentos = 0;
  await assert.rejects(
    dns.conReintento(
      async () => { intentos++; throw Object.assign(new Error('no existe'), { code: 'ENOTFOUND' }); },
      { reintentos: 3, esperaInicial: 5 }
    ),
    /no existe/
  );
  assert.equal(intentos, 1, 'un solo intento: la respuesta ya es definitiva');
});

/* ------------------------------------------------------------------ *
 * Codigos del resolvedor
 * ------------------------------------------------------------------ */

test('el error crudo del resolvedor sobrevive a los reintentos', async () => {
  // Si se pierde, NXDOMAIN y SERVFAIL se vuelven el mismo error generico y la
  // herramienta acaba diciendo "no existe" de nombres que si existen.
  const original = Object.assign(new Error('queryA ENOTFOUND ejemplo.com'), { code: 'ENOTFOUND' });
  let capturado = null;
  try {
    await dns.conReintento(async () => { throw original; }, { reintentos: 2, espera: 5 });
  } catch (e) {
    capturado = e;
  }
  assert.equal(capturado.code, 'ENOTFOUND', 'el codigo ENOTFOUND tiene que conservarse');
});

/* ------------------------------------------------------------------ *
 * Contra la red real (opcionales)
 * ------------------------------------------------------------------ */

test('una consulta real trae TTL y valores', { skip: false }, async (t) => {
  if (!(await haySalida())) return t.skip('sin salida a Internet');
  const r = await dns.consultar('ejemplo.com', 'A', { timeout: 5000, reintentos: 1 });
  assert.equal(r.ok, true, `deberia resolver: ${r.error || ''}`);
  assert.ok(r.valores.length > 0);
  assert.ok(Array.isArray(r.valores) && net.isIP(r.valores[0]) === 4, 'los valores de A son IPv4');
  assert.ok(Number.isInteger(r.ttl) && r.ttl > 0, `TTLUtil: ${r.ttl}`);
});

test('un nombre inexistente da ENOTFOUND, no un error generico', { skip: false }, async (t) => {
  if (!(await haySalida())) return t.skip('sin salida a Internet');
  const r = await dns.consultar('este-no-existe-jamas-abcxyz-987.com', 'A', { timeout: 5000, reintentos: 0 });
  assert.equal(r.ok, false);
  assert.equal(r.codigoDns, 'ENOTFOUND');
});

test('solo A y AAAA traen TTL; el resto llega sin el', { skip: false }, async (t) => {
  // Dato medido con la API de Node: resolveMx, resolveNs y resolveTxt no
  // exponen el TTL. Inventar uno o poner un 0 seria mentir en el informe.
  if (!(await haySalida())) return t.skip('sin salida a Internet');
  const conTtl = ['A', 'AAAA'];
  const sinTtl = ['MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA'];

  for (const tipo of conTtl) {
    const r = await dns.consultar('ejemplo.com', tipo, { timeout: 5000, reintentos: 1 });
    if (r.ok) assert.ok(r.ttl !== null && r.ttl !== undefined, `${tipo} deberia traer TTL`);
  }
  for (const tipo of sinTtl) {
    const r = await dns.consultar('ejemplo.com', tipo, { timeout: 5000, reintentos: 1 });
    assert.equal(r.ttl, null, `${tipo} no debe inventar un TTL`);
  }
});
