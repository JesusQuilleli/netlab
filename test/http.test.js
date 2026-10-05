'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { getJSON, conQuery } = require('../src/core/net/http');
const { NetlabError, CODES } = require('../src/core/errors');

/** Respuesta falsa con lo justo para que getJSON la pueda usar. */
function respuesta({ status = 200, cuerpo = {}, headers = {} } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers[String(k).toLowerCase()] },
    text: async () => (typeof cuerpo === 'string' ? cuerpo : JSON.stringify(cuerpo))
  };
}

test('conQuery ignora los parametros vacios', () => {
  const url = conQuery('https://ejemplo.com/check', { a: 1, b: undefined, c: null, d: '', e: 'x' });
  assert.equal(url, 'https://ejemplo.com/check?a=1&e=x');
});

test('devuelve el cuerpo parseado cuando todo va bien', async () => {
  let vistas;
  const datos = await getJSON({
    url: 'https://ejemplo.com/check',
    query: { ip: '203.0.113.1' },
    fetchImpl: async (url, opts) => {
      vistas = { url, opts };
      return respuesta({ cuerpo: { data: { ok: 1 } } });
    }
  });

  assert.deepEqual(datos, { data: { ok: 1 } });
  assert.equal(vistas.url, 'https://ejemplo.com/check?ip=203.0.113.1');
  assert.equal(vistas.opts.method, 'GET');
});

test('un 401 es un fallo de credencial y no se reintenta', async () => {
  // Reintentar un 401 no puede mejorar nada: o la clave esta mal o el recurso
  // no existe. Si reintentara, quemaria cuota para acabar en lo mismo.
  let llamadas = 0;
  await assert.rejects(
    getJSON({
      url: 'https://ejemplo.com/check',
      intentos: 3,
      esperaBaseMs: 1,
      fetchImpl: async () => {
        llamadas++;
        return respuesta({ status: 401, cuerpo: { errors: [{ detail: 'Invalid key' }] } });
      }
    }),
    (e) => {
      assert.ok(e instanceof NetlabError);
      assert.equal(e.code, CODES.CREDENCIAL_INVALIDA);
      assert.match(e.message, /401/);
      assert.match(e.details.cuerpo, /Invalid key/);
      return true;
    }
  );
  assert.equal(llamadas, 1, 'no debe reintentar un 401');
});

test('un 400 no se reintenta', async () => {
  let llamadas = 0;
  await assert.rejects(
    getJSON({
      url: 'https://ejemplo.com/check',
      intentos: 3,
      esperaBaseMs: 1,
      fetchImpl: async () => {
        llamadas++;
        return respuesta({ status: 400, cuerpo: { errors: [{ detail: 'Required parameter' }] } });
      }
    }),
    (e) => e.code === CODES.PARAM_INVALIDO
  );
  assert.equal(llamadas, 1);
});

test('un 429 si se reintenta, porque es el unico 4xx que se resuelve solo', async () => {
  let llamadas = 0;
  await assert.rejects(
    getJSON({
      url: 'https://ejemplo.com/check',
      intentos: 3,
      esperaBaseMs: 1,
      fetchImpl: async () => {
        llamadas++;
        return respuesta({ status: 429, cuerpo: { errors: [{ detail: 'quota' }] } });
      }
    }),
    (e) => e.code === CODES.API_CUOTA
  );
  assert.equal(llamadas, 3, 'debe agotar los tres intentos');
});

test('un 429 que se responde bien a la segunda es un exito', async () => {
  // El caso que importa: esperar y reintentar evita un fallo que no era real.
  let llamadas = 0;
  const datos = await getJSON({
    url: 'https://ejemplo.com/check',
    intentos: 3,
    esperaBaseMs: 1,
    fetchImpl: async () => {
      llamadas++;
      return llamadas === 1 ? respuesta({ status: 429 }) : respuesta({ cuerpo: { data: 'bien' } });
    }
  });
  assert.deepEqual(datos, { data: 'bien' });
  assert.equal(llamadas, 2);
});

test('un 5xx si se reintenta', async () => {
  let llamadas = 0;
  const datos = await getJSON({
    url: 'https://ejemplo.com/check',
    intentos: 3,
    esperaBaseMs: 1,
    fetchImpl: async () => {
      llamadas++;
      return llamadas < 3 ? respuesta({ status: 503 }) : respuesta({ cuerpo: { ok: true } });
    }
  });
  assert.deepEqual(datos, { ok: true });
  assert.equal(llamadas, 3);
});

test('un corte de red se reintenta y al final se informa como red', async () => {
  let llamadas = 0;
  await assert.rejects(
    getJSON({
      url: 'https://ejemplo.com/check',
      intentos: 2,
      esperaBaseMs: 1,
      fetchImpl: async () => {
        llamadas++;
        throw new Error('socket hang up');
      }
    }),
    (e) => {
      assert.equal(e.code, CODES.RED);
      assert.match(e.message, /socket hang up/);
      return true;
    }
  );
  assert.equal(llamadas, 2);
});

test('un tiempo agotado se distingue del corte de red', async () => {
  // "No respondio a tiempo" y "no se pudo contactar" llevan a acciones distintas:
  // uno es lentitud o filtro, el otro es un problema de conexion de esta maquina.
  const abortado = new Error('aborted');
  abortado.name = 'AbortError';

  await assert.rejects(
    getJSON({
      url: 'https://ejemplo.com/check',
      intentos: 1,
      fetchImpl: async () => {
        throw abortado;
      }
    }),
    (e) => e.code === CODES.TIMEOUT
  );
});

test('una respuesta que no es JSON se informa sin romperse', async () => {
  await assert.rejects(
    getJSON({
      url: 'https://ejemplo.com/check',
      intentos: 1,
      fetchImpl: async () => respuesta({ cuerpo: '<html>mantenimiento</html>' })
    }),
    (e) => {
      assert.equal(e.code, CODES.API_EXTERNA);
      assert.match(e.details.vista, /mantenimiento/);
      return true;
    }
  );
});

test('un cuerpo vacio en un 200 se trata como objeto vacio', async () => {
  const datos = await getJSON({
    url: 'https://ejemplo.com/check',
    intentos: 1,
    fetchImpl: async () => respuesta({ cuerpo: '' })
  });
  assert.deepEqual(datos, {});
});

test('un cuerpo de error que no es JSON no tapa el error real', async () => {
  // El detalle del error va en el mensaje del NetlabError, nunca en la excepcion
  // que escapo del fetch: si no, ver el 500 real en la consola es otraPesadilla.
  await assert.rejects(
    getJSON({
      url: 'https://ejemplo.com/check',
      intentos: 1,
      fetchImpl: async () => respuesta({ status: 502, cuerpo: '<html>bad gateway</html>' })
    }),
    (e) => e.code === CODES.API_EXTERNA && /502/.test(e.message)
  );
});

test('sin fetch no se puede trabajar y se dice por que', async () => {
  // `fetchImpl: null` no sirve para esto: `null` es falsy y por el `||` cae al
  // fetch global. Hay que quitarlo de verdad para probar la guarda.
  const original = globalThis.fetch;
  delete globalThis.fetch;
  try {
    await assert.rejects(
      getJSON({ url: 'https://ejemplo.com' }),
      (e) => {
        assert.ok(e instanceof NetlabError);
        assert.equal(e.code, CODES.INTERNO);
        assert.match(e.message, /fetch/);
        return true;
      }
    );
  } finally {
    globalThis.fetch = original;
  }
});

test('un fetch que se pasa como null NO desactiva el global', async () => {
  // Por el mismo `||`, pasar null significa "usa el que haya". Se comprueba
  // para que nadie lea el parametro como un interruptor.
  const datos = await getJSON({
    url: 'https://ejemplo.com',
    fetchImpl: async () => respuesta({ cuerpo: { ok: true } })
  });
  assert.deepEqual(datos, { ok: true });
});
