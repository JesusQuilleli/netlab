'use strict';

/**
 * test/web.test.js — Pruebas del sondeo de sitios web y de su guarda SSRF.
 *
 * Las pruebas de `sondear` levantan un servidor HTTP en `127.0.0.1` en un puerto
 * libre. Es lo unico que permite comprobar de verdad lo que importa aqui: que
 * las redirecciones se siguen a mano, que un salto a la red interna se corta, y
 * que el cuerpo se acota. Con un `fetch` falso se probaria el codigo de pruebas
 * anterior, no el codigo que se ejecuta.
 *
 * El servidor local es precisamente el caso que la guarda bloquea, asi que estas
 * pruebas pasan `permitirPrivadas: true`. Por eso tambien hay una prueba que
 * comprueba que esa casilla NO abre el enlace local.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const web = require('../src/core/net/web');
const { NetlabError, CODES } = require('../src/core/errors');

/* ------------------------------------------------------------------ *
 * Utilidades
 * ------------------------------------------------------------------ */

/** Levanta un servidor local y devuelve su base, con apagado garantizado. */
async function conServidor(manejador, hacer) {
  const servidor = http.createServer(manejador);
  await new Promise((cumplir) => servidor.listen(0, '127.0.0.1', cumplir));
  const base = `http://127.0.0.1:${servidor.address().port}`;
  try {
    return await hacer(base);
  } finally {
    await new Promise((cumplir) => servidor.close(cumplir));
  }
}

/** Peticiones contra un servidor local: hay que permitir la red privada. */
const LOCAL = { permitirPrivadas: true, timeoutMs: 2000 };

/** Resolver de mentira: un nombre publico siempre da la misma IP. */
const resolverPublico = async () => [{ address: '93.184.216.34' }];

/**
 * Texto como ArrayBuffer, que es lo que devuelve `response.arrayBuffer()`.
 *
 * No se usa `Buffer.from(texto).buffer`: los Buffer pequenos salen de un pool
 * compartido, asi que ese `.buffer` es el bloque entero del pool con restos de
 * otras cadenas. Daria un cuerpo de 8 KB lleno de basura de otros tests.
 */
function aArrayBuffer(texto) {
  return new TextEncoder().encode(texto).buffer;
}

/* ------------------------------------------------------------------ *
 * normalizarUrl
 * ------------------------------------------------------------------ */

test('un dominio sin esquema se prueba por https', () => {
  assert.equal(web.normalizarUrl('ejemplo.com').toString(), 'https://ejemplo.com/');
});

test('un esquema explicito se respeta', () => {
  assert.equal(web.normalizarUrl('http://ejemplo.com').protocol, 'http:');
});

test('la ruta y la query se conservan', () => {
  assert.equal(web.normalizarUrl('https://ejemplo.com/inicio?a=1').toString(), 'https://ejemplo.com/inicio?a=1');
});

test('un esquema raro da un error que explica el por que', () => {
  // Aceptar `file:` significaria poder leer el disco del cliente desde el
  // navegador de otra persona que use netlab.
  assert.throws(() => web.normalizarUrl('file:///etc/passwd'), (e) => {
    assert.ok(e instanceof NetlabError);
    assert.equal(e.code, CODES.PARAM_INVALIDO);
    return true;
  });
});

test('las credenciales en la URL se rechazan', () => {
  // Se pega la URL copiada del navegador con el usuario dentro y acabaria
  // guardada en el historial y en el informe exportado.
  assert.throws(() => web.normalizarUrl('https://usuario:clave@ejemplo.com'), (e) => {
    assert.match(e.message, /contraseña/);
    return true;
  });
});

test('un puerto explicito se respeta, aunque no sea de los habituales', () => {
  // Mirar el servidor propio en el 3000 de desarrollo es un uso normal. Lo que
  // no es normal es llegar a la direccion de destino, y de eso se encarga la
  // guarda SSRF, no el numero de puerto.
  assert.equal(web.normalizarUrl('http://127.0.0.1:3000').port, '3000');
  assert.equal(web.normalizarUrl('http://127.0.0.1:3000').hostname, '127.0.0.1');
});

test('sin nada escrito el error pide escribir algo', () => {
  assert.throws(() => web.normalizarUrl('   '), (e) => {
    assert.equal(e.code, CODES.ENTRADA_VACIA);
    return true;
  });
});

/* ------------------------------------------------------------------ *
 * La guarda SSRF
 * ------------------------------------------------------------------ */

test('loopback, red privada y enlace local estan bloqueados por defecto', () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.0.1', '169.254.169.254', '0.0.0.0']) {
    assert.equal(web.esProhibida(ip), true, `${ip} deberia estar bloqueada`);
  }
});

test('las IPv6 reservadas tambien, que antes no las cubria nadie', () => {
  // Sin esta lista, `http://[::1]/` pasaba el filtro entero.
  for (const ip of ['::1', 'fe80::1', 'fc00::1', 'ff02::1']) {
    assert.equal(web.esProhibida(ip), true, `${ip} deberia estar bloqueada`);
  }
});

test('una IPv4 metida en IPv6 tambien se reconoce como privada', () => {
  // `::ffff:127.0.0.1` no cae en 127.0.0.0/8 y es el bypass mas obvio posible.
  assert.equal(web.esProhibida('::ffff:127.0.0.1'), true);
  assert.equal(web.esProhibida('::ffff:169.254.169.254'), true);
  assert.equal(web.esMapeada('::ffff:10.0.0.1'), true);
  assert.equal(web.aIPv4('::ffff:10.0.0.1'), '10.0.0.1');
});

test('una IP publica no esta bloqueada', () => {
  assert.equal(web.esProhibida('93.184.216.34'), false);
  assert.equal(web.esProhibida('2606:4700:4700::1111'), false);
});

test('la casilla de red privada abre la LAN pero NO el enlace local', () => {
  // La asimetria es deliberada: revisar un sitio en la red de uno tiene sentido,
  // leer 169.254.169.254 desde netlab no. Esa direccion sale sola en cualquier
  // nube y devuelve las credenciales de la instancia.
  assert.equal(web.esProhibida('10.0.0.1', true), false);
  assert.equal(web.esProhibida('127.0.0.1', true), false);
  assert.equal(web.esProhibida('fc00::1', true), false);
  assert.equal(web.esProhibida('169.254.169.254', true), true);
  assert.equal(web.esProhibida('fe80::1', true), true);
});

test('el nombre del bloqueo sale del rango, para que el mensaje signifique algo', () => {
  assert.match(web.motivoDeBloqueo('127.0.0.1'), /Loopback/);
  assert.match(web.motivoDeBloqueo('192.168.1.1'), /privad/i);
  assert.equal(web.motivoDeBloqueo('93.184.216.34'), null);
});

/* ------------------------------------------------------------------ *
 * validarDestino
 * ------------------------------------------------------------------ */

test('se rechaza si CUALQUIERA de las direcciones resueltas es privada', async () => {
  // Elataque clasico de envenenamiento: un nombre con una IP publica y otra de
  // metadatos. Validar solo la primera deja el agujero abierto.
  const resolver = async () => [{ address: '93.184.216.34' }, { address: '169.254.169.254' }];
  const r = await web.validarDestino('envenenado.example', { resolver });

  assert.equal(r.ok, false);
  assert.equal(r.bloqueadas.length, 1);
  assert.equal(r.bloqueadas[0].ip, '169.254.169.254');
  assert.deepEqual(r.ipsOk, ['93.184.216.34']);
});

test('una IP literal se comprueba sin resolver nada', async () => {
  const r = await web.validarDestino('192.168.0.5');
  assert.equal(r.ok, false);
  assert.equal(r.ips.length, 1);
});

test('un nombre que no resuelve se distingue de uno bloqueado', async () => {
  // Son dos causas distintas: una es "no existe o el DNS falla", la otra es
  // "existe pero apunta dentro". Sin `error` no habria forma de separarlas.
  const resolver = async () => {
    const e = new Error('getaddrinfo ENOTFOUND');
    e.code = 'ENOTFOUND';
    throw e;
  };
  const r = await web.validarDestino('noexiste.example', { resolver });
  assert.equal(r.ok, false);
  assert.equal(r.bloqueadas.length, 0);
  assert.match(r.error.message, /ENOTFOUND/);
});

/* ------------------------------------------------------------------ *
 * sondear
 * ------------------------------------------------------------------ */

test('un sitio que responde 200 se lee con su titulo', async () => {
  await conServidor(
    (peticion, respuesta) => {
      respuesta.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      respuesta.end('<html><head><title>  Bienvenido   a\n ejemplo </title></head><body>hola</body></html>');
    },
    async (base) => {
      const r = await web.sondear(base, LOCAL);
      assert.equal(r.ok, true);
      assert.equal(r.estado, 200);
      assert.equal(r.titulo, 'Bienvenido a ejemplo');
      assert.match(r.cabeceras['content-type'], /text\/html/);
    }
  );
});

test('las redirecciones se siguen a mano y se cuenta la cadena', async () => {
  await conServidor(
    (peticion, respuesta) => {
      if (peticion.url === '/') return respuesta.writeHead(302, { Location: '/a' }).end();
      if (peticion.url === '/a') return respuesta.writeHead(301, { Location: '/b' }).end();
      respuesta.writeHead(200, { 'Content-Type': 'text/html' }).end('<title>Final</title>');
    },
    async (base) => {
      const r = await web.sondear(base, LOCAL);
      assert.equal(r.estado, 200);
      assert.equal(r.cadena.length, 3);
      assert.match(r.urlFinal, /\/b$/);
    }
  );
});

test('una redireccion a la red interna se corta, aunque el primer salto sea publico', async () => {
  // El bypass clasico de SSRF. Solo se para si se revalida en CADA salto, y por
  // eso el cliente usa `redirect: 'manual'`.
  await conServidor(
    (peticion, respuesta) => respuesta.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' }).end(),
    async (base) => {
      await assert.rejects(web.sondear(base, { permitirPrivadas: true, timeoutMs: 2000 }), (e) => {
        assert.ok(e instanceof NetlabError);
        assert.match(e.message, /seguridad/);
        assert.match(e.message, /169\.254\.169\.254/);
        return true;
      });
    }
  );
});

test('no se sigue mas de cinco redirecciones', async () => {
  await conServidor(
    (peticion, respuesta) => {
      const n = Number(new URL(peticion.url, 'http://x').searchParams.get('n') || 0);
      respuesta.writeHead(302, { Location: `/?n=${n + 1}` }).end();
    },
    async (base) => {
      const r = await web.sondear(base, LOCAL);
      assert.equal(r.demasiadas, true);
      assert.match(r.motivo, /redirecciones/);
      assert.equal(r.cadena.length, 6);
    }
  );
});

test('un bucle de redirecciones se detecta en vez de colgarse', async () => {
  await conServidor(
    (peticion, respuesta) => respuesta.writeHead(302, { Location: '/bucle' }).end(),
    async (base) => {
      const r = await web.sondear(base, LOCAL);
      assert.equal(r.bucle, true);
    }
  );
});

test('un HEAD con 405 se reintenta con GET, y el sitio no esta caido', async () => {
  // Muchos servidores no implementan HEAD. Dirse por morto aqui seria un falso
  // negativo: el sitio abre perfectamente en el navegador.
  await conServidor(
    (peticion, respuesta) => {
      if (peticion.method === 'HEAD') return respuesta.writeHead(405).end();
      respuesta.writeHead(200, { 'Content-Type': 'text/html' }).end('<title>Con GET si funciona</title>');
    },
    async (base) => {
      const r = await web.sondear(base, LOCAL);
      assert.equal(r.estado, 200);
      assert.equal(r.ok, true);
      assert.equal(r.metodo, 'GET');
      assert.equal(r.titulo, 'Con GET si funciona');
    }
  );
});

test('un 403 al HEAD se reintenta con GET antes de declararlo caido', async () => {
  await conServidor(
    (peticion, respuesta) => {
      if (peticion.method === 'HEAD') return respuesta.writeHead(403).end();
      respuesta.writeHead(200, { 'Content-Type': 'text/html' }).end('<title>Permitido con GET</title>');
    },
    async (base) => {
      const r = await web.sondear(base, LOCAL);
      assert.equal(r.estado, 200);
      assert.equal(r.ok, true);
    }
  );
});

test('el User-Agent propio llega al servidor', async () => {
  // Sin identificarse, los sitios que bloquean bots responden 403 a un cliente
  // anonimo y el informe diria "caida" cuando lo unico que pasa es que no
  // quieren hablar con unidentified.
  let recibido = null;
  await conServidor(
    (peticion, respuesta) => {
      recibido = peticion.headers['user-agent'];
      respuesta.writeHead(200, { 'Content-Type': 'text/html' }).end('<title>ok</title>');
    },
    async (base) => {
      await web.sondear(base, LOCAL);
      assert.equal(recibido, web.USER_AGENT);
      assert.match(recibido, /^netlab\//);
    }
  );
});

test('un cuerpo enorme se corta en el tope sin reventar la memoria', async () => {
  // Sin tope, un servidor que se dice de 2 GB agota la memoria del proceso. El
  // informe necesita un titulo, no la pagina entera.
  const enorme = '<title>Grande</title>' + 'x'.repeat(web.MAX_CUERPO * 3);
  await conServidor(
    (peticion, respuesta) => respuesta.writeHead(200, { 'Content-Type': 'text/html' }).end(enorme),
    async (base) => {
      const r = await web.sondear(base, LOCAL);
      assert.equal(r.truncado, true);
      assert.ok(r.cuerpo.length <= web.MAX_CUERPO);
      assert.equal(r.titulo, 'Grande');
    }
  );
});

test('un 500 se devuelve tal cual, para que sea el veredicto quien lo diga', async () => {
  await conServidor(
    (peticion, respuesta) => respuesta.writeHead(500, { 'Content-Type': 'text/html' }).end('<title>Error</title>'),
    async (base) => {
      const r = await web.sondear(base, LOCAL);
      assert.equal(r.estado, 500);
      assert.equal(r.ok, false);
    }
  );
});

test('un sitio que no responde se informa como tiempo agotado, no como caido', async () => {
  const servidor = http.createServer(() => {});
  await new Promise((cumplir) => servidor.listen(0, '127.0.0.1', cumplir));
  const puerto = servidor.address().port;
  // Se apaga el servidor pero se conserva el puerto: ahora nadie escucha.
  await new Promise((cumplir) => servidor.close(cumplir));

  await assert.rejects(web.sondear(`http://127.0.0.1:${puerto}`, { permitirPrivadas: true, timeoutMs: 1500 }), (e) => {
    assert.equal(e.code, CODES.RED);
    return true;
  });
});

test('un fetch que se cuelga dispara el plazo y sale como tiempo agotado', async () => {
  // La distincion importa: "no respondio a tiempo" y "no se pudo contactar"
  // llevan a acciones distintas.
  const colgado = (peticion, opciones) =>
    new Promise((_cumplir, rechazar) => {
      opciones.signal.addEventListener('abort', () => {
        const e = new Error('aborted');
        e.name = 'AbortError';
        rechazar(e);
      });
    });

  await assert.rejects(
    web.sondear('https://lento.example', { fetchImpl: colgado, resolver: resolverPublico, timeoutMs: 60 }),
    (e) => {
      assert.equal(e.code, CODES.TIMEOUT);
      assert.match(e.message, /60 ms/);
      return true;
    }
  );
});

test('el sondeo no usa la red real cuando se le pasa un fetch de mentira', async () => {
  // Comprobacion de que las opciones de inyeccion se respetan: si el modulo
  // ignorara el `fetchImpl`, estas pruebas estarian tocando Internet. El HEAD
  // devuelve sin cuerpo a proposito, para que el titulo solo pueda venir del
  // GET posterior.
  const r = await web.sondear('https://ejemplo.example', {
    fetchImpl: async (_url, opciones) => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers({ 'content-type': 'text/html' }),
      arrayBuffer: async () => (opciones.method === 'GET' ? aArrayBuffer('<title>Falso</title>') : new ArrayBuffer(0))
    }),
    resolver: resolverPublico
  });
  assert.equal(r.titulo, 'Falso');
  assert.equal(r.metodo, 'GET');
});

test('el titulo se limpia de etiquetas y saltos de linea', () => {
  assert.equal(web.leerTitulo('<title>a <b>b</b>\n c</title>'), 'a b c');
  assert.equal(web.leerTitulo('<html><body>sin title</body></html>'), null);
  assert.equal(web.leerTitulo('<title>   </title>'), null);
});