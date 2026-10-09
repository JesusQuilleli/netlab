'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { Auth, hashPassword, verificarPassword, limitadorIntentos, igual, leerCookie } = require('../src/server/auth');
const { Historial, hashParams } = require('../src/server/historial');
const { validar } = require('../src/server/validar');
const herramientas = require('../src/server/herramientas');
const { crearApp } = require('../src/server/app');
const formats = require('../src/formats');
const { Backup } = require('../src/server/backup');

const { createResult, addSection, finalize } = require('../src/core/result');
const { CODES } = require('../src/core/errors');

// ===================================================================== auth

test('el hash de contrasena no contiene la contrasena', () => {
  const hash = hashPassword('contrasena-secreta');
  assert.ok(hash.startsWith('scrypt$'));
  assert.equal(hash.includes('contrasena-secreta'), false);
  assert.equal(verificarPassword('contrasena-secreta', hash), true);
  assert.equal(verificarPassword('otra', hash), false);
});

test('el mismo hash se puede verificar varias veces', () => {
  // scrypt lleva sal dentro: dos llamadas dan hashes distintos y ambos valen.
  const a = hashPassword('misma');
  const b = hashPassword('misma');
  assert.notEqual(a, b);
  assert.equal(verificarPassword('misma', a), true);
  assert.equal(verificarPassword('misma', b), true);
});

test('un hash manipulado no revienta el proceso', () => {
  for (const malo of ['', 'scrypt$', 'scrypt$abc', 'scrypt$16384$8$1$c2FsdA==', 'no-es-scrypt']) {
    assert.equal(verificarPassword('x', malo), false, `con "${malo}"`);
  }
});

test('un N gigante en el hash se rechaza antes de reservar memoria', () => {
  // Sin este limite, un .env con N enorme haria que el proceso muera al arrancar
  // por falta de memoria en vez de decir que el hash no es valido.
  const loco = 'scrypt$99999999$8$1$c2FsdHNhbA==$' + Buffer.alloc(64).toString('base64');
  assert.equal(verificarPassword('x', loco), false);
});

test('la comparacion de cadenas es en tiempo constante y correcta', () => {
  assert.equal(igual('abc', 'abc'), true);
  assert.equal(igual('abc', 'abd'), false);
  assert.equal(igual('abc', 'abcd'), false);
  assert.equal(igual('abc', ''), false);
});

test('leer cookie devuelve el valor y no se rompe con basura', () => {
  assert.equal(leerCookie('a=1; netlab_sesion=xyz; b=2', 'netlab_sesion'), 'xyz');
  assert.equal(leerCookie('netlab_sesion=con%20espacio', 'netlab_sesion'), 'con espacio');
  assert.equal(leerCookie('netlab_sesion=%roto', 'netlab_sesion'), '');
  assert.equal(leerCookie(undefined, 'netlab_sesion'), '');
  assert.equal(leerCookie('otra=1', 'netlab_sesion'), '');
});

test('AUTH_ENABLED=true sin usuarios no arranca', () => {
  // Fallo cerrado: es preferible que el servidor no levante antes que quedar
  // escuchando en Internet creyéndose protegido.
  assert.throws(() => new Auth({ activo: true, usuarios: null }), /Usuarios no inicializado/);
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  assert.doesNotThrow(() => new Auth({ activo: true, usuarios }));
});

test('en modo local todo es el mismo dueño y el CSRF no estorba', () => {
  const auth = new Auth({ activo: false });
  assert.deepEqual(auth.identidad({ headers: {} }), { usuario: 'local', role: 'admin', local: true });
  assert.equal(auth.csrfValido({ headers: {} }), true);
});

test('la sesion caduca', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  usuarios.crear({ username: 'ana', password: 'password123', role: 'admin' });
  const auth = new Auth({ activo: true, usuarios });
  const entrada = auth.entrar('ana', 'password123', 'ip');
  const req = { headers: { cookie: `netlab_sesion=${entrada.cookie}` } };
  assert.equal(auth.identidad(req).usuario, 'ana');

  // Se caduca a mano en vez de esperar ocho horas.
  auth.sesiones.get(entrada.cookie).expira = Date.now() - 1;
  assert.equal(auth.identidad(req).usuario, null);
});

test('un token de sesion inventado no da acceso', () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  usuarios.crear({ username: 'ana', password: 'password123', role: 'admin' });
  const auth = new Auth({ activo: true, usuarios });
  assert.equal(auth.identidad({ headers: { cookie: 'netlab_sesion=inventado' } }).usuario, null);
});

test('el limitador corta los intentos repetidos', () => {
  const lim = limitadorIntentos({ maximo: 3, ventanaMs: 10_000 });
  assert.equal(lim.permitir('ip').ok, true);
  assert.equal(lim.permitir('ip').ok, true);
  assert.equal(lim.permitir('ip').ok, true);
  const cuarto = lim.permitir('ip');
  assert.equal(cuarto.ok, false);
  assert.ok(cuarto.reintentarEn > 0);

  // Otra IP no se ve afectada.
  assert.equal(lim.permitir('otra-ip').ok, true);

  // Tras limpiar, vuelve a pasar.
  lim.limpiar('ip');
  assert.equal(lim.permitir('ip').ok, true);
});

// ============================================================== validacion

test('solo pasan los campos que la herramienta declara', () => {
  const herramienta = herramientas.obtener('ip-audit');
  const { params } = validar(herramienta.campos, { ip: '8.8.8.8', ABUSEIPDB_API_KEY: 'secreto', otro: 1 });
  assert.equal(params.ip, '8.8.8.8');
  assert.equal('ABUSEIPDB_API_KEY' in params, false, 'una clave inventada no puede colarse hasta el Result');
  assert.equal('otro' in params, false);
});

test('shownWhen aparta el campo aunque venga en el cuerpo', () => {
  const herramienta = herramientas.obtener('ip-audit');
  const { params, avisos } = validar(herramienta.campos, { ip: '8.8.8.8', dnsbl: false, listas: 'amplia' });
  assert.equal('listas' in params, false);
  assert.equal(avisos.length, 1);
  assert.match(avisos[0], /listas/);
});

test('requiredUnless funciona aunque el campo que lo activa se declare despues', () => {
  // En dns-checker, `dominio` es el primer campo y `compararArchivo` el quinto.
  // Sin resolver las casillas antes, `dominio` saldria obligatorio siempre.
  const herramienta = herramientas.obtener('dns-checker');
  assert.doesNotThrow(() => validar(herramienta.campos, { compararArchivo: true, archivoContenido: 'x' }));
  assert.throws(() => validar(herramienta.campos, {}), /Dominio/);
});

test('un select solo admite los valores declarados', () => {
  const herramienta = herramientas.obtener('ip-audit');
  assert.throws(() => validar(herramienta.campos, { ip: '8.8.8.8', listas: 'enorme' }), /no admite/);
  assert.equal(validar(herramienta.campos, { ip: '8.8.8.8', listas: 'amplia' }).params.listas, 'amplia');
});

test('un numero fuera de rango se recorta en vez de fallar', () => {
  const herramienta = herramientas.obtener('ip-audit');
  assert.equal(validar(herramienta.campos, { ip: '8.8.8.8', timeout: 99_999_999 }).params.timeout, 60_000);
  assert.equal(validar(herramienta.campos, { ip: '8.8.8.8', timeout: 1 }).params.timeout, 1000);
});

test('un numero que no es numero da error de parametro', () => {
  const herramienta = herramientas.obtener('ip-audit');
  assert.throws(() => validar(herramienta.campos, { ip: '8.8.8.8', timeout: 'mucho' }), (e) => e.code === CODES.PARAM_INVALIDO);
});

test('un campo obligatorio que falta dice cual falta', () => {
  const herramienta = herramientas.obtener('ip-audit');
  assert.throws(() => validar(herramienta.campos, {}), (e) => e.code === CODES.PARAM_INVALIDO && e.details.campo === 'ip');
});

test('una casilla acepta las formas que envia un formulario', () => {
  const herramienta = herramientas.obtener('subnet-analyzer');
  assert.equal(validar(herramienta.campos, { red: '10.0.0.0/8', listar: 'on' }).params.listar, true);
  assert.equal(validar(herramienta.campos, { red: '10.0.0.0/8', listar: 'false' }).params.listar, false);
  assert.equal(validar(herramienta.campos, { red: '10.0.0.0/8' }).params.listar, false);
});

test('un archivo por encima del limite se rechaza', () => {
  const herramienta = herramientas.obtener('dns-checker');
  const grande = 'x'.repeat(1024 * 1024 + 10);
  assert.throws(
    () => validar(herramienta.campos, { compararArchivo: true, archivoContenido: grande }),
    /demasiado grande/
  );
});

// ============================================================== herramientas

test('el catalogo expone los campos pero no la funcion ejecutar', () => {
  const catalogo = herramientas.listar();
  assert.ok(catalogo.length >= 4);
  for (const h of catalogo) {
    assert.equal(h.ejecutar, undefined, `${h.id} no debe enseñar su funcion`);
    assert.ok(h.id && h.titulo);
    assert.ok(Array.isArray(h.campos));
  }
});

test('un archivo de herramientas que no cumple los requisitos se omite con aviso', () => {
  // Un error de sintaxis recien escrito no debe tumbar la web entera.
  const { herramientas: lista, avisos } = herramientas.cargar({ dir: require('node:path').join(__dirname, '_sin_herramientas') });
  assert.deepEqual(lista, []);
  assert.ok(avisos.length >= 1);
  assert.match(avisos[0], /carpeta/);
});

test('obtener devuelve null para una herramienta que no existe', () => {
  assert.equal(herramientas.obtener('no-existe'), null);
});

// ================================================================ historial

/** Result minimo con una tabla, para probar el viaje completo. */
function resultadoDePrueba(texto = 'hola', ms = 100) {
  const r = createResult({ tool: 'prueba', toolTitle: 'Prueba de titulo', target: '10.0.0.1' });
  addSection(r, { kind: 'table', title: 'Tabla', columns: [{ key: 'a', label: 'A' }], rows: [{ a: texto }] });
  r.startedAt = '2026-01-01T10:00:00.000Z';
  r.durationMs = ms;
  return finalize(r);
}

test('el hash de parametros no depende del orden', () => {
  assert.equal(hashParams({ a: 1, b: 2 }), hashParams({ b: 2, a: 1 }));
  assert.notEqual(hashParams({ a: 1 }), hashParams({ a: 2 }));
});

test('una ejecucion identica se reconoce como repetida', () => {
  // Es el motivo de que la huella vacie el reloj de los logs: sin eso, dos
  // ejecuciones identicasofillorian dos entradas distintas en el historial.
  const h = new Historial({ ruta: ':memory:' });
  const primera = h.guardar({ tool: 'prueba', params: { ip: '8.8.8.8' }, result: resultadoDePrueba('igual', 100), owner: 'ana' });
  const segunda = h.guardar({ tool: 'prueba', params: { ip: '8.8.8.8' }, result: resultadoDePrueba('igual', 999), owner: 'ana' });

  assert.equal(primera.duplicado, false);
  assert.equal(segunda.duplicado, true);
  assert.equal(segunda.id, primera.id);
  assert.equal(h.listar({ owner: 'ana' }).total, 1);
  h.cerrar();
});

test('un resultado distinto si crea una entrada nueva', () => {
  const h = new Historial({ ruta: ':memory:' });
  h.guardar({ tool: 'prueba', params: {}, result: resultadoDePrueba('uno'), owner: 'ana' });
  const otra = h.guardar({ tool: 'prueba', params: {}, result: resultadoDePrueba('otro'), owner: 'ana' });
  assert.equal(otra.duplicado, false);
  h.cerrar();
});

test('un dueno no ve el historial de otro', () => {
  const h = new Historial({ ruta: ':memory:' });
  const g = h.guardar({ tool: 'prueba', params: {}, result: resultadoDePrueba(), owner: 'ana' });

  assert.equal(h.obtener(g.id, 'ana') !== null, true);
  assert.equal(h.obtener(g.id, 'bea'), null, 'la busqueda lleva el dueno en la consulta, no se comprueba despues');
  assert.equal(h.listar({ owner: 'bea' }).total, 0);
  assert.equal(h.borrar(g.id, 'bea'), false);
  assert.equal(h.borrar(g.id, 'ana'), true);
  h.cerrar();
});

test('la lista no arrastra el Result entero', () => {
  // Un Result con 40 filas pesa bastante; la lista solo necesita la cabecera.
  const h = new Historial({ ruta: ':memory:' });
  const g = h.guardar({ tool: 'prueba', params: { ip: '8.8.8.8' }, result: resultadoDePrueba(), owner: 'ana' });
  const item = h.listar({ owner: 'ana' }).items[0];

  assert.equal('result' in item, false);
  assert.equal(item.status, 'pass');
  assert.equal(item.params.ip, '8.8.8.8');
  assert.equal(h.obtener(g.id, 'ana').result.sections.length, 1);
  h.cerrar();
});

test('un Result releido del historial renderiza en los cinco formatos', async () => {
  // ESTA PRUEBA EXISTE POR UN FALLO REAL. El guardado copiaba una lista blanca
  // de campos a mano y se le habia olvidado `toolTitle`. El TXT lo pone en
  // mayusculas, asi que reventaba con "cannot read properties of undefined"
  // mientras el MD, el HTML, el JSON y el PDF seguian funcionando: cuatro de
  // cinco formatos bien, uno roto, y nada en los tests de formatos lo detectaba
  // porque ahi el Result venia entero y nunca pasaba por la base de datos.
  const h = new Historial({ ruta: ':memory:' });
  const g = h.guardar({ tool: 'prueba', params: {}, result: resultadoDePrueba(), owner: 'ana' });
  const releido = h.obtener(g.id, 'ana').result;

  assert.equal(releido.toolTitle, 'Prueba de titulo', 'toolTitle debe sobrevivir al viaje');

  for (const formato of ['txt', 'md', 'html', 'json', 'pdf']) {
    // Con `await`: `formats.render` es asincrono, y sin el la longitud de una
    // promesa es `undefined` y el `assert` pasaria por el motivo equivocado.
    const salida = await formats.render(releido, formato);
    assert.ok(salida.length > 0, `${formato} sale vacio`);
  }
  h.cerrar();
});

test('el historial guarda los archivos generados y no los borra al limpiar', () => {
  const h = new Historial({ ruta: ':memory:' });
  const g = h.guardar({ tool: 'prueba', params: {}, result: resultadoDePrueba(), owner: 'ana' });
  h.archivar(g.id, { formato: 'pdf', filename: 'x.pdf', file: 'data/reports/prueba/x.pdf', bytes: 10 });

  assert.equal(h.archivos(g.id).length, 1);
  // Un informe ya descargado no desaparece porque alguien limpie su lista.
  h.borrar(g.id, 'ana');
  assert.equal(h.listar({ owner: 'ana' }).total, 0);
  h.cerrar();
});

// ================================================================== la API

/** Levanta la app en un puerto libre y devuelve una funcion para hablar con ella. */
async function conServidor(opciones, hacer) {
  const { app, historial, auth } = crearApp({ historial: new Historial({ ruta: ':memory:' }), ...opciones });
  const server = await new Promise((cumplir) => {
    const s = app.listen(0, '127.0.0.1');
    s.once('listening', () => cumplir(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  const pedir = async (ruta, opciones = {}) => {
    const respuesta = await fetch(base + ruta, {
      method: opciones.metodo || 'GET',
      headers: { ...(opciones.cuerpo ? { 'Content-Type': 'application/json' } : {}), ...(opciones.cabeceras || {}) },
      body: opciones.cuerpo ? JSON.stringify(opciones.cuerpo) : undefined
    });
    const tipo = respuesta.headers.get('content-type') || '';
    const cuerpo = tipo.includes('json') ? await respuesta.json() : null;
    return { status: respuesta.status, cuerpo, tipo, cabeceras: respuesta.headers };
  };

  /**
   * Entra y devuelve las cabeceras que hacen falta para hablar como ese usuario.
   *
   * El token de sesion no va en el cuerpo de la respuesta, solo en la cookie
   * `Set-Cookie`, asi que hay que leerlo de ahi. `Headers.get('set-cookie')` los
   * devuelve todos juntos, y el token es el primero de la lista.
   */
  const entrar = async (usuario, password) => {
    const r = await pedir('/api/sesion', { metodo: 'POST', cuerpo: { usuario, password } });
    assert.equal(r.status, 200, `no se pudo entrar: ${JSON.stringify(r.cuerpo)}`);

    const setCookie = r.cabeceras.get('set-cookie') || '';
    const emparejado = /netlab_sesion=([^;]+)/.exec(setCookie);
    assert.ok(emparejado, `la respuesta del login no trae la cookie de sesion: "${setCookie}"`);

    return {
      usuario: r.cuerpo.usuario,
      csrf: r.cuerpo.csrf,
      cabeceras: { Cookie: `netlab_sesion=${emparejado[1]}`, 'X-CSRF-Token': r.cuerpo.csrf }
    };
  };

  try {
    await hacer({ pedir, entrar, base, auth, historial });
  } finally {
    historial.cerrar();
    server.close();
  }
}

test('la sesion local responde sin pedir nada', async () => {
  await conServidor({}, async ({ pedir }) => {
    const r = await pedir('/api/sesion');
    assert.equal(r.status, 200);
    assert.equal(r.cuerpo.autenticado, true);
    assert.equal(r.cuerpo.local, true);
    assert.equal(r.cuerpo.usuario, 'local');
  });
});

// El despliegue real es netlab en localhost con un proxy inverso delante, asi que
// la IP del cliente llega en X-Forwarded-For y no en el socket. Si el servidor
// no leyera esa cabecera, todas las peticiones contarian como la misma IP:
// el limite de intentos seria global (un bloqueo por fuerza bruta tumbaria el
// login de todos) y la auditoria guardaria siempre 127.0.0.1.
test('detras de un proxy, el limite por IP usa la IP real y no la del proxy', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  usuarios.crear({ username: 'ana', password: 'la-clave-secreta', role: 'admin' });
  await conServidor({ auth: new Auth({ activo: true, usuarios }) }, async ({ pedir }) => {
    const falloDesde = (ip) => pedir('/api/sesion', {
      metodo: 'POST',
      cuerpo: { usuario: 'ana', password: 'incorrecta' },
      cabeceras: { 'X-Forwarded-For': ip }
    });

    // Ocho intentos fallidos desde la misma IP real.
    for (let n = 0; n < 8; n++) {
      assert.equal((await falloDesde('203.0.113.9')).status, 401, `intento ${n + 1} deberia fallar`);
    }
    assert.equal((await falloDesde('203.0.113.9')).status, 429, 'la novena vez deberia estar bloqueada');

    // Otra IP real no comparte el contador.
    assert.equal((await falloDesde('198.51.100.4')).status, 401, 'otra IP no deberia estar bloqueada');
  });
});

test('el catalogo llega completo y sin la funcion ejecutar', async () => {
  await conServidor({}, async ({ pedir }) => {
    const r = await pedir('/api/herramientas');
    assert.equal(r.status, 200);
    assert.ok(r.cuerpo.herramientas.length >= 4);
    for (const h of r.cuerpo.herramientas) {
      assert.equal(h.ejecutar, undefined);
      assert.ok(h.campos.length > 0);
    }
  });
});

test('ejecutar una herramienta y descargar los cinco formatos', async () => {
  await conServidor({}, async ({ pedir, base }) => {
    const r = await pedir('/api/run', {
      metodo: 'POST',
      cuerpo: { tool: 'subnet-analyzer', params: { red: '192.168.0.0/24', subredes: 4 } }
    });

    assert.equal(r.status, 200);
    assert.equal(r.cuerpo.result.status, 'pass');
    assert.ok(r.cuerpo.id);

    for (const [formato, prefijo] of [['json', '{'], ['md', '#'], ['html', '<'], ['pdf', '%PDF']]) {
      const respuesta = await fetch(`${base}/api/run/${r.cuerpo.id}/${formato}`);
      const cuerpo = await respuesta.text();
      assert.equal(respuesta.status, 200, `${formato} devolvio ${respuesta.status}`);
      assert.ok(cuerpo.startsWith(prefijo), `${formato} deberia empezar por ${prefijo}`);
      assert.match(respuesta.headers.get('content-type'), new RegExp(formato === 'pdf' ? 'pdf' : formato === 'json' ? 'json' : 'text'));
    }
  });
});

test('la contrasena de una herramienta no se guarda en el historial', async () => {
  await conServidor({}, async ({ pedir }) => {
    const secreto = 'clave-que-no-debe-quedar';
    const r = await pedir('/api/run', {
      metodo: 'POST',
      cuerpo: {
        tool: 'smtp-validator',
        params: {
          host: '127.0.0.1',
          puerto: 1,
          seguridad: 'ninguno',
          usuario: 'usuario@ejemplo.com',
          contrasena: secreto,
          timeout: 1000
        }
      }
    });

    assert.equal(r.status, 200);
    assert.equal(JSON.stringify(r.cuerpo).includes(secreto), false, 'la respuesta ya la filtra');

    const detalle = await pedir(`/api/historial/${r.cuerpo.id}`);
    assert.equal(detalle.status, 200);
    assert.equal(JSON.stringify(detalle.cuerpo).includes(secreto), false, 'el historial guarda la contrasena');

    const params = detalle.cuerpo.registro.params;
    assert.notEqual(params.contrasena, secreto);
    assert.ok(params.contrasena, 'el campo sigue existiendo, enmascarado');
  });
});

test('un parametro obligatorio que falta da 400 diciendo cual', async () => {
  await conServidor({}, async ({ pedir }) => {
    const r = await pedir('/api/run', { metodo: 'POST', cuerpo: { tool: 'ip-audit', params: {} } });
    assert.equal(r.status, 400);
    assert.equal(r.cuerpo.error.code, CODES.PARAM_INVALIDO);
    assert.match(r.cuerpo.error.message, /IP/);
  });
});

test('una herramienta inexistente da 404', async () => {
  await conServidor({}, async ({ pedir }) => {
    const r = await pedir('/api/run', { metodo: 'POST', cuerpo: { tool: 'inventada', params: {} } });
    assert.equal(r.status, 404);
    assert.equal(r.cuerpo.error.code, 'HERRAMIENTA_DESCONOCIDA');
  });
});

test('un cuerpo que no es JSON da 400 y no revienta el servidor', async () => {
  await conServidor({}, async ({ base }) => {
    const respuesta = await fetch(`${base}/api/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{esto no es json'
    });
    assert.equal(respuesta.status, 400);
    assert.equal((await respuesta.json()).error.code, 'JSON_INVALIDO');
  });
});

test('un formato que no existe da 400 con la lista de los que si', async () => {
  await conServidor({}, async ({ pedir }) => {
    const r = await pedir('/api/run', { metodo: 'POST', cuerpo: { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } } });
    const malo = await pedir(`/api/run/${r.cuerpo.id}/xls`);
    assert.equal(malo.status, 400);
    assert.equal(malo.cuerpo.error.code, 'FORMATO_DESCONOCIDO');
    assert.match(malo.cuerpo.error.remediation, /pdf/);
  });
});

test('el dueno de una ejecucion sale de la sesion, nunca del cuerpo', async () => {
  // Si el dueño saliera de lo que manda el navegador, cualquiera podria leer y
  // borrar el historial de otro escribiendo {"owner":"ana"} en el cuerpo.
  await conServidor({}, async ({ pedir }) => {
    const creada = await pedir('/api/run', {
      metodo: 'POST',
      cuerpo: {
        tool: 'subnet-analyzer',
        params: { red: '10.0.0.0/24' },
        owner: 'inventado',
        dueno: 'otro'
      }
    });
    assert.equal(creada.status, 200);

    const item = (await pedir('/api/historial')).cuerpo.items[0];
    assert.equal(item.owner, 'local', 'el dueno lo pone la sesion');
    assert.equal(item.id, creada.cuerpo.id);
  });
});

test('con la sesion cerrada las ejecuciones propias ya no se ven', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  usuarios.crear({ username: 'ana', password: 'password123', role: 'admin' });
  const auth = new Auth({ activo: true, usuarios });
  await conServidor({ auth }, async ({ pedir, entrar }) => {
    const sesion = await entrar('ana', 'password123');
    const creada = await pedir('/api/run', {
      metodo: 'POST',
      cabeceras: sesion.cabeceras,
      cuerpo: { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } }
    });
    const id = creada.cuerpo.id;
    assert.equal((await pedir(`/api/run/${id}`, { cabeceras: sesion.cabeceras })).status, 200);

    await pedir('/api/sesion', { metodo: 'DELETE', cabeceras: sesion.cabeceras });

    // Sin sesion ya no hay ni lectura ni descarga.
    assert.equal((await pedir(`/api/run/${id}`)).status, 401);
    assert.equal((await pedir(`/api/run/${id}/pdf`)).status, 401);
  });
});

test('sin sesion no se puede ni listar ni ejecutar', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  usuarios.crear({ username: 'ana', password: 'password123', role: 'admin' });
  await conServidor({ auth: new Auth({ activo: true, usuarios }) }, async ({ pedir }) => {
    assert.equal((await pedir('/api/herramientas')).status, 401);
    assert.equal((await pedir('/api/historial')).status, 401);
    assert.equal((await pedir('/api/run', { metodo: 'POST', cuerpo: { tool: 'ip-audit', params: { ip: '8.8.8.8' } } })).status, 401);
  });
});

test('el login acepta la buena y rechaza la mala sin decir cual fallo', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  usuarios.crear({ username: 'ana', password: 'la-clave-secreta', role: 'admin' });
  const auth = new Auth({ activo: true, usuarios });
  await conServidor({ auth }, async ({ pedir }) => {
    const malaClave = await pedir('/api/sesion', { metodo: 'POST', cuerpo: { usuario: 'ana', password: 'no' } });
    const malUsuario = await pedir('/api/sesion', { metodo: 'POST', cuerpo: { usuario: 'bea', password: 'la-clave-secreta' } });

    assert.equal(malaClave.status, 401);
    assert.equal(malUsuario.status, 401);
    assert.equal(malaClave.cuerpo.error.message, malUsuario.cuerpo.error.message, 'el mensaje no puede distinguish los dos fallos');

    const buena = await pedir('/api/sesion', { metodo: 'POST', cuerpo: { usuario: 'ana', password: 'la-clave-secreta' } });
    assert.equal(buena.status, 200);
    assert.equal(buena.cuerpo.usuario, 'ana');
    assert.ok(buena.cuerpo.csrf);
  });
});

test('sin token CSRF no se puede cambiar nada', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  usuarios.crear({ username: 'ana', password: 'password123', role: 'admin' });
  const auth = new Auth({ activo: true, usuarios });
  await conServidor({ auth }, async ({ pedir, entrar }) => {
    const sesion = await entrar('ana', 'password123');
    const cookie = { Cookie: sesion.cabeceras.Cookie };

    // Con cookie pero sin CSRF: se rechaza.
    const sinCsrf = await pedir('/api/run', {
      metodo: 'POST',
      cabeceras: cookie,
      cuerpo: { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } }
    });
    assert.equal(sinCsrf.status, 403);
    assert.equal(sinCsrf.cuerpo.error.code, 'CSRF_INVALIDO');

    // Con CSRF inventado tambien.
    const conCsrfFalso = await pedir('/api/run', {
      metodo: 'POST',
      cabeceras: { ...cookie, 'X-CSRF-Token': 'inventado' },
      cuerpo: { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } }
    });
    assert.equal(conCsrfFalso.status, 403);

    // Con el bueno, pasa.
    const bien = await pedir('/api/run', { metodo: 'POST', cabeceras: sesion.cabeceras, cuerpo: { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } } });
    assert.equal(bien.status, 200);

    // Cerrar sesion invalida el token.
    const cierre = await pedir('/api/sesion', { metodo: 'DELETE', cabeceras: sesion.cabeceras });
    assert.equal(cierre.status, 200);
    assert.equal(
      (await pedir('/api/run', { metodo: 'POST', cabeceras: sesion.cabeceras, cuerpo: { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } } })).status,
      401
    );
  });
});

test('el tope por minuto corta una tanda de ejecuciones', async () => {
  await conServidor({ maxPorMinuto: 2 }, async ({ pedir }) => {
    const cuerpo = { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } };
    assert.equal((await pedir('/api/run', { metodo: 'POST', cuerpo })).status, 200);
    assert.equal((await pedir('/api/run', { metodo: 'POST', cuerpo })).status, 200);

    const tercera = await pedir('/api/run', { metodo: 'POST', cuerpo });
    assert.equal(tercera.status, 429);
    assert.equal(tercera.cuerpo.error.code, 'DEMASIADAS_EJECUCIONES');
  });
});

test('el historial se lista, se abre y se borra', async () => {
  await conServidor({}, async ({ pedir }) => {
    const r = await pedir('/api/run', { metodo: 'POST', cuerpo: { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } } });
    const id = r.cuerpo.id;

    const lista = await pedir('/api/historial');
    assert.equal(lista.status, 200);
    assert.equal(lista.cuerpo.total, 1);
    assert.equal(lista.cuerpo.items[0].tool, 'subnet-analyzer');

    const detalle = await pedir(`/api/historial/${id}`);
    assert.equal(detalle.status, 200);
    assert.equal(detalle.cuerpo.result.tool, 'subnet-analyzer');

    assert.equal((await pedir(`/api/historial/${id}`, { metodo: 'DELETE' })).cuerpo.borrado, true);
    assert.equal((await pedir('/api/historial')).cuerpo.total, 0);
    assert.equal((await pedir(`/api/historial/${id}`, { metodo: 'DELETE' })).status, 404);
  });
});

test('el historial se puede filtrar por herramienta', async () => {
  await conServidor({}, async ({ pedir }) => {
    await pedir('/api/run', { metodo: 'POST', cuerpo: { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } } });
    await pedir('/api/run', { metodo: 'POST', cuerpo: { tool: 'subnet-analyzer', params: { red: '192.168.0.0/24' } } });

    assert.equal((await pedir('/api/historial')).cuerpo.total, 2);
    assert.equal((await pedir('/api/historial?tool=ip-audit')).cuerpo.total, 0);
    assert.equal((await pedir('/api/historial?tool=subnet-analyzer')).cuerpo.total, 2);
  });
});

test('una ejecucion repetida no llena el historial', async () => {
  await conServidor({}, async ({ pedir }) => {
    const cuerpo = { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } };
    const a = await pedir('/api/run', { metodo: 'POST', cuerpo });
    const b = await pedir('/api/run', { metodo: 'POST', cuerpo });

    assert.equal(b.cuerpo.duplicado, true);
    assert.equal(b.cuerpo.id, a.cuerpo.id);
    assert.equal((await pedir('/api/historial')).cuerpo.total, 1);
  });
});

test('api/config no enseña ninguna credencial', async () => {
  await conServidor({}, async ({ pedir }) => {
    const r = await pedir('/api/config');
    assert.equal(r.status, 200);

    // Aunque haya una clave en el entorno, sale solo si esta o no.
    const texto = JSON.stringify(r.cuerpo);
    assert.equal(/ABUSEIPDB_API_KEY"\s*:\s*"/.test(texto), false);
    for (const p of r.cuerpo.perfilesCorreo || []) {
      assert.equal('PASS' in p, false, 'no sale el nombre de la variable de contrasena');
      assert.equal(typeof p.contrasena, 'boolean', 'solo se dice si hay contrasena');
    }
  });
});

test('una ruta de api inexistente da 404 en json, no el index', async () => {
  await conServidor({}, async ({ pedir }) => {
    const r = await pedir('/api/inventada');
    assert.equal(r.status, 404);
    assert.equal(r.cuerpo.error.code, 'RUTA_DESCONOCIDA');
  });
});

test('la pagina y sus ficheros se sirven con cabeceras de seguridad', async () => {
  await conServidor({}, async ({ base }) => {
    const pagina = await fetch(`${base}/`);
    assert.equal(pagina.status, 200);
    assert.match(pagina.headers.get('content-type'), /text\/html/);
    assert.equal(pagina.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(pagina.headers.get('x-frame-options'), 'DENY');
    // `default-src 'self'` es lo que permite no tener scripts en linea.
    assert.match(pagina.headers.get('content-security-policy'), /default-src 'self'/);
    assert.match(pagina.headers.get('content-security-policy'), /object-src 'none'/);

    // El HTML no se cachea: es el que apunta a los assets con hash, y cachearlo
    // es como se sirve una version vieja de la aplicacion.
    assert.equal(pagina.headers.get('cache-control'), 'no-cache');

    // Los JS y CSS se toman de lo que el propio HTML referencia, en vez de de
    // nombres escritos aqui: con `web/dist` los ficheros llevan hash y `app.js`
    // ya no existe, asi que una lista fija en el test solo podria estar
    // desactualizada.
    const cuerpo = await pagina.text();
    const assets = [...cuerpo.matchAll(/(?:src|href)="(\/assets\/[^"]+)"/g)].map((m) => m[1]);
    assert.ok(assets.length > 0, `el HTML no referencia assets: ${cuerpo}`);
    for (const asset of assets) {
      const r = await fetch(base + asset);
      assert.equal(r.status, 200, asset);
      // Con hash en el nombre, se pueden cachear para siempre.
      assert.match(r.headers.get('cache-control'), /immutable/, asset);
    }

    // El HTML no lleva scripts en linea, para que la CSP no tenga que abrirse.
    assert.equal(/<script(?![^>]*\bsrc=)/.test(cuerpo), false, 'no hay <script> sin src');
    assert.equal(/<style[\s>]/.test(cuerpo), false, 'no hay <style> en linea');
    assert.equal(/\son[a-z]+=/i.test(cuerpo), false, 'no hay manejadores on* en linea');
  });
});

test('las rutas del SPA se resuelven con el index, no con un 404', async () => {
  // Sin este fallback, recargar en `/historial` o abrir el enlace profundo a
  // una ejecucion devuelve 404: el servidor busca un fichero `historial` que no
  // existe, porque la ruta la resuelve el navegador.
  await conServidor({}, async ({ base }) => {
    for (const ruta of ['/historial', '/config', '/herramienta/smtp-validator', '/herramienta/smtp-validator?run=abc']) {
      const r = await fetch(`${base}${ruta}`);
      assert.equal(r.status, 200, ruta);
      assert.match(r.headers.get('content-type'), /text\/html/, ruta);
    }
  });
});

test('un asset que no existe sale 404, no el index', async () => {
  // Si el fallback cogiera tambien lo que tiene extension, un asset perdido
  // llegaria al navegador con un 200 de HTML y el fallo se veria como un error
  // de JavaScript en vez de como el 404 que es.
  await conServidor({}, async ({ base }) => {
    const r = await fetch(`${base}/assets/no-existe-1234.js`);
    assert.equal(r.status, 404);
  });
});

test('una ruta de API inexistente sigue siendo JSON, no el index', async () => {
  await conServidor({}, async ({ base }) => {
    const r = await fetch(`${base}/api/inventada`);
    assert.equal(r.status, 404);
    assert.match(r.headers.get('content-type'), /application\/json/);
    assert.equal((await r.json()).error.code, 'RUTA_DESCONOCIDA');
  });
});

test('el limite del cuerpo de la peticion se aplica antes de leerlo entero', async () => {
  await conServidor({}, async ({ base }) => {
    const enorme = 'x'.repeat(3 * 1024 * 1024);
    const respuesta = await fetch(`${base}/api/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool: 'dns-checker', params: { compararArchivo: true, archivoContenido: enorme } })
    });
    assert.ok([400, 413].includes(respuesta.status), `llego con estado ${respuesta.status}`);
  });
});

// ============================================== setup del administrador principal

test('sin usuarios, el sistema avisa de que falta el administrador principal', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  await conServidor({ auth: new Auth({ activo: true, usuarios }) }, async ({ pedir }) => {
    const r = await pedir('/api/setup/status');
    assert.equal(r.status, 200);
    assert.equal(r.cuerpo.completado, false);
    assert.equal(r.cuerpo.requiereSetup, true);
  });
});

test('el primer ingreso crea el administrador principal y cierra el setup', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  const auth = new Auth({ activo: true, usuarios });
  await conServidor({ auth }, async ({ pedir, entrar }) => {
    assert.equal((await pedir('/api/setup/status')).cuerpo.requiereSetup, true);

    // Sin sesion ni CSRF: es la unica ruta del sistema que se puede usar sin
    // tener cuenta, y por eso mismo tiene que cerrarse en cuanto deja de hacer
    // falta. Si exigiera sesion, no habria forma de crear la primera.
    const creado = await pedir('/api/setup/first-admin', {
      metodo: 'POST',
      cuerpo: { username: 'admin', password: 'la-clave-del-admin' }
    });
    assert.equal(creado.status, 201);
    assert.equal(creado.cuerpo.usuario.role, 'admin');

    // El setup queda cerrado para siempre.
    const estado = await pedir('/api/setup/status');
    assert.equal(estado.cuerpo.completado, true);
    assert.equal(estado.cuerpo.requiereSetup, false);

    const repetido = await pedir('/api/setup/first-admin', {
      metodo: 'POST',
      cuerpo: { username: 'intruso', password: 'la-clave-del-intruso' }
    });
    assert.equal(repetido.status, 403);
    assert.equal(repetido.cuerpo.error.code, 'SETUP_YA_COMPLETADO');
    assert.equal(usuarios.obtener('intruso'), null);

    // Y la cuenta creada sirve para entrar de verdad.
    const sesion = await entrar('admin', 'la-clave-del-admin');
    assert.equal(sesion.usuario, 'admin');
    assert.equal((await pedir('/api/usuarios', { cabeceras: sesion.cabeceras })).cuerpo.usuarios.length, 1);
  });
});

test('el setup inicial rechaza lo que no sirve como administrador', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  await conServidor({ auth: new Auth({ activo: true, usuarios }) }, async ({ pedir }) => {
    const sinCampos = await pedir('/api/setup/first-admin', { metodo: 'POST', cuerpo: {} });
    assert.equal(sinCampos.status, 400);
    assert.equal(sinCampos.cuerpo.error.code, 'FALTAN_DATOS');

    const claveCorta = await pedir('/api/setup/first-admin', {
      metodo: 'POST',
      cuerpo: { username: 'admin', password: 'corta' }
    });
    assert.equal(claveCorta.status, 400);
    assert.equal(claveCorta.cuerpo.error.code, 'PASSWORD_CORTA');

    assert.equal(usuarios.contar(), 0, 'un setup fallido no deja cuentas a medias');
  });
});

test('el setup no se pide cuando la autenticacion esta desactivada', async () => {
  // En local no hay nada que configurar: ya se corre como administrador, y pedir
  // una contrasena seria una pantalla inutil delante de la aplicacion.
  await conServidor({}, async ({ pedir }) => {
    const estado = await pedir('/api/setup/status');
    assert.equal(estado.cuerpo.completado, true);
    assert.equal(estado.cuerpo.requiereSetup, false);

    const intento = await pedir('/api/setup/first-admin', { metodo: 'POST', cuerpo: { username: 'x', password: '12345678' } });
    assert.equal(intento.status, 200);
    assert.equal(intento.cuerpo.ok, true);
  });
});

test('la creacion del administrador principal queda auditada', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const { Auditoria } = require('../src/server/auditoria');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  const auditoria = new Auditoria({ ruta: ':memory:' });
  await conServidor({ auth: new Auth({ activo: true, usuarios }), auditoria }, async ({ pedir, entrar }) => {
    await pedir('/api/setup/first-admin', { metodo: 'POST', cuerpo: { username: 'admin', password: 'la-clave-del-admin' } });

    // Quien creo la cuenta principal tiene que poder verlo: es el primer hecho
    // de la auditoria de cualquier despliegue, y es la prueba de que la primera
    // cuenta fue la que se quiso y no una que colara otro.
    const sesion = await entrar('admin', 'la-clave-del-admin');
    const r = await pedir('/api/auditoria?tipo=setup_admin_creado', { cabeceras: sesion.cabeceras });

    assert.equal(r.status, 200);
    assert.equal(r.cuerpo.total, 1);
    assert.equal(r.cuerpo.items[0].usuario, 'admin');
    assert.ok(r.cuerpo.items[0].ip, 'el evento guarda la IP de origen');
  });
});

// ==================================================== compartir y revocar

test('revocar un enlace inexistente da 404 en json, no un 500', async () => {
  // ESTA PRUEBA EXISTE POR UN FALLO REAL: el handler leia `revogado` (con g) y
  // nunca habia definido esa variable. La revocacion funcionaba escribiendo la
  // auditoria primero (con el tipo mal escrito) y luego reventaba con un
  // ReferenceError que terminaba en 500. Hasta el error daba una respuesta que
  // no era la de la persona que intenta revocar un enlace ya muerto.
  await conServidor({}, async ({ pedir }) => {
    const r = await pedir('/api/compartir/nunca-existio', { metodo: 'DELETE' });
    assert.equal(r.status, 404);
    assert.equal(r.cuerpo.revocado, false);
    assert.equal(r.cuerpo.error, undefined, 'la revocacion fallida responde en formato de revocacion');
  });
});

test('revocar un enlace que si existe devuelve 200 y lo audita con el tipo correcto', async () => {
  const { Auditoria } = require('../src/server/auditoria');
  await conServidor({ auditoria: new Auditoria({ ruta: ':memory:' }) }, async ({ pedir }) => {
    const run = await pedir('/api/run', { metodo: 'POST', cuerpo: { tool: 'subnet-analyzer', params: { red: '10.0.0.0/24' } } });
    const compartido = await pedir('/api/compartir', { metodo: 'POST', cuerpo: { ejecucionId: run.cuerpo.id } });
    assert.equal(compartido.status, 200);

    const token = compartido.cuerpo.shareUrl.split('/').pop();
    const revocado = await pedir(`/api/compartir/${token}`, { metodo: 'DELETE' });
    assert.equal(revocado.status, 200, 'revocar un enlace vivo no puede ser un 500');
    assert.equal(revocado.cuerpo.revocado, true);

    // El tipo de evento es el del enumerado, no un texto pegado a mano: la
    // interfaz de auditoria agrupa por tipo, y un typo partiria la historia en dos.
    const log = await pedir('/api/auditoria?tipo=compartir_revocado');
    assert.equal(log.cuerpo.total, 1);
    assert.equal(log.cuerpo.items[0].detalles.shareToken, token);
  });
});

// ================================================================= backups

/** Base de fichero de mentira para que VACUUM INTO tenga algo que copiar. */
function baseDeFichero() {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const { DatabaseSync } = require('node:sqlite');
  const directorio = fs.mkdtempSync(path.join(os.tmpdir(), 'netlab-server-backup-'));
  const ruta = path.join(directorio, 'netlab.db');
  const db = new DatabaseSync(ruta);
  db.exec('CREATE TABLE t (a INTEGER)');
  db.prepare('INSERT INTO t VALUES (?)').run(7);
  db.close();
  return { ruta, directorio };
}

test('GET /api/backups solo lo ve quien puede administrar', async () => {
  const { Usuarios } = require('../src/server/usuarios');
  const usuarios = new Usuarios({ ruta: ':memory:' });
  usuarios.crear({ username: 'ana', password: 'password123', role: 'admin' });
  const { ruta, directorio } = baseDeFichero();
  const fs = require('node:fs');
  try {
    await conServidor({ auth: new Auth({ activo: true, usuarios }), backup: new Backup({ ruta, directorio }) }, async ({ pedir, entrar }) => {
      assert.equal((await pedir('/api/backups')).status, 401, 'sin sesion no se lista nada');
      const sesion = await entrar('ana', 'password123');
      const r = await pedir('/api/backups', { cabeceras: sesion.cabeceras });
      assert.equal(r.status, 200);
      assert.equal(Array.isArray(r.cuerpo.backups), true);
      assert.equal(r.cuerpo.retencion, 7);
      assert.equal(r.cuerpo.hora, 3);
    });
  } finally {
    fs.rmSync(directorio, { recursive: true, force: true });
  }
});

test('POST /api/backups crea una copia y deja rastro en la auditoria', async () => {
  const { Auditoria } = require('../src/server/auditoria');
  const fs = require('node:fs');
  const { ruta, directorio } = baseDeFichero();
  try {
    await conServidor({ auditoria: new Auditoria({ ruta: ':memory:' }), backup: new Backup({ ruta, directorio }) }, async ({ pedir }) => {
      const hecho = await pedir('/api/backups', { metodo: 'POST' });
      assert.equal(hecho.status, 201, 'una copia bien hecha responde 201');
      assert.ok(hecho.cuerpo.backup.nombre, 'el nombre de la copia');
      assert.ok(hecho.cuerpo.backup.tamano > 0, 'la copia pesa algo');

      const lista = await pedir('/api/backups');
      assert.equal(lista.cuerpo.backups.length, 1);

      const log = await pedir('/api/auditoria?tipo=backup_realizado');
      assert.equal(log.cuerpo.total, 1);
      assert.equal(log.cuerpo.items[0].detalles.nombre, hecho.cuerpo.backup.nombre);

      // Una segunda copia deja dos. El nombre lleva segundos, asi que hay que
      // esperar a que cambie: dos copias en el mismo segundo son la misma.
      await new Promise((r) => setTimeout(r, 1100));
      assert.equal((await pedir('/api/backups', { metodo: 'POST' })).status, 201);
      assert.equal((await pedir('/api/backups')).cuerpo.backups.length, 2);
    });
  } finally {
    fs.rmSync(directorio, { recursive: true, force: true });
  }
});

test('POST /api/backups sin base responde el error con recomendacion', async () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const directorio = fs.mkdtempSync(path.join(os.tmpdir(), 'netlab-server-backup-'));
  try {
    await conServidor({ backup: new Backup({ ruta: path.join(directorio, 'no-existe.db'), directorio }) }, async ({ pedir }) => {
      const r = await pedir('/api/backups', { metodo: 'POST' });
      assert.equal(r.status, 404);
      assert.equal(r.cuerpo.error.code, 'FICHERO_NO_ENCONTRADO');
      assert.ok(r.cuerpo.error.remediation, 'se dice que hacer con el fallo');
    });
  } finally {
    fs.rmSync(directorio, { recursive: true, force: true });
  }
});
