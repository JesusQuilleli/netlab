'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const spamhaus = require('../src/core/net/spamhaus');
const { NetlabError, CODES } = require('../src/core/errors');

const IP = '203.0.113.7';
const CLAVE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/**
 * Doble de `dns.consultar`.
 *
 * Se responde por el ULTIMO octeto de la respuesta, que es como se comporta el
 * DNS de verdad: el nombre se busca y el codigo dice que lista ha-developped.
 */
function dnsQueDevuelve(ip) {
  return async (nombre, tipo) => {
    assert.equal(tipo, 'A', 'una zona de lista negra se pregunta con registros A');
    if (ip === null) {
      // NXDOMAIN: el nombre no existe. Es la respuesta de "no listada".
      return { ok: false, valores: [], ttl: null, error: 'no such name', codigo: CODES.NO_ENCONTRADO, codigoDns: 'ENOTFOUND' };
    }
    return { ok: true, valores: [ip], ttl: 60, error: null, codigo: null, codigoDns: null };
  };
}

/** Un fallo de red: la zona no contesta y no es por culpa de la IP. */
const dnsCaido = async () => ({
  ok: false,
  valores: [],
  ttl: null,
  error: 'ETIMEDOUT',
  codigo: CODES.TIMEOUT,
  codigoDns: 'ETIMEDOUT'
});

// --------------------------------------------------------------- sintaxis DNS

test('la clave va en el nombre, delante de todo, y la zona es .net', () => {
  // Esto es lo unico que hace DQS distinto de las zonas publicas: el acceso va
  // en el nombre. Sin la clave delante, esto es una zona que no existe.
  const nombre = spamhaus.nombreConsulta(IP, 'zen', CLAVE);

  assert.equal(nombre, `${CLAVE}.113.0.203.zen.dq.spamhaus.net`);
  assert.ok(nombre.endsWith('.dq.spamhaus.net'), 'las zonas de DQS son .net, no .org');
  assert.ok(!nombre.includes('.org'), 'una zona .org con clave delante no funciona');
});

test('cada zona quita el ultimo octeto si su ficha lo dice', () => {
  // ZEN y SBL son por /24: preguntar por la IP entera devuelve "no existe"
  // siempre, y el resultado seria "no listada" sin haber preguntado nada.
  assert.equal(spamhaus.nombreConsulta(IP, 'zen', CLAVE), `${CLAVE}.113.0.203.zen.dq.spamhaus.net`);
  assert.equal(spamhaus.nombreConsulta(IP, 'sbl', CLAVE), `${CLAVE}.113.0.203.sbl.dq.spamhaus.net`);

  // XBL, PBL y AuthBL sí van por IP completa.
  assert.equal(spamhaus.nombreConsulta(IP, 'xbl', CLAVE), `${CLAVE}.7.113.0.203.xbl.dq.spamhaus.net`);
  assert.equal(spamhaus.nombreConsulta(IP, 'pbl', CLAVE), `${CLAVE}.7.113.0.203.pbl.dq.spamhaus.net`);
  assert.equal(spamhaus.nombreConsulta(IP, 'authbl', CLAVE), `${CLAVE}.7.113.0.203.authbl.dq.spamhaus.net`);
});

test('una IPv6 se pone en nibbles, y no en bytes', () => {
  const nombre = spamhaus.nombreConsulta('2001:db8::1', 'xbl', CLAVE);

  // Los bytes al reves darian un nombre que existe pero nunca contesta lo que
  // se le pregunta, que es un "no listada" falso sin ningun error visible.
  assert.ok(nombre.includes('.1.0.0.2.'), 'el orden tiene que ser el de los nibbles');
  assert.ok(nombre.endsWith('.xbl.dq.spamhaus.net'));
});

test('ninguna zona monta un nombre sin la clave delante', () => {
  // Un nombre construido sin clave no es "consulta sin permiso": es un nombre
  // que no existe, y su respuesta es "no listada" sin haber preguntado a nadie.
  for (const lista of spamhaus.LISTAS_DQS.map((l) => l.clave)) {
    assert.ok(
      spamhaus.nombreConsulta(IP, lista, CLAVE).startsWith(`${CLAVE}.`),
      `${lista} tiene que llevar la clave`
    );
  }
});

// ------------------------------------------------------------------ BCL

test('BCL no se puede consultar en DQS, y el error lo explica', () => {
  // Esta es la razon de ser de media parte de este modulo. BCL, la lista de IPs
  // que controlan bots, no esta en el pack gratuito ni en el comercial por
  // DNS Query. Ofrecerla aqui seria prometer un dato que no existe.
  assert.ok(!spamhaus.LISTAS_DQS.some((l) => l.clave === 'bcl'));

  assert.throws(
    () => spamhaus.nombreConsulta(IP, 'bcl', CLAVE),
    (error) => {
      assert.ok(error instanceof NetlabError);
      assert.equal(error.code, CODES.PARAM_INVALIDO);
      // El mensaje tiene que decir donde esta BCL, no solo "no existe".
      assert.match(error.remediation, /resolvedores registrados/);
      return true;
    }
  );
});

test('tampoco se ofrece BCL "por si acaso", ni como zona libre', () => {
  for (const nombre of spamhaus.LISTAS_DQS.map((l) => l.clave)) {
    assert.notEqual(nombre, 'bcl');
  }
});

// ------------------------------------------------------------- interpretacion

test('el codigo de respuesta dice en que sublista esta', () => {
  // El ultimo octeto no es un 1 cualquiera: identifica la sublista. Sin esto,
  // el informe solo puede decir "listada", que es menos de lo que la respuesta
  // ya sabe.
  const casos = [
    ['127.0.0.2', 'SBL'],
    ['127.0.0.3', 'CSS'],
    ['127.0.0.4', 'XBL'],
    ['127.0.0.9', 'DROP'],
    ['127.0.0.10', 'PBL'],
    ['127.0.0.20', 'AuthBL']
  ];

  for (const [codigo, sublista] of casos) {
    const r = spamhaus.interpretarRespuesta(codigo);
    assert.equal(r.estado, spamhaus.ESTADOS.LISTADA, `${codigo} es "listada"`);
    assert.equal(r.sublista.nombre, sublista, `${codigo} es ${sublista}`);
    assert.ok(r.motivo, `${codigo} tiene que traer un motivo legible`);
  }
});

test('un 127.255.255.x es "no he dado datos", nunca "no listada"', () => {
  // El fallo mas caro de este modulo seria traducir esto a "no listada": el
  // informe cerraria un caso sin que nadie haya preguntado.
  for (const codigo of ['127.255.255.252', '127.255.255.254', '127.255.255.255']) {
    const r = spamhaus.interpretarRespuesta(codigo);
    assert.equal(r.estado, spamhaus.ESTADOS.DESCONOCIDO, `${codigo} no es un veredicto`);
    assert.ok(r.advertencia, `${codigo} tiene que explicar que no sabe`);
  }

  // Y el 254, que es el "no te contesto" clasico, se reconoce aparte.
  const sinAcceso = spamhaus.interpretarRespuesta(spamhaus.SIN_ACCESO);
  assert.match(sinAcceso.advertencia, /no esta registrado/);
});

test('un nombre inexistente es "no listada", y no un fallo', () => {
  const r = spamhaus.interpretarRespuesta('');
  assert.equal(r.estado, spamhaus.ESTADOS.NO_LISTADA);
  assert.equal(r.advertencia, null, 'no listada es un resultado, no un aviso');
});

test('un codigo de listada desconocido se dice, en vez de inventarse una sublista', () => {
  const r = spamhaus.interpretarRespuesta('127.0.0.77');

  assert.equal(r.estado, spamhaus.ESTADOS.LISTADA);
  assert.equal(r.sublista, null, 'no se inventa una sublista');
  assert.match(r.advertencias || r.advertencia, /sublista nueva/);
});

// ------------------------------------------------------------------ consultar

test('sin clave no se consulta, y el mensaje dice donde se pide una', async () => {
  let llamado = false;
  const consultarDns = async () => {
    llamado = true;
    return { ok: true, valores: ['127.0.0.2'], ttl: 60, error: null, codigo: null, codigoDns: null };
  };

  await assert.rejects(
    () => spamhaus.consultar(IP, { consultarDns }),
    (error) => {
      assert.ok(error instanceof NetlabError);
      assert.equal(error.code, CODES.CREDENCIAL_AUSENTE);
      assert.match(error.remediation, /portal\.spamhaus\.com\/auth\/account-setup/);
      return true;
    }
  );

  assert.equal(llamado, false, 'sin clave no se hace ninguna consulta DNS');
});

test('una IP listada trae el codigo, la sublista y el motivo', async () => {
  const r = await spamhaus.consultar(IP, { clave: CLAVE, lista: 'sbl', consultarDns: dnsQueDevuelve('127.0.0.2') });

  assert.equal(r.estado, spamhaus.ESTADOS.LISTADA);
  assert.equal(r.codigo, '127.0.0.2');
  assert.equal(r.sublista, 'SBL');
  assert.equal(r.ipRespuesta, '127.0.0.2');
  assert.match(r.motivo, /Spamhaus Blocklist/);
  assert.ok(r.consultadoEn);
  // Y avisa de que quitarlo no es automatico: sin esto, "listada" se lee como
  // "solvable en cinco minutos".
  assert.ok(r.advertencias.some((a) => /no es automatico/.test(a)));
});

test('NXDOMAIN sale como "no listada" y no como error', async () => {
  // Con clave puesta, NXDOMAIN es una respuesta legitima: la IP no esta en esa
  // lista. Tratarlo como fallo daria un informe lleno de errores en IPs limpias.
  const r = await spamhaus.consultar(IP, { clave: CLAVE, consultarDns: dnsQueDevuelve(null) });

  assert.equal(r.estado, spamhaus.ESTADOS.NO_LISTADA);
  assert.equal(r.codigo, null);
  assert.deepEqual(r.advertencias, []);
});

test('un fallo de red sale como desconocido, con su motivo', async () => {
  const r = await spamhaus.consultar(IP, { clave: CLAVE, consultarDns: dnsCaido });

  assert.equal(r.estado, spamhaus.ESTADOS.DESCONOCIDO);
  assert.match(r.advertencias.join(' '), /ETIMEDOUT/);
});

test('la clave NO sale en el informe, ni dentro de un error de DNS', async () => {
  // La clave viaja dentro del nombre de la zona, asi que cualquier error de DNS
  // se la lleva en el mensaje. Y ese mensaje acaba en un informe que se puede
  // exportar y enviar a alguien. Una credencial dentro de un PDF compartido es
  // una credencial quemada.
  //
  // Este caso no es hipotetico: con la cuenta sin activar, todas las zonas dan
  // SERVFAIL y el nombre entero, clave incluida, va al informe.
  const errorConClave = `El servidor de nombres no pudo completar la consulta al consultar A de ${CLAVE}.0.0.127.zen.dq.spamhaus.net (SERVFAIL).`;
  const consultarDns = async () => ({ ok: false, valores: [], ttl: null, error: errorConClave, codigo: CODES.TIMEOUT, codigoDns: 'ESERVFAIL' });

  const r = await spamhaus.consultar(IP, { clave: CLAVE, lista: 'zen', consultarDns });

  const todo = JSON.stringify(r);
  assert.ok(!todo.includes(CLAVE), 'la clave no puede aparecer en ninguna parte del resultado');
  // Y tiene que quedar claro que es una credencial, no un fallo de red normal.
  assert.match(todo, /\*{10,}YZ/, 'la clave sale enmascarada, con los dos ultimos digitos');
});

test('enmascararClave deja los dos ultimos digitos y tapa el resto', () => {
  const tapada = spamhaus.enmascararClave(`nombre ${CLAVE}.zen.dq.spamhaus.net`, CLAVE);

  assert.ok(!tapada.includes(CLAVE));
  assert.ok(tapada.endsWith('YZ.zen.dq.spamhaus.net'), 'sigue siendo legible como nombre de zona');

  // Los ultimos cuatro NO valen: con cuatro se puede comprobar una clave
  // probando las 36^4 combinaciones. Con dos no.
  assert.ok(!tapada.includes(CLAVE.slice(-4)));

  // Y sin clave o sin texto no rompe nada.
  assert.equal(spamhaus.enmascararClave('', CLAVE), '');
  assert.equal(spamhaus.enmascararClave('texto', ''), 'texto');
});

test('una IP invalida se rechaza antes de tocar el DNS', async () => {
  let llamado = false;
  await assert.rejects(
    () => spamhaus.consultar('no es una ip', { clave: CLAVE, consultarDns: async () => { llamado = true; } }),
    (error) => {
      assert.equal(error.code, CODES.PARAM_INVALIDO);
      return true;
    }
  );
  assert.equal(llamado, false);
});

test('una zona invalida se rechaza antes que la clave ausente', async () => {
  // El orden importa: un nombre de zona malo es un error de quien escribe la
  // llamada, y reportarlo como "falta la clave" manda a buscar una clave que ya
  // se tiene.
  await assert.rejects(
    () => spamhaus.consultar(IP, { lista: 'inventada' }),
    (error) => {
      assert.equal(error.code, CODES.PARAM_INVALIDO, 'es un parametro malo, no una credencial ausente');
      return true;
    }
  );
});

// ------------------------------------------------------------------ varias

test('consultarVarias guarda cada zona por separado', async () => {
  const r = await spamhaus.consultarVarias(IP, {
    clave: CLAVE,
    listas: ['zen', 'sbl'],
    consultarDns: async (nombre) =>
      nombre.includes('.sbl.') ? dnsQueDevuelve('127.0.0.2')(nombre, 'A') : dnsQueDevuelve(null)(nombre, 'A')
  });

  assert.equal(r.resultados.length, 2);
  assert.equal(r.resultados.find((x) => x.lista === 'sbl').estado, spamhaus.ESTADOS.LISTADA);
  assert.equal(r.resultados.find((x) => x.lista === 'zen').estado, spamhaus.ESTADOS.NO_LISTADA);
  assert.equal(r.algunoListada, true);
  assert.equal(r.algunoDesconocido, false);
  assert.equal(r.errores.length, 0);
});

test('una zona que falla no borra el resultado de las otras', async () => {
  // Si al caer una zona se perdiera todo, el informe pasaria de "te tienen
  // listada en ZEN" a "no se ha podido comprobar", que es el cambio que hace
  // que alguien cierre el caso sin mirarlo.
  const r = await spamhaus.consultarVarias(IP, {
    clave: CLAVE,
    listas: ['zen', 'sbl'],
    consultarDns: async (nombre, tipo) =>
      nombre.includes('.zen.') ? dnsQueDevuelve('127.0.0.2')(nombre, tipo) : dnsCaido(nombre, tipo)
  });

  const zen = r.resultados.find((x) => x.lista === 'zen');
  const sbl = r.resultados.find((x) => x.lista === 'sbl');

  // La que contesta conserva su veredicto...
  assert.equal(zen.estado, spamhaus.ESTADOS.LISTADA);
  assert.equal(zen.codigo, '127.0.0.2');

  // ...y la que no contesta se queda como "no se sabe", con el motivo puesto, en
  // vez de desaparecer del informe.
  assert.equal(sbl.estado, spamhaus.ESTADOS.DESCONOCIDO);
  assert.match(sbl.advertencias.join(' '), /ETIMEDOUT/);

  assert.equal(r.algunoListada, true);
  assert.equal(r.algunoDesconocido, true);
});

test('una zona que ni siquiera existe va a errores, sin tumbar la consulta', async () => {
  // Un nombre de zona invalido es un error de quien escribe la llamada, no un
  // problema de la zona. Se separa para no mezclarlo con "Spamhaus no contesta".
  const r = await spamhaus.consultarVarias(IP, {
    clave: CLAVE,
    listas: ['zen', 'inventada'],
    consultarDns: dnsQueDevuelve(null)
  });

  assert.equal(r.resultados.length, 1);
  assert.equal(r.resultados[0].lista, 'zen');
  assert.equal(r.errores.length, 1);
  assert.equal(r.errores[0].lista, 'inventada');
  assert.match(r.errores[0].mensaje, /no existe en DQS/);
});

test('consultarVarias sin clave lanza, y no devuelve un vacio tranquilo', async () => {
  await assert.rejects(
    () => spamhaus.consultarVarias(IP, { consultarDns: dnsQueDevuelve(null) }),
    (error) => {
      assert.equal(error.code, CODES.CREDENCIAL_AUSENTE);
      return true;
    }
  );
});