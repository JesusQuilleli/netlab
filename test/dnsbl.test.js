'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const dnsbl = require('../src/core/net/dnsbl');
const dns = require('../src/core/net/dns');

/** Respuestas DNS prefabricadas, en el mismo formato que devuelve `core/net/dns`. */
function rnx() { return { ok: true, valores: [], ttl: null, error: null, codigoDns: 'ENOTFOUND' }; }
function rtxt(...valores) { return { ok: true, valores, ttl: 60, error: null, codigoDns: 'NOERROR' }; }
function rtxtChunks(...filas) { return { ok: true, valores: filas, ttl: 60, error: null, codigoDns: 'NOERROR' }; }
function rfail(codigo, mensaje) { return { ok: false, valores: [], ttl: null, error: mensaje || codigo, codigoDns: codigo }; }

const IP = '203.0.113.10';

// ---------------------------------------------------------------- consultas

test('las zonas se piden por direccion invertida, con el ultimo octeto fuera', () => {
  // 203.0.113.10 pegada seria 10.113.0.203.zen... y Spamhaus devuelve NXDOMAIN
  // siempre. El "no listada" seria inventado.
  assert.equal(dnsbl.nombreDeConsulta(IP, { zona: 'zen.spamhaus.org', quitarUltimoOcteto: true }), '113.0.203.zen.spamhaus.org');
  assert.equal(dnsbl.nombreDeConsulta(IP, { zona: 'bl.spamcop.net' }), '10.113.0.203.bl.spamcop.net');
});

test('el nombre de consulta NO lleva la zona inversa pegada en medio', () => {
  // Este es un fallo que ya estuvo en produccion, y merece su propio test porque
  // es del tipo que no da error visible: nada falla, el informe sale, y la zona
  // responde NXDOMAIN siempre, que es justo lo que devuelve una IP limpia.
  //
  // El sufijo `.in-addr.arpa` (o `.ip6.arpa`) pertenece a la zona inversa del
  // DNS, no a las zonas de lista negra. Pegado en medio produce
  // `10.113.0.203.in-addr.arpa.bl.spamcop.net`, un nombre que no existe en
  // ninguna parte del arbol, para cualquier IP y para cualquier lista.
  for (const zona of ['bl.spamcop.net', 'zen.spamhaus.org', 'dnsbl-1.uceprotect.net']) {
    const nombre = dnsbl.nombreDeConsulta(IP, { zona });
    assert.ok(nombre, 'deberia construir el nombre');
    assert.ok(!nombre.includes('in-addr.arpa'), `${nombre} no puede llevar in-addr.arpa`);
    assert.ok(nombre.endsWith(`.${zona}`), `${nombre} deberia terminar en ${zona}`);
    assert.equal(nombre.split('.').length, 4 + zona.split('.').length);
  }
});

test('octetosInvertidos quita la zona inversa y deja solo los octetos', () => {
  assert.equal(dnsbl.octetosInvertidos(IP), '10.113.0.203');
  assert.equal(dnsbl.octetosInvertidos('166.1.88.195'), '195.88.1.166');
  assert.equal(dnsbl.octetosInvertidos('no es una ip'), null);
});

test('sin zona no se inventa un nombre que no existe', () => {
  assert.equal(dnsbl.nombreDeConsulta(IP, {}), null);
  assert.equal(dnsbl.nombreDeConsulta('no es una ip', { zona: 'zen.spamhaus.org' }), null);
});

// ---------------------------------------------------------------- estados

test('NXDOMAIN es que no hay registro, es decir, no listada', () => {
  const r = dnsbl.interpretarRespuesta(rnx());
  assert.equal(r.estado, dnsbl.ESTADOS.LIMPIA);
  assert.equal(r.codigo, null);
  assert.equal(r.error, null);
});

test('una respuesta 127.x.x.x significa listada, y el codigo es el ultimo grupo', () => {
  const r = dnsbl.interpretarRespuesta(rtxt('127.0.0.2'));
  assert.equal(r.estado, dnsbl.ESTADOS.LISTADA);
  assert.equal(r.codigo, '127.0.0.2');

  // El codigo no es solo decoracion: es lo que dice el motivo de la vez.
  assert.equal(dnsbl.interpretarRespuesta(rtxt('127.0.0.10')).codigo, '127.0.0.10');
  assert.equal(dnsbl.interpretarRespuesta(rtxt('127.0.0.3')).codigo, '127.0.0.3');
});

test('solo se acepta 127.0.0.0/8 como respuesta de listado', () => {
  // Una zona mal configurar puede devolver cualquier A. Darlo por bueno
  // acusaria a una IP limpia, que es el peor fallo posible en un informe.
  for (const valor of ['8.8.8.8', 'esto no es una IP', '127.0.0', '126.0.0.2']) {
    const r = dnsbl.interpretarRespuesta(rtxt(valor));
    assert.equal(r.estado, dnsbl.ESTADOS.SIN_DATOS, `${valor} no puede ser un listado`);
    assert.equal(r.codigo, null);
    assert.match(r.error, /no es una direccion de listado/);
  }

  // Y dentro de 127/8 valen los codigos de listado de verdad, que son 127.0.x.x
  // y 127.1.x.x. El resto de 127/8 que se usa son diagnosticos, y se tratan
  // aparte: ver el test siguiente.
  for (const valor of ['127.0.0.2', '127.0.0.3', '127.0.0.10', '127.0.0.11', '127.0.1.2', '127.1.2.3']) {
    assert.equal(dnsbl.interpretarRespuesta(rtxt(valor)).estado, dnsbl.ESTADOS.LISTADA, `${valor} si es un listado`);
  }
});

test('127.255.255.0/24 es diagnostico de Spamhaus, jamas un listado', () => {
  // Este es el fallo mas caro que puede tener este modulo, asi que va con test
  // propio y con casos de cada codigo.
  //
  // 127.255.255.0/24 es el bloque que Spamhaus reserva para responder "no te voy
  // a contestar", no para listar a nadie. Comprobado contra las entradas de
  // prueba que publica el propio Spamhaus, que deben devolver SIEMPRE codigo de
  // listado:
  //
  //     127.0.0.2  ->  127.255.255.254      (deberia ser 127.0.0.2)
  //
  // Si ese 127.255.255.254 se aceptara como listado, el informe acusaria a una
  // IP de ser un controlador de botnet cuando lo unico que ha pasado es que no
  // nos han dejado mirar. Un informe que se inventa un listado es peor que uno
  // que no dice nada.
  const codigos = {
    '127.255.255.2': /tipo de consulta no valido/,
    '127.255.255.252': /direccion de consulta mal formada o acceso no concedido/,
    '127.255.255.254': /no esta registrado en Spamhaus/,
    '127.255.255.255': /volumen/
  };

  for (const [codigo, attendu] of Object.entries(codigos)) {
    const r = dnsbl.interpretarRespuesta(rtxt(codigo));

    assert.equal(r.estado, dnsbl.ESTADOS.SIN_DATOS, `${codigo} no puede ser "listada"`);
    assert.notEqual(r.estado, dnsbl.ESTADOS.LISTADA);
    // El codigo SI se guarda, y esta a proposito: es la prueba que permite leer
    // de donde salio el "sin datos" en vez de tener que fiarse del texto.
    assert.equal(r.codigo, codigo);
    assert.match(r.error, attendu);
  }
});

test('cualquier 127.255.255.x se trata como diagnostico, tenga codigo conocido o no', () => {
  // El bloque entero se reserva, no solo los codigos de la tabla. Si Spamhaus
  // anade uno nuevo, tiene que seguir siendo "sin datos" sin tocar el codigo.
  for (const codigo of ['127.255.255.1', '127.255.255.99', '127.255.255.128', '127.255.255.253']) {
    const r = dnsbl.interpretarRespuesta(rtxt(codigo));
    assert.equal(r.estado, dnsbl.ESTADOS.SIN_DATOS, `${codigo} no puede ser "listada"`);
    assert.equal(dnsbl.esDiagnostico(codigo), true);
  }

  // Y el limite del bloque: ni 127.255.254.x ni 127.0.0.255 son diagnostico.
  assert.equal(dnsbl.esDiagnostico('127.255.254.254'), false);
  assert.equal(dnsbl.esDiagnostico('127.0.0.2'), false);
});

test('SERVFAIL y los timeouts son sin datos, nunca "no listada"', () => {
  // Esta es la diferencia que mas importa de todo el modulo: un "no listada"
  // inventado por un fallo de red manda a leer un informe con una seguridad que
  // no tiene.
  for (const codigo of ['ESERVFAIL', 'ETIMEOUT', 'EREFUSED']) {
    const r = dnsbl.interpretarRespuesta(rfail(codigo));
    assert.equal(r.estado, dnsbl.ESTADOS.SIN_DATOS, codigo + ' no puede ser "limpia"');
  }
});

test('ENODATA y ENODOMAIN tambien son "no hay registro"', () => {
  for (const codigo of ['ENOTFOUND', 'ENODATA', 'ENODOMAIN']) {
    assert.equal(dnsbl.interpretarRespuesta(rfail(codigo)).estado, dnsbl.ESTADOS.LIMPIA);
  }
});

// ---------------------------------------------------------------- consultar

/** Sustituye `core/net/dns` para poder dictar las respuestas por nombre. */
function conDns(respuestas) {
  return {
    consultarLote: async (consultas) => consultas.map((c) => {
      const r = respuestas[c.nombre];
      if (typeof r === 'function') return r(c);
      return r || rnx();
    })
  };
}

/**
 * El mismo doble, pero dando por hecho que el resolvedor esta registrado en
 * Spamhaus.
 *
 * Almost todos los tests de este archivo escriben zonas de Spamhaus con
 * listados reales, y con el canario de por medio eso solo funciona si el canario
 * tambien responde como lo haria un resolvedor registrado. Ponerlo aqui evita
 * tener que repetirlo en cada test, y deja claro cual es el caso raro: el de
 * verdad sin registro, que se escribe a mano cuando se quiere probar.
 */
function conDnsRegistrado(respuestas) {
  return conDns({ '3.0.0.127.zen.spamhaus.org': rtxt('127.0.0.3'), ...respuestas });
}

test('consultar reparte los resultados de vuelta a su lista, en orden', () => {
  const listas = [
    { clave: 'uno', nombre: 'Uno', proveedor: 'Uno', zona: 'uno.example' },
    { clave: 'dos', nombre: 'Dos', proveedor: 'Dos', zona: 'dos.example' }
  ];

  return dnsbl.consultar(IP, {
    listas,
    dns: conDns({
      '10.113.0.203.uno.example': rtxt('127.0.0.2'),
      '10.113.0.203.dos.example': rnx()
    })
  }).then((r) => {
    assert.equal(r.resultados.length, 2);
    assert.equal(r.resultados[0].nombre, 'Uno');
    assert.equal(r.resultados[0].estado, dnsbl.ESTADOS.LISTADA);
    assert.equal(r.resultados[1].nombre, 'Dos');
    assert.equal(r.resultados[1].estado, dnsbl.ESTADOS.LIMPIA);
    assert.equal(r.resumen.listadas, 1);
    assert.equal(r.resumen.limpias, 1);
  });
});

test('el motivo se pide en TXT, y solo para las IP listadas', async () => {
  const pedidas = [];
  const listas = [
    { clave: 'uno', nombre: 'Uno', proveedor: 'Uno', zona: 'uno.example' },
    { clave: 'dos', nombre: 'Dos', proveedor: 'Dos', zona: 'dos.example' }
  ];

  const dnsDoble = {
    consultarLote: (consultas) => {
      for (const c of consultas) {
        pedidas.push(c);
        if (c.tipo === 'TXT') {
          return consultas.map(() => rtxtChunks(['Spam', ' relay']));
        }
      }
      return consultas.map((c) => (c.nombre.includes('uno') ? rtxt('127.0.0.2') : rnx()));
    }
  };

  const r = await dnsbl.consultar(IP, { listas, dns: dnsDoble, motivos: true });

  const txt = pedidas.filter((c) => c.tipo === 'TXT');
  assert.equal(txt.length, 1, 'solo se pregunta el motivo de la que esta listada');
  assert.ok(txt[0].nombre.endsWith('uno.example'));

  // Las partes de un TXT van sueltas y hay que juntarlas.
  assert.equal(r.resultados[0].motivo, 'Spam relay');
  assert.equal(r.resultados[1].motivo, null);
});

test('sin pedir motivos no sale ninguna consulta TXT', async () => {
  const tipos = [];
  const listas = [{ clave: 'uno', nombre: 'Uno', proveedor: 'Uno', zona: 'uno.example' }];

  await dnsbl.consultar(IP, {
    listas,
    motivos: false,
    dns: {
      consultarLote: (consultas) => {
        tipos.push(...consultas.map((c) => c.tipo));
        return consultas.map(() => rtxt('127.0.0.2'));
      }
    }
  });

  assert.deepEqual([...new Set(tipos)], ['A']);
});

test('una zona caida no arrastra a las demas, y se cuenta aparte', async () => {
  const listas = [
    { clave: 'caida', nombre: 'Caida', proveedor: 'Caida', zona: 'caida.example' },
    { clave: 'ok', nombre: 'Ok', proveedor: 'Ok', zona: 'ok.example' }
  ];

  const r = await dnsbl.consultar(IP, {
    listas,
    motivos: false,
    dns: conDns({
      '10.113.0.203.caida.example': rfail('ESERVFAIL', 'SERVFAIL'),
      '10.113.0.203.ok.example': rnx()
    })
  });

  assert.equal(r.resumen.sinDatos, 1);
  assert.equal(r.resumen.limpias, 1);
  assert.equal(r.resultados[0].estado, dnsbl.ESTADOS.SIN_DATOS);
  assert.ok(r.resultados[0].error, 'el fallo queda a la vista');
});

test('el resumen cuenta operadores distintos, no zonas', async () => {
  // Tres zonas de Spamhaus son un unico operador diciendo tres veces lo mismo.
  // Si se contasen zonas, un unico operador pasaria por tres fuentes y el
  // veredicto saldria mas grave de lo que es.
  const listas = [
    { clave: 'zen', nombre: 'ZEN', proveedor: 'Spamhaus', zona: 'zen.spamhaus.org', quitarUltimoOcteto: true },
    { clave: 'xbl', nombre: 'XBL', proveedor: 'Spamhaus', zona: 'xbl.spamhaus.org', quitarUltimoOcteto: true },
    { clave: 'sbl', nombre: 'SBL', proveedor: 'Spamhaus', zona: 'sbl.spamhaus.org', quitarUltimoOcteto: true },
    { clave: 'sc', nombre: 'SpamCop', proveedor: 'SpamCop', zona: 'bl.spamcop.net' }
  ];

  const r = await dnsbl.consultar(IP, {
    listas,
    motivos: false,
dns: conDnsRegistrado({
      '113.0.203.zen.spamhaus.org': rtxt('127.0.0.2'),
      '113.0.203.xbl.spamhaus.org': rtxt('127.0.0.3'),
      '113.0.203.sbl.spamhaus.org': rtxt('127.0.0.4'),
      '10.113.0.203.bl.spamcop.net': rnx()
    })
  });

  assert.equal(r.resumen.listadas, 3, 'son tres zonas');
  assert.equal(r.resumen.proveedoresDistintos, 1, 'pero un solo operador');
});

test('con dos operadores distintos el resumen los cuenta como dos', async () => {
  const listas = [
    { clave: 'zen', nombre: 'ZEN', proveedor: 'Spamhaus', zona: 'zen.spamhaus.org', quitarUltimoOcteto: true },
    { clave: 'sc', nombre: 'SpamCop', proveedor: 'SpamCop', zona: 'bl.spamcop.net' }
  ];

  const r = await dnsbl.consultar(IP, {
    listas,
    motivos: false,
dns: conDnsRegistrado({
      '113.0.203.zen.spamhaus.org': rtxt('127.0.0.2'),
      '10.113.0.203.bl.spamcop.net': rtxt('127.0.0.2')
    })
  });

  assert.equal(r.resumen.proveedoresDistintos, 2);
  assert.equal(r.resumen.listadas, 2);
});

test('el porcentaje se calcula sobre las zonas contestadas, no sobre todas', async () => {
  // Una de las tres zonas calla. El 50% de las que contestaron es un dato; el
  // 33% del total seria pondrar un fallo de red como si fuera un "no".
  const listas = [
    { clave: 'a', nombre: 'A', proveedor: 'A', zona: 'a.example' },
    { clave: 'b', nombre: 'B', proveedor: 'B', zona: 'b.example' },
    { clave: 'c', nombre: 'C', proveedor: 'C', zona: 'c.example' }
  ];

  const r = await dnsbl.consultar(IP, {
    listas,
    motivos: false,
    dns: conDns({
      '10.113.0.203.a.example': rtxt('127.0.0.2'),
      '10.113.0.203.b.example': rfail('ESERVFAIL', 'SERVFAIL'),
      '10.113.0.203.c.example': rnx()
    })
  });

  assert.equal(r.resumen.listadas, 1);
  assert.equal(r.resumen.sinDatos, 1);
  assert.equal(r.resumen.porcentajeListado, 50);
});

// ---------------------------------------------------------------- IPv6

test('una IPv6 no se consulta: no hay zonas, y se dice que no hay', async () => {
  let preguntadas = 0;
  const r = await dnsbl.consultar('2001:db8::1', {
    listas: dnsbl.LISTAS_CORTA,
    dns: { consultarLote: (c) => { preguntadas += c.length; return c.map(rnx); } }
  });

  assert.equal(preguntadas, 0, 'no se manda ninguna consulta a la nada');
  assert.equal(r.resumen.consultadas, 0);
  assert.equal(r.resumen.noAplica, dnsbl.LISTAS_CORTA.length);
  assert.equal(r.resumen.listadas, 0);
  // Sin zonas que apliquen no se puede calcular nada, y no se rellena con un cero
  // que se leeria como "cero por ciento de algo".
  assert.equal(r.resumen.porcentajeListado, null);
  assert.ok(r.resultados.every((x) => x.estado === dnsbl.ESTADOS.SIN_APLICAR));
});

// ---------------------------------------------------------------- listas

test('las listas incluidas son zonas vivas, IPv4, y con proveedor', () => {
  for (const l of dnsbl.LISTAS_CORTA) {
    assert.ok(l.zona, `${l.clave} sin zona`);
    assert.ok(l.proveedor, `${l.clave} sin proveedor: sin proveedor no se puede contar operadores`);
    assert.equal(l.ipv6, false, l.clave + ' declara cobertura IPv6 sin tenerla');
    assert.equal(typeof l.nota, 'string');
  }
  assert.equal(new Set(dnsbl.LISTAS_CORTA.map((l) => l.zona)).size, dnsbl.LISTAS_CORTA.length, 'zonas repetidas');
});

test('cada lista corta tiene su forma de consulta declarada', () => {
  for (const l of dnsbl.LISTAS_CORTA) {
    assert.equal(typeof l.quitarUltimoOcteto, 'boolean', `${l.clave} no dice como se invierte`);
  }

  // Las listas que van por /24 son ZEN, XBL y SBL. BCL es la excepcion de
  // Spamhaus: su ficha registra una IP concreta, asi que va con los cuatro
  // octetos. Meterla en el /24 daria un nombre que no existe, y un "no listada"
  // de una IP que si lo esta.
  const porBloque = dnsbl.LISTAS_CORTA.filter((l) => l.quitarUltimoOcteto).map((l) => l.clave);
  assert.deepEqual([...porBloque].sort(), ['spamhaus-sbl', 'spamhaus-xbl', 'spamhaus-zen'].filter((c) => porBloque.includes(c)).sort());

  // Y ninguna lista que no sea de ese grupo puede declarar /24.
  const otras = dnsbl.LISTAS_CORTA.filter((l) => l.proveedor !== 'Spamhaus');
  assert.ok(otras.every((l) => l.quitarUltimoOcteto === false), 'una lista que no es de Spamhaus no va por /24');
});

test('BCL esta en la lista corta y se consulta por IP completa', () => {
  // BCL es la lista de la alerta de botnet C&C, y no puede faltar en el conjunto
  // por defecto: si solo estuviera en la amplia, el informe corto daria "no hay
  // rastro" de un listado que existe.
  const bcl = dnsbl.LISTAS_CORTA.find((l) => l.clave === 'spamhaus-bcl');

  assert.ok(bcl, 'BCL tiene que estar en el conjunto por defecto');
  assert.equal(bcl.zona, 'bcl.spamhaus.org');
  assert.equal(bcl.quitarUltimoOcteto, false, 'BCL va por IP, no por /24');
  assert.equal(bcl.categoria, 'botnet-c2');

  // El nombre que sale tiene que ser el de una IP concreta, no el del bloque.
  assert.equal(dnsbl.nombreDeConsulta('166.1.88.195', bcl), '195.88.1.166.bcl.spamhaus.org');
});

test('cada lista dice de que categoria es, y BCL es la unica de botnet', () => {
  for (const l of dnsbl.LISTAS_CORTA) {
    assert.ok(['correo', 'botnet-c2'].includes(l.categoria), `${l.clave} con categoria rara: ${l.categoria}`);
  }

  const botnet = dnsbl.LISTAS_CORTA.filter((l) => l.categoria === 'botnet-c2');
  assert.deepEqual(botnet.map((l) => l.clave), ['spamhaus-bcl']);

  // Es lo que permite separar la tabla de correo de la de botnet en el informe.
  // Sin `categoria` no hay forma de saber cuales son.
  assert.ok(botnet.every((l) => l.proveedor === 'Spamhaus'));
});

test('la lista amplia contiene la corta, y añade zonas', () => {
  const cortas = dnsbl.LISTAS_CORTA.map((l) => l.zona);
  for (const z of cortas) {
    assert.ok(dnsbl.LISTAS_AMPLIA.some((l) => l.zona === z), `la amplia perdio ${z}`);
  }
  assert.ok(dnsbl.LISTAS_AMPLIA.length > dnsbl.LISTAS_CORTA.length);
});

test('el aviso de Spamhaus existe y es explicito sobre el registro', () => {
  assert.ok(dnsbl.AVISO_SPAMHAUS);
  assert.match(dnsbl.AVISO_SPAMHAUS, /registrad/i);
});

test('la interfaz real de `core/net/dns` sirve para simular sin red', () => {
  // Si `consultarLote` cambiasse de firma, el doble de arriba dejaria de
  // detectar nada y todos los tests de este archivo pasarian con un `undefined`
  // silencioso. Aqui se comprueba que la forma sigue encajando.
  assert.equal(typeof dns.consultarLote, 'function');
  assert.equal(dns.consultarLote.length >= 1, true);
});

// ------------------------------------------------- comprobacion de acceso

// Estas pruebas cubren el segundo fallo del modulo, el mas silencioso: cuando
// Spamhaus no deja mirar a este resolvedor, sus zonas devuelven NXDOMAIN, que es
// lo mismo que devuelve una IP limpia. Sin comprobarlo antes, el modulo traducía
// "no me han dejado mirar" por "no listada", y el informe salia limpio.

const LISTAS_SPAMHAUS = dnsbl.LISTAS_CORTA.filter((l) => l.proveedor === 'Spamhaus');
const OTRAS = dnsbl.LISTAS_CORTA.filter((l) => l.proveedor !== 'Spamhaus');

test('la comprobacion de acceso se hace con la entrada de prueba de Spamhaus', async () => {
  const pedidas = [];
  const r = await dnsbl.detectarAccesoSpamhaus({
    dns: {
      consultarLote: async (consultas) => {
        pedidas.push(...consultas);
        return consultas.map(() => rtxt('127.0.0.3'));
      }
    }
  });

  assert.equal(pedidas.length, 1);
  assert.equal(pedidas[0].nombre, '3.0.0.127.zen.spamhaus.org');
  assert.equal(pedidas[0].tipo, 'A');
  assert.equal(r.hayDatos, true, 'si la entrada de prueba sale listada, hay datos');
  assert.equal(r.motivo, null);
});

test('si la entrada de prueba no viene listada, no hay datos', async () => {
  // Un resolvedor sin registrar devuelve 127.255.255.254 para la entrada que
  // siempre esta listada. Con eso ya se sabe que ninguna zona de Spamhaus vale.
  for (const respuesta of [rtxt('127.255.255.254'), rtxt('127.255.255.252'), rnx(), rfail('ESERVFAIL', 'SERVFAIL')]) {
    const r = await dnsbl.detectarAccesoSpamhaus({
      dns: { consultarLote: async (c) => c.map(() => respuesta) }
    });

    assert.equal(r.hayDatos, false);
    assert.ok(r.motivo, 'siempre tiene que decir por que no hay datos');
  }
});

test('sin acceso a Spamhaus, sus zonas pasan a "sin datos" y las demas no se tocan', async () => {
  // Este es el caso real que motivo el cambio: un NXDOMAIN de una zona que no
  // contesta es indistinguible de una IP limpia, asi que no puede quedarse como
  // "no listada".
  const respuestas = {};

  // Todas las zonas de Spamhaus dan NXDOMAIN: es lo que devuelven cuando no te
  // dejan mirar.
  for (const l of LISTAS_SPAMHAUS) respuestas[dnsbl.nombreDeConsulta(IP, l)] = rnx();
  // Las demas responden de verdad: una sale listada y otra no.
  respuestas[dnsbl.nombreDeConsulta(IP, OTRAS[0])] = rtxt('127.0.0.2');

  const r = await dnsbl.consultar(IP, { dns: conDns(respuestas), motivos: false });

  for (const x of r.resultados.filter((y) => y.proveedor === 'Spamhaus')) {
    assert.equal(x.estado, dnsbl.ESTADOS.SIN_DATOS, `${x.clave} no puede decir "limpia" sin haber preguntado`);
    assert.match(x.error, /no ha podido comprobar|no ha dado datos|Registrar|resuelto|contesta/i);
  }

  // Y las zonas de otros operadores siguen siendo creibles: su NXDOMAIN si es
  // un veredicto, porque contestan.
  const ajena = r.resultados.find((x) => x.clave === OTRAS[0].clave);
  assert.equal(ajena.estado, dnsbl.ESTADOS.LISTADA);

  // El NXDOMAIN de BCL no puede contarse como "sin listar".
  const bcl = r.resultados.find((x) => x.clave === 'spamhaus-bcl');
  assert.notEqual(bcl.estado, dnsbl.ESTADOS.LIMPIA);
  assert.equal(r.resumen.limpias, r.resultados.filter((x) => x.estado === dnsbl.ESTADOS.LIMPIA).length);
});

test('el aviso de acceso identifica la causa, no dice solo "sin datos"', async () => {
  const respuestas = {};
  for (const l of LISTAS_SPAMHAUS) respuestas[dnsbl.nombreDeConsulta(IP, l)] = rnx();

  const r = await dnsbl.consultar(IP, { dns: conDns(respuestas), motivos: false });

  assert.equal(r.accesoSpamhaus.hayDatos, false);
  assert.equal(r.avisos.length, 1);
  // El aviso tiene que decir las dos cosas que importan: por que no hay datos, y
  // que "sin datos" no es "no aparece".
  assert.match(r.avisos[0], /no ha podido comprobar|sin datos|resuelto/i);
  assert.match(r.avisos[0], /NO es un "no aparece"/);
});

test('con acceso a Spamhaus, sus zonas se leen como contestan', async () => {
  const respuestas = { '3.0.0.127.zen.spamhaus.org': rtxt('127.0.0.3') };

  // BCL responde con un listado real, ZEN con NXDOMAIN, y una zona ajena tambien.
  const bcl = LISTAS_SPAMHAUS.find((l) => l.clave === 'spamhaus-bcl');
  const zen = LISTAS_SPAMHAUS.find((l) => l.clave === 'spamhaus-zen');

  respuestas[dnsbl.nombreDeConsulta(IP, bcl)] = rtxt('127.0.0.10');
  respuestas[dnsbl.nombreDeConsulta(IP, zen)] = rnx();
  respuestas[dnsbl.nombreDeConsulta(IP, OTRAS[0])] = rnx();

  const r = await dnsbl.consultar(IP, { dns: conDns(respuestas), motivos: false });

  assert.equal(r.accesoSpamhaus.hayDatos, true);
  assert.equal(r.resultados.find((x) => x.clave === 'spamhaus-bcl').estado, dnsbl.ESTADOS.LISTADA);
  assert.equal(r.resultados.find((x) => x.clave === 'spamhaus-bcl').codigo, '127.0.0.10');
  // Aqui el NXDOMAIN si es un veredicto, porque el canario ha pasado.
  assert.equal(r.resultados.find((x) => x.clave === 'spamhaus-zen').estado, dnsbl.ESTADOS.LIMPIA);
  assert.equal(r.resumen.botnetListadas, 1);
  assert.deepEqual(r.resumen.zonasBotnet, ['bcl.spamhaus.org']);
});

test('la comprobacion de acceso se puede apagar', async () => {
  // Los dobles de prueba que no saben responder al canario no deben tener que
  // hacerlo, y hay veces que interesa el dato sin el canario.
  const respuestas = {};
  for (const l of LISTAS_SPAMHAUS) respuestas[dnsbl.nombreDeConsulta(IP, l)] = rtxt('127.0.0.10');

  const r = await dnsbl.consultar(IP, { dns: conDns(respuestas), motivos: false, accesoSpamhaus: false });

  assert.equal(r.accesoSpamhaus, null);
  assert.equal(r.resumen.listadas, LISTAS_SPAMHAUS.length);
});

test('sin zonas de Spamhaus no se hace la comprobacion de acceso', async () => {
  // Preguntar por el canario cuando no se va a usar su respuesta seria una
  // consulta a Spamhaus que no aporta nada a nadie.
  let preguntadas = 0;
  const r = await dnsbl.consultar(IP, {
    listas: OTRAS,
    motivos: false,
    dns: { consultarLote: (c) => { preguntadas += c.length; return c.map(rnx); } }
  });

  assert.equal(preguntadas, OTRAS.length, 'solo las zonas de la lista, sin canario');
  assert.equal(r.accesoSpamhaus, null);
});

// ---------------------------------------------------------------- DBL (dominios)

test('un dominio limpio en DBL se consulta tal cual y sale "limpio"', async () => {
  const r = await dnsbl.consultarDominio('ejemplo.com', {
    accesoSpamhaus: false,
    dns: conDns({ 'ejemplo.com.dbl.spamhaus.org': rnx() })
  });

  assert.equal(r.estado, dnsbl.ESTADOS.LIMPIA);
  assert.equal(r.consultado, 'ejemplo.com');
  assert.equal(r.codigo, null);
});

test('un dominio en DBL se detecta con su codigo de listado', async () => {
  const r = await dnsbl.consultarDominio('ejemplo.com', {
    accesoSpamhaus: false,
    dns: conDns({ 'ejemplo.com.dbl.spamhaus.org': rtxt('127.0.1.2') })
  });

  assert.equal(r.estado, dnsbl.ESTADOS.LISTADA);
  assert.equal(r.consultado, 'ejemplo.com');
  assert.equal(r.codigo, '127.0.1.2');
});

test('un subdominio limpio hereda el listado del dominio del que cuelga', async () => {
  const r = await dnsbl.consultarDominio('boletin.ejemplo.com', {
    accesoSpamhaus: false,
    dns: conDns({ 'boletin.ejemplo.com.dbl.spamhaus.org': rnx(), 'ejemplo.com.dbl.spamhaus.org': rtxt('127.0.1.2') })
  });

  assert.equal(r.estado, dnsbl.ESTADOS.LISTADA);
  assert.equal(r.consultado, 'ejemplo.com', 'el listado esta en el padre, y se dice');
});

test('un dominio que no lo parece devuelve sin-datos, no una consulta inventada', async () => {
  const r = await dnsbl.consultarDominio('no esto no es un dominio', { accesoSpamhaus: false });

  assert.equal(r.estado, dnsbl.ESTADOS.SIN_DATOS);
  assert.equal(r.consultado, null);
  assert.match(r.error, /dominio/);
});

test('sin acceso a Spamhaus, un "limpio" de DBL pasa a "sin datos"', async () => {
  const r = await dnsbl.consultarDominio('ejemplo.com', {
    dns: conDns({ 'ejemplo.com.dbl.spamhaus.org': rnx() })
  });

  assert.equal(r.estado, dnsbl.ESTADOS.SIN_DATOS, 'el NXDOMAIN sin canario no prueba nada');
  assert.ok(r.avisos.length, 'el aviso dice por que');
});
