'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const ip = require('../src/core/net/ipaddr');

test('reconoce la familia y da null cuando no es una IP', () => {
  assert.equal(ip.bitsDe('203.0.113.10'), 32);
  assert.equal(ip.bitsDe('2001:db8::1'), 128);
  assert.equal(ip.bitsDe('no es una ip'), null);
  assert.equal(ip.bitsDe('203.0.113.999'), null, 'un octeto de mas no es una IP');
  assert.equal(ip.bitsDe(''), null);
});

test('rellena IPv6 a 32 digitos, con la compresion resuelta', () => {
  assert.equal(ip.expandirIPv6('2001:db8::1'), '20010db8000000000000000000000001');
  assert.equal(ip.expandirIPv6('::1'), '00000000000000000000000000000001');
  assert.equal(ip.expandirIPv6('::'), '00000000000000000000000000000000');
  // La forma larga y la comprimida tienen que dar exactamente lo mismo.
  assert.equal(
    ip.expandirIPv6('2001:0db8:0000:0000:0000:0000:0000:0001'),
    ip.expandirIPv6('2001:db8::1'),
    'la forma larga y la corta no pueden diferir'
  );
});

test('cuenta bien una IPv4 al final de una IPv6', () => {
  // `::ffff:192.0.2.1` son ocho grupos: cinco a cero, `ffff`, y la IPv4 en dos.
  // Si la cola se parte mal, se cuela un grupo de mas y TODA la direccion se
  // desplaza, que es como se acaba preguntando a la zona equivocada.
  assert.equal(ip.expandirIPv6('::ffff:192.0.2.1'), '00000000000000000000ffffc0000201');
  assert.equal(ip.aBytes('::ffff:192.0.2.1').length, 16);
  assert.deepEqual(ip.aBytes('::ffff:192.0.2.1').slice(10), [255, 255, 192, 0, 2, 1]);
});

test('quita el identificador de zona antes de trabajar', () => {
  assert.equal(ip.expandirIPv6('fe80::1%eth0'), 'fe800000000000000000000000000001');
  assert.equal(ip.comprimirIPv6('fe80::1%eth0'), 'fe80::1');
});

test('devuelve null con una IPv6 mal formada, en vez de inventar una', () => {
  assert.equal(ip.expandirIPv6('2001:db8::1::2'), null);
  assert.equal(ip.expandirIPv6('2001:db8:zz::1'), null);
  assert.equal(ip.expandirIPv6('no-es-ipv6'), null);
});

test('comprime la IPv6 como manda el RFC 5952, sin ceros a la izquierda', () => {
  assert.equal(ip.comprimirIPv6('2001:db8:0:0:1:0:0:1'), '2001:db8::1:0:0:1');
  assert.equal(ip.comprimirIPv6('2001:0db8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
  // Una sola racha de un cero no se abre: "::" no se usa para un solo grupo.
  assert.equal(ip.comprimirIPv6('2001:db8:0:1:1:1:1:1'), '2001:db8:0:1:1:1:1:1');
});

test('comprimirIPv6 deja las IPv4 intactas', () => {
  assert.equal(ip.comprimirIPv6('203.0.113.10'), '203.0.113.10');
});

test('decide si un prefijo contiene una direccion', () => {
  assert.equal(ip.contiene('1.0.0.0/8', '1.2.3.4'), true);
  assert.equal(ip.contiene('1.3.0.0/16', '1.2.3.4'), false);
  assert.equal(ip.contiene('0.0.0.0/0', '203.0.113.10'), true, '/0 contiene todas');
  assert.equal(ip.contiene('2001:db8::/32', '2001:db8::1'), true);
  assert.equal(ip.contiene('2001:db9::/32', '2001:db8::1'), false);
});

test('un prefijo de una familia no contiene direcciones de la otra', () => {
  // Comparar 32 bits contra 128 daria unShift de mas de 32 y, con BigInt, un
  // cero silencioso: pareceria que todo esta dentro.
  assert.equal(ip.contiene('1.0.0.0/8', '::1'), false);
  assert.equal(ip.contiene('2001:db8::/32', '203.0.113.10'), false);
});

test('un prefijo mal formado no contiene nada, y no lanza', () => {
  assert.equal(ip.contiene('no-es-un-prefijo', '203.0.113.10'), false);
  assert.equal(ip.contiene('1.0.0.0/33', '203.0.113.10'), false);
  assert.equal(ip.contiene('1.0.0.0/abc', '203.0.113.10'), false);
  assert.equal(ip.contiene('1.0.0.0', '203.0.113.10'), false, 'sin longitud no hay prefijo');
});

test('gana el prefijo mas largo, no el primero de la lista', () => {
  // El bootstrap de IANA viene ordenado de mas general a mas especifico. Si se
  // cogiera el primero que encaja, una IP de ARIN acabaria preguntada al
  // servidor de /0 y el informe diria "no hay registro" sin llegar a preguntar.
  const prefijos = ['0.0.0.0/0', '1.0.0.0/8', '1.2.0.0/16'];
  assert.equal(ip.prefijoMasLargo('1.2.3.4', prefijos), '1.2.0.0/16');

  // Y al reves: la lista mas especifica primero tambien tiene que dar el mismo.
  assert.equal(ip.prefijoMasLargo('1.2.3.4', [...prefijos].reverse()), '1.2.0.0/16');
});

test('prefijoMasLargo devuelve null si nada encaja', () => {
  assert.equal(ip.prefijoMasLargo('203.0.113.10', ['9.0.0.0/8']), null);
  assert.equal(ip.prefijoMasLargo('203.0.113.10', []), null);
});

test('escribe el nombre de zona inversa de una IPv4 con los octetos al reves', () => {
  assert.equal(ip.nombreInvertido('203.0.113.10'), '10.113.0.203.in-addr.arpa');
  assert.equal(ip.nombreInvertido('1.2.3.4'), '4.3.2.1.in-addr.arpa');
});

test('escribe el nombre de zona inversa de una IPv6 con 32 nibbles al reves', () => {
  // El error clasico es dar la vuelta a los BYTES en vez de a los nibbles. El
  // nombre resultante existe pero nunca responde, y el resultado es un "no
  // listada" falso.
  const nibbles = ip.nombreInvertido('2001:db8::1').replace('.ip6.arpa', '').split('.');

  assert.equal(nibbles.length, 32, 'son 32 nibbles, no 16 bytes');
  assert.ok(!ip.nombreInvertido('2001:db8::1').includes('00.00'), 'no se pueden dar la vuelta a los bytes');

  // Ida y vuelta: al revés de la vuelta tiene que aparecer el hexadecimal
  // expandido. Es la comprobacion que de verdad atrapa un byte/nibble
  // equivocado, sin depender de escribir 32 numeros a mano sin errores.
  assert.equal(nibbles.slice().reverse().join(''), ip.expandirIPv6('2001:db8::1'));

  // Y los primeros nibbles, que son los que se leen en un informe.
  assert.equal(nibbles.slice(0, 4).join('.'), '1.0.0.0');
  assert.equal(nibbles.slice(-8).join('.'), '8.b.d.0.1.0.0.2');
});

test('normalizarIPv4 quita ceros a la izquierda y rechaza lo que no es', () => {
  // `net.isIPv4` rechaza esta forma a proposito: `010` en octal valia otra
  // cosa. Por eso esta funcion existe y no se apoya en el resolvedor.
  assert.equal(ip.normalizarIPv4('010.001.000.001'), '10.1.0.1');
  assert.equal(ip.normalizarIPv4('203.0.113.10'), '203.0.113.10');
  assert.equal(ip.normalizarIPv4('999.1.1.1'), null);
  assert.equal(ip.normalizarIPv4('1.2.3'), null);
  assert.equal(ip.normalizarIPv4('a.b.c.d'), null);
});
