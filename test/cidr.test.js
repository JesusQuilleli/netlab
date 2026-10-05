'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { analizarRed, listarHosts, dividirVLSM, normalizarPrefijo, prefijoDesdeMascara, mascaraDesdePrefijo } = require('../src/core/net/cidr');

// --- Casos basicos del bug que existia en legacy/Validate IP/info-ip.js

test('/30: debe respetar RFC 3021 (2 hosts utilizables, no 0)', () => {
  // legacy/Validate IP/info-ip.js:26-45 calculaba usableHosts = total - 2,
  // lo que daba 0 para /30 (total 4). RFC 3021: en punto a punto /31 los dos
  // extremos son utilizables. El codigo nuevo trata /30 correctamente (y /31
  // con 2 hosts). Aqui verificamos el caso del test del legacy: /30.
  const r = analizarRed('192.168.1.10', '255.255.255.252');
  assert.strictEqual(r.prefijo, 30);
  assert.strictEqual(r.hostsTotales, 4);
  assert.strictEqual(r.hostsUtilizables, 2, 'RFC 3021 aplica para /31; para /30 hay red+bc = 2 reservados');
  assert.strictEqual(r.direccionRed, '192.168.1.8');
  assert.strictEqual(r.direccionBroadcast, '192.168.1.11');
  assert.strictEqual(r.rangoUtilizable.primeraIP, '192.168.1.9');
  assert.strictEqual(r.rangoUtilizable.ultimaIP, '192.168.1.10');
});

test('/32: host unico, solo una IP utilizable', () => {
  const r = analizarRed('166.0.112.206', '255.255.255.255');
  assert.strictEqual(r.prefijo, 32);
  assert.strictEqual(r.hostsUtilizables, 1);
  assert.strictEqual(r.direccionRed, '166.0.112.206');
  assert.strictEqual(r.direccionBroadcast, '166.0.112.206');
  assert.strictEqual(r.rangoUtilizable.primeraIP, '166.0.112.206');
  assert.strictEqual(r.rangoUtilizable.ultimaIP, '166.0.112.206');
});

test('/31: punto a punto (RFC 3021) con 2 hosts utilizables', () => {
  const r = analizarRed('10.0.0.0', '/31');
  assert.strictEqual(r.prefijo, 31);
  assert.strictEqual(r.hostsUtilizables, 2);
  assert.strictEqual(r.direccionesReservadas, 0);
  assert.strictEqual(r.rangoUtilizable.primeraIP, '10.0.0.0');
  assert.strictEqual(r.rangoUtilizable.ultimaIP, '10.0.0.1');
});

// --- Normalizacion de prefijos y mascaras

test('normalizarPrefijo acepta /30, 30 y mascara punteada', () => {
  assert.strictEqual(normalizarPrefijo('/30'), 30);
  assert.strictEqual(normalizarPrefijo('30'), 30);
  assert.strictEqual(normalizarPrefijo('255.255.255.252'), 30);
  assert.strictEqual(normalizarPrefijo('255.255.255.0'), 24);
  assert.strictEqual(normalizarPrefijo('0.0.0.0'), 0);
});

test('prefijoDesdeMascara rechaza mascaras no contiguas', () => {
  assert.throws(() => prefijoDesdeMascara('255.255.255.253'), /máscara/);
  assert.throws(() => prefijoDesdeMascara('255.0.255.0'), /máscara/);
});

test('mascaraDesdePrefijo devuelve la mascara correcta', () => {
  assert.strictEqual(mascaraDesdePrefijo(30), '255.255.255.252');
  assert.strictEqual(mascaraDesdePrefijo(24), '255.255.255.0');
  assert.strictEqual(mascaraDesdePrefijo(32), '255.255.255.255');
  assert.strictEqual(mascaraDesdePrefijo(0), '0.0.0.0');
});

// --- Casos de red clasicos

test('/24 clasico', () => {
  const r = analizarRed('192.168.1.10', '/24');
  assert.strictEqual(r.direccionRed, '192.168.1.0');
  assert.strictEqual(r.direccionBroadcast, '192.168.1.255');
  assert.strictEqual(r.hostsTotales, 256);
  assert.strictEqual(r.hostsUtilizables, 254);
  assert.strictEqual(r.rangoUtilizable.primeraIP, '192.168.1.1');
  assert.strictEqual(r.rangoUtilizable.ultimaIP, '192.168.1.254');
  assert.ok(r.ambito.privada, '192.168.0.0/16 es privada');
});

test('/16 y /8', () => {
  const r16 = analizarRed('172.16.5.5', '/16');
  assert.strictEqual(r16.hostsTotales, 65536);
  assert.strictEqual(r16.hostsUtilizables, 65534);
  assert.ok(r16.ambito.privada);

  const r8 = analizarRed('10.20.30.40', '/8');
  assert.strictEqual(r8.hostsTotales, 16777216);
  assert.ok(r8.ambito.privada);
});

// --- Validacion de entrada

test('rechaza IPv4 invalida', () => {
  assert.throws(() => analizarRed('192.168.1.256', '/24'), /IPv4/);
  assert.throws(() => analizarRed('192.168.1', '/24'), /IPv4/);
  assert.throws(() => analizarRed('abc.def.ghi.jkl', '/24'), /IPv4/);
  assert.throws(() => analizarRed('192.168.1.10', '/33'), /prefijo/);
  assert.throws(() => analizarRed('192.168.1.10', '255.255.0.255'), /máscara/);
});

// --- Listado de hosts y VLSM

test('listarHosts limita correctamente para no inundar', () => {
  const lista = listarHosts('192.168.0.0', '/16', { limite: 10 });
  assert.strictEqual(lista.hosts.length, 10);
  assert.strictEqual(lista.truncada, true);
  assert.strictEqual(lista.total, 65534);
});

test('listarHosts no trunca cuando cabe todo', () => {
  const lista = listarHosts('10.0.0.0', '/30', { limite: 1024 });
  assert.strictEqual(lista.truncada, false);
  assert.deepStrictEqual(lista.hosts, ['10.0.0.1', '10.0.0.2']);
});

test('dividirVLSM reparte en subredes iguales', () => {
  const v = dividirVLSM('192.168.1.0', '/24', 4);
  assert.strictEqual(v.viable, true);
  assert.strictEqual(v.subredes.length, 4);
  assert.strictEqual(v.prefijoHijo, 26);
  assert.strictEqual(v.subredes[0].cidr, '192.168.1.0/26');
  assert.strictEqual(v.subredes[1].cidr, '192.168.1.64/26');
  assert.strictEqual(v.subredes[3].cidr, '192.168.1.192/26');
  assert.strictEqual(v.subredes[0].hostsUtilizables, 62);
});

test('dividirVLSM avisa cuando no es potencia de dos', () => {
  const v = dividirVLSM('192.168.1.0', '/24', 3);
  assert.strictEqual(v.viable, true);
  assert.strictEqual(v.subredes.length, 3);
  assert.ok(v.nota.includes('no es potencia de dos'));
});

test('dividirVLSM devuelve viable=false si no cabe', () => {
  const v = dividirVLSM('192.168.1.0', '/30', 10);
  assert.strictEqual(v.viable, false);
  assert.ok(v.nota.includes('/32'));
  assert.deepStrictEqual(v.subredes, []);
});