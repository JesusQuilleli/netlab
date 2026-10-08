/**
 * dominio-vencimiento - pruebas del parseo WHOIS y de la fusion de fuentes.
 *
 * El bug que cubren: parsearWhois guardaba estados y nameservers en claves
 * en singular (`estado`, `nameserver`) y combinarResultados leia las plurales,
 * asi que el fallback WHOIS perdia esos dos campos siempre.
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const herramienta = require('../src/tools/dominio-vencimiento');

test('parsearWhois extrae estados, nameservers y fechas', () => {
  const raw = [
    'Domain Name: EXAMPLE.COM',
    'Registrar: RESERVED-Internet Assigned Numbers Authority',
    'Updated Date: 2026-08-14T07:01:35Z',
    'Creation Date: 1995-08-14T04:00:00Z',
    'Registry Expiry Date: 2027-08-13T04:00:00Z',
    'Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited',
    'Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited',
    'Name Server: ELLIOTT.NS.CLOUDFLARE.COM',
    'Name Server: ELLIOTT.NS.CLOUDFLARE.COM.',
    'Name Server: HERA.NS.CLOUDFLARE.COM'
  ].join('\n');

  const p = herramienta.parsearWhois(raw, 'example.com');

  assert.equal(p.registrador, 'RESERVED-Internet Assigned Numbers Authority');
  assert.equal(p.creacion, '1995-08-14T04:00:00Z');
  assert.equal(p.expiracion, '2027-08-13T04:00:00Z');
  assert.deepEqual(p.estados, ['client delete prohibited', 'client transfer prohibited']);
  assert.deepEqual(p.nameservers, ['elliott.ns.cloudflare.com', 'hera.ns.cloudflare.com']);
});

test('los estados EPP pierden la URL de ICANN y ganan espacios', () => {
  const raw = 'Domain Status: serverHold https://icann.org/epp#serverHold';
  const p = herramienta.parsearWhois(raw, 'x.com');
  assert.deepEqual(p.estados, ['server hold']);
});

test('combinarResultados une y deduplica estados y nameservers de ambas fuentes', () => {
  const rdap = {
    disponible: true,
    consultable: true,
    estados: 'client transfer prohibited, client delete prohibited',
    nombreservers: ['NS1.GOOGLE.COM.', 'ns2.google.com'],
    registro: '1997-09-15T07:00:00Z',
    caducidad: '2028-09-14T07:00:00Z'
  };
  const whois = {
    disponible: true,
    estados: ['client transfer prohibited', 'client update prohibited'],
    nameservers: ['ns1.google.com', 'ns3.google.com'],
    registrador: 'MarkMonitor Inc.'
  };

  const c = herramienta.combinarResultados(rdap, whois, 'google.com');

  assert.equal(c.registrador, 'MarkMonitor Inc.');
  assert.ok(c.estados.includes('client transfer prohibited'));
  assert.ok(c.estados.includes('client delete prohibited'));
  assert.ok(c.estados.includes('client update prohibited'));
  assert.equal(c.estados.length, 3, 'sin duplicados entre RDAP y WHOIS');
  assert.deepEqual(
    [...c.nameservers].sort(),
    ['ns1.google.com', 'ns2.google.com', 'ns3.google.com']
  );
  assert.equal(c.expiracion, '2028-09-14');
  assert.ok(c.diasRestantes > 0);
});

test('sin expiration no hay diasRestantes, y no se inventa ninguno', () => {
  const c = herramienta.combinarResultados(null, null, 'nadie.com');
  assert.equal(c.diasRestantes, null);
  assert.equal(c.fuente, 'none');
  assert.equal(c.consultable, false);
});

test('entiende el formato de NIC.VE: expire, changed, DD.MM.YYYY y org', () => {
  const raw = [
    'domain:       berakah.com.ve',
    'registrant:   CON000073989',
    'registrar:    NIC-VE',
    'registered:   04.05.2026 05:33:39',
    'changed:      12.05.2026 06:34:23',
    'expire:       04.05.2027',
    'org:          Corporacion Berakah, C.a',
    'nserver:      bjorn.ns.cloudflare.com',
    'nserver:      karsyn.ns.cloudflare.com'
  ].join('\n');

  const p = herramienta.parsearWhois(raw, 'berakah.com.ve');

  assert.equal(p.registrador, 'NIC-VE');
  assert.equal(p.titular, 'Corporacion Berakah, C.a');
  assert.equal(p.creacion, '04.05.2026 05:33:39');
  assert.equal(p.expiracion, '04.05.2027');
  assert.equal(p.actualizacion, '12.05.2026 06:34:23');
  assert.deepEqual(p.nameservers, ['bjorn.ns.cloudflare.com', 'karsyn.ns.cloudflare.com']);

  const c = herramienta.combinarResultados(null, { ...p, disponible: true }, 'berakah.com.ve');
  assert.equal(c.creacion, '2026-05-04');
  assert.equal(c.expiracion, '2027-05-04');
  assert.ok(c.diasRestantes > 0, 'los dias se calculan con la fecha DD.MM.YYYY ya convertida');
  assert.equal(c.fuente, 'whois');
});
