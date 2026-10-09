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
const { createResult } = require('../src/core/result');
const dnsNet = require('../src/core/net/dns');

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

test('parsearWhois extrae el ID de IANA del registrador', () => {
  const raw = [
    'Domain Name: EJEMPLO.COM',
    'Registrar: MarkMonitor Inc.',
    'Registrar IANA ID: 292',
    'Registry Expiry Date: 2028-01-01'
  ].join('\n');

  const p = herramienta.parsearWhois(raw, 'ejemplo.com');
  assert.equal(p.registradorId, '292');
  assert.equal(p.registrador, 'MarkMonitor Inc.');

  const sinId = herramienta.parsearWhois('Registrar: Namecheap', 'ejemplo.com');
  assert.equal(sinId.registradorId, null, 'sin la línea IANA no se inventa un ID');
});

test('combinarResultados conserva el ID de IANA del WHOIS', () => {
  const c = herramienta.combinarResultados(
    { disponible: true, consultable: true },
    { disponible: true, registrador: 'MarkMonitor Inc.', registradorId: '292' },
    'ejemplo.com'
  );
  assert.equal(c.registradorId, '292');
});

/* ------------------------------------------------------------------ *
 * DNSSEC
 * ------------------------------------------------------------------ */

function resultado() {
  return createResult({ tool: 'dominio-vencimiento', target: 'ejemplo.com', params: {} });
}

/** Una DNSKEY mínima pero con la forma que deja `dns.js`. */
function clave(flags, keyTag) {
  return { flags, algorithm: 8, key: Buffer.alloc(32, keyTag), keyTag };
}

const OK = { ok: true, valores: [], ttl: null, error: null };
const FALLO = { ok: false, valores: [], ttl: null, error: 'sin respuesta' };

test('verificarDnssec distingue los seis estados de la cadena', () => {
  const v = herramienta.verificarDnssec;
  const ksk = clave(257, 1111);

  assert.equal(v({ dnskey: OK, ds: OK }).verificacion, 'sin-firma');
  assert.equal(v({ dnskey: FALLO, ds: FALLO }).verificacion, 'sin-datos');
  assert.equal(v({ dnskey: { ok: true, valores: [ksk] }, ds: OK }).verificacion, 'firmado-sin-ds');
  assert.equal(
    v({ dnskey: { ok: true, valores: [ksk] }, ds: { ok: true, valores: [{ keyTag: 9999 }] } }).verificacion,
    'ds-sin-clave'
  );
  assert.equal(
    v({ dnskey: { ok: true, valores: [ksk] }, ds: { ok: true, valores: [{ keyTag: 1111, algorithm: 8, digestType: 2, digestHex: 'abcd'.repeat(8) }] } }).verificacion,
    'digest-roto',
    'un keyTag correcto con un digest que no cuadra es un fallo, no un matiz'
  );
  assert.equal(v({ dnskey: OK, ds: { ok: true, valores: [{ keyTag: 1 }] } }).verificacion, 'ds-sin-claves');
});

test('un DS con el digest de la clave publicada se da por validado', () => {
  const ksk = clave(257, 1111);
  const digest = dnsNet.calcularDigestoDs(ksk, 'ejemplo.com', 2);
  const ds = { ok: true, valores: [{ keyTag: 1111, algorithm: 8, digestType: 2, digestHex: digest }] };

  const v = herramienta.verificarDnssec({ dominio: 'ejemplo.com', dnskey: { ok: true, valores: [ksk] }, ds });
  assert.equal(v.verificacion, 'valido');
});

test('un DS con el digest de OTRA clave es un fallo, no un matiz', () => {
  const ksk = clave(257, 1111);
  const otra = clave(257, 2222);
  const digestDeOtra = dnsNet.calcularDigestoDs(otra, 'ejemplo.com', 2);
  const ds = { ok: true, valores: [{ keyTag: 1111, algorithm: 8, digestType: 2, digestHex: digestDeOtra }] };

  const v = herramienta.verificarDnssec({ dominio: 'ejemplo.com', dnskey: { ok: true, valores: [ksk] }, ds });
  assert.equal(v.verificacion, 'digest-roto');
});

test('el estado DNSSEC se pinta en su tabla y se cuenta en los hallazgos', () => {
  const ksk = clave(257, 1111);
  const digest = dnsNet.calcularDigestoDs(ksk, 'ejemplo.com', 2);
  const ds = { ok: true, valores: [{ keyTag: 1111, algorithm: 8, digestType: 2, digestHex: digest }] };
  const args = { dominio: 'ejemplo.com', dnskey: { ok: true, valores: [ksk] }, ds };

  const r = resultado();
  herramienta.pintarDnssec(r, args);
  herramienta.revisarDnssec(r, args);

  const seccion = r.sections.find((s) => s.title === 'DNSSEC');
  assert.ok(seccion);
  assert.equal(seccion.kind, 'table');
  assert.ok(seccion.rows.some(([k, v]) => k === 'Estado' && v.valor === 'Firmado y verificado'));
  assert.ok(r.findings.some((f) => /vigente y verificado/.test(f.title) && f.severity === 'ok'));
});

test('un dominio firmado sin DS es un aviso, no un fallo', () => {
  const ksk = clave(257, 1111);
  const args = { dominio: 'ejemplo.com', dnskey: { ok: true, valores: [ksk] }, ds: OK };

  const r = resultado();
  herramienta.revisarDnssec(r, args);
  assert.ok(r.findings.some((f) => /firmado pero la zona padre/.test(f.title) && f.severity === 'warn'));
});

test('un DS sin claves publicadas detrás es un fallo de verdad', () => {
  const args = { dominio: 'ejemplo.com', dnskey: OK, ds: { ok: true, valores: [{ keyTag: 1 }] } };

  const r = resultado();
  herramienta.revisarDnssec(r, args);
  assert.ok(r.findings.some((f) => /DS pero el dominio no publica/.test(f.title) && f.severity === 'error'));
});

test('consultarDnssec lee de ctx.dns y pregunta los dos tipos', async () => {
  const consultas = [];
  const dns = {
    consultar: async (nombre, tipo) => {
      consultas.push(tipo);
      return OK;
    }
  };

  const r = resultado();
  const { dnskey, ds } = await herramienta.consultarDnssec(r, 'ejemplo.com', 5000, { dns });

  assert.deepEqual(consultas, ['DNSKEY', 'DS']);
  assert.equal(dnskey.ok, true);
  assert.equal(ds.ok, true);
});

test('un fallo de red en DNSSEC no tumba el informe', async () => {
  const dns = {
    consultar: async () => {
      throw new Error('ECONNRESET');
    }
  };

  const r = resultado();
  const { dnskey, ds } = await herramienta.consultarDnssec(r, 'ejemplo.com', 5000, { dns });
  assert.equal(dnskey, null);
  assert.equal(ds, null);

  herramienta.revisarDnssec(r, { dominio: 'ejemplo.com', dnskey, ds });
  assert.ok(r.findings.some((f) => /No se pudo comprobar el estado DNSSEC/.test(f.title)));
});
