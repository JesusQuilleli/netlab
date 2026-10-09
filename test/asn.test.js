'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const asn = require('../src/core/net/asn');

// ---------------------------------------------------------------- dobles

/**
 * Doble de `core/net/dns` para las pruebas, sin tocar la red.
 *
 * Contesta solo a los nombres que haya en el mapa; cualquier otro es un
 * "no anunciada" (NXDOMAIN), que es la respuesta mas comun.
 *
 * @param {object} mapa `{ nombre: {o: string | string[] | null, err?: string, codigo?: string} }`.
 */
function conDns(mapa = {}) {
  return {
    consultar: async (nombre, tipo, opciones) => {
      const entrada = mapa[nombre];
      if (!entrada) {
        return { ok: false, valores: [], ttl: null, error: 'El nombre no existe', codigoDns: 'ENOTFOUND' };
      }
      if (entrada.err) {
        return { ok: false, valores: [], ttl: null, error: entrada.err, codigoDns: entrada.codigo || 'ESERVFAIL' };
      }
      const valores = Array.isArray(entrada) ? entrada : [entrada];
      return { ok: true, valores, ttl: 60, error: null, codigoDns: 'NOERROR' };
    }
  };
}

const ORIGEN_V4 = asn.nombreDeOrigen('203.0.113.10'); // 10.113.0.203.origin.asn.cymru.com
const ORIGEN_V6 = asn.nombreDeOrigen('2001:db8::1'); // ...origin6.asn.cymru.com
const REGISTRO_15169 = asn.nombreDeAsn('15169');

const DATOS_V4 = '15169 | 8.8.8.0/24 | US | arin | 2023-12-28';
const NOMBRE_V4 = '15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US';

// ---------------------------------------------------------------- nombres

test('el nombre de origen es la IP al reves en la zona de Team Cymru', () => {
  assert.equal(ORIGEN_V4, '10.113.0.203.origin.asn.cymru.com');
  assert.equal(ORIGEN_V6, '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com');

  // La zona inversa NO puede colarse en medio: su sufijo pertenece a la zona
  // inversa, no a una zona cualquiera. Pegado, el nombre nunca existe.
  assert.ok(!ORIGEN_V4.includes('in-addr.arpa'));
  assert.ok(!ORIGEN_V6.includes('ip6.arpa'));

  // La familia decide la zona: IPv4 e IPv6 no comparten zona.
  assert.match(ORIGEN_V4, /\.origin\.asn\.cymru\.com$/);
  assert.match(ORIGEN_V6, /\.origin6\.asn\.cymru\.com$/);
  assert.equal(asn.nombreDeOrigen('no es una ip'), null);
});

test('el nombre de registro es "AS<n>" en la zona de registro', () => {
  assert.equal(REGISTRO_15169, 'AS15169.asn.cymru.com');
  assert.equal(asn.nombreDeAsn('AS13335'), 'AS13335.asn.cymru.com');
});

// ---------------------------------------------------------------- parsing

test('interpretarOrigen lee las cinco columnas del TXT', () => {
  const r = asn.interpretarOrigen(DATOS_V4);
  assert.deepEqual(r, { asn: '15169', prefijo: '8.8.8.0/24', pais: 'US', registro: 'arin', asignado: '2023-12-28' });

  // Node entrega los TXT largos como lista de fragmentos; se unen antes de
  // parsear, y da lo mismo.
  assert.deepEqual(asn.interpretarOrigen(['15169 | 8.8.8.0', '/24 | US | arin | ']), { asn: '15169', prefijo: '8.8.8.0/24', pais: 'US', registro: 'arin', asignado: null });
});

test('interpretarRegistro guarda el nombre entero del ASN', () => {
  const r = asn.interpretarRegistro(NOMBRE_V4);
  assert.equal(r.asn, '15169');
  assert.equal(r.pais, 'US');
  assert.equal(r.registro, 'arin');
  assert.equal(r.asignado, '2000-03-30');
  assert.equal(r.nombre, 'GOOGLE - Google LLC, US');

  // El texto tras la raya no se trocea: es el nombre oficial, entero.
  assert.match(r.nombre, /^GOOGLE - Google LLC, US$/);
});

// ---------------------------------------------------------------- consulta

test('una IP anunciada devuelve el ASN y su nombre', async () => {
  const r = await asn.consultar('203.0.113.10', {
    dns: conDns({ [ORIGEN_V4]: DATOS_V4, [REGISTRO_15169]: NOMBRE_V4 })
  });

  assert.equal(r.estado, asn.ESTADOS.ENCONTRADO);
  assert.equal(r.asn, '15169');
  assert.equal(r.prefijo, '8.8.8.0/24');
  assert.equal(r.pais, 'US');
  assert.equal(r.registro, 'arin');
  assert.equal(r.asignado, '2023-12-28');
  assert.equal(r.nombre, 'GOOGLE - Google LLC, US');
  assert.equal(r.avisos.length, 0);
});

test('una IPv6 se consulta en la zona origin6, no en la de IPv4', async () => {
  const r = await asn.consultar('2001:db8::1', {
    dns: conDns({
      [ORIGEN_V6]: '13335 | 2606:4700:4700::/48 | US | arin | 2011-11-01',
      [asn.nombreDeAsn('13335')]: '13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US'
    })
  });

  assert.equal(r.estado, asn.ESTADOS.ENCONTRADO);
  assert.equal(r.asn, '13335');
  assert.equal(r.nombre, 'CLOUDFLARENET - Cloudflare, Inc., US');
});

test('NXDOMAIN es "no anunciada", que no es un fallo', async () => {
  // Rangos reservados, TEST-NET e internos no los anuncia nadie: Team Cymru
  // responde NXDOMAIN, que es una respuesta valida y no un hueco.
  const r = await asn.consultar('192.0.2.1', { dns: conDns({}) });
  assert.equal(r.estado, asn.ESTADOS.NO_ANUNCIADA);
  assert.equal(r.asn, null);
  assert.equal(r.error, undefined);
});

test('AS0 es "no anunciada"', async () => {
  const r = await asn.consultar('10.0.0.1', {
    dns: conDns({ [asn.nombreDeOrigen('10.0.0.1')]: '0 | 10.0.0.0/8 | - | not applicable | 1995-01-01' })
  });
  assert.equal(r.estado, asn.ESTADOS.NO_ANUNCIADA);
  assert.equal(r.asn, null);
});

test('un fallo de red no es "no anunciada": es sin-datos', async () => {
  const r = await asn.consultar('203.0.113.10', {
    dns: conDns({ [ORIGEN_V4]: { err: 'SERVFAIL', codigo: 'ESERVFAIL' } })
  });
  assert.equal(r.estado, asn.ESTADOS.SIN_DATOS);
  assert.match(r.error, /No se pudo consultar/);
});

test('si el resolver lanza, se trata como sin-datos y nunca reventa', async () => {
  const r = await asn.consultar('203.0.113.10', {
    dns: { consultar: async () => { throw new Error('red caida'); } }
  });
  assert.equal(r.estado, asn.ESTADOS.SIN_DATOS);
  assert.match(r.error, /red caida/);
});

test('si la zona de registro no contesta, el ASN sigue valiendo', async () => {
  const r = await asn.consultar('203.0.113.10', {
    dns: conDns({ [ORIGEN_V4]: DATOS_V4, [REGISTRO_15169]: { err: 'ETIMEDOUT', codigo: 'ETIMEDOUT' } })
  });

  assert.equal(r.estado, asn.ESTADOS.ENCONTRADO);
  assert.equal(r.asn, '15169', 'el numero no depende del nombre');
  assert.equal(r.nombre, null);
  assert.equal(r.avisos.length, 1);
  assert.match(r.avisos[0], /no se pudo conseguir/i);
});

test('un prefijo con varios ASN se guardan todos y manda el primero', async () => {
  const origen = asn.nombreDeOrigen('203.0.113.10');
  const r = await asn.consultar('203.0.113.10', {
    dns: conDns({
      [origen]: [
        '15169 | 8.8.8.0/24 | US | arin | 2023-12-28',
        '13335 | 8.8.8.0/24 | US | arin | 2010-07-14'
      ],
      [asn.nombreDeAsn('15169')]: NOMBRE_V4
    })
  });

  assert.equal(r.asn, '15169');
  assert.deepEqual(r.asns, ['15169', '13335']);
});

test('una IP que no es IP lanza con remediation', async () => {
  await assert.rejects(() => asn.consultar('no es una ip', { dns: conDns() }), (error) => {
    assert.equal(error.code, 'PARAM_INVALIDO');
    assert.ok(error.remediation);
    return true;
  });
});