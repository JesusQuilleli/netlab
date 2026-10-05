'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const rdap = require('../src/core/net/rdap');

// ------------------------------------------------------------------ dominios

/**
 * Bootstrap de nombres. La diferencia con el de IPs no es cosmetica: aqui el
 * primer elemento de cada entrada es una LISTA de sufijos, no un prefijo, asi
 * que es justo el caso que rompe `aEntradas` y `servidorPara` si se reutilizan.
 */
const BOOTSTRAP_DOMINIOS = [
  [['com', 'net'], ['https://rdap.ejemplo-registro.example/']],
  [['org'], ['https://rdap.fallido.example/', 'https://rdap.respaldo.example/']],
  [['ve'], ['https://rdap.venezuela.example/']]
];

/** `domain` de un registro, con los campos que consulta la herramienta web. */
const DOMINIO = {
  objectClassName: 'domain',
  ldhName: 'ejemplo.com',
  handle: 'DOM-1-2-3',
  status: ['client delete prohibited', 'client transfer prohibited'],
  country: 'US',
  nameservers: [{ ldhName: 'NS1.EJEMPLO.COM' }, { ldhName: 'ns2.ejemplo.com' }],
  events: [
    { eventAction: 'registration', eventDate: '2015-06-01T10:00:00Z' },
    { eventAction: 'last changed', eventDate: '2025-01-02T08:30:00Z' },
    { eventAction: 'expiration', eventDate: '2031-06-01T10:00:00Z' }
  ],
  entities: [
    { roles: ['registrar'], vcardArray: vcard(['fn', 'Example Registrar Inc']) },
    { roles: ['registrant'], vcardArray: vcard(['fn', 'Titular Del Dominio']) },
    { roles: ['technical'], vcardArray: vcard(['fn', 'Tecnico Del Dominio']) }
  ],
  links: [{ rel: 'self', href: 'https://rdap.ejemplo-registro.example/domain/ejemplo.com' }]
};

test('consulta la caducidad y el registrador de un dominio', async () => {
  const r = await rdap.consultarDominio('ejemplo.com', {
    bootstrap: BOOTSTRAP_DOMINIOS,
    fetchImpl: doble(DOMINIO)
  });
  assert.equal(r.disponible, true);
  assert.equal(r.dominio, 'ejemplo.com');
  assert.equal(r.caducidad, '2031-06-01T10:00:00Z');
  assert.equal(r.registro, '2015-06-01T10:00:00Z');
  assert.equal(r.registrador, 'Example Registrar Inc');
  assert.equal(r.titular, 'Titular Del Dominio');
  assert.equal(r.servidor, 'https://rdap.ejemplo-registro.example/');
});

test('construye la URL /domain/ con el nombre en minuscula', async () => {
  const vistas = [];
  await rdap.consultarDominio('EJEMPLO.COM', {
    bootstrap: BOOTSTRAP_DOMINIOS,
    fetchImpl: async (url) => {
      vistas.push(String(url));
      return { ok: true, status: 200, json: async () => DOMINIO, text: async () => JSON.stringify(DOMINIO) };
    }
  });
  assert.ok(vistas[0].startsWith('https://rdap.ejemplo-registro.example/domain/ejemplo.com'));
});

test('encuentra el TLD aunque la entrada agrupe varios sufijos', () => {
  const e = rdap.servidorParaTld('net', BOOTSTRAP_DOMINIOS);
  assert.equal(e.prefijo, 'net');
  assert.deepEqual(e.urls, ['https://rdap.ejemplo-registro.example/']);
});

test('el punto delante del TLD no rompe la busqueda', () => {
  assert.equal(rdap.servidorParaTld('.com', BOOTSTRAP_DOMINIOS).prefijo, 'com');
});

test('buscar un TLD sin bootstrap devuelve null en vez de reventar', () => {
  // Se llama a mano, no desde `consultarDominio`, y es facil olvidar el segundo
  // argumento. Que eso lance un TypeError convierte una llamada mal formada en
  // un fallo de modulo, y el error que sale ("services is not iterable") no
  // dice nada de que el problema era la lista de servicios.
  assert.equal(rdap.servidorParaTld('com'), null);
  assert.equal(rdap.servidorParaTld('com', null), null);
  assert.equal(rdap.servidorParaTld('com', {}), null);
  assert.equal(rdap.servidorParaTld('', BOOTSTRAP_DOMINIOS), null);
  assert.deepEqual(rdap.entradasDeDominio(undefined), []);
});

test('una entrada de bootstrap con forma rara se salta en vez de romper', () => {
  // El bootstrap lo publica IANA y no lo controlamos: una entrada rara no puede
  // impedir que se consulten los TLD que sí valen.
  const entradas = rdap.entradasDeDominio([
    null,
    ['no-es-una-entrada'],
    [[]],
    [['com'], ['https://rdap.ejemplo-registro.example/']],
    [['net', 'org'], ['https://rdap.ejemplo-registro.example/'], 'sobra']
  ]);

  assert.equal(entradas.length, 2);
  assert.deepEqual(entradas[0].tlds, ['com']);
  assert.deepEqual(entradas[1].tlds, ['net', 'org']);
});

test('client transfer prohibited NO es una retencion', async () => {
  // Casi todos los dominios del mundo lo tienen, para que nadie se los lleve por
  // error. Avisar de eso llenaria el informe de ruido.
  const r = await rdap.consultarDominio('ejemplo.com', {
    bootstrap: BOOTSTRAP_DOMINIOS,
    fetchImpl: doble(DOMINIO)
  });
  assert.match(r.estados, /client transfer prohibited/);
  assert.deepEqual(r.retenciones, []);
});

test('client hold es una retencion y se separa de los estados normales', async () => {
  const retenido = { ...DOMINIO, status: ['client hold', 'client transfer prohibited'] };
  const r = await rdap.consultarDominio('ejemplo.com', {
    bootstrap: BOOTSTRAP_DOMINIOS,
    fetchImpl: doble(retenido)
  });
  assert.deepEqual(r.retenciones, ['client hold']);
});

test('un TLD sin RDAP dice que no es consultable, no que el dominio no existe', async () => {
  // Esta distincion es la que evita decir "el dominio esta vacio" cuando en
  // realidad no lo ha preguntado nadie.
  const r = await rdap.consultarDominio('ejemplo.invalidotld', {
    bootstrap: BOOTSTRAP_DOMINIOS,
    fetchImpl: doble(DOMINIO)
  });
  assert.equal(r.disponible, false);
  assert.equal(r.consultable, false);
  assert.match(r.motivo, /\.invalidotld/);
});

test('un nombre sin TLD se rechaza con un mensaje util', async () => {
  await assert.rejects(() => rdap.consultarDominio('localhost', { bootstrap: BOOTSTRAP_DOMINIOS }), (e) => {
    assert.match(e.remediation, /TLD/);
    return true;
  });
});

test('404 en todos los servidores es "no registrado", no un fallo', async () => {
  // Todos los servidores del TLD contestan 404: eso es una respuesta, no una
  // averia. El informe debe poder decir "no aparece en ningun registro".
  const r = await rdap.consultarDominio('ejemplo.org', {
    bootstrap: BOOTSTRAP_DOMINIOS,
    fetchImpl: async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '{}' })
  });
  assert.equal(r.disponible, false);
  assert.equal(r.consultable, true);
  assert.match(r.motivo, /Ningun registro publico/);
});

test('si el primer registro falla por red, prueba el siguiente', async () => {
  let n = 0;
  const r = await rdap.consultarDominio('ejemplo.org', {
    bootstrap: BOOTSTRAP_DOMINIOS,
    fetchImpl: async (url) => {
      n += 1;
      if (String(url).includes('fallido')) {
        return { ok: false, status: 500, json: async () => ({}), text: async () => 'error' };
      }
      return { ok: true, status: 200, json: async () => DOMINIO, text: async () => JSON.stringify(DOMINIO) };
    }
  });
  assert.equal(r.disponible, true);
  assert.ok(n >= 2, 'debe haber intentado el segundo servidor');
});

test('un fallo de red en todos los registros lanza, no inventa', async () => {
  await assert.rejects(
    () =>
      rdap.consultarDominio('ejemplo.org', {
        bootstrap: BOOTSTRAP_DOMINIOS,
        fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}), text: async () => 'nope' })
      }),
    (e) => {
      assert.match(e.remediation, /temporal/);
      return true;
    }
  );
});

test('no se copian los contactos tecnico ni administrativo', async () => {
  // Son datos personales de los titulares y el informe no los usa.
  const r = await rdap.consultarDominio('ejemplo.com', {
    bootstrap: BOOTSTRAP_DOMINIOS,
    fetchImpl: doble(DOMINIO)
  });
  const serializado = JSON.stringify(r);
  assert.ok(!serializado.includes('Tecnico Del Dominio'));
});

/**
 * Bootstrap de mentira, con la misma forma que el de IANA: una entrada por
 * bloque, con sus URLs. Se pasa en `opciones.bootstrap` para no tocar la red.
 */
const BOOTSTRAP_FALSO = [
  [['0.0.0.0/0'], ['https://rdap.example.ra/', 'https://rdap.example.co/']],
  [['1.0.0.0/8'], ['https://rdap.ochenta.example/']],
  [['1.2.0.0/16'], ['https://rdap.dieciseis.example/']],
  [['2001:db8::/32'], ['https://rdap.seis.example/']]
];

/** Propiedad de vCard como la devuelve RDAP: nombre, parametros, tipo, valor. */
function vcard(...pares) {
  return ['vcard', pares.map(([propiedad, valor]) => [propiedad, {}, 'text', valor])];
}

/** `inetnum` de ARIN, recortado a los campos que se tocan. */
const INETNUM = {
  objectClassName: 'inetnum',
  handle: 'NET-1-2-3-0-1',
  startAddress: '1.2.0.0',
  endAddress: '1.2.255.255',
  name: 'Example Networks',
  type: 'ASSIGNED',
  country: 'US',
  cidr0_cidrs: [{ v4prefix: '1.2.0.0', length: 16 }],
  events: [
    { eventAction: 'registration', eventDate: '2021-03-04T10:00:00Z' },
    { eventAction: 'last changed', eventDate: '2025-01-02T08:30:00Z' }
  ],
  entities: [
    { roles: ['abuse'], vcardArray: vcard(['fn', 'Example Abuse'], ['email', 'abuse@example.net']) },
    { roles: ['technical'], vcardArray: vcard(['fn', 'Ejemplo Tecnico'], ['email', 'tec@example.net']) }
  ],
  remarks: [{ title: 'remarks', description: ['Bloque de ejemplo.'] }],
  links: [{ rel: 'self', href: 'https://rdap.dieciseis.example/ip/1.2.3.4' }],
  status: ['active']
};

/** `fetch` de mentira que responde con el mismo cuerpo a cualquier URL. */
function doble(cuerpo, { solo404 = false } = {}) {
  return async (url) => {
    if (solo404 && !String(url).includes('respaldo')) {
      return { ok: false, status: 404, json: async () => ({}), text: async () => '{}' };
    }
    return {
      ok: true,
      status: 200,
      json: async () => cuerpo,
      text: async () => JSON.stringify(cuerpo)
    };
  };
}

// ------------------------------------------------------------------ longest prefix

test('elige el prefijo mas largo, no el primero que encaja', async () => {
  const r = await rdap.consultar('1.2.3.4', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: doble(INETNUM) });
  assert.equal(r.prefijoRegistro, '1.2.0.0/16');
  assert.equal(r.servidor, 'https://rdap.dieciseis.example/');
});

test('con el bootstrap al reves, el mas largo sigue ganando', async () => {
  const r = await rdap.consultar('1.2.3.4', {
    bootstrap: [...BOOTSTRAP_FALSO].reverse(),
    fetchImpl: doble(INETNUM)
  });
  assert.equal(r.prefijoRegistro, '1.2.0.0/16');
});

test('si ningun prefijo concreto encaja, cae al /0', async () => {
  // El /0 es la ultima salida de siempre. Sin el, una IP de un tramo no
  // cubierto por bloques pequenos no tendria a quien preguntar.
  const r = await rdap.consultar('8.8.8.8', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: doble(INETNUM) });
  assert.equal(r.prefijoRegistro, '0.0.0.0/0');
});

test('un /32 no gana a un /24 que lo contiene', async () => {
  const b = [[['8.8.8.0/24'], ['https://rdap.veinticuatro.example/']], [['8.8.8.8/32'], ['https://rdap.exacto.example/']]];
  const r = await rdap.consultar('8.8.8.8', { bootstrap: b, fetchImpl: doble(INETNUM) });
  assert.equal(r.prefijoRegistro, '8.8.8.8/32');
});

// ------------------------------------------------------------------ IPv6

test('una IPv6 usa el bootstrap de IPv6 y no el de IPv4', async () => {
  let vistas = [];
  const cuerpo = {
    objectClassName: 'inet6num',
    name: 'Ejemplo v6',
    startAddress: '2001:db8::',
    endAddress: '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'
  };
  const fetchImpl = async (url) => {
    vistas.push(url);
    return { ok: true, status: 200, json: async () => cuerpo, text: async () => JSON.stringify(cuerpo) };
  };

  const r = await rdap.consultar('2001:db8::1', { bootstrap: BOOTSTRAP_FALSO, fetchImpl });
  assert.equal(r.prefijoRegistro, '2001:db8::/32');
  assert.equal(r.servidor, 'https://rdap.seis.example/');
  assert.ok(vistas[0].startsWith('https://rdap.seis.example/ip/2001'));
  assert.ok(decodeURIComponent(vistas[0]).includes('2001:db8::1'), 'la IPv6 llega al servidor legible');
  assert.ok(!vistas.some((u) => u.includes('/0')), 'no se pregunta al servidor del /0');
});

test('una IPv6 no casa con un prefijo IPv4', async () => {
  const soloV4 = BOOTSTRAP_FALSO.filter(([prefijos]) => prefijos.every((p) => !p.includes(':')));
  const r = await rdap.consultar('2001:db8::1', { bootstrap: soloV4, fetchImpl: doble(INETNUM) });

  // Sin coincidencia no hay servidor, y eso se dice en vez de preguntar al /0
  // de IPv4, que no es su registro.
  assert.equal(r.disponible, false);
  assert.match(r.motivo, /ningun servidor/i);
});

// ------------------------------------------------------------------ normalización

test('normaliza un inetnum con todos los campos utiles', async () => {
  const r = await rdap.consultar('1.2.3.4', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: doble(INETNUM) });

  assert.equal(r.disponible, true);
  assert.equal(r.handle, 'NET-1-2-3-0-1');
  assert.equal(r.nombre, 'Example Networks');
  assert.equal(r.tipo, 'ASSIGNED');
  assert.equal(r.pais, 'US');
  assert.equal(r.inicio, '1.2.0.0');
  assert.equal(r.fin, '1.2.255.255');
  assert.equal(r.prefijoCidr, '1.2.0.0/16');
  assert.equal(r.estado, 'active');
  assert.equal(r.nota, 'Bloque de ejemplo.');
  assert.equal(r.enlace, 'https://rdap.dieciseis.example/ip/1.2.3.4');
  assert.equal(r.registro, '2021-03-04T10:00:00Z');
  assert.equal(r.ultimoCambio, '2025-01-02T08:30:00Z');
});

test('coge el contacto de abuso y no el tecnico', async () => {
  const r = await rdap.consultar('1.2.3.4', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: doble(INETNUM) });

  assert.deepEqual(r.contactoAbuso, { nombre: 'Example Abuse', correo: 'abuse@example.net' });
  assert.ok(!JSON.stringify(r).includes('tec@example.net'), 'el contacto tecnico no se copia');
});

test('no copia el correo del titular: es dato personal y no hace falta', async () => {
  const datos = {
    ...INETNUM,
    entities: [
      { roles: ['abuse'], vcardArray: vcard(['email', 'abuse@example.net']) },
      { roles: ['registrant'], vcardArray: vcard(['fn', 'Persona Fisica'], ['email', 'privada@example.net']) }
    ]
  };

  const r = await rdap.consultar('1.2.3.4', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: doble(datos) });

  assert.equal(r.titular, 'Persona Fisica', 'el nombre del titular si sirve');
  assert.ok(!JSON.stringify(r).includes('privada@example.net'), 'su correo no se guarda en ninguna parte');
  assert.equal(r.contactoAbuso.correo, 'abuse@example.net');
});

test('la entidad de abuso anidada tambien se encuentra (formato ARIN)', async () => {
  // ARIN cuelga la organizacion del bloque un nivel mas abajo. Mirando solo el
  // nivel superior, `8.8.8.0/24` y casi todo su espacio salen sin contacto de
  // abuso, que es justo para lo que se mira un registro.
  const datos = {
    objectClassName: 'inetnum',
    handle: 'NET-8-8-8-0-2',
    name: 'Google LLC',
    startAddress: '8.8.8.0',
    endAddress: '8.8.255.255',
    entities: [
      {
        handle: 'GOGL',
        roles: ['registrant'],
        vcardArray: vcard(['fn', 'Google LLC']),
        entities: [
          { handle: 'ABUSE5250-ARIN', roles: ['abuse'], vcardArray: vcard(['fn', 'Abuse Contact'], ['email', 'network-abuse@google.com']) },
          { handle: 'ZG39-ARIN', roles: ['technical', 'administrative'], vcardArray: vcard(['fn', 'Technical'], ['email', 'tec@google.com']) }
        ]
      }
    ]
  };

  const r = await rdap.consultar('8.8.8.8', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: doble(datos) });

  assert.deepEqual(r.contactoAbuso, { nombre: 'Abuse Contact', correo: 'network-abuse@google.com' });
  assert.ok(!JSON.stringify(r).includes('tec@google.com'), 'el tecnico sigue sin copiarse');
});

test('sin etiqueta de abuso, no se disfraza a una entidad cualquiera', async () => {
  // El bloque de REDHOST no trae entidad de abuso: referencia `IL-892` como
  // `registrant`. Poner ese correo como "contacto de abuso" seria afirmar algo
  // que el registro no dice.
  const datos = {
    objectClassName: 'inetnum',
    handle: 'C11492042',
    name: 'REDHOST',
    startAddress: '166.0.112.0',
    endAddress: '166.0.112.255',
    entities: [
      {
        handle: 'IL-892',
        roles: ['registrant'],
        vcardArray: vcard(['fn', 'InterLIR LLC']),
        entities: [{ handle: 'TIMOK4-ARIN', roles: ['administrative'], vcardArray: vcard(['fn', 'InterLIR'], ['email', 'contact@interlir.example']) }]
      }
    ]
  };

  const r = await rdap.consultar('166.0.112.226', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: doble(datos) });

  assert.equal(r.contactoAbuso, null, 'no hay contacto de abuse publicado');
  assert.equal(r.titular, 'InterLIR LLC');
});

test('sin rango no inventa el ambito del bloque', async () => {
  const datos = { objectClassName: 'inetnum', handle: 'NET-SIN-RANGO', name: 'Ejemplo' };
  const r = await rdap.consultar('1.2.3.4', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: doble(datos) });

  assert.equal(r.inicio, null);
  assert.equal(r.fin, null);
  assert.equal(r.prefijoCidr, null);
  assert.equal(r.prefijoRegistro, '1.2.0.0/16', 'pero si se sabe a quien se pregunto');
});

test('un objeto entity sin nombre de bloque cae al handle', async () => {
  const datos = { objectClassName: 'entity', handle: 'E-12345' };
  const r = await rdap.consultar('1.2.3.4', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: doble(datos) });
  assert.equal(r.nombre, 'E-12345');
  assert.equal(r.tipoObjeto, 'entity');
});

// ------------------------------------------------------------------ fallos

test('sin datos de rango ni handle, el informe no se queda sin nada', async () => {
  const r = await rdap.consultar('1.2.3.4', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: doble({}) });
  assert.equal(r.disponible, true);
  assert.equal(r.handle, null);
  assert.equal(r.contactoAbuso, null);
  assert.equal(r.inicio, null);
});

test('si el primer servidor falla con 404, prueba el siguiente', async () => {
  // Los servidores RDAP de una misma base responden distinto segun quien tenga
  // el bloque, y es normal que uno no sepa y otro si.
  const r = await rdap.consultar('8.8.8.8', {
    bootstrap: [[['8.8.8.0/24'], ['https://rdap.primero.example/', 'https://rdap.respaldo.example/']]],
    fetchImpl: doble(INETNUM, { solo404: true })
  });

  assert.equal(r.disponible, true);
  assert.equal(r.servidor, 'https://rdap.respaldo.example/');
});

test('si nadie tiene la IP registrada, lo dice sin lanzar', async () => {
  const r = await rdap.consultar('8.8.8.8', {
    bootstrap: [[['8.8.8.0/24'], ['https://rdap.example/']]],
    fetchImpl: doble({}, { solo404: true })
  });

  assert.equal(r.disponible, false);
  assert.ok(r.motivo, 'deja escrito por que no hay registro');
  assert.ok(r.motivo.length > 0);
});

test('una IP que no es una IP falla antes de salir a la red', async () => {
  let llamadas = 0;
  await assert.rejects(
    () => rdap.consultar('no es una ip', { bootstrap: BOOTSTRAP_FALSO, fetchImpl: async () => { llamadas++; } }),
    (e) => {
      assert.ok(e.remediation, 'el error dice que escribir');
      return true;
    }
  );
  assert.equal(llamadas, 0, 'no se sale a la red con una entrada invalida');
});

test('si el bootstrap de IANA no trae servicios, avisa de donde actualizarlo', async () => {
  await assert.rejects(
    () => rdap.consultar('1.2.3.4', { fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => '{}' }) }),
    (e) => {
      assert.match(e.remediation, /BOOTSTRAP/);
      assert.match(e.remediation, /data\.iana\.org/);
      return true;
    }
  );
});
