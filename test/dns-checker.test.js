'use strict';

/**
 * test/dns-checker.test.js — Pruebas del comprobador de DNS.
 *
 * Todas las pruebas usan un módulo DNS falso inyectado por `ctx.dns`. Es
 * deliberado: una prueba que consulta gmail.com de verdad pasa hoy y falla
 * dentro de seis meses cuando Google cambia un registro, o cuando el equipo
 * está sin red. Lo que hay que verificar aquí es la lógica de los hallazgos y
 * el formato del informe, y eso no necesita Internet.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const dns = require('../src/tools/dns-checker');
const formats = require('../src/formats');
const { SECCION_KINDS: K } = require('../src/core/result');

/* ------------------------------------------------------------------ *
 * Utilidades
 * ------------------------------------------------------------------ */

function seccion(result, titulo) {
  const encontrada = result.sections.find((s) => s.title === titulo);
  assert.ok(encontrada, `no existe la seccion "${titulo}". Hay: ${result.sections.map((s) => s.title).join(', ')}`);
  return encontrada;
}

function hallazgo(result, texto) {
  const encontrado = result.findings.find((f) => f.title.includes(texto));
  assert.ok(encontrado, `no hay ningun hallazgo que hable de "${texto}". Hay: ${result.findings.map((f) => f.title).join(' ; ')}`);
  return encontrado;
}

function sinHallazgo(result, texto) {
  const encontrado = result.findings.find((f) => f.title.includes(texto));
  assert.ok(!encontrado, `no deberia haber un hallazgo sobre "${texto}", pero dice: "${encontrado?.title}"`);
}

/** Registro con resultado correcto. */
function ok(valores, ttl = null) {
  return { ok: true, valores, ttl, error: null, codigo: null, codigoDns: null };
}

/** Registro con fallo, distinguiendo el código crudo del resolvedor. */
function fallo(codigoDns, mensaje = 'fallo simulado') {
  return { ok: false, valores: [], ttl: null, error: mensaje, codigo: 'RED', codigoDns };
}

/**
 * Módulo DNS falso.
 *
 * @param {object} porTipo Respuesta por tipo de registro.
 * @param {object} [extra] { dmarc, ptr, dnssec }
 *   `dnssec` es un mapa tipo → resultado que se sirve vía `consultarDnssec`.
 *   Si no se dan, el método no existe y el chequeo DNSSEC se salta (como cuando
 *   se inyecta un módulo que no lo soporta).
 */
function dnsFalso(porTipo, extra = {}) {
  const dmarc = extra.dmarc ?? fallo('ENODATA', 'sin DMARC');
  const falso = {
    consultarLote: async (consultas) => consultas.map((c) => ({ ...c, ...(porTipo[c.tipo] ?? fallo('ENODATA', `sin ${c.tipo}`)) })),
    consultar: async (nombre, tipo) => {
      if (nombre.startsWith('_dmarc.')) return dmarc;
      return porTipo[tipo] ?? fallo('ENODATA', `sin ${tipo}`);
    },
    resolverPTR: async () => extra.ptr ?? []
  };
  if (extra.dnssec) {
    falso.consultarDnssec = async (_nombre, tipo) => extra.dnssec[tipo] ?? fallo('ENODATA', `sin ${tipo}`);
  }
  return falso;
}

/** DNSKEY y DS que casan entre sí, para un dominio firmado sin problemas. */
function dnssecSano() {
  return {
    DNSKEY: ok([
      { flags: 257, algorithm: 13, key: Buffer.from('00', 'hex'), keyTag: 2371 },
      { flags: 256, algorithm: 13, key: Buffer.from('00', 'hex'), keyTag: 34505 }
    ]),
    DS: ok([{ keyTag: 2371, algorithm: 13, digestType: 2, digest: Buffer.alloc(32, 1) }])
  };
}

/** Un dominio que resuelve bien en todo, como punto de partida. */
function baseSana() {
  return {
    A: ok(['93.184.216.34'], 300),
    AAAA: ok(['2606:2800:220:1:248:1893:25c8:1946'], 300),
    CNAME: fallo('ENODATA', 'sin CNAME'),
    MX: ok([{ exchange: 'mx1.ejemplo.com', priority: 10 }]),
    NS: ok(['ns1.ejemplo.com', 'ns2.ejemplo.com']),
    TXT: ok([['v=spf1 include:_spf.ejemplo.com ~all']]),
    SOA: ok([{ nsname: 'ns1.ejemplo.com', hostmaster: 'dns.ejemplo.com', serial: 2026093001, refresh: 900, retry: 900, expire: 1800, minttl: 60 }]),
    CAA: ok([{ critical: 0, issue: 'letsencrypt.org' }])
  };
}

/* ------------------------------------------------------------------ *
 * Formulario y normalización
 * ------------------------------------------------------------------ */

test('declara los campos que necesita el formulario', () => {
  assert.equal(dns.id, 'dns-checker');
  const nombres = dns.campos.map((c) => c.name);
  for (const esperado of ['dominio', 'tipos', 'inversa', 'comparar', 'timeout']) {
    assert.ok(nombres.includes(esperado), `falta el campo ${esperado}`);
  }
  const comparar = dns.campos.find((c) => c.name === 'comparar');
  assert.equal(comparar.default, false, 'comparar resolvers debe venir apagado: manda trafico a terceros');
});

test('limpia lo que se pega tal cual venga', async () => {
  const { normalizarDominio } = dns._internas;
  const casos = [
    ['ejemplo.com', 'ejemplo.com'],
    ['EJEMPLO.COM', 'ejemplo.com'],
    ['  ejemplo.com  ', 'ejemplo.com'],
    ['https://ejemplo.com', 'ejemplo.com'],
    ['http://ejemplo.com/', 'ejemplo.com'],
    ['https://ejemplo.com/mail?u=1#ancla', 'ejemplo.com'],
    ['https://ejemplo.com:8443/admin', 'ejemplo.com'],
    ['ejemplo.com.', 'ejemplo.com'],
    ['https://usuario:clave@ejemplo.com', 'ejemplo.com'],
    ['www.ejemplo.com', 'www.ejemplo.com'],
    ['servidor01', 'servidor01'],
    // Los nombres de servicio empiezan por guion bajo. Si el validador los
    // rechaza, el tipo SRV del formulario no sirve para nada.
    ['_dmarc.ejemplo.com', '_dmarc.ejemplo.com'],
    ['_sip._tcp.ejemplo.com', '_sip._tcp.ejemplo.com'],
    ['_25._tcp.ejemplo.com', '_25._tcp.ejemplo.com']
  ];
  for (const [entrada, esperado] of casos) {
    assert.equal(normalizarDominio(entrada), esperado, `"${entrada}" deberia quedar como "${esperado}"`);
  }
});

test('rechaza lo que no es un nombre de host', async () => {
  const { normalizarDominio } = dns._internas;
  // Ojo: `a/b` NO va aqui. La barra se interpreta como ruta, igual que en
  // `ejemplo.com/mail`, y queda `a`. Eso es lo correcto.
  for (const malo of ['esto no es un dominio', 'ejemplo.com|x', '-principio.com', 'fin-', 'a b.com', '😀.com', 'a..b', '.com']) {
    assert.throws(() => normalizarDominio(malo), /no parece un nombre de dominio|PARAM/, `"${malo}" deberia rechazarse`);
  }
});

test('la barra se interpreta como ruta de una URL, no como un nombre', async () => {
  const { normalizarDominio } = dns._internas;
  assert.equal(normalizarDominio('a/b'), 'a');
  assert.equal(normalizarDominio('ejemplo.com/mail'), 'ejemplo.com');
});

test('un dominio invalido devuelve un Result con error y no lanza', async () => {
  // Esto es lo que evita que el usuario vea un stack de Node en el navegador.
  for (const malo of ['esto no es un dominio', 'ejemplo.com|x', '-x.com']) {
    const r = await dns.ejecutar({ dominio: malo });
    assert.equal(r.status, 'error', `"${malo}" deberia dar error, no lanzar`);
    assert.ok(r.error.code, 'el error necesita un codigo estable');
    assert.ok(r.error.remediation, 'el error deberia sugerir como corregirlo');
  }
});

test('sin dominio devuelve ENTRADA_VACIA', async () => {
  for (const vacio of ['', '   ', null, undefined]) {
    const r = await dns.ejecutar({ dominio: vacio });
    assert.equal(r.status, 'error');
    assert.equal(r.error.code, 'ENTRADA_VACIA', `"${vacio}" deberia dar ENTRADA_VACIA`);
  }
});

test('el objetivo guarda lo que se escribio, no el nombre ya limpio', async () => {
  // Si el dominio esta mal escrito, el informe tiene que poder reproducirlo.
  const r = await dns.ejecutar({ dominio: 'esto no vale' });
  assert.equal(r.target, 'esto no vale', 'el objetivo debe ser la entrada original');
});

test('valida la lista de tipos de registro', async () => {
  const { parseTipos, TIPOS_SOPORTADOS } = dns._internas;
  assert.deepEqual(parseTipos(''), ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'], 'vacio significa todos');
  assert.deepEqual(parseTipos('a, mx'), ['A', 'MX'], 'normaliza y quita duplicados');
  assert.deepEqual(parseTipos('A  MX  A'), ['A', 'MX'], 'los repetidos se eliminan');
  assert.deepEqual(parseTipos('SRV'), ['SRV'], 'SRV es valido para nombres de servicio');
  assert.throws(() => parseTipos('A, INVENTADO'), /no soportado/);
  assert.ok(!TIPOS_SOPORTADOS.includes('PTR'), 'PTR no se pide por nombre: usa el campo de la IP');
  assert.throws(() => parseTipos('PTR'), /no soportado/, 'y debe rechazarse si se escribe a mano');
});

test('valida la IP de la resolucion inversa', async () => {
  const { normalizarIp } = dns._internas;
  assert.equal(normalizarIp('8.8.8.8'), '8.8.8.8');
  assert.equal(normalizarIp('[2001:db8::1]'), '2001:db8::1', 'admite IPv6 entre corchetes');
  assert.equal(normalizarIp(''), null, 'vacio significa que no se pide');
  assert.equal(normalizarIp(null), null);
  assert.throws(() => normalizarIp('999.1.1.1'), /no es una direcci[oó]n IP/i);
  assert.throws(() => normalizarIp('no-es-ip'), /no es una direcci[oó]n IP/i);
  assert.throws(() => normalizarIp('2001:db8::1::2'), /no es una direcci[oó]n IP/i, 'una IPv6 mal formada tambien se rechaza');
});

/* ------------------------------------------------------------------ *
 * Hallazgos
 * ------------------------------------------------------------------ */

test('un nombre que no existe es un fallo y no seSigue inventando', async () => {
  const r = await dns.ejecutar(
    { dominio: 'no-existe-este.com' },
    { dns: dnsFalso({ A: fallo('ENOTFOUND', 'El nombre no existe (NXDOMAIN)'), AAAA: fallo('ENOTFOUND', 'El nombre no existe (NXDOMAIN)') }) }
  );

  assert.equal(r.status, 'fail', 'NXDOMAIN tiene que ser un fallo, no un aviso');
  const h = hallazgo(r, 'no existe');
  assert.equal(h.severity, 'error');
  assert.match(h.recommendation, /ortografia|delegad/i);
  // Un nombre inexistente no puede decirte que le faltan SPF o DMARC: no hay
  // nada que arreglar en un dominio que no esta.
  assert.equal(r.findings.length, 1, 'debe quedarse en un unico hallazgo');
});

test('detecta que el nombre existe pero no resuelve a ninguna direccion', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso({ A: ok([]), AAAA: ok([]), NS: ok(['ns1.ejemplo.com']) }) });
  assert.equal(r.status, 'fail');
  hallazgo(r, 'no resuelve a ninguna');
});

test('avisa cuando hay IPv4 pero no IPv6, y lo distingue de un error', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]) }) });
  const solo4 = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso({ ...baseSana(), AAAA: ok([]) }, { dmarc: ok([['v=DMARC1; p=none']]) }) });

  hallazgo(r, 'IPv4 e IPv6');
  sinHallazgo(r, 'Sin IPv6');
  assert.equal(solo4.status, 'pass', 'solo IPv4 es normal, no un fallo');
  assert.equal(hallazgo(solo4, 'Sin IPv6').severity, 'info');
});

test('un dominio sin correo da informacion, no un aviso', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso({ ...baseSana(), MX: ok([]) }, { dmarc: ok([['v=DMARC1; p=none']]) }) }
  );
  assert.equal(hallazgo(r, 'Sin servidores de correo').severity, 'info', 'no tener MX es normal en un sitio web');
  sinHallazgo(r, 'Sin registro SPF');
  sinHallazgo(r, 'Sin registro DMARC');
});

test('con correo pero sin SPF avisa', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso({ ...baseSana(), TXT: ok([['google-site-verification=abc']]) }, { dmarc: ok([['v=DMARC1; p=reject']]) }) }
  );
  assert.equal(hallazgo(r, 'Sin registro SPF').severity, 'warn');
  sinHallazgo(r, 'Sin registro DMARC');
});

test('el DMARC se busca en _dmarc, no en los TXT del dominio', async () => {
  // Regresión: se buscaba "v=DMARC1" entre los TXT del propio dominio, donde
  // nunca está, así que la comprobación daba "no hay DMARC" siempre, incluso
  // en dominios que sí lo tienen publicado.
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=reject; rua=mailto:a@ejemplo.com']]) }) }
  );

  sinHallazgo(r, 'Sin registro DMARC');
  const log = r.logs.find((l) => l.channel === 'dns' && /DMARC/.test(l.message));
  assert.ok(log, 'debe quedar constancia de que se consulto _dmarc');
  assert.match(log.message, /encontrado/);
});

test('avisa si el DMARC de verdad no esta', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso(baseSana(), { dmarc: fallo('ENODATA', 'sin DMARC') }) });
  const h = hallazgo(r, 'Sin registro DMARC');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /_dmarc\.ejemplo\.com/, 'el detalle debe nombrar el registro que falta');
});

test('detecta un alias y explica que impide poner otros registros', async () => {
  const r = await dns.ejecutar(
    { dominio: 'www.ejemplo.com' },
    { dns: dnsFalso({ ...baseSana(), CNAME: ok(['ejemplo.com']) }, { dmarc: ok([['v=DMARC1; p=none']]) }) }
  );
  const h = hallazgo(r, 'alias');
  assert.match(h.detail, /ejemplo\.com/);
  assert.match(h.recommendation, /CNAME/);
});

test('avisa de un TTL muy bajo pero no lo convierte en problema', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso({ ...baseSana(), A: ok(['93.184.216.34'], 30) }, { dmarc: ok([['v=DMARC1; p=none']]) }) }
  );
  assert.equal(hallazgo(r, 'TTL muy bajo').severity, 'info');
  assert.equal(r.status, 'pass');
});

test('avisa de SERVFAIL por separado de NXDOMAIN', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso({ A: fallo('ESERVFAIL', 'SERVFAIL'), AAAA: ok(['2606::1']) }) });
  assert.equal(hallazgo(r, 'SERVFAIL').severity, 'error');
  sinHallazgo(r, 'no existe', 'SERVFAIL no es NXDOMAIN: el nombre sí existe');
});

test('avisa de la consulta agotada sin romper el resto del informe', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso({ A: ok(['93.184.216.34'], 300), MX: fallo('ETIMEDOUT', 'tiempo agotado') }, { dmarc: ok([['v=DMARC1; p=none']]) }) }
  );
  assert.equal(hallazgo(r, 'agotó').severity, 'warn');
  // El resto de la tabla se sigue mostrando: un registro que falla no puede
  // vaciar el informe entero.
  assert.equal(seccion(r, 'Registros').rows.length, 8, 'deben aparecer los ocho tipos');
});

test('avisa si la IP no tiene PTR', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com', inversa: '192.0.2.1' },
    { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]), ptr: [] }) }
  );
  assert.equal(hallazgo(r, 'no tiene PTR').severity, 'warn');

  const tabla = seccion(r, 'Resolución inversa');
  assert.deepEqual(tabla.columns, ['Dirección', 'Nombre (PTR)', 'Resultado']);
  assert.equal(tabla.rows[0][0], '192.0.2.1');
  assert.equal(tabla.rows[0][1], '—', 'sin PTR, la celda del nombre va con guion');
  assert.equal(tabla.rows[0][2].valor, 'Sin PTR');
  assert.equal(tabla.rows[0][2].tone, 'warn');
});

test('muestra el PTR si la IP lo tiene', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com', inversa: '8.8.8.8' },
    { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]), ptr: ['dns.google'] }) }
  );
  const fila = seccion(r, 'Resolución inversa').rows[0];
  assert.equal(fila[1], 'dns.google');
  assert.equal(fila[2].valor, 'Definido');
  assert.equal(hallazgo(r, 'tiene PTR').severity, 'info');
});

test('no dice nada de la inversa si no se pide', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]) }) });
  assert.ok(!r.sections.some((s) => s.title === 'Resolución inversa'));
  sinHallazgo(r, 'PTR');
});

test('acortar los tipos no inventa avisos sobre lo no consultado', async () => {
  // Regresión de fondo: un tipo que no se pidió se estaba tratando igual que uno
  // que se pidió y vino vacío. Al pedir solo los TXT de una politica DMARC, que
  // por definicion no tiene ni A ni MX ni NS, el informe salia con "el nombre no
  // resuelve a ninguna direccion" en rojo. Eso hacia que acortar la consulta,
  // que es lo razonable para ahorrar lookups, empeorase el informe.
  const r = await dns.ejecutar(
    { dominio: '_dmarc.ejemplo.com', tipos: 'TXT' },
    { dns: dnsFalso({ TXT: ok([['v=DMARC1; p=reject; rua=mailto:a@ejemplo.com']]) }) }
  );

  assert.equal(r.status, 'pass', 'un TXT pedido y recibido es un informe correcto');
  assert.equal(r.findings.length, 0, `sin hallazgos, pero salen: ${r.findings.map((f) => f.title).join(' ; ')}`);
  assert.equal(seccion(r, 'Registros').rows.length, 1, 'una sola fila, la del TXT pedido');
  assert.ok(!r.sections.some((s) => s.title === 'Cabecera SOA'), 'no se consulto SOA, no se inventa la seccion');
});

test('pedir un subconjunto de tipos no complains de los demas', async () => {
  // A, AAAA, MX, NS, SOA vacios: solo se consulta el TXT, y no debe decir ni
  // que falta IPv6, ni que no hay correo, ni que faltan NS.
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com', tipos: 'TXT' },
    { dns: dnsFalso({ TXT: ok([['texto suelto']]) }) }
  );
  sinHallazgo(r, 'IPv6');
  sinHallazgo(r, 'direcciones');
  sinHallazgo(r, 'correo');
  sinHallazgo(r, 'servidores de nombres');
  sinHallazgo(r, 'resuelve');
});

test('un SRV se puede consultar gracias al guion bajo', async () => {
  const srv = { priority: 10, weight: 5, port: 587, name: 'smtp.ejemplo.com' };
  const r = await dns.ejecutar(
    { dominio: '_sip._tcp.ejemplo.com', tipos: 'SRV' },
    { dns: dnsFalso({ SRV: ok([srv]) }) }
  );

  assert.equal(r.status, 'pass');
  const fila = seccion(r, 'Registros').rows[0];
  assert.equal(fila[0], 'SRV');
  assert.equal(fila[1], '10 5 587 smtp.ejemplo.com', 'prioridad, peso, puerto y nombre en ese orden');
});

test('un DMARC se puede consultar a mano y sale bien', async () => {
  const r = await dns.ejecutar(
    { dominio: '_dmarc.ejemplo.com', tipos: 'TXT' },
    { dns: dnsFalso({ TXT: ok([['v=DMARC1; p=none; sp=quarantine']]) }) }
  );
  const fila = seccion(r, 'Registros').rows[0];
  assert.equal(fila[1], 'v=DMARC1; p=none; sp=quarantine', 'el TXT se lee entero, no cortado');
});

/* ------------------------------------------------------------------ *
 * DNSSEC
 * ------------------------------------------------------------------ */

test('en el chequeo por defecto diagnostica un dominio firmado', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]), dnssec: dnssecSano() }) }
  );

  assert.equal(r.status, 'pass', `hallazgos: ${r.findings.map((f) => f.title).join(' ; ')}`);
  assert.equal(hallazgo(r, 'Firmado con DNSSEC').severity, 'info');
  sinHallazgo(r, 'DS no corresponde');
  sinHallazgo(r, 'sin DS en la zona padre');

  const secc = seccion(r, 'Estado DNSSEC');
  assert.equal(secc.items.find(([k]) => k === 'Estado')[1], 'Firmado');
  const claves = secc.items.find(([k]) => k === 'Claves DNSKEY')[1];
  assert.match(claves, /KSK/, 'cuenta la KSK');
  assert.match(claves, /keyTag 2371/, 'y dice el keyTag');
  assert.equal(secc.items.find(([k]) => k === 'DS en la zona padre')[1], '1 DS (keyTag 2371)');
  assert.equal(r.summary.find((s) => s.label === 'DNSSEC').value, 'Firmado');
});

test('un dominio sin firmar es información, no un aviso ni un fallo', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]), dnssec: { DNSKEY: ok([]), DS: ok([]) } }) }
  );
  assert.equal(r.status, 'pass');
  assert.equal(hallazgo(r, 'Sin DNSSEC').severity, 'info');
  assert.equal(seccion(r, 'Estado DNSSEC').items.find(([k]) => k === 'Estado')[1], 'Sin firmar');
});

test('un DS sin clave publicada detrás es un fallo de verdad', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso(baseSana(), { dnssec: { DNSKEY: ok([]), DS: ok([{ keyTag: 999, algorithm: 13, digestType: 2, digest: Buffer.alloc(32, 1) }]) } }) }
  );
  assert.equal(r.status, 'fail', 'una promesa de clave sin clave rompe la resolución');
  assert.equal(hallazgo(r, 'no publica las claves').severity, 'error');
});

test('firmado pero sin DS en la zona padre avisa', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]), dnssec: { ...dnssecSano(), DS: ok([]) } }) }
  );
  assert.equal(r.status, 'warn');
  assert.equal(hallazgo(r, 'sin DS en la zona padre').severity, 'warn');
});

test('un DS que no corresponde con ninguna DNSKEY es un fallo', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso(baseSana(), { dnssec: { DNSKEY: ok([{ flags: 257, algorithm: 13, key: Buffer.from('00', 'hex'), keyTag: 2371 }]), DS: ok([{ keyTag: 999, algorithm: 13, digestType: 2, digest: Buffer.alloc(32, 1) }]) } }) }
  );
  assert.equal(r.status, 'fail');
  const h = hallazgo(r, 'no corresponde con ninguna clave');
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /keyTag 999/, 'debe nombrar la DS problemática');
  assert.match(h.detail, /keyTag 2371/, 'y la clave que sí está publicada');
});

test('acortar los tipos no dispara la consulta DNSSEC', async () => {
  let llamadas = 0;
  const espia = dnsFalso({ TXT: ok([['v=DMARC1; p=reject; rua=mailto:a@ejemplo.com']]) });
  espia.consultarDnssec = async () => { llamadas++; return ok([]); };

  const r = await dns.ejecutar({ dominio: '_dmarc.ejemplo.com', tipos: 'TXT' }, { dns: espia });

  assert.equal(llamadas, 0, 'un tipo pedido a mano no debe arrastrar DNSKEY ni DS');
  assert.ok(!r.sections.some((s) => s.title === 'Estado DNSSEC'), 'no debe existir la sección');
  assert.equal(r.findings.length, 0);
});

test('DNSKEY y DS se pueden pedir a mano y la cadena se sigue revisando', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com', tipos: 'DNSKEY,DS' },
    {
      dns: dnsFalso(
        {
          ...baseSana(),
          DNSKEY: ok([{ flags: 257, algorithm: 13, key: Buffer.from('00', 'hex'), keyTag: 2371 }]),
          DS: ok([{ keyTag: 2371, algorithm: 13, digestType: 2, digest: Buffer.alloc(32, 1) }])
        },
        { dmarc: ok([['v=DMARC1; p=none']]) }
      )
    }
  );

  assert.equal(r.status, 'pass');
  assert.equal(seccion(r, 'Registros').rows.length, 2, 'una fila por tipo pedido');
  assert.equal(hallazgo(r, 'Firmado con DNSSEC').severity, 'info', 'se reutiliza lo pedido para el veredicto');
});

test('los registros DNSSEC se formatean en una línea legible', () => {
  const { formatear, rolClave, nombrarAlgoritmo } = dns._internas;

  assert.equal(rolClave(257), 'KSK');
  assert.equal(rolClave(256), 'ZSK');
  assert.equal(nombrarAlgoritmo(13), 'ECDSAP256SHA256');

  assert.equal(
    formatear({ flags: 257, algorithm: 13, keyTag: 2371, key: Buffer.from('00', 'hex') }),
    'KSK · ECDSAP256SHA256 · keyTag 2371'
  );
  assert.equal(
    formatear({ keyTag: 2371, algorithm: 13, digestType: 2, digest: Buffer.alloc(32, 1), digestHex: '11'.repeat(32) }),
    'keyTag 2371 · ECDSAP256SHA256 · SHA-256 · 1111111111111111…'
  );
  assert.equal(
    formatear({ typeCovered: 'DNSKEY', algorithm: 13, keyTag: 2371, signersName: 'ejemplo.com', signature: Buffer.from('aa', 'hex'), expira: '2026-10-01' }),
    'RRSIG DNSKEY · ECDSAP256SHA256 · keyTag 2371 · ejemplo.com · expira 2026-10-01'
  );
  assert.equal(formatear({ nextDomain: 'next.ejemplo.com', rrtypes: ['A', 'MX'] }), 'NSEC → next.ejemplo.com · A MX');
  assert.equal(
    formatear({ iterations: 5, saltHex: 'ab12', rrtypes: ['A'], nextDomain: Buffer.from('ff', 'hex') }),
    'NSEC3 iter 5 · salt ab12 · A'
  );
  assert.equal(formatear({ flags: 0, iterations: 1, salt: Buffer.alloc(0), saltHex: '-' }), 'NSEC3PARAM iter 1 · salt -');
});

/* ------------------------------------------------------------------ *
 * Presentación
 * ------------------------------------------------------------------ */

test('la tabla de registros muestra el TTL o un guion si no se conoce', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]) }) });
  const tabla = seccion(r, 'Registros');

  assert.equal(tabla.kind, K.TABLA);
  assert.deepEqual(tabla.columns, ['Tipo', 'Valor', 'TTL', 'Resultado']);
  assert.equal(tabla.rows.length, 8, 'un tipo por fila');

  const a = tabla.rows.find((f) => f[0] === 'A');
  assert.equal(a[1], '93.184.216.34');
  assert.equal(a[2], '300');
  assert.equal(a[3].valor, '1 encontrado');

  const mx = tabla.rows.find((f) => f[0] === 'MX');
  assert.equal(mx[1], '10 mx1.ejemplo.com', 'el MX debe verse con su prioridad');

  const cname = tabla.rows.find((f) => f[0] === 'CNAME');
  assert.equal(cname[2], '—', 'sin TTL conocido se muestra un guion, no un 0 inventado');
  assert.equal(cname[3].tone, 'bad');
});

test('los TXT se enlazan sin separador', async () => {
  // Un registro de SPF partido en trozos tiene que releerse entero. Unirlo con
  // puntos produciría un registro inválido en el informe.
  const { formatear } = dns._internas;
  assert.equal(formatear(['v=spf1', 'include:_spf.ejemplo.com', '~all']), 'v=spf1include:_spf.ejemplo.com~all');
  assert.equal(formatear('texto plano'), 'texto plano');
  assert.equal(formatear({ exchange: 'mx.ejemplo.com', priority: 10 }), '10 mx.ejemplo.com');
  assert.equal(formatear({ port: 587, priority: 10, weight: 5, name: 'smtp.ejemplo.com' }), '10 5 587 smtp.ejemplo.com');
  assert.equal(formatear({ nsname: 'ns1.ejemplo.com', serial: 7 }), 'ns1.ejemplo.com (serial 7)');
  assert.equal(formatear({ critical: 0, issue: 'letsencrypt.org' }), '0 issue "letsencrypt.org"');
  assert.equal(formatear(null), '—');
});

test('muestra la cabecera SOA con el serial', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]) }) });
  const soa = seccion(r, 'Cabecera SOA');
  const valor = (clave) => soa.items.find(([k]) => k === clave)[1];

  assert.equal(valor('Servidor de nombres primario'), 'ns1.ejemplo.com');
  assert.equal(valor('Correo del responsable'), 'dns.ejemplo.com');
  assert.equal(valor('Serial'), 2026093001);
  assert.equal(r.summary.find((s) => s.label === 'Serial SOA').value, '2026093001');
});

test('avisa si la zona no devuelve SOA', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso({ ...baseSana(), SOA: ok([]) }, { dmarc: ok([['v=DMARC1; p=none']]) }) });
  assert.equal(hallazgo(r, 'no devuelve SOA').severity, 'warn');
});

test('el resumen cuenta lo encontrado', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]) }) });
  const valor = (etiqueta) => r.summary.find((s) => s.label === etiqueta)?.value;

  assert.equal(valor('Direcciones IPv4'), '1');
  assert.equal(valor('Direcciones IPv6'), '1');
  assert.equal(valor('Servidores de correo'), '1');
  assert.equal(valor('Servidores de nombres'), '2');
  assert.equal(valor('Resuelve'), 'Sí');
});

/* ------------------------------------------------------------------ *
 * Comparación de resolvers
 * ------------------------------------------------------------------ */

test('sin la casilla no se toca ningún otro resolver', async () => {
  let enLote = 0;
  const sueltos = [];
  const espia = {
    consultarLote: async (cs) => { enLote += cs.length; return cs.map((c) => ({ ...c, ...baseSana()[c.tipo] })); },
    consultar: async (nombre, tipo, opts) => { sueltos.push({ nombre, tipo, opts }); return ok([['v=DMARC1; p=none']]); },
    resolverPTR: async () => []
  };
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: espia });

  assert.equal(enLote, 8, 'un lote con los ocho tipos');
  assert.equal(sueltos.length, 1, 'y solo la consulta suelta del DMARC');
  assert.equal(sueltos[0].nombre, '_dmarc.ejemplo.com');
  assert.ok(!sueltos[0].opts.servers, 'ninguna consulta debe ir dirigida a un resolver publico');

  assert.ok(!r.sections.some((s) => s.title === 'Comparación de resolvers'), 'no debe existir la sección');
  sinHallazgo(r, 'resolvers');
});

test('diferencias de correo o de zona avisan, diferencias de dirección no', async () => {
  // Clasificación clave: un A distinto entre resolvers suele ser balanceo de
  // carga, mientras que un MX distinto significa que el correo depende de
  // quién pregunta.
  function dnsQueDifiere(tipoDiferente, valorSistema, valorOtro) {
    const propio = (tipo) => (tipo === tipoDiferente ? valorSistema : baseSana()[tipo]);
    const publico = (tipo) => (tipo === tipoDiferente ? valorOtro : baseSana()[tipo]);
    return {
      consultarLote: async (cs) => cs.map((c) => ({ ...c, ...baseSana()[c.tipo] })),
      consultar: async (nombre, tipo, opts) => {
        if (nombre.startsWith('_dmarc.')) return ok([['v=DMARC1; p=none']]);
        return opts?.servers ? publico(tipo) : propio(tipo);
      },
      resolverPTR: async () => []
    };
  }

  const enMX = await dns.ejecutar(
    { dominio: 'ejemplo.com', comparar: true, tipos: 'A,MX' },
    { dns: dnsQueDifiere('MX', baseSana().MX, ok([{ exchange: 'mx-interno.ejemplo.local', priority: 10 }])) }
  );
  assert.equal(hallazgo(enMX, 'no coinciden en MX').severity, 'warn', 'un MX distinto entre publicos y sistema es serio');
  sinHallazgo(enMX, 'direcciones de');

  const enA = await dns.ejecutar(
    { dominio: 'ejemplo.com', comparar: true, tipos: 'A,MX' },
    { dns: dnsQueDifiere('A', ok(['10.0.0.1'], 300), ok(['10.0.0.2'], 300)) }
  );
  sinHallazgo(enA, 'no coinciden en MX', 'el MX es identico en los tres, no debe aparecer');
  assert.equal(hallazgo(enA, 'no coinciden entre resolvers').severity, 'info', 'direcciones distintas es balanceo de carga, no un fallo');
});

test('una diferencia en un nombre interno se explica, no se alarma', async () => {
  function dnsInterno() {
    return {
      consultarLote: async (cs) => cs.map((c) => ({ ...c, ...baseSana()[c.tipo] })),
      consultar: async (nombre, tipo, opts) => {
        if (opts?.servers) return ok([]); // los publicos no conocen un nombre interno
        return tipo === 'A' ? ok(['10.0.0.5'], 300) : baseSana()[tipo];
      },
      resolverPTR: async () => []
    };
  }
  const r = await dns.ejecutar({ dominio: 'servidor01', comparar: true, tipos: 'A,MX' }, { dns: dnsInterno() });
  const h = r.findings.find((f) => /no coinciden/.test(f.title));
  assert.ok(h, 'debe comentar la diferencia');
  assert.equal(h.severity, 'info', 'que un resolver publico no conozca un nombre interno es lo esperable');
  assert.match(h.detail, /públicos?/);
});

test('si los tres resolvers coinciden lo dice', async () => {
  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com', comparar: true, tipos: 'A' },
    {
      dns: {
        consultarLote: async (cs) => cs.map((c) => ({ ...c, ...baseSana()[c.tipo] })),
        consultar: async (nombre, tipo) => (nombre.startsWith('_dmarc.') ? ok([['v=DMARC1; p=none']]) : baseSana()[tipo]),
        resolverPTR: async () => []
      }
    }
  );
  assert.equal(hallazgo(r, 'coinciden').severity, 'info');
  const tabla = seccion(r, 'Comparación de resolvers');
  assert.deepEqual(tabla.columns, ['Tipo', 'Sistema', 'Comparado con', 'Respuesta del otro', 'Veredicto']);
  assert.ok(tabla.rows.every((f) => f[4].valor === 'Igual'));
  assert.deepEqual([...new Set(tabla.rows.map((f) => f[2]))].sort(), ['Cloudflare', 'Google'], 'una fila por cada resolver publico');
});

test('el orden de los registros no cuenta como diferencia', async () => {
  // Dos resolvers que devuelven las mismas IPs en distinto orden no se están
  // contradiciendo: es balanceo de carga. Comparar sin ordenar daba "Difiere"
  // en casi todos los dominios grandes, y eso convertiría una función útil en
  // ruido que el usuario aprende a ignorar.
  const delSistema = ok(['93.184.216.34', '93.184.216.35', '93.184.216.36'], 300);
  const delPublico = ok(['93.184.216.36', '93.184.216.34', '93.184.216.35'], 300);

  const r = await dns.ejecutar(
    { dominio: 'ejemplo.com', comparar: true, tipos: 'A' },
    {
      dns: {
        consultarLote: async (cs) => cs.map((c) => ({ ...c, ...baseSana()[c.tipo] })),
        consultar: async (nombre, tipo, opts) => {
          if (nombre.startsWith('_dmarc.')) return ok([['v=DMARC1; p=none']]);
          return opts?.servers ? delPublico : delSistema;
        },
        resolverPTR: async () => []
      }
    }
  );

  const filas = seccion(r, 'Comparación de resolvers').rows;
  assert.equal(filas.length, 2, 'Cloudflare y Google');
  assert.ok(filas.every((f) => f[4].valor === 'Igual'), 'mismo conjunto, distinto orden: debe decir Igual');
  assert.ok(hallazgo(r, 'coinciden'), 'y el hallazgo debe confirmarlo');
});

/* ------------------------------------------------------------------ *
 * Comparación contra un archivo
 * ------------------------------------------------------------------ */

const ZONA_MINIMA = `ejemplo.com\t3600\tIN\tSOA\tns1.ejemplo.com. dns.ejemplo.com. 1 10000 2400 604800 3600
ejemplo.com\t86400\tIN\tNS\tns1.ejemplo.com.
ejemplo.com\t1\tIN\tA\t93.184.216.34 ; cf_tags=cf-proxied:false
ejemplo.com\t1\tIN\tMX\t10 mx1.ejemplo.com.
ejemplo.com\t1\tIN\tTXT\t"v=spf1 include:_spf.ejemplo.com ~all"
_dmarc.ejemplo.com\t1\tIN\tTXT\t"v=DMARC1; p=quarantine"
www.ejemplo.com\t1\tIN\tA\t93.184.216.34 ; cf_tags=cf-proxied:false
`;

/** DNS falso que responde lo que dice la zona de arriba. */
function dnsQueCumpleLaZona(ajustes = {}) {
  const base = {
    SOA: ok([{ nsname: 'ns1.ejemplo.com', hostmaster: 'dns.ejemplo.com', serial: 1, refresh: 10000, retry: 2400, expire: 604800, minttl: 3600 }]),
    NS: ok(['ns1.ejemplo.com']),
    A: ok(['93.184.216.34']),
    MX: ok([{ exchange: 'mx1.ejemplo.com', priority: 10 }]),
    TXT: ok([['v=spf1 include:_spf.ejemplo.com ~all']])
  };
  return {
    consultarLote: async (cs) =>
      cs.map((c) => {
        // Primero lo específico de cada nombre, y si no, la tabla por tipo.
        // Al revés devolvía el mismo registro A para los ocho tipos, y el
        // informe recibía IPs donde esperaba MX y TXT.
        const propio = ajustes.porNombre?.[c.nombre]?.[c.tipo];
        if (propio) return { ...c, ...propio };
        if (c.nombre === '_dmarc.ejemplo.com') return { ...c, ...ok([['v=DMARC1; p=quarantine']]) };
        return { ...c, ...(ajustes[c.tipo] ?? base[c.tipo] ?? fallo('ENODATA', `sin ${c.tipo}`)) };
      }),
    consultar: async (nombre) => (nombre.startsWith('_dmarc.') ? ok([['v=DMARC1; p=quarantine']]) : ok([])),
    resolverPTR: async () => []
  };
}

test('el texto del archivo no queda guardado en el Result', async () => {
  // El Result va al HTML, al PDF, al JSON y al historial. Guardar aqui el texto
  // del archivo dejaria una copia de la zona DNS del cliente en la base de
  // datos de la herramienta, sin que nadie lo pidiera. Al Result solo van el
  // nombre y el tamano.
  //
  // La sonda es un comentario: el parser lo ignora, asi que no puede salir en
  // ninguna seccion ni en los registros, y sin embargo estaria en el JSON si el
  // contenido se guardara entero. Un registro como "v=spf1" no sirve de sonda,
  // porque ese si aparece legítimamente en los resultados del DNS.
  const conComentario = `; sobra-interno-que-no-debe-persistir\n${ZONA_MINIMA}`;
  const r = await dns.ejecutar(
    { compararArchivo: true, archivoNombre: 'zona.txt', archivoContenido: conComentario },
    { dns: dnsQueCumpleLaZona() }
  );

  assert.equal(r.params.archivoContenido, undefined, 'el contenido no puede viajar en el Result');
  assert.equal(r.params.archivoNombre, 'zona.txt');
  assert.equal(r.params.archivoBytes, Buffer.byteLength(conComentario, 'utf8'));

  // Y tampoco puede quedar en ninguna parte del JSON serializado, que es lo
  // que se guarda de verdad.
  assert.ok(
    !JSON.stringify(r).includes('sobra-interno-que-no-debe-persistir'),
    'ni una linea del archivo puede quedar en el JSON'
  );
});

test('sin archivo no aparece la ficha del archivo', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: baseSana() });
  assert.ok(!('archivoBytes' in r.params), 'no hay archivo que medir');
  assert.ok(!('archivoContenido' in r.params));
});

test('compara el archivo contra el DNS y dice que coincide', async () => {
  const r = await dns.ejecutar({ compararArchivo: true, archivoContenido: ZONA_MINIMA }, { dns: dnsQueCumpleLaZona() });

  assert.equal(r.status, 'pass', `estado inesperado; hallazgos: ${r.findings.map((f) => f.title).join(' ; ')}`);
  const valor = (etiqueta) => r.summary.find((s) => s.label === etiqueta)?.value;
  assert.equal(valor('Formato del archivo'), 'Zona BIND (Cloudflare)');
  assert.equal(valor('Nombres en el archivo'), '3');
  assert.equal(valor('Coinciden'), '7');

  const tabla = seccion(r, 'Comparación con el archivo');
  assert.deepEqual(tabla.columns, ['Nombre', 'Tipo', 'Esperado en el archivo', 'Encontrado en DNS', 'Estado']);
  assert.equal(tabla.rows.length, 7);
  assert.ok(tabla.rows.every((f) => f[4].valor === 'Coincide'));

  const h = hallazgo(r, 'coincide con el archivo');
  assert.equal(h.severity, 'info');
});

test('un registro sin publicar es "Falta", no "Distinto"', async () => {
  // "No está publicado" y "está publicado con otro valor" piden acciones
  // opuestas: crear el registro o corregirlo. Juntarlos bajo "distinto" hace
  // que quien lo lea vaya a editar un registro que no existe.
  const r = await dns.ejecutar(
    { compararArchivo: true, archivoContenido: ZONA_MINIMA },
    { dns: dnsQueCumpleLaZona({ porNombre: { 'www.ejemplo.com': { A: ok([]) } } }) }
  );

  assert.equal(r.status, 'fail', 'un registro sin publicar es un fallo');
  assert.equal(r.summary.find((s) => s.label === 'Faltan').value, '1');

  const fila = seccion(r, 'Comparación con el archivo').rows.find((f) => f[0] === 'www.ejemplo.com');
  assert.equal(fila[4].valor, 'Falta');
  assert.equal(fila[3], 'sin registros');

  const h = hallazgo(r, 'no están publicados');
  assert.equal(h.severity, 'error');
  assert.match(h.recommendation, /crearlo/);
});

test('detecta un registro con otro valor', async () => {
  const r = await dns.ejecutar(
    { compararArchivo: true, archivoContenido: ZONA_MINIMA },
    { dns: dnsQueCumpleLaZona({ MX: ok([{ exchange: 'mx-DIFERENTE.ejemplo.com', priority: 10 }]) }) }
  );

  assert.equal(r.status, 'warn');
  const h = hallazgo(r, 'valor distinto');
  assert.equal(h.severity, 'warn');

  const fila = seccion(r, 'Comparación con el archivo').rows.find((f) => f[1] === 'MX');
  assert.equal(fila[4].valor, 'Distinto');
  assert.match(fila[3], /mx-diferente/i, 'los nombres se comparan en minúsculas: no importan las mayúsculas');
});

test('un registro distinto no se cuenta además como sobrante', async () => {
  // El valor real de un registro distinto no está en el archivo por
  // definición. Sin descartarlo salían dos avisos por el mismo problema y el
  // recuento de "sobrantes" mentía.
  const r = await dns.ejecutar(
    { compararArchivo: true, archivoContenido: ZONA_MINIMA },
    { dns: dnsQueCumpleLaZona({ MX: ok([{ exchange: 'mx-DIFERENTE.ejemplo.com', priority: 10 }]) }) }
  );
  assert.ok(!r.sections.some((s) => s.title === 'Registros que no están en el archivo'));
  assert.equal(r.summary.find((s) => s.label === 'Sobrantes'), undefined);
});

test('avisa de un registro de más, y de más peso si es de correo', async () => {
  const r = await dns.ejecutar(
    { compararArchivo: true, archivoContenido: ZONA_MINIMA },
    {
      dns: dnsQueCumpleLaZona({
        TXT: ok([['v=spf1 include:_spf.ejemplo.com ~all'], ['v=DKIM1; k=rsa; p=CLAVE']])
      })
    }
  );

  assert.equal(r.status, 'warn');
  const h = hallazgo(r, 'de correo o nombres extra');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /TXT/);

  const extras = seccion(r, 'Registros que no están en el archivo');
  assert.equal(extras.rows.length, 1);
  assert.match(extras.rows[0][2], /v=DKIM1/);
});

test('una IP de más da información, no alarma', async () => {
  const r = await dns.ejecutar(
    { compararArchivo: true, archivoContenido: ZONA_MINIMA },
    { dns: dnsQueCumpleLaZona({ A: ok(['93.184.216.34', '93.184.216.35']) }) }
  );
  const h = hallazgo(r, 'no son de correo');
  assert.equal(h.severity, 'info', 'una IP más puede ser una CDN y no es un problema');
  assert.equal(r.findings.filter((f) => f.severity === 'warn').length, 0);
});

test('el dominio escrito limita los nombres del archivo', async () => {
  const r = await dns.ejecutar(
    { dominio: 'www.ejemplo.com', compararArchivo: true, archivoContenido: ZONA_MINIMA },
    { dns: dnsQueCumpleLaZona() }
  );

  assert.equal(r.summary.find((s) => s.label === 'Nombres revisados').value, '1 de 3', 'solo se revisa el dominio pedido');
  assert.equal(seccion(r, 'Comparación con el archivo').rows.length, 1);
  assert.equal(seccion(r, 'Comparación con el archivo').rows[0][0], 'www.ejemplo.com');

  // La comparación del archivo no debe traer avisos propios: coincide entero.
  sinHallazgo(r, 'valor distinto');
  sinHallazgo(r, 'no están en el archivo');
  sinHallazgo(r, 'no se pudieron comprobar');
});

test('avisa si ningún nombre del archivo pertenece al dominio pedido', async () => {
  const r = await dns.ejecutar(
    { dominio: 'otro.com', compararArchivo: true, archivoContenido: ZONA_MINIMA },
    { dns: dnsQueCumpleLaZona() }
  );
  const h = hallazgo(r, 'Ningún nombre');
  assert.equal(h.severity, 'warn');
  assert.match(h.recommendation, /ejemplo\.com/, 'debe(listar los nombres que sí había');
});

test('acepta el formato de ticket igual que el de zona', async () => {
  const ticket = '**Registro MX** para el correo:\n\nNombre: `ejemplo.com`\nPrioridad: `10`\nValor: `mx1.ejemplo.com`\n';
  const r = await dns.ejecutar({ compararArchivo: true, archivoContenido: ticket }, { dns: dnsQueCumpleLaZona() });

  assert.equal(r.summary.find((s) => s.label === 'Formato del archivo').value, 'Texto de ticket');
  assert.equal(r.status, 'pass', `hallazgos: ${r.findings.map((f) => f.title).join(' ; ')}`);
});

test('un archivo ilegible da un error claro, no un informe vacío', async () => {
  const r = await dns.ejecutar({ compararArchivo: true, archivoContenido: 'esto no es un archivo de zona' });
  const h = hallazgo(r, 'No se reconoce el formato');
  assert.equal(h.severity, 'error');
  assert.match(h.recommendation, /Cloudflare/);
});

test('marcar la casilla sin adjuntar nada avisa de ello', async () => {
  const r = await dns.ejecutar({ compararArchivo: true });
  const h = hallazgo(r, 'no se adjuntó');
  assert.equal(h.severity, 'warn');
  assert.match(h.recommendation, /desactiva la casilla/);
});

test('una consulta que falla no dice que el registro falte', async () => {
  // "No lo sé" y "no está" son cosas distintas. Confundirlas hace que alguien
  // vaya a crear un registro que ya existe.
  const r = await dns.ejecutar(
    { compararArchivo: true, archivoContenido: ZONA_MINIMA },
    {
      dns: {
        consultarLote: async (cs) =>
          cs.map((c) => {
            if (c.tipo === 'SOA') return { ...c, ...fallo('ETIMEDOUT', 'tiempo agotado') };
            if (c.nombre === '_dmarc.ejemplo.com') return { ...c, ...ok([['v=DMARC1; p=quarantine']]) };
            if (c.nombre === 'www.ejemplo.com') return { ...c, ...ok(['93.184.216.34']) };
            return { ...c, ...dnsQueCumpleLaZona().consultarLote && {} };
          }),
        consultar: async () => ok([]),
        resolverPTR: async () => []
      }
    }
  );

  const h = hallazgo(r, 'no se pudieron comprobar');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /No es lo mismo que falte/);
});

test('sin dominio y sin archivo se explica qué hacer', async () => {
  const r = await dns.ejecutar({});
  assert.equal(r.status, 'error');
  assert.match(r.error.remediation, /archivo/i);
});

test('el archivo se puede combinar con la consulta normal y la inversa', async () => {
  const r = await dns.ejecutar(
    {
      dominio: 'ejemplo.com',
      compararArchivo: true,
      archivoContenido: ZONA_MINIMA,
      inversa: '8.8.8.8',
      tipos: 'A,MX'
    },
    {
      dns: {
        ...dnsQueCumpleLaZona(),
        resolverPTR: async () => ['dns.ejemplo.com']
      }
    }
  );

  assert.ok(seccion(r, 'Comparación con el archivo'), 'la comparación');
  assert.ok(seccion(r, 'Registros'), 'los registros del dominio consultado');
  assert.ok(seccion(r, 'Resolución inversa'), 'y la inversa');
});

test('la comparación no filtra el contenido del archivo a los logs', async () => {
  const lineas = [];
  await dns.ejecutar(
    { compararArchivo: true, archivoContenido: ZONA_MINIMA },
    { dns: dnsQueCumpleLaZona(), log: { info: (m) => lineas.push(m), warn: (m) => lineas.push(m), error: (m) => lineas.push(m) } }
  );
  assert.ok(lineas.length);
  assert.ok(!lineas.some((l) => l.includes('_spf.ejemplo.com')), 'el log resume, no vuelca el archivo entero');
});

/* ------------------------------------------------------------------ *
 * Contrato
 * ------------------------------------------------------------------ */

test('los cinco formatos renderizan un informe completo', async () => {
  const r = await dns.ejecutar(
    { dominio: 'https://ejemplo.com/x', inversa: '8.8.8.8', comparar: true, tipos: 'A,MX,NS,TXT,SOA' },
    {
      dns: {
        consultarLote: async (cs) => cs.map((c) => ({ ...c, ...baseSana()[c.tipo] })),
        consultar: async (nombre, tipo) => (nombre.startsWith('_dmarc.') ? ok([['v=DMARC1; p=none']]) : baseSana()[tipo]),
        resolverPTR: async () => ['dns.ejemplo.com']
      }
    }
  );

  assert.equal(r.status, 'pass');
  for (const formato of formats.soportados().map((f) => f.nombre)) {
    const salida = await formats.render(r, formato);
    assert.ok(salida.length > 0, `el formato ${formato} produjo una salida vacia`);
  }
  const txt = (await formats.render(r, 'txt')).toString('utf8');
  assert.match(txt, /ejemplo\.com/);
  assert.ok(Math.max(...txt.split('\n').map((l) => l.length)) <= 100, 'el TXT debe caber en el ancho del reporte');
});

test('un informe con error tambien se puede renderizar', async () => {
  const r = await dns.ejecutar({ dominio: 'no existe esto' });
  assert.equal(r.status, 'error');
  for (const formato of ['txt', 'md', 'html', 'json', 'pdf']) {
    assert.ok((await formats.render(r, formato)).length > 0, `${formato} deberia renderizar un Result con error`);
  }
});

test('el log del contexto recibe la traza', async () => {
  const lineas = [];
  await dns.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]) }), log: { info: (m) => lineas.push(m), error: (m) => lineas.push(m), warn: (m) => lineas.push(m) } }
  );
  assert.ok(lineas.length >= 1, 'debe registrar algo');
  assert.ok(lineas.some((l) => /ejemplo\.com/.test(l)), 'la traza debe nombrar el dominio');
});

test('funciona sin contexto ni logger', async () => {
  const r = await dns.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsFalso(baseSana(), { dmarc: ok([['v=DMARC1; p=none']]) }) });
  assert.equal(r.status, 'pass');
});
