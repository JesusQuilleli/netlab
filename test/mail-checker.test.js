'use strict';

/**
 * test/mail-checker.test.js — Pruebas del comprobador de correo.
 *
 * Se inyecta un DNS falso por `ctx.dns` y una comprobación de listas negras
 * falsa por `ctx.dnsbl`. Ninguna prueba sale a Internet: los registros de
 * ejemplo cambian, y una prueba que depende de ellos se rompe sola.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const mail = require('../src/tools/mail-checker');
const formats = require('../src/formats');
const mensajes = require('../src/core/mail/mensaje');
const verificar = require('../src/core/mail/verificar');
const { SECCION_KINDS: K } = require('../src/core/result');

/* ------------------------------------------------------------------ *
 * Utilidades
 * ------------------------------------------------------------------ */

function ok(valores, ttl = null) {
  return { ok: true, valores, ttl, error: null, codigo: null, codigoDns: null };
}

function fallo(codigoDns, mensaje = 'fallo simulado') {
  return { ok: false, valores: [], ttl: null, error: mensaje, codigo: 'RED', codigoDns };
}

/** DNS falso por nombre y tipo. */
function dnsMail(zonas = {}, extra = {}) {
  const ptr = extra.ptr || {};
  return {
    consultarLote: async (consultas) =>
      consultas.map((c) => ({ ...c, ...(zonas[c.nombre]?.[c.tipo] ?? fallo('ENODATA', `sin ${c.tipo} de ${c.nombre}`)) })),
    consultar: async (nombre, tipo) => zonas[nombre]?.[tipo] ?? fallo('ENODATA', `sin ${tipo}`),
    resolverPTR: async (ip) => ptr[ip] || []
  };
}

/** Listas negras falsas: dice lo que se le pide. */
function dnsblFalso(config = {}) {
  const listadas = new Set(config.listadas || []);
  const sinDatos = config.sinDatos || 0;
  const dbl = config.dbl; // 'limpio' | 'listada' | 'sin-datos'
  return {
    consultar: async (ip) => {
      const esta = listadas.has(ip);
      return {
        resultados: [],
        resumen: {
          listadas: esta ? 1 : 0,
          sinDatos,
          zonasListadas: esta ? ['zen.spamhaus.org'] : []
        }
      };
    },
    ...(dbl
      ? {
          consultarDominio: async (dominio) => ({
            estado: dbl,
            dominio,
            consultado: dominio,
            codigo: dbl === 'listada' ? '127.0.1.2' : null,
            error: dbl === 'sin-datos' ? 'no registrado en Spamhaus' : null,
            avisos: []
          })
        }
      : {})
  };
}

const RUTA_FIXTURES = path.join(__dirname, 'fixtures');
const correoSano = fs.readFileSync(path.join(RUTA_FIXTURES, 'correo-sano.eml'), 'utf8');
const correoSpam = fs.readFileSync(path.join(RUTA_FIXTURES, 'correo-spam.eml'), 'utf8');

/** Clave DKIM real, generada una sola vez. */
const CLAVE_DKIM = (() => {
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
})();

function seccion(result, titulo) {
  const encontrada = result.sections.find((s) => s.title === titulo);
  assert.ok(encontrada, `no existe la sección "${titulo}". Hay: ${result.sections.map((s) => s.title).join(', ')}`);
  return encontrada;
}

function hallazgo(result, texto) {
  const encontrado = result.findings.find((f) => f.title.includes(texto));
  assert.ok(encontrado, `no hay ningún hallazgo sobre "${texto}". Hay: ${result.findings.map((f) => f.title).join(' ; ')}`);
  return encontrado;
}

function sinHallazgo(result, texto) {
  const encontrado = result.findings.find((f) => f.title.includes(texto));
  assert.ok(!encontrado, `no debería haber un hallazgo sobre "${texto}", pero dice: "${encontrado?.title}"`);
}

function valorResumen(result, etiqueta) {
  return result.summary.find((s) => s.label === etiqueta)?.value;
}

/** Zona de un dominio de correo bien configurado. */
function zonaSana() {
  return {
    'ejemplo.com': {
      A: ok(['93.184.216.34']),
      MX: ok([{ exchange: 'mx1.ejemplo.com', priority: 10 }]),
      TXT: ok([['v=spf1 -all']])
    },
    'mx1.ejemplo.com': { A: ok(['93.184.216.34']) },
    '_dmarc.ejemplo.com': { TXT: ok([['v=DMARC1; p=reject; rua=mailto:dmarc@ejemplo.com']]) },
    'default._domainkey.ejemplo.com': { TXT: ok([['v=DKIM1; k=rsa; p=' + CLAVE_DKIM]]) },
    '_mta-sts.ejemplo.com': { TXT: ok([['v=STSv1; id=20260101']]) },
    '_smtp._tls.ejemplo.com': { TXT: ok([['v=TLSRPTv1; rua=mailto:informes@ejemplo.com']]) },
    'default._bimi.ejemplo.com': { TXT: ok([['v=BIMI1; l=https://ejemplo.com/l.svg; a=https://ejemplo.com/vmc.pem']]) }
  };
}

/** Texto por defecto de la política MTA-STS que sirve la web falsa. */
const POLITICA_MTA_STS_SANA = 'version: STSv1\nmode: enforce\nmx: mx1.ejemplo.com\nmax_age: 86400\n';

/**
 * Web falsa: responde a `pedir` de MTA-STS como se le pida. Sin ella, un
 * dominio con registro `_mta-sts` haría una petición real y la prueba saldría
 * a Internet.
 */
function webMtaSts(config = {}) {
  const cuerpo = config.cuerpo ?? POLITICA_MTA_STS_SANA;
  const estado = config.estado ?? 200;
  return {
    pedir: async () => ({
      estado,
      ok: estado >= 200 && estado < 300,
      cuerpo: { texto: cuerpo, truncado: false },
      url: config.url || 'https://mta-sts.ejemplo.com/.well-known/mta-sts.txt',
      motivo: '',
      cabeceras: {},
      destino: null,
      ttfbMs: 10
    })
  };
}

function entornoSano(extra = {}) {
  return {
    dns: dnsMail(zonaSana(), { ptr: { '93.184.216.34': ['mx1.ejemplo.com'], ...(extra.ptr || {}) } }),
    dnsbl: extra.dnsbl || dnsblFalso(),
    web: webMtaSts()
  };
}

/* ------------------------------------------------------------------ *
 * Firma DKIM en tiempo de ejecución
 * ------------------------------------------------------------------ */

/** Par de claves propio, distinto del de la zona fija, para firmar en el test. */
const CLAVE_DKIM_EFIMERA = (() => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    privada: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publica: publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
  };
})();

/** Un correo de ejemplo con todas las cabeceras que piden las comprobaciones. */
function emlAutenticado() {
  return [
    'Received: from mail.ejemplo.com (mail.ejemplo.com [93.184.216.34])',
    '\tby mx.destino.com with ESMTPS id 7GtY',
    'From: Remitente <remitente@ejemplo.com>',
    'To: Destino <destino@destino.com>',
    'Date: Tue, 06 Oct 2026 09:00:00 +0200',
    'Message-ID: <d0f1ab-42@ejemplo.com>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset="utf-8"',
    'Subject: Un asunto normal para probar',
    'List-Unsubscribe: <mailto:salir@ejemplo.com>',
    'List-Unsubscribe-Post: List-Unsubscribe=One-Click',
    '',
    'Hola, esto es una prueba de firma DKIM.',
    '',
    'Un cordial saludo.'
  ].join('\r\n');
}

/**
 * Añade a un .eml una DKIM-Signature real (rsa-sha256, c=relaxed/relaxed) con
 * el selector "probe" de ejemplo.com. Usa la misma canonización que el motor
 * de verificación, de modo que la prueba cubre el camino criptográfico entero.
 */
function firmarConDkim(emlSinFirma) {
  const parseado = mensajes.parsear(emlSinFirma);
  const cuerpoCanon = verificar.canonizarCuerpo(parseado.cuerpo, 'relaxed');
  const bh = crypto.createHash('sha256').update(cuerpoCanon).digest('base64');
  const cabeceras = Object.keys(parseado.cabeceras);
  const valor = `v=1; a=rsa-sha256; c=relaxed/relaxed; d=ejemplo.com; s=probe; h=${cabeceras.join(':')}; bh=${bh}; b=`;
  const conFirma = { ...parseado, cabeceras: { ...parseado.cabeceras, 'dkim-signature': [valor] } };
  const canon = verificar.canonizarCabeceras(conFirma, cabeceras, 'relaxed');
  const b = crypto.sign('sha256', canon, CLAVE_DKIM_EFIMERA.privada).toString('base64');
  const [cabecerasBloque, ...cuerpo] = emlSinFirma.split(/\r?\n\r?\n/);
  return `${cabecerasBloque}\nDKIM-Signature: ${valor}${b}\n\n${cuerpo.join('\n\n')}`;
}

/** DNS del dominio "probe" con el que se firmó el .eml. */
function dnsDkimProbe(extra = {}) {
  return dnsMail(
    {
      'ejemplo.com': { TXT: ok([['v=spf1 ip4:93.184.216.34 -all']]) },
      'probe._domainkey.ejemplo.com': { TXT: ok([['v=DKIM1; k=rsa; p=' + CLAVE_DKIM_EFIMERA.publica]]) },
      '_dmarc.ejemplo.com': { TXT: ok([['v=DMARC1; p=reject']]) }
    },
    { ptr: { '93.184.216.34': ['mail.ejemplo.com'], ...(extra.ptr || {}) } }
  );
}

/* ------------------------------------------------------------------ *
 * Formulario
 * ------------------------------------------------------------------ */

test('declara los campos que necesita el formulario', () => {
  assert.equal(mail.id, 'mail-checker');
  const nombres = mail.campos.map((c) => c.name);
  for (const esperado of ['dominio', 'analizarMensaje', 'mensajeArchivo', 'mensajePegado', 'selectores', 'extensiones', 'listasNegras', 'timeout']) {
    assert.ok(nombres.includes(esperado), `falta el campo ${esperado}`);
  }
  const dominio = mail.campos.find((c) => c.name === 'dominio');
  assert.equal(dominio.requiredUnless, 'analizarMensaje', 'el dominio no es obligatorio si se analiza un mensaje');

  const archivo = mail.campos.find((c) => c.name === 'mensajeArchivo');
  assert.equal(archivo.type, 'file');
  assert.equal(archivo.shownWhen, 'analizarMensaje');
  assert.ok(archivo.maxBytes <= 1024 * 1024, 'el .eml debe caber en el límite del cuerpo');

  assert.equal(mail.campos.find((c) => c.name === 'extensiones').default, true);
  assert.equal(mail.campos.find((c) => c.name === 'listasNegras').default, true);
});

/* ------------------------------------------------------------------ *
 * Modo dominio
 * ------------------------------------------------------------------ */

test('un dominio de correo bien montado saca un 10', async () => {
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, entornoSano());

  assert.equal(r.status, 'pass', `hallazgos: ${r.findings.map((f) => f.title).join(' ; ')}`);
  assert.equal(valorResumen(r, 'Puntuación'), '10.0 / 10');
  assert.equal(valorResumen(r, 'Modo'), 'Dominio');
  assert.equal(r.findings.length, 0);

  const barra = seccion(r, 'Puntuación');
  assert.equal(barra.kind, K.BARRA);
  assert.equal(barra.value, 100);

  const comprobaciones = seccion(r, 'Comprobaciones');
  assert.equal(comprobaciones.kind, K.TABLA);
  assert.deepEqual(comprobaciones.columns, ['Comprobación', 'Categoría', 'Resultado', 'Puntos', 'Detalle']);
  assert.equal(comprobaciones.rows.length, 10, 'las diez comprobaciones del modo dominio');
  assert.ok(comprobaciones.rows.every((f) => f[2].valor === 'OK'));

  assert.ok(seccion(r, 'Servidores de correo (MX)'));
  assert.ok(seccion(r, 'SPF'));
  assert.ok(seccion(r, 'DKIM'));
  assert.ok(seccion(r, 'DMARC'));
  assert.ok(seccion(r, 'Extensiones de transporte'));

  const registros = seccion(r, 'Registros y valores encontrados');
  assert.ok(registros.rows.some((f) => f[1] === 'TXT (SPF)'));
  assert.ok(registros.rows.some((f) => f[1] === 'TXT (DKIM)'));
});

test('avisa de todo lo que falta sin salir mal del todo', async () => {
  const dns = dnsMail(
    {
      'ejemplo.com': { A: ok(['93.184.216.34']), MX: ok([{ exchange: 'mx1.ejemplo.com', priority: 10 }]) },
      'mx1.ejemplo.com': { A: ok(['93.184.216.34']) }
    },
    { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }
  );
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns, dnsbl: dnsblFalso() });

  assert.equal(r.status, 'warn');
  hallazgo(r, 'SPF');
  hallazgo(r, 'DKIM');
  hallazgo(r, 'DMARC');
  hallazgo(r, 'MTA-STS');
  sinHallazgo(r, 'El dominio existe');
  sinHallazgo(r, 'Servidores de correo');
});

test('un dominio que no existe devuelve un error y no consulta nada más', async () => {
  const dns = dnsMail({});
  const r = await mail.ejecutar({ dominio: 'no-existe-este.com' }, { dns });

  assert.equal(r.status, 'error');
  assert.equal(r.error.code, 'DNS_SIN_REGISTROS');
  assert.match(r.error.message, /no existe/i);
  assert.ok(r.error.remediation);
});

test('sin dominio devuelve ENTRADA_VACIA', async () => {
  const r = await mail.ejecutar({ dominio: '   ' });
  assert.equal(r.status, 'error');
  assert.equal(r.error.code, 'ENTRADA_VACIA');
});

test('un dominio con URL pegada se limpia y el objetivo guarda lo escrito', async () => {
  const r = await mail.ejecutar({ dominio: 'https://ejemplo.com/inicio' }, entornoSano());
  assert.equal(r.target, 'https://ejemplo.com/inicio', 'el objetivo reproduce la entrada original');
  assert.equal(valorResumen(r, 'Dominio'), 'ejemplo.com');
});

test('varios SPF publicados son un fallo', async () => {
  const zonas = zonaSana();
  zonas['ejemplo.com'].TXT = ok([['v=spf1 -all'], ['v=spf1 include:otro.com -all']]);
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }), web: webMtaSts() });

  assert.equal(r.status, 'fail');
  const h = hallazgo(r, 'SPF');
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /varios|Solo puede haber uno|registros SPF/i);
});

test('un SPF con "+all" es un fallo', async () => {
  const zonas = zonaSana();
  zonas['ejemplo.com'].TXT = ok([['v=spf1 +all']]);
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }), web: webMtaSts() });
  assert.equal(r.status, 'fail');
  assert.match(hallazgo(r, 'SPF').detail, /CUALQUIER servidor/);
});

test('un DKIM revocado es un fallo', async () => {
  const zonas = zonaSana();
  zonas['default._domainkey.ejemplo.com'].TXT = ok([['v=DKIM1; k=rsa; p=']]);
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }), web: webMtaSts() });
  assert.equal(r.status, 'fail');
  assert.match(hallazgo(r, 'DKIM').detail, /revocada|VACÍA/i);
});

test('un DMARC con "p=none" es un aviso, no un fallo', async () => {
  const zonas = zonaSana();
  zonas['_dmarc.ejemplo.com'].TXT = ok([['v=DMARC1; p=none']]);
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }), web: webMtaSts() });

  const h = hallazgo(r, 'DMARC');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /solo observa/);
});

test('un "null MX" se reconoce y se explica', async () => {
  const zonas = zonaSana();
  zonas['ejemplo.com'].MX = ok([{ exchange: '.', priority: 0 }]);
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: {} }), web: webMtaSts() });

  const h = hallazgo(r, 'Servidores de correo');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /null MX|RFC 7505/);
});

test('un MX que no resuelve es un fallo', async () => {
  const zonas = zonaSana();
  delete zonas['mx1.ejemplo.com'];
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: {} }), web: webMtaSts() });

  assert.equal(r.status, 'fail');
  assert.match(hallazgo(r, 'Servidores de correo').detail, /Sin dirección/);
});

test('una IP en listas negras es el problema más grave', async () => {
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { ...entornoSano(), dnsbl: dnsblFalso({ listadas: ['93.184.216.34'] }) }
  );

  assert.equal(r.status, 'fail');
  const h = hallazgo(r, 'Listas negras');
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /zen\.spamhaus\.org/);

  const tablaMx = seccion(r, 'Servidores de correo (MX)');
  assert.ok(tablaMx.rows[0].some((c) => c && c.valor === 'listada'));
});

test('sin PTR en los MX se avisa', async () => {
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { ...entornoSano(), dns: dnsMail(zonaSana(), { ptr: {} }) });
  const h = hallazgo(r, 'inversa');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /Sin PTR/);
});

test('desactivar las extensiones no las penaliza', async () => {
  const zonas = zonaSana();
  delete zonas['_mta-sts.ejemplo.com'];
  delete zonas['_smtp._tls.ejemplo.com'];
  delete zonas['default._bimi.ejemplo.com'];
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com', extensiones: false },
    { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }) }
  );

  assert.equal(r.status, 'pass', `hallazgos: ${r.findings.map((f) => f.title).join(' ; ')}`);
  assert.ok(!r.sections.some((s) => s.title === 'Extensiones de transporte'));
  assert.equal(valorResumen(r, 'Puntuación'), '10.0 / 10', 'el máximo se recalcula sin las extensiones');
});

test('desactivar las listas negras las saca del cálculo', async () => {
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com', listasNegras: false },
    { ...entornoSano(), dnsbl: { consultar: async () => { throw new Error('no debería llamarse'); } } }
  );
  assert.equal(r.status, 'pass');
  assert.ok(!r.sections.some((s) => s.title === 'Servidores de correo (MX)' && s.columns.includes('Listas negras')));
});

/* ------------------------------------------------------------------ *
 * DANE y política MTA-STS
 * ------------------------------------------------------------------ */

test('un TLSA válido (DANE-EE) en el MX se reconoce y no rompe el 10', async () => {
  const zonas = zonaSana();
  zonas['_25._tcp.mx1.ejemplo.com'] = { TLSA: ok([{ usage: 3, selector: 1, matchingType: 1, certificate: 'YWJjZGVmZw==' }]) };
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }), dnsbl: dnsblFalso(), web: webMtaSts() }
  );

  assert.equal(r.status, 'pass', `hallazgos: ${r.findings.map((f) => f.title).join(' ; ')}`);
  assert.equal(valorResumen(r, 'Puntuación'), '10.0 / 10');
  sinHallazgo(r, 'DANE');

  const sec = seccion(r, 'DANE (TLSA) en los servidores de correo');
  assert.equal(sec.rows[0][0], 'mx1.ejemplo.com');
  assert.equal(sec.rows[0][2], 'DANE-EE 1/1');

  const comprobaciones = seccion(r, 'Comprobaciones');
  assert.equal(comprobaciones.rows.length, 11, 'con DANE publicado entra la comprobación');
  const fila = comprobaciones.rows.find((f) => f[0].includes('DANE'));
  assert.equal(fila[2].valor, 'OK');
  assert.equal(fila[3], '0.5/0.5');

  const registros = seccion(r, 'Registros y valores encontrados');
  assert.ok(registros.rows.some((f) => f[1] === 'TLSA'));
});

test('un TLSA solo con usos PKIX (0/1) no es DANE y avisa', async () => {
  const zonas = zonaSana();
  zonas['_25._tcp.mx1.ejemplo.com'] = { TLSA: ok([{ usage: 1, selector: 0, matchingType: 1, certificate: 'YWJj' }]) };
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }), dnsbl: dnsblFalso(), web: webMtaSts() }
  );

  const h = hallazgo(r, 'DANE');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /usos 0\/1|PKIX/);

  const sec = seccion(r, 'DANE (TLSA) en los servidores de correo');
  assert.ok(sec.rows[0].some((c) => c && c.valor === 'Solo PKIX'));
});

test('sin TLSA el DANE se muestra como ausente sin restar nota', async () => {
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, entornoSano());
  assert.equal(r.status, 'pass');
  assert.equal(valorResumen(r, 'Puntuación'), '10.0 / 10');
  sinHallazgo(r, 'DANE');

  const comprobaciones = seccion(r, 'Comprobaciones');
  assert.equal(comprobaciones.rows.length, 10, 'sin TLSA no entra la comprobación DANE');

  const sec = seccion(r, 'DANE (TLSA) en los servidores de correo');
  assert.ok(sec.rows[0].some((c) => c && c.valor === 'Sin TLSA'), 'la ausencia se ve, sin castigo');
});

test('una política MTA-STS inválida convierte MTA-STS en un fallo', async () => {
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { ...entornoSano(), web: webMtaSts({ cuerpo: 'version: STSv1\nmode: enforce\nmax_age: 86400\n' }) }
  );

  assert.equal(r.status, 'fail');
  const h = hallazgo(r, 'MTA-STS');
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /no es válida/);

  const sec = seccion(r, 'Política MTA-STS');
  assert.ok(sec.items.some((f) => f[0] === 'Modo' && f[1] === 'enforce'));
});

test('una política que no se sirve (HTTP 404) avisa', async () => {
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { ...entornoSano(), web: webMtaSts({ estado: 404, cuerpo: '' }) }
  );

  const h = hallazgo(r, 'MTA-STS');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /404/);

  const sec = seccion(r, 'Política MTA-STS');
  assert.ok(sec.items.some((f) => f[0] === 'Estado' && /No servida/.test(String(f[1]))));
});

test('una política en modo testing avisa pero la estructura vale', async () => {
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { ...entornoSano(), web: webMtaSts({ cuerpo: 'version: STSv1\nmode: testing\nmx: mx1.ejemplo.com\nmax_age: 86400\n' }) }
  );

  const h = hallazgo(r, 'MTA-STS');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /testing/);
});

test('el desglose por categoría agrega los puntos perdidos', async () => {
  const zonas = zonaSana();
  zonas['_dmarc.ejemplo.com'].TXT = ok([['v=DMARC1; p=none']]);
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }), dnsbl: dnsblFalso(), web: webMtaSts() }
  );

  const desglose = seccion(r, 'Desglose por categoría');
  const dmarc = desglose.rows.find((f) => f[0] === 'DMARC');
  assert.ok(dmarc, 'aparece la categoría DMARC');
  assert.equal(dmarc[1], 0.75, 'un warn vale la mitad');
  assert.equal(dmarc[2], 1.5);
});

test('consultarPoliticaMtaSts solo pide cuando existe el registro y nunca lanza', async () => {
  const { consultarPoliticaMtaSts } = mail._internas;

  const sinRegistro = await consultarPoliticaMtaSts('ejemplo.com', null, {
    pedir: async () => { throw new Error('no debería llamarse'); }
  });
  assert.equal(sinRegistro, null);

  let llamado = false;
  const r = await consultarPoliticaMtaSts('ejemplo.com', { presente: true, id: 'x' }, {
    pedir: async () => {
      llamado = true;
      return { estado: 200, cuerpo: { texto: POLITICA_MTA_STS_SANA } };
    }
  });
  assert.equal(llamado, true);
  assert.equal(r.estado, 'ok');
  assert.equal(r.policy.mode, 'enforce');

  const roto = await consultarPoliticaMtaSts('ejemplo.com', { presente: true }, {
    pedir: async () => { throw new Error('conexión caída'); }
  });
  assert.equal(roto.estado, 'inaccesible');
  assert.ok(roto.errores.some((e) => /conexión caída/.test(e)));
});

test('consultarDane trae el estado de cada MX y normaliza el TLSA', async () => {
  const { consultarDane } = mail._internas;
  const dns = dnsMail({
    '_25._tcp.mx1.ejemplo.com': { TLSA: ok([{ usage: 3, selector: 1, matchingType: 1, certificate: 'YWJj' }]) },
    '_25._tcp.mx2.ejemplo.com': { TLSA: fallo('ENODATA') }
  });
  const servidores = [
    { host: 'mx1.ejemplo.com', direcciones: ['93.184.216.34'] },
    { host: 'mx2.ejemplo.com', direcciones: ['93.184.216.35'] },
    { host: '(implícito)', direcciones: ['93.184.216.36'], implicito: true }
  ];
  const r = await consultarDane(dns, servidores, 5000);
  assert.equal(r.consultado, true);
  assert.equal(r.hosts.length, 2, 'el implícito se descarta');
  assert.equal(r.hosts[0].estado, 'dane');
  assert.equal(r.hosts[0].registros[0].usage, 3);
  assert.equal(r.hosts[1].estado, 'sin-tlsa');
});

/* ------------------------------------------------------------------ *
 * Modo mensaje
 * ------------------------------------------------------------------ */

test('un correo bien autenticado saca un 10', async () => {
  const dns = dnsMail(
    {
      'ejemplo.com': { TXT: ok([['v=spf1 ip4:93.184.216.34 -all']]) },
      'default._domainkey.ejemplo.com': { TXT: ok([['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnZAkfWk46ENB7WLZwtL1KtCARxsxYwJNlQO6VkXeIpMmVwV1QUZ7z6GDym8BvOq20xosGTC1q5ZFqjkTOrJ7Rvf/zDsjUYuPlUh3YGJwa+9eKgAeFgPZ94WUacUn+Wv+4SAXcfJbRN866PVqybtqvtuTyr5CfxWLYz3x4ss6aOHSbhDvEEzPwVYLUtgAc0B7Z5aQdrn+asXFOZsD1dQN2nrR730HeDHRpK3N/jYmV1TRlmANLCLIy16w51S8GDQiMkVgxB7HEJ3cGfGsukJUDGQ3gj3UVGe+wZ1dPIFO/t0LU/Z+sh6TBMZk7S/jEKUEV6/zkA2T0w8C6V07KFOLIwIDAQAB']]) },
      '_dmarc.ejemplo.com': { TXT: ok([['v=DMARC1; p=reject; rua=mailto:d@ejemplo.com']]) }
    },
    { ptr: { '93.184.216.34': ['mail.ejemplo.com'] } }
  );
  const r = await mail.ejecutar(
    { analizarMensaje: true, mensajePegado: correoSano, listasNegras: true },
    { dns, dnsbl: dnsblFalso() }
  );

  assert.equal(r.status, 'pass', `hallazgos: ${r.findings.map((f) => f.title).join(' ; ')}`);
  assert.equal(valorResumen(r, 'Modo'), 'Mensaje');
  assert.equal(valorResumen(r, 'Puntuación'), '10.0 / 10');
  assert.equal(r.target, 'ejemplo.com');
  assert.equal(valorResumen(r, 'IP remitente'), '93.184.216.34');
  assert.ok(!r.summary.some((s) => s.label === 'Objetivo'), 'el resumen no repite "Objetivo", que ya imprime la cabecera');

  assert.ok(seccion(r, 'Cabeceras del mensaje'));
  assert.ok(seccion(r, 'Resultado de autenticación'));
  assert.ok(seccion(r, 'Contenido del mensaje'));
  assert.ok(seccion(r, 'IP emisora'));
  assert.ok(seccion(r, 'DMARC'));

  // El cuerpo del correo no puede quedar guardado en el Result.
  assert.ok(!JSON.stringify(r).includes('pedido numero 42'), 'el cuerpo no debe persistir');
  assert.match(r.params.mensajePegado, /^\(correo pegado, \d+ caracteres\)$/);
});

test('un correo sin autenticación se marca en cada método', async () => {
  const dns = dnsMail({}, { ptr: {} });
  const r = await mail.ejecutar(
    { analizarMensaje: true, mensajePegado: correoSpam, listasNegras: true },
    { dns, dnsbl: dnsblFalso() }
  );

  assert.equal(r.status, 'fail', 'el acortador y las señales de spam son fallos');
  hallazgo(r, 'SPF del remitente');
  hallazgo(r, 'Firma DKIM');
  hallazgo(r, 'DMARC del remitente');
  hallazgo(r, 'Enlaces acortados');
  hallazgo(r, 'Palabras que los filtros castigan');
  hallazgo(r, 'List-Unsubscribe');

  const auth = seccion(r, 'Resultado de autenticación');
  assert.equal(auth.rows.length, 3);
});

test('el archivo .eml se acepta igual que el texto pegado', async () => {
  const dns = dnsMail(
    {
      'ejemplo.com': { TXT: ok([['v=spf1 ip4:93.184.216.34 -all']]) },
      'default._domainkey.ejemplo.com': { TXT: ok([['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnZAkfWk46ENB7WLZwtL1KtCARxsxYwJNlQO6VkXeIpMmVwV1QUZ7z6GDym8BvOq20xosGTC1q5ZFqjkTOrJ7Rvf/zDsjUYuPlUh3YGJwa+9eKgAeFgPZ94WUacUn+Wv+4SAXcfJbRN866PVqybtqvtuTyr5CfxWLYz3x4ss6aOHSbhDvEEzPwVYLUtgAc0B7Z5aQdrn+asXFOZsD1dQN2nrR730HeDHRpK3N/jYmV1TRlmANLCLIy16w51S8GDQiMkVgxB7HEJ3cGfGsukJUDGQ3gj3UVGe+wZ1dPIFO/t0LU/Z+sh6TBMZk7S/jEKUEV6/zkA2T0w8C6V07KFOLIwIDAQAB']]) },
      '_dmarc.ejemplo.com': { TXT: ok([['v=DMARC1; p=reject']]) }
    },
    { ptr: { '93.184.216.34': ['mail.ejemplo.com'] } }
  );
  const r = await mail.ejecutar(
    { analizarMensaje: true, mensajeArchivo: correoSano, listasNegras: true },
    { dns, dnsbl: dnsblFalso() }
  );
  assert.equal(r.status, 'pass');
  assert.match(r.params.mensajeArchivo, /^\(correo adjunto, \d+ bytes\)$/);
});

test('analizar sin correo y sin archivo se explica, no revienta', async () => {
  const r = await mail.ejecutar({ analizarMensaje: true });
  assert.equal(r.status, 'error');
  assert.equal(r.error.code, 'PARAM_INVALIDO');
  assert.match(r.error.remediation, /\.eml|código/i);
});

test('un texto que no es un correo se rechaza con un error claro', async () => {
  const r = await mail.ejecutar({ analizarMensaje: true, mensajePegado: 'solo una frase suelta' });
  assert.equal(r.status, 'error');
  assert.equal(r.error.code, 'PARAM_INVALIDO');
});

test('una firma DKIM real, creada aquí mismo, se valida', async () => {
  const eml = firmarConDkim(emlAutenticado());
  const r = await mail.ejecutar(
    { analizarMensaje: true, mensajePegado: eml, listasNegras: true },
    { dns: dnsDkimProbe(), dnsbl: dnsblFalso() }
  );

  assert.equal(r.status, 'pass', `hallazgos: ${r.findings.map((f) => f.title).join(' ; ')}`);
  sinHallazgo(r, 'Firma DKIM');

  const tabla = seccion(r, 'Comprobaciones');
  const fila = tabla.rows.find((f) => f[0] === 'Firma DKIM');
  assert.ok(fila, 'la tabla debe incluir la fila de la firma');
  assert.equal(fila[2].valor, 'OK');

  const propia = seccion(r, 'Verificación propia');
  assert.ok(propia.items.some((f) => f[0].startsWith('DKIM') && /válida/.test(String(f[1]))), 'la evidencia propia debe decir que la firma vale');
});

test('un cuerpo alterado hace fallar la firma DKIM', async () => {
  const eml = firmarConDkim(emlAutenticado()).replace('esto es una prueba', 'esto es OTRA prueba');
  const r = await mail.ejecutar(
    { analizarMensaje: true, mensajePegado: eml, listasNegras: true },
    { dns: dnsDkimProbe(), dnsbl: dnsblFalso() }
  );

  assert.equal(r.status, 'fail');
  const h = hallazgo(r, 'Firma DKIM');
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /modificad|bh|no valida|alterad/i);
});

test('un correo sin remitente no inventa fallos, se queda sin comprobar', async () => {
  const sinRemitente = [
    'Received: from mail.ejemplo.com (mail.ejemplo.com [93.184.216.34])',
    '\tby mx.destino.com with ESMTPS id ab12',
    'Date: Tue, 06 Oct 2026 10:00:00 +0200',
    'Message-ID: <sin-remitente-1@mx.destino.com>',
    'MIME-Version: 1.0',
    'Subject: Sin remitente',
    'List-Unsubscribe: <mailto:baja@destino.com>',
    'List-Unsubscribe-Post: List-Unsubscribe=One-Click',
    '',
    'No hay From ni Return-Path.'
  ].join('\r\n');
  const dns = dnsMail({}, { ptr: { '93.184.216.34': ['mail.ejemplo.com'] } });
  const r = await mail.ejecutar(
    { analizarMensaje: true, mensajePegado: sinRemitente, listasNegras: true },
    { dns, dnsbl: dnsblFalso() }
  );

  const tabla = seccion(r, 'Comprobaciones');
  for (const titulo of ['SPF del remitente', 'Firma DKIM', 'DMARC del remitente']) {
    const fila = tabla.rows.find((f) => f[0] === titulo);
    assert.ok(fila, `falta la fila "${titulo}" en las comprobaciones`);
    assert.equal(fila[2].valor, 'Sin comprobar');
    assert.equal(fila[3], '—');
  }
  sinHallazgo(r, 'SPF del remitente');
  sinHallazgo(r, 'Firma DKIM');
  sinHallazgo(r, 'DMARC del remitente');
  assert.match(valorResumen(r, 'Comprobaciones'), /sin comprobar/);
});

test('los vectores dorados de canonización DKIM no se mueven', () => {
  assert.equal(verificar.canonizarCuerpo('A\r\n\tB  \r\n\r\n\r\nC\r\n\r\n', 'relaxed'), 'A\r\nB\r\n\r\n\r\nC\r\n');
  assert.equal(verificar.canonizarCuerpo('A\r\n\tB  \r\nC', 'simple'), 'A\r\n\tB  \r\nC\r\n');
  assert.equal(verificar.canonizarCuerpo('', 'relaxed'), '');
  assert.equal(verificar.canonizarCuerpo('\r\n\r\n', 'relaxed'), '');

  const mensaje = { cabeceras: { from: ['Joe  SixPack  <joe@football.example.com>'], subject: ['  lunch  '] } };
  assert.equal(
    verificar.canonizarCabeceras(mensaje, ['from', 'subject'], 'relaxed'),
    'from:Joe SixPack <joe@football.example.com>\r\nsubject:lunch\r\n'
  );

  const conFirma = { cabeceras: { 'dkim-signature': ['v=1; a=rsa-sha256; d=x.com; s=k; bh=AAAA; b=XYZ=='] } };
  assert.equal(verificar.canonizarCabeceras(conFirma, ['dkim-signature'], 'relaxed'), 'dkim-signature:v=1; a=rsa-sha256; d=x.com; s=k; bh=AAAA; b=\r\n');
});

test('un PTR que no resuelve de vuelta a la IP (FCrDNS) se avisa', async () => {
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsMail(zonaSana(), { ptr: { '93.184.216.34': ['otro-nombre.ejemplo.com'] } }), dnsbl: dnsblFalso() }
  );

  const h = hallazgo(r, 'inversa');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /FCrDNS/);
});

test('una IP autorizada por el SPF y listada es un fallo', async () => {
  const zonas = zonaSana();
  zonas['ejemplo.com'].TXT = ok([['v=spf1 ip4:198.51.100.7 -all']]);
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }), dnsbl: dnsblFalso({ listadas: ['198.51.100.7'] }), web: webMtaSts() }
  );

  assert.equal(r.status, 'fail');
  const h = hallazgo(r, 'Listas negras');
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /198\.51\.100\.7/);

  const sec = seccion(r, 'IPs autorizadas por el SPF');
  assert.ok(sec.rows.some((f) => f[0] === '198.51.100.7' && /^listada/.test(String(f[2]?.valor))));
});

test('un dominio del remitente en DBL hace fallar la reputación aun con la IP limpia', async () => {
  const eml = firmarConDkim(emlAutenticado());
  const r = await mail.ejecutar(
    { analizarMensaje: true, mensajePegado: eml, listasNegras: true },
    { dns: dnsDkimProbe(), dnsbl: dnsblFalso({ dbl: 'listada' }) }
  );

  assert.equal(r.status, 'fail');
  const h = hallazgo(r, 'Listas negras');
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /DBL/);
});

test('un dominio en DBL es un fallo de reputación en modo dominio', async () => {
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { ...entornoSano(), dnsbl: dnsblFalso({ dbl: 'listada' }) }
  );

  assert.equal(r.status, 'fail');
  const h = hallazgo(r, 'Listas negras');
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /DBL/);

  const registros = seccion(r, 'Registros y valores encontrados');
  assert.ok(registros.rows.some((f) => f[1] === 'DBL'), 'la fila DBL queda a la vista en los registros');
});

test('DBL sin datos se dice en el detalle y no baja el veredicto', async () => {
  const r = await mail.ejecutar(
    { dominio: 'ejemplo.com' },
    { ...entornoSano(), dnsbl: dnsblFalso({ dbl: 'sin-datos' }) }
  );

  assert.equal(r.status, 'pass', `hallazgos: ${r.findings.map((f) => f.title).join(' ; ')}`);
  assert.equal(valorResumen(r, 'Puntuación'), '10.0 / 10');
  const fila = seccion(r, 'Comprobaciones').rows.find((f) => f[0] === 'Listas negras');
  assert.match(fila[4], /DBL/, 'el detalle avisa de que DBL no respondio');
});

test('un correo sin List-Unsubscribe avisa pero no resta puntos', async () => {
  const eml = firmarConDkim(
    emlAutenticado()
      .split('\n')
      .filter((l) => !/^List-Unsubscribe/i.test(l))
      .join('\n')
  );
  const r = await mail.ejecutar(
    { analizarMensaje: true, mensajePegado: eml, listasNegras: true },
    { dns: dnsDkimProbe(), dnsbl: dnsblFalso() }
  );

  assert.equal(r.status, 'warn', 'la ausencia de la cabecera avisa (hallazgo warn), igual que el resto del marco');
  assert.equal(valorResumen(r, 'Puntuación'), '10.0 / 10', 'la ausencia de la cabecera no penaliza la nota');
  const h = hallazgo(r, 'List-Unsubscribe');
  assert.equal(h.severity, 'warn');
  const fila = seccion(r, 'Comprobaciones').rows.find((f) => f[0] === 'Cabecera List-Unsubscribe');
  assert.equal(fila[3], '0/0', 'peso 0 y estado warn: aviso informativo, nada que ganar ni perder');
});

/* ------------------------------------------------------------------ *
 * Internas y contrato
 * ------------------------------------------------------------------ */

test('los selectores propios se suman a los habituales', () => {
  const { elegirSelectores } = mail._internas;
  const lista = elegirSelectores('mio, otro');
  assert.ok(lista.includes('mio'));
  assert.ok(lista.includes('otro'));
  assert.ok(lista.includes('default'));
  assert.ok(lista.length <= 40, 'no se consultan selectores sin fin');
  assert.ok(elegirSelectores('').length > 0, 'sin selectores propios quedan los comunes');
});

test('el parser de MX detecta sus tres estados', () => {
  const { parsearMx } = mail._internas;
  assert.equal(parsearMx(fallo('ENODATA')).estado, 'sin-mx');
  assert.equal(parsearMx(ok([{ exchange: '.', priority: 0 }])).estado, 'null-mx');
  const sano = parsearMx(ok([{ exchange: 'mx2.ejemplo.com', priority: 20 }, { exchange: 'mx1.ejemplo.com', priority: 10 }]));
  assert.equal(sano.estado, 'ok');
  assert.deepEqual(sano.presentes.map((h) => h.exchange), ['mx1.ejemplo.com', 'mx2.ejemplo.com'], 'ordenados por prioridad');
});

test('paramsSeguros no deja pasar el cuerpo del correo', () => {
  const { paramsSeguros } = mail._internas;
  const seguro = paramsSeguros({ analizarMensaje: true, mensajePegado: correoSano, mensajeArchivo: correoSano });
  assert.match(seguro.mensajePegado, /^\(correo pegado/);
  assert.match(seguro.mensajeArchivo, /^\(correo adjunto/);
  assert.ok(!JSON.stringify(seguro).includes('noreply@ejemplo.com'));
});

test('los cinco formatos renderizan los dos modos', async () => {
  const dominio = await mail.ejecutar({ dominio: 'ejemplo.com' }, entornoSano());
  const mensaje = await mail.ejecutar(
    { analizarMensaje: true, mensajePegado: correoSano, listasNegras: true },
    {
      dns: dnsMail(
        { 'ejemplo.com': { TXT: ok([['v=spf1 -all']]) }, '_dmarc.ejemplo.com': { TXT: ok([['v=DMARC1; p=reject']]) } },
        { ptr: { '93.184.216.34': ['mail.ejemplo.com'] } }
      ),
      dnsbl: dnsblFalso()
    }
  );

  for (const r of [dominio, mensaje]) {
    for (const formato of formats.soportados().map((f) => f.nombre)) {
      const salida = await formats.render(r, formato);
      assert.ok(salida.length > 0, `el formato ${formato} salió vacío`);
    }
  }
});

test('un informe con error también se renderiza', async () => {
  const r = await mail.ejecutar({ dominio: 'no existe esto' });
  assert.equal(r.status, 'error');
  for (const formato of ['txt', 'md', 'html', 'json', 'pdf']) {
    assert.ok((await formats.render(r, formato)).length > 0, `${formato} debería renderizar un Result con error`);
  }
});
