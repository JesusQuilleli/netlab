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
    }
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

function entornoSano(extra = {}) {
  return {
    dns: dnsMail(zonaSana(), { ptr: { '93.184.216.34': ['mx1.ejemplo.com'], ...(extra.ptr || {}) } }),
    dnsbl: extra.dnsbl || dnsblFalso()
  };
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
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }) });

  assert.equal(r.status, 'fail');
  const h = hallazgo(r, 'SPF');
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /varios|Solo puede haber uno|registros SPF/i);
});

test('un SPF con "+all" es un fallo', async () => {
  const zonas = zonaSana();
  zonas['ejemplo.com'].TXT = ok([['v=spf1 +all']]);
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }) });
  assert.equal(r.status, 'fail');
  assert.match(hallazgo(r, 'SPF').detail, /CUALQUIER servidor/);
});

test('un DKIM revocado es un fallo', async () => {
  const zonas = zonaSana();
  zonas['default._domainkey.ejemplo.com'].TXT = ok([['v=DKIM1; k=rsa; p=']]);
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }) });
  assert.equal(r.status, 'fail');
  assert.match(hallazgo(r, 'DKIM').detail, /revocada|VACÍA/i);
});

test('un DMARC con "p=none" es un aviso, no un fallo', async () => {
  const zonas = zonaSana();
  zonas['_dmarc.ejemplo.com'].TXT = ok([['v=DMARC1; p=none']]);
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: { '93.184.216.34': ['mx1.ejemplo.com'] } }) });

  const h = hallazgo(r, 'DMARC');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /solo observa/);
});

test('un "null MX" se reconoce y se explica', async () => {
  const zonas = zonaSana();
  zonas['ejemplo.com'].MX = ok([{ exchange: '.', priority: 0 }]);
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: {} }) });

  const h = hallazgo(r, 'Servidores de correo');
  assert.equal(h.severity, 'warn');
  assert.match(h.detail, /null MX|RFC 7505/);
});

test('un MX que no resuelve es un fallo', async () => {
  const zonas = zonaSana();
  delete zonas['mx1.ejemplo.com'];
  const r = await mail.ejecutar({ dominio: 'ejemplo.com' }, { dns: dnsMail(zonas, { ptr: {} }) });

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
 * Modo mensaje
 * ------------------------------------------------------------------ */

test('un correo bien autenticado saca un 10', async () => {
  const dns = dnsMail(
    {
      'ejemplo.com': { TXT: ok([['v=spf1 -all']]) },
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
    { 'ejemplo.com': { TXT: ok([['v=spf1 -all']]) }, '_dmarc.ejemplo.com': { TXT: ok([['v=DMARC1; p=reject']]) } },
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
