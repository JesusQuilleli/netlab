'use strict';

/**
 * test/web-checker.test.js — Pruebas del comprobador de sitios web.
 *
 * Ninguna prueba sale a Internet. Se inyectan dobles por `ctx.web`, `ctx.dns`,
 * `ctx.rdap` y `ctx.tls`, que es justo la costura que existe para esto: un sitio
 * real cambia de estado entre dos ejecuciones y una prueba que depende de él se
 * rompe sola.
 *
 * Lo que se mira sobre todo es la COHERENCIA del informe: que el titular, el
 * estado global y las severidades digan lo mismo. Un informe que dice "está
 * operativa" con un "CON FALLOS" delante, o que afirma "responde con una página
 * de venta" sin explicarla, es peor que no dar informe.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const webChecker = require('../src/tools/web-checker');
const formats = require('../src/formats');
const { SECCION_KINDS: K, SEVERIDADES, ESTADOS } = require('../src/core/result');

/* ------------------------------------------------------------------ *
 * Dobles
 * ------------------------------------------------------------------ */

/** Una respuesta HTTP con los valores de un sitio sano. */
function responde(extra = {}) {
  return {
    ok: true,
    estado: 200,
    motivo: 'OK',
    motivoAlternativo: null,
    url: 'https://ejemplo.com/',
    urlFinal: 'https://ejemplo.com/',
    cadena: [{ url: 'https://ejemplo.com/', estado: 200 }],
    metodo: 'HEAD',
    cabeceras: { server: 'nginx', 'content-type': 'text/html' },
    titulo: 'Ejemplo — Inicio',
    cuerpo: '<html><head><title>Ejemplo — Inicio</title></head></html>',
    truncado: false,
    ttfbMs: 120,
    ...extra
  };
}

/** Error de red con el código que decidirá el titular. */
function errorRed(codigo = 'RED', mensaje = 'ECONNREFUSED') {
  const e = new Error(mensaje);
  e.code = codigo;
  return e;
}

/** Corte por seguridad, tal y como lo lanza `web.js`. */
function errorSsrf() {
  const e = new Error('La comprobación se ha cancelado por seguridad: el destino apunta a 127.0.0.1 (Loopback).');
  e.code = 'PARAM_INVALIDO';
  e.remediation = 'Escribe el dominio de la web que quieres comprobar.';
  e.details = { ssrf: true, bloqueadas: ['127.0.0.1 (Loopback)'] };
  return e;
}

function ok(valores, ttl = null) {
  return { ok: true, valores, ttl, error: null, codigo: 'SIN_ERROR', codigoDns: null };
}

function fallo(codigoDns, mensaje) {
  return { ok: false, valores: [], ttl: null, error: mensaje, codigo: 'RED', codigoDns };
}

/**
 * DNS falso: responde lo que se le pone por nombre y tipo.
 *
 * Los métodos se guardan en el objeto en vez de escribirlo con forma abreviada
 * porque hacen falta para contar consultas, y una flecha `this` no es el
 * objeto: el fallo aparecería como "Cannot read properties of undefined" en
 * mitad de una prueba, muy lejos de su causa.
 */
function dnsFalso(zonas = {}) {
  const self = {
    consultas: [],
    consultarLote: async (consultas) => {
      self.consultas.push(...consultas);
      return consultas.map((c) => ({ ...c, ...(zonas[c.nombre]?.[c.tipo] ?? fallo('ENODATA', `sin ${c.tipo}`)) }));
    },
    consultar: async (nombre, tipo, opciones = {}) => {
      self.consultas.push({ nombre, tipo, servers: opciones.servers });
      return zonas[nombre]?.[tipo] ?? fallo('ENODATA', `sin ${tipo}`);
    }
  };
  return self;
}

const DNS_SANO = dnsFalso({
  'ejemplo.com': { A: ok(['93.184.216.34'], 300), AAAA: ok(['2606:2800:220:1:248:1893:25c8:1946'], 300) }
});

/**
 * TLS falso. `verificar` decide si la conexión "pasa", como en el módulo real,
 * y se guardan las llamadas para poder afirmar que se intentó validar primero.
 */
function tlsFalso(config = {}) {
  const self = {
    llamadas: [],
    conectar: async (opciones) => {
      self.llamadas.push(opciones);
      if (opciones.verificar && config.fallaAlVerificar) throw new Error('unable to verify the first certificate');
      return {
        socket: { destroy() { self.destruido = true; } },
        certificado: config.certificado ?? null,
        avisos: []
      };
    },
    auditarCertificado: config.auditar || require('../src/core/net/tls').auditarCertificado
  };
  return self;
}

const TLS_SANO = tlsFalso({
  certificado: {
    sujeto: 'ejemplo.com',
    emisor: 'R3',
    validoHasta: '2027-01-01 00:00:00 GMT',
    diasRestantes: 400,
    protocolo: 'TLSv1.3',
    cifrado: 'TLS_AES_256_GCM_SHA384',
    nombresAlternativos: ['DNS:ejemplo.com', 'DNS:www.ejemplo.com'],
    autoFirmado: false,
    autoridadCertificadora: true,
    motivoRechazo: null
  }
});

function rdapFalso(datos) {
  return { consultarDominio: async () => datos };
}

/**
 * Contexto completo y sano. Se sobrescribe lo que haga falta en cada prueba,
 * que es más legible que reescribir el contexto entero cada vez.
 */
function contexto(extra = {}) {
  return {
    web: { sondear: async () => responde() },
    dns: DNS_SANO,
    tls: TLS_SANO,
    rdap: rdapFalso({
      disponible: true,
      consultable: true,
      dominio: 'ejemplo.com',
      caducidad: '2031-06-01 10:00:00 GMT',
      registro: '2015-06-01 10:00:00 GMT',
      registrador: 'Example Inc',
      estados: 'ok',
      retenciones: [],
      nombreservers: ['ns1.ejemplo.com']
    }),
    ...extra
  };
}

/** Títulos de los hallazgos, para no depender del orden en pruebas sueltas. */
function titulos(r) {
  return r.findings.map((f) => f.title);
}

/** Severidad máxima de los hallazgos: el dato que decide el estado global. */
function peorSeveridad(r) {
  if (r.findings.some((f) => f.severity === SEVERIDADES.ERROR)) return SEVERIDADES.ERROR;
  if (r.findings.some((f) => f.severity === SEVERIDADES.WARN)) return SEVERIDADES.WARN;
  return SEVERIDADES.INFO;
}

/* ------------------------------------------------------------------ *
 * Metadatos de la herramienta
 * ------------------------------------------------------------------ */

test('declara un solo campo visible y esconde el resto', () => {
  const visibles = webChecker.campos.filter((c) => !c.shownWhen);
  const ocultos = webChecker.campos.filter((c) => c.shownWhen === 'avanzado');
  const compartirOcultos = webChecker.campos.filter((c) => c.shownWhen === 'compartir');

  assert.equal(webChecker.id, 'web-checker');
  assert.deepEqual(visibles.map((c) => c.name), ['url', 'avanzado']);
  assert.ok(visibles.find((c) => c.name === 'url').required);

  assert.deepEqual(ocultos.map((c) => c.name), [
    'timeout',
    'permitirRedPrivada',
    'consultarCaducidad',
    'compararResolvers',
    'compartir'
  ]);

  assert.deepEqual(compartirOcultos.map((c) => c.name), [
    'ttlDiasCompartir'
  ]);

  // El interruptor "avanzado" tiene que existir, o `shownWhen` no abre nada.
  assert.ok(visibles.find((c) => c.name === 'avanzado'), 'falta el campo avanzado');
  assert.equal(webChecker.sinRed, false);
});

test('cada opción avanzada explica qué hace y qué NO hace', () => {
  const porNombre = Object.fromEntries(webChecker.campos.map((c) => [c.name, c]));

  // Sin esto el usuario no sabe que activar la red privada no abre los metadatos.
  assert.match(porNombre.permitirRedPrivada.help, /metadatos/i);
  assert.match(porNombre.consultarCaducidad.label, /caducidad/i);
  assert.match(porNombre.consultarCaducidad.help, /sin pagar/i);
  assert.match(porNombre.compararResolvers.help, /1\.1\.1\.1|Cloudflare/i);
  assert.equal(porNombre.timeout.default, 8000);
});

/* ------------------------------------------------------------------ *
 * El caso normal
 * ------------------------------------------------------------------ */

test('un sitio sano pasa y lo dice en el titular', async () => {
  const r = await webChecker.ejecutar({ url: 'ejemplo.com' }, contexto());

  assert.equal(r.status, ESTADOS.PASS);
  assert.equal(r.headline, 'ejemplo.com está operativa');
  assert.equal(r.target, 'ejemplo.com');
  assert.equal(r.tool, 'web-checker');
  assert.equal(r.error, null);
  assert.deepEqual(r.findings, [], 'un sitio sano no necesita hallazgos');
});

test('el sitio sano enseña los hechos y las cuatro comprobaciones', async () => {
  const r = await webChecker.ejecutar({ url: 'ejemplo.com' }, contexto());

  const etiquetas = r.summary.map((s) => s.label);
  assert.deepEqual(etiquetas, ['Código', 'Tiempo', 'IP', 'URL final']);
  assert.equal(r.summary[0].value, '200');
  assert.equal(r.summary[1].value, '120 ms');
  // La tarjeta enseña la dirección de verdad, no una pista de una cabecera.
  assert.match(r.summary[2].value, /93\.184\.216\.34/);

  assert.deepEqual(
    r.sections.map((s) => s.title),
    ['Qué ha pasado', 'Direcciones del nombre', 'Certificado', 'Caducidad del dominio']
  );
});

test('con muchas direcciones la tarjeta se recorta y lo dice', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({
      dns: dnsFalso({
        'ejemplo.com': {
          A: ok(['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4']),
          AAAA: ok([])
        }
      })
    })
  );

  const ip = r.summary.find((s) => s.label === 'IP');
  assert.match(ip.value, /^\+?203\.0\.113\.1, 203\.0\.113\.2 \(\+2\)$/);
});

test('las tarjetas de arriba son solo lo que se lee sin leer', async () => {
  const r = await webChecker.ejecutar({ url: 'ejemplo.com' }, contexto());

  // Las cuatro tarjetas principales son un contrato con la interfaz: si el
  // frontend las conoce y el módulo inventa una quinta, la vista se rompe.
  assert.ok(r.summary.length <= 6, 'demasiadas tarjetas para la vista de arriba');
  for (const s of r.summary) {
    assert.equal(typeof s.label, 'string');
    assert.equal(typeof s.value, 'string');
  }
});

test('las secciones usan los tipos que los formatos saben pintar', async () => {
  const r = await webChecker.ejecutar({ url: 'ejemplo.com' }, contexto());
  for (const s of r.sections) {
    assert.ok(Object.values(K).includes(s.kind), `tipo desconocido: ${s.kind}`);
  }
});

test('una URL con esquema http:// se respeta y no se cambia por https', async () => {
  const ctx = contexto();
  let pedida;
  ctx.web = {
    sondear: async (url) => {
      pedida = url;
      return responde({ url: url.toString(), urlFinal: url.toString() });
    }
  };

  const r = await webChecker.ejecutar({ url: 'http://ejemplo.com' }, ctx);

  // No se reescribe el esquema: quien escribe http quiere saber de http.
  assert.equal(pedida.protocol, 'http:');
  assert.equal(r.headline, 'ejemplo.com está operativa');
  // Y como el sitio responde pero sin cifrar, es una observación, no un fallo.
  assert.equal(r.status, ESTADOS.WARN);
  assert.ok(titulos(r).some((t) => /no usa HTTPS/.test(t)));
});

test('la caducidad del dominio se puede desactivar sin romper nada', async () => {
  let consultado = false;
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com', consultarCaducidad: false },
    contexto({
      rdap: {
        consultarDominio: async () => {
          consultado = true;
          return {};
        }
      }
    })
  );

  assert.equal(consultado, false, 'no debe preguntar a RDAP si está desactivado');
  assert.equal(r.status, ESTADOS.PASS);
  assert.ok(!r.sections.some((s) => s.title === 'Caducidad del dominio'));
});

/* ------------------------------------------------------------------ *
 * Cuando no responde
 * ------------------------------------------------------------------ */

test('un sitio que no contesta es un fallo, no un error', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({
      web: { sondear: async () => { throw errorRed('RED', 'ECONNREFUSED'); } }
    })
  );

  // La diferencia importa: `fail` dice "el sitio no está", `error` diría "no he
  // podido comprobarlo". Con la conexión rechazada sí sabemos cuál de las dos.
  assert.equal(r.status, ESTADOS.FAIL);
  assert.equal(r.headline, 'ejemplo.com no ha respondido');
  assert.ok(titulos(r).some((t) => /No se pudo conectar/.test(t)));
});

test('el tiempo agotado se distingue de la conexión rechazada', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ web: { sondear: async () => { throw errorRed('TIMEOUT', 'timeout'); } } })
  );

  assert.equal(r.status, ESTADOS.FAIL);
  assert.ok(titulos(r).some((t) => /no respondió dentro del plazo/.test(t)));
  // Y las tarjetas lo dicen en su idioma, sin inventar un código.
  assert.equal(r.summary[0].value, 'Sin conexión');
  assert.equal(r.summary[1].value, 'Tiempo agotado');
  assert.ok(!r.summary.some((s) => s.label === 'Código'));
});

test('si el nombre tampoco resuelve, el informe da la causa, no el síntoma', async () => {
  const r = await webChecker.ejecutar(
    { url: 'noexiste.example' },
    contexto({
      web: { sondear: async () => { throw errorRed('RED', 'getaddrinfo ENOTFOUND'); } },
      dns: dnsFalso({})
    })
  );

  assert.equal(r.status, ESTADOS.FAIL);
  assert.ok(titulos(r).some((t) => /no resuelve a ninguna dirección/.test(t)));
});

test('dice que la comprobación es de un momento y un equipo', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ web: { sondear: async () => { throw errorRed(); } } })
  );

  // Es el malentendido más frecuente con este módulo: si el sitio abre en el
  // navegador y no sale aquí, no está caído.
  assert.ok(titulos(r).some((t) => /desde este equipo/.test(t)));
});

test('nunca dice que un sitio está caído para todo el mundo', async () => {
  const escenarios = [
    contexto(),
    contexto({ web: { sondear: async () => { throw errorRed(); } } }),
    contexto({ web: { sondear: async () => responde({ estado: 500, motivo: 'Error interno' }) } }),
    contexto({ web: { sondear: async () => responde({ estado: 404 }) } })
  ];

  for (const ctx of escenarios) {
    const r = await webChecker.ejecutar({ url: 'ejemplo.com' }, ctx);
    assert.ok(r.headline, 'siempre debe haber titular');
    assert.doesNotMatch(r.headline, /ca[ií]d[oa]\b/i, `afirmación de caída global: ${r.headline}`);
    assert.doesNotMatch(r.headline, /para todo el mundo|todo el planeta|globalmente/i);
  }
});

/* ------------------------------------------------------------------ *
 * El corte por seguridad
 * ------------------------------------------------------------------ */

test('un destino bloqueado es ERROR y no un sitio caído', async () => {
  const r = await webChecker.ejecutar(
    { url: 'interno.local' },
    contexto({ web: { sondear: async () => { throw errorSsrf(); } } })
  );

  // `fail` aquí sería una mentira: nadie ha mirado el sitio. El código se
  // distingue por `details.ssrf`, no por la frase del mensaje.
  assert.equal(r.status, ESTADOS.ERROR);
  assert.equal(r.error.code, 'PARAM_INVALIDO');
  assert.deepEqual(r.findings, [], 'un corte por seguridad no habla del sitio');
});

test('el corte por seguridad sobrevive a un error que no es NetlabError', async () => {
  // Si el envoltorio de `sondear` se comiera `details`, esto saldría como `fail`
  // y el informe afirmaría que una red interna está caída.
  const r = await webChecker.ejecutar(
    { url: 'interno.local' },
    contexto({ web: { sondear: async () => { throw errorSsrf(); } } })
  );
  assert.equal(r.status, ESTADOS.ERROR);
});

/* ------------------------------------------------------------------ *
 * Códigos HTTP
 * ------------------------------------------------------------------ */

test('un 5xx es un fallo del sitio', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({
      web: { sondear: async () => responde({ ok: false, estado: 502, motivo: 'Bad Gateway' }) }
    })
  );

  assert.equal(r.status, ESTADOS.FAIL);
  assert.equal(r.headline, 'ejemplo.com responde con un error 502');
  assert.ok(titulos(r).some((t) => /devuelve un error 502/.test(t)));
});

test('un 503 sugiere mantenimiento en vez de solo culpar al backend', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ web: { sondear: async () => responde({ ok: false, estado: 503, motivo: 'Service Unavailable' }) } })
  );
  const hallazgo = r.findings.find((f) => /error 503/.test(f.title));
  assert.match(hallazgo.recommendation, /mantenimiento/i);
});

test('un 4xx es un aviso, no un sitio roto', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com/pagina-que-no-existe' },
    contexto({ web: { sondear: async () => responde({ ok: false, estado: 404, motivo: 'Not Found' }) } })
  );

  // El sitio está en pie y la ruta no existe. Decir "caído" sería falso.
  assert.equal(r.status, ESTADOS.WARN);
  assert.equal(r.headline, 'ejemplo.com responde con un error 404');
  const hallazgo = r.findings.find((f) => /responde 404/.test(f.title));
  assert.match(hallazgo.detail, /en pie/i);
});

test('cada 4xx conocido explica su propio significado', async () => {
  for (const estado of [400, 401, 403, 404, 410, 429]) {
    const r = await webChecker.ejecutar(
      { url: 'ejemplo.com' },
      contexto({ web: { sondear: async () => responde({ ok: false, estado, motivo: String(estado) }) } })
    );
    const hallazgo = r.findings.find((f) => new RegExp(`responde ${estado}`).test(f.title));
    assert.ok(hallazgo, `falta el hallazgo del ${estado}`);
    assert.ok(hallazgo.detail.length > 40, `el ${estado} se explica en corto`);
    assert.ok(hallazgo.recommendation, `el ${estado} no dice qué hacer`);
    assert.equal(r.status, ESTADOS.WARN);
  }
});

test('un 429 es límite de peticiones, no caída', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ web: { sondear: async () => responde({ ok: false, estado: 429, motivo: 'Too Many Requests' }) } })
  );
  const hallazgo = r.findings.find((f) => /responde 429/.test(f.title));
  assert.match(hallazgo.detail, /agotado|peticiones/i);
});

test('un bucle de redirecciones es un fallo y lo dice', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({
      web: {
        sondear: async () =>
          responde({ bucle: true, estado: 302, motivo: 'Bucle de redirecciones: se ha repetido el mismo destino 5 veces' })
      }
    })
  );

  assert.equal(r.status, ESTADOS.FAIL);
  assert.equal(r.headline, 'ejemplo.com se redirige a sí mismo');
});

test('demasiadas redirecciones es un fallo con su propio motivo', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({
      web: { sondear: async () => responde({ demasiadas: true, estado: 302, motivo: 'Más de 5 redirecciones' }) }
    })
  );

  assert.equal(r.status, ESTADOS.FAIL);
  assert.equal(r.headline, 'ejemplo.com encadena demasiadas redirecciones');
  assert.ok(titulos(r).some((t) => /demasiadas redirecciones/.test(t)));
});

/* ------------------------------------------------------------------ *
 * Coherencia titular ↔ estado ↔ severidades
 * ------------------------------------------------------------------ */

test('el titular y el estado global nunca se contradicen', async () => {
  const casos = {
    'sitio sano': contexto(),
    'no responde': contexto({ web: { sondear: async () => { throw errorRed(); } } }),
    'error 500': contexto({ web: { sondear: async () => responde({ ok: false, estado: 500, motivo: 'Error' }) } }),
    'error 404': contexto({ web: { sondear: async () => responde({ ok: false, estado: 404 }) } }),
    'corte de seguridad': contexto({ web: { sondear: async () => { throw errorSsrf(); } } }),
    'certificado roto': contexto({ tls: tlsFalso({ fallaAlVerificar: true, certificado: { sujeto: 'ejemplo.com', validoHasta: '2020-01-01', diasRestantes: -100, protocolo: 'TLSv1', cifrado: 'NULL', nombresAlternativos: [], autoFirmado: true, autoridadCertificadora: false, motivoRechazo: 'SELF_SIGNED_CERT_IN_CHAIN' } }) })
  };

  for (const [nombre, ctx] of Object.entries(casos)) {
    const r = await webChecker.ejecutar({ url: 'ejemplo.com' }, ctx);

    // Un `fail` tiene que decir algo malo, y un `pass` no puede llevar un error.
    if (r.status === ESTADOS.FAIL) {
      assert.match(r.headline, /no ha respondido|error|redirige|demasiadas|demasiadas/, `${nombre}: ${r.headline}`);
      assert.ok(peorSeveridad(r) === SEVERIDADES.ERROR, `${nombre}: fallo sin hallazgo de error`);
    }
    if (r.status === ESTADOS.PASS) {
      assert.equal(peorSeveridad(r), SEVERIDADES.INFO, `${nombre}: pass con un hallazgo de warn o error`);
    }
  }
});

test('un 200 con un certificado inválido NO se convierte en fallo', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({
      tls: tlsFalso({
        fallaAlVerificar: true,
        certificado: {
          sujeto: 'ejemplo.com',
          emisor: 'ejemplo.com',
          validoHasta: '2020-01-01 00:00:00 GMT',
          diasRestantes: -200,
          protocolo: 'TLSv1',
          cifrado: 'NULL',
          nombresAlternativos: [],
          autoFirmado: true,
          autoridadCertificadora: false,
          motivoRechazo: 'SELF_SIGNED_CERT_IN_CHAIN'
        }
      })
    })
  );

  // El sitio responde 200. Decir "CON FALLOS" sería mentir sobre lo que el
  // usuario preguntó. Pero los problemas del certificado tienen que verse.
  assert.equal(r.status, ESTADOS.WARN);
  assert.equal(r.headline, 'ejemplo.com está operativa');
  assert.ok(peorSeveridad(r) !== SEVERIDADES.ERROR, 'un detalle secundario no puede tumbar el veredicto');
  assert.ok(titulos(r).some((t) => /autofirmado/i.test(t)));
  assert.ok(titulos(r).some((t) => /expirado/i.test(t)));
});

test('un sitio lento se avisa, no se pasa como si nada', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ web: { sondear: async () => responde({ ttfbMs: 4200 }) } })
  );

  assert.equal(r.status, ESTADOS.WARN);
  assert.ok(titulos(r).some((t) => /Tarda 4200 ms/.test(t)));
});

/* ------------------------------------------------------------------ *
 * Parking y páginas vacías
 * ------------------------------------------------------------------ */

test('el parking se detecta, se explica y no se llama caída', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({
      web: { sondear: async () => responde({ titulo: 'ejemplo.com está en venta | Sedo', server: 'Sedo Parking' }) }
    })
  );

  assert.equal(r.headline, 'ejemplo.com responde con una página de venta');
  assert.notEqual(r.status, ESTADOS.FAIL, 'una página de venta no es una caída');
  // El titular afirma algo: el informe tiene que explicarlo debajo.
  assert.ok(titulos(r).some((t) => /página de venta|aparcado/i.test(t)));
});

test('una página en construcción es una nota, no un problema', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ web: { sondear: async () => responde({ titulo: 'Muy pronto — Coming Soon' }) } })
  );

  assert.equal(r.headline, 'ejemplo.com responde con una página en construcción');
  assert.equal(r.status, ESTADOS.PASS);
});

test('un título corriente no se confunde con parking', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ web: { sondear: async () => responde({ titulo: 'Aparcamiento gratuito en el centro | InmoEjemplo' }) } })
  );
  assert.equal(r.status, ESTADOS.PASS);
});

test('el parking en chino también se detecta', async () => {
  // `\b` no puede funcionar pegado a un carácter chino: en JavaScript `\w` es
  // ASCII y no hay frontera de palabra al lado de un ideograma. Con las
  // alternativas metidas en la expresión con `\b`, esto no se detectaría nunca.
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.cn' },
    contexto({ web: { sondear: async () => responde({ titulo: '此域名出售' }) } })
  );

  assert.equal(r.headline, 'ejemplo.cn responde con una página de venta');
  assert.ok(titulos(r).some((t) => /página de venta|aparcado/i.test(t)));
});

test('una palabra que contiene "parking" no dispara la alarma', async () => {
  // `preparkinghouse` no es parking, pero un `includes` sin más lo daría.
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ web: { sondear: async () => responde({ titulo: 'Preparkinghouse Analytics' }) } })
  );
  assert.equal(r.status, ESTADOS.PASS);
});

/* ------------------------------------------------------------------ *
 * Redirecciones y método
 * ------------------------------------------------------------------ */

test('una redirección se cuenta y se enseña', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({
      web: {
        sondear: async () =>
          responde({
            urlFinal: 'https://www.ejemplo.com/',
            cadena: [
              { url: 'http://ejemplo.com/', estado: 301 },
              { url: 'https://ejemplo.com/', estado: 301 },
              { url: 'https://www.ejemplo.com/', estado: 200 }
            ]
          })
      }
    })
  );

  const cadena = r.sections.find((s) => s.title === 'Cadena de redirecciones');
  assert.ok(cadena, 'con dos saltos hay que enseñar la cadena');
  assert.equal(cadena.rows.length, 3);
  assert.equal(r.status, ESTADOS.PASS, 'redirigir bien no es un problema');
});

test('el fallback de HEAD a GET es una nota, no un aviso', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ web: { sondear: async () => responde({ metodo: 'GET', motivoAlternativo: 405 }) } })
  );

  const hallazgo = r.findings.find((f) => /no admite HEAD/.test(f.title));
  assert.equal(hallazgo.severity, SEVERIDADES.INFO);
  assert.equal(r.status, ESTADOS.PASS, 'que no soporte HEAD no estropea el veredicto');
});

/* ------------------------------------------------------------------ *
 * TLS
 * ------------------------------------------------------------------ */

test('el certificado se pide exigiendo validación antes que nada', async () => {
  const tls = tlsFalso({ certificado: TLS_SANO.certificado || null });
  tls.conectar = async function (opciones) {
    this.llamadas.push(opciones);
    return { socket: { destroy() {} }, certificado: opciones.verificar ? null : null, avisos: [] };
  };
  const ctx = contexto({ tls });
  await webChecker.ejecutar({ url: 'ejemplo.com' }, ctx);

  assert.equal(tls.llamadas[0].verificar, true, 'primero se exige el certificado');
});

test('un certificado que no valida se lee igualmente para poder contarlo', async () => {
  const tls = tlsFalso({
    fallaAlVerificar: true,
    certificado: { sujeto: 'ejemplo.com', validoHasta: '2030-01-01', diasRestantes: 900, protocolo: 'TLSv1.3', cifrado: 'AES', nombresAlternativos: ['DNS:ejemplo.com'], autoFirmado: false, autoridadCertificadora: false, motivoRechazo: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' }
  });

  const r = await webChecker.ejecutar({ url: 'ejemplo.com' }, contexto({ tls }));

  assert.equal(tls.llamadas.length, 2, 'segunda vuelta sin verificar para leer la ficha');
  const seccion = r.sections.find((s) => s.title === 'Certificado');
  assert.ok(seccion.items.some(([etiqueta]) => etiqueta === 'Estado'));
  // El motivo del rechazo es el dato que explica el aviso del navegador.
  assert.ok(JSON.stringify(seccion).includes('UNABLE_TO_VERIFY_LEAF_SIGNATURE'));
});

test('un certificado ilegible no tumba el informe', async () => {
  const tls = {
    conectar: async () => { throw new Error('ECONNRESET'); },
    auditarCertificado: () => []
  };
  const r = await webChecker.ejecutar({ url: 'ejemplo.com' }, contexto({ tls }));

  assert.notEqual(r.status, ESTADOS.FAIL, 'no poder leer un certificado no es una caída');
  assert.ok(titulos(r).some((t) => /No se pudo leer el certificado/.test(t)));
});

/* ------------------------------------------------------------------ *
 * RDAP
 * ------------------------------------------------------------------ */

test('un dominio caducado se dice con días, no con una fecha suelta', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ rdap: rdapFalso({ disponible: true, consultable: true, caducidad: '2019-03-04 10:00:00 GMT', retenciones: [] }) })
  );

  assert.ok(titulos(r).some((t) => /caducó hace \d+ días/.test(t)));
});

test('una retención activa se nombra', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ rdap: rdapFalso({ disponible: true, consultable: true, caducidad: '2031-06-01 10:00:00 GMT', retenciones: ['clientHold'] }) })
  );

  const hallazgo = r.findings.find((f) => /retención activa/.test(f.title));
  assert.ok(hallazgo, `no se avisó de la retención: ${titulos(r).join(' | ')}`);
  assert.match(hallazgo.title, /clientHold/);
});

test('un TLD sin RDAP no se convierte en "dominio libre"', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.desconocido' },
    contexto({
      web: { sondear: async () => responde({ url: 'https://ejemplo.desconocido/', urlFinal: 'https://ejemplo.desconocido/', cadena: [{ url: 'https://ejemplo.desconocido/', estado: 200 }] }) },
      dns: dnsFalso({ 'ejemplo.desconocido': { A: ok(['198.51.100.7']), AAAA: ok([]) } }),
      rdap: rdapFalso({ disponible: false, consultable: false, motivo: 'El directorio de IANA no lista un servidor RDAP para esta terminación.' })
    })
  );

  // "No hay registro público" y "no está registrado" son frases opuestas.
  assert.ok(titulos(r).some((t) => /no tiene un registro público/.test(t)));
  assert.ok(!titulos(r).some((t) => /no aparece en ningún registro/.test(t)));
});

test('un dominio que no aparece en ningún registro sí se dice', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ rdap: rdapFalso({ disponible: false, consultable: true, motivo: 'Ninguna respuesta RDAP tiene este nombre.' }) })
  );

  assert.ok(titulos(r).some((t) => /no aparece en ningún registro/.test(t)));
});

test('un RDAP que falla es un hueco, no una prueba de nada', async () => {
  const r = await webChecker.ejecutar(
    { url: 'ejemplo.com' },
    contexto({ rdap: { consultarDominio: async () => { throw new Error('ECONNRESET'); } } })
  );

  assert.ok(titulos(r).some((t) => /No se pudo consultar el registro/.test(t)));
  assert.notEqual(r.status, ESTADOS.FAIL, 'no poder mirar no es estar mal');
});

/* ------------------------------------------------------------------ *
 * Direcciones literales
 * ------------------------------------------------------------------ */

test('una IP literal no se busca en DNS ni se acusa de no resolver', async () => {
  const dns = dnsFalso({});
  const r = await webChecker.ejecutar(
    { url: 'https://192.0.2.10/' },
    contexto({
      dns,
      web: { sondear: async () => responde({ url: 'https://192.0.2.10/', urlFinal: 'https://192.0.2.10/', cadena: [{ url: 'https://192.0.2.10/', estado: 200 }] }) },
      rdap: rdapFalso({ disponible: false, consultable: true, motivo: 'sin registro' })
    })
  );

  assert.equal(dns.consultas.length, 0, 'a una IP no se le pregunta por DNS');
  assert.ok(!titulos(r).some((t) => /no resuelve/.test(t)));
  assert.ok(titulos(r).some((t) => /No hay dominio que consultar/.test(t)));
  assert.ok(!r.sections.some((s) => s.title === 'Caducidad del dominio'));
});

/* ------------------------------------------------------------------ *
 * Comparar resolvers
 * ------------------------------------------------------------------ */

test('comparar resolvers está apagado salvo que se pida', async () => {
  const dns = DNS_SANO;
  await webChecker.ejecutar({ url: 'ejemplo.com' }, contexto({ dns }));
  assert.ok(!dns.consultas.some((c) => c.servers), 'no debe preguntar a 1.1.1.1 sin permiso');
});

test('resolvers distintos se explican como diferencia de visibilidad', async () => {
  const dns = {
    consultarLote: DNS_SANO.consultarLote.bind(DNS_SANO),
    consultar: async (nombre, tipo, opciones = {}) => {
      if (opciones.servers) return ok(['203.0.113.9'], 60);
      return ok(['93.184.216.34'], 300);
    }
  };

  const r = await webChecker.ejecutar({ url: 'ejemplo.com', compararResolvers: true }, contexto({ dns }));

  const tabla = r.sections.find((s) => s.title === 'La dirección depende de quién pregunta');
  assert.ok(tabla, 'hay que enseñar la comparación');
  assert.equal(tabla.rows.length, 2);
  assert.ok(titulos(r).some((t) => /distinga según el resolvedor|direcciones distintas/.test(t)));
});

test('resolvers que coinciden no añaden ruido', async () => {
  const dns = {
    consultarLote: DNS_SANO.consultarLote.bind(DNS_SANO),
    consultar: async (nombre, tipo) => ok(['93.184.216.34'], 300)
  };

  const r = await webChecker.ejecutar({ url: 'ejemplo.com', compararResolvers: true }, contexto({ dns }));

  assert.ok(r.sections.some((s) => s.title === 'La dirección depende de quién pregunta'));
  assert.ok(!titulos(r).some((t) => /distinga según el resolvedor|direcciones distintas/.test(t)));
});

/* ------------------------------------------------------------------ *
 * Entrada
 * ------------------------------------------------------------------ */

test('sin dirección se explica qué escribir', async () => {
  const r = await webChecker.ejecutar({}, contexto());
  assert.equal(r.status, ESTADOS.ERROR);
  assert.equal(r.error.code, 'ENTRADA_VACIA');
});

test('una dirección mal escrita da un error, no un sondeo', async () => {
  const r = await webChecker.ejecutar({ url: 'no es una url' }, contexto());
  assert.equal(r.status, ESTADOS.ERROR);
  assert.equal(r.error.code, 'PARAM_INVALIDO');
});

test('el objetivo guarda lo que se escribió, sin los espacios del pegado', async () => {
  const r = await webChecker.ejecutar({ url: '  EJEMPLO.com/ruta  ' }, contexto());

  // Se recortan los bordes porque el formulario los manda con espacios
  // Pegados, pero el contenido se respeta tal cual: si alguien escribe otra
  // cosa, el informe tiene que enseñar esa otra cosa.
  assert.equal(r.target, 'EJEMPLO.com/ruta');
  // El titular sale del `URL` normalizado, y `URL` pasa el nombre a minúsculas
  // porque DNS no distingue mayúsculas. La ruta, en cambio, sí distingue, y por
  // eso un sitio con `/Ruta` y `/ruta` puede romperse con un 404.
  assert.equal(r.headline, 'ejemplo.com está operativa');
  assert.equal(r.params.url, '  EJEMPLO.com/ruta  ', 'los parámetros sí conservan lo enviado');
});

test('los parámetros no se guardan con secretos dentro', async () => {
  const r = await webChecker.ejecutar({ url: 'https://usuario:secreto@ejemplo.com' }, contexto());
  assert.ok(!JSON.stringify(r.params).includes('secreto'));
});

test('las opciones por defecto son las del formulario', () => {
  const leer = webChecker._internas.leerOpciones;
  assert.deepEqual(leer({}), {
    timeoutMs: 8000,
    permitirPrivadas: false,
    consultarCaducidad: true,
    compararResolvers: false,
    compartir: false,
    ttlDiasCompartir: 7
  });
  assert.equal(leer({ timeout: 500 }).timeoutMs, 1000, 'el mínimo se respeta');
  assert.equal(leer({ timeout: 999999 }).timeoutMs, 30000, 'el máximo se respeta');
  assert.equal(leer({ timeout: 'abc' }).timeoutMs, 8000, 'un timeout tonto cae al defecto');
  assert.equal(leer({ permitirRedPrivada: 'sí' }).permitirPrivadas, false, 'una casilla no se activa con texto');
});

/* ------------------------------------------------------------------ *
 * El titular, aislado
 * ------------------------------------------------------------------ */

test('el titular depende solo de la respuesta del servidor', () => {
  const t = webChecker._internas.titularDe;
  const h = 'ejemplo.com';

  assert.equal(t(h, responde()), `${h} está operativa`);
  assert.equal(t(h, responde({ error: errorRed() })), `${h} no ha respondido`);
  assert.equal(t(h, responde({ bucle: true })), `${h} se redirige a sí mismo`);
  assert.equal(t(h, responde({ estado: 500 })), `${h} responde con un error 500`);
  assert.equal(t(h, responde({ estado: 404 })), `${h} responde con un error 404`);
  assert.equal(t(h, responde({ titulo: 'Dominio en venta | Afternic' })), `${h} responde con una página de venta`);
  assert.equal(t(h, responde({ titulo: 'Coming Soon' })), `${h} responde con una página en construcción`);
});

test('díasPara no inventa cifras con una fecha ilegible', () => {
  const d = webChecker._internas.diasPara;
  assert.equal(d(null), null);
  assert.equal(d(''), null);
  assert.equal(d('no es una fecha'), null);
  assert.equal(typeof d('2031-06-01 10:00:00 GMT'), 'number');
});

test('canónico ordena direcciones para compararlas', () => {
  const c = webChecker._internas.canonico;
  assert.equal(c(['1.1.1.2', '1.1.1.1', '1.1.1.1']), '1.1.1.1,1.1.1.2');
  assert.equal(c([]), '');
});

/* ------------------------------------------------------------------ *
 * Renderizado
 * ------------------------------------------------------------------ */

test('los cinco formatos renderizan el informe completo', async () => {
  const r = await webChecker.ejecutar({ url: 'ejemplo.com' }, contexto());
  for (const formato of formats.soportados().map((f) => f.nombre)) {
    const salida = await formats.render(r, formato);
    assert.ok(salida.length > 0, `${formato} sale vacío`);
  }
  // Los renderizadores devuelven Buffer, no cadena: hay queConvertir antes de
  // comparar texto, y olvidarlo es el fallo clásico de estas pruebas.
  assert.match((await formats.render(r, 'txt')).toString('utf8'), /está operativa/);
  assert.match((await formats.render(r, 'md')).toString('utf8'), /está operativa/);
  assert.match((await formats.render(r, 'html')).toString('utf8'), /está operativa/);
});

test('un informe con error también se renderiza', async () => {
  const r = await webChecker.ejecutar({ url: 'interno.local' }, contexto({ web: { sondear: async () => { throw errorSsrf(); } } }));
  assert.equal(r.status, ESTADOS.ERROR);
  for (const formato of formats.soportados().map((f) => f.nombre)) {
    assert.ok((await formats.render(r, formato)).length > 0, `${formato} no renderiza un error`);
  }
});

test('el JSON del informe lleva el esquema y el titular', async () => {
  const r = await webChecker.ejecutar({ url: 'ejemplo.com' }, contexto());
  const json = JSON.parse((await formats.render(r, 'json')).toString('utf8'));
  assert.equal(json.schema, 2);
  assert.equal(json.tool, 'web-checker');
  assert.equal(json.headline, 'ejemplo.com está operativa');
  assert.ok(Array.isArray(json.sections));
});