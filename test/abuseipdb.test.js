'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const abuseipdb = require('../src/core/net/abuseipdb');
const { NetlabError, CODES } = require('../src/core/errors');

/** Respuesta falsa con lo justo para que getJSON la pueda usar. */
function respuesta({ status = 200, cuerpo = {} } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    text: async () => (typeof cuerpo === 'string' ? cuerpo : JSON.stringify(cuerpo))
  };
}

/** Datos completos de la API, como los devuelve AbuseIPDB. */
function cuerpoApi(extra = {}) {
  return {
    data: {
      ipAddress: '203.0.113.10',
      isPublic: true,
      isWhitelisted: false,
      isMobile: false,
      usageType: 'Data Center',
      isp: 'Ejemplo Hosting',
      domain: 'ejemplo.com',
      countryCode: 'US',
      countryName: 'United States',
      abuseConfidenceScore: 42,
      totalReports: 7,
      numDistinctUsers: 4,
      lastReportedAt: '2025-03-04T15:07:00+00:00',
      reports: [],
      ...extra
    }
  };
}

/** fetch que siempre devuelve el mismo cuerpo de la API. */
const responderCon = (cuerpo) => async () => respuesta({ cuerpo });

test('sin clave no se llega a llamar a la API', async () => {
  let llamado = false;
  await assert.rejects(
    abuseipdb.consultar('203.0.113.10', { clave: '', fetchImpl: async () => { llamado = true; } }),
    (e) => {
      assert.ok(e instanceof NetlabError);
      assert.equal(e.code, CODES.CREDENCIAL_AUSENTE);
      assert.match(e.remediation, /ABUSEIPDB_API_KEY/);
      return true;
    }
  );
  assert.equal(llamado, false, 'no se debe gastar una llamada sin credencial');
});

test('normaliza la respuesta y conserva el numero de autores distintos', async () => {
  const d = await abuseipdb.consultar('203.0.113.10', {
    clave: 'k',
    fetchImpl: responderCon(cuerpoApi())
  });

  assert.equal(d.ip, '203.0.113.10');
  assert.equal(d.totalReportes, 7);
  assert.equal(d.autoresDistintos, 4, 'este es el dato que legacy/ ignoraba');
  assert.equal(d.puntuacionConfianza, 42);
  assert.equal(d.tipoUsoEs, 'Centro de datos');
  assert.match(d.ultimoReporteTexto, /^2025-03-04 15:07 UTC$/);
});

test('la ventana por defecto es de 30 dias, no de 5', async () => {
  // legacy/ consultaba 5 dias. Con esa ventana, una IP con avisos de hace una
  // semana salia limpia, y ese es justo el fallo que hay que no repetir.
  let vista;
  await abuseipdb.consultar('203.0.113.10', {
    clave: 'k',
    fetchImpl: async (url) => {
      vista = url;
      return respuesta({ cuerpo: cuerpoApi() });
    }
  });

  assert.match(vista, /maxAgeInDays=30/);
});

test('la ventana se acota a lo que la API acepta', async () => {
  for (const [pedido, esperado] of [[0, 1], [-4, 1], [400, 365], [30, 30]]) {
    let vista;
    await abuseipdb.consultar('203.0.113.10', {
      clave: 'k',
      maxAgeInDays: pedido,
      fetchImpl: async (url) => {
        vista = url;
        return respuesta({ cuerpo: cuerpoApi() });
      }
    });
    assert.match(vista, new RegExp(`maxAgeInDays=${esperado}`), `pedido ${pedido} -> ${esperado}`);
  }
});

test('detallado decide si se pide la lista de avisos', async () => {
  let vista;
  await abuseipdb.consultar('203.0.113.10', {
    clave: 'k',
    detallado: false,
    fetchImpl: async (url) => {
      vista = url;
      return respuesta({ cuerpo: cuerpoApi() });
    }
  });
  // verbose=0 es lo que hace que la respuesta no venga con los informes.
  assert.match(vista, /verbose=0/);
});

test('un 200 con "errors" es un rechazo, no un exito', async () => {
  // AbuseIPDB responde 200 OK con un cuerpo de error cuando el parametro no
  // vale. Sin esta comprobacion, `data` llega undefined y el informe sale a
  // medias sin decir por que.
  await assert.rejects(
    abuseipdb.consultar('no-es-una-ip', {
      clave: 'k',
      fetchImpl: responderCon({ errors: [{ status: 400, detail: 'Invalid IP address' }] })
    }),
    (e) => {
      assert.equal(e.code, CODES.API_EXTERNA);
      assert.match(e.message, /Invalid IP address/);
      return true;
    }
  );
});

test('un 200 sin "data" se nota como respuesta inesperada', async () => {
  await assert.rejects(
    abuseipdb.consultar('203.0.113.10', { clave: 'k', fetchImpl: responderCon({ hola: 'que tal' }) }),
    (e) => e.code === CODES.API_EXTERNA
  );
});

test('la clave viaja en la cabecera Key y nunca en la query', async () => {
  // En la URL acabaria en el log del proxy, en el historial del navegador y en
  // cualquier mensaje de error que incluya la URL completa.
  let vista;
  await abuseipdb.consultar('203.0.113.10', {
    clave: 'clave-secreta-123',
    fetchImpl: async (url, opts) => {
      vista = { url, opts };
      return respuesta({ cuerpo: cuerpoApi() });
    }
  });

  assert.ok(!vista.url.includes('clave-secreta-123'), 'la clave no puede ir en la URL');
  assert.equal(vista.opts.headers.Key, 'clave-secreta-123');
});

test('traduce las categorias que conoce y dice las que no', async () => {
  assert.equal(abuseipdb.traducirCategorias([14, 11]), 'Escaneo de puertos, Spam por correo');
  assert.equal(abuseipdb.traducirCategorias([]), 'Sin especificar');

  // Un id sin traducir sale visible como id. Ponerle un nombre inventado seria
  // peor: dirigiria a leer un informe hacia una pista que no existe.
  assert.equal(abuseipdb.nombreCategoria(4242), 'Categoria 4242');
  assert.match(abuseipdb.traducirCategorias([4242]), /Categoria 4242/);
});

test('resume las categorias por veces de mayor a menor', async () => {
  const resumen = abuseipdb.resumirCategorias([
    { categories: [14, 11] },
    { categories: [14] },
    { categories: [14, 9] }
  ]);

  // Los empates se ordenan por identificador, no por el orden de entrada: asi
  // el resumen es estable y dos ejecuciones sobre los mismos datos dan el
  // mismo informe, que es lo que hace comparable un PDF de ayer con el de hoy.
  assert.deepEqual(resumen, [
    { id: 14, nombre: 'Escaneo de puertos', veces: 3 },
    { id: 9, nombre: 'Proxy abierto', veces: 1 },
    { id: 11, nombre: 'Spam por correo', veces: 1 }
  ]);
});

test('resume categorias sin romperse con datos raros', () => {
  assert.deepEqual(abuseipdb.resumirCategorias([]), []);
  assert.deepEqual(abuseipdb.resumirCategorias([{}]), []);
  assert.deepEqual(abuseipdb.resumirCategorias([{ categories: null }]), []);
});

test('las fechas se formatean en UTC y se nota', async () => {
  // legacy/ usaba la zona horaria del servidor, de modo que el mismo informe
  // salia con fecha distinta segun quien lo generara.
  assert.equal(abuseipdb.formatearFecha('2025-03-04T15:07:00Z'), '2025-03-04 15:07 UTC');
  assert.equal(abuseipdb.formatearFecha('2025-03-04T15:07:00+05:00'), '2025-03-04 10:07 UTC');
  assert.equal(abuseipdb.formatearFecha(null), 'Sin datos');
  assert.equal(abuseipdb.formatearFecha('no es una fecha'), 'Fecha ilegible');
});

test('los avisos se normalizan a campos con fecha ya formateada', async () => {
  const d = await abuseipdb.consultar('203.0.113.10', {
    clave: 'k',
    fetchImpl: responderCon(
      cuerpoApi({
        reports: [
          {
            id: 1,
            reportedAt: '2025-03-01T10:00:00Z',
            reporterCountryCode: 'RU',
            reporterCountryName: 'Rusia',
            categories: [14],
            comment: 'escaneo'
          }
        ]
      })
    )
  });

  assert.equal(d.totalEnVentana, 1);
  assert.equal(d.reportes[0].fechaTexto, '2025-03-01 10:00 UTC');
  assert.equal(d.reportes[0].pais, 'RU');
  assert.equal(d.reportes[0].categoriasTexto, 'Escaneo de puertos');
  assert.deepEqual(d.resumenCategorias, [{ id: 14, nombre: 'Escaneo de puertos', veces: 1 }]);
});

test('un 401 de la API es problema de credencial, no de red', async () => {
  await assert.rejects(
    abuseipdb.consultar('203.0.113.10', { clave: 'mala', fetchImpl: async () => respuesta({ status: 401, cuerpo: { errors: [{ detail: 'Unauthorized' }] } }) }),
    (e) => e.code === CODES.CREDENCIAL_INVALIDA
  );
});

test('sin numero de autores distintos se devuelve null, no un 0 inventado', async () => {
  // Un 0 seria una mentira: diria "nadie ha reportado esto" cuando en realidad
  // la API no ha dicho nada. La herramienta distingue los dos casos.
  const d = await abuseipdb.consultar('203.0.113.10', {
    clave: 'k',
    fetchImpl: responderCon(cuerpoApi({ numDistinctUsers: undefined }))
  });
  assert.equal(d.autoresDistintos, null);
});

// --- El mismo principio aplicado al resto de numeros -------------------------
//
// `numDistinctUsers` ya devolvia null cuando faltaba, pero sus dos hermanos
// no. El desajuste era justo el que causaba el fallo: un campo ausente se
// convertia en un 0 y la herramienta afirmaba que la IP no tenia avisos.

test('sin totalReports sale null, no un 0 que parece una IP limpia', async () => {
  // Este es el fallo mas grave del modulo. Con un 0 aqui, una IP con 9 autores
  // distintos y 100 % de abuso sale en el informe como "no tiene avisos".
  const d = await abuseipdb.consultar('203.0.113.10', {
    clave: 'k',
    fetchImpl: responderCon(cuerpoApi({ totalReports: undefined }))
  });
  assert.equal(d.totalReportes, null);
});

test('un numero escrito como texto si se lee', async () => {
  // Que venga como cadena es drift de esquema o un proxy por medio. Con
  // Number.isFinite se perdia el 100 % de abuso sin dejar rastro.
  const d = await abuseipdb.consultar('203.0.113.10', {
    clave: 'k',
    fetchImpl: responderCon(cuerpoApi({ totalReports: '12', numDistinctUsers: '9', abuseConfidenceScore: '100' }))
  });
  assert.equal(d.totalReportes, 12);
  assert.equal(d.autoresDistintos, 9);
  assert.equal(d.puntuacionConfianza, 100);
});

test('un cero de verdad sigue siendo un cero, no se pierde', async () => {
  const d = await abuseipdb.consultar('203.0.113.10', {
    clave: 'k',
    fetchImpl: responderCon(cuerpoApi({ totalReports: 0, numDistinctUsers: 0, abuseConfidenceScore: 0 }))
  });
  assert.equal(d.totalReportes, 0);
  assert.equal(d.autoresDistintos, 0);
  assert.equal(d.puntuacionConfianza, 0);
});

test('un numero que no es un numero sale null en vez de NaN', async () => {
  const d = await abuseipdb.consultar('203.0.113.10', {
    clave: 'k',
    fetchImpl: responderCon(cuerpoApi({ totalReports: 'muchos', abuseConfidenceScore: true, numDistinctUsers: null }))
  });
  assert.equal(d.totalReportes, null);
  assert.equal(d.puntuacionConfianza, null);
  assert.equal(d.autoresDistintos, null);
});

test('si la API responde de otra IP, es un error y no un informe equivocado', async () => {
  // Un informe que titula "198.51.100.99" cuando se pidio "203.0.113.10" lleva
  // a leer la reputacion de una direccion que nadie ha consultado.
  await assert.rejects(
    abuseipdb.consultar('203.0.113.10', {
      clave: 'k',
      fetchImpl: responderCon(cuerpoApi({ ipAddress: '198.51.100.99' }))
    }),
    (e) => {
      assert.equal(e.code, CODES.API_EXTERNA);
      assert.match(e.message, /198\.51\.100\.99/);
      assert.match(e.message, /203\.0\.113\.10/);
      return true;
    }
  );
});

test('una IPv6 en otra notacion no se confunde con otra direccion', async () => {
  // La API puede devolver la IPv6 escrita de otra manera. Eso no es un fallo: si
  // se comparan las cadenas a pelo, toda IPv6 pasaria por direccion distinta.
  const pedida = '2001:db8::1';
  const d = await abuseipdb.consultar(pedida, {
    clave: 'k',
    fetchImpl: responderCon(cuerpoApi({ ipAddress: '2001:0DB8:0000:0000:0000:0000:0000:0001' }))
  });
  assert.equal(d.ip, pedida);
});

test('sin isPublic sale null, no un "no es publica" inventado', async () => {
  // Un false aqui se pinta como un hecho en la tabla de identificacion.
  const d = await abuseipdb.consultar('203.0.113.10', {
    clave: 'k',
    fetchImpl: responderCon(cuerpoApi({ isPublic: undefined }))
  });
  assert.equal(d.esPublica, null);
});
