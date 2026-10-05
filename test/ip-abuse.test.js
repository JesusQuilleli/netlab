'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const ipAbuse = require('../src/tools/ip-abuse');
const { NetlabError, CODES } = require('../src/core/errors');
const { ESTADOS } = require('../src/core/result');

/** Datos con forma de respuesta de AbuseIPDB, con valores por defecto razonables. */
function datos(extra = {}) {
  return {
    ip: '203.0.113.10',
    esPublica: true,
    esWhitelisted: false,
    esMovil: false,
    tipoUso: 'Data Center',
    tipoUsoEs: 'Centro de datos',
    isp: 'Ejemplo Hosting',
    dominio: 'ejemplo.com',
    codigoPais: 'US',
    nombrePais: 'Estados Unidos',
    puntuacionConfianza: 0,
    totalReportes: 0,
    autoresDistintos: 0,
    ultimoReporte: null,
    ultimoReporteTexto: 'Sin datos',
    ventanaDias: 30,
    totalEnVentana: 0,
    reportes: [],
    resumenCategorias: [],
    ...extra
  };
}

/** Doble de la consulta: aplica el mismo objeto a cualquier IP. */
function doble(objeto) {
  return async (ip) => {
    const d = typeof objeto === 'function' ? objeto(ip) : objeto;
    if (d instanceof Error) throw d;
    return { ...datos(), ...d, ip };
  };
}

/** Doble de la consulta: cada IP devuelve su propio objeto. */
function doblePorIp(mapa) {
  return async (ip) => {
    const d = mapa[ip];
    if (d instanceof Error) throw d;
    return { ...datos(), ...d, ip };
  };
}

/** Ejecuta con la clave puesta, para saltar el error de credencial. */
function ejecutar(params, ctx = {}) {
  return ipAbuse.ejecutar(params, { clave: 'clave-de-prueba', ...ctx });
}

/** Busca un hallazgo cuyo titulo encaje con el patron. */
function hallazgo(result, patron) {
  return result.findings.find((f) => patron.test(f.title));
}

/** Busca una seccion por titulo. */
function seccion(result, titulo) {
  return result.sections.find((s) => s.title === titulo);
}

test('rechaza una entrada sin ninguna IP valida', async () => {
  const r = await ejecutar({ ip: 'esto no es una ip' });
  assert.equal(r.status, ESTADOS.ERROR);
  assert.equal(r.error.code, CODES.PARAM_INVALIDO);
  assert.match(r.error.remediation, /203\.0\.113\.10/);
});

test('sin clave lo dice y dice como arreglarlo', async () => {
  const r = await ipAbuse.ejecutar({ ip: '203.0.113.10' }, { clave: '' });
  assert.equal(r.status, ESTADOS.ERROR);
  assert.equal(r.error.code, CODES.CREDENCIAL_AUSENTE);
  assert.match(r.error.remediation, /ABUSEIPDB_API_KEY/);
});

test('la clave nunca sale en el Result', async () => {
  // Si la clave se colara en params, acabaria en el historial y en el PDF. Por
  // eso se comprueba el texto entero del Result, no solo una parte.
  const clave = 'AKIA3EJEMPLOMUYSECRETO123456';
  const r = await ejecutar({ ip: '203.0.113.10' }, { clave });

  const serializado = JSON.stringify(r);
  assert.ok(!serializado.includes(clave), 'la clave no puede aparecer en ninguna parte del Result');

  // Y lo que si se ve es la version enmascarada, para poder confirmar cual se uso.
  const resumenClave = r.summary.find((s) => s.label === 'Clave usada');
  assert.ok(resumenClave, 'debe indicar que clave se ha usado');
  assert.ok(!resumenClave.value.includes('EJEMPLO'));
  assert.match(resumenClave.value, /•/);
});

test('una IP sin avisos pasa y avisa de que se ha mirado poco', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, { abuse: doble({}) });

  assert.equal(r.status, ESTADOS.PASS);
  assert.equal(r.summary.find((s) => s.label === 'Avisos en la ventana').value, '0');
  assert.ok(hallazgo(r, /no tiene avisos/));
});

test('con ventana corta sugiere ampliarla si no hay avisos', async () => {
  // El fallo de legacy/: con 5 dias de ventana, una IP con avisos antiguos
  // salia limpia. Sin este aviso, el informe miente sin querer.
  const r = await ejecutar({ ip: '203.0.113.10', dias: 7 }, { abuse: doble({ ventanaDias: 7 }) });
  const h = hallazgo(r, /no tiene avisos/);
  assert.match(h.recommendation, /amplia la ventana/);
});

test('con ventana ancha no pide ampliarla', async () => {
  const r = await ejecutar({ ip: '203.0.113.10', dias: 180 }, { abuse: doble({ ventanaDias: 180 }) });
  const h = hallazgo(r, /no tiene avisos/);
  assert.ok(!/amplia la ventana/.test(h.recommendation), 'con 180 dias no tiene sentido pedir mas');
});

test('muchos avisos de un solo autor se marcan como ruido probable', async () => {
  // El caso que legacy/ no distinguia: 40 avisos de la misma fuente no es lo
  // mismo que avisos repartidos. Marcarse por el total lleva aSenalar a una IP
  // que solo ha visto un escaner.
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    { abuse: doble({ totalReportes: 40, autoresDistintos: 1, puntuacionConfianza: 12 }) }
  );

  const h = hallazgo(r, /de un solo autor/);
  assert.ok(h, 'debe avisar del reparto de autores');
  assert.equal(h.severity, 'warn');
  assert.match(h.recommendation, /pista, no como un veredicto/);
  assert.ok(!hallazgo(r, /autores distintos/), 'no debe alarmar como si fueran fuentes independientes');
});

test('avisos de muchos autores distintos si alarman', async () => {
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    {
      abuse: doble({
        totalReportes: 25,
        autoresDistintos: 8,
        puntuacionConfianza: 88,
        resumenCategorias: [{ id: 14, nombre: 'Escaneo de puertos', veces: 20 }]
      })
    }
  );

  assert.equal(r.status, ESTADOS.FAIL);
  const h = hallazgo(r, /8 autores distintos/);
  assert.equal(h.severity, 'error');
  assert.match(h.detail, /25 aviso\(s\) de 8 fuentes/);
  assert.match(h.recommendation, /no confiable/);
});

test('varios autores con pocos avisos es observacion, no fallo', async () => {
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    { abuse: doble({ totalReportes: 4, autoresDistintos: 3, puntuacionConfianza: 30 }) }
  );
  assert.equal(r.status, ESTADOS.WARN);
  assert.equal(hallazgo(r, /autores distintos/).severity, 'warn');
});

test('un 100 % de confianza es fallo y se dice el porque', async () => {
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    { abuse: doble({ totalReportes: 9, autoresDistintos: 6, puntuacionConfianza: 100 }) }
  );
  assert.equal(r.status, ESTADOS.FAIL);
  assert.ok(hallazgo(r, /100 % de confianza/));
});

test('una IP en lista blanca lo dice sin ocultarlo', async () => {
  // La lista blanca no debe tapar los avisos: si hay 12, se dice.
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    { abuse: doble({ esWhitelisted: true, totalReportes: 12, autoresDistintos: 5 }) }
  );
  const h = hallazgo(r, /lista blanca/);
  assert.ok(h);
  assert.match(h.detail, /12 aviso/);
  assert.equal(h.severity, 'info', 'informativo: no es por si mismo un problema');
});

test('una IP movil avisa de que el bloqueo no es justo', async () => {
  // Solo tiene sentido con avisos en juego: el problema de una IP movil es que
  // hereda los de otros usuarios. Sin avisos no hay nada queasl warnir.
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    { abuse: doble({ esMovil: true, tipoUso: 'Mobile Network', tipoUsoEs: 'Red movil', totalReportes: 4, autoresDistintos: 3 }) }
  );
  const h = hallazgo(r, /red m.vil/);
  assert.ok(h, 'con avisos debe avisar de que la IP se comparte');
  assert.match(h.recommendation, /no han hecho nada/);
});

test('sin dominio descarta el aviso de PTR solo si hay avisos', async () => {
  // Con cero avisos, que no haya PTR es la situacion normal de cualquier IP y
  // no merece una linea en el informe.
  const sinAvisos = await ejecutar({ ip: '203.0.113.10' }, { abuse: doble({ dominio: null }) });
  assert.ok(!hallazgo(sinAvisos, /PTR declarado/));

  const conAvisos = await ejecutar(
    { ip: '203.0.113.10' },
    { abuse: doble({ dominio: null, totalReportes: 3, autoresDistintos: 2 }) }
  );
  assert.ok(hallazgo(conAvisos, /PTR declarado/));
});

test('los comentarios de terceros van ocultos salvo que se pidan', async () => {
  const base = { totalReportes: 2, autoresDistintos: 2, reportes: [{ fechaTexto: '2025-01-01 00:00 UTC', pais: 'RU', categoriasTexto: 'Escaneo de puertos', comentario: 'mucho trafico raro' }] };

  const sinComentarios = await ejecutar({ ip: '203.0.113.10' }, { abuse: doble(base) });
  const tabla = seccion(sinComentarios, 'Avisos (203.0.113.10)');
  assert.deepEqual(tabla.columns, ['Fecha', 'Pais', 'Categorias']);
  assert.ok(!JSON.stringify(tabla.rows).includes('mucho trafico raro'));

  const conComentarios = await ejecutar({ ip: '203.0.113.10', comentarios: true }, { abuse: doble(base) });
  const tabla2 = seccion(conComentarios, 'Avisos (203.0.113.10)');
  assert.equal(tabla2.columns.length, 4);
  assert.match(tabla2.rows[0][3], /mucho trafico raro/);
});

test('sin detalle no hay tabla de avisos', async () => {
  const r = await ejecutar(
    { ip: '203.0.113.10', detalle: false },
    { abuse: doble({ totalReportes: 5, autoresDistintos: 3, reportes: [{ fechaTexto: 'x', pais: 'RU', categoriasTexto: 'y' }] }) }
  );
  assert.equal(seccion(r, 'Avisos (203.0.113.10)'), undefined);
  // Pero el veredicto sigue estando: desactivar el detalle no oculta el riesgo.
  assert.ok(hallazgo(r, /autores distintos/));
});

test('un comentario largo se recorta para no reventar la tabla', async () => {
  const enorme = 'x'.repeat(2000);
  const r = await ejecutar(
    { ip: '203.0.113.10', comentarios: true },
    { abuse: doble({ totalReportes: 1, autoresDistintos: 1, reportes: [{ fechaTexto: 'x', pais: 'RU', categoriasTexto: 'y', comentario: enorme }] }) }
  );
  const celda = seccion(r, 'Avisos (203.0.113.10)').rows[0][3];
  assert.equal(celda.length, 300);
});

test('se recorta el numero de avisos mostrados y se dice cuantos faltan', async () => {
  const reportes = Array.from({ length: 12 }, (_, i) => ({ fechaTexto: `2025-01-${String(i + 1).padStart(2, '0')}`, pais: 'RU', categoriasTexto: 'X' }));
  const r = await ejecutar(
    { ip: '203.0.113.10', maxAvisos: 5 },
    { abuse: doble({ totalReportes: 12, autoresDistintos: 3, reportes }) }
  );

  const tabla = seccion(r, 'Avisos (203.0.113.10)');
  assert.equal(tabla.rows.length, 5);
  assert.match(tabla.description, /5 m.s recientes de 12/);
});

test('con varias IPs sale una tabla ordenada de peor a mejor', async () => {
  const mapa = {
    '203.0.113.1': { totalReportes: 1, autoresDistintos: 1 },
    '203.0.113.2': { totalReportes: 90, autoresDistintos: 20, puntuacionConfianza: 95 },
    '203.0.113.3': { totalReportes: 0, autoresDistintos: 0 }
  };
  const r = await ejecutar(
    { ip: '203.0.113.1, 203.0.113.2 203.0.113.3' },
    { abuse: doblePorIp(mapa) }
  );

  const tabla = seccion(r, 'Resumen de las direcciones consultadas');
  assert.deepEqual(tabla.rows.map((f) => f[0]), ['203.0.113.2', '203.0.113.1', '203.0.113.3']);
  assert.equal(r.summary.find((s) => s.label === 'Direcciones consultadas').value, '3');
});

test('acepta IPv6 y descarta lo que no es IP sin tirar la lista', async () => {
  // Una coma sobrante al escribir veinte direcciones no debe invalidarlo todo.
  // El estado pasa a "warn" porque hay una entrada que no se ha consultado, y
  // eso hay que verlo: perder una IP en silencio es justo lo que se evita.
  const r = await ejecutar(
    { ip: '2001:db8::1, no-es-una-ip, 203.0.113.5' },
    { abuse: doble({}) }
  );
  assert.equal(r.status, ESTADOS.WARN);
  assert.equal(r.summary.find((s) => s.label === 'Direcciones consultadas').value, '2');
});

test('un separador sobrante no genera aviso, no hay nada que descartar', async () => {
  // La diferencia con el caso anterior: una coma final no es una entrada, es
  // ruido del separador. Avisar de esto seria ruido en el informe.
  const r = await ejecutar({ ip: '203.0.113.5,' }, { abuse: doble({}) });
  assert.equal(r.status, ESTADOS.PASS);
  assert.ok(!hallazgo(r, /no son IPs/i));
});

test('sin numero de avisos no se afirma que la IP este limpia', async () => {
  // El fallo grave: si el campo no llega y se convierte en un 0, la herramienta
  // cierra la puerta con "no tiene avisos". Aqui la API ademas dice 9 autores y
  // 100 % de abuso, asi que el informe se contradiria con los datos de al lado.
  const r = await ejecutar({ ip: '203.0.113.10' }, { abuse: doble({ totalReportes: null }) });

  assert.ok(!hallazgo(r, /no tiene avisos/), 'no puede decir que no hay avisos si no lo sabe');
  const aviso = hallazgo(r, /no se ha podido comprobar/i);
  assert.ok(aviso, 'tiene que dejar claro que no se pudo comprobar');
  assert.equal(aviso.severity, 'warn');
});

test('sin autores distintos se dice que no se ha podido saber, no se calla', async () => {
  // El reparto entre autores es justo lo que separa el ruido del problema. Si
  // falta, la conclusion se debilita sin avisar de que se ha debilitado.
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    { abuse: doble({ totalReportes: 12, autoresDistintos: null, puntuacionConfianza: 90 }) }
  );

  const aviso = hallazgo(r, /no se sabe de cuantos autores/);
  assert.ok(aviso, 'debe avisar de que falta el reparto por autores');
  assert.match(aviso.detail, /autores distintos/);
  assert.equal(aviso.severity, 'info');
  // Y lo que no puede pasar: inventar un recuento a partir de nada.
  assert.ok(!hallazgo(r, /\d+ autores distintos/), 'no se puede fabricar un numero de autores');
  // El volumen de avisos sigue siendo un hecho, aunque no se pueda repartir.
  assert.ok(hallazgo(r, /acumula 12 aviso/));
});

test('los numeros escritos como texto no pierden el veredicto', async () => {
  // Una respuesta con "100" en vez de 100 es drift de esquema, no un dato nulo.
  // Con Number.isFinite el 100 % de abuso se perdia en silencio.
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    { abuse: doble({ totalReportes: '12', autoresDistintos: '9', puntuacionConfianza: '100' }) }
  );

  assert.ok(hallazgo(r, /100 % de confianza/));
  assert.ok(hallazgo(r, /9 autores distintos/));
});

test('las IPs descartadas por no ser validas se dicen en el informe', async () => {
  // Descartarlas sin decir nada es perder direcciones en silencio: de 20 IPs
  // pegadas con dos erratas, nadie sabria que dos no se miraron.
  const r = await ejecutar(
    { ip: '203.0.113.10, 203.0.113.11, no-es-una-ip, 203.0.113.0.300' },
    { abuse: doble({}) }
  );

  const aviso = hallazgo(r, /no son IPs/i);
  assert.ok(aviso, 'tiene que decir cuantas entradas se quedaron sin consultar');
  assert.match(aviso.title, /^2 de las entradas/);
  assert.match(aviso.detail, /no-es-una-ip/);
  assert.match(aviso.detail, /203\.0\.113\.0\.300/);
  assert.equal(aviso.severity, 'warn');
});

test('si no se descarta nada, no hay aviso de descartadas', async () => {
  const r = await ejecutar({ ip: '203.0.113.10, 203.0.113.11' }, { abuse: doble({}) });
  assert.ok(!hallazgo(r, /no son IPs/i), 'un aviso sin motivo solo mete ruido');
  assert.equal(r.status, ESTADOS.PASS);
});

test('una IP que falla no tumba el resto y se avisa', async () => {
  const r = await ejecutar(
    { ip: '203.0.113.1, 203.0.113.2' },
    {
      abuse: async (ip) => {
        if (ip === '203.0.113.1') throw new NetlabError(CODES.API_CUOTA, 'Cuota agotada');
        return datos({ ip, totalReportes: 0 });
      }
    }
  );

  assert.equal(r.status, ESTADOS.WARN);
  assert.ok(hallazgo(r, /1 de 2 direcciones/));
  assert.ok(seccion(r, 'Resumen de las direcciones consultadas'), 'el resto del informe sigue saliendo');
});

test('si fallan todas, es un error y no un informe a medias', async () => {
  const r = await ejecutar(
    { ip: '203.0.113.1, 203.0.113.2' },
    { abuse: async () => { throw new NetlabError(CODES.API_EXTERNA, 'Servicio caido'); } }
  );
  assert.equal(r.status, ESTADOS.ERROR);
  assert.equal(r.error.code, CODES.API_EXTERNA);
  assert.match(r.error.message, /ninguna de las 2/);
});

test('la ventana se acota al rango que acepta la API', async () => {
  // Fuera de 1 a 365 dias la API responde 400. Un valor absurdo escrito en el
  // formulario no debe convertirse en un error de la API.
  let vistos = [];
  await ejecutar(
    { ip: '203.0.113.1', dias: 99999 },
    { abuse: async (ip) => { vistos.push(1); return datos({ ip, ventanaDias: 365 }); } }
  );
  assert.equal(vistos.length, 1);

  const bajo = await ejecutar({ ip: '203.0.113.1', dias: -5 }, { abuse: doble({}) });
  assert.ok(bajo.summary, 'un valor negativo no debe romper la ejecucion');
});

test('declara su forma como herramienta dinamica', () => {
  assert.equal(ipAbuse.id, 'ip-abuse');
  assert.equal(ipAbuse.sinRed, false, 'la consulta es exactamente lo que hace red');
  assert.ok(Array.isArray(ipAbuse.campos));
  // El campo de destino tiene que existir y ser obligatorio: la herramienta
  // consulta lo que le digan, no una lista fija.
  const destino = ipAbuse.campos.find((c) => c.name === 'ip');
  assert.equal(destino.required, true);
});

test('parseIps separa bien y tolera separadores raros', () => {
  assert.deepEqual(ipAbuse.parseIps('203.0.113.1'), ['203.0.113.1']);
  assert.deepEqual(ipAbuse.parseIps('203.0.113.1,203.0.113.2'), ['203.0.113.1', '203.0.113.2']);
  assert.deepEqual(ipAbuse.parseIps('203.0.113.1; 203.0.113.2\n203.0.113.3'), ['203.0.113.1', '203.0.113.2', '203.0.113.3']);
  assert.deepEqual(ipAbuse.parseIps(''), []);
  assert.deepEqual(ipAbuse.parseIps('basura'), []);
});

test('parseIps descarta lo que no es una IP tambien en un array', () => {
  // La web envia un array. Si ahi no se filtra, una IP mal tecleada se cuela
  // hasta la API, que la rechaza y el informe sale a medias.
  assert.deepEqual(ipAbuse.parseIps(['203.0.113.1', 'no-es-una-ip']), ['203.0.113.1']);
  assert.deepEqual(ipAbuse.parseIps([' 203.0.113.1 ', '', null, '203.0.113.2']), ['203.0.113.1', '203.0.113.2']);
  assert.deepEqual(ipAbuse.parseIps(['basura']), []);
});
