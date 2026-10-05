/**
 * test/subnet-analyzer.test.js — Pruebas de la herramienta de subredes.
 *
 * La herramienta es el primer consumidor completo del contrato `Result`: aqui
 * se comprueba que el reparto es correcto y, sobre todo, que los fallos de
 * entrada se devuelven como un Result con estado 'error' y no como una
 * excepcion. La interfaz web y la CLI renderizan ese Result; si aqui se
 * escapara una excepcion, el usuario veria un stack de Node en el navegador.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const subnet = require('../src/tools/subnet-analyzer');
const formats = require('../src/formats');
const { SECCION_KINDS: K } = require('../src/core/result');

/** Devuelve la seccion con ese titulo, o falla el test con un mensaje util. */
function seccion(result, titulo) {
  const encontrada = result.sections.find((s) => s.title === titulo);
  assert.ok(encontrada, `no existe la seccion "${titulo}". Hay: ${result.sections.map((s) => s.title).join(', ')}`);
  return encontrada;
}

/** Devuelve el hallazgo cuyo titulo contiene ese texto. */
function hallazgo(result, texto) {
  const encontrado = result.findings.find((f) => f.title.includes(texto));
  assert.ok(encontrado, `no hay ningun hallazgo que hable de "${texto}"`);
  return encontrado;
}

test('las tablas anchas declaran los pesos de sus columnas', () => {
  // El PDF reparte el ancho de la tabla entre las columnas. Si se anade una
  // columna y se olvida el peso, `calcularAnchos` deja de usar los pesos y
  // vuelve a repartir a partes iguales sin avisar, que es justo el defecto que
  // estos pesos arreglan.
  const vlsm = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: 'Ventas:100\nAlmacén:20' });
  const tablaVlsm = seccion(vlsm, 'Reparto VLSM');
  assert.ok(Array.isArray(tablaVlsm.anchoColumnas), 'la tabla de VLSM debe declarar los pesos');
  assert.equal(tablaVlsm.anchoColumnas.length, tablaVlsm.columns.length, 'debe haber un peso por columna');
  assert.ok(tablaVlsm.anchoColumnas.every((w) => w > 0), 'ningun peso puede ser cero');

  const fdm = subnet.ejecutar({ red: '10.0.0.0/24', subredes: 8 });
  const tablaFdm = seccion(fdm, 'Reparto en subredes iguales');
  assert.equal(tablaFdm.anchoColumnas.length, tablaFdm.columns.length, 'tambien la de subredes iguales');
});

test('los pesos de columna no rompen la salida de ningun formato', async () => {
  const r = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: 'Ventas:100\nAlmacén:20', subredes: 8 });
  const json = JSON.parse((await formats.render(r, 'json')).toString('utf8'));
  const seccionJson = json.sections.find((s) => s.title === 'Reparto VLSM');
  assert.equal(seccionJson.columns.length, 8, 'el JSON debe seguir llevando las ocho columnas');
  assert.equal(seccionJson.rows.length, 2, 'y las filas del reparto');
  for (const formato of ['txt', 'md', 'html', 'pdf']) {
    const salida = await formats.render(r, formato);
    assert.ok(salida.length > 0, `${formato} no deberia romperse por los pesos`);
  }
});

test('la herramienta declara los campos que necesita el formulario', () => {
  assert.equal(subnet.id, 'subnet-analyzer');
  const nombres = subnet.campos.map((c) => c.name);
  for (const esperado of ['red', 'subredes', 'vlsm', 'listar', 'limite']) {
    assert.ok(nombres.includes(esperado), `falta el campo ${esperado}`);
  }
});

test('acepta las cuatro formas de escribir una red', () => {
  const entradas = ['192.168.1.0/24', '192.168.1.0/255.255.255.0', '192.168.1.5/24', '192.168.1.0'];
  for (const red of entradas) {
    const r = subnet.ejecutar({ red });
    assert.notEqual(r.status, 'error', `${red} deberia entenderse, no rechazarse`);
    const id = seccion(r, 'Identificación de la red');
    assert.equal(id.items.find(([k]) => k === 'Dirección de red')[1], '192.168.1.0', `${red} debe normalizarse a la direccion de red`);
  }
});

test('avisa cuando la IP escrita tiene bits de host o es un /32', () => {
  // Un /24 con la direccion de red escrita no tiene nada de raro.
  assert.equal(subnet.ejecutar({ red: '192.168.1.0/24' }).status, 'pass');

  // Escribir el host en vez de la red es un error tipico, y merece un aviso.
  const conHost = subnet.ejecutar({ red: '192.168.1.5/24' });
  assert.equal(conHost.status, 'pass', 'se resuelve igual, pero hay que avisar');
  const aviso = hallazgo(conHost, 'no es la de red');
  assert.equal(aviso.severity, 'info');

  // Una IP suelta es un /32: técnicamente válido, inservible como red de
  // usuarios, y por eso baja a aviso en vez de a error.
  const suelta = subnet.ejecutar({ red: '192.168.1.0' });
  assert.equal(suelta.status, 'warn');
  assert.match(hallazgo(suelta, '/32').title, /no sirve como red de usuarios/);
});

test('reconoce y explica cada formato de entrada', () => {
  const casos = [
    ['192.168.1.0/24', 'Notación CIDR'],
    ['192.168.1.0/255.255.255.0', 'Máscara punteada'],
    ['192.168.1.7/24', 'Notación CIDR'],
    ['192.168.1.0', 'se asume /32']
  ];
  for (const [entrada, fragmento] of casos) {
    const r = subnet.ejecutar({ red: entrada });
    const id = seccion(r, 'Identificación de la red');
    const formato = id.items.find(([k]) => k === 'Formato reconocido')[1];
    assert.ok(formato.includes(fragmento), `"${entrada}" deberia reconocerse como "${fragmento}", dijo "${formato}"`);
  }
});

test('devuelve un Result con estado error ante una IP invalida, sin lanzar', () => {
  for (const mala of ['esto-no-es-una-red', '192.168.1.0/33', '999.1.1.1/24', '']) {
    const r = subnet.ejecutar({ red: mala });
    assert.equal(r.status, 'error', `"${mala}" deberia dar error`);
    assert.ok(r.error, `"${mala}" deberia traer un error con codigo`);
    assert.ok(r.error.code, 'el error necesita un codigo estable para la UI');
    assert.ok(r.error.message, 'el error necesita un mensaje legible');
  }
});

test('el error de entrada se puede renderizar como informe', async () => {
  const r = subnet.ejecutar({ red: 'esto-no-es-una-red' });
  for (const formato of ['txt', 'md', 'html', 'json', 'pdf']) {
    const salida = await formats.render(r, formato);
    assert.ok(salida.length > 0, `el formato ${formato} deberia producir salida`);
  }
  const txt = (await formats.render(r, 'txt')).toString('utf8');
  assert.match(txt, /PARAM_INVALIDO/, 'el TXT deberia mostrar el codigo del error');
  assert.match(txt, /ERROR/, 'el TXT deberia marcar el bloque de error');
});

test('rechaza un numero de subredes que no sea un entero mayor que uno', () => {
  for (const malo of ['0', '1', '-4', '2.5', 'muchas', 'NaN']) {
    const r = subnet.ejecutar({ red: '10.0.0.0/24', subredes: malo });
    assert.equal(r.status, 'error', `"${malo}" deberia dar error`);
    assert.equal(r.error.code, 'PARAM_INVALIDO');
    assert.ok(r.error.remediation, 'el error deberia sugerir como corregirlo');
  }
});

test('divide en subredes iguales mostrando el prefijo hijo real', () => {
  const r = subnet.ejecutar({ red: '10.0.0.0/24', subredes: 8 });
  const tabla = seccion(r, 'Reparto en subredes iguales');

  assert.equal(tabla.kind, K.TABLA);
  assert.equal(tabla.rows.length, 8, 'deben salir las ocho subredes');
  assert.deepEqual(
    tabla.rows.map((f) => f[2]),
    Array(8).fill('/27'),
    'un /24 en ocho partes son ocho /27, no un /24 repetido'
  );
  assert.deepEqual(tabla.rows.map((f) => f[1]), [
    '10.0.0.0/27', '10.0.0.32/27', '10.0.0.64/27', '10.0.0.96/27',
    '10.0.0.128/27', '10.0.0.160/27', '10.0.0.192/27', '10.0.0.224/27'
  ]);
  // La primera fila no puede tener hosts: es la direccion de red del tramo.
  assert.equal(tabla.rows[0][5], 30, 'un /27 tiene 30 hosts utilizables');
  assert.equal(tabla.rows[0][6], '10.0.0.31', 'el broadcast del primer /27 es la anterior al siguiente');
});

test('avisa cuando el numero de subredes no es alcanzable', () => {
  const r = subnet.ejecutar({ red: '10.0.0.0/24', subredes: 1024 });
  const hallazgoErr = r.findings.find((f) => f.severity === 'error');
  assert.ok(hallazgoErr, 'debe haber un hallazgo de error');
  assert.match(hallazgoErr.title, /no es posible dividir/i);
});

test('avisa si se piden los dos repartos a la vez', () => {
  const ambos = subnet.ejecutar({ red: '10.0.0.0/24', subredes: 4, vlsm: 'Ventas:20' });
  assert.equal(ambos.status, 'warn', 'deberia quedar en aviso, no en error');

  const soloIguales = subnet.ejecutar({ red: '10.0.0.0/24', subredes: 4 });
  assert.equal(soloIguales.status, 'pass', 'piden subredes, avisar de VLSM seria ruido');

  const soloVlsm = subnet.ejecutar({ red: '10.0.0.0/24', vlsm: 'Ventas:20' });
  assert.equal(soloVlsm.status, 'pass');
});

test('el reparto VLSM ordena por tamaño pero mantiene el orden de entrada', () => {
  const r = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: 'Pequeño:10\nGrande:100\nMediano:20' });
  const tabla = seccion(r, 'Reparto VLSM');

  assert.deepEqual(tabla.rows.map((f) => f[0]), ['Pequeño', 'Grande', 'Mediano'], 'las filas deben seguir el orden en que se escribieron');
  // El grande se lleva el /25, el mediano el /27 y el pequeño el /28, porque se
  // reparte de mayor a menor aunque se muestre al reves.
  assert.deepEqual(tabla.rows.map((f) => f[1].split('/')[1]), ['28', '25', '27']);
});

test('el reparto VLSM da error si un tramo no cabe', () => {
  // Un /26 da 62 utilizables, asi que 50 entra, pero 50 + 30 = 80 ya no.
  const cabe = subnet.ejecutar({ red: '192.168.1.0/26', vlsm: 'Grande:50' });
  assert.equal(cabe.status, 'pass', 'un solo tramo de 50 si cabe en 62');

  const r = subnet.ejecutar({ red: '192.168.1.0/26', vlsm: 'Grande:50\nMediano:30' });
  assert.equal(r.status, 'fail', 'una red que no cubre el pedido no es un acierto');
  const h = hallazgo(r, 'no cubre todos los tramos');
  assert.equal(h.severity, 'error');
  assert.ok(seccion(r, 'Requisitos que no caben'), 'debe explicar que tramo queda fuera');
});

test('avisa del desperdicio cuando los tramos asignan mucho mas de lo pedido', () => {
  // 100 -> /25 (126), 20 -> /27 (30) y 2 -> /31 (2): 158 asignados por 122
  // pedidos, 1,29 veces. Es un reparto razonable y no debe avisar.
  const ajustado = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: 'A:100\nB:20\nC:2' });
  assert.equal(ajustado.status, 'pass', 'un reparto razonable no deberia avisar');

  // 17 y 17 caen cada uno en un /27 (30): 60 asignados por 34 pedidos, 1,76
  // veces, que es justamente por encima del umbral.
  const muyDesperdiciado = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: 'A:17\nB:17' });
  assert.equal(muyDesperdiciado.status, 'warn');
  const h = hallazgo(muyDesperdiciado, 'aprovechan');
  assert.match(h.title, /\d+(\.\d)? %/, 'el titulo deberia llevar la cifra de aprovechamiento del reparto');
  assert.match(h.detail, /34/, 'el detalle debe decir cuantos hosts se pidieron');
  assert.match(h.detail, /60/, 'el detalle debe decir cuantos se asignan');
});

test('el resumen del VLSM cuadra con lo que muestra la tabla', () => {
  const r = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: 'Ventas:100\nAlmacén:20\nImpresión:2' });
  const tabla = seccion(r, 'Reparto VLSM');
  const resumen = seccion(r, 'Resumen del reparto');
  const valor = (clave) => resumen.items.find(([k]) => k === clave)[1];

  const pedidos = tabla.rows.reduce((a, f) => a + f[5], 0);
  const asignados = tabla.rows.reduce((a, f) => a + f[6], 0);
  const desperdicio = tabla.rows.reduce((a, f) => a + f[7], 0);

  assert.equal(valor('Hosts pedidos'), pedidos, 'los hosts pedidos de la tabla deben sumar lo del resumen');
  assert.equal(valor('Hosts asignados'), asignados);
  assert.equal(valor('Desperdicio en los tramos'), desperdicio);
  assert.equal(desperdicio, asignados - pedidos, 'desperdiciar es la diferencia entre lo asignado y lo pedido');
});

test('la ocupacion de la red padre se mide sobre el total de la red, no sobre lo pedido', () => {
  // Es la confusion mas facil de cometer al leer el informe: hay dos
  // porcentajes distintos y ambos se llamaban "aprovechamiento".
  const r = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: 'Ventas:100\nAlmacén:20\nImpresión:2' });
  const resumen = seccion(r, 'Resumen del reparto');
  const valor = (clave) => resumen.items.find(([k]) => k === clave)[1];

  const pedidos = valor('Hosts pedidos');
  const asignados = valor('Hosts asignados');
  const ocupacion = Number(String(valor('Ocupación de la red padre')).replace('%', '').trim());
  const padre = 1022; // direcciones utilizables de un /22

  assert.equal(ocupacion, Math.round((asignados / padre) * 1000) / 10, 'la ocupacion es lo asignado sobre el total de la red padre');
  assert.notEqual(ocupacion, Math.round((pedidos / asignados) * 1000) / 10, 'no debe ser lo pedido sobre lo asignado');
});

test('da un /31 al tramo que pide dos hosts', () => {
  const r = subnet.ejecutar({ red: '192.168.0.0/24', vlsm: 'Enlace:2' });
  const tabla = seccion(r, 'Reparto VLSM');
  assert.equal(tabla.rows[0][1], '192.168.0.0/31', 'un tramo de dos hosts es un enlace punto a punto');
  assert.equal(tabla.rows[0][6], 2, 'un /31 da las dos direcciones utiles sin broadcast');
});

test('lista las direcciones utilizables cuando se pide', () => {
  const r = subnet.ejecutar({ red: '192.168.1.0/29', listar: true });
  const bloque = seccion(r, 'Direcciones utilizables');
  assert.equal(bloque.kind, K.CODIGO);
  const lineas = bloque.value.split('\n');
  assert.equal(lineas.length, 6, 'un /29 tiene seis direcciones utilizables');
  assert.equal(lineas[0], '192.168.1.1');
  assert.equal(lineas[5], '192.168.1.6', 'la .6 es la ultima antes del broadcast .7');
  assert.ok(!lineas.includes('192.168.1.0'), 'la direccion de red no se lista');
  assert.ok(!lineas.includes('192.168.1.7'), 'el broadcast no se lista');
});

test('trunca el listado de una red grande y lo dice', () => {
  const r = subnet.ejecutar({ red: '10.0.0.0/8', listar: true, limite: 10 });
  const bloque = seccion(r, 'Direcciones utilizables');
  assert.equal(bloque.value.split('\n').length, 10, 'debe respetar el limite pedido');
  assert.match(bloque.description, /primeras 10 de/, 'la descripcion debe explicar el truncado');
  const h = hallazgo(r, 'Listado truncado');
  assert.equal(h.severity, 'info', 'un truncado pedido no es un fallo');
});

test('no lista nada si no se pide el listado', () => {
  const r = subnet.ejecutar({ red: '10.0.0.0/8' });
  assert.ok(!r.sections.some((s) => s.title === 'Direcciones utilizables'), 'una red /8 no debe(listarse por sorpresa');
});

test('acepta varias formas de escribir los requisitos de VLSM', () => {
  const entradas = ['Ventas:50', 'Ventas=50', 'Ventas, 50', '50', ' Ventas : 50 '];
  for (const texto of entradas) {
    const r = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: texto });
    assert.notEqual(r.status, 'error', `"${texto}" deberia entenderse`);
    const tabla = seccion(r, 'Reparto VLSM');
    assert.equal(tabla.rows.length, 1, `"${texto}" deberia producir un tramo`);
    assert.equal(tabla.rows[0][5], 50, `"${texto}" deberia pedir 50 hosts`);
  }
});

test('acepta varios requisitos en lineas separadas', () => {
  const r = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: 'Ventas:50\n\nAlmacén:10\n' });
  assert.equal(seccion(r, 'Reparto VLSM').rows.length, 2, 'las lineas vacias se ignoran');
});

test('da error si un requisito no se puede interpretar', () => {
  for (const malo of ['Ventas:muchos', 'Ventas:0', 'Ventas:-3', 'Ventas:abc']) {
    const r = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: malo });
    assert.equal(r.status, 'error', `"${malo}" deberia dar error`);
    assert.equal(r.error.code, 'PARAM_INVALIDO');
  }
});

test('los cinco formatos renderizan un reparto VLSM completo', async () => {
  const r = subnet.ejecutar({ red: '192.168.0.0/22', vlsm: 'Ventas:100\nAlmacén:20\nImpresión:2', subredes: 8 });
  for (const formato of formats.soportados().map((f) => f.nombre)) {
    const salida = await formats.render(r, formato);
    assert.ok(salida.length > 0, `el formato ${formato} produjo una salida vacia`);
  }
});

test('el Result lleva los parametros de entrada y un log de la interpretacion', () => {
  const r = subnet.ejecutar({ red: '192.168.1.5/24', subredes: 4 });
  assert.equal(r.target, '192.168.1.5/24', 'el objetivo es lo que se escribio, no la red normalizada');
  assert.deepEqual(r.params.red, '192.168.1.5/24');
  const entrada = r.logs.find((l) => l.channel === 'entrada');
  assert.ok(entrada, 'debe quedar constancia de como se interpreto la entrada');
  assert.match(entrada.message, /192\.168\.1\.5\/24/, 'el log debe citar lo escrito');
});

test('el log del contexto recibe la traza si se pasa un logger', () => {
  const llamadas = [];
  const log = { info: (m) => llamadas.push(['info', m]), error: (m) => llamadas.push(['error', m]) };
  subnet.ejecutar({ red: '10.0.0.0/24', subredes: 4 }, { log });
  assert.ok(llamadas.length >= 1, 'debe quedar al menos la linea de entrada');
  assert.ok(llamadas.every(([nivel]) => ['info', 'error', 'warn'].includes(nivel)), 'el logger solo admite niveles conocidos');
  assert.match(llamadas[0][1], /10\.0\.0\.0\/24/, 'la primera linea debe ser la entrada interpretada');

  const errores = [];
  subnet.ejecutar({ red: 'malo' }, { log: { info: () => {}, error: (m) => errores.push(m) } });
  assert.equal(errores.length, 1, 'un fallo de entrada debe llegar al logger una sola vez');
});

test('la herramienta funciona aunque no se pase contexto ni logger', () => {
  // La CLI y un futuro script de consola pueden llamar a ejecutar() sin ctx.
  const r = subnet.ejecutar({ red: '10.0.0.0/24', subredes: 4 });
  assert.equal(r.status, 'pass');
  const conError = subnet.ejecutar({ red: 'malo' });
  assert.equal(conError.status, 'error', 'sin logger, el error sigue siendo un Result, no una excepcion');
});
