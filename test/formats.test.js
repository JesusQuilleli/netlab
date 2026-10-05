/**
 * test/formats.test.js — Pruebas de la capa de salida.
 *
 * Comprueba dos cosas:
 *   1. Que los cinco formatos rendericen un Result completo sin romperse.
 *   2. Que el JSON sea canonico (mismo contenido, mismos bytes), que es lo que
 *      hace funcionar la deduplicacion del historial.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const formats = require('../src/formats');
const json = require('../src/formats/json');
const {
  createResult,
  setHeadline,
  addSection,
  addSummary,
  addFinding,
  addLog,
  finalize,
  SECCION_KINDS: K
} = require('../src/core/result');
const { sanear, COLORES, estadoBadge } = require('../src/formats/pdf/theme');

/** Result de ejemplo que ejercita todos los tipos de seccion. */
function ejemplo() {
  const r = createResult({ tool: 'subnet-analyzer', toolTitle: 'Analizador de subred', target: '192.168.1.0/24' });
  addSummary(r, 'Direcciones utiles', '254', 'ok');
  addSummary(r, 'Puertos de red', '1', 'neutral');

  addSection(r, {
    title: 'Subredes VLSM',
    kind: K.TABLA,
    columns: ['Red', 'Prefijo', 'Puertas de enlace', 'Hosts'],
    rows: [
      ['192.168.1.0/26', '26', '192.168.1.1', 62],
      ['192.168.1.64/27', '27', '192.168.1.65', 30]
    ]
  });

  addSection(r, {
    title: 'Direccionamiento',
    kind: K.PARES,
    items: [
      ['Mascara', '255.255.255.0'],
      ['Total de direcciones', 256],
      ['Red', { valor: '192.168.1.0', tone: 'ok' }]
    ]
  });

  addSection(r, {
    title: 'Telemetria',
    kind: K.CODIGO,
    value: '[12:00:01] INFO  analysing 192.168.1.0/24\n[12:00:02] OK    4 subnets'
  });

  addSection(r, { title: 'Notas', kind: K.LISTA, items: ['Subred A', 'Subred B'] });
  addSection(r, { title: 'Espacio en uso', kind: K.BARRA, value: 42, tone: 'warn' });

  addFinding(r, {
    severity: 'warn',
    title: 'La subred B tiene pocos hosts',
    detail: '30 direcciones puede quedarse corto.',
    recommendation: 'Considera /26 para la siguienteAmpliacion.'
  });
  addFinding(r, { severity: 'info', title: 'Todo correcto', detail: 'Sin incidencias graves.' });

  addLog(r, { level: 'info', message: 'analysing 192.168.1.0/24' });
  return finalize(r);
}

test('los cinco formatos renderizan sin error', async () => {
  const r = ejemplo();
  for (const f of ['txt', 'md', 'html', 'json']) {
    const salida = await formats.render(r, f);
    assert.ok(salida.length > 100, `${f} deberia producir contenido`);
    assert.ok(!salida.includes('undefined'), `${f} no debe contener la cadena literal "undefined"`);
    assert.ok(!salida.includes('[object Object]'), `${f} must not stringify objects crudely`);
  }

  const pdfBuf = await formats.render(r, 'pdf');
  assert.ok(pdfBuf.length > 1000, 'the PDF must be a plausible size');
  assert.equal(pdfBuf.subarray(0, 5).toString(), '%PDF-', 'the PDF must start with the PDF magic number');
});

test('el titular aparece en los cuatro formatos de texto y en el PDF', async () => {
  const r = ejemplo();
  setHeadline(r, 'example.com está operativa');

  assert.ok((await formats.render(r, 'txt')).includes('example.com está operativa'));
  assert.ok((await formats.render(r, 'md')).includes('example.com está operativa'));
  assert.ok((await formats.render(r, 'html')).includes('example.com está operativa'));
  assert.equal(JSON.parse(await formats.render(r, 'json')).headline, 'example.com está operativa');

  const pdf = await formats.render(r, 'pdf');
  assert.ok(pdf.length > 1000);
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
});

test('sin titular los formatos siguen poniendo el nombre de la herramienta', async () => {
  const r = ejemplo();
  assert.equal(r.headline, null);

  // El txt y el html lo ponen en mayusculas y el md conserva las suyas, asi
  // que se comparan en minuscula: lo que importa es que el nombre siga
  // apareciendo y no se haya quedado solo el estado.
  const esperado = 'analizador de subred';
  for (const f of ['txt', 'md', 'html']) {
    const salida = String(await formats.render(r, f)).toLowerCase();
    assert.ok(salida.includes(esperado), `${f} debe conservar el titulo de la herramienta`);
  }
});

test('un titular en blanco no se cuela como texto vacio ni como null', () => {
  const r = createResult({ tool: 'x', toolTitle: 'X' });
  setHeadline(r, '   ');
  assert.equal(r.headline, null);
  setHeadline(r, 'hola.');
  assert.equal(r.headline, 'hola', 'el punto final sobra y queda feo en un titular');
});

test('el titular cuenta en la huella: cambiarlo es un resultado distinto', () => {
  const a = ejemplo();
  const b = ejemplo();
  setHeadline(b, 'example.com no responde');
  assert.notEqual(json.huella(a), json.huella(b));
});

test('el formato PDF devuelve un Buffer y el resto texto', async () => {
  const r = ejemplo();
  assert.ok(Buffer.isBuffer(await formats.render(r, 'pdf')));
  assert.ok(Buffer.isBuffer(await formats.render(r, 'txt')));
});

test('un formato desconocido da un error util', async () => {
  await assert.rejects(() => formats.render(ejemplo(), 'docx'), /Formato desconocido/);
});

test('JSON es canonico: mismo contenido produce los mismos bytes', () => {
  const a = { b: 2, a: 1, c: { z: 1, y: 2 } };
  const b = { c: { y: 2, z: 1 }, a: 1, b: 2 };
  assert.equal(json.render(a, { pretty: false }), json.render(b, { pretty: false }));
});

test('JSON elimina undefined en lugar de convertirlo en null', () => {
  assert.equal(json.render({ a: 1, b: undefined }, { pretty: false }), '{"a":1}');
});

test('la huella cambia si cambia un dato del Result', () => {
  const r1 = ejemplo();
  const r2 = ejemplo();
  assert.equal(json.huella(r1), json.huella(r2));
  r2.target = '10.0.0.0/8';
  assert.notEqual(json.huella(r1), json.huella(r2));
});

test('la huella ignora el reloj, porque no es parte del resultado', () => {
  // Sin esto la deduplicacion del historial no funciona nunca: dos
  // comprobaciones identicas del mismo dominio se guardan como distintas por
  // haber empezado en milisegundos diferentes.
  const r1 = ejemplo();
  const r2 = ejemplo();

  r1.startedAt = '2025-01-01T00:00:00.000Z';
  r2.startedAt = '2031-12-31T23:59:59.999Z';
  r1.durationMs = 12;
  r2.durationMs = 98765;

  assert.equal(json.huella(r1), json.huella(r2), 'el reloj no debe entrar en la huella');
});

test('la huella ignora tambien el reloj de los logs', () => {
  // Cada entrada de `result.logs` lleva su propio `ts`. Si ese reloj se queda
  // dentro de la huella, dos comprobaciones identicas solo se parecen si han
  // caido en el mismo milisegundo: casi siempre, pero no siempre. El historial
  // se llenaria de copias identicas que el deduplicador no reconoce.
  //
  // Por eso esta prueba fija los `ts` a mano en vez de dejar que corra el
  // reloj: asi el fallo sale siempre, y no una de cada tantas.
  const r1 = ejemplo();
  const r2 = ejemplo();

  r1.logs.forEach((l, i) => { l.ts = `2025-01-01T00:00:0${i}.000Z`; });
  r2.logs.forEach((l, i) => { l.ts = `2031-06-30T23:59:5${i}.000Z`; });

  assert.equal(json.huella(r1), json.huella(r2), 'el reloj de los logs no debe entrar en la huella');
});

test('pero si cambia el texto de un log, la huella cambia', () => {
  const r1 = ejemplo();
  const r2 = ejemplo();
  r1.logs.forEach((l) => { l.ts = '2025-01-01T00:00:00.000Z'; });
  r2.logs.forEach((l) => { l.ts = '2025-01-01T00:00:00.000Z'; });
  r2.logs[0].message = 'otra cosa distinta';

  assert.notEqual(json.huella(r1), json.huella(r2), 'el contenido del log si es parte del resultado');
});

test('pero el JSON si lleva el reloj, porque el informe lo necesita', () => {
  // La huella lo quita; el informe no. Son dos cosas distintas y conviene que
  // las dos normales esten escritas a mano para que no se confundan.
  const r = ejemplo();
  r.startedAt = '2025-01-01T00:00:00.000Z';
  const salida = JSON.parse(json.render(r));
  assert.equal(salida.startedAt, '2025-01-01T00:00:00.000Z');
});

test('el HTML escapa y no deja HTML inyectado desde los datos', async () => {
  const r = createResult({ tool: 'dns-checker', target: '<img src=x onerror=alert(1)>' });
  addSummary(r, 'Dominio', '<script>alert(1)</script>', 'bad');
  const salida = await formats.render(r, 'html');

  // Lo que importa es que los datos nunca abran una etiqueta nueva. Que el
  // texto "onerror=alert(1)" aparezca es inofensivo si no hay "<img" delante.
  assert.ok(!salida.includes('<img'), 'no debe sobrevivir ninguna etiqueta inyectada desde los datos');
  assert.ok(!salida.includes('<script>alert'), 'el script debe aparecer escapado');
  assert.ok(salida.includes('&lt;script&gt;'), 'el script debe verse escapado');
  assert.ok(salida.includes('&lt;img'), 'la etiqueta img debe verse escapada');

  // Ninguna etiqueta del documento puede haber nacido de los datos.
  const etiquetas = Array.from(salida.toString('utf8').matchAll(/<([a-zA-Z][a-zA-Z0-9]*)/g)).map((m) => m[1].toLowerCase());
  const permitidas = new Set([
    'html', 'head', 'meta', 'title', 'body', 'main', 'style', 'header', 'h1', 'h2', 'h3',
    'p', 'span', 'section', 'div', 'dl', 'dt', 'dd', 'table', 'thead', 'tbody', 'tr', 'th',
    'td', 'pre', 'code', 'ul', 'ol', 'li', 'footer', 'strong', 'br'
  ]);
  const intrusos = etiquetas.filter((t) => !permitidas.has(t));
  assert.deepEqual(intrusos, [], `etiquetas no esperadas en el HTML: ${intrusos.join(', ')}`);
});

test('el HTML redacta secretos presentes en los datos', async () => {
  const r = createResult({ tool: 'smtp-validator', target: 'smtp.example.com' });
  addSection(r, {
    title: 'Credenciales',
    kind: K.PARES,
    items: [['Contraseña', 'AKIAIOSFODNN7EXAMPLE']]
  });
  const salida = await formats.render(r, 'html');
  assert.ok(!salida.includes('AKIAIOSFODNN7EXAMPLE'), 'the API key must not reach the report');
});

test('el PDF sanea los caracteres que Helvetica no puede dibujar', () => {
  assert.equal(sanear('✅ Correcto'), '[OK] Correcto');
  assert.equal(sanear('❌ Fallo'), '[X] Fallo');
  assert.equal(sanear('⚠️ Aviso'), '[!] Aviso');
  assert.equal(sanear('a → b'), 'a -> b');
  assert.ok(!/[^\x00-\xFF]/.test(sanear('emojis 🚀 aquí')), 'no debe quedar ningún carácter fuera de WinAnsi');
});

test('el saneo conserva la ñ, que si existe en WinAnsi', () => {
  assert.ok(sanear('mañana').includes('ñ'));
  assert.ok(sanear('ÑOÑO').includes('Ñ'));
});

test('el saneo es idempotente', () => {
  const una = sanear('✅ ❌ ⚠️ → …');
  assert.equal(sanear(una), una);
});

test('los tonos se traducen a los colores del tema', () => {
  assert.equal(estadoBadge('pass').tone, 'ok');
  assert.equal(estadoBadge('warn').tone, 'warn');
  assert.equal(estadoBadge('fail').tone, 'bad');
  assert.equal(estadoBadge('error').tone, 'bad');
  assert.equal(COLORES.ok.toLowerCase(), '#10b981');
});

test('el TXT mantiene tildes y no las convierte en puntos', async () => {
  const r = createResult({ tool: 'dns-checker', target: 'ejemplo.com' });
  addSection(r, { title: 'Descripción con tilde', kind: K.TEXTO, value: 'Configuración correcta' });
  const salida = (await formats.render(r, 'txt')).toString('utf8');

  assert.ok(salida.includes('Configuración'), 'la tilde debe sobrevivir en el cuerpo');

  // El titulo se imprime en mayusculas, asi que la tilde pasa a mayuscula.
  assert.ok(salida.includes('Ó'), 'la tilde del titulo debe sobrevivir en mayuscula');
  assert.ok(!salida.includes('Descripci.n'), 'la tilde del titulo no debe convertirse en punto');
  assert.ok(!salida.includes('Configuraci.n'), 'la tilde del cuerpo no debe convertirse en punto');
});

test('el TXT ajusta una tabla ancha al ancho del reporte en vez de desbordarla (regresion)', async () => {
  // Una tabla de ocho columnas de un reparto VLSM suma unos 105 caracteres.
  // Antes de arreglarlo, cada columna se recortaba por separado y la linea
  // resultante se iba a 138: ilegible en una terminal.
  const r = createResult({ tool: 'subnet-analyzer', target: '192.168.0.0/22' });
  addSection(r, {
    title: 'Reparto VLSM',
    kind: K.TABLA,
    columns: ['Tramo', 'Red', 'Máscara', 'Rango asignable', 'Puerta de enlace', 'Hosts pedidos', 'Hosts asignados', 'Desperdicio'],
    rows: [
      ['Ventas', '192.168.0.0/25', '255.255.255.128', '192.168.0.1 - 192.168.0.126', '192.168.0.1', 100, 126, 26],
      ['Almacén', '192.168.0.128/27', '255.255.255.224', '192.168.0.129 - 192.168.0.158', '192.168.0.129', 20, 30, 10]
    ]
  });
  const salida = (await formats.render(r, 'txt')).toString('utf8');
  const lineas = salida.split('\n');

  const maxima = Math.max(...lineas.map((l) => l.length));
  assert.ok(maxima <= 100, `la linea mas larga mide ${maxima} y deberia caber en 100`);

  // Todas las filas de la tabla siguen teniendo una celda por columna.
  const filasTabla = lineas.filter((l) => l.startsWith('Tramo') || /^-+\s+-+\s/.test(l) || l.startsWith('Ventas') || l.startsWith('Almac'));
  assert.equal(filasTabla.length, 4, 'deben verse cabecera, regla y las dos filas');
  for (const fila of filasTabla) {
    assert.equal(fila.split(/\s{2,}/).length, 8, 'ninguna columna debe perderse al estrechar');
  }
});

test('el TXT parte los textos largos en vez de dejar lineas desbordadas (regresion)', async () => {
  const r = createResult({ tool: 'subnet-analyzer', target: '192.168.0.0/22' });
  addFinding(r, {
    severity: 'info',
    title: 'Prefijo /22: no cumple la regla 4-2-1',
    detail: 'La forma 11111111.11111111.11111100.00000000 no encaja con un esquema de subredes de tamaño potencia de dos.',
    recommendation: 'Es perfectamente válido para enrutar; solo ten en cuenta que al dividir en subredes de tamaño potencia de dos aparecería un /24.'
  });
  addSection(r, {
    title: 'Direccionamiento',
    kind: K.PARES,
    items: [['Bits de red', '11111111.11111111.11111111.00000000.00000000.00000000.00000000.00000000.00000000.00000000']]
  });
  const salida = (await formats.render(r, 'txt')).toString('utf8');
  const lineas = salida.split('\n');

  assert.ok(Math.max(...lineas.map((l) => l.length)) <= 100, 'ninguna linea debe pasar de 100');

  // El texto debe seguir integro: partir por palabras, no por caracteres.
  const reensamblado = lineas.join(' ').replace(/\s+/g, ' ');
  assert.ok(reensamblado.includes('no encaja con un esquema de subredes de tamaño potencia de dos.'));
});

test('el TXT conserva la columna de valores en las fichas largas', async () => {
  const r = createResult({ tool: 'subnet-analyzer', target: '10.0.0.0/8' });
  addSection(r, {
    title: 'Direccionamiento',
    kind: K.PARES,
    items: [
      ['Máscara punteada', '255.0.0.0'],
      ['Bits de red', '11111111.00000000.00000000.00000000.00000000.00000000.00000000.00000000.00000000.00000000.00000000.00000000.00000000']
    ]
  });
  const lineas = ((await formats.render(r, 'txt')).toString('utf8')).split('\n');
  const mascara = lineas.find((l) => l.startsWith('Máscara punteada:'));
  const iBits = lineas.findIndex((l) => l.startsWith('Bits de red:'));

  assert.ok(mascara, 'debe existir la ficha de la mascara');
  assert.ok(iBits >= 0, 'debe existir la ficha de los bits');

  // Las dos fichas comparten la columna del valor, y el desborde del valor
  // largo vuelve bajo la columna, no al margen izquierdo.
  const columna = mascara.indexOf('255.0.0.0');
  assert.equal(lineas[iBits].indexOf('11111111'), columna, 'la primera linea empieza el valor en la columna comun');

  // El token binario no tiene espacios, asi que solo se puede cortar a la
  // fuerza: se reconstituye quitando la sangria de cada fragmento.
  const original = '11111111.00000000.00000000.00000000.00000000.00000000.00000000.00000000.00000000.00000000.00000000.00000000.00000000';
  const fragmentos = [lineas[iBits].slice(columna)];
  let j = iBits + 1;
  // Las lineas de continuacion son las siguientes que empiezan a esa misma
  // columna, es decir, con al menos `columna` espacios delante. El ancho se
  // saca de la ficha corta, que no parte, en vez de fijarlo a mano: el
  // renderizador lo calcula sobre la clave mas larga del bloque.
  while (j < lineas.length && new RegExp(`^\\s{${columna},}\\S`).test(lineas[j])) {
    fragmentos.push(lineas[j].slice(columna));
    j++;
  }
  assert.ok(fragmentos.length > 1, 'un token sin espacios debe partirse en varias lineas');
  assert.equal(fragmentos.join(''), original, 'los fragmentos deben reconstituir el valor original');
  assert.equal(lineas[j].trim(), '', 'despues de la continuacion no debe quedar texto pegado');
});

test('el TXT deja al menos un espacio entre la clave y el valor', async () => {
  // La columna de claves se mide sobre la clave mas larga del bloque. Con un
  // relleno calculado sin margen, "Direcciones libres al final:" llegaba justa
  // al ancho y el valor se quedaba pegado a los dos puntos.
  const r = createResult({ tool: 'subnet-analyzer', target: '192.168.0.0/22' });
  addSection(r, {
    title: 'Resumen del reparto',
    kind: K.PARES,
    items: [
      ['Red de origen', '192.168.0.0/22'],
      ['Direcciones libres al final', 862],
      ['Ocupación de la red padre', '16.8 %']
    ]
  });
  const lineas = ((await formats.render(r, 'txt')).toString('utf8')).split('\n');
  const valorDe = (clave) => lineas.find((l) => l.startsWith(`${clave}:`));

  assert.equal(valorDe('Red de origen').match(/:\s+(\S+)/)[1], '192.168.0.0/22');
  assert.equal(valorDe('Direcciones libres al final').match(/:\s+(\S+)/)[1], '862', 'la clave mas larga del bloque tambien debe dejar hueco');
  assert.equal(valorDe('Ocupación de la red padre').match(/:\s+(\S+)/)[1], '16.8');

  // Y todas las claves del bloque comparten columna de valor.
  const columnas = ['Red de origen', 'Direcciones libres al final', 'Ocupación de la red padre']
    .map((k) => valorDe(k).search(/\S(?=\s*\S+$)/) === 0 ? -1 : valorDe(k).indexOf(valorDe(k).match(/:\s+(\S+)/)[1]));
  assert.equal(new Set(columnas).size, 1, 'las tres fichas deben alinear el valor en la misma columna');
});

test('el PDF reparte el ancho de la tabla segun los pesos de columna declarados', async () => {
  // Una tabla de ocho columnas de un reparto VLSM queda ilegible si el PDF
  // reparte el ancho a partes iguales: la celda del rango asignable acaba
  // partida en tres lineas de diez caracteres. Los pesos declarados en la
  // seccion evitan eso, y esta prueba comprueba que de verdad se aplican.
  //
  // El truco para poder observarlo desde fuera es una celda enorme: al
  // estrechar su columna, el alto de la fila crece y la tabla salta de pagina.
  const largo = 'X'.repeat(400);
  const tabla = (conPesos) => {
    const r = createResult({ tool: 'prueba', target: 'x' });
    addSection(r, {
      title: 'Tabla de dos columnas',
      kind: K.TABLA,
      columns: ['Estrecha', 'Ancha'],
      ...(conPesos ? { anchoColumnas: [8, 92] } : {}),
      rows: Array.from({ length: 10 }, () => [largo, largo])
    });
    return r;
  };

  const paginas = (b) => (b.toString('latin1').match(/\/Type\s*\/Page[^s]/g) || []).length;
  const sinPesos = paginas(await formats.render(tabla(false), 'pdf'));
  const conPesos = paginas(await formats.render(tabla(true), 'pdf'));

  assert.ok(conPesos > sinPesos, `estrechar la columna deberia alargar las filas: ${sinPesos} paginas sin pesos y ${conPesos} con ellos`);
});

test('cada formato anuncia su tipo MIME', () => {
  assert.match(formats.mime('pdf'), /^application\/pdf/);
  assert.match(formats.mime('json'), /^application\/json/);
  assert.match(formats.mime('html'), /^text\/html/);
  assert.equal(formats.mime('desconocido'), 'application/octet-stream');
});

test('la lista de formatos soportados incluye los cinco', () => {
  const nombres = formats.soportados().map((s) => s.nombre);
  for (const esperado of ['txt', 'md', 'html', 'json', 'pdf']) {
    assert.ok(nombres.includes(esperado), `falta el formato ${esperado}`);
  }
});

test('el PDF no crea paginas en blanco al final (regresion)', async () => {
  // Regresion: el limite inferior del modulo de PDF era mas alto que el margen
  // real del documento, asi que el motor de texto de pdfkit saltaba de pagina
  // por su cuenta. Ademas filaKV reutilizaba la coordenada anterior, encadenando
  // una pagina vacia por fila. Con 200 filas se llegaban a 11 paginas de las
  // cuales 5 estaban en blanco. Ahora deben caber en 6 y ninguna en blanco.
  const PDFDocument = require('pdfkit');
  const original = PDFDocument.prototype.addPage;
  let addPage = 0;
  PDFDocument.prototype.addPage = function (...args) {
    addPage++;
    return original.apply(this, args);
  };

  try {
    const filas = Array.from({ length: 200 }, (_, i) => [
      `192.168.${i}.0/26`, '26', `192.168.${i}.1`, 62, 'Libre'
    ]);
    const r = createResult({ tool: 'diag', toolTitle: 'Prueba de paginacion', target: '10.0.0.0/16' });
    addSummary(r, 'Filas', 200, 'neutral');
    addSection(r, { title: 'Tabla', kind: K.TABLA, columns: ['Red', 'Prefijo', 'Puerta de enlace', 'Hosts', 'Estado'], rows: filas });
    finalize(r);

    await formats.render(r, 'pdf');
    assert.ok(addPage <= 6, `200 filas no deberian pasar de 6 paginas, hicieron ${addPage}`);
  } finally {
    PDFDocument.prototype.addPage = original;
  }
});

test('el PDF escala de forma monotona con el numero de filas', async () => {
  // Si el numero de paginas no crece de forma regular, hay saltos espurios.
  const PDFDocument = require('pdfkit');
  const original = PDFDocument.prototype.addPage;
  let paginas = 0;
  PDFDocument.prototype.addPage = function (...args) {
    paginas++;
    return original.apply(this, args);
  };

  try {
    const esperadas = new Map([[5, 1], [50, 2], [100, 3], [200, 6]]);
    for (const [n, maximo] of esperadas) {
      paginas = 0;
      const filas = Array.from({ length: n }, (_, i) => [`10.0.${i}.0/24`, '24', `10.0.${i}.1`, 254, 'Libre']);
      const r = createResult({ tool: 'diag', toolTitle: 'Paginacion', target: '10.0.0.0/8' });
      addSection(r, { title: 'Tabla', kind: K.TABLA, columns: ['Red', 'Prefijo', 'Puerta de enlace', 'Hosts', 'Estado'], rows: filas });
      finalize(r);
      await formats.render(r, 'pdf');
      assert.ok(paginas <= maximo, `${n} filas deberian caber en ${maximo} pagina(s), hicieron ${paginas}`);
    }
  } finally {
    PDFDocument.prototype.addPage = original;
  }
});