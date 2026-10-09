'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const herramienta = require('../src/tools/ip-audit');
const formatos = require('../src/formats');
const dnsbl = require('../src/core/net/dnsbl');

// ------------------------------------------------------------------ dobles

/** RDAP de mentira, completo. */
const RDAP_OK = {
  ip: '203.0.113.10',
  disponible: true,
  servidor: 'https://rdap.ejemplo/',
  prefijoRegistro: '203.0.0.0/24',
  tipoObjeto: 'inetnum',
  handle: 'NET-EJEMPLO-1',
  nombre: 'Example Networks',
  tipo: 'ASSIGNED',
  pais: 'US',
  inicio: '203.0.0.0',
  fin: '203.0.255.255',
  prefijoCidr: '203.0.0.0/24',
  titular: 'Example Networks Inc.',
  contactoAbuso: { nombre: 'Ejemplo Abuse', correo: 'abuse@ejemplo.net' },
  registro: '2021-03-04T10:00:00Z',
  ultimoCambio: '2025-01-02T08:30:00Z',
  caducidad: null,
  estado: 'active',
  nota: null,
  enlace: 'https://rdap.ejemplo/ip/203.0.113.10'
};

const PTR_OK = { nombres: ['host.ejemplo.net'], configurado: true, error: null };
const PTR_NULO = { nombres: [], configurado: false, error: null };

/**
 * ASN de mentira, completo.
 *
 * El pais coincide con el de RDAP_OK a proposito: si no, todos los informes de
 * los tests de abajo llevarian un hallazgo extra de "paises no coinciden" que
 * no tiene que ver con lo que estan midiendo.
 */
const ASN_OK = {
  ip: '203.0.113.10',
  estado: require('../src/core/net/asn').ESTADOS.ENCONTRADO,
  asns: ['15169'],
  asn: '15169',
  prefijo: '8.8.8.0/24',
  pais: 'US',
  registro: 'arin',
  asignado: '2023-12-28',
  nombre: 'GOOGLE - Google LLC, US',
  avisos: []
};

/**
 * DNSBL de mentira.
 *
 * NO reimplementa el modulo: llama al de verdad y solo sustituye la capa DNS.
 * Un doble escrito a mano se saltaria justo lo que se quiere comprobar aqui,
 * que es que una IPv6 se marque como no aplicable.
 *
 * El doble representa a un resolvedor que FUNCIONA, asi que contesta
 * correctamente a la comprobacion de acceso de Spamhaus. Sin eso, todas las
 * zonas de Spamhaus saldrian en "sin datos" y los tests de abajo estarian
 * midiendo el fallo de un resolvedor imaginario en vez de lo que quieren medir.
 */
/**
 * Doble de `core/net/dnsbl`.
 *
 * @param {object} [porOperador] Estado por operador ('listada', 'limpia'...).
 * @param {boolean} [spambausSinRegistro=false] Simula la situacion real desde
 *   un servidor: Spamhaus no da datos. El canario tambien falla, que es como se
 *   detecta, y no solo una zona suelta.
 */
function dnsblDoble(porOperador = {}, spambausSinRegistro = false) {
  return {
    consultar: (ip, opciones = {}) =>
      dnsbl.consultar(ip, {
        ...opciones,
        dns: {
          consultarLote: (consultas) =>
            consultas.map((c) => {
              // La entrada de prueba de Spamhaus siempre esta listada, y solo
              // devuelve el codigo de listado a un resolvedor registrado.
              const esCanario = c.nombre === `${dnsbl.CANARIO.ip.split('.').reverse().join('.')}.${dnsbl.CANARIO.zona}`;
              if (esCanario) {
                // Sin registro, el canario contesta con su codigo de
                // diagnostico, que es como el modulo se da cuenta de que sus
                // zonas no valen.
                const valores = spambausSinRegistro ? [SPAMHAUS_SIN_ACCESO] : ['127.0.0.3'];
                return { ok: true, valores, ttl: 60, error: null, codigoDns: 'NOERROR' };
              }

              const lista = dnsbl.LISTAS_CORTA.find((l) => c.nombre.endsWith(l.zona));

              // Sin acceso a Spamhaus, sus zonas devuelven su codigo de
              // diagnostico en vez de un veredicto.
              if (spambausSinRegistro && lista?.proveedor === 'Spamhaus') {
                return { ok: true, valores: ['127.255.255.252'], ttl: 60, error: null, codigoDns: 'NOERROR' };
              }

              const estado = (lista && porOperador[lista.proveedor]) || 'limpia';

              if (c.tipo === 'TXT') {
                return { ok: true, valores: [['Relay abierto']], ttl: 60, error: null, codigoDns: 'NOERROR' };
              }
              return estado === 'listada'
                ? { ok: true, valores: ['127.0.0.2'], ttl: 60, error: null, codigoDns: 'NOERROR' }
                : { ok: true, valores: [], ttl: null, error: null, codigoDns: 'ENOTFOUND' };
            })
        }
      })
  };
}

/**
 * Ejecuta la herramienta con las fuentes sustituidas.
 *
 * `claveSpamhaus` se pasa con una clave de mentira para que ningun test toque el
 * entorno real ni la red. Por defecto es una cadena vacia, que es lo que hace
 * que la casilla de la API se comporte como cuando no hay clave puesta.
 */
function ejecutar(
  params,
  { rdap = RDAP_OK, ptr = PTR_OK, dnsbl: db = dnsblDoble(), asn: as, spamhaus: sh, claveSpamhaus = '' } = {}
) {
  return herramienta.ejecutar(params, {
    rdap: { consultar: async () => rdap },
    ptr: { resolver: async () => ptr },
    dnsbl: db,
    asn: as || { consultar: async () => ASN_OK },
    spamhaus: sh,
    claveSpamhaus
  });
}

/**
 * Codigo con el que Spamhaus responde a un resolvedor que no tiene registrado.
 *
 * No dice "no listada": dice "no te he dado datos". Es el valor que devuelve la
 * entrada de prueba cuando la consulta viene de un servidor corriente.
 */
const SPAMHAUS_SIN_ACCESO = '127.255.255.254';

/** Respuesta de las zonas de pago de Spamhaus, tal como la normaliza `core/net/spamhaus`. */
function dqs(cuerpo) {
  return {
    consultarVarias: async () => ({
      ip: '203.0.113.10',
      resultados: cuerpo,
      errores: [],
      algunoListada: cuerpo.some((x) => x.estado === 'listada'),
      algunoDesconocido: cuerpo.some((x) => x.estado === 'desconocido')
    })
  };
}

const DQS_SBL_LISTADA = {
  ip: '203.0.113.10',
  lista: 'sbl',
  listaNombre: 'SBL',
  queMide: 'Direcciones que Spamhaus considera maliciosas a proposito.',
  estado: 'listada',
  codigo: '127.0.0.2',
  ipRespuesta: '127.0.0.2',
  sublista: 'SBL',
  motivo: 'Direccion en la Spamhaus Blocklist.',
  consultadoEn: '2026-09-28T11:00:00.000Z',
  advertencias: ['Quitar un listado no es automatico: hay que pedirlo y esperar a que lo revisen.']
};

const DQS_NO_LISTADA = {
  ip: '203.0.113.10',
  lista: 'zen',
  listaNombre: 'ZEN',
  queMide: 'Correo no deseado y actividad sospechosa.',
  estado: 'no-listada',
  codigo: null,
  ipRespuesta: null,
  sublista: null,
  motivo: null,
  consultadoEn: '2026-09-28T11:00:00.000Z',
  advertencias: ['Que no este listada no significa que el problema de fondo este resuelto.']
};

// ------------------------------------------------------------------ contrato

test('la herramienta se declara como espera', () => {
  assert.equal(herramienta.id, 'ip-audit');
  assert.equal(herramienta.sinRed, false);
  assert.ok(herramienta.titulo);
  assert.ok(herramienta.descripcion);
});

test('el objetivo lo elige el usuario, y las listas vienen activadas', () => {
  const ip = herramienta.campos.find((c) => c.name === 'ip');
  assert.equal(ip.required, true, 'sin IP no hay nada que auditar');

  // El usuario decidio que la lista corta fuera la de partida.
  const dnsblCampo = herramienta.campos.find((c) => c.name === 'dnsbl');
  assert.equal(dnsblCampo.default, true);

  const listas = herramienta.campos.find((c) => c.name === 'listas');
  assert.equal(listas.default, 'corta');
  assert.ok(listas.options.some((o) => o.value === 'corta'));
  assert.ok(listas.options.some((o) => o.value === 'amplia'));

  // El selector de listas no tiene sentido si las listas estan apagadas.
  assert.equal(listas.shownWhen, 'dnsbl');
  assert.equal(herramienta.campos.find((c) => c.name === 'motivos').shownWhen, 'dnsbl');
});

// ------------------------------------------------------------------ orquestación

test('un informe completo trae las tres secciones y termina bien', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' });

  assert.equal(r.tool, 'ip-audit');
  assert.equal(r.target, '203.0.113.10');
  assert.equal(r.status, 'pass');

  const titulos = r.sections.map((s) => s.title);
  assert.ok(titulos.some((t) => t.includes('Registro')));
  assert.ok(titulos.some((t) => t.includes('PTR')));
  assert.ok(titulos.some((t) => t.includes('Listas negras')));
});

test('el registro se lee con los datos queNormaliza rdap', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' });
  const seccion = r.sections.find((s) => s.title.includes('Registro'));

  const par = (etiqueta) => seccion.items.find(([k]) => k === etiqueta)?.[1];
  assert.equal(par('Titular'), 'Example Networks');
  assert.equal(par('Rango'), '203.0.0.0 - 203.0.255.255');
  assert.equal(par('Contacto de abuse') || par('Contacto de abuso'), 'Ejemplo Abuse — abuse@ejemplo.net');
  assert.equal(par('Registrado'), '2021-03-04');
  assert.equal(par('Caduca'), 'Sin dato', 'una fecha ausente se dice, no se inventa');
});

test('la tarjeta de resumen dice la familia y la IP', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' });
  const tarjeta = (etiqueta) => r.summary.find((s) => s.label === etiqueta)?.value;

  assert.equal(tarjeta('Direccion'), '203.0.113.10');
  assert.equal(tarjeta('Familia'), 'IPv4');
  // El numero sale del conjunto por defecto, no escrito a mano: BCL se anadio y
  // la lista son nueve. Si vuelve a cambiar, avisa este test.
  assert.equal(tarjeta('Listas negras'), `0 de ${dnsbl.LISTAS_CORTA.length}`);
});

test('una IPv6 se reconoce como IPv6 en el resumen', async () => {
  const r = await ejecutar({ ip: '2001:db8::1' });
  assert.equal(r.summary.find((s) => s.label === 'Familia').value, 'IPv6');
});

// ------------------------------------------------------------------ sistema autonomo

test('el sistema autonomo sale en su seccion, con el operador por delante', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' });
  const seccion = r.sections.find((s) => s.title.includes('Sistema autonomo'));

  assert.ok(seccion, 'la consulta siempre se hace: no hay casilla que la apague');
  const par = (etiqueta) => seccion.items.find(([k]) => k === etiqueta)?.[1];
  assert.equal(par('Operador'), 'GOOGLE - Google LLC, US');
  assert.equal(par('Numero'), 'AS15169');
  assert.equal(par('Prefijo anunciado'), '8.8.8.0/24');
  assert.equal(par('Pais'), 'US');
});

test('la tarjeta de resumen lleva el pais y el sistema autonomo', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' });
  const tarjeta = (etiqueta) => r.summary.find((s) => s.label === etiqueta)?.value;

  // El pais del bloque gana al del ASN, y solo se cae al segundo si el registro
  // no trae pais.
  assert.equal(tarjeta('Pais'), 'US');
  assert.equal(tarjeta('Sistema autonomo'), 'AS15169 — GOOGLE - Google LLC, US');
});

test('si el registro no tiene pais, el del ASN cubre la tarjeta', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, { rdap: { ...RDAP_OK, pais: null } });
  assert.equal(r.summary.find((s) => s.label === 'Pais').value, 'US');
});

test('un ASN sin datos avisa, y no se lee como "no anunciada"', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, {
    asn: { consultar: async () => ({ ip: '203.0.113.10', estado: require('../src/core/net/asn').ESTADOS.SIN_DATOS, error: 'ETIMEDOUT' }) }
  });

  const hueco = r.findings.find((f) => f.title.includes('No se pudo averiguar que sistema autonomo'));
  assert.ok(hueco, 'un hueco de verdad se avisa');
  assert.equal(hueco.severity, 'warn');
  assert.equal(r.summary.find((s) => s.label === 'Sistema autonomo').value, 'Sin datos');
  assert.equal(r.summary.find((s) => s.label === 'Sistema autonomo').tone, 'warn');
});

test('si el modulo de ASN lanza, el informe no se cae', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, {
    asn: { consultar: async () => { throw new Error('red caida'); } }
  });

  assert.notEqual(r.status, 'error', 'las fuentes son independientes');
  const seccion = r.sections.find((s) => s.title.includes('Sistema autonomo'));
  assert.ok(seccion);
  assert.match(JSON.stringify(seccion.items), /Sin datos/);
  assert.ok(r.findings.some((f) => f.title.includes('sistema autonomo')));
});

test('una IP no anunciada se muestra como tal, sin hallazgo', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, {
    asn: { consultar: async () => ({ ip: '203.0.113.10', estado: require('../src/core/net/asn').ESTADOS.NO_ANUNCIADA }) }
  });

  // "No anunciada" es la respuesta normal para rangos reservados y de prueba: no
  // huele a fallo y el informe no debe decir que lo sea.
  assert.equal(r.summary.find((s) => s.label === 'Sistema autonomo').value, 'No anunciada');
  assert.ok(!r.findings.some((f) => f.title.includes('sistema autonomo')), 'no hay hallazgo que contar');
});

test('los paises que no coinciden se apuntan, sin inventar un veredicto', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, {
    asn: { consultar: async () => ({ ...ASN_OK, pais: 'ES' }) }
  });

  const aviso = r.findings.find((f) => f.title.includes('no coincide'));
  assert.ok(aviso, 'la diferencia sale, porque se ve');
  assert.equal(aviso.severity, 'info');
  assert.match(aviso.recommendation, /no es necesariamente un problema/i);
});

test('sin nombre de ASN, la seccion lo dice y no tumba el numero', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, {
    asn: { consultar: async () => ({ ...ASN_OK, nombre: null, avisos: ['La zona de registro no contesto.'] }) }
  });

  const seccion = r.sections.find((s) => s.title.includes('Sistema autonomo'));
  const par = (etiqueta) => seccion.items.find(([k]) => k === etiqueta)?.[1];
  assert.equal(par('Numero'), 'AS15169', 'el numero no depende del nombre');
  assert.match(par('Nombre'), /Sin dato/);
  assert.equal(r.summary.find((s) => s.label === 'Sistema autonomo').value, 'AS15169');
});

// ------------------------------------------------------------------ fallos parciales

test('si el registro falla, el resto del informe sigue saliendo', async () => {
  // Las tres fuentes son independientes. Tirar el informe entero porque el
  // registro no respondio perderia justo los datos de correo, que son los que
  // se vinieron a mirar.
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    { rdap: { ip: '203.0.113.10', disponible: false, motivo: 'El registro no responde', error: true } }
  );

  assert.notEqual(r.status, 'error');
  const titulos = r.sections.map((s) => s.title);
  assert.ok(titulos.some((t) => t.includes('Registro')));
  assert.ok(titulos.some((t) => t.includes('Listas negras')), 'las listas se consultan igual');

  const hallazgo = r.findings.find((f) => f.title.includes('quien registro'));
  assert.ok(hallazgo, 'y se avisa de que falta el dato');
  assert.match(hallazgo.detail, /no responde/);
});

test('si fallan las listas, el registro y el PTR siguen a salvo', async () => {
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    { dnsbl: { consultar: async () => { throw new Error('todas las zonas caidas'); } } }
  );

  const titulos = r.sections.map((s) => s.title);
  assert.ok(titulos.some((t) => t.includes('Registro')));
  assert.ok(titulos.some((t) => t.includes('PTR')));
  assert.equal(r.summary.find((s) => s.label === 'Listas negras').value, 'No consultadas');
});

test('si el PTR no resuelve, el informe no lo disfraza de "sin PTR"', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, { ptr: { nombres: [], configurado: false, error: 'SERVFAIL' } });
  const seccion = r.sections.find((s) => s.title.includes('PTR'));

  // Un fallo y un "no existe" son cosas distintas, y `ptr.interpretar` las
  // distingue; lo que no puede pasar es que el fallo se lea como un PTR
  // configurado y limpio.
  assert.notEqual(seccion.items.find(([k]) => k === 'Estado')[1], 'Configurado');
  assert.ok(r.findings.some((f) => f.title.includes('nombre inverso')));
});

test('una IP invalida termina en error, y dice que escribir', async () => {
  for (const ip of ['', 'no es una ip', '999.1.1.1']) {
    const r = await ejecutar({ ip });
    assert.equal(r.status, 'error', `"${ip}" deberia fallar`);
    assert.ok(r.error.remediation, 'y decir que escribir');
  }
});

// ------------------------------------------------------------------ DNSBL en el informe

test('una zona listada en un solo operador es aviso, no error', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, { dnsbl: dnsblDoble({ SpamCop: 'listada' }) });

  const listado = r.findings.find((f) => f.title.includes('una lista negra'));
  assert.ok(listado);
  assert.equal(listado.severity, 'warn');
  assert.match(listado.detail, /bl\.spamcop\.net/);
  assert.match(listado.detail, /Relay abierto/, 'el motivo de la zona se incluye');
});

test('varios operadores distintos suben el hallazgo a error', async () => {
  const r = await ejecutar(
    { ip: '203.0.113.10' },
    { dnsbl: dnsblDoble({ Spamhaus: 'listada', SpamCop: 'listada' }) }
  );

  const grave = r.findings.find((f) => f.title.includes('operadores distintos'));
  assert.ok(grave, 'con dos operadores el titulo lo dice');
  assert.equal(grave.severity, 'error');
});

test('las zonas apagadas no se cuentan como "todo limpio"', async () => {
  const r = await ejecutar({ ip: '203.0.113.10', dnsbl: false });

  // Sin consultar no hay veredicto, y el informe tiene que decirlo en vez de
  // dejar un hueco que se lee como "todo bien".
  assert.ok(!r.sections.some((s) => s.title.includes('Listas negras')));
  const aviso = r.findings.find((f) => f.title.includes('No se consultaron'));
  assert.ok(aviso);
  assert.equal(r.summary.find((s) => s.label === 'Listas negras').value, 'No consultadas');
});

test('si DNSBL esta apagado no se consulta ninguna zona', async () => {
  let consultadas = 0;
  await herramienta.ejecutar({ ip: '203.0.113.10', dnsbl: false }, {
    rdap: { consultar: async () => RDAP_OK },
    ptr: { resolver: async () => PTR_OK },
    dnsbl: { consultar: async () => { consultadas++; return dnsblDoble()(); } }
  });
  assert.equal(consultadas, 0);
});

test('el aviso de Spamhaus llega al informe, con su tono informativo', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' });
  const aviso = r.findings.find((f) => f.title.includes('Spamhaus'));

  assert.ok(aviso, 'sin este aviso, un "no listada" de Spamhaus se lee con demasiada seguridad');
  assert.equal(aviso.severity, 'info');
  assert.equal(aviso.detail, dnsbl.AVISO_SPAMHAUS);
});

test('el estado "sin datos" sale como tal, no como limpio', async () => {
  const db = dnsblDoble({ Spamhaus: 'listada' });
  const original = db.consultar;
  // Los argumentos se reenvian: sin ellos el modulo real recibiria `undefined`
  // y el fallo que llegaria al informe seria otro distinto al que se prueba.
  db.consultar = async (...args) => {
    const r = await original(...args);
    // Una zona que no contesta. Se elige una de un operador que NO es Spamhaus a
    // proposito: si lo que se cae es una zona de Spamhaus, el informe baja el
    // tono a aviso porque el motivo es el registro del resolvedor, y ese caso
    // tiene su propio test mas abajo.
    const caida = r.resultados.find((x) => x.proveedor !== 'Spamhaus');
    caida.estado = 'sin-datos';
    caida.error = 'SERVFAIL';
    caida.codigo = null;
    r.resumen.sinDatos = 1;
    r.resumen.limpias -= 1;
    return r;
  };

  const r = await ejecutar({ ip: '203.0.113.10' }, { dnsbl: db });

  const hueco = r.findings.find((f) => f.title.includes('no respondieron'));
  assert.ok(hueco, 'una zona caida se dice');
  assert.equal(hueco.severity, 'warn');
  assert.match(hueco.recommendation, /no es lo mismo que/i);
});

test('sin listados ni fallos, el veredicto es limpio', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' });

  assert.equal(r.status, 'pass');
  assert.equal(r.summary.find((s) => s.label === 'Listas negras').tone, 'ok');
  assert.ok(!r.findings.some((f) => f.severity === 'error'));
});

test('una IPv6 deja las listas como "no aplican", sin fingir cobertura', async () => {
  const r = await ejecutar({ ip: '2001:db8::1' });

  const aviso = r.findings.find((f) => f.title.includes('no cubren esta familia'));
  assert.ok(aviso, 'no consultar IPv6 no es lo mismo que decir que esta limpia');
  assert.equal(aviso.severity, 'info');

  // "0 de 0" se lee como "se consulto nada y no hay ninguno", que es justo lo
  // contrario de lo que pasa: es que no hay zonas de IPv6.
  const tarjeta = r.summary.find((s) => s.label === 'Listas negras');
  assert.equal(tarjeta.value, 'Sin zonas para IPv6');
  assert.notEqual(tarjeta.tone, 'ok', 'no se presenta como limpio');
});

// ------------------------------------------------------------------ botnet C&C

test('BCL va en su propia seccion, y no mezclada con las de correo', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, { dnsbl: dnsblDoble({ Spamhaus: 'listada' }) });

  const correo = r.sections.find((s) => s.title.includes('Listas negras de correo'));
  const botnet = r.sections.find((s) => s.title.includes('Botnet C&C'));

  assert.ok(correo, 'la tabla de correo sigue existiendo');
  assert.ok(botnet, 'y la de botnet va aparte');

  // La zona de BCL no puede aparecer en la de correo: si aparece, el informe
  // entero se lee como "una IP que manda correo de mas".
  assert.ok(!JSON.stringify(correo.rows).includes('bcl.spamhaus.org'));
  assert.ok(JSON.stringify(botnet.rows).includes('bcl.spamhaus.org'));
});

test('estar en BCL es error, con su propia gravedad y su aviso de retirada', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, { dnsbl: dnsblDoble({ Spamhaus: 'listada' }) });

  const botnet = r.findings.find((f) => f.title.includes('botnet C&C'));
  assert.ok(botnet, 'el hallazgo de botnet va con su propio titulo');
  assert.equal(botnet.severity, 'error');
  assert.match(botnet.title, /bcl\.spamhaus\.org/);

  // Y dice las dos cosas utiles: que hay que parar el proceso, y que quitar el
  // listado no es automatico.
  assert.match(botnet.recommendation, /check\.spamhaus\.org/);
  assert.match(botnet.recommendation, /no es automatica/i);
});

test('el titular del informe pone el botnet por delante de todo lo demas', async () => {
  // Una IP puede estar listada por correo y por botnet a la vez. El titular solo
  // tiene una linea, y lo que hay que leer primero es el botnet.
  const r = await ejecutar({ ip: '203.0.113.10' }, { dnsbl: dnsblDoble({ Spamhaus: 'listada', SpamCop: 'listada' }) });

  assert.ok(r.headline, 'el informe necesita un titular de una linea');
  assert.match(r.headline, /botnet/i);
});

test('sin acceso a Spamhaus, el informe no dice "no listada" en su zona de BCL', async () => {
  // El caso que motivo todo esto: un resolvedor sin registrar en Spamhaus. Sus
  // zonas dan NXDOMAIN, que sin comprobar nada parece una IP limpia.
  const db = dnsblDoble();
  const original = db.consultar;
  db.consultar = async (...args) => {
    const r = await original(...args);
    r.accesoSpamhaus = {
      hayDatos: false,
      consulta: '3.0.0.127.zen.spamhaus.org',
      codigo: '127.255.255.254',
      motivo: 'este resolvedor no esta registrado en Spamhaus, asi que sus zonas no devuelven datos'
    };
    for (const x of r.resultados.filter((y) => y.proveedor === 'Spamhaus')) {
      x.estado = 'sin-datos';
      x.error = 'este resolvedor no esta registrado en Spamhaus, asi que sus zonas no devuelven datos';
    }
    r.resumen.sinDatos = r.resultados.filter((y) => y.proveedor === 'Spamhaus').length;
    r.resumen.limpias -= r.resumen.sinDatos;
    r.avisos = ['Spamhaus no ha dado datos. Sus zonas (ZEN, XBL, SBL, BCL) han quedado en "sin datos": no se ha podido comprobar si la IP aparece en ellas. Esto NO es un "no aparece".'];
    return r;
  };

  const r = await ejecutar({ ip: '203.0.113.10' }, { dnsbl: db });

  const bcl = r.sections
    .find((s) => s.title.includes('Botnet C&C'))
    .rows.find((fila) => fila[0] && String(fila[0].valor ?? fila[0]).includes('BCL'));

  // La fila de BCL tiene que decir que no se ha podido mirar, y en ningun caso
  // "No listada".
  const textoFila = JSON.stringify(bcl);
  assert.match(textoFila, /Sin respuesta/i);
  assert.ok(!/No listada/i.test(textoFila), 'BCL no puede salir como "No listada" sin haber preguntado');

  // Y el titular tiene que decirlo en vez de decir "todo bien".
  assert.match(r.headline, /Sin veredicto posible/);
  assert.ok(r.findings.some((f) => f.title.includes('no ha dado datos')));
});

test('si solo faltan zonas de Spamhaus, el aviso no sube a error', async () => {
  // Falta informacion, pero la que falta es cosa de quien ejecuta la
  // herramienta (el registro del resolvedor), no de la IP auditada. Merece un
  // aviso, no un disgusto.
  const db = dnsblDoble();
  const original = db.consultar;
  db.consultar = async (...args) => {
    const r = await original(...args);
    r.accesoSpamhaus = { hayDatos: false, consulta: 'x', codigo: '127.255.255.254', motivo: 'sin registro' };
    for (const x of r.resultados.filter((y) => y.proveedor === 'Spamhaus')) {
      x.estado = 'sin-datos';
      x.error = 'sin registro en Spamhaus';
    }
    r.resumen.sinDatos = 3;
    r.resumen.limpias -= 3;
    return r;
  };

  const r = await ejecutar({ ip: '203.0.113.10' }, { dnsbl: db });

  const fallos = r.findings.find((f) => f.title.includes('sin datos'));
  assert.ok(fallos, 'se avisa igualmente');
  assert.equal(fallos.severity, 'info', 'pero como aviso, no como error');
});

// ------------------------------------------- zonas de pago (Blocklists via DNS Query)

test('la casilla de las zonas de pago viene apagada, y apagada no se consulta', async () => {
  // Por defecto no se pregunta: sin clave no se puede, y con clave es una
  // consulta extra que solo tiene sentido si se ha pedido.
  const casilla = herramienta.campos.find((c) => c.name === 'spamhaus');
  assert.ok(casilla, 'la casilla tiene que existir');
  assert.equal(casilla.default, false);
  assert.equal(casilla.shownWhen, 'dnsbl');

  let llamadas = 0;
  const r = await ejecutar({ ip: '203.0.113.10' }, {
    claveSpamhaus: 'k',
    spamhaus: { consultarVarias: async () => { llamadas++; return { ip: '203.0.113.10', resultados: [], errores: [], algunoListada: false, algunoDesconocido: false }; } }
  });

  assert.equal(llamadas, 0, 'no se toca nada si nadie lo pide');
  assert.ok(!r.sections.some((s) => s.title.includes('DNS Query de Spamhaus')));
});

test('sin clave, el informe dice que no ha comprobado, en vez de suponer limpia', async () => {
  const r = await ejecutar({ ip: '203.0.113.10', spamhaus: true }, { claveSpamhaus: '' });

  const seccion = r.sections.find((s) => s.title.includes('DNS Query de Spamhaus'));
  assert.ok(seccion, 'la seccion sale igualmente: el hueco se enseña');
  assert.match(JSON.stringify(seccion.items), /Sin comprobacion/);

  // Y el texto tiene que decir que "no comprobado" no es "no listada", que es
  // justo la confusion que hace que alguien cierre un caso sin mirarlo.
  const aviso = r.findings.find((f) => f.title.includes('No se ha verificado'));
  assert.ok(aviso);
  assert.match(aviso.detail, /no es lo mismo que/i);
  // Y el sitio de pedir la clave tiene que ser el bueno, no uno inventado.
  assert.match(aviso.recommendation, /portal\.spamhaus\.com\/auth\/account-setup/);
});

test('con clave, una zona listada sale con su codigo y su sublista', async () => {
  const r = await ejecutar({ ip: '203.0.113.10', spamhaus: true }, { claveSpamhaus: 'k', spamhaus: dqs([DQS_SBL_LISTADA]) });

  const hallazgo = r.findings.find((f) => f.title.includes('confirma que la IP esta en'));
  assert.ok(hallazgo, 'la zona de pago confirma y el informe lo dice');
  assert.equal(hallazgo.severity, 'warn');
  // El codigo dice en que sublista esta: sin eso, "listada" no dice nada util.
  assert.match(hallazgo.detail, /127\.0\.0\.2/);
  assert.match(hallazgo.detail, /SBL/);
  // Y dice que quitarlo no es automatico, que es lo que uno se lleva mal lea solo
  // el titulo.
  assert.match(hallazgo.recommendation, /check\.spamhaus\.org/);
});

test('BCL no se pide, porque no existe en ese servicio', async () => {
  // Pedir BCL por una zona de pago es un error garantizado. Si alguien lo
  // anade, el informe entero pierde el unico dato que importa en un caso de bot.
  let pedidas = null;
  await ejecutar({ ip: '203.0.113.10', spamhaus: true }, {
    claveSpamhaus: 'k',
    spamhaus: {
      consultarVarias: async (ip, opciones) => {
        pedidas = opciones.listas;
        return { ip, resultados: [], errores: [], algunoListada: false, algunoDesconocido: false };
      }
    }
  });

  assert.ok(!pedidas.includes('bcl'), 'BCL no se consulta');
});

test('no listado avisa de que eso no demuestra nada sobre el problema', async () => {
  const r = await ejecutar({ ip: '203.0.113.10', spamhaus: true }, { claveSpamhaus: 'k', spamhaus: dqs([DQS_NO_LISTADA]) });

  const aviso = r.findings.find((f) => f.title.includes('no aparece ahora mismo'));
  assert.ok(aviso, 'se dice explicitamente');
  assert.equal(aviso.severity, 'info');
  // Esta es la parte que evita el cierre prematuro del caso.
  assert.match(aviso.recommendation, /vuelve a entrar|no demuestra/i);
});

test('una zona sin veredicto no se lee como "no listada"', async () => {
  const sinSaber = {
    ...DQS_NO_LISTADA,
    estado: 'desconocido',
    advertencias: ['La zona no ha contestado, asi que no se sabe si la IP esta en ella.']
  };
  const r = await ejecutar({ ip: '203.0.113.10', spamhaus: true }, { claveSpamhaus: 'k', spamhaus: dqs([sinSaber]) });

  assert.ok(r.findings.some((f) => f.title.includes('no ha dado veredicto')), 'una zona sin respuesta se avisa');
  assert.ok(!r.findings.some((f) => f.title.includes('no aparece ahora mismo')), 'y no se traduce a "no listada"');
});

test('si las zonas de pago fallan, el informe no se queda sin el dato de las publicas', async () => {
  const r = await ejecutar({ ip: '203.0.113.10', spamhaus: true }, {
    claveSpamhaus: 'k',
    spamhaus: { consultarVarias: async () => ({ ip: '203.0.113.10', resultados: [], errores: [{ lista: 'zen', mensaje: 'ETIMEDOUT', codigo: null }] }) },
    dnsbl: dnsblDoble({ SpamCop: 'listada' })
  });

  const aviso = r.findings.find((f) => f.title.includes('No se pudo verificar'));
  assert.ok(aviso);
  assert.match(aviso.detail, /ETIMEDOUT/);
  // La consulta por zonas sigue dando su resultado: son fuentes independientes.
  assert.ok(r.findings.some((f) => f.title.includes('una lista negra')));
});

test('BCL sin datos se dice que no se ha podido mirar, no que este limpia', async () => {
  // El caso que motiva todo esto: las zonas de Spamhaus no contestan desde un
  // servidor sin registrar, y BCL con ellas. Si aqui saliera "no listada",
  // alguien cerraria el caso.
  const r = await ejecutar({ ip: '203.0.113.10' }, { dnsbl: dnsblDoble({}, true) });

  const seccion = r.sections.find((s) => s.title.includes('Botnet C&C'));
  assert.ok(seccion, 'la seccion de botnet va aparte');

  const aviso = r.findings.find((f) => f.title.includes('botnet C&C'));
  assert.ok(aviso, 'hay que decirlo en voz alta');
  assert.match(aviso.detail, /no se ha preguntado a nadie/);
  // Y que la clave gratuita no lo arregla: si no se dice, alguien la pedira
  // pensando que si.
  assert.match(aviso.detail, /BCL no forma parte de ese servicio/i);
  assert.match(aviso.recommendation, /no significa que la IP no tenga botnet/i);
  // Y que hay un camino que si funciona, para no quedarse sin hacer nada.
  assert.match(aviso.recommendation, /check\.spamhaus\.org/);
});

// ------------------------------------------------------------------ formatos

test('el informe sale en los cinco formatos, y ninguno sale vacio', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, { dnsbl: dnsblDoble({ SpamCop: 'listada' }) });

  for (const f of ['txt', 'md', 'html', 'json', 'pdf']) {
    const salida = await formatos.render(r, f);
    assert.ok(Buffer.isBuffer(salida), `${f} deberia salir como buffer`);
    assert.ok(salida.length > 200, `${f} sale vacio o demasiado corto (${salida.length} bytes)`);
  }
});

test('el PDF es un PDF de verdad, no texto con extension .pdf', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' });
  const pdf = await formatos.render(r, 'pdf');
  assert.equal(pdf.subarray(0, 5).toString('latin1'), '%PDF-');
});

test('el JSON incluye las tres fuentes y su veredicto', async () => {
  const r = await ejecutar({ ip: '203.0.113.10' }, { dnsbl: dnsblDoble({ SpamCop: 'listada' }) });
  const salida = await formatos.render(r, 'json');
  const datos = JSON.parse(salida.toString('utf8'));

  const texto = JSON.stringify(datos);
  assert.match(texto, /Example Networks/, 'el registro');
  assert.match(texto, /host\.ejemplo\.net/, 'el PTR');
  assert.match(texto, /spamcop/, 'las listas');
});
