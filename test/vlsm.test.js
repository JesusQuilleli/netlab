/**
 * test/vlsm.test.js — Pruebas del planificador VLSM y del parser de entrada.
 *
 * Estas dos funciones son las que hacen util la herramienta subnet-analyzer.
 * Ninguna existia en legacy/, asi que aqui no hay un defecto que corregir sino
 * que fijar el comportamiento correcto desde el principio.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { planificarVLSM, parseEntrada, analizarRed, ipToInt } = require('../src/core/net/cidr');

// --- parseEntrada: las tres formas que la gente teclea de verdad

test('parseEntrada acepta notacion CIDR con prefijo', () => {
  const p = parseEntrada('192.168.1.0/24');
  assert.strictEqual(p.ip, '192.168.1.0');
  assert.strictEqual(p.mask, '24');
  assert.strictEqual(p.forma, 'cidr-prefijo');
});

test('parseEntrada acepta IP y mascara separadas por espacio', () => {
  const p = parseEntrada('192.168.1.0 255.255.255.0');
  assert.strictEqual(p.ip, '192.168.1.0');
  assert.strictEqual(p.mask, '255.255.255.0');
  assert.strictEqual(p.forma, 'ip-mascara');
});

test('parseEntrada acepta una IP de host con mascara (lo que da un ipconfig)', () => {
  const p = parseEntrada('192.168.1.10/255.255.255.0');
  assert.strictEqual(p.ip, '192.168.1.10');
  assert.strictEqual(p.mask, '255.255.255.0');
  assert.strictEqual(p.forma, 'cidr-mascara');
});

test('parseEntrada asume /32 cuando solo le pasan una IP', () => {
  const p = parseEntrada('10.0.0.1');
  assert.strictEqual(p.mask, '32');
  assert.strictEqual(p.forma, 'host');
});

test('parseEntry ignora espacios sobrantes', () => {
  const p = parseEntrada('  172.16.5.0/24  ');
  assert.strictEqual(p.ip, '172.16.5.0');
  assert.strictEqual(p.mask, '24');
});

test('parseEntrada avisa si falta la mascara tras la barra', () => {
  assert.throws(() => parseEntrada('192.168.1.0/'), /Falta la m/);
});

test('parseEntrada avisa si la entrada esta vacia', () => {
  assert.throws(() => parseEntrada('   '), /No se indic/);
});

// --- planificarVLSM: el reparto que si sirve

test('VLSM asigna a cada tramo el bloque minimo que lo contiene', () => {
  const p = planificarVLSM('192.168.0.0', '22', [
    { nombre: 'Ventas', hosts: 100 },
    { nombre: 'Almacen', hosts: 20 },
    { nombre: 'Invitados', hosts: 10 }
  ]);

  assert.strictEqual(p.viable, true);
  const porNombre = Object.fromEntries(p.asignaciones.map((a) => [a.nombre, a]));

  // 100 hosts necesitan 102 direcciones: /25 (128 direcciones, 126 usables).
  assert.strictEqual(porNombre.Ventas.cidr, '192.168.0.0/25');
  assert.strictEqual(porNombre.Ventas.hostsAsignados, 126);
  // 20 necesitan 22: /27 (32 direcciones, 30 usables).
  assert.strictEqual(porNombre.Almacen.cidr, '192.168.0.128/27');
  assert.strictEqual(porNombre.Almacen.hostsAsignados, 30);
  // 10 necesitan 12: /28 (16 direcciones, 14 usables).
  assert.strictEqual(porNombre.Invitados.cidr, '192.168.0.160/28');
  assert.strictEqual(porNombre.Invitados.hostsAsignados, 14);
});

test('VLSM reparte de mayor a menor aunque se pida en otro orden', () => {
  const p = planificarVLSM('192.168.0.0', '22', [
    { nombre: 'Invitados', hosts: 10 },
    { nombre: 'Ventas', hosts: 100 }
  ]);
  const porNombre = Object.fromEntries(p.asignaciones.map((a) => [a.nombre, a]));
  // El grande se lleva el primer bloque, aunque se pidiera el segundo.
  assert.strictEqual(porNombre.Ventas.cidr, '192.168.0.0/25');
  assert.strictEqual(porNombre.Invitados.cidr, '192.168.0.128/28');
});

test('VLSM devuelve las asignaciones en el orden en que se pidieron', () => {
  const p = planificarVLSM('192.168.0.0', '22', [
    { nombre: 'Invitados', hosts: 10 },
    { nombre: 'Ventas', hosts: 100 }
  ]);
  assert.deepStrictEqual(p.asignaciones.map((a) => a.nombre), ['Invitados', 'Ventas']);
});

test('VLSM usa /31 para un enlace de exactamente 2 hosts', () => {
  // RFC 3021: en punto a punto no hay red ni broadcast, asi que /31 da 2 utiles.
  const p = planificarVLSM('192.168.0.0', '24', [{ nombre: 'Enlace', hosts: 2 }]);
  assert.strictEqual(p.asignaciones[0].cidr, '192.168.0.0/31');
  assert.strictEqual(p.asignaciones[0].hostsAsignados, 2);
});

test('VLSM no solapa bloques (ordenados por direccion)', () => {
  const p = planificarVLSM('10.0.0.0', '16', [
    { nombre: 'A', hosts: 200 },
    { nombre: 'B', hosts: 50 },
    { nombre: 'C', hosts: 300 },
    { nombre: 'D', hosts: 20 }
  ]);
  assert.strictEqual(p.viable, true);

  // OJO: las asignaciones se devuelven en el orden en que se pidieron, que no
  // es el orden de direccion. Para comprobar que no se solapan hay que ordenar.
  const porDireccion = [...p.asignaciones].sort((a, b) => ipToInt(a.direccionRed) - ipToInt(b.direccionRed));

  for (let i = 1; i < porDireccion.length; i++) {
    const previa = porDireccion[i - 1];
    const actual = porDireccion[i];
    assert.ok(
      ipToInt(actual.direccionRed) > ipToInt(previa.broadcast),
      `${actual.nombre} (${ipToInt(actual.direccionRed)}) deberia empezar despues del broadcast de ${previa.nombre} (${ipToInt(previa.broadcast)})`
    );
  }
});

test('VLSM cubre el reparto voraz de mayor a menor aunque la salida no lo parezca', () => {
  const p = planificarVLSM('10.0.0.0', '16', [
    { nombre: 'A', hosts: 200 },
    { nombre: 'C', hosts: 300 }
  ]);
  // C necesita mas sitio, asi que es el primero en reservarlo aunque se haya
  // pedido el segundo.
  const c = p.asignaciones.find((a) => a.nombre === 'C');
  assert.strictEqual(c.cidr, '10.0.0.0/23');
  assert.ok(ipToInt(c.broadcast) < ipToInt(p.asignaciones.find((a) => a.nombre === 'A').direccionRed));
});

test('VLSM alinea el siguiente bloque para no dejar huecos', () => {
  // Un /25 ocupa 128 direcciones. El siguiente bloque debe empezar en el
  // multiplo de 32 mas cercano, no justo despues.
  const p = planificarVLSM('192.168.0.0', '24', [
    { nombre: 'Grande', hosts: 100 },
    { nombre: 'Pequena', hosts: 5 }
  ]);
  const grande = p.asignaciones.find((a) => a.nombre === 'Grande');
  const pequena = p.asignaciones.find((a) => a.nombre === 'Pequena');
  assert.strictEqual(ipToInt(pequena.direccionRed) % 32, 0, 'un /29 debe empezar en un multiplo de 32');
  assert.ok(ipToInt(pequena.direccionRed) > ipToInt(grande.broadcast));
});

test('VLSM avisa de los requisitos que no caben sin romper el resto', () => {
  // A pide 50: necesita 52 direcciones, o sea un /26, que se come la red
  // entera. B pide 30: cabria por separado, pero ya no queda sitio.
  const p = planificarVLSM('192.168.1.0', '26', [
    { nombre: 'Cabe', hosts: 50 },
    { nombre: 'NoCabe', hosts: 30 }
  ]);

  assert.strictEqual(p.viable, false);
  assert.strictEqual(p.asignaciones.length, 1);
  assert.strictEqual(p.asignaciones[0].nombre, 'Cabe');
  assert.strictEqual(p.sinAsignar.length, 1);
  assert.strictEqual(p.sinAsignar[0].nombre, 'NoCabe');
  assert.match(p.sinAsignar[0].motivo, /No queda espacio/);
  assert.match(p.nota, /no caben/);
});

test('VLSM rechaza un requisito que no cabe ni en una red mayor de la actual', () => {
  // Aqui si es un error de entrada, no un reparto imposible: da igual la red
  // que se elija, 5000 hosts no entran en un /26. Se lanza excepcion para que
  // la persona lo vea claro en lugar de recibir un plan vacio.
  assert.throws(
    () => planificarVLSM('192.168.1.0', '26', [{ nombre: 'Imposible', hosts: 5000 }]),
    /solo tiene 62 utilizables/
  );
});

test('VLSM rechaza hosts no enteros o no positivos', () => {
  assert.throws(() => planificarVLSM('10.0.0.0', '24', [{ nombre: 'X', hosts: 0 }]), /mayor que 0/);
  assert.throws(() => planificarVLSM('10.0.0.0', '24', [{ nombre: 'X', hosts: 2.5 }]), /entero/);
  assert.throws(() => planificarVLSM('10.0.0.0', '24', []), /al menos un requisito/);
});

test('VLSM es reproducible: mismos datos, mismo plan byte a byte', () => {
  const requisitos = [
    { nombre: 'A', hosts: 77 },
    { nombre: 'B', hosts: 33 },
    { nombre: 'C', hosts: 5 },
    { nombre: 'D', hosts: 130 }
  ];
  const uno = planificarVLSM('172.20.0.0', '20', requisitos);
  const otro = planificarVLSM('172.20.0.0', '20', requisitos);
  assert.deepStrictEqual(uno, otro);
});

test('VLSM respeta la RFC 3021 al calcular el total de un /31 padre', () => {
  // Un /31 padre tiene 2 utilizables. Pedir 2 debe funcionar.
  const p = planificarVLSM('10.0.0.0', '31', [{ nombre: 'Enlace', hosts: 2 }]);
  assert.strictEqual(p.viable, true);
  assert.strictEqual(p.asignaciones[0].cidr, '10.0.0.0/31');
});

test('el resumen del VLSM cuadra con las asignaciones', () => {
  const p = planificarVLSM('192.168.0.0', '22', [
    { nombre: 'A', hosts: 100 },
    { nombre: 'B', hosts: 20 }
  ]);
  const suma = p.asignaciones.reduce((acc, a) => acc + a.hostsAsignados, 0);
  assert.strictEqual(p.resumen.hostsAsignados, suma);
  assert.strictEqual(p.resumen.hostsPedidos, 120);
  assert.strictEqual(p.resumen.desperdicio, suma - 120);
  // Todo lo asignado cae dentro de la red padre.
  const padre = analizarRed('192.168.0.0', '22');
  for (const a of p.asignaciones) {
    assert.ok(ipToInt(a.direccionRed) >= ipToInt(padre.direccionRed));
    assert.ok(ipToInt(a.broadcast) <= ipToInt(padre.direccionBroadcast));
  }
});
