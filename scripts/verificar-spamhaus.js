'use strict';

// scripts/verificar-spamhaus.js -- ¿funciona ya la clave de Spamhaus?
//
// Lee la clave del entorno (SPAMHAUS_DQS_KEY) y, si no esta, busca un fichero
//txt que la traiga. Nunca la escribe en ningun sitio: el unico motivo por el que
//se lee de un fichero es que a veces alguien la deja a mano en la carpeta.
//
// POR QUE EXISTE. Un alta gratuita de Blocklists via DNS Query no da la clave
// utilisizable en el momento. El orden que publica Spamhaus es:
//
//   1. Rellenar el formulario.
//   2. Verificar el correo y montar la cuenta.
//   3. Recibir la query key.
//
//   Entre el paso 2 y el 3, y tambien despues si el alta esta a medias, la clave
//   ya existe pero no autoriza nada. Y los dos sintomas son distintos:
//
//     - DNS   -> SERVFAIL en todas las zonas
//     - HTTPS -> 401 Unauthorized
//
//   Un SERVFAIL tambien aparece si el nombre de la zona esta mal montado, asi
//   que un 401 por HTTPS es lo que lo zanja: si la clave vale, la zona existe.
//
// QUE COMPRUEBA, en este orden:
//
//   1. Que la zona exista. `zen.dq.spamhaus.net` tiene que tener SOA. Esto no
//      necesita clave y separa "nombre mal" de "clave sin permisos".
//   2. Que BCL no exista. Independientemente de lo que diga la documentacion:
//      si `bcl.dq.spamhaus.net` da NXDOMAIN, BCL no se puede consultar con una
//      clave, se lea como se lea.
//   3. La IP de prueba que publica la propia documentacion: 127.0.0.2 en ZEN tiene
//      que salir listada. Si esa no sale, la clave no sirve para nada.
//   4. Una IP documentada que no deberia estar listada, para comprobar que
//      "no listada" tambien se distingue bien.
//
// Uso: node scripts/verificar-spamhaus.js [IP...]

const fs = require('fs');
const path = require('path');

const dns = require('../src/core/net/dns');
const spamhaus = require('../src/core/net/spamhaus');

const RAIZ = path.join(__dirname, '..');

/** Busca la clave en el entorno y, si no, en un txt suelto de la carpeta. */
function leerClave() {
  if (process.env.SPAMHAUS_DQS_KEY) {
    return { clave: process.env.SPAMHAUS_DQS_KEY.trim(), de: 'la variable de entorno' };
  }

  if (fs.existsSync(path.join(RAIZ, '.env'))) {
    const linea = fs.readFileSync(path.join(RAIZ, '.env'), 'utf8').match(/^SPAMHAUS_DQS_KEY=(.+)$/m);
    if (linea && linea[1].trim()) {
      return { clave: linea[1].trim(), de: '.env' };
    }
  }

  for (const nombre of fs.readdirSync(RAIZ)) {
    if (!/\.txt$/i.test(nombre)) continue;
    const encontrada = fs.readFileSync(path.join(RAIZ, nombre), 'utf8').match(/Query Key\s*\r?\n\s*([a-z0-9]{26})/i);
    if (encontrada) return { clave: encontrada[1], de: `"${nombre}"` };
  }

  return { clave: null, de: null };
}

/** Consulta cruda, para poder distinguir NXDOMAIN de SERVFAIL sin interpretar. */
async function cruda(nombre, tipo = 'A') {
  const r = await dns.consultar(nombre, tipo);
  return { ok: r.ok, valores: r.valores, codigoDns: r.codigoDns };
}

function linea(etiqueta, valor) {
  console.log(`  ${etiqueta.padEnd(30)} ${valor}`);
}

(async () => {
  const { clave, de } = leerClave();
  const ips = process.argv.slice(2);
  const ipPrincipal = ips[0] || '166.1.88.195';

  console.log(`Clave de ${clave ? de : 'ningun sitio'} (${clave ? `${clave.length} caracteres` : 'NO ENCONTRADA'})\n`);

  // 1. Las zonas existen, con o sin clave.
  console.log('--- 1. Estructura de zonas de DQS (no necesita clave) ---');
  for (const zona of ['zen', 'sbl', 'bcl']) {
    const nombre = `${zona}.dq.spamhaus.net`;
    const r = await cruda(nombre, 'SOA');
    linea(nombre, r.ok ? 'EXISTE' : `no existe (${r.codigoDns})`);
  }
  console.log('');

  // 2. BCL, que es la pregunta que motivo todo esto.
  console.log('--- 2. BCL ---');
  const bcl = await cruda('bcl.dq.spamhaus.net', 'SOA');
  if (!bcl.ok) {
    console.log('  bcl.dq.spamhaus.net NO existe. BCL no se puede consultar con una clave de pago.');
    console.log('  Para el dato de BCL por IP: https://check.spamhaus.org');
  } else {
    console.log('  bcl.dq.spamhaus.net existe. La documentacion se ha quedado corta: avisame.');
  }
  console.log('');

  if (!clave) {
    console.log('Sin clave no hay nada mas que comprobar. Ponla en SPAMHAUS_DQS_KEY o en .env.');
    return;
  }

  // 3. La IP de prueba de la documentacion. Esta es la que decide si vale.
  console.log('--- 3. IP de prueba de Spamhaus (127.0.0.2 en ZEN, debe salir listada) ---');
  const nombrePrueba = spamhaus.nombreConsulta('127.0.0.2', 'zen', clave);
  const crudaPrueba = await cruda(nombrePrueba);
  linea('consulta cruda', crudaPrueba.ok ? JSON.stringify(crudaPrueba.valores) : crudaPrueba.codigoDns);

  const prueba = await spamhaus.consultar('127.0.0.2', { clave, lista: 'zen' });
  linea('interpretado', `${prueba.estado}${prueba.codigo ? ` (${prueba.codigo}, ${prueba.sublista})` : ''}`);

  // El diagnostico, porque es lo que hay que hacer despues.
  if (crudaPrueba.codigoDns === 'ESERVFAIL') {
    console.log('\n  SERVFAIL con una clave que parece buena.');
    console.log('  Spamhaus devuelve un "refused" cuando la clave no tiene ese servicio activo.');
    console.log('  Lo mas probable es que la cuenta no este lista: falta verificar el correo.');
    console.log('  Repite esto en cuanto lo hagas: node scripts/verificar-spamhaus.js');
  }

  // 4. HTTPS, que dice si la clave vale sin depender del nombre de la zona.
  console.log('\n--- 4. La misma clave por HTTPS (403 = clave sin permiso, 401 = clave no valida) ---');
  for (const zona of ['zen', 'sbl']) {
    try {
      const r = await fetch(`https://apibl.spamhaus.net/lookup/v1/${zona}/127.0.0.2`, {
        headers: { accept: 'application/json', authorization: `Bearer ${clave}` }
      });
      linea(`${zona}/127.0.0.2`, `HTTP ${r.status} ${r.statusText}`);
    } catch (error) {
      linea(`${zona}/127.0.0.2`, `error de red: ${error.message}`);
    }
  }

  // 5. Y ya, si la clave sirve, la consulta de verdad.
  console.log(`\n--- 5. Consulta real de ${ipPrincipal} ---`);
  for (const zona of ['zen', 'sbl', 'xbl', 'pbl', 'authbl']) {
    const r = await spamhaus.consultar(ipPrincipal, { clave, lista: zona });
    const detalle = r.codigo ? `${r.codigo}${r.sublista ? ` (${r.sublista})` : ''}` : '';
    linea(`${r.listaNombre}${r.motivo ? `: ${r.motivo}` : ''}`, `${r.estado} ${detalle}`);
  }

  // 6. Y una que no deberia estar en nada, para ver que se distingue.
  console.log('\n--- 6. 203.0.113.10 (documentada, no deberia estar en ninguna) ---');
  const varias = await spamhaus.consultarVarias('203.0.113.10', { clave, listas: ['zen', 'sbl'] });
  for (const r of varias.resultados) {
    linea(r.listaNombre, `${r.estado}${r.codigo ? ` ${r.codigo}` : ''}`);
  }

  console.log(`\n  algunoListada=${varias.algunoListada} algunoDesconocido=${varias.algunoDesconocido}`);
})().catch((error) => {
  console.error(`FALLO: ${error.message}`);
  process.exit(1);
});