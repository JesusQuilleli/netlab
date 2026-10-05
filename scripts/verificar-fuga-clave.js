'use strict';

// Comprobacion de que el informe de ip-audit no filtra la clave de Spamhaus.
//
// La clave va dentro del nombre de la zona, asi que cualquier error de DNS la
// lleva en el texto. Este script es la red de seguridad: si un dia cambia algo
// que vuelve asacarla, esto lo dice.

const fs = require('fs');
const path = require('path');

const clave = fs
  .readFileSync(path.join(__dirname, '..', '.env'), 'utf8')
  .split(/\r?\n/)
  .find((l) => l.startsWith('SPAMHAUS_DQS_KEY='))
  .split('=')[1]
  .trim();

const herramienta = require('../src/tools/ip-audit');

(async () => {
  const r = await herramienta.ejecutar({ ip: '166.1.88.195', dnsbl: true, spamhaus: true, listas: 'corta' });

  const donde = {
    'el informe entero': JSON.stringify(r),
    'los logs': JSON.stringify(r.logs || []),
    'los hallazgos': JSON.stringify(r.findings || []),
    'las secciones': JSON.stringify(r.sections || [])
  };

  let limpio = true;
  for (const [sitio, texto] of Object.entries(donde)) {
    if (texto.includes(clave)) {
      limpio = false;
      console.log(`FUGA: la clave aparece en ${sitio}`);
    }
  }

  // Los ultimos cuatro tampoco, que es lo que haria falta para comprobarla.
  const ultimosCuatro = clave.slice(-4);
  if (JSON.stringify(r).includes(ultimosCuatro)) {
    limpio = false;
    console.log('FUGA: los ultimos cuatro digitos de la clave aparecen en el informe');
  }

  console.log(limpio ? 'Correcto: la clave no sale por ningun lado.' : 'HAY UNA FUGA.');

  console.log('\n--- la seccion de zonas de pago, ya sin la clave ---');
  for (const s of r.sections || []) {
    if (!s.title.includes('Blocklists')) continue;
    for (const f of s.rows || []) {
      console.log(`  ${String(f[0]).padEnd(6)}| ${String(f[2]).padEnd(14)}| ${f[4]}`);
    }
  }
})().catch((error) => {
  console.error(`ERROR: ${error.message}`);
  process.exit(1);
});