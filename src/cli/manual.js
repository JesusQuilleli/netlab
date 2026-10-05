/**
 * manual.js — Genera el manual de netlab en PDF y la revision de produccion.
 *
 * Uso:  npm run manual
 *       npm run manual -- [ruta-de-salida.pdf]
 *
 * Escribe el PDF en `docs/manual-netlab.pdf` por defecto. La revision de
 * preparacion para produccion se imprime en consola: son comprobaciones que hay
 * que resolver antes de exponer el servicio, y el sitio donde se decide eso es
 * la terminal donde se despliega.
 *
 * @module cli/manual
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const manual = require('../docs/manual');

/** Etiqueta y color por estado de la revision. */
const ESTADOS = {
  ok: 'OK      ',
  warn: 'REVISAR ',
  fail: 'FALLA   '
};

/** Imprime la revision de produccion en la consola. */
function imprimirRevision() {
  const registros = manual.revisarProduccion();
  const fallos = registros.filter((r) => r.estado === 'fail').length;
  const avisos = registros.filter((r) => r.estado === 'warn').length;

  console.log('\n  Preparacion para produccion\n');

  const mapa = new Map();
  for (const r of registros) {
    const lista = mapa.get(r.area) || [];
    lista.push(r);
    mapa.set(r.area, lista);
  }

  for (const [area, lista] of mapa) {
    console.log(`  ${area}`);
    for (const r of lista) {
      console.log(`    ${ESTADOS[r.estado]} ${r.comprobacion}`);
      if (r.estado !== 'ok') console.log(`             ${r.detalle}`);
    }
  }

  console.log(
    `\n  ${fallos} bloqueante(s), ${avisos} aviso(s).` +
      (fallos ? '\n  No desplegar hasta resolver los bloqueantes.\n' : '\n  Sin bloqueantes.\n')
  );
}

if (require.main === module) {
  const destino = path.resolve(process.argv[2] || path.join(process.cwd(), 'docs', 'manual-netlab.pdf'));

  manual
    .render()
    .then((buffer) => {
      fs.mkdirSync(path.dirname(destino), { recursive: true });
      fs.writeFileSync(destino, buffer);
      console.log(`\n  Manual escrito en ${destino} (${Math.round(buffer.length / 1024)} KB)\n`);
      imprimirRevision();
    })
    .catch((e) => {
      console.error(`\n  No se pudo generar el manual: ${e.message}\n`);
      process.exit(1);
    });
}

module.exports = { imprimirRevision };