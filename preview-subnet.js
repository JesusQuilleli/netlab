// Prueba manual de subnet-analyzer de extremo a extremo.
// Genera los informes reales para revisarlos a ojo.
const t = require('./src/tools/subnet-analyzer');
const formats = require('./src/formats');

const casos = [
  { nombre: 'vlsm-oficinas', params: { red: '192.168.0.0/22', vlsm: 'Ventas:100\nAlmacén:20\nInvitados:10\nImpresión:2' } },
  { nombre: 'subredes-iguales', params: { red: '10.0.0.0/24', subredes: 8 } },
  { nombre: 'solo-red', params: { red: '192.168.1.10/255.255.255.0' } },
  { nombre: 'vlsm-que-no-cabe', params: { red: '192.168.1.0/26', vlsm: 'Grande:50\nMediano:30' } },
  { nombre: 'entrada-invalida', params: { red: 'esto-no-es-una-red' } }
];

(async () => {
  for (const c of casos) {
    const r = t.ejecutar(c.params);
    console.log(
      c.nombre.padEnd(20),
      ('estado=' + r.status).padEnd(14),
      ('hallazgos=' + r.findings.length).padEnd(15),
      c.params.red
    );
    if (r.error) console.log(' '.repeat(22), 'error:', r.error.code, '-', r.error.message);

    if (c.nombre === 'vlsm-oficinas') {
      for (const f of ['txt', 'md', 'html', 'json', 'pdf']) {
        const g = await formats.guardar(r, f, { pie: 'netlab · subnet-analyzer' });
        console.log(' '.repeat(22), f.padEnd(5), String(g.bytes).padStart(7), 'B');
      }
    }
  }
})();