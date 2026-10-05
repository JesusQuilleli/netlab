// Genera los cinco formatos de un informe de muestra para revisarlos a ojo.
const path = require('node:path');
const {
  createResult, addSection, addSummary, addFinding, addLog, finalize, SECCION_KINDS: K
} = require('./src/core/result');
const formats = require('./src/formats');

const filas = [];
for (let i = 0; i < 45; i++) {
  filas.push([
    `192.168.${i}.0/26`,
    '26',
    `192.168.${i}.1`,
    62,
    i % 7 === 0 ? 'En uso' : 'Libre'
  ]);
}

const r = createResult({
  tool: 'subnet-analyzer',
  toolTitle: 'Analizador de subredes VLSM',
  target: '192.168.0.0/22',
  params: { prefijo: 22, nombre: 'oficinas' }
});

const nf = new Intl.NumberFormat('es-ES');
addSummary(r, 'Subredes', '16', 'ok');
addSummary(r, 'Direcciones útiles', nf.format(3980), 'ok');
addSummary(r, 'Direcciones de red', '16', 'neutral');
addSummary(r, 'Espacio en uso', '42 %', 'warn');

addSection(r, {
  title: 'Reparto VLSM',
  description: 'Subredes generadas a partir del prefijo de entrada.',
  kind: K.TABLA,
  columns: ['Red', 'Prefijo', 'Puerta de enlace', 'Hosts', 'Estado'],
  rows: filas
});

addSection(r, {
  title: 'Parámetros de entrada',
  kind: K.PARES,
  items: [
    ['Prefijo', '/22'],
    ['Máscara', '255.255.255.192'],
    ['Total de direcciones', nf.format(1024)],
    ['Direcciones reservadas', '16'],
    ['Hosts utilizables', nf.format(1008)]
  ]
});

addSection(r, {
  title: 'Espacio asignado',
  kind: K.BARRA,
  value: 42,
  tone: 'warn'
});

addSection(r, {
  title: 'Telemetría de ejecución',
  kind: K.CODIGO,
  value: Array.from({ length: 20 }, (_, i) => `[12:0${i % 10}:01] ${i % 3 ? 'INFO ' : 'DEBUG'} subnet 192.168.${i}.0/26`).join('\n')
});

addFinding(r, {
  severity: 'warn',
  title: 'Posible conflicto de DHCP en la subred 192.168.7.0/26',
  detail: 'El tramo tiene un host ocupado fuera del rango previsto por la distribución.',
  recommendation: 'Verifica la reserva DHCP antes de dar por buena la distribución.'
});
addFinding(r, {
  severity: 'info',
  title: 'El reparto cubre toda la máscara',
  detail: 'Las 16 subredes suman exactamente 1 024 direcciones, sin desperdicio.'
});
addFinding(r, {
  severity: 'error',
  title: 'Prefijo /31 solicitado para una red grande',
  detail: 'Un /31 solo tiene sentido para enlaces punto a punto.',
  recommendation: 'Usa /24 o mayor para un segmento de usuarios.'
});

addLog(r, { level: 'info', message: 'iniciando análisis VLSM' });
finalize(r);

(async () => {
  for (const f of ['json', 'txt', 'md', 'html', 'pdf']) {
    const g = await formats.guardar(r, f, { pie: 'netlab · informe de prueba' });
    console.log(f.padEnd(5), String(g.bytes).padStart(8), 'B ', g.filename);
  }
  console.log('\nCarpeta:', path.join(process.cwd(), 'data', 'reports'));
})();