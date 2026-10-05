'use strict';

// Sonda: reproduce respuestas de AbuseIPDB con campos ausentes o raros y mira
// que dice la herramienta. No juzga, solo imprime, para ver el fallo antes de
// escribir las pruebas que lo fijan.

const abuseipdb = require('../src/core/net/abuseipdb');
const ipAbuse = require('../src/tools/ip-abuse');

/** Respuesta falsa de la API, con los campos que se le pida quitar. */
function respuesta(cuerpo) {
  return async () => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    text: async () => JSON.stringify(cuerpo)
  });
}

/** Cuerpo completo y luego le quita los campos indicados. */
function cuerpo(sin = []) {
  const d = {
    ipAddress: '203.0.113.10',
    isPublic: true,
    isWhitelisted: false,
    isMobile: false,
    usageType: 'Data Center',
    isp: 'Ejemplo Hosting',
    countryCode: 'US',
    countryName: 'United States',
    abuseConfidenceScore: 100,
    totalReports: 12,
    numDistinctUsers: 9,
    lastReportedAt: '2025-03-04T15:07:00+00:00',
    reports: []
  };
  for (const campo of sin) delete d[campo];
  return { data: d };
}

const CASOS = [
  ['control: respuesta completa', []],
  ['sin totalReports (la API cambio de nombre)', ['totalReports']],
  ['sin numDistinctUsers', ['numDistinctUsers']],
  ['sin abuseConfidenceScore', ['abuseConfidenceScore']],
  ['sin ninguno de los tres', ['totalReports', 'numDistinctUsers', 'abuseConfidenceScore']],
  ['numeros como texto', []],
  ['la API responde de otra IP', ['__otraIp__']]
];

(async () => {
  for (const [nombre, campos] of CASOS) {
    const c = cuerpo(campos);
    if (campos.includes('__otraIp__')) c.data.ipAddress = '198.51.100.99';
    if (nombre === 'numeros como texto') {
      c.data.totalReports = '12';
      c.data.numDistinctUsers = '9';
      c.data.abuseConfidenceScore = '100';
    }

    const d = await abuseipdb.consultar('203.0.113.10', { clave: 'k', fetchImpl: respuesta(c) });

    const r = await ipAbuse.ejecutar(
      { ip: '203.0.113.10' },
      { clave: 'k', abuse: async () => d }
    );

    console.log(`\n### ${nombre}`);
    console.log(
      `   normalizado -> totalReportes=${JSON.stringify(d.totalReportes)}` +
        ` autoresDistintos=${JSON.stringify(d.autoresDistintos)}` +
        ` puntuacionConfianza=${JSON.stringify(d.puntuacionConfianza)}` +
        ` ip=${d.ip}`
    );
    const graves = r.findings.filter((f) => f.severity === 'error');
    console.log(`   veredicto -> ERROR: ${graves.length}`);
    for (const f of r.findings) console.log(`     [${f.severity}] ${f.title}`);
    if (!r.findings.length) console.log('     (sin hallazgos: la herramienta no dice nada)');
  }

  // Y el caso de las IPs descartadas en silencio.
  console.log('\n### lista con dos ips mal escritas');
  const r2 = await ipAbuse.ejecutar(
    { ip: '203.0.113.10, 203.0.113.11, no-es-una-ip, 203.0.113.0.300' },
    { clave: 'k', abuse: async (ip) => ({ ip, esPublica: true, esWhitelisted: false, esMovil: false, tipoUso: null, tipoUsoEs: null, isp: null, dominio: null, codigoPais: null, nombrePais: null, puntuacionConfianza: 0, totalReportes: 0, autoresDistintos: 0, ultimoReporte: null, ultimoReporteTexto: 'Sin datos', ventanaDias: 30, totalEnVentana: 0, reportes: [], resumenCategorias: [] }) }
  );
  console.log(`   consultadas: ${ipAbuse.parseIps('203.0.113.10, 203.0.113.11, no-es-una-ip, 203.0.113.0.300').length} de 4`);
  console.log(`   dice algo de las 2 descartadas: ${JSON.stringify(r2.findings.map((f) => f.title))}`);
})().catch((e) => {
  console.error('ERROR:', e.message);
  process.exit(1);
});