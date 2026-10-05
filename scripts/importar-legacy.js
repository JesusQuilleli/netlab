'use strict';

/**
 * scripts/importar-legacy.js — Vuelca las credenciales de `legacy/` a `.env`.
 *
 * Los proyectos antiguos tienen las claves escritas dentro del código. Este
 * script las saca de ahí y las lleva a un `.env` local, único fichero que está
 * en el `.gitignore`.
 *
 * Reglas que sigue, y que conviene no romper:
 *
 *   1. Nunca imprime un valor. Solo nombres de variable y de qué archivo salió
 *      cada una. Con la salida en un log compartido no se filtra nada.
 *   2. No mezcla campos de archivos distintos. Hay dos credenciales distintas
 *      en `legacy/`, no una, y juntarlas produce un host con la contraseña de
 *      otro: un error de autenticación que no dice nada útil.
 *   3. No sobrescribe a ciegas. Si la variable ya está en `.env`, la respeta.
 *   4. Solo lee una lista blanca de variables.
 *
 * Uso:  node scripts/importar-legacy.js           (no pisa lo existente)
 *       node scripts/importar-legacy.js --forzar  (pisa con lo de legacy)
 */

const fs = require('node:fs');
const path = require('node:path');

const RAIZ = path.resolve(__dirname, '..');
const DESTINO = path.join(RAIZ, '.env');
const FUERZAR = process.argv.includes('--forzar');

/**
 * Los dos perfiles que hay en `legacy/`, con sus variables ya separadas.
 *
 * El buzón de la empresa es un buzón normal, con IMAP y SMTP propios. La salida
 * es otra cosa: es la cuenta que usa el hosting para enviar en nombre del
 * dominio del cliente, y su usuario tiene forma de clave de AWS pero no lo es.
 */
const PERFILES = [
  {
    clave: 'buzon',
    titulo: 'Buzón de la empresa (IMAP + SMTP propio)',
    origen: 'legacy/Validate config SMTP/validate-smtp.js',
    variables: {
      NETLAB_MAIL_BUZON_HOST: 'host[1]',
      NETLAB_MAIL_BUZON_PORT: 'port[1]',
      NETLAB_MAIL_BUZON_SECURE: 'secure',
      NETLAB_MAIL_BUZON_IMAP_PORT: 'port[0]',
      NETLAB_MAIL_BUZON_USER: 'user',
      NETLAB_MAIL_BUZON_PASS: 'pass'
    }
  },
  {
    clave: 'salida',
    titulo: 'Salida en nombre del dominio del cliente',
    origen: 'legacy/Validate config SMTP/validate-smtp-2.js, smtp-simple.js, php/test.php',
    variables: {
      NETLAB_MAIL_SALIDA_HOST: 'host',
      NETLAB_MAIL_SALIDA_PORT: 'port',
      NETLAB_MAIL_SALIDA_SECURE: 'secure',
      NETLAB_MAIL_SALIDA_USER: 'user',
      NETLAB_MAIL_SALIDA_PASS: 'pass',
      REMITENTE_POR_DEFECTO: 'remitente',
      DESTINO_POR_DEFECTO: 'destinatario'
    }
  }
];

const ORDEN = ['ABUSEIPDB_API_KEY'];

/* ------------------------------------------------------------------ *
 * Lectura
 * ------------------------------------------------------------------ */

function leer(relative) {
  const completa = path.join(RAIZ, relative);
  return fs.existsSync(completa) ? fs.readFileSync(completa, 'utf8') : null;
}

/**
 * Lee un par `clave: 'valor'`, `clave: "valor"` o `clave: 465` de un objeto de
 * configuración. Acepta números y booleanos sin comillas, que es como los
 * escriben estos scripts: `port: 465` y `secure: true` van a pelo.
 */
function campos(texto, clave) {
  const re = new RegExp(`\\b${clave}\\s*:\\s*(?:(['"])([^'"\\n]*)\\1|([^,\\n}]+?))\\s*,?\\s*(?=[,\\n}])`, 'g');
  const salida = [];
  let m;
  while ((m = re.exec(texto))) salida.push((m[2] ?? m[3] ?? '').trim());
  return salida;
}

function correos(texto) {
  return [...new Set(texto.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g) || [])];
}

/** ¿Usa el SDK de AWS de verdad, o solo tiene una clave que lo parece? */
function usaAwsDeVerdad(texto) {
  return /require\(['"]aws-sdk['"]\)|new\s+AWS\.|AWS\.config|SES\s*\(/i.test(texto);
}

/* ------------------------------------------------------------------ *
 * Recolección
 * ------------------------------------------------------------------ */

function perfilBuzon(texto) {
  const origen = 'legacy/Validate config SMTP/validate-smtp.js';
  const users = campos(texto, 'user');
  const passes = campos(texto, 'pass');
  const hosts = campos(texto, 'host');
  const ports = campos(texto, 'port');

  if (!users[0] || !passes[0] || !hosts[0]) return {};

  const seguro = campos(texto, 'secure')[0] === 'true';
  return {
    // `host` aparece dos veces: el primero es el de IMAP y el segundo el de
    // SMTP. Se invierten al nombrarlos, porque en la convencion de netlab el
    // host del perfil es el de salida.
    NETLAB_MAIL_BUZON_HOST: hosts[1] ?? hosts[0],
    NETLAB_MAIL_BUZON_PORT: ports[1] ?? (seguro ? '465' : '587'),
    NETLAB_MAIL_BUZON_SECURE: String(seguro),
    NETLAB_MAIL_BUZON_IMAP_PORT: ports[0] ?? '993',
    // El mismo buzón se autentica igual por IMAP y por SMTP.
    NETLAB_MAIL_BUZON_USER: users[0],
    NETLAB_MAIL_BUZON_PASS: passes[0],
    _origen: origen
  };
}

function perfilSalida(texto, origen) {
  const users = campos(texto, 'user');
  const passes = campos(texto, 'pass');
  const hosts = campos(texto, 'host');
  const ports = campos(texto, 'port');

  // Sin host + user + pass el perfil no sirve: es preferible no escribir nada
  // que escribir un trio incompleto que fallara al conectar.
  if (!hosts[0] || !users[0] || !passes[0]) return {};

  const seguro = campos(texto, 'secure')[0] === 'true';
  const todos = correos(texto);
  const salida = {
    NETLAB_MAIL_SALIDA_HOST: hosts[0],
    NETLAB_MAIL_SALIDA_PORT: ports[0] ?? (seguro ? '465' : '587'),
    NETLAB_MAIL_SALIDA_SECURE: String(seguro),
    NETLAB_MAIL_SALIDA_USER: users[0],
    NETLAB_MAIL_SALIDA_PASS: passes[0],
    REMITENTE_POR_DEFECTO: todos.find((c) => c.includes('berakah')) ?? todos[0],
    DESTINO_POR_DEFECTO: todos.find((c) => c.includes('redmasiva')) ?? null,
    _origen: origen
  };
  for (const k of Object.keys(salida)) if (salida[k] === undefined) delete salida[k];
  return salida;
}

function recopilar() {
  const encontradas = {};

  // --- AbuseIPDB ---
  // Su `.env` va como `CLAVE=valor` sin comillas, así que no sirve el parser
  // de campos de JavaScript.
  const envAbuse = leer(path.join('legacy', 'Check IP Abuse', 'abuse', '.env'));
  if (envAbuse) {
    const m = envAbuse.match(/^\s*ABUSEIPDB_API_KEY\s*=\s*(.+)$/m);
    if (m) {
      encontradas.ABUSEIPDB_API_KEY = {
        valor: m[1].trim().replace(/^['"]|['"]$/g, ''),
        origen: 'legacy/Check IP Abuse/abuse/.env'
      };
    }
  }

  // --- Buzón ---
  const buzon = leer(path.join('legacy', 'Validate config SMTP', 'validate-smtp.js'));
  if (buzon) {
    for (const [variable, valor] of Object.entries(perfilBuzon(buzon))) {
      if (variable === '_origen' || !valor) continue;
      encontradas[variable] = { valor, origen: 'legacy/Validate config SMTP/validate-smtp.js' };
    }
  }

  // --- Salida ---
  for (const archivo of ['validate-smtp-2.js', 'smtp-simple.js', path.join('php', 'test.php')]) {
    const texto = leer(path.join('legacy', 'Validate config SMTP', archivo));
    if (!texto) continue;

    // Aviso de seguridad, no un dato que volcar: alguno de estos scripts
    // autentica contra el SMTP del proveedor con un usuario que tiene forma de
    // clave de AWS. No lo es. Confundirlos deja el `.env` con credenciales que
    // no sirven y hace creer que hay acceso a AWS cuando no lo hay.
    if (usaAwsDeVerdad(texto)) {
      console.warn(`  (aviso) ${archivo} sí usa el SDK de AWS: revisa esas claves a mano.`);
    }

    for (const [variable, valor] of Object.entries(perfilSalida(texto, archivo))) {
      if (variable === '_origen' || !valor) continue;
      if (encontradas[variable]) continue; // El primer perfil completo gana.
      encontradas[variable] = { valor, origen: `legacy/Validate config SMTP/${archivo}` };
    }
  }

  return encontradas;
}

/* ------------------------------------------------------------------ *
 * Escritura
 * ------------------------------------------------------------------ */

function leerEnvActual() {
  if (!fs.existsSync(DESTINO)) return {};
  const salida = {};
  for (const linea of fs.readFileSync(DESTINO, 'utf8').split(/\r?\n/)) {
    const m = linea.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*)$/);
    if (m) salida[m[1]] = m[2];
  }
  return salida;
}

function escribir(finales, secciones) {
  const lineas = [
    '# netlab — configuración local.',
    '# Generado por scripts/importar-legacy.js. NO versionar: está en .gitignore.',
    '# Origen: legacy/, que sigue congelado con las claves en texto plano.',
    ''
  ];

  for (const { titulo, variables } of secciones) {
    const presentes = variables.filter((v) => finales[v] !== undefined);
    if (!presentes.length) continue;
    lineas.push(`# --- ${titulo} ---`);
    for (const v of presentes) lineas.push(`${v}=${finales[v]}`);
    lineas.push('');
  }

  fs.writeFileSync(DESTINO, `${lineas.join('\n').trimEnd()}\n`, 'utf8');
}

function main() {
  const encontradas = recopilar();
  const actuales = leerEnvActual();

  const secciones = [
    { titulo: 'Consultas de abuso', variables: ORDEN },
    ...PERFILES.map((p) => ({ titulo: p.titulo, variables: Object.keys(p.variables) }))
  ];
  const todas = [...ORDEN, ...PERFILES.flatMap((p) => Object.keys(p.variables))];

  const finales = {};
  const lineas = [];

  for (const variable of todas) {
    const previa = actuales[variable];
    const hallada = encontradas[variable];

    if (previa && !FUERZAR) {
      finales[variable] = previa;
      lineas.push(`  ${variable}: se conserva el valor que ya estaba en .env`);
    } else if (hallada) {
      finales[variable] = hallada.valor;
      lineas.push(`  ${variable}: importada de ${hallada.origen}`);
    }
  }

  const faltan = todas.filter((v) => finales[v] === undefined);
  if (faltan.length) lineas.push(`  sin valor: ${faltan.join(', ')}`);

  escribir(finales, secciones);

  // Aquí no se imprime ningún valor: solo nombres y procedencias.
  console.log('Variables escritas en .env:');
  console.log(lineas.join('\n'));
  console.log(`\nTotal: ${Object.keys(finales).length} de ${todas.length} posibles.`);
  console.log('Recuerda: estas credenciales estaban en texto plano dentro de legacy/. Rota las que sigan vivas.');
}

main();
