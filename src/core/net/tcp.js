/**
 * net/tcp.js — Escaneo de puertos TCP con banner grabbing.
 *
 * MODULO QUE AMPLIA UNA CAPACIDAD. legacy/Check IP Abuse/checked/check-ip.js
 * solo comprobaba si el puerto abria o cerraba (`checkPort`, lineas 62-75).
 * Eso da un si/no y poco mas.
 *
 * Aqui, cuando un puerto abre, se lee el banner que el servicio envia al
 * conectar: la version del software, a veces el hostname, a veces el motor de
 * base de datos. Eso convierte "el puerto 22 esta abierto" en "OpenSSH
 * 8.9p1 Ubuntu-3ubuntu0.4, que tiene vulnerabilidades conocidas", que es lo
 * que sirve para un informe de cumplimiento.
 *
 * @module core/net/tcp
 */

'use strict';

const net = require('node:net');
const { wrap } = require('../errors');

/**
 * Catalogo de puertos conocidos, con la severidad que usa cada herramienta.
 *
 * `severity`:
 *   critical -> exposicion grave (administracion remota sin MFA, SMB, etc.)
 *   risky    -> protocolo claro o envejecido
 *   standard -> servicio web normal, no es un problema por si mismo
 *   info     -> informativo
 */
const PUERTOS_CONOCIDOS = [
  { port: 21, name: 'FTP', protocol: 'ftp', severity: 'risky', banner: true, note: 'Transfiere usuario y clave en texto plano.' },
  { port: 22, name: 'SSH', protocol: 'ssh', severity: 'critical', banner: true, note: 'Administracion remota. Exponerlo sin limites es el vector mas habitual de acceso no autorizado.' },
  { port: 23, name: 'Telnet', protocol: 'telnet', severity: 'critical', banner: true, note: 'Todo el trafico, incluida la contrasena, viaja en texto plano. Deberia retirarse.' },
  { port: 25, name: 'SMTP', protocol: 'smtp', severity: 'critical', banner: true, note: 'Si esta abierto sin autenticacion ni limites, es un relay abierto: luego lo usan para spam.' },
  { port: 53, name: 'DNS', protocol: 'dns', severity: 'info', banner: false, note: 'Solo informativo.' },
  { port: 80, name: 'HTTP', protocol: 'http', severity: 'standard', banner: false, note: 'Servicio web normal.' },
  { port: 110, name: 'POP3', protocol: 'pop3', severity: 'risky', banner: true, note: 'POP3 sin TLS transmite credenciales en claro.' },
  { port: 143, name: 'IMAP', protocol: 'imap', severity: 'standard', banner: true, note: 'Acceso a buzon. Sin TLS seria un riesgo.' },
  { port: 443, name: 'HTTPS', protocol: 'https', severity: 'standard', banner: false, note: 'Servicio web cifrado.' },
  { port: 445, name: 'SMB', protocol: 'smb', severity: 'critical', banner: false, note: 'Usado por EternalBlue y otros fallos graves. No deberia estar expuesto a internet.' },
  { port: 587, name: 'SMTP-Submission', protocol: 'smtp', severity: 'standard', banner: true, note: 'Envio autenticado de correo.' },
  { port: 993, name: 'IMAPS', protocol: 'imap', severity: 'standard', banner: true, note: 'IMAP sobre TLS.' },
  { port: 995, name: 'POP3S', protocol: 'pop3', severity: 'standard', banner: true, note: 'POP3 sobre TLS.' },
  { port: 1433, name: 'MSSQL', protocol: 'mssql', severity: 'critical', banner: true, note: 'Bases de datos no deberian exponerse a internet.' },
  { port: 3306, name: 'MySQL', protocol: 'mysql', severity: 'critical', banner: true, note: 'Bases de datos no deberian exponerse a internet.' },
  { port: 3389, name: 'RDP', protocol: 'rdp', severity: 'critical', banner: false, note: 'Escritorio remoto. Es el objetivo habitual de los ataques de fuerza bruta.' },
  { port: 5432, name: 'PostgreSQL', protocol: 'postgres', severity: 'critical', banner: true, note: 'Bases de datos no deberian exponerse a internet.' },
  { port: 5900, name: 'VNC', protocol: 'vnc', severity: 'critical', banner: true, note: 'VNC en muchas configuraciones no cifra nada.' },
  { port: 6379, name: 'Redis', protocol: 'redis', severity: 'critical', banner: false, note: 'Si responde sin AUTH, cualquiera puede leer y escribir en la base de datos.' },
  { port: 8080, name: 'HTTP-Alt', protocol: 'http', severity: 'standard', banner: false, note: 'HTTP alternativo, habitual en paneles y proxies.' },
  { port: 8443, name: 'HTTPS-Alt', protocol: 'https', severity: 'standard', banner: false, note: 'HTTPS alternativo.' },
  { port: 9200, name: 'Elasticsearch', protocol: 'http', severity: 'critical', banner: false, note: 'Si esta abierto sin autenticacion, expone el indice completo.' },
  { port: 27017, name: 'MongoDB', protocol: 'mongo', severity: 'critical', banner: true, note: 'MongoDB ha sido uno de los servicios mas expuestos por error de configuracion.' }
];

/** Diálogo que se envía para provocar un banner en los servicios mudos. */
const SONDAS = {
  http: 'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
  https: 'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
  telnet: null,
  redis: 'INFO server\r\n'
};

/**
 * Comprueba si un puerto TCP acepta conexiones, leyendo su banner si puede.
 *
 * A diferencia de la version de legacy/, siempre resuelve: tanto si el puerto
 * esta abierto, filtrado, cerrado o hay un error, la promesa se resuelve con
 * un objeto. Nunca se queda colgada, porque hay un plazo maximo.
 *
 * @param {string} ip Direccion a comprobar.
 * @param {object} puertoItem Entrada de PUERTOS_CONOCIDOS o {port, name, severity, banner}.
 * @param {object} [options]
 * @param {number} [options.timeout=2000] Plazo de conexion.
 * @param {number} [options.bannerTimeout=700] Plazo de lectura del banner.
 * @returns {Promise<{port, name, severity, note, abierto, banner, error, duracionMs}>}
 */
function comprobarPuerto(ip, puertoItem, options = {}) {
  const { timeout = 2000, bannerTimeout = 700 } = options;

  return new Promise((resolve) => {
    const inicio = Date.now();
    const socket = new net.Socket();
    let abierto = false;
    let buffer = '';
    let cerrado = false;
    let temporizadorBanner = null;

    const finalizar = (error = null) => {
      if (cerrado) return;
      cerrado = true;
      clearTimeout(temporizadorBanner);
      socket.destroy();
      resolve({
        port: puertoItem.port,
        name: puertoItem.name,
        protocol: puertoItem.protocol || null,
        severity: puertoItem.severity || 'info',
        note: puertoItem.note || null,
        abierto,
        banner: limpiarBanner(buffer),
        error,
        duracionMs: Date.now() - inicio
      });
    };

    socket.setTimeout(timeout);
    socket.once('connect', () => {
      abierto = true;
      // Algunos servicios solo bablean si se les escribe algo primero.
      const sonda = SONDAS[puertoItem.protocol];
      if (sonda) socket.write(sonda);
      // Plazo propio para el banner: si no contesta, seguimos con puerto abierto.
      temporizadorBanner = setTimeout(() => finalizar(), puertoItem.banner === false ? 0 : bannerTimeout);
    });

    socket.once('timeout', () => finalizar(abierto ? null : 'Tiempo agotado'));
    socket.once('error', (err) => finalizar(abierto ? null : wrap(err).message));
    socket.once('data', (chunk) => {
      buffer += chunk.toString('latin1');
      // Un banner llega de golpe; en cuanto tenemos algo legible, cerramos.
      if (buffer.includes('\n') || buffer.length > 200) finalizar();
    });
    socket.once('close', () => finalizar());

    socket.connect(puertoItem.port, ip);
  });
}

/**
 * Comprueba varios puertos en paralelo con un tope de concurrencia.
 *
 * @param {string} ip
 * @param {object[]} puertos
 * @param {object} [options]
 * @param {number} [options.concurrencia=8]
 * @returns {Promise<object[]>} Resultados en el mismo orden que la entrada.
 */
async function comprobarPuertos(ip, puertos, options = {}) {
  const { concurrencia = 8, ...resto } = options;

  const pendientes = [...puertos];
  const resultados = new Array(puertos.length);
  let indice = 0;

  async function trabajador() {
    while (indice < puertos.length) {
      const i = indice++;
      resultados[i] = await comprobarPuerto(ip, puertos[i], resto);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrencia, puertos.length) }, trabajador));
  return resultados;
}

/**
 * Limpia un banner para que sea legible en un informe.
 *
 * @param {string} banner
 * @returns {string} Primera linea util, sin caracteres de control.
 */
function limpiarBanner(banner) {
  if (!banner) return '';
  const primeraLinea = banner
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find(Boolean);
  if (!primeraLinea) return '';
  return primeraLinea.replace(/[^\x20-\x7e]+/g, ' ').replace(/\s{2,}/g, ' ').slice(0, 160);
}

/**
 * Devuelve el perfil de puertos por defecto, o el indicado por nombre.
 *
 * @param {string} [perfil='auditoria'] 'auditoria' | 'web' | 'todos'
 * @returns {object[]}
 */
function perfil(perfilNombre = 'auditoria') {
  switch (perfilNombre) {
    case 'web':
      return PUERTOS_CONOCIDOS.filter((p) => p.severity === 'standard');
    case 'todos':
      return [...PUERTOS_CONOCIDOS];
    case 'auditoria':
    default:
      return [...PUERTOS_CONOCIDOS];
  }
}

/**
 * Interpreta una lista de puertos escrita por la persona usuaria.
 * Acepta "22,80,443" y "22" y nombres libres como "8080/custom".
 *
 * @param {string} lista
 * @returns {object[]} Entradas normalizadas.
 */
function parsearPuertos(lista) {
  return String(lista)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((trozo) => {
      const [p, etiqueta] = trozo.split('/');
      const port = Number(p);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw Object.assign(new Error(`"${trozo}" no es un puerto válido.`), {
          code: 'PARAM_INVALIDO',
          remediation: 'Un puerto va de 1 a 65535. Ejemplos: 22, 80, 443, 8080/custom'
        });
      }
      const conocido = PUERTOS_CONOCIDOS.find((k) => k.port === port);
      return {
        port,
        name: etiqueta || conocido?.name || `Puerto ${port}`,
        protocol: conocido?.protocol || null,
        severity: conocido?.severity || 'info',
        banner: conocido?.banner !== false,
        note: conocido?.note || 'Puerto indicado manualmente.'
      };
    });
}

module.exports = { comprobarPuerto, comprobarPuertos, perfil, parsearPuertos, limpiarBanner, PUERTOS_CONOCIDOS };