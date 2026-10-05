/**
 * config.js — Lectura de la configuracion y de las credenciales.
 *
 * MODULO DE SEGURIDAD Y DE CONVENCION. Ninguna herramienta debe leer
 * `process.env` directamente, por dos motivos:
 *
 *   1. El valor nunca debe acabar en `result.params` ni en un log. Si cada
 *      herramienta lee `process.env.SU_CLAVE` por su cuenta, el dia que alguien
 *      pase `{ apiKey: process.env.ABUSEIPDB_API_KEY }` a un Result, la clave
 *      viaja al historial y al PDF. Leyendo por aqui, la clave se queda en el
 *      modulo y se entrega ya enmascarada cuando hay que mostrarla.
 *   2. Los perfiles de correo son una LISTA, no un numero fijo de variables.
 *      legacy/ los tenia escritos a mano en cada script, y por eso acabaramos
 *      con el host de un buzon junto a la contrasena de otro. Aqui los
 *      perfiles se descubren por patron, de modo que anadir uno es escribir su
 *      bloque en el .env y nada mas.
 *
 * CONVENCION DE PERFILES DE CORREO
 *   NETLAB_MAIL_<PERFIL>_HOST
 *   NETLAB_MAIL_<PERFIL>_PORT
 *   NETLAB_MAIL_<PERFIL>_SECURE
 *   NETLAB_MAIL_<PERFIL>_IMAP_PORT   (opcional)
 *   NETLAB_MAIL_<PERFIL>_USER
 *   NETLAB_MAIL_<PERFIL>_PASS
 *   NETLAB_MAIL_<PERFIL>_DESCRIPCION (opcional)
 *
 * En la base de datos se guarda el NOMBRE del perfil y el nombre de cada
 * variable, nunca su valor.
 *
 * @module core/config
 */

'use strict';

const path = require('node:path');
const { createRedactor } = require('./redact');

/** Prefijo y sufijo con el que se reconoce un perfil de correo. */
const PREFIJO_PERFIL = 'NETLAB_MAIL_';

/**
 * Sufijos que unen las variables de un perfil de correo.
 *
 * El orden importa: se comparan de mas largo a mas corto porque `_IMAP_PORT`
 * acaba en `_PORT`. Buscando `_PORT` primero, `NETLAB_MAIL_BUZON_IMAP_PORT`
 * se habria leido como un perfil llamado `BUZON_IMAP` con un puerto suelto, y
 * el perfil `BUZON` de verdad habria aparecido sin su puerto IMAP.
 */
const SUFIJOS_PERFIL = ['_DESCRIPCION', '_IMAP_PORT', '_HOST', '_PORT', '_SECURE', '_USER', '_PASS'];

/** Nombres de variable cuyo valor se considera secreto. */
const RE_SECRETO = /(?:^|_)(?:PASS(?:WORD|WD)?|SECRET|TOKEN|KEY|CREDENTIAL|CLAVE|CONTRASENA|CONTRASENYA)(?:_|$)/i;

let cargado = false;
let redactorGlobal = null;

/**
 * Carga el `.env` en `process.env`, una sola vez por proceso.
 *
 * Usa `process.loadEnvFile()` de Node, asi que no hace falta ninguna
 * dependencia. Si el archivo no existe no es un error: se trabaja con las
 * variables que ya_esten en el entorno (util en Docker y en la VPS, donde las
 * credenciales llegan por variables de entorno y no por archivo).
 *
 * @param {string} [ruta] Ruta al .env. Por defecto, la raiz del proyecto.
 * @returns {boolean} true si se llego a leer un archivo.
 */
function cargar(ruta) {
  if (cargado) return true;

  const destino = ruta || path.join(__dirname, '..', '..', '.env');
  if (typeof process.loadEnvFile !== 'function') {
    cargado = true;
    return false;
  }

  try {
    process.loadEnvFile(destino);
  } catch {
    // Sin .env. Es el caso normal en un despliegue con variables de entorno.
  }

  cargado = true;
  return true;
}

/**
 * Lee una variable de entorno ya sin comillas ni espacios.
 *
 * @param {string} nombre
 * @returns {string|undefined} `undefined` si no esta definida o esta vacia.
 */
function leer(nombre) {
  cargar();
  const bruto = process.env[nombre];
  if (bruto === undefined || bruto === null) return undefined;
  const valor = String(bruto).trim().replace(/^["']|["']$/g, '');
  return valor === '' ? undefined : valor;
}

/**
 * Lee una variable numerica, acotada a un rango.
 *
 * @param {string} nombre
 * @param {object} [opciones]
 * @param {number} [opciones.min]
 * @param {number} [opciones.max]
 * @param {number} [opciones.porDefecto]
 * @returns {number}
 */
function leerNumero(nombre, { min = -Infinity, max = Infinity, porDefecto } = {}) {
  const bruto = leer(nombre);
  if (bruto === undefined) return porDefecto;
  const valor = Number(bruto);
  if (!Number.isFinite(valor)) return porDefecto;
  return Math.min(max, Math.max(min, Math.trunc(valor)));
}

/**
 * Indica si una variable existe y tiene contenido, sin devolver el valor.
 *
 * Es lo que se usa al describir un perfil de correo para la web: hay que
 * poder decir "hay contrasena configurada" sin devolverla.
 *
 * @param {string} nombre
 * @returns {boolean}
 */
function definida(nombre) {
  return leer(nombre) !== undefined;
}

/**
 * Redactor con todos los secretos del entorno ya conocidos.
 *
 * Se construye una vez y se reutiliza: así, aunque una cadena con la clave se
 * cuele en un mensaje de log, se limpia igual. No sustituye a no mandar el
 * valor, pero es la red de seguridad.
 *
 * @returns {Function} Redactor, igual que el de core/redact.
 */
function redactor() {
  if (redactorGlobal) return redactorGlobal;

  cargar();
  const secretos = Object.entries(process.env)
    .filter(([nombre, valor]) => RE_SECRETO.test(nombre) && typeof valor === 'string' && valor.length >= 4)
    .map(([, valor]) => valor);

  redactorGlobal = createRedactor({ secrets: secretos });
  return redactorGlobal;
}

/**
 * Lista los perfiles de correo definidos en el entorno.
 *
 * Descubre los perfiles por patron en lugar de tener una lista fija, asi que
 * anadir uno al .env es suficiente. Solo se devuelven datos publicables: el
 * usuario se marca como presente o ausente, nunca su valor.
 *
 * @returns {Array<{nombre: string, clave: string, variables: string[], host?: string, port?: number, secure?: boolean, imapPort?: number, descripcion?: string, usuario?: boolean, contrasena?: boolean}>}
 */
function listarPerfilesCorreo() {
  cargar();

  /** @type {Map<string, string[]>} */
  const porPerfil = new Map();
  for (const nombre of Object.keys(process.env)) {
    if (!nombre.startsWith(PREFIJO_PERFIL)) continue;
    const resto = nombre.slice(PREFIJO_PERFIL.length);
    const sufijo = SUFIJOS_PERFIL.find((s) => resto.endsWith(s));
    if (!sufijo) continue;
    const clave = resto.slice(0, -sufijo.length);
    if (!clave) continue;
    if (!porPerfil.has(clave)) porPerfil.set(clave, []);
    porPerfil.get(clave).push(nombre);
  }

  return [...porPerfil.entries()]
    .map(([clave, variables]) => {
      const v = (sufijo) => leer(`${PREFIJO_PERFIL}${clave}${sufijo}`);
      const puerto = Number(v('_PORT'));

      return {
        nombre: clave,
        clave,
        variables: variables.sort(),
        host: v('_HOST'),
        port: Number.isFinite(puerto) ? puerto : undefined,
        secure: v('_SECURE') === 'true',
        imapPort: Number(v('_IMAP_PORT')) || undefined,
        descripcion: v('_DESCRIPCION'),
        usuario: definida(`${PREFIJO_PERFIL}${clave}_USER`),
        contrasena: definida(`${PREFIJO_PERFIL}${clave}_PASS`)
      };
    })
    .sort((a, b) => a.nombre.localeCompare(b.nombre));
}

/**
 * Nombre de la variable que guarda un dato de un perfil de correo.
 *
 * Es la funcion que usa la base de datos: guarda el NOMBRE, no el valor, de
 * modo que rotar una contrasena en el .env no obliga a tocar el historial.
 *
 * @param {string} perfil
 * @param {string} campo 'HOST' | 'PORT' | 'SECURE' | 'USER' | 'PASS' | ...
 * @returns {string}
 */
function variablePerfil(perfil, campo) {
  return `${PREFIJO_PERFIL}${String(perfil).toUpperCase()}_${String(campo).toUpperCase()}`;
}

/**
 * Valor enmascarado de una credencial, para poder mostrarla en un informe sin
 * filtrarla. Solo se revela el final, que es lo justo para que alguien
 * reconozca si ha puesto la contrasena correcta.
 *
 * @param {string} valor
 * @param {number} [visibles=4]
 * @returns {string} p. ej. "••••••••ab12"
 */
function enmascarar(valor, visibles = 4) {
  if (!valor) return '(sin configurar)';
  const texto = String(valor);
  if (texto.length <= visibles) return '•'.repeat(texto.length);
  return `${'•'.repeat(Math.min(12, texto.length - visibles))}${texto.slice(-visibles)}`;
}

module.exports = {
  PREFIJO_PERFIL,
  cargar,
  leer,
  leerNumero,
  definida,
  redactor,
  listarPerfilesCorreo,
variablePerfil,
  enmascarar
};
