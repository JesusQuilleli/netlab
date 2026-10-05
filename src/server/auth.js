/**
 * auth.js — Autenticacion, sesiones, CSRF y limite de intentos.
 *
 * MODULO DE SEGURIDAD. Lee su configuracion de `core/config`, no de
 * `process.env`, siguiendo la convencion del proyecto: las credenciales no se
 * sueltan en este archivo.
 *
 * MODO SIN AUTENTICAR (local)
 *   `AUTH_ENABLED=false` no hay cookie ni sesion: todo corre como el dueño
 *   `local` y las rutas que cambian algo no piden CSRF. Es comodo para develops
 *   y no debe usarse en un servidor expuesto, de ahi que el valor por defecto
 *   sea `HOST=127.0.0.1`.
 *
 * MODO AUTENTICADO (VPS)
 *   Cookie de sesion firmada, opaca y aleatoria. `httpOnly` para que el
 *   JavaScript de la pagina no la pueda leer, `sameSite=strict` para que no la
 *   mande otro sitio. La sesion vive en memoria, asi que reiniciar el servidor
 *   cierra las sesiones abiertas; es el comportamiento correcto para una
 *   herramienta de diagnostico que se despliega de una en vez.
 *
 * CIERRE POR FALTA DE CONFIGURACION
 *   Si alguien pone `AUTH_ENABLED=true` sin usuario ni contrasena, arrancar
 *   seria poner un servidor de diagnostico abierto en Internet creyendo que
 *   esta protegido. Aqui es un error de arranque, no un aviso.
 *
 * @module server/auth
 */

'use strict';

const crypto = require('node:crypto');
const config = require('../core/config');
const { obtenerUsuarios } = require('./usuarios');
const { hashPassword, verificarPassword, igual } = require('./password');

const NOMBRE_COOKIE = 'netlab_sesion';
const NOMBRE_CSRF = 'netlab_csrf';
const DURACION_SESION_MS = 8 * 60 * 60 * 1000; // 8 horas
const DURACION_CSRF_MS = 2 * 60 * 60 * 1000; // 2 horas

/** Limpia una sesion caducada de la tabla en memoria. */
function purgarVencidas(mapa) {
  const ahora = Date.now();
  for (const [clave, dato] of mapa) {
    if (dato.expira <= ahora) mapa.delete(clave);
  }
}

/**
 * Limitador de intentos por IP.
 *
 * Solo en memoria: si se perdiera al reiniciar, alguien tendria que reiniciar el
 * servidor para saltarselo, y a cambio se evita guardar una tabla de intentos
 * que acaba creciendo sin limite.
 *
 * @param {object} [opciones]
 * @param {number} [opciones.maximo=8] Intentos por ventana.
 * @param {number} [opciones.ventanaMs=15*60*1000]
 * @returns {{permitir(clave: string): {ok: boolean, restantes: number, reintentarEn?: number}, limpiar(clave: string): void}}
 */
function limitadorIntentos({ maximo = 8, ventanaMs = 15 * 60 * 1000 } = {}) {
  /** @type {Map<string, number[]>} */
  const intentos = new Map();

  return {
    permitir(clave) {
      const ahora = Date.now();
      const previos = (intentos.get(clave) || []).filter((t) => ahora - t < ventanaMs);

      if (previos.length >= maximo) {
        const espera = Math.ceil((ventanaMs - (ahora - previos[0])) / 1000);
        intentos.set(clave, previos);
        return { ok: false, restantes: 0, reintentarEn: espera };
      }

      previos.push(ahora);
      intentos.set(clave, previos);
      return { ok: true, restantes: maximo - previos.length };
    },
    limpiar(clave) {
      intentos.delete(clave);
    }
  };
}

/** Lee una cookie de la cabecera `Cookie`. @returns {string} */
function leerCookie(cabecera, nombre) {
  if (!cabecera) return '';
  for (const trozo of String(cabecera).split(';')) {
    const i = trozo.indexOf('=');
    if (i === -1) continue;
    if (trozo.slice(0, i).trim() === nombre) {
      try {
        return decodeURIComponent(trozo.slice(i + 1).trim());
      } catch {
        return '';
      }
    }
  }
  return '';
}

/**
 * Control de acceso del proceso.
 *
 * @class Auth
 */
class Auth {
  /**
   * @param {object} [opciones]
   * @param {boolean} [opciones.activo] Fuerza el modo, ignorando el entorno.
   * @param {object} [opciones.usuarios] Instancia de Usuarios para pruebas.
   * @param {number} [opciones.maxIntentos]
   * @param {boolean} [opciones.cookieSegura] Fuerza `Secure` en la cookie.
   */
  constructor(opciones = {}) {
    this.activo = opciones.activo !== undefined ? opciones.activo === true : config.leer('AUTH_ENABLED') === 'true';
    this.usuarios = opciones.usuarios !== undefined ? opciones.usuarios : (this.activo ? obtenerUsuarios() : null);

    if (this.activo && !this.usuarios) {
      throw new Error('Error interno: Usuarios no inicializado en modo autenticado.');
    }

    this.enTextoPlano = false;

    /** @type {Map<string, {usuario: string, role: string, expira: number}>} */
    this.sesiones = new Map();
    /** @type {Map<string, {expira: number}>} */
    this.csrfs = new Map();

    this.seguro = opciones.cookieSegura !== undefined ? opciones.cookieSegura === true : null;
    this.intentos = limitadorIntentos({ maximo: opciones.maxIntentos ?? 8 });
  }

  /** Si la cookie de sesion debe llevar el atributo `Secure`. */
  usarCookieSegura(req) {
    if (this.seguro !== null) return this.seguro;
    const protocolo = String(req?.protocol || '').replace(':', '');
    return protocolo === 'https';
  }

  /**
   * Intenta autenticar.
   *
   * @param {string} usuario
   * @param {string} password
   * @param {string} claveIp Clave del limitador de intentos.
   * @returns {{ok: true, cookie: string, csrf: string, expira: number, role: string}|{ok: false, motivo: string, reintentarEn?: number}}
   */
  entrar(usuario, password, claveIp = 'desconocida') {
    if (!this.activo) {
      return { ok: true, cookie: '', csrf: '', expira: Date.now() + DURACION_SESION_MS, local: true, role: 'admin' };
    }

    const limite = this.intentos.permitir(claveIp);
    if (!limite.ok) {
      return { ok: false, motivo: 'demasiados', reintentarEn: limite.reintentarEn };
    }

    const auth = this.usuarios.autenticar(usuario, password);
    if (!auth) {
      return { ok: false, motivo: 'credenciales' };
    }

    this.intentos.limpiar(claveIp);

    const token = crypto.randomBytes(32).toString('base64url');
    const csrf = crypto.randomBytes(32).toString('base64url');
    const expira = Date.now() + DURACION_SESION_MS;

    this.sesiones.set(token, { usuario: auth.username, role: auth.role, expira });
    this.csrfs.set(csrf, { expira: Date.now() + DURACION_CSRF_MS });

    return { ok: true, cookie: token, csrf, expira, role: auth.role, usuario: auth.username };
  }

  /**
   * Cierra la sesion de un token.
   *
   * @param {string} token
   * @returns {boolean} Si habia sesion que cerrar.
   */
  salir(token) {
    return this.sesiones.delete(token);
  }

  /**
   * Dice quien es la peticion.
   *
   * @param {object} req Peticion de express.
   * @returns {{usuario: string, role: string, local: boolean}}
   */
  identidad(req) {
    if (!this.activo) return { usuario: 'local', role: 'admin', local: true };

    const token = leerCookie(req?.headers?.cookie, NOMBRE_COOKIE);
    if (!token) return { usuario: null, role: null, local: false };

    const sesion = this.sesiones.get(token);
    if (!sesion) return { usuario: null, role: null, local: false };
    if (sesion.expira <= Date.now()) {
      this.sesiones.delete(token);
      return { usuario: null, role: null, local: false };
    }
    return { usuario: sesion.usuario, role: sesion.role, local: false };
  }

  /**
   * Comprueba el token CSRF de una peticion que cambia algo.
   *
   * El token no va en la cookie: viaja en la cabecera `X-CSRF-Token` y lo pide
   * `/api/sesion`. Un sitio de terceros podria mandar la peticion con la cookie
   * (el navegador las manda solas) pero no puede leer el token, y por eso no
   * puede hacer que el navegador lo envie.
   *
   * @param {object} req
   * @returns {boolean}
   */
  csrfValido(req) {
    if (!this.activo) return true;

    const enviado = req?.headers?.['x-csrf-token'];
    if (!enviado) return false;

    const registro = this.csrfs.get(String(enviado));
    if (!registro) return false;
    if (registro.expira <= Date.now()) {
      this.csrfs.delete(String(enviado));
      return false;
    }
    return true;
  }

  /** Empieza el token de una sesion ya iniciada. @returns {string} */
  nuevoCsrf() {
    const csrf = crypto.randomBytes(32).toString('base64url');
    this.csrfs.set(csrf, { expira: Date.now() + DURACION_CSRF_MS });
    return csrf;
  }

  /** Empieza el token de CSRF sin sesion, para la pantalla de entrada. @returns {string} */
  csrfPreliminar() {
    return this.nuevoCsrf();
  }

  /**
   * Valor de la cabecera `Set-Cookie` para la sesion.
   *
   * @param {string} token
   * @param {object} req
   * @returns {string}
   */
  cookieSesion(token, req) {
    if (!token) return '';
    const partes = [
      `${NOMBRE_COOKIE}=${token}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${Math.floor(DURACION_SESION_MS / 1000)}`
    ];
    if (this.usarCookieSegura(req)) partes.push('Secure');
    return partes.join('; ');
  }

  /** Cabecera `Set-Cookie` para cerrar la sesion. @returns {string} */
  cookieCierre() {
    return `${NOMBRE_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
  }

  /** Elimina sesiones caducadas. Lo llama el servidor cada cierto tiempo. */
  limpiar() {
    purgarVencidas(this.sesiones);
    purgarVencidas(this.csrfs);
  }
}

module.exports = {
  Auth,
  hashPassword,
  verificarPassword,
  limitadorIntentos,
  igual,
  leerCookie,
  NOMBRE_COOKIE,
  NOMBRE_CSRF,
  DURACION_SESION_MS
};
