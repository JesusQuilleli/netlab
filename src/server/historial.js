/**
 * historial.js — Historial de ejecuciones en SQLite.
 *
 * MODULO DE PERSISTENCIA. Usa `node:sqlite`, que viene en Node 24, asi que
 * el historial no anade ninguna dependencia al proyecto.
 *
 * QUE SE GUARDA Y QUE NO
 *   Se guarda el `Result` completo en JSON. Es lo que permite volver a ver una
 *   ejecucion y volver a descargar sus cinco formatos sin volver a consultar la
 *   red, que ademas ya habria cambiado.
 *
 *   NO se guarda un "cache" del informe: el Result no es el informe. Los cinco
 *   formatos se generan otra vez desde el Result guardado. Es lo que hace que
 *   arreglar un fallo del PDF no obligue a reejecutar 400 diagnosticos.
 *
 *   `params` se guarda, pero solo despues de pasar por `server/validar`. No se
 *   guarda lo que el navegador mando, sino lo que la herramienta acepto.
 *
 * DEDUPLICACION POR HUELLA
 *   La `huella` es el hash del Result sin los campos de reloj. Dos ejecuciones
 *   con distinto reloj pero el mismo resultado dan la misma huella, y la segunda
 *   se reconoce como repetida en vez de crear una entrada nueva. Es el motivo de
 *   que `formats/json.js` vacie tambien `logs[].ts`: si el reloj se colara en la
 *   huella, esto no deduplicaria nada.
 *
 * @module server/historial
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const jsonFormats = require('../formats/json');

const RUTA_POR_DEFECTO = path.join(process.cwd(), 'data', 'netlab.db');

const SQL_ESQUEMA = `
CREATE TABLE IF NOT EXISTS ejecuciones (
  id           TEXT PRIMARY KEY,
  tool         TEXT NOT NULL,
  target       TEXT,
  status       TEXT,
  params_json  TEXT NOT NULL,
  params_hash  TEXT NOT NULL,
  huella       TEXT NOT NULL,
  owner        TEXT NOT NULL DEFAULT 'local',
  result_json  TEXT,
  created_at   TEXT NOT NULL,
  duration_ms  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_ej_owner     ON ejecuciones(owner, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ej_owner_tool ON ejecuciones(owner, tool, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ej_huella    ON ejecuciones(owner, huella);

CREATE TABLE IF NOT EXISTS resultados (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ejecucion_id TEXT NOT NULL REFERENCES ejecuciones(id) ON DELETE CASCADE,
  formato      TEXT NOT NULL,
  filename     TEXT NOT NULL,
  ruta         TEXT NOT NULL,
  bytes        INTEGER NOT NULL,
  created_at   TEXT NOT NULL,
  UNIQUE (ejecucion_id, formato)
);

CREATE TABLE IF NOT EXISTS compartidos (
  shareToken   TEXT PRIMARY KEY,
  ejecucionId  TEXT NOT NULL REFERENCES ejecuciones(id) ON DELETE CASCADE,
  owner        TEXT NOT NULL,
  expiraEn     TEXT NOT NULL,
  revocado     INTEGER NOT NULL DEFAULT 0,
  creadoEn     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_share_owner ON compartidos(owner, creadoEn DESC);
`;

/**
 * Hash de los parametros, para saber si dos ejecuciones se pidieron igual.
 *
 * Se ordena clave por clave: `{a:1,b:2}` y `{b:2,a:1}` son la misma peticion y
 * deben dar el mismo hash. Sin ordenar, el mismo formulario con las casillas
 * marcadas en otro orden contaria como peticion diferente.
 *
 * @param {object} params
 * @returns {string} sha256 en hexadecimal.
 */
function hashParams(params = {}) {
  const ordenado = {};
  for (const clave of Object.keys(params).sort()) ordenado[clave] = params[clave];
  return crypto.createHash('sha256').update(JSON.stringify(ordenado)).digest('hex');
}

/**
 * Completa un Result con lo que el contrato garantiza, sin quitarle nada.
 *
 * Esto se escribio al principio como una lista blanca de campos, copiando uno
 * a uno los que sabia. Fue un error: la lista se quedo corta y `toolTitle`
 * desaparecio, de modo que al releer del historial el TXT reventaba con
 * "cannot read properties of undefined" mientras que el MD, el HTML, el JSON y
 * el PDF seguian bien, porque solo el TXT pone el titulo en mayusculas.
 *
 * Copiar una lista de campos a mano convierte cada campo nuevo del contrato en
 * un fallo silencioso. As que se copia el Result entero y solo se rellenan los
 * que falten.
 *
 * @param {object} result
 * @returns {object}
 */
function resultPorDefecto(result = {}) {
  return {
    ...result,
    tool: result.tool || '',
    toolTitle: result.toolTitle || result.tool || 'netlab',
    target: result.target || '',
    status: result.status || '',
    params: result.params || {},
    // `summary` es una LISTA de { label, value, tone }, no un objeto.
    summary: result.summary || [],
    sections: result.sections || [],
    findings: result.findings || [],
    logs: result.logs || [],
    notes: result.notes || [],
    warnings: result.warnings || [],
    error: result.error || null,
    startedAt: result.startedAt || new Date().toISOString(),
    durationMs: result.durationMs ?? null,
    schema: result.schema ?? null
  };
}

/**
 * Persistencia del historial.
 *
 * Se envuelve en una clase y no en funciones sueltas porque hay estado: la
 * conexion. Compartir una conexion de SQLite entre peticiones concurrentes
 * referring al mismo objecto es justo lo que produce "database is locked".
 *
 * @class Historial
 */
class Historial {
  /**
   * @param {object} [opciones]
   * @param {string} [opciones.ruta] Ruta del fichero. `:memory:` para pruebas.
   */
  constructor(opciones = {}) {
    this.ruta = opciones.ruta || RUTA_POR_DEFECTO;

    if (this.ruta !== ':memory:') {
      fs.mkdirSync(path.dirname(this.ruta), { recursive: true });
    }

    this.db = new DatabaseSync(this.ruta);
    // WAL soporta mejor varias lecturas simultaneas. En memoria no existe.
    if (this.ruta !== ':memory:') this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec(SQL_ESQUEMA);

    this._ins = {
      ejecucion: this.db.prepare(
        `INSERT INTO ejecuciones
           (id, tool, target, status, params_json, params_hash, huella, owner, result_json, created_at, duration_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ),
      porHuella: this.db.prepare('SELECT * FROM ejecuciones WHERE owner = ? AND huella = ? LIMIT 1'),
      porId: this.db.prepare('SELECT * FROM ejecuciones WHERE id = ? AND owner = ?'),
      listar: this.db.prepare(
        `SELECT id, tool, target, status, params_json, params_hash, huella, owner, created_at, duration_ms
           FROM ejecuciones WHERE owner = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
      ),
      contar: this.db.prepare('SELECT COUNT(*) AS n FROM ejecuciones WHERE owner = ?'),
      borrar: this.db.prepare('DELETE FROM ejecuciones WHERE id = ? AND owner = ?'),
      archivar: this.db.prepare(
        `INSERT OR IGNORE INTO resultados (ejecucion_id, formato, filename, ruta, bytes, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      ),
      archivos: this.db.prepare('SELECT formato, filename, bytes FROM resultados WHERE ejecucion_id = ?'),
      borrarArchivos: this.db.prepare('DELETE FROM resultados WHERE ejecucion_id = ?'),
      porToken: this.db.prepare('SELECT * FROM compartidos WHERE shareToken = ?'),
      crearCompartido: this.db.prepare(
        `INSERT INTO compartidos (shareToken, ejecucionId, owner, expiraEn, revocado, creadoEn)
         VALUES (?, ?, ?, ?, ?, ?)`
      ),
      revocarCompartido: this.db.prepare(
        `UPDATE compartidos SET revocado = 1 WHERE shareToken = ? AND owner = ?`
      )
    };
  }

  /**
   * Guarda una ejecucion.
   *
   * @param {object} entrada
   * @param {string} entrada.tool
   * @param {object} [entrada.params] Parametros ya validados.
   * @param {object} [entrada.result] Result completo.
   * @param {string} [entrada.owner] Dueño de la ejecucion. Viene de la sesion, nunca del cuerpo.
   * @returns {{id: string, duplicado: boolean, createdAt: string}}
   */
  guardar({ tool, params = {}, result = null, owner = 'local' }) {
    const resultCompleto = result ? resultPorDefecto(result) : null;
    const huella = resultCompleto ? jsonFormats.huella(resultCompleto) : hashParams(params);
    const paramsHash = hashParams(params);
    const createdAt = resultCompleto?.startedAt || new Date().toISOString();

    const previo = this._ins.porHuella.get(owner, huella);
    if (previo) {
      return { id: previo.id, duplicado: true, createdAt: previo.created_at };
    }

    const id = crypto.randomUUID();
    this._ins.ejecucion.run(
      id,
      tool,
      resultCompleto?.target ?? null,
      resultCompleto?.status ?? null,
      JSON.stringify(params),
      paramsHash,
      huella,
      owner,
      resultCompleto ? JSON.stringify(resultCompleto) : null,
      createdAt,
      resultCompleto?.durationMs ?? null
    );

    return { id, duplicado: false, createdAt };
  }

  /**
   * Anota que se ha generado un archivo en disco de una ejecucion.
   *
   * @param {string} ejecucionId
   * @param {{formato: string, filename: string, file: string, bytes: number}} archivo
   * @returns {object} Lo que se guardo.
   */
  archivar(ejecucionId, archivo) {
    this._ins.archivar.run(
      ejecucionId,
      archivo.formato,
      archivo.filename,
      archivo.file,
      archivo.bytes ?? 0,
      new Date().toISOString()
    );
    return { ejecucionId, ...archivo };
  }

  /**
   * Archivos ya generados de una ejecucion.
   *
   * @param {string} ejecucionId
   * @returns {Array<{formato: string, filename: string, bytes: number}>}
   */
  archivos(ejecucionId) {
    return this._ins.archivos.all(ejecucionId);
  }

  /**
   * Recupera una ejecucion.
   *
   * El `owner` va siempre en la consulta y no se comprueba despues: una
   * comprobacion en JavaScript seria un instante de ventana en el que otra
   * peticion podria leer el registro, y aqui no hace falta arriesgarlo.
   *
   * @param {string} id
   * @param {string} owner
   * @returns {{registro: object, result: object|null}|null}
   */
  obtener(id, owner = 'local') {
    const fila = this._ins.porId.get(String(id), owner);
    if (!fila) return null;

    let result = null;
    try {
      result = fila.result_json ? JSON.parse(fila.result_json) : null;
    } catch {
      // Un registro corrupto no debe tumbar el listado: se devuelve sin result.
      result = null;
    }

    return { registro: this.aFila(fila), result };
  }

  /**
   * Convierte una fila cruda en el objeto que ve el navegador.
   *
   * `result_json` y `params_hash` no salen: el primero pesa y no hace falta
   * para pintar una lista, y el segundo es interno de deduplicacion.
   *
   * @param {object} fila
   * @returns {object}
   */
  aFila(fila) {
    let params = null;
    try {
      params = fila.params_json ? JSON.parse(fila.params_json) : null;
    } catch {
      params = null;
    }

    return {
      id: fila.id,
      tool: fila.tool,
      target: fila.target,
      status: fila.status,
      params,
      huella: fila.huella,
      owner: fila.owner,
      createdAt: fila.created_at,
      durationMs: fila.duration_ms
    };
  }

  /**
   * Lista el historial de un dueño, del mas reciente al mas antiguo.
   *
   * @param {object} [opciones]
   * @param {string} [opciones.owner]
   * @param {string} [opciones.tool] Filtra por herramienta.
   * @param {number} [opciones.limite=50]
   * @param {number} [opciones.desde=0]
   * @returns {{items: object[], total: number, limite: number, desde: number}}
   */
  listar({ owner = 'local', tool = null, limite = 50, desde = 0 } = {}) {
    const max = Math.min(200, Math.max(1, Math.trunc(Number(limite) || 50)));
    const offset = Math.max(0, Math.trunc(Number(desde) || 0));

    if (tool) {
      // Filtro por herramienta: consulta propia, con los mismos limites.
      const filas = this.db
        .prepare(
          `SELECT id, tool, target, status, params_json, params_hash, huella, owner, created_at, duration_ms
             FROM ejecuciones WHERE owner = ? AND tool = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
        )
        .all(owner, tool, max, offset);
      return {
        items: filas.map((f) => this.aFila(f)),
        total: this.db.prepare('SELECT COUNT(*) AS n FROM ejecuciones WHERE owner = ? AND tool = ?').get(owner, tool).n,
        limite: max,
        desde: offset
      };
    }

    return {
      items: this._ins.listar.all(owner, max, offset).map((f) => this.aFila(f)),
      total: this._ins.contar.get(owner).n,
      limite: max,
      desde: offset
    };
  }

  /**
   * Borra una ejecucion del historial.
   *
   * Los archivos de disco NO se borran: se quedan en `data/reports/` porque un
   * informe ya descargado, o compartido, no debe desaparecer porque alguien
   * limpio su lista. Quien quiera tambien puede borrarlos a mano.
   *
   * @param {string} id
   * @param {string} owner
   * @returns {boolean} Si habia algo que borrar.
   */
  borrar(id, owner = 'local') {
    this._ins.borrarArchivos.run(id);
    return this._ins.borrar.run(id, owner).changes > 0;
  }

  /**
   * Genera un token opaco para compartir.
   * @returns {string}
   */
  _tokenCompartir() {
    return crypto.randomBytes(5).toString('base64url');
  }

  /**
   * Crea un enlace de comparticion para una ejecucion.
   *
   * @param {object} opts
   * @param {string} opts.ejecucionId
   * @param {string} opts.owner
   * @param {number} [opts.ttlDias=7] Dias de validez (1-90).
   * @returns {{shareToken: string, shareUrl: string, expiraEn: string}}
   */
  crearCompartido({ ejecucionId, owner, ttlDias = 7 }) {
    const maxTtl = Number(process.env.SHARE_TTL_MAX_DIAS) || 90;
    const ttl = Math.min(Math.max(1, Math.trunc(Number(ttlDias) || 7)), maxTtl);
    const expiraEn = new Date(Date.now() + ttl * 864e5).toISOString();
    const creadoEn = new Date().toISOString();

    let shareToken;
    for (let i = 0; i < 5; i++) {
      shareToken = this._tokenCompartir();
      const colision = this._ins.porToken.get(shareToken);
      if (!colision) break;
    }

    this._ins.crearCompartido.run(shareToken, ejecucionId, owner, expiraEn, 0, creadoEn);

    const base = process.env.PUBLIC_URL || '';
    return {
      shareToken,
      shareUrl: `${base}/r/${shareToken}`,
      expiraEn
    };
  }

  /**
   * Obtiene un compartido valido (no revocado, no expirado).
   *
   * @param {string} shareToken
   * @returns {object|null} { ejecucionId, owner, expiraEn } o null.
   */
  obtenerCompartido(shareToken) {
    const fila = this._ins.porToken.get(shareToken);
    if (!fila) return null;
    if (fila.revocado === 1) return null;
    if (new Date(fila.expiraEn) < new Date()) return null;
    return { ejecucionId: fila.ejecucionId, owner: fila.owner, expiraEn: fila.expiraEn };
  }

  /**
   * Revoca un enlace de comparticion (solo el owner).
   *
   * @param {string} shareToken
   * @param {string} owner
   * @returns {boolean} Si se revoco algo.
   */
  revocarCompartido(shareToken, owner) {
    const res = this._ins.revocarCompartido.run(shareToken, owner);
    return res.changes > 0;
  }

  /** Cierra la conexion. */
  cerrar() {
    try {
      this.db.close();
    } catch {
      // Cerrar dos veces no es un problema.
    }
  }
}

let instancia = null;

/**
 * Historial del proceso.
 *
 * @param {object} [opciones]
 * @returns {Historial}
 */
function obtenerHistorial(opciones = {}) {
  if (!instancia) instancia = new Historial(opciones);
  return instancia;
}

/** Cierra y olvida la instancia. Lo usan las pruebas. */
function cerrarHistorial() {
  if (instancia) instancia.cerrar();
  instancia = null;
}

module.exports = { Historial, obtenerHistorial, cerrarHistorial, hashParams, RUTA_POR_DEFECTO, crearCompartido: (opts) => obtenerHistorial().crearCompartido(opts), obtenerCompartido: (token) => obtenerHistorial().obtenerCompartido(token), revocarCompartido: (token, owner) => obtenerHistorial().revocarCompartido(token, owner) };
