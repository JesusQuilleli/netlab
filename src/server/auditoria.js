/**
 * auditoria.js — Log de auditoría en SQLite.
 *
 * MODULO DE AUDITORÍA. Registra eventos de seguridad y administración.
 * Usa la misma BD que el historial (node:sqlite).
 *
 * @module server/auditoria
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const RUTA_POR_DEFECTO = path.join(process.cwd(), 'data', 'netlab.db');

const SQL_ESQUEMA = `
CREATE TABLE IF NOT EXISTS auditoria (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  tipo         TEXT NOT NULL,
  usuario      TEXT,
  ip           TEXT,
  detalles     TEXT,
  createdAt    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aud_tipo    ON auditoria(tipo, createdAt DESC);
CREATE INDEX IF NOT EXISTS idx_aud_usuario ON auditoria(usuario, createdAt DESC);
CREATE INDEX IF NOT EXISTS idx_aud_ip      ON auditoria(ip, createdAt DESC);
`;

/**
 * Tipos de eventos de auditoría.
 */
const TIPOS = {
  SETUP_ADMIN_CREADO: 'setup_admin_creado',
  LOGIN_EXITOSO: 'login_exitoso',
  LOGIN_FALLIDO: 'login_fallido',
  LOGOUT: 'logout',
  USUARIO_CREADO: 'usuario_creado',
  USUARIO_ACTUALIZADO: 'usuario_actualizado',
  USUARIO_BORRADO: 'usuario_borrado',
  COMPARTIR_CREADO: 'compartir_creado',
  COMPARTIR_REVOCADO: 'compartir_revocado',
  EJECUCION_INICIADA: 'ejecucion_iniciada',
  EJECUCION_COMPLETADA: 'ejecucion_completada',
  EJECUCION_FALLIDA: 'ejecucion_fallida',
  FORMATO_DESCARGADO: 'formato_descargado',
};

class Auditoria {
  /**
   * @param {object} [opciones]
   * @param {string} [opciones.ruta] Ruta del fichero SQLite.
   */
  constructor(opciones = {}) {
    this.ruta = opciones.ruta || RUTA_POR_DEFECTO;
    fs.mkdirSync(path.dirname(this.ruta), { recursive: true });
    this.db = new DatabaseSync(this.ruta);
    if (this.ruta !== ':memory:') this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec(SQL_ESQUEMA);

    this._ins = {
      registrar: this.db.prepare('INSERT INTO auditoria (tipo, usuario, ip, detalles, createdAt) VALUES (?, ?, ?, ?, ?)'),
      listar: this.db.prepare('SELECT * FROM auditoria ORDER BY createdAt DESC LIMIT ? OFFSET ?'),
      listarPorTipo: this.db.prepare('SELECT * FROM auditoria WHERE tipo = ? ORDER BY createdAt DESC LIMIT ? OFFSET ?'),
      listarPorUsuario: this.db.prepare('SELECT * FROM auditoria WHERE usuario = ? ORDER BY createdAt DESC LIMIT ? OFFSET ?'),
      contar: this.db.prepare('SELECT COUNT(*) AS n FROM auditoria'),
      contarPorTipo: this.db.prepare('SELECT COUNT(*) AS n FROM auditoria WHERE tipo = ?'),
      contarPorUsuario: this.db.prepare('SELECT COUNT(*) AS n FROM auditoria WHERE usuario = ?'),
      limpiar: this.db.prepare('DELETE FROM auditoria WHERE createdAt < ?'),
    };
  }

  /**
   * Registra un evento de auditoría.
   *
   * @param {object} evento
   * @param {string} evento.tipo
   * @param {string} [evento.usuario]
   * @param {string} [evento.ip]
   * @param {object} [evento.detalles]
   */
  registrar({ tipo, usuario = null, ip = null, detalles = null }) {
    this._ins.registrar.run(tipo, usuario, ip, detalles ? JSON.stringify(detalles) : null, new Date().toISOString());
  }

  /**
   * Lista eventos con paginación.
   *
   * @param {object} [opciones]
   * @param {string} [opciones.tipo]
   * @param {string} [opciones.usuario]
   * @param {number} [opciones.limite=50]
   * @param {number} [opciones.desde=0]
   * @returns {{items: object[], total: number, limite: number, desde: number}}
   */
  listar({ tipo = null, usuario = null, limite = 50, desde = 0 } = {}) {
    const max = Math.min(200, Math.max(1, Math.trunc(Number(limite) || 50)));
    const offset = Math.max(0, Math.trunc(Number(desde) || 0));

    let items, total;
    if (tipo) {
      items = this._ins.listarPorTipo.all(tipo, max, offset);
      total = this._ins.contarPorTipo.get(tipo).n;
    } else if (usuario) {
      items = this._ins.listarPorUsuario.all(usuario, max, offset);
      total = this._ins.contarPorUsuario.get(usuario).n;
    } else {
      items = this._ins.listar.all(max, offset);
      total = this._ins.contar.get().n;
    }

    return {
      items: items.map(f => ({
        id: f.id,
        tipo: f.tipo,
        usuario: f.usuario,
        ip: f.ip,
        detalles: f.detalles ? JSON.parse(f.detalles) : null,
        createdAt: f.createdAt
      })),
      total,
      limite: max,
      desde: offset
    };
  }

  /**
   * Limpia eventos antiguos.
   *
   * @param {number} diasAntiguedad - Eventos más antiguos que esto se borran.
   * @returns {number} Número de eventos borrados.
   */
  limpiar(diasAntiguedad = 90) {
    const corte = new Date(Date.now() - diasAntiguedad * 864e5).toISOString();
    return this._ins.limpiar.run(corte).changes;
  }

  /** Cierra la conexión. */
  cerrar() {
    try { this.db.close(); } catch {}
  }
}

let instancia = null;

/**
 * Instancia singleton de auditoría.
 * @param {object} [opciones]
 * @returns {Auditoria}
 */
function obtenerAuditoria(opciones = {}) {
  if (!instancia) instancia = new Auditoria(opciones);
  return instancia;
}

function cerrarAuditoria() {
  if (instancia) instancia.cerrar();
  instancia = null;
}

module.exports = { Auditoria, obtenerAuditoria, cerrarAuditoria, TIPOS, RUTA_POR_DEFECTO };