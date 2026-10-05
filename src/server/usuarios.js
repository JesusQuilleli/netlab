/**
 * usuarios.js — Gestión de usuarios en SQLite.
 *
 * MODULO DE USUARIOS. Permite crear, listar y eliminar usuarios con roles.
 * Se usa SQLite (node:sqlite) que viene en Node 24.
 *
 * @module server/usuarios
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { hashPassword, verificarPassword } = require('./password');

const RUTA_POR_DEFECTO = path.join(process.cwd(), 'data', 'netlab.db');

const SQL_ESQUEMA = `
CREATE TABLE IF NOT EXISTS usuarios (
  id           TEXT PRIMARY KEY,
  username     TEXT NOT NULL UNIQUE,
  passwordHash TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'user',
  activo       INTEGER NOT NULL DEFAULT 1,
  createdAt    TEXT NOT NULL,
  lastLogin    TEXT
);
CREATE INDEX IF NOT EXISTS idx_usuarios_username ON usuarios(username);
`;

/**
 * Genera un ID único para usuario.
 * @returns {string}
 */
function nuevoId() {
  return crypto.randomBytes(8).toString('base64url');
}

class Usuarios {
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
      crear: this.db.prepare('INSERT INTO usuarios (id, username, passwordHash, role, activo, createdAt) VALUES (?, ?, ?, ?, ?, ?)'),
      porUsername: this.db.prepare('SELECT * FROM usuarios WHERE username = ?'),
      porId: this.db.prepare('SELECT * FROM usuarios WHERE id = ?'),
      listar: this.db.prepare('SELECT id, username, role, activo, createdAt, lastLogin FROM usuarios ORDER BY createdAt DESC'),
      actualizar: this.db.prepare('UPDATE usuarios SET passwordHash = ?, role = ?, activo = ?, lastLogin = ? WHERE id = ?'),
      borrar: this.db.prepare('DELETE FROM usuarios WHERE id = ?'),
      contar: this.db.prepare('SELECT COUNT(*) AS n FROM usuarios')
    };
  }

  /**
   * Crea un usuario nuevo.
   *
   * @param {object} datos
   * @param {string} datos.username
   * @param {string} datos.password
   * @param {string} [datos.role='user'] 'admin' | 'user'
   * @returns {{id: string, username: string, role: string}}
   */
  crear({ username, password, role = 'user' }) {
    if (!username || !password) throw new Error('Usuario y contraseña son obligatorios.');
    if (username.length > 64) throw new Error('El nombre de usuario es demasiado largo.');
    if (password.length < 8) throw new Error('La contraseña debe tener al menos 8 caracteres.');

    const existe = this._ins.porUsername.get(username);
    if (existe) throw new Error('Ese nombre de usuario ya existe.');

    const id = nuevoId();
    const passwordHash = hashPassword(password);
    const createdAt = new Date().toISOString();

    this._ins.crear.run(id, username, passwordHash, role, 1, createdAt);
    return { id, username, role };
  }

  /**
   * Autentica un usuario.
   *
   * @param {string} username
   * @param {string} password
   * @returns {{id: string, username: string, role: string}|null}
   */
  autenticar(username, password) {
    const usuario = this._ins.porUsername.get(username);
    if (!usuario || !usuario.activo) return null;
    if (!verificarPassword(password, usuario.passwordHash)) return null;

    this._ins.actualizar.run(usuario.passwordHash, usuario.role, usuario.activo, new Date().toISOString(), usuario.id);
    return { id: usuario.id, username: usuario.username, role: usuario.role };
  }

  /**
   * Lista todos los usuarios.
   *
   * @returns {Array<{id: string, username: string, role: string, activo: number, createdAt: string, lastLogin: string|null}>}
   */
  listar() {
    return this._ins.listar.all();
  }

  /**
   * Obtiene un usuario por ID.
   *
   * @param {string} id
   * @returns {object|null}
   */
  obtener(id) {
    return this._ins.porId.get(id) || null;
  }

  /**
   * Actualiza un usuario (contraseña, rol, estado).
   *
   * @param {string} id
   * @param {object} datos
   * @param {string} [datos.password]
   * @param {string} [datos.role]
   * @param {number} [datos.activo]
   * @returns {boolean}
   */
  actualizar(id, { password, role, activo }) {
    const usuario = this._ins.porId.get(id);
    if (!usuario) return false;

    const passwordHash = password ? hashPassword(password) : usuario.passwordHash;
    const nuevoRole = role ?? usuario.role;
    const nuevoActivo = activo !== undefined ? activo : usuario.activo;

    this._ins.actualizar.run(passwordHash, nuevoRole, nuevoActivo, usuario.lastLogin, id);
    return true;
  }

  /**
   * Borra un usuario.
   *
   * @param {string} id
   * @returns {boolean}
   */
  borrar(id) {
    return this._ins.borrar.run(id).changes > 0;
  }

  /**
   * Cuenta usuarios totales.
   *
   * @returns {number}
   */
  contar() {
    const r = this._ins.contar.get();
    return r?.n || 0;
  }

  /**
   * Cierra la conexión.
   */
  cerrar() {
    try { this.db.close(); } catch {}
  }
}

let instancia = null;

/**
 * Obtiene la instancia singleton.
 * @param {object} [opciones]
 * @returns {Usuarios}
 */
function obtenerUsuarios(opciones = {}) {
  if (!instancia) instancia = new Usuarios(opciones);
  return instancia;
}

function cerrarUsuarios() {
  if (instancia) instancia.cerrar();
  instancia = null;
}

module.exports = { Usuarios, obtenerUsuarios, cerrarUsuarios, nuevoId, RUTA_POR_DEFECTO };