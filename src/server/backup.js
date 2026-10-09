/**
 * backup.js — Copia de seguridad periodica de la base de datos.
 *
 * MODULO DE MANTENIMIENTO. Copia `data/netlab.db` a `data/backups/` con
 * `VACUUM INTO`, que produce una instantanea consistente en un solo fichero sin
 * importar que la base este en modo WAL ni que haya escrituras en marcha. Es la
 * misma tecnica que usaria un `sqlite3 .backup`: copiar el fichero a pelo
 * dejaria media transaccion.
 *
 * EL SITIO DEL BACKUP. Se guarda dentro de `data/`, justo donde el servicio
 * systemd permite escribir (`ReadWritePaths=/opt/netlab/data`); un backup fuera
 * de ahi se caeria en el primer reinicio y nadie se enteraria. `data/` no se
 * versiona, y eso esta bien: una copia del dia dentro de un servidor no es lo
 * mismo que un backup fuera de el. El respaldo periodico de la VPS entera (o de
 * `data/`) es cosa del operador; aqui se cubre lo que la aplicacion puede cubrir
 * sola: que un borrado o una corrupcion de la base no se coma el historial.
 *
 * CUANDO SE EJECUTA. `programar()` dispara una copia inmediata al arrancar (asi
 * siempre hay una aunque el servidor no pase por su hora) y luego una al dia a
 * la hora configurable, por defecto las tres de la manana que es cuando menos
 * uso hay. La retencion se aplica en cada copia: se guardan las ultimas N, por
 * defecto siete (una por dia), y el resto se borra. Con eso el disco no crece
 * sin limite y siempre hay una semana para volver atras.
 *
 * @module server/backup
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { NetlabError, CODES } = require('../core/errors');

const RUTA_POR_DEFECTO = path.join(process.cwd(), 'data', 'netlab.db');
const RETENCION_POR_DEFECTO = 7;
const HORA_POR_DEFECTO = 3;
const MIN_INTERVALO_MS = 60_000;

/**
 * Cuando toca el proximo disparo.
 *
 * La hora se entiende en la zona local del servidor, que es la que usa el
 * sistema de ficheros y la que ve quien opera la maquina. Si esa hora ya paso
 * hoy, el disparo es manana, no dentro de veinticuatro horas desde "ahora": un
 * servidor que se reinicia a las diez no debe pasarse al respaldo de la una.
 *
 * @param {Date} ahora
 * @param {number} hora 0-23.
 * @returns {Date}
 */
function siguienteDisparo(ahora, hora) {
  const objetivo = new Date(ahora);
  objetivo.setHours(
    Math.max(0, Math.min(23, Math.trunc(hora) || 0)),
    0,
    0,
    0
  );
  if (objetivo.getTime() <= ahora.getTime()) {
    objetivo.setDate(objetivo.getDate() + 1);
  }
  return objetivo;
}

/** `netlab-20261009-030000.sqlite`, legible y ordenable de mas nueva a mas vieja. */
function nombreDeArchivo(ahora = new Date()) {
  const dos = (n) => String(n).padStart(2, '0');
  return `netlab-${ahora.getFullYear()}${dos(ahora.getMonth() + 1)}${dos(ahora.getDate())}` +
    `-${dos(ahora.getHours())}${dos(ahora.getMinutes())}${dos(ahora.getSeconds())}.sqlite`;
}

class Backup {
  /**
   * @param {object} [opciones]
   * @param {string} [opciones.ruta] Ruta de la base de origen.
   * @param {string} [opciones.directorio] Donde se guardan las copias.
   * @param {number} [opciones.retencion=7] Copias que se conservan.
   * @param {string|number} [opciones.hora=3] Hora local del disparo diario.
   * @param {(e: Error) => void} [opciones.avisar] Quien se entera de un fallo.
   */
  constructor(opciones = {}) {
    this.ruta = opciones.ruta || RUTA_POR_DEFECTO;
    this.directorio = opciones.directorio || path.join(path.dirname(this.ruta), 'backups');
    this.retencion = Math.max(1, Math.trunc(Number(opciones.retencion ?? RETENCION_POR_DEFECTO)) || RETENCION_POR_DEFECTO);
    this.hora = Math.max(0, Math.min(23, Math.trunc(Number(opciones.hora ?? HORA_POR_DEFECTO)) || HORA_POR_DEFECTO));
    this.avisar = opciones.avisar || null;
    this._temporizador = null;
  }

  /**
   * Lista las copias existentes, de la mas nueva a la mas vieja.
   *
   * @returns {{nombre: string, ruta: string, tamano: number, creadoEn: string}[]}
   */
  listar() {
    if (!fs.existsSync(this.directorio)) return [];
    return fs
      .readdirSync(this.directorio)
      .filter((f) => f.endsWith('.sqlite'))
      .map((nombre) => {
        const ruta = path.join(this.directorio, nombre);
        const stat = fs.statSync(ruta);
        return { nombre, ruta, tamano: stat.size, creadoEn: stat.mtime.toISOString() };
      })
      .sort((a, b) => (a.creadoEn < b.creadoEn ? 1 : -1));
  }

  /**
   * Hace una copia ahora mismo y aplica la retencion.
   *
   * @returns {{nombre: string, ruta: string, tamano: number, creadoEn: string}}
   */
  hacer() {
    if (!fs.existsSync(this.ruta)) {
      throw new NetlabError(CODES.FICHERO_NO_ENCONTRADO, `La base de datos ${this.ruta} no existe: no hay nada que respaldar.`, {
        remediation: 'Aun no se ha guardado nada en el historial. Ejecuta una herramienta primero.'
      });
    }

    fs.mkdirSync(this.directorio, { recursive: true });

    // VACUUM INTO falla si el destino ya existe; el nombre lleva segundos, asi
    // que dos copias en el mismo segundo solo pasan si se aproximan a mano. El
    // fallo seria confuso, asi que se avisa antes de intentarlo.
    const destino = path.join(this.directorio, nombreDeArchivo());
    if (fs.existsSync(destino)) {
      const stat = fs.statSync(destino);
      return { nombre: path.basename(destino), ruta: destino, tamano: stat.size, creadoEn: stat.mtime.toISOString() };
    }

    const { DatabaseSync } = require('node:sqlite');
    const db = new DatabaseSync(this.ruta, { readOnly: true });
    try {
      fs.mkdirSync(this.directorio, { recursive: true });
      db.exec(`VACUUM INTO '${destino}'`);
    } finally {
      db.close();
    }

    this._purgar();

    const stat = fs.statSync(destino);
    return { nombre: path.basename(destino), ruta: destino, tamano: stat.size, creadoEn: stat.mtime.toISOString() };
  }

  /**
   * Programa la copia diaria y hace la inmediata de arranque.
   *
   * @returns {this}
   */
  programar() {
    if (this._temporizador) return this;

    // Al arrancar siempre hay una copia, aunque la hora programada este lejos.
    // Si la base todavia no existe (instalacion fresca, nadie ha ejecutado nada)
    // no hay nada que copiar y no es un fallo: el temporizador igual se arma.
    if (fs.existsSync(this.ruta)) {
      try {
        this.hacer();
      } catch (e) {
        this.avisar?.(e);
      }
    }

    const alDiaSiguiente = () => {
      const espera = siguienteDisparo(new Date(), this.hora).getTime() - Date.now();
      this._temporizador = setTimeout(() => {
        try {
          this.hacer();
        } catch (e) {
          this.avisar?.(e);
        }
        alDiaSiguiente();
      }, espera);
      this._temporizador.unref?.();
    };
    alDiaSiguiente();

    return this;
  }

  /** Detiene el temporizador; deja las copias ya hechas. */
  detener() {
    if (this._temporizador) clearTimeout(this._temporizador);
    this._temporizador = null;
  }

  /** Borra hasta quedarse con las `retencion` mas recientes. */
  _purgar() {
    const copias = this.listar();
    const sobrantes = copias.slice(this.retencion);
    for (const sobra of sobrantes) {
      try {
        fs.unlinkSync(sobra.ruta);
      } catch {
        // Una copia que ya no exista (borrada a mano) no tiene que tumbar el resto.
      }
    }
    return sobrantes.length;
  }
}

module.exports = { Backup, siguienteDisparo, nombreDeArchivo, RUTA_POR_DEFECTO, RETENCION_POR_DEFECTO };