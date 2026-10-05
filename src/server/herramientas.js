/**
 * herramientas.js — Descubrimiento de las herramientas de src/tools.
 *
 * MODULO DE CONVENcion. El servidor NO mantiene una lista de herramientas.
 * Cada archivo en `src/tools/` que exporte `id`, `titulo` y `ejecutar` se
 * ofrece automaticamente en la web y en la API. Escribir una herramienta nueva
 * no obliga a tocar el servidor, la API ni el HTML: es dejar el archivo.
 *
 * Una lista fija se desincroniza en cuanto alguien anade una herramienta y se
 * olvida de registrarla, y entonces aparece en la CLI y no en la web, o al
 * reves, sin que nada avise.
 *
 * Aqui solo se expone la DESCRIPCION. La funcion `ejecutar` no se manda al
 * navegador: el formulario se construye a partir de `campos`, de modo que el
 * cliente no necesita ningun JavaScript especifico por herramienta.
 *
 * @module server/herramientas
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DIR_TOOLS = path.join(__dirname, '..', 'tools');

/** Claves que un modulo debe exportar para considerarse una herramienta. */
const REQUISITOS = ['id', 'titulo', 'ejecutar'];

/**
 * Un descriptor publico de herramienta: lo que el navegador puede ver.
 *
 * Se construye con una lista blanca de claves en lugar de quitar las privadas,
 * porque si manana se exporta algo nuevo en la herramienta, lo que no este en
 * la lista no puede colarse por accidente.
 *
 * @param {object} modulo
 * @returns {{id: string, titulo: string, descripcion: string, icon: string, sinRed: boolean, campos: object[]}}
 */
function descriptor(modulo) {
  return {
    id: modulo.id,
    titulo: modulo.titulo,
    descripcion: modulo.descripcion || '',
    icon: modulo.icon || '',
    sinRed: modulo.sinRed === true,
    campos: Array.isArray(modulo.campos) ? modulo.campos : []
  };
}

/**
 * Carga todas las herramientas disponibles.
 *
 * Un archivo que no cumple los requisitos se salta con un aviso en vez de
 * tumbar el arranque: un error de sintaxis en una herramienta recien escrita no
 * debe dejar la web entera sin arrancar, porque las demas siguen siendo validas.
 *
 * @param {object} [opciones]
 * @param {string} [opciones.dir] Carpeta de herramientas. Por defecto src/tools.
 * @returns {{herramientas: object[], avisos: string[]}}
 */
function cargar(opciones = {}) {
  const dir = opciones.dir || DIR_TOOLS;
  const herramientas = [];
  const avisos = [];

  let entradas = [];
  try {
    entradas = fs.readdirSync(dir).filter((n) => n.endsWith('.js'));
  } catch {
    avisos.push(`No se pudo leer la carpeta de herramientas: ${dir}`);
    return { herramientas, avisos };
  }

  for (const nombre of entradas.sort()) {
    const ruta = path.join(dir, nombre);

    let modulo;
    try {
      modulo = require(ruta);
    } catch (e) {
      avisos.push(`${nombre}: no se pudo cargar (${e.message}). Se omite.`);
      continue;
    }

    const falta = REQUISITOS.filter((k) => modulo[k] === undefined);
    if (falta.length) {
      avisos.push(`${nombre}: no es una herramienta, le falta ${falta.join(', ')}. Se omite.`);
      continue;
    }

    if (typeof modulo.ejecutar !== 'function') {
      avisos.push(`${nombre}: "ejecutar" no es una funcion. Se omite.`);
      continue;
    }

    herramientas.push({ ...descriptor(modulo), modulo });
  }

  // Por id, no por posicion: las rutas van por nombre en la URL y en la base
  // de datos, y ese nombre no puede depender de como se ordenaron los archivos.
  herramientas.sort((a, b) => a.id.localeCompare(b.id));

  return { herramientas, avisos };
}

let cache = null;

/**
 * Registro de herramientas del proceso, cargado una vez.
 *
 * @param {object} [opciones] Se pasan a {@link cargar}.
 * @returns {{herramientas: object[], avisos: string[]}}
 */
function registro(opciones = {}) {
  if (!cache) cache = cargar(opciones);
  return cache;
}

/** Vacia la cache. Lo usan las pruebas al cambiar los archivos de herramientas. */
function limpiarCache() {
  cache = null;
}

/**
 * Busca una herramienta por su id.
 *
 * @param {string} id
 * @returns {object|null}
 */
function obtener(id) {
  const idBuscado = String(id || '').toLowerCase();
  return registro().herramientas.find((h) => h.id === idBuscado) || null;
}

/**
 * Lista publica, sin la referencia al modulo.
 *
 * @returns {object[]}
 */
function listar() {
  return registro().herramientas.map((h) => descriptor(h));
}

module.exports = { cargar, registro, obtener, listar, descriptor, limpiarCache, DIR_TOOLS };
