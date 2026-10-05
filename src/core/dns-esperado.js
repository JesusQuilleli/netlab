'use strict';

/**
 * src/core/dns-esperado.js — Lee un archivo de texto con el estado esperado
 * de una zona y lo convierte en algo comparable.
 *
 * Hay dos formatos en circulación, y los dos aparecen en la práctica:
 *
 *   1. Exportación de zona BIND, que es lo que descarga Cloudflare. Cada línea
 *      es `nombre TTL clase TIPO datos`, con comentarios que empiezan por `;`.
 *      Los TXT van entre comillas y llegan partidos en varias cadenas.
 *
 *   2. Un texto de ticket, escrito a mano, con `Nombre:`, `Valor:` y
 *      `Prioridad:` bajo un título que dice de qué registro se trata.
 *
 * El módulo no adivina: mira cuál de los dos reconoce y avisa si no entiende
 * el archivo. Un parser que se inventa registros produce un informe que dice
 * "coincide" porque no ha comparado nada, y eso es peor que un error claro.
 */

/** Tipos que se pueden verificar. PTR queda fuera: necesita una IP, no un nombre. */
const TIPOS_VERIFICABLES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'SRV'];

/** Cuántos caracteres de un valor largo se muestran completos en el informe. */
const RECORTE = 120;

/* ------------------------------------------------------------------ *
 * Normalización
 * ------------------------------------------------------------------ */

/**
 * Un nombre de DNS no depende de que termine en punto ni de las mayúsculas:
 * `Ejemplo.COM.` y `ejemplo.com` son el mismo nombre. Sin esto, medio archivo
 * se marcaría como diferente cuando no lo es.
 *
 * @param {string} nombre
 * @returns {string}
 */
function normalizarNombre(nombre) {
  return String(nombre ?? '')
    .trim()
    .replace(/\.$/, '')
    .toLowerCase();
}

/**
 * Quita las comillas de un TXT y concatena sus trozos sin separador, que es lo
 * que dice el RFC: las cadenas de un mismo TXT forman un único valor. Unir con
 * espacios produce un registro distinto e imposible de validar.
 *
 * @param {string} bruto
 * @returns {string}
 */
function limpiarTxt(bruto) {
  const partes = String(bruto).match(/"([^"]*)"/g);
  if (partes) return partes.map((p) => p.slice(1, -1)).join('');
  return String(bruto).replace(/^"+|"+$/g, '');
}

/**
 * Deja un registro en una forma única, comparable y legible.
 *
 * @param {string} tipo
 * @param {string} valor Datos del registro, sin el tipo delante.
 * @param {number|null} [prioridad]
 * @returns {string}
 */
function normalizarValor(tipo, valor, prioridad = null) {
  const bruto = String(valor ?? '').trim();
  switch (tipo) {
    case 'TXT':
      return limpiarTxt(bruto);
    case 'MX':
      return `${prioridad ?? '?'} ${normalizarNombre(bruto)}`;
    case 'SRV': {
      // El SRV llega en dos formas según de dónde venga: con la prioridad
      // dentro (`10 5 587 smtp.`) o separada, como el resto de formatos. Si se
      // supone una de las dos y llega la otra, los campos se desplazan y se
      // comparan `10 587 smtp` contra `10 5 587 smtp`, que nunca cuadra.
      const p = bruto.split(/\s+/).filter(Boolean);
      const [prio, peso, puerto, destino] = prioridad !== null && p.length === 3
        ? [prioridad, p[0], p[1], p[2]]
        : [p[0] ?? '?', p[1] ?? 0, p[2] ?? '?', p[3] ?? ''];
      return `${prio} ${peso} ${puerto} ${normalizarNombre(destino)}`.trim();
    }
    case 'SOA': {
      // mname rname serial refresh retry expire minimum
      const p = bruto.split(/\s+/).filter(Boolean);
      if (p.length >= 2) return `${normalizarNombre(p[0])} ${normalizarNombre(p[1])} ${p.slice(2).join(' ')}`;
      return bruto.toLowerCase();
    }
    case 'CAA':
      // flags tag "value"
      return bruto.replace(/^(\d+)\s+(\S+)\s+(.*)$/, (_, flags, tag, valor) => `${flags} ${tag.toLowerCase()} ${valor.toLowerCase()}`);
    case 'NS':
    case 'CNAME':
      return normalizarNombre(bruto);
    case 'A':
    case 'AAAA':
      return bruto;
    default:
      return bruto;
  }
}

/** Recorta un valor largo para no reventar una celda de tabla. */
function recortar(texto, limite = RECORTE) {
  const t = String(texto ?? '');
  return t.length <= limite ? t : `${t.slice(0, limite - 1)}…`;
}

/* ------------------------------------------------------------------ *
 * Detección
 * ------------------------------------------------------------------ */

/**
 * Reconoce el formato por su propia estructura, sin mirar el nombre del
 * archivo: un `berakah.com.ve.txt` no dice nada, su contenido sí.
 *
 * @param {string} texto
 * @returns {'ticket'|'bind'|null}
 */
function detectarFormato(texto) {
  const t = String(texto ?? '');
  if (!t.trim()) return null;
  // El ticket tiene etiquetas `Nombre:` en la línea, que ninguna zona BIND tiene.
  if (/^\s*Nombre\s*:/im.test(t)) return 'ticket';
  // La zona BIND tiene al menos una línea con la clase `IN` y un tipo conocido.
  // El TTL es opcional: hay exportaciones que lo quitan, y exigirlo hacía que
  // un archivo perfectamente válido se rechazara entero.
  if (/^\S+\s+(?:\d+\s+)?(?:IN|CH|HS)\s+(A|AAAA|CNAME|MX|NS|TXT|SOA|CAA|SRV|PTR)\s+/im.test(t)) return 'bind';
  return null;
}

/* ------------------------------------------------------------------ *
 * Formato ticket
 * ------------------------------------------------------------------ */

/**
 * Lee el formato de ticket: un título que dice el tipo y luego `Nombre:`,
 * `Valor:` y, en los MX, `Prioridad:`.
 *
 * @param {string} texto
 * @returns {{registros: object[], avisos: string[]}}
 */
function parsearTicket(texto) {
  const registros = [];
  const avisos = [];
  let tipo = null;
  let nombre = null;
  let prioridad = null;
  // El bloque abierto que todavía no ha recibido su `Valor:`. Sin esta marca,
  // abrir un bloque nuevo parece siempre un bloque a medias y el archivo
  // entero sale con cinco avisos falsos de "se anuncia pero no llega a tener
  // valor", uno por cada registro que sí está completo.
  let pendiente = null;

  const limpiar = (v) =>
    String(v ?? '')
      .trim()
      .replace(/^`+|`+$/g, '')
      .trim();

  const cerrar = () => {
    if (pendiente) avisos.push(`"${pendiente.nombre}" (${pendiente.tipo}) se anuncia pero no llega a tener valor.`);
    pendiente = null;
  };

  for (const linea of String(texto).split(/\r?\n/)) {
    // El título de cada bloque: `**Registro TXT** para el DKIM:`
    const titulo = linea.match(/\*\*(?:registro|record)\s+([A-Z]+)\*\*/i) || linea.match(/\b(?:registro|record)\s+([A-Z]+)\b/i);
    if (titulo) {
      cerrar();
      tipo = titulo[1].toUpperCase();
      nombre = null;
      prioridad = null;
      pendiente = { tipo, nombre: null };
      continue;
    }

    const campoNombre = linea.match(/(?:^|[\s*\-*\d.]+)Nombre\s*:\s*(.+)$/i);
    if (campoNombre) {
      nombre = normalizarNombre(limpiar(campoNombre[1]));
      if (pendiente) pendiente.nombre = nombre;
      continue;
    }

    const campoPrioridad = linea.match(/(?:^|[\s*\-*\d.]+)Prioridad\s*:\s*(.+)$/i);
    if (campoPrioridad) {
      prioridad = Number.parseInt(limpiar(campoPrioridad[1]), 10);
      if (Number.isNaN(prioridad)) prioridad = null;
      continue;
    }

    const campoValor = linea.match(/(?:^|[\s*\-*\d.]+)Valor\s*:\s*(.+)$/i);
    if (campoValor) {
      if (!tipo) {
        avisos.push('Hay un "Valor:" sin título que diga el tipo. Se ignora.');
        continue;
      }
      if (!nombre) {
        avisos.push(`Un "Valor:" de tipo ${tipo} no tiene "Nombre:" delante. Se ignora.`);
        continue;
      }
      const bruto = limpiar(campoValor[1]);
      registros.push({
        nombre,
        tipo,
        // En el ticket el tipo puede venir dentro del propio título ("Registro
        // MX") pero el valor solo trae el host, sin la prioridad.
        prioridad,
        valor: bruto,
        normalizado: normalizarValor(tipo, bruto, prioridad),
        linea: 0
      });
      pendiente = null;
      continue;
    }
  }

  cerrar();

  return { registros, avisos };
}

/* ------------------------------------------------------------------ *
 * Formato BIND
 * ------------------------------------------------------------------ */

/**
 * Lee una exportación de zona BIND.
 *
 * @param {string} texto
 * @returns {{registros: object[], avisos: string[]}}
 */
function parsearBind(texto) {
  const registros = [];
  const avisos = [];
  let ignoradas = 0;

  const lineas = String(texto).split(/\r?\n/);

  lineas.forEach((linea, indice) => {
    const numero = indice + 1;
    const recortada = linea.trim();

    // Comentarios y líneas vacías.
    if (!recortada || recortada.startsWith(';')) return;

    // `nombre [ttl] [clase] TIPO datos`
    const m = recortada.match(/^(\S+)\s+(?:(\d+)\s+)?(?:IN|CH|HS)\s+([A-Z]+)\s*(.*)$/i);
    if (!m) {
      ignoradas++;
      return;
    }

    const [, nombreCrudo, , tipoCrudo, resto] = m;
    const tipo = tipoCrudo.toUpperCase();

    if (!TIPOS_VERIFICABLES.includes(tipo)) {
      // PTR y los tipos raros no se pueden comprobar sin saber la IP de origen.
      ignoradas++;
      return;
    }

    // Los comentarios de Cloudflare vienen detrás de `;`, pero en los TXT el
    // punto y coma puede ser parte del valor, así que solo se corta si lo que
    // sigue no parece contenido.
    let datos = resto.trim();
    if (tipo !== 'TXT') {
      const corte = datos.indexOf(' ;');
      if (corte >= 0) datos = datos.slice(0, corte).trim();
    }

    const nombre = normalizarNombre(nombreCrudo);

    // MX lleva la prioridad delante; SRV lleva prioridad, peso y puerto.
    let prioridad = null;
    if (tipo === 'MX') {
      const p = datos.split(/\s+/);
      prioridad = Number.parseInt(p[0], 10);
      if (Number.isNaN(prioridad)) prioridad = null;
      datos = p.slice(1).join(' ');
    } else if (tipo === 'SRV') {
      prioridad = Number.parseInt(datos.split(/\s+/)[0], 10);
      if (Number.isNaN(prioridad)) prioridad = null;
    }

    if (!datos) {
      avisos.push(`Línea ${numero}: el registro ${tipo} de ${nombre} no trae valor.`);
      return;
    }

    registros.push({
      nombre,
      tipo,
      prioridad,
      valor: datos,
      normalizado: normalizarValor(tipo, datos, prioridad),
      linea: numero
    });
  });

  if (ignoradas) {
    avisos.push(
      `${ignoradas} línea(s) ignoradas: tipos que no se pueden verificar (PTR y otros) o formato no reconocido.`
    );
  }

  return { registros, avisos };
}

/* ------------------------------------------------------------------ *
 * API
 * ------------------------------------------------------------------ */

/**
 * Parsea el archivo y devuelve el estado esperado listo para comparar.
 *
 * @param {string} texto Contenido del archivo.
 * @returns {{formato: string|null, registros: object[], avisos: string[], nombres: string[]}}
 */
function parsear(texto) {
  const formato = detectarFormato(texto);
  const base = formato ? (formato === 'bind' ? parsearBind(texto) : parsearTicket(texto)) : { registros: [], avisos: [] };

  const avisos = [...base.avisos];
  if (!formato) {
    avisos.push(
      'No se reconoce el formato del archivo. Se admiten una exportación de zona BIND (la que descarga Cloudflare) o un texto con líneas "Nombre:" y "Valor:".'
    );
  }

  // Se dedupican: un archivo con la misma línea repetida no debe generar
  // avisos duplicados, solo comparar dos veces lo mismo.
  const vistos = new Set();
  const registros = [];
  for (const r of base.registros) {
    const clave = `${r.nombre}|${r.tipo}|${r.normalizado}`;
    if (vistos.has(clave)) continue;
    vistos.add(clave);
    registros.push(r);
  }

  const nombres = [...new Set(registros.map((r) => r.nombre))].sort();

  return {
    formato,
    registros,
    avisos,
    nombres,
    porNombre: registros.reduce((acc, r) => {
      (acc[r.nombre] ||= []).push(r);
      return acc;
    }, {})
  };
}

module.exports = {
  parsear,
  detectarFormato,
  normalizarNombre,
  normalizarValor,
  limpiarTxt,
  recortar,
  TIPOS_VERIFICABLES
};
