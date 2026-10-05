/**
 * abuseipdb.js — Cliente de la API de AbuseIPDB.
 *
 * MODULO DE RED. Traduce la respuesta cruda de la API a algo presentable:
 * categorias con nombre, fechas legibles y una lectura del riesgo que no se
 * base solo en un numero.
 *
 * DOS COSAS QUE legacy/ HACIA MAL Y AQUI NO:
 *
 * 1. `maxAgeInDays` valia 5. Es una ventana tan corta que una IP con veinte
 *    avisos se ve limpia si el ultimo fue hace seis dias. El valor por defecto
 *    de la API son 30 dias, que es lo que usa el panel, y aqui tambien.
 *
 * 2. El informe solo miraba `totalReports` y pintaba la puntuacion en rojo o
 *    verde segun pasara de 50. Eso confunde dos cosas distintas: cuantos
 *    avisos hay, y cuantos/USUOS DISTINTOS los han puesto. Cincuenta avisos de
 *    un mismo repetidor no es lo mismo que cinco de cinco redes distintas, que
 *    es el caso que de verdad conviene mirar. Por eso `consultar()` devuelve
 *    los dos numeros y el diagnostico los pondera.
 *
 * Y un criterio que se aplica a todos los campos de aqui:
 *
 * 3. Un dato que no llega sale como `null`, nunca como su valor por defecto. Los
 *    tres numeros que deciden el veredicto se leian cada uno a su manera, y las
 *    tres formas fallaban: `Number(totalReports) || 0` convertia un campo
 *    ausente en un cero, de modo que una IP con nueve autores distintos y 100 %
 *    de abuso salia en el informe como si no tuviera ni un aviso. Es el fallo
 *    mas grave que ha tenido este modulo, y solo se ve cuando la API responde
 *    algo que no esperabas. Ver `numeroODesconocido`.
 *
 * @module core/net/abuseipdb
 */

'use strict';

const { getJSON } = require('./http');
const ipaddr = require('./ipaddr');
const { NetlabError, CODES } = require('../errors');

const BASE = 'https://api.abuseipdb.com/api/v2/check';

/**
 * Catalogo de categorias de AbuseIPDB.
 *
 * DELIBERADAMENTE INCOMPLETO. Y esto es una decision, no una oubli.
 *
 * legacy/ tenia trece entradas sueltas y el resto salia como "Unknown (88)",
 * que es como un tecnico pierde el tiempo: si la categoria importa para decidir,
 * tiene que tener nombre.
 *
 * Se comprobó que un catalogo escrito de memoria no sirve: aparecen
 * identificadores que no existen y nombres inventados, y el resultado es peor
 * que no traducir nada, porque un informe etiquetado con una categoria falsa
 * dirige a quien lo lee hacia la pista equivocada sin avisarle de nada.
 *
 * Lo que hay aqui son solo los identificadores que se han podido confirmar en
 * la documentacion del proveedor o en el reporte historico de legacy/. El
 * listado completo esta en la documentacion de AbuseIPDB y debe copiarse de
 * ahi, no de memoria.
 *
 * Un identificador sin entrada sale como "Categoria {id}". Es feo, y es
 * deliberado: delata que falta la traduccion en vez de mentir sobre ella.
 */
const CATEGORIAS = {
  3: 'Fraude',
  4: 'Ataque DDoS',
  9: 'Proxy abierto',
  10: 'Spam web',
  11: 'Spam por correo',
  14: 'Escaneo de puertos',
  15: 'Intrusión / hackeo',
  18: 'Fuerza bruta',
  19: 'Bot web malicioso',
  20: 'Equipo explotado',
  21: 'Ataque a aplicación web',
  22: 'Ataque por SSH',
  23: 'Dispositivo IoT atacado'
};

/** Cantidad de identificadores con nombre propio. */
const COBERTURA_CATALOGO = Object.keys(CATEGORIAS).length;

/**
 * Devuelve el nombre de una categoria.
 *
 * @param {number} id
 * @returns {string} El nombre, o "Categoria {id}" si no esta en el catalogo.
 */
function nombreCategoria(id) {
  return CATEGORIAS[id] || `Categoria ${id}`;
}

/** Tipos de uso declarados por la API, con su lectura en espanol. */
const TIPOS_USO = {
  'Data Center': 'Centro de datos',
  Hosting: 'Alojamiento',
  ISP: 'Proveedor de servicios',
  Education: 'Educacion',
  Government: 'Organismo publico',
  Commercial: 'Corporativo',
  Military: 'Militar',
  Trust: 'Infraestructura de confianza',
  Reseller: 'Distribuidor',
  'Content Delivery Network': 'Red de entrega de contenidos',
  'Mobile Network': 'Red movil',
  Reserved: 'Reservado'
};

/**
 * Lee un numero de la respuesta distinguiendo "cero" de "no ha llegado".
 *
 * Existe por un fallo concreto. Los tres numeros que deciden el veredicto se
 * leian de tres maneras distintas: `totalReports` con `Number(x) || 0`, que
 * convierte un campo ausente en un cero, y los otros dos con
 * `Number.isFinite(x)`, que descarta un numero legitimo que llegue como texto.
 * Cada forma estaba bien para su campo y mal para el de al lado.
 *
 * Aqui hay un solo criterio: lo que no se puede leer como numero es `null`, que
 * es "no lo se", y nunca un 0, que es "lo se y es cero". Confundir las dos cosas
 * hace que una IP con nueve autores distintos y 100 % de AbuseIPDB salga en el
 * informe como si no tuviera ni un aviso, porque el campo del total no llego.
 *
 * @param {*} valor
 * @returns {number|null}
 */
function numeroODesconocido(valor) {
  if (valor === null || valor === undefined || valor === '') return null;
  if (typeof valor === 'boolean') return null;
  const n = typeof valor === 'string' ? Number(valor.trim()) : valor;
  return Number.isFinite(n) ? n : null;
}

/** Igual que `numeroODesconocido`, pero para un campo que es si o no. */
function booleanoODesconocido(valor) {
  if (valor === null || valor === undefined || valor === '') return null;
  return Boolean(valor);
}

/**
 * Compara dos direcciones sin que la notacion IPv6 las confunda.
 *
 * La API devuelve `2001:0db8:0000:...:0001` donde el usuario ha escrito
 * `2001:db8::1`. Comparar las cadenas a pelo daria dos direcciones distintas y
 * tumbar una consulta que era correcta.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function mismaIp(a, b) {
  const ta = String(a).trim();
  const tb = String(b).trim();
  if (ta.toLowerCase() === tb.toLowerCase()) return true;
  // `expandirIPv6` conserva las mayusculas del hexadecimal que le llega, asi
  // que la misma direccion comprimida y expandida sale con distinta caja. Sin
  // bajar las dos, `2001:db8::1` y `2001:0DB8::1` parecieran dos IPs.
  const ca = String(ipaddr.comprimirIPv6(ta) || '').toLowerCase();
  const cb = String(ipaddr.comprimirIPv6(tb) || '').toLowerCase();
  return ca !== '' && ca === cb;
}

/**
 * Traduce una lista de identificadores de categoria a texto legible.
 *
 * @param {number[]} ids
 * @returns {string}
 */
function traducirCategorias(ids = []) {
  if (!ids.length) return 'Sin especificar';
  return ids.map(nombreCategoria).join(', ');
}

/**
 * Cuenta cuantas veces aparece cada categoria.
 *
 * @param {Array<{categories: number[]}>} reportes
 * @returns {Array<{id: number, nombre: string, veces: number}>} De mas a menos veces.
 */
function resumirCategorias(reportes = []) {
  const cuenta = new Map();
  for (const reporte of reportes) {
    for (const id of reporte?.categories || []) {
      cuenta.set(id, (cuenta.get(id) || 0) + 1);
    }
  }
  return [...cuenta.entries()]
    .map(([id, veces]) => ({ id, nombre: nombreCategoria(id), veces }))
    .sort((a, b) => b.veces - a.veces || a.id - b.id);
}

/**
 * Formatea una marca de tiempo ISO en algo legible y sin ambiguedad.
 *
 * legacy/ usaba `toLocaleDateString` con el reloj del servidor, asi que el
 * mismo informe salia con fecha distinta seguiendo la zona horaria de quien lo
 * generaba. Aqui se fija a UTC y se dice explicitamente, que es lo que se puede
 * comparar luego con un registro de AbuseIPDB.
 *
 * @param {string|null} iso
 * @returns {string}
 */
function formatearFecha(iso) {
  if (!iso) return 'Sin datos';
  const fecha = new Date(iso);
  if (Number.isNaN(fecha.getTime())) return 'Fecha ilegible';
  const dosDig = (n) => String(n).padStart(2, '0');
  return (
    `${fecha.getUTCFullYear()}-${dosDig(fecha.getUTCMonth() + 1)}-${dosDig(fecha.getUTCDate())} ` +
    `${dosDig(fecha.getUTCHours())}:${dosDig(fecha.getUTCMinutes())} UTC`
  );
}

/**
 * Consulta una IP en AbuseIPDB.
 *
 * @param {string} ip
 * @param {object} [opciones]
 * @param {string} opciones.clave API key. Obligatoria.
 * @param {number} [opciones.maxAgeInDays=30] Ventana de busqueda.
 * @param {boolean} [opciones.detallado=true] `verbose`: trae la lista de reportes.
 * @param {number} [opciones.timeoutMs]
 * @param {Function} [opciones.fetchImpl] Doble para las pruebas.
 * @param {string} [opciones.host] Endpoint, por si hace falta uno de pruebas.
 * @returns {Promise<object>} Datos ya normalizados.
 * @throws {NetlabError}
 */
async function consultar(ip, opciones = {}) {
  const { clave, maxAgeInDays = 30, detallado = true, timeoutMs, fetchImpl, host = BASE } = opciones;

  if (!clave) {
    throw new NetlabError(CODES.CREDENCIAL_AUSENTE, 'No hay clave de AbuseIPDB configurada.', {
      remediation:
        'Define ABUSEIPDB_API_KEY en el .env. Se puede copiar con "node scripts/importar-legacy.js", pero recuerda que esa credencial estaba expuesta y hay que rotarla.'
    });
  }

  // Ojo con el `||`: `Number(0) || 30` devuelve 30, porque 0 es falsy. Con eso,
  // pedir una ventana de 0 dias consultaba 30 en vez del minimo. El valor por
  // defecto se aplica solo cuando no hay numero utilizable.
  const pedido = Number(maxAgeInDays);
  const ventana = Math.min(365, Math.max(1, Math.trunc(Number.isFinite(pedido) ? pedido : 30)));

  const cuerpo = await getJSON({
    url: host,
    query: { ipAddress: ip, maxAgeInDays: ventana, verbose: detallado ? 2 : 0 },
    headers: { Key: clave, Accept: 'application/json' },
    timeoutMs: timeoutMs ?? 15000,
    fetchImpl,
    servicio: 'AbuseIPDB'
  });

  // AbuseIPDB responde 200 con { errors: [...] } cuando el parametro no vale,
  // y tambien cuando la IP es invalida. Es la misma forma de error que un
  // corte de red visto desde fuera, asi que se comprueba aqui.
  if (Array.isArray(cuerpo?.errors) && cuerpo.errors.length) {
    const detalle = cuerpo.errors
      .map((e) => [e?.detail || e?.title, e?.status ? `(${e.status})` : ''].filter(Boolean).join(' '))
      .join('; ');
    throw new NetlabError(CODES.API_EXTERNA, `AbuseIPDB ha rechazado la consulta: ${detalle}`, {
      remediation: 'Comprueba que la IP esta bien escrita. Si es correcta, el problema es de la clave o del servicio.',
      details: { ip, errores: cuerpo.errors }
    });
  }

  const datos = cuerpo?.data;
  if (!datos || typeof datos !== 'object') {
    throw new NetlabError(CODES.API_EXTERNA, 'AbuseIPDB ha devuelto una respuesta sin datos.', {
      remediation: 'La respuesta no tiene el campo "data". Suele ser un cambio en la API; revisa su documentacion.',
      details: { ip, recibido: cuerpo }
    });
  }

const reportes = Array.isArray(datos.reports) ? datos.reports : [];

  // Si la API contesta con datos de otra direccion, el informe hablaria de una
  // IP que nadie ha pedido. Se para aqui en vez de renombrar el resultado: es un
  // fallo del proveedor o una confusion en la cache, y en los dos casos lo que se
  // tiene delante no es una lectura de la IP pedida.
  if (datos.ipAddress && !mismaIp(datos.ipAddress, ip)) {
    throw new NetlabError(CODES.API_EXTERNA, `AbuseIPDB ha respondido con datos de otra direccion: se pidio ${ip} y ha llegado ${datos.ipAddress}.`, {
      remediation:
        'No se usa esta respuesta: seria un informe sobre una IP que no has consultado. Vuelve a intentarlo; si se repite, el dato devuelto no corresponde a la consulta.',
      details: { pedida: ip, recibida: datos.ipAddress }
    });
  }

  return {
    // Se devuelve la que se pidio, no la que vino: si son la misma da igual, y si
    // no lo son ya se ha lanzado el error de arriba.
    ip,
    esPublica: booleanoODesconocido(datos.isPublic),
    esWhitelisted: Boolean(datos.isWhitelisted),
    esMovil: Boolean(datos.isMobile),
    tipoUso: datos.usageType || null,
    tipoUsoEs: TIPOS_USO[datos.usageType] || null,
    isp: datos.isp || null,
    dominio: datos.domain || null,
    codigoPais: datos.countryCode || null,
    nombrePais: datos.countryName || null,
    puntuacionConfianza: numeroODesconocido(datos.abuseConfidenceScore),
    // Los tres numeros que deciden el veredicto. Todos con la misma regla:
    // null es "no lo se", 0 es "lo se y es cero". Ver `numeroODesconocido`.
    totalReportes: numeroODesconocido(datos.totalReports),
    // El dato que legacy/ ignoraba y el que mas cambia la lectura: cuantos
    // autores distintos han puesto un aviso. 40 avisos de una sola red es ruido
    // automatizado; 4 de 4 redes distintas es una señal repartida.
    autoresDistintos: numeroODesconocido(datos.numDistinctUsers),
    ultimoReporte: datos.lastReportedAt || null,
    ultimoReporteTexto: formatearFecha(datos.lastReportedAt),
    ventanaDias: ventana,
    totalEnVentana: reportes.length,
    reportes: reportes.map((r) => ({
      id: r.id,
      fecha: r.reportedAt || null,
      fechaTexto: formatearFecha(r.reportedAt),
      pais: r.reporterCountryCode || null,
      paisNombre: r.reporterCountryName || null,
      categorias: Array.isArray(r.categories) ? r.categories : [],
      categoriasTexto: traducirCategorias(r.categories),
      comentario: r.comment || null
    })),
    resumenCategorias: resumirCategorias(reportes)
  };
}

module.exports = {
  BASE,
  CATEGORIAS,
  COBERTURA_CATALOGO,
  TIPOS_USO,
  consultar,
  nombreCategoria,
  traducirCategorias,
  resumirCategorias,
  formatearFecha,
  numeroODesconocido,
  booleanoODesconocido,
  mismaIp
};
