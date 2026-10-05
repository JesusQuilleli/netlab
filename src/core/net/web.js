/**
 * net/web.js — Comprobar si un sitio web responde, y no dejarse engañar al
 * intentarlo.
 *
 * MODULO NUEVO, Y POR QUE HACE FALTA. Las otras piezas de red ya existen
 * (`dns`, `tcp`, `tls`, `getJSON`), pero ninguna baja una pagina web, y las que
 * bajan no sirven aqui:
 *
 *   - `http.getJSON` pone `Accept: application/json`, no manda User-Agent y no
 *     controla redirecciones. Una pagina pedida como JSON con el User-Agent por
 *     defecto de Node la rechazan sitios de forma rutinaria.
 *   - No hay tope de cuerpo: descargar la pagina entera de un servidor hostil
 *     que dice tenerla de 2 GB es agotamiento de memoria, denial of service
 *     contra la propia herramienta.
 *
 * EL PROBLEMA DE SEGURIDAD, Y POR QUE ESTA EN SU PROPIO ARCHIVO.
 *
 * Netlab corre en local, sin autenticacion, y esta herramienta abre una URL que
 * escribe el usuario. Eso es SSRF (Server-Side Request Forgery) con todas las
 * letras: el navegador de quien la usa dice "pide esto", el servidor lo pide, y
 * el resultado se lo enseña. Sin mas, el modulo sirve para leer
 * `http://169.254.169.254/latest/meta-data/` en una nube y enseñarle las
 * credenciales de la instancia, o para escanear la red interna del cliente y
 * devolverle un mapa de lo que hay.
 *
 * El detalle que hace que esto no se resuelva con una lista de rangos es que la
 * validacion tiene que hacerse en DOS momentos:
 *
 *   1. Antes de conectar, resolviendo el nombre y mirando las direcciones.
 *   2. En CADA redireccion. Un sitio publico que responde 302 hacia
 *      `http://127.0.0.1:8080/admin` pasa intacto por cualquier filtro hecho
 *      solo sobre la URL inicial. Es el bypass clasico, y por eso el cliente usa
 *      `redirect: 'manual'` y repite la comprobacion en cada salto.
 *
 * LO QUE ESTE MODULO NO PUEDE HACER.
 *
 * Entre resolver el nombre y conectarse a la direccion hay una ventana en la
 * que un atacante con control de su DNS puede cambiar la respuesta (DNS
 * rebinding): la direccion se valida publica y al conectar ya es privada.
 * Cerrar eso del todo exige fijar la IP resuelta en el socket, con un
 * dispatcher propio, que es desproporcionado para un diagnostico. Se acepta el
 * riesgo y se deja escrito en el codigo, en vez de dar una falsa sensacion de
 * seguridad.
 *
 * @module core/net/web
 */

'use strict';

const { NetlabError, CODES } = require('../errors');
const ipaddr = require('./ipaddr');

/**
 * Rangos a los que no se conecta sin permiso explicito.
 *
 * `cidr.ESPECIALES` ya lista los de IPv4 (loopback, RFC 1918, enlace local,
 * multicast, documentacion...). Aqui se importan y se ANADEN los de IPv6, que
 * no estaban en ninguna parte del proyecto: sin ellos, `http://[::1]/` y
 * `http://[fe80::1]/` pasaban limpios.
 *
 * Las IPv4 mapeadas en IPv6 (`::ffff:127.0.0.1`) son un caso aparte y no están
 * en la lista como prefijo genérico: van en `esProhibida` porque hay que
 * desenvolverlas antes de compararlas.
 */
const { ESPECIALES: ESPECIALES_V4 } = require('./cidr');

/** Rangos reservados de IPv6 que no son ni privados ni publicos. */
const ESPECIALES_V6 = [
  { cidr: '::/128', nombre: 'Indeterminada' },
  { cidr: '::1/128', nombre: 'Loopback' },
  { cidr: 'fe80::/10', nombre: 'Enlace local' },
  { cidr: 'fc00::/7', nombre: 'Privada unica (ULA)' },
  { cidr: 'fec0::/10', nombre: 'Enlace local obsoleto' },
  { cidr: 'ff00::/8', nombre: 'Multicast' },
  { cidr: '2002::/16', nombre: 'Tunel 6to4' },
  { cidr: '64:ff9b::/96', nombre: 'Traduccion IPv4/IPv6' }
];

/** Prefijo de las IPv4 mapeadas dentro de IPv6. */
const V4_MAPEADA = '::ffff:0:0/96';

/** Todos los rangos prohibidos, IPv4 primero. */
const RANGOS_PROHIBIDOS = [...ESPECIALES_V4, ...ESPECIALES_V6];

/**
 * Puertos que se consideran web.
 *
 * No se imponen: sirven para que la herramienta sepa que puerto mirar cuando la
 * URL no lo trae, y para proponerlos como atajo en la interfaz.
 */
const PUERTOS_WEB = [80, 443, 8080, 8000, 8443, 3000, 5000];

/**
 * Identificarse en cada peticion.
 *
 * Sin esto, los sitios que bloquean bots responden 403 o 429 a un `HEAD`
 * cualquiera, y el informe diria "caida" cuando lo que pasa es que el sitio no
 * quiere hablar con clientes que no se identifican. Es tambien la unica forma
 * de que el operador del sitio sepa que le estan comprobando desde netlab, y no
 * una conexion anonima.
 */
const USER_AGENT = 'netlab/1.0 (+comprobacion de disponibilidad de sitio web)';

/** Cuerpo maximo que se lee de una pagina, en bytes. */
const MAX_CUERPO = 512 * 1024;

/** Tope de redirecciones seguidas en un mismo sondeo. */
const MAX_REDIRECCIONES = 5;

/* ------------------------------------------------------------------ *
 * Direcciones
 * ------------------------------------------------------------------ */

/**
 * ¿Esta direccion cae en algun rango prohibido?
 *
 * `permitirPrivadas` relaja lo que es "una maquina de esta misma red": RFC 1918,
 * ULA y el loopback de la propia maquina (127.0.0.0/8 y ::1), que es lo que
 * necesita alguien probando un sitio en su equipo.
 *
 * NO relaja el enlace local, ni la multicast, ni las direcciones de traduccion.
 * El caso que de verdad se busca es `169.254.169.254`: es la unica direccion de
 * esta lista que un atacante no tiene por que montar, porque sale sola en
 * cualquier nube, y devuelve credenciales. Sigue bloqueada con la casilla
 * activada. Esa asimetria es deliberada.
 *
 * @param {string} ip
 * @param {boolean} [permitirPrivadas=false]
 * @returns {boolean}
 */
function esProhibida(ip, permitirPrivadas = false) {
  const limpio = ipaddr.sinZona(String(ip || '').trim());

  // Una IPv4 mapeada en IPv6 es una IPv4. Sin desenvolverla, `::ffff:127.0.0.1`
  // no cae en 127.0.0.0/8 y dejaria pasar el caso mas obvio de todos.
  const normalizada = esMapeada(limpio) ? aIPv4(limpio) : limpio;
  if (!normalizada) return true;

  const redes = ipaddr.bitsDe(normalizada) === 32 ? ESPECIALES_V4 : ipaddr.bitsDe(normalizada) === 128 ? ESPECIALES_V6 : [];

  for (const rango of redes) {
    // Con el permiso de red privada solo se salta lo que de verdad es privado o
    // local: RFC 1918 y ULA. Loopback, enlace local, multicast y traduccion se
    // respetan siempre, asi que esa lista se filtra aparte.
    if (permitirPrivadas && PRIVATAS.has(rango.cidr)) continue;
    if (ipaddr.contiene(rango.cidr, normalizada)) return true;
  }

  return false;
}

/**
 * Rangos que el permiso de red privada sí permite.
 *
 * Incluye el loopback porque sin él no se podría comprobar un sitio que se está
 * desarrollando en la propia máquina, y porque las pruebas necesitan un servidor
 * local. No incluye el enlace local: ver `esProhibida`.
 */
const PRIVATAS = new Set([
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '127.0.0.0/8',
  '::1/128',
  'fc00::/7'
]);

/** ¿Es una IPv4 metida en un prefijo IPv6 (`::ffff:a.b.c.d`)? */
function esMapeada(ip) {
  const limpio = ipaddr.sinZona(String(ip || ''));
  return Boolean(limpio && ipaddr.bitsDe(limpio) === 128 && ipaddr.contiene(V4_MAPEADA, limpio));
}

/** Saca la IPv4 de una direccion mapeada en IPv6. */
function aIPv4(ip) {
  const bytes = ipaddr.aBytes(ipaddr.sinZona(ip));
  if (!bytes || bytes.length !== 16) return null;
  return bytes.slice(12).join('.');
}

/**
 * Nombre del rango prohibido en el que cae una direccion, para el mensaje.
 *
 * @param {string} ip
 * @param {boolean} [permitirPrivadas=false]
 * @returns {string|null}
 */
function motivoDeBloqueo(ip, permitirPrivadas = false) {
  const limpio = ipaddr.sinZona(String(ip || '').trim());
  const normalizada = esMapeada(limpio) ? aIPv4(limpio) : limpio;
  if (!normalizada) return 'dirección no válida';

  const redes = ipaddr.bitsDe(normalizada) === 32 ? ESPECIALES_V4 : ESPECIALES_V6;
  for (const rango of redes) {
    if (permitirPrivadas && PRIVATAS.has(rango.cidr)) continue;
    if (ipaddr.contiene(rango.cidr, normalizada)) return rango.nombre;
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Validación de la URL
 * ------------------------------------------------------------------ */

/**
 * Limpia lo que el usuario escribe y lo devuelve como URL.
 *
 * La gente escribe `ejemplo.com`, `www.ejemplo.com`, `https://ejemplo.com/path`,
 * `EJEMPLO.COM` y todo eso tiene que acabar en la misma peticion. Se asume
 * `https` porque es lo que se quiere comprobar hoy, y si el sitio solo habla
 * http el sondeo lo dira en vez de fallar por un esquema.
 *
 * @param {string} bruto
 * @returns {URL}
 * @throws {NetlabError} Si no queda una URL utilizable.
 */
function normalizarUrl(bruto) {
  const texto = String(bruto || '').trim();
  if (!texto) {
    throw new NetlabError(CODES.ENTRADA_VACIA, 'No se indicó ninguna dirección.', {
      remediation: 'Escribe el sitio que quieres comprobar, por ejemplo ejemplo.com.'
    });
  }

  // Un esquema explicito se respeta; si no lo hay, se asume https.
  const conEsquema = /^[a-z][a-z0-9+.-]*:\/\//i.test(texto) ? texto : `https://${texto}`;

  let url;
  try {
    url = new URL(conEsquema);
  } catch {
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${texto}" no es una dirección válida.`, {
      remediation: 'Escribe un dominio, como ejemplo.com, o una URL completa como https://ejemplo.com/inicio.'
    });
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `Solo se comprueban direcciones http o https, no "${url.protocol}".`, {
      remediation: 'Una URL con otro esquema (file:, gopher:, ftp:) no es una pagina web que se pueda comprobar desde fuera.'
    });
  }

  // Credenciales en la URL: se rechazan en vez de ignorarse. Aparecen si alguien
  // pega una URL copiada del navegador, y acabarian en el historial y en el
  // informe. Mejor un error claro que un informe con la contraseña del cliente
  // dentro.
  if (url.username || url.password) {
    throw new NetlabError(CODES.PARAM_INVALIDO, 'La dirección no debe llevar usuario ni contraseña.', {
      remediation: 'Escribe solo el dominio, sin las credenciales delante. Si la web pide iniciar sesión, comprueba el acceso con mail-checker.'
    });
  }

  // Un puerto raro no se rechaza: alguien mirando su servidor en el 3000 de
  // desarrollo es un uso legitimo. La guarda de seguridad no es esta, es
  // `esProhibida`, que decide si se conecta a la direccion de destino.
  return url;
}

/**
 * Resuelve el nombre y comprueba que todas sus direcciones sean publicables.
 *
 * Se rechazan si CUALQUIERA de las direcciones es prohibida, no solo si lo es
 * la primera. Un atacante que publica un nombre con una IP publica y otra
 * metadatos no busca que se conecte a la publica: busca que el codigo coja la
 * primera de la lista, la haya visto pasar, y ese mismo codigo sea el que use
 * para conectar. Validar una y descartar la otra deja el agujero abierto.
 *
 * @param {string} host
 * @param {object} [opciones]
 * @param {Function} [opciones.resolver] `dns.promises.lookup`, inyectable.
 * @param {boolean} [opciones.permitirPrivadas=false]
 * @param {number} [opciones.timeoutMs=5000]
 * @returns {Promise<{ok: boolean, ips: string[], ipsOk: string[], bloqueadas: {ip, motivo}[]}>}
 */
async function validarDestino(host, opciones = {}) {
  const { resolver, permitirPrivadas = false, timeoutMs = 5000 } = opciones;

  if (ipaddr.bitsDe(host)) {
    const ip = ipaddr.sinZona(host);
    if (esProhibida(ip, permitirPrivadas)) {
      return { ok: false, ips: [ip], ipsOk: [], bloqueadas: [{ ip, motivo: motivoDeBloqueo(ip, permitirPrivadas) }] };
    }
    return { ok: true, ips: [ip], ipsOk: [ip], bloqueadas: [] };
  }

  const pedir = resolver || require('node:dns').promises.lookup;
  let lookup;
  try {
    lookup = await pedir(host, { all: true, timeout: timeoutMs });
  } catch (error) {
    return { ok: false, ips: [], ipsOk: [], bloqueadas: [], error: error };
  }

  const ips = (Array.isArray(lookup) ? lookup : [lookup]).map((x) => (typeof x === 'string' ? x : x?.address)).filter(Boolean);
  const bloqueadas = ips.filter((ip) => esProhibida(ip, permitirPrivadas)).map((ip) => ({ ip, motivo: motivoDeBloqueo(ip, permitirPrivadas) }));

  return { ok: bloqueadas.length === 0 && ips.length > 0, ips, ipsOk: ips.filter((ip) => !bloqueadas.some((b) => b.ip === ip)), bloqueadas };
}

/* ------------------------------------------------------------------ *
 * Sondeo
 * ------------------------------------------------------------------ */

/**
 * Escribe un NetlabError para un destino prohibido.
 *
 * @param {string[]} bloqueadas
 * @param {boolean} permitirPrivadas
 * @returns {NetlabError}
 */
function errorDeDestino(bloqueadas, permitirPrivadas) {
  const detalle = bloqueadas.map((b) => `${b.ip} (${b.motivo})`).join(', ');
  const conCredencial = permitirPrivadas ? ' Aun así se está permitiendo la red privada.' : '';
  return new NetlabError(CODES.PARAM_INVALIDO, `La comprobación se ha cancelado por seguridad: el destino apunta a ${detalle}.${conCredencial}`, {
    // `ssrf` va en `details` y no se deduce del texto: quien consume el error
    // necesita distinguir "no se ha comprobado nada" de "el sitio no responde",
    // y eso no se puede decidir leyendo una frase que puede cambiar.
    details: { ssrf: true, bloqueadas: bloqueadas.map((b) => `${b.ip} (${b.motivo})`) },
    remediation: permitirPrivadas
      ? 'Se ha alcanzado una dirección interna. Si la comprobación es legítima y el sitio está en tu red, activa "Permitir direcciones internas" en las opciones avanzadas.'
      : 'Este módulo no se conecta a la red interna ni a direcciones de la máquina donde corre netlab. Si necesitas revisar un sitio de tu LAN, activa "Permitir direcciones internas" en las opciones avanzadas.'
  });
}

/**
 * Una peticion HTTP, sin seguir redirecciones y con el cuerpo acotado.
 *
 * @param {URL} url
 * @param {object} [opciones]
 * @returns {Promise<object>}
 */
async function pedir(url, opciones = {}) {
  const { timeoutMs = 8000, metodo = 'HEAD', fetchImpl, permitirPrivadas = false, resolver } = opciones;
  const pedirFetch = fetchImpl || globalThis.fetch;

  const validado = await validarDestino(url.hostname, { resolver, permitirPrivadas });
  if (validado.bloqueadas.length) throw errorDeDestino(validado.bloqueadas, permitirPrivadas);

  const controlador = new AbortController();
  const reloj = setTimeout(() => controlador.abort(), timeoutMs);
  const inicio = Date.now();

  try {
    const respuesta = await pedirFetch(url.toString(), {
      method: metodo,
      redirect: 'manual',
      signal: controlador.signal,
      headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,application/xhtml+xml,*/*;q=0.8' }
    });

    const ttfb = Date.now() - inicio;
    // Un HEAD no trae cuerpo por definicion. Guardarlo igual, como objeto, evita
    // que el consumidor tenga que distinguir entre cadena y objeto.
    const cuerpo = metodo === 'HEAD' ? { texto: '', truncado: false } : await leerCuerpo(respuesta);

    return {
      url: url.toString(),
      estado: respuesta.status,
      motivo: respuesta.statusText || '',
      ok: respuesta.ok,
      cabeceras: cabeceraDe(respuesta.headers),
      destino: respuesta.headers.get('location') || null,
      ttfbMs: ttfb,
      cuerpo,
      truncado: cuerpo.truncado === true
    };
  } catch (error) {
    // "No respondio a tiempo" y "no se pudo contactar" llevan a acciones
    // distintas, y en `net/http.js` ya se distinguen: agotado es lentitud o
    // filtro, error de red es un problema de conexion de esta maquina. Aqui se
    // mantiene el mismo codigo para que el informe no diga una cosa y el titulo
    // otra.
    if (error.name === 'AbortError' || error.code === 'ABORT_ERR') {
      throw new NetlabError(CODES.TIMEOUT, `${url.hostname} no respondió dentro de ${timeoutMs} ms.`, {
        remediation: 'Un servidor que no contesta en ese plazo suele estar sobrecargado o bloqueando a este equipo. Si el sitio carga en el navegador, puede estar filtrando clientes automatizados.'
      });
    }
    throw new NetlabError(CODES.RED, `No se pudo conectar con ${url.hostname}: ${error.message}`, {
      remediation: 'Comprueba que el dominio exista y que el servidor acepte conexiones desde Internet.',
      cause: error
    });
  } finally {
    clearTimeout(reloj);
  }
}

/** Lee el cuerpo hasta el tope, dejando constancia si se ha cortado. */
async function leerCuerpo(respuesta) {
  let texto = '';
  let truncado = false;

  try {
    // `arrayBuffer` es el camino normal: da bytes, y recortar bytes antes de
    // decodificar evita partir un caracter UTF-8 por la mitad y dejar un
    // caracter basura al final. Los bytes van primero a proposito.
    //
    // Ojo al recortar: `subarray` es de los TypedArray, no de ArrayBuffer. Sobre
    // el ArrayBuffer que devuelve `response.arrayBuffer()` hay que usar `slice`.
    if (typeof respuesta.arrayBuffer === 'function') {
      const todo = await respuesta.arrayBuffer();
      truncado = todo.byteLength > MAX_CUERPO;
      texto = Buffer.from(truncado ? todo.slice(0, MAX_CUERPO) : todo).toString('utf8');
    } else if (typeof respuesta.text === 'function') {
      texto = await respuesta.text();
      truncado = texto.length > MAX_CUERPO;
      if (truncado) texto = texto.slice(0, MAX_CUERPO);
    }
  } catch {
    // El cuerpo da igual para el veredicto. Un `Content-Length` enorme con la
    // conexion cortada a mitad no debe tumbar la comprobacion entera.
    texto = '';
    truncado = false;
  }

  return { texto, truncado };
}

/** Cabeceras de respuesta en un objeto plano, en minuscula. */
function cabeceraDe(headers) {
  const salida = {};
  if (!headers) return salida;
  try {
    for (const [clave, valor] of headers.entries()) salida[String(clave).toLowerCase()] = String(valor);
  } catch {
    for (const clave of ['content-type', 'server', 'location']) {
      const v = headers.get?.(clave);
      if (v) salida[clave] = v;
    }
  }
  return salida;
}

/**
 * Comprueba una URL y sigue su cadena de redirecciones.
 *
 * Cada salto vuelve a validar su destino: ese es el punto entero del modulo.
 *
 * @param {string|URL} entrada
 * @param {object} [opciones]
 * @param {number} [opciones.timeoutMs=8000]
 * @param {number} [opciones.maxRedirecciones=MAX_REDIRECCIONES]
 * @param {boolean} [opciones.permitirPrivadas=false]
 * @param {Function} [opciones.fetchImpl]
 * @param {Function} [opciones.resolver]
 * @returns {Promise<{ok, cadena, estado, urlFinal, cuerpo, titulo, truncado}>}
 */
async function sondear(entrada, opciones = {}) {
  const {
    timeoutMs = 8000,
    maxRedirecciones = MAX_REDIRECCIONES,
    permitirPrivadas = false,
    fetchImpl,
    resolver
  } = opciones;

  let url = entrada instanceof URL ? entrada : normalizarUrl(entrada);
  const cadena = [];
  const vistos = new Set();

  for (let salto = 0; ; salto += 1) {
    const clave = url.toString();
    if (vistos.has(clave)) {
      return { ok: false, cadena, bucle: true, urlFinal: clave, motivo: 'La URL se redirige a sí misma en bucle.' };
    }
    vistos.add(clave);

    const r = await pedir(url, { timeoutMs, metodo: 'HEAD', fetchImpl, permitirPrivadas, resolver });
    cadena.push(r);

    // Un HEAD que el servidor no implementa, o que responde 403 porque filtra
    // clientes automatizados, no significa que la pagina este caida: significa
    // que no admite HEAD. Se reintenta con GET, que es el metodo que de verdad
    // usa un visitante, y el que trae el titulo.
    if (r.estado === 405 || r.estado === 501 || r.estado === 403) {
      const conGet = await pedir(url, { timeoutMs, metodo: 'GET', fetchImpl, permitirPrivadas, resolver });
      Object.assign(cadena[cadena.length - 1], conGet, { metodo: 'GET', motivoAlternativo: r.estado });
      return ajustar(cadena[cadena.length - 1], cadena);
    }

    if ([301, 302, 303, 307, 308].includes(r.estado) && r.destino) {
      if (salto >= maxRedirecciones) {
        return { ok: false, cadena, demasiadas: true, urlFinal: clave, motivo: `La URL encadena más de ${maxRedirecciones} redirecciones.` };
      }
      let siguiente;
      try {
        siguiente = new URL(r.destino, url);
      } catch {
        return { ok: false, cadena, estado: r.estado, urlFinal: clave, motivo: `La redirección apunta a "${r.destino}", que no es una dirección válida.` };
      }
      url = siguiente;
      continue;
    }

    // Con un 200 de tipo HTML, el titulo sigue sin estar: HEAD no trae cuerpo.
    // Se hace un GET solo sobre la URL final, y solo si hace falta el titulo
    // para distinguir un sitio real de una pagina de parking.
    if (r.ok && esHtml(r.cabeceras)) {
      const conGet = await pedir(url, { timeoutMs, metodo: 'GET', fetchImpl, permitirPrivadas, resolver });
      Object.assign(r, conGet, { metodo: 'GET' });
      return ajustar(r, cadena);
    }

    return ajustar(r, cadena);
  }
}

/** ¿La respuesta es una pagina HTML? */
function esHtml(cabeceras) {
  return Boolean(cabeceras?.['content-type']?.includes('text/html'));
}

/** Completa el resultado con el cuerpo disponible. */
function ajustar(r, cadena) {
  const cuerpo = r.cuerpo?.texto || '';
  return {
    ok: r.ok,
    cadena,
    estado: r.estado,
    motivo: r.motivo,
    urlFinal: r.url,
    cabeceras: r.cabeceras,
    ttfbMs: r.ttfbMs,
    cuerpo,
    truncado: Boolean(r.cuerpo?.truncado),
    titulo: cuerpo ? leerTitulo(cuerpo) : null,
    metodo: r.metodo || 'HEAD'
  };
}

/** Saca el `<title>` de una pagina, para decidir si es una pagina de verdad. */
function leerTitulo(html) {
  const m = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  if (!m) return null;
  return m[1]
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200) || null;
}

module.exports = {
  normalizarUrl,
  validarDestino,
  sondear,
  pedir,
  esProhibida,
  motivoDeBloqueo,
  esMapeada,
  aIPv4,
  leerTitulo,
  RANGOS_PROHIBIDOS,
  ESPECIALES_V6,
  PUERTOS_WEB,
  MAX_CUERPO,
  MAX_REDIRECCIONES,
  USER_AGENT
};