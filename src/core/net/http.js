/**
 * http.js — Cliente HTTP minimo para consultar APIs externas.
 *
 * MODULO DE CONVENCION. legacy/ usaba axios y trataba el error como
 * `error.response.status`, asi que un corte de red y un 401 de clave
 * caducada acababan en el mismo `catch` y el mensaje que veia el usuario era
 * "Error de red: socket hang up" sin mas. Aqui los casos se separan:
 *
 *   400/401/403 -> no tiene sentido reintentar; es una peticion o una credencial
 *                  que esta mal, y la API no va a cambiar de opinion.
 *   429        -> cuota agotada; se espera y se reintenta con espera creciente,
 *                  porque es el unico 4xx que se resuelve solo.
 *   5xx / red  -> transitorio; se reintenta.
 *
 * Ademas corta por tiempo con AbortController, algo que axios hacia solo si se
 * rememberaba el parametro `timeout`. Aqui es imposible olvidarlo.
 *
 * @module core/net/http
 */

'use strict';

const { NetlabError, CODES } = require('../errors');

/**
 * Espera bloqueante entre reintentos.
 *
 * @param {number} ms
 * @returns {Promise<void>}
 */
function esperar(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Construye una URL anadiendo parametros de consulta.
 *
 * @param {string} base Sin query.
 * @param {object} [query]
 * @returns {string}
 */
function conQuery(base, query = {}) {
  const url = new URL(base);
  for (const [clave, valor] of Object.entries(query)) {
    if (valor === undefined || valor === null || valor === '') continue;
    url.searchParams.set(clave, String(valor));
  }
  return url.toString();
}

/**
 * Descarga un JSON.
 *
 * @param {object} opciones
 * @param {string} opciones.url
 * @param {object} [opciones.query] Parametros de consulta.
 * @param {object} [opciones.headers]
 * @param {number} [opciones.timeoutMs=15000]
 * @param {number} [opciones.intentos=3] Intentos totales, incluido el primero.
 * @param {number} [opciones.esperaBaseMs=800] Espera del primer reintento.
 * @param {Function} [opciones.fetchImpl] Para poder inyectar un doble en las pruebas.
 * @param {string} [opciones.servicio] Nombre legible, para los mensajes.
 * @returns {Promise<object>} El cuerpo ya parseado.
 * @throws {NetlabError} Con codigo RED, API_EXTERNA, API_CUOTA o INTERNO.
 */
async function getJSON({
  url,
  query,
  headers = {},
  timeoutMs = 15000,
  intentos = 3,
  esperaBaseMs = 800,
  fetchImpl,
  servicio = 'la API'
}) {
  const pedir = fetchImpl || globalThis.fetch;
  if (typeof pedir !== 'function') {
    throw new NetlabError(CODES.INTERNO, 'Este entorno no tiene fetch disponible.', {
      remediation: 'Ejecuta la herramienta con Node 18 o superior.'
    });
  }

  const completa = conQuery(url, query);
  let ultimoError;

  for (let intento = 1; intento <= intentos; intento++) {
    const controlador = new AbortController();
    const reloj = setTimeout(() => controlador.abort(), timeoutMs);

    try {
      const respuesta = await pedir(completa, {
        method: 'GET',
        headers: { Accept: 'application/json', ...headers },
        signal: controlador.signal
      });

      if (respuesta.ok) {
        const texto = await respuesta.text();
        if (!texto) return {};
        try {
          return JSON.parse(texto);
        } catch (error) {
          throw new NetlabError(CODES.API_EXTERNA, `${servicio} ha devuelto una respuesta que no es JSON.`, {
            remediation: 'Comprueba la URL y el estado del servicio. Si persiste, es una incidencia del proveedor.',
            details: { httpStatus: respuesta.status, vista: texto.slice(0, 200) }
          });
        }
      }

      // --- Errores HTTP: aqui esta el trabajo real -------------------------
      const cuerpo = await cuerpoSeguro(respuesta);

      if (respuesta.status === 429) {
        // Unica situacion 4xx que mejora con el tiempo.
        ultimoError = new NetlabError(CODES.API_CUOTA, `${servicio} ha rechazado la peticion por cuota (429).`, {
          remediation:
            'Has superado el limite de peticiones del plan gratuito. Espera un minuto y vuelve a intentarlo; si sigue igual, revisa el uso de la clave.',
          details: { httpStatus: 429, reintentosAgotados: intento >= intentos }
        });
        if (intento < intentos) {
          // Respeta la espera que pida la API, si la manda.
          await esperar(Math.max(esperaBaseMs * 2 ** (intento - 1), Number(respuesta.headers?.get?.('retry-after')) * 1000 || 0));
          continue;
        }
        throw ultimoError;
      }

      if (respuesta.status === 401 || respuesta.status === 403) {
        throw new NetlabError(CODES.CREDENCIAL_INVALIDA, `${servicio} no ha aceptado la credencial (${respuesta.status}).`, {
          remediation: 'La clave no es valida, ha caducado o no tiene permiso para este recurso. Comprueba el .env y que la clave corresponda al servicio.',
          details: { httpStatus: respuesta.status, cuerpo: cuerpo.resumen }
        });
      }

      if (respuesta.status === 404) {
        throw new NetlabError(CODES.INTERNO, `${servicio} no conoce el recurso pedido (404).`, {
          remediation: 'La URL o el identificador estan mal. Es un fallo de configuracion, no del dato consultado.',
          details: { httpStatus: 404, cuerpo: cuerpo.resumen }
        });
      }

      if (respuesta.status === 400) {
        throw new NetlabError(CODES.PARAM_INVALIDO, `${servicio} ha rechazado la peticion (400).`, {
          remediation: 'Revisa el valor consultado. Las APIs suelen rechazar aqui un formato de IP no valido.',
          details: { httpStatus: 400, cuerpo: cuerpo.resumen }
        });
      }

      ultimoError = new NetlabError(CODES.API_EXTERNA, `${servicio} ha devuelto un error ${respuesta.status}.`, {
        remediation: 'Puede ser un problema puntual del servicio. Si se repite, consulta su pagina de estado.',
        details: { httpStatus: respuesta.status, cuerpo: cuerpo.resumen }
      });
    } catch (error) {
      // Un NetlabError aqui es una decision nuestra: o el recurso no existe, o
      // la credencial es mala, o la respuesta no es JSON. En ninguno de esos
      // casos tiene sentido reintentar, asi que sale hacia arriba tal cual.
      if (error instanceof NetlabError) throw error;

      // Cualquier otra cosa (abort por tiempo, DNS, TLS, socket) puede ser
      // pasajera, y por eso si vale la pena volver a intentarlo.
      const porTiempo = error?.name === 'AbortError';
      ultimoError = porTiempo
        ? new NetlabError(CODES.TIMEOUT, `${servicio} no ha respondido en ${timeoutMs} ms.`, {
            remediation: 'El servicio va lento o no se alcanza desde aqui. Se ha reintentado sin exito.',
            details: { url: completa.split('?')[0], timeoutMs }
          })
        : new NetlabError(CODES.RED, `No se pudo contactar con ${servicio}: ${error?.message || error}`, {
            remediation: 'Comprueba la conexion a Internet y, si usas un proxy, que este configurado en el entorno.',
            details: { url: completa.split('?')[0] }
          });
    } finally {
      clearTimeout(reloj);
    }

    if (intento < intentos) await esperar(esperaBaseMs * 2 ** (intento - 1));
  }

  throw ultimoError || new NetlabError(CODES.RED, `${servicio} no respondio.`);
}

/**
 * Lee el cuerpo de una respuesta de error sin que un cuerpo no-JSON rompa el
 * manejo del error. Devolver el error real es mas util que el exotico.
 *
 * @param {Response} respuesta
 * @returns {Promise<{texto: string, resumen: string}>}
 */
async function cuerpoSeguro(respuesta) {
  let texto = '';
  try {
    texto = await respuesta.text();
  } catch {
    texto = '';
  }
  let resumen = texto.slice(0, 200);
  try {
    const datos = JSON.parse(texto);
    if (datos && typeof datos === 'object') {
      resumen = JSON.stringify(datos.errors || datos.messages || datos).slice(0, 200);
    }
  } catch {
    /* no es JSON: nos quedamos con el texto recortado */
  }
  return { texto, resumen };
}

module.exports = { getJSON, conQuery, esperar };
