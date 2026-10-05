/**
 * validar.js — Validacion de los parametros que llegan por HTTP.
 *
 * MODULO DE SEGURIDAD Y DE CONVENcion. Es distinto de `core/args`, que
 * analiza `process.argv` para la CLI: aqui la entrada es un objeto JSON que
 * puede traer cualquier clave, y esa diferencia lo cambia todo.
 *
 * El servidor NO se limita a pasarle el cuerpo de la peticion a la
 * herramienta. Sin este filtro, `POST /api/run` con `{"tool":"ip-audit"}`
 * llegaria a `ip-audit.ejecutar()` con las variables de entorno adjuntas si
 * el navegador las mandara, y cualquier campo que la herramienta no espera se
 * colaria en `result.params` y de ahi al PDF y al historial. Se valida contra
 * la lista de `campos`, que es la unica descripcion de la entrada valida.
 *
 * Reglas:
 *   - Solo pasan las claves que la herramienta declara.
 *   - `shownWhen` aparta un campo que no aplica: si el formulario no lo enseño,
 *     el servidor tampoco lo acepta. Asi un `?dnsbl=false` con `listas=amplia`
 *     dentro no puede colarse por la puerta de atras.
 *   - El rango de un numero se recorta al `min`/`max` declarado, no se rechaza:
 *     es mas util "hecho" que un error por escribir 40000 en el tiempo de espera.
 *   - Un campo obligatorio que no llega se avisa con el nombre del campo, no con
 *     un error generico, para que el formulario pueda marcarlo.
 *
 * @module server/validar
 */

'use strict';

const { NetlabError, CODES } = require('../core/errors');

/**
 * Un campo esta activo segun `shownWhen` contra los valores ya collected.
 *
 * `shownWhen` solo mira un booleano de nivel superior. Es lo que necesitan las
 * herramientas actuales (comparar contra archivo, activar DNSBL) y evita
 * inventar un lenguaje de condiciones entero.
 *
 * @param {object} params Valores ya validados de otros campos.
 * @param {string|undefined} condicion Nombre del booleano que lo activa.
 * @returns {boolean}
 */
function activo(params, condicion) {
  if (!condicion) return true;
  return params[condicion] === true;
}

/**
 * Aplica el valor por defecto de un campo.
 *
 * @param {object} campo
 * @returns {*}
 */
function porDefecto(campo) {
  if (!('default' in campo)) return undefined;
  switch (campo.type) {
    case 'checkbox':
      return campo.default === true;
    case 'number':
      return Number.isFinite(Number(campo.default)) ? Number(campo.default) : undefined;
    case 'file':
      return '';
    default:
      return campo.default;
  }
}

/**
 * Convierte un valor a numero y lo acota al rango declarado.
 *
 * @param {*} valor
 * @param {object} campo
 * @returns {number}
 * @throws {NetlabError} Si no hay forma de entenderlo como numero.
 */
function aNumero(valor, campo) {
  // El texto que llega del formulario llega como cadena. Un valor vacio en un
  // campo numerico con default significa "dejalo como esta".
  const n = Number(String(valor).trim());
  if (!Number.isFinite(n)) {
    throw new NetlabError(
      CODES.PARAM_INVALIDO,
      `«${campo.label || campo.name}» debe ser un número.`,
      { remediation: `Escribe un número, por ejemplo ${campo.default ?? 5}.`, details: { campo: campo.name } }
    );
  }
  if (campo.min !== undefined && n < campo.min) return campo.min;
  if (campo.max !== undefined && n > campo.max) return campo.max;
  return n;
}

/**
 * Resuelve por adelantado el valor de las casillas de verificacion.
 *
 * Hace falta una prepasada porque de un campo dependen otros dos mecanismos:
 * `shownWhen` esconde un campo segun una casilla, y `requiredUnless` perdona
 * una obligatoriedad segun otra casilla. Y el orden en que la herramienta
 * declara los campos no ayuda: en dns-checker, `dominio` es el primero y la
 * casilla `compararArchivo` la quinta, asi que al llegar a `dominio` el valor
 * de `compararArchivo` todavia no existe.
 *
 * Sin esta prepasada, comparar contra un archivo exigiria el dominio siempre,
 * justo lo contrario de lo que dice la ayuda del campo: el caso de uso de
 * comparar un archivo entero no lleva ningun dominio escrito.
 *
 * @param {object[]} campos
 * @param {object} cuerpo
 * @returns {Record<string, boolean>}
 */
function resolverCasillas(campos, cuerpo) {
  const casillas = {};

  for (const campo of campos || []) {
    if (!campo || !campo.name || campo.type !== 'checkbox') continue;

    const recibido = Object.prototype.hasOwnProperty.call(cuerpo, campo.name)
      ? cuerpo[campo.name]
      : undefined;

    if (typeof recibido === 'boolean') casillas[campo.name] = recibido;
    else if (recibido === undefined) casillas[campo.name] = campo.default === true;
    else casillas[campo.name] = recibido === 'true' || recibido === 'on' || recibido === '1';
  }

  return casillas;
}

/**
 * Valida y normaliza el cuerpo de una peticion contra los campos de la herramienta.
 *
 * @param {object} campos Lista `campos` de la herramienta.
 * @param {object} cuerpo Cuerpo de la peticion, ya JSON.
 * @returns {{params: object, avisos: string[]}}
 * @throws {NetlabError} Si falta un campo obligatorio o un valor no es utilizable.
 */
function validar(campos, cuerpo = {}) {
  const entrante = cuerpo && typeof cuerpo === 'object' && !Array.isArray(cuerpo) ? cuerpo : {};
  const params = {};
  const avisos = [];
  const casillas = resolverCasillas(campos, entrante);

  // Los campos se recorren en el orden en que los declaro la herramienta, no en
  // el orden del JSON. Asi `shownWhen` ve el valor del campo del que depende
  // aunque el navegador mandara las claves en el orden contrario.
  for (const campo of campos || []) {
    if (!campo || !campo.name) continue;

    const recibido = Object.prototype.hasOwnProperty.call(entrante, campo.name)
      ? entrante[campo.name]
      : undefined;

    // Campo escondido por su condicion: se descarta aunque venga en el cuerpo.
    // La condicion se consulta contra las casillas ya resueltas, no contra
    // `params`, para que no dependa del orden de declaracion.
    if (!activo(casillas, campo.shownWhen)) {
      if (recibido !== undefined && recibido !== '' && recibido !== false) {
        avisos.push(`Se ignoró «${campo.label || campo.name}»: su opción activadora no está activa.`);
      }
      continue;
    }

    switch (campo.type) {
      case 'checkbox': {
        params[campo.name] = casillas[campo.name];
        break;
      }

      case 'number': {
        if (recibido === undefined || recibido === null || String(recibido).trim() === '') {
          const def = porDefecto(campo);
          if (def !== undefined) params[campo.name] = def;
          break;
        }
        params[campo.name] = aNumero(recibido, campo);
        break;
      }

      case 'select': {
        const opciones = Array.isArray(campo.options) ? campo.options : [];
        const permitidos = opciones.map((o) => o.value ?? o.label);
        const valor = recibido === undefined || recibido === null || recibido === ''
          ? porDefecto(campo)
          : String(recibido);

        if (valor !== undefined && !permitidos.includes(valor)) {
          throw new NetlabError(
            CODES.PARAM_INVALIDO,
            `«${campo.label || campo.name}» no admite el valor «${valor}».`,
            {
              remediation: `Valores posibles: ${permitidos.join(', ')}.`,
              details: { campo: campo.name, admitidos: permitidos }
            }
          );
        }
        if (valor !== undefined) params[campo.name] = valor;
        break;
      }

      case 'file': {
        const texto = recibido === undefined || recibido === null ? '' : String(recibido);
        // El texto de un archivo es lo que viaja en el cuerpo; el limite se
        // comprueba en bytes, no en caracteres, y por eso va sobre el buffer.
        if (campo.maxBytes && Buffer.byteLength(texto, 'utf8') > campo.maxBytes) {
          throw new NetlabError(
            CODES.PARAM_INVALIDO,
            `El archivo de «${campo.label || campo.name}» es demasiado grande.`,
            {
              remediation: `El límite son ${Math.round(campo.maxBytes / 1024)} kB.`,
              details: { campo: campo.name, maxBytes: campo.maxBytes }
            }
          );
        }
        if (texto) params[campo.name] = texto;
        break;
      }

      case 'lista-requisitos':
      case 'text':
      default: {
        const texto = recibido === undefined || recibido === null ? undefined : String(recibido);
        const valor = texto === undefined || texto === '' ? porDefecto(campo) : texto;
        if (valor !== undefined && valor !== '') params[campo.name] = valor;
        break;
      }
    }

    // Obligatoriedad: `required`, o `requiredUnless` apuntando a otro campo.
    // Ambas miran las casillas resueltas, no `params`, por el mismo motivo que
    // `shownWhen`.
    const esObligatorio =
      campo.required === true || (campo.requiredUnless && !casillas[campo.requiredUnless]);
    if (esObligatorio && (params[campo.name] === undefined || params[campo.name] === '')) {
      throw new NetlabError(
        CODES.PARAM_INVALIDO,
        `Falta «${campo.label || campo.name}».`,
        { remediation: campo.help || `Rellena el campo «${campo.label || campo.name}».`, details: { campo: campo.name } }
      );
    }
  }

  return { params, avisos };
}

module.exports = { validar, activo, aNumero };
