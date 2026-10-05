/**
 * args.js — Parser de argumentos de linea de comandos.
 *
 * MODULO DE CONVENcion. Los scripts de legacy/ usaban `process.argv[2]` a
 * pelo: sin `--help`, sin validacion, sin codigos de salida. Una herramienta
 * de diagnostico que se usa en un servidor necesita las tres cosas.
 *
 * Soporta:
 *   --clave valor        opcion con valor
 *   --clave=valor        opcion con valor, forma alternativa
 *   --booleano          bandera
 *   --sin-booleano       desactiva una bandera
 *   -abc                banderas agrupadas
 *   --                  fin de opciones: lo que sigue es posicional
 *   -                   posicionales sueltos
 *
 * @module core/args
 */

'use strict';

const { NetlabError, CODES } = require('./errors');

/**
 * Analiza `process.argv` segun una especificacion de opciones.
 *
 * @param {object} spec
 * @param {object} [spec.flags] { nombre: { type:'boolean'|'string'|'number', alias:'n', describe, default } }
 * @param {string[]} [spec.positional] Nombres de los argumentos posicionales, en orden.
 * @returns {object} { options, positional, help }
 */
function parse(spec = {}) {
  const flags = spec.flags || {};
  const nombresPosicionales = spec.positional || [];

  const porAlias = new Map();
  for (const [name, def] of Object.entries(flags)) {
    porAlias.set(name, name);
    if (def.alias) porAlias.set(def.alias, name);
  }

  const options = {};
  for (const [name, def] of Object.entries(flags)) {
    if ('default' in def) options[name] = def.default;
  }

  const positional = [];
  const argv = process.argv.slice(2);
  let soloPosicionales = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (soloPosicionales) {
      positional.push(arg);
      continue;
    }

    if (arg === '--') {
      soloPosicionales = true;
      continue;
    }

    if (arg === '-') {
      positional.push(arg);
      continue;
    }

    if (arg.startsWith('--')) {
      let cuerpo = arg.slice(2);
      let valor;

      const igual = cuerpo.indexOf('=');
      if (igual !== -1) {
        valor = cuerpo.slice(igual + 1);
        cuerpo = cuerpo.slice(0, igual);
      }

      // --sin-algo apaga la bandera "algo".
      if (cuerpo.startsWith('no-') && porAlias.has(cuerpo.slice(3))) {
        options[porAlias.get(cuerpo.slice(3))] = false;
        continue;
      }

      const nombre = porAlias.get(cuerpo);
      if (!nombre) {
        throw new NetlabError(CODES.PARAM_INVALIDO, `Opción desconocida: --${cuerpo}.`, {
          remediation: `Usa --help para ver las opciones disponibles.`
        });
      }

      const def = flags[nombre];
      if (def.type === 'boolean') {
        options[nombre] = valor === undefined ? true : valor !== 'false';
        continue;
      }

      if (valor === undefined) {
        valor = argv[++i];
        if (valor === undefined) {
          throw new NetlabError(CODES.PARAM_INVALIDO, `La opción --${cuerpo} necesita un valor.`, {
            remediation: `Escribe --${cuerpo}=valor o --${cuerpo} valor.`
          });
        }
      }

      options[nombre] = coerce(valor, def, cuerpo);
      continue;
    }

    if (arg.startsWith('-') && arg.length > 1) {
      // Banderas agrupadas: -abc = -a -b -c
      for (const letra of arg.slice(1)) {
        const nombre = porAlias.get(letra);
        if (!nombre) {
          throw new NetlabError(CODES.PARAM_INVALIDO, `Opción desconocida: -${letra}.`, {
            remediation: 'Usa --help para ver las opciones disponibles.'
          });
        }
        if (flags[nombre].type === 'boolean') {
          options[nombre] = true;
        } else {
          const valor = argv[++i];
          if (valor === undefined) {
            throw new NetlabError(CODES.PARAM_INVALIDO, `La opción -${letra} necesita un valor.`, {});
          }
          options[nombre] = coerce(valor, flags[nombre], letra);
          break;
        }
      }
      continue;
    }

    positional.push(arg);
  }

  // Los posicionales que tienen nombre se exponen tambien por nombre.
  const named = {};
  nombresPosicionales.forEach((nombre, i) => {
    if (positional[i] !== undefined) named[nombre] = positional[i];
  });

  return { options, positional, named, ...renderHelp(spec, options) };
}

/** Convierte y valida el valor de una opcion segun su tipo declarado. */
function coerce(valor, def, nombre) {
  if (def.type === 'number') {
    const n = Number(valor);
    if (!Number.isFinite(n)) {
      throw new NetlabError(CODES.PARAM_INVALIDO, `--${nombre} espera un numero, no "${valor}".`, {});
    }
    return n;
  }
  if (def.type === 'list') {
    return String(valor)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return valor;
}

/**
 * Construye el texto de `--help` a partir de la especificacion.
 *
 * @param {object} spec
 * @param {object} options Valores actuales, para marcar los que estan puestos.
 * @returns {{ usage: string, describe: string, help: string }}
 */
function renderHelp(spec, options = {}) {
  const flags = spec.flags || {};
  const etiquetas = Object.entries(flags).map(([name, def]) => {
    const alias = def.alias ? `-${def.alias}, ` : '    ';
    const tipo = def.type === 'boolean' ? '' : ` <${def.type || 'valor'}>`;
    return { etiqueta: `${alias}--${name}${tipo}`, describe: def.describe || '', def, name };
  });

  const ancho = Math.max(0, ...etiquetas.map((e) => e.etiqueta.length));

  const usage = [
    `Uso: netlab ${spec.usage || ''}`.trim(),
    '',
    spec.summary || '',
    '',
    spec.positional?.length ? '  Argumentos:' : '',
    ...(spec.positional || []).map(
      (n, i) => `    ${String(i).padEnd(2)} ${n}`.padEnd(ancho + 8)
    ),
    '',
    '  Opciones:',
    ...etiquetas.map((e) => {
      const marcado = options[e.name] !== undefined && options[e.name] !== false ? ' (activo)' : '';
      return `    ${e.etiqueta.padEnd(ancho)}  ${e.describe}${marcado}`;
    }),
    spec.examples?.length ? ['', '  Ejemplos:', ...spec.examples.map((x) => `    ${x}`)] : [],
    ''
  ]
    .filter((l) => l !== undefined)
    .join('\n');

  return { usage, describe: spec.summary || '', help: usage };
}

module.exports = { parse };