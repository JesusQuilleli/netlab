/**
 * tools/ip-abuse.js — Herramienta 3 de 5: reputacion de una IP.
 *
 * DE DONDE SALE. legacy/Check IP Abuse/abuse/check-abuse.js era un script de
 * 194 lineas que consultaba AbuseIPDB, escribia un PDF en el directorio de
 * trabajo y no devolvia nada. Aqui no se escribe nada en disco: `ejecutar()`
 * devuelve un `Result` y quien lo llama decide el formato.
 *
 * LO QUE ESTA HECHO DISTINTO, Y POR QUE:
 *
 * 1. Ventana de 30 dias en vez de 5. Con 5 dias, una IP con veinte avisos se
 *    ve limpia si el ultimo fue hace seis dias. El valor por defecto de la
 *    propia API son 30, y es el que se usa.
 *
 * 2. Se mira cuantos USUARIOS DISTINTOS han puesto un aviso, y no solo cuantos
 *    avisos hay. Cuarenta avisos de un solo repetidor no significan lo mismo
 *    que cuatro de cuatro redes distintas, y decidir por el total lleva a
 *    marcar como maliciosa una IP que solo ha visto un robot.
 *
 * 3. El catalogo de categorias va marcado con su cobertura. Un identificador
 *    sin traducir sale como "Categoria 123", no como un nombre inventado.
 *
 * 4. Los comentarios de quien reporta van ocultos por defecto. Son texto libre
 *    escrito por desconocidos: puede traer datos personales y casi nunca aporta
 *    a la decision. El checkbox los ensena si se piden.
 *
 * SEGURIDAD. La clave viene de `core/config` y no sale nunca en el Result: no va
 * en `params`, ni en los logs, ni en las secciones. En el informe solo aparece
 * enmascarada, para poder confirmar que se ha usado la clave correcta.
 *
 * @module tools/ip-abuse
 */

'use strict';

const net = require('node:net');

const {
  createResult, addSection, addSummary, addFinding, addLog,
  finalize, failWith, SEVERIDADES, SECCION_KINDS: K
} = require('../core/result');
const abuseipdb = require('../core/net/abuseipdb');
const config = require('../core/config');
const { NetlabError, CODES } = require('../core/errors');
const { redactDeep } = require('../core/redact');

const ID = 'ip-abuse';

/** Campos del formulario. Todos los objetivos los elige el usuario. */
const CAMPOS = [
  {
    name: 'ip',
    label: 'Direccion IP',
    type: 'text',
    required: true,
    placeholder: '203.0.113.10',
    help: 'Una IP, o varias separadas por comas o espacios. Admite IPv4 e IPv6. Se consultan de una en una.'
  },
  {
    name: 'dias',
    label: 'Ventana de busqueda',
    type: 'number',
    required: false,
    default: 30,
    min: 1,
    max: 365,
    unit: 'dias',
    help: 'Dias hacia atras que se consultan. Treinta es lo normal; el ano entero es para ver el historial largo de una IP que se quiere repuntar.'
  },
  {
    name: 'detalle',
    label: 'Incluir los avisos uno a uno',
    type: 'checkbox',
    required: false,
    default: true,
    help: 'Desactivalo si solo quieres el veredicto y el resumen. La API no gasta mas cuota por esto, pero la respuesta es mucho mas larga.'
  },
  {
    name: 'comentarios',
    label: 'Incluir los comentarios de quien reporta',
    type: 'checkbox',
    required: false,
    default: false,
    help: 'Son texto libre escrito por desconocidos. Util para ver el detalle, pero puede traer datos personales y casi nunca cambia la decision.'
  },
  {
    name: 'maxAvisos',
    label: 'Maximo de avisos a detallar',
    type: 'number',
    required: false,
    default: 100,
    min: 1,
    max: 1000
  },
  {
    name: 'timeout',
    label: 'Tiempo de espera',
    type: 'number',
    required: false,
    default: 15000,
    min: 1000,
    max: 60000,
    unit: 'ms',
    help: 'Por consulta. Con varias IPs se van sumando.'
  }
];

/**
 * Punto de entrada de la herramienta.
 *
 * @param {object} params Entrada del formulario.
 * @param {object} [ctx] Contexto de ejecucion. `ctx.abuse` permite inyectar un
 *   doble en las pruebas y `ctx.clave` pasar la clave sin tocar el entorno.
 * @returns {Promise<object>} Result completo, listo para renderizar.
 */
async function ejecutar(params = {}, ctx = {}) {
  const inicio = new Date();
  const log = ctx.log || null;

  const ips = parseIps(params.ip);
  // `ctx.clave !== undefined` y no un `||`: si quien llama pasa una clave vacia
  // a proposito (una prueba, o un despliegue sin credencial), debe respetarse y
  // producir el error de credencial, no caer en la del entorno por sorpresa.
  const clave = ctx.clave !== undefined ? ctx.clave : config.leer('ABUSEIPDB_API_KEY');

  const result = createResult({
    tool: ID,
    toolTitle: 'Reputacion de IP',
    // Con varias IPs el objetivo no puede ser una sola direccion: se dice cuantas.
    target: ips.length === 1 ? ips[0] : `${ips.length} direcciones`,
    params: redactDeep(params)
  });

  try {
    if (!ips.length) {
      throw new NetlabError(CODES.PARAM_INVALIDO, 'No hay ninguna direccion IP que consultar.', {
        remediation: 'Escribe al menos una IP, por ejemplo 203.0.113.10. Se pueden separar varias con comas.'
      });
    }

    // La ausencia de clave se comprueba DESPUES de leer la entrada y no antes,
    // porque si el unico mensaje fuera "falta la clave" quien lo lee no sabria
    // si ha escrito mal la IP o no.
    if (!clave) {
      throw new NetlabError(CODES.CREDENCIAL_AUSENTE, 'No hay clave de AbuseIPDB configurada.', {
        remediation:
          'Define ABUSEIPDB_API_KEY en el .env. La que hay en legacy/ estuvo expuesta en un archivo versionado: usala para probar y pide una nueva.'
      });
    }

    const dias = acotar(params.dias, 1, 365, 30);
    const timeoutMs = acotar(params.timeout, 1000, 60000, 15000);
    const maxAvisos = acotar(params.maxAvisos, 1, 1000, 100);
    const detallado = params.detalle !== false;
    const conComentarios = Boolean(params.comentarios);

    addLog(result, {
      level: 'info',
      channel: 'entrada',
      message: `${ips.length} IP a consultar, ventana de ${dias} dias, detalle ${detallado ? 'completo' : 'resumido'}`
    });
    addSummary(result, 'Direcciones consultadas', ips.length);
    addSummary(result, 'Ventana', `${dias} dias`);
    addSummary(result, 'Clave usada', config.enmascarar(clave));
    addSummary(result, 'Catalogo de categorias', `${abuseipdb.COBERTURA_CATALOGO} traducidas`);

    const consultar =
      ctx.abuse || ((ip) => abuseipdb.consultar(ip, { clave, maxAgeInDays: dias, detallado, timeoutMs }));

    const datos = [];
    const errores = [];

    for (const ip of ips) {
      try {
        addLog(result, { level: 'info', channel: 'api', message: `Consultando ${ip}...` });
        datos.push(await consultar(ip));
      } catch (error) {
        // Una IP que falla no debe tumbar el resto. Se anota y se sigue, que es
        // justo lo que hace falta cuando se pasa una lista larga.
        const codigo = error instanceof NetlabError ? error.code : CODES.INTERNO;
        errores.push({ ip, codigo, mensaje: error.message, remediation: error?.remediation || null });
        addLog(result, { level: 'error', channel: 'api', message: `${ip}: ${error.message}` });
      }
    }

    if (!datos.length && errores.length) {
      const primero = errores[0];
      throw new NetlabError(primero.codigo, `No se pudo consultar ninguna de las ${ips.length} direcciones.`, {
        remediation: primero.remediation,
        details: { fallos: errores }
      });
    }

    // Lo que no ha llegado a ser IP se dice. Descartarlo en silencio esta bien
    // para que una coma sobrante no invalide veinte direcciones, pero es grave
    // en el otro extremo: de una lista de veinte con dos erratas, quien lee el
    // informe ve dieciocho IPs consultadas y no tiene forma de saber que dos no
    // se han mirado.
    const descartadas = descartadasDe(params.ip);
    if (descartadas.length) {
      addFinding(result, {
        severity: SEVERIDADES.WARN,
        title: `${descartadas.length} de las entradas no son IPs y no se han consultado`,
        detail: `Se han descartado: ${descartadas.join(', ')}.`,
        recommendation:
          'Revisa la lista antes de fiarte del resultado. Una direccion mal escrita no produce ningun aviso de error: simplemente no se consulta.'
      });
    }

    // La tabla comparativa se usa en cuanto se han pedido varias direcciones,
    // no solo cuando varias respondieron. Si de cinco se consultan tres, quien
    // lee necesita ver las tres en una tabla, no un informe a un lado y dos
    // lineas sueltas al otro.
    if (ips.length > 1) pintarVarias(result, datos, { detallado, conComentarios, maxAvisos });
    else pintarUna(result, datos[0], { detallado, conComentarios, maxAvisos });

    if (errores.length) {
      addFinding(result, {
        severity: SEVERIDADES.WARN,
        title: `${errores.length} de ${ips.length} direcciones no se pudieron consultar`,
        detail: errores.map((e) => `${e.ip}: ${e.mensaje}`).join(' | '),
        recommendation: 'El resto del informe sigue siendo valido. Comprueba si esas IPs fallan por cuota, por credencial o por estar mal escritas.'
      });
    }

    return finalize(result, inicio);
  } catch (error) {
    addLog(result, { level: 'error', channel: 'error', message: error.message });
    log?.error?.(`ip-abuse fallo: ${error.message}`);
    return failWith(finalize(result, inicio), error instanceof NetlabError ? error : new NetlabError(CODES.INTERNO, error.message));
  }
}

/** Una sola IP: informe completo. */
function pintarUna(result, d, opciones) {
  addSummary(result, 'IP', d.ip);
  addSummary(result, 'Puntuacion de confianza', d.puntuacionConfianza === null ? 'sin dato' : `${d.puntuacionConfianza} %`, d.puntuacionConfianza >= 50 ? 'bad' : 'ok');
  addSummary(result, 'Avisos en la ventana', d.totalReportes === null ? 'sin dato' : d.totalReportes, d.totalReportes === null ? 'warn' : d.totalReportes > 0 ? 'warn' : 'ok');
  addSummary(result, 'Autores distintos', d.autoresDistintos === null ? 'sin dato' : d.autoresDistintos, (d.autoresDistintos || 0) > 1 ? 'warn' : 'neutral');

  addSection(result, {
    title: 'Identificacion',
    kind: K.PARES,
    items: [
      ['Direccion', d.ip],
      ['Es publica', d.esPublica === null ? 'Sin datos' : d.esPublica ? 'Si' : 'No', d.esPublica === null ? 'warn' : d.esPublica ? 'neutral' : 'warn'],
      ['En lista blanca', d.esWhitelisted ? 'Si' : 'No', d.esWhitelisted ? 'ok' : 'neutral'],
      ['ISP / propietario', d.isp || 'Sin datos'],
      ['Dominio asociado', d.dominio || 'Sin datos'],
      ['Tipo de uso', [d.tipoUsoEs, d.tipoUso].filter(Boolean).join(' · ') || 'Sin datos'],
      ['Pais', d.nombrePais ? `${d.nombrePais} (${d.codigoPais || '??'})` : 'Sin datos'],
      ['Es red movil', d.esMovil ? 'Si' : 'No'],
      ['Ventana consultada', `${d.ventanaDias} dias`],
      ['Ultimo aviso global', d.ultimoReporteTexto]
    ]
  });

  pintarCategorias(result, d);
  revisar(result, d);
  if (opciones.detallado) pintarAvisos(result, d, opciones);
}

/** Varias IPs: tabla comparativa, que es lo que se pide cuando hay una lista. */
function pintarVarias(result, datos, opciones) {
  addSection(result, {
    title: 'Resumen de las direcciones consultadas',
    description: 'Ordenadas de peor a mejor segun los avisos. Con varias IPs la tabla es el informe; el detalle se anade debajo si se pide.',
    kind: K.TABLA,
    columns: ['IP', 'Avisos', 'Autores', 'Puntuacion', 'Blanca', 'Ultimo aviso', 'ISP'],
    // La columna ISP es la mas larga del enunciado y la que mas se trunca sin
    // peso, asi que se lleva una parte importante del ancho.
    anchoColumnas: [14, 8, 8, 9, 8, 17, 36],
    rows: [...datos]
      // Un total desconocido no es un cero: al ordenar, se va al final en vez de
      // quedarse el primero porque `null - 0` no es un numero y el comparador
      // deja el orden como le ha tocado.
      .sort((a, b) => (b.totalReportes ?? -1) - (a.totalReportes ?? -1) || (b.puntuacionConfianza || 0) - (a.puntuacionConfianza || 0))
      .map((d) => [
        d.ip,
        d.totalReportes ?? '—',
        d.autoresDistintos ?? '—',
        d.puntuacionConfianza === null ? '—' : `${d.puntuacionConfianza} %`,
        d.esWhitelisted ? 'Si' : 'No',
        d.ultimoReporteTexto,
        d.isp || '—'
      ])
  });

  for (const d of datos) revisar(result, d);

  if (opciones.detallado) {
    for (const d of datos) {
      pintarCategorias(result, d);
      pintarAvisos(result, d, opciones);
    }
  }
}

/** Desglose de categorias de una IP. */
function pintarCategorias(result, d) {
  if (!d.resumenCategorias.length) return;
  addSection(result, {
    title: `Categorias de los avisos (${d.ip})`,
    kind: K.TABLA,
    columns: ['Categoria', 'Apariciones'],
    anchoColumnas: [80, 20],
    rows: d.resumenCategorias.map((c) => [c.nombre, c.veces])
  });
}

/** Detalle de los avisos de una IP. */
function pintarAvisos(result, d, { conComentarios, maxAvisos }) {
  if (!d.reportes.length) return;

  const cortados = d.reportes.length > maxAvisos;
  const visibles = d.reportes.slice(0, maxAvisos);

  addSection(result, {
    title: `Avisos (${d.ip})`,
    description: cortados
      ? `Se muestran los ${visibles.length} mas recientes de ${d.reportes.length}. La API los devuelve del mas nuevo al mas antiguo.`
      : `Los ${visibles.length} avisos de la ventana, del mas reciente al mas antiguo.`,
    kind: K.TABLA,
    columns: conComentarios ? ['Fecha', 'Pais', 'Categorias', 'Comentario'] : ['Fecha', 'Pais', 'Categorias'],
    anchoColumnas: conComentarios ? [16, 8, 28, 48] : [20, 10, 70],
    rows: visibles.map((r) =>
      conComentarios
        ? [r.fechaTexto, r.pais || '—', r.categoriasTexto, limpiarComentario(r.comentario)]
        : [r.fechaTexto, r.pais || '—', r.categoriasTexto]
    )
  });
}

/**
 * Traduce los datos de una IP en hallazgos.
 *
 * Aqui esta el criterio, y es la parte que legacy/ no tenia: no decide solo por
 * el total de avisos, sino por como se reparten entre autores distintos. La
 * misma cifra da dos lecturas opuestas segun quien haya reportado, y quien
 * decide si una IP es de fiar necesita ver esa diferencia.
 *
 * @param {object} result
 * @param {object} d Datos normalizados de la IP.
 */
function revisar(result, d) {
  const autores = d.autoresDistintos;
  const total = d.totalReportes;

  // El caso en el que no se decide nada. Si la API no ha dicho cuantos avisos
  // hay, cualquier veredicto es inventado: se sabe tanto que la IP esta limpia
  // como que tiene veinte. Aqui se decide parar y decirlo, porque escribir "no
  // tiene avisos" cuando el dato no ha llegado es lo unico que no se puede
  // recuperar leyendo el informe despues.
  if (total === null) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: `${d.ip}: no se ha podido comprobar cuantos avisos tiene`,
      detail: `AbuseIPDB no ha devuelto el numero de avisos${autores !== null ? `, aunque si dice que hay ${autores} autor(es) distinto(s), lo que no cuadra` : ''}.`,
      recommendation:
        'El informe de esta IP no es concluyente: no se ha podido leer el dato principal. Puede ser un cambio en la API; revisa la respuesta antes de fiarte.'
    });
    return;
  }

  if (d.esWhitelisted) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `${d.ip} esta en una lista blanca de AbuseIPDB`,
      detail: `La marca como lista de confianza${total ? `, aunque acumula ${total} aviso(s) en la ventana.` : '.'}`,
      recommendation:
        'La lista blanca pesa, pero no es un permiso absoluto. Si los avisos son recientes y de autores distintos, miralos antes de confiarte del todo.'
    });
  }

  if (!total) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `${d.ip} no tiene avisos en los ultimos ${d.ventanaDias} dias`,
      detail: 'No hay ningun reporte de abuso en la ventana consultada.',
      recommendation:
        d.ventanaDias < 90
          ? 'Si esperabas historial, amplia la ventana: con 30 dias una IP con avisos antiguos sale igualmente limpia.'
          : 'Sin avisos en una ventana amplia. Aun asi, una lista negra no cubre todo el espectro del abuso.'
    });
    return;
  }

  // El reparto de autores es lo que separa el ruido del problema. Si no ha
  // llegado, se dice: sin esto, una IP con veinte avisos de un solo repetidor y
  // una con veinte de veinte redes salen con el mismo perfil, y la diferencia
  // es justo la que hace falta para decidir.
  if (autores === null) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `${d.ip} acumula ${total} aviso(s) pero no se sabe de cuantos autores`,
      detail: 'La API no ha devuelto el numero de autores distintos, que es el dato que separa el ruido de un problema real.',
      recommendation:
        'No saques conclusiones del volumen de avisos por si solo. Con autores desconocidos, veinte avisos pueden ser un repetidor o veinte redes.'
    });
  }

  // Reparto de autores: la distincion que separa el ruido del problema.
  if (autores !== null && autores <= 1 && total > 3) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: `${d.ip} acumula ${total} avisos, pero de un solo autor`,
      detail: `Los ${total} avisos los ha puesto la misma fuente. Suele ser un escaner o una queja que se repite desde el mismo sitio.`,
      recommendation:
        'Pondera poco esta cifra: un solo autor puede estar equivocado o simplemente insistir. Tomalo como una pista, no como un veredicto.'
    });
  }

  if (autores !== null && autores >= 3) {
    addFinding(result, {
      severity: total >= 10 || d.puntuacionConfianza >= 50 ? SEVERIDADES.ERROR : SEVERIDADES.WARN,
      title: `${d.ip} tiene avisos de ${autores} autores distintos`,
      detail: `${total} aviso(s) de ${autores} fuentes independientes${d.puntuacionConfianza === null ? '.' : `, y AbuseIPDB le asigna un ${d.puntuacionConfianza} % de confianza de abuso.`}`,
      recommendation:
        total >= 10
          ? 'Varias fuentes independientes y en volumen: tratala como no confiable. Si es tuya, revisa que se esta escaneando o atacando desde ella; si es de un tercero, mejor no pasar por ella.'
          : 'Varias fuentes coinciden, aunque en poco volumen. Vale la pena mirarlo antes de darla por buena.'
    });
  }

  // La puntuacion sola no decide nada: un 100 con un solo aviso y un 60 con
  // veinte de cinco redes son cosas distintas, asi que siempre va acompanada.
  if (d.puntuacionConfianza !== null && d.puntuacionConfianza >= 100) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: `${d.ip} esta marcada al 100 % de confianza de abuso`,
      detail: 'AbuseIPDB le da la maxima confianza, lo que suele indicar historial consistente y varios autores distintos.',
      recommendation: 'No la uses para trafico legitimo hasta revisar que ha cambiado. Si es tuya, empieza por los avisos mas recientes del desglose.'
    });
  }

  // Una IP movil se reasigna y se comparte: los avisos se heredan de usuarios que
  // no han hecho nada, asi que no sirven para juzgar a quien la tiene ahora.
  if (d.esMovil || d.tipoUso === 'Mobile Network') {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `${d.ip} pertenece a una red movil`,
      detail: 'En redes moviles la direccion se reasigna y se comparte entre muchos usuarios, de modo que los avisos se heredan.',
      recommendation: 'No tomes decisiones de bloqueo a partir de una IP movil: afectas a usuarios que no han hecho nada.'
    });
  }

  if (!d.dominio && total > 0) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `${d.ip} no tiene dominio ni PTR declarado`,
      detail: 'La API no devuelve nombre de dominio para esta direccion, lo que suele significar que el propietario no la ha declarado en su DNS inverso.',
      recommendation: 'Es normal en un servidor sin PTR, pero tiene dos efectos: los correos que salen de ahi acaban antes en spam y los registros de la tabla aparecen sin nombre.'
    });
  }
}

/** Limpia un comentario de tercero para poder meterlo en una celda. */
function limpiarComentario(texto) {
  if (!texto) return 'Sin comentario';
  return String(texto).replace(/\s+/g, ' ').trim().slice(0, 300) || 'Sin comentario';
}

/**
 * Devuelve las entradas que no son IPs, para poder decir que se han descartado.
 *
 * Comparte el criterio con `parseIps` a proposito: si los dos filtraran de forma
 * distinta, el aviso podria acusar entradas que si se consultaron, o al
 * reves. Se calcula aparte en vez de tocar `parseIps` porque el filtro de ahi
 * tiene que seguir siendo silencioso para no romper la lista.
 *
 * @param {string|string[]} bruto
 * @returns {string[]}
 */
function descartadasDe(bruto) {
  if (!bruto) return [];
  const candidatos = Array.isArray(bruto)
    ? bruto.map((s) => String(s).trim())
    : String(bruto).split(/[\s,;]+/).map((s) => s.trim());

  return candidatos.filter((s) => s.length > 0 && !net.isIP(s));
}

/**
 * Divide el campo de entrada en una lista de IPs validas.
 *
 * Las invalidas se descartan en silencio a proposito: si queda alguna valida se
 * sigue con ella, porque al escribir una lista de veinte direcciones una coma
 * sobrante no debe tirar el trabajo. Si no queda ninguna, `ejecutar` lanza el
 * error de "no hay ninguna direccion IP", que ya explica como se escribe.
 *
 * @param {string|string[]} bruto
 * @returns {string[]}
 */
function parseIps(bruto) {
  if (!bruto) return [];
  if (Array.isArray(bruto)) {
    // Un array viene ya separado, pero no viene necesariamente limpio. Antes se
    // aceptaba tal cual y un 'no-es-una-ip' dentro pasaba el filtro y gastaba
    // una llamada a la API para que la API lo rechazara. Mejor decidir aqui y
    // avisar de la entrada mala, que fallar mas tarde con un error de otro.
    return bruto
      .map((s) => String(s).trim())
      .filter((s) => s.length > 0 && net.isIP(s));
  }

  return String(bruto)
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter((s) => net.isIP(s));
}

/** Acota un numero a un rango, con valor por defecto si no es utilizable. */
function acotar(valor, min, max, porDefecto) {
  const n = Number(valor);
  if (!Number.isFinite(n)) return porDefecto;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

module.exports = {
  id: ID,
  titulo: 'Reputacion de IP',
  descripcion: 'Consulta AbuseIPDB para saber si una IP tiene avisos de abuso, de cuantas fuentes independientes y de que tipo.',
  sinRed: false,
  icon: '🛡️',
  campos: CAMPOS,
  ejecutar,
  parseIps
};
