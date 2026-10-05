/**
 * tools/subnet-analyzer.js — Herramienta 1 de 5: calculadora de subredes.
 *
 * PRIMERA HERRAMIENTA COMPLETA DEL PROYECTO. Sirve de referencia para las otras
 * cuatro, asi que su forma es la que hay que repetir:
 *
 *   1. Declara sus `campos` con la misma estructura, para que la web monte el
 *      formulario sin escribir HTML especifico para cada herramienta.
 *   2. `ejecutar()` es una funcion pura: recibe parametros, devuelve un
 *      `Result`. No escribe en disco, no imprime nada, no toca la red.
 *      Quien quiera (CLI, API o web) decide despues que formato genera.
 *   3. Todo lo accionable va en `findings`, con severidad y recomendacion.
 *      Un reporte que dice "esto es /22" no sirve de nada; uno que dice "has
 *      pedido 400 hosts en una red que tiene 62, usa una /23" sí.
 *
 * DE DONDE SALE. legacy/Validate IP/info-ip.js eran dos lineas sueltas que
 * calculaban un entero y lo reconvertian, sin CLI, sin validacion y sin
 * exportar nada. Aqui la misma matematica vive en core/net/cidr.js (con sus
 * pruebas) y esta herramienta solo la presenta.
 *
 * @module tools/subnet-analyzer
 */

'use strict';

const {
  createResult, addSection, addSummary, addFinding, addLog,
  finalize, failWith, SEVERIDADES, SECCION_KINDS: K
} = require('../core/result');
const { analizarRed, dividirVLSM, planificarVLSM, parseEntrada, listarHosts, normalizarPrefijo } = require('../core/net/cidr');
const { NetlabError, CODES } = require('../core/errors');
const { redactDeep } = require('../core/redact');

/** Identificador de la herramienta. Es el nombre de la carpeta del historial. */
const ID = 'subnet-analyzer';

/**
 * Descripcion de los campos, que es lo que consume el formulario de la web.
 * El tipo `lista-requisitos` lo interpreta el cliente como un bloque de texto
 * con una linea por subred, en formato "Nombre:hosts".
 */
const CAMPOS = [
  {
    name: 'red',
    label: 'Red',
    type: 'text',
    required: true,
    placeholder: '192.168.0.0/22',
    help: 'En CIDR (192.168.0.0/22), o IP y máscara separadas (192.168.0.0 255.255.255.0).'
  },
  {
    name: 'subredes',
    label: 'Reparto en subredes iguales',
    type: 'number',
    required: false,
    min: 2,
    max: 4096,
    placeholder: '8',
    help: 'Opcional. Divide la red en N trozos del mismo tamaño. Es FDM clásico; para tamaños distintos usa el reparto VLSM.'
  },
  {
    name: 'vlsm',
    label: 'Reparto VLSM por tamaño',
    type: 'lista-requisitos',
    required: false,
    placeholder: 'Ventas:100\nAlmacén:20\nInvitados:10',
    help: 'Opcional. Una línea por tramo, "Nombre:número de hosts". Asigna a cada uno el bloque más pequeño que lo contiene.'
  },
  {
    name: 'listar',
    label: 'Incluir el listado de direcciones',
    type: 'checkbox',
    required: false,
    default: false,
    help: 'Añade el rango utilizable completo. Se corta si la red es muy grande.'
  },
  {
    name: 'limite',
    label: 'Máximo de direcciones a listar',
    type: 'number',
    required: false,
    default: 256,
    min: 1,
    max: 4096
  }
];

/**
 * Punto de entrada de la herramienta.
 *
 * @param {object} params Entrada ya validada por el formulario.
 * @param {object} [ctx] Contexto de ejecucion (logger, etc.). Opcional.
 * @returns {object} Result completo, listo para renderizar en cualquier formato.
 */
function ejecutar(params = {}, ctx = {}) {
  const inicio = new Date();
  const log = ctx.log || null;

  const result = createResult({
    tool: ID,
    toolTitle: 'Analizador de subredes',
    target: String(params.red || '').trim(),
    params: redactDeep(params)
  });

  try {
    const entrada = parseEntrada(params.red);
    addLog(result, { level: 'info', channel: 'entrada', message: `Entrada "${entrada.entradaOriginal}" interpretada como ${entrada.ip} / ${entrada.mask}` });
    log?.info?.(`subnet-analyzer: ${entrada.ip}/${entrada.mask}`);

    const red = analizarRed(entrada.ip, entrada.mask);
    addLog(result, { level: 'info', channel: 'cidr', message: `Red ${red.notacionCIDR}, ${red.hostsUtilizables} direcciones utilizables` });

    pintarIdentificacion(result, red, entrada);
    pintarDireccionamiento(result, red);
    revisarRed(result, red, entrada);

    const subredesIguales = pintarIguales(result, params, red);
    const vlsm = pintarVLSM(result, params, red);

    if (!subredesIguales && !vlsm) {
      pintarListado(result, params, red);
    }

    pintarHallazgosFinales(result, red, vlsm);

    return finalize(result, inicio);
  } catch (error) {
    // Un error de entrada no es un fallo del programa: se devuelve un Result
    // con estado 'error' para que se pueda renderizar igual y el usuario lea
    // el mensaje, en vez de un stack de Node.
    addLog(result, { level: 'error', channel: 'error', message: error.message });
    log?.error?.(`subnet-analyzer fallo: ${error.message}`);
    return failWith(finalize(result, inicio), error instanceof NetlabError ? error : new NetlabError(CODES.INTERNO, error.message));
  }
}

/** Bloque "Identificación de la red". */
function pintarIdentificacion(result, red, entrada) {
  addSection(result, {
    title: 'Identificación de la red',
    description: 'Cómo se ha interpretado lo que se escribió.',
    kind: K.PARES,
    items: [
      ['Entrada original', entrada.entradaOriginal],
      ['Formato reconocido', DESCRIPCION_FORMA[entrada.forma] || entrada.forma],
      ['Dirección de red', red.direccionRed],
      ['Máscara punteada', red.mascaraPunteada],
      ['Prefijo', `/${red.prefijo}`],
      ['Tipo de red', red.tipoRed],
      ['Ámbito', red.ambito.nombre, red.ambito.privada ? 'warn' : 'neutral']
    ]
  });
}

/** Bloque "Direccionamiento". */
function pintarDireccionamiento(result, red) {
  addSection(result, {
    title: 'Direccionamiento',
    kind: K.PARES,
    items: [
      ['Dirección de red', red.direccionRed],
      ['Rango utilizable', `${red.rangoUtilizable.primeraIP} - ${red.rangoUtilizable.ultimaIP}`],
      ['Dirección de broadcast', red.direccionBroadcast],
      ['Máscara wildcard', red.mascaraWildcard],
      ['Direcciones totales', red.hostsTotales],
      ['Direcciones reservadas', red.direccionesReservadas],
      ['Direcciones utilizables', red.hostsUtilizables, 'ok'],
      ['Bits de red', red.bitsRed.red],
      ['Bits de host', red.bitsHost],
      ['Clase histórica', red.claseSinPrefijo]
    ]
  });
}

/** Revisa la red en si y anade los hallazgos que se deriven de ella. */
function revisarRed(result, red, entrada) {
  // La IP escrita no es la direccion de red: es normal (lo da un ipconfig),
  // pero conviene decirlo para que nadie espere que lo sea.
  if (red.ipConsultada !== red.direccionRed) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'La dirección escrita está dentro de la red, no es la de red',
      detail: `Se escribió ${red.ipConsultada}, que es una dirección de host. La red es ${red.notacionCIDR}.`,
      recommendation: `Si lo que querías era describir la red completa, usa ${red.notacionCIDR}.`
    });
  }

  if (red.prefijo === 31 || red.prefijo === 32) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: `/${red.prefijo} no sirve como red de usuarios`,
      detail:
        red.prefijo === 31
          ? 'Un /31 es un enlace punto a punto de la RFC 3021, con dos direcciones y sin broadcast.'
          : 'Un /32 es un único host.',
      recommendation: 'Si esto es un segmento de usuarios o de servidores, necesitas como mucho un /29.'
    });
  }

  // La regla 4-2-1 no es una obligacion, pero conviene avisar cuando el
  // prefijo chosen no encaja con la forma de la red.
  if (red.prefijo === 23 || red.prefijo === 22) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `Prefijo /${red.prefijo}: no cumple la regla 4-2-1`,
      detail: `La forma ${red.bitsRed.red} no encaja con un esquema de subredes de tamaño potencia de dos.`,
      recommendation: 'Es perfectamente válido para enrutar; solo ten en cuenta que al dividir en subredes de tamaño potencia de dos aparecería un /24.'
    });
  }

  if (red.ambito.nombre.includes('Enlace local')) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Dirección de enlace local (APIPA)',
      detail: 'El rango 169.254.0.0/16 se autoconfigura cuando un equipo no obtiene dirección por DHCP.',
      recommendation: 'Suele indicar un fallo de DHCP o un cable suelto. No lo uses para planificar direccionamiento.'
    });
  }

  if (red.ambito.nombre === 'Loopback') {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'Dirección de loopback',
      detail: '127.0.0.0/8 apunta al propio equipo y no se enruta.',
      recommendation: 'No la uses como red de trabajo.'
    });
  }

  if (!red.ambito.privada && !red.ambito.nombre.includes('Red actual')) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'La red cae en espacio público',
      detail: `${red.notacionCIDR} no está en los rangos privados de la RFC 1918.`,
      recommendation: 'Si es una red interna, debería caer en 10.0.0.0/8, 172.16.0.0/12 o 192.168.0.0/16.'
    });
  }
}

/** Reparto en subredes iguales. Devuelve true si se pintó. */
function pintarIguales(result, params, red) {
  const bruto = params.subredes;
  if (bruto === undefined || bruto === null || bruto === '') return false;

  const partes = Number(bruto);
  if (!Number.isInteger(partes) || partes < 2) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${bruto}" no es un número válido de subredes.`, {
      remediation: 'Indica un entero mayor que 1, por ejemplo 8.'
    });
  }

  const reparto = dividirVLSM(red.direccionRed, red.prefijo, partes);
  addLog(result, { level: 'info', channel: 'fdm', message: `Reparto en ${partes} subredes iguales: ${reparto.viable ? 'viable' : 'no viable'}` });

  addSection(result, {
    title: 'Reparto en subredes iguales',
    description: reparto.viable
      ? `Cada subred es un /${reparto.prefijoHijo}. ${reparto.nota}`
      : reparto.nota,
    kind: K.TABLA,
    columns: ['#', 'Red', 'Prefijo', 'Máscara', 'Rango utilizable', 'Hosts', 'Broadcast'],
    // Pesa mas la columna del rango, que es la mas larga de las siete. Sin
    // esto el PDF reparte el ancho a partes iguales y "Rango utilizable" queda
    // en tres lineas de diez caracteres.
    anchoColumnas: [5, 16, 7, 15, 24, 7, 16],
    rows: reparto.subredes.map((s) => [
      s.indice,
      s.cidr,
      `/${normalizarPrefijo(String(s.cidr).split('/')[1])}`,
      s.mascara,
      s.rangoUtilizable,
      s.hostsUtilizables,
      s.broadcast
    ])
  });

  if (!reparto.viable) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'No es posible dividir la red en ese número de subredes',
      detail: reparto.nota,
      recommendation: `Reduce el número de subredes: con ${red.notacionCIDR} no se puede llegar a ese número sin superar /32.`
    });
    return true;
  }

  // Si tambien hay VLSM, avisar de que son dos repartos distintos del mismo
  // espacio: aplicarlos los dos a la vez es un error tipico.
  if (params.vlsm) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Has pedido dos repartos a la vez',
      detail: 'El reparto en subredes iguales y el reparto VLSM son dos formas distintas de dividir la misma red.',
      recommendation: 'Aplícalos por separado: o bien repartes todo al mismo tamaño, o bien usas tamaños distintos según la necesidad de cada tramo.'
    });
  }

  return true;
}

/** Reparto VLSM. Devuelve el plan o null si no se pidió. */
function pintarVLSM(result, params, red) {
  const requisitos = parseRequisitos(params.vlsm);
  if (!requisitos.length) return null;

  const plan = planificarVLSM(red.direccionRed, red.prefijo, requisitos);
  addLog(result, {
    level: plan.viable ? 'info' : 'warn',
    channel: 'vlsm',
    message: `Plan VLSM: ${plan.asignaciones.length} de ${requisitos.length} tramos asignados`
  });

  addSection(result, {
    title: 'Reparto VLSM',
    description: plan.nota,
    kind: K.TABLA,
    columns: ['Tramo', 'Red', 'Máscara', 'Rango asignable', 'Puerta de enlace', 'Hosts pedidos', 'Hosts asignados', 'Desperdicio'],
    // Con ocho columnas, repartir el ancho a partes iguales deja las celdas
    // demasiado estrechas. Se pesa cada una segun lo que suele medir su
    // contenido: las direcciones y mascaras necesitan mas, los titulos como
    // "Desperdicio" no deben quedar tan estrechos que el texto se encoja.
    anchoColumnas: [12, 15, 15, 16, 14, 9, 9, 12],
    rows: plan.asignaciones.map((a) => [
      a.nombre,
      a.cidr,
      a.mascara,
      a.rangoUtilizable,
      a.puertaEnlaceSugerida,
      a.hostsPedidos,
      a.hostsAsignados,
      a.desperdicio
    ])
  });

  addSection(result, {
    title: 'Resumen del reparto',
    kind: K.PARES,
    items: [
      ['Red de origen', plan.resumen.redOrigen],
      ['Hosts pedidos', plan.resumen.hostsPedidos],
      ['Hosts asignados', plan.resumen.hostsAsignados, 'ok'],
      ['Desperdicio en los tramos', plan.resumen.desperdicio, plan.resumen.desperdicio > plan.resumen.hostsPedidos * 0.2 ? 'warn' : 'neutral'],
      // Ojo con el nombre: este porcentaje es sobre el total de la red padre,
      // no sobre lo que se ha pedido. Son dos cifras distintas y confundirlas
      // lleva a pensar que un reparto razonable desperdicia la red entera.
      ['Ocupación de la red padre', `${plan.resumen.utilizationPct} %`],
      ['Direcciones libres al final', plan.resumen.huecosFinales]
    ]
  });

  addSection(result, {
    title: 'Aprovechamiento de la red',
    kind: K.BARRA,
    value: plan.resumen.utilizationPct,
    tone: plan.resumen.utilizationPct >= 70 ? 'ok' : plan.resumen.utilizationPct >= 30 ? 'warn' : 'bad'
  });

  if (plan.sinAsignar.length) {
    addSection(result, {
      title: 'Requisitos que no caben',
      kind: K.LISTA,
      items: plan.sinAsignar.map((r) => `${r.nombre || r.id}: ${r.motivo}`)
    });
  }

  return plan;
}

/** Listado de direcciones utilizables, si se pidió. */
function pintarListado(result, params, red) {
  if (!params.listar) return;

  const limite = Math.max(1, Math.min(4096, Number(params.limite) || 256));
  const listado = listarHosts(red.direccionRed, red.prefijo, { limite });

  addSection(result, {
    title: 'Direcciones utilizables',
    description: listado.truncada
      ? `Se muestran las primeras ${listado.hosts.length} de ${listado.total}. La red es demasiado grande para listarla entera.`
      : `Las ${listado.hosts.length} direcciones del rango.`,
    kind: K.CODIGO,
    value: listado.hosts.join('\n')
  });

  if (listado.truncada) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'Listado truncado',
      detail: `La red tiene ${listado.total} direcciones utilizables y solo se han mostrado ${listado.hosts.length}.`,
      recommendation: 'Sube el límite si necesitas el rango completo, pero ten en cuenta que un listado enorme no aporta nada al informe.'
    });
  }
}

/** Hallazgos que dependen de cómo ha quedado el conjunto del reparto. */
function pintarHallazgosFinales(result, red, vlsm) {
  if (!vlsm) return;

  if (!vlsm.viable) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'El reparto VLSM no cubre todos los tramos',
      detail: vlsm.nota,
      recommendation: 'Sube el prefijo de la red padre o reparte el requisito más grande en dos tramos.'
    });
  }

  // Un reparto muy desperdiciado suele delatar un prefijo padre demasiado
  // grande para lo que realmente se va a usar.
  //
  // El umbral es "se asigna mas de 1,5 veces lo pedido", que equivale a
  // desperdiciar mas de un tercio de lo asignado. La cifra que se muestra es
  // el aprovechamiento de cada tramo sobre lo que ocupa, NO la ocupacion de la
  // red padre: son dos medidas distintas y aqui la que interesa es la del
  // reparto, porque es la que delata tramos sobredimensionados.
  const { hostsPedidos, hostsAsignados } = vlsm.resumen;
  if (hostsPedidos > 0 && hostsAsignados > hostsPedidos * 1.5) {
    const pctSobrePedido = Math.round((hostsPedidos / hostsAsignados) * 1000) / 10;
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: `Los tramos solo aprovechan el ${pctSobrePedido} % de las direcciones que ocupan`,
      detail: `Pides ${hostsPedidos} hosts y el reparto asigna ${hostsAsignados}: cada tramo debe ocupar una potencia de dos, y los sobrantes no se pueden repartir.`,
      recommendation: 'Reparte el tramo grande en varios tramos mas pequenos, o baja un prefijo en la red padre (por ejemplo, de /22 a /23) para no arrastrar espacio sobrante.'
    });
  }
}

/**
 * Convierte el texto del campo VLSM en requisitos.
 *
 * Acepta "Nombre:50", "Nombre=50" y "Nombre, 50", y tambien solo "50", que se
 * nombrará por su posición. Se permiten varias líneas y se ignoran las vacías.
 *
 * @param {string} texto
 * @returns {Array<{nombre: string, hosts: number}>}
 * @throws {NetlabError} Si una línea no se puede entender.
 */
function parseRequisitos(texto) {
  if (texto === undefined || texto === null) return [];
  if (Array.isArray(texto)) return texto; // ya viene estructurado desde la API

  const lineas = String(texto)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  if (!lineas.length) return [];

  return lineas.map((linea, i) => {
    const partes = linea.split(/[:=,\t]/).map((p) => p.trim());
    const numero = partes.pop();
    const nombre = partes.join(' ').trim() || `Tramo ${i + 1}`;

    if (!/^\d+$/.test(numero)) {
      throw new NetlabError(CODES.PARAM_INVALIDO, `La línea "${linea}" no termina en un número de hosts.`, {
        remediation: 'Escribe cada tramo como "Nombre:número". Por ejemplo: Ventas:100'
      });
    }

    return { nombre, hosts: Number(numero) };
  });
}

/** Descripciones legibles de los formatos de entrada reconocidos. */
const DESCRIPCION_FORMA = {
  'cidr-prefijo': 'Notación CIDR, con el prefijo en número de bits (192.168.1.0/24)',
  'cidr-mascara': 'Máscara punteada, los 32 bits en decimal (192.168.1.0/255.255.255.0)',
  'ip-mascara': 'IP y máscara escritas por separado',
  host: 'Solo una IP, sin prefijo: se asume /32'
};

module.exports = {
  id: ID,
  titulo: 'Analizador de subredes',
  descripcion: 'Calcula el direccionamiento de una red, reparte subredes iguales o hace un reparto VLSM por tamaño de cada tramo.',
  sinRed: false,
  icon: '🕸️',
  campos: CAMPOS,
  ejecutar,
  parseRequisitos
};
