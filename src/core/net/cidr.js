/**
 * net/cidr.js — Matematica de subredes IPv4.
 *
 * MODULO DE ARREGLO. legacy/Validate IP/info-ip.js tenia dos problemas reales:
 *
 *   1. Contaba los bits del prefijo con un truco: `toString(2).split('1').length - 1`.
 *      Para 255 funciona por casualidad, pero es fragil e ilegible.
 *   2. Trataba /31 como "0 hosts utilizables". RFC 3021 define /31 (point-to-point)
 *      con 2 direcciones utilizables, porque el prefijo y el broadcast no existen
 *      como tal en un enlace punto a punto.
 *
 * Ademas el script original era un `console.log` de dos casos fijos: no tenia
 * CLI, no validaba la entrada y no exportaba nada. Aqui es una funcion pura,
 * reutilizable desde la web y desde cualquier otra herramienta.
 *
 * @module core/net/cidr
 */

'use strict';

const { NetlabError, CODES } = require('../errors');

/** Rangos especiales de IPv4 (RFC 1918 y reservados). */
const ESPECIALES = [
  { cidr: '0.0.0.0/8', nombre: 'Red actual (este host)' },
  { cidr: '10.0.0.0/8', nombre: 'Privada RFC 1918' },
  { cidr: '100.64.0.0/10', nombre: 'Espacio compartido RFC 6598 (CGNAT)' },
  { cidr: '127.0.0.0/8', nombre: 'Loopback' },
  { cidr: '169.254.0.0/16', nombre: 'Enlace local (APIPA)' },
  { cidr: '172.16.0.0/12', nombre: 'Privada RFC 1918' },
  { cidr: '192.0.2.0/24', nombre: 'Documentacion RFC 5737' },
  { cidr: '192.168.0.0/16', nombre: 'Privada RFC 1918' },
  { cidr: '198.18.0.0/15', nombre: 'Pruebas de rendimiento RFC 2544' },
  { cidr: '224.0.0.0/4', nombre: 'Multicast' },
  { cidr: '240.0.0.0/4', nombre: 'Reservada' },
  { cidr: '255.255.255.255/32', nombre: 'Difusion limitada' }
];

/**
 * Valida que una cadena sea una IPv4 y devuelve sus cuatro octetos.
 *
 * @param {string} ip
 * @returns {number[]} [a, b, c, d]
 * @throws {NetlabError} Si no es una IPv4 valida.
 */
function octetos(ip) {
  const partes = String(ip ?? '').trim().split('.');
  if (partes.length !== 4) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${ip}" no es una IPv4 válida.`, {
      remediation: 'Una IPv4 tiene cuatro números separados por puntos, entre 0 y 255. Ejemplo: 192.168.1.10'
    });
  }

  const nums = partes.map((p) => {
    if (!/^\d{1,3}$/.test(p)) {
      throw new NetlabError(CODES.PARAM_INVALIDO, `"${ip}" no es una IPv4 válida.`, {
        remediation: 'Cada octeto debe ser un número entero sin signo. Ejemplo: 192.168.1.10'
      });
    }
    const n = Number(p);
    if (n > 255) {
      throw new NetlabError(CODES.PARAM_INVALIDO, `"${ip}" no es una IPv4 válida.`, {
        remediation: `El octeto ${p} supera el máximo de 255.`
      });
    }
    return n;
  });

  return nums;
}

/**
 * Convierte una mascara punteada en longitud de prefijo.
 *
 * @param {string} mask Ej. '255.255.255.252'
 * @returns {number} 0..32
 * @throws {NetlabError} Si la mascara no es valida o no es contigua.
 */
function prefijoDesdeMascara(mask) {
  const octs = octetos(mask);
  const bits = octs.map((o) => o.toString(2).padStart(8, '0')).join('');

  // Una mascara valida es una racha de unos seguida de ceros: /24 = 11111111
  // 11111111 11111111 00000000. Con un hueco en medio no describe ninguna red.
  if (!/^1*0*$/.test(bits)) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${mask}" no es una máscara de subred válida.`, {
      remediation: 'Una máscara válida es una secuencia de bits 1 seguida de bits 0, sin interrupciones. Ejemplo: 255.255.255.252 = /30'
    });
  }

  return bits.split('0')[0].length;
}

/**
 * Acepta la máscara en cualquiera de sus dos formas y devuelve el prefijo.
 *
 * @param {string} entrada '255.255.255.252' o '/30' o '30'
 * @returns {number} 0..32
 */
function normalizarPrefijo(entrada) {
  const s = String(entrada ?? '').trim();

  if (/^\d{1,2}$/.test(s)) {
    const n = Number(s);
    if (n > 32) {
      throw new NetlabError(CODES.PARAM_INVALIDO, `El prefijo /${s} no existe.`, {
        remediation: 'Un prefijo IPv4 va de /0 a /32.'
      });
    }
    return n;
  }

  if (s.startsWith('/')) {
    const n = Number(s.slice(1));
    if (!Number.isInteger(n) || n < 0 || n > 32) {
      throw new NetlabError(CODES.PARAM_INVALIDO, `El prefijo ${s} no es válido.`, {
        remediation: 'Un prefijo IPv4 va de /0 a /32.'
      });
    }
    return n;
  }

  return prefijoDesdeMascara(s);
}

/** Construye la mascara punteada de un prefijo. */
function mascaraDesdePrefijo(prefijo) {
  const n = Math.min(32, Math.max(0, prefijo));
  const int = n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0;
  return intToIp(int);
}

/** Convierte un entero de 32 bits a notacion IPv4. */
function intToIp(int) {
  const v = int >>> 0;
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
}

/** Convierte una IPv4 a entero de 32 bits. */
function ipToInt(ip) {
  const [a, b, c, d] = octetos(ip);
  // >>> 0 es necesario: sin el, JS trata el resultado como signed y las
  // direcciones por encima de 127.255.255.255 salen negativas.
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

/**
 * Analiza una red completa a partir de una IP y una máscara.
 *
 * @param {string} ip Direccion IPv4.
 * @param {string} mask Mascara punteada o prefijo ('255.255.255.252', '/30', '30').
 * @returns {object} Descripcion completa de la red.
 * @throws {NetlabError} Con datos invalidos.
 */
function analizarRed(ip, mask) {
  const ipInt = ipToInt(ip);
  const prefijo = normalizarPrefijo(mask);
  const mascaraInt = prefijo === 0 ? 0 : (0xffffffff << (32 - prefijo)) >>> 0;
  const wildcardInt = ~mascaraInt >>> 0;

  const redInt = (ipInt & mascaraInt) >>> 0;
  const broadcastInt = (redInt | wildcardInt) >>> 0;

  const total = 2 ** (32 - prefijo);

  // /31 -> RFC 3021: punto a punto, ambas direcciones utilizables.
  // /32 -> host unico: la unica direccion es la del propio host.
  // resto -> se reservan red y broadcast.
  let utilizables;
  let primera;
  let ultima;
  let reservadas;

  if (prefijo === 32) {
    utilizables = 1;
    primera = intToIp(redInt);
    ultima = intToIp(redInt);
    reservadas = 0;
  } else if (prefijo === 31) {
    utilizables = 2;
    primera = intToIp(redInt);
    ultima = intToIp(broadcastInt);
    reservadas = 0;
  } else {
    utilizables = total - 2;
    primera = intToIp((redInt + 1) >>> 0);
    ultima = intToIp((broadcastInt - 1) >>> 0);
    reservadas = 2;
  }

  const direccionRed = intToIp(redInt);
  const enRango =
    ipInt >= redInt && ipInt <= broadcastInt;

  return {
    ipConsultada: String(ip).trim(),
    prefijo,
    notacionCIDR: `${direccionRed}/${prefijo}`,
    mascaraPunteada: mascaraDesdePrefijo(prefijo),
    mascaraWildcard: intToIp(wildcardInt),
    direccionRed,
    direccionBroadcast: intToIp(broadcastInt),
    rangoUtilizable: { primeraIP: primera, ultimaIP: ultima },
    hostsTotales: total,
    hostsUtilizables: utilizables,
    direccionesReservadas: reservadas,
    tipoRed: clasificarRed(prefijo),
    ambito: clasificarAmbito(redInt, prefijo),
    bitsRed: bitsDePrefijo(prefijo),
    bitsHost: 32 - prefijo,
    ipDentroDeLaRed: enRango,
    claseSinPrefijo: claseHistorica(redInt)
  };
}

/** Clasifica la red segun su tamano, en espanol. */
function clasificarRed(prefijo) {
  if (prefijo === 32) return 'Host único';
  if (prefijo === 31) return 'Punto a punto (RFC 3021)';
  if (prefijo >= 30) return 'Red de enlace / LAN pequeña';
  if (prefijo >= 24) return 'Red de tamaño medio';
  if (prefijo >= 16) return 'Red corporativa grande';
  if (prefijo >= 8) return 'Red muy grande (bloque /8)';
  return 'Superrred o ruta por defecto';
}

/** Devuelve true si la red cae dentro de un rango reservado o privado. */
function clasificarAmbito(redInt, prefijo) {
  const redIp = intToIp(redInt);
  for (const { cidr } of ESPECIALES) {
    const [dir, preStr] = cidr.split('/');
    const prefEspecial = normalizarPrefijo(preStr.startsWith('/') ? preStr : `/${preStr}`);
    const redEspecialInt = ipToInt(dir);
    const mascaraEspecialInt = prefEspecial === 0 ? 0 : (0xffffffff << (32 - prefEspecial)) >>> 0;
    const inicioEspecial = (redInt & mascaraEspecialInt) >>> 0;
    if (inicioEspecial === redEspecialInt && prefijo >= prefEspecial) {
      const privada =
        cidr.startsWith('10.') ||
        cidr.startsWith('192.168.') ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(dir);
      return { nombre: ESPECIALES.find((e) => e.cidr === cidr)?.nombre || 'Reservada', cidr: `${redIp}/${prefijo}`, privada };
    }
  }
  return { nombre: 'Pública', cidr: `${redIp}/${prefijo}`, privada: false };
}

/** Devuelve la clase historica (A, B, C) que tendria sin mascara. */
function claseHistorica(redInt) {
  const primerOcteto = (redInt >>> 24) & 255;
  if (primerOcteto <= 126) return 'Clase A';
  if (primerOcteto <= 191) return 'Clase B';
  if (primerOcteto <= 223) return 'Clase C';
  return 'Clase D/E';
}

/** Representacion binaria de los bits de red y de host. */
function bitsDePrefijo(prefijo) {
  const red = '1'.repeat(prefijo) + '0'.repeat(32 - prefijo);
  const host = '0'.repeat(prefijo) + '1'.repeat(32 - prefijo);
  return {
    red: `${red.slice(0, 8)}.${red.slice(8, 16)}.${red.slice(16, 24)}.${red.slice(24)}`,
    host: `${host.slice(0, 8)}.${host.slice(8, 16)}.${host.slice(16, 24)}.${host.slice(24)}`
  };
}

/**
 * Lista de direcciones utiles de una red.
 *
 * @param {string} ip
 * @param {string} mask
 * @param {object} [options]
 * @param {number} [options.limite=1024] Tope para no inundar el reporte.
 * @returns {{ hosts: string[], truncada: boolean, total: number }}
 */
function listarHosts(ip, mask, options = {}) {
  const { limite = 1024 } = options;
  const red = analizarRed(ip, mask);
  const total = red.hostsUtilizables;
  const aMostrar = Math.min(total, limite);

  const inicio = ipToInt(red.rangoUtilizable.primeraIP);
  const hosts = [];
  for (let i = 0; i < aMostrar; i++) hosts.push(intToIp((inicio + i) >>> 0));

  return { hosts, truncada: total > aMostrar, total };
}

/**
 * Descompone una red en `n` subredes de tamaño uniforme.
 *
 * Es la calculadora VLSM basica: reparte `n` partes iguales y calcula los
 * prefijos que hace falta.
 *
 * @param {string} ip
 * @param {string} mask
 * @param {number} partes Numero de subredes deseadas (potencia de dos o no).
 * @returns {object} { viable, subredes: [...], nota }
 */
function dividirVLSM(ip, mask, partes) {
  const red = analizarRed(ip, mask);

  if (!Number.isInteger(partes) || partes < 1) {
    throw new NetlabError(CODES.PARAM_INVALIDO, 'El número de subredes debe ser un entero mayor que 0.', {});
  }

  if (red.prefijo + Math.ceil(Math.log2(partes)) > 32) {
    return {
      viable: false,
      nota: `No es posible dividir ${red.notacionCIDR} en ${partes} subredes: el prefijo pasaria de /32.`,
      subredes: []
    };
  }

  const prefijoHijo = red.prefijo + Math.ceil(Math.log2(partes));
  const subredes = [];
  const inicio = ipToInt(red.direccionRed);
  const paso = 2 ** (32 - prefijoHijo);

  for (let i = 0; i < partes; i++) {
    const netInt = (inicio + i * paso) >>> 0;
    const bcastInt = (netInt | ~(0xffffffff << (32 - prefijoHijo)) >>> 0) >>> 0;
    subredes.push({
      indice: i + 1,
      cidr: `${intToIp(netInt)}/${prefijoHijo}`,
      mascara: mascaraDesdePrefijo(prefijoHijo),
      rangoUtilizable: `${intToIp((netInt + 1) >>> 0)} - ${intToIp((bcastInt - 1) >>> 0)}`,
      hostsUtilizables: prefijoHijo === 31 ? 2 : paso - 2,
      broadcast: intToIp(bcastInt)
    });
  }

  return {
    viable: true,
    nota:
      partes === 2 ** Math.ceil(Math.log2(partes))
        ? `Reparto exacto en ${partes} subredes /${prefijoHijo}.`
        : `${partes} no es potencia de dos: se crean ${partes} subredes /${prefijoHijo} y sobran ${
            2 ** Math.ceil(Math.log2(partes)) - partes
          } direcciones de bloque.`,
    prefijoHijo,
    subredes
  };
}

/**
 * Planifica un reparto VLSM a partir de requisitos de hosts reales.
 *
 * ESTO NO EXISTIA Y ES LA RAZON DE SER DE LA HERRAMIENTA. `dividirVLSM` reparte
 * la red en N trozos iguales, que es un reparto FDM classico y casi nunca es lo
 * que se quiere en una red real: un tramo de contabilidad de 8 equipos y otro
 * de acceso deILO para 300 equipos no pueden medir lo mismo. El VLSM asigna a
 * cada tramo justo el bloque que necesita.
 *
 * El reparto es voraz y va de mayor a menor tamano de requisito. Es el
 * algoritmo que se enseña y el que mas veces funciona bien, pero conviene
 * saber su limitacion: no es optimo. Hay repartos VLSM imposibles de conseguir
 * de forma voraz que si lo son con backtracking. Para un calculo de planificacion
 * el voraz es la opcion razonable; para una prueba de examen, la unica.
 *
 * @param {string} ip Direccion de la red.
 * @param {string} mask Mascara o prefijo.
 * @param {Array<{nombre?: string, hosts: number, id?: string}>} requisitos
 * @returns {object} { viable, asignaciones, sinAsignar, resumen, nota }
 */
function planificarVLSM(ip, mask, requisitos) {
  const red = analizarRed(ip, mask);

  if (!Array.isArray(requisitos) || requisitos.length === 0) {
    throw new NetlabError(CODES.PARAM_INVALIDO, 'Hay que indicar al menos un requisito de subred.', {
      remediation: 'Ejemplo: [{ nombre: "Ventas", hosts: 50 }, { nombre: "Invitados", hosts: 20 }]'
    });
  }

  for (const r of requisitos) {
    if (!Number.isInteger(r.hosts) || r.hosts < 1) {
      throw new NetlabError(CODES.PARAM_INVALIDO, `El requisito "${r.nombre || r.id || 'sin nombre'}" debe pedir un número entero de hosts mayor que 0.`, {});
    }
    if (r.hosts > red.hostsUtilizables) {
      throw new NetlabError(
        CODES.PARAM_INVALIDO,
        `El requisito "${r.nombre || r.id || 'sin nombre'}" pide ${r.hosts} hosts, pero ${red.notacionCIDR} solo tiene ${red.hostsUtilizables} utilizables.`,
        { remediation: 'Reduce el requisito o elige una red padre mas grande.' }
      );
    }
  }

  // Ordena de mayor a menor. Se desempata por el orden de entrada para que el
  // resultado sea reproducible: dos ejecuciones con los mismos datos dan
  // exactamente el mismo plan.
  const ordenados = requisitos
    .map((r, i) => ({ ...r, _orden: i }))
    .sort((a, b) => b.hosts - a.hosts || a._orden - b._orden);

  const inicioRed = ipToInt(red.direccionRed);
  const finRed = (inicioRed + red.hostsTotales - 1) >>> 0;

  // Cursor: siguiente direccion libre. Empieza en la red, no en la primera
  // utilizable, porque la asignacion de un bloque incluye su propia direccion
  // de red.
  let cursor = inicioRed;
  const asignaciones = [];
  const sinAsignar = [];

  for (const req of ordenados) {
    // Cada tramo reserva su red y su broadcast, salvo en punto a punto.
    const necesarias = req.hosts === 2 ? 2 : req.hosts + 2;
    const bits = Math.ceil(Math.log2(necesarias));
    const prefijo = 32 - bits;
    const tamano = 2 ** bits;

    if (prefijo < 0) {
      sinAsignar.push({ ...req, motivo: 'El requisito no cabe en un prefijo válido de IPv4.' });
      continue;
    }

    // Alinea el cursor al tamaño del bloque: sin esto, el reparto deja huecos
    // que hacen que el aprovechamiento de la red caiga.
    const alineado = (Math.ceil(cursor / tamano) * tamano) >>> 0;

    if (alineado + tamano - 1 > finRed) {
      sinAsignar.push({
        ...req,
        motivo: `No queda espacio: quedan ${Math.max(0, finRed - cursor + 1)} direcciones libres y este tramo necesita ${tamano}.`
      });
      continue;
    }

    const broadcast = (alineado + tamano - 1) >>> 0;
    const utilizables = req.hosts === 2 ? 2 : tamano - 2;

    asignaciones.push({
      id: req.id || req.nombre || `subred-${asignaciones.length + 1}`,
      nombre: req.nombre || req.id || `Subred ${asignaciones.length + 1}`,
      hostsPedidos: req.hosts,
      hostsAsignados: utilizables,
      desperdicio: utilizables - req.hosts,
      cidr: `${intToIp(alineado)}/${prefijo}`,
      prefijo,
      mascara: mascaraDesdePrefijo(prefijo),
      direccionRed: intToIp(alineado),
      rangoUtilizable:
        req.hosts === 2
          ? `${intToIp(alineado)} - ${intToIp(broadcast)}`
          : `${intToIp((alineado + 1) >>> 0)} - ${intToIp((broadcast - 1) >>> 0)}`,
      primeraUtilizable: req.hosts === 2 ? intToIp(alineado) : intToIp((alineado + 1) >>> 0),
      ultimaUtilizable: req.hosts === 2 ? intToIp(broadcast) : intToIp((broadcast - 1) >>> 0),
      puertaEnlaceSugerida: req.hosts === 2 ? intToIp(alineado) : intToIp((alineado + 1) >>> 0),
      broadcast: intToIp(broadcast),
      tipoRed: clasificarRed(prefijo)
    });

    cursor = (alineado + tamano) >>> 0;
  }

  // Ordena el resultado por el orden en que se pidio, que es como lo lee la
  // persona que pidio el reparto.
  asignaciones.sort((a, b) => requisitos.findIndex((r) => (r.id || r.nombre) === a.id) - requisitos.findIndex((r) => (r.id || r.nombre) === b.id));

  const quedaEspacio = cursor <= finRed;
  const usados = asignaciones.reduce((acc, a) => acc + a.hostsAsignados, 0);
  const desperdiciado = asignaciones.reduce((acc, a) => acc + a.desperdicio, 0);
  const huecos = Math.max(0, finRed - cursor + 1);

  return {
    viable: sinAsignar.length === 0,
    asignaciones,
    sinAsignar,
    resumen: {
      redOrigen: red.notacionCIDR,
      direccionesTotales: red.hostsTotales,
      hostsPedidos: requisitos.reduce((acc, r) => acc + r.hosts, 0),
      hostsAsignados: usados,
      desperdicio: desperdiciado,
      utilizationPct: red.hostsUtilizables ? Number(((usados / red.hostsUtilizables) * 100).toFixed(1)) : 0,
      huecosFinales: huecos,
      quedaEspacio
    },
    nota: sinAsignar.length
      ? `${sinAsignar.length} requisito(s) no caben en ${red.notacionCIDR}.`
      : `Todos los requisitos caben en ${red.notacionCIDR}.`
  };
}

/**
 * Interpreta la entrada de red que escribe una persona y la separa en IP y
 * mascara, que es lo que necesitan el resto de funciones.
 *
 * Acepta las tres formas habituales, porque en un formulario de la web la
 * gente teclea como le sale y nonequivale a que este equivocado:
 *
 *   192.168.1.0/24          notacion CIDR
 *   192.168.1.0 255.255.255.0   IP y mascara separadas
 *   192.168.1.10/255.255.255.0  IP de host con mascara (la mas comun al copiar
 *                                de un ipconfig)
 *
 * @param {string} entrada Texto introducido por la persona.
 * @returns {{ip: string, mask: string, forma: string, entradaOriginal: string}}
 * @throws {NetlabError} Si no se reconoce el formato.
 */
function parseEntrada(entrada) {
  const texto = String(entrada ?? '').trim().replace(/\s+/g, ' ');

  if (!texto) {
    throw new NetlabError(CODES.PARAM_INVALIDO, 'No se indicó ninguna red.', {
      remediation: 'Escribe una red en CIDR, por ejemplo 192.168.1.0/24'
    });
  }

  // Forma "IP mascara": separador de espacios.
  if (/\s/.test(texto)) {
    const partes = texto.split(' ');
    if (partes.length === 2) {
      return { ip: partes[0], mask: partes[1], forma: 'ip-mascara', entradaOriginal: texto };
    }
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${texto}" no se pudo interpretar.`, {
      remediation: 'Se esperaba una IP y una máscara separadas por un espacio. Ejemplo: 192.168.1.0 255.255.255.0'
    });
  }

  // Forma "IP/mascara": el separador puede ser "/" o cualquier barra.
  if (texto.includes('/')) {
    const [ip, mask] = texto.split('/');
    if (!mask) {
      throw new NetlabError(CODES.PARAM_INVALIDO, `Falta la máscara en "${texto}".`, {
        remediation: 'Ejemplo: 192.168.1.0/24'
      });
    }
    return { ip, mask, forma: mask.includes('.') ? 'cidr-mascara' : 'cidr-prefijo', entradaOriginal: texto };
  }

  // Forma "IP sola": se asume /32 (un host).
  return { ip: texto, mask: '32', forma: 'host', entradaOriginal: texto };
}

module.exports = {
  analizarRed,
  listarHosts,
  dividirVLSM,
  planificarVLSM,
  parseEntrada,
  normalizarPrefijo,
  prefijoDesdeMascara,
  mascaraDesdePrefijo,
  octetos,
  ipToInt,
  intToIp,
  ESPECIALES
};