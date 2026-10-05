/**
 * net/dnsbl.js — Consulta de listas negras por DNS.
 *
 * COMO FUNCIONA UNA LISTA NEGRA. No hay un servidor central al que preguntar
 * "¿esta IP es mala?". Cada lista publica su propia zona DNS, y la pregunta se
 * hace escribiendo la IP AL REVES en esa zona. Si la zona responde con un
 * registro A, la IP esta listada; si responde "no existe ese nombre", no lo esta.
 *
 * TRES DETALLES QUE ROMPEN LA CONSULTA SI SE IGNORAN:
 *
 * 1. El nombre al reves son los OCTETOS en IPv4 y los NIBBLES en IPv6. Escribir
 *    los bytes al reves en IPv6 produce un nombre que existe pero nunca devuelve
 *    lo que se le pregunta, y el resultado es un "no listada" falso. De ahi que
 *    el calculo viva en `core/net/ipaddr`.
 *
 * 2. Spamhaus ZEN se consulta con el ULTIMO OCTETO FUERA. Su zona no tiene una
 *    entrada por IP, tiene una por /24, asi que `203.0.113.7` se pregunta como
 *    `3.113.0.203.zen.spamhaus.org`. Consultarla con los cuatro octetos devuelve
 *    "no existe" siempre, y el informe sale limpio para una IP que si esta
 *    listada. Cada lista dice en su ficha si lo necesita.
 *
 * 3. Un fallo de red NO es "no listada". Si la zona no responde, o devuelve
 *    SERVFAIL, no se sabe nada: la zona esta caida o el bloque de la IP prohibe
 *    consultar esas zonas. Por eso hay tres estados y no dos, y "sin datos" se
 *    cuenta aparte en el informe. Una lista negra que devuelve SERVFAIL a todo
 *    el mundo se lleva por delante el informe entero, y con un resumen que solo
 *    distingue lista/no listada eso seria un "todo limpio" falso.
 *
 * @module core/net/dnsbl
 */

'use strict';

const ipaddr = require('./ipaddr');
const dnsNet = require('./dns');
const { NetlabError, CODES } = require('../errors');

/** La IP es de las que estas listas no cubren. */
const SIN_APLICAR = 'no-aplica';
const LIMPIA = 'limpio';
const LISTADA = 'listada';
const SIN_DATOS = 'sin-datos';

/**
 * Las listas que se consultan por defecto.
 *
 * Son ocho de uso general y gratuitas. La eleccion es deliberadamente corta:
 * consultar cuarenta zonas cuesta tiempo y, sobre todo, cada lista que se apaga
 * sin avisar mete ruido en el informe. Si el usuario quiere mas, pide el
 * conjunto ampliado.
 *
 * Ninguna es fiable al cien por cien. Spamhaus, en concreto, tiene niveles de
 * confianza y solo devuelve datos a quien consulta desde una IP registrada en su
 * sistema, asi que desde una IP de servidor puede responder vacio. Eso es una
 * limitacion real de la consulta y por eso el informe la dice, en vez de
 * presentar un "todo limpio" con la misma seguridad que un "todo sucio".
 */
const LISTAS_CORTA = [
  {
    clave: 'spamhaus-zen',
    nombre: 'Spamhaus ZEN',
    proveedor: 'Spamhaus',
    categoria: 'correo',
    zona: 'zen.spamhaus.org',
    ipv6: false,
    quitarUltimoOcteto: true,
    nota: 'La lista mas referida. En IPv4 se consulta por bloques /24.'
  },
  {
    clave: 'spamhaus-xbl',
    nombre: 'Spamhaus XBL',
    proveedor: 'Spamhaus',
    categoria: 'correo',
    zona: 'xbl.spamhaus.org',
    ipv6: false,
    quitarUltimoOcteto: true,
    nota: 'Equipos comprometidos, distinta de ZEN.'
  },
  {
    clave: 'spamhaus-bcl',
    nombre: 'Spamhaus BCL (Botnet C&C)',
    proveedor: 'Spamhaus',
    categoria: 'botnet-c2',
    zona: 'bcl.spamhaus.org',
    ipv6: false,
    // BCL NO va por bloques /24 como ZEN: la ficha de una IP registra esa IP
    // concreta. Preguntar por el /24 entero daria un nombre que no existe, y un
    // "no listada" de una IP que si lo esta. Por eso `quitarUltimoOcteto` es
    // `false` aqui y `true` en ZEN, con la misma zona de por medio.
    quitarUltimoOcteto: false,
    nota: 'Controladores de botnet. A diferencia de las otras, no mide correo: mide a quien manda el malware, y por eso va en su propia seccion del informe.'
  },
  {
    clave: 'spamcop',
    nombre: 'SpamCop',
    proveedor: 'SpamCop',
    categoria: 'correo',
    zona: 'bl.spamcop.net',
    ipv6: false,
    quitarUltimoOcteto: false,
    nota: 'Lista de supuestos remitentes de spam.'
  },
  {
    clave: 'barracuda',
    nombre: 'Barracuda',
    proveedor: 'Barracuda',
    categoria: 'correo',
    zona: 'b.barracudacentral.org',
    ipv6: false,
    quitarUltimoOcteto: false,
    nota: 'Lista de reputacion de servidores de correo.'
  },
  {
    clave: 'uceprotect1',
    nombre: 'UCEPROTECT (nivel 1)',
    proveedor: 'UCEPROTECT',
    categoria: 'correo',
    zona: 'dnsbl-1.uceprotect.net',
    ipv6: false,
    quitarUltimoOcteto: false,
    nota: 'Nivel 1: las senales de listado mas claras, con menos falsos positivos.'
  },
  {
    clave: 'uceprotect2',
    nombre: 'UCEPROTECT (nivel 2)',
    proveedor: 'UCEPROTECT',
    categoria: 'correo',
    zona: 'dnsbl-2.uceprotect.net',
    ipv6: false,
    quitarUltimoOcteto: false,
    nota: 'Nivel 2: mas cobertura y mas falsos positivos que el nivel 1.'
  },
  {
    clave: 'surriel-psbl',
    nombre: 'PSBL (Surgos)',
    proveedor: 'PSBL',
    categoria: 'correo',
    zona: 'psbl.surriel.com',
    ipv6: false,
    quitarUltimoOcteto: false,
    nota: 'Lista mantenida a mano. Solo contiene entradas confirmadas.'
  },
  {
    clave: 'dronebl',
    nombre: 'DroneBL',
    proveedor: 'DroneBL',
    categoria: 'correo',
    zona: 'dnsbl.dronebl.org',
    ipv6: false,
    quitarUltimoOcteto: false,
    nota: 'Zonas separadas por pais y por servicio.'
  }
];
/**
 * Conjunto ampliado, para cuando con ocho no se ve lo que se busca.
 *
 * Se anaden las dos zonas que siguen respondiendo y no estan en la lista corta:
 * SBL y el nivel 3 de UCEPROTECT. Las dos vienen con la misma advertencia que
 * sus irmas, y el nivel 3 de UCEPROTECT es agresivo por definicion: mete IP de
 * servidores enteros por un solo aviso, asi que su opinion vale menos que la
 * del nivel 1.
 *
 * Lo que NO esta aqui, y conviene decir por que:
 *
 * - `bl.trix.org.uk`, `bl.spamarrest.com`, `bl.spamcan.com`, `dnsbl.sorbs.net`,
 *   `bl.0spam.org`, `bl.mailspike.net`, `rbl.ints.net`: se comprobo que ya no
 *   publican registro SOA, o sea que la zona no existe. Una zona muerta devuelve
 *   "no existe" igual que una zona sana, asi que meterlas solo da un falso
 *   "no listada".
 * - `cbl.abuseat.org`: la zona sigue viva, pero el servicio esta retirado. Igual
 *   que en el caso anterior, devolveria un "todo limpio" sin base.
 * - `dbl.spamhaus.org`: es una lista de DOMINIOS, no de direcciones. Se
 *   comprobo que responde con un registro a cualquier nombre que se le pregunte,
 *   incluida la IP al reves, y eso es exactamente la trampa de consultar una
 *   lista para algo que no es.
 *
 * @type {object[]}
 */
const LISTAS_AMPLIA = [
  ...LISTAS_CORTA,
  {
    clave: 'spamhaus-sbl',
    nombre: 'Spamhaus SBL',
    proveedor: 'Spamhaus',
    categoria: 'correo',
    zona: 'sbl.spamhaus.org',
    ipv6: false,
    quitarUltimoOcteto: true,
    nota: 'Solo se admite consulta desde una direccion registrada en Spamhaus.'
  },
  {
    clave: 'uceprotect3',
    nombre: 'UCEPROTECT (nivel 3)',
    proveedor: 'UCEPROTECT',
    categoria: 'correo',
    zona: 'dnsbl-3.uceprotect.net',
    ipv6: false,
    quitarUltimoOcteto: false,
    nota: 'Nivel 3: agresivo. Un solo aviso puede meter una IP entera.'
  }
];

/**
 * Aviso que viaja con el resultado, porque cambia como se lee el informe.
 *
 * Spamhaus no da su veredicto de gracia a quien consulta desde una IP de centro
 * de datos. Responde "no existe" tanto si la IP esta limpia como si quien
 * pregunta no tiene acceso a los datos. Desde fuera es indistinguible, y por eso
 * se dice en el informe en vez de dejar que "todo limpio" parezca una certeza.
 */
const AVISO_SPAMHAUS =
  'Spamhaus solo devuelve datos a quien consulta desde una direccion registrada en su sistema. ' +
  'Desde un servidor o una VPS, un "no listada" de sus zonas puede querer decir "sin datos para ti" ' +
  'y no "IP limpia".';

/**
 * Los octetos (IPv4) o nibbles (IPv6) de una IP, AL REVES y SIN zona.
 *
 * `ipaddr.nombreInvertido` devuelve el nombre completo de la zona inversa, con
 * `.in-addr.arpa` o `.ip6.arpa` al final. Ese sufijo es correcto para pedir un
 * PTR, y es exactamente lo que NO hay que poner al preguntar a una lista negra.
 * Las listas no cuelgan de la zona inversa: la zona de la lista es una zona mas.
 *
 * Pegar las dos cosas produce `195.88.1.166.in-addr.arpa.bl.spamcop.net`, que
 * no existe en ninguna parte del arbol DNS, y por lo tanto responde NXDOMAIN
 * SIEMPRE, para cualquier IP y para cualquier lista. Como NXDOMAIN es la misma
 * cosa que devuelve una IP limpia, el informe sale "todo limpio" sin mirar
 * nada. Es un fallo silencioso: no da error, no avisa, y el unico sintoma es que
 * el modulo nunca ha encontrado a nadie en ninguna lista, en toda su vida.
 *
 * Aqui se quita el sufijo y solo se quedan los octetos, que es lo que la lista
 * espera antes de su zona.
 *
 * @param {string} ip
 * @returns {string|null}
 */
function octetosInvertidos(ip) {
  const nombre = ipaddr.nombreInvertido(ip);
  if (!nombre) return null;
  return nombre.replace(/\.(?:in-addr|ip6)\.arpa$/, '');
}

/**
 * Construye el nombre a consultar en una zona de lista negra.
 *
 * @param {string} ip
 * @param {object} lista Ficha de la lista.
 * @returns {string|null} Nombre completo, o `null` si la IP no se puede consultar.
 */
function nombreDeConsulta(ip, lista) {
  const bits = ipaddr.bitsDe(ip);
  if (!bits) return null;

  // Una ficha sin zona no se puede consultar. Devolver `${base}.undefined`
  // construiria un nombre que no existe en el arbol DNS: NXDOMAIN, "no
  // listada", y un informe que afirma algo que nadie ha comprobado.
  if (!lista || !lista.zona) return null;

  const invertido = octetosInvertidos(ip);
  if (!invertido) return null;

  // Quitar el ultimo octeto deja `3.113.0.203` en vez de `7.113.0.203`.
  const base = lista.quitarUltimoOcteto ? invertido.split('.').slice(1).join('.') : invertido;

  return `${base}.${lista.zona}`;
}

/** Codigos de error del resolvedor que SI significan "esta IP no esta listada". */
const AUSENTES = new Set(['ENOTFOUND', 'ENODATA', 'ENODOMAIN']);

/**
 * SIGNIFICADO DE 127.255.255.0/24.
 *
 * Aqui esta el problema de fondo de toda la consulta a Spamhaus. El rango
 * 127.0.0.0/8 es el "no existe tal host" de toda la red, y las listas de correo
 * Answer usan dentro los codigos 127.0.x.x y 127.1.x.x para decir "esta IP esta
 * listada, y el motivo es x". El ultimo /24, 127.255.255.0/24, NO lista a nadie:
 * es donde Spamhaus mete sus respuestas de diagnostico, o sea "no te voy a
 * contestar".
 *
 * La diferencia no es academica. Comprobado contra las entradas de prueba que
 * publica el propio Spamhaus (127.0.0.2, 127.0.0.3, 127.0.0.10, 127.0.0.11), que
 * deben devolver SIEMPRE un codigo de listado:
 *
 *     127.0.0.2  ->  127.255.255.254      (deberia ser 127.0.0.2)
 *
 * Ese 127.255.255.254 no dice que la zona funciona: dice que el resolvedor desde
 * el que se pregunta no esta registrado en Spamhaus. Y si esa respuesta se
 * aceptara como "listada", el informe acusaria a una IP de ser un botnet C&C
 * cuando lo unico que ha pasado es que no nos han dejado mirar.
 *
 * Antes de leer esto como un listado real, hay que confirmar que la respuesta
 * no cae en este bloque. `esDiagnostico` es el unico sitio que decide eso.
 */
const DIAGNOSTICOS = {
  '127.255.255.2': 'tipo de consulta no valido',
  '127.255.255.3': 'consulta no permitida',
  '127.255.255.4': 'consulta no permitida',
  '127.255.255.5': 'consulta no permitida',
  '127.255.255.6': 'consulta no permitida',
  '127.255.255.7': 'consulta no permitida',
  '127.255.255.8': 'consulta no permitida',
  '127.255.255.9': 'consulta no permitida',
  '127.255.255.10': 'consulta no permitida',
  '127.255.255.11': 'consulta no permitida',
  '127.255.255.252': 'la zona ha rechazado la consulta: direccion de consulta mal formada o acceso no concedido',
  '127.255.255.253': 'la zona ha rechazado la consulta',
  '127.255.255.254': 'este resolvedor no esta registrado en Spamhaus, asi que sus zonas no devuelven datos',
  '127.255.255.255': 'consultas bloqueadas por volumen'
};

/**
 * ¿Esta respuesta es un diagnostico de Spamhaus y no un listado?
 *
 * @param {string} codigo
 * @returns {boolean}
 */
function esDiagnostico(codigo) {
  return String(codigo).startsWith('127.255.255.');
}

/**
 * Traduce la respuesta de una consulta A a un estado de la lista.
 *
 * @param {object} respuesta Resultado de `core/net/dns.consultar`.
 * @returns {{estado: string, codigo: string|null, error: string|null}}
 */
function interpretarRespuesta(respuesta) {
  if (respuesta.ok) {
    if (!respuesta.valores.length) return { estado: LIMPIA, codigo: null, error: null };

    // Las listas devuelven 127.0.0.x. El ultimo numero es el motivo, y hay
    // tablas publicadas para cada lista. Se guarda el codigo entero y que el
    // informe lo interprete, en vez de inventar aqui un significado que depende
    // de la lista.
    //
    // Pero solo se acepta una respuesta de 127.0.0.0/8. Una zona mal
    // configurada, un NX recordador de por medio o un resolver que devuelve otra
    // cosa, daria una accusation falsa contra una IP limpia, y eso es peor que
    // no saberlo: el informe se lee como si alguien lo hubiera confirmado.
    const codigo = String(respuesta.valores[0]);
    if (!/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(codigo)) {
      return {
        estado: SIN_DATOS,
        codigo: null,
        error: `la zona respondio ${codigo}, que no es una direccion de listado`
      };
    }

    // Y de ese /8 se descuenta 127.255.255.0/24, que es donde Spamhaus responde
    // "no te contesto" en vez de dar el veredicto. Esto va ANTES de devolver
    // LISTADA a proposito: es la diferencia entre un informe honesto y uno que
    // se inventa un listado.
    //
    // El codigo se conserva en el resultado, aunque el estado sea "sin datos",
    // porque es la prueba que permite a quien lee el informe ver de donde salio
    // el "no se pudo comprobar" en vez de tener que fiarse del texto.
    if (esDiagnostico(codigo)) {
      const detalle = DIAGNOSTICOS[codigo] || 'respuesta de diagnostico de la zona, sin datos sobre esta IP';
      return { estado: SIN_DATOS, codigo, error: `Spamhaus respondio ${codigo}: ${detalle}` };
    }

    return { estado: LISTADA, codigo, error: null };
  }

  if (AUSENTES.has(respuesta.codigoDns)) return { estado: LIMPIA, codigo: null, error: null };

  // SERVFAIL, EREFUSED, tiempos agotados: aqui no se sabe nada.
  return {
    estado: SIN_DATOS,
    codigo: null,
    error: respuesta.error || respuesta.codigoDns || 'fallo desconocido'
  };
}

/**
 * LA PRUEBA DE ACCESO A SPAMHAUS.
 *
 * Arreglar la interpretacion de 127.255.255.0/24 no basta, porque hay una
 * segunda mitad del problema que es mas silenciosa: cuando Spamhaus no esta
 * dispuesto a contestar a este resolvedor, para una IP cualquiera devuelve
 * NXDOMAIN, y NXDOMAIN es exactamente lo mismo que devuelve una IP limpia.
 *
 * Antes de decir "esta IP no esta en ZEN" hay que poder decir "ZEN me ha
 * contestado de verdad". Para eso estan las entradas de prueba que publica el
 * propio Spamhaus en 127.0.0.0/8 y que por definicion DEVUELVEN codigo de
 * listado siempre: 127.0.0.2 es SBL, 127.0.0.3 es XBL, 127.0.0.10 y 127.0.0.11
 * son PBL. Si esa comprobacion no devuelve un codigo de listado, Spamhaus no le
 * esta dando datos a este resolvedor, y entonces SUS zonas no se pueden usar
 * para nada: ni para acusar ni para tranquilizar.
 *
 * Se consulta con la IP al reves COMPLETA, y no por /24 como las zonas de
 * consulta. Las entradas de prueba son de una IP concreta, y ademas asi se
 * distingue el "no me dejes mirar" (127.255.255.254, que llega) del "no existe"
 * por formato, que es lo unico que devuelve una consulta escrita mal.
 */
const CANARIO = {
  ip: '127.0.0.3',
  zona: 'zen.spamhaus.org',
  queEs: 'XBL'
};

/**
 * Comprueba si Spamhaus esta sirviendo datos a este resolvedor.
 *
 * @param {object} [opciones]
 * @param {object} [opciones.dns] Módulo DNS inyectable (para pruebas).
 * @param {number} [opciones.timeout=8000]
 * @returns {Promise<{hayDatos: boolean, consulta: string, codigo: string|null, motivo: string|null}>}
 */
async function detectarAccesoSpamhaus(opciones = {}) {
  const { dns = dnsNet, timeout = 8000 } = opciones;

  const invertido = octetosInvertidos(CANARIO.ip);
  const consulta = invertido ? `${invertido}.${CANARIO.zona}` : null;
  if (!consulta) {
    return {
      hayDatos: false,
      consulta: null,
      codigo: null,
      motivo: 'no se ha podido construir la comprobacion de acceso a Spamhaus'
    };
  }

  // Se consulta por `consultarLote` y no por `consultar` a proposito: es el
  // mismo camino que usa el resto del modulo, y asi un doble de pruebas que solo
  // implemente `consultarLote` sigue sirviendo.
  const [r = {}] = await dns.consultarLote([{ nombre: consulta, tipo: 'A' }], {
    concurrencia: 1,
    dns: { timeout, reintentos: 0 }
  });

  // Un fallo aqui NO es "Spamhaus dice que no". Es que ni siquiera sabemos si
  // Spamhaus esta disponible, y ante la duda tampoco se levan sus zonas.
  if (!r.ok) {
    return {
      hayDatos: false,
      consulta,
      codigo: null,
      motivo: `Spamhaus no ha respondido a la comprobacion de acceso (${r.codigoDns || r.error || 'sin codigo'})`
    };
  }

  const codigo = r.valores.length ? String(r.valores[0]) : null;

  if (!codigo || esDiagnostico(codigo)) {
    return {
      hayDatos: false,
      consulta,
      codigo,
      motivo:
        (codigo ? DIAGNOSTICOS[codigo] : null) ||
        `Spamhaus no ha dado datos para ${CANARIO.ip} (${CANARIO.queEs}), que siempre esta listada; sus zonas no se pueden usar para esta IP`
    };
  }

  return { hayDatos: true, consulta, codigo, motivo: null };
}

/**
 * Consulta un conjunto de listas negras para una IP.
 *
 * @param {string} ip
 * @param {object} [opciones]
 * @param {object[]} [opciones.listas] Fichas; por defecto, las ocho cortas.
 * @param {object} [opciones.dns] Módulo DNS inyectable (para pruebas).
 * @param {number} [opciones.timeout=8000]
 * @param {number} [opciones.concurrencia=4]
 * @param {boolean} [opciones.motivos=true] Pedir el TXT con el motivo de los listados.
 * @param {boolean} [opciones.accesoSpamhaus=true] Comprobar antes si Spamhaus da datos a este resolvedor.
 * @returns {Promise<{resultados: object[], resumen: object}>}
 */
async function consultar(ip, opciones = {}) {
  const {
    listas = LISTAS_CORTA,
    dns = dnsNet,
    timeout = 8000,
    concurrencia = 4,
    motivos = true,
    accesoSpamhaus = true
  } = opciones;

  const bits = ipaddr.bitsDe(ip);
  if (!bits) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `"${ip}" no es una direccion IP.`, {
      remediation: 'Escribe una IPv4 (203.0.113.10) o una IPv6 (2001:db8::1).'
    });
  }

  // Las listas que no cubren esta familia se anotan y no se consultan. Preguntar
  // a una zona IPv4 con una IPv6 al reves da un nombre que no existe, y el
  // resultado seria "no listada" sin haber preguntado a nadie.
  const aplicables = [];
  const descartadas = [];
  for (const lista of listas) {
    if (bits === 128 && !lista.ipv6) {
      descartadas.push({
        ...lista,
        consulta: null,
        estado: SIN_APLICAR,
        codigo: null,
        motivo: null,
        error: null
      });
      continue;
    }
    const consulta = nombreDeConsulta(ip, lista);
    if (!consulta) continue;
    aplicables.push({ ...lista, consulta });
  }

  const respuestas = await dns.consultarLote(
    aplicables.map((l) => ({ nombre: l.consulta, tipo: 'A' })),
    { concurrencia, dns: { timeout, reintentos: 1 } }
  );

  const resultados = aplicables.map((lista, i) => {
    const r = interpretarRespuesta(respuestas[i]);
    return {
      clave: lista.clave,
      nombre: lista.nombre,
      proveedor: lista.proveedor,
      categoria: lista.categoria || 'correo',
      zona: lista.zona,
      consulta: lista.consulta,
      nota: lista.nota,
      estado: r.estado,
      codigo: r.codigo,
      motivo: null,
      error: r.error
    };
  });

  // --- COMPROBACION DE ACCESO A SPAMHAUS ---
  //
  // Se hace despues de consultar y antes de pedir los motivos TXT, porque si
  // Spamhaus no esta sirviendo datos a este resolvedor, sus zonas devuelven
  // NXDOMAIN y se leerian como "limpia". Un "todo limpio" asi es inventado: se
  // tiene el NXDOMAIN de una zona que no ha contestado, no el veredicto de
  // nadie. Cuando esto salta, sus zonas pasan a "sin datos" con el motivo a la
  // vista.
  const haySpamhaus = resultados.some((r) => r.proveedor === 'Spamhaus');
  let acceso = null;

  if (haySpamhaus && accesoSpamhaus) {
    acceso = await detectarAccesoSpamhaus({ dns, timeout });

    if (!acceso.hayDatos) {
      const motivo =
        `${acceso.motivo}. ` +
        'Registrar este resolvedor en Spamhaus (o usar sus zonas de pago con una clave) para que estas zonas valgan algo; ' +
        'mientras tanto, ni que aparezca ni que no aparezca sirve de prueba de nada.';

      for (const r of resultados) {
        if (r.proveedor !== 'Spamhaus') continue;
        r.estado = SIN_DATOS;
        // El codigo se deja si la zona dio una respuesta de diagnostico, porque
        // es la prueba del "no me dejes mirar". Si la zona dio NXDOMAIN no hay
        // codigo que guardar.
        r.error = motivo;
      }
    }
  }

  // El motivo va en el TXT, y solo tiene sentido si la IP esta listada. Consultar
  // el TXT de todo lo demas serian el doble de consultas para nada.
  const listadas = resultados.filter((r) => r.estado === LISTADA && r.consulta);
  if (motivos && listadas.length) {
    const textos = await dns.consultarLote(
      listadas.map((r) => ({ nombre: r.consulta, tipo: 'TXT' })),
      { concurrencia, dns: { timeout, reintentos: 1 } }
    );

    listadas.forEach((r, i) => {
      const t = textos[i];
      if (t?.ok && t.valores.length) {
        r.motivo = t.valores
          .map((v) => (Array.isArray(v) ? v.join('') : String(v)))
          .join(' ')
          .slice(0, 300);
      }
    });
  }

  const resumen = {
    total: resultados.length + descartadas.length,
    consultadas: resultados.length,
    limpias: resultados.filter((r) => r.estado === LIMPIA).length,
    listadas: listadas.length,
    sinDatos: resultados.filter((r) => r.estado === SIN_DATOS).length,
    noAplica: descartadas.length,
    porcentajeListado: null,

    // CUANTOS OPERADORES DISTINTOS han puesto la IP, no solo cuantas zonas.
    //
    // Es el mismo punto que hace falta en `tools/ip-abuse` con los usuarios
    // distintos: tres zonas de Spamhaus son un unico operador diciendo tres
    // veces lo mismo. Decir "listada en 3 listas" suena a tres fuentes
    // independientes corroborandose y no lo son. El informe usa este numero para
    // decidir la gravedad, y no el total de zonas.
    proveedoresDistintos: [...new Set(listadas.map((r) => r.proveedor).filter(Boolean))].length,
    zonasListadas: listadas.map((r) => r.zona),

    // Los "sin datos" que no cuentan como un hueco del informe.
    //
    // Una zona de Spamhaus que no contesta porque este resolvedor no esta
    // registrado es una limitacion de quien hace la consulta, no un problema de
    // la zona ni de la IP. Por eso va aparte: asi un informe puede avisar de
    // ello sin inflar el numero de "listas que no respondieron", que es el
    // numero que se usa para puntuar. Si las dos cosas se sumaran, cualquier
    // comprobador de correo bajaria siempre de nota solo por estar en un servidor
    // sin registro, que es la situacion de casi todo el mundo.
    sinDatosSinAcceso: resultados.filter((r) => r.estado === SIN_DATOS && r.proveedor === 'Spamhaus' && acceso && !acceso.hayDatos).length,

    // Lo mismo, pero para botnet C&C, que va aparte porque no es lo mismo.
    //
    // Una IP en BCL no es una IP que manda mucho correo: es una IP desde la que
    // se manda el malware. Mezclarlo con el recuento de zonas de correo hacia
    // que el informe lo lea como una Ip cualquiera que "sale en tres listas",
    // cuando en realidad lo importante es que hay un controlador de botnet
    // detras. El informe usa estos dos numeros para separarlos.
    botnetListadas: listadas.filter((r) => r.categoria === 'botnet-c2').length,
    zonasBotnet: listadas.filter((r) => r.categoria === 'botnet-c2').map((r) => r.zona)
  };

  // El porcentaje se calcula solo sobre las que han respondido de verdad.
  // Meter los "sin datos" en el denominador haria bajar el numero y que un
  // informe con tres listas caidas pareciera un 0 % limpio.
  const conRespuesta = resumen.consultadas - resumen.sinDatos;
  if (conRespuesta > 0) {
    resumen.porcentajeListado = Math.round((resumen.listadas / conRespuesta) * 100);
  }

  // El aviso de Spamhaus cambia de texto segun lo que haya pasado la
  // comprobacion de acceso. Con el aviso de siempre, un informe con tres zonas
  // de Spamhaus en "sin datos" parece un problema de red pasajero, cuando lo
  // que hay es que no nos han dejado mirar. El aviso tiene que decir eso.
  let avisoSpamhaus = AVISO_SPAMHAUS;
  if (acceso && !acceso.hayDatos) {
    avisoSpamhaus =
      `${acceso.motivo}. Sus zonas (ZEN, XBL, SBL, BCL) han quedado en "sin datos" ` +
      'para esta consulta: no se ha podido comprobar si la IP aparece en ellas. ' +
      'Esto NO es un "no aparece". Registra el resolvedor en Spamhaus, o usa sus zonas de pago con una clave, ' +
      'para que el informe pueda pronunciarse.';
  }

  return {
    resultados: [...resultados, ...descartadas],
    resumen,
    accesoSpamhaus: acceso,
    avisos: resumen.consultadas ? [avisoSpamhaus] : []
  };
}

module.exports = {
  consultar,
  nombreDeConsulta,
  octetosInvertidos,
  interpretarRespuesta,
  detectarAccesoSpamhaus,
  esDiagnostico,
  LISTAS_CORTA,
  LISTAS_AMPLIA,
  AVISO_SPAMHAUS,
  CANARIO,
  DIAGNOSTICOS,
  ESTADOS: { LIMPIA, LISTADA, SIN_DATOS, SIN_APLICAR }
};
