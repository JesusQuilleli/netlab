/**
 * tools/ip-audit.js — Herramienta 4 de 5: quien es esta IP.
 *
 * DE DONDE SALE. legacy/Validate IP/info-ip.js eran tres lineas sueltas con un
 * conversor de IPv4 a entero, sin programa que las llamara. No habia nada que
 * migrar: esta herramienta es nueva, hecha sobre las piezas que si existen
 * (`core/net/rdap`, `core/net/dnsbl`, `core/net/ptr`).
 *
 * QUE PREUNTA, Y EN QUE ORDEN:
 *
 * 1. RDAP: quien tiene el bloque asignado y a quien se escribe para quejarse.
 * 2. PTR: que nombre apunta a la IP. En una IP de correo es la mitad del
 *    diagnostico de suplantacion, y hay quien bloquea solo por no tener PTR.
 * 3. DNSBL: si la IP esta en listas negras de correo.
 * 4. BCL: si la IP figura como controlador de botnet. Va aparte de las de
 *    correo porque no es lo mismo: una IP en BCL es una IP desde la que se manda
 *    malware a otros equipos, y mezclarla con el recuento de reputacion de
 *    correo hace que el informe entero se lea como "una IP que manda mucho
 *    correo", que es justo el malentendido que cuesta caro.
 * 5. Blocklists via DNS Query de Spamhaus, si hay clave: si la IP SIGUE listada ahora mismo.
 *
 * LAS CUATRO COSAS QUE ESTA HECHO DISTINTO:
 *
 * 1. UNA IP, no una lista. `ip-abuse` acepta varias porque el dato por IP es
 *    barato. Aqui cada IP son tres consultas mas: registro, PTR y nueve zonas.
 *    Con cinco IPs son 50 preguntas y un informe que nadie lee entero. El
 *    informe de una IP ya tiene bastante.
 *
 * 2. Cuenta OPERADORES DISTINTOS, no zonas. Las nueve zonas cortas son de seis
 *    operadores, y cuatro de ellas son de Spamhaus. Una IP listada en ZEN, XBL,
 *    SBL y BCL son un unico operador diciendo cuatro veces lo mismo, no cuatro
 *    fuentes corroborandose. La gravedad sale de cuantos operadores dicen que si,
 *    igual que en `ip-abuse` se cuenta cuantos usuarios distintos reportaron. Con
 *    la excepcion de BCL, que es error con una sola entrada: ahi no se espera
 *    corroboracion de nadie.
 *
 * 3. Distingue "no listada" de "no se ha podido preguntar". Las nueve zonas se
 *    consultan, y un fallo de red se cuenta aparte. Un informe que solo sabe
 *    decir que si o que no daria un "todo limpio" con cinco zonas caidas.
 *
 * 4. ANTES de leer nada de Spamhaus, comprueba que Spamhaus le esta contestando.
 *    Sus zonas solo devuelven datos a un resolvedor registrado; al resto le
 *    devuelven NXDOMAIN, que es indistinguible del NXDOMAIN de una IP limpia.
 *    Sin esa comprobacion, un informe puede dar "no listada" sin que nadie haya
 *    preguntado. Esa comprobacion usa la entrada de prueba que publica el propio
 *    Spamhaus y siempre esta listada: si esa tampoco sale listada, sus zonas
 *    pasan a "sin datos" y el informe lo dice.
 *
 * @module tools/ip-audit
 */

'use strict';

const ipaddr = require('../core/net/ipaddr');
const rdap = require('../core/net/rdap');
const dnsbl = require('../core/net/dnsbl');
const spamhaus = require('../core/net/spamhaus');
const ptr = require('../core/net/ptr');
const config = require('../core/config');
const {
  createResult, addSection, addSummary, addFinding, addLog,
  finalize, failWith, setHeadline, SEVERIDADES, SECCION_KINDS: K
} = require('../core/result');
const { NetlabError, CODES } = require('../core/errors');

const ID = 'ip-audit';

/** Campos del formulario. El objetivo lo elige el usuario, como en las demas. */
const CAMPOS = [
  {
    name: 'ip',
    label: 'Direccion IP',
    type: 'text',
    required: true,
    placeholder: '203.0.113.10',
    help: 'Una sola IP. Admite IPv4 e IPv6. Cada IP son tres consultas (registro, nombre inverso y listas negras), asi que se auditan de una en una.'
  },
  {
    name: 'dnsbl',
    label: 'Consultar listas negras',
    type: 'checkbox',
    required: false,
    default: true,
    help:
      `${dnsbl.LISTAS_CORTA.length} zonas gratuitas, y una de ellas es la de bots de Spamhaus. Apagado solo se ` +
      'consulta el registro y el nombre inverso, que van al instante.'
  },
  {
    name: 'listas',
    label: 'Cuantas listas consultar',
    type: 'select',
    required: false,
    default: 'corta',
    options: [
      { value: 'corta', label: `Las ${dnsbl.LISTAS_CORTA.length} habituales` },
      { value: 'amplia', label: `${dnsbl.LISTAS_AMPLIA.length}, anadiendo las de menor precision` }
    ],
    shownWhen: 'dnsbl',
    help: 'Las de la lista amplia meten mas IPs, y tambien mas falsos positivos.'
  },
  {
    name: 'motivos',
    label: 'Pedir el motivo de los listados',
    type: 'checkbox',
    required: false,
    default: true,
    shownWhen: 'dnsbl',
    help: 'Las zonas explican el motivo en un registro TXT, pero solo cuando la IP esta listada.'
  },
  {
    name: 'spamhaus',
    label: 'Verificar en las zonas de pago de Spamhaus',
    type: 'checkbox',
    required: false,
    default: false,
    shownWhen: 'dnsbl',
    help:
      'Las zonas publicas de Spamhaus solo contestan a un resolvedor registrado. Con esto se pregunta a sus zonas de pago, ' +
      'por la clave que haya en el .env, y es la unica forma de confirmar si la IP sigue en la lista. ' +
      'Sin clave configurada, el informe lo dice en vez de suponer que esta limpia.'
  },
  {
    name: 'timeout',
    label: 'Tiempo de espera',
    type: 'number',
    required: false,
    default: 10000,
    min: 1000,
    max: 60000,
    unit: 'ms',
    help: 'Por consulta. Las zonas van en paralelo, asi que el total no es el tiempo por una.'
  }
];

/** Palabras que delatan un servicio de ocultacion en el titular del registro. */
const RE_PRIVACIDAD = /\b(privacy|privacidad|redacted|redact|withheld|withhold|whoisguard|proxy|proxyrus|anonymize|anonym|maskprotect|perfect privacy|dont ?reveal|not ?disclosed)\b/i;

/**
 * Punto de entrada de la herramienta.
 *
 * @param {object} params Entrada del formulario.
 * @param {object} [ctx] Contexto. `ctx.rdap`, `ctx.dnsbl`, `ctx.spamhaus` y
 *   `ctx.ptr` permiten inyectar dobles; `ctx.fetchImpl` se pasa al cliente HTTP
 *   de RDAP y al de Spamhaus; `ctx.claveSpamhaus` sustituye a la del entorno.
 * @returns {Promise<object>} Result completo, listo para renderizar.
 */
async function ejecutar(params = {}, ctx = {}) {
  const inicio = new Date();
  const log = ctx.log || null;

  const ip = String(params.ip ?? '').trim();
  const timeout = acotar(params.timeout, 1000, 60000, 10000);

  const result = createResult({ tool: ID, toolTitle: 'Auditoria de IP', target: ip });

  try {
    const bits = ipaddr.bitsDe(ip);
    if (!bits) {
      throw new NetlabError(CODES.ENTRADA_VACIA, 'No se indico una direccion IP valida.', {
        remediation: 'Escribe una IPv4 (203.0.113.10) o una IPv6 (2001:db8::1).'
      });
    }

    addLog(result, { level: 'info', channel: 'entrada', message: `Auditando ${ip} (IPv${bits === 32 ? 4 : 6})` });
    log?.info?.(`ip-audit: ${ip} bits=${bits} dnsbl=${params.dnsbl !== false}`);

    const registro = await consultarRegistro(result, ip, ctx, log);
    const inverso = await consultarInverso(result, ip, ctx);
    const listas = await consultarListas(result, ip, params, ctx, log);
    const consultaSpamhaus = await consultarSpamhaus(result, ip, params, ctx, log);

    revisarRegistro(result, registro, ip);
    revisarInverso(result, inverso);
    revisarListas(result, listas);
    revisarSpamhaus(result, consultaSpamhaus);

    addSummary(result, 'Direccion', ip, 'neutral');
    addSummary(result, 'Familia', `IPv${bits === 32 ? 4 : 6}`, 'neutral');
    addSummary(result, 'Titular del bloque', registro.disponible ? registro.nombre || registro.titular || 'Sin dato' : 'Sin dato', 'neutral');
    addSummary(result, 'Nombre inverso', inverso.configurado ? inverso.nombres[0] : 'Sin PTR', inverso.configurado ? 'ok' : 'warn');
    addSummary(
      result,
      'Listas negras',
      textoListas(listas),
      tonoListas(listas)
    );

    setHeadline(result, titular(listas, consultaSpamhaus));

    return finalize(result, inicio);
  } catch (error) {
    addLog(result, { level: 'error', channel: 'error', message: error.message });
    log?.error?.(`ip-audit fallo: ${error.message}`);
    return failWith(result, error);
  }
}

/**
 * El titular de una linea del informe.
 *
 * Antes no lo tenia, y se notaba: la tarjeta de arriba decia "8 de 8 sin listar"
 * y no habia ninguna frase que dijera si eso era una buena noticia o una
 * pantalla de error. Aqui la hay, y en el orden en que se lee un informe: lo
 * grave primero, despues si el dato esta completo, y solo si no hay nada grave
 * se dice que no hay nada grave.
 *
 * @param {object|null} listas
 * @param {object|null} consultaSpamhaus
 * @returns {string|null}
 */
function titular(listas, consultaSpamhaus) {
  // Lo de botnet C&C va por delante de cualquier otra cosa. Una IP que manda
  // malware no es una IP con "algo de mal reputation de correo".
  if (listas?.resumen?.botnetListadas > 0) {
    return `${listas.resumen.botnetListadas} lista(s) de botnet C&C: desde esta IP se controla una botnet`;
  }

  if (consultaSpamhaus?.resultados?.some((r) => r.estado === spamhaus.ESTADOS.LISTADA)) {
    return 'Spamhaus la lista ahora mismo, con su clave';
  }

  // Aqui esta el caso del falso "todo limpio": si el proveedor no ha dado datos,
  // no se puede decir que la IP este limpia, porque nadie ha podido mirar.
  if (listas?.accesoSpamhaus && !listas.accesoSpamhaus.hayDatos) {
    return 'Sin veredicto posible: Spamhaus no da datos a este resolvedor';
  }

  if (listas?.resumen?.listadas > 0) {
    return `Listada en ${listas.resumen.listadas} zonas de ${listas.resumen.proveedoresDistintos} operador(es)`;
  }

  if (listas?.resumen?.consultadas > 0 && listas.resumen.sinDatos === 0) {
    return 'Sin rastro en las zonas consultadas';
  }

  return null;
}

/** RDAP. Un fallo aqui no tumba el informe: el resto de fuentes sigue valiendo. */
async function consultarRegistro(result, ip, ctx, log) {
  const consultar = ctx.rdap?.consultar || rdap.consultar;
  try {
    const r = await consultar(ip, { fetchImpl: ctx.fetchImpl });
    addLog(result, { level: 'info', channel: 'rdap', message: `Registro consultado en ${r.servidor || r.motivo}` });
    log?.info?.(`ip-audit rdap ok: ${r.servidor}`);
    return r;
  } catch (error) {
    addLog(result, { level: 'warn', channel: 'rdap', message: `No se pudo consultar el registro: ${error.message}` });
    log?.warn?.(`ip-audit rdap fallo: ${error.message}`);
    return { ip, disponible: false, motivo: error.message, error: true };
  }
}

/** PTR. */
async function consultarInverso(result, ip, ctx) {
  const resolver = ctx.ptr?.resolver || ptr.resolver;
  try {
    return await resolver(ip);
  } catch (error) {
    addLog(result, { level: 'warn', channel: 'ptr', message: `No se pudo resolver el nombre inverso: ${error.message}` });
    return { nombres: [], configurado: false, error: error.message };
  }
}

/**
 * DNSBL. Si el usuario apaga la casilla no se consulta nada, y el informe lo
 * dice en vez de dejar un hueco que se lee como "todo limpio".
 */
async function consultarListas(result, ip, params, ctx, log) {
  if (params.dnsbl === false) return null;

  const consultar = ctx.dnsbl?.consultar || dnsbl.consultar;
  const lista = params.listas === 'amplia' ? dnsbl.LISTAS_AMPLIA : dnsbl.LISTAS_CORTA;
  const timeout = acotar(params.timeout, 1000, 60000, 10000);

  try {
    const r = await consultar(ip, {
      listas: lista,
      dns: ctx.dns || undefined,
      timeout,
      motivos: params.motivos !== false
    });
    addLog(
      result,
      { level: 'info', channel: 'dnsbl', message: `Consultadas ${r.resumen.consultadas} zonas: ${r.resumen.listadas} listadas, ${r.resumen.sinDatos} sin respuesta` }
    );
    log?.info?.(`ip-audit dnsbl: ${JSON.stringify(r.resumen)}`);
    return r;
  } catch (error) {
    addLog(result, { level: 'warn', channel: 'dnsbl', message: `No se pudieron consultar las listas: ${error.message}` });
    log?.warn?.(`ip-audit dnsbl fallo: ${error.message}`);
    return null;
  }
}

/**
 * Blocklists via DNS Query, que es donde de verdad se puede confirmar un listado.
 *
 * Va separada de la consulta por zonas publicas a proposito. Las zonas
 * publicas son gratis, pero solo responden a un resolvedor registrado, y cuando
 * no responden devuelven un NXDOMAIN que no se puede distinguir del "no listada"
 * de una IP limpia. Las zonas de DQS contestan a cualquiera con clave, porque la
 * clave va en el nombre de la zona.
 *
 * NO SE CONSULTA BCL, Y NO ES UN OLVIDO. BCL, la lista de IPs que controlan
 * bots, no forma parte de DQS: ni del pack gratuito ni del comercial. Solo
 * existe en las zonas publicas, o sea, solo para resolvedores registrados. Por
 * eso la clave gratuita no arregla el caso de botnet C&C, y el informe lo dice
 * en la seccion de BCL en vez de dar un "no listada" sin comprobar. Ver la
 * cabecera de `core/net/spamhaus`.
 *
 * Las dos consultas se hacen y las dos se muestran, aunque se contradigan. Si
 * las zonas publicas dicen una cosa y DQS otra, DQS manda, porque es la fuente
 * que responde de verdad. Ese caso sale en pantalla, porque un informe que se
 * contradice a si mismo necesita una nota que diga cual de las dos se ha usado.
 */
async function consultarSpamhaus(result, ip, params, ctx, log) {
  if (params.dnsbl === false) return null;
  if (params.spamhaus !== true) return null;

  // `ctx.claveSpamhaus !== undefined` y no un `||`: si quien llama pasa una
  // cadena vacia a proposito (probando), lo que quiere decir es "sin clave", y
  // no "usa la del entorno".
  const clave =
    ctx.claveSpamhaus !== undefined ? ctx.claveSpamhaus : config.leer('SPAMHAUS_DQS_KEY');

  if (!clave) {
    addLog(result, { level: 'warn', channel: 'spamhaus', message: 'Sin SPAMHAUS_DQS_KEY: no se puede confirmar el listado' });
    return { ip, resultados: [], errores: [], sinClave: true };
  }

  const consultar = ctx.spamhaus?.consultarVarias || spamhaus.consultarVarias;

  try {
    // ZEN y SBL. BCL no se pide porque no existe aqui: pedirla seria un error
    // garantizado y un dato menos sobre por que no se puede comprobar.
    const r = await consultar(ip, {
      clave,
      listas: ['zen', 'sbl'],
      consultarDns: ctx.consultarDns
    });
    addLog(
      result,
      {
        level: 'info',
        channel: 'spamhaus',
        message:
          `Spamhaus DQS: ${r.resultados.filter((x) => x.estado === spamhaus.ESTADOS.LISTADA).length} de ` +
          `${r.resultados.length} zonas con entrada` +
          (r.algunoDesconocido ? `, alguna sin respuesta` : '') +
          (r.errores.length ? `, ${r.errores.length} con error` : '')
      }
    );
    log?.info?.(`ip-audit dqs: ${JSON.stringify(r.resultados.map((x) => [x.lista, x.estado]))}`);
    return r;
  } catch (error) {
    addLog(result, { level: 'warn', channel: 'spamhaus', message: `La consulta a Spamhaus fallo: ${error.message}` });
    log?.warn?.(`ip-audit dqs fallo: ${error.message}`);
    return { ip, resultados: [], errores: [{ lista: 'zen', mensaje: error.message, codigo: error?.code || null }], fallo: true };
  }
}

/** Pinta el bloque de registro, o el motivo por el que no se pudo pintar. */
function revisarRegistro(result, registro, ip) {
  if (!registro.disponible) {
    addSection(result, {
      title: 'Registro (RDAP)',
      kind: K.PARES,
      items: [
        ['Estado', 'Sin datos'],
        ['Motivo', registro.motivo || 'El registro no devolvio informacion']
      ]
    });

    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'No se pudo averiguar quien registro la IP',
      detail: registro.motivo || 'La consulta al registro no devolvio nada utilizable.',
      recommendation:
        'Sin registro no se sabe a quien escribir si la IP hay que reportarla. Reintenta; si sigue igual, mira en el whois publico del registro regional.'
    });
    return;
  }

  addSection(result, {
    title: 'Registro (RDAP)',
    kind: K.PARES,
    items: [
      ['Titular', registro.nombre || registro.titular || 'Sin dato'],
      ['Tipo', registro.tipo || 'Sin dato'],
      ['Identificador', registro.handle || 'Sin dato'],
      ['Pais', registro.pais || 'Sin dato'],
      ['Rango', rangoTexto(registro)],
      ['Titular del registro', registro.titular || 'Sin dato'],
      ['Contacto de abuso', textoAbuso(registro)],
      ['Registrado', fechaCorta(registro.registro)],
      ['Ultimo cambio', fechaCorta(registro.ultimoCambio)],
      ['Caduca', fechaCorta(registro.caducidad)],
      ['Servidor consultado', registro.servidor || 'Sin dato']
    ]
  });

  if (registro.enlace) {
    addSection(result, {
      title: 'Ficha completa del registro',
      kind: K.CODIGO,
      value: registro.enlace
    });
  }
}

/** El registro no siempre viene bien: hay que decir cuando falta algo de verdad. */
function revisarListas(result, listas) {
  if (!listas) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'No se consultaron listas negras',
      detail: 'La consulta se apago en el formulario.',
      recommendation: 'Sin ese dato el informe no dice nada sobre la reputacion de correo de la IP.'
    });
    return;
  }

  const { resumen, resultados } = listas;

  // BCL va a su propia seccion y sale de esta tabla.
  //
  // Una entrada en BCL no es una IP con "algo de mal reputacion de correo": es
  // una IP desde la que se controla una botnet y se manda el malware a otros
  // equipos. Son dos problemas con dos gravedad distintas. Si BCL se queda en la
  // tabla de correo, el informe entero lo lee como una IP mas que mandaba
  // correo, y el titular acaba diciendo "3 de 9" sin mencionar para nada lo
  // unico que de verdad importa en esa linea.
  const sonCorreo = resultados.filter((r) => r.categoria !== 'botnet-c2');
  const sonBotnet = resultados.filter((r) => r.categoria === 'botnet-c2');

  addSection(result, {
    title: 'Listas negras de correo',
    kind: K.TABLA,
    columns: ['Lista', 'Operador', 'Zona', 'Resultado', 'Codigo', 'Motivo'],
    rows: sonCorreo.map((r) => [
      r.nombre,
      r.proveedor,
      r.zona,
      etiquetaEstado(r.estado),
      r.codigo || '',
      r.motivo || (r.error ? r.error : '')
    ]),
    // La zona y el motivo son los que se leen, y el "Resultado" solo tiene tres
    // o cuatro letras. Sin pesos, el motivo acaba en una columna de veinte
    // caracteres partida en cuatro lineas.
    anchoColumnas: [1.3, 1, 1.6, 0.9, 0.7, 2.5]
  });

  addSection(result, {
    title: 'Botnet C&C (BCL)',
    kind: K.TABLA,
    columns: ['Lista', 'Zona', 'Resultado', 'Codigo', 'Motivo'],
    rows: sonBotnet.map((r) => [
      r.nombre,
      r.zona,
      etiquetaEstado(r.estado),
      r.codigo || '',
      r.motivo || (r.error ? r.error : '')
    ]),
    anchoColumnas: [1.5, 1.6, 0.9, 0.7, 2.6]
  });

  // Y se dice por que BCL casi nunca se puede comprobar, que es la parte que
  // evita dar por bueno un dato que nadie ha mirado.
  //
  // BCL es de las pocas zonas que no estan en las zonas de pago, ni en las de
  // DQS: solo existe en el espejo publico, que solo contesta a resolvedores
  // registrados. Comprarla con clave no ayuda. Asi que desde un servidor el
  // resultado es siempre "sin datos", y eso hay que decirlo con esas palabras,
  // no con un "no listada" que alguien va a leer como limpio.
  if (sonBotnet.length && sonBotnet.every((r) => r.estado === dnsbl.ESTADOS.SIN_DATOS)) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'La comprobacion de botnet C&C no se ha hecho, y no se puede hacer desde aqui',
      detail:
        'La zona BCL solo responde a resolvedores registrados por Spamhaus, y este informe se ha generado desde ' +
        'uno que no lo esta. Por eso sale "sin respuesta" en lugar de "no listada": no se ha preguntado a nadie. ' +
        'La clave gratuita de Blocklists via DNS Query no resuelve esto, porque BCL no forma parte de ese servicio.',
      recommendation:
        'Para el dato de BCL hay dos caminos: consultar la IP en https://check.spamhaus.org, que es la pagina de ' +
        'Spamhaus, o registrar este resolvedor en Spamhaus para que sus zonas publicas contesten. Que la clave de ' +
        'DQS salga vacia aqui NO significa que la IP no tenga botnet.'
    });
  }

  if (resumen.listadas > 0) {
    // El detalle va en una seccion aparte y no solo en la tabla: la tabla puede
    // ser larga y el motivo es justo lo que hay que leer.
    addSection(result, {
      title: 'En que listas aparece y por que',
      kind: K.LISTA,
      items: resultados
        .filter((r) => r.estado === dnsbl.ESTADOS.LISTADA)
        .map((r) => `${r.nombre} (${r.proveedor}): ${r.codigo || 'sin codigo'}${r.motivo ? ` — ${r.motivo}` : ''}`)
    });
  }

  // El caso de botnet C&C tiene su propia gravedad, y no la del resto.
  //
  // El recuento de zonas de arriba saca su gravedad del numero de OPERADORES, y
  // esa regla esta pensada para correo: tres zonas de un mismo operador son una
  // sola voz. Pero si la entrada es de botnet C&C, da igual que la haya puesto
  // un operador o tres: una sola entrada significa que hay malware saliendo, y
  // eso no espera a tener corroboracion.
  if (resumen.botnetListadas > 0) {
    const entradas = resultados.filter((r) => r.estado === dnsbl.ESTADOS.LISTADA && r.categoria === 'botnet-c2');

    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: `La IP esta en una lista de botnet C&C (${resumen.zonasBotnet.join(', ')})`,
      detail: entradas
        .map((r) => `${r.nombre} (${r.zona}): ${r.codigo || 'sin codigo'}${r.motivo ? ` — ${r.motivo}` : ''}`)
        .join('; '),
      recommendation:
        'Desde esta IP se esta controlando una botnet, o se ha enviado malware desde ella. Averigua que proceso ' +
        'corresponde a esa IP en el equipo y paralo antes de nada. Deslistarla no basta por si sola: mientras ' +
        'el equipo siga haciendo lo que hace, la IP vuelve a entrar. Luego pide la retirada en ' +
        'https://check.spamhaus.org, que no es automatica.'
    });
  }

  addSection(result, {
    title: 'Cobertura de la consulta',
    kind: K.PARES,
    items: [
      ['Zonas consultadas', `${resumen.consultadas} de ${resumen.total}`],
      ['Sin listar', String(resumen.limpias)],
      ['Listadas', String(resumen.listadas)],
      ['De ellas, botnet C&C', resumen.botnetListadas ? String(resumen.botnetListadas) : 'Ninguna'],
      ['Sin respuesta', String(resumen.sinDatos)],
      ['No aplicables', resumen.noAplica ? String(resumen.noAplica) : 'Ninguna']
    ]
  });

  // --- La gravedad sale de los OPERADORES, no de las zonas. ---

  if (resumen.proveedoresDistintos >= 2) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: `La IP aparece en ${resumen.listadas} zonas de ${resumen.proveedoresDistintos} operadores distintos`,
      detail: resultados
        .filter((r) => r.estado === dnsbl.ESTADOS.LISTADA)
        .map((r) => `${r.nombre} (${r.zona}): ${r.codigo || 'sin codigo'}`)
        .join('; '),
      recommendation:
        'Varios operadores independientes coincidian: es una señal fuerte. Contacta con tu proveedor de correo para que la revise, y si la IP es tuya, mira el PTR y la salida por la que envia.'
    });
  } else if (resumen.listadas === 1) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'La IP aparece en una lista negra',
      detail: resultados
        .filter((r) => r.estado === dnsbl.ESTADOS.LISTADA)
        .map((r) => `${r.nombre} (${r.zona}): ${r.codigo || 'sin codigo'}${r.motivo ? ` — ${r.motivo}` : ''}`)
        .join('; '),
      recommendation:
        'Una sola lista no es una prueba. Mira el motivo que da y, si el listado no te parece justo, su propio sitio suele tener un proceso de retirada.'
    });
  }

  if (resumen.sinDatos > 0) {
    // Esto NO baja el veredicto a limpio ni lo sube a sucio: solo dice que el
    // informe tiene un agujero, y de que tamano.
    //
    // Y la gravedad depende del agujero. Si lo que falta son las zonas de
    // Spamhaus y nada mas, el motivo es el registro del resolvedor, que es cosa
    // de quien ejecuta la herramienta y no de la IP auditada: eso es un aviso.
    // Si ademas faltan zonas de otros operadores, entonces hay algo que no se
    // ha podido mirar por un fallo real, y si avisa en serio.
    const caidos = resultados.filter((r) => r.estado === dnsbl.ESTADOS.SIN_DATOS);
    const soloSpamhaus = caidos.length > 0 && caidos.every((r) => r.proveedor === 'Spamhaus');

    addFinding(result, {
      severity: soloSpamhaus ? SEVERIDADES.INFO : SEVERIDADES.WARN,
      title: soloSpamhaus
        ? `${resumen.sinDatos} zonas de Spamhaus sin datos (por falta de registro, no por fallo)`
        : `${resumen.sinDatos} listas no respondieron`,
      detail: caidos
        .map((r) => `${r.nombre}: ${r.error || 'sin detalle'}`)
        .join('; '),
      recommendation: soloSpamhaus
        ? 'Registra este resolvedor en Spamhaus, o pon una clave de Blocklists via DNS Query, para que la consulta sea concluyente. ' +
          'Mientras tanto, estas zonas no cuentan ni a favor ni en contra.'
        : 'Un fallo al consultar no es lo mismo que "no listada". Estas zonas no cuentan ni a favor ni en contra del veredicto.'
    });
  }

  if (resumen.noAplica > 0) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `Las listas negras no cubren esta familia de direcciones`,
      detail:
        'Las zonas de lista negra publica son, casi todas, de IPv4. Para una IPv6 no hay consulta que hacer, y no es que la IP salga limpia: es que nadie la ha mirado.',
      recommendation: 'Para una IPv6 la reputacion hay que buscarla en el registro y en las metricas del operador.'
    });
  }

  for (const aviso of listas.avisos || []) {
    // El titulo cambia segun el motivo. Con el aviso generico, un informe con
    // tres zonas de Spamhaus en "sin datos" por culpa del registro parece un
    // problema de red pasajero, cuando lo que hay es que nadie ha mirado. El
    // titulo tiene que decirlo, porque es la primera linea que se lee.
    const sinAcceso = listas.accesoSpamhaus && !listas.accesoSpamhaus.hayDatos;

    // La gravedad depende de cuanto se haya quedado sin mirar. Si lo unico que
    // falta son las zonas de Spamhaus, y solo por no tener el resolvedor
    // registrado, eso es un aviso: el resto de zonas ha contestado de verdad y el
    // informe puede pronunciarse sobre ellas. Si ademas hay zonas caidas por
    // red, entonces si hay un agujero de verdad y toca avisar en serio.
    const sinDatos = resultados.filter((r) => r.estado === dnsbl.ESTADOS.SIN_DATOS);
    const soloSpamhaus = sinAcceso && sinDatos.length > 0 && sinDatos.every((r) => r.proveedor === 'Spamhaus');

    addFinding(result, {
      severity: soloSpamhaus ? SEVERIDADES.INFO : sinAcceso ? SEVERIDADES.WARN : SEVERIDADES.INFO,
      title: sinAcceso
        ? 'Spamhaus no ha dado datos: su zona no se ha podido consultar'
        : 'Como hay que leer un "no listada" de Spamhaus',
      detail: aviso,
      recommendation: sinAcceso
        ? 'Registra este resolvedor en Spamhaus para que sus zonas valgan, o activa la casilla de sus zonas de pago en el ' +
          'formulario para consultar ZEN y SBL con una clave. Mientras tanto, la zona de BCL de este informe ' +
          'dice "Sin respuesta", y eso NO significa que la IP este limpia.'
        : 'Para una respuesta de Spamhaus con garantias, consulta desde una direccion registrada por su sistema.'
    });
  }
}

/**
 * La parte de las zonas de pago de Spamhaus.
 *
 * Aqui es donde el informe puede contestar a la pregunta que de verdad importa:
 * si la IP sigue en la lista o ya no. Y contesta tambien, y por separado, a la
 * otra, que es si el problema de fondo esta resuelto. Son dos cosas distintas:
 * un listado se quita cuando alguien lo pide, no solo cuando el problema deja de
 * existir. Una IP puede llevar dias sin botnet y seguir listada porque nadie ha
 * pedido la retirada, y el informe no debe dejar que se lea al reves.
 */
function revisarSpamhaus(result, consulta) {
  if (!consulta) return;

  if (consulta.sinClave) {
    addSection(result, {
      title: 'Blocklists via DNS Query de Spamhaus',
      kind: K.PARES,
      items: [
        ['Estado', 'Sin comprobacion'],
        ['Motivo', 'No hay SPAMHAUS_DQS_KEY configurada'],
        ['Que significa', 'No se ha podido confirmar si la IP sigue listada. No es lo mismo que "no listada".']
      ]
    });

    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'No se ha verificado el listado en las zonas de pago de Spamhaus',
      detail:
        'Las zonas DNS de Spamhaus solo devuelven datos a un resolvedor registrado, asi que su veredicto no es ' +
        'acreditable desde aqui. Las zonas con clave si lo son, y netlab no la ha consultado porque falta la clave. ' +
        'Esto es lo mismo que "no se ha podido comprobar", y NO es lo mismo que "no listada".',
      recommendation:
        'Pide una clave gratuita en https://portal.spamhaus.com/auth/account-setup?ps=free_dqs_product y ponla en SPAMHAUS_DQS_KEY. Con ella, este informe dira si la IP '+
      'sigue en ZEN o en SBL o ya no, en vez de dejarlo sin comprobar. OJO: no dira nada de BCL, porque esa lista no esta en DQS.'
    });
    return;
  }

  if (!consulta.resultados?.length && consulta.errores?.length) {
    addSection(result, {
      title: 'Blocklists via DNS Query de Spamhaus',
      kind: K.PARES,
      items: [
        ['Estado', 'La zona de pago no ha podido consultarse'],
        ['Motivo', consulta.errores.map((e) => `${e.lista}: ${e.mensaje}`).join('; ')]
      ]
    });

    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'No se pudo verificar el listado por las zonas de pago de Spamhaus',
      detail: consulta.errores.map((e) => `${e.lista}: ${e.mensaje}`).join('; '),
      recommendation: 'Revisa la clave y la conexion, y vuelve a intentarlo. El estado del listado sigue sin comprobar.'
    });
    return;
  }

  if (!consulta.resultados?.length) return;

addSection(result, {
    title: 'Blocklists via DNS Query de Spamhaus',
    kind: K.TABLA,
    columns: ['Zona', 'Que mide', 'Estado', 'Codigo', 'Por que'],
    rows: consulta.resultados.map((r) => [
      r.listaNombre,
      r.queMide || '',
      etiquetaSpamhaus(r.estado),
      r.codigo || '',
      // El motivo va aqui y no en una columna aparte porque es lo que
      // determina la gravedad: estar en SBL y estar en PBL no es lo mismo.
      r.motivo || r.advertencias?.join(' ') || ''
    ]),
    anchoColumnas: [1.1, 1.8, 1, 0.9, 2.2]
  });

  for (const r of consulta.resultados) {
    if (r.estado === spamhaus.ESTADOS.LISTADA) {
      addFinding(result, {
        severity: SEVERIDADES.WARN,
        title: `Spamhaus confirma que la IP esta en ${r.listaNombre}`,
        detail:
          `Codigo ${r.codigo || 'sin codigo'}${r.sublista ? ` (${r.sublista})` : ''}` +
          `${r.motivo ? `: ${r.motivo}` : ''}. Es el estado de hoy, no de cuando lo anadieron.`,
        recommendation:
          'Mitiga el abuso en el equipo o servidor correspondiente. La entrada no desaparece sola: hay que pedir ' +
          'la retirada en https://check.spamhaus.org.'
      });
    }
  }

  // Aqui esta el matiz que evita el malentendido caro. Si el listado ya no esta,
  // lo mas probable es que quien lo lea cierre el caso. Pero que no este listado
  // no dice que el equipo este limpio: dice que la lista no lo tiene ahora mismo.
  if (consulta.resultados.some((r) => r.estado === spamhaus.ESTADOS.NO_LISTADA)) {
    const advertencias = consulta.resultados.flatMap((r) => r.advertencias || []);

    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'La IP no aparece ahora mismo en las listas de Spamhaus consultadas',
      detail:
        advertencias.join(' ') ||
        'Spamhaus no tiene entrada para esta IP en las listas consultadas en este momento.',
      recommendation:
        'Comprueba por que estaba listada. Que ya no aparezca no demuestra que el problema de fondo este ' +
        'resuelto: si la actividad de abuso continua, la IP vuelve a entrar.'
    });
  }

  if (consulta.algunoDesconocido) {
    // Solo es un problema si ALGUNA zona quedo sin saber. Si las zonas que
    // contestaron dicen "no listada", el veredicto sigue siendo utilizable.
    const sinSaber = consulta.resultados.filter((r) => r.estado === spamhaus.ESTADOS.DESCONOCIDO);
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Spamhaus no ha dado veredicto en alguna zona',
      detail:
        `${sinSaber.map((r) => `${r.listaNombre}: ${r.advertencias?.join(' ') || 'sin respuesta'}`).join('; ')}. ` +
        'Ese resultado no cuenta ni como listada ni como limpia.',
      recommendation:
        'Si es un fallo de red, reintenta. Si es su codigo 127.255.255.254, la clave no tiene acceso a esa zona: ' +
        'mira en tu cuenta de Spamhaus si esta activada.'
    });
  }
}

/**
 * El nombre inverso y su lectura en lenguaje llano.
 *
 * Aqui no se intenta adivinar si el PTR "es el que esperaba el usuario". El
 * registro suele traer el nombre de una empresa sin dominio, asi que comparar
 * ambas cosas produce conclusions inventadas, y un hallazgo que dice "este PTR no
 * es el tuyo" sin saber de donde salio la referencia dirige a la pista
 * equivocada. Si el PTR esta puesto, no hay nada que senalar.
 */
function revisarInverso(result, inverso) {
  const lectura = ptr.interpretar(inverso);

  addSection(result, {
    title: 'Nombre inverso (PTR)',
    kind: K.PARES,
    items: [
      ['Estado', lectura.estado],
      ['Nombres', inverso.configurado ? inverso.nombres.join(', ') : 'Ninguno'],
      ['Que implica', lectura.descripcion]
    ]
  });

  if (!inverso.configurado) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'La IP no tiene nombre inverso',
      detail: lectura.descripcion,
      recommendation: lectura.recomendacion
    });
  }
}

/**
 * Que poner en la tarjeta de las listas negras.
 *
 * "0 de 0" se lee como "se consultaron cero zonas y no hay ninguna listada", que
 * es justo lo que no ha pasado en una IPv6: alli no se consulto ninguna porque
 * no hay ninguna que sirva.
 */
function textoListas(listas) {
  if (!listas) return 'No consultadas';
  const { consultadas, listadas, sinDatos, noAplica, botnetListadas } = listas.resumen;

  if (consultadas === 0) return noAplica > 0 ? 'Sin zonas para IPv6' : 'Sin zonas que consultar';

  // El dato de botnet va detras de una raya, no mezclado en el recuento. Es lo
  // primero que hay que leer cuando no es cero, y no puede sumar-se al total de
  // correo porque son dos problemas distintos con dos gravedades distintas.
  const base = sinDatos > 0 ? `${listadas} de ${consultadas} (${sinDatos} sin respuesta)` : `${listadas} de ${consultadas}`;

  return botnetListadas > 0 ? `${base} — ${botnetListadas} de botnet C&C` : base;
}

/** El tono de la tarjeta de resumen segun lo que hayan dicho las listas. */
function tonoListas(listas) {
  if (!listas) return 'neutral';

  // Sin zonas consultadas no hay veredicto que poner de color. Ponerlo en
  // verde diria "todo limpio" sobre una pregunta que no se ha hecho, que para
  // una IPv6 es el caso normal y no una excepcion.
  if (listas.resumen.consultadas === 0) return 'neutral';

  if (listas.resumen.listadas > 0) return 'bad';
  if (listas.resumen.sinDatos > 0) return 'warn';
  return 'ok';
}

/** `203.0.0.1 - 203.0.255.254`, o el prefijo si el registro no da los extremos. */
function rangoTexto(registro) {
  if (registro.inicio && registro.fin) return `${registro.inicio} - ${registro.fin}`;
  if (registro.prefijoCidr) return registro.prefijoCidr;
  if (registro.inicio) return registro.inicio;
  return 'Sin dato';
}

function textoAbuso(registro) {
  const a = registro.contactoAbuso;
  if (!a || (!a.nombre && !a.correo)) return 'Sin dato';
  return [a.nombre, a.correo].filter(Boolean).join(' — ');
}

/** Fechas de RDAP a dia y mes. `null` se distingue de "no hay dato". */
function fechaCorta(fecha) {
  if (!fecha) return 'Sin dato';
  const d = new Date(fecha);
  if (Number.isNaN(d.getTime())) return String(fecha);
  return d.toISOString().slice(0, 10);
}

function etiquetaEstado(estado) {
  return {
    [dnsbl.ESTADOS.LISTADA]: 'LISTADA',
    [dnsbl.ESTADOS.LIMPIA]: 'No listada',
    [dnsbl.ESTADOS.SIN_DATOS]: 'Sin respuesta',
    [dnsbl.ESTADOS.SIN_APLICAR]: 'No aplica'
  }[estado] || estado;
}

/**
 * Los tres estados de una consulta, en palabras que no se puedan confundir.
 *
 * "No listada" y "sin comprobar" tienen que distinguirse a la primera vista, que
 * es como se lee una tabla. Por eso el tercero no se llama tampoco "no listada":
 * si no se ha podido preguntar, no hay nada que leer de esa celda.
 */
function etiquetaSpamhaus(estado) {
  return {
    [spamhaus.ESTADOS.LISTADA]: 'LISTADA AHORA',
    [spamhaus.ESTADOS.NO_LISTADA]: 'No listada ahora',
    [spamhaus.ESTADOS.DESCONOCIDO]: 'Sin comprobar'
  }[estado] || estado;
}

/** Acota un numero, sin confundir el 0 con "no informado". */
function acotar(valor, min, max, porDefecto) {
  const n = Number(valor);
  if (!Number.isFinite(n)) return porDefecto;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

module.exports = {
  id: ID,
  titulo: 'Auditoria de IP',
  descripcion:
    'Quien registro la IP, que nombre inverso tiene, si aparece en listas negras de correo y si figura como ' +
    'controlador de botnet. Ojo: BCL no se puede comprobar desde un servidor sin resolver; ver la seccion de botnet C&C.',
  sinRed: false,
  icon: '🔎',
  campos: CAMPOS,
  ejecutar
};
