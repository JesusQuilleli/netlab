'use strict';

/**
 * dns-checker — comprobación de la resolución DNS de un nombre.
 *
 * Consulta los registros que importan para diagnosear un dominio (A, AAAA,
 * CNAME, MX, NS, TXT, SOA y CAA), monta un informe con lo encontrado y, sobre
 * todo, dice qué significa: que no haya MX, que falte SPF o que los resolvers
 * públicos no coincidan con el del sistema son datos, pero el hallazgo es lo que
 * convierte un volcado de registros en algo accionable.
 *
 * Decisión de diseño: la comparación entre resolvers viene APAGADA. Es la
 * función que más valor aporta para diagnosticar split-horizon, pero cada
 * ejecución manda consultas a Cloudflare y a Google. Como eso es un efecto
 * externo que el usuario tiene que autorizar de forma consciente, se activa con
 * una casilla y no por defecto.
 */

const {
  createResult,
  addSection,
  addSummary,
  addFinding,
  addLog,
  failWith,
  finalize,
  SECCION_KINDS: K,
  SEVERIDADES
} = require('../core/result');
const { NetlabError, CODES } = require('../core/errors');
const { redactDeep } = require('../core/redact');
const dnsNet = require('../core/net/dns');
const {
  parsear: parsearEsperado,
  normalizarNombre,
  normalizarValor,
  recortar
} = require('../core/dns-esperado');
const { normalizarDominio, normalizarIp, normalizarTimeout } = require('../core/dominio');

const ID = 'dns-checker';

/** Tipos que se consultan si el usuario no indica otros. */
const TIPOS_POR_DEFECTO = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];

/**
 * Tipos de registro DNSSEC.
 *
 * Forman parte de `TIPOS_SOPORTADOS`, asi que se pueden pedir a mano, y ademas
 * DNSKEY y DS se consultan solos cuando el usuario no recorta el chequeo (ver
 * `consultarDnssecContexto`): con esas dos respuestas se decide si el dominio
 * esta firmado y si la DS de la zona padre encaja con las claves publicadas.
 * Los demas (RRSIG, NSEC, NSEC3, NSEC3PARAM) solo se piden a mano.
 */
const TIPOS_DNSSEC = ['DNSKEY', 'DS', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM'];

/** Con DNSKEY y DS se decide el estado de la cadena; el resto se pide a mano. */
const DNSSEC_DIAGNOSTICOS = ['DNSKEY', 'DS'];

/**
 * Tipos que se pueden pedir desde el formulario.
 *
 * `PTR` no está y a propósito: la resolución inversa no es un registro de este
 * nombre sino de una dirección, así que consultarlo aquí no significa nada.
 * Tiene su propio campo, que es donde se introduce la IP.
 */
const TIPOS_SOPORTADOS = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'SRV', ...TIPOS_DNSSEC];

/** Respuestas definitivas: un NXDOMAIN no se rellena de avisos. */
const CODIGO_DEFINITIVO = 'ENOTFOUND';

/** Nombre de cada algoritmo DNSSEC, para las celdas y los hallazgos. */
const ALGORITMOS_DNSSEC = {
  1: 'RSAMD5',
  3: 'DSA',
  5: 'RSASHA1',
  6: 'DSA-NSEC3-SHA1',
  7: 'RSASHA1-NSEC3-SHA1',
  8: 'RSASHA256',
  10: 'RSASHA512',
  12: 'ECCGOST',
  13: 'ECDSAP256SHA256',
  14: 'ECDSAP384SHA384',
  15: 'ED25519',
  16: 'ED448'
};

/** Nombre de cada tipo de digerido del DS. */
const DIGESTOS_DS = { 1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384' };

function nombrarAlgoritmo(algorithm) {
  return ALGORITMOS_DNSSEC[algorithm] || `algoritmo ${algorithm}`;
}

/** Rol de una DNSKEY a partir de sus flags (RFC 4034). */
function rolClave(flags) {
  if ((flags & 0x0001) !== 0) return 'KSK';
  if ((flags & 0x0100) !== 0) return 'ZSK';
  return `flags ${flags}`;
}

/** Resolvers con los que se compara cuando el usuario lo pide. */
const RESOLVER_A_COMPARAR = [
  { nombre: 'Sistema', servers: undefined },
  { nombre: 'Cloudflare', servers: ['1.1.1.1'] },
  { nombre: 'Google', servers: ['8.8.8.8'] }
];

/** Campos del formulario, que es lo que consume la web. */
const CAMPOS = [
  {
    name: 'dominio',
    label: 'Dominio o nombre de host',
    type: 'text',
    // Deja de ser obligatorio cuando se compara contra un archivo: entonces el
    // dominio sale del propio archivo y el campo pasa a ser un filtro.
    requiredUnless: 'compararArchivo',
    placeholder: 'ejemplo.com',
    help: 'Se puede escribir con https:// delante o con la ruta; se limpia solo. Para la resolución inversa usa el campo de abajo. Si comparas contra un archivo, déjalo vacío para revisar todos los nombres que traiga, o escribe un dominio para limitarlo a ese.'
  },
  {
    name: 'tipos',
    label: 'Tipos de registro',
    type: 'text',
    required: false,
    placeholder: 'A, AAAA, MX, TXT',
    help: `Opcional, separados por comas. Si lo dejas vacío se consultan: ${TIPOS_POR_DEFECTO.join(', ')} (y se revisa el estado DNSSEC). Además puedes pedir registros DNSSEC a mano: ${TIPOS_DNSSEC.join(', ')}. Al comparar contra un archivo no hace falta: los tipos se sacan del archivo.`
  },
  {
    name: 'inversa',
    label: 'Resolución inversa de una IP',
    type: 'text',
    required: false,
    placeholder: '8.8.8.8',
    help: 'Opcional. Consulta el PTR de una dirección suelta en el mismo informe.'
  },
  {
    name: 'compararArchivo',
    label: 'Comparar con un archivo .txt',
    type: 'checkbox',
    required: false,
    default: false,
    help: 'Opcional y apagado por defecto. Sube un archivo con el estado que debería tener la zona y el informe dirá qué coincide, qué falta, qué ha cambiado y qué se ha añadido de más.'
  },
  {
    name: 'archivoNombre',
    label: 'Nombre del archivo',
    type: 'text',
    required: false,
    placeholder: 'berakah.com.ve.txt',
    shownWhen: 'compararArchivo',
    help: 'Solo informativo: sale en la cabecera del informe. No hace falta escribirlo si el navegador ya da el nombre.'
  },
  {
    name: 'archivoContenido',
    label: 'Archivo',
    type: 'file',
    accept: '.txt,text/plain',
    required: false,
    maxBytes: 1024 * 1024,
    shownWhen: 'compararArchivo',
    help: 'Se admiten dos formatos: la exportación de zona que descarga Cloudflare, o un texto con líneas "Nombre:" y "Valor:". Se lee entero, en memoria, y no se guarda en disco.'
  },
  {
    name: 'comparar',
    label: 'Comparar con Cloudflare y Google',
    type: 'checkbox',
    required: false,
    default: false,
    help: 'Opcional y apagado por defecto. Repite las consultas contra 1.1.1.1 y 8.8.8.8 y avisa si no coinciden con las del sistema, que es la huella de un split-horizon. Al comparar contra un archivo no añade nada: el archivo ya dice lo que debería haber.'
  },
  {
    name: 'timeout',
    label: 'Tiempo de espera por consulta (ms)',
    type: 'number',
    required: false,
    default: 5000,
    min: 500,
    max: 30000,
    help: 'Cuánto esperar por registro antes de dalo por agotado.'
  }
];

/**
 * Ejecuta la comprobación.
 *
 * @param {object} params
 * @param {object} [ctx]
 * @param {object} [ctx.log] Logger con `info`/`warn`/`error`.
 * @param {object} [ctx.dns] Inyección del módulo DNS. Existe para poder probar
 *   la lógica de los hallazgos sin salir a la red: sin esto, cada test
 *   dependería de que gmail.com siga teniendo los mismos registros.
 * @returns {Promise<object>} Result
 */
async function ejecutar(params = {}, ctx = {}) {
  const inicio = new Date();
  const log = ctx.log || null;
  const dns = ctx.dns || dnsNet;

  // El objetivo se lee antes de validar, y a proposito sin limpiar: si el
  // dominio esta mal escrito, el informe debe decir que se escribio eso y no
  // un nombre ya recortado, que es justo lo que haria falta para reproducir el
  // problema. La validacion va dentro del try: si no, un dominio invalido
  // escaparia como excepcion y el usuario veria un stack en vez del informe.
  const crudo = String(params.dominio ?? '').trim();

  const result = createResult({
    tool: ID,
    toolTitle: 'Comprobador de DNS',
    target: crudo,
    params: paramsParaInforme(params)
  });

  try {
    const timeout = normalizarTimeout(params.timeout);
    const ipInversa = normalizarIp(params.inversa);

    // Con archivo, el dominio es opcional: los nombres salen del archivo y el
    // campo solo sirve para filtrar. Sin archivo, es obligatorio.
    const dominio = crudo ? normalizarDominio(crudo) : null;
    if (!dominio && !params.compararArchivo) {
      throw new NetlabError(CODES.ENTRADA_VACIA, 'No se indicó ningún dominio ni ningún archivo.', {
        remediation: 'Escribe el dominio que quieres comprobar, por ejemplo ejemplo.com, o activa la casilla de comparar contra un archivo.'
      });
    }

    if (params.compararArchivo) {
      await compararConArchivo(result, dns, { dominio, timeout, contenido: params.archivoContenido }, log);
    }

    if (!dominio) {
      // Solo hay archivo: ya se ha pintado todo lo que hay que pintar.
      return finalize(result, inicio);
    }

    const tipos = parseTipos(params.tipos);
    addLog(result, { level: 'info', channel: 'entrada', message: `Comprobando ${dominio} (${tipos.join(', ')})` });
    log?.info?.(`dns-checker: ${dominio} tipos=${tipos.join(',')} comparar=${Boolean(params.comparar)}`);

    const consultas = tipos.map((tipo) => ({ nombre: dominio, tipo }));
    const registros = await dns.consultarLote(consultas, {
      concurrencia: Math.min(8, tipos.length),
      dns: { timeout, reintentos: 1 }
    });

    const mapa = indexar(registros);
    addLog(result, {
      level: 'info',
      channel: 'dns',
      message: `${registros.filter((r) => r.ok).length} de ${registros.length} tipos con resultado`
    });

    pintarResumen(result, mapa, dominio);
    pintarRegistros(result, registros);

    // DNSSEC: con las 8 consultas por defecto, o si el usuario pidió algún
    // registro DNSSEC a mano, se consulta DNSKEY y DS para leer el estado de
    // la cadena. Un NXDOMAIN no se rellena de avisos de firma, y sin método
    // (tests inyectados) simplemente se omite.
    let dnssec = null;
    const tiposPorDefecto = tipos.length === TIPOS_POR_DEFECTO.length && TIPOS_POR_DEFECTO.every((t) => tipos.includes(t));
    const quiereDnss = tipos.some((t) => TIPOS_DNSSEC.includes(t));
    const nombreInexistente = registros.some((r) => r.codigoDns === CODIGO_DEFINITIVO);
    // Se entra si se pidió DNSSEC (a mano o por defecto) y hay forma de
    // obtener los datos: el método de consulta directa, o bien DNSKEY/DS que
    // ya hayan llegado en el lote pedido.
    const dnssecDisponible = typeof dns.consultarDnssec === 'function';
    const yaHayDatos = DNSSEC_DIAGNOSTICOS.some((t) => tipos.includes(t) && mapa.has(t));
    if ((tiposPorDefecto || quiereDnss) && !nombreInexistente && (dnssecDisponible || yaHayDatos)) {
      dnssec = await consultarDnssecContexto(result, { dns, dominio, tipos, mapa, timeout });
      pintarDnssec(result, { dominio, dnssec });
    }

    let ptr = null;
    if (ipInversa) {
      ptr = await consultarInversa(result, dns, ipInversa);
    }

    // DMARC vive en un nombre aparte, `_dmarc.<dominio>`, no en el TXT del
    // dominio. Sin esta consulta la comprobacion de DMARC miraria donde no
    // hay nada y siempre daria "no hay DMARC", tambien en los dominios que si
    // lo tienen. Solo tiene sentido si el dominio recibe correo.
    let dmarc = null;
    const mx = mapa.get('MX');
    if (mx?.ok && mx.valores.length) {
      dmarc = await dns.consultar(`_dmarc.${dominio}`, 'TXT', { timeout, reintentos: 1 });
      addLog(result, {
        level: 'info',
        channel: 'dns',
        message: `DMARC de ${dominio}: ${dmarc.ok ? 'encontrado' : 'sin registro'}`
      });
    }

    let diferencias = null;
    if (params.comparar) {
      diferencias = await compararResolvers(result, dns, dominio, tipos, timeout);
    }

    revisar(result, { dominio, tipos, mapa, registros, ipInversa, ptr, dmarc, comparo: Boolean(params.comparar), diferencias, dnssec });

    return finalize(result, inicio);
  } catch (error) {
    addLog(result, { level: 'error', channel: 'error', message: error.message });
    log?.error?.(`dns-checker fallo: ${error.message}`);
    return failWith(
      finalize(result, inicio),
      error instanceof NetlabError ? error : new NetlabError(CODES.INTERNO, error.message)
    );
  }
}

/* ------------------------------------------------------------------ *
 * Normalización de la entrada
 *
 * `normalizarDominio`, `normalizarIp` y `normalizarTimeout` viven en
 * `core/dominio.js`: comprobador de DNS y comprobador de correo comparten
 * exactamente la misma limpieza de entrada.
 * ------------------------------------------------------------------ */

/** Convierte la lista de tipos en un array validado y sin repetir. */
function parseTipos(bruto) {
  const texto = String(bruto ?? '').trim();
  if (!texto) return [...TIPOS_POR_DEFECTO];

  const tipos = [...new Set(texto.split(/[\s,]+/).map((t) => t.trim().toUpperCase()).filter(Boolean))];
  const malos = tipos.filter((t) => !TIPOS_SOPORTADOS.includes(t));
  if (malos.length) {
    throw new NetlabError(CODES.PARAM_INVALIDO, `Tipo de registro no soportado: ${malos.join(', ')}.`, {
      remediation: `Tipos disponibles: ${TIPOS_SOPORTADOS.join(', ')}.`
    });
  }
  return tipos;
}

/** Indexa los resultados por tipo en mayúsculas. */
function indexar(registros) {
  const mapa = new Map();
  for (const r of registros) {
    mapa.set(String(r.tipo).toUpperCase(), r);
  }
  return mapa;
}

/* ------------------------------------------------------------------ *
 * Presentación
 * ------------------------------------------------------------------ */

/** Cabecera con los contadores que resumen el dominio. */
function pintarResumen(result, mapa, dominio) {
  const cuenta = (tipo) => (mapa.get(tipo)?.ok ? mapa.get(tipo).valores.length : 0);

  addSummary(result, 'Direcciones IPv4', String(cuenta('A')));
  addSummary(result, 'Direcciones IPv6', String(cuenta('AAAA')));
  addSummary(result, 'Servidores de correo', String(cuenta('MX')));
  addSummary(result, 'Servidores de nombres', String(cuenta('NS')));

  const a = mapa.get('A');
  const aaaa = mapa.get('AAAA');
  const resuelve = (a?.ok && a.valores.length) || (aaaa?.ok && aaaa.valores.length);
  addSummary(result, 'Resuelve', resuelve ? 'Sí' : 'No', resuelve ? 'ok' : 'bad');
}

/** Tabla principal con un tipo por fila. */
function pintarRegistros(result, registros) {
  addSection(result, {
    title: 'Registros',
    kind: K.TABLA,
    columns: ['Tipo', 'Valor', 'TTL', 'Resultado'],
    anchoColumnas: [12, 54, 12, 22],
    rows: registros.map((r) => [
      r.tipo,
      resumirValores(r.valores),
      r.ttl == null ? '—' : String(r.ttl),
      r.ok ? { valor: `${r.valores.length} encontrado${r.valores.length === 1 ? '' : 's'}`, tone: 'ok' }
           : { valor: r.error, tone: 'bad' }
    ])
  });
}

/**
 * Consulta DNSKEY y DS para el diagnostico DNSSEC, en paralelo.
 *
 * Si el usuario ya pidió alguno de los dos a mano, su resultado está en el
 * `mapa` del lote y se reutiliza; los que falten se consultan ahora. Devuelve
 * los dos juntos para que `revisar` pueda decidir sobrela cadena completa.
 */
async function consultarDnssecContexto(result, { dns, dominio, tipos, mapa, timeout }) {
  const pendientes = DNSSEC_DIAGNOSTICOS.filter((tipo) => !tipos.includes(tipo));
  const extra =
    typeof dns.consultarDnssec === 'function' && pendientes.length
      ? await Promise.all(
          pendientes.map((tipo) =>
            dns.consultarDnssec(dominio, tipo, { timeout, reintentos: 1 }).then((r) => ({ tipo, ...r }))
          )
        )
      : [];

  for (const r of extra) {
    mapa.set(r.tipo, { ok: r.ok, valores: r.valores, ttl: r.ttl, error: r.error, codigo: r.codigo, codigoDns: r.codigoDns, ad: r.ad });
    addLog(result, {
      level: 'info',
      channel: 'dns',
      message: `${r.tipo} de ${dominio}: ${r.ok ? `${r.valores.length} encontrado${r.valores.length === 1 ? '' : 's'}` : `sin resultado (${r.codigoDns || 'error'})`}`
    });
  }

  return {
    activo: true,
    dnskey: mapa.get('DNSKEY'),
    ds: mapa.get('DS')
  };
}

/** Cabecera y resumen del estado DNSSEC (solo cuando se consultó). */
function pintarDnssec(result, { dominio, dnssec }) {
  const { dnskey, ds } = dnssec;
  const ad = Boolean(dnskey?.ad) || Boolean(ds?.ad);

  const firmado = Boolean(dnskey?.ok && dnskey.valores.length);
  const sinFirmar = Boolean(dnskey?.ok) && !dnskey.valores.length;
  const dsConDatos = Boolean(ds?.ok && ds.valores.length);

  const estado = firmado ? 'Firmado' : sinFirmar ? 'Sin firmar' : 'No se pudo comprobar';
  addSummary(result, 'DNSSEC', estado, firmado ? 'ok' : sinFirmar ? 'neutral' : 'warn');

  const claves = firmado
    ? dnskey.valores.map((v) => `${rolClave(v.flags)} ${nombrarAlgoritmo(v.algorithm)} (keyTag ${v.keyTag})`).join(' · ')
    : sinFirmar
      ? 'Ninguna'
      : '—';

  const dsTexto = dsConDatos
    ? ds.valores.length === 1
      ? `1 DS (keyTag ${ds.valores[0].keyTag})`
      : `${ds.valores.length} registros DS`
    : ds?.ok
      ? 'Ninguna'
      : '—';

  addSection(result, {
    title: 'Estado DNSSEC',
    kind: K.PARES,
    items: [
      ['Estado', estado, firmado ? 'ok' : sinFirmar ? 'neutral' : 'warn'],
      ['Claves DNSKEY', claves],
      ['DS en la zona padre', dsTexto],
      ['Respuesta validada (AD)', ad ? 'Sí' : 'No']
    ]
  });

  addLog(result, { level: 'info', channel: 'dns', message: `DNSSEC de ${dominio}: ${estado}` });
}

/** Resolución inversa, si se pidió. */
async function consultarInversa(result, dns, ip) {
  const nombres = await dns.resolverPTR(ip);
  addLog(result, { level: 'info', channel: 'ptr', message: `PTR de ${ip}: ${nombres.length ? nombres.join(', ') : 'sin registro'}` });

  addSection(result, {
    title: 'Resolución inversa',
    kind: K.TABLA,
    columns: ['Dirección', 'Nombre (PTR)', 'Resultado'],
    anchoColumnas: [22, 56, 22],
    rows: [[ip, nombres.length ? nombres.join(', ') : '—', nombres.length ? { valor: 'Definido', tone: 'ok' } : { valor: 'Sin PTR', tone: 'warn' }]]
  });

  return nombres;
}

/**
 * Repite las consultas contra otros resolvers y señala las discrepancias.
 *
 * Solo se llama si el usuario activó la casilla. Aparece apagada por lo dicho
 * al principio del archivo: manda tráfico a terceros.
 */
async function compararResolvers(result, dns, dominio, tipos, timeout) {
  const filas = [];

  // Las 24 consultas (8 tipos por 3 resolvers) van en paralelo. En serie eran
  // casi ocho segundos de espera para un informe que el usuario solo quiere de
  // vez en cuando, y el timeout de cada una se suma.
  const todo = await Promise.all(
    tipos.flatMap((tipo) =>
      RESOLVER_A_COMPARAR.map((r) => {
        const opciones = r.servers ? { servers: r.servers, timeout, reintentos: 1 } : { timeout, reintentos: 1 };
        return dns.consultar(dominio, tipo, opciones).then((res) => ({ tipo, nombre: r.nombre, ...res }));
      })
    )
  );

  const clave = (x) => (x.ok ? canonico(x.valores) : `error:${x.codigoDns || x.codigo}`);

  for (const tipo of tipos) {
    const porResolver = todo.filter((x) => x.tipo === tipo);
    const base = porResolver.find((x) => x.nombre === RESOLVER_A_COMPARAR[0].nombre);

    for (const otro of porResolver.slice(1)) {
      const iguales = clave(base) === clave(otro);
      filas.push([
        tipo,
        { valor: resumenComparacion(base.valores), tone: base.ok ? 'neutral' : 'bad' },
        otro.nombre,
        { valor: resumenComparacion(otro.valores), tone: otro.ok ? 'neutral' : 'bad' },
        iguales ? { valor: 'Igual', tone: 'ok' } : { valor: 'Difiere', tone: 'warn' }
      ]);
    }
  }

  addLog(result, { level: 'info', channel: 'comparar', message: `Comparados ${tipos.length} tipos con ${RESOLVER_A_COMPARAR.length} resolvers` });


  const diferencias = filas.filter((f) => f[4].valor === 'Difiere').length;

  addSection(result, {
    title: 'Comparación de resolvers',
    description: 'Consultas repetidas contra el resolvedor del sistema, Cloudflare y Google. Si difieren, la respuesta depende de quién pregunta, que es la huella de un split-horizon.',
    kind: K.TABLA,
    columns: ['Tipo', 'Sistema', 'Comparado con', 'Respuesta del otro', 'Veredicto'],
    anchoColumnas: [10, 15, 16, 47, 12],
    rows: filas
  });

  // Se devuelven las diferencias para que `revisar` las convierta en
  // hallazgos. Dejarlas solo en la tabla no sirve de nada: la tabla obliga a
  // buscarlas a ojo y el hallazgo es lo que el usuario lee.
  return filas
    .filter((f) => f[4].valor === 'Difiere')
    .map((f) => ({ tipo: f[0], contra: f[2] }));
}

/* ------------------------------------------------------------------ *
 * Hallazgos
 * ------------------------------------------------------------------ */

/**
 * Convierte los resultados en hallazgos accionables.
 *
 * `tipos` es lo que el usuario pidió consultar, y importa más de lo que parece:
 * un hallazgo sobre un tipo que no se consulted no significa nada. Si alguien
 * pide solo los TXT de `_dmarc.ejemplo.com` y la respuesta es "el nombre no
 * resuelve a ninguna dirección" y "no tiene servidores de correo", el informe
 * esta describiendo un dominio que nadie ha mirado: el nombre de una politica
 * de DMARC no tiene por que tener direccion, correo ni servidores de nombres,
 * y exigirselo es ruido que hace desconfiar del resto.
 *
 * Esa comprobacion era la que hacia inutilizable el campo de tipos: acortabas
 * la consulta para no pagar ocho lookups y el informe se llenaba de avisos
 * sobre datos que no habias pedido.
 */
function revisar(result, { dominio, tipos, mapa, registros, ipInversa, ptr, dmarc: ctxDmarc, comparo, diferencias, dnssec }) {
  const pedido = (...nombres) => nombres.some((n) => tipos.includes(n));
  const quiereDirecciones = pedido('A', 'AAAA');

  const a = mapa.get('A');
  const aaaa = mapa.get('AAAA');
  const mx = mapa.get('MX');
  const ns = mapa.get('NS');
  const soa = mapa.get('SOA');
  const txt = mapa.get('TXT');
  const cname = mapa.get('CNAME');

  // --- El nombre existe? ---
  const nxdomain = registros.some((r) => r.codigoDns === 'ENOTFOUND');
  const servfail = registros.some((r) => r.codigoDns === 'ESERVFAIL');
  const timeout = registros.some((r) => r.codigoDns === 'ETIMEDOUT' || r.codigoDns === 'EAI_AGAIN');

  if (nxdomain) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: `El nombre ${dominio} no existe`,
      detail: 'El servidor de nombres ha respondido NXDOMAIN: no hay ningún registro con ese nombre, ni en la zona ni delegando a otro sitio.',
      recommendation: 'Revisa la ortografía, que la zona esté delegada en los NS de la zona padre y que los servidores autoritativos estén cargando el nombre.'
    });
    return; // Nada más que decir de un nombre que no existe.
  }

  if (servfail) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'Un servidor de nombres devolvió SERVFAIL',
      detail: 'El servidor autoritativo reconoce el nombre pero no puede completar la consulta.',
      recommendation: 'Suele deberse a un CNAME que apunta a un nombre inexistente, a una zona mal cargada o a un problema de DNSSEC. Mira el log del servidor de nombres.'
    });
  }

  if (timeout) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Alguna consulta se agotó',
      detail: 'No se pudo obtener respuesta de uno de los registros dentro del plazo.',
      recommendation: 'Si se repite, el servidor de nombres está saturado o inalcanzable desde aquí. Puedes subir el tiempo de espera en las opciones.'
    });
  }

  // --- Resoluble? ---
  const tieneA = Boolean(a?.ok && a.valores.length);
  const tieneAAAA = Boolean(aaaa?.ok && aaaa.valores.length);

  if (quiereDirecciones && !tieneA && !tieneAAAA) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'El nombre no resuelve a ninguna dirección',
      detail: 'No hay registros A ni AAAA, así que nada puede conectarse a este nombre.',
      recommendation: 'Si el nombre es un alias, mira si el CNAME apunta a otro nombre que sí exista. Si es un host propio, falta el registro de dirección.'
    });
  } else if (quiereDirecciones && !tieneAAAA) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'Sin IPv6',
      detail: `Solo hay direcciones IPv4. Un cliente que solo soporte IPv6 no podrá conectar con ${dominio}.`,
      recommendation: 'No es un error si el servicio es interno o si la IPv6 no está desplegada todavía. Publicar un AAAA sin servicio detrás es peor que no publicarlo.'
    });
  }

  if (quiereDirecciones && tieneA && tieneAAAA) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'Resuelve a IPv4 e IPv6',
      detail: 'Hay registros de los dos tipos, que es lo correcto en un dominio con doble pila.',
      recommendation: 'Comprueba que el servidor también escuta en IPv6: publicar un AAAA sin servicio detrás es peor que no publicarlo.'
    });
  }

  // --- Correo ---
  if (tipos.includes('MX')) {
    if (mx?.ok && mx.valores.length) {
      revisarCorreo(result, txt, ctxDmarc, dominio);
    } else {
      addFinding(result, {
        severity: SEVERIDADES.INFO,
        title: 'Sin servidores de correo',
        detail: 'No hay registros MX, así que este nombre no recibe correo.',
        recommendation: 'Normal en un sitio web que no manda correos. Si debería recibirlos, falta el MX.'
      });
    }
  }

  // --- Zona ---
  if (tipos.includes('NS') && (!ns?.ok || !ns.valores.length)) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Sin servidores de nombres',
      detail: 'No se han podido consultar los NS del dominio.',
      recommendation: 'Sin NS autoritativos el dominio no está delegado. Si es un subdominio, comprueba que el CNAME de la zona padre sea correcto.'
    });
  }

  if (soa?.ok && soa.valores.length) {
    const s = soa.valores[0];
    if (s && typeof s === 'object') {
      addSummary(result, 'Serial SOA', String(s.serial ?? '—'));
      addSection(result, {
        title: 'Cabecera SOA',
        kind: K.PARES,
        items: [
          ['Servidor de nombres primario', s.nsname ?? '—'],
          ['Correo del responsable', s.hostmaster ?? '—'],
          ['Serial', s.serial ?? '—'],
          ['Refresh', s.refresh ?? '—'],
          ['Retry', s.retry ?? '—'],
          ['Expire', s.expire ?? '—'],
          ['Mínimo TTL', s.minttl ?? '—']
        ]
      });
    }
  } else if (mapa.has('SOA')) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'La zona no devuelve SOA',
      detail: 'El tipo SOA no ha respondido. Sin cabecera SOA una zona no es válida.',
      recommendation: 'Revisa la configuración de la zona en el servidor de nombres.'
    });
  }

  // --- Alias ---
  if (cname?.ok && cname.valores.length) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'Es un alias (CNAME)',
      detail: `${dominio} es un alias a ${cname.valores.join(', ')}.`,
      recommendation: 'Un CNAME en la raíz del dominio impide poner otros registros ahí (MX, TXT). Si necesitas correo o SPF, usa el subdominio en vez del ápice.'
    });
  }

  // --- TTL muy bajo ---
  const ttlBajo = [a, aaaa].filter((r) => r?.ok && typeof r.ttl === 'number' && r.ttl < 60);
  if (ttlBajo.length) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'TTL muy bajo',
      detail: `El TTL de las direcciones es de ${ttlBajo[0].ttl} segundos.`,
      recommendation: 'Un TTL bajo hace que los cambios se propaguen rápido, pero genera más consultas al servidor de nombres. Es una decisión consciente: solo te avisa en caso de que te haya pillado por sorpresa.'
    });
  }

  // --- Inversa ---
  if (ipInversa) {
    if (ptr && ptr.length) {
      addFinding(result, {
        severity: SEVERIDADES.INFO,
        title: 'La IP tiene PTR',
        detail: `${ipInversa} resuelve a ${ptr.join(', ')}.`,
        recommendation: 'Es lo esperable si esa IP corresponde a un host con nombre propio.'
      });
    } else {
      addFinding(result, {
        severity: SEVERIDADES.WARN,
        title: 'La IP no tiene PTR',
        detail: `${ipInversa} no resuelve a ningún nombre.`,
        recommendation: `Sin PTR el correo sale sin nombre de remitente y muchos servidores lo rechazan o lo marcan como spam. Si esta IP manda correo, el PTR debería existir y coincidir con el nombre que se usa en el SMTP.`
      });
    }
  }

  if (comparo) {
    revisarDiferencias(result, dominio, diferencias);
  }

  // El estado de la cadena DNSSEC se cierra el último: depende de DNSKEY y DS
  // juntos, y no tiene sentido antes de saber si el nombre siquiera existe.
  if (dnssec?.activo) {
    revisarDnssec(result, { dominio, dnskey: dnssec.dnskey, ds: dnssec.ds });
  }
}

/**
 * Convierte DNSKEY + DS en un veredicto de DNSSEC.
 *
 * La regla de fondo es no confundir "no está firmado" con "no lo sé": la
 * severidad sube solo cuando hay un desajuste entre lo que promete la zona
 * padre (DS) y lo que publica el dominio (DNSKEY). Un dominio sin firmar es una
 * decisión legítima y sale como información; un DS que no encaja rompe la
 * resolución para los validadores y sale como error.
 */
function revisarDnssec(result, { dominio, dnskey, ds }) {
  const firmado = Boolean(dnskey?.ok && dnskey.valores.length);
  const dsConDatos = Boolean(ds?.ok && ds.valores.length);

  if (!firmado) {
    if (dsConDatos) {
      addFinding(result, {
        severity: SEVERIDADES.ERROR,
        title: 'La zona padre tiene DS pero el dominio no publica las claves',
        detail: `${dominio} no devuelve DNSKEY y sin embargo hay ${ds.valores.length} registro(s) DS apuntando a claves que no están. Un validador busca la clave que el DS promete, no la encuentra y la resolución acaba en SERVFAIL.`,
        recommendation: 'Publica la DNSKEY correspondiente, o retira el DS de la zona padre si la clave ya no debe existir. DS y clave han de convivir.'
      });
    } else if (dnskey?.ok) {
      addFinding(result, {
        severity: SEVERIDADES.INFO,
        title: 'Sin DNSSEC',
        detail: `No hay ningún registro DNSKEY en ${dominio}, así que no está firmado. Sin firma no hay cadena que validar, pero tampoco la integridad que DNSSEC aporta.`,
        recommendation: 'Firmar la zona es opcional y siempre exige coordinar el DS con la zona padre. Si el dominio no lo necesita, no es un fallo.'
      });
    } else {
      addFinding(result, {
        severity: SEVERIDADES.INFO,
        title: 'No se pudo comprobar el estado DNSSEC',
        detail: ds
          ? 'La consulta de DNSKEY no devolvió nada utilizable, así que no se puede decir si el dominio está firmado o no.'
          : 'Las consultas de DNSKEY y DS no respondieron. No hay datos para hablar de DNSSEC.',
        recommendation: 'Revisa la conectividad y repite. Este aviso no significa que al dominio le falte algo.'
      });
    }
    return;
  }

  const ksk = dnskey.valores.filter((v) => (v.flags & 0x0001) !== 0).length;
  const algoritmos = [...new Set(dnskey.valores.map((v) => nombrarAlgoritmo(v.algorithm)))].join(', ');

  addFinding(result, {
    severity: SEVERIDADES.INFO,
    title: 'Firmado con DNSSEC',
    detail: `${dominio} publica ${dnskey.valores.length} clave(s), ${ksk} KSK, con algoritmo(s) ${algoritmos}.`,
    recommendation: 'Planifica la rotación de claves: al cambiar una KSK, actualiza primero el DS de la zona padre y espera a la propagación antes de dar de baja la clave vieja.'
  });

  if (ds?.ok) {
    if (!dsConDatos) {
      addFinding(result, {
        severity: SEVERIDADES.WARN,
        title: 'Firmado pero sin DS en la zona padre',
        detail: 'El dominio tiene DNSKEY pero la zona padre no publica ningún registro DS. Un validador estricto no puede construir la cadena de confianza desde la raíz.',
        recommendation: 'Publica en la zona padre un DS con el keyTag y el algoritmo de la KSK. Es el paso que une la zona con la de arriba.'
      });
    } else {
      const tagsPublicados = new Set(dnskey.valores.map((v) => v.keyTag));
      const coinciden = ds.valores.filter((d) => tagsPublicados.has(d.keyTag));
      if (!coinciden.length) {
        addFinding(result, {
          severity: SEVERIDADES.ERROR,
          title: 'El DS no corresponde con ninguna clave publicada',
          detail: `El DS anuncia ${ds.valores.map((d) => `keyTag ${d.keyTag}`).join(', ')}, pero el dominio publica ${[...tagsPublicados].map((t) => `keyTag ${t}`).join(', ')}. El validador no puede casar los dos lados.`,
          recommendation: 'O el DS apunta a una clave retirada (actualízalo a la KSK actual) o falta publicar en la zona la KSK que el DS promete. Nuevo DS y clave han de convivir durante la transición.'
        });
      }
    }
  } else if (ds) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'El estado del DS no se pudo comprobar',
      detail: 'El dominio está firmado, pero la consulta del DS no respondió: la cadena puede estar bien o rota.',
      recommendation: 'Repite la consulta más tarde. Sin el DS no se puede dar la cadena por buena.'
    });
  }
}

/**
 * Traduce las discrepancias entre resolvers en hallazgos.
 *
 * No todas las diferencias son lo mismo, y treatarlas igual produce un informe
 * lleno de ruido:
 *
 *   - En MX, NS, SOA o TXT, dos resolvers que no coinciden significan que el
 *     correo o la delegacion de la zona dependen de quien pregunta. Eso es un
 *     problema de verdad.
 *   - En A y AAAA, lo normal es que haya varias direcciones y cada consulta
 *     devuelve una distinta por balanceo de carga. Marca el mismo nombre con
 *     dos IPs legitimas. Aviso, no error.
 *   - En nombres internos (sin punto, o con sufijo .local, .lan, .internal)
 *     que ademas se han comparado con resolvers publicos, la diferencia es lo
 *     esperable: los publicos no tienen esos nombres.
 */
function revisarDiferencias(result, dominio, diferencias) {
  addFinding(result, {
    severity: SEVERIDADES.INFO,
    title: 'Comparación de resolvers activada',
    detail: 'Se consultó además contra Cloudflare y Google, lo que genera tráfico hacia esos proveedores.',
    recommendation: 'Si solo querías ver los registros, desactiva la casilla para no depender de terceros ni salir a la red extra.'
  });

  if (!diferencias || !diferencias.length) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'Los tres resolvers coinciden',
      detail: `Ni el del sistema, ni Cloudflare, ni Google devuelven resultados distintos para ${dominio}.`,
      recommendation: 'No hay split-horizon en los tipos comprobados. Un nombre público resuelto igual desde dentro y desde fuera es el comportamiento normal.'
    });
    return;
  }

  const tipos = [...new Set(diferencias.map((d) => d.tipo))];
  const zonaOCorreo = tipos.filter((t) => ['MX', 'NS', 'SOA', 'TXT', 'SRV', 'CAA'].includes(t));
  const direcciones = tipos.filter((t) => ['A', 'AAAA', 'CNAME'].includes(t));
  const contra = [...new Set(diferencias.map((d) => d.contra))].join(', ');

  const esInterno = !dominio.includes('.') || /\.(local|lan|internal|home|corp|intranet)$/i.test(dominio);

  if (zonaOCorreo.length) {
    addFinding(result, {
      severity: esInterno ? SEVERIDADES.INFO : SEVERIDADES.WARN,
      title: `Los resolvers no coinciden en ${zonaOCorreo.join(', ')}`,
      detail: esInterno
        ? `${dominio} es un nombre interno y se ha comparado con resolvers públicos, que lógicamente no lo conocen. La diferencia con Cloudflare y Google es la esperada.`
        : `Para ${dominio}, el resolvedor del sistema y ${contra} devuelven registros distintos de tipo ${zonaOCorreo.join(', ')}. Eso significa que el correo o la delegación de la zona dependen de quién pregunta.`,
      recommendation: esInterno
        ? 'Para comprobar split-horizon en un nombre interno, hay que comparar contra el servidor de nombres de la empresa, no contra Cloudflare ni Google.'
        : 'Comprueba que los NS autoritativos responden igual a todos. Si solo difieren los registros de correo, revisa que no haya responders internos publicados en la zona.'
    });
  }

  if (direcciones.length) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `Las direcciones de ${dominio} no coinciden entre resolvers`,
      detail: `Los tipos ${direcciones.join(', ')} devuelven direcciones distintas según quién consulta. En la mayoría de los casos es balanceo de carga, con varias IPs y cada consulta devuelve una.`,
      recommendation: 'Para confirmarlo, repite la comparación varias veces: si van apareciendo IPs diferentes del mismo conjunto, es balanceo. Si siempre devuelve la misma distinta, entonces sí hay split-horizon.'
    });
  }
}

/** Revisa SPF y DMARC, que solo tienen sentido si hay correo. */
function revisarCorreo(result, txt, dmarc, dominio) {
  const registros = txt?.ok ? txt.valores : [];
  const textos = registros.map((t) => formatear(t));
  const tieneSpf = textos.some((t) => /^\s*v=spf1\b/i.test(t));
  const tieneDmarc = Boolean(dmarc?.ok) && dmarc.valores.some((t) => /v=DMARC1/i.test(formatear(t)));

  if (!tieneSpf) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Sin registro SPF',
      detail: `No hay ningún TXT con v=spf1 en ${dominio}, así que no se declara qué servidores pueden enviar en su nombre.`,
      recommendation: 'Añade un TXT con v=spf1. Sin él, el correo que sale con tu nombre es más propenso a que lo rechacen o a que acabe marcado como phishing.'
    });
  }

  if (!tieneDmarc) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Sin registro DMARC',
      detail: `La consulta a _dmarc.${dominio} no ha devuelto ninguna política.`,
      recommendation: `Publica un DMARC en _dmarc.${dominio}. Es lo que da visibilidad de quién intenta suplantarte y lo que evita que te lo quiten.`
    });
  }
}

/* ------------------------------------------------------------------ *
 * Utilidades
 * ------------------------------------------------------------------ */

/** Compacta una lista de valores para una celda de tabla. */
function resumirValores(valores) {
  if (!valores || !valores.length) return '—';
  return valores.map((v) => formatear(v)).join(', ');
}

/** Convierte un registro en texto legible. */
function formatear(valor) {
  if (valor == null) return '—';
  // Una lista vacia no es "nada que decir": en la tabla significa que el tipo se
  // consulto y respondio sin registros. Sin esto la celda queda en blanco y
  // parece que el tipo no se llego a preguntar.
  if (Array.isArray(valor)) return valor.length ? valor.join('') : '—';
  if (typeof valor === 'string') return valor;
  // Los TXT llegan como array de trozos que hay que ENLAZAR sin separador: un
  // registro de SPF partido en "v=spf1" y "include:_spf.google.com" debe leerse
  // "v=spf1include:_spf.google.com". Unirlos con punto lo dejaria invalido.

  // El "null MX" de la RFC 7505 es un MX de prioridad 0 con exchange vacio:
  // el dominio declara explicitamente que no recibe correo. Sin este caso la
  // celda sale como "0 ", que no dice nada y parece un registro roto.
  if (valor.exchange !== undefined) {
    if (!valor.exchange) return '0 (null MX: no recibe correo)';
    return `${valor.priority ?? '?'} ${valor.exchange}`;
  }
  if (valor.port !== undefined) return `${valor.priority ?? 0} ${valor.weight ?? 0} ${valor.port} ${valor.name ?? ''}`; // SRV
  if (valor.address !== undefined) return valor.address;
  if (valor.nsname !== undefined) return `${valor.nsname} (serial ${valor.serial})`; // SOA
  if (valor.issue !== undefined) return `${valor.critical ?? 0} issue "${valor.issue}"`; // CAA
  if (valor.name !== undefined) return valor.name; // PTR

  // DNSSEC. El orden importa: varias claves comparten campos, y la forma de
  // distinguirlas es el campo que les es propio.
  if (Buffer.isBuffer(valor.key) && valor.flags !== undefined) {
    return `${rolClave(valor.flags)} · ${nombrarAlgoritmo(valor.algorithm)} · keyTag ${valor.keyTag}`; // DNSKEY
  }
  if (Buffer.isBuffer(valor.digest)) {
    const digesto = DIGESTOS_DS[valor.digestType] || `DS tipo ${valor.digestType}`;
    return `keyTag ${valor.keyTag} · ${nombrarAlgoritmo(valor.algorithm)} · ${digesto} · ${valor.digestHex?.slice(0, 16) || valor.digest.toString('hex').slice(0, 16)}…`; // DS
  }
  if (valor.typeCovered && Buffer.isBuffer(valor.signature)) {
    return `RRSIG ${valor.typeCovered} · ${nombrarAlgoritmo(valor.algorithm)} · keyTag ${valor.keyTag} · ${valor.signersName}${valor.expira ? ` · expira ${valor.expira}` : ''}`; // RRSIG
  }
  if (Array.isArray(valor.rrtypes)) {
    if (Buffer.isBuffer(valor.nextDomain)) {
      return `NSEC3 iter ${valor.iterations} · salt ${valor.saltHex ?? '-'} · ${valor.rrtypes.join(' ')}`;
    }
    return `NSEC → ${valor.nextDomain} · ${valor.rrtypes.join(' ')}`;
  }
  if (valor.flags !== undefined && valor.iterations !== undefined && valor.salt !== undefined) {
    return `NSEC3PARAM iter ${valor.iterations} · salt ${valor.saltHex ?? '-'}`;
  }

  return String(valor);
}

/** Clave estable para comparar listas de valores entre resolvers. */
function canonico(valores) {
  if (!valores || !valores.length) return '';
  return valores
    .map((v) => (typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)))
    .sort()
    .join('|');
}

/** Resumen de una celda en la tabla de comparación. */
function resumenComparacion(valores) {
  if (!valores || !valores.length) return '—';
  if (valores.length === 1) return formatear(valores[0]);
  return `${valores.length} registros: ${formatear(valores[0])}…`;
}

/* ------------------------------------------------------------------ *
 * Comparación contra un archivo de estado esperado
 * ------------------------------------------------------------------ */

/** Estados de una fila de comparación. */
const ESTADO = {
  COINCIDE: { valor: 'Coincide', tone: 'ok' },
  DISTINTO: { valor: 'Distinto', tone: 'warn' },
  FALTA: { valor: 'Falta', tone: 'bad' },
  SIN_DATOS: { valor: 'Sin datos', tone: 'muted' }
};

/**
 * Traduce a la misma forma normalizada lo que devuelve Node, para poder
 * compararlo con lo que venía en el archivo.
 *
 * Node no devuelve los registros en el mismo formato con el que los escribe
 * Cloudflare: el MX viene como `{exchange, priority}`, el TXT como un array de
 * trozos, el NS con punto final. Sin esta capa, todo aparecería como distinto
 * y el informe sería ruido puro.
 *
 * @param {string} tipo
 * @param {any[]} valores
 * @returns {string[]}
 */
function normalizarValoresReales(tipo, valores) {
  if (!Array.isArray(valores)) return [];
  return valores.map((v) => {
    switch (tipo) {
      case 'TXT':
        return normalizarValor('TXT', Array.isArray(v) ? v.join('') : v);
      case 'MX':
        return normalizarValor('MX', v?.exchange ?? v, v?.priority ?? null);
      case 'SRV':
        return normalizarValor('SRV', `${v?.priority ?? 0} ${v?.weight ?? 0} ${v?.port ?? 0} ${v?.name ?? ''}`, v?.priority ?? null);
      case 'SOA':
        return normalizarValor(
          'SOA',
          `${v?.nsname ?? ''} ${v?.hostmaster ?? ''} ${v?.serial ?? ''} ${v?.refresh ?? ''} ${v?.retry ?? ''} ${v?.expire ?? ''} ${v?.minttl ?? ''}`
        );
      case 'CAA':
        return normalizarValor('CAA', `${v?.critical ?? 0} ${v?.issue ?? ''} "${v?.value ?? ''}"`);
      default:
        return normalizarValor(tipo, v);
    }
  }).filter(Boolean);
}

/** Tipos donde un registro sobrante suele significar algo. */
const TIPOS_SOBRANTES_RELEVANTES = ['MX', 'TXT', 'CNAME', 'SRV', 'CAA'];

/**
 * Parametros que van al Result, con el archivo reducido a su ficha.
 *
 * El `Result` viaja al HTML, al PDF, al JSON y al historial. Si el texto del
 * archivo se guardara tal cual, cada copia de la zona DNS del cliente acabaria
 * guardada en la base de datos de la herramienta. El contenido se usa en
 * memoria mientras dura la ejecucion; al Result solo van el nombre y el
 * tamano, que es lo que hace falta para saber que se comparo contra algo.
 *
 * @param {object} params
 * @returns {object}
 */
function paramsParaInforme(params) {
  const limpio = redactDeep(params);
  if (!('archivoContenido' in limpio)) return limpio;

  const contenido = String(params.archivoContenido ?? '');
  delete limpio.archivoContenido;
  limpio.archivoBytes = Buffer.byteLength(contenido, 'utf8');
  return limpio;
}

/**
 * Lee el archivo, consulta cada nombre que trae y contrasta lo esperado con lo
 * que hay.
 *
 * @param {object} result
 * @param {object} dns Módulo DNS (inyectable).
 * @param {{dominio: string|null, timeout: number, contenido: string}} opciones
 * @param {object} [log]
 */
async function compararConArchivo(result, dns, { dominio, timeout, contenido }, log) {
  const bruto = String(contenido ?? '').trim();

  if (!bruto) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Se pidió comparar con un archivo pero no se adjuntó ninguno',
      detail: 'La casilla está activa pero no llegó ningún contenido.',
      recommendation: 'Sube el archivo .txt, o desactiva la casilla si solo querías ver los registros.'
    });
    return;
  }

  const nombreArchivo = String(result.params?.archivoNombre ?? '').trim() || 'archivo.txt';
  const esperado = parsearEsperado(bruto);

  addLog(result, {
    level: 'info',
    channel: 'archivo',
    message: `Archivo "${nombreArchivo}": ${esperado.registros.length} registros esperados en ${esperado.nombres.length} nombres`
  });
  log?.info?.(`dns-checker: archivo=${nombreArchivo} registros=${esperado.registros.length} nombres=${esperado.nombres.length}`);

  if (!esperado.formato) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'No se reconoce el formato del archivo',
      detail: esperado.avisos[0] ?? 'El archivo no contiene registros legibles.',
      recommendation: 'Se admite la exportación de zona que descarga Cloudflare, o un texto con líneas "Nombre:" y "Valor:".'
    });
    return;
  }

  for (const aviso of esperado.avisos) {
    addLog(result, { level: 'warn', channel: 'archivo', message: aviso });
  }

  addSummary(result, 'Formato del archivo', esperado.formato === 'bind' ? 'Zona BIND (Cloudflare)' : 'Texto de ticket');
  addSummary(result, 'Nombres en el archivo', String(esperado.nombres.length));

  // Filtro opcional por dominio, subdominios incluidos.
  let nombres = esperado.nombres;
  let filtrado = false;
  if (dominio) {
    nombres = esperado.nombres.filter((n) => n === dominio || n.endsWith(`.${dominio}`));
    filtrado = true;
  }

  if (!nombres.length) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Ningún nombre del archivo pertenece a ese dominio',
      detail: `El archivo tiene ${esperado.nombres.length} nombres y ninguno es ${dominio} ni un subdominio suyo.`,
      recommendation: `Nombres del archivo: ${recortar(esperado.nombres.join(', '), 300)}.`
    });
    return;
  }

  if (filtrado) {
    addSummary(result, 'Nombres revisados', `${nombres.length} de ${esperado.nombres.length}`);
    addLog(result, { level: 'info', channel: 'archivo', message: `Filtro por dominio: ${nombres.length} de ${esperado.nombres.length} nombres` });
  }

  // Una consulta por nombre y tipo, que es lo que tarda: el número de
  // consultas sale del archivo, no del formulario.
  const consultas = [];
  for (const nombre of nombres) {
    for (const tipo of new Set(esperado.porNombre[nombre].map((r) => r.tipo))) {
      consultas.push({ nombre, tipo });
    }
  }

  addLog(result, { level: 'info', channel: 'dns', message: `${consultas.length} consultas DNS derivadas del archivo` });

  const registros = await dns.consultarLote(consultas, {
    concurrencia: Math.min(8, consultas.length),
    dns: { timeout, reintentos: 1 }
  });

  // --- Contraste ---
  const filas = [];
  const resumen = { coinciden: 0, distintos: 0, faltan: 0, sinDatos: 0 };
  const sobrantes = [];
  // Pares nombre+tipo que ya se han marcado como distintos. El valor real de un
  // registro distinto no está en el archivo por definición, así que sin esta
  // lista aparecería también como "sobrante" y el mismo problema se contaría
  // dos veces: una como diferencia y otra como añadido.
  const yaDistintos = new Set();

  for (const nombre of nombres) {
    const esperados = esperado.porNombre[nombre];

    for (const r of esperados) {
      const real = registros.find((x) => x.nombre === r.nombre && x.tipo === r.tipo);

      if (!real) {
        resumen.sinDatos++;
        filas.push([r.nombre, r.tipo, recortar(r.normalizado), '—', ESTADO.SIN_DATOS]);
        continue;
      }

      if (!real.ok) {
        resumen.sinDatos++;
        filas.push([r.nombre, r.tipo, recortar(r.normalizado), recortar(real.error ?? real.codigoDns ?? 'error'), ESTADO.SIN_DATOS]);
        continue;
      }

      const reales = normalizarValoresReales(r.tipo, real.valores);

      if (reales.includes(r.normalizado)) {
        resumen.coinciden++;
        filas.push([r.nombre, r.tipo, recortar(r.normalizado), recortar(r.normalizado), ESTADO.COINCIDE]);
      } else if (!reales.length) {
        // El tipo responde pero no hay ningún registro. Es distinto de "tiene
        // otro valor": aquí el registro no está publicado, y la solución es
        // crearlo, no corregirlo.
        resumen.faltan++;
        yaDistintos.add(`${nombre}|${r.tipo}`);
        filas.push([r.nombre, r.tipo, recortar(r.normalizado), 'sin registros', ESTADO.FALTA]);
      } else {
        resumen.distintos++;
        yaDistintos.add(`${nombre}|${r.tipo}`);
        filas.push([r.nombre, r.tipo, recortar(r.normalizado), recortar(reales.join(' · ') || 'sin registros'), ESTADO.DISTINTO]);
      }
    }

    // Al revés: lo que hay en DNS y no estaba en el archivo. Es lo que detecta
    // que alguien ha añadido algo por su cuenta.
    for (const tipo of new Set(esperados.map((r) => r.tipo))) {
      // Si este par ya salió como "Distinto", su valor real ya sale en la tabla
      // de diferencias. No se cuenta además como sobrante.
      if (yaDistintos.has(`${nombre}|${tipo}`)) continue;

      const real = registros.find((x) => x.nombre === nombre && x.tipo === tipo);
      if (!real?.ok || !real.valores.length) continue;

      const enArchivo = new Set(esperados.filter((r) => r.tipo === tipo).map((r) => r.normalizado));
      for (const valor of normalizarValoresReales(tipo, real.valores)) {
        if (!enArchivo.has(valor)) sobrantes.push({ nombre, tipo, valor });
      }
    }
  }

  addSection(result, {
    title: 'Comparación con el archivo',
    description: `Cada registro del archivo contra lo que responde el DNS ahora mismo. Formato detectado: ${esperado.formato === 'bind' ? 'exportación de zona BIND' : 'texto de ticket'}.`,
    kind: K.TABLA,
    columns: ['Nombre', 'Tipo', 'Esperado en el archivo', 'Encontrado en DNS', 'Estado'],
    rows: filas
  });

  if (sobrantes.length) {
    addSection(result, {
      title: 'Registros que no están en el archivo',
      description: 'Están publicados en DNS pero el archivo no los menciona. Suelen ser lo que alguien añadió sin actualizar la copia de referencia.',
      kind: K.TABLA,
      columns: ['Nombre', 'Tipo', 'Valor en DNS'],
      rows: sobrantes.map((s) => [s.nombre, s.tipo, recortar(s.valor)])
    });
  }

  addSummary(result, 'Coinciden', String(resumen.coinciden));
  if (resumen.distintos) addSummary(result, 'Distintos', String(resumen.distintos));
  if (resumen.faltan) addSummary(result, 'Faltan', String(resumen.faltan));
  if (resumen.sinDatos) addSummary(result, 'Sin datos', String(resumen.sinDatos));
  if (sobrantes.length) addSummary(result, 'Sobrantes', String(sobrantes.length));

  revisarArchivo(result, { resumen, sobrantes, nombreArchivo });
}

/** Convierte el recuento de filas en hallazgos. */
function revisarArchivo(result, { resumen, sobrantes, nombreArchivo }) {
  // `faltan` va en la suma porque, si no, seis coincidencias y un registro sin
  // publicar dan total = 6 = coinciden, y el informe cerraba diciendo que la
  // zona coincidía con el archivo. Justamente el caso que hay que avisar.
  const total = resumen.coinciden + resumen.distintos + resumen.faltan + resumen.sinDatos;

  if (total && resumen.coinciden === total && !sobrantes.length) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'La zona coincide con el archivo',
      detail: `Los ${resumen.coinciden} registros de "${nombreArchivo}" están publicados tal cual, y no hay ninguno de más en DNS.`,
      recommendation: 'Nada que corregir. Si cambiaste la zona, descarga la exportación nueva y sustituye el archivo para tener la referencia al día.'
    });
    return;
  }

  if (resumen.distintos) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: `${resumen.distintos} registro(s) con un valor distinto al del archivo`,
      detail: 'El nombre existe y responde, pero con otro valor. Puede ser un cambio legítimo que no se ha copia de seguridad, o un cambio que no hiciste.',
      recommendation: 'Mira la tabla: si el valor nuevo es el correcto, actualiza el archivo. Si no lo reconoces, revisa quién hizo el cambio antes de dar por buena la zona.'
    });
  }

  if (resumen.faltan) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: `${resumen.faltan} registro(s) del archivo no están publicados`,
      detail: 'El nombre se consulta bien pero no tiene ese registro. A diferencia de un valor distinto, aquí no hay nada: el registro simplemente no existe.',
      recommendation: 'Si debería existir, hay que crearlo. Fíjate en el nombre y el tipo de la tabla: casi siempre es un registro mal escrito o publicado en la zona equivocada.'
    });
  }

  if (resumen.sinDatos) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: `${resumen.sinDatos} registro(s) no se pudieron comprobar`,
      detail: 'La consulta no devolvió nada utilizable, así que el informe no sabe si el registro está o no. No es lo mismo que falte.',
      recommendation: 'Sube el tiempo de espera y repite. Si sigue igual, mira si el nombre tiene delegation correcta y si los servidores autoritativos responden.'
    });
  }

  const relevantes = sobrantes.filter((s) => TIPOS_SOBRANTES_RELEVANTES.includes(s.tipo));
  if (relevantes.length) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: `${relevantes.length} registro(s) de correo o nombres extra en DNS`,
      detail: `${relevantes.map((s) => `${s.nombre} ${s.tipo}`).join(', ')} están publicados y no figuran en "${nombreArchivo}". Un MX, un TXT o un CNAME de más cambia a dónde va el correo y quién resuelve el nombre.`,
      recommendation: 'Si son intencionados, añádelos al archivo. Si no, mira quién los ha puesto: es el rastro más claro de un cambio fuera de control.'
    });
  }

  const otros = sobrantes.length - relevantes.length;
  if (otros > 0) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `${otros} registro(s) de más que no son de correo`,
      detail: 'Direcciones o servidores de nombres publicados que el archivo no menciona.',
      recommendation: 'Suele ser normal si el archivo se descargó hace tiempo o si hay una CDN por delante. Comprueba que no haya ninguna IP que no reconozcas.'
    });
  }
}

module.exports = {
  id: ID,
  titulo: 'Comprobador de DNS',
  descripcion: 'Consulta los registros de un dominio y avisa de lo que está mal: SPF, DMARC, IPv6, alias, DNSSEC o discrepancias entre resolvers.',
  sinRed: false,
  icon: '🌐',
  campos: CAMPOS,
  ejecutar,
  // Expuestos para poder probarlos sin red.
  _internas: { normalizarDominio, normalizarIp, parseTipos, resumirValores, formatear, revisar, TIPOS_SOPORTADOS, TIPOS_POR_DEFECTO, TIPOS_DNSSEC, nombrarAlgoritmo, rolClave, RESOLVER_A_COMPARAR }
};
