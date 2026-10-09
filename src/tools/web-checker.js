/**
 * tools/web-checker.js — ¿Está esta web en pie?
 *
 * HERRAMIENTA NUEVA. Todas las que había hasta ahora miran un dato: un registro
 * DNS, un certificado, una lista negra. Esta hace una pregunta de las que la
 * gente se hace de verdad, y la respuesta es un dato que no se puede ver de una
 * vez mirando por separado: el sitio responde o no.
 *
 * MODELADO SOBRE WebsitePlanet DOWN OR NOT, no copiado de él. Se miró porque hace
 * exactamente esto, y la lección es que su simplicidad esconde una decisión de
 * fondo: lo que la gente busca es una frase, no una tabla de veinte filas. Aquí
 * el titular (`headline`) lleva la frase, las tarjetas llevan los hechos y el
 * diagnóstico va debajo.
 *
 * LO QUE ESTE INFORME NO DICE, Y POR QUÉ
 *
 * Se comprueba desde este equipo, con su conexión, a su hora. Eso es una muestra
 * de una. Si aquí responde y en casa no, la respuesta honesta es que el sitio
 * está en pie y que hay un problema por medio, no que esté caído. Por eso el
 * informe nunca afirma disponibilidad global: el titular lleva el sujeto y el
 * verbo, y quien lo lee pone el "desde este equipo" que corresponde. Afirmar que
 * una web está caída para todo el mundo desde una sola conexión es la forma más
 * rápida de mentir sin querer.
 *
 * ORDEN DE LAS COMPROBACIONES, Y POR QUÉ ESE
 *
 * 1. El sondeo HTTP, primero y sin condiciones. Es la pregunta del usuario.
 * 2. DNS. Si falló el sondeo, casi siempre la causa está aquí, y es lo único
 *    que lo explica.
 * 3. TLS, solo si el destino es https. Contra un sitio http no hay certificado
 *    que auditar, y decir "no tiene certificado" sería inventar un problema.
 * 4. RDAP. La caducidad del dominio es la avería más silenciosa: un nombre
 *    puede resolver y servir durante meses después de dejar de pagarse.
 *
 * LO QUE SE DEJA FUERA A PROPÓSITO
 *
 * - Parking y "coming soon": aviso, y solo con evidencia en el título. Un sitio
 *   que devuelve 200 con un formulario de captación no está caído.
 * - Comparación contra resolvers públicos: existe, apagada por defecto, porque
 *   son consultas a terceros que hay que autorizar (igual que en `dns-checker`).
 * - Reputación, listas negras, PTR: hay herramientas para eso. Metidas aquí
 *   inflarían el informe con datos que no responden a la pregunta.
 *
 * @module tools/web-checker
 */

'use strict';

const {
  createResult, setHeadline, addSection, addSummary, addFinding, addLog,
  finalize, failWith, SEVERIDADES, SECCION_KINDS: K, ESTADOS
} = require('../core/result');
const { NetlabError, CODES } = require('../core/errors');
const { redactDeep } = require('../core/redact');
const web = require('../core/net/web');
const dnsNet = require('../core/net/dns');
const rdapNet = require('../core/net/rdap');
const tlsNet = require('../core/net/tls');
const { normalizarTimeout } = require('../core/dominio');

const ID = 'web-checker';

/**
 * Campos del formulario.
 *
 * Solo el primero se ve. El resto va detrás de `avanzado`: un campo que no hace
 * falta para la pregunta esconde la pregunta, porque si el formulario enseña
 * cinco opciones, quien llega ya parte de que hay trabajo de por medio.
 */
const CAMPOS = [
  {
    name: 'url',
    label: 'Dirección del sitio',
    type: 'text',
    required: true,
    placeholder: 'ejemplo.com',
    help: 'El dominio o la URL completa. Se prueba por https; si el sitio no habla https, el informe lo dice.'
  },
  {
    name: 'avanzado',
    label: 'Mostrar opciones avanzadas',
    type: 'checkbox',
    required: false,
    default: false,
    help: 'Tiempo de espera, red interna, caducidad del dominio y comparación de resolvers.'
  },
  {
    name: 'timeout',
    label: 'Tiempo de espera (ms)',
    type: 'number',
    required: false,
    default: 8000,
    min: 1000,
    max: 30000,
    shownWhen: 'avanzado',
    help: 'Por petición. Con redirecciones se van sumando: un sitio que encadena cinco saltos puede consumir ese tiempo cinco veces.'
  },
  {
    name: 'permitirRedPrivada',
    label: 'Permitir direcciones internas',
    type: 'checkbox',
    required: false,
    default: false,
    shownWhen: 'avanzado',
    help: 'Solo para revisar un sitio de tu propia red. Apagado, el módulo no se conecta a direcciones privadas ni a la red local: sin esto, el servidor haría peticiones a las páginas internas de quien lo usa y enseñaría el resultado en el navegador. El enlace local y las direcciones de metadatos de la nube siguen bloqueados aunque actives esta casilla.'
  },
  {
    name: 'consultarCaducidad',
    label: 'Consultar la caducidad del dominio (RDAP)',
    type: 'checkbox',
    required: false,
    default: true,
    shownWhen: 'avanzado',
    help: 'Un dominio sin pagar puede seguir resolviendo y sirviendo durante meses. Es la causa más silenciosa y la única que el sondeo por sí solo no ve.'
  },
  {
    name: 'compararResolvers',
    label: 'Comparar con Cloudflare y Google',
    type: 'checkbox',
    required: false,
    default: false,
    shownWhen: 'avanzado',
    help: 'Repite la consulta de direcciones contra 1.1.1.1 y 8.8.8.8 y avisa si no coinciden con las del sistema. Cuando difieren, la respuesta depende de quién pregunta, y hay sitios que solo se ven desde dentro de una red concreta.'
  },
  {
    name: 'compartir',
    label: 'Crear enlace público temporal',
    type: 'checkbox',
    required: false,
    default: false,
    shownWhen: 'avanzado',
    help: 'Genera un enlace compartible (ej. /r/abc123) que cualquiera puede abrir para ver el informe sin autenticarse. Expira en 7 días por defecto (máx. 90).'
  },
  {
    name: 'ttlDiasCompartir',
    label: 'Días de validez del enlace',
    type: 'number',
    required: false,
    default: 7,
    min: 1,
    max: 90,
    shownWhen: 'compartir',
    help: 'Cuántos días estará activo el enlace compartido. Mínimo 1, máximo 90.'
  }
];

/**
 * Punto de entrada.
 *
 * @param {object} params Entrada del formulario.
 * @param {object} [ctx] Contexto. `ctx.web`, `ctx.dns`, `ctx.rdap` y `ctx.tls`
 *   permiten inyectar dobles; sin ellos se sale a la red de verdad.
 * @returns {Promise<object>} Result completo.
 */
async function ejecutar(params = {}, ctx = {}) {
  const inicio = new Date();
  const log = ctx.log || null;
  const bruto = String(params.url ?? '').trim();

  // El objetivo se lee sin limpiar, a propósito: si la URL va mal escrita, el
  // informe tiene que decir qué se escribió, porque eso es lo que hay que
  // corregir. La normalización va después de crear el Result.
  const result = createResult({
    tool: ID,
    toolTitle: 'Comprobador de sitios web',
    target: bruto,
    params: redactDeep(params)
  });

  try {
    if (!bruto) {
      throw new NetlabError(CODES.ENTRADA_VACIA, 'No se indicó ninguna dirección.', {
        remediation: 'Escribe el sitio que quieres comprobar, por ejemplo ejemplo.com.'
      });
    }

    const opciones = leerOpciones(params);
    addLog(result, { level: 'info', channel: 'entrada', message: `Comprobando ${bruto}` });
    log?.info?.(`web-checker: ${bruto} timeout=${opciones.timeoutMs} privada=${opciones.permitirPrivadas}`);

const url = web.normalizarUrl(bruto);
    const sondeo = await sondear(url, opciones, ctx);

    // Un sondeo cortado por la guardia SSRF no es un sitio que no responde: es
    // una comprobación que no se ha hecho. Por eso sale como `error`.
    if (sondeo.bloqueado) {
      addLog(result, { level: 'error', channel: 'http', message: sondeo.error.message });
      log?.warn?.(`web-checker bloqueado: ${sondeo.error.message}`);
      return failWith(finalize(result, inicio), sondeo.error);
    }

    const dns = await consultarDns(result, url.hostname, opciones, ctx);
    pintarHechos(result, url, sondeo.respuesta, dns);

    const tls = url.protocol === 'https:' ? await consultarTls(result, url.hostname, opciones, ctx) : null;
    const registro = await consultarRegistro(result, url.hostname, opciones, ctx);

    // Las cabeceras solo existen si hubo respuesta. Sin respuesta no se analiza
    // nada: inventar "falta HSTS" sobre un sitio que no contestó es ruido.
    const cabeceras = !sondeo.respuesta?.error
      ? analizarCabeceras(sondeo.respuesta?.cabeceras, { https: url.protocol === 'https:' })
      : null;
    const protocolo = determinarProtocolo(tls, dns.https);
    const conexion = await calificarConexion(tls, cabeceras, url, opciones, ctx);

    if (opciones.compararResolvers) await compararResolvers(result, url.hostname, opciones, ctx);

    pintarDiagnostico(result, { url, r: sondeo.respuesta, dns, tls, registro, cabeceras, protocolo, conexion });
    revisar(result, { url, r: sondeo.respuesta, dns, tls, registro, cabeceras, protocolo, conexion });

    return finalize(result, inicio);
  } catch (error) {
    addLog(result, { level: 'error', channel: 'error', message: error.message });
    log?.error?.(`web-checker fallo: ${error.message}`);
    return failWith(finalize(result, inicio), error instanceof NetlabError ? error : new NetlabError(CODES.INTERNO, error.message));
  }
}

/* ------------------------------------------------------------------ *
 * Entrada
 * ------------------------------------------------------------------ */

/**
 * Lee las opciones con sus valores por defecto.
 *
 * Los valores por defecto están aquí y no solo en `CAMPOS`: la CLI y las
 * pruebas llaman a `ejecutar` sin pasar por el formulario del servidor, y una
 * opción que dependiera de que otro campo la rellene sería falsa en cuanto se
 * llama directamente.
 */
function leerOpciones(params) {
  return {
    timeoutMs: normalizarTimeout(params.timeout, { defecto: 8000, min: 1000, max: 30000 }),
    permitirPrivadas: params.permitirRedPrivada === true,
    consultarCaducidad: params.consultarCaducidad !== false,
    compararResolvers: params.compararResolvers === true,
    compartir: params.compartir === true,
    ttlDiasCompartir: params.ttlDiasCompartir ? Math.min(Math.max(1, Math.trunc(Number(params.ttlDiasCompartir))), 90) : 7
  };
}

/* ------------------------------------------------------------------ *
 * Sondeo
 * ------------------------------------------------------------------ */

/**
 * El sondeo HTTP, en una forma que esta herramienta sepa pintar.
 *
 * Un error de red NO se relanza: "no se pudo contactar con el sitio" es un
 * resultado, y el más importante cuando es lo que ha pasado. Lo que sí se
 * distingue es el corte por seguridad, porque ese no dice nada del sitio: dice
 * que nadie ha mirado.
 *
 * @returns {Promise<{respuesta: object, error: NetlabError|null, bloqueado: boolean}>}
 */
async function sondear(url, opciones, ctx) {
  const sondearReal = ctx.web?.sondear || web.sondear;
  try {
    const respuesta = await sondearReal(url, {
      timeoutMs: opciones.timeoutMs,
      permitirPrivadas: opciones.permitirPrivadas,
      fetchImpl: ctx.fetchImpl,
      resolver: ctx.resolver
    });
    return { respuesta, error: null, bloqueado: false };
  } catch (error) {
    // Al envolver se copian `code`, `details` y `remediation`. Perderlos sería
    // la forma más fácil de tener un informe que dice "caído" para un destino
    // que se canceló por seguridad: el corte SSRF es justo el dato que decide
    // entre `fail` y `error`, y un envoltorio que lo tira lo convierte en `fail`.
    const envuelto =
      error instanceof NetlabError
        ? error
        : new NetlabError(error.code || CODES.RED, error.message, {
            remediation: error.remediation,
            details: error.details
          });
    if (esBloqueoDeSeguridad(envuelto)) return { respuesta: null, error: envuelto, bloqueado: true };
    return { respuesta: { error: envuelto }, error: envuelto, bloqueado: false };
  }
}

/**
 * ¿Este error es el corte por seguridad y no un fallo de red?
 *
 * Se mira `details.ssrf`, no el texto del mensaje: quien decide entre "está
 * caído" y "no se ha comprobado" no puede depender de una frase que puede
 * cambiar sin que nadie se entere.
 */
function esBloqueoDeSeguridad(error) {
  return error?.details?.ssrf === true;
}

/* ------------------------------------------------------------------ *
 * Comprobaciones secundarias
 * ------------------------------------------------------------------ */

/**
 * Direcciones del nombre, por los dos métodos.
 *
 * No se consulta CNAME: el sondeo ya demuestra que el nombre acaba en algo que
 * responde, y encadenar el alias a mano solo duplicaría el dato dando la
 * impresión de que el módulo sabe seguirlo.
 */
async function consultarDns(result, host, opciones, ctx) {
  // Una dirección literal no tiene nombre que resolver. Preguntarlo igualmente
  // devolvería un NXDOMAIN que no es un problema del sitio, y el informe
  // acabaría diciendo "no resuelve a ninguna dirección" de algo que sí responde.
  if (esIpLiteral(host)) {
    addLog(result, { level: 'info', channel: 'dns', message: `${host} es una dirección, no hay nombre que resolver` });
    return { literal: true, resuelve: true, direcciones: [host], a: null, aaaa: null, https: null };
  }

  const dns = ctx.dns || dnsNet;
  const registros = await dns.consultarLote(
    [
      { nombre: host, tipo: 'A' },
      { nombre: host, tipo: 'AAAA' },
      // El registro HTTPS dice qué versiones de HTTP anuncia el servidor (h3,
      // h2). Sin él, HTTP/3 no se puede ni sospechar: se negocia en otro
      // transporte y no aparece en el handshake TLS clásico.
      { nombre: host, tipo: 'HTTPS' }
    ],
    { concurrencia: 3, dns: { timeout: opciones.timeoutMs, reintentos: 1 } }
  );

  const salida = {
    literal: false,
    a: registros.find((r) => r.tipo === 'A') || null,
    aaaa: registros.find((r) => r.tipo === 'AAAA') || null,
    https: registros.find((r) => r.tipo === 'HTTPS') || null
  };
  salida.direcciones = [...(salida.a?.valores || []), ...(salida.aaaa?.valores || [])];
  salida.resuelve = salida.direcciones.length > 0;

  addLog(result, {
    level: salida.resuelve ? 'info' : 'warn',
    channel: 'dns',
    message: `${host}: ${salida.resuelve ? salida.direcciones.join(', ') : 'no resuelve a ninguna dirección'}`
  });

  return salida;
}

/**
 * Certificado del servidor. Nunca tumba el informe: es un dato, no el veredicto.
 *
 * Se intenta primero EXIGIENDO el certificado. Es la forma de saber si un
 * navegador lo aceptaría, sin depender de que el socket con
 * `rejectUnauthorized:false` siga calculando `authorized`. Si esa conexión sale,
 * el certificado es válido y no hay nada que recountar: una sola vuelta.
 *
 * Si falla, se repite sin exigirlo para poder LEER el certificado y decir por qué
 * no valía. Dos conexiones solo en el caso que hay algo que contar, que es justo
 * cuando una de más se nota menos.
 */
async function consultarTls(result, host, opciones, ctx) {
  const tls = ctx.tls || tlsNet;
  const socketCerrar = (socket) => {
    try {
      socket?.destroy?.();
    } catch {
      /* un socket ya cerrado no es un fallo del informe */
    }
  };

  const ALPN = ['h2', 'http/1.1'];

  try {
    const { socket, certificado, alpn } = await tls.conectar({
      host,
      port: 443,
      verificar: true,
      timeout: opciones.timeoutMs,
      alpnProtocols: ALPN
    });
    socketCerrar(socket);
    addLog(result, { level: 'info', channel: 'tls', message: `Certificado de ${host} valido` });
    return { certificado, verificado: true, motivoRechazo: null, error: null, auditar: tls.auditarCertificado, alpn: alpn || certificado?.alpn || null };
  } catch (error) {
    addLog(result, { level: 'info', channel: 'tls', message: `Certificado de ${host} no validado: ${error.message}` });
  }

  try {
    const { socket, certificado, avisos, alpn } = await tls.conectar({
      host,
      port: 443,
      verificar: false,
      timeout: opciones.timeoutMs,
      alpnProtocols: ALPN
    });
    socketCerrar(socket);
    // `avisos` se descarta a propósito: los que `conectar` añade sin
    // verificación hablan de cómo ha conectado ESTA herramienta, no del sitio.
    // Mostrarlos sería contarle al usuario que su web tiene un problema que en
    // realidad tenemos nosotros.
    void avisos;
    return {
      certificado,
      verificado: false,
      motivoRechazo: certificado?.motivoRechazo || null,
      error: null,
      auditar: tls.auditarCertificado,
      alpn: alpn || certificado?.alpn || null
    };
  } catch (error) {
    addLog(result, { level: 'warn', channel: 'tls', message: `No se pudo leer el certificado: ${error.message}` });
    return { certificado: null, verificado: null, motivoRechazo: null, error: error.message, auditar: tls.auditarCertificado };
  }
}

/**
 * Caducidad del dominio por RDAP.
 *
 * Devuelve `{aplica: false}` cuando el destino es una IP literal: no hay
 * dominio que consultar, y se dice en el informe en lugar de dejar un hueco que
 * se lee como "no se ha podido mirar".
 */
async function consultarRegistro(result, host, opciones, ctx) {
  if (!opciones.consultarCaducidad) return { aplica: false, motivo: 'desactivado' };
  if (esIpLiteral(host)) return { aplica: false, motivo: 'El destino es una dirección IP, no un nombre de dominio.' };

  const rdap = ctx.rdap || rdapNet;
  try {
    const datos = await rdap.consultarDominio(host, { fetchImpl: ctx.fetchImpl });
    addLog(result, {
      level: 'info',
      channel: 'rdap',
      message: `Registro de ${host}: ${datos.disponible ? 'encontrado' : datos.motivo}`
    });
    return { aplica: true, datos };
  } catch (error) {
    addLog(result, { level: 'warn', channel: 'rdap', message: `No se pudo consultar el registro: ${error.message}` });
    return { aplica: true, datos: null, error: error.message };
  }
}

/** ¿Es el destino una dirección y no un nombre? */
function esIpLiteral(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

/**
 * Compara la resolución del sistema con 1.1.1.1 y 8.8.8.8.
 *
 * Solo si el usuario lo pide, por lo dicho al principio del archivo. La
 * diferencia importa cuando el sitio responde para unos y no para otros: eso
 * no es una caída, es una configuración que cambia por quién pregunta.
 */
async function compararResolvers(result, host, opciones, ctx) {
  const dns = ctx.dns || dnsNet;
  const externos = [
    { nombre: 'Cloudflare', servers: ['1.1.1.1'] },
    { nombre: 'Google', servers: ['8.8.8.8'] }
  ];

  const consulta = (servidor) => dns.consultar(host, 'A', { servers: servidor, timeout: opciones.timeoutMs, reintentos: 1 });

  const delSistema = (await consulta(undefined)).valores || [];
  const filas = [];

  for (const externo of externos) {
    const propias = (await consulta(externo.servers)).valores || [];
    const iguales = canonico(propias) === canonico(delSistema);
    filas.push({ nombre: externo.nombre, aqui: delSistema, alli: propias, iguales });
  }

  addLog(result, { level: 'info', channel: 'comparar', message: `Resolución comparada con ${externos.length} resolvers` });

  addSection(result, {
    title: 'La dirección depende de quién pregunta',
    description:
      'Cuando los resolvers públicos no coinciden con los de este equipo, el sitio se ve desde unos sitios y desde otros no. Suele ser una configuración de red interna, no una caída.',
    kind: K.TABLA,
    columns: ['Resolvedor', 'Este equipo', 'El otro', 'Veredicto'],
    anchoColumnas: [16, 28, 28, 12],
    rows: filas.map((f) => [
      f.nombre,
      f.aqui.join(', ') || 'Sin respuesta',
      f.alli.join(', ') || 'Sin respuesta',
      f.iguales ? { valor: 'Igual', tone: 'ok' } : { valor: 'Difiere', tone: 'warn' }
    ])
  });

  const diferencias = filas.filter((f) => !f.iguales);
  if (diferencias.length) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'El nombre resuelve a direcciones distintas según el resolvedor',
      detail: diferencias.map((f) => `${f.nombre}: ${f.alli.join(', ') || 'sin respuesta'}`).join(' · '),
      recommendation:
        'Si el sitio te funciona y a otros no, esta es la explicación más probable. Un resolvedor interno puede estar repartiendo un tráfico a un servidor que no es el de producción, o al revés.'
    });
  }

  return filas;
}

/**
 * Lee las cabeceras de seguridad de la respuesta y las traduce a una tabla y a
 * hallazgos.
 *
 * Es una función PURA para que la tabla y los hallazgos no puedan discrepar: lo
 * que se enseña y lo que se avisa salen del mismo cálculo. Un informe que lista
 * "Content-Security-Policy: ausente" y no lo cuenta en el diagnóstico (o al
 * revés) hace dudar de todo lo demás.
 *
 * La severidad no es la misma para todas: sin HSTS o sin CSP el sitio funciona,
 * pero pierde defensas que un tercero puede aprovechar; sin `Referrer-Policy`
 * solo se filtra un poco más de contexto. Tratar las seis igual convertiría el
 * informe en una lista de deberes en la que nada destaca.
 *
 * @returns {{filas: Array, hallazgos: Array, hsts: boolean}}
 */
function analizarCabeceras(cabeceras = {}, { https } = {}) {
  const c = {};
  for (const [clave, valor] of Object.entries(cabeceras || {})) {
    c[String(clave).toLowerCase()] = Array.isArray(valor) ? valor.join(', ') : valor;
  }

  const filas = [];
  const hallazgos = [];

  const hsts = c['strict-transport-security'] || null;
  const csp = c['content-security-policy'] || null;
  const xcto = c['x-content-type-options'] || null;
  const xfo = c['x-frame-options'] || null;
  const referrer = c['referrer-policy'] || null;
  const permisos = c['permissions-policy'] || null;

  const fila = (nombre, valor, presente) => {
    filas.push([nombre, { valor: presente ? 'Presente' : 'Ausente', tone: presente ? 'ok' : 'warn' }, valor || '—']);
  };

  // HSTS solo tiene sentido sobre https: en una respuesta http la cabecera se
  // ignora por definición y avisar de su ausencia sería inventar un problema.
  if (https) {
    fila('Strict-Transport-Security', hsts, Boolean(hsts));
    if (!hsts) {
      hallazgos.push({
        severity: SEVERIDADES.WARN,
        title: 'El sitio no fuerza HTTPS en las visitas posteriores (sin HSTS)',
        detail: 'No envía la cabecera Strict-Transport-Security. Sin ella, la primera visita a http:// sigue siendo interceptable y el navegador no recuerda exigir https las siguientes veces.',
        recommendation: "Añade `Strict-Transport-Security: max-age=63072000; includeSubDomains` cuando el certificado y las redirecciones estén listos. Empieza con un max-age bajo y súbelo."
      });
    } else {
      const maxAge = Number((hsts.match(/max-age\s*=\s*(\d+)/i) || [])[1]);
      if (Number.isFinite(maxAge) && maxAge < 15552000) {
        hallazgos.push({
          severity: SEVERIDADES.INFO,
          title: 'La política HSTS caduca pronto',
          detail: `El max-age es de ${maxAge} segundos (menos de 180 días). Con valores bajos, el navegador deja de exigir https entre visitas.`,
          recommendation: 'Súbelo a 31536000 (un año) cuando todo el sitio funcione por https, incluidos los subdominios.'
        });
      }
      if (!/includeSubDomains/i.test(hsts)) {
        hallazgos.push({
          severity: SEVERIDADES.INFO,
          title: 'HSTS no cubre los subdominios',
          detail: 'La cabecera incluye max-age, pero no `includeSubDomains`: un subdominio puede seguir sirviéndose por http.',
          recommendation: 'Añade `includeSubDomains` si todos los subdominios tienen certificado y hablan https.'
        });
      }
    }
  }

  fila('Content-Security-Policy', csp, Boolean(csp));
  if (!csp) {
    hallazgos.push({
      severity: SEVERIDADES.WARN,
      title: 'El sitio no define una política de seguridad de contenido (CSP)',
      detail: 'Sin Content-Security-Policy, el navegador ejecuta cualquier script que llegue a la página. Es la defensa principal contra el código inyectado.',
      recommendation: 'Empieza con `Content-Security-Policy: default-src \'self\'` en modo informe para ver qué se rompe, y ve abriendo lo que necesites.'
    });
  } else if (/unsafe-inline|unsafe-eval/i.test(csp)) {
    hallazgos.push({
      severity: SEVERIDADES.WARN,
      title: 'La CSP permite código incrustado (unsafe-inline o unsafe-eval)',
      detail: 'La política existe, pero `unsafe-inline`/`unsafe-eval` dejan pasar el script incrustado en el HTML, que es justo el vehículo del XSS.',
      recommendation: 'Sustituye el script incrustado por un fichero propio y usa nonces o hashes. Quita `unsafe-inline`/`unsafe-eval` cuando lo hayas hecho.'
    });
  }

  const nosniff = /nosniff/i.test(xcto || '');
  fila('X-Content-Type-Options', xcto, nosniff);
  if (!nosniff) {
    hallazgos.push({
      severity: SEVERIDADES.WARN,
      title: 'Falta X-Content-Type-Options: nosniff',
      detail: 'Sin esta cabecera, el navegador puede adivinar el tipo de un fichero por su contenido y tratar como script algo que no lo es.',
      recommendation: 'Añade `X-Content-Type-Options: nosniff`. No rompe nada y quita una vía clásica de ataque.'
    });
  }

  const protegido = Boolean(xfo) || /frame-ancestors/i.test(csp || '');
  fila('X-Frame-Options / frame-ancestors', xfo || (/frame-ancestors/i.test(csp || '') ? 'frame-ancestors' : null), protegido);
  if (!protegido) {
    hallazgos.push({
      severity: SEVERIDADES.WARN,
      title: 'El sitio se puede incrustar en otra página (sin protección de framing)',
      detail: 'No hay X-Frame-Options ni `frame-ancestors` en la CSP. Otra web puede meter esta dentro de un iframe y superponer botones encima (clickjacking).',
      recommendation: "Añade `X-Frame-Options: DENY` (o SAMEORIGIN) o, mejor, `frame-ancestors 'none'` dentro de la CSP."
    });
  }

  fila('Referrer-Policy', referrer, Boolean(referrer));
  if (!referrer) {
    hallazgos.push({
      severity: SEVERIDADES.INFO,
      title: 'No hay Referrer-Policy',
      detail: 'Sin ella, el navegador manda la URL completa como referer a los terceros a los que enlaza la página.',
      recommendation: "Añade `Referrer-Policy: strict-origin-when-cross-origin`. Es una línea y evita filtrar rutas internas."
    });
  }

  fila('Permissions-Policy', permisos, Boolean(permisos));
  if (!permisos) {
    hallazgos.push({
      severity: SEVERIDADES.INFO,
      title: 'No hay Permissions-Policy',
      detail: 'La página no declara qué funciones del navegador (cámara, ubicación, micrófono) pueden usar ella y sus iframes.',
      recommendation: "Añade `Permissions-Policy` apagando lo que no uses, por ejemplo `geolocation=(), camera=(), microphone=()`."
    });
  }

  // Versión del servidor: no es una defensa que falte, es una pista que se
  // regala. `nginx` a secas no dice nada; `nginx/1.25.3` sí.
  const servidor = String(c.server || '');
  if (xPoweredByPeligroso(c) || /\/\d/.test(servidor)) {
    hallazgos.push({
      severity: SEVERIDADES.INFO,
      title: 'El servidor publica su versión',
      detail: `La respuesta incluye ${c['x-powered-by'] ? `X-Powered-By: ${c['x-powered-by']}` : `Server: ${servidor}`}. Eso le dice a quien busca a qué versión concreta atacar.`,
      recommendation: 'Oculta la versión: en nginx, `server_tokens off`; en Apache, `ServerTokens Prod`; y quita X-Powered-By del framework.'
    });
  }

  return { filas, hallazgos, hsts: Boolean(hsts) };
}

/** El framework se delata con X-Powered-By: eso es información de más. */
function xPoweredByPeligroso(c) {
  return Boolean(c['x-powered-by']);
}

/**
 * Qué versiones de HTTP anuncia el sitio, cruzando lo que dice el handshake TLS
 * con lo que publica el registro HTTPS de DNS.
 *
 * Son dos fuentes a propósito: el ALPN de TLS solo puede ver h2 y http/1.1,
 * porque HTTP/3 va sobre QUIC y no pasa por ahí. El registro HTTPS es el único
 * sitio donde el servidor declara h3 de antemano.
 *
 * @returns {{alpnTls:string|null, alpnDns:string[], h2:boolean, h3:boolean, conocido:boolean}}
 */
function determinarProtocolo(tls, https) {
  const alpnTls = tls?.alpn || tls?.certificado?.alpn || null;
  const params = (https?.ok && https.valores?.[0]?.params) || [];
  const parametroAlpn = params.find((p) => p.key === 1)?.valor;
  const alpnDns = Array.isArray(parametroAlpn) ? parametroAlpn : [];
  return {
    alpnTls,
    alpnDns,
    h2: alpnTls === 'h2' || alpnDns.includes('h2'),
    h3: alpnDns.includes('h3'),
    conocido: Boolean(alpnTls) || alpnDns.length > 0
  };
}

/**
 * Nota TLS del sitio, reutilizando el calificador de `tls-checker`.
 *
 * Solo se intenta si el módulo inyectado sabe sondear protocolos y calificar.
 * Los dobles de las pruebas no lo hacen y tampoco pasa nada: la sección que la
 * pinta solo aparece cuando hay algo medido que enseñar.
 */
async function calificarConexion(tls, cabeceras, url, opciones, ctx) {
  if (url.protocol !== 'https:' || !tls || tls.error || !tls.certificado) return null;
  const tlsMod = ctx.tls || tlsNet;
  if (typeof tlsMod.sondearProtocolos !== 'function' || typeof tlsMod.calcularNota !== 'function') return null;

  const host = url.hostname;
  try {
    const protocolos = await tlsMod.sondearProtocolos({ host, port: 443, timeout: opciones.timeoutMs });
    const certificado = tls.certificado;
    const nota = tlsMod.calcularNota({
      protocoloNegociado: certificado.protocolo,
      protocolos,
      certificado,
      cifradoDebil: typeof tlsMod.esCifradoDebil === 'function' ? tlsMod.esCifradoDebil(certificado.cifrado) : false,
      forwardSecrecy: typeof tlsMod.tieneForwardSecrecy === 'function' ? tlsMod.tieneForwardSecrecy(certificado.cifrado, certificado.protocolo) : true,
      ocspStapled: certificado.ocspStapled ?? null,
      hsts: cabeceras ? { presente: cabeceras.hsts } : null
    });
    return { protocolos, nota };
  } catch (error) {
    addLogSafe(ctx, `No se pudo calificar la conexión: ${error.message}`);
    return null;
  }
}

/** Log opcional: el contexto puede no traerlo. */
function addLogSafe(ctx, mensaje) {
  ctx?.log?.warn?.(`web-checker: ${mensaje}`);
}

/* ------------------------------------------------------------------ *
 * Presentación
 * ------------------------------------------------------------------ */

/**
 * Las tarjetas de arriba: lo que se mira sin leer.
 *
 * Cuando no hubo conexión no se inventan las que faltan. Poner "Código: —" en
 * un sitio al que no se pudo llegar deja vacío justo el dato más importante del
 * informe, y un hueco sin explicación se lee como un fallo del módulo.
 */
function pintarHechos(result, url, r, dns) {
  if (r.error) {
    addSummary(result, 'Resultado', 'Sin conexión', 'bad');
    addSummary(result, 'Motivo', r.error.code === CODES.TIMEOUT ? 'Tiempo agotado' : 'Error de red', 'bad');
    addSummary(result, 'URL', url.toString());
    return;
  }

  const direcciones = dns.direcciones.length;
  const extra = direcciones > 2 ? ` (+${direcciones - 2})` : '';

  addSummary(result, 'Código', String(r.estado), tonoEstado(r.estado));
  addSummary(result, 'Tiempo', r.ttfbMs == null ? '—' : `${r.ttfbMs} ms`, r.ttfbMs > 2000 ? 'warn' : 'neutral');
  // Se enseña la dirección del SONDEO, no la cabecera `x-served-by` que algunos
  // servidores publican: esa es una pista, y una tarjeta con una pista es peor
  // que una tarjeta con la dirección de verdad.
  addSummary(
    result,
    'IP',
    dns.direcciones.length ? `${dns.direcciones.slice(0, 2).join(', ')}${extra}` : '—'
  );
  addSummary(result, 'URL final', r.urlFinal || url.toString());
}

/** El color del código. Un 4xx no es un sitio roto: es una ruta que no se sirve. */
function tonoEstado(estado) {
  if (estado >= 200 && estado < 300) return 'ok';
  if (estado >= 300 && estado < 400) return 'neutral';
  if (estado >= 400 && estado < 500) return 'warn';
  return 'bad';
}

/** El bloque de debajo: por qué pasó esto. */
function pintarDiagnostico(result, { url, r, dns, tls, registro, cabeceras, protocolo, conexion }) {
  const fallo = Boolean(r.error);

  addSection(result, {
    title: 'Qué ha pasado',
    kind: K.PARES,
    items: [
      ['URL pedida', url.toString()],
      ['URL final', fallo ? '—' : r.urlFinal],
      ['Código', fallo ? 'Sin respuesta' : String(r.estado)],
      ['Título de la página', fallo ? '—' : r.titulo || 'Sin título'],
      ['Método', fallo ? '—' : r.metodo],
      ['Redirecciones', fallo ? '—' : String(Math.max(0, (r.cadena?.length || 1) - 1))],
      ['Servidor', fallo ? '—' : r.cabeceras?.server || 'Sin dato']
    ]
  });

  if (!fallo && r.cadena?.length > 1) {
    addSection(result, {
      title: 'Cadena de redirecciones',
      description:
        'Cada salto se vuelve a comprobar antes de seguirlo. Por eso una redirección a una dirección interna se corta aquí, y no al final del recorrido.',
      kind: K.TABLA,
      columns: ['#', 'URL', 'Código'],
      rows: r.cadena.map((salto, i) => [String(i + 1), salto.url, String(salto.estado)])
    });
  }

  addSection(result, {
    title: 'Direcciones del nombre',
    kind: K.PARES,
    items: dns.literal
      ? [
          ['Resuelve', 'No hay nombre que resolver: el destino ya es una dirección'],
          ['Destino', dns.direcciones.join(', ')]
        ]
      : [
          ['Resuelve', dns.resuelve ? `Sí — ${dns.direcciones.join(', ')}` : 'No resuelve', dns.resuelve ? 'ok' : 'bad'],
          ['IPv4', textoValores(dns.a)],
          ['IPv6', textoValores(dns.aaaa)]
        ]
  });

  if (tls) {
    const c = tls.certificado;
    const estadoCert =
      tls.error
        ? 'No se pudo leer'
        : tls.verificado
          ? 'Válido'
          : 'No lo acepta un navegador';
    addSection(result, {
      title: 'Certificado',
      kind: K.PARES,
      items: [
        ['Estado', estadoCert, tls.error ? 'bad' : tls.verificado ? 'ok' : 'bad'],
        ['Para', c?.sujeto || '—'],
        ['Emitido por', c?.emisor || '—'],
        ['Caduca', c?.validoHasta ? `${c.validoHasta}${c.diasRestantes != null ? ` (en ${c.diasRestantes} días)` : ''}` : '—'],
        ['Protocolo', c?.protocolo || '—'],
        ['Cifrado', c?.cifrado || '—'],
        ['Nombres alternativos', c?.nombresAlternativos?.length ? c.nombresAlternativos.join(', ') : 'Ninguno declarado'],
        ['Motivo del rechazo', tls.motivoRechazo || c?.motivoRechazo || '—']
      ]
    });
  }

  if (cabeceras) {
    addSection(result, {
      title: 'Cabeceras de seguridad',
      description:
        'Defensas que el servidor añade a la respuesta. Que falte alguna no tumba el sitio, pero deja una puerta que un tercero puede empujar.',
      kind: K.TABLA,
      columns: ['Cabecera', 'Estado', 'Valor'],
      anchoColumnas: [30, 10, 46],
      rows: cabeceras.filas
    });
  }

  if (conexion || protocolo?.conocido) {
    const items = [];
    if (conexion?.nota) {
      items.push(['Nota TLS', `${conexion.nota.letra} (${conexion.nota.puntos}/100)`, tonoNota(conexion.nota.letra)]);
      items.push(['Resumen TLS', conexion.nota.resumen]);
    }
    if (conexion?.protocolos) items.push(['Versiones TLS aceptadas', describirProtocolos(conexion.protocolos)]);
    if (protocolo?.conocido) {
      items.push(['HTTP/2', protocolo.h2 ? 'Sí, negociado' : 'No detectado']);
      items.push(['HTTP/3', protocolo.h3 ? 'Sí, anunciado en DNS' : 'No anunciado']);
    }
    addSection(result, {
      title: 'Seguridad de la conexión',
      description:
        'La nota resume el certificado, las versiones de TLS y el cifrado negociado. Los apartados grises son los que este cliente moderno ya no sabe medir (TLS 1.0/1.1).',
      kind: K.PARES,
      items
    });
  }

  if (registro?.aplica) {
    const d = registro.datos;
    addSection(result, {
      title: 'Caducidad del dominio',
      description: 'Un nombre puede seguir resolviendo y sirviendo meses después de dejar de pagarse. Esta es la única causa silenciosa de las cuatro.',
      kind: K.PARES,
      items: d
        ? [
            ['Caduca', d.caducidad || 'Sin dato'],
            ['Registrado', d.registro || 'Sin dato'],
            ['Registrador', d.registrador || 'Sin dato'],
            ['Estado del registro', d.estados || 'Sin dato']
          ]
        : [['Estado', `No se pudo consultar: ${registro.error || 'el registro no devolvió datos'}`]]
    });
  }
}

/** Une los valores de una consulta DNS, o el motivo por el que no hay. */
function textoValores(registro) {
  if (!registro) return 'Sin dato';
  if (registro.ok) return registro.valores.length ? registro.valores.join(', ') : 'Ninguna';
  return registro.error || 'Sin dato';
}

/** El color de la nota TLS, con la misma escala que `tls-checker`. */
function tonoNota(letra) {
  if (letra === 'A' || letra === 'B') return 'ok';
  if (letra === 'C') return 'neutral';
  if (letra === 'D') return 'warn';
  return 'bad';
}

/**
 * Resume el mapa de versiones TLS en una frase.
 *
 * La distinción que no se puede perder es `false` (el servidor la rechaza) frente
 * a `null` (este cliente no ha podido medirla, normalmente porque OpenSSL ya no
 * ofrece TLS 1.0/1.1). Meterlas en el mismo saco afirmaría un rechazo que nadie
 * ha comprobado.
 */
function describirProtocolos(protocolos = {}) {
  const aceptadas = Object.entries(protocolos).filter(([, v]) => v === true).map(([k]) => k);
  const rechazadas = Object.entries(protocolos).filter(([, v]) => v === false).map(([k]) => k);
  const sinMedir = Object.entries(protocolos).filter(([, v]) => v == null).map(([k]) => k);
  const partes = [];
  partes.push(aceptadas.length ? `Acepta ${aceptadas.join(', ')}` : 'No acepta ninguna versión moderna');
  if (rechazadas.length) partes.push(`rechaza ${rechazadas.join(', ')}`);
  if (sinMedir.length) partes.push(`${sinMedir.join(', ')} sin poder medir desde este cliente`);
  return `${partes.join('; ')}.`;
}

/* ------------------------------------------------------------------ *
 * Veredicto y hallazgos
 * ------------------------------------------------------------------ */

/**
 * El titular, y solo el titular.
 *
 * Va separado de los hallazgos a propósito. El titular es lo primero que se lee
 * y tiene que estar decidido ANTES de escribir nada más, para que ninguna
 * observación posterior pueda cambiarlo por sorpresa. Y depende solo de lo que
 * devolvió el servidor: los detalles van en los hallazgos, que es donde el
 * usuario baja cuando quiere saber por qué.
 *
 * El verbo es siempre "está operativa", "responde con", "no ha respondido",
 * nunca "está caída". La diferencia no es de estilo: una sola conexión no puede
 * afirmar que un sitio está caído para todo el mundo.
 *
 * @param {string} host
 * @param {object} r Respuesta del sondeo.
 * @returns {string}
 */
function titularDe(host, r) {
  if (r.error) return `${host} no ha respondido`;
  if (r.bucle) return `${host} se redirige a sí mismo`;
  if (r.demasiadas) return `${host} encadena demasiadas redirecciones`;
  if (r.estado >= 500) return `${host} responde con un error ${r.estado}`;
  if (r.estado >= 400) return `${host} responde con un error ${r.estado}`;
  if (detectarParking(r)) return `${host} responde con una página de venta`;
  if (enConstruccion(r)) return `${host} responde con una página en construcción`;
  return `${host} está operativa`;
}

/**
 * Traduce los datos en hallazgos.
 *
 * Dos reglas gobiernan toda esta función.
 *
 * LA GRAVEDAD LA MANDA EL SONDEO, no los detalles. Si el sitio responde 200,
 * un certificado autofirmado es un problema serio pero no convierte el sitio en
 * un sitio caído, y un informe que lo hiciera enseñaría "caído" con un 200
 * delante. Por eso `limitar()` recorta los hallazgos secundarios cuando el
 * sondeo va bien, y garantiza un `error` cuando va mal.
 *
 * LOS ERRORES QUE NO SON DEL SITIO NO CUENTAN COMO CAÍDA. Un fallo al leer el
 * certificado o al preguntar al registro deja un agujero en el informe, no
 * evidencia de que el sitio esté mal. Se dice con esas palabras.
 */
function revisar(result, { url, r, dns, tls, registro, cabeceras, conexion, protocolo }) {
  const host = url.hostname;
  setHeadline(result, titularDe(host, r));

  // Los hallazgos del sondeo HTTP van aparte porque son los que pueden subir el
  // veredicto a `fail` sin más.
  const bloqueantes = [];

  if (r.error) {
    bloqueantes.push(...revisarFalloDeRed(result, host, r.error));
  } else {
    bloqueantes.push(...revisarHttp(result, host, r));
    revisarDificultades(result, host, r);
    revisarCabeceras(result, cabeceras);
    revisarConexion(result, { conexion, protocolo, url });
  }

  revisarDns(result, host, dns, r);
  revisarTls(result, host, tls, url);
  revisarRegistro(result, host, registro);

  ajustarGravedad(result, { host, r, bloqueantes });
}

/**
 * Vuelca los hallazgos de las cabeceras ya analizadas.
 *
 * No vuelve a decidir nada: la severidad y el texto salieron de
 * `analizarCabeceras`, la misma función que pinta la tabla. Así lo que se ve y
 * lo que se avisa no pueden separarse.
 */
function revisarCabeceras(result, cabeceras) {
  if (!cabeceras) return;
  for (const f of cabeceras.hallazgos) addFinding(result, f);
}

/**
 * La nota TLS y las versiones de HTTP, como hallazgo cuando hay algo que decir.
 *
 * Una nota baja se cuenta una vez, con su motivo, en vez de repetir uno por uno
 * los problemas que el auditor del certificado ya enumera: dos listas de lo
 * mismo con palabras distintas es la forma más rápida de que el usuario deje de
 * leerlas.
 */
function revisarConexion(result, { conexion, protocolo, url }) {
  if (url.protocol !== 'https:') return;

  if (conexion?.nota && conexion.nota.letra === 'F') {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: `La configuración TLS suspende (nota ${conexion.nota.letra})`,
      detail: conexion.nota.resumen,
      recommendation: 'Revisa los apartados del certificado y de las versiones de TLS. Una nota F suele ser un protocolo obsoleto, un cifrado roto o un certificado que no valida.'
    });
  }

  // Solo se avisa si se MIDIÓ que habla HTTP/1.1. Si no se pudo detectar (un
  // servidor que no negocia ALPN), callar es más honesto que afirmar un atraso.
  if (protocolo?.conocido && !protocolo.h2 && !protocolo.h3 && protocolo.alpnTls) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'El sitio no ofrece HTTP/2 ni HTTP/3',
      detail: `El handshake negoció ${protocolo.alpnTls} y el registro DNS no anuncia h3. Con HTTP/1.1 cada recurso de la página abre su propia conexión.`,
      recommendation: 'Activa HTTP/2 en el servidor o el proxy. Es gratis en los servidores actuales y acelera la carga sin tocar el código.'
    });
  }
}

/**
 * El sitio no respondió. Aquí no hay nada que matizar.
 *
 * @returns {Array} Los hallazgos que deben poder subir el veredicto a `fail`.
 */
function revisarFalloDeRed(result, host, error) {
  const tiempoAgotado = error.code === CODES.TIMEOUT;

  const principal = {
    severity: SEVERIDADES.ERROR,
    title: tiempoAgotado ? `${host} no respondió dentro del plazo` : `No se pudo conectar con ${host}`,
    detail: `${error.message}${error.details?.bloqueadas ? ` (${error.details.bloqueadas.join(', ')})` : ''}`,
    recommendation:
      error.remediation ||
      'Comprueba que el dominio exista y que el servidor acepte conexiones. Si responde en tu navegador y no aquí, el problema está en el camino entre tu equipo y el servidor: un proxy, un DNS local o un cortafuegos.'
  };
  addFinding(result, principal);

  // El malentendido más frecuente con este módulo: si el sitio abre en el
  // navegador y no sale aquí, no está caído. Ponerlo por escrito evita el
  // "yo lo veo bien" de quien lee el informe sin contexto.
  addFinding(result, {
    severity: SEVERIDADES.INFO,
    title: 'Esta comprobación se ha hecho desde este equipo, ahora mismo',
    detail:
      'Es una muestra de una: una conexión, un momento y una ruta. Si el sitio te funciona en el navegador, entonces está en pie y lo que falla es el camino entre tu equipo y él.',
    recommendation: 'Para saber si se ve desde otras redes, prueba desde otro dispositivo o desde la red móvil.'
  });

  return [principal];
}

/**
 * Qué significa el código que devolvió el servidor.
 *
 * La distinción que más importa aquí es 4xx contra 5xx. Un 404 o un 403
 * significan que el sitio está en pie y que esa ruta no se sirve a quien
 * pregunta; un 502 significa que el sitio tiene un problema. Tratarlos igual
 * convierte "escribiste mal la ruta" en "tu web está caída", que es justo la
 * mentira que este módulo no debe decir.
 *
 * @returns {Array} Hallazgos que pueden subir el veredicto.
 */
function revisarHttp(result, host, r) {
  const { estado } = r;

  if (r.bucle) {
    const f = {
      severity: SEVERIDADES.ERROR,
      title: 'Las redirecciones forman un bucle',
      detail: r.motivo,
      recommendation: 'Revisa la regla de redirección del servidor. Un bucle deja la web inaccesible, no solo para este cliente.'
    };
    addFinding(result, f);
    return [f];
  }

  if (r.demasiadas) {
    const f = {
      severity: SEVERIDADES.ERROR,
      title: 'La URL encadena demasiadas redirecciones',
      detail: r.motivo,
      recommendation:
        'Cada salto añade latencia. Suele ser una cadena http → https → www → http que se resuelve quitando uno de los eslabones.'
    };
    addFinding(result, f);
    return [f];
  }

  if (estado >= 500) {
    const f = {
      severity: SEVERIDADES.ERROR,
      title: `El servidor devuelve un error ${estado}`,
      detail: `El servidor responde, pero con un fallo propio. ${r.motivo || ''}`.trim(),
      recommendation:
        estado === 502 || estado === 503
          ? 'Un 502 o un 503 suele ser un backend caído o un mantenimiento en curso. Si se repite, mira el registro de errores del servidor.'
          : 'Mira el registro de errores del servidor. Un 500 con visitas delante es una incidencia.'
    };
    addFinding(result, f);
    return [f];
  }

  if (estado >= 400) {
    const f = {
      severity: SEVERIDADES.WARN,
      title: `El servidor responde ${estado} a esta dirección`,
      detail: DETALLE_4XX[estado] || `El servidor ha respondido ${estado} a la petición.`,
      recommendation: RECOMENDACION_4XX[estado] || 'Abre esa misma dirección en un navegador para ver qué devuelve.'
    };
    addFinding(result, f);
    return [f];
  }

  return [];
}

/** Lo que significa cada 4xx. Un 4xx es una ruta que no se sirve, no un sitio roto. */
const DETALLE_4XX = {
  400: 'El servidor ha rechazado la petición por estar mal formada. Con una URL normal es raro: suele venir de un proxy intermedio.',
  401: 'El servidor pide autenticación. La ruta existe, pero no es pública.',
  403: 'El servidor rechaza la petición. En muchos sitios es una protección contra robots: el navegador de una persona sí puede verla.',
  404: 'La ruta no existe en el servidor. El sitio está en pie, pero la dirección escrita no lleva a ninguna página.',
  410: 'El servidor dice que este contenido se retiró y no va a volver. Es una respuesta deliberada, no un fallo.',
  429: 'Se han agotado las peticiones permitidas desde esta dirección. Es señal de que este origen satura el límite, no de que el sitio esté caído.'
};

const RECOMENDACION_4XX = {
  400: 'Repite la comprobación. Si sigue igual, el problema está en la ruta que has escrito o en un proxy por medio.',
  401: 'La dirección necesita iniciar sesión. Para revisar el acceso a un correo usa mail-checker.',
  403: 'Comprueba si la web abre en el navegador. Si abre, el servidor está filtrando clientes automatizados y el sitio está disponible para la gente.',
  404: 'Revisa que la dirección sea la correcta. Si lo que querías era la portada, entra en el dominio sin ruta.',
  410: 'No hay nada que arreglar en el sitio: es una retirada intencionada.',
  429: 'Espera unos minutos. Si se repite siempre, este equipo o esa red está saturando el límite de peticiones del servidor.'
};

/**
 * Lo que estropea el informe sin ser un problema del sitio.
 *
 * Casi todo aquí son `warn`: lentitud, TLS, Parking. `ajustarGravedad` los
 * limita, pero nunca los borra, porque son cosas que el titular no puede decir
 * y el usuario sí necesita saber.
 */
function revisarDificultades(result, host, r) {
  if (r.metodo === 'GET') {
    // `info` y no `warn`: es un dato sobre CÓMO se comprobó, no un defecto del
    // sitio. El titular ya dice que está operativa, y con un `warn` aquí el
    // informe abriría con "CON OBSERVACIONES" por algo que no molesta a nadie.
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'El servidor no admite HEAD y se ha comprobado con GET',
      detail: `Respondió ${r.motivoAlternativo || 405} al HEAD, así que se repitió con GET, que es lo que usa un visitante. El resultado es bueno igualmente.`,
      recommendation: 'Nada que hacer. Se anota porque, si el sitio empieza a filtrar bots, el veredicto dependería de este detalle.'
    });
  }

  if (r.cadena?.length > 1) {
    const saltos = r.cadena.length - 1;
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: `La dirección escrita redirige a otra (${saltos} salto${saltos === 1 ? '' : 's'})`,
      detail: `Termina en ${r.urlFinal}. Cada salto suma latencia, y en móvil se nota.`,
      recommendation:
        'Si va de http a https, está bien y conviene dejarla. Si va a otro dominio, comprueba que sea intencionado: encadenar redirecciones entre dominios pierde posicionamiento.'
    });
  }

  // Parking y "en construcción" van aquí y no en `titularDe` porque son cosas
  // que el titular AFIRMA y el informe tiene que explicar. Un titular que dice
  // "responde con una página de venta" sin un hallazgo que lo diga deja al
  // usuario con una afirmación sin respaldo justo debajo.
  if (detectarParking(r)) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Delante del sitio hay una página de venta o dominio aparcado',
      detail: `El título de la respuesta es "${r.titulo}". El dominio responde, pero quien entre no verá un sitio: verá una oferta de compra.`,
      recommendation:
        'Si el dominio es tuyo y esperabas un sitio, lo más probable es que se haya quedado sin hosting y el registrador haya puesto su página por defecto. Comprueba en el panel del registrador.'
    });
  }

  if (enConstruccion(r)) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'El sitio se declara en construcción',
      detail: `El título de la respuesta es "${r.titulo}". El servidor responde y entrega una página, pero no hay contenido real todavía.`,
      recommendation:
        'No es una avería. Si esperabas encontrar el sitio terminado, revisa que la publicación esté hecha y que el título de la portada sea el correcto.'
    });
  }

  if (r.ttfbMs > 2000) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: `Tarda ${r.ttfbMs} ms en contestar`,
      detail: 'El tiempo hasta el primer byte es alto para una visita normal.',
      recommendation: 'Si se nota también en el navegador, mira la base de datos y el tiempo de generación en el servidor antes que la red.'
    });
  }

  if (r.truncado) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'La página se ha leído solo en parte',
      detail: `Se han leído los primeros ${Math.round(web.MAX_CUERPO / 1024)} kB, que es el tope que este módulo se pone para no agotar la memoria con una respuesta enorme.`,
      recommendation: 'No afecta al veredicto: solo importa el principio de la página, que es donde está el título.'
    });
  }
}

/**
 * Señales de que delante del sitio hay un intermediario.
 *
 * Los avisos en chino están aparte a propósito. `\b` en JavaScript se define
 * con `\w`, que es ASCII: pegado a un carácter chino no hay frontera de palabra
 * y `此域名\b` no puede encontrar NADA, por muyta correcta que sea la frase. En
 * una expresión con `\b` alrededor, esas alternativas serían código muerto que
 * parece funcionar.
 */
const RE_PARKING = /\b(parking|parked|domain for sale|domain sale|sedo|afternic|hugedomains|namecheap parking)\b/i;
const RE_PARKING_CJK = /此域名|出售|域名停放/;

function detectarParking(r) {
  const texto = `${r.titulo || ''} ${r.cabeceras?.server || ''}`;
  return RE_PARKING.test(texto) || RE_PARKING_CJK.test(texto);
}

/** Un sitio que responde 200 pero está vacío, dicho por él mismo. */
function enConstruccion(r) {
  return Boolean(r.titulo && /(coming soon|próximamente|proximamente|under construction|en construcción|en construccion|very soon)/i.test(r.titulo));
}

/* ------------------------------------------------------------------ *
 * DNS, TLS y registro
 * ------------------------------------------------------------------ */

/** DNS: casi siempre es aquí donde está el motivo de una caída. */
function revisarDns(result, host, dns, r) {
  // Un destino literal no tiene nada que revisar aquí: ya se sabe su dirección.
  if (dns.literal) return;

  if (!dns.resuelve) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: `El nombre ${host} no resuelve a ninguna dirección`,
      detail: [dns.a?.ok ? 'Sin registros A' : dns.a?.error, dns.aaaa?.ok ? 'Sin registros AAAA' : dns.aaaa?.error]
        .filter(Boolean)
        .join(' · ') || 'Ni A ni AAAA devuelven nada.',
      recommendation:
        'Si el sitio funcionaba antes, el problema casi siempre es que el dominio caducó o que se han borrado sus registros de zona. Mira la fecha de caducidad, más abajo.'
    });
    return;
  }

  if (dns.a?.ok && !dns.a.valores.length && dns.aaaa?.ok && dns.aaaa.valores.length) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'El sitio solo tiene dirección IPv6',
      detail: 'No hay ningún registro A, solo AAAA.',
      recommendation: 'Es cada vez más normal, pero deja fuera a quien no tenga IPv6. Si es tu sitio, añade un registro A.'
    });
  }

  if (r.error) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'El nombre resuelve pero no se pudo completar la conexión',
      detail: `${dns.direcciones.join(', ')} responden a DNS, pero la conexión no llegó a terminar.`,
      recommendation:
        'Si el servidor está detrás de un cortafuegos, comprueba que acepte el 80 y el 443 desde Internet. A veces bloquea por rango de direcciones.'
    });
  }
}

/** TLS: los fallos de aquí se ven como "no abre" en el navegador. */
function revisarTls(result, host, tls, url) {
  if (url.protocol !== 'https:') {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'El sitio no usa HTTPS',
      detail: `La comprobación se ha hecho sobre http://${host}. Sin TLS el tráfico va en claro y los navegadores marcan la página como no segura.`,
      recommendation:
        "En hosting compartido suele haber una redirección a https en el panel o en el .htaccess. Con un certificado gratuito de Let's Encrypt se hace en cinco minutos."
    });
    return;
  }

  if (!tls) return;

  if (tls.error) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'No se pudo leer el certificado',
      detail: tls.error,
      recommendation: 'Un certificado que no se puede leer es un problema que antes o después se ve en el navegador de cualquier visitante.'
    });
    return;
  }

  // Los hallazgos del auditor ya traen severidad y acción. Reutilizarlos es
  // mejor que volver a decidir aquí qué es grave, que es donde dos módulos del
  // mismo proyecto acaban discrepando. Se usa el auditor INYECTADO, no el del
  // módulo real, para que las pruebas puedan decidir qué encuentra.
  for (const f of tls.auditar(tls.certificado)) {
    addFinding(result, {
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      recommendation: f.recommendation
    });
  }
}

/** La caducidad: la causa que no se ve desde fuera. */
function revisarRegistro(result, host, registro) {
  if (!registro?.aplica) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'No hay dominio que consultar',
      detail: registro?.motivo || 'La comprobación de la caducidad no aplica aquí.',
      recommendation: 'Para revisar la caducidad, escribe un nombre de dominio en lugar de una dirección IP.'
    });
    return;
  }

  if (!registro.datos) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'No se pudo consultar el registro del dominio',
      detail: registro.error || 'El registro no devolvió datos utilizables.',
      recommendation:
        'Sin registro no se puede descartar que el dominio esté caducado, que es la causa silenciosa más habitual de este tipo de avería.'
    });
    return;
  }

  const d = registro.datos;

  // Aquí está la diferencia que no se puede colapsar: "este TLD no tiene
  // registro público" y "el dominio no está registrado" son dos frases
  // opuestas. Usar la segunda daría un informe que afirma una vacante que
  // nadie ha comprobado.
  if (!d.disponible && !d.consultable) {
    addFinding(result, {
      severity: SEVERIDADES.INFO,
      title: 'Este TLD no tiene un registro público que consultar',
      detail: d.motivo || 'El directorio de IANA no lista un servidor RDAP para esta terminación.',
      recommendation: 'La caducidad no se ha podido comprobar en este caso. Puedes mirarla en el whois del registro del TLD.'
    });
    return;
  }

  if (!d.disponible) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'El dominio no aparece en ningún registro público',
      detail: d.motivo || 'Ningún registro consultado tiene asignado este nombre.',
      recommendation:
        'Si el sitio funciona, es que el registro de este TLD no publica por RDAP y no se ha podido comprobar. Si no funciona, un dominio sin registrar no puede tener un sitio detrás: ese es el fallo.'
    });
    return;
  }

  if (d.retenciones?.length) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: `El registro tiene una retención activa: ${d.retenciones.join(', ')}`,
      detail: 'Con una retención, el registrador no deja cambiar los datos del dominio, y a menudo tampoco lo resuelve.',
      recommendation: 'Habla con el registrador que aparece en el informe. Es el único que puede levantarla.'
    });
  }

  const dias = diasPara(d.caducidad);
  if (dias !== null && dias < 0) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: `El dominio caducó hace ${Math.abs(dias)} días`,
      detail: `La fecha de caducidad del registro es ${d.caducidad}. Un nombre caducado sigue resolviendo y sirviendo durante semanas, y de golpe deja de hacerlo.`,
      recommendation:
        'Renueva en el registrador. Si ya lo has hecho y sigue igual, mira si el pago no se ha cargo y si hay un bloqueo pendiente en el panel.'
    });
  } else if (dias !== null && dias <= 30) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: `El dominio caduca en ${dias} día${dias === 1 ? '' : 's'}`,
      detail: `Fecha de caducidad: ${d.caducidad}.`,
      recommendation: 'Renueva antes. Un dominio que caduca se queda sin sitio sin avisar, y recuperarlo después tiene un coste.'
    });
  }
}

/**
 * Días que faltan para una fecha ISO. `null` si no hay fecha o no se entiende.
 *
 * Un número inventado aquí sería peor que no decir nada: "caduca en -3 días"
 * sobre una fecha mal leída mandaría a renovar un dominio que tiene cuatro años
 * de margen.
 */
function diasPara(fecha) {
  if (!fecha) return null;
  const d = new Date(fecha);
  if (Number.isNaN(d.getTime())) return null;
  return Math.floor((d.getTime() - Date.now()) / 86400e3);
}

/** Ordena direcciones para comparar listas sin depender del orden de llegada. */
function canonico(valores) {
  return [...new Set(valores.map(String))].sort().join(',');
}

/**
 * Recorta la gravedad para que el veredicto y el titular no se contradigan.
 *
* El sondeo manda. Si el sitio respondió con un 2xx, el veredicto es del sitio
 * y un certificado autofirmado pasa a ser una observación, no un fallo: de lo
 * contrario el informe diría "caído" con un 200 delante. Y si el sitio NO
 * respondió, tiene que quedar al menos un hallazgo de severidad `error`, para
 * que `deriveStatus` no deje el estado en `pass` mientras el titular dice que no
 * ha respondido.
 */
function ajustarGravedad(result, { r, bloqueantes }) {
  const hayErrorBloqueante = bloqueantes.some((f) => f.severity === SEVERIDADES.ERROR);
  if (r.error || hayErrorBloqueante) return;

  const vaBien = r.estado >= 200 && r.estado < 400;
  if (!vaBien) return;

  // Se RECORTA a `warn`, no se baja a `info`.
  //
  // Lo que no puede pasar es que un detalle secundario convierta un 200 en
  // "CON FALLOS": el sitio está en pie y eso es innegable. Lo que sí tiene que
  // pasar es que el aviso siga viéndose. Un certificado autofirmado o tres
  // segundos de espera son cosas que el titular no puede decir y el usuario sí
  // necesita saber; bajarlas a `info` las esconde y deja un "está operativa"
  // con los problemas debajo, que es la forma educada de no mencionarlos.
  for (const hallazgo of result.findings) {
    if (hallazgo.severity === SEVERIDADES.ERROR) hallazgo.severity = SEVERIDADES.WARN;
  }
}

module.exports = {
  id: ID,
  titulo: 'Comprobador de sitios web',
  descripcion:
    'Comprueba si un sitio responde y, si algo falla, dice por qué: DNS, TLS, redirecciones, caducidad del dominio y si hay una página de venta delante.',
  sinRed: false,
  icon: '🌍',
  campos: CAMPOS,
  ejecutar,
  // Expuestas para poder probarlas sin red.
  _internas: {
    leerOpciones,
    sondear,
    esBloqueoDeSeguridad,
    titularDe,
    tonoEstado,
    detectarParking,
    enConstruccion,
    revisar,
    revisarHttp,
    revisarDns,
    revisarTls,
    revisarRegistro,
    revisarCabeceras,
    revisarConexion,
    pintarDiagnostico,
    pintarHechos,
    analizarCabeceras,
    determinarProtocolo,
    calificarConexion,
    describirProtocolos,
    ajustarGravedad,
    diasPara,
    canonico
  }
};