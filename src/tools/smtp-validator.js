/**
 * smtp-validator — prueba en vivo un servidor SMTP (y, si se pide, IMAP) con
 * los datos que escribe quien usa la herramienta.
 *
 * MODULO NUEVO. Sustituye a "Validate config SMTP/validate-smtp.js", que hacia
 * lo mismo pero con una diferencia importante: leia las credenciales del .env.
 * Aqui el formulario empieza vacio y no se mira el .env en ningun momento. La
 * diferencia no es de estilo: una herramienta de diagnostico que rellena sola
 * un usuario y una contrasena acabaria guardandolos en el historial de quien la
 * usa, y ese historial es un fichero en disco.
 *
 * Que comprueba, en orden:
 *   1. Que el puerto abre y el servidor se identifica (banner).
 *   2. El cifrado: TLS directo, STARTTLS anunciado y aplicado, o texto plano.
 *   3. Las capacidades que anuncia el EHLO.
 *   4. La autenticacion, con las credenciales que se hayan escrito.
 *   5. Opcionalmente, un envio real a una direccion que se indique.
 *   6. Opcionalmente, la entrada IMAP con las mismas credenciales.
 *
 * Lo que no hace nunca: guardar la contrasena, ni escribirla en el informe, ni
 * enviarla sin que la casilla este marcada.
 *
 * @module tools/smtp-validator
 */

'use strict';

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
const { createRedactor, redactDeep } = require('../core/redact');
const { normalizarTimeout } = require('../core/dominio');
const smtp = require('../core/mail/smtp');
const imap = require('../core/mail/imap');

const ID = 'smtp-validator';

const TITLE = 'Validador SMTP';

/** Campos del formulario, que consume la web. */
const CAMPOS = [
  {
    name: 'host',
    label: 'Servidor SMTP',
    type: 'text',
    required: true,
    placeholder: 'smtp.ejemplo.com',
    help: 'El nombre del servidor de salida. No se lee ningún valor guardado: escribe el que quieras probar.'
  },
  {
    name: 'puerto',
    label: 'Puerto',
    type: 'number',
    required: true,
    default: 587,
    min: 1,
    max: 65535,
    help: '587 para STARTTLS, 465 para TLS directo, 25 en texto plano.'
  },
  {
    name: 'seguridad',
    label: 'Cómo empieza la conexión',
    type: 'select',
    required: false,
    default: 'starttls',
    options: [
      { value: 'starttls', label: 'STARTTLS — cifrar después del saludo (lo habitual en 587)' },
      { value: 'tls', label: 'TLS directo — cifrar desde el principio (465)' },
      { value: 'ninguno', label: 'Sin cifrar — texto plano (25)' }
    ],
    help: 'Si el servidor no ofrece STARTTLS y elegías cifrar, la prueba lo dirá y seguirá en claro para poder contarte el resto.'
  },
  {
    name: 'usuario',
    label: 'Usuario',
    type: 'text',
    required: false,
    placeholder: 'correo@ejemplo.com',
    help: 'Vacío si el servidor no necesita autenticación. Con usuario, se intentará entrar.'
  },
  {
    name: 'contrasena',
    label: 'Contraseña',
    type: 'password',
    required: false,
    help: 'No se guarda en el informe, ni en el historial, ni en el PDF. Solo viaja al servidor al que escribes su nombre.'
  },
  {
    name: 'verificarCertificado',
    label: 'Exigir que el certificado sea válido y esté emitido por una autoridad de confianza',
    type: 'checkbox',
    required: false,
    default: true,
    help: 'Desactívalo solo para ver qué dice un certificado caducado o autofirmado; la prueba lo marcará como advertencia.'
  },
  {
    name: 'timeout',
    label: 'Espera máxima por paso',
    type: 'number',
    required: false,
    default: 10000,
    min: 500,
    max: 30000,
    unit: 'ms',
    help: 'Si el servidor acepta la conexión y luego no contesta, la prueba se rinde en este plazo en vez de quedarse colgada.'
  },
  {
    name: 'enviarPrueba',
    label: 'Enviar además un correo de prueba',
    type: 'checkbox',
    required: false,
    default: false,
    help: 'Desmarcado por defecto: autenticar y enviar son cosas distintas. Al activarlo sale un correo real hacia la dirección que indiques.'
  },
  {
    name: 'remitente',
    label: 'Remitente del correo de prueba',
    type: 'text',
    requiredUnless: 'enviarPrueba',
    placeholder: 'correo@ejemplo.com',
    shownWhen: 'enviarPrueba',
    help: 'La cuenta desde la que se envía. Suele ser la misma que has puesto arriba.'
  },
  {
    name: 'destinatario',
    label: 'Destinatario del correo de prueba',
    type: 'text',
    requiredUnless: 'enviarPrueba',
    placeholder: 'destino@ejemplo.com',
    shownWhen: 'enviarPrueba',
    help: 'Donde va a parar el mensaje. Pon una dirección tuya.'
  },
  {
    name: 'asunto',
    label: 'Asunto del correo de prueba',
    type: 'text',
    required: false,
    default: 'Prueba de salida SMTP (netlab)',
    shownWhen: 'enviarPrueba'
  },
  {
    name: 'probarImap',
    label: 'Probar también IMAP con las mismas credenciales',
    type: 'checkbox',
    required: false,
    default: false,
    help: 'Abre una sesión IMAP aparte, la mira y entra. Sale bien marcada en el informe.'
  },
  {
    name: 'imapHost',
    label: 'Servidor IMAP',
    type: 'text',
    requiredUnless: 'probarImap',
    placeholder: 'imap.ejemplo.com',
    shownWhen: 'probarImap',
    help: 'A menudo se llama igual que el de salida, pero no siempre: Gmail usa smtp.gmail.com para enviar e imap.gmail.com para entrar.'
  },
  {
    name: 'imapPuerto',
    label: 'Puerto IMAP',
    type: 'number',
    required: false,
    default: 993,
    min: 1,
    max: 65535,
    shownWhen: 'probarImap',
    help: 'El 993 es IMAP sobre TLS.'
  }
];

/* ------------------------------------------------------------------ *
 * Entrada de la herramienta
 * ------------------------------------------------------------------ */

/**
 * @param {object} params
 * @param {object} [ctx]
 * @returns {Promise<object>} Result
 */
async function ejecutar(params = {}, ctx = {}) {
  const inicio = new Date();
  const log = ctx.log || null;
  const timeout = normalizarTimeout(params.timeout, { defecto: 10000 });
  const host = String(params.host ?? '').trim();
  const puerto = Number(params.puerto ?? 587);

  // Inyeccion para las pruebas: `ctx.smtp`, `ctx.imap` y `ctx.deps` sustituyen
  // a los modulos de red, igual que mail-checker hace con `ctx.dns`.
  const moduloSmtp = ctx.smtp || smtp;
  const moduloImap = ctx.imap || imap;
  const deps = ctx.deps || {};

  // Redactor de la ejecucion: ademas de los patrones, conoce el secreto
  // literal de este intento. Si un servidor lo devolviera por error en alguna
  // respuesta, queda enmascarado igual. El usuario no se declara secreto,
  // porque en el informe si conviene ver con que cuenta se entro.
  const redactar = createRedactor({ secrets: [params.contrasena].filter((s) => typeof s === 'string' && s.length >= 4) });

  const result = createResult({
    tool: ID,
    toolTitle: TITLE,
    target: host ? `${host}:${puerto}` : '',
    params: paramsSeguros(params)
  });

  try {
    if (!host) {
      throw new NetlabError(CODES.ENTRADA_VACIA, 'No se indicó ningún servidor SMTP.', {
        remediation: 'Escribe el servidor de salida, por ejemplo smtp.ejemplo.com.'
      });
    }

    log?.info?.(`Probando ${host}:${puerto} (${params.seguridad || 'starttls'})`);
    addLog(result, { level: 'info', channel: 'conexion', message: `Conectando a ${host}:${puerto}.` });

    const sesion = await moduloSmtp.probar(
      {
        host,
        puerto,
        seguridad: params.seguridad || 'starttls',
        usuario: params.usuario,
        contrasena: params.contrasena,
        verificar: params.verificarCertificado !== false,
        timeout,
        redactar,
        enviar: params.enviarPrueba ? datosEnvio(params) : null
      },
      deps.smtp
    );

    addSummary(result, 'Servidor', `${host}:${puerto}`);
    addSummary(result, 'Respuesta', sesion.banner || 'sin respuesta');
    addSummary(result, 'Cifrado', etiquetaSeguridad(sesion), tonoSeguridad(sesion));
    addSummary(result, 'Autenticación', etiquetaAuth(sesion.auth), sesion.auth.ok ? 'ok' : sesion.auth.enviado ? 'bad' : 'neutral');

    seccionConexion(result, sesion);
    seccionSeguridad(result, sesion);
    seccionCapacidades(result, sesion);
    seccionEtapas(result, sesion.etapas, 'smtp');
    seccionAuth(result, sesion);
    if (sesion.envio) seccionEnvio(result, sesion.envio);
    hallazgosSmtp(result, sesion, params);

    if (params.probarImap) {
      const sesionImap = await probarImap(result, params, { timeout, redactar, log, modulo: moduloImap, deps: deps.imap });
      if (sesionImap) {
        seccionImap(result, sesionImap);
        seccionEtapas(result, sesionImap.etapas, 'imap');
        hallazgosImap(result, sesionImap);
      }
    }

    if (sesion.error && !sesion.banner) {
      throw sesion.error;
    }

    return finalize(result, inicio);
  } catch (error) {
    addLog(result, { level: 'error', channel: 'error', message: error.message });
    log?.error?.(`smtp-validator falló: ${error.message}`);
    return failWith(finalize(result, inicio), error instanceof NetlabError ? error : new NetlabError(CODES.INTERNO, error.message));
  }
}

/**
 * Quita la contraseña de `params` antes de que llegue a ningún sitio.
 *
 * Se sustituye por una marca de que había contraseña, no por su valor: saber si
 * el intento iba con contraseña es útil para leer el informe, y el valor no. La
 * marca se escribe DESPUÉS de redactar, porque `redactDeep` enmascara cualquier
 * valor de la clave `contrasena` y se llevaría por delante la marca.
 */
function paramsSeguros(params) {
  const { contrasena, ...resto } = params;
  const limpio = redactDeep(resto);
  if (contrasena) limpio.contrasena = '(indicada, no se guarda)';
  return limpio;
}

/** Datos del correo de prueba, si se han pedido. */
function datosEnvio(params) {
  return {
    remitente: String(params.remitente ?? '').trim(),
    destinatario: String(params.destinatario ?? '').trim(),
    asunto: String(params.asunto ?? '').trim(),
    texto: 'Mensaje enviado por el validador SMTP de netlab.'
  };
}

/** Sesión IMAP opcional. Los fallos aquí no tumban el informe del SMTP. */
async function probarImap(result, params, { timeout, redactar, log, modulo, deps }) {
  const imapHost = String(params.imapHost ?? '').trim();
  if (!imapHost) {
    addLog(result, { level: 'warn', channel: 'imap', message: 'Se pidió probar IMAP pero no se indicó el servidor, así que se omitió.' });
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Falta el servidor IMAP',
      detail: 'Se marcó la casilla de probar IMAP, pero el campo del servidor quedó vacío.',
      recommendation: 'Escribe el host IMAP (suele acabar en .imap. o llamarse imap.) o desmarca la casilla.'
    });
    return null;
  }

  const puerto = Number(params.imapPuerto ?? 993);
  log?.info?.(`Probando IMAP ${imapHost}:${puerto}`);
  const sesion = await (modulo || imap).probar(
    {
      host: imapHost,
      puerto,
      usuario: params.usuario,
      contrasena: params.contrasena,
      verificar: params.verificarCertificado !== false,
      timeout,
      redactar
    },
    deps
  );

  addSummary(result, 'IMAP', sesion.banner ? 'conectado' : 'sin respuesta', sesion.banner ? 'ok' : 'bad');
  return sesion;
}

/* ------------------------------------------------------------------ *
 * Presentación
 * ------------------------------------------------------------------ */

function seccionConexion(result, s) {
  addSection(result, {
    id: 'conexion',
    title: 'Conexión',
    kind: K.PARES,
    items: [
      ['Servidor', `${s.host}:${s.puerto}`],
      ['Banner', s.banner || 'sin respuesta'],
      ['Cifrado pedido', etiquetaSeguridadPedida(s.seguridadPedida)],
      ['Cifrado obtenido', etiquetaSeguridad(s)],
      ['Duración', `${s.duracionMs} ms`]
    ]
  });
}

function seccionSeguridad(result, s) {
  if (!s.tls && !s.starttls) return;
  const items = [
    ['Cifrado', etiquetaSeguridad(s)],
    ['Protocolo negociado', s.tls?.protocolo || '—'],
    ['Cifrado negociado', s.tls?.cifrado || '—']
  ];

  if (s.starttls) {
    items.push(['STARTTLS anunciado', s.starttls.anunciado ? 'sí' : 'no', s.starttls.anunciado ? 'ok' : 'warn']);
    items.push(['STARTTLS aplicado', s.starttls.aplicado ? 'sí' : 'no', s.starttls.aplicado ? 'ok' : 'bad']);
    if (s.starttls.motivo) items.push(['Motivo', s.starttls.motivo]);
  }

  if (s.tls) {
    items.push([
      'Certificado validado por una CA',
      s.tls.autoridadCertificadora ? 'sí' : 'no',
      s.tls.autoridadCertificadora ? 'ok' : 'warn'
    ]);
    if (s.tls.motivoRechazo) items.push(['Motivo del rechazo', String(s.tls.motivoRechazo), 'warn']);
  }

  addSection(result, {
    id: 'seguridad',
    title: 'Seguridad del canal',
    kind: K.PARES,
    items
  });
}

function seccionCapacidades(result, s) {
  addSection(result, {
    id: 'capacidades',
    title: 'Capacidades del servidor',
    description: 'Lo que el EHLO respondió, línea a línea y sin interpretar.',
    kind: K.TABLA,
    columns: ['#', 'Respuesta del EHLO'],
    anchoColumnas: [6, 94],
    rows: (s.respuestasEhlo.length ? s.respuestasEhlo : ['(no hubo respuesta)']).map((linea, i) => [String(i + 1), linea])
  });
}

function seccionEtapas(result, etapas, clave) {
  if (!etapas.length) return;
  addSection(result, {
    id: `etapas-${clave}`,
    title: `Pasos de la sesión ${clave.toUpperCase()}`,
    description: 'Cada comando y lo que contestó el servidor, en orden y con su duración.',
    kind: K.TABLA,
    columns: ['Paso', 'Código', 'Respuesta', 'ms'],
    anchoColumnas: [22, 10, 56, 12],
    rows: etapas.map((e) => [
      e.paso,
      e.codigo ?? '—',
      { valor: recortar(e.respuesta || '—', 160), tone: e.error ? 'bad' : 'neutral' },
      String(e.ms)
    ])
  });
}

function seccionAuth(result, s) {
  const a = s.auth;
  const items = [
    ['Mecanismos anunciados', a.soportados.length ? a.soportados.join(', ') : 'ninguno'],
    ['Mecanismo usado', a.mecanismo || '—'],
    ['Intentada', a.enviado ? 'sí' : 'no'],
    ['Resultado', etiquetaAuth(a), a.ok ? 'ok' : a.enviado ? 'bad' : 'neutral'],
    ['Respuesta del servidor', a.mensaje || '—']
  ];
  addSection(result, {
    id: 'auth-smtp',
    title: 'Autenticación SMTP',
    description: 'La contraseña no aparece aquí: solo el mecanismo y lo que el servidor respondió.',
    kind: K.PARES,
    items
  });
}

function seccionEnvio(result, envio) {
  addSection(result, {
    id: 'envio',
    title: 'Envío de prueba',
    description: envio.ok ? 'Salió un correo real desde la cuenta indicada.' : 'No llegó a salir el correo.',
    kind: K.TABLA,
    columns: ['Paso', 'Código', 'Respuesta'],
    anchoColumnas: [26, 12, 62],
    rows: [
      ['Destinatario', '—', envio.destinatario || '—'],
      ['Resultado', '—', { valor: envio.ok ? 'Enviado' : 'Falló', tone: envio.ok ? 'ok' : 'bad' }],
      ...(envio.motivo ? [['Motivo', '—', envio.motivo]] : []),
      ...(envio.etapas || []).map((e) => [e.paso, e.codigo ?? '—', recortar(e.respuesta || '—', 120)])
    ]
  });
}

function seccionImap(result, s) {
  const items = [
    ['Servidor', `${s.host}:${s.puerto}`],
    ['Banner', s.banner || 'sin respuesta'],
    ['Sesión ya autenticada (PREAUTH)', s.preautenticado ? 'sí' : 'no', s.preautenticado ? 'warn' : 'ok'],
    ['Capacidades', s.capacidades.length ? s.capacidades.join(' ') : '—'],
    ['Intento de entrada', s.auth.intentado ? 'sí' : 'no'],
    ['Resultado de entrada', s.auth.ok ? 'Correcto' : s.auth.mensaje || '—', s.auth.ok ? 'ok' : 'warn'],
    ['Duración', `${s.duracionMs} ms`]
  ];
  if (s.tls) {
    items.push(['Cifrado', s.tls.cifrado || '—']);
    items.push(['Certificado validado por una CA', s.tls.autoridadCertificadora ? 'sí' : 'no', s.tls.autoridadCertificadora ? 'ok' : 'warn']);
  }
  addSection(result, {
    id: 'imap',
    title: 'Entrada IMAP (opcional)',
    kind: K.PARES,
    items
  });
}

/* ------------------------------------------------------------------ *
 * Hallazgos
 * ------------------------------------------------------------------ */

function hallazgosSmtp(result, s, params) {
  if (s.error) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'La prueba de SMTP no pudo terminar',
      detail: s.error.message,
      recommendation: s.error.remediation || 'Revisa el host, el puerto y que no haya un firewall en medio.'
    });
  }

  if (s.seguridadEfectiva === 'ninguno') {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'La sesión no quedó cifrada',
      detail: s.starttls?.motivo
        ? `Se pidió cifrar pero no se consiguió: ${s.starttls.motivo}`
        : 'Se conectó en texto plano. El usuario y la contraseña viajarían sin cifrar.',
      recommendation: 'Usa el puerto 465 con TLS directo o el 587 con STARTTLS, y revisa que el servidor lo anuncie en el EHLO.'
    });
  }

  if (s.tls && !s.tls.autoridadCertificadora) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'El certificado no está firmado por una autoridad de confianza',
      detail: s.tls.motivoRechazo
        ? `Motivo: ${s.tls.motivoRechazo}. La sesión se abrió igualmente porque en la prueba se pidió no exigirlo.`
        : 'La sesión se abrió con un certificado que el sistema no da por válido. Podría ser autofirmado o estar caducado.',
      recommendation: 'Instala el certificado correcto en el servidor, o reinstala la cadena de confianza.'
    });
  }

  if (s.seguridadEfectiva === 'ninguno' && s.auth.mecanismo === 'LOGIN') {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'Autenticación sin cifrar con AUTH LOGIN',
      detail: 'En texto plano, AUTH LOGIN manda el usuario y la contraseña en base64, que no es secreto: es solo una codificación.',
      recommendation: 'Nunca autentiques sin TLS. Activa STARTTLS o usa el puerto 465.'
    });
  }

  if (s.auth.enviado && !s.auth.ok) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'La autenticación falló',
      detail: `El servidor respondió ${s.auth.codigo ?? '—'} a ${s.auth.mecanismo}: ${s.auth.mensaje || 'sin mensaje'}`,
      recommendation: 'Revisa el usuario y la contraseña. Si es Gmail u Outlook, puede hacer falta una contraseña de aplicación en vez de la normal.'
    });
  }

  if (!s.auth.enviado && params.usuario && !s.auth.soportados.length) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'El servidor no anuncia ningún mecanismo de autenticación',
      detail: 'Se indicó un usuario, pero el EHLO no ofrece AUTH con nada que este módulo sepa usar.',
      recommendation: 'Muchos servidores solo ofrecen autenticación tras cifrar con STARTTLS: revisa que la casilla de STARTTLS esté activa y se aplique.'
    });
  }

  if (s.envio && !s.envio.ok) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'El correo de prueba no se pudo enviar',
      detail: s.envio.motivo || 'El servidor no aceptó el mensaje.',
      recommendation: 'Revisa que la cuenta pueda enviar, que el remitente esté autorizado y que el destinatario sea válido.'
    });
  }
}

function hallazgosImap(result, s) {
  if (s.error) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'La prueba de IMAP no pudo terminar',
      detail: s.error.message,
      recommendation: s.error.remediation || 'Revisa el host y el puerto IMAP.'
    });
  }

  if (s.preautenticado) {
    addFinding(result, {
      severity: SEVERIDADES.WARN,
      title: 'El servidor IMAP da la sesión por autenticada',
      detail: 'El saludo dice PREAUTH: acepta la sesión sin pedir contraseña, normalmente por estar en la misma red o por Kerberos.',
      recommendation: 'Si esperabas que te pidiera la contraseña, significa que el servidor confía en tu IP. Comprueba que sea intencionado.'
    });
  }

  if (s.auth.intentado && !s.auth.ok) {
    addFinding(result, {
      severity: SEVERIDADES.ERROR,
      title: 'La entrada IMAP falló',
      detail: s.auth.mensaje || 'El servidor no aceptó las credenciales.',
      recommendation: 'Revisa el usuario y la contraseña, y que ese servidor use las mismas credenciales que el SMTP.'
    });
  }
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

function etiquetaSeguridadPedida(valor) {
  if (valor === 'tls') return 'TLS directo';
  if (valor === 'ninguno') return 'Sin cifrar';
  return 'STARTTLS';
}

function etiquetaSeguridad(s) {
  if (s.seguridadEfectiva === 'tls') return `TLS directo (${s.tls?.protocolo || '—'})`;
  if (s.seguridadEfectiva === 'starttls') return `STARTTLS (${s.tls?.protocolo || '—'})`;
  return 'Texto plano';
}

function tonoSeguridad(s) {
  return s.seguridadEfectiva === 'ninguno' ? 'bad' : s.tls && !s.tls.autoridadCertificadora ? 'warn' : 'ok';
}

function etiquetaAuth(a) {
  if (a.ok) return 'Correcta';
  if (a.enviado) return `Falló (${a.codigo ?? '—'})`;
  return 'No intentada';
}

function recortar(texto, max) {
  const limpio = String(texto).replace(/\s+/g, ' ').trim();
  return limpio.length > max ? `${limpio.slice(0, max - 1)}…` : limpio;
}

module.exports = {
  id: ID,
  titulo: TITLE,
  descripcion:
    'Prueba un servidor SMTP con los datos que escribas: conexión, STARTTLS o TLS, capacidades, autenticación y, si lo pides, un envío real y una sesión IMAP.',
  icon: '✉️',
  sinRed: false,
  campos: CAMPOS,
  ejecutar,
  _internas: {
    CAMPOS,
    paramsSeguros,
    recortar,
    etiquetaSeguridad,
    etiquetaSeguridadPedida,
    etiquetaAuth
  }
};