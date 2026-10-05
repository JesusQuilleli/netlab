/**
 * redact.js — Enmascarado de secretos.
 *
 * MODULO DE SEGURIDAD. Ningun log ni reporte debe poder filtrar una
 * credencial. Este modulo centraliza ese trabajo para que las herramientas
 * no tengan que acordarse de hacerlo.
 *
 * Que protege:
 *   1. Secretos conocidos en tiempo de ejecucion (los del .env y los args).
 *      Busca su valor literal en cualquier cadena y lo reemplaza. Es la
 *      defensa mas fiable porque no depende de detectar el "forma" del secreto.
 *   2. Secretos que NO conocemos pero tienen forma recognizable: claves de AWS,
 *      API keys largas, JWT, cadenas base64 largas, URLs con password embebida.
 *   3. Tags de protocolo que los valores de autenticacion usan en texto plano
 *      (AUTH LOGIN / IMAP LOGIN / XOAUTH2) y sus cargas base64.
 *
 * @module core/redact
 */

'use strict';

const MASK = '[REDACTADO]';

/**
 * Secretos con forma reconocible, evaluados por el patron de la regla.
 *
 * NOTA sobre las funciones `mask`: el callback de String.replace recibe
 * (coincidencia, g1, g2, ..., posicion, cadena). El primer parametro es el
 * TEXTO QUE COINCIDIO, no un array de grupos; los grupos llegan como
 * parametros sueltos. Hay que nombrarlos, nunca indexarlos como `m[1]`,
 * porque eso devolveria un caracter de la coincidencia en vez del grupo.
 */
const PATTERNS = [
  {
    // Claves de acceso AWS (AKIA, ASIA, AIDA, AROA, ANPA, ...). Es el formato
    // del par access-key-id / secret-access-key de AWS.
    name: 'aws-access-key-id',
    re: /\b(?:AKIA|ASIA|AIDA|AROA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
    mask: () => 'AKIA****[REDACTADO]'
  },
  {
    // Secret access key de AWS: 40 caracteres base64. Se ancla a lo que le
    // precede para no devorar cadenas base64 legitimas de otros protocolos.
    name: 'aws-secret-access-key',
    re: /\b[A-Za-z0-9/+=]{40}\b/g,
    mask: () => '[REDACTADO:40]'
  },
  {
    // Cabeceras Authorization con token. Cubre Bearer y Basic.
    name: 'authorization-header',
    re: /\b(Authorization\s*[:=]\s*)(\S+\s+)?\S+/gi,
    mask: (match, prefix, scheme) => `${prefix}${scheme || ''}${MASK}`
  },
  {
    // URLs con credenciales embebidas: scheme://user:pass@host
    name: 'url-credentials',
    re: /\b([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi,
    mask: (match, scheme, user) => `${scheme}${user}:${MASK}@`
  },
  {
    // Cabeceras de API estilo AbuseIPDB: Key: <64 hex>
    name: 'api-key-header',
    re: /\b(Key|Api[-_]?Key|Apikey|Token|X-Auth-Token)\s*[:=]\s*\S{16,}/gi,
    mask: (match, key) => `${key}: ${MASK}`
  },
  {
    // Asignaciones del estilo SECRET=valor o "password": "valor".
    name: 'assignment',
    re:
      /\b((?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|credential|contrasenya|clave)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi,
    mask: (match, prefix) => `${prefix}${MASK}`
  },
  {
    // JSON con esos mismos nombres de campo.
    name: 'json-field',
    re:
      /("(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|credential|contrasenya|clave)"\s*:\s*)"(?:[^"\\]|\\.)*"/gi,
    mask: (match, prefix) => `${prefix}"${MASK}"`
  },
  {
    // Comandos de autenticacion IMAP: LOGIN "user" "pass". En texto plano
    // dentro del tunel TLS, pero aparece en la telemetria que guardamos.
    name: 'imap-login',
    re: /(\bLOGIN\s+)(\S+|"[^"]*")\s+("?)([^\s"]+)\3/gi,
    mask: (match, prefix, user) => `${prefix}${user} ${MASK}`
  },
  {
    // Cargas base64 de AUTH LOGIN / XOAUTH2 / SASL.
    name: 'sasl-payload',
    re: /((?:^|\s)(?:[A-Za-z0-9+/]{24,}={0,2}))(?=\s*(?:[\r\n]|$))/g,
    mask: () => `${MASK}:base64`
  },
  {
    // Tokens JWT: header.payload.signature
    name: 'jwt',
    re: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g,
    mask: () => `${MASK}:jwt`
  },
  {
    // Claves privadas PEM, si alguien las pega en un campo de texto.
    name: 'private-key',
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    mask: () => `${MASK}:private-key`
  }
];

/**
 * Normaliza un valor secreto para poder buscarlo dentro de un texto.
 *
 * Necesario porque el mismo secreto aparece con distintas formas: el codigo
 * base64 de una contrasena no es igual a la contrasena, pero contiene su forma
 * legible cuando se decodifica. Normalizamos a una version "plana" y buscamos
 * tanto la original como sus variantes.
 *
 * @param {string} secret Valor a registrar como sensible.
 * @returns {string[]} Variantes por las que hay que buscar, sin vacios.
 */
function buildNeedles(secret) {
  if (typeof secret !== 'string') return [];
  const trimmed = secret.trim();
  if (trimmed.length < 4) return [];

  const needles = new Set([trimmed]);

  // Si el secreto parece base64, agregar tambien su forma decodificada: es el
  // caso tipico de AUTH LOGIN, donde la contrasena viaja codificada.
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) && trimmed.length >= 8) {
    try {
      const decoded = Buffer.from(trimmed, 'base64').toString('utf8');
      if (/^[\x20-\x7e]+$/.test(decoded) && decoded.length >= 4) needles.add(decoded);
    } catch {
      /* no es base64 valido: solo queda la forma original */
    }
  }

  return [...needles];
}

/**
 * Crea un redactor con los secretos de la ejecucion actual ya conocidos.
 *
 * Uso tipico, en el arranque del proceso:
 *
 *   const redact = createRedactor({ secrets: [process.env.MY_API_KEY] });
 *   logger.info('conectando con', apiKey);   // -> 'conectando con [REDACTADO]'
 *
 * @param {object} [options]
 * @param {string[]} [options.secrets] Valores literales a enmascarar.
 * @returns {string} Funcion que recibe cualquier valor y devuelve texto seguro.
 */
function createRedactor(options = {}) {
  const { secrets = [] } = options;

  // Los needles mas largos primero, para que un secreto corto que este
  // contenido dentro de uno largo se sustituya completo.
  const needles = secrets
    .flatMap(buildNeedles)
    .sort((a, b) => b.length - a.length)
    .map(escapeRegExp);

  /**
   * Enmascara un valor. Acepta cualquier tipo; lo no textual se serializa.
   *
   * @param {unknown} input Valor a limpiar.
   * @returns {string} Texto sin secretos.
   */
  function redact(input) {
    if (input === null || input === undefined) return '';
    let text = typeof input === 'string' ? input : String(input);
    if (!text) return '';

    // 1. Secretos conocidos literalmente.
    for (const escaped of needles) {
      text = text.replace(new RegExp(escaped, 'g'), MASK);
    }

    // 2. Secretos reconocibles por forma.
    for (const rule of PATTERNS) {
      rule.re.lastIndex = 0;
      text = text.replace(rule.re, rule.mask);
    }

    return text;
  }

  redact.secrets = secrets.filter((s) => typeof s === 'string' && s.length >= 4);
  redact.patterns = PATTERNS.map((p) => p.name);
  return redact;
}

/**
 * Redactor por defecto, sin secretos conocidos. Aplica solo los patrones.
 * Util para datos que no vienen de esta ejecucion (respuestas de terceros,
 * archivos subidos por el usuario).
 */
const redact = createRedactor();

/** Escapa un literal para usarlo dentro de una RegExp. */
function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Nombres de campo que se consideran secretos por defecto.
 *
 * Deliberadamente NO incluyen 'key' ni 'auth': en este dominio 'key' es un
 * termino legitimo (llaves DKIM, claves de API que queremos conservar para
 * diagnostico) y 'auth' es un objeto contenedor, no un valor. Si una
 * herramienta necesita mas, pasa su propia lista.
 */
const DEFAULT_SECRET_KEYS = [
  'password',
  'passwd',
  'pass',
  'secret',
  'token',
  'apikey',
  'api_key',
  'apiKey',
  'credential',
  'credencial',
  'contrasena',
  'contraseña',
  'authKey'
];

/**
 * Enmascara una estructura anidada (objetos, arrays) de forma recursiva.
 * Las claves que nombran un secreto se enmascaran completas.
 *
 * Los valores que no son texto (numeros, booleanos, null) se copian tal cual:
 * enmascararlos convertiria un puerto 465 en la cadena '465' y rompiente el
 * JSON que consume la interfaz.
 *
 * @param {unknown} input Estructura a limpiar.
 * @param {string[]} [secretKeys] Nombres de campo considerada sensibles.
 * @returns {unknown} Copia sin secretos.
 */
function redactDeep(input, secretKeys = DEFAULT_SECRET_KEYS) {
  const lowered = secretKeys.map((k) => k.toLowerCase());

  if (Array.isArray(input)) return input.map((item) => redactDeep(item, secretKeys));

  if (input && typeof input === 'object') {
    const out = {};
    for (const [key, value] of Object.entries(input)) {
      const esSecreto = lowered.includes(key.toLowerCase()) && (typeof value === 'string' || typeof value === 'number');
      out[key] = esSecreto ? MASK : redactDeep(value, secretKeys);
    }
    return out;
  }

  if (typeof input === 'string') return redact(input);
  return input;
}

module.exports = { createRedactor, redact, redactDeep, DEFAULT_SECRET_KEYS, MASK };