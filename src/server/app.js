/**
 * app.js — Aplicacion express con la API y los ficheros estaticos.
 *
 * MODULO DE ENTRADA DEL SERVIDOR. Se separa de `index.js` a proposito: aqui se
 * construye la app sin abrir ningun puerto, de modo que las pruebas pueden
 * levantarla en un puerto efimero, mandarle peticiones de verdad y cerrarla.
 * `index.js` solo la escucha.
 *
 * PRINCIPIO DE DISEÑO
 *   El servidor no sabe nada de ninguna herramienta en concreto. No hay un
 *   `if (tool === 'ip-audit')` en ningun sitio. Las herramientas aportan su
 *   propia descripcion (`campos`) y su `ejecutar`, y el servidor solo traduce
 *   HTTP a esa forma y de vuelta. Por eso anadir una herramienta no obliga a
 *   tocar nada de aqui.
 *
 * RUTAS
 *   GET    /api/sesion            estado de autenticacion y token CSRF
 *   POST   /api/sesion            entrar
 *   DELETE /api/sesion            salir
 *   GET    /api/herramientas      catalogo
 *   POST   /api/run               ejecuta: { tool, params }
 *   GET    /api/run/:id           vuelve a leer una ejecucion guardada
 *   GET    /api/run/:id/:formato  descarga un formato
 *   GET    /api/historial         listado paginado
 *   GET    /api/historial/:id     detalle
 *   DELETE /api/historial/:id     borra del historial
 *
 * @module server/app
 */

'use strict';

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');

const config = require('../core/config');
const { NetlabError, CODES, wrap } = require('../core/errors');
const formats = require('../formats');
const { obtener: obtenerHerramienta, listar: listarHerramientas, registro } = require('./herramientas');
const { validar } = require('./validar');
const { redactDeep } = require('../core/redact');
const { Auth, leerCookie, NOMBRE_COOKIE } = require('./auth');
const { Historial } = require('./historial');
const { Auditoria, obtenerAuditoria } = require('./auditoria');
const { Metricas, obtenerMetricas } = require('./metricas');
const { addSummary } = require('../core/result');

const DIR_SPA = path.join(__dirname, '..', '..', 'web', 'dist');

/**
 * Codigo HTTP para cada codigo de error del dominio.
 *
 * Sin esto, todo seria 500 y el formulario no podria distinguir "escribiste mal
 * la IP" de "AbuseIPDB no respondio": son dos mensajes completamente distintos
 * para la persona que esta usando la pagina.
 */
const HTTP_POR_CODIGO = {
  [CODES.PARAM_INVALIDO]: 400,
  [CODES.ENTRADA_VACIA]: 400,
  [CODES.FICHERO_NO_ENCONTRADO]: 404,
  [CODES.CREDENCIAL_AUSENTE]: 503,
  [CODES.CREDENCIAL_INVALIDA]: 401,
  [CODES.TIMEOUT]: 504,
  [CODES.RED]: 502,
  [CODES.API_EXTERNA]: 502,
  [CODES.API_CUOTA]: 429,
  [CODES.SMTP_RECHAZADO]: 502,
  [CODES.TLS_INVALIDO]: 502,
  [CODES.DNS_SIN_REGISTROS]: 200,
  [CODES.INTERNO]: 500
};

/** Traduce una excepcion a una respuesta HTTP con su codigo. */
function responderError(res, error) {
  const envuelto = error instanceof NetlabError ? error : wrap(error);
  const estado = HTTP_POR_CODIGO[envuelto.code] || 500;

  // El interior de un error ajeno puede traer una traza con rutas del
  // servidor. Al navegador solo sale el mensaje si el error es del dominio.
  const cuerpo = {
    error: {
      code: envuelto.code,
      message: envuelto.message,
      remediation: envuelto.remediation || null,
      details: envuelto.details || null
    }
  };

  if (!envuelto.expose) {
    cuerpo.error.message = 'Error interno del servidor.';
    cuerpo.error.remediation = null;
    cuerpo.error.details = null;
  }

  res.status(estado).json(cuerpo);
}

/**
 * Construye la aplicacion.
 *
 * @param {object} [opciones]
 * @param {object} [opciones.auth] Instancia de {@link Auth} para las pruebas.
 * @param {object} [opciones.historial] Instancia de {@link Historial} para las pruebas.
 * @param {number} [opciones.maxEjecuciones=4] Cuantas ejecuciones a la vez.
 * @param {number} [opciones.maxPorMinuto=30] Tope por minuto y usuario.
 * @returns {{app: import('express').Express, auth: Auth, historial: Historial}}
 */
function crearApp(opciones = {}) {
  const app = express();

  const auth = opciones.auth || new Auth();
  const historial = opciones.historial || new Historial();
  const auditoria = opciones.auditoria || obtenerAuditoria();
  const metricas = opciones.metricas || obtenerMetricas();

  const maxEjecuciones = opciones.maxEjecuciones ?? 4;
  const maxPorMinuto = opciones.maxPorMinuto ?? 30;

  let enCurso = 0;
  /** @type {Map<string, number[]>} */
  const recently = new Map();

  // ---------------------------------------------------------------- cuerpo
  // El limite es 2 MB porque `dns-checker` acepta un archivo de hasta 1 MB y
  // llega como texto dentro del JSON. El limite va en el servidor y no solo en
  // el campo, para que un cliente que no pase por el formulario tambien tope.
  app.use(express.json({ limit: '2mb' }));

  app.disable('x-powered-by');

  // Confianza en las cabeceras de proxy (X-Forwarded-For).
  //
  // El despliegue recomendado es netlab en localhost con nginx/caddy delante,
  // y ahi la IP real del cliente SOLO viaja en X-Forwarded-For. Con
  // `trust proxy` en false, `req.ip` vale 127.0.0.1 en todas las peticiones, y
  // eso rompe dos cosas a la vez:
  //   - el limite por IP pasa a ser global, asi que un intento de fuerza bruta
  //     bloquea el login de todo el mundo;
  //   - la auditoria registra siempre 127.0.0.1 y no sirve para nada.
  //
  // Por defecto se confia solo en el loopback ('loopback'): se leen esas
  // cabeceras unicamente si quien conecta es la propia maquina, de modo que un
  // cliente que llegue directamente desde Internet no puede inventarse su IP.
  // Se puede cambiar con TRUST_PROXY:
  //   loopback (por defecto) | false | true | <numero de saltos>
  const confianza = config.leer('TRUST_PROXY') || 'loopback';
  const trustProxy = /^\d+$/.test(confianza) ? Number(confianza) : ['true', 'false'].includes(confianza) ? confianza === 'true' : confianza;
  app.set('trust proxy', trustProxy);

  // Cabeceras de seguridad. La politica de contenido es `default-src 'self'`:
  // todo el JavaScript y el CSS estan en archivos proprios, sin scripts en
  // linea, asi que no hace falta abrir Exceptions para que funcione.
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    );
    next();
  });

  // Métricas Prometheus - middleware para colectar métricas de requests
  app.use((req, res, next) => {
    const inicio = process.hrtime.bigint();
    res.on('finish', () => {
      const duracionMs = Number(process.hrtime.bigint() - inicio) / 1e6;
      const ruta = req.route?.path || req.path;
      const metodo = req.method;
      const status = res.statusCode;

      metricas.incrementar('http_requests_total', { metodo, ruta, status: String(status) });
      metricas.observar('http_request_duration_seconds', { metodo, ruta }, duracionMs / 1000);
    });
    next();
  });

  // ---------------------------------------------------------------- sesion
  /** Identidad de la peticion, calculada una vez y colgada en `req`. */
  app.use((req, _res, next) => {
    req.auth = auth.identidad(req);
    next();
  });

  // ------------------------------------------------------------ setup inicial
  /**
   * Dice si falta crear el administrador principal.
   *
   * No lleva `exigeSesion` a proposito: es la unica peticion que se puede hacer
   * sin tener cuenta, y solo responde si falta o si ya esta hecho.
   */
  app.get('/api/setup/status', (_req, res) => {
    const usuarios = auth.usuarios;
    const completado = !auth.activo || (usuarios ? usuarios.contar() > 0 : false);
    res.json({ completado, requiereSetup: !completado });
  });

  /**
   * Crea el administrador principal.
   *
   * Se cierra en cuanto hay un usuario: en cuanto existe la primera cuenta, esta
   * ruta responde 403. Si no se cerrara, cualquiera que llegara al servidor
   * despues del despliegue podria crear su propia cuenta de administrador.
   *
   * Tampoco exige sesion ni CSRF, porque a esta altura no hay ninguna sesion que
   * valga. La unica garantia es el cierre anterior: mientras no haya usuarios, no
   * hay nada que proteger todavia.
   */
  app.post('/api/setup/first-admin', (req, res) => {
    if (!auth.activo) {
      return res.json({ ok: true, mensaje: 'Autenticación desactivada, no requiere setup.' });
    }
    const usuarios = auth.usuarios;
    if (!usuarios) {
      return res.status(500).json({ error: { code: 'ERROR_INTERNO', message: 'Usuarios no inicializado.' } });
    }
    if (usuarios.contar() > 0) {
      return res.status(403).json({
        error: {
          code: 'SETUP_YA_COMPLETADO',
          message: 'El setup inicial ya fue completado.',
          remediation: 'Entra con la cuenta de administrador que ya existe.',
          details: null
        }
      });
    }
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({
        error: { code: 'FALTAN_DATOS', message: 'Usuario y contraseña son obligatorios.', remediation: null, details: null }
      });
    }
    if (password.length < 8) {
      return res.status(400).json({
        error: {
          code: 'PASSWORD_CORTA',
          message: 'La contraseña debe tener al menos 8 caracteres.',
          remediation: null,
          details: null
        }
      });
    }
    try {
      const u = usuarios.crear({ username, password, role: 'admin' });
      auditoria.registrar({ tipo: 'setup_admin_creado', usuario: u.username, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida') });
      res.status(201).json({ ok: true, usuario: u });
    } catch (e) {
      responderError(res, e);
    }
  });

  /**
   * Exige sesion iniciada. En modo local pasa siempre.
   *
   * @param {object} req
   * @param {object} res
   * @param {Function} next
   */
  function exigeSesion(req, res, next) {
    if (auth.activo && !req.auth.usuario) {
      return res.status(401).json({
        error: { code: 'SIN_SESION', message: 'Hay que iniciar sesión.', remediation: null, details: null }
      });
    }
    next();
  }

  /**
   * Exige el token CSRF en las peticiones que cambian algo.
   *
   * @param {object} req
   * @param {object} res
   * @param {Function} next
   */
  function exigeCsrf(req, res, next) {
    if (!auth.csrfValido(req)) {
      return res.status(403).json({
        error: {
          code: 'CSRF_INVALIDO',
          message: 'Falta el token de seguridad de la sesión.',
          remediation: 'Recarga la página y vuelve a intentarlo.',
          details: null
        }
      });
    }
    next();
  }

  app.get('/api/sesion', (req, res) => {
    const autenticado = !auth.activo || Boolean(req.auth.usuario);
    res.json({
      autenticado,
      local: !auth.activo,
      usuario: req.auth.usuario || null,
      role: req.auth.role || (auth.activo ? null : 'admin'),
      modoTextoPlano: auth.enTextoPlano,
      // En modo local no hace falta token, pero se manda uno igualmente para que
      // el cliente no tenga dos caminos distintos segun la configuracion.
      csrf: autenticado ? (req.headers['x-csrf-token'] ? String(req.headers['x-csrf-token']) : auth.nuevoCsrf()) : null,
      herramientas: registro().herramientas.length,
      avisos: registro().avisos
    });
  });

  app.post('/api/sesion', (req, res) => {
    const ip = String(req.ip || req.socket?.remoteAddress || 'desconocida');
    const { usuario, password } = req.body || {};

    if (!auth.activo) {
      return res.json({ autenticado: true, local: true, usuario: 'local', csrf: null, mensaje: 'Autenticación desactivada.' });
    }

    const entrada = auth.entrar(usuario, password, ip);

    if (!entrada.ok) {
      if (entrada.motivo === 'demasiados') {
        return res.status(429).json({
          error: {
            code: 'DEMASIADOS_INTENTOS',
            message: 'Demasiados intentos de acceso.',
            remediation: `Espera ${entrada.reintentarEn} segundos y vuelve a intentarlo.`,
            details: { reintentarEn: entrada.reintentarEn }
          }
        });
      }
      // Mismo mensaje para usuario inexistente y contraseña incorrecta, para no
      // decir cual de las dos cosas fallo.
      return res.status(401).json({
        error: { code: 'CREDENCIAL_INVALIDA', message: 'Usuario o contraseña incorrectos.', remediation: null, details: null }
      });
    }

  // Login exitoso - registrar y responder
  auditoria.registrar({ tipo: 'login_exitoso', usuario: entrada.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida') });
  res.setHeader('Set-Cookie', auth.cookieSesion(entrada.cookie, req));
  res.json({ autenticado: true, local: false, usuario: entrada.usuario, role: entrada.role, csrf: entrada.csrf });
});

  app.delete('/api/sesion', exigeSesion, exigeCsrf, (req, res) => {
    const token = leerCookie(req.headers.cookie, NOMBRE_COOKIE);
    if (token) auth.salir(token);
    auditoria.registrar({ tipo: 'logout', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida') });
    res.setHeader('Set-Cookie', auth.cookieCierre());
    res.json({ autenticado: false, mensaje: 'Sesión cerrada.' });
  });

  // ------------------------------------------------------------ usuarios
  // Solo administradores pueden gestionar usuarios
  function exigeAdmin(req, res, next) {
    if (!auth.activo) return next();
    if (req.auth.role !== 'admin') {
      return res.status(403).json({
        error: { code: 'SIN_PERMISOS', message: 'Se requieren permisos de administrador.', remediation: null, details: null }
      });
    }
    next();
  }

  app.get('/api/usuarios', exigeSesion, exigeAdmin, (_req, res) => {
    const usuarios = auth.usuarios.listar();
    res.json({ usuarios: usuarios.map(u => ({ id: u.id, username: u.username, role: u.role, activo: u.activo, createdAt: u.createdAt, lastLogin: u.lastLogin })) });
  });

  app.post('/api/usuarios', exigeSesion, exigeAdmin, exigeCsrf, (req, res) => {
    const { username, password, role = 'user' } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: { code: 'FALTAN_DATOS', message: 'Usuario y contraseña son obligatorios.', remediation: null, details: null } });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: { code: 'PASSWORD_CORTA', message: 'La contraseña debe tener al menos 8 caracteres.', remediation: null, details: null } });
    }
    if (!['admin', 'user'].includes(role)) {
      return res.status(400).json({ error: { code: 'ROL_INVALIDO', message: 'El rol debe ser "admin" o "user".', remediation: null, details: null } });
    }
    try {
      const u = auth.usuarios.crear({ username, password, role });
      auditoria.registrar({ tipo: 'usuario_creado', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida'), detalles: { nuevoUsuario: u.username, role: u.role } });
      res.status(201).json({ usuario: u });
    } catch (e) {
      if (e.message.includes('ya existe')) {
        return res.status(409).json({ error: { code: 'USUARIO_EXISTE', message: e.message, remediation: null, details: null } });
      }
      responderError(res, e);
    }
  });

  app.patch('/api/usuarios/:id', exigeSesion, exigeAdmin, exigeCsrf, (req, res) => {
    const { password, role, activo } = req.body || {};
    if (!auth.usuarios.obtener(req.params.id)) {
      return res.status(404).json({ error: { code: 'NO_ENCONTRADO', message: 'Usuario no encontrado.', remediation: null, details: null } });
    }
    if (password && password.length < 8) {
      return res.status(400).json({ error: { code: 'PASSWORD_CORTA', message: 'La contraseña debe tener al menos 8 caracteres.', remediation: null, details: null } });
    }
    if (role && !['admin', 'user'].includes(role)) {
      return res.status(400).json({ error: { code: 'ROL_INVALIDO', message: 'El rol debe ser "admin" o "user".', remediation: null, details: null } });
    }
    const ok = auth.usuarios.actualizar(req.params.id, { password, role, activo });
    auditoria.registrar({ tipo: 'usuario_actualizado', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida'), detalles: { usuarioId: req.params.id, cambios: { password: !!password, role, activo } } });
    res.json({ actualizado: ok });
  });

  app.delete('/api/usuarios/:id', exigeSesion, exigeAdmin, exigeCsrf, (req, res) => {
    // Evitar borrar el propio usuario admin
    if (req.auth.usuario && req.params.id === auth.usuarios.obtener(req.auth.usuario)?.id) {
      return res.status(400).json({ error: { code: 'NO_AUTO_BORRAR', message: 'No puedes borrar tu propio usuario.', remediation: null, details: null } });
    }
    const ok = auth.usuarios.borrar(req.params.id);
    auditoria.registrar({ tipo: 'usuario_borrado', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida'), detalles: { usuarioId: req.params.id } });
    res.status(ok ? 200 : 404).json({ borrado: ok });
  });

  // ------------------------------------------------------------ auditoría
  app.get('/api/auditoria', exigeSesion, exigeAdmin, (req, res) => {
    const { tipo, usuario, limite, desde } = req.query;
    res.json(auditoria.listar({
      tipo: tipo ? String(tipo) : null,
      usuario: usuario ? String(usuario) : null,
      limite: limite ? Number(limite) : undefined,
      desde: desde ? Number(desde) : undefined
    }));
  });

  app.post('/api/auditoria/limpiar', exigeSesion, exigeAdmin, exigeCsrf, (req, res) => {
    const { dias = 90 } = req.body || {};
    const borrados = auditoria.limpiar(Number(dias) || 90);
    res.json({ borrados });
  });

  // ----------------------------------------------------------- herramientas
  app.get('/api/herramientas', exigeSesion, (_req, res) => {
    res.json({ herramientas: listarHerramientas(), avisos: registro().avisos });
  });

  // ------------------------------------------------------------------- run
  app.post('/api/run', exigeSesion, exigeCsrf, async (req, res) => {
    const cuerpo = req.body || {};
    const herramienta = obtenerHerramienta(cuerpo.tool);

    if (!herramienta) {
      return res.status(404).json({
        error: {
          code: 'HERRAMIENTA_DESCONOCIDA',
          message: `No existe la herramienta «${cuerpo.tool || ''}».`,
          remediation: 'Consulta GET /api/herramientas para ver las disponibles.',
          details: null
        }
      });
    }

    const owner = req.auth.usuario || 'local';

    // Tope por minuto y por dueño. Una ejecucion sale a Internet y abre hasta
    // ocho consultas DNSBL: sin este tope, un formulario abierto en una pagina
    // reenviada seria una forma barata de cargar la red desde el servidor.
    const ahora = Date.now();
    const previos = (recently.get(owner) || []).filter((t) => ahora - t < 60_000);
    if (previos.length >= maxPorMinuto) {
      return res.status(429).json({
        error: {
          code: 'DEMASIADAS_EJECUCIONES',
          message: `Has llegado al límite de ${maxPorMinuto} ejecuciones por minuto.`,
          remediation: 'Espera un momento.',
          details: null
        }
      });
    }

    if (enCurso >= maxEjecuciones) {
      return res.status(429).json({
        error: {
          code: 'SERVICIO_OCUPADO',
          message: 'Ya hay ejecuciones en curso.',
          remediation: 'Espera a que terminen.',
          details: { enCurso, maxEjecuciones }
        }
      });
    }

    let params;
    try {
      const validado = validar(herramienta.campos, cuerpo.params);
      params = validado.params;
      req.avisosValidacion = validado.avisos;
    } catch (e) {
      return responderError(res, e);
    }

    enCurso++;
    auditoria.registrar({ tipo: 'ejecucion_iniciada', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida'), detalles: { tool: herramienta.id, target: cuerpo.params?.url || cuerpo.params?.ip || cuerpo.params?.red || '' } });
    try {
      const result = await herramienta.modulo.ejecutar(params, { tool: herramienta.id });
      // La herramienta ya limpia la contraseña de `result.params`, pero el
      // registro del historial guarda los params validados, con el valor tal
      // cual. Se enmascara aquí: la huella tampoco debe cambiar por la clave.
      const paramsGuardables = redactDeep(params);
      const guardada = historial.guardar({ tool: herramienta.id, params: paramsGuardables, result, owner });

      let shareUrl = null;
      let expiraEn = null;
      if (params.compartir === true) {
        const share = historial.crearCompartido({ ejecucionId: guardada.id, owner, ttlDias: params.ttlDiasCompartir });
        shareUrl = share.shareUrl;
        expiraEn = share.expiraEn;
        if (result.summary) {
          addSummary(result, 'Enlace compartido', shareUrl, 'ok');
          addSummary(result, 'Expira', new Date(expiraEn).toLocaleString('es-ES'), 'neutral');
        }
        auditoria.registrar({ tipo: 'compartir_creado', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida'), detalles: { ejecucionId: guardada.id, shareUrl, expiraEn } });
      }

      auditoria.registrar({ tipo: 'ejecucion_completada', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida'), detalles: { ejecucionId: guardada.id, status: result.status, headline: result.headline } });

      res.json({
        id: guardada.id,
        duplicado: guardada.duplicado,
        avisos: req.avisosValidacion || [],
        result,
        shareUrl,
        expiraEn
      });
    } catch (e) {
      auditoria.registrar({ tipo: 'ejecucion_fallida', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida'), detalles: { tool: herramienta.id, error: e.message } });
      responderError(res, e);
    } finally {
      enCurso--;
      previos.push(ahora);
      recently.set(owner, previos);
    }
  });

  app.get('/api/run/:id', exigeSesion, (req, res) => {
    const encontrado = historial.obtener(req.params.id, req.auth.usuario || 'local');
    if (!encontrado) {
      return res.status(404).json({
        error: { code: 'NO_ENCONTRADO', message: 'Esa ejecución no existe.', remediation: null, details: null }
      });
    }
    res.json({ id: req.params.id, duplicado: false, avisos: [], result: encontrado.result, registro: encontrado.registro });
  });

  app.get('/api/run/:id/:formato', exigeSesion, async (req, res) => {
    const encontrado = historial.obtener(req.params.id, req.auth.usuario || 'local');
    if (!encontrado || !encontrado.result) {
      return res.status(404).json({
        error: { code: 'NO_ENCONTRADO', message: 'Esa ejecución no existe.', remediation: null, details: null }
      });
    }

    const formato = String(req.params.formato).toLowerCase();
    if (!formats.soportados().some((f) => f.nombre === formato)) {
      return res.status(400).json({
        error: {
          code: 'FORMATO_DESCONOCIDO',
          message: `Formato «${req.params.formato}» no soportado.`,
          remediation: `Disponibles: ${formats.soportados().map((f) => f.nombre).join(', ')}.`,
          details: null
        }
      });
    }

    try {
      // Se vuelve a renderizar desde el Result guardado, no se guarda el
      // informe ya hecho. Asi corregir el PDF vale para todo el historico.
      const contenido = await formats.render(encontrado.result, formato);
      auditoria.registrar({ tipo: 'formato_descargado', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida'), detalles: { ejecucionId: req.params.id, formato } });
      res.setHeader('Content-Type', formats.mime(formato));
      res.setHeader('Content-Length', contenido.length);
      res.setHeader('X-Netlab-Id', req.params.id);
      if (formato === 'json' || formato === 'txt' || formato === 'md' || formato === 'html') {
        res.setHeader('Content-Disposition', `inline; filename="netlab_${req.params.id.slice(0, 8)}.${formato}"`);
      } else {
        res.setHeader('Content-Disposition', `attachment; filename="netlab_${req.params.id.slice(0, 8)}.${formato}"`);
      }
      res.end(contenido);
    } catch (e) {
      responderError(res, e);
    }
  });

  // --------------------------------------------------------------- historial
  app.get('/api/historial', exigeSesion, (req, res) => {
    res.json(
      historial.listar({
        owner: req.auth.usuario || 'local',
        tool: req.query.tool ? String(req.query.tool) : null,
        limite: req.query.limite,
        desde: req.query.desde
      })
    );
  });

  app.get('/api/historial/:id', exigeSesion, (req, res) => {
    const encontrado = historial.obtener(req.params.id, req.auth.usuario || 'local');
    if (!encontrado) {
      return res.status(404).json({
        error: { code: 'NO_ENCONTRADO', message: 'Esa ejecución no existe.', remediation: null, details: null }
      });
    }
    res.json({ ...encontrado, archivos: historial.archivos(req.params.id) });
  });

  app.delete('/api/historial/:id', exigeSesion, exigeCsrf, (req, res) => {
    const borrado = historial.borrar(req.params.id, req.auth.usuario || 'local');
    res.status(borrado ? 200 : 404).json({ borrado });
  });

  // ------------------------------------------------------------ compartir
  app.post('/api/compartir', exigeSesion, exigeCsrf, (req, res) => {
    const { ejecucionId, ttlDias } = req.body || {};
    if (!ejecucionId) {
      return res.status(400).json({
        error: { code: 'FALTA_EJECUCION', message: 'Falta el ID de la ejecución.', remediation: 'Proporciona ejecucionId en el cuerpo.', details: null }
      });
    }

    const owner = req.auth.usuario || 'local';
    const encontrado = historial.obtener(ejecucionId, owner);
    if (!encontrado) {
      return res.status(404).json({
        error: { code: 'NO_ENCONTRADO', message: 'Esa ejecución no existe o no es tuya.', remediation: null, details: null }
      });
    }

    try {
      const share = historial.crearCompartido({ ejecucionId, owner, ttlDias });
      auditoria.registrar({ tipo: 'compartir_creado', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida'), detalles: { ejecucionId, shareUrl: share.shareUrl, expiraEn: share.expiraEn } });
      res.json({ shareUrl: share.shareUrl, expiraEn: share.expiraEn });
    } catch (e) {
      responderError(res, e);
    }
  });

  app.delete('/api/compartir/:shareToken', exigeSesion, exigeCsrf, (req, res) => {
    const owner = req.auth.usuario || 'local';
    const revocado = historial.revocarCompartido(req.params.shareToken, owner);
    auditoria.registrar({ tipo: 'compartir_revogado', usuario: req.auth.usuario, ip: String(req.ip || req.socket?.remoteAddress || 'desconocida'), detalles: { shareToken: req.params.shareToken } });
    res.status(revogado ? 200 : 404).json({ revocado });
  });

  // Public endpoint para ver informe compartido (sin autenticación)
app.get('/r/:shareToken', async (req, res) => {
    // El informe compartido es un documento autónomo: su CSS va en un <style>
    // inline y su navegacion en un <script> inline, a proposito (tiene que
    // abrirse sin servidor, guardarse como evidencia y seguir viendose igual).
    // El CSP global es `default-src 'self'`, que bloquea ambos y deja el
    // informe en HTML crudo sin estilos. Se relaja solo para esta ruta, sin
    // abrir ningun origen externo.
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    );
    const share = historial.obtenerCompartido(req.params.shareToken);
    if (!share) {
      return res.status(410).type('html').send(
        '<!doctype html><meta charset="utf-8"><title>Enlace expirado</title>' +
        '<style>body{font:16px/1.5 system-ui;max-width:500px;margin:60px auto;padding:0 20px;text-align:center}</style>' +
        '<h1>Enlace expirado o revocado</h1>' +
        '<p>Este enlace de compartici��n ya no es vǭlido.</p>' +
        '<p><a href="/">Volver a netlab</a></p>'
      );
    }

    const encontrado = historial.obtener(share.ejecucionId, share.owner);
    if (!encontrado || !encontrado.result) {
      return res.status(404).type('html').send(
        '<!doctype html><meta charset="utf-8"><title>No encontrado</title>' +
        '<style>body{font:16px/1.5 system-ui;max-width:500px;margin:60px auto;padding:0 20px;text-align:center}</style>' +
        '<h1>Informe no disponible</h1>' +
        '<p>El resultado asociado a este enlace ya no existe.</p>' +
        '<p><a href="/">Volver a netlab</a></p>'
      );
    }

    try {
      const pie = `Compartido desde netlab �� Expira el ${new Date(share.expiraEn).toLocaleString('es-ES')}`;
      const shareUrl = `${req.protocol}://${req.get('host')}/r/${req.params.shareToken}`;
      const shareExpira = new Date(share.expiraEn).toLocaleString('es-ES');
      const shareAutor = share.owner;
      const html = await formats.render(encontrado.result, 'html', {
        standalone: true,
        pie,
        shared: true,
        shareUrl,
        shareExpira,
        shareAutor
      });
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache');
      res.end(html);
    } catch (e) {
      responderError(res, e);
    }
  });

  // ----------------------------------------------------------------- varios
  app.get('/api/formats', exigeSesion, (_req, res) => {
    res.json({ formatos: formats.soportados() });
  });

  app.get('/api/config', exigeSesion, (_req, res) => {
    // Solo datos publicables. Las credenciales del entorno no se consultan
    // aqui en ningun caso: lo unico que sale es si hay algo configurado.
    res.json({
      marca: config.leer('REPORT_BRAND') || 'netlab',
      perfilesCorreo: config.listarPerfilesCorreo(),
      abuseipdb: config.definida('ABUSEIPDB_API_KEY')
    });
  });

  // Endpoint de métricas Prometheus (sin autenticación para que Prometheus pueda raspar)
  app.get('/metrics', (_req, res) => {
    res.setHeader('Content-Type', metricas.getContentType());
    res.end(metricas.generar());
  });

  app.use('/api', (_req, res) => {
    res.status(404).json({ error: { code: 'RUTA_DESCONOCIDA', message: 'Esa ruta no existe.', remediation: null, details: null } });
  });

  // ------------------------------------------------------------- estaticos
  // La interfaz es `web/dist`, y solo existe si alguien ha ejecutado el build.
  // Antes no hacia falta: `public/` se servia tal cual, sin compilar. Ahora, sin
  // `npm run build`, `/` daria un 404 sin explicación, que es la peor forma de
  // enterarse. Se dice qué falta.
  const raiz = DIR_SPA;
  if (!fs.existsSync(path.join(raiz, 'index.html'))) {
    app.get('/', (_req, res) => {
      res
        .status(503)
        .type('html')
        .send(
          '<!doctype html><meta charset="utf-8"><title>netlab</title>' +
            '<h1>Falta compilar la interfaz</h1>' +
            '<p>La interfaz web vive en <code>web/dist</code>, que se genera al compilar. No hay nada que servir todavia.</p>' +
            '<p>Ejecuta <code>npm run build</code> en el proyecto y recarga.</p>'
        );
    });
  }

  app.use(
    express.static(raiz, {
      index: 'index.html',
      // `index.html` nunca se cachea: es el que apunta a los JS y CSS con hash,
      // y cachearlo es como se sirve una version vieja de la aplicacion.
      // Los ficheros de `assets/` si llevan hash en el nombre, asi que se pueden
      // cachear para siempre: si cambian, cambia tambien su nombre.
      //
      // El resto de cabeceras (CSP, nosniff, referrer) las pone el middleware
      // global de arriba; repetirlas aqui solo crea dos sitios que editar.
      setHeaders(res, ruta) {
        const enAssets = ruta.includes(`${path.sep}assets${path.sep}`);
        res.setHeader('Cache-Control', enAssets ? 'public, max-age=31536000, immutable' : 'no-cache');
      }
    })
  );

  // Fallback del SPA. Sin esto, recargar en `/historial` o abrir un enlace
  // profundo a `/herramienta/smtp-validator?run=abc` devuelve 404: el servidor
  // busca un fichero llamado `historial` y no existe, porque la ruta la resuelve
  // el navegador y no el servidor.
  //
  // Solo para peticiones sin extension: si falta un asset con hash, devolver el
  // `index.html` con un 200 haria que el fallo se manifestara como un error de
  // JavaScript en lugar de como un 404 de un asset, que es lo que de verdad es.
  app.get('*', (req, res, next) => {
    if (path.extname(req.path)) return next();
    const entrada = path.join(raiz, 'index.html');
    if (!fs.existsSync(entrada)) return next();
    res.setHeader('Cache-Control', 'no-cache');
    return res.sendFile(entrada);
  });

  // Ultimo, porque un error de una ruta sin manejar debe caer aqui y no dejar
  // la peticion colgada.
  app.use((error, _req, res, _next) => {
    if (error?.type === 'entity.too.large') {
      return res.status(413).json({
        error: {
          code: 'CUERPO_DEMASIADO_GRANDE',
          message: 'El archivo enviado supera el límite de 2 MB.',
          remediation: 'Reduce el tamaño del archivo y vuelve a intentarlo.',
          details: null
        }
      });
    }
    if (error instanceof SyntaxError && 'body' in error) {
      return res.status(400).json({
        error: { code: 'JSON_INVALIDO', message: 'El cuerpo de la petición no es JSON válido.', remediation: null, details: null }
      });
    }
    responderError(res, error);
  });

  return { app, auth, historial, auditoria, metricas };
}

module.exports = { crearApp, HTTP_POR_CODIGO, DIR_SPA };
