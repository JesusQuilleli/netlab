/**
 * manual.js - Genera el manual de netlab en PDF.
 *
 * MODULO DE DOCUMENTACION. No es un informe de diagnostico: no recibe un Result
 * ni depende de ninguna herramienta. Toma la lista de herramientas del registro
 * y explica, para cada modulo del sistema, que hace, para que sirve y que
 * problema resuelve.
 *
 * El texto vive aqui, no en el generador de PDF, para que el manual se pueda
 * revisar como codigo y no haya que recompilar el frontend para corregir una
 * frase.
 *
 * @module docs/manual
 */

'use strict';

const path = require('node:path');
const fs = require('node:fs');
const doc = require('../formats/pdf/doc');
const { COLORES, TIPOGRAFIA, PAGINA, sanear } = require('../formats/pdf/theme');
const { registro } = require('../server/herramientas');

/**
 * Contenido del manual: una entrada por seccion.
 *
 * Cada modulo sigue la misma quartet: que hace, para que sirve, que soluciona y
 * su flujo. Se mantiene aqui en vez de generarlo del codigo porque el codigo
 * dice COMO, no PARA QUE.
 */
const MODULOS = [
  {
    id: 'autenticacion',
    titulo: 'Autenticacion y sesiones',
    resumen: 'Quien entra, con que prueba y durante cuanto tiempo.',
    hace: [
      'Valida usuario y contrasena contra la tabla de usuarios de SQLite.',
      'Emite una cookie de sesion firmada, opaca y aleatoria, marcada HttpOnly y SameSite=Strict.',
      'Emite un token CSRF independiente que debe viajar en la cabecera X-CSRF-Token en toda peticion que modifique datos.',
      'Caduca la sesion a las 8 horas y el token CSRF a las 2 horas.',
      'Limita a 8 los intentos de acceso por IP cada 15 minutos, con espera creciente.',
      'Cierra las sesiones al reiniciar el servidor: la sesion vive en memoria, no en disco.'
    ],
    sirve: 'Para que solo quien tiene cuenta pueda lanzar diagnosticos desde el servidor, y para que una pagina de terceros no pueda suplantar al navegador que ya esta dentro.',
    soluciona: [
      'Un puerto de diagnostico abierto a Internet es un escaner de ports gratuito para cualquiera que llegue al puerto.',
      'El robo de cookie por JavaScript de terceros: la cookie es HttpOnly, asi que no se puede leer desde la pagina.',
      'El CSRF: un sitio ajeno puede pedir al navegador que envie la cookie, pero no puede conocer el token que va en la cabecera.',
      'La fuerza bruta: el limite por IP corta los intentos repetidos aunque las credenciales sean adivinables.'
    ],
    flujo: [
      'El usuario envia POST /api/sesion con usuario y contrasena.',
      'El servidor comprueba el limite de intentos de esa IP. Si se pasa, responde 429 con los segundos que faltan.',
      'Se verifica la contrasena con scrypt. Si falla, la respuesta es la misma para usuario inexistente y contrasena incorrecta.',
      'Si es correcta, se crea el token de sesion y el token CSRF, se devuelve la cookie y el cliente guarda el CSRF.',
      'Cada peticion posterior se identifica con la cookie; las que modifican datos ademas exigen la cabecera del CSRF.',
      'DELETE /api/sesion cierra la sesion y borra la cookie.'
    ]
  },
  {
    id: 'setup-inicial',
    titulo: 'Configuracion del administrador principal',
    resumen: 'El primer ingreso al sistema obliga a crear la cuenta que gobierna todas las demas.',
    hace: [
      'Al cargar la pagina, el cliente consulta GET /api/setup/status.',
      'Si la tabla de usuarios esta vacia, el servidor responde que el setup esta pendiente y la web muestra el formulario de administrador principal en lugar del login.',
      'POST /api/setup/first-admin crea el primer usuario con rol admin. La contrasena se guarda con scrypt, nunca en texto plano.',
      'En cuanto existe un usuario, la ruta responde 403 y deja de ser utilizable: el setup no se puede repetir.',
      'Toda la creacion queda registrada en la auditoria con el tipo setup_admin_creado y la IP de origen.',
      'Si la autenticacion esta desactivada (AUTH_ENABLED=false), el setup no aplica: el sistema ya corre como administrador local.'
    ],
    sirve: 'Para que nunca exista un despliegue en produccion sin un administrador, y para que ese administrador sea siempre el primero que entro, no alguien que se registro antes que el.',
    soluciona: [
      'El despliegue que se queda sin admin: hasta ahora habia que crear el admin con un comando manual por SSH, y ese paso se puede saltar.',
      'La ventana de tiempo en la que el sistema es accesible sin control de acceso.',
      'La duda de quien decide los permisos: el administrador principal queda registrado en auditoria desde el primer momento.'
    ],
    flujo: [
      'Se abre la pagina y el navegador pide GET /api/setup/status.',
      'Si la respuesta es completado: false, se muestra el formulario de configuracion del administrador principal.',
      'Elige nombre de usuario y contrasena de al menos 8 caracteres, y la repite para confirmar.',
      'El navegador envia POST /api/setup/first-admin.',
      'El servidor comprueba que no haya ningun usuario. Si los hay, responde 403 y no hace nada.',
      'Si no hay ninguno, crea el admin, lo registra en auditoria y responde 201.',
      'La pagina vuelve a consultar el estado, ahora completado, y muestra el login normal.'
    ]
  },
  {
    id: 'administracion',
    titulo: 'Administracion de usuarios',
    resumen: 'El administrador principal da de alta, edita y desactiva el resto de cuentas.',
    hace: [
      'GET /api/usuarios devuelve la lista de cuentas con rol, estado, fecha de creacion y ultimo acceso.',
      'POST /api/usuarios crea una cuenta nueva con rol user o admin. La contrasena minima es de 8 caracteres.',
      'PATCH /api/usuarios/:id cambia contrasena, rol o estado activo. El nombre de usuario no se puede cambiar.',
      'DELETE /api/usuarios/:id borra la cuenta, con la excepcion de que un administrador no puede borrarse a si mismo.',
      'Todas las operaciones exigen rol admin y token CSRF, y todas dejan rastro en la auditoria.',
      'El rol decide el alcance: un usuario normal usa las herramientas y ve su historial; un administrador accede tambien a esta pantalla y a la auditoria.'
    ],
    sirve: 'Para dar acceso a un equipo sin compartir la misma contrasena, y para poder cortar el acceso de una persona concreta sin tocar el servidor.',
    soluciona: [
      'La contrasena unica compartida por todo el equipo, que no permite saber quien hizo cada consulta.',
      'El caso de una persona que deja la empresa y sigue entrando porque su cuenta nunca se desactivo.',
      'La necesidad de saber que accounts existen y cuando se usaron por ultima vez.'
    ],
    flujo: [
      'El administrador entra con su cuenta y abre /admin. Un usuario normal que intente esa ruta es devuelto a la pagina principal.',
      'Pulsa Nuevo usuario y rellena nombre, contrasena, rol y estado.',
      'El navegador envia POST /api/usuarios con el token CSRF.',
      'El servidor exige rol admin, comprueba la longitud de la contrasena y que el nombre no este ocupado.',
      'La cuenta se crea y el evento queda en la auditoria.',
      'Para cambiar o desactivar una cuenta, pulsa Editar, ajusta lo necesario y guarda con PATCH.',
      'Para eliminar una cuenta, pulsa Borrar y confirma. El propio administrador no aparece con boton de borrar.'
    ]
  },
  {
    id: 'auditoria',
    titulo: 'Auditoria',
    resumen: 'Registro de quien hizo cada accion y desde que IP.',
    hace: [
      'Registra accesos correctos e incorrectos, cierre de sesion, ejecuciones lanzadas y completadas, ejecuciones fallidas, altas y cambios de usuarios, borrados, descargas de informe y creacion de enlaces compartidos.',
      'GET /api/auditoria filtra por tipo de evento, por usuario y por antiguedad, con limite de registros.',
      'POST /api/auditoria/limpiar borra los registros anteriores a un numero de dias, 90 por defecto.',
      'Los datos sensibles se guardan ya enmascarados: las contrasenas nunca llegan al registro de auditoria.',
      'Solo accesible con rol admin.'
    ],
    sirve: 'Para responder a la pregunta de quien lanzo una comprobacion concreta y que se obtuve, y para detectar accesos que no corresponden a nadie del equipo.',
    soluciona: [
      'La investigacion sin rastro: cuando un cliente pregunta por un informe de hace tres meses, no hay forma de saber si se llego a generar.',
      'El acceso indebido silencioso: una cuenta robada deja rastro con IP y hora.',
      'El crecimiento indefinido de la base de datos, con la limpieza por antiguedad.'
    ],
    flujo: [
      'Cualquier accion relevante dispara un registro con tipo, usuario, IP y momento.',
      'El administrador abre la auditoria y filtra por usuario o por tipo de evento.',
      'Revisa la lista y, si hace falta, borra los registros antiguos con el endpoint de limpieza.'
    ]
  },
  {
    id: 'herramientas',
    titulo: 'Herramientas de diagnostico',
    resumen: 'El catalogo de comprobaciones que netlab puede ejecutar.',
    hace: [
      'Cada herramienta declara su identificador, su titulo, su descripcion y los campos que necesita.',
      'El servidor no tiene una lista fija: descubre los ficheros de src/tools al arrancar, de modo que anadir una comprobacion es dejar el archivo.',
      'El formulario se construye a partir de los campos declarados, sin JavaScript especifico por herramienta.',
      'Cada ejecucion se valida en el servidor antes de salir a Internet, y se enmascara antes de guardarse.',
      'El resultado se devuelve con un veredicto, un resumen, secciones de detalle, hallazgos con su recomendacion y la telemetria de la ejecucion.'
    ],
    sirve: 'Para responder preguntas concretas de infraestructura y correo desde una sola herramienta, sin scripts sueltos por consola ni acceso al servidor.',
    soluciona: [
      'Cada diagnostico era antes un script independiente con su propia paleta, su formato de informe y su forma de numerar paginas.',
      'Los errores no se podian distinguir de un dato malo: ahora cada fallo tiene su codigo, su mensaje y lo que hay que hacer.',
      'Los informes no eran reproducibles: se vuelve a renderizar desde el resultado guardado, no desde el PDF ya hecho.'
    ],
    flujo: [
      'El usuario elige una herramienta del menu lateral.',
      'Rellena el formulario, que se ha construido con los campos que declara la herramienta.',
      'Pulsa Ejecutar y el navegador envia POST /api/run con el identificador y los parametros.',
      'El servidor valida los parametros, comprueba el limite por minuto y por usuario, y lanza la comprobacion.',
      'El resultado se guarda en el historial, ya enmascarado, y se devuelve al navegador.',
      'El informe muestra veredicto, resumen, detalle, hallazgos y telemetria, y se puede descargar en PDF, HTML, JSON, Markdown o TXT.'
    ]
  },
  {
    id: 'historial',
    titulo: 'Historial',
    resumen: 'Todas las ejecuciones, con quien las lanzo y que parametro se uso.',
    hace: [
      'GET /api/historial devuelve la lista paginada del usuario actual, con filtro opcional por herramienta.',
      'GET /api/historial/:id devuelve el detalle y los archivos generados.',
      'DELETE /api/historial/:id borra una ejecucion del historial.',
      'Cada ejecucion conserva el objetivo, el estado, la duracion y los parametros ya enmascarados.',
      'Un usuario solo ve lo suyo; el historial no es compartido entre cuentas.'
    ],
    sirve: 'Para no repetir la misma comprobacion cada vez que alguien pregunta, y para recuperar el informe de una ejecucion anterior.',
    soluciona: [
      'Repetir un diagnostico que ya se habia hecho: si la respuesta no cambio, volver a lanzarlo wastes tiempo y cuota de terceros.',
      'Perder un informe que estaba en pantalla y no se guardo.',
      'La confusion de quien lanzo una ejecucion: cada registro lleva su autor.'
    ],
    flujo: [
      'Tras una ejecucion, la entrada aparece sola en el historial reciente del menu lateral.',
      'Se abre /historial para verlas todas, con filtro por herramienta.',
      'Al abrir una, se ve el detalle completo y se puede volver a descargar en cualquier formato.',
      'Se puede borrar la entrada si ya no interesa.'
    ]
  },
  {
    id: 'informes',
    titulo: 'Informes y enlaces compartidos',
    resumen: 'Como se entrega el resultado y como se comparte con alguien de fuera.',
    hace: [
      'El mismo resultado se renderiza en PDF, HTML, JSON, Markdown y TXT.',
      'El renderizado se hace siempre desde el resultado guardado, no desde un informe ya impreso, de modo que corregir el formato mejora todo el historico.',
      'Una ejecucion se puede compartir mediante un enlace publico temporal, con caducidad configurable entre 1 y 90 dias.',
      'El enlace usa un token opaco que no revela el identificador interno ni el autor.',
      'Quien tiene el enlace puede abrir el informe sin iniciar sesion, y el enlace deja de funcionar al expirar o al revocarlo.',
      'El contenido publicado pasa antes por el enmascarado de secretos.'
    ],
    sirve: 'Para entregar a un cliente el resultado de un diagnostico sin darle acceso a la herramienta, y con la garantia de que el enlace dejara de servir dentro de un plazo.',
    soluciona: [
      'Enviar un informe que caduca mal y queda accesible para siempre.',
      'Dar credenciales de la herramienta a alguien que solo necesitaba leer un resultado.',
      'Tener cinco versiones distintas del mismo informe segun el formato, que se contradicen entre si.'
    ],
    flujo: [
      'Se lanza la comprobacion y, si procede, se marca la casilla de compartir y el numero de dias de validez.',
      'El servidor crea el enlace y devuelve su URL y su fecha de caducidad.',
      'Se copia el enlace y se envia a quien corresponda.',
      'Quien lo abre ve el informe en HTML sin necesidad de cuenta.',
      'Pasados los dias indicados, el enlace devuelve un aviso de caducidad; el propietario puede revocarlo antes.'
    ]
  },
  {
    id: 'metricas',
    titulo: 'Metricas',
    resumen: 'Contadores y tiempos de las peticiones, para vigilar el comportamiento del servicio.',
    hace: [
      'Cuenta peticiones HTTP por metodo, ruta y codigo de respuesta.',
      'Mide la duracion de cada peticion.',
      'Sirve el volcado de las metricas en formato Prometheus, para integrarlas en un sistema de monitorizacion.',
      'No registra ni valores enviados por el usuario ni credenciales: solo metodo, ruta, estado y tiempo.'
    ],
    sirve: 'Para saber si el servicio esta lento o saturado, y para detecting abnormalidades antes de que se conviertan en una caida.',
    soluciona: [
      'Descubrir un problema de rendimiento cuando ya lo estan sufriendo los usuarios.',
      'Tener datos de monitoring de la aplicacion sin instrumentarla a mano.'
    ],
    flujo: [
      'Cada peticion pasa por el middleware de metricas.',
      'Al terminar la respuesta, se incrementa el contador y se observa la duracion.',
      'El volcado se consulta para verlos en Grafana, Prometheus u otra herramienta compatible.'
    ]
  }
];

/**
 * Verifica si el sistema esta listo para produccion.
 *
 * Devuelve una lista de comprobaciones con su estado: 'ok', 'warn' o 'fail'.
 * Las de tipo 'fail' son las que impiden el despliegue.
 *
 * @returns {Array<{area: string, comprobacion: string, estado: string, detalle: string}>}
 */
function revisarProduccion() {
  const config = require('../core/config');
  config.cargar();

  const authActiva = config.leer('AUTH_ENABLED') === 'true';
  const host = config.leer('HOST') || '127.0.0.1';

  const registros = [];

  registros.push({
    area: 'Autenticacion',
    comprobacion: 'AUTH_ENABLED activa',
    estado: authActiva ? 'ok' : 'fail',
    detalle: authActiva
      ? 'La autenticacion esta activada.'
      : 'Con AUTH_ENABLED=false cualquiera que llegue al puerto puede lanzar diagnosticos. Es obligatorio en produccion.'
  });

  registros.push({
    area: 'Autenticacion',
    comprobacion: 'Contrasenas con hash scrypt',
    estado: 'ok',
    detalle:
      'Las cuentas viven en la tabla de usuarios de SQLite y sus contrasenas se derivan con scrypt. No hay ninguna contrasena en texto plano. AUTH_USER y AUTH_PASSWORD_HASH del .env ya no se usan: se pueden borrar.'
  });

  registros.push({
    area: 'Sesiones',
    comprobacion: 'Sesion en memoria, no en disco',
    estado: 'ok',
    detalle:
      'Las sesiones viven en memoria del proceso. Reiniciar el servidor cierra todas las sesiones abiertas, que es lo correcto para una herramienta que se despliega de una en vez.'
  });

  registros.push({
    area: 'Red',
    comprobacion: 'HOST no expuesto a Internet sin TLS',
    estado: host === '127.0.0.1' || host === 'localhost' ? 'ok' : 'fail',
    detalle:
      host === '127.0.0.1' || host === 'localhost'
        ? 'El servidor escucha solo en local, que es lo correcto: el acceso se hace a traves del proxy inverso.'
        : `HOST=${host} deja el puerto de diagnostico accesible desde Internet. El servidor no gestiona TLS, asi que la contrasena viajaria en claro. Pon HOST=127.0.0.1 y deja el proxy con HTTPS delante.`
  });

  registros.push({
    area: 'Sesiones',
    comprobacion: 'Cookie marcada Secure',
    estado: 'warn',
    detalle: 'El atributo Secure se activa solo si la peticion llega por HTTPS. Sin HTTPS, la cookie viaja sin ese atributo.'
  });

  registros.push({
    area: 'Base de datos',
    comprobacion: 'SQLite en data/',
    estado: 'ok',
    detalle: 'Los usuarios, el historial y la auditoria viven en data/netlab.db. Ese directorio tiene que ser escribible por el usuario del servicio y conviene incluirlo en la copia de seguridad.'
  });

  registros.push({
    area: 'Base de datos',
    comprobacion: 'Primer administrador creado',
    estado: 'ok',
    detalle: 'Al abrir la pagina, si la tabla de usuarios esta vacia, el sistema pide crear el administrador principal. No hace falta crearlo por consola.'
  });

  const webCompilada = fs.existsSync(path.join(process.cwd(), 'web', 'dist', 'index.html'));

  registros.push({
    area: 'Frontend',
    comprobacion: 'Compilacion de la web',
    estado: webCompilada ? 'ok' : 'fail',
    detalle: webCompilada
      ? 'web/dist existe. En la VPS hay que compilar antes de arrancar: npm run build.'
      : 'No existe web/dist/index.html. El servidor no encontrara la pagina: ejecuta npm run build.'
  });

  registros.push({
    area: 'Base de datos',
    comprobacion: 'Directorio data/ escribible',
    estado: comprobarEscritura(path.join(process.cwd(), 'data')) ? 'ok' : 'fail',
    detalle: 'SQLite necesita escribir data/netlab.db. Si el directorio no es escribible por el usuario del servicio, el arranque falla.'
  });

  registros.push({
    area: 'Secretos',
    comprobacion: 'Claves de terceros presentes',
    estado: 'ok',
    detalle:
      'Las credenciales de AbuseIPDB y Spamhaus son opcionales: sin ellas las herramientas siguen funcionando y lo dicen en el informe. Los perfiles de correo los introduce quien hace la prueba, no se precargan.'
  });

  registros.push({
    area: 'Secretos',
    comprobacion: '.env ignorado por git',
    estado: comprobarEnvIgnorado() ? 'ok' : 'fail',
    detalle:
      'El .env contiene credenciales reales. Si no esta en .gitignore, basta con un commit para publicarlo. En la VPS debe quedar en chmod 600 y fuera de cualquier directorio servido por el servidor web.'
  });

  registros.push({
    area: 'Secretos',
    comprobacion: 'Ausencia de secretos en el historial',
    estado: 'ok',
    detalle: 'Los parametros se enmascaran antes de guardarse, de modo que una contrasena de correo no queda escrita en el historial ni en los informes.'
  });

  registros.push({
    area: 'Limites',
    comprobacion: 'Topes por minuto y por usuario',
    estado: 'ok',
    detalle: '30 ejecuciones por minuto y usuario, y 4 simultaneas. Sin esto, un formulario reenviado seria una forma barata de cargar la red desde el servidor.'
  });

  registros.push({
    area: 'Cabeceras',
    comprobacion: 'Politica de seguridad de contenidos',
    estado: 'ok',
    detalle: 'El servidor envia CSP con default-src self, sin scripts en linea, mas nosniff, Referrer-Policy y X-Frame-Options DENY.'
  });

  return registros;
}

/** Indica si se puede escribir en un directorio. */
function comprobarEscritura(dir) {
  try {
    if (!fs.existsSync(dir)) return false;
    fs.accessSync(dir, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

/** Indica si el .env esta en .gitignore. */
function comprobarEnvIgnorado() {
  try {
    const texto = fs.readFileSync(path.join(process.cwd(), '.gitignore'), 'utf8');
    return /^\s*\.env\s*$/m.test(texto);
  } catch {
    return false;
  }
}

/** Agrupa las comprobaciones por area, conservando el orden de aparicion. */
function porArea(registros) {
  const mapa = new Map();
  for (const r of registros) {
    const lista = mapa.get(r.area) || [];
    lista.push(r);
    mapa.set(r.area, lista);
  }
  return [...mapa.entries()];
}

/** Titulo de la portada. */
const TITULO = 'Manual de netlab';

/** Subtitulo de la portada. */
const SUBTITULO = 'Flujo de puesta en marcha y funcion de cada modulo';

/**
 * Genera el PDF del manual.
 *
 * @param {object} [opciones]
 * @param {string} [opciones.marca] Nombre que aparece en la cabecera.
 * @param {string} [opciones.pie] Texto del pie de pagina.
 * @returns {Promise<Buffer>}
 */
function render(opciones = {}) {
  const { marca = 'netlab', pie = 'Documento generado automaticamente por netlab' } = opciones;

  return new Promise((resolve, reject) => {
    const pdf = doc.crear();
    const trozos = [];

    pdf.on('data', (t) => trozos.push(t));
    pdf.on('end', () => resolve(Buffer.concat(trozos)));
    pdf.on('error', reject);

    portada(pdf);
    indice(pdf);
    seccionResumen(pdf, marca);
    seccionModulos(pdf);
    seccionProduccion(pdf);
    seccionHerramientas(pdf);
    seccionDespliegue(pdf);

    doc.fijarTitulo(pdf, TITULO);
    doc.pieConNumeracion(pdf, pie);
    pdf.end();
  });
}

/** Primera pagina: nombre, subtitulo y fecha. */
function portada(pdf) {
  const { margen, ancho, alto } = PAGINA;

  pdf.addPage();
  pdf.rect(0, 0, ancho, 250).fill(COLORES.fondoCabecera);

  pdf
    .fillColor(COLORES.textoClaro)
    .font(TIPOGRAFIA.fuenteTitulo)
    .fontSize(34)
    .text(sanear(TITULO), margen, 90, { width: ancho - margen * 2 });

  pdf
    .fillColor(COLORES.textoSuave)
    .font(TIPOGRAFIA.fuenteTexto)
    .fontSize(13)
    .text(sanear(SUBTITULO), margen, 140, { width: ancho - margen * 2 });

  pdf
    .fillColor(COLORES.texto)
    .font(TIPOGRAFIA.fuenteTitulo)
    .fontSize(12)
    .text('Que hace, para que sirve y que problema resuelve', margen, 290, { width: ancho - margen * 2 });

  pdf
    .fillColor(COLORES.textoMedio)
    .font(TIPOGRAFIA.fuenteTexto)
    .fontSize(10)
    .text(`Generado el ${new Date().toLocaleDateString('es-ES')}`, margen, 310, { width: ancho - margen * 2 });

  pdf.y = 360;
}

/** Sumario de los modulos. */
function indice(pdf) {
  doc.nuevaPagina(pdf, 'Contenido', true);

  doc.seccion(pdf, 'Como leer este manual');

  parrafo(
    pdf,
    'Cada modulo se explica con las mismas cuatro preguntas: que hace, para que sirve, que problema resuelve y como se recorre. Las dos primeras describen el comportamiento; la tercera es la que importa cuando alguien pregunta para que sirve una pieza concreta; la cuarta es el recorrido real, paso a paso.'
  );

  doc.seccion(pdf, 'Modulos');

  for (const m of MODULOS) {
    parrafo(pdf, `${m.titulo} - ${m.resumen}`);
  }

  doc.seccion(pdf, 'Apendices');
  parrafo(pdf, 'Las herramientas de diagnostico, con su identificador y su proposito.');
  parrafo(pdf, 'La revision de preparación para produccion, con el estado de cada comprobacion.');
  parrafo(pdf, 'El despliegue en la VPS, con los pasos y el orden correcto.');
}

/** Resumen general y flujo de arranque. */
function seccionResumen(pdf, marca) {
  doc.nuevaPagina(pdf, 'Resumen', true);

  doc.seccion(pdf, 'Que es netlab', 'Suite de diagnostico de red, DNS, IP y correo');
  parrafo(
    pdf,
    `${marca} es una aplicacion web de diagnostico de infraestructura. Reune en una sola interfaz las comprobaciones que antes eran scripts sueltos: analisis de IP y de reputacion, consultas DNS, verificacion de correo, validador de SMTP, reparto de subredes y comprobacion de sitios web. Cada ejecucion produce un informe con veredicto, resumen, detalle, hallazgos y recomendacion, descargable en cinco formatos.`
  );

  doc.seccion(pdf, 'Arquitectura', 'Como encajan las piezas');
  parrafo(pdf, 'Servidor Node.js con Express en src/server, que expone una API JSON y sirve la interfaz compilada.');
  parrafo(pdf, 'SPA en React y Vite en web/src, compilada a web/dist.');
  parrafo(pdf, 'Herramientas de diagnostico en src/tools, descubiertas al arrancar.');
  parrafo(pdf, 'Capa comun en src/core: configuracion, errores del dominio, resultado normalizado, enmascarado de secretos y utilidades de red.');
  parrafo(pdf, 'Formatos de salida en src/formats, con PDF, HTML, JSON, Markdown y TXT a partir del mismo resultado.');
  parrafo(pdf, 'Persistencia en SQLite: usuarios, historial, enlaces compartidos y auditoria.');

  doc.seccion(pdf, 'Flujo de arranque', 'Del primer ingreso al diagnostico');
  pasos(pdf, [
    'Arranca el servidor. Carga la configuracion, descubre las herramientas y abre el puerto.',
    'Se comprueba el estado de la autenticacion. Si esta activa y no hay ningun usuario, el sistema arranca en modo setup.',
    'La pagina consulta el estado del setup. Si falta el administrador, muestra el formulario de creacion en lugar del login.',
    'Se crea el administrador principal. A partir de ese momento, el setup queda cerrado y ya no se puede repetir.',
    'El administrador entra con su cuenta y usa las herramientas. Solo el rol admin accede a la gestion de usuarios y a la auditoria.',
    'Cada ejecucion se valida, se limita, se enmascara antes de guardarse y queda en el historial de quien la lanzo.',
    'El resultado se puede descargar en PDF, HTML, JSON, Markdown o TXT, y compartir mediante un enlace publico temporal.'
  ]);
}

/** Un modulo por seccion. */
function seccionModulos(pdf) {
  doc.nuevaPagina(pdf, 'Modulos', true);

  for (const m of MODULOS) {
    doc.seccion(pdf, m.titulo, m.resumen);

    doc.seccion(pdf, 'Que hace');
    vinetas(pdf, m.hace);

    doc.seccion(pdf, 'Para que sirve');
    parrafo(pdf, m.sirve);

    doc.seccion(pdf, 'Que soluciona');
    vinetas(pdf, m.soluciona);

    doc.seccion(pdf, 'Flujo');
    pasos(pdf, m.flujo);
  }
}

/** Revision de produccion. */
function seccionProduccion(pdf) {
  doc.nuevaPagina(pdf, 'Produccion', true);

  const registros = revisarProduccion();
  const fallos = registros.filter((r) => r.estado === 'fail');
  const avisos = registros.filter((r) => r.estado === 'warn');

  doc.seccion(pdf, 'Estado de la revision');
  parrafo(
    pdf,
    fallos.length
      ? `Hay ${fallos.length} comprobacion(es) que impiden el despliegue y ${avisos.length} aviso(s) que conviene resolver antes de exponer el servicio.`
      : `No hay comprobaciones bloqueantes. Quedan ${avisos.length} aviso(s) por revisar.`
  );

  if (fallos.length) {
    doc.seccion(pdf, 'Bloqueantes');
    for (const r of fallos) {
      doc.filaKV(pdf, r.comprobacion, 'FALLA', 'bad');
      parrafo(pdf, r.detalle);
    }
  }

  if (avisos.length) {
    doc.seccion(pdf, 'Avisos');
    for (const r of avisos) {
      doc.filaKV(pdf, r.comprobacion, 'REVISAR', 'warn');
      parrafo(pdf, r.detalle);
    }
  }

  doc.seccion(pdf, 'Correcto');
  for (const r of registros.filter((x) => x.estado === 'ok')) {
    doc.filaKV(pdf, r.comprobacion, 'OK', 'ok');
  }

  doc.seccion(pdf, 'Resumen por area');
  const filas = porArea(registros).map(([area, lista]) => {
    const conFallo = lista.filter((x) => x.estado === 'fail').length;
    const conAviso = lista.filter((x) => x.estado === 'warn').length;
    const estado = conFallo ? 'Falla' : conAviso ? 'Revisar' : 'Correcto';
    return [
      { valor: area },
      { valor: String(lista.length) },
      { valor: estado, tone: conFallo ? 'bad' : conAviso ? 'warn' : 'ok' }
    ];
  });

  doc.tabla(pdf, { title: 'Estado por area', columns: ['Area', 'Comprobaciones', 'Estado'], rows: filas });
}

/** Catalogo de herramientas, leido del registro real. */
function seccionHerramientas(pdf) {
  doc.nuevaPagina(pdf, 'Herramientas', true);

  const herramientas = registro().herramientas;

  doc.seccion(pdf, 'Catalogo', `${herramientas.length} herramientas disponibles`);
  parrafo(
    pdf,
    'La lista no esta escrita en ningun sitio del servidor: se construye leyendo los ficheros de src/tools al arrancar. Anadir una comprobacion nueva es dejar el archivo, sin tocar el servidor ni la interfaz.'
  );

  for (const h of herramientas) {
    doc.seccion(pdf, h.titulo, `Identificador: ${h.id}`);
    if (h.descripcion) parrafo(pdf, h.descripcion);
    if (Array.isArray(h.campos) && h.campos.length) {
      doc.filaKV(pdf, 'Campos', h.campos.map((c) => c.label || c.name).join(', '));
    }
    doc.filaKV(pdf, 'Requiere salida a internet', h.sinRed ? 'No, funciona sin red' : 'Si');
  }
}

/** Despliegue en la VPS. */
function seccionDespliegue(pdf) {
  doc.nuevaPagina(pdf, 'Despliegue', true);

  doc.seccion(pdf, 'Requisitos');
  vinetas(pdf, [
    'Node.js 24 o superior. La version importa: la base de datos usa el modulo de SQLite integrado.',
    '512 MB de memoria como minimo; 1 GB recomendado.',
    'Un proxy inverso con HTTPS delante, para no exponer la contrasena en claro.'
  ]);

  doc.seccion(pdf, 'Orden de despliegue');
  pasos(pdf, [
    'Instalar Node.js 24 en el servidor.',
    'Copiar el proyecto, instalar dependencias con npm ci y compilar la interfaz con npm run build.',
    'Crear el archivo .env a partir de .env.example con AUTH_ENABLED=true y protegerlo con chmod 600.',
    'Dejar el servidor escuchando solo en localhost, con HOST=127.0.0.1, y publicarlo con el proxy inverso.',
    'Dar permisos de escritura al usuario del servicio sobre el directorio data.',
    'Arrancar el servicio y comprobar el estado.',
    'Abrir la pagina: aparecera el formulario del administrador principal. Crear la cuenta y entrar.',
    'Las cuentas del administrador principal y del resto de usuarios se dan de alta desde la propia aplicacion. AUTH_USER y AUTH_PASSWORD_HASH del .env ya no se usan: se pueden borrar.',
    'Configurar el proxy con HTTPS y verificar que la cookie de sesion llega marcada como Secure.'
  ]);

  doc.seccion(pdf, 'Verificacion tras el despliegue');
  vinetas(pdf, [
    'La pagina responde y muestra el formulario de administrador principal.',
    'El login funciona con la cuenta creada.',
    'Una ejecucion de prueba se completa y aparece en el historial.',
    'El informe se descarga en PDF.',
    'GET /api/sesion responde autenticado con el rol esperado.',
    'El proxy responde con el certificado valido y la peticion llega por HTTPS.'
  ]);

  doc.seccion(pdf, 'Copia de seguridad');
  parrafo(
    pdf,
    'Lo unico que hay que respaldar es el directorio data: usuarios, historial, enlaces compartidos y auditoria. El .env tambien, porque contiene las credenciales de los servicios externos, pero no debe ir al repositorio.'
  );
}

/** Parrafojustificado con salto de pagina automatico. */
function parrafo(pdf, texto) {
  const { margen, anchoUtil } = PAGINA;
  doc.asegurarEspacio(pdf, 40);
  pdf
    .fillColor(COLORES.texto)
    .font(TIPOGRAFIA.fuenteTexto)
    .fontSize(9.5)
    .text(sanear(texto), margen, pdf.y, { width: anchoUtil, align: 'justify' });
  pdf.y += 8;
}

/** Lista con vinetas. */
function vinetas(pdf, elementos) {
  const { margen, anchoUtil } = PAGINA;
  for (const item of elementos) {
    doc.asegurarEspacio(pdf, 30);
    const y = pdf.y;
    pdf.fillColor(COLORES.textoMedio).font(TIPOGRAFIA.fuenteTexto).fontSize(9.5);
    pdf.text('-', margen, y, { width: 12 });
    pdf.fillColor(COLORES.texto).font(TIPOGRAFIA.fuenteTexto).fontSize(9.5);
    pdf.text(sanear(item), margen + 14, y, { width: anchoUtil - 14, align: 'justify' });
    pdf.y += 3;
  }
  pdf.y += 6;
}

/** Lista numerada de pasos. */
function pasos(pdf, elementos) {
  const { margen, anchoUtil } = PAGINA;
  elementos.forEach((item, i) => {
    doc.asegurarEspacio(pdf, 30);
    const y = pdf.y;
    pdf.fillColor(COLORES.textoMedio).font(TIPOGRAFIA.fuenteTitulo).fontSize(9.5);
    pdf.text(`${i + 1}.`, margen, y, { width: 20 });
    pdf.fillColor(COLORES.texto).font(TIPOGRAFIA.fuenteTexto).fontSize(9.5);
    pdf.text(sanear(item), margen + 22, y, { width: anchoUtil - 22, align: 'justify' });
    pdf.y += 3;
  });
  pdf.y += 6;
}

module.exports = { render, revisarProduccion, MODULOS, TITULO };