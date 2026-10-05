'use strict';

/**
 * test/smtp-validator.test.js — Pruebas del validador SMTP.
 *
 * Los servidores falsos escuchan en 127.0.0.1 con un puerto efímero, así que la
 * conversación SMTP e IMAP se prueba de verdad, byte a byte: si el parser de
 * respuestas está mal, el test se queda esperando y falla por plazo, no por un
 * mock que siempre responde bien.
 *
 * Sobre el TLS: en esta máquina no hay openssl ni biblioteca para emitir
 * certificados, y meter una dependencia solo para las pruebas no compensa. Lo
 * que se sustituye es la capa criptográfica, no la conversación:
 *
 *   - `deps.tls.conectar` devuelve el socket de TCP con los métodos que leen los
 *     informes (getProtocol, getCipher, authorized...). El flujo de bytes es real.
 *   - `deps.lineas.subirStartTls` entrega una segunda conexión REAL de la que el
 *     propio servidor falso es el otro extremo, para que el EHLO posterior a
 *     STARTTLS viaje de verdad sin poder cifrarlo.
 *
 * Lo que NO cubren estos tests es la criptografía en sí: que `tls.connect` acepte
 * un certificado real, que los nombres coincidan y que la verificación falle
 * cuando toca. Eso lo cubre core/net/tls, que usa sockets de verdad.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');

const herramienta = require('../src/tools/smtp-validator');
const smtp = require('../src/core/mail/smtp');
const imap = require('../src/core/mail/imap');
const lineas = require('../src/core/mail/lineas');

const NUL = '\u0000';

/* ------------------------------------------------------------------ *
 * Servidor SMTP falso
 * ------------------------------------------------------------------ */

/**
 * Levanta un servidor SMTP de mentira.
 *
 * @param {object} [opciones]
 * @param {boolean} [opciones.cifradoFalso=false] Subir a STARTTLS creates a real second connection.
 * @param {string[]} [opciones.antesDeStarttls]
 * @param {string[]} [opciones.despuesDeStarttls]
 * @param {number} [opciones.codigoStarttls=220]
 * @param {string} [opciones.codigoAuth='235']
 * @param {boolean} [opciones.mudo=false] Acepta la conexión y no dice nada.
 * @returns {Promise<object>} { puerto, recibido, cuerpo, clientePostTls, cerrar }
 */
async function servidorSmtp(opciones = {}) {
  const {
    cifradoFalso = false,
    antesDeStarttls = ['PIPELINING', '8BITMIME', 'STARTTLS', 'AUTH LOGIN PLAIN'],
    despuesDeStarttls = ['PIPELINING', '8BITMIME', 'AUTH LOGIN PLAIN'],
    codigoStarttls = 220,
    codigoAuth = '235',
    mudo = false
  } = opciones;

  const recibido = [];
  const cuerpo = [];
  // Todos los sockets que tocan el servidor, los dos de cada pierna. Se guardan
  // para poder destruirlos al terminar: el tunel "cifrado" es una segunda
  // conexion, y el socket en claro original se abandona a proposito, asi que
  // `close()` a secas se queda esperando a algo que no va a cerrar nunca.
  const sockets = new Set();
  const anotarSocket = (socket) => {
    sockets.add(socket);
    // El cliente destruye el socket al terminar su recorrido y el sistema
    // operativo responde con un RST. Sin este manejador, ese error sube como
    // excepcion sin capturar y tumba una prueba que ya habia pasado.
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
    return socket;
  };

  let cifrado = false;
  let resolverPostTls = null;

  /** El tunel cifrado es una segunda conexión a este mismo servidor. */
  const segundoTunel = new Promise((r) => {
    resolverPostTls = r;
  });

  const servidor = net.createServer((socket) => {
    anotarSocket(socket);
    hablar(socket, { conBanner: !cifrado });
  });

  /** Una pierna de la conversación, ya sea antes o después de STARTTLS. */
  function hablar(socket, { conBanner }) {
    const escribir = (texto) => socket.write(`${texto}\r\n`);
    if (conBanner && !mudo) escribir('220 falso.test ESMTP listo');

    let buffer = '';
    let enDatos = false;
    let pasoAuth = 0;
    let cuerpoActual = '';

    socket.on('data', (trozo) => {
      buffer += trozo.toString('utf8');
      let corte;
      while ((corte = buffer.indexOf('\n')) !== -1) {
        const linea = buffer.slice(0, corte).replace(/\r$/, '');
        buffer = buffer.slice(corte + 1);

        // Dentro de DATA todo es cuerpo hasta el punto solo.
        if (enDatos) {
          if (linea === '.') {
            enDatos = false;
            cuerpo.push(cuerpoActual);
            cuerpoActual = '';
            escribir('250 Mensaje aceptado: id=abc123');
          } else {
            cuerpoActual += `${linea}\n`;
          }
          continue;
        }

        recibido.push(linea);
        const comando = linea.toUpperCase();
        const capacidades = cifrado ? despuesDeStarttls : antesDeStarttls;

        if (comando.startsWith('EHLO') || comando.startsWith('HELO')) {
          escribir('250-falso.test');
          for (const capacidad of capacidades.slice(0, -1)) escribir(`250-${capacidad}`);
          escribir(`250 ${capacidades[capacidades.length - 1]}`);
        } else if (comando === 'STARTTLS') {
          escribir(`${codigoStarttls} Listo para cifrar`);
          if (codigoStarttls === 220) {
            cifrado = true;
            if (cifradoFalso) {
              const saliente = anotarSocket(net.connect(servidor.address().port, '127.0.0.1'));
              saliente.once('connect', () => resolverPostTls(saliente));
            }
          }
        } else if (comando.startsWith('AUTH PLAIN')) {
          escribir(codigoAuth === '235' ? '235 2.7.0 Autenticado' : '535 5.7.8 Credenciales rechazadas');
        } else if (comando === 'AUTH LOGIN') {
          escribir('334 VXNlcm5hbWU6');
          pasoAuth = 1;
        } else if (pasoAuth === 1) {
          escribir('334 UGFzc3dvcmQ6');
          pasoAuth = 2;
        } else if (pasoAuth === 2) {
          escribir(codigoAuth === '235' ? '235 2.7.0 Autenticado' : '535 5.7.8 Credenciales rechazadas');
          pasoAuth = 0;
        } else if (comando.startsWith('MAIL FROM')) {
          escribir('250 2.1.0 Emisor aceptado');
        } else if (comando.startsWith('RCPT TO')) {
          escribir('250 2.1.5 Destinatario aceptado');
        } else if (comando === 'DATA') {
          escribir('354 Fin de los datos con <CRLF>.<CRLF>');
          enDatos = true;
        } else if (comando === 'QUIT') {
          escribir('221 2.0.0 Cerrando');
          socket.end();
        } else {
          escribir('500 5.5.2 No entiendo ese comando');
        }
      }
    });
  }

  await new Promise((r) => servidor.listen(0, '127.0.0.1', r));

  return {
    puerto: servidor.address().port,
    recibido,
    cuerpo,
    /** Espera al socket que hace de tunel cifrado y lo devuelve. */
    segundoTunel: async () => segundoTunel,
    /** Destruye todos los sockets y cierra el servidor. */
    cerrar: async () => {
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      await new Promise((r) => servidor.close(r));
    }
  };
}

/**
 * Suplanta a core/mail/lineas.subirStartTls.
 *
 * El "cifrado" es una segunda conexión real cuyo otro extremo es el mismo
 * servidor falso, así que los bytes viajan enteros por el socket.
 *
 * @param {object} servidor Servidor SMTP falso con `cifradoFalso: true`.
 * @returns {object} Dependencias para smtp.probar.
 */
function depsConStartTlsFalso(servidor) {
  return {
    lineas: {
      ...lineas,
      subirStartTls: async () => {
        const socket = await servidor.segundoTunel();
        socket.getProtocol = () => 'TLSv1.3';
        socket.getCipher = () => ({ name: 'TLS_AES_256_GCM_SHA384' });
        socket.authorized = true;
        return { socket, certificado: { sujeto: 'CN=falso.test' } };
      }
    }
  };
}

/* ------------------------------------------------------------------ *
 * Suplantaciones de TLS e IMAP
 * ------------------------------------------------------------------ */

/**
 * Suplanta a core/net/tls: el socket es de verdad, los metodos del informe se
 * añaden encima. El flujo de bytes no cambia.
 *
 * @param {object} [config]
 * @param {boolean} [config.verificado=false]
 * @param {string} [config.motivo='UNABLE_TO_VERIFY_LEAF_SIGNATURE']
 * @returns {{conectar: Function, inspeccionar: Function, esIp: Function}}
 */
function tlsFalso({ verificado = false, motivo = 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' } = {}) {
  return {
    esIp: (host) => /^\d{1,3}(\.\d{1,3}){3}$/.test(String(host)) || String(host).includes(':'),
    conectar: async ({ port }) => {
      const socket = await conectarTcp(port);
      socket.getProtocol = () => 'TLSv1.3';
      socket.getCipher = () => ({ name: 'TLS_AES_256_GCM_SHA384' });
      socket.authorized = verificado;
      socket.authorizationError = verificado ? undefined : motivo;
      return {
        socket,
        certificado: {
          sujeto: 'CN=falso.test',
          emisor: 'CN=falso.test',
          protocolo: 'TLSv1.3',
          cifra: 'TLS_AES_256_GCM_SHA384'
        }
      };
    },
    inspeccionar: () => ({ sujeto: 'CN=falso.test' })
  };
}

/** Conecta a 127.0.0.1 en un puerto dado, sin plazo. */
function conectarTcp(puerto) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(puerto, '127.0.0.1', () => resolve(socket));
    socket.once('error', reject);
  });
}

/** Servidor IMAP de mentira. La capa TLS se sustituye aparte. */
async function servidorImap({ preauth = false, aceptaLogin = true } = {}) {
  const recibido = [];
  const sockets = new Set();

  const servidor = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
    const escribir = (texto) => socket.write(`${texto}\r\n`);
    escribir(preauth ? '* PREAUTH IMAP4rev1 listo' : '* OK IMAP4rev1 listo');
    escribir('* CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN');

    let buffer = '';
    socket.on('data', (trozo) => {
      buffer += trozo.toString('utf8');
      let corte;
      while ((corte = buffer.indexOf('\n')) !== -1) {
        const linea = buffer.slice(0, corte).replace(/\r$/, '');
        buffer = buffer.slice(corte + 1);
        recibido.push(linea);

        if (/^a1 CAPABILITY/i.test(linea)) {
          escribir('* CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN');
          escribir('a1 OK CAPABILITY completed');
        } else if (/^a2 LOGIN/i.test(linea)) {
          escribir(
            aceptaLogin
              ? 'a2 OK [CAPABILITY IMAP4rev1 IDLE] Logged in'
              : 'a2 NO [AUTHENTICATIONFAILED] Invalid credentials'
          );
        } else if (/^a3 LOGOUT/i.test(linea)) {
          escribir('* BYE cerrando');
          escribir('a3 OK LOGOUT completed');
          socket.end();
        } else {
          escribir('a4 BAD No entiendo ese comando');
        }
      }
    });
  });

  await new Promise((r) => servidor.listen(0, '127.0.0.1', r));
  return {
    puerto: servidor.address().port,
    recibido,
    cerrar: async () => {
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      await new Promise((r) => servidor.close(r));
    }
  };
}

/** Base de una sesion SMTP contra el servidor falso, en texto plano. */
function sesionSimple(servidor, extra = {}) {
  return {
    host: '127.0.0.1',
    puerto: servidor.puerto,
    seguridad: 'ninguno',
    timeout: 2000,
    ...extra
  };
}

/* ------------------------------------------------------------------ *
 * Funciones puras
 * ------------------------------------------------------------------ */

test('limpiarCapacidades quita el codigo de las lineas del EHLO', () => {
  assert.deepEqual(smtp.limpiarCapacidades(['250-falso.test', '250-PIPELINING', '250-STARTTLS', '250 AUTH LOGIN PLAIN']), [
    'falso.test',
    'PIPELINING',
    'STARTTLS',
    'AUTH LOGIN PLAIN'
  ]);
});

test('extraerMecanismos acepta las dos formas de la RFC 4954', () => {
  assert.deepEqual(smtp.extraerMecanismos(['AUTH LOGIN PLAIN', 'PIPELINING']), ['LOGIN', 'PLAIN']);
  assert.deepEqual(smtp.extraerMecanismos(['AUTH=LOGIN PLAIN']), ['LOGIN', 'PLAIN']);
  assert.deepEqual(smtp.extraerMecanismos(['PIPELINING']), []);
});

test('elegirMecanismo usa PLAIN solo si la sesion va cifrada', () => {
  assert.equal(smtp.elegirMecanismo(['PLAIN', 'LOGIN'], true), 'PLAIN');
  assert.equal(smtp.elegirMecanismo(['PLAIN', 'LOGIN'], false), 'LOGIN');
  assert.equal(smtp.elegirMecanismo(['XOAUTH2'], true), null);
  assert.equal(smtp.elegirMecanismo([], true), null);
});

test('componerMensaje pone cabeceras y escapa los puntos del cuerpo', () => {
  const mensaje = smtp.componerMensaje({ remitente: 'uno@ejemplo.com', destinatario: 'dos@ejemplo.com', asunto: 'Prueba' });
  assert.match(mensaje, /^From: <uno@ejemplo\.com>\r\n/);
  assert.match(mensaje, /\r\nTo: <dos@ejemplo\.com>\r\n/);
  assert.match(mensaje, /\r\nSubject: Prueba\r\n/);
  assert.match(mensaje, /\r\n\r\n/);

  const conPunto = smtp.componerMensaje({ remitente: 'a@b.c', destinatario: 'd@e.f', texto: '.primera' });
  assert.match(conPunto, /\r\n\.\.primera/, 'un punto inicial se duplica para que no cierre los datos');
});

test('codigoEtiquetado entiende las respuestas IMAP', () => {
  assert.equal(imap.codigoEtiquetado('a2 OK Logged in', 'a2'), 0);
  assert.equal(imap.codigoEtiquetado('a2 NO [AUTHENTICATIONFAILED] Invalid', 'a2'), 1);
  assert.equal(imap.codigoEtiquetado('a2 BAD Command unknown', 'a2'), 1);
  assert.equal(imap.codigoEtiquetado('* OK Still here', 'a2'), null);
});

test('extraerCapacidades lee solo las lineas CAPABILITY de IMAP', () => {
  assert.deepEqual(imap.extraerCapacidades(['* CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN', '* CAPABILITY UIDPLUS', 'a1 OK Completed']), [
    'IMAP4REV1',
    'IDLE',
    'AUTH=PLAIN',
    'UIDPLUS'
  ]);
});

test('escapar cierra comillas para no romper el comando IMAP', () => {
  assert.equal(imap.escapar('a"b\\c'), 'a\\"b\\\\c');
});

test('respuestaCompleta espera al cierre del bloque multilinea', () => {
  assert.equal(lineas.respuestaCompleta('250-falso.test\r\n'), false, 'una linea 250- no cierra el bloque');
  assert.equal(lineas.respuestaCompleta('250-falso.test\r\n250 HELP\r\n'), true);
  assert.equal(lineas.respuestaCompleta('220 hola\r\n'), true);
  assert.equal(lineas.respuestaCompleta('* OK IMAP4rev1\r\n'), true);
});

test('respuestaCompleta no se fia de una linea a medio llegar', () => {
  // El cuarto caracter de "250 hola" es un espacio, igual que en una respuesta
  // cerrada: sin mirar el salto de linea final, un "250 hola" partido entre dos
  // trozos de TCP se tomaria por respuesta entera.
  assert.equal(lineas.respuestaCompleta('220 hol'), false);
  assert.equal(lineas.respuestaCompleta('250-falso.test\r\n250 HEL'), false);
  assert.equal(lineas.respuestaCompleta(''), false);
});

test('interpretar saca el codigo de la ultima linea, que es la que lo lleva', () => {
  const respuesta = lineas.interpretar('250-falso.test\r\n250-PIPELINING\r\n250 HELP\r\n', (t) => t);
  assert.equal(respuesta.codigo, 250);
  assert.equal(respuesta.multilinea, true);
  assert.equal(respuesta.lineas.length, 3);
});

/* ------------------------------------------------------------------ *
 * Sesion SMTP
 * ------------------------------------------------------------------ */

test('conecta, autentica y no envia nada si no se le pide', async () => {
  const servidor = await servidorSmtp({ cifradoFalso: true });
  try {
    const sesion = await smtp.probar(
      sesionSimple(servidor, {
        seguridad: 'starttls',
        usuario: 'usuario@ejemplo.com',
        contrasena: 'secreto'
      }),
      depsConStartTlsFalso(servidor)
    );

    assert.match(sesion.banner, /ESMTP/);
    assert.equal(sesion.starttls.anunciado, true);
    assert.equal(sesion.starttls.aplicado, true);
    assert.equal(sesion.seguridadEfectiva, 'starttls');
    assert.equal(sesion.auth.ok, true);
    assert.equal(sesion.auth.mecanismo, 'PLAIN');
    assert.equal(sesion.envio, null, 'sin datos de envio no se envia');

    // Tras cifrar se repite el EHLO, y ya no debe anunciarse STARTTLS.
    const ehlos = servidor.recibido.filter((l) => /^EHLO/i.test(l));
    assert.equal(ehlos.length, 2, 'un EHLO antes de cifrar y otro despues');
    assert.ok(!sesion.capacidades.some((c) => /^STARTTLS/i.test(c)));
    assert.ok(!servidor.recibido.some((l) => /^MAIL FROM/i.test(l)), 'no debe haber envio sin pedirlo');
  } finally {
    await servidor.cerrar();
  }
});

test('el payload de AUTH PLAIN lleva bytes NUL y no espacios', async () => {
  // PLAIN solo se elige si la sesion va cifrada, asi que este caso necesita el
  // tunel: en claro el codigo prefiere AUTH LOGIN a proposito.
  const servidor = await servidorSmtp({ cifradoFalso: true });
  try {
    await smtp.probar(
      sesionSimple(servidor, { seguridad: 'starttls', usuario: 'usuario@ejemplo.com', contrasena: 'secreto' }),
      depsConStartTlsFalso(servidor)
    );

    const lineaAuth = servidor.recibido.find((l) => l.startsWith('AUTH PLAIN'));
    assert.ok(lineaAuth, 'el servidor recibio un AUTH PLAIN');
    const carga = Buffer.from(lineaAuth.split(' ')[2], 'base64');
    assert.equal(carga[0], 0, 'el separador inicial es un byte NUL, no un espacio');
    assert.equal(carga.toString('utf8'), `${NUL}usuario@ejemplo.com${NUL}secreto`);
  } finally {
    await servidor.cerrar();
  }
});

test('AUTH LOGIN viaja en tres pasos cuando la sesion va en claro', async () => {
  const servidor = await servidorSmtp({ antesDeStarttls: ['AUTH LOGIN'] });
  try {
    const sesion = await smtp.probar(sesionSimple(servidor, { usuario: 'usuario@ejemplo.com', contrasena: 'secreto' }));

    assert.equal(sesion.auth.mecanismo, 'LOGIN', 'en claro no se usa PLAIN');
    assert.equal(sesion.auth.ok, true);
    assert.deepEqual(servidor.recibido.slice(-4).slice(0, 3), [
      'AUTH LOGIN',
      Buffer.from('usuario@ejemplo.com').toString('base64'),
      Buffer.from('secreto').toString('base64')
    ]);
  } finally {
    await servidor.cerrar();
  }
});

test('si el servidor no anuncia STARTTLS, lo dice y no lo intenta', async () => {
  // Sin STARTTLS la sesion sigue en claro, y en claro toca AUTH LOGIN: por eso
  // el servidor anuncia los dos mecanismos.
  const servidor = await servidorSmtp({ antesDeStarttls: ['PIPELINING', 'AUTH LOGIN PLAIN'] });
  try {
    const sesion = await smtp.probar(
      sesionSimple(servidor, { seguridad: 'starttls', usuario: 'u@e.com', contrasena: 'secreto' })
    );

    assert.equal(sesion.starttls.anunciado, false);
    assert.equal(sesion.starttls.aplicado, false);
    assert.equal(sesion.seguridadEfectiva, 'ninguno');
    assert.ok(!servidor.recibido.some((l) => l === 'STARTTLS'), 'ni siquiera se intenta si no lo anuncia');
    assert.equal(sesion.auth.ok, true, 'la prueba sigue hasta el final para poder contarlo todo');
  } finally {
    await servidor.cerrar();
  }
});

test('si el servidor rechaza STARTTLS con otro codigo, lo cuenta', async () => {
  const servidor = await servidorSmtp({ codigoStarttls: 454 });
  try {
    const sesion = await smtp.probar(sesionSimple(servidor, { seguridad: 'starttls' }));
    assert.equal(sesion.starttls.anunciado, true);
    assert.equal(sesion.starttls.aplicado, false);
    assert.match(sesion.starttls.motivo, /454/);
  } finally {
    await servidor.cerrar();
  }
});

test('un STARTTLS que no llega a cifrar se reporta sin romper la prueba', async () => {
  // El servidor anuncia STARTTLS y responde 220 pero sigue hablando en claro:
  // es el caso del proxy mal puesto, y el TLS de verdad falla al negociar.
  const servidor = await servidorSmtp();
  try {
    const sesion = await smtp.probar(sesionSimple(servidor, { seguridad: 'starttls', timeout: 700 }));
    assert.equal(sesion.starttls.anunciado, true);
    assert.equal(sesion.starttls.aplicado, false);
    assert.ok(sesion.starttls.motivo, 'debe explicar por que no se pudo cifrar');
    assert.equal(sesion.seguridadEfectiva, 'ninguno');
  } finally {
    await servidor.cerrar();
  }
});

test('las credenciales incorrectas se cuentan como autenticacion fallida', async () => {
  const servidor = await servidorSmtp({ codigoAuth: '535' });
  try {
    const sesion = await smtp.probar(sesionSimple(servidor, { usuario: 'u@e.com', contrasena: 'mala' }));
    assert.equal(sesion.auth.enviado, true);
    assert.equal(sesion.auth.ok, false);
    assert.equal(sesion.auth.codigo, 535);
  } finally {
    await servidor.cerrar();
  }
});

test('sin usuario no se intenta autenticar', async () => {
  const servidor = await servidorSmtp();
  try {
    const sesion = await smtp.probar(sesionSimple(servidor));
    assert.equal(sesion.auth.enviado, false);
    assert.match(sesion.auth.mensaje, /usuario/i);
    assert.ok(!servidor.recibido.some((l) => l.startsWith('AUTH')));
  } finally {
    await servidor.cerrar();
  }
});

test('sin mecanismo anunciable no se intenta autenticar', async () => {
  const servidor = await servidorSmtp({ antesDeStarttls: ['PIPELINING'] });
  try {
    const sesion = await smtp.probar(sesionSimple(servidor, { usuario: 'u@e.com', contrasena: 'secreto' }));
    assert.equal(sesion.auth.enviado, false);
    assert.match(sesion.auth.mensaje, /autenticaci/i);
  } finally {
    await servidor.cerrar();
  }
});

test('con datos de envio salen MAIL FROM, RCPT TO, DATA y el cuerpo', async () => {
  const servidor = await servidorSmtp();
  try {
    const sesion = await smtp.probar(
      sesionSimple(servidor, {
        usuario: 'u@e.com',
        contrasena: 'secreto',
        enviar: { remitente: 'u@e.com', destinatario: 'destino@ejemplo.com', asunto: 'Prueba' }
      })
    );

    assert.equal(sesion.envio.ok, true);
    assert.ok(servidor.recibido.includes('MAIL FROM:<u@e.com>'));
    assert.ok(servidor.recibido.includes('RCPT TO:<destino@ejemplo.com>'));
    assert.ok(servidor.recibido.includes('DATA'));
    assert.equal(servidor.cuerpo.length, 1, 'llego un cuerpo de mensaje');
    assert.match(servidor.cuerpo[0], /To: <destino@ejemplo\.com>/);
    assert.match(servidor.cuerpo[0], /Subject: Prueba/);
  } finally {
    await servidor.cerrar();
  }
});

test('sin autenticacion correcta no se envia, aunque se pidan datos de envio', async () => {
  const servidor = await servidorSmtp({ codigoAuth: '535' });
  try {
    const sesion = await smtp.probar(
      sesionSimple(servidor, {
        usuario: 'u@e.com',
        contrasena: 'mala',
        enviar: { remitente: 'u@e.com', destinatario: 'd@e.com' }
      })
    );
    assert.equal(sesion.envio.ok, false);
    assert.match(sesion.envio.motivo, /autenticaci/i);
    assert.ok(!servidor.recibido.some((l) => /^MAIL FROM/i.test(l)));
  } finally {
    await servidor.cerrar();
  }
});

test('un servidor mudo no cuelga la prueba: se rinde con el plazo', async () => {
  const servidor = await servidorSmtp({ mudo: true });
  try {
    const sesion = await smtp.probar(sesionSimple(servidor, { timeout: 400 }));
    assert.ok(sesion.error, 'la prueba termina con un error');
    assert.match(sesion.error.message, /400 ms/);
    assert.equal(sesion.banner, null);
  } finally {
    await servidor.cerrar();
  }
});

test('un puerto cerrado falla sin colgarse', async () => {
  const servidor = await servidorSmtp();
  const puerto = servidor.puerto;
  await servidor.cerrar();

  const sesion = await smtp.probar({ host: '127.0.0.1', puerto, seguridad: 'ninguno', timeout: 800 });
  assert.ok(sesion.error);
  assert.equal(sesion.banner, null);
});

test('un puerto invalido se rechaza antes de abrir nada', async () => {
  await assert.rejects(
    () => smtp.probar({ host: '127.0.0.1', puerto: 99999, seguridad: 'ninguno' }),
    (error) => error.code === 'PARAM_INVALIDO'
  );
});

test('una forma de cifrado inventada se rechaza', async () => {
  await assert.rejects(
    () => smtp.probar({ host: '127.0.0.1', puerto: 25, seguridad: 'ssl' }),
    (error) => error.code === 'PARAM_INVALIDO'
  );
});

test('TLS directo usa la capa de cifrado y lee su certificado', async () => {
  const servidor = await servidorSmtp();
  try {
    const sesion = await smtp.probar(sesionSimple(servidor, { seguridad: 'tls' }), { tls: tlsFalso({ verificado: true }) });

    assert.equal(sesion.seguridadEfectiva, 'tls');
    assert.equal(sesion.tls.protocolo, 'TLSv1.3');
    assert.equal(sesion.tls.cifrado, 'TLS_AES_256_GCM_SHA384');
    assert.equal(sesion.tls.autoridadCertificadora, true);
    assert.equal(sesion.certificado.sujeto, 'CN=falso.test');
  } finally {
    await servidor.cerrar();
  }
});

test('un certificado que no valida se nota en el informe', async () => {
  const servidor = await servidorSmtp();
  try {
    const sesion = await smtp.probar(
      sesionSimple(servidor, { seguridad: 'tls', verificar: false }),
      { tls: tlsFalso({ verificado: false }) }
    );
    assert.equal(sesion.tls.autoridadCertificadora, false);
    assert.equal(sesion.tls.motivoRechazo, 'UNABLE_TO_VERIFY_LEAF_SIGNATURE');
  } finally {
    await servidor.cerrar();
  }
});

/* ------------------------------------------------------------------ *
 * Sesion IMAP
 * ------------------------------------------------------------------ */

test('IMAP: saluda, pide capacidades y entra', async () => {
  const servidor = await servidorImap();
  try {
    const sesion = await imap.probar(
      { host: '127.0.0.1', puerto: servidor.puerto, usuario: 'u@e.com', contrasena: 'secreto', timeout: 2000 },
      { tls: tlsFalso({ verificado: true }) }
    );

    assert.match(sesion.banner, /IMAP4rev1/);
    assert.equal(sesion.preautenticado, false);
    assert.ok(sesion.capacidades.includes('IDLE'));
    assert.equal(sesion.auth.ok, true);
    assert.equal(sesion.auth.intentado, true);
    assert.equal(sesion.tls.autoridadCertificadora, true);
  } finally {
    await servidor.cerrar();
  }
});

test('IMAP: un PREAUTH se cuenta como sesion ya autenticada', async () => {
  const servidor = await servidorImap({ preauth: true });
  try {
    const sesion = await imap.probar(
      { host: '127.0.0.1', puerto: servidor.puerto, usuario: 'u@e.com', contrasena: 'x', timeout: 2000 },
      { tls: tlsFalso() }
    );
    assert.equal(sesion.preautenticado, true);
    assert.equal(sesion.auth.ok, true);
    assert.equal(sesion.auth.intentado, false, 'con PREAUTH no hace falta mandar LOGIN');
    assert.ok(!servidor.recibido.some((l) => /^a2 LOGIN/i.test(l)));
  } finally {
    await servidor.cerrar();
  }
});

test('IMAP: unas credenciales malas se notifican sin tirar la prueba', async () => {
  const servidor = await servidorImap({ aceptaLogin: false });
  try {
    const sesion = await imap.probar(
      { host: '127.0.0.1', puerto: servidor.puerto, usuario: 'u@e.com', contrasena: 'mala', timeout: 2000 },
      { tls: tlsFalso() }
    );
    assert.equal(sesion.auth.intentado, true);
    assert.equal(sesion.auth.ok, false);
    assert.match(sesion.auth.mensaje, /AUTHENTICATIONFAILED/i);
  } finally {
    await servidor.cerrar();
  }
});

test('IMAP: la contrasena del LOGIN no aparece en el informe', async () => {
  const servidor = await servidorImap();
  try {
    const sesion = await imap.probar(
      { host: '127.0.0.1', puerto: servidor.puerto, usuario: 'u@e.com', contrasena: 'contrasena-muy-larga', timeout: 2000 },
      { tls: tlsFalso() }
    );
    assert.ok(!JSON.stringify(sesion).includes('contrasena-muy-larga'));
    assert.ok(
      servidor.recibido.some((l) => l.includes('contrasena-muy-larga')),
      'el servidor si la recibio: lo que se evita es que quede escrita en el informe'
    );
  } finally {
    await servidor.cerrar();
  }
});

test('IMAP: un puerto invalido se rechaza antes de abrir nada', async () => {
  await assert.rejects(
    () => imap.probar({ host: '127.0.0.1', puerto: 0 }),
    (error) => error.code === 'PARAM_INVALIDO'
  );
});

/* ------------------------------------------------------------------ *
 * La herramienta entera
 * ------------------------------------------------------------------ */

test('la herramienta monta el informe sin filtrar la contrasena', async () => {
  const servidor = await servidorSmtp();
  try {
    const result = await herramienta.ejecutar(sesionSimple(servidor, {
      usuario: 'usuario@ejemplo.com',
      contrasena: 'contrasena-que-no-debe-salir'
    }));

    assert.equal(result.tool, 'smtp-validator');
    assert.ok(result.summary.some((s) => s.label === 'Autenticación' && s.tone === 'ok'));
    assert.equal(result.params.contrasena, '(indicada, no se guarda)');
    assert.ok(!JSON.stringify(result).includes('contrasena-que-no-debe-salir'));
  } finally {
    await servidor.cerrar();
  }
});

test('la herramienta avisa cuando la sesion se queda sin cifrar', async () => {
  const servidor = await servidorSmtp({ antesDeStarttls: ['AUTH PLAIN'] });
  try {
    const result = await herramienta.ejecutar(sesionSimple(servidor, {
      seguridad: 'starttls',
      usuario: 'u@e.com',
      contrasena: 'secreto'
    }));

    const titulos = result.findings.map((f) => f.title);
    assert.ok(titulos.some((t) => /no qued[oó] cifrada/i.test(t)), `hallazgos: ${titulos.join(' | ')}`);
    assert.ok(result.summary.some((s) => s.label === 'Cifrado' && s.value === 'Texto plano'));
    assert.equal(result.status, 'warn');
  } finally {
    await servidor.cerrar();
  }
});

test('la herramienta reporta el fallo de autenticacion como hallazgo grave', async () => {
  const servidor = await servidorSmtp({ codigoAuth: '535' });
  try {
    const result = await herramienta.ejecutar(sesionSimple(servidor, { usuario: 'u@e.com', contrasena: 'mala' }));

    // Con la sesion en claro y AUTH LOGIN advertisement, tambien sale el aviso de
    // "sin cifrar": ese es de tipo warn, no el fallo de credenciales.
    const fallo = result.findings.find((f) => /autenticaci[oó]n fall/i.test(f.title));
    assert.ok(fallo, `debe haber un hallazgo de autenticacion: ${result.findings.map((f) => f.title).join(' | ')}`);
    assert.equal(fallo.severity, 'error');
    assert.match(fallo.detail, /535/);
    assert.equal(result.status, 'fail');
  } finally {
    await servidor.cerrar();
  }
});

test('la herramienta no toca el envio si la casilla no esta marcada', async () => {
  const servidor = await servidorSmtp();
  try {
    await herramienta.ejecutar(sesionSimple(servidor, { usuario: 'u@e.com', contrasena: 'secreto' }));
    assert.ok(!servidor.recibido.some((l) => /^MAIL FROM/i.test(l)));
  } finally {
    await servidor.cerrar();
  }
});

test('la herramienta envia solo si la casilla esta marcada', async () => {
  const servidor = await servidorSmtp();
  try {
    const result = await herramienta.ejecutar(sesionSimple(servidor, {
      usuario: 'u@e.com',
      contrasena: 'secreto',
      enviarPrueba: true,
      remitente: 'u@e.com',
      destinatario: 'destino@ejemplo.com'
    }));

    assert.ok(servidor.recibido.includes('MAIL FROM:<u@e.com>'));
    assert.ok(result.sections.some((s) => s.id === 'envio'));
  } finally {
    await servidor.cerrar();
  }
});

test('la herramienta anade IMAP al informe cuando se pide', async () => {
  const smtpFalso = await servidorSmtp();
  const imapFalso = await servidorImap();
  try {
    const result = await herramienta.ejecutar(
      sesionSimple(smtpFalso, {
        usuario: 'u@e.com',
        contrasena: 'secreto',
        probarImap: true,
        imapHost: '127.0.0.1',
        imapPuerto: imapFalso.puerto
      }),
      { deps: { imap: { tls: tlsFalso({ verificado: true }) } } }
    );

    assert.ok(result.sections.some((s) => s.id === 'imap'), 'debe haber seccion de IMAP');
    assert.ok(result.sections.some((s) => s.id === 'etapas-imap'));
    assert.ok(result.summary.some((s) => s.label === 'IMAP'));
  } finally {
    await smtpFalso.cerrar();
    await imapFalso.cerrar();
  }
});

test('probarImap sin servidor IMAP avisa en vez de romper', async () => {
  const servidor = await servidorSmtp();
  try {
    const result = await herramienta.ejecutar(sesionSimple(servidor, { probarImap: true, imapHost: '   ' }));
    assert.ok(result.findings.some((f) => /servidor IMAP/i.test(f.title)));
  } finally {
    await servidor.cerrar();
  }
});

test('sin host, la herramienta falla con una entrada clara', async () => {
  const result = await herramienta.ejecutar({});
  assert.equal(result.status, 'error');
  assert.ok(result.error);
  assert.match(JSON.stringify(result.error), /host|servidor/i);
});

/* ------------------------------------------------------------------ *
 * Lo que el formulario declara
 * ------------------------------------------------------------------ */

test('el formulario declara la contrasena como campo de tipo password', () => {
  const campo = herramienta.campos.find((c) => c.name === 'contrasena');
  assert.ok(campo, 'debe existir el campo contrasena');
  assert.equal(campo.type, 'password');
});

test('el envio de prueba viene desmarcado de serie', () => {
  const enviar = herramienta.campos.find((c) => c.name === 'enviarPrueba');
  assert.equal(enviar.type, 'checkbox');
  assert.equal(enviar.default, false);
});

test('el formulario no trae ninguna credencial por defecto', () => {
  for (const campo of herramienta.campos) {
    if (campo.default === undefined) continue;
    assert.doesNotMatch(String(campo.default), /@/, `${campo.name} no deberia traer un usuario por defecto`);
    assert.doesNotMatch(String(campo.default), /pass|secret/i, `${campo.name} no deberia traer una clave por defecto`);
  }
  for (const nombre of ['usuario', 'contrasena']) {
    const campo = herramienta.campos.find((c) => c.name === nombre);
    assert.equal(campo.default, undefined, `${nombre} no debe venir relleno`);
  }
});

test('los campos de IMAP y de envio solo se muestran cuando hacen falta', () => {
  const porNombre = new Map(herramienta.campos.map((c) => [c.name, c]));
  assert.equal(porNombre.get('remitente').shownWhen, 'enviarPrueba');
  assert.equal(porNombre.get('destinatario').shownWhen, 'enviarPrueba');
  assert.equal(porNombre.get('imapHost').shownWhen, 'probarImap');
  assert.equal(porNombre.get('probarImap').default, false);
});