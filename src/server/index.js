/**
 * index.js — Arranque del servidor web.
 *
 * MODULO DE ENTRADA. Todo lo comprobable esta en `app.js`; aqui solo se lee la
 * configuracion, se avisa de lo que importa y se abre el puerto.
 *
 * Los avisos no son adorno: cada uno de los que sale por consola es una
 * situacion en la que la web funciona pero hace menos de lo que uno creeria.
 *
 * @module server/index
 */

'use strict';

const config = require('../core/config');
const { crearApp } = require('./app');
const { registro } = require('./herramientas');

/**
 * Arranca el servidor.
 *
 * @param {object} [opciones]
 * @param {number|string} [opciones.port] Puerto. Por defecto, PORT o 4310.
 * @param {string} [opciones.host] Interfaz. Por defecto, HOST o 127.0.0.1.
 * @returns {Promise<{app: object, server: import('node:http').Server, url: string, cerrar: () => Promise<void>}>}
 */
async function arrancar(opciones = {}) {
  config.cargar();

  const host = opciones.host || config.leer('HOST') || (process.env.PORT ? '0.0.0.0' : '127.0.0.1');
  const puerto = Number(process.env.PORT ?? opciones.port ?? config.leer('PORT') ?? 4310);

  const { app, auth, historial, backup } = crearApp();

  // Copia de seguridad diaria de `data/netlab.db`. El planificador falla sin
  // tumbar el proceso: hace una copia al arrancar, avisa de los fallos y se
  // refresca solo (el timer es `unref`, asi que no mantiene vivo el proceso).
  backup.avisar = (e) => console.error(`  ERROR: backup no realizado: ${e.message}`);
  backup.programar();

  // El aviso que mas importa: un servidor de diagnostico escuchando en todas las
  // interfaces sin autenticacion es un escaner de puertos abierto a Internet.
  if (host !== '127.0.0.1' && host !== 'localhost' && !auth.activo) {
    console.warn(
      '\n  AVISO: escuchando en %s sin autenticación (AUTH_ENABLED=false).\n' +
        '  Cualquiera que llegue a este puerto puede lanzar diagnósticos desde tu servidor.\n' +
        '  Pon AUTH_ENABLED=true, o deja HOST=127.0.0.1 si es local.\n',
      host
    );
  }

  if (auth.enTextoPlano) {
    console.warn(
      '\n  AVISO: AUTH_PASSWORD_HASH no está en formato scrypt, así que la contraseña\n' +
        '  se compara en texto plano. Es solo para pruebas; genera el hash con\n' +
        '  npm run hash-password -- "tu-password" y ponlo en el .env\n'
    );
  }

  for (const aviso of registro().avisos) console.warn(`  AVISO: ${aviso}`);

  // Limpieza periodica de sesiones caducadas, para que el mapa en memoria no
  // crezca sin limite si el servidor vive mucho tiempo con muchos usuarios.
  const limpieza = setInterval(() => auth.limpiar(), 15 * 60 * 1000);
  limpieza.unref?.();

  const server = await new Promise((cumplir, fallar) => {
    const s = app.listen(puerto, host);
    s.once('listening', () => cumplir(s));
    s.once('error', fallar);
  });

  const direccion = server.address();
  const shown = direccion.address === '0.0.0.0' || direccion.address === '::' ? 'localhost' : direccion.address;
  const url = `http://${shown}:${direccion.port}`;

  console.log(`  netlab escuchando en ${url}`);
  console.log(`  ${registro().herramientas.length} herramientas · ${auth.activo ? `sesión con «${auth.usuario}»` : 'sin autenticación'}`);

  const cerrar = () =>
    new Promise((cumplir) => {
      clearInterval(limpieza);
      backup.detener();
      historial.cerrar();
      server.close(() => cumplir());
    });

  return { app, server, auth, historial, url, cerrar };
}

/** Se ejecuta solo cuando el archivo se lanza directamente, no cuando se importa. */
if (require.main === module) {
  arrancar().catch((e) => {
    console.error(`\n  No se pudo arrancar netlab: ${e.message}\n`);
    process.exit(1);
  });
}

module.exports = { arrancar };
