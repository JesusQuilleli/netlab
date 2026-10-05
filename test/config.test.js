'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const config = require('../src/core/config');

/**
 * Estas pruebas tocan `process.env`, que es global. Se guarda lo que se toca y
 * se restaura despues, porque si no una prueba puede dejar una credencial
 * puesta para las siguientes.
 */
function conVariables(variables, prueba) {
  const previas = {};
  for (const nombre of Object.keys(variables)) previas[nombre] = process.env[nombre];
  Object.assign(process.env, variables);
  try {
    return prueba();
  } finally {
    for (const nombre of Object.keys(variables)) {
      if (previas[nombre] === undefined) delete process.env[nombre];
      else process.env[nombre] = previas[nombre];
    }
  }
}

test('leer devuelve el valor y trata el vacio como que no esta', () => {
  conVariables({ PRUEBA_A: 'valor', PRUEBA_B: '   ', PRUEBA_C: '' }, () => {
    assert.equal(config.leer('PRUEBA_A'), 'valor');
    assert.equal(config.leer('PRUEBA_B'), undefined, 'espacios no son un valor');
    assert.equal(config.leer('PRUEBA_C'), undefined, 'cadena vacia no es un valor');
    assert.equal(config.leer('PRUEBA_INEXISTENTE'), undefined);
  });
});

test('leer quita las comillas que un .env deja pegadas', () => {
  // `KEY="secreto"` en .env significa el valor secreto, sin las comillas.
  conVariables({ PRUEBA_COTAS: '"entre comillas"' }, () => {
    assert.equal(config.leer('PRUEBA_COTAS'), 'entre comillas');
  });
});

test('leerNumero acota y avisa con el valor por defecto cuando no se puede', () => {
  conVariables({ N_BIEN: '587', N_ROTO: 'no es un numero', N_NEGATIVO: '-5' }, () => {
    assert.equal(config.leerNumero('N_BIEN', { min: 1, max: 1024 }), 587);
    assert.equal(config.leerNumero('N_BIEN', { min: 1, max: 100 }), 100, 'debe acotar por arriba');
    assert.equal(config.leerNumero('N_NEGATIVO', { min: 1, porDefecto: 25 }), 1, 'debe acotar por abajo');
    assert.equal(config.leerNumero('N_ROTO', { porDefecto: 30 }), 30);
    assert.equal(config.leerNumero('N_INEXISTENTE', { porDefecto: 30 }), 30);
  });
});

test('leerNumero no confunde el cero con un valor ausente', () => {
  // `Number(0) || porDefecto` daria el valor por defecto. Un puerto 0 es un
  // numero perfectamente valido y con esta comprobacion se respeta.
  conVariables({ N_CERO: '0' }, () => {
    assert.equal(config.leerNumero('N_CERO', { porDefecto: 30 }), 0);
  });
});

test('definida dice que hay algo puesto sin devolver el secreto', () => {
  conVariables({ PRUEBA_CON: 'secreto', PRUEBA_SIN: '' }, () => {
    assert.equal(config.definida('PRUEBA_CON'), true);
    assert.equal(config.definida('PRUEBA_SIN'), false);
    assert.equal(config.definida('PRUEBA_INEXISTENTE'), false);
  });
});

test('enmascarar deja ver el final y tapa el resto', () => {
  // Solo el final: es lo justo para reconocer una contrasena sin enseñarla.
  // El principio no hace falta y cuanto mas se enseña peor.
  const mascara = config.enmascarar('ABCDEFGHIJKLMNOP');
  assert.ok(mascara.endsWith('MNOP'), 'el final debe verse');
  assert.ok(!mascara.includes('ABCDEFGH'), 'el principio no debe verse');
  assert.ok(!mascara.includes('EFGHIJKL'), 'el medio no debe verse');
});

test('enmascarar tapa entero un valor corto, en vez de enseñar una parte', () => {
  // Enseñar "•••abc" de un valor de tres letras no ocultaria nada. Con cuatro
  // o menos no hay nada seguro que enseñar, asi que se tapa todo.
  for (const corto of ['abcd', 'abc', 'a']) {
    const mascara = config.enmascarar(corto);
    assert.ok(!mascara.includes(corto), `"${corto}" no debe quedar a la vista`);
    assert.match(mascara, /^•+$/, 'debe quedar todo enmascarado');
  }
});

test('enmascarar no filtra valores vacios', () => {
  assert.equal(config.enmascarar(''), '(sin configurar)');
  assert.equal(config.enmascarar(null), '(sin configurar)');
  assert.equal(config.enmascarar(undefined), '(sin configurar)');
});

test('variablePerfil construye el nombre de la variable', () => {
  assert.equal(config.variablePerfil('buzon', 'HOST'), 'NETLAB_MAIL_BUZON_HOST');
  assert.equal(config.variablePerfil('BUZON', 'IMAP_PORT'), 'NETLAB_MAIL_BUZON_IMAP_PORT');
});

test('IMAP_PORT es del perfil BUZON, no un perfil aparte', () => {
  // El fallo: `_IMAP_PORT` acaba en `_PORT`, asi que buscando el sufijo corto
  // primero la variable se leia como el perfil "BUZON_IMAP" con un puerto
  // suelto. En la web eso ofrecia un perfil de correo que no tiene ni host ni
  // usuario, y el BUZON de verdad aparecia sin su puerto IMAP.
  conVariables(
    {
      NETLAB_MAIL_BUZON_HOST: 'correo.example',
      NETLAB_MAIL_BUZON_PORT: '465',
      NETLAB_MAIL_BUZON_IMAP_PORT: '993',
      NETLAB_MAIL_BUZON_USER: 'boton@example',
      NETLAB_MAIL_BUZON_PASS: 'secreto',
      NETLAB_MAIL_SALIDA_HOST: 'salida.example',
      NETLAB_MAIL_SALIDA_PORT: '587'
    },
    () => {
      const perfiles = config.listarPerfilesCorreo();
      const claves = perfiles.map((p) => p.clave).sort();

      assert.deepEqual(claves, ['BUZON', 'SALIDA'], 'no debe aparecer ningun perfil fantasma');

      const buzon = perfiles.find((p) => p.clave === 'BUZON');
      assert.equal(buzon.imapPort, 993);
      assert.ok(
        buzon.variables.includes('NETLAB_MAIL_BUZON_IMAP_PORT'),
        'IMAP_PORT debe declararse como parte del BUZON'
      );
    }
  );
});

test('un perfil se describe sin devolver la contrasena', () => {
  conVariables(
    {
      NETLAB_MAIL_BUZON_HOST: 'correo.example',
      NETLAB_MAIL_BUZON_PORT: '465',
      NETLAB_MAIL_BUZON_SECURE: 'true',
      NETLAB_MAIL_BUZON_USER: 'boton@example',
      NETLAB_MAIL_BUZON_PASS: 'la-contrasena-secreta'
    },
    () => {
      const buzon = config.listarPerfilesCorreo().find((p) => p.clave === 'BUZON');

      assert.equal(buzon.host, 'correo.example');
      assert.equal(buzon.port, 465);
      assert.equal(buzon.secure, true);
      assert.equal(buzon.usuario, true, 'dice que hay usuario, no cual');
      assert.equal(buzon.contrasena, true, 'dice que hay contrasena, no cual');

      // Lo importante: la cadena de la contrasena no puede aparecer por ningun
      // lado de la descripcion del perfil.
      const serializado = JSON.stringify(buzon);
      assert.ok(!serializado.includes('la-contrasena-secreta'), 'la contrasena no puede aparecer en la descripcion');
      assert.ok(!serializado.includes('boton@example'), 'el usuario tampoco hace falta para describirlo');
    }
  );
});
