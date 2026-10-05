'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createRedactor, redact, redactDeep, MASK } = require('../src/core/redact');

test('enmascara un secreto conocido en texto arbitrario', () => {
  const r = createRedactor({ secrets: ['nM9SewyCcYd?78z%'] });
  const salida = r('usuario ok, pass nM9SewyCcYd?78z% conectado');
  assert.ok(!salida.includes('nM9SewyCcYd?78z%'), 'el secreto debe desaparecer');
  assert.ok(salida.includes(MASK));
});

test('enmascara todas las apariciones, no solo la primera', () => {
  const r = createRedactor({ secrets: ['secreto123'] });
  const salida = r('secreto123 y secreto123 otra vez');
  assert.strictEqual(salida.split(MASK).length - 1, 2);
});

test('enmascara un secreto aunque venga escapado en una regex', () => {
  const r = createRedactor({ secrets: ['a.b*c+d'] });
  const salida = r('valor = a.b*c+d');
  assert.ok(!salida.includes('a.b*c+d'));
});

test('detecta el par access-key-id / secret de AWS aunque no esten registrados', () => {
  // Par real extraido de legacy/Validate config SMTP/validate-smtp-2.js
  const texto = 'user=AKIA3RFPSBVNWYFQ6CO7 pass=BP41v3R6Sq6itLgShxAa9QY6MKBPvUIH0ltb1AW8devI';
  const salida = redact(texto);
  assert.ok(!salida.includes('AKIA3RFPSBVNWYFQ6CO7'), 'el access key debe desaparecer');
  assert.ok(!salida.includes('BP41v3R6Sq6itLgShxAa9QY6MKBPvUIH0ltb1AW8devI'), 'el secret debe desaparecer');
});

test('enmascara URLs con credenciales embebidas', () => {
  const salida = redact('conectando a imaps://usuario:sup3rsecreto@imap.ejemplo.com:993');
  assert.ok(salida.includes('usuario:'), 'el usuario se conserva');
  assert.ok(!salida.includes('sup3rsecreto'), 'la password no');
});

test('enmascara el payload base64 de AUTH LOGIN usando su forma decodificada', () => {
  // "BP41v3R6Sq6itLgShxAa9QY6MKBPvUIH0ltb1AW8devI" codificado en base64
  const r = createRedactor({ secrets: ['BP41v3R6Sq6itLgShxAa9QY6MKBPvUIH0ltb1AW8devI'] });
  const b64 = Buffer.from('BP41v3R6Sq6itLgShxAa9QY6MKBPvUIH0ltb1AW8devI').toString('base64');
  const salida = r(`[SMTP] C244: BASE64 ${b64}`);
  assert.ok(!salida.includes(b64), 'el base64 debe desaparecer');
});

test('enmascara el comando IMAP LOGIN completo', () => {
  const salida = redact('a1 LOGIN mi@correo.com "claveSecreta123"');
  assert.ok(!salida.includes('claveSecreta123'));
  assert.ok(salida.includes('mi@correo.com'), 'el usuario se conserva para diagnostico');
});

test('enmascara cabeceras de API key', () => {
  const salida = redact('Key: 8380166e0a98431dbf1d5b4ab5524d1e7 headers enviados');
  assert.ok(!salida.includes('8380166e0a98431dbf1d5b4ab5524d1e7'));
});

test('enmascara un bloque de clave privada PEM', () => {
  const pem = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEAx0000secret0000secret0000secret',
    '-----END RSA PRIVATE KEY-----'
  ].join('\n');
  const salida = redact(`pegado por el usuario:\n${pem}`);
  assert.ok(!salida.includes('secret0000'));
  assert.ok(salida.includes('private-key'));
});

test('NO destruye texto legitimo que parece una IP o un host', () => {
  const texto = 'Conexión a 166.1.88.250:465 y a smtp.hostingssi.com OK';
  assert.strictEqual(redact(texto), texto, 'no debe alterar datos de diagnostico normales');
});

test('NO destruye banners SMTP/IMAPlegitimos', () => {
  const banner = '220 smtp.hostingssi.com ESMTP Amazon SES - mm1east1';
  assert.strictEqual(redact(banner), banner);
});

test('redactDeep borra campos sensibles sin tocar los demas', () => {
  const entrada = { user: 'angel@ejemplo.com', password: 'clave123', puerto: 465 };
  const salida = redactDeep(entrada);
  assert.strictEqual(salida.user, 'angel@ejemplo.com');
  assert.strictEqual(salida.puerto, 465);
  assert.strictEqual(salida.password, MASK);
});

test('redactDeep recorre arrays y objetos anidados', () => {
  const entrada = { corridas: [{ config: { auth: { pass: 'secreto' } } }] };
  const salida = redactDeep(entrada);
  assert.strictEqual(salida.corridas[0].config.auth.pass, MASK);
});

test('redactDeep no muta el original', () => {
  const original = { password: 'visible' };
  redactDeep(original);
  assert.strictEqual(original.password, 'visible');
});

test('acepta null y undefined sin lanzar', () => {
  assert.strictEqual(redact(null), '');
  assert.strictEqual(redact(undefined), '');
});

test('redactDeep conserva los numeros como numeros, no como texto', () => {
  // Convierten a '465' el puerto 465 se rompia al serializar para la UI.
  const salida = redactDeep({ puerto: 465, puertoTxt: '465', activo: true, vacio: null });
  assert.strictEqual(salida.puerto, 465);
  assert.strictEqual(salida.activo, true);
  assert.strictEqual(salida.vacio, null);
});

test('redactDeep no considera secreto un campo llamado "key" ni "auth"', () => {
  // 'key' es legitimo en este dominio (llaves DKIM, claves de API que se
  // quieren conservar para diagnostico) y 'auth' es un objeto contenedor.
  const salida = redactDeep({ auth: { user: 'angel@ejemplo.com', mechanism: 'LOGIN' }, key: 'mg._domainkey' });
  assert.strictEqual(salida.auth.user, 'angel@ejemplo.com');
  assert.strictEqual(salida.key, 'mg._domainkey');
});

test('acepta una lista propia de campos sensibles', () => {
  const salida = redactDeep({ apiKey: 'AKIA3RFPSBVNWYFQ6CO7' }, ['apiKey']);
  assert.strictEqual(salida.apiKey, MASK);
});

test('redactDeep acepta null y undefined sin lanzar', () => {
  assert.strictEqual(redactDeep(null), null);
  assert.strictEqual(redactDeep(undefined), undefined);
});

test('ignora secretos demasiado cortos para no romper texto normal', () => {
  const r = createRedactor({ secrets: ['ab', 'a'] });
  assert.strictEqual(r('la palabra abc aparece aqui'), 'la palabra abc aparece aqui');
});