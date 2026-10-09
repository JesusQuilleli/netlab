'use strict';

/**
 * test/tls-checker.test.js — Pruebas del verificador TLS.
 *
 * El servidor TLS falso usa un certificado autofirmado de `test/fixtures/tls`,
 * así que la criptografía es real: `tls.connect` interpreta y valida el
 * certificado de verdad. Lo que se prueba, por tanto, no es un mock que siempre
 * responde bien, sino la cadena completa (inspección, sondeo de protocolos,
 * auditoría y calificación).
 *
 * `calcularNota` se prueba aparte, como función pura, porque concentra las
 * reglas de la nota y no necesita red.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const tls = require('node:tls');

const herramienta = require('../src/tools/tls-checker');
const tlsNet = require('../src/core/net/tls');

const CERT = path.join(__dirname, 'fixtures', 'tls', 'selfsigned.crt.pem');
const KEY = path.join(__dirname, 'fixtures', 'tls', 'selfsigned.key.pem');

function levantarServidor() {
  const servidor = tls.createServer(
    {
      cert: fs.readFileSync(CERT),
      key: fs.readFileSync(KEY)
    },
    (socket) => {
      // El servidor TLS no habla HTTP aquí: solo hace falta el handshake.
      socket.on('error', () => {});
    }
  );
  return new Promise((resolve) => {
    servidor.listen(0, '127.0.0.1', () => {
      resolve({ servidor, puerto: servidor.address().port });
    });
  });
}

/* ------------------------------------------------------------------ *
 * Funciones puras
 * ------------------------------------------------------------------ */

test('esCifradoDebil reconoce familias inseguras', () => {
  assert.equal(tlsNet.esCifradoDebil('RC4-SHA'), true);
  assert.equal(tlsNet.esCifradoDebil('DES-CBC3-SHA'), true);
  assert.equal(tlsNet.esCifradoDebil('ECDHE-RSA-AES256-GCM-SHA384'), false);
  assert.equal(tlsNet.esCifradoDebil('TLS_AES_256_GCM_SHA384'), false);
  assert.equal(tlsNet.esCifradoDebil('ADH-AES256-GCM-SHA384'), true);
});

test('tieneForwardSecrecy distingue ECDHE de RSA', () => {
  assert.equal(tlsNet.tieneForwardSecrecy('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.2'), true);
  assert.equal(tlsNet.tieneForwardSecrecy('AES256-GCM-SHA384', 'TLSv1.2'), false);
  // TLS 1.3 siempre da secreto hacia adelante, independientemente del nombre.
  assert.equal(tlsNet.tieneForwardSecrecy('TLS_AES_256_GCM_SHA384', 'TLSv1.3'), true);
});

test('calcularNota: una configuración impecable saca un A', () => {
  const nota = tlsNet.calcularNota({
    protocoloNegociado: 'TLSv1.3',
    protocolos: { 'TLSv1.3': true, 'TLSv1.2': true, 'TLSv1.1': false, 'TLSv1': false },
    certificado: {
      diasRestantes: 200,
      autoFirmado: false,
      autoridadCertificadora: true,
      nombresAlternativos: ['DNS:ejemplo.com'],
      tipoClave: 'rsa',
      tamanoClave: 2048,
      algoritmoFirma: 'sha256WithRSAEncryption'
    },
    cifradoDebil: false,
    forwardSecrecy: true,
    ocspStapled: true,
    hsts: { presente: true }
  });
  assert.equal(nota.letra, 'A');
  assert.equal(nota.puntos, 100);
  assert.equal(nota.caps.length, 0);
});

test('calcularNota: un certificado expirado hunde la nota a F', () => {
  const nota = tlsNet.calcularNota({
    protocoloNegociado: 'TLSv1.3',
    protocolos: { 'TLSv1.3': true, 'TLSv1.2': true },
    certificado: {
      diasRestantes: -3,
      autoFirmado: false,
      autoridadCertificadora: true,
      nombresAlternativos: ['DNS:ejemplo.com'],
      tipoClave: 'rsa',
      tamanoClave: 2048,
      algoritmoFirma: 'sha256WithRSAEncryption'
    },
    cifradoDebil: false,
    forwardSecrecy: true,
    ocspStapled: true,
    hsts: { presente: true }
  });
  assert.equal(nota.letra, 'F');
  assert.ok(nota.caps.some((c) => /expirado/i.test(c.titulo)));
});

test('calcularNota: un autofirmado hunde la nota aunque el resto esté bien', () => {
  const nota = tlsNet.calcularNota({
    protocoloNegociado: 'TLSv1.3',
    protocolos: { 'TLSv1.3': true, 'TLSv1.2': true },
    certificado: {
      diasRestantes: 300,
      autoFirmado: true,
      autoridadCertificadora: false,
      nombresAlternativos: ['DNS:localhost'],
      tipoClave: 'rsa',
      tamanoClave: 2048,
      algoritmoFirma: 'sha256WithRSAEncryption'
    },
    cifradoDebil: false,
    forwardSecrecy: true,
    ocspStapled: true,
    hsts: { presente: true }
  });
  assert.equal(nota.letra, 'F');
});

test('calcularNota: aceptar TLS 1.0 resta y lo deja en la tabla de deducciones', () => {
  const nota = tlsNet.calcularNota({
    protocoloNegociado: 'TLSv1.2',
    protocolos: { 'TLSv1.3': true, 'TLSv1.2': true, 'TLSv1.1': false, 'TLSv1': true },
    certificado: {
      diasRestantes: 200,
      autoFirmado: false,
      autoridadCertificadora: true,
      nombresAlternativos: ['DNS:ejemplo.com'],
      tipoClave: 'rsa',
      tamanoClave: 2048,
      algoritmoFirma: 'sha256WithRSAEncryption'
    },
    cifradoDebil: false,
    forwardSecrecy: true,
    ocspStapled: true,
    hsts: { presente: true }
  });
  assert.equal(nota.letra, 'B');
  assert.ok(nota.deducciones.some((d) => /obsoletos/i.test(d.titulo)));
});

test('calcularNota: clave RSA corta limita la nota a C como mucho', () => {
  const nota = tlsNet.calcularNota({
    protocoloNegociado: 'TLSv1.3',
    protocolos: { 'TLSv1.3': true, 'TLSv1.2': true },
    certificado: {
      diasRestantes: 200,
      autoFirmado: false,
      autoridadCertificadora: true,
      nombresAlternativos: ['DNS:ejemplo.com'],
      tipoClave: 'rsa',
      tamanoClave: 1024,
      algoritmoFirma: 'sha256WithRSAEncryption'
    },
    cifradoDebil: false,
    forwardSecrecy: true,
    ocspStapled: true,
    hsts: { presente: true }
  });
  assert.ok(['B', 'C'].includes(nota.letra));
  assert.ok(nota.caps.some((c) => /RSA/i.test(c.titulo)));
});

test('calcularNota: no comprobado no es lo mismo que fallo (sin deducción)', () => {
  const base = {
    protocoloNegociado: 'TLSv1.3',
    protocolos: { 'TLSv1.3': true, 'TLSv1.2': true },
    certificado: {
      diasRestantes: 200,
      autoFirmado: false,
      autoridadCertificadora: true,
      nombresAlternativos: ['DNS:ejemplo.com'],
      tipoClave: 'rsa',
      tamanoClave: 2048,
      algoritmoFirma: 'sha256WithRSAEncryption'
    },
    cifradoDebil: false,
    forwardSecrecy: true
  };
  const sinDatos = tlsNet.calcularNota({ ...base, ocspStapled: null, hsts: null });
  const conFallo = tlsNet.calcularNota({ ...base, ocspStapled: false, hsts: { presente: false } });
  assert.equal(sinDatos.letra, 'A');
  assert.equal(sinDatos.deducciones.length, 0);
  assert.equal(conFallo.letra, 'A');
  assert.equal(conFallo.deducciones.length, 2);
});

/* ------------------------------------------------------------------ *
 * Integración con servidor TLS real
 * ------------------------------------------------------------------ */

test('inspeccionar lee un certificado real (autofirmado, con clave y SAN)', async () => {
  const { servidor, puerto } = await levantarServidor();
  try {
    const { socket, certificado } = await tlsNet.conectar({ host: '127.0.0.1', port: puerto, timeout: 5000 });
    try {
      assert.ok(certificado);
      assert.equal(certificado.autoFirmado, true);
      assert.equal(certificado.autoridadCertificadora, false);
      assert.equal(certificado.tipoClave, 'rsa');
      assert.equal(certificado.tamanoClave, 2048);
      assert.match(certificado.algoritmoFirma, /sha256/i);
      assert.ok(certificado.nombresAlternativos.some((n) => /DNS:localhost/.test(n)));
      assert.ok(Array.isArray(certificado.cadena));
      assert.ok(certificado.huella256);
    } finally {
      socket.destroy();
    }
  } finally {
    servidor.close();
  }
});

test('sondearProtocolos detecta que el servidor local acepta TLS 1.3 y 1.2', async () => {
  const { servidor, puerto } = await levantarServidor();
  try {
    const soporte = await tlsNet.sondearProtocolos({ host: '127.0.0.1', port: puerto, timeout: 5000 });
    assert.equal(soporte['TLSv1.3'], true);
    assert.equal(soporte['TLSv1.2'], true);
  } finally {
    servidor.close();
  }
});

test('la herramienta completa audita un servidor autofirmado y da F', async () => {
  const { servidor, puerto } = await levantarServidor();
  try {
    const resultado = await herramienta.ejecutar({
      host: '127.0.0.1',
      puerto,
      verificarCertificado: true,
      comprobarProtocolos: false,
      comprobarStapling: false,
      comprobarHSTS: false,
      timeout: 5000
    });

    assert.equal(resultado.tool, 'tls-checker');
    const titulos = resultado.sections.map((s) => s.title);
    assert.ok(titulos.includes('Ficha del certificado'));
    assert.ok(titulos.includes('Cadena de certificados'));
    assert.ok(titulos.some((t) => /nota/i.test(t)));

    const nota = resultado.summary.find((s) => /Nota TLS/i.test(s.label));
    assert.equal(nota.value, 'F');

    // Debe haber al menos un hallazgo de error (autofirmado / no validado).
    assert.ok(resultado.findings.some((f) => f.severity === 'error'));
  } finally {
    servidor.close();
  }
});
