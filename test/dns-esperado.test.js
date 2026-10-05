'use strict';

/**
 * test/dns-esperado.test.js — Pruebas del parser de estado esperado.
 *
 * Los dos formatos de entrada son los que hay en `legacy/Check DNS/`, así que
 * las pruebas usan el mismo contenido real. Si cambia el formato de lo que
 * exporta Cloudflare, este es el sitio donde hay que enterarse.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { parsear, detectarFormato, normalizarNombre, normalizarValor, limpiarTxt } = require('../src/core/dns-esperado');

/** Exportación de zona real, recortada a lo que importa para las pruebas. */
const ZONA = `;;
;; Domain:     berakah.com.ve.
;; Exported:   2026-09-25 17:44:22
;;
;; This file is intended for use for informational and archival
;;
berakah.com.ve	3600	IN	SOA	bjorn.ns.cloudflare.com. dns.cloudflare.com. 2054202486 10000 2400 604800 3600

;; NS Records
berakah.com.ve.	86400	IN	NS	bjorn.ns.cloudflare.com.
berakah.com.ve.	86400	IN	NS	karsyn.ns.cloudflare.com.

;; A Records
berakah.com.ve.	1	IN	A	166.1.85.133 ; cf_tags=cf-proxied:false
www.berakah.com.ve.	1	IN	A	166.1.85.133 ; cf_tags=cf-proxied:false

;; MX Records
berakah.com.ve	1	IN	MX	10 mail.berakah.com.ve.

;; PTR Records
berakah.com.ve	1	IN	PTR	berakah.com.ve.

;; TXT Records
berakah.com.ve	1	IN	TXT	"v=spf1 include:spf.mg.hostingssi.com ~all"
_dmarc.berakah.com.ve.	1	IN	TXT	"v=DMARC1; p=quarantine"
mg._domainkey.berakah.com.ve.	1	IN	TXT	"p=MIIBIjANBg" "hkdfj392hd"
`;

/** Formato de ticket, tal cual estaba en legacy/Check DNS/validar.txt. */
const TICKET = `**Registro TXT** para DKIM:

Nombre: \`mg._domainkey.berakah.com.ve\`
Valor: \`v=DKIM1; k=rsa; p=MIIBIjANBgkqhkih\`

**Registro TXT** para SPF del dominio principal:

Nombre: \`berakah.com.ve\`
Valor: \`v=spf1 include:spf.mg.hostingssi.com ~all\`

**Registro MX** para los rebotes:

Nombre: \`bounces.berakah.com.ve\`
Prioridad: \`10\`
Valor: \`feedback-smtp.us-east-1.amazonses.com\`
`;

/* ------------------------------------------------------------------ *
 * Normalización
 * ------------------------------------------------------------------ */

test('el nombre se independiza del punto final y de las mayúsculas', () => {
  assert.equal(normalizarNombre('Ejemplo.COM.'), 'ejemplo.com');
  assert.equal(normalizarNombre('  ejemplo.com  '), 'ejemplo.com');
  assert.equal(normalizarNombre('_dmarc.ejemplo.com.'), '_dmarc.ejemplo.com');
});

test('los trozos de un TXT se enlazan sin separador', () => {
  // El RFC dice que las cadenas de un mismo TXT forman un solo valor. Meter un
  // espacio entre ellas produce un registro distinto e imposible de validar,
  // que es justo lo que pasaba con las claves DKIM partidas.
  assert.equal(limpiarTxt('"v=DKIM1; k=rsa; p=AAA" "BBB"'), 'v=DKIM1; k=rsa; p=AAABBB');
  assert.equal(limpiarTxt('"texto suelto"'), 'texto suelto');
  assert.equal(limpiarTxt('sin comillas'), 'sin comillas');
});

test('normalizarValor deja cada tipo en una forma comparable', () => {
  assert.equal(normalizarValor('TXT', '"v=spf1 ~all"'), 'v=spf1 ~all');
  assert.equal(normalizarValor('MX', 'mail.ejemplo.com.', 10), '10 mail.ejemplo.com');
  assert.equal(normalizarValor('MX', 'MAIL.Ejemplo.COM.', 10), '10 mail.ejemplo.com', 'sin punto ni mayúsculas');
  assert.equal(normalizarValor('NS', 'NS1.Ejemplo.COM.'), 'ns1.ejemplo.com');
  assert.equal(normalizarValor('A', '1.2.3.4'), '1.2.3.4');
  assert.equal(normalizarValor('SRV', '5 587 smtp.ejemplo.com.', 10), '10 5 587 smtp.ejemplo.com');
});

/* ------------------------------------------------------------------ *
 * Detección
 * ------------------------------------------------------------------ */

test('detecta cada formato por su estructura, no por su nombre', () => {
  assert.equal(detectarFormato(ZONA), 'bind');
  assert.equal(detectarFormato(TICKET), 'ticket');
  assert.equal(detectarFormato('esto es un texto suelto sin ninguna estructura'), null);
  assert.equal(detectarFormato(''), null);
  assert.equal(detectarFormato(null), null);
});

test('un archivo que no se reconoce no inventa registros', () => {
  const r = parsear('Hola, esto es una nota, no un archivo de zona.');
  assert.equal(r.formato, null);
  assert.equal(r.registros.length, 0);
  assert.ok(r.avisos.some((a) => /No se reconoce el formato/.test(a)), 'debe decirlo claramente');
});

/* ------------------------------------------------------------------ *
 * Formato BIND
 * ------------------------------------------------------------------ */

test('lee una exportación de zona de Cloudflare', () => {
  const r = parsear(ZONA);

  assert.equal(r.formato, 'bind');
  assert.equal(r.registros.length, 9, 'soa + 2 ns + 2 a + 1 mx + 3 txt; el PTR queda fuera');
  assert.deepEqual(r.nombres, [
    '_dmarc.berakah.com.ve',
    'berakah.com.ve',
    'mg._domainkey.berakah.com.ve',
    'www.berakah.com.ve'
  ]);

  const soa = r.registros.find((x) => x.tipo === 'SOA');
  assert.match(soa.normalizado, /bjorn\.ns\.cloudflare\.com dns\.cloudflare\.com 2054202486/);

  const mx = r.registros.find((x) => x.tipo === 'MX');
  assert.equal(mx.normalizado, '10 mail.berakah.com.ve', 'la prioridad se separa del host');

  const dmarc = r.registros.find((x) => x.nombre === '_dmarc.berakah.com.ve');
  assert.equal(dmarc.normalizado, 'v=DMARC1; p=quarantine');

  const dkim = r.registros.find((x) => x.tipo === 'TXT' && x.nombre.includes('domainkey'));
  assert.equal(dkim.normalizado, 'p=MIIBIjANBghkdfj392hd', 'las dos cadenas se pegan sin espacio');
});

test('salta el comentario de Cloudflare que va detrás del valor', () => {
  const r = parsear(ZONA);
  const a = r.registros.find((x) => x.tipo === 'A' && x.nombre === 'www.berakah.com.ve');
  assert.equal(a.normalizado, '166.1.85.133', 'el "; cf_tags=..." no se cuela en el valor');
});

test('los PTR se ignoran pero se avisa de que se han dejado fuera', () => {
  // Un PTR necesita saber la IP de origen para comprobarse, y un archivo de
  // zona no la trae. Dejarlo pasar como si se pudiera verificar daría un
  // "coincide" que nadie ha comprobado.
  const r = parsear(ZONA);
  assert.ok(!r.registros.some((x) => x.tipo === 'PTR'));
  assert.ok(r.avisos.some((a) => /ignoradas/.test(a)));
});

test('agrupa por nombre para poder consultar lo justo', () => {
  const r = parsear(ZONA);
  const delDominio = r.porNombre['berakah.com.ve'].map((x) => x.tipo).sort();
  assert.deepEqual(delDominio, ['A', 'MX', 'NS', 'NS', 'SOA', 'TXT']);
});

test('los duplicados se eliminan para no comparar dos veces lo mismo', () => {
  const repetido = ZONA + '\nberakah.com.ve.	1	IN	A	166.1.85.133 ; cf_tags=cf-proxied:false\n';
  const r = parsear(repetido);
  const aes = r.registros.filter((x) => x.tipo === 'A' && x.nombre === 'berakah.com.ve');
  assert.equal(aes.length, 1);
});

/* ------------------------------------------------------------------ *
 * Formato ticket
 * ------------------------------------------------------------------ */

test('lee el formato de ticket con Nombre, Valor y Prioridad', () => {
  const r = parsear(TICKET);

  assert.equal(r.formato, 'ticket');
  assert.equal(r.registros.length, 3);

  const mx = r.registros.find((x) => x.tipo === 'MX');
  assert.equal(mx.nombre, 'bounces.berakah.com.ve');
  assert.equal(mx.normalizado, '10 feedback-smtp.us-east-1.amazonses.com');

  const dkim = r.registros.find((x) => x.nombre.includes('domainkey'));
  assert.equal(dkim.normalizado, 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkih', 'se quitan las comillas inversas');
});

test('un ticket bien escrito no produce avisos falsos', () => {
  // Regresión: se avisaba de "se anuncia pero no llega a tener valor" una vez
  // por cada bloque, aunque todos tuvieran su Valor. Cinco avisos falsos en un
  // archivo de cinco líneas, y el usuario deja de leer los avisos.
  const r = parsear(TICKET);
  assert.deepEqual(r.avisos, [], `avisos inesperados: ${r.avisos.join(' ; ')}`);
});

test('avisa de un bloque que se anuncia y se queda sin valor', () => {
  const roto = TICKET + '\n**Registro A** para el servidor:\n\nNombre: `nuevo.ejemplo.com`\n';
  const r = parsear(roto);
  assert.ok(
    r.avisos.some((a) => /nuevo\.ejemplo\.com.*se anuncia pero no llega a tener valor/.test(a)),
    `debería avisar del bloque incompleto; avisos: ${r.avisos.join(' ; ')}`
  );
});

test('avisa de un Valor sin título que diga el tipo', () => {
  const r = parsear('Nombre: `ejemplo.com`\nValor: `1.2.3.4`\n');
  assert.equal(r.registros.length, 0);
  assert.ok(r.avisos.some((a) => /sin título/.test(a)));
});

/* ------------------------------------------------------------------ *
 * Casos raros
 * ------------------------------------------------------------------ */

test('un TXT con punto y coma no se confunde con un comentario', () => {
  // El SPF y el DMARC llevan punto y coma dentro del valor. Si se cortara la
  // línea en el primer `;`, la comparación fallaría siempre.
  const zona = 'ejemplo.com\t1\tIN\tTXT\t"v=spf1 include:_spf.ejemplo.com ~all" ; comentario\n';
  const r = parsear(zona);
  assert.equal(r.registros.length, 1);
  assert.equal(r.registros[0].normalizado, 'v=spf1 include:_spf.ejemplo.com ~all');
});

test('acepta líneas sin TTL y sin clase', () => {
  const r = parsear('ejemplo.com IN MX 20 mx2.ejemplo.com.\n');
  assert.equal(r.registros.length, 1);
  assert.equal(r.registros[0].normalizado, '20 mx2.ejemplo.com');
});

test('avisa de un registro que se anuncia pero no trae datos', () => {
  const r = parsear('ejemplo.com\t1\tIN\tMX\n');
  assert.ok(r.avisos.some((a) => /no trae valor/.test(a)));
});
