/**
 * fixture.ts — Copia literal de lo que devuelve `GET /api/herramientas`.
 *
 * Se copio del backend en marcha, no se escribio a mano. Es lo que hay que
 * consultar cuando una duda es "que envia el servidor de verdad": la respuesta
 * esta aqui, y los tests del formulario y del informe trabajan contra esto en
 * lugar de contra una suposicion.
 *
 * Solo estan `smtp-validator` y `subnet-analyzer`, los dos que tienen los
 * detalles que rompen: el desplegable de seguridad (opciones `value`/`label`) y
 * el campo VLSM de tipo `lista-requisitos`.
 */

import type { Herramienta } from '../lib/tipos'

export const SMTP_VALIDATOR: Herramienta = {
  id: 'smtp-validator',
  titulo: 'Validador SMTP',
  descripcion:
    'Prueba un servidor SMTP con los datos que escribas: conexión, STARTTLS o TLS, capacidades, autenticación y, si lo pides, un envío real y una sesión IMAP.',
  icon: 'x',
  sinRed: false,
  campos: [
    { name: 'host', label: 'Servidor SMTP', type: 'text', required: true, placeholder: 'smtp.ejemplo.com' },
    { name: 'puerto', label: 'Puerto', type: 'number', required: true, min: 1, max: 65535, default: 587 },
    {
      name: 'seguridad',
      label: 'Cómo empieza la conexión',
      type: 'select',
      default: 'starttls',
      options: [
        { value: 'starttls', label: 'STARTTLS — cifrar después del saludo (lo habitual en 587)' },
        { value: 'tls', label: 'TLS directo — cifrar desde el principio (465)' },
        { value: 'ninguno', label: 'Sin cifrar — texto plano (25)' }
      ]
    },
    { name: 'usuario', label: 'Usuario', type: 'text', placeholder: 'correo@ejemplo.com' },
    { name: 'contrasena', label: 'Contraseña', type: 'password' },
    {
      name: 'verificarCertificado',
      label: 'Exigir que el certificado sea válido y esté emitido por una autoridad de confianza',
      type: 'checkbox',
      default: true
    },
    { name: 'timeout', label: 'Espera máxima por paso', type: 'number', unit: 'ms', min: 500, max: 30000, default: 10000 },
    { name: 'enviarPrueba', label: 'Enviar además un correo de prueba', type: 'checkbox', default: false },
    {
      name: 'remitente',
      label: 'Remitente del correo de prueba',
      type: 'text',
      requiredUnless: 'enviarPrueba',
      shownWhen: 'enviarPrueba',
      placeholder: 'correo@ejemplo.com'
    },
    {
      name: 'destinatario',
      label: 'Destinatario del correo de prueba',
      type: 'text',
      requiredUnless: 'enviarPrueba',
      shownWhen: 'enviarPrueba',
      placeholder: 'destino@ejemplo.com'
    },
    {
      name: 'asunto',
      label: 'Asunto del correo de prueba',
      type: 'text',
      shownWhen: 'enviarPrueba',
      default: 'Prueba de salida SMTP (netlab)'
    },
    { name: 'probarImap', label: 'Probar también IMAP con las mismas credenciales', type: 'checkbox', default: false },
    {
      name: 'imapHost',
      label: 'Servidor IMAP',
      type: 'text',
      requiredUnless: 'probarImap',
      shownWhen: 'probarImap',
      placeholder: 'imap.ejemplo.com'
    },
    { name: 'imapPuerto', label: 'Puerto IMAP', type: 'number', shownWhen: 'probarImap', min: 1, max: 65535, default: 993 }
  ]
}

export const SUBNET_ANALYZER: Herramienta = {
  id: 'subnet-analyzer',
  titulo: 'Analizador de subredes',
  descripcion:
    'Calcula el direccionamiento de una red, reparte subredes iguales o hace un reparto VLSM por tamaño de cada tramo.',
  icon: 'x',
  sinRed: false,
  campos: [
    { name: 'red', label: 'Red', type: 'text', required: true, placeholder: '192.168.0.0/22' },
    {
      name: 'subredes',
      label: 'Reparto en subredes iguales',
      type: 'number',
      min: 2,
      max: 4096,
      placeholder: '8'
    },
    {
      name: 'vlsm',
      label: 'Reparto VLSM por tamaño',
      type: 'lista-requisitos',
      placeholder: 'Ventas:100\nAlmacén:20\nInvitados:10'
    },
    { name: 'listar', label: 'Incluir el listado de direcciones', type: 'checkbox', default: false },
    { name: 'limite', label: 'Máximo de direcciones a listar', type: 'number', min: 1, max: 4096, default: 256 }
  ]
}

export const HERRAMIENTAS: Herramienta[] = [SMTP_VALIDATOR, SUBNET_ANALYZER]