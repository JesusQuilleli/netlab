/**
 * DynamicForm.test.tsx — El formulario contra el contrato real.
 *
 * Estos tests trabajan contra `fixture.ts`, que es una copia de
 * `GET /api/herramientas`. Los dos casos que se rompieron estan aqui como
 * pruebas de regresion:
 *
 *   - el desplegable de seguridad salia vacio porque las opciones se leian con
 *     `valor`/`etiqueta` en vez de `value`/`label`;
 *   - el campo VLSM de subnet-analyzer caia en el `else` y se pintaba como un
 *     input, porque el tipo `lista-requisitos` no estaba contemplado.
 */

import { describe, expect, test, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DynamicForm } from './DynamicForm'
import { SMTP_VALIDATOR, SUBNET_ANALYZER } from '../../test/fixture'
import type { Campo } from '../../lib/tipos'

/** Ejecuta el formulario y devuelve lo que se mandaria al servidor. */
async function enviar(campos: Campo[], initial?: Record<string, unknown>) {
  const onSubmit = vi.fn()
  const user = userEvent.setup()
  render(<DynamicForm campos={campos} initial={initial} ejecutando={false} onSubmit={onSubmit} onCancel={() => {}} />)
  await user.click(screen.getByRole('button', { name: /Ejecutar diagnóstico/i }))
  return onSubmit.mock.calls[0]?.[0] as Record<string, unknown> | undefined
}

/**
 * El asterisco de obligatorio va dentro de la etiqueta, asi que forma parte del
 * texto que Testing Library lee. Sin esto, "Puerto" y "Puerto IMAP" no se
 * distinguen y "^Puerto$" no encuentra nada.
 */
const etq = (texto: string) => new RegExp(`^${texto.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} \\*$`)

describe('desplegables', () => {
  test('las opciones tienen texto visible y valor real', async () => {
    // El fallo era silencioso: un `<select>` con `<option value={undefined}>` no
    // da error, simplemente sale en blanco y el servidor aplica su default.
    render(
      <DynamicForm
        campos={SMTP_VALIDATOR.campos}
        ejecutando={false}
        onSubmit={() => {}}
        onCancel={() => {}}
      />
    )
    const select = screen.getByLabelText(/Cómo empieza la conexión/) as HTMLSelectElement
    expect(select.tagName).toBe('SELECT')
    expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual([
      '—',
      'STARTTLS — cifrar después del saludo (lo habitual en 587)',
      'TLS directo — cifrar desde el principio (465)',
      'Sin cifrar — texto plano (25)'
    ])
    expect(select.value).toBe('starttls')
  })

  test('elegir otra opcion manda ese valor, no el texto de la etiqueta', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <DynamicForm campos={SMTP_VALIDATOR.campos} ejecutando={false} onSubmit={onSubmit} onCancel={() => {}} />
    )
    await user.selectOptions(screen.getByLabelText(/Cómo empieza la conexión/), 'ninguno')
    await user.type(screen.getByLabelText(/Servidor SMTP/), 'smtp.ejemplo.com')
    await user.click(screen.getByRole('button', { name: /Ejecutar diagnóstico/i }))
    expect(onSubmit.mock.calls[0][0]).toMatchObject({ seguridad: 'ninguno' })
  })
})

describe('lista-requisitos', () => {
  test('se pinta como area de texto, no como input', () => {
    render(<DynamicForm campos={SUBNET_ANALYZER.campos} ejecutando={false} onSubmit={() => {}} onCancel={() => {}} />)
    const campo = screen.getByLabelText(/Reparto VLSM/)
    expect(campo.tagName).toBe('TEXTAREA')
    expect(campo).toHaveAttribute('placeholder', 'Ventas:100\nAlmacén:20\nInvitados:10')
  })

  test('las lineas viajan tal cual, con los saltos', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(<DynamicForm campos={SUBNET_ANALYZER.campos} ejecutando={false} onSubmit={onSubmit} onCancel={() => {}} />)
    await user.type(screen.getByLabelText(/^Red/), '10.0.0.0/24')
    await user.type(screen.getByLabelText(/Reparto VLSM/), 'Ventas:100{enter}Almacén:20')
    await user.click(screen.getByRole('button', { name: /Ejecutar diagnóstico/i }))
    expect(onSubmit.mock.calls[0][0]).toMatchObject({ red: '10.0.0.0/24', vlsm: 'Ventas:100\nAlmacén:20' })
  })
})

describe('unidad del campo', () => {
  test('se enseña junto a la etiqueta', () => {
    render(<DynamicForm campos={SMTP_VALIDATOR.campos} ejecutando={false} onSubmit={() => {}} onCancel={() => {}} />)
    expect(screen.getByText('(ms)')).toBeInTheDocument()
  })
})

describe('campos que dependen de una casilla', () => {
  test('shownWhen esconde lo que no aplica', () => {
    render(<DynamicForm campos={SMTP_VALIDATOR.campos} ejecutando={false} onSubmit={() => {}} onCancel={() => {}} />)
    expect(screen.queryByLabelText(/Remitente del correo/)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/Servidor IMAP/)).not.toBeInTheDocument()
  })

  test('al marcar la casilla aparecen sus campos', async () => {
    const user = userEvent.setup()
    render(<DynamicForm campos={SMTP_VALIDATOR.campos} ejecutando={false} onSubmit={() => {}} onCancel={() => {}} />)
    await user.click(screen.getByLabelText(/Probar también IMAP/))
    expect(screen.getByLabelText(/Servidor IMAP/)).toBeInTheDocument()
    expect(screen.getByLabelText(/Puerto IMAP/)).toBeInTheDocument()
  })

  test('lo escondido no se manda aunque el servidor lo ignore', async () => {
// Sin host, el navegador bloquea el envio por campo obligatorio y no habria
    // nada que mirar: se rellena solo lo minimo.
    const p = await enviar(SMTP_VALIDATOR.campos, { host: 'smtp.ejemplo.com' })
    expect(p).toBeDefined()
    expect(p).not.toHaveProperty('imapHost')
    expect(p).not.toHaveProperty('remitente')
  })

  test('requiredUnless se calcula como en server/validar.js: obligatorio si el otro NO esta activo', () => {
    // Con `probarImap` apagado, `imapHost` queda escondido y da igual. Lo que
    // importa es la formula, no el caso visible: se comprueba con un campo
    // visible y `requiredUnless` unmetido.
    const campos: Campo[] = [
      { name: 'activo', label: 'Activo', type: 'checkbox', default: false },
      { name: 'detalle', label: 'Detalle', type: 'text', requiredUnless: 'activo' },
      { name: 'fijo', label: 'Fijo', type: 'text', required: true }
    ]
    render(<DynamicForm campos={campos} ejecutando={false} onSubmit={() => {}} onCancel={() => {}} />)
    expect(screen.getByLabelText(/Detalle/)).toBeRequired()
    expect(screen.getByLabelText(/Fijo/)).toBeRequired()
  })

  test('un campo normal no marcado como obligatorio no bloquea el formulario', async () => {
    const campos: Campo[] = [{ name: 'nota', label: 'Nota', type: 'text' }]
    const p = await enviar(campos)
    expect(p).toEqual({})
  })
})

describe('valores por defecto y precarga', () => {
  test('los default del servidor se aplican al pintar', () => {
    render(<DynamicForm campos={SMTP_VALIDATOR.campos} ejecutando={false} onSubmit={() => {}} onCancel={() => {}} />)
    expect(screen.getByLabelText(etq('Puerto'))).toHaveValue(587)
    expect(screen.getByLabelText(/Espera máxima por paso/)).toHaveValue(10000)
    expect(screen.getByLabelText(/Exigir que el certificado/)).toBeChecked()
  })

  test('una ejecucion anterior rellena los campos, con la contrasena enmascarada', () => {
    render(
      <DynamicForm
        campos={SMTP_VALIDATOR.campos}
        initial={{ host: 'smtp.antiguo.com', puerto: 465, contrasena: '[REDACTADO]', timeout: 2000 }}
        ejecutando={false}
        onSubmit={() => {}}
        onCancel={() => {}}
      />
    )
    expect(screen.getByLabelText(/Servidor SMTP/)).toHaveValue('smtp.antiguo.com')
    expect(screen.getByLabelText(etq('Puerto'))).toHaveValue(465)
    expect(screen.getByLabelText(/Espera máxima por paso/)).toHaveValue(2000)
    // La contrasena real no existe en ningun sitio: ni se rellena ni se adivina.
    expect(screen.getByLabelText(/Contraseña/)).toHaveValue('')
    expect(screen.getByPlaceholderText('[REDACTADO] en la ejecución anterior')).toBeInTheDocument()
  })
})

describe('envio de lo escrito', () => {
  test('los numeros salen como numero, no como cadena', async () => {
    const p = await enviar(SMTP_VALIDATOR.campos, { host: 'smtp.ejemplo.com' })
    expect(p).toMatchObject({ host: 'smtp.ejemplo.com', puerto: 587, timeout: 10000 })
    expect(typeof p!.puerto).toBe('number')
    expect(typeof p!.timeout).toBe('number')
  })

  test('un campo vacio no se manda, para que el servidor aplique su default', async () => {
    const p = await enviar(SMTP_VALIDATOR.campos, { host: 'smtp.ejemplo.com' })
    expect(p).not.toHaveProperty('usuario')
    expect(p).not.toHaveProperty('asunto')
  })
})