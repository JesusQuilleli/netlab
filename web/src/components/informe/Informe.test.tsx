/**
 * Informe.test.tsx — Que el renderer pinte el contrato de verdad.
 *
 * `lib/tabla-modelo.test.ts` fija el modelo, pero ese archivo nació precisamente
 * porque el modelo estaba bien y el renderer no lo usaba: leía las columnas como
 * objetos y las filas por clave, así que la página salía vacía mientras los siete
 * formatos de informe sacaban los registros. Un test del módulo no habría
 * pillado eso.
 *
 * Estos tests renderizan el componente contra una ejecución con la forma que
 * emite `core/result.js` y comprueban lo que aparece en pantalla.
 */

import { describe, expect, test, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { SeccionRenderer } from './Informe'
import type { Resultado, RunResp, Seccion } from '../../lib/tipos'

/** `Informe` pide la lista de formatos al montar; aquí no interesa. */
beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ formatos: [] }) }))
})
afterEach(() => vi.unstubAllGlobals())

const seccion = (s: Partial<Seccion>): Seccion => ({ title: 'Sección', kind: 'table', ...s })

describe('tablas', () => {
  /**
   * El texto de cada celda. Se lee del `title` del `.val` porque dentro del span
   * va también el boton de copiar, que se engancha a IPs, hosts y CIDR.
   */
  const textos = (fila: HTMLElement) =>
    within(fila)
      .getAllByRole('cell')
      .map((c) => c.querySelector<HTMLElement>('.val')?.getAttribute('title'))

  test('las cabeceras salen con su texto, no en blanco', () => {
    // El fallo original: `col.label` era undefined y todas las cabeceras salían
    // vacías porque se leían como objetos.
    render(<SeccionRenderer s={seccion({ columns: ['Tipo', 'Valor', 'TTL'], rows: [['A', '1.2.3.4', '21']] })} />)
    const ths = within(screen.getByRole('table')).getAllByRole('columnheader')
    expect(ths.map((t) => t.textContent)).toEqual(['Tipo', 'Valor', 'TTL'])
  })

  test('una fila corta se rellena con guion en vez de descuadrar la tabla', () => {
    // Al faltar un campo opcional, el resto de la fila tenía que shifting para
    // que los valores no acabaran bajo la columna equivocada.
    render(<SeccionRenderer s={seccion({ columns: ['Tipo', 'Valor', 'TTL'], rows: [['A', '1.2.3.4']] })} />)
    const fila = within(screen.getByRole('table')).getAllByRole('row')[1]
    expect(textos(fila)).toEqual(['A', '1.2.3.4', '—'])
  })

  test('el tono de una celda llega a su columna, no a otra', () => {
    render(
      <SeccionRenderer
        s={seccion({ columns: ['a', 'b'], rows: [[{ valor: 'ok', tone: 'ok' }, { valor: 'mal', tone: 'bad' }]] })}
      />
    )
    const celdas = within(screen.getByRole('table')).getAllByRole('cell')
    expect(celdas[0].className).toContain('bg-ok')
    expect(celdas[1].className).toContain('bg-bad')
  })

  test('una tabla vacia lo dice, en vez de salir con la cabeza suelta', () => {
    render(<SeccionRenderer s={seccion({ columns: [], rows: [] })} />)
    expect(screen.getByText(/Tabla sin datos/)).toBeInTheDocument()
  })
})

describe('pares clave/valor', () => {
  test('la etiqueta sale de la tupla, no de una clave `label` inexistente', () => {
    // El otro consumidor que no seguía el contrato: `item.label` era undefined y
    // todas las filas salían con la clave en blanco y el valor a «—».
    render(<SeccionRenderer s={seccion({ kind: 'kv', items: [['Entrada original', '10.0.0.0/24'], ['Prefijo', '/24']] })} />)
    expect(screen.getByText('Entrada original')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.0/24')).toBeInTheDocument()
    expect(screen.getByText('Prefijo')).toBeInTheDocument()
  })

  test('conserva el tono que va en el tercer elemento de la tupla', () => {
    // `[['Ámbito', 'Privada', 'warn']]`: el tono no está en el valor, va aparte.
    // Leerlo con `[k, v]` lo pierde y el aviso sale en negro.
    const { container } = render(
      <SeccionRenderer s={seccion({ kind: 'kv', items: [['Ámbito', 'Privada', 'warn']] })} />
    )
    expect(container.querySelector('.kv > .bg-warn')).not.toBeNull()
  })

  test('un valor vacio sale como cadena vacia, no como guion', () => {
    render(<SeccionRenderer s={seccion({ kind: 'kv', items: [['Z', { valor: null, tone: 'bad' }]] })} />)
    const dd = document.querySelector('dd')
    expect(dd?.textContent).toBe('')
  })
})

describe('los otros tipos de sección', () => {
  test('código y texto leen `value` tal cual', () => {
    const { unmount } = render(<SeccionRenderer s={seccion({ kind: 'code', value: 'línea 1\nlínea 2' })} />)
    expect(screen.getByText(/línea 1/).tagName).toBe('PRE')
    unmount()
    render(<SeccionRenderer s={seccion({ kind: 'text', value: 42 })} />)
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  test('una lista vacia lo dice', () => {
    render(<SeccionRenderer s={seccion({ kind: 'list', items: [] })} />)
    expect(screen.getByText(/Sin elementos/)).toBeInTheDocument()
  })

  test('el medidor se queda dentro de 0-100 aunque el valor se pase', () => {
    const { container } = render(<SeccionRenderer s={seccion({ kind: 'meter', value: 140 })} />)
    const m = screen.getByRole('meter')
    expect(m).toHaveAttribute('aria-valuenow', '100')
    expect(container.querySelector('.fill')).toHaveStyle({ width: '100%' })
  })

  test('un kind desconocido avisa en vez de pintar en blanco', () => {
    render(<SeccionRenderer s={seccion({ kind: 'desconocido' as Seccion['kind'] })} />)
    expect(screen.getByText(/no soportado/)).toBeInTheDocument()
  })
})

describe('el informe entero', () => {
  const run = (parcial: Partial<Resultado> = {}): RunResp => ({
    id: 'r1',
    duplicado: false,
    avisos: [],
    result: {
      schema: 1,
      tool: 'subnet-analyzer',
      toolTitle: 'Analizador de subredes',
      status: 'pass',
      target: '10.0.0.0/24',
      params: {},
      summary: [{ label: 'Hosts', value: '254', tone: 'ok' }],
      sections: [],
      findings: [],
      logs: [],
      startedAt: '2026-01-01T10:00:00Z',
      durationMs: 12,
      error: null,
      ...parcial
    }
  })

  test('cabecera, resumen y secciones en orden', async () => {
    const { Informe } = await import('./Informe')
    render(
      <Informe
        run={run({
          sections: [seccion({ kind: 'kv', items: [['Prefijo', '/24']] })],
          findings: [
            {
              severity: 'warn',
              title: 'Ámbito privado',
              detail: 'No sale a internet.',
              recommendation: 'Usar una red pública.'
            }
          ]
        })}
      />
    )
    expect(screen.getByText(/Analizador de subredes/)).toBeInTheDocument()
    expect(screen.getByText('10.0.0.0/24')).toBeInTheDocument()
    expect(screen.getByText('Hosts')).toBeInTheDocument()
    expect(screen.getByText('Ámbito privado')).toBeInTheDocument()
    expect(screen.getByText(/Usar una red pública/)).toBeInTheDocument()
  })

  test('el titular sustituye al nombre de la herramienta cuando viene', async () => {
    const { Informe } = await import('./Informe')
    render(<Informe run={run({ headline: 'example.com está operativa', toolTitle: 'Comprobador web' })} />)
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('example.com está operativa')
  })

  test('sin titular cae al titulo de la herramienta con el estado', async () => {
    const { Informe } = await import('./Informe')
    render(<Informe run={run({ toolTitle: 'Comprobador web', status: 'fail' })} />)
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('Comprobador web · Con fallos')
  })

  test('el titular vacío no deja la cabecera a medias', async () => {
    const { Informe } = await import('./Informe')
    // Una cadena solo con espacios no es un titular: sin esta comprobacion el
    // encabezado se queda en blanco y el informe pierde su primera linea.
    render(<Informe run={run({ headline: '   ', toolTitle: 'Comprobador web' })} />)
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('Comprobador web · Correcto')
  })

  test('los avisos de una ejecución repetida se enseñan', async () => {
    const { Informe } = await import('./Informe')
    render(<Informe run={{ ...run(), avisos: ['Se corrigieron 2 campos de la ejecución anterior.'] }} />)
    expect(screen.getByRole('note')).toHaveTextContent(/Se corrigieron 2 campos/)
  })

  test('sin hallazgos lo dice, en vez de dejar el hueco', async () => {
    const { Informe } = await import('./Informe')
    render(<Informe run={run()} />)
    expect(screen.getByText('Sin hallazgos.')).toBeInTheDocument()
  })
})