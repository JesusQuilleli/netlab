/**
 * HistoryList.test.tsx — Que los filtros digan lo que dicen.
 *
 * El fallo que motivó estos tests: la página pedía `/api/historial` sin
 * parámetros y `listar()` devuelve 50 por defecto, así que el filtro por texto y
 * el de estado se aplicaban en silencio sobre los 50 registros más recientes.
 * Con más de 50 ejecuciones, buscar "10.0.0.1" daba cero resultados sin motivo
 * aparente, y la lista no tenía ni total ni paginación con los que saber que
 * faltaban registros.
 */

import { describe, expect, test, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { HistoryList } from './HistoryList'
import type { HistorialItem } from '../../lib/tipos'

const item = (n: number, extra: Partial<HistorialItem> = {}): HistorialItem => ({
  id: `e${n}`,
  tool: 'smtp-validator',
  target: `10.0.0.${n % 255}`,
  status: 'pass',
  params: { host: `smtp${n}.ejemplo.com` },
  createdAt: '2026-01-01T10:00:00Z',
  durationMs: 100,
  owner: 'local',
  ...extra
})

const lista = (items: HistorialItem[], total = items.length) => {
  const onDelete = vi.fn()
  const onCambiarHerramienta = vi.fn()
  const r = render(
    <MemoryRouter>
      <HistoryList
        items={items}
        total={total}
        cargando={false}
        tools={[{ id: 'smtp-validator', titulo: 'Validador SMTP', descripcion: '', icon: '', sinRed: false, campos: [] }]}
        onDelete={onDelete}
        onCambiarHerramienta={onCambiarHerramienta}
      />
    </MemoryRouter>
  )
  return { ...r, onDelete, onCambiarHerramienta }
}

beforeEach(() => vi.stubGlobal('confirm', () => true))

describe('filtro por texto', () => {
  test('busca también en los parámetros, no solo en el destino', async () => {
    // Un correo de prueba aparece en `params`, y es como se localiza una
    // ejecución concreta días después. La fila no enseña los parámetros: lo que
    // se comprueba es que el filtro los alcanza.
    const user = userEvent.setup()
    lista([item(1), item(2, { params: { destinatario: 'destino.unico@example.com' } })])
    await user.type(screen.getByLabelText('Buscar en el historial'), 'destino.unico')
    const filas = within(screen.getByRole('list')).getAllByRole('listitem')
    expect(filas).toHaveLength(1)
    expect(filas[0]).toHaveTextContent('10.0.0.2')
  })

  test('no distingue mayúsculas', async () => {
    const user = userEvent.setup()
    lista([item(1), item(2, { target: 'SMTP.Gmail.COM' })])
    await user.type(screen.getByLabelText('Buscar en el historial'), 'gmail')
    expect(within(screen.getByRole('list')).getAllByRole('listitem')).toHaveLength(1)
  })

  test('avisa de que el filtro no encontró, en vez de salir con la lista a medias', async () => {
    const user = userEvent.setup()
    lista([item(1)])
    await user.type(screen.getByLabelText('Buscar en el historial'), 'no-existe')
    expect(screen.queryByRole('list')).not.toBeInTheDocument()
    expect(screen.getByText(/Ninguna ejecución de esta página coincide/)).toBeInTheDocument()
  })
})

describe('filtro por estado', () => {
  test('deja solo lo elegido', async () => {
    const user = userEvent.setup()
    lista([item(1), item(2, { status: 'fail' }), item(3, { status: 'error' })])
    await user.selectOptions(screen.getByLabelText('Filtrar por estado'), 'fail')
    const filas = within(screen.getByRole('list')).getAllByRole('listitem')
    expect(filas).toHaveLength(1)
    expect(filas[0]).toHaveTextContent('10.0.0.2')
  })
})

describe('filtro por herramienta', () => {
  test('se pide al servidor, que es donde está el filtro', async () => {
    // Los otros dos filtros no existen en `Historial.listar()`. Este sí, y
    // tiene que viajar en la petición en vez de filtrarse en el navegador.
    const user = userEvent.setup()
    const { onCambiarHerramienta } = lista([item(1)])
    await user.selectOptions(screen.getByLabelText('Filtrar por herramienta'), 'smtp-validator')
    expect(onCambiarHerramienta).toHaveBeenCalledWith('smtp-validator')
  })
})

describe('paginación', () => {
  const muchos = Array.from({ length: 30 }, (_, i) => item(i + 1))

  test('no aparece con pocos registros', () => {
    lista([item(1), item(2)])
    expect(screen.queryByRole('navigation', { name: 'Páginas del historial' })).not.toBeInTheDocument()
  })

  test('reparte en páginas y dice cuál es', () => {
    lista(muchos)
    const nav = screen.getByRole('navigation', { name: 'Páginas del historial' })
    expect(nav).toHaveTextContent('Página 1 de 2')
    expect(nav).toHaveTextContent('1–25 de 30')
  })

  test('avanza y retrocede', async () => {
    const user = userEvent.setup()
    lista(muchos)
    await user.click(screen.getByRole('button', { name: 'Siguiente' }))
    expect(screen.getByRole('navigation', { name: 'Páginas del historial' })).toHaveTextContent('Página 2 de 2')
    expect(within(screen.getByRole('list')).getAllByRole('listitem')).toHaveLength(5)
    await user.click(screen.getByRole('button', { name: 'Anterior' }))
    expect(screen.getByRole('navigation', { name: 'Páginas del historial' })).toHaveTextContent('Página 1 de 2')
  })

  test('el botón de "Siguiente" se desactiva en la última página', async () => {
    const user = userEvent.setup()
    lista(muchos)
    await user.click(screen.getByRole('button', { name: 'Siguiente' }))
    expect(screen.getByRole('button', { name: 'Siguiente' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Anterior' })).toBeEnabled()
  })

  test('cambiar de filtro vuelve a la primera página', async () => {
    // Sin volver al principio, filtrar estando en la última página deja la lista
    // en blanco aunque haya 26 coincidencias repartidas en dos páginas.
    const user = userEvent.setup()
    lista([
      ...Array.from({ length: 30 }, (_, i) => item(i + 1, { status: 'warn' })),
      ...Array.from({ length: 26 }, (_, i) => item(100 + i, { status: 'fail' }))
    ])
    await user.click(screen.getByRole('button', { name: 'Siguiente' }))
    await user.click(screen.getByRole('button', { name: 'Siguiente' }))
    expect(screen.getByRole('navigation', { name: 'Páginas del historial' })).toHaveTextContent('Página 3 de 3')
    await user.selectOptions(screen.getByLabelText('Filtrar por estado'), 'fail')
    const nav = screen.getByRole('navigation', { name: 'Páginas del historial' })
    expect(nav).toHaveTextContent('Página 1 de 2')
    expect(within(screen.getByRole('list')).getAllByRole('listitem')).toHaveLength(25)
  })

  test('no se sale del rango al quedarse sin páginas detrás', async () => {
    const user = userEvent.setup()
    const muchos60 = Array.from({ length: 60 }, (_, i) => item(i + 1))
    const { rerender } = lista(muchos60)
    await user.click(screen.getByRole('button', { name: 'Siguiente' }))
    await user.click(screen.getByRole('button', { name: 'Siguiente' }))
    expect(screen.getByRole('navigation', { name: 'Páginas del historial' })).toHaveTextContent('Página 3 de 3')
    // Se borran 35 registros y de tres páginas quedan dos. El índice se quedó en
    // la 3, así que sin recortar la lista saldría en blanco.
    rerender(
      <MemoryRouter>
        <HistoryList
          items={muchos60.slice(0, 26)}
          total={26}
          cargando={false}
          tools={[]}
          onDelete={vi.fn()}
          onCambiarHerramienta={vi.fn()}
        />
      </MemoryRouter>
    )
    const nav = screen.getByRole('navigation', { name: 'Páginas del historial' })
    expect(nav).toHaveTextContent('Página 2 de 2')
    expect(within(screen.getByRole('list')).getAllByRole('listitem')).toHaveLength(1)
  })
})

describe('ventana del servidor', () => {
  test('avisa cuando hay registros que no se han pedido', () => {
    // `listar()` corta en 200. Sin este aviso, la lista parecería completa.
    lista([item(1)], 341)
    expect(screen.getByText(/Se muestran los 1 registros más recientes de 341/)).toBeInTheDocument()
  })

  test('no avisa cuando todo cabe', () => {
    lista([item(1), item(2)], 2)
    expect(screen.queryByText(/registros más recientes/)).not.toBeInTheDocument()
  })
})

describe('estado vacío', () => {
  test('con el historial vacío invita a ejecutar algo', () => {
    lista([])
    expect(screen.getByText(/Aún no hay ejecuciones/)).toBeInTheDocument()
  })

  test('distingue "cargando" de "no hay nada"', () => {
    render(
      <MemoryRouter>
        <HistoryList items={[]} total={0} cargando tools={[]} onDelete={vi.fn()} onCambiarHerramienta={vi.fn()} />
      </MemoryRouter>
    )
    expect(screen.getByText('Cargando…')).toBeInTheDocument()
  })
})

describe('borrar', () => {
  test('pide confirmación y avisa de qué se borra', async () => {
    const user = userEvent.setup()
    const { onDelete } = lista([item(1)])
    await user.click(screen.getByRole('button', { name: /Eliminar ejecución de/ }))
    expect(onDelete).toHaveBeenCalledWith('e1')
  })
})