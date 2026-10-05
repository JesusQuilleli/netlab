/**
 * HerramientaPage.test.tsx — El enlace profundo.
 *
 * `GET /api/run/:id` devuelve una ejecución entera, así que una ejecución es una
 * URL. Lo que faltaba era escribirla: el informe se quedaba en memoria y se
 * perdía con F5, no se podía compartir y el botón "atrás" no deshacía una
 * ejecución.
 *
 * Aquí se comprueban las tres cosas de las que depende el resto:
 *   1. al terminar, el `?run=<id>` aparece en la URL;
 *   2. abrir una URL con `?run=` pide esa ejecución y rellena el formulario;
 *   3. publicar el enlace no vuelve a pedir la ejecución que ya está en memoria.
 * El tercero es el que se cuelga solo: al escribir `?run=`, `rid` cambia y el
 * efecto de carga se dispara otra vez.
 */

import { describe, expect, test, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import HerramientaPage from './HerramientaPage'
import type { Herramienta, RunResp } from '../lib/tipos'

const HERRAMIENTA: Herramienta = {
  id: 'dns-checker',
  titulo: 'Comprobador DNS',
  descripcion: 'Resuelve un nombre.',
  icon: '◈',
  sinRed: false,
  campos: [{ name: 'nombre', label: 'Nombre', type: 'text', required: true }]
}

const run = (id: string): RunResp => ({
  id,
  duplicado: false,
  avisos: [],
  result: {
    schema: 1,
    tool: 'dns-checker',
    toolTitle: 'Comprobador DNS',
    status: 'pass',
    target: 'ejemplo.com',
    params: { nombre: 'ejemplo.com' },
    summary: [],
    sections: [],
    findings: [],
    logs: [],
    startedAt: '2026-01-01T10:00:00Z',
    durationMs: 5,
    error: null
  }
})

let pedir: ReturnType<typeof vi.fn>
let enviados: [string, string | undefined][]

/** Pinta la URL: es lo que hay que comprobar. */
function Ruta() {
  const l = useLocation()
  return <span data-testid="url">{l.pathname + l.search}</span>
}

const pantalla = (urlInicial: string) =>
  render(
    <MemoryRouter initialEntries={[urlInicial]}>
      <Routes>
        <Route
          path="/herramienta/:id"
          element={
            <>
              <Ruta />
              <HerramientaPage tools={[HERRAMIENTA]} onDone={() => {}} />
            </>
          }
        />
      </Routes>
    </MemoryRouter>
  )

const url = () => screen.getByTestId('url').textContent
const lecturas = () => enviados.filter(([, m]) => m === 'GET').map(([u]) => u)

beforeEach(() => {
  enviados = []
  pedir = vi.fn(async (u: string, opts?: RequestInit) => {
    enviados.push([String(u), opts?.method ?? 'GET'])
    // `Informe` también pide la lista de formatos al montar; si el simulo
    // devuelve una ejecución para eso, `formatos` queda sin forma y el informe
    // entero revienta al pintar.
    if (u === '/api/formats') return { ok: true, json: async () => ({ formatos: [] }) }
    // El GET devuelve la ejecución del id que se pide. Si devolviera siempre la
    // misma, la URL "?run=r-nuevo" se reescribiría con el id del simulacro en
    // cuanto el efecto de carga la leyera.
    const id = opts?.method === 'POST' ? 'r-nuevo' : (u.split('/').pop() ?? 'r-9')
    return { ok: true, json: async () => run(id) }
  })
  vi.stubGlobal('fetch', pedir)
})
afterEach(() => vi.unstubAllGlobals())

/** Rellena el único campo obligatorio y manda el formulario. */
async function ejecutar() {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('Nombre *'), 'ejemplo.com')
  await user.click(screen.getByRole('button', { name: /Ejecutar diagnóstico/i }))
  await waitFor(() => expect(pedir).toHaveBeenCalled())
}

describe('al terminar una ejecución', () => {
  test('su id pasa a la URL', async () => {
    pantalla('/herramienta/dns-checker')
    await ejecutar()
    await waitFor(() => expect(url()).toContain('run=r-nuevo'))
    expect(url()).toBe('/herramienta/dns-checker?run=r-nuevo')
  })

  test('el informe se pinta y se ofrece el enlace para copiarlo', async () => {
    pantalla('/herramienta/dns-checker')
    await ejecutar()
    await waitFor(() => expect(screen.getByText(/Comprobador DNS · Correcto/)).toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Copiar el enlace de esta ejecución' })).toBeInTheDocument()
  })

  test('publicar el enlace no pide otra vez la misma ejecución', async () => {
    // Al escribir `?run=`, `rid` cambia. Si el efecto de carga comparase con
    // `rid` en vez de con el `id` ya en memoria, saldría una segunda petición de
    // lo que se acaba de ejecutar.
    pantalla('/herramienta/dns-checker')
    await ejecutar()
    await waitFor(() => expect(url()).toContain('run=r-nuevo'))
    await waitFor(() => expect(screen.getByText(/Comprobador DNS · Correcto/)).toBeInTheDocument())
    expect(lecturas().filter((u) => u.startsWith('/api/run/'))).toHaveLength(0)
  })
})

describe('al abrir un enlace', () => {
  test('carga la ejecución del `?run=`', async () => {
    pantalla('/herramienta/dns-checker?run=r-9')
    await waitFor(() => expect(screen.getByText(/Comprobador DNS · Correcto/)).toBeInTheDocument())
    expect(lecturas()).toContain('/api/run/r-9')
  })

  test('rellena el formulario con lo que se ejecutó', async () => {
    // Es lo que hace útil un enlace: no solo el informe, también los parámetros,
    // para poder reejecutar lo mismo cambiando una cosa.
    pantalla('/herramienta/dns-checker?run=r-9')
    await waitFor(() => expect(screen.getByLabelText('Nombre *')).toHaveValue('ejemplo.com'))
  })

  test('sin `?run=` no pide ninguna ejecución', async () => {
    pantalla('/herramienta/dns-checker')
    await waitFor(() => expect(screen.getByLabelText('Nombre *')).toBeInTheDocument())
    expect(lecturas().filter((u) => u.startsWith('/api/run/'))).toHaveLength(0)
  })
})

describe('herramienta desconocida', () => {
  test('lo dice en vez de quedarse en blanco', () => {
    render(
      <MemoryRouter initialEntries={['/herramienta/no-existe']}>
        <Routes>
          <Route path="/herramienta/:id" element={<HerramientaPage tools={[HERRAMIENTA]} onDone={() => {}} />} />
        </Routes>
      </MemoryRouter>
    )
    expect(screen.getByText('Herramienta no encontrada.')).toBeInTheDocument()
  })
})