/**
 * AdminPage.test.tsx — La pestaña de administración habla con el backend.
 *
 * Los tres bloques (usuarios, copias y auditoría) se cargan al montar, así que
 * un solo render pinta una página entera. Lo que se comprueba aquí es el más
 * fácil de romper en silencio: que el filtro de actividad viaja al servidor,
 * que es donde existe el filtro, en vez de aplicarse a los 50 registros que ya
 * llegaron.
 */

import { describe, expect, test, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import AdminPage from './AdminPage'
import type { Sesion } from '../lib/tipos'

const SESION: Sesion = { autenticado: true, local: true, usuario: 'local', role: 'admin', csrf: 'x', avisos: [] }

let pedir: ReturnType<typeof vi.fn>
let pedidas: [string, string | undefined][]

beforeEach(() => {
  pedidas = []
  pedir = vi.fn(async (u: string, opts?: RequestInit) => {
    pedidas.push([String(u), opts?.method ?? 'GET'])
    const url = String(u)
    if (url.startsWith('/api/usuarios')) {
      return {
        ok: true,
        json: async () => ({
          usuarios: [{ id: 'u1', username: 'ana', role: 'admin', activo: 1, createdAt: '2026-01-01T10:00:00Z', lastLogin: null }]
        })
      }
    }
    if (url.startsWith('/api/auditoria')) {
      const tipos = url.includes('tipo=')
        ? /tipo=([a-z_]+)/.exec(url)?.[1] === 'usuario_creado'
          ? [{ id: 2, tipo: 'usuario_creado', usuario: 'bea', ip: '192.0.2.5', detalles: { nuevoUsuario: 'bea', role: 'user' }, createdAt: '2026-01-02T09:00:00Z' }]
          : []
        : [
            { id: 1, tipo: 'login_exitoso', usuario: 'ana', ip: '192.0.2.4', detalles: null, createdAt: '2026-01-01T10:00:00Z' },
            { id: 2, tipo: 'usuario_creado', usuario: 'bea', ip: '192.0.2.5', detalles: { nuevoUsuario: 'bea', role: 'user' }, createdAt: '2026-01-02T09:00:00Z' }
          ]
      return { ok: true, json: async () => ({ items: tipos, total: tipos.length, limite: 50, desde: 0 }) }
    }
    if (url.startsWith('/api/backups')) {
      return {
        ok: true,
        json: async () => ({
          backups: [{ nombre: 'netlab-20261009-030000.sqlite', ruta: '/x', tamano: 4096, creadoEn: '2026-10-09T03:00:00Z' }],
          retencion: 7,
          hora: 2
        })
      }
    }
    return { ok: true, json: async () => ({}) }
  })
  vi.stubGlobal('fetch', pedir)
})

afterEach(() => vi.unstubAllGlobals())

describe('actividad', () => {
  const tabla = () => screen.getByRole('table', { name: /auditoría/i })

  test('muestra los eventos registrados', async () => {
    render(<AdminPage sesion={SESION} />)
    await waitFor(() => expect(within(tabla()).getByText('Inicio de sesión')).toBeInTheDocument())

    const filas = within(tabla()).getAllByRole('row')
    // Cabecera + dos eventos.
    expect(filas).toHaveLength(3)
    expect(within(tabla()).getByText('ana')).toBeInTheDocument()
    expect(within(tabla()).getByText('bea')).toBeInTheDocument()
  })

  test('el filtro por tipo se pide al servidor, que es donde está el filtro', async () => {
    const user = userEvent.setup()
    render(<AdminPage sesion={SESION} />)
    await waitFor(() => expect(screen.getByLabelText('Filtrar auditoría por tipo')).toBeInTheDocument())

    await user.selectOptions(screen.getByLabelText('Filtrar auditoría por tipo'), 'usuario_creado')

    expect(pedidas.some(([u]) => u === '/api/auditoria?tipo=usuario_creado')).toBe(true)
    await waitFor(() => expect(within(tabla()).getByText('bea')).toBeInTheDocument())
    expect(within(tabla()).getAllByRole('row')).toHaveLength(2)
    expect(within(tabla()).queryByText('Inicio de sesión')).not.toBeInTheDocument()
  })
})

describe('copias de seguridad', () => {
  test('enumera las copias y explica la retención', async () => {
    render(<AdminPage sesion={SESION} />)
    await waitFor(() => expect(screen.getByText(/Se conservan las 7 más recientes/)).toBeInTheDocument())
    expect(screen.getByText('netlab-20261009-030000.sqlite')).toBeInTheDocument()
    expect(screen.getByText(/02:00 \(hora local\)/)).toBeInTheDocument()
  })

  test('crear una copia llama al POST del servidor', async () => {
    const user = userEvent.setup()
    render(<AdminPage sesion={SESION} />)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Crear copia ahora' })).toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: 'Crear copia ahora' }))

    expect(pedidas.some(([u, m]) => u === '/api/backups' && m === 'POST')).toBe(true)
  })
})