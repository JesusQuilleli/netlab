import { useCallback, useEffect, useRef, useState } from 'react'
import { api, post, setCsrf, ApiError } from '../lib/api'
import type { Herramienta, HistorialItem, HistorialPagina, RunResp, Sesion } from '../lib/tipos'

export function useSetupStatus() {
  const [data, setData] = useState<{ completado: boolean; requiereSetup: boolean } | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [cargando, setCargando] = useState(true)
  const cargar = useCallback(async () => {
    try {
      setCargando(true)
      const s = await api<{ completado: boolean; requiereSetup: boolean }>('/api/setup/status')
      setData(s)
      setError(null)
    } catch (e) {
      setError(e as ApiError)
    } finally {
      setCargando(false)
    }
  }, [])
  useEffect(() => { cargar() }, [cargar])
  return { data, error, cargando, recargar: cargar }
}

export function useSesion() {
  const [data, setData] = useState<Sesion | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const cargar = useCallback(async () => {
    try { const s = await api<Sesion>('/api/sesion'); setCsrf(s.csrf); setData(s); setError(null) }
    catch (e) { setError(e as ApiError) }
  }, [])
  useEffect(() => { cargar() }, [cargar])
  const login = async (usuario: string, password: string) => { await post('/api/sesion', { usuario, password }); await cargar() }
  return { data, error, login, recargar: cargar }
}
export function useHerramientas(activo: boolean) {
  const [tools, setTools] = useState<Herramienta[]>([]); const [error, setError] = useState<ApiError | null>(null)
  useEffect(() => { if (activo) api<{ herramientas: Herramienta[] }>('/api/herramientas').then(d => setTools(d.herramientas)).catch(setError) }, [activo])
  return { tools, error }
}
export function useHistorial({
  tool = '',
  limite = 200,
  activo = true,
}: { tool?: string; limite?: number; activo?: boolean } = {}) {
  const [data, setData] = useState<HistorialPagina>({ items: [], total: 0, limite, desde: 0 })
  const [error, setError] = useState<ApiError | null>(null)
  const [cargando, setCargando] = useState(false)

  const recargar = useCallback(async () => {
    if (!activo) return
    setCargando(true)
    try {
      // Solo `tool` se filtra en el servidor: es lo unico de los tres filtros
      // que `Historial.listar()` entiende. Texto y estado se filtran despues, en
      // la pagina, y por eso el limite se pide alto en vez de paginarse aqui.
      const qs = new URLSearchParams({ limite: String(limite) })
      if (tool) qs.set('tool', tool)
      const d = await api<HistorialPagina>(`/api/historial?${qs}`)
      setData(d)
      setError(null)
    } catch (e) {
      setError(e as ApiError)
    } finally {
      setCargando(false)
    }
  }, [tool, limite, activo])

  useEffect(() => { void recargar() }, [recargar])

  const borrar = async (id: string) => { await api(`/api/historial/${id}`, { method: 'DELETE' }); await recargar() }
  return { items: data.items, total: data.total, cargando, error, recargar, borrar }
}
type Estado = 'inactivo' | 'ejecutando' | 'listo' | 'error'
export function useEjecucion() {
  const [estado, setEstado] = useState<Estado>('inactivo'); const [run, setRun] = useState<RunResp | null>(null); const [error, setError] = useState<ApiError | null>(null)
  const ac = useRef<AbortController | null>(null)
  const iniciar = async (fn: (s: AbortSignal) => Promise<RunResp>) => {
    ac.current?.abort(); const c = new AbortController(); ac.current = c
    setEstado('ejecutando'); setError(null); setRun(null)
    try { const r = await fn(c.signal); setRun(r); setEstado('listo'); return r }
    catch (e) { if ((e as Error).name === 'AbortError') { setEstado('inactivo'); return null } setError(e as ApiError); setEstado('error'); return null }
  }
  return {
    estado, run, error,
    ejecutar: (tool: string, params: Record<string, unknown>) => iniciar(s => post<RunResp>('/api/run', { tool, params }, s)),
    cargar: (id: string) => iniciar(s => api<RunResp>(`/api/run/${id}`, { signal: s })),
    cancelar: () => ac.current?.abort(),
    reset: () => { ac.current?.abort(); setEstado('inactivo'); setRun(null); setError(null) },
  }
}
