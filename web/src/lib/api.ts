export class ApiError extends Error {
  constructor(message: string, public code = 'http', public remediation?: string, public status = 0) { super(message) }
}
let csrf = ''
export const setCsrf = (t: string) => { csrf = t }
export async function api<T>(url: string, opts: RequestInit = {}): Promise<T> {
  const metodo = (opts.method ?? 'GET').toUpperCase()
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (opts.body) headers['Content-Type'] = 'application/json'
  if (metodo !== 'GET') headers['X-CSRF-Token'] = csrf
  let r: Response
  try { r = await fetch(url, { ...opts, credentials: 'include', headers }) }
  catch (e) { if ((e as Error).name === 'AbortError') throw e; throw new ApiError('No se pudo conectar con el backend.', 'red', 'Comprueba que el servidor está activo en 127.0.0.1:4310.') }
  let d: any = null
  try { d = await r.json() } catch { /* sin cuerpo */ }
  if (!r.ok) { const e = d?.error ?? d ?? {}; throw new ApiError(e.message ?? `Error HTTP ${r.status}`, e.code ?? 'http', e.remediation, r.status) }
  return d as T
}
export const post = <T,>(url: string, body: unknown, signal?: AbortSignal) => api<T>(url, { method: 'POST', body: JSON.stringify(body), signal })
