/**
 * AdminPage.tsx — Administración (solo admin): usuarios, copias de seguridad y log de auditoría.
 */
import { useEffect, useState } from 'react'
import { api, post } from '../lib/api'
import type { Sesion } from '../lib/tipos'

interface Usuario {
  id: string
  username: string
  role: 'admin' | 'user'
  activo: number
  createdAt: string
  lastLogin: string | null
}

interface LogAuditoria {
  id: number
  tipo: string
  usuario: string | null
  ip: string | null
  detalles: Record<string, unknown> | null
  createdAt: string
}

interface PaginaAuditoria {
  items: LogAuditoria[]
  total: number
  limite: number
  desde: number
}

interface BackupInfo {
  nombre: string
  ruta: string
  tamano: number
  creadoEn: string
}

/** Los tipos que el servidor registra. El número es la clave del filtro. */
const TIPOS = [
  ['setup_admin_creado', 'Creación del administrador'],
  ['login_exitoso', 'Inicio de sesión'],
  ['login_fallido', 'Inicio de sesión fallido'],
  ['logout', 'Cierre de sesión'],
  ['usuario_creado', 'Usuario creado'],
  ['usuario_actualizado', 'Usuario actualizado'],
  ['usuario_borrado', 'Usuario borrado'],
  ['compartir_creado', 'Enlace compartido'],
  ['compartir_revocado', 'Enlace revocado'],
  ['ejecucion_iniciada', 'Ejecución iniciada'],
  ['ejecucion_completada', 'Ejecución completada'],
  ['ejecucion_fallida', 'Ejecución fallida'],
  ['formato_descargado', 'Informe descargado'],
  ['backup_realizado', 'Copia de seguridad'],
] as const

const etiquetaTipo = (tipo: string) => TIPOS.find(([t]) => t === tipo)?.[1] ?? tipo

const formatearTamano = (bytes: number) =>
  bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`

const resumirDetalles = (d: Record<string, unknown> | null) => {
  if (!d) return '—'
  const partes = Object.entries(d).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
  return partes.join(' · ')
}

export default function AdminPage({ sesion }: { sesion: Sesion }) {
  const [usuarios, setUsuarios] = useState<Usuario[]>([])
  const [cargando, setCargando] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [editando, setEditando] = useState<Usuario | null>(null)
  const [form, setForm] = useState({ username: '', password: '', role: 'user' as 'admin' | 'user', activo: true })
  const [mostrarFormulario, setMostrarFormulario] = useState(false)

  const [logs, setLogs] = useState<LogAuditoria[]>([])
  const [totalLogs, setTotalLogs] = useState(0)
  const [filtroTipo, setFiltroTipo] = useState('')

  const [backups, setBackups] = useState<BackupInfo[]>([])
  const [retencion, setRetencion] = useState(7)
  const [horaBackup, setHoraBackup] = useState(3)
  const [haciendoBackup, setHaciendoBackup] = useState(false)

  const cargar = async () => {
    try {
      setCargando(true)
      const d = await api<{ usuarios: Usuario[] }>('/api/usuarios')
      setUsuarios(d.usuarios)
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setCargando(false)
    }
  }

  useEffect(() => { cargar() }, [])

  const cargarLogs = async (tipo = filtroTipo) => {
    try {
      // Vaciar antes de pedir: mientras llega la respuesta, la tabla anterior
      // con un filtro nuevo confunde mas que un "cargando" en blanco.
      setLogs([])
      const q = tipo ? `?tipo=${encodeURIComponent(tipo)}` : ''
      const d = await api<PaginaAuditoria>(`/api/auditoria${q}`)
      setLogs(d.items)
      setTotalLogs(d.total)
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const cargarBackups = async () => {
    try {
      const d = await api<{ backups: BackupInfo[]; retencion: number; hora: number }>('/api/backups')
      setBackups(d.backups)
      setRetencion(d.retencion)
      setHoraBackup(d.hora)
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  useEffect(() => { cargarBackups() }, [])
  useEffect(() => { cargarLogs(filtroTipo) }, [filtroTipo])

  const hacerBackup = async () => {
    setHaciendoBackup(true)
    try {
      const d = await api<{ backups: BackupInfo[] }>('/api/backups', { method: 'POST', body: '{}' })
      setBackups(d.backups)
      await cargarLogs()
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setHaciendoBackup(false)
    }
  }

  const guardar = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (editando) {
        const body: Record<string, unknown> = {}
        if (form.password) body.password = form.password
        body.role = form.role
        body.activo = form.activo ? 1 : 0
        await api(`/api/usuarios/${editando.id}`, { method: 'PATCH', body: JSON.stringify(body) })
      } else {
        await post('/api/usuarios', form)
      }
      setMostrarFormulario(false)
      setEditando(null)
      setForm({ username: '', password: '', role: 'user', activo: true })
      await cargar()
      await cargarLogs()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const editar = (u: Usuario) => {
    setEditando(u)
    setForm({ username: u.username, password: '', role: u.role, activo: u.activo === 1 })
    setMostrarFormulario(true)
  }

  const nuevo = () => {
    setEditando(null)
    setForm({ username: '', password: '', role: 'user', activo: true })
    setMostrarFormulario(true)
  }

  const borrar = async (id: string) => {
    if (!confirm('¿Borrar este usuario? No se puede deshacer.')) return
    try {
      await api(`/api/usuarios/${id}`, { method: 'DELETE' })
      await cargar()
      await cargarLogs()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div className="pagina">
      <header>
        <h1>⚙️ Administración</h1>
        <p className="desc">Cuentas de acceso, copias de seguridad y log de auditoría. Solo administradores.</p>
      </header>

      {error && <div className="error-box" role="alert">{error}</div>}

      {mostrarFormulario && (
        <section className="panel">
          <h2>{editando ? 'Editar usuario' : 'Nuevo usuario'}</h2>
          <form onSubmit={guardar} className="grid">
            <div className="campo">
              <label htmlFor="u">Usuario</label>
              <input id="u" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} required disabled={!!editando} />
              {editando && <small>El nombre de usuario no se puede cambiar</small>}
            </div>
            <div className="campo">
              <label htmlFor="p">Contraseña</label>
              <input id="p" type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} required={!editando} autoComplete="new-password" />
              {editando && <small>Deja en blanco para no cambiar</small>}
            </div>
            <div className="campo">
              <label htmlFor="r">Rol</label>
              <select id="r" value={form.role} onChange={e => setForm({ ...form, role: e.target.value as 'admin' | 'user' })}>
                <option value="user">Usuario</option>
                <option value="admin">Administrador</option>
              </select>
            </div>
            <div className="campo chk">
              <label>
                <input type="checkbox" checked={form.activo} onChange={e => setForm({ ...form, activo: e.target.checked })} />
                <span>Activo</span>
              </label>
            </div>
            <div className="acciones">
              <button type="submit" className="btn primary">{editando ? 'Guardar' : 'Crear'}</button>
              <button type="button" className="btn" onClick={() => { setMostrarFormulario(false); setEditando(null) }}>Cancelar</button>
            </div>
          </form>
        </section>
      )}

      <section className="panel">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h2 style={{ margin: 0 }}>Usuarios ({usuarios.length})</h2>
          <button className="btn primary" onClick={nuevo}>Nuevo usuario</button>
        </div>

        {cargando ? (
          <div className="skeleton"><i /><i /><i /></div>
        ) : (
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Usuario</th>
                  <th>Rol</th>
                  <th>Estado</th>
                  <th>Creado</th>
                  <th>Último acceso</th>
                  <th style={{ width: '120px' }}>Acciones</th>
                </tr>
              </thead>
              <tbody>
                {usuarios.map(u => (
                  <tr key={u.id}>
                    <td>{u.username}</td>
                    <td><span className={`badge t-${u.role === 'admin' ? 'warn' : 'neutral'}`}>{u.role}</span></td>
                    <td><span className={`badge t-${u.activo === 1 ? 'ok' : 'bad'}`}>{u.activo === 1 ? 'Activo' : 'Inactivo'}</span></td>
                    <td className="mono">{new Date(u.createdAt).toLocaleString('es-ES')}</td>
                    <td className="mono">{u.lastLogin ? new Date(u.lastLogin).toLocaleString('es-ES') : '—'}</td>
                    <td>
                      <button className="btn" onClick={() => editar(u)} title="Editar">✎</button>
                      {/* Borrar la propia cuenta se oculta, no se deshabilita: el
                          servidor la rechaza igual, pero un boton que siempre va a
                          fallar solo confunde. La cuenta se llama como se quiera al
                          crearla, asi que la comparacion es con la sesion, no con un
                          nombre fijo. */}
                      {u.username !== sesion.usuario && (
                        <button className="btn" style={{ marginLeft: '0.4rem', color: 'var(--bad)' }} onClick={() => borrar(u.id)} title="Borrar">🗑</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h2 style={{ margin: 0 }}>Copias de seguridad</h2>
          <button className="btn primary" onClick={hacerBackup} disabled={haciendoBackup}>
            {haciendoBackup ? 'Copiando…' : 'Crear copia ahora'}
          </button>
        </div>
        <p className="desc">
          `data/netlab.db` se copia cada día a las {String(horaBackup).padStart(2, '0')}:00 (hora local) y al arrancar.
          Se conservan las {retencion} más recientes; las anteriores se borran solas.
        </p>

        {backups.length === 0 ? (
          <p className="desc">Todavía no hay ninguna copia.</p>
        ) : (
          <div className="scroll">
            <table aria-label="Copias de seguridad">
              <thead>
                <tr>
                  <th>Copia</th>
                  <th>Fecha</th>
                  <th>Tamaño</th>
                </tr>
              </thead>
              <tbody>
                {backups.map(b => (
                  <tr key={b.nombre}>
                    <td className="mono">{b.nombre}</td>
                    <td className="mono">{new Date(b.creadoEn).toLocaleString('es-ES')}</td>
                    <td className="mono">{formatearTamano(b.tamano)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h2 style={{ margin: 0 }}>Actividad ({totalLogs})</h2>
          <label>
            <span className="desc" style={{ marginRight: '0.5rem' }}>Filtrar por tipo</span>
            <select aria-label="Filtrar auditoría por tipo" value={filtroTipo} onChange={e => setFiltroTipo(e.target.value)}>
              <option value="">Todos</option>
              {TIPOS.map(([tipo, etiqueta]) => (
                <option key={tipo} value={tipo}>{etiqueta}</option>
              ))}
            </select>
          </label>
        </div>

        {logs.length === 0 && totalLogs === 0 ? (
          <p className="desc">No hay eventos registrados todavía.</p>
        ) : (
          <div className="scroll">
            <table aria-label="Actividad (log de auditoría)">
              <thead>
                <tr>
                  <th>Fecha</th>
                  <th>Tipo</th>
                  <th>Usuario</th>
                  <th>IP</th>
                  <th>Detalles</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(l => (
                  <tr key={l.id}>
                    <td className="mono">{new Date(l.createdAt).toLocaleString('es-ES')}</td>
                    <td>{etiquetaTipo(l.tipo)}</td>
                    <td>{l.usuario ?? '—'}</td>
                    <td className="mono">{l.ip ?? '—'}</td>
                    <td className="mono">{resumirDetalles(l.detalles)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}