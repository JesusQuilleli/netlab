/**
 * AdminPage.tsx — Administración de usuarios (solo admin).
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

export default function AdminPage({ sesion }: { sesion: Sesion }) {
  const [usuarios, setUsuarios] = useState<Usuario[]>([])
  const [cargando, setCargando] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [editando, setEditando] = useState<Usuario | null>(null)
  const [form, setForm] = useState({ username: '', password: '', role: 'user' as 'admin' | 'user', activo: true })
  const [mostrarFormulario, setMostrarFormulario] = useState(false)

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
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div className="pagina">
      <header>
        <h1>⚙️ Administración de usuarios</h1>
        <p className="desc">Gestión de cuentas de acceso. Solo administradores.</p>
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
    </div>
  )
}