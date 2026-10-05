import { useState } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell'
import { useHerramientas, useHistorial, useSesion, useSetupStatus } from './hooks'
import { post } from './lib/api'
import HerramientaPage from './routes/HerramientaPage'
import HistorialPage from './routes/HistorialPage'
import ConfigPage from './routes/ConfigPage'
import AdminPage from './routes/AdminPage'

function Acceso({ onLogin }: { onLogin: (u: string, p: string) => Promise<void> }) {
  const [u, setU] = useState(''), [p, setP] = useState(''), [err, setErr] = useState('')
  return <form className="login panel" onSubmit={async e => { e.preventDefault(); try { await onLogin(u, p) } catch (x) { setErr((x as Error).message); setP('') } }}>
    <h1>Netlab</h1><div className="campo"><label htmlFor="u">Usuario</label><input id="u" value={u} onChange={e => setU(e.target.value)} autoComplete="username" required /></div>
    <div className="campo"><label htmlFor="p">Contraseña</label><input id="p" type="password" value={p} onChange={e => setP(e.target.value)} autoComplete="off" spellCheck={false} required /></div>
    {err && <div className="error-box" role="alert">{err}</div>}<button className="btn primary">Entrar</button></form>
}

/**
 * Formulario del primer ingreso: crea el administrador principal.
 *
 * Solo aparece cuando la tabla de usuarios esta vacia. El servidor cierra esa
 * ruta en cuanto existe una cuenta, asi que desde aqui solo se puede llegar una
 * vez por instalacion.
 */
function PrimerAdmin({ onListo }: { onListo: () => void }) {
  const [u, setU] = useState('admin')
  const [p, setP] = useState('')
  const [p2, setP2] = useState('')
  const [err, setErr] = useState('')
  const [ok, setOk] = useState(false)

  return <form className="login panel" onSubmit={async e => {
    e.preventDefault()
    setErr('')
    if (p !== p2) { setErr('Las contraseñas no coinciden'); return }
    try {
      await post('/api/setup/first-admin', { username: u, password: p })
      setOk(true)
      setTimeout(onListo, 800)
    } catch (x) { setErr((x as Error).message) }
  }}>
    <h1>Configurar administrador principal</h1>
    <p className="desc">Primera vez que entras. Esta es la cuenta que despues dara de alta al resto de usuarios.</p>
    <div className="campo"><label htmlFor="ua">Usuario</label><input id="ua" value={u} onChange={e => setU(e.target.value)} autoComplete="username" required /></div>
    <div className="campo"><label htmlFor="pa">Contraseña</label><input id="pa" type="password" value={p} onChange={e => setP(e.target.value)} autoComplete="new-password" spellCheck={false} minLength={8} required /><small>Mínimo 8 caracteres</small></div>
    <div className="campo"><label htmlFor="pa2">Repetir contraseña</label><input id="pa2" type="password" value={p2} onChange={e => setP2(e.target.value)} autoComplete="new-password" spellCheck={false} minLength={8} required /></div>
    {err && <div className="error-box" role="alert">{err}</div>}
    {ok && <div className="ok-box" role="status">Administrador creado. Entrando...</div>}
    <button className="btn primary" disabled={ok}>Crear administrador</button>
  </form>
}

/**
 * La aplicacion de verdad, con sesion.
 *
 * Va en su propio componente para que sus hooks se ejecuten siempre: en el
 * componente raiz hay una pantalla de setup antes del login, y si los hooks
 * estuvieran en el mismo sitio se Saltarian en esa vuelta.
 */
function ConSesion() {
  const ses = useSesion()
  const ok = !!ses.data && (ses.data.autenticado || ses.data.local)
  const { tools, error: et } = useHerramientas(ok)
  // `activo: ok` para no pedir el historial antes de tener sesión: son peticiones
  // que el servidor rechaza y no paran de caer mientras se está en la pantalla de
  // acceso.
  const recientes = useHistorial({ limite: 12, activo: ok })

  if (ses.error) return <div className="login panel error-box"><strong>{ses.error.message}</strong>{ses.error.remediation && <p>{ses.error.remediation}</p>}</div>
  if (!ses.data) return <div className="login" aria-busy>Cargando...</div>
  if (!ok) return <Acceso onLogin={ses.login} />

  return <AppShell tools={tools} items={recientes.items} sesion={ses.data}>
    {et && <div className="error-box"><strong>{et.message}</strong>{et.remediation && <p>{et.remediation}</p>}</div>}
    <Routes>
      <Route path="/herramienta/:id" element={<HerramientaPage tools={tools} onDone={recientes.recargar} />} />
      <Route path="/historial" element={<HistorialPage tools={tools} />} />
      <Route path="/config" element={<ConfigPage />} />
      <Route path="/admin" element={ses.data.role === 'admin' ? <AdminPage sesion={ses.data} /> : <Navigate to="/" replace />} />
      <Route path="*" element={tools[0] ? <Navigate to={`/herramienta/${tools.find(t => t.id === 'smtp-validator')?.id ?? tools[0].id}`} replace /> : null} />
    </Routes>
  </AppShell>
}

export default function App() {
  const setup = useSetupStatus()

  if (setup.cargando) return <div className="login" aria-busy>Cargando...</div>
  if (setup.error) return <div className="login panel error-box"><strong>{setup.error.message}</strong>{setup.error.remediation && <p>{setup.error.remediation}</p>}</div>

  // Sin ningun usuario en la base de datos, entrar es imposible, porque no hay
  // con quien. Antes de enseñar el login se ofrece crear el administrador que
  // gobierna las demas cuentas.
  if (setup.data && !setup.data.completado) return <PrimerAdmin onListo={setup.recargar} />

  return <ConSesion />
}