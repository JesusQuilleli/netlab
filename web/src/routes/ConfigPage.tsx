import { useEffect, useState } from 'react'
import { api } from '../lib/api'
export default function ConfigPage() {
  const [cfg, setCfg] = useState<any>(null); const [err, setErr] = useState('')
  useEffect(() => { api('/api/config').then(setCfg).catch(e => setErr(e.message)) }, [])
  const perfiles = cfg?.perfilesCorreo
  return <div className="pagina"><header><h1>Configuración</h1><p className="desc">Solo lectura. Los perfiles de correo muestran host y opciones, nunca credenciales.</p></header>
    {err && <div className="error-box"><strong>{err}</strong></div>}
    {perfiles && <section className="panel"><h2>Perfiles de correo</h2><div className="scroll"><pre className="code mono">{JSON.stringify(perfiles, (k, v) => /pass/i.test(k) ? undefined : v, 2)}</pre></div></section>}
    {cfg && <details className="sec"><summary>Configuración completa</summary><pre className="code mono">{JSON.stringify(cfg, (k, v) => /pass/i.test(k) ? undefined : v, 2)}</pre></details>}</div>
}
