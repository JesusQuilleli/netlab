import { useEffect, useState, type ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { CommandPalette } from './CommandPalette'
import type { Herramienta, HistorialItem, Sesion } from '../../lib/tipos'

const GRUPOS: [string, string[]][] = [['Red', ['dns-checker', 'ip-audit', 'ip-abuse', 'subnet-analyzer']], ['Correo', ['mail-checker', 'smtp-validator']]]

export function Sidebar({ tools, abierto, cerrar, esAdmin }: { tools: Herramienta[]; abierto: boolean; cerrar: () => void; esAdmin: boolean }) {
  const resto = tools.filter(t => !GRUPOS.some(g => g[1].includes(t.id)))
  const grupos = [...GRUPOS.map(([n, ids]) => [n, ids.map(i => tools.find(t => t.id === i)).filter(Boolean) as Herramienta[]] as const), ...(resto.length ? [['Otras', resto] as const] : [])]
  return <nav className={`sidebar ${abierto ? 'open' : ''}`} aria-label="Principal" onClick={cerrar}>
    <div className="brand">Net<span>lab</span></div>
    {grupos.map(([n, l]) => <div key={n}><h2 className="grp">{n}</h2>{l.map(t => <NavLink key={t.id} to={`/herramienta/${t.id}`} className="item"><span aria-hidden>{t.icon}</span><span><b>{t.titulo}</b><small>{t.descripcion}</small></span></NavLink>)}</div>)}
    <div><h2 className="grp">Sistema</h2><NavLink to="/historial" className="item"><span aria-hidden>🕘</span><span><b>Historial</b></span></NavLink><NavLink to="/config" className="item"><span aria-hidden>⚙</span><span><b>Configuración</b></span></NavLink>{esAdmin && <NavLink to="/admin" className="item"><span aria-hidden>👥</span><span><b>Administración</b></span></NavLink>}</div>
  </nav>
}

export function AppShell({ tools, items, sesion, children }: { tools: Herramienta[]; items: HistorialItem[]; sesion: Sesion; children: ReactNode }) {
  const [menu, setMenu] = useState(false), [pal, setPal] = useState(false)
  const [tema, setTema] = useState(() => localStorage.getItem('theme') ?? 'auto')
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPal(p => !p) } }
    addEventListener('keydown', h); return () => removeEventListener('keydown', h)
  }, [])
  useEffect(() => { tema === 'auto' ? document.documentElement.removeAttribute('data-theme') : (document.documentElement.dataset.theme = tema); localStorage.setItem('theme', tema) }, [tema])
  const sig = { auto: 'dark', dark: 'light', light: 'auto' }[tema as 'auto'] as string
  const esAdmin = sesion.role === 'admin'
  return <div className="shell">
    <header className="topbar">
      <button className="btn menu" aria-label="Abrir menú" onClick={() => setMenu(true)}>☰</button>
      <button className="btn buscar" onClick={() => setPal(true)}>Buscar… <kbd>Ctrl K</kbd></button>
      <button className="btn" onClick={() => setTema(sig)} aria-label={`Tema: ${tema}. Cambiar a ${sig}`}>Tema: {tema === 'auto' ? 'sistema' : tema === 'dark' ? 'oscuro' : 'claro'}</button>
    </header>
    {menu && <div className="scrim" onClick={() => setMenu(false)} />}
    <Sidebar tools={tools} abierto={menu} cerrar={() => setMenu(false)} esAdmin={esAdmin} />
    <main>{children}</main>
    <footer className="statusbar"><span><i className="dot" />{sesion.local ? 'Sesión local' : `Sesión: ${sesion.usuario ?? 'autenticado'} (${sesion.role ?? 'user'})`}</span><span className="mono">Datos: API /api → 127.0.0.1:4310</span>{sesion.modoTextoPlano && <span className="t-warn badge">Modo texto plano</span>}</footer>
    <CommandPalette open={pal} onClose={() => setPal(false)} tools={tools} items={items} />
  </div>
}
