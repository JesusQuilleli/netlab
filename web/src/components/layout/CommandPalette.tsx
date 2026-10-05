import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { Herramienta, HistorialItem } from '../../lib/tipos'

export function CommandPalette({ open, onClose, tools, items }: { open: boolean; onClose: () => void; tools: Herramienta[]; items: HistorialItem[] }) {
  const [q, setQ] = useState(''), [sel, setSel] = useState(0); const nav = useNavigate(); const ref = useRef<HTMLInputElement>(null)
  useEffect(() => { if (open) { setQ(''); setSel(0); setTimeout(() => ref.current?.focus()) } }, [open])
  const res = useMemo(() => {
    const s = q.toLowerCase()
    const a = tools.filter(t => !s || (t.titulo + t.id).toLowerCase().includes(s)).map(t => ({ k: t.id, l: `${t.icon} ${t.titulo}`, s: 'Herramienta', to: `/herramienta/${t.id}` }))
    const b = s ? items.filter(i => i.target.toLowerCase().includes(s)).slice(0, 8).map(i => ({ k: i.id, l: i.target, s: `Historial · ${i.tool}`, to: `/herramienta/${i.tool}?run=${i.id}` })) : []
    return [...a, ...b]
  }, [q, tools, items])
  if (!open) return null
  const ir = (to: string) => { nav(to); onClose() }
  return <div className="overlay" onMouseDown={onClose}><div className="palette" role="dialog" aria-modal="true" aria-label="Paleta de comandos" onMouseDown={e => e.stopPropagation()}>
    <input ref={ref} value={q} placeholder="Buscar herramienta o destino del historial…" aria-label="Buscar" onChange={e => { setQ(e.target.value); setSel(0) }}
      onKeyDown={e => { if (e.key === 'Escape') onClose(); if (e.key === 'ArrowDown') { e.preventDefault(); setSel(x => Math.min(x + 1, res.length - 1)) } if (e.key === 'ArrowUp') { e.preventDefault(); setSel(x => Math.max(x - 1, 0)) } if (e.key === 'Enter' && res[sel]) ir(res[sel].to) }} />
    <ul>{res.map((r, i) => <li key={r.k}><button className={i === sel ? 'on' : ''} onClick={() => ir(r.to)}><span className={r.s === 'Herramienta' ? '' : 'mono'}>{r.l}</span><small>{r.s}</small></button></li>)}
      {!res.length && <li className="vacio">Sin resultados.</li>}</ul></div></div>
}
