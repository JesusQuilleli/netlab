/**
 * Copiar.tsx — El boton de copiar, en un solo sitio.
 *
 * Vive aqui porque lo usan dos ramas distintas de la app (los datos copiables de
 * un informe y el enlace profundo de una ejecución) y porque necesita el mismo
 * detalle en las dos: `navigator.clipboard` puede no existir o estar bloqueado
 * sin contexto seguro, y entonces un `catch` mudo deja el boton marcando "✓"
 * sin haber copiado nada.
 */

import { useEffect, useRef, useState } from 'react'

export function Copiar({ t, etiqueta, className = 'copy' }: { t: string; etiqueta?: string; className?: string }) {
  const [estado, setEstado] = useState<'quieto' | 'hecho' | 'fallo'>('quieto')
  const t0 = useRef<number | undefined>(undefined)

  useEffect(() => () => window.clearTimeout(t0.current), [])

  const copiar = async () => {
    try {
      await navigator.clipboard.writeText(t)
      setEstado('hecho')
    } catch {
      setEstado('fallo')
    }
    window.clearTimeout(t0.current)
    t0.current = window.setTimeout(() => setEstado('quieto'), 1400)
  }

  return (
    <button
      type="button"
      className={className}
      aria-label={etiqueta ?? `Copiar ${t}`}
      title={estado === 'fallo' ? 'No se pudo copiar. Selecciona el texto y cópialo a mano.' : undefined}
      onClick={copiar}
    >
      {estado === 'hecho' ? '✓' : estado === 'fallo' ? '⚠' : '⧉'}
    </button>
  )
}