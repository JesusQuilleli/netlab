/**
 * HistorialPage.tsx — El historial, y quién pide los datos.
 *
 * La página tiene su propio `useHistorial` en vez de usar el de `App`. El de
 * `App` alimenta la lista de recientes de la barra lateral con los últimos
 * registros; este necesita el total, el filtro de herramienta y el estado de
 * carga. Compartir uno obligaría a subir el estado de filtros a `App`, que no
 * sabe nada de ellos.
 */

import { useState } from 'react'
import { HistoryList } from '../components/historial/HistoryList'
import { useHistorial } from '../hooks'
import type { Herramienta } from '../lib/tipos'

/**
 * Registros que se piden al servidor.
 *
 * `listar()` acepta como mucho 200 (`Math.min(200, ...)`). Se piden todos
 * porque el filtro por texto y por estado se aplican en el navegador, y con la
 * ventana por defecto de 50 ambos darían cero resultados en cuanto el historial
 * pasara de 50, sin avisar.
 */
const LIMITE = 200

export default function HistorialPage({ tools }: { tools: Herramienta[] }) {
  const [tool, setTool] = useState('')
  const { items, total, cargando, error, borrar } = useHistorial({ tool, limite: LIMITE })

  return (
    <div className="pagina">
      <header>
        <h1>Historial</h1>
        <p className="desc">
          Ejecuciones guardadas en el servidor. Abre una para recargar su informe y parámetros.
        </p>
      </header>
      {error ? (
        <div className="error-box" role="alert">
          <strong>{error.message}</strong>
          {error.remediation && <p>{error.remediation}</p>}
        </div>
      ) : (
        <HistoryList
          items={items}
          total={total}
          cargando={cargando}
          tools={tools}
          onDelete={borrar}
          onCambiarHerramienta={setTool}
        />
      )}
    </div>
  )
}