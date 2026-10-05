/**
 * HistoryList.tsx — El historial, con sus filtros.
 *
 * QUÉ FILTRA EL SERVIDOR Y QUÉ NO
 *   `GET /api/historial` solo entiende `limite`, `desde` y `tool`. No hay filtro
 *   por estado ni busqueda por texto en el API, asi que no se pueden mandar: si
 *   se mandaran, el servidor los ignoraria en silencio y la lista saldria
 *   "filtrada" sin estarlo.
 *
 *   Por eso la pagina pide una ventana alta (200, el maximo de `listar()`), y el
 *   estado y el texto se filtran aqui. Es la unica manera de que los tres filtros
 *   signifiquen algo sin tocar el backend. Cuando el servidor tiene mas
 *   registros que esa ventana, se dice en pantalla en vez de dejar que la lista
 *   parezca completa; el filtro por herramienta, que si va al servidor, es la
 *   salida.
 *
 *   La version anterior pedia la pagina sin parametros: `limite` vale 50 por
 *   defecto, y los filtros se aplicaban en silencio sobre esos 50. Con mas de 50
 *   ejecuciones, buscar por texto o por estado daba cero resultados sin motivo
 *   aparente.
 */

import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { StatusBadge } from '../informe/Informe'
import { duracion, fecha } from '../../lib/formato'
import type { Herramienta, HistorialItem } from '../../lib/tipos'

/** Registros por pagina una vez filtrados. */
const POR_PAGINA = 25

const coincide = (i: HistorialItem, q: string, estado: string) =>
  (!estado || i.status === estado) &&
  (!q || `${i.target} ${JSON.stringify(i.params ?? {})} ${i.tool}`.toLowerCase().includes(q.toLowerCase()))

export function HistoryList({
  items,
  total,
  cargando,
  tools,
  onDelete,
  onCambiarHerramienta,
}: {
  items: HistorialItem[]
  /** Lo que el servidor dice que hay en total, no lo que ha devuelto. */
  total: number
  cargando: boolean
  tools: Herramienta[]
  onDelete: (id: string) => void
  /** Cambia el filtro de herramienta; reinicia la pagina. */
  onCambiarHerramienta: (tool: string) => void
}) {
  const [q, setQ] = useState('')
  const [st, setSt] = useState('')
  const [pagina, setPagina] = useState(0)

  // El filtro de herramienta es el único que va al servidor, así que su estado
  // vive aquí pero la recarga la dispara quien tiene el hook.
  const [tool, setTool] = useState('')

  const filtrados = useMemo(() => items.filter((i) => coincide(i, q, st)), [items, q, st])
  const paginas = Math.max(1, Math.ceil(filtrados.length / POR_PAGINA))
  // Si se borra la última fila de la última página, el índice se queda atrás y la
  // lista sale en blanco hasta que se toca algo.
  const actual = Math.min(pagina, paginas - 1)
  const desde = actual * POR_PAGINA
  const vista = filtrados.slice(desde, desde + POR_PAGINA)
  // `items` cambia al recargar tras un borrado; si la página era la última, `actual`
  // ya no vale y el estado se queda en un índice que ya no existe.
  useEffect(() => { if (actual !== pagina) setPagina(actual) }, [actual, pagina])

  const nombre = (id: string) => tools.find((t) => t.id === id)?.titulo ?? id
  const quedanFuera = Math.max(0, total - items.length)

  const cambiarHerramienta = (v: string) => {
    setTool(v)
    setPagina(0)
    onCambiarHerramienta(v)
  }

  return (
    <div>
      <div className="filtros">
        <input
          type="search"
          aria-label="Buscar en el historial"
          placeholder="Buscar por destino o parámetros"
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            setPagina(0)
          }}
        />
        <select
          aria-label="Filtrar por herramienta"
          value={tool}
          onChange={(e) => cambiarHerramienta(e.target.value)}
        >
          <option value="">Todas las herramientas</option>
          {tools.map((t) => (
            <option key={t.id} value={t.id}>
              {t.titulo}
            </option>
          ))}
        </select>
        <select
          aria-label="Filtrar por estado"
          value={st}
          onChange={(e) => {
            setSt(e.target.value)
            setPagina(0)
          }}
        >
          <option value="">Todos los estados</option>
          <option value="pass">Correcto</option>
          <option value="warn">Con observaciones</option>
          <option value="fail">Con fallos</option>
          <option value="error">Error</option>
        </select>
      </div>

      {quedanFuera > 0 && (
        <p className="aviso-limite">
          Se muestran los {items.length} registros más recientes de {total}. Filtra por herramienta para
          ver los anteriores.
        </p>
      )}

      {vista.length === 0 ? (
        <p className="vacio">
          {cargando
            ? 'Cargando…'
            : items.length
              ? 'Ninguna ejecución de esta página coincide con los filtros.'
              : 'Aún no hay ejecuciones. Elige una herramienta y ejecútala.'}
        </p>
      ) : (
        <ul className="hist">
          {vista.map((i) => (
            <li key={i.id}>
              <Link to={`/herramienta/${i.tool}?run=${i.id}`}>
                <span className="h-tool">{nombre(i.tool)}</span>
                <span className="mono h-target" title={i.target}>
                  {i.target}
                </span>
                <StatusBadge s={i.status} />
                <span className="desc num">
                  {fecha(i.createdAt)} · {duracion(i.durationMs)}
                </span>
              </Link>
              <button
                className="btn"
                aria-label={`Eliminar ejecución de ${i.target}`}
                onClick={() => confirm('¿Eliminar esta ejecución del historial?') && onDelete(i.id)}
              >
                Eliminar
              </button>
            </li>
          ))}
        </ul>
      )}

      {filtrados.length > POR_PAGINA && (
        <nav className="paginacion" aria-label="Páginas del historial">
          <button className="btn" disabled={actual === 0} onClick={() => setPagina(actual - 1)}>
            Anterior
          </button>
          <span className="num">
            Página {actual + 1} de {paginas} · {desde + 1}–{Math.min(desde + POR_PAGINA, filtrados.length)} de{' '}
            {filtrados.length}
          </span>
          <button className="btn" disabled={actual >= paginas - 1} onClick={() => setPagina(actual + 1)}>
            Siguiente
          </button>
        </nav>
      )}
    </div>
  )
}