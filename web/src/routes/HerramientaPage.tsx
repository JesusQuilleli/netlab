/**
 * HerramientaPage.tsx — Una herramienta, su formulario y su informe.
 *
 * Lo que sí hace bien esta página y conviene no romper: ejecutar cancela la
 * ejecución anterior, el formulario se remonta al cambiar de ejecución para que
 * no conserve campos de la anterior, y el resultado se anuncia con
 * `aria-live`.
 *
 * El enlace profundo. El backend ya guarda cada ejecución y
 * `GET /api/run/:id` la devuelve entera, así que una ejecución es una URL. Al
 * terminar se escribe `?run=<id>`, y eso da las tres cosas que faltaban: recargar
 * no pierde el informe, el enlace se puede compartir y el botón "atrás" del
 * navegador deshace una ejecución. Sin esto, el informe solo vivía en memoria y
 * se perdía con F5.
 *
 * El `id` va en el query, no en el path, porque la ruta la ocupa el nombre de la
 * herramienta y una ejecución se puede abrir desde el historial de cualquier otra.
 */

import { useEffect, useRef } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { DynamicForm } from '../components/form/DynamicForm'
import { Informe } from '../components/informe/Informe'
import { Copiar } from '../components/ui/Copiar'
import { useEjecucion } from '../hooks'
import type { Herramienta } from '../lib/tipos'

export default function HerramientaPage({ tools, onDone }: { tools: Herramienta[]; onDone: () => void }) {
  const { id } = useParams()
  const [sp, setSp] = useSearchParams()
  const rid = sp.get('run')
  const tool = tools.find((t) => t.id === id)
  const ex = useEjecucion()

  // Se guarda el `id` que ya está en pantalla. El efecto de carga compara con él
  // en vez de con `rid` porque, al escribir `?run=` en la URL, `rid` cambia una
  // vez y `ex.run.id` no: sin esta comparación, publicar el enlace disparaba una
  // segunda petición de la misma ejecución que ya estaba en memoria.
  const cargado = useRef<string | null>(null)

  useEffect(() => {
    if (rid) {
      if (cargado.current === rid) return
      cargado.current = rid
      void ex.cargar(rid)
    } else {
      cargado.current = null
      ex.reset()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, rid])

  // Al terminar una ejecución, su id pasa a la URL. Es lo que convierte el
  // informe en algo enlazable.
  //
  // Antes se marca `cargado` con ese id: la respuesta del POST ya trae la
  // ejecución entera, así que al cambiar `rid` y dispararse el efecto de carga
  // no hay que volver a pedir lo que se acaba de ejecutar. Si el enlace se abre
  // a mano o desde el historial, `cargado` valdrá `null` y sí se pide.
  useEffect(() => {
    if (ex.estado !== 'listo' || !ex.run) return
    if (rid === ex.run.id) return
    cargado.current = ex.run.id
    const siguiente = new URLSearchParams(sp)
    siguiente.set('run', ex.run.id)
    setSp(siguiente, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ex.estado, ex.run?.id])

  if (!tool) return <p className="vacio">Herramienta no encontrada.</p>

  // `registro.params` es lo que el usuario escribió (con la contraseña
  // enmascarada); `result.params` es la copia saneada. Se prefiere el primero.
  const initial = ex.run?.registro?.params ?? ex.run?.result.params
  const enlace = typeof window === 'undefined' ? '' : window.location.href

  return (
    <div className="pagina">
      <header>
        <h1>
          {tool.icon} {tool.titulo}
        </h1>
        <p className="desc">
          {tool.descripcion}
          {tool.sinRed && ' · Funciona sin conexión a internet.'}
        </p>
      </header>

      <section className="panel">
        {/*
          El `key` lleva también el id de la ejecución cargada, y no solo el de
          la URL, porque al abrir un enlace el formulario se monta antes de que
          llegue la respuesta: `initial` llega después y un `useState` ya
          inicializado no lo vuelve a leer. Sin esta parte del key, el informe
          aparece pero el formulario sale en blanco y no se puede reejecutar.
        */}
        <DynamicForm
          key={`${tool.id}-${rid ?? 'nuevo'}-${ex.run?.id ?? ''}`}
          campos={tool.campos}
          initial={initial}
          ejecutando={ex.estado === 'ejecutando'}
          onSubmit={async (p) => {
            if (await ex.ejecutar(tool.id, p)) onDone()
          }}
          onCancel={ex.cancelar}
        />
      </section>

      <div aria-live="polite" aria-busy={ex.estado === 'ejecutando'}>
        {ex.estado === 'ejecutando' && (
          <div className="skeleton" aria-label="Ejecutando">
            <i />
            <i />
            <i />
          </div>
        )}

        {ex.estado === 'error' && ex.error && (
          <div className="error-box" role="alert">
            <strong>{ex.error.message}</strong>
            {ex.error.remediation && <p>{ex.error.remediation}</p>}
          </div>
        )}

        {ex.estado === 'listo' && ex.run && (
          <>
            <div className="enlace">
              <Copiar t={enlace} etiqueta="Copiar el enlace de esta ejecución" className="btn" />
            </div>
            <Informe run={ex.run} />
          </>
        )}
      </div>
    </div>
  )
}