/**
 * Informe.tsx — Como se lee una ejecución.
 *
 * Todo lo que llega de `sections` se interpreta con `lib/tabla-modelo.ts` y se
 * pinta a partir de ahí. Este archivo no decide ni una vez qué es una tabla: si
 * el contrato cambia, cambia el modelo y no los seis `kind`.
 *
 * Lo que no se puede volver a hacer aquí (y por eso el módulo está aparte):
 *   - leer las columnas como si fueran objetos (`col.label` era `undefined` y las
 *     cabeceras salían en blanco);
 *   - pintar solo las celdas quePAREN en la fila, descuadrando la tabla cuando
 *     un campo opcional no llegó;
 *   - perder el tono de los pares `[etiqueta, valor, tono]`, que es el tercer
 *     elemento de la tupla y no un campo del valor.
 */

import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import { STATUS, duracion, fecha } from '../../lib/formato'
import { modeloTabla, paresDe, textoCelda } from '../../lib/tabla-modelo'
import { Copiar } from '../ui/Copiar'
import type { Resultado, RunResp, Seccion, Tone } from '../../lib/tipos'

export const StatusBadge = ({ s }: { s: Resultado['status'] }) => {
  const [t, l, i] = STATUS[s]
  return (
    <span className={`badge t-${t}`}>
      <b aria-hidden>{i}</b>
      {l}
    </span>
  )
}

/** Un IP, una URL o un host: merece un boton de copiar al lado. */
const esDato = (s: string) =>
  /^(\d{1,3}(\.\d{1,3}){3}(\/\d+)?|[a-z0-9-]+(\.[a-z0-9-]+)+|[0-9a-f:]+:[0-9a-f:]+)$/i.test(s)

function Val({ texto }: { texto: string }) {
  const numerico = /^-?\d+(\.\d+)?$/.test(texto)
  return (
    <span className={`val mono ${numerico ? 'num' : ''}`} title={texto}>
      {texto}
      {esDato(texto) && <Copiar t={texto} />}
    </span>
  )
}

const Tabla = ({ s }: { s: Seccion }) => {
  // Toda la lectura del contrato pasa por aquí. `filas` viene normalizada a la
  // largura de `columnas`, con lo que falte ya relleno y el tono ya filtrado.
  const m = modeloTabla(s)
  if (m.columnasNum === 0) return <p className="desc">Tabla sin datos.</p>
  return (
    <div className="scroll">
      <table>
        {m.anchos && (
          <colgroup>
            {m.anchos.map((w, i) => (
              <col key={i} style={{ width: `${w}%` }} />
            ))}
          </colgroup>
        )}
        <thead>
          <tr>
            {m.columnas.map((c, i) => (
              <th key={i}>{c.texto}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {m.filas.map((fila, i) => (
            <tr key={i}>
              {fila.map((celda, j) => (
                <td key={j} className={celda.tone ? `bg-${celda.tone}` : ''}>
                  <Val texto={celda.texto} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const Kv = ({ s }: { s: Seccion }) => {
  const pares = paresDe(s)
  if (pares.length === 0) return <p className="desc">Sin datos.</p>
  return (
    <dl className="kv">
      {pares.map((p, i) => (
        <div key={i} className={p.tone ? `bg-${p.tone}` : ''}>
          <dt>{p.label}</dt>
          <dd>
            <Val texto={p.value} />
          </dd>
        </div>
      ))}
    </dl>
  )
}

const Codigo = ({ s }: { s: Seccion }) => <pre className="code mono">{textoCelda(s.value)}</pre>

const Lista = ({ s }: { s: Seccion }) => {
  const items = Array.isArray(s.items) ? s.items : []
  if (items.length === 0) return <p className="desc">Sin elementos.</p>
  return (
    <ul className="lista">
      {items.map((x, i) => (
        <li key={i}>
          <Val texto={textoCelda(x)} />
        </li>
      ))}
    </ul>
  )
}

const Medidor = ({ s }: { s: Seccion }) => {
  const n = Math.max(0, Math.min(100, Number(s.value) || 0))
  const t: Tone = s.tone ?? (n >= 80 ? 'ok' : n >= 50 ? 'warn' : 'bad')
  return (
    <div className="meter" role="meter" aria-valuenow={n} aria-valuemin={0} aria-valuemax={100}>
      <div className={`fill t-${t}`} style={{ width: `${n}%` }}>
        <span className="num">{n}%</span>
      </div>
    </div>
  )
}

export function SeccionRenderer({ s }: { s: Seccion }) {
  const B = {
    table: Tabla,
    kv: Kv,
    code: Codigo,
    text: ({ s }: { s: Seccion }) => <p className="texto">{textoCelda(s.value)}</p>,
    list: Lista,
    meter: Medidor
  }[s.kind]
  return (
    <details className={`sec ${s.tone ? `edge-${s.tone}` : ''}`} open>
      <summary>{s.title}</summary>
      {s.description && <p className="desc">{s.description}</p>}
      {B ? <B s={s} /> : <p className="desc">Tipo de sección no soportado: {s.kind}</p>}
    </details>
  )
}

const SEV = { error: 'Errores', warn: 'Advertencias', info: 'Información' } as const
const SEVT = { error: 'bad', warn: 'warn', info: 'neutral' } as const

function CompartirBtn({ runId, shareUrl, expiraEn }: { runId: string; shareUrl?: string | null; expiraEn?: string | null }) {
  const [estado, setEstado] = useState<'quieto' | 'cargando' | 'hecho' | 'fallo'>('quieto')
  const [url, setUrl] = useState<string | undefined>(shareUrl ?? undefined)
  const [expira, setExpira] = useState<string | undefined>(expiraEn ?? undefined)

  const crear = async () => {
    setEstado('cargando')
    try {
      const res = await api<{ shareUrl: string; expiraEn: string }>('/api/compartir', {
        method: 'POST',
        body: JSON.stringify({ ejecucionId: runId })
      })
      setUrl(res.shareUrl)
      setExpira(res.expiraEn)
      setEstado('hecho')
    } catch {
      setEstado('fallo')
    }
  }

  const cargando = estado === 'cargando'
  const mostrarBoton = !url && estado === 'quieto'

  if (mostrarBoton) {
    return (
      <button type="button" className="btn" onClick={crear} disabled={cargando}>
        {cargando ? '…' : 'Compartir'}
      </button>
    )
  }

  return (
    <div className="compartido">
      <label>
        <span>Enlace público</span>
        <div className="fila">
          <input type="text" value={url ?? ''} readOnly />
          <Copiar t={url ?? ''} etiqueta="Copiar enlace compartido" />
        </div>
      </label>
      {expira && <small>Expira: {new Date(expira).toLocaleString('es-ES')}</small>}
    </div>
  )
}

function Hallazgos({ f }: { f: Resultado['findings'] }) {
  if (!f.length) return <p className="desc">Sin hallazgos.</p>
  return (
    <section aria-label="Hallazgos">
      {(['error', 'warn', 'info'] as const).map((sv) => {
        const l = f.filter((x) => x.severity === sv)
        if (!l.length) return null
        return (
          <div key={sv} className="grupo">
            <h3>
              {SEV[sv]} ({l.length})
            </h3>
            {l.map((x, i) => (
              <article key={i} className={`finding edge-${SEVT[sv]}`}>
                <h4>{x.title}</h4>
                <p>{x.detail}</p>
                {x.recommendation && (
                  <p className="remed">
                    <b>Cómo resolverlo: </b>
                    {x.recommendation}
                  </p>
                )}
              </article>
            ))}
          </div>
        )
      })}
    </section>
  )
}

export function Informe({ run }: { run: RunResp }) {
  const r = run.result
  const [formatos, setFormatos] = useState<{ nombre: string }[]>([])
  useEffect(() => {
    // `?? []` y no solo el `catch`: los botones de descarga son un adorno
    // encima del informe, y sin ellos el informe entero tiene que seguir
    // leyéndose. Con una forma inesperada de la respuesta, un `setFormatos(
    // undefined)` dejaba la página en blanco.
    api<{ formatos?: { nombre: string }[] }>('/api/formats')
      .then((d) => setFormatos(Array.isArray(d.formatos) ? d.formatos : []))
      .catch(() => setFormatos([]))
  }, [])

  return (
    <div className="informe">
      <header className="verdict">
        <div className={`ic t-${STATUS[r.status][0]}`} aria-hidden>
          {STATUS[r.status][2]}
        </div>
        <div>
          <h2>
            {r.headline?.trim() || `${r.toolTitle} · ${STATUS[r.status][1]}`}
          </h2>
          <p className="mono target">{r.target}</p>
        </div>
        <div className="meta num">
          {duracion(r.durationMs)}
          <br />
          {fecha(r.startedAt)}
        </div>
      </header>

      {run.avisos?.length > 0 && (
        <div className="avisos" role="note">
          {run.avisos.map((a, i) => (
            <p key={i}>ⓘ {a}</p>
          ))}
        </div>
      )}

      {r.error && (
        <div className="error-box">
          <strong>{r.error.message}</strong>
          {r.error.remediation && <p>{r.error.remediation}</p>}
        </div>
      )}

      {r.summary.length > 0 && (
        <div className="cards">
          {r.summary.map((c, i) => (
            <div key={i} className={`card edge-${c.tone}`}>
              <small>{c.label}</small>
              <b className="mono num">{c.value}</b>
            </div>
          ))}
        </div>
      )}

      <Hallazgos f={r.findings} />

      {r.sections.map((s, i) => (
        <SeccionRenderer key={s.id ?? i} s={s} />
      ))}

      {r.logs.length > 0 && (
        <details className="sec">
          <summary>Detalles técnicos ({r.logs.length})</summary>
          <div className="logs mono">
            {r.logs.map((l, i) => (
              <div key={i} className={`lv-${l.level}`}>
                <span>{l.at ?? ''}</span>
                <b>{l.level}</b> {l.message}
              </div>
            ))}
          </div>
        </details>
      )}

      {formatos.length > 0 && (
        <div className="descargas">
          <span>Descargar informe:</span>
          {formatos.map((f) => (
            <a key={f.nombre} className="btn" href={`/api/run/${run.id}/${f.nombre}`} download>
              {f.nombre.toUpperCase()}
            </a>
          ))}
        </div>
      )}

      <CompartirBtn runId={run.id} shareUrl={run.shareUrl} expiraEn={run.expiraEn} />
    </div>
  )
}