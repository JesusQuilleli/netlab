/**
 * DynamicForm.tsx — El formulario de las seis herramientas.
 *
 * No hay un componente por herramienta: las seis se pintan desde `campos`, que
 * es la unica descripcion de la entrada que el servidor acepta. Anadir una
 * herramienta nueva al backend no toca este archivo.
 *
 * Tres detalles del contrato que hay que respetar y que ya han roto:
 *
 *   1. `options` llega con las claves `value` y `label`. Leerlas como
 *      `{valor, etiqueta}` deja el desplegable vacio.
 *   2. El tipo `lista-requisitos` es un area de texto con una linea por tramo
 *      ("Nombre:hosts"), no un input. Lo usa el reparto VLSM de subnet-analyzer.
 *   3. `requiredUnless` significa "obligatorio mientras ese otro campo NO este
 *      activo", exactamente la misma formula que aplica `server/validar.js`.
 *      Interpretarlo al reves marca como opcional justo lo que el servidor va
 *      a rechazar.
 */

import { useMemo, useState } from 'react'
import type { Campo as C } from '../../lib/tipos'
import { bytes } from '../../lib/formato'

type Valor = unknown
type Valores = Record<string, Valor>

/** Un campo se ve si su condicion activadora esta activa. */
const visible = (c: C, v: Valores): boolean => {
  if (!c.shownWhen) return true
  const [clave, esperado] = c.shownWhen.split(/[=:]/)
  return esperado === undefined ? Boolean(v[clave]) : String(v[clave]) === esperado
}

/** Copia de la formula de `server/validar.js`, no una aproximacion. */
const obligatorio = (c: C, v: Valores): boolean => Boolean(c.required) || Boolean(c.requiredUnless && !v[c.requiredUnless])

/**
 * Campo de texto que acompaña a un archivo, si lo hay.
 *
 * `dns-checker` declara `archivoNombre` para ponerlo en la cabecera del informe.
 * Es el nombre de un `*Nombre` junto a un `file`, no un convenio inventado aqui.
 */
const campoNombreDe = (campos: C[], c: C): C | undefined =>
  c.type === 'file' ? campos.find((o) => o.name.endsWith('Nombre')) : undefined

type CampoProps = {
  c: C
  valor: Valor
  requerido: boolean
  /** Valor de la ejecucion anterior, ya enmascarado por el servidor. */
  previo: Valor
  alCambiar: (valor: Valor) => void
  /** Al elegir archivo, ademas del contenido llega su nombre. */
  alElegirArchivo?: (nombre: string, contenido: string) => void
}

function Campo({ c, valor, requerido, previo, alCambiar, alElegirArchivo }: CampoProps) {
  const id = `f-${c.name}`
  const ayuda = c.help ? `${id}-h` : undefined
  const comun = { id, name: c.name, 'aria-describedby': ayuda }

  // Un campo que el backend ya guardo enmascarado se ensena como tal. Rellenar
  // el valor real de una contrasena no es posible ni se intenta: nunca se guardo.
  const marcador = c.type === 'password' && previo === '[REDACTADO]'
  const texto = valor === undefined || valor === null ? '' : String(valor)

  let control
  if (c.type === 'checkbox') {
    control = (
      <input {...comun} type="checkbox" checked={Boolean(valor)} onChange={(e) => alCambiar(e.target.checked)} />
    )
  } else if (c.type === 'select') {
    control = (
      <select {...comun} value={texto} onChange={(e) => alCambiar(e.target.value)}>
        {!requerido && <option value="">—</option>}
        {(c.options ?? []).map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    )
  } else if (c.type === 'file') {
    control = <input {...comun} type="file" accept={c.accept} onChange={async (e) => {
      const f = e.target.files?.[0]
      if (!f) return alCambiar('')
      if (c.maxBytes && f.size > c.maxBytes) {
        alert(`El archivo supera el máximo de ${bytes(c.maxBytes)}.`)
        e.target.value = ''
        return alCambiar('')
      }
      const contenido = await f.text()
      // Con campo de nombre al lado, el nombre del archivo se rellena solo: si no,
      // la cabecera del informe sale con el hueco del nombre vacio.
      if (alElegirArchivo) alElegirArchivo(f.name, contenido)
      else alCambiar(contenido)
    }} />
  } else if (c.type === 'lista-requisitos') {
    control = (
      <textarea
        {...comun}
        rows={4}
        className="mono"
        value={texto}
        placeholder={c.placeholder}
        onChange={(e) => alCambiar(e.target.value)}
      />
    )
  } else {
    control = (
      <input
        {...comun}
        type={c.type}
        value={texto}
        required={requerido}
        min={c.min}
        max={c.max}
        className={c.type === 'password' ? '' : 'mono'}
        placeholder={marcador ? '[REDACTADO] en la ejecución anterior' : c.placeholder}
        autoComplete={c.type === 'password' ? 'off' : undefined}
        spellCheck={c.type === 'password' ? false : undefined}
        onChange={(e) => alCambiar(e.target.value)}
      />
    )
  }

  return (
    <div className={`campo${c.type === 'checkbox' ? ' chk' : ''}${c.type === 'file' || c.type === 'lista-requisitos' ? ' ancho' : ''}`}>
      <label htmlFor={id}>
        {c.label}
        {c.unit && <span className="unidad"> ({c.unit})</span>}
        {requerido && (
          <span className="req" aria-hidden>
            {' '}
            *
          </span>
        )}
      </label>
      {control}
      {c.help && <small id={ayuda}>{c.help}</small>}
    </div>
  )
}

type Props = {
  campos: C[]
  /** Parametros de una ejecucion anterior. La contrasena llega enmascarada. */
  initial?: Record<string, unknown>
  ejecutando: boolean
  onSubmit: (params: Record<string, unknown>) => void
  onCancel: () => void
}

export function DynamicForm({ campos, initial, ejecutando, onSubmit, onCancel }: Props) {
  const [v, setV] = useState<Valores>(() => {
    const base: Valores = {}
    for (const c of campos) {
      base[c.name] = c.default !== undefined && c.default !== null ? c.default : c.type === 'checkbox' ? false : ''
    }
    // El archivo nunca se rellena desde una ejecucion anterior: su contenido se
    // leyo en memoria y no se guardo en ningun sitio.
    if (initial) {
      for (const c of campos) {
        if (c.name in initial && c.type !== 'password' && c.type !== 'file') base[c.name] = initial[c.name]
      }
    }
    return base
  })

  const nombreDe = useMemo(() => {
    const mapa: Record<string, C> = {}
    for (const c of campos) {
      const nombre = campoNombreDe(campos, c)
      if (nombre) mapa[c.name] = nombre
    }
    return mapa
  }, [campos])

  const fijar = (c: C) => (valor: Valor) => setV((antes) => ({ ...antes, [c.name]: valor }))

  const elegirArchivo = (c: C) => (nombre: string, contenido: string) =>
    setV((antes) => ({ ...antes, [c.name]: contenido, [nombreDe[c.name].name]: nombre }))

  const enviar = (e: React.FormEvent) => {
    e.preventDefault()
    const params: Record<string, unknown> = {}
    for (const c of campos) {
      // Lo que no se ve, no se manda: el servidor descarta lo escondido y ademas
      // avisa de ello, asi que mandarlo solo genera ruido.
      if (!visible(c, v)) continue
      const x = v[c.name]
      if (x === '' || x === undefined || x === null) continue
      params[c.name] = c.type === 'number' ? Number(x) : x
    }
    onSubmit(params)
  }

  return (
    <form className="form" onSubmit={enviar}>
      <div className="grid">
        {campos
          .filter((c) => visible(c, v))
          .map((c) => (
            <Campo
              key={c.name}
              c={c}
              valor={v[c.name]}
              requerido={obligatorio(c, v)}
              previo={initial?.[c.name]}
              alCambiar={fijar(c)}
              alElegirArchivo={nombreDe[c.name] ? elegirArchivo(c) : undefined}
            />
          ))}
      </div>
      <div className="acciones">
        <button className="btn primary" disabled={ejecutando}>
          {ejecutando ? 'Ejecutando…' : 'Ejecutar diagnóstico'}
        </button>
        {ejecutando && (
          <button type="button" className="btn" onClick={onCancel}>
            Cancelar
          </button>
        )}
      </div>
    </form>
  )
}