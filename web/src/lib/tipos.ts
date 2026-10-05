/**
 * tipos.ts — El contrato que habla el backend.
 *
 * Este archivo es la traducción del servidor, no una lista de tipos inventados.
 * Cada forma de aqui sale de `GET /api/herramientas` y de `core/result.js`, y
 * hay tests que la comprueban contra el fixture real (`src/test/fixture.ts`).
 *
 * El detalle que mas caro salio: las opciones de un `select` llegan con las
 * claves `value` y `label`, en ingles y no en castellano. Leerlas como
 * `{valor, etiqueta}` deja el desplegable sin una sola opcion visible, y como
 * el campo no llega, el servidor aplica su valor por defecto en silencio. El
 * `seguridad` de smtp-validator (STARTTLS, TLS directo o texto plano) se
 * quedaba asi sin que nada fallara.
 */

/** Tonos semanticos. Se usan igual en el informe, en las tablas y en los bordes. */
export type Tone = 'ok' | 'warn' | 'bad' | 'neutral'

/** Veredicto de una ejecucion. */
export type Status = 'pass' | 'warn' | 'fail' | 'error'

/** Opcion de un desplegable. El servidor las llama `value` y `label`. */
export type Opcion = { value: string; label: string }

/**
 * Tipos de campo que el backend emite.
 *
 * `lista-requisitos` no es un descuido: `subnet-analyzer` lo usa para el reparto
 * VLSM, y es un area de texto con una linea por tramo en formato "Nombre:hosts".
 * No es un `<input>`.
 */
export type TipoCampo = 'text' | 'number' | 'password' | 'select' | 'checkbox' | 'file' | 'lista-requisitos'

export type Campo = {
  name: string
  label: string
  type: TipoCampo
  /** Obligatorio siempre. */
  required?: boolean
  /** Nombre de otro campo: mientras ese no este activo, este no es obligatorio. */
  requiredUnless?: string
  /** Nombre de una casilla: si no esta activa, el campo no se muestra ni se acepta. */
  shownWhen?: string
  placeholder?: string
  help?: string
  default?: unknown
  min?: number
  max?: number
  /** Sufijo de la etiqueta, como "(ms)". El servidor lo usa en los tiempos de espera. */
  unit?: string
  options?: Opcion[]
  accept?: string
  maxBytes?: number
}

export type Herramienta = {
  id: string
  titulo: string
  descripcion: string
  icon: string
  /** true si la herramienta funciona sin salida a internet. */
  sinRed: boolean
  campos: Campo[]
}

/** Una celda puede ser un valor simple o un objeto `{ valor, tone }`. */
export type Celda = { valor: string | number; tone?: Tone }

/** Una seccion es tabla, pares, codigo, texto, lista o medidor. */
export type SeccionKind = 'table' | 'kv' | 'code' | 'text' | 'list' | 'meter'

export type Seccion = {
  id?: string | null
  title: string
  description?: string | null
  kind: SeccionKind
  tone?: Tone
  /** tabla: anchos relativos en porcentaje, para repartir el ancho de las columnas. */
  anchoColumnas?: number[] | null
  /** tabla: `columns` son textos y `rows` una fila por registro. */
  columns?: string[] | null
  rows?: unknown[] | null
  /** kv: tuplas `[etiqueta, valor]` o `[etiqueta, valor, tono]`. */
  items?: unknown[] | null
  /** code y text: el texto entero. */
  value?: string | number | null
}

export type Resultado = {
  schema: number
  tool: string
  toolTitle: string
  status: Status
  /** Titular del veredicto. Ausente en resultados anteriores al esquema 2. */
  headline?: string | null
  target: string
  params: Record<string, unknown>
  summary: { label: string; value: string; tone: Tone }[]
  sections: Seccion[]
  findings: {
    severity: 'info' | 'warn' | 'error'
    title: string
    detail: string
    /**
     * Lo que hay que hacer. El backend lo llama `recommendation` y es el mismo
     * nombre que usan los cinco formatos de exportación; aqui se llamaba
     * `remediation` y por eso la linea no salia nunca.
     */
    recommendation?: string | null
  }[]
  logs: { level: string; message: string; at?: string }[]
  startedAt: string
  durationMs: number
  error: { code: string; message: string; remediation?: string } | null
}

export type RunResp = {
  id: string
  duplicado: boolean
  avisos: string[]
  result: Resultado
  /** Solo viene en `GET /api/run/:id`: los parametros tal como se guardaron. */
  registro?: { params?: Record<string, unknown> }
  /** Enlace público compartido (si se creó con POST /api/compartir). */
  shareUrl?: string | null
  /** Expiración del enlace compartido. */
  expiraEn?: string | null
}

export type HistorialItem = {
  id: string
  tool: string
  target: string
  status: Status
  params: Record<string, unknown>
  createdAt: string
  durationMs: number
  owner: string
}

export type Sesion = {
  autenticado: boolean
  local: boolean
  usuario?: string
  role?: 'admin' | 'user' | null
  modoTextoPlano?: boolean
  csrf: string
  herramientas?: number
  avisos: string[]
}

/** Respuesta paginada del historial. */
export type HistorialPagina = {
  items: HistorialItem[]
  total: number
  limite: number
  desde: number
}