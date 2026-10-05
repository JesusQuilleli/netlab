/**
 * tabla-modelo.ts — Lectura del contrato de tabla, sin DOM.
 *
 * MÓDULO DE CONVENCIÓN. `core/result.js` define cómo es una tabla: `columns` es
 * un array de textos y `rows` un array de filas, donde cada celda ocupa la
 * posición de su columna. Una celda puede ser un valor simple o un objeto
 * `{ valor, tone }`, que es lo que permite pintar "2 encontrados" en verde sin
 * que el dato deje de ser un dato.
 *
 *   columns: ['Tipo', 'Valor', 'TTL', 'Resultado']
 *   rows:    [['A', '1.2.3.4', '21', { valor: '2 encontrados', tone: 'ok' }]]
 *
 * Este módulo es el único sitio donde se interpreta ese contrato. `Informe.tsx`
 * solo pinta lo que aquí sale, y los tests comprueban este archivo en vez de
 * necesitar un navegador.
 *
 * POR QUÉ EXISTE ESTE ARCHIVO
 *   El renderer de la web implementó durante un tiempo otro contrato (columnas
 *   como objetos con `label`/`key` y filas indexadas por clave). Con el
 *   contrato real, `col.label` era `undefined` y `fila[col.key]` también, así
 *   que la tabla salía con las cabeceras en blanco y todas las celdas a «—».
 *   Los siete formatos de `src/formats/` sí lo leían bien, de ahí que el
 *   informe PDF tuviera los registros y la página no.
 *
 *   Los tests de `test/formats.test.js` ya fijaban el contrato de strings, pero
 *   no había ninguno del lado del navegador: el único consumidor sin verificar
 *   es el que rompió.
 */

/** Tonos que tienen color propio. Cualquier otro se pinta como texto normal. */
const TONOS = new Set<string>(['ok', 'warn', 'bad'])

export type Tono = 'ok' | 'warn' | 'bad' | null

/** Celda ya normalizada: texto y tono listos para pintar. */
export type CeldaModelo = { texto: string; tone: Tono }

/** Par clave/valor ya normalizado. */
export type ParModelo = { label: string; value: string; tone: Tono }

export type ModeloTabla = {
  columnas: { texto: string }[]
  filas: CeldaModelo[][]
  anchos: number[] | null
  columnasNum: number
}

/**
 * Forma minima que este modulo necesita de una seccion. Acepta de mas a proposito
 * (indice abierto): aqui solo se leen `columns`, `rows`, `anchoColumnas` e
 * `items`, y las secciones reales llegan con `kind`, `title`, `tone` y demas.
 */
type Fuente = { columns?: unknown; rows?: unknown; anchoColumnas?: unknown; items?: unknown; [k: string]: unknown }

/**
 * Devuelve el texto de una celda, sea simple u objeto.
 */
export function textoCelda(celda: unknown): string {
  if (celda === null || celda === undefined) return '—'
  if (typeof celda === 'boolean') return celda ? 'sí' : 'no'
  if (typeof celda === 'object') {
    if (Array.isArray(celda)) return celda.map(textoCelda).join(', ')
    return textoCelda((celda as { valor?: unknown }).valor)
  }
  return String(celda)
}

/**
 * Devuelve el tono de una celda, o `null` si no tiene.
 *
 * El tono se filtra contra `TONOS` a proposito: un `tone` inventado por una
 * herramienta se queda en `null` en lugar de acabar siendo un atributo `bg-*`
 * que no existe en la hoja de estilos.
 */
export function tonoCelda(celda: unknown): Tono {
  if (!celda || typeof celda !== 'object' || Array.isArray(celda)) return null
  const tone = (celda as { tone?: unknown }).tone
  return typeof tone === 'string' && TONOS.has(tone) ? (tone as Tono) : null
}

/**
 * Normaliza una fila a la longitud de las columnas.
 *
 * Una fila más corta que las columnas no es un error de la herramienta: pasa
 * cuando un campo opcional no llegó. Rellenar con celdas vacías deja la tabla
 * alineada en vez de descuadrarla en la última columna.
 */
export function celdasDeFila(fila: unknown, nColumnas: number): CeldaModelo[] {
  const bruto = Array.isArray(fila) ? fila : [fila]
  const celdas: CeldaModelo[] = []
  for (let i = 0; i < nColumnas; i += 1) {
    const celda = bruto[i]
    celdas.push({ texto: textoCelda(celda), tone: tonoCelda(celda) })
  }
  return celdas
}

/**
 * Convierte una sección de tabla en algo que se pueda pintar.
 */
export function modeloTabla(seccion: Fuente): ModeloTabla {
  const columnas = Array.isArray(seccion?.columns) ? (seccion.columns as unknown[]) : []
  const crudas = Array.isArray(seccion?.rows) ? (seccion.rows as unknown[]) : []

  // Si una fila trae más celdas que columnas declaradas, esas celdas se
  // perderían al recortar a `nColumnas`. Se cuelan como columnas extra en vez de
  // desaparecer sin aviso.
  const maximo = crudas.reduce<number>((mayor, fila) => {
    const largo = Array.isArray(fila) ? fila.length : fila === undefined ? 0 : 1
    return Math.max(mayor, largo)
  }, columnas.length)

  const textosColumna: string[] = []
  for (let i = 0; i < maximo; i += 1) {
    textosColumna.push(columnas[i] === undefined ? '' : textoCelda(columnas[i]))
  }

  return {
    columnas: textosColumna.map((texto) => ({ texto })),
    filas: crudas.map((fila) => celdasDeFila(fila, maximo)),
    anchos: Array.isArray(seccion?.anchoColumnas) ? (seccion.anchoColumnas as number[]) : null,
    columnasNum: maximo
  }
}

/**
 * Lee los pares de una sección `kind: 'kv'`.
 *
 * El contrato real de `items` es una lista de tuplas `[etiqueta, valor]`, donde
 * el valor puede ser un escalar o un objeto `{ valor, tone }`, y el tono puede
 * venir también como tercer elemento de la tupla:
 *
 *   [['Entrada original', '10.0.0.0/24'], ['Ámbito', 'Privada', 'warn']]
 *
 * Los siete formatos de `src/formats/` leen justo esa forma (`for (const [k, v]
 * of s.items)`). El renderer de la web la leía como `{ label, value }`, así que
 * `item.label` era `undefined` y todas las filas salían con la clave en blanco y
 * el valor a «—». Igual que pasó con las tablas, era el único consumidor que no
 * seguía el contrato.
 */
export function paresDe(seccion: Fuente): ParModelo[] {
  const items = Array.isArray(seccion?.items) ? (seccion.items as unknown[]) : []
  const salida: ParModelo[] = []

  for (const item of items) {
    if (item === null || item === undefined) continue

    let label: unknown = ''
    let crudo: unknown = item
    let tone: string | null = null

    if (Array.isArray(item)) {
      label = item[0]
      crudo = item[1]
      // El tono va en el objeto valor o, si el valor es simple, en el tercer
      // elemento. Los formatos solo miran el objeto, de modo que se admite
      // también el tercer elemento para no perder el color.
      tone = (typeof item[2] === 'string' ? item[2] : null) || null
    } else if (typeof item === 'object') {
      const o = item as { label?: unknown; key?: unknown; value?: unknown; tone?: unknown }
      label = o.label ?? o.key ?? ''
      crudo = o.value
      tone = (typeof o.tone === 'string' ? o.tone : null) || null
    }

    if (crudo && typeof crudo === 'object' && !Array.isArray(crudo)) {
      const v = crudo as { tone?: unknown; valor?: unknown }
      tone = (typeof v.tone === 'string' ? v.tone : tone) || tone
      crudo = v.valor
    }

    salida.push({
      label: textoCelda(label),
      value: crudo === null || crudo === undefined ? '' : textoCelda(crudo),
      tone: TONOS.has(tone as string) ? (tone as Tono) : null
    })
  }

  return salida
}

export { TONOS }