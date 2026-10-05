/**
 * tabla-modelo.test.ts — El contrato de tabla, sin navegador.
 *
 * MÓDULO DE CONVENCIÓN. Estos tests fijan el único punto donde se interpreta
 * como tabla un `Resultado`: `lib/tabla-modelo.ts`. `Informe.tsx` solo pinta lo
 * que este módulo devuelve.
 *
 * El caso que motivó el archivo: el renderer leía las columnas como si fueran
 * objetos con `label`/`key`, cuando el contrato de `core/result.js` son strings
 * y filas por posición. Con el contrato real, `col.label` era `undefined` y la
 * tabla salía vacía en la página y correcta en los siete formatos de informe.
 * Las 12 tablas de las 4 herramientas estaban afectadas.
 *
 * Es la traducción de `test/tabla-modelo.test.js`, caso por caso.
 */

import { describe, expect, test } from 'vitest'
import { modeloTabla, celdasDeFila, textoCelda, tonoCelda, paresDe } from './tabla-modelo'

describe('cabeceras y filas', () => {
  test('las cabeceras salen en su orden y con su texto', () => {
    const m = modeloTabla({
      kind: 'table',
      columns: ['Tipo', 'Valor', 'TTL', 'Resultado'],
      rows: [['A', '1.2.3.4', '21', '1 encontrado']]
    })
    expect(m.columnas.map((c) => c.texto)).toEqual(['Tipo', 'Valor', 'TTL', 'Resultado'])
  })

  test('las celdas se leen por posicion, no por clave', () => {
    const m = modeloTabla({
      kind: 'table',
      columns: ['Tipo', 'Valor'],
      rows: [
        ['A', '172.66.147.243'],
        ['AAAA', '2606:4700::1111']
      ]
    })
    expect(m.filas[0]).toEqual([
      { texto: 'A', tone: null },
      { texto: '172.66.147.243', tone: null }
    ])
    expect(m.filas[1]).toEqual([
      { texto: 'AAAA', tone: null },
      { texto: '2606:4700::1111', tone: null }
    ])
  })

  test('una tabla sin filas conserva las cabeceras', () => {
    const m = modeloTabla({ kind: 'table', columns: ['Lista', 'Resultado'], rows: [] })
    expect(m.columnas.length).toBe(2)
    expect(m.filas).toEqual([])
  })

  test('una seccion sin columns no rompe y no inventa columnas', () => {
    const m = modeloTabla({ kind: 'table', rows: [] })
    expect(m.columnasNum).toBe(0)
    expect(m.columnas).toEqual([])
    expect(m.filas).toEqual([])
  })

  test('sin rows tampoco rompe', () => {
    const m = modeloTabla({ kind: 'table', columns: ['a'] })
    expect(m.columnas).toEqual([{ texto: 'a' }])
    expect(m.filas).toEqual([])
  })
})

describe('desajuste entre filas y columnas', () => {
  test('una fila mas corta que las columnas se rellena, no se descuadra', () => {
    const m = modeloTabla({ kind: 'table', columns: ['Tipo', 'Valor', 'TTL'], rows: [['A', '1.2.3.4']] })
    expect(m.filas[0].length).toBe(3)
    expect(m.filas[0][2]).toEqual({ texto: '—', tone: null })
  })

  test('una fila mas larga que las columnas no pierde celdas', () => {
    const m = modeloTabla({
      kind: 'table',
      columns: ['Tipo', 'Valor'],
      rows: [['A', '1.2.3.4', 'sobra1', 'sobra2']]
    })
    expect(m.columnasNum).toBe(4)
    expect(m.filas[0].length).toBe(4)
    expect(m.filas[0][3].texto).toBe('sobra2')
    // La columna que no se declaro no se inventa un titulo: queda vacia.
    expect(m.columnas[3].texto).toBe('')
  })

  test('una fila que no es array se trata como una celda unica', () => {
    const m = modeloTabla({ kind: 'table', columns: ['a', 'b'], rows: ['suelto'] })
    expect(m.filas[0]).toEqual([
      { texto: 'suelto', tone: null },
      { texto: '—', tone: null }
    ])
  })

  test('los anchos solo se devuelven si el contrato los trae', () => {
    const conAnchos = modeloTabla({
      kind: 'table',
      columns: ['Red', 'Prefijo'],
      rows: [['10.0.0.0/8', '8']],
      anchoColumnas: [70, 30]
    })
    const sinAnchos = modeloTabla({ kind: 'table', columns: ['a'], rows: [['x']] })
    expect(conAnchos.anchos).toEqual([70, 30])
    expect(sinAnchos.anchos).toBeNull()
  })
})

describe('tonos de celda', () => {
  test('una celda {valor, tone} pinta el valor y conserva el tono', () => {
    const m = modeloTabla({
      kind: 'table',
      columns: ['Tipo', 'Resultado'],
      rows: [['A', { valor: '2 encontrados', tone: 'ok' }]]
    })
    expect(m.filas[0][1]).toEqual({ texto: '2 encontrados', tone: 'ok' })
  })

  test('cada tono del contrato llega a su celda', () => {
    const m = modeloTabla({
      kind: 'table',
      columns: ['a', 'b', 'c'],
      rows: [[{ valor: 'ok', tone: 'ok' }, { valor: 'warn', tone: 'warn' }, { valor: 'bad', tone: 'bad' }]]
    })
    expect(m.filas[0].map((c) => c.tone)).toEqual(['ok', 'warn', 'bad'])
  })

  test('un tone que no existe se ignora en vez de volverse atributo', () => {
    const m = modeloTabla({ kind: 'table', columns: ['a'], rows: [[{ valor: 'x', tone: 'inventado' }]] })
    expect(m.filas[0][0].tone).toBeNull()
    expect(m.filas[0][0].texto).toBe('x')
  })

  test('tonoCelda ignora valores que no son celdas con tono', () => {
    expect(tonoCelda('texto')).toBeNull()
    expect(tonoCelda(null)).toBeNull()
    expect(tonoCelda(['ok'])).toBeNull()
    expect(tonoCelda({ valor: 'x' })).toBeNull()
  })
})

describe('texto de celda', () => {
  test('un array como celda se une con comas', () => {
    expect(textoCelda(['mx1.example.com', 'mx2.example.com'])).toBe('mx1.example.com, mx2.example.com')
  })

  test('los booleanos se leen en castellano', () => {
    expect(textoCelda(true)).toBe('sí')
    expect(textoCelda(false)).toBe('no')
  })

  test('null y undefined salen como guion, no como "null"', () => {
    expect(textoCelda(null)).toBe('—')
    expect(textoCelda(undefined)).toBe('—')
  })

  test('un objeto sin clave valor se muestra como guion, no como [object Object]', () => {
    expect(textoCelda({})).toBe('—')
    expect(textoCelda({ tone: 'ok' })).toBe('—')
  })

  test('celdasDeFila recorta y rellena a la longitud pedida', () => {
    expect(celdasDeFila(['a', 'b'], 1)).toEqual([{ texto: 'a', tone: null }])
    expect(celdasDeFila(['a'], 2)).toEqual([
      { texto: 'a', tone: null },
      { texto: '—', tone: null }
    ])
  })
})

describe('pares clave/valor', () => {
  test('paresDe lee tuplas [etiqueta, valor], que es el contrato real', () => {
    const items = paresDe({
      items: [
        ['Entrada original', '10.0.0.0/24'],
        ['Prefijo', '/24'],
        ['Direcciones totales', 256]
      ]
    })
    expect(items).toEqual([
      { label: 'Entrada original', value: '10.0.0.0/24', tone: null },
      { label: 'Prefijo', value: '/24', tone: null },
      { label: 'Direcciones totales', value: '256', tone: null }
    ])
  })

  test('paresDe respeta el tono en el tercer elemento y en {valor, tone}', () => {
    const items = paresDe({
      items: [
        ['Direcciones utilizables', 254, 'ok'],
        ['Ámbito', { valor: 'Privada RFC 1918', tone: 'warn' }]
      ]
    })
    expect(items).toEqual([
      { label: 'Direcciones utilizables', value: '254', tone: 'ok' },
      { label: 'Ámbito', value: 'Privada RFC 1918', tone: 'warn' }
    ])
  })

  test('paresDe sigue entendiendo la forma {label, value} y los escalares', () => {
    const items = paresDe({ items: [{ label: 'Titular', value: 'GOGL' }, 'Suelto'] })
    expect(items).toEqual([
      { label: 'Titular', value: 'GOGL', tone: null },
      { label: '', value: 'Suelto', tone: null }
    ])
  })

  test('paresDe ignora tonos que no existen y deja el valor limpio', () => {
    const items = paresDe({ items: [['X', 'y', 'inventado'], ['Z', { valor: null, tone: 'bad' }]] })
    expect(items).toEqual([
      { label: 'X', value: 'y', tone: null },
      { label: 'Z', value: '', tone: 'bad' }
    ])
  })
})