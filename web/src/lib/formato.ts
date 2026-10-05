export const fecha = (s: string) => new Date(s).toLocaleString('es', { dateStyle: 'medium', timeStyle: 'medium' })
export const bytes = (n: number) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`
export const duracion = (ms: number) => ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(2)} s`
export const STATUS = { pass: ['ok', 'Correcto', '✓'], warn: ['warn', 'Con observaciones', '!'], fail: ['bad', 'Con fallos', '✕'], error: ['bad', 'Error', '⚠'] } as const
