/**
 * metricas.js — Métricas estilo Prometheus.
 *
 * MODULO DE OBSERVABILIDAD. Expone contadores y gauges en formato Prometheus
 * para ser raspados por un servidor Prometheus.
 *
 * @module server/metricas
 */

'use strict';

/**
 * Clase simple para métricas estilo Prometheus.
 * No usa librerías externas para mantener las dependencias mínimas.
 */
class Metricas {
  constructor() {
    /** @type {Map<string, number>} */
    this.contadores = new Map();
    /** @type {Map<string, number>} */
    this.gauges = new Map();
    /** @type {Map<string, number[]>} */
    this.histogramas = new Map();

    // Métricas base del sistema
    this.incrementar('netlab_info', { version: '1.0.0' });
  }

  /**
   * Incrementa un contador.
   * @param {string} nombre
   * @param {object} [etiquetas={}]
   * @param {number} [valor=1]
   */
  incrementar(nombre, etiquetas = {}, valor = 1) {
    const clave = this._clave(nombre, etiquetas);
    this.contadores.set(clave, (this.contadores.get(clave) || 0) + valor);
  }

  /**
   * Establece un gauge (valor que puede subir y bajar).
   * @param {string} nombre
   * @param {object} [etiquetas={}]
   * @param {number} valor
   */
  gauge(nombre, etiquetas = {}, valor) {
    const clave = this._clave(nombre, etiquetas);
    this.gauges.set(clave, valor);
  }

  /**
   * Observa un valor en un histograma.
   * @param {string} nombre
   * @param {object} [etiquetas={}]
   * @param {number} valor
   */
  observar(nombre, etiquetas = {}, valor) {
    const clave = this._clave(nombre, etiquetas);
    const arr = this.histogramas.get(clave) || [];
    arr.push(valor);
    // Mantener solo los últimos 1000 valores para no crecer indefinidamente
    if (arr.length > 1000) arr.shift();
    this.histogramas.set(clave, arr);
  }

  /**
   * Genera la clave única para nombre + etiquetas.
   * @param {string} nombre
   * @param {object} etiquetas
   * @returns {string}
   */
  _clave(nombre, etiquetas) {
    const etiquetasStr = Object.keys(etiquetas)
      .sort()
      .map(k => `${k}="${etiquetas[k]}"`)
      .join(',');
    return etiquetasStr ? `${nombre}{${etiquetasStr}}` : nombre;
  }

  /**
   * Genera la salida en formato Prometheus.
   * @returns {string}
   */
  generar() {
    const lineas = [];

    // Contadores
    for (const [clave, valor] of this.contadores) {
      lineas.push(`# TYPE ${clave.split('{')[0]} counter`);
      lineas.push(`${clave} ${valor}`);
    }

    // Gauges
    for (const [clave, valor] of this.gauges) {
      lineas.push(`# TYPE ${clave.split('{')[0]} gauge`);
      lineas.push(`${clave} ${valor}`);
    }

    // Histogramas (summary simple: count, sum, buckets)
    for (const [clave, valores] of this.histogramas) {
      const nombre = clave.split('{')[0];
      if (valores.length === 0) continue;

      const suma = valores.reduce((a, b) => a + b, 0);
      const cuenta = valores.length;
      const ordenados = [...valores].sort((a, b) => a - b);

      lineas.push(`# TYPE ${nombre} summary`);
      lineas.push(`${nombre}_count ${cuenta}`);
      lineas.push(`${nombre}_sum ${suma}`);

      // Percentiles básicos
      const p50 = ordenados[Math.floor(cuenta * 0.5)];
      const p90 = ordenados[Math.floor(cuenta * 0.9)];
      const p99 = ordenados[Math.floor(cuenta * 0.99)];
      lineas.push(`${nombre}{quantile="0.5"} ${p50}`);
      lineas.push(`${nombre}{quantile="0.9"} ${p90}`);
      lineas.push(`${nombre}{quantile="0.99"} ${p99}`);
    }

    return lineas.join('\n') + '\n';
  }

  /**
   * Obtiene el contenido tipo para la respuesta HTTP.
   * @returns {string}
   */
  getContentType() {
    return 'text/plain; version=0.0.4; charset=utf-8';
  }
}

let instancia = null;

/**
 * Instancia singleton de métricas.
 * @param {object} [opciones]
 * @returns {Metricas}
 */
function obtenerMetricas(opciones = {}) {
  if (!instancia) instancia = new Metricas(opciones);
  return instancia;
}

module.exports = { Metricas, obtenerMetricas };