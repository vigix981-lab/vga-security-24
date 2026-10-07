/**
 * lazy-cdn.js — Carga bajo demanda de librerías CDN pesadas.
 * 
 * En vez de bloquear el <head> con scripts de ~1.5 MB que el usuario
 * no necesita hasta hacer clic en "Exportar" o abrir el mapa, los
 * cargamos recién cuando se usan. Si ya están cargados, la promesa
 * se resuelve al instante.
 *
 * Compatible con CSP (SRI), no rompe nada existente.
 */
(function () {
  const cache = {};

  /**
   * Carga un script CDN bajo demanda con SRI (integrity).
   * Devuelve una Promise que se resuelve cuando el script terminó de cargar.
   * Si el script ya se cargó antes, resuelve de una.
   *
   * @param {string} id      — identificador único (ej: 'xlsx')
   * @param {string} src     — URL del CDN
   * @param {string} integrity — hash SRI sha384/sha512
   * @param {string} [crossorigin='anonymous']
   * @returns {Promise<void>}
   */
  function cargarCDN(id, src, integrity, crossorigin) {
    if (cache[id]) return cache[id];
    if (document.querySelector('script[data-lazy-id="' + id + '"]')) {
      return Promise.resolve();
    }
    cache[id] = new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = src;
      s.setAttribute('data-lazy-id', id);
      if (integrity) {
        s.integrity = integrity;
        s.crossOrigin = crossorigin || 'anonymous';
      }
      s.referrerPolicy = 'no-referrer';
      s.onload = function () { resolve(); };
      s.onerror = function () {
        delete cache[id];
        reject(new Error('Error cargando CDN: ' + id + ' (' + src + ')'));
      };
      document.head.appendChild(s);
    });
    return cache[id];
  }

  /**
   * Carga una hoja de estilos CDN bajo demanda.
   */
  function cargarCSS(id, href, integrity, crossorigin) {
    if (document.querySelector('link[data-lazy-id="' + id + '"]')) {
      return Promise.resolve();
    }
    return new Promise(function (resolve, reject) {
      var l = document.createElement('link');
      l.rel = 'stylesheet';
      l.href = href;
      l.setAttribute('data-lazy-id', id);
      if (integrity) {
        l.integrity = integrity;
        l.crossOrigin = crossorigin || 'anonymous';
      }
      l.referrerPolicy = 'no-referrer';
      l.onload = function () { resolve(); };
      l.onerror = function () { reject(new Error('Error cargando CSS: ' + id)); };
      document.head.appendChild(l);
    });
  }

  /**
   * Carga un lote de scripts CDN en orden secuencial.
   * Cada item: { id, src, integrity, crossorigin? }
   */
  function cargarLote(items) {
    return items.reduce(function (prom, item) {
      return prom.then(function () {
        return cargarCDN(item.id, item.src, item.integrity, item.crossorigin);
      });
    }, Promise.resolve());
  }

  window.cargarCDN = cargarCDN;
  window.cargarCSScdn = cargarCSS;
  window.cargarLoteCDN = cargarLote;
})();
