// plan-nav.js — Oculta en el menú de navegación compartido los enlaces de
// funciones que el plan contratado NO incluye (elementos con data-plan-funcion).
// Script clásico, autohospedado (sin CDN) y CSP-safe (sin inline, sin unsafe-*,
// solo addEventListener y clases ya horneadas en styles.css).
//
// IMPORTANTE (fail-closed VISUAL): en el HTML los enlaces opcionales vienen con
// la clase `hidden` por defecto. Este script SOLO los MUESTRA cuando logra leer
// /config/plan (con el usuario autenticado) y confirma que la función está
// incluida. Así, antes del login —cuando aún no hay token y no se puede leer el
// plan— el enlace permanece oculto, que es justo lo deseado: no mostrar nada que
// el plan no habilite.
//
// Las Reglas de Firebase dan config/plan .read = (auth != null); por eso basta un
// usuario autenticado (vigilador/supervisor/admin) para leerlo. Esta capa es
// puramente VISUAL y ACOMPAÑA al candado DURO de las Reglas (que ya rechazan la
// escritura si el plan no incluye la función).
(function () {
  'use strict';

  var URL_BASE = 'https://mercosur-seguridad-default-rtdb.firebaseio.com';

  // Getters de token que exponen los distintos módulos de cada página.
  var GETTERS = [
    'obtenerTokenRondas',
    'obtenerTokenVigilador',
    'obtenerTokenSupervisor'
  ];

  var aplicado = false;
  var timer = null;

  function aplicar(funciones) {
    try {
      var marcados = document.querySelectorAll('nav [data-plan-funcion]');
      for (var i = 0; i < marcados.length; i++) {
        var el = marcados[i];
        var f = el.getAttribute('data-plan-funcion');
        // Muestra solo si la función está habilitada; si no, la deja oculta.
        el.classList.toggle('hidden', !funciones[f]);
      }
    } catch (_) {}
  }

  function obtenerToken() {
    // Intenta cada getter disponible y devuelve el primer token válido.
    var cadena = Promise.resolve(null);
    GETTERS.forEach(function (nombre) {
      cadena = cadena.then(function (prev) {
        if (prev) return prev;
        var g = window[nombre];
        if (typeof g !== 'function') return null;
        return Promise.resolve().then(g).catch(function () { return null; });
      });
    });
    return cadena;
  }

  function intentar() {
    if (aplicado) return;
    obtenerToken().then(function (token) {
      if (!token) return; // Sin sesión aún: la nav sigue oculta (fail-closed).
      var url = URL_BASE + '/config/plan.json?ts=' + Date.now() +
                '&auth=' + encodeURIComponent(token);
      return fetch(url, { cache: 'no-store' }).then(function (res) {
        if (!res.ok) return; // No se pudo leer: reintentamos más tarde.
        return res.json().then(function (p) {
          var funciones = (p && p.funciones && typeof p.funciones === 'object')
            ? p.funciones
            : {}; // Plan leído sin funciones: todo opcional queda oculto.
          aplicar(funciones);
          aplicado = true;
          if (timer) { clearInterval(timer); timer = null; }
        });
      });
    }).catch(function () {});
  }

  // Reintenta periódicamente para cubrir el caso de login POSTERIOR a la carga
  // de la página (la sesión Firebase aparece tras loguearse). Se detiene al leer
  // el plan una vez, y como tope de seguridad deja de reintentar a los 10 min.
  timer = setInterval(intentar, 1500);
  setTimeout(function () { if (timer) { clearInterval(timer); timer = null; } }, 600000);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', intentar);
  } else {
    intentar();
  }
})();
