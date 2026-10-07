/* =========================================================================
   LICENCIA.JS - Control de licencia de prueba (vencimiento por fecha)
   -------------------------------------------------------------------------
   >>> UNICO LUGAR QUE TENES QUE TOCAR PARA CAMBIAR LA PRUEBA <<<
   Cambia SOLO los valores de abajo. El resto es la logica (no tocar).
   ========================================================================= */

window.LICENCIA = {
  // Nombre del cliente / de esta copia. Aparece en el cartel de vencimiento.
  cliente: "Demo Asistencia",

  // Nombre del servicio/marca que aparece en los avisos (ej: "vga security 24").
  marca: "vga security 24",

  // Fecha y hora EXACTA en que vence la prueba (hora de Argentina, -03:00).
  // Formato:  "AAAA-MM-DDTHH:MM:SS-03:00"
  // Para dar mas dias, solo cambia la fecha (ej: "2026-11-30T23:59:59-03:00").
  vence: "2026-10-16T23:59:59-03:00",

  // Que hacer cuando vence:
  //   "bloquear"     -> tapa la pantalla, no se puede usar nada (recomendado para demos).
  //   "solo-lectura" -> deja ver, pero DESHABILITA todos los botones (no se puede fichar/guardar).
  modo: "bloquear",

  // Cuantos dias antes del vencimiento avisa (contador en alerta + aviso emergente).
  avisarDiasAntes: 3,

  // Mostrar el contador siempre visible arriba (true/false).
  mostrarContador: true,

  // Mostrar el aviso emergente (ventanita) cuando falta poco (true/false).
  avisoEmergente: true,

  // TABLA DE ESTADOS DE COLOR segun los dias que faltan para vencer.
  // Se recorre de arriba hacia abajo y se usa el PRIMER renglon que cumpla
  // "dias restantes <= hastaDias". El ultimo (hastaDias: null) es el resto.
  //   color = color del numero del contador | borde = color del borde de la barra
  estadosColor: [
    { hastaDias: 1,    etiqueta: "Critico (ultimo dia)", color: "#f87171", borde: "#7f1d1d" },
    { hastaDias: 3,    etiqueta: "Alerta (por vencer)",  color: "#fbbf24", borde: "#78350f" },
    { hastaDias: null, etiqueta: "Normal",               color: "#f8fafc", borde: "#334155" }
  ],

  // Guardar en el navegador un registro (log) de los eventos del aviso:
  // cuando se mostro y cuando se cerro (y con que boton). true/false.
  logs: true,
  // Cuantos eventos como maximo se conservan (los mas nuevos pisan a los viejos).
  logMax: 200
};

/* ========================= LOGICA (no editar) ============================ */
(function () {
  var L = window.LICENCIA || {};
  var venceMs = Date.parse(L.vence);
  if (!venceMs || isNaN(venceMs)) return; // Sin fecha valida: no hace nada.

  var MS_DIA = 86400000;
  var MARCA = L.marca || L.cliente || 'el proveedor';
  var bloqueado = false;

  // Desfase entre la hora del servidor y la del dispositivo (ms). Se fija con
  // el servidor para que el contador sea fiel aunque muevan el reloj a mano.
  var offsetServidorMs = 0;
  function ahora() { return Date.now() + offsetServidorMs; }
  function diasRestantes(t) { return Math.ceil((venceMs - t) / MS_DIA); }

  // Hora oficial del SERVIDOR (header Date de la respuesta HTTP). Resistente a
  // que cambien el reloj local. Si falla (sin conexion), devuelve null.
  function horaServidor() {
    return fetch(location.href, { method: 'HEAD', cache: 'no-store' })
      .then(function (r) {
        var d = r.headers.get('date');
        if (d) { var t = Date.parse(d); if (!isNaN(t)) return t; }
        return null;
      })
      .catch(function () { return null; });
  }

  function dos(n) { return (n < 10 ? '0' : '') + n; }
  function fechaLegible(ms) {
    var f = new Date(ms);
    return dos(f.getDate()) + '/' + dos(f.getMonth() + 1) + '/' + f.getFullYear() +
           ' ' + dos(f.getHours()) + ':' + dos(f.getMinutes());
  }
  function restanteTexto(ms) {
    if (ms < 0) ms = 0;
    var seg = Math.floor(ms / 1000);
    var d = Math.floor(seg / 86400); seg -= d * 86400;
    var h = Math.floor(seg / 3600);  seg -= h * 3600;
    var m = Math.floor(seg / 60);    seg -= m * 60;
    return d + 'd ' + dos(h) + ':' + dos(m) + ':' + dos(seg);
  }
  // Texto del aviso segun cuantos dias faltan.
  function textoAviso(dias) {
    var cab = (dias <= 1)
      ? 'Hoy vence tu licencia de prueba.'
      : ('Tu licencia de prueba vence en ' + dias + ' dias.');
    return cab + ' Para seguir utilizando los servicios de ' + MARCA +
           ', comunicate con nuestros representantes.';
  }

  // ===================== SISTEMA DE LOGS DEL AVISO =====================
  // Guarda en el navegador (localStorage) un registro de los eventos del aviso
  // de licencia: cuando se mostro y cuando se cerro (con la X o con "Entendido").
  // No se envia nada a ningun servidor; queda en el dispositivo. Para verlo o
  // vaciarlo desde la consola del navegador (F12):
  //    LicenciaLogs.ver()      -> muestra la tabla de eventos
  //    LicenciaLogs.exportar() -> devuelve el texto JSON para copiar/guardar
  //    LicenciaLogs.limpiar()  -> borra el registro
  var LOG_KEY = 'licenciaLogs';

  function leerLogs() {
    try { return JSON.parse(localStorage.getItem(LOG_KEY) || '[]'); }
    catch (_) { return []; }
  }
  function registrarLog(evento, extra) {
    if (L.logs === false) return;
    try {
      var lista = leerLogs();
      var reg = {
        fecha: new Date(ahora()).toISOString(),
        evento: evento,
        pagina: location.pathname.split('/').pop() || location.pathname,
        diasRestantes: diasRestantes(ahora())
      };
      if (extra) for (var k in extra) { if (extra.hasOwnProperty(k)) reg[k] = extra[k]; }
      lista.push(reg);
      var max = L.logMax || 200;
      if (lista.length > max) lista = lista.slice(lista.length - max);
      localStorage.setItem(LOG_KEY, JSON.stringify(lista));
      if (window.console && console.log) console.log('[Licencia][log]', reg);
    } catch (_) {}
  }

  // API publica para consultar los logs desde la consola del navegador.
  window.LicenciaLogs = {
    ver: function () {
      var lista = leerLogs();
      try { if (console.table) console.table(lista); else console.log(lista); } catch (_) {}
      return lista;
    },
    exportar: function () { return JSON.stringify(leerLogs(), null, 2); },
    limpiar: function () {
      try { localStorage.removeItem(LOG_KEY); } catch (_) {}
      return true;
    }
  };

  // ===================== CONTADOR SIEMPRE VISIBLE (ARRIBA) =====================
  var elContador = null, elReloj = null, tick = null;
  var paddingBodyPrevio = null;

  function crearContador() {
    if (!L.mostrarContador || document.getElementById('licenciaContador')) return;
    var box = document.createElement('div');
    box.id = 'licenciaContador';
    var s = box.style;
    // Barra fija centrada ARRIBA. Reserva su espacio (ver ajustarEspacio) para
    // no superponerse a la navegacion ni a ningun boton, tampoco al scrollear.
    s.position = 'fixed'; s.top = '0'; s.left = '50%';
    s.transform = 'translateX(-50%)';
    s.zIndex = '2147483645';
    s.display = 'flex'; s.alignItems = 'center'; s.gap = '10px';
    s.flexWrap = 'wrap'; s.justifyContent = 'center'; s.maxWidth = '100vw';
    s.background = 'rgba(15,23,42,0.97)';
    s.borderBottom = '1px solid #334155';
    s.borderRadius = '0 0 12px 12px';
    s.padding = '6px 16px';
    s.boxShadow = '0 4px 16px rgba(0,0,0,0.45)';
    s.font = '600 11px system-ui,-apple-system,"Segoe UI",Roboto,sans-serif';
    s.color = '#cbd5e1'; s.pointerEvents = 'none'; s.lineHeight = '1';

    var t1 = document.createElement('span');
    t1.textContent = 'VERSION DE PRUEBA';
    t1.style.fontSize = '9px'; t1.style.letterSpacing = '1px';
    t1.style.color = '#34d399'; t1.style.fontWeight = '700';

    var t2 = document.createElement('span');
    t2.textContent = 'Vence ' + fechaLegible(venceMs);
    t2.style.color = '#94a3b8';

    elReloj = document.createElement('span');
    elReloj.style.fontSize = '14px'; elReloj.style.fontWeight = '800';
    elReloj.style.color = '#f8fafc';
    elReloj.style.fontVariantNumeric = 'tabular-nums';

    box.appendChild(t1); box.appendChild(t2); box.appendChild(elReloj);
    (document.body || document.documentElement).appendChild(box);
    elContador = box;
    layoutResponsive();
    actualizarContador();
    ajustarEspacio();
    // Animacion suave de entrada: la barra baja desde arriba y aparece.
    s.opacity = '0';
    s.top = '-80px';
    s.transition = 'top .45s ease, opacity .45s ease';
    try {
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { s.opacity = '1'; s.top = '0'; });
      });
    } catch (_) { s.opacity = '1'; s.top = '0'; }
    // En pantallas chicas la altura puede cambiar al terminar de dibujarse
    // (wrap a 2 renglones, carga de fuentes). Reajustamos cuando el navegador
    // termina el layout y, por las dudas, un instante despues.
    try { requestAnimationFrame(ajustarEspacio); } catch (_) {}
    setTimeout(ajustarEspacio, 300);
    // Si cambia la altura de la barra (ej: pasa a 2 lineas), reajustamos solos.
    try {
      if (window.ResizeObserver) {
        var ro = new ResizeObserver(ajustarEspacio);
        ro.observe(box);
      }
    } catch (_) {}
  }

  // Adapta la barra al ancho de la pantalla: en celular ocupa todo el ancho
  // (texto mas compacto) y en pantallas grandes queda centrada tipo pastilla.
  function layoutResponsive() {
    if (!elContador) return;
    var s = elContador.style;
    var angosta = window.innerWidth < 560;
    if (angosta) {
      s.left = '0'; s.right = '0'; s.transform = 'none';
      s.maxWidth = '100%'; s.borderRadius = '0 0 10px 10px';
      s.padding = '5px 10px'; s.gap = '6px';
    } else {
      s.left = '50%'; s.right = 'auto'; s.transform = 'translateX(-50%)';
      s.maxWidth = '100vw'; s.borderRadius = '0 0 12px 12px';
      s.padding = '6px 16px'; s.gap = '10px';
    }
  }

  // Empuja el contenido hacia abajo tanto como mida la barra, para que NUNCA
  // tape la navegacion ni los botones (ni en reposo ni al hacer scroll).
  function ajustarEspacio() {
    if (!elContador || !document.body) return;
    if (paddingBodyPrevio === null) {
      paddingBodyPrevio = document.body.style.paddingTop || '';
    }
    var alto = elContador.getBoundingClientRect().height;
    document.body.style.paddingTop = (alto + 6) + 'px';
  }
  function restaurarEspacio() {
    if (document.body && paddingBodyPrevio !== null) {
      document.body.style.paddingTop = paddingBodyPrevio;
    }
  }

  // Elige el estado de color (de la tabla configurable) segun los dias restantes.
  var ESTADOS_DEF = [
    { hastaDias: 1,    color: '#f87171', borde: '#7f1d1d' },
    { hastaDias: 3,    color: '#fbbf24', borde: '#78350f' },
    { hastaDias: null, color: '#f8fafc', borde: '#334155' }
  ];
  function elegirEstado(d) {
    var tabla = (L.estadosColor && L.estadosColor.length) ? L.estadosColor : ESTADOS_DEF;
    for (var i = 0; i < tabla.length; i++) {
      var e = tabla[i];
      if (e.hastaDias == null || d <= e.hastaDias) return e;
    }
    return tabla[tabla.length - 1];
  }

  function actualizarContador() {
    var falta = venceMs - ahora();
    if (falta <= 0) {
      if (elReloj) elReloj.textContent = 'VENCIDA';
      ocultarContador();
      aplicarVencimiento();
      return;
    }
    if (elReloj) {
      elReloj.textContent = restanteTexto(falta);
      var est = elegirEstado(diasRestantes(ahora()));
      elReloj.style.color = est.color || '#f8fafc';
      if (elContador) elContador.style.borderBottomColor = est.borde || '#334155';
    }
  }

  function ocultarContador() {
    if (tick) { clearInterval(tick); tick = null; }
    if (elContador) { elContador.remove(); elContador = null; }
    restaurarEspacio();
  }

  // ===================== AVISO EMERGENTE (ventanita) =====================
  function mostrarAvisoEmergente(dias) {
    if (!L.avisoEmergente) return;
    if (document.getElementById('licenciaAviso')) return;
    // Mostrar una sola vez por sesion de pestana para no molestar en cada recarga.
    try {
      var clave = 'licenciaAvisoVisto_' + L.vence;
      if (sessionStorage.getItem(clave)) return;
      sessionStorage.setItem(clave, '1');
    } catch (_) {}

    var ov = document.createElement('div');
    ov.id = 'licenciaAviso';
    var s = ov.style;
    s.position = 'fixed'; s.top = '0'; s.left = '0'; s.right = '0'; s.bottom = '0';
    s.zIndex = '2147483646';
    s.display = 'flex'; s.alignItems = 'center'; s.justifyContent = 'center';
    s.padding = '24px'; s.background = 'rgba(2,6,23,0.75)';
    s.fontFamily = 'system-ui,-apple-system,"Segoe UI",Roboto,sans-serif';

    var card = document.createElement('div');
    var c = card.style;
    c.position = 'relative';
    c.maxWidth = '400px'; c.width = '100%'; c.textAlign = 'center';
    c.background = '#0f172a'; c.border = '1px solid #78350f';
    c.borderRadius = '18px'; c.padding = '28px 24px';
    c.boxShadow = '0 20px 60px rgba(0,0,0,0.6)'; c.color = '#e2e8f0';

    // Boton de cierre manual (X) arriba a la derecha.
    var cerrar = document.createElement('span');
    cerrar.textContent = '\u2715';
    var xs = cerrar.style;
    xs.position = 'absolute'; xs.top = '12px'; xs.right = '14px';
    xs.cursor = 'pointer'; xs.fontSize = '16px'; xs.fontWeight = '700';
    xs.color = '#94a3b8'; xs.lineHeight = '1'; xs.padding = '4px';
    cerrar.setAttribute('aria-label', 'Cerrar');
    cerrar.addEventListener('click', function () {
      registrarLog('aviso_cerrado', { metodo: 'x' });
      ov.remove();
    });

    var icono = document.createElement('div');
    icono.textContent = '\u23F3';
    icono.style.fontSize = '40px'; icono.style.marginBottom = '10px';

    var titulo = document.createElement('div');
    titulo.textContent = (dias <= 1) ? 'Tu licencia vence hoy' : 'Tu licencia esta por vencer';
    titulo.style.fontSize = '18px'; titulo.style.fontWeight = '700';
    titulo.style.color = '#fbbf24'; titulo.style.marginBottom = '10px';

    var txt = document.createElement('div');
    txt.textContent = textoAviso(dias);
    txt.style.fontSize = '14px'; txt.style.lineHeight = '1.5'; txt.style.color = '#cbd5e1';

    var btn = document.createElement('button');
    btn.textContent = 'Entendido';
    var bs = btn.style;
    bs.marginTop = '18px'; bs.padding = '10px 22px'; bs.border = 'none';
    bs.borderRadius = '10px'; bs.background = '#059669'; bs.color = '#fff';
    bs.fontWeight = '700'; bs.fontSize = '14px'; bs.cursor = 'pointer';
    btn.setAttribute('data-licencia-ok', '1'); // que no lo deshabilite el modo solo-lectura
    btn.addEventListener('click', function () {
      registrarLog('aviso_cerrado', { metodo: 'boton_entendido' });
      ov.remove();
    });

    card.appendChild(cerrar);
    card.appendChild(icono); card.appendChild(titulo);
    card.appendChild(txt); card.appendChild(btn);
    ov.appendChild(card);
    (document.body || document.documentElement).appendChild(ov);
    registrarLog('aviso_mostrado', { dias: dias });
  }

  // ---- Cartel de bloqueo (pantalla completa) ----
  function modoBloqueo() {
    if (document.getElementById('licenciaOverlay')) return;
    var ov = document.createElement('div');
    ov.id = 'licenciaOverlay';
    var s = ov.style;
    s.position = 'fixed'; s.top = '0'; s.left = '0'; s.right = '0'; s.bottom = '0';
    s.zIndex = '2147483647';
    s.display = 'flex'; s.alignItems = 'center'; s.justifyContent = 'center';
    s.padding = '24px'; s.background = 'rgba(2,6,23,0.98)';
    s.fontFamily = 'system-ui,-apple-system,"Segoe UI",Roboto,sans-serif';

    var card = document.createElement('div');
    var c = card.style;
    c.maxWidth = '420px'; c.width = '100%'; c.textAlign = 'center';
    c.background = '#0f172a'; c.border = '1px solid #334155';
    c.borderRadius = '18px'; c.padding = '32px 26px';
    c.boxShadow = '0 20px 60px rgba(0,0,0,0.6)'; c.color = '#e2e8f0';

    var icono = document.createElement('div');
    icono.textContent = '\u23F0';
    icono.style.fontSize = '44px'; icono.style.marginBottom = '12px';

    var titulo = document.createElement('div');
    titulo.textContent = 'Periodo de prueba finalizado';
    titulo.style.fontSize = '20px'; titulo.style.fontWeight = '700';
    titulo.style.color = '#f8fafc'; titulo.style.marginBottom = '8px';

    var sub = document.createElement('div');
    sub.textContent = L.cliente || '';
    sub.style.fontSize = '12px'; sub.style.letterSpacing = '1px';
    sub.style.textTransform = 'uppercase'; sub.style.color = '#34d399';
    sub.style.fontWeight = '700'; sub.style.marginBottom = '16px';

    var txt = document.createElement('div');
    txt.textContent = 'Para seguir utilizando los servicios de ' + MARCA +
                      ', comunicate con nuestros representantes.';
    txt.style.fontSize = '14px'; txt.style.lineHeight = '1.5'; txt.style.color = '#94a3b8';

    card.appendChild(icono); card.appendChild(titulo);
    card.appendChild(sub); card.appendChild(txt);
    ov.appendChild(card);
    (document.body || document.documentElement).appendChild(ov);

    document.documentElement.style.overflow = 'hidden';
    if (document.body) document.body.style.overflow = 'hidden';
  }

  // ---- Modo solo lectura: banner fijo + deshabilitar todos los botones ----
  function modoSoloLectura() {
    bannerFijo('\u26A0 Prueba vencida. Para seguir utilizando los servicios de ' +
               MARCA + ', comunicate con nuestros representantes.', '#7f1d1d', '#fecaca');
    function desactivar() {
      var btns = document.querySelectorAll('button, input[type=submit], input[type=button]');
      for (var i = 0; i < btns.length; i++) {
        var b = btns[i];
        if (b.getAttribute('data-licencia-ok') === '1') continue;
        b.disabled = true;
        b.style.opacity = '0.5';
        b.style.cursor = 'not-allowed';
      }
    }
    desactivar();
    try {
      var obs = new MutationObserver(desactivar);
      if (document.body) obs.observe(document.body, { childList: true, subtree: true });
    } catch (_) {}
  }

  function aplicarVencimiento() {
    if (bloqueado) return;
    bloqueado = true;
    ocultarContador();
    if (L.modo === 'solo-lectura') modoSoloLectura();
    else modoBloqueo();
  }

  function bannerFijo(mensaje, fondo, color) {
    if (document.getElementById('licenciaBanner')) return;
    var b = document.createElement('div');
    b.id = 'licenciaBanner';
    var s = b.style;
    s.position = 'fixed'; s.top = '0'; s.left = '0'; s.right = '0';
    s.zIndex = '2147483646';
    s.background = fondo; s.color = color;
    s.font = '600 13px system-ui,-apple-system,"Segoe UI",Roboto,sans-serif';
    s.padding = '10px 16px'; s.textAlign = 'center';
    s.boxShadow = '0 2px 10px rgba(0,0,0,0.4)';
    b.textContent = mensaje;
    (document.body || document.documentElement).appendChild(b);
  }

  // ---- Arranque ----
  function evaluarAvisos() {
    var d = diasRestantes(ahora());
    if (d <= (L.avisarDiasAntes || 0)) mostrarAvisoEmergente(d);
  }

  function iniciar() {
    if (ahora() >= venceMs) { aplicarVencimiento(); return; }
    crearContador();
    tick = setInterval(actualizarContador, 1000);
    evaluarAvisos();
    // Reajustar el espacio y el ancho cuando cambia el tamano o la orientacion
    // de la pantalla (clave en celulares: girar el telefono, barra a 2 lineas).
    function reacomodar() { layoutResponsive(); ajustarEspacio(); }
    window.addEventListener('resize', reacomodar);
    window.addEventListener('orientationchange', function () {
      reacomodar(); setTimeout(reacomodar, 300);
    });
    window.addEventListener('load', reacomodar);
    // Confirmacion con la hora del servidor (atrapa relojes cambiados a mano).
    horaServidor().then(function (hs) {
      if (hs) {
        offsetServidorMs = hs - Date.now();
        actualizarContador();
        if (!bloqueado) evaluarAvisos();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', iniciar);
  } else {
    iniciar();
  }
})();
