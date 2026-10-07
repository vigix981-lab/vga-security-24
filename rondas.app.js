/* rondas.app.js — Pantalla DEDICADA de Rondas con QR (lado vigilador).
 * Lee el QR de cada punto de control con la camara (jsQR autohospedado),
 * valida el punto contra la base (objetivos/<id>/rondas/puntos/<idPunto>) y
 * registra el paso en el nodo rondasRegistros (append-only, por legajo propio).
 * La sesion (login por Worker + token) la maneja rondas.module.js.
 * CSP cerrada: sin inline handlers, sin eval, todo wired por addEventListener.
 */
(function () {
  'use strict';

  var URL_FIREBASE = 'https://vga-security-24-default-rtdb.firebaseio.com';

  // Prefijo del payload del QR: VIGIX1|idObjetivo|idPunto|token
  var PREFIJO_QR = 'VIGIX1';
  // No volver a registrar el MISMO punto antes de estos ms (evita duplicados
  // por mantener el QR frente a la camara).
  var COOLDOWN_PUNTO_MS = 60000;

  // ---- Estado interno del escaner ----
  var stream = null;         // MediaStream de la camara
  var rafId = null;          // id de requestAnimationFrame
  var procesando = false;    // hay una lectura en curso
  var escaneando = false;    // el loop esta activo
  var ultimoPorPunto = {};   // idPunto -> timestamp del ultimo registro OK
  var registrosSesion = [];  // historial visible de esta sesion
  var rondasHabilitadas = true;  // guia amable: false si el plan no incluye Rondas

  // ---- Utilidades ----
  function $(id) { return document.getElementById(id); }

  function escaparHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // Distancia en metros entre dos coordenadas (Haversine).
  function distanciaMetros(lat1, lon1, lat2, lon2) {
    var R = 6371000;
    var toRad = function (g) { return g * Math.PI / 180; };
    var dLat = toRad(lat2 - lat1), dLon = toRad(lon2 - lon1);
    var a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
    return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  }

  function horaCorta(ms) {
    try {
      return new Date(ms).toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (_) { return new Date(ms).toISOString(); }
  }

  function ahoraServidorMs() {
    return (typeof window.ahoraServidorRondasMs === 'function') ? window.ahoraServidorRondasMs() : Date.now();
  }

  // Estado textual bajo el marco del escaner.
  function estado(mensaje, tipo) {
    var el = $('estadoRondas');
    if (!el) return;
    var color = tipo === 'error' ? 'text-rose-400'
              : tipo === 'ok' ? 'text-emerald-400'
              : tipo === 'warn' ? 'text-amber-400'
              : 'text-slate-400';
    el.className = 'vigix-ronda-estado text-sm text-center ' + color;
    el.textContent = mensaje;
  }

  // ---- Login / navegacion de pantallas ----
  function mostrarEscaner(sesion) {
    var login = $('pantallaLoginRondas');
    var panel = $('pantallaRondas');
    if (login) login.classList.add('hidden');
    if (panel) panel.classList.remove('hidden');
    var lbl = $('lblSesionRondas');
    if (lbl) lbl.textContent = sesion && sesion.legajo ? ('Legajo ' + sesion.legajo) : '—';
    // Guia amable: consultar si el plan de la empresa incluye Rondas.
    verificarPlanRondas();
  }

  // Lee config/plan y, si Rondas no esta incluida o la cuenta esta suspendida,
  // muestra un mensaje claro y deshabilita el escaner. Es solo una guia de UX:
  // el bloqueo REAL e infranqueable vive en las Reglas de Firebase.
  async function verificarPlanRondas() {
    rondasHabilitadas = true;
    // Estado por defecto: contenido operativo visible, aviso de bloqueo oculto.
    var op0 = $('operativoRondas'); if (op0) op0.classList.remove('hidden');
    var bq0 = $('bloqueoRondas'); if (bq0) bq0.classList.add('hidden');
    try {
      var url = URL_FIREBASE + '/config/plan.json';
      var res = await window.fetchConAuthRondas(url, { cache: 'no-store' });
      if (!res || !res.ok) return;  // ante la duda, dejamos que las Reglas decidan
      var plan = await res.json();
      if (!plan) return;
      var incluyeRondas = !!(plan.funciones && plan.funciones.rondas === true);
      var suspendido = plan.estado === 'suspendido';
      if (suspendido) {
        bloquearRondas('Tu cuenta está suspendida. Rondas no está disponible hasta regularizar el plan.');
      } else if (!incluyeRondas) {
        bloquearRondas('Tu plan actual no incluye Rondas. Pedile al administrador que active la función en el plan Profesional o Empresa.');
      }
    } catch (_) { /* sin red: dejamos que las Reglas decidan al registrar */ }
  }

  // Deshabilita el escaner y avisa en pantalla con un mensaje claro.
  function bloquearRondas(mensaje) {
    rondasHabilitadas = false;
    detenerCamara();
    // Oculta TODO el contenido operativo del escaner y muestra el aviso claro de
    // "no disponible": no debe quedar ninguna función de Rondas a mano.
    var op = $('operativoRondas'); if (op) op.classList.add('hidden');
    var bq = $('bloqueoRondas'); if (bq) bq.classList.remove('hidden');
    var bqMsg = $('bloqueoRondasMsg'); if (bqMsg) bqMsg.textContent = mensaje;
    var bi = $('btnIniciarEscaner'); if (bi) bi.disabled = true;
    var bd = $('btnDetenerEscaner'); if (bd) bd.disabled = true;
  }

  function mostrarLogin() {
    var login = $('pantallaLoginRondas');
    var panel = $('pantallaRondas');
    if (panel) panel.classList.add('hidden');
    if (login) login.classList.remove('hidden');
  }

  function statusLogin(mensaje, tipo) {
    var el = $('loginStatusRondas');
    if (!el) return;
    if (!mensaje) { el.classList.add('hidden'); el.textContent = ''; return; }
    el.className = 'text-xs mt-1 text-center ' + (tipo === 'error' ? 'text-rose-400' : (tipo === 'ok' ? 'text-emerald-400' : 'text-slate-400'));
    el.textContent = mensaje;
    el.classList.remove('hidden');
  }

  function fmtSegundos(seg) {
    seg = Math.max(0, Math.ceil(Number(seg) || 0));
    var m = Math.floor(seg / 60), s = seg % 60;
    if (m > 0) return m + ' min ' + (s < 10 ? '0' : '') + s + ' s';
    return s + ' s';
  }

  async function manejarLogin(ev) {
    if (ev) ev.preventDefault();
    var legajo = ($('loginLegajoRondas').value || '').trim();
    var pin = ($('loginPinRondas').value || '').trim();
    if (!legajo || !pin) { statusLogin('Ingresá tu legajo y tu PIN.', 'error'); return; }
    if (typeof window.loginVigiladorRondas !== 'function') {
      statusLogin('Aún cargando la sesión. Reintentá en unos segundos.', 'error'); return;
    }
    var btn = $('btnIngresarRondas');
    var orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Ingresando…'; }
    statusLogin('Verificando…', 'info');
    var r = await window.loginVigiladorRondas(legajo, pin);
    if (btn) { btn.disabled = false; btn.textContent = orig; }
    if (r && r.ok) {
      statusLogin('', '');
      var pinEl = $('loginPinRondas'); if (pinEl) pinEl.value = '';
      mostrarEscaner(window.sesionRondas || { legajo: r.legajo });
      return;
    }
    var razon = r && r.razon;
    if (razon === 'bloqueado') {
      statusLogin('Demasiados intentos. Probá de nuevo en ' + fmtSegundos(r.segundosRestantes) + '.', 'error');
    } else if (razon === 'red') {
      statusLogin('No se pudo contactar el servicio de acceso. Revisá tu conexión.', 'error');
    } else if (razon === 'faltan_datos') {
      statusLogin('Ingresá tu legajo y tu PIN.', 'error');
    } else {
      var extra = (r && typeof r.intentosRestantes === 'number' && r.intentosRestantes > 0 && r.intentosRestantes <= 2)
        ? (' Te queda' + (r.intentosRestantes === 1 ? '' : 'n') + ' ' + r.intentosRestantes + ' intento' + (r.intentosRestantes === 1 ? '' : 's') + '.')
        : '';
      statusLogin('Legajo o PIN incorrectos.' + extra, 'error');
    }
  }

  async function manejarLogout() {
    detenerCamara();
    if (typeof window.logoutVigiladorRondas === 'function') {
      try { await window.logoutVigiladorRondas(); } catch (_) {}
    }
    registrosSesion = [];
    ultimoPorPunto = {};
    renderRegistros();
    var r = $('resultadoRondas'); if (r) { r.classList.add('hidden'); r.innerHTML = ''; }
    mostrarLogin();
  }

  // ---- Camara + escaneo ----
  async function iniciarCamara() {
    if (escaneando) return;
    if (!rondasHabilitadas) {
      estado('Rondas no está disponible en tu plan actual.', 'warn');
      return;
    }
    if (typeof window.jsQR !== 'function') {
      estado('El lector de QR aún se está cargando. Reintentá en unos segundos.', 'error');
      return;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      estado('Este navegador no permite usar la cámara.', 'error');
      return;
    }
    var video = $('videoRondas');
    estado('Encendiendo la cámara…', 'info');
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { facingMode: { ideal: 'environment' } }
      });
    } catch (e) {
      var m = 'No se pudo acceder a la cámara.';
      if (e && (e.name === 'NotAllowedError' || e.name === 'SecurityError')) {
        m = 'El navegador bloqueó la cámara. Permití el acceso para este sitio y reintentá.';
      } else if (e && e.name === 'NotFoundError') {
        m = 'No se encontró ninguna cámara en el dispositivo.';
      }
      estado(m, 'error');
      return;
    }
    video.srcObject = stream;
    video.setAttribute('playsinline', 'true');
    try { await video.play(); } catch (_) {}
    var mira = $('miraRondas'); if (mira) mira.classList.remove('hidden');
    $('btnIniciarEscaner').disabled = true;
    $('btnDetenerEscaner').disabled = false;
    escaneando = true;
    estado('Buscando código QR…', 'info');
    rafId = requestAnimationFrame(loopEscaneo);
  }

  function detenerCamara() {
    escaneando = false;
    if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    if (stream) {
      try { stream.getTracks().forEach(function (t) { t.stop(); }); } catch (_) {}
      stream = null;
    }
    var video = $('videoRondas');
    if (video) { try { video.pause(); } catch (_) {} video.srcObject = null; }
    var mira = $('miraRondas'); if (mira) mira.classList.add('hidden');
    var bi = $('btnIniciarEscaner'); if (bi) bi.disabled = false;
    var bd = $('btnDetenerEscaner'); if (bd) bd.disabled = true;
    estado('La cámara está apagada.', 'info');
  }

  function loopEscaneo() {
    if (!escaneando) return;
    var video = $('videoRondas');
    var canvas = $('canvasRondas');
    if (video && canvas && video.readyState === video.HAVE_ENOUGH_DATA && !procesando) {
      var w = video.videoWidth, h = video.videoHeight;
      if (w && h) {
        canvas.width = w; canvas.height = h;
        var ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(video, 0, 0, w, h);
        var img;
        try { img = ctx.getImageData(0, 0, w, h); } catch (_) { img = null; }
        if (img) {
          var code = window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
          if (code && code.data) {
            procesarQR(code.data);
          }
        }
      }
    }
    rafId = requestAnimationFrame(loopEscaneo);
  }

  // ---- Procesar un QR leido ----
  async function procesarQR(texto) {
    if (procesando) return;
    procesando = true;
    try {
      var partes = String(texto).split('|');
      if (partes[0] !== PREFIJO_QR || partes.length < 4) {
        estado('Ese QR no es de una ronda vga security 24.', 'error');
        await pausa(1200);
        return;
      }
      var idObjetivo = partes[1], idPunto = partes[2], token = partes.slice(3).join('|');
      if (!idObjetivo || !idPunto || !token) {
        estado('El QR está incompleto o dañado.', 'error');
        await pausa(1200);
        return;
      }

      // Anti-duplicado: mismo punto registrado hace muy poco.
      var ahora = ahoraServidorMs();
      if (ultimoPorPunto[idPunto] && (ahora - ultimoPorPunto[idPunto]) < COOLDOWN_PUNTO_MS) {
        estado('Ya registraste este punto recién.', 'warn');
        await pausa(1500);
        return;
      }

      var sesion = window.sesionRondas || {};
      if (!sesion.uid || !sesion.legajo) {
        estado('Tu sesión expiró. Volvé a ingresar.', 'error');
        await pausa(1500);
        return;
      }

      estado('Validando el punto…', 'info');
      var punto = await leerPunto(idObjetivo, idPunto);
      if (!punto) {
        estado('El punto no existe o el QR no corresponde a esta base.', 'error');
        await pausa(1800);
        return;
      }
      if (punto.activo === false) {
        estado('Este punto está desactivado. Avisá a tu supervisor.', 'error');
        await pausa(1800);
        return;
      }
      if (String(punto.token || '') !== String(token)) {
        estado('El QR no coincide con el punto (puede ser uno viejo).', 'error');
        await pausa(1800);
        return;
      }

      // GPS best-effort: no bloquea el registro, pero se sella y se marca si
      // quedó fuera del radio o con precisión pobre (el supervisor lo revisa).
      estado('Tomando tu ubicación…', 'info');
      var gps = await obtenerGPS();
      var dist = null, dentro = false, precisionBaja = false;
      if (gps && punto.lat != null && punto.lng != null) {
        dist = distanciaMetros(gps.lat, gps.lng, Number(punto.lat), Number(punto.lng));
        var radio = Number(punto.radioMetros) || 30;
        dentro = dist <= radio;
        var precMin = Number(punto.precisionGpsMin) || 50;
        precisionBaja = (gps.precision != null) && (gps.precision > precMin);
      }

      estado('Registrando el punto…', 'info');
      var registro = {
        legajo: String(sesion.legajo),
        authUid: sesion.uid,
        idObjetivo: idObjetivo,
        idPunto: idPunto,
        nombrePunto: punto.nombre || '',
        token: String(token),
        latitud: gps ? gps.lat : null,
        longitud: gps ? gps.lng : null,
        precisionGps: gps ? gps.precision : null,
        distanciaMetros: (dist != null) ? Math.round(dist) : null,
        ubicacionValidada: !!dentro,
        gpsDisponible: !!gps,
        precisionBaja: !!precisionBaja,
        radioMetros: Number(punto.radioMetros) || null,
        timestamp: new Date(ahora).toISOString(),
        fechaHoraDispositivo: new Date().toISOString(),
        origen: 'escaner_qr'
      };

      var okEscrito = await guardarRegistro(registro);
      if (!okEscrito) {
        estado('No se pudo guardar el registro. Revisá tu conexión y reintentá.', 'error');
        await pausa(1800);
        return;
      }

      ultimoPorPunto[idPunto] = ahora;
      registrosSesion.unshift(registro);
      renderRegistros();
      mostrarResultado(registro);

      if (!gps) {
        estado('Punto registrado (sin ubicación GPS).', 'warn');
      } else if (!dentro) {
        estado('Punto registrado, pero fuera del radio del punto.', 'warn');
      } else {
        estado('¡Punto registrado correctamente!', 'ok');
      }
      await pausa(1800);
    } finally {
      procesando = false;
      if (escaneando) estado('Buscando código QR…', 'info');
    }
  }

  function pausa(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  // Lee un punto de control (objetivos/<id>/rondas/puntos/<idPunto>).
  async function leerPunto(idObjetivo, idPunto) {
    var url = URL_FIREBASE + '/objetivos/' + encodeURIComponent(idObjetivo) +
              '/rondas/puntos/' + encodeURIComponent(idPunto) + '.json';
    try {
      var res = await window.fetchConAuthRondas(url, { cache: 'no-store' });
      if (!res.ok) return null;
      var data = await res.json();
      return data || null;
    } catch (_) { return null; }
  }

  // Escribe el registro en rondasRegistros (POST = clave nueva, append-only).
  async function guardarRegistro(registro) {
    var url = URL_FIREBASE + '/rondasRegistros.json';
    try {
      var res = await window.fetchConAuthRondas(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(registro)
      });
      return !!(res && res.ok);
    } catch (_) { return false; }
  }

  // GPS con limite de tiempo; nunca cuelga el flujo.
  function obtenerGPS() {
    return new Promise(function (resolve) {
      if (!navigator.geolocation) { resolve(null); return; }
      var listo = false;
      var t = setTimeout(function () { if (!listo) { listo = true; resolve(null); } }, 9000);
      navigator.geolocation.getCurrentPosition(function (pos) {
        if (listo) return; listo = true; clearTimeout(t);
        resolve({ lat: pos.coords.latitude, lng: pos.coords.longitude, precision: pos.coords.accuracy });
      }, function () {
        if (listo) return; listo = true; clearTimeout(t); resolve(null);
      }, { enableHighAccuracy: true, timeout: 8000, maximumAge: 0 });
    });
  }

  // ---- Render ----
  function mostrarResultado(reg) {
    var cont = $('resultadoRondas');
    if (!cont) return;
    var okUbic = reg.ubicacionValidada;
    var borde = okUbic ? 'border-emerald-500/40' : 'border-amber-500/40';
    var fondo = okUbic ? 'bg-emerald-950' : 'bg-amber-600/15';
    var ico = okUbic ? 'fa-circle-check text-emerald-400' : 'fa-triangle-exclamation text-amber-400';
    var detalleUbic;
    if (!reg.gpsDisponible) {
      detalleUbic = 'Sin ubicación GPS';
    } else if (okUbic) {
      detalleUbic = 'Dentro del radio' + (reg.distanciaMetros != null ? ' (' + reg.distanciaMetros + ' m)' : '');
    } else {
      detalleUbic = 'Fuera del radio' + (reg.distanciaMetros != null ? ' (' + reg.distanciaMetros + ' m)' : '');
    }
    cont.className = 'rounded-xl border ' + borde + ' ' + fondo + ' p-4';
    cont.innerHTML =
      '<div class="flex items-center gap-3">' +
        '<i class="fa-solid ' + ico + ' text-2xl"></i>' +
        '<div>' +
          '<p class="text-sm font-bold text-white">' + escaparHtml(reg.nombrePunto || 'Punto de control') + '</p>' +
          '<p class="text-xs text-slate-300">' + escaparHtml(horaCorta(Date.parse(reg.timestamp) || Date.now())) + ' · ' + escaparHtml(detalleUbic) + '</p>' +
        '</div>' +
      '</div>';
    cont.classList.remove('hidden');
  }

  function renderRegistros() {
    var cont = $('listaRegistrosRondas');
    if (!cont) return;
    if (!registrosSesion.length) {
      cont.innerHTML = '<p id="listaVaciaRondas" class="text-sm text-slate-500">Aún no registraste ningún punto.</p>';
      return;
    }
    var html = '';
    for (var i = 0; i < registrosSesion.length; i++) {
      var r = registrosSesion[i];
      var okUbic = r.ubicacionValidada;
      var claseIco = okUbic ? 'vigix-ronda-reg-ok' : 'vigix-ronda-reg-warn';
      var faIco = okUbic ? 'fa-circle-check' : 'fa-triangle-exclamation';
      var meta = escaparHtml(horaCorta(Date.parse(r.timestamp) || Date.now()));
      if (!r.gpsDisponible) meta += ' · sin GPS';
      else if (!okUbic) meta += ' · fuera de radio' + (r.distanciaMetros != null ? ' (' + r.distanciaMetros + ' m)' : '');
      else meta += ' · en el punto';
      html +=
        '<div class="vigix-ronda-reg">' +
          '<div class="vigix-ronda-reg-ico ' + claseIco + '"><i class="fa-solid ' + faIco + '"></i></div>' +
          '<div class="vigix-ronda-reg-txt">' +
            '<div class="vigix-ronda-reg-nombre">' + escaparHtml(r.nombrePunto || 'Punto de control') + '</div>' +
            '<div class="vigix-ronda-reg-meta">' + meta + '</div>' +
          '</div>' +
        '</div>';
    }
    cont.innerHTML = html;
  }

  // ---- Arranque ----
  function init() {
    var form = $('formLoginRondas');
    if (form) form.addEventListener('submit', manejarLogin);
    var bl = $('btnCerrarSesionRondas');
    if (bl) bl.addEventListener('click', manejarLogout);
    var bi = $('btnIniciarEscaner');
    if (bi) bi.addEventListener('click', function () { iniciarCamara(); });
    var bd = $('btnDetenerEscaner');
    if (bd) bd.addEventListener('click', function () { detenerCamara(); });

    // Si la pestana se oculta, apagamos la camara (ahorro de bateria/privacidad).
    document.addEventListener('visibilitychange', function () {
      if (document.hidden && escaneando) detenerCamara();
    });
    window.addEventListener('pagehide', function () { detenerCamara(); });

    // El modulo nos avisa si Firebase restauró una sesión al recargar.
    window.onSesionRondasLista = function (sesion) {
      if (sesion && sesion.uid && sesion.legajo) mostrarEscaner(sesion);
    };
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
