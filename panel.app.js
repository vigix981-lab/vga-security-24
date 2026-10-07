// ==========================================
// CONFIGURACIÓN DE SEGURIDAD (LOGIN REAL FIREBASE AUTH)
// ==========================================

window.onload = function() {
  // La restauracion de sesion la decide Firebase Auth (onAuthStateChanged),
  // NO un flag editable en sessionStorage. Ver listener en el modulo Firebase.
};

function validarPassword(e) {
  e.preventDefault();
  let email = (document.getElementById('inputEmail') ? document.getElementById('inputEmail').value : '').trim();
  // Ingreso simplificado: si escribio SOLO el legajo (sin "@"), agregamos el
  // dominio sintetico de los usuarios creados desde el panel ("@vga.security24").
  // Si escribio un correo completo (ej: supervisor@vigix.com, creado a mano en la
  // base), se respeta tal cual. Asi conviven ambos tipos de cuenta.
  if (email && email.indexOf('@') === -1) email = email + '@vga.security24';
  const input = document.getElementById('inputPass').value;
  const errorMsg = document.getElementById('msgErrorPass');
  errorMsg.classList.add('hidden');

  // --- Login REAL con Firebase Auth (correo + contraseña) ---
  if (typeof window.loginSupervisorReal === 'function') {
    const btnLogin = e.target ? e.target.querySelector('button[type="submit"]') : null;
    if (btnLogin) btnLogin.disabled = true;

    // Red de seguridad (celulares): si el ingreso tarda demasiado (conexion
    // lenta o storage restringido del navegador movil), reactivar el boton y
    // avisar en vez de quedar trabado sin hacer nada. Aditivo.
    let ingresoResuelto = false;
    const watchdog = setTimeout(function () {
      if (ingresoResuelto) return;
      ingresoResuelto = true;
      if (btnLogin) btnLogin.disabled = false;
      errorMsg.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> La conexión está demorando. Verificá tu internet y reintentá.';
      errorMsg.classList.remove('hidden');
    }, 20000);

    window.loginSupervisorReal(email, input).then(function(res) {
      if (ingresoResuelto) return;
      ingresoResuelto = true;
      clearTimeout(watchdog);
      if (btnLogin) btnLogin.disabled = false;
      if (res && res.ok) {
        sessionStorage.setItem('auth_supervisor', 'true');
        if (res.rol) sessionStorage.setItem('rol_supervisor', res.rol);
        if (res.uid) sessionStorage.setItem('uid_supervisor', res.uid);
        mostrarPanel();
      } else {
        // El Worker ya aplica el bloqueo y arma el mensaje (bloqueo o intentos
        // restantes). El cliente solo lo muestra.
        errorMsg.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> ' + ((res && res.mensaje) || 'Correo o contraseña incorrectos.');
        errorMsg.classList.remove('hidden');
        document.getElementById('inputPass').value = '';
        document.getElementById('inputPass').focus();
      }
    }).catch(function () {
      if (ingresoResuelto) return;
      ingresoResuelto = true;
      clearTimeout(watchdog);
      if (btnLogin) btnLogin.disabled = false;
      errorMsg.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> No se pudo completar el ingreso. Reintentá en unos segundos.';
      errorMsg.classList.remove('hidden');
    });
    return;
  }

  // El sistema de login aún no terminó de cargar (sin conexión o CDN de Firebase no disponible)
  errorMsg.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> El sistema de acceso está cargando. Verificá tu conexión y reintentá en unos segundos.';
  errorMsg.classList.remove('hidden');
}

function mostrarPanel() {
  document.getElementById('pantallaLogin').classList.add('hidden');
  document.getElementById('contenidoPanel').classList.remove('hidden');
  cargarDatos();
  iniciarActualizacionAutomatica();
  // [PLAN] Oculta en el panel del supervisor lo que el plan NO incluye
  // (rondas, exportar). Se corre tras el login real (ya hay token para leer
  // /config/plan). Fail-closed: si no se puede leer, se ocultan las opcionales.
  cargarPlanPanel();
}

// ============================================================================
//  [PLAN] GATING DE FUNCIONES EN EL PANEL DEL SUPERVISOR
//  Lee /config/plan (solo lectura; lo escribe el Worker con la service account)
//  y oculta los elementos con data-plan-funcion="X" cuyo plan no incluye X.
//  Mismo criterio que admin.html: la capa visual acompana al candado DURO de
//  las Reglas de Firebase. CSP-safe (sin inline), solo toggle de 'hidden'.
// ============================================================================
window.PLAN_VIGIX_PANEL = null;

function planTieneFuncionPanel(nombre) {
  var fn = (window.PLAN_VIGIX_PANEL && window.PLAN_VIGIX_PANEL.funciones) || {};
  return !!fn[nombre];
}
window.planTieneFuncionPanel = planTieneFuncionPanel;

function aplicarFuncionesUIPanel() {
  try {
    var marcados = document.querySelectorAll('[data-plan-funcion]');
    for (var i = 0; i < marcados.length; i++) {
      var el = marcados[i];
      var f = el.getAttribute('data-plan-funcion');
      el.classList.toggle('hidden', !planTieneFuncionPanel(f));
    }
  } catch (_) {}
}
window.aplicarFuncionesUIPanel = aplicarFuncionesUIPanel;

async function cargarPlanPanel() {
  try {
    try { if (window.authListoPanel) await window.authListoPanel; } catch (_) {}
    var res = await window.fetchConAuthPanel(`${URL_BASE_FIREBASE}/config/plan.json?ts=${Date.now()}`, { cache: 'no-store' });
    var p = res && res.ok ? await res.json() : null;
    window.PLAN_VIGIX_PANEL = {
      nombre: (p && p.nombre) ? String(p.nombre) : 'esencial',
      estado: (p && String(p.estado).toLowerCase() === 'suspendido') ? 'suspendido' : 'activo',
      funciones: (p && p.funciones && typeof p.funciones === 'object') ? p.funciones : {}
    };
  } catch (_) {
    // Fail-closed: sin plan legible, se ocultan las funciones opcionales.
    window.PLAN_VIGIX_PANEL = window.PLAN_VIGIX_PANEL || { nombre: 'esencial', estado: 'activo', funciones: {} };
  }
  aplicarFuncionesUIPanel();
}
window.cargarPlanPanel = cargarPlanPanel;

// Autoactualizacion del panel "Control en Tiempo Real" mediante polling
// controlado (suficiente para la infraestructura gratuita actual). Solo
// consulta cuando la pestana esta visible, para no gastar lecturas de mas.
let intervaloPolling = null;
const INTERVALO_POLLING_MS = 30000; // 30 segundos
function iniciarActualizacionAutomatica() {
  if (intervaloPolling) return;
  intervaloPolling = setInterval(() => {
    if (document.visibilityState === 'visible') cargarDatos();
  }, INTERVALO_POLLING_MS);
}
function detenerActualizacionAutomatica() {
  if (intervaloPolling) { clearInterval(intervaloPolling); intervaloPolling = null; }
}

function cerrarSesion() {
  detenerActualizacionAutomatica();
  sessionStorage.removeItem('auth_supervisor');
  sessionStorage.removeItem('rol_supervisor');
  sessionStorage.removeItem('uid_supervisor');
  if (typeof window.logoutSupervisorReal === 'function') { try { window.logoutSupervisorReal(); } catch (_) {} }
  location.reload();
}

// ==========================================
// LÓGICA DE DATOS Y DASHBOARD (FIREBASE: DEMO ASISTENCIA)
// ==========================================
const URL_BASE_FIREBASE = "https://mercosur-seguridad-default-rtdb.firebaseio.com";
const URL_FIREBASE = `${URL_BASE_FIREBASE}/fichadas.json`;

// ─────────────────────────────────────────────────────────────────────────────
//  CARGA BAJO DEMANDA DE LIBRERÍAS CDN PESADAS (xlsx ~600KB, jspdf+autotable ~350KB, Chart.js ~200KB)
//  Se cargan recién cuando se necesitan, no bloquean el <head>.
// ─────────────────────────────────────────────────────────────────────────────
var LAZY_CDN = {
  xlsx:      { id:'xlsx',      src:'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js',             integrity:'sha512-r22gChDnGvBylk90+2e/ycr3RVrDi8DIOkIGNhJlKfuyQM4tIRAI062MaV8sfjQKYVGjOBaZBOA87z+IhZE9DA==' },
  jspdf:     { id:'jspdf',     src:'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',            integrity:'sha512-qZvrmS2ekKPF2mSznTQsxqPgnpkI4DNTlrdUmTzrDgektczlKNRRhy5X5AAOnx5S09ydFYWWNSfcEqDTTHgtNA==' },
  autotable: { id:'autotable', src:'https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.31/jspdf.plugin.autotable.min.js', integrity:'sha512-/cZZTKETbsuutvNXdPji/z8N+9e+LHq9D60JhcBCigq9I5a2VDEcLzml8PdVlVqzmWlVbhZCuTx+9CTi2xb30A==' },
  chartjs:   { id:'chartjs',   src:'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.5.1/chart.umd.min.js',           integrity:'sha512-WoViKhKD4qI2WruSZqv9+kvM4WfFhUMQCLN4QlDTt5aU56fLQy2gYoxWIqlEnXqJy/+Ac5q/hk1oWfqnMDhwMA==' }
};

var _lazyExportPromise = null;
function lazyExport() {
  if (_lazyExportPromise) return _lazyExportPromise;
  _lazyExportPromise = window.cargarLoteCDN([LAZY_CDN.xlsx, LAZY_CDN.jspdf, LAZY_CDN.autotable]);
  return _lazyExportPromise;
}
var _lazyChartPromise = null;
function lazyChart() {
  if (_lazyChartPromise) return _lazyChartPromise;
  _lazyChartPromise = window.cargarCDN(LAZY_CDN.chartjs.id, LAZY_CDN.chartjs.src, LAZY_CDN.chartjs.integrity);
  return _lazyChartPromise;
}


const URL_PERSONAL = `${URL_BASE_FIREBASE}/personal.json`;
const URL_TURNOS = `${URL_BASE_FIREBASE}/asignacionesTurnos.json`;

let datosLocales = [];
let datosFiltradosActuales = [];
let datosSupervisorGlobal = [];
let datosAnuladasGlobal = []; // Fichadas anuladas: se conservan como evidencia pero no se contabilizan
let firebaseKeysMap = {}; // Guarda la relación de los elementos con sus IDs de Firebase
// Clave estable de una fichada para el mapa de IDs de Firebase. Usa solo los
// campos identificatorios (fecha, legajo, nombre, objetivo, tipo, mapa) y
// EXCLUYE la foto en base64: esa foto puede pesar cientos de KB y, al
// serializarse con JSON.stringify por cada fila y en cada render, disparaba
// el costo de memoria/CPU del panel. La combinación restante ya es única.
function claveFichada(arr) { return JSON.stringify(Array.isArray(arr) ? arr.slice(0, 6) : arr); }

// Comparacion unificada de legajo (misma logica que mismoLegajoAdmin en
// admin.html y mismoLegajoVig en mis-horas.html): normaliza con trim y, si
// ambos son numericos, compara tambien por valor entero para tolerar ceros
// a la izquierda (ej: "0286" === "286"). Legajo SIEMPRE se maneja como string.
function mismoLegajo(a, b) {
  const x = String(a == null ? '' : a).trim();
  const y = String(b == null ? '' : b).trim();
  if (x === '' || y === '') return false;
  if (x === y) return true;
  const nx = parseInt(x, 10), ny = parseInt(y, 10);
  return Number.isFinite(nx) && Number.isFinite(ny) && nx === ny;
}
let mapaConfiguracionPersonalPanel = {};
let asignacionesTurnosPanel = [];
// Configuración global de tolerancias (misma fuente que Admin: /configuracionGlobal).
let configGlobalPanel = { toleranciaIngresoMin: 15, toleranciaEgresoMin: 30 };

let instChartDona = null;
let instChartBarras = null;

async function cargarDatos() {
  const icono = document.getElementById('icono-reload');
  if (icono) icono.classList.add('fa-spin');

  try {
    // Esperar a que Firebase Auth restaure la sesión tras un reload, para que
    // urlConAuthPanel pueda adjuntar el token y las reglas permitan la lectura.
    try { if (window.authListoPanel) await window.authListoPanel; } catch (_) {}
    // Construir las 4 URLs firmadas en paralelo (urlConAuthPanel adjunta el token)
    // y disparar las 4 lecturas en un único Promise.all, para que la config
    // global viaje junto con fichadas/personal/turnos en vez de esperar una
    // segunda vuelta secuencial (una round-trip menos en cada polling de 30s).
    const [res, resPersonal, resTurnos, resCfg] = await Promise.all([
      window.fetchConAuthPanel(URL_FIREBASE),
      window.fetchConAuthPanel(`${URL_PERSONAL}?ts=${Date.now()}`, { cache: 'no-store' }),
      window.fetchConAuthPanel(`${URL_TURNOS}?ts=${Date.now()}`, { cache: 'no-store' }),
      // La config es opcional: si falla, no debe tumbar el resto del panel.
      window.fetchConAuthPanel(`${URL_BASE_FIREBASE}/configuracionGlobal.json?ts=${Date.now()}`, { cache: 'no-store' }).catch(() => null)
    ]);
    const resFirebase = res.ok ? await res.json() : null;
    const resPersonalData = resPersonal.ok ? await resPersonal.json() : null;
    const resTurnosData = resTurnos.ok ? await resTurnos.json() : null;

    // Aplicar tolerancias globales (aditivo, no interrumpe si falla).
    try {
      const cfg = (resCfg && resCfg.ok) ? await resCfg.json() : null;
      if (cfg && typeof cfg === 'object') {
        if (Number.isFinite(Number(cfg.toleranciaIngresoMin))) configGlobalPanel.toleranciaIngresoMin = Number(cfg.toleranciaIngresoMin);
        if (Number.isFinite(Number(cfg.toleranciaEgresoMin))) configGlobalPanel.toleranciaEgresoMin = Number(cfg.toleranciaEgresoMin);
      }
    } catch (e) { console.warn('No se pudo cargar la configuración global de tolerancias.', e); }

    mapaConfiguracionPersonalPanel = {};
    if (resPersonalData) {
      Object.entries(resPersonalData).forEach(([id, persona]) => {
        if (persona) mapaConfiguracionPersonalPanel[id] = { ...persona, firebaseId: id };
      });
    }
    asignacionesTurnosPanel = resTurnosData
      ? Object.entries(resTurnosData).map(([id, t]) => ({ ...t, id })).filter(t => t && t.legajo)
      : [];

    let fichadasArray = [];
    firebaseKeysMap = {}; 

    if (resFirebase) {
      Object.keys(resFirebase).forEach(key => {
        const item = resFirebase[key];
        const arrayItem = [
          // Hora OFICIAL para tabla, metricas y alertas de supervision: se toma
          // primero el sello del servidor Firebase unificado (item.timestampServidor,
          // .sv=timestamp, NO manipulable). 'timestamp' queda como compat de registros
          // antiguos y el reloj del dispositivo SOLO como fallback final. Asi un
          // telefono con la hora adelantada/atrasada no puede falsear cumplimiento.
          item.timestampServidor || item.timestampEstimadoDispositivo || item.timestamp || item.fechaHoraDispositivo || item.fecha,
          item.legajo,
          item.nombre,
          item.objetivo,
          item.tipo,
          item.mapa || item.urlMapa || `https://www.google.com/maps?q=${item.latitud},${item.longitud}`,
          item.foto || item.urlFoto || item.fotoBase64 || '',
          // [7] Fichada registrada SIN CONEXIÓN: la hora proviene del dispositivo y
          //     NO fue sellada por el servidor. [8] Además sigue pendiente de que
          //     un administrador la verifique manualmente.
          (item.origenOffline === true || item.sincronizadoDesdeOffline === true || item.horaVerificadaServidor === false),
          ((item.origenOffline === true || item.sincronizadoDesdeOffline === true || item.horaVerificadaServidor === false) && item.verificacionOfflineResuelta !== true),
          // [9] Fichada ANULADA: se conserva como evidencia pero no se contabiliza
          //     en métricas, gráficos, alertas ni auditoría de horas del supervisor.
          item.anulada === true
        ];
        fichadasArray.push(arrayItem);
        firebaseKeysMap[claveFichada(arrayItem)] = key;
      });
    }

    // Separar fichadas anuladas del dataset activo. Las anuladas se conservan
    // como evidencia pero NO cuentan para tabla visible, métricas, gráficos,
    // alertas de supervisión ni auditoría de horas del supervisor.
    const fichadasAnuladas = fichadasArray.filter(f => f[9] === true);
    datosLocales = fichadasArray.filter(f => f[9] !== true);
    datosAnuladasGlobal = fichadasAnuladas;
    filtrarTabla();
    // Deriva y sincroniza las alertas de supervisión (llegadas tarde / salidas anticipadas).
    generarAlertasSupervision(datosLocales);
    // [Opción A] Vigilancia de rondas: detecta puntos no marcados a tiempo.
    evaluarRondasAtrasadas();

  } catch (err) {
    console.error(err);
    document.getElementById('cuerpoTabla').innerHTML = `
      <tr>
        <td colspan="9" class="p-8 text-center text-rose-400">
          <i class="fa-solid fa-circle-exclamation text-xl mb-1"></i>
          <p>Error al obtener registros desde Firebase. Revisa tu conexión.</p>
        </td>
      </tr>`;
  } finally {
    if (icono) icono.classList.remove('fa-spin');
  }
}

// ── Seguridad (anti-XSS) ─────────────────────────────────────────────
// Escapa caracteres peligrosos antes de insertar datos de la base (creados
// desde el kiosco de forma anónima) dentro de innerHTML. Evita XSS.
function escaparHtml(valor) {
  return String(valor == null ? '' : valor)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ==========================================
// ALERTAS DE SUPERVISIÓN (llegadas tarde / salidas anticipadas)
// ==========================================
// Nodos Firebase: /alertasLlegadasTarde y /alertasSalidasAnticipadas.
// - Se derivan de las fichadas con la MISMA lógica de cumplimiento del panel.
// - Se guardan con clave ESTABLE (legajo+fecha+objetivo+tipo) para no duplicar
//   entre recargas ni entre dispositivos (Firebase = consistencia multi-equipo).
// - El archivado es persistente: se marca en Firebase y como respaldo local,
//   así una alerta revisada NO reaparece al recargar.
const NODO_ALERTA = { LLEGADA_TARDE: 'alertasLlegadasTarde', SALIDA_ANTICIPADA: 'alertasSalidasAnticipadas' };
const CLAVE_ALERTAS_SUP_ARCHIVADAS = 'vigix_alertas_sup_archivadas';
let alertasSupervisionDetectadas = [];

function leerArchivadasSupLocal() {
  try { const a = JSON.parse(localStorage.getItem(CLAVE_ALERTAS_SUP_ARCHIVADAS) || '[]'); return Array.isArray(a) ? a : []; }
  catch (_) { return []; }
}
function guardarArchivadasSupLocal(claves) {
  try { localStorage.setItem(CLAVE_ALERTAS_SUP_ARCHIVADAS, JSON.stringify(Array.from(new Set(claves)))); } catch (_) {}
}
// Deja SOLO caracteres seguros para claves de Firebase y para el onclick inline.
function sanitizarClaveFirebase(v) {
  return String(v == null ? '' : v).trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '_').slice(0, 120) || '_';
}
function construirClaveAlerta(legajo, fechaClave, objetivo, tipoAlerta) {
  return [sanitizarClaveFirebase(legajo), sanitizarClaveFirebase(fechaClave), sanitizarClaveFirebase(objetivo), tipoAlerta].join('__');
}

// Deriva las alertas de las fichadas cargadas y las sincroniza con Firebase.
async function generarAlertasSupervision(registros) {
  const detectadas = [];
  (registros || []).forEach(fila => {
    const tipo = String(fila[4] || '').toUpperCase();
    const horario = obtenerHorarioProgramado(fila[0], fila[1], fila[3]);
    const cumpl = calcularCumplimientoFichada(tipo, fila[0], horario);
    if (!cumpl) return;
    let tipoAlerta = null;
    if (tipo === 'ENTRADA' && /Llegada tarde/i.test(cumpl.texto)) tipoAlerta = 'LLEGADA_TARDE';
    else if (tipo === 'SALIDA' && /Salida anticipada/i.test(cumpl.texto)) tipoAlerta = 'SALIDA_ANTICIPADA';
    if (!tipoAlerta) return;
    const fechaObj = new Date(fila[0]);
    const fechaClave = obtenerFechaLocalClave(fechaObj);
    const legajo = String(fila[1] == null ? '' : fila[1]).trim();
    const objetivo = String(fila[3] || 'Objetivo General').trim();
    const clave = construirClaveAlerta(legajo, fechaClave, objetivo, tipoAlerta);
    detectadas.push({
      clave, tipoAlerta, legajo, nombre: fila[2] || `Legajo ${legajo}`,
      objetivo, fecha: fila[0], fechaClave, detalle: cumpl.texto,
      horarioProgramado: { inicio: (horario && horario.inicio) || '', fin: (horario && horario.fin) || '' }
    });
  });
  alertasSupervisionDetectadas = detectadas;

  // Sincroniza con Firebase: lee lo ya guardado (para respetar archivadas de
  // otros dispositivos) y sube SOLO las nuevas que aún no existen.
  try {
    const [rt, rs] = await Promise.all([
      window.fetchConAuthPanel(`${URL_BASE_FIREBASE}/${NODO_ALERTA.LLEGADA_TARDE}.json?ts=${Date.now()}`, { cache: 'no-store' }).then(r => r.ok ? r.json() : null).catch(() => null),
      window.fetchConAuthPanel(`${URL_BASE_FIREBASE}/${NODO_ALERTA.SALIDA_ANTICIPADA}.json?ts=${Date.now()}`, { cache: 'no-store' }).then(r => r.ok ? r.json() : null).catch(() => null)
    ]);
    const existentes = Object.assign({}, rt || {}, rs || {});
    // Merge de archivadas del server hacia el respaldo local (multi-dispositivo).
    const archLocal = new Set(leerArchivadasSupLocal());
    Object.entries(existentes).forEach(([k, v]) => { if (v && v.archivada) archLocal.add(k); });
    guardarArchivadasSupLocal(Array.from(archLocal));

    const authUid = sessionStorage.getItem('uid_supervisor') || '';
    for (const a of detectadas) {
      if (existentes[a.clave]) continue; // ya existe: no pisar (podría estar archivada)
      const payload = {
        legajo: a.legajo, nombre: a.nombre, objetivo: a.objetivo,
        fecha: a.fecha, fechaClave: a.fechaClave, tipoAlerta: a.tipoAlerta,
        detalle: a.detalle, horarioInicio: a.horarioProgramado.inicio,
        horarioFin: a.horarioProgramado.fin, authUid, archivada: false,
        registradoEnMs: Date.now()
      };
      try {
        await window.fetchConAuthPanel(`${URL_BASE_FIREBASE}/${NODO_ALERTA[a.tipoAlerta]}/${a.clave}.json`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
        });
      } catch (_) { /* si falla el guardado, igual se muestra localmente */ }
    }
  } catch (_) { /* sin conexión: se muestran las detectadas localmente */ }

  renderAlertasSupervision();
}

function renderAlertasSupervision() {
  const cont = document.getElementById('listaAlertasSupervision');
  const contador = document.getElementById('contadorAlertasSup');
  if (!cont) return;
  const chk = document.getElementById('chkMostrarArchivadasSup');
  const mostrarArch = !!(chk && chk.checked);
  const archivadas = new Set(leerArchivadasSupLocal());
  const visibles = alertasSupervisionDetectadas
    .filter(a => mostrarArch ? true : !archivadas.has(a.clave))
    .sort((x, y) => new Date(y.fecha) - new Date(x.fecha));

  const activas = alertasSupervisionDetectadas.filter(a => !archivadas.has(a.clave)).length;
  if (contador) {
    contador.textContent = String(activas);
    contador.classList.toggle('hidden', activas === 0);
  }

  if (!visibles.length) {
    cont.innerHTML = `<p class="text-sm text-slate-400 py-4 text-center"><i class="fa-solid fa-circle-check text-emerald-400"></i> No hay alertas ${mostrarArch ? '' : 'pendientes '}de supervisión.</p>`;
    return;
  }

  cont.innerHTML = '';
  visibles.forEach(a => {
    const estaArch = archivadas.has(a.clave);
    const esTarde = a.tipoAlerta === 'LLEGADA_TARDE';
    const icono = esTarde ? 'fa-user-clock' : 'fa-person-walking-arrow-right';
    const etiqueta = esTarde ? 'Llegada tarde' : 'Salida anticipada';
    const colorBorde = estaArch ? 'border-slate-600' : 'border-rose-500/50';
    const fechaTxt = a.fecha ? new Date(a.fecha).toLocaleString('es-AR', { hour12: false }) : '-';
    const hp = a.horarioProgramado || { inicio: '', fin: '' };
    const horarioTxt = (hp.inicio || hp.fin) ? ` · Horario ${escaparHtml(hp.inicio || '?')}-${escaparHtml(hp.fin || '?')}` : '';
    const div = document.createElement('div');
    div.className = `flex flex-col md:flex-row md:items-center justify-between gap-2 bg-slate-900/70 border ${colorBorde} rounded-xl px-4 py-3 ${estaArch ? 'opacity-60' : ''}`;
    div.innerHTML = `
      <div class="flex items-start gap-3">
        <i class="fa-solid ${icono} ${esTarde ? 'text-rose-400' : 'text-amber-400'} mt-0.5"></i>
        <div class="text-xs">
          <p class="font-bold text-white">${escaparHtml(a.nombre)} <span class="text-slate-400 font-normal">(Legajo ${escaparHtml(a.legajo)})</span></p>
          <p class="text-slate-300"><span class="font-semibold ${esTarde ? 'text-rose-300' : 'text-amber-300'}">${etiqueta}</span> · ${escaparHtml(a.detalle)}</p>
          <p class="text-slate-400">${escaparHtml(a.objetivo)} · ${escaparHtml(fechaTxt)}${horarioTxt}</p>
        </div>
      </div>
      <div class="flex-shrink-0">
        ${estaArch
          ? `<button type="button" data-accion-alerta="desarchivar" data-clave="${escaparHtml(a.clave)}" class="text-xs bg-slate-700 hover:bg-slate-600 text-slate-200 border border-slate-600 px-3 py-1.5 rounded-lg transition flex items-center gap-1.5"><i class="fa-solid fa-rotate-left"></i> Restaurar</button>`
          : `<button type="button" data-accion-alerta="archivar" data-clave="${escaparHtml(a.clave)}" class="text-xs bg-emerald-600/20 hover:bg-emerald-600/40 text-emerald-300 border border-emerald-500/40 px-3 py-1.5 rounded-lg transition flex items-center gap-1.5"><i class="fa-solid fa-box-archive"></i> Archivar</button>`}
      </div>`;
    cont.appendChild(div);
  });
}

async function archivarAlertaSupervision(clave) {
  const arch = new Set(leerArchivadasSupLocal());
  arch.add(clave);
  guardarArchivadasSupLocal(Array.from(arch));
  renderAlertasSupervision();
  // Persistir en Firebase (consistencia entre dispositivos).
  const a = alertasSupervisionDetectadas.find(x => x.clave === clave);
  const patch = { archivada: true, archivadaEnMs: Date.now(), archivadaPor: sessionStorage.getItem('uid_supervisor') || '' };
  const nodos = a ? [NODO_ALERTA[a.tipoAlerta]] : Object.values(NODO_ALERTA);
  for (const nodo of nodos) {
    try {
      await window.fetchConAuthPanel(`${URL_BASE_FIREBASE}/${nodo}/${clave}.json`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) });
    } catch (_) {}
  }
}

async function desarchivarAlertaSupervision(clave) {
  const arch = new Set(leerArchivadasSupLocal());
  arch.delete(clave);
  guardarArchivadasSupLocal(Array.from(arch));
  renderAlertasSupervision();
  const a = alertasSupervisionDetectadas.find(x => x.clave === clave);
  const patch = { archivada: false, archivadaEnMs: null };
  const nodos = a ? [NODO_ALERTA[a.tipoAlerta]] : Object.values(NODO_ALERTA);
  for (const nodo of nodos) {
    try {
      await window.fetchConAuthPanel(`${URL_BASE_FIREBASE}/${nodo}/${clave}.json`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) });
    } catch (_) {}
  }
}
window.archivarAlertaSupervision = archivarAlertaSupervision;
window.desarchivarAlertaSupervision = desarchivarAlertaSupervision;
window.renderAlertasSupervision = renderAlertasSupervision;

function renderizarTabla(registros) {
  const cuerpo = document.getElementById('cuerpoTabla');
  cuerpo.innerHTML = "";

  if (!registros || registros.length === 0) {
    cuerpo.innerHTML = `
      <tr>
        <td colspan="9" class="p-8 text-center text-slate-400">No hay registros cargados en Firebase aún.</td>
      </tr>`;
    return;
  }

  // Orden REAL por fecha/hora (mas reciente arriba). Antes se usaba
  // [...registros].reverse(), que dependia del orden interno de las claves
  // de Firebase; si una fichada se guardaba con una clave no cronologica,
  // quedaba fuera de lugar (p.ej. debajo de un dia anterior). Ahora se ordena
  // por el sello oficial fila[0], dejando al fondo las filas sin fecha valida.
  const ordenados = [...registros].sort((a, b) => {
    const ta = a && a[0] ? new Date(a[0]).getTime() : NaN;
    const tb = b && b[0] ? new Date(b[0]).getTime() : NaN;
    const va = Number.isFinite(ta) ? ta : -Infinity;
    const vb = Number.isFinite(tb) ? tb : -Infinity;
    return vb - va;
  });

  ordenados.forEach(fila => {
    const fecha = fila[0] ? new Date(fila[0]).toLocaleString('es-AR', { hour12: false }) : '-';
    const legajo = fila[1] !== undefined ? String(fila[1]) : '-';
    const nombre = fila[2] || '-';
    const objetivo = fila[3] || '-';
    const tipo = fila[4] || '-';
    const urlMapa = fila[5] || '';
    const urlFoto = fila[6] || '';
    // Marca de fichada offline: la hora es del dispositivo (no sellada por el
    // servidor). Si además sigue pendiente de verificación se resalta en ámbar.
    const esOfflineFila = fila[7] === true;
    const pendienteVerifFila = fila[8] === true;
    const esAnuladaFila = fila[9] === true;
    const notaOfflineFila = esOfflineFila
      ? `<div class="mt-1 inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold ${pendienteVerifFila ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30' : 'bg-slate-500/15 text-slate-300 border border-slate-500/30'}" title="Fichada registrada sin conexión: la hora proviene del dispositivo y no fue sellada por el servidor${pendienteVerifFila ? '. Pendiente de verificación por un administrador.' : ' (ya verificada manualmente).'}"><i class="fa-solid fa-clock-rotate-left"></i> hora del dispositivo${pendienteVerifFila ? ' · pendiente de verificación' : ''}</div>`
      : '';
    // Marca visual de fichada ANULADA: se muestra con tachado y badge rojo.
    const notaAnuladaFila = esAnuladaFila
      ? '<div class="mt-1 inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/40"><i class="fa-solid fa-ban"></i> ANULADA — no contabiliza</div>'
      : '';

    const badgeColor = tipo === 'ENTRADA' 
      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
      : 'bg-rose-500/10 text-rose-400 border-rose-500/20';

    // Cumplimiento (misma lógica que Admin): tolerancia / tarde / anticipada / extra.
    const horarioProgFila = obtenerHorarioProgramado(fila[0], fila[1], fila[3]);
    const cumplimiento = calcularCumplimientoFichada(tipo, fila[0], horarioProgFila);
    const celdaCumplimiento = cumplimiento
      ? `<span class="inline-block px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${cumplimiento.clase}">${cumplimiento.texto}</span>`
      : `<span class="text-xs text-slate-500">Sin horario</span>`;

    const btnMapa = (urlMapa && urlMapa.includes('http'))
      ? `<a href="${escaparHtml(urlMapa)}" target="_blank" class="inline-flex items-center gap-1 bg-sky-600/20 text-sky-400 hover:bg-sky-600/40 border border-sky-500/30 px-3 py-1 rounded-lg text-xs font-semibold transition">
          <i class="fa-solid fa-map-location-dot"></i> Mapa
         </a>`
      : `<span class="text-xs text-slate-500">Sin GPS</span>`;

    const btnFoto = (urlFoto && (urlFoto.includes('http') || urlFoto.includes('data:image')))
      ? `<button type="button" data-accion="ver-foto" data-url="${escaparHtml(urlFoto)}" class="inline-flex items-center gap-1 bg-amber-600/20 text-amber-400 hover:bg-amber-600/40 border border-amber-500/30 px-3 py-1 rounded-lg text-xs font-semibold transition">
          <i class="fa-solid fa-image"></i> Ver Foto
         </button>`
      : `<span class="text-xs text-slate-500">Sin Foto</span>`;

    const firebaseKey = firebaseKeysMap[claveFichada(fila)];
    // Panel de SOLO LECTURA para supervisores: el borrado de fichadas queda
    // reservado al rol admin (ademas de estar bloqueado por las Reglas de Firebase).
    const esAdminPanel = sessionStorage.getItem('rol_supervisor') === 'admin';
    const btnBorrar = (firebaseKey && esAdminPanel)
      ? `<button type="button" data-accion="eliminar-fichada" data-key="${escaparHtml(firebaseKey)}" class="bg-rose-600/20 hover:bg-rose-600/40 text-rose-400 border border-rose-500/30 px-2.5 py-1 rounded-lg text-xs font-semibold transition" title="Anular registro (se conserva como evidencia)">
          <i class="fa-solid fa-ban"></i>
         </button>`
      : `<span class="text-[10px] text-slate-500">-</span>`;

    const tr = document.createElement('tr');
    tr.className = `hover:bg-slate-700/30 transition${esAnuladaFila ? ' opacity-50' : ''}`;
    tr.innerHTML = `
      <td class="p-4 font-mono text-xs text-slate-300${esAnuladaFila ? ' line-through' : ''}">${fecha}${notaOfflineFila}${notaAnuladaFila}</td>
      <td class="p-4 font-semibold text-white${esAnuladaFila ? ' line-through opacity-60' : ''}">${escaparHtml(legajo)}</td>
      <td class="p-4 font-medium text-slate-200${esAnuladaFila ? ' line-through opacity-60' : ''}">${escaparHtml(nombre)}</td>
      <td class="p-4 text-slate-400${esAnuladaFila ? ' line-through opacity-60' : ''}">${escaparHtml(objetivo)}</td>
      <td class="p-4 text-center">
        <span class="inline-block px-2.5 py-0.5 rounded-full text-xs font-bold border ${badgeColor}">${escaparHtml(tipo)}</span>
      </td>
      <td class="p-4 text-center">${celdaCumplimiento}</td>
      <td class="p-4 text-center">${btnMapa}</td>
      <td class="p-4 text-center">${btnFoto}</td>
      <td class="p-4 text-center">${btnBorrar}</td>
    `;
    cuerpo.appendChild(tr);
  });
}

// ANULACION LOGICA de fichada (NO borrado fisico). Antes esta funcion hacia un
// DELETE /fichadas/<id> que destruia la evidencia. Ahora llama al Worker
// autoritativo (accion 'anularFichada'), que valida el rol admin, marca la
// fichada como anulada=true con motivo/actor/fecha y deja registro en /auditoria.
// La fichada se conserva siempre como evidencia laboral.
async function eliminarFichadaFirebase(firebaseKey) {
  // Solo el rol admin puede anular (defensa en profundidad; el Worker tambien
  // revalida el rol admin server-side).
  if (sessionStorage.getItem('rol_supervisor') !== 'admin') {
    alert('Tu rol es de solo lectura. La anulación de fichadas está reservada al administrador.');
    return;
  }
  const motivo = prompt('Motivo de la ANULACIÓN (la fichada NO se borra: queda guardada como evidencia, marcada como anulada y sin contar en los reportes):', '');
  if (motivo === null) return; // cancelado

  const URL_WORKER_ANULAR = 'https://vga-security-24.micasa27822024.workers.dev/';
  try {
    const idToken = await window.obtenerTokenSupervisor();
    if (!idToken) { alert('Tu sesión expiró. Volvé a iniciar sesión e intentalo de nuevo.'); return; }
    const resp = await fetch(URL_WORKER_ANULAR, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken, accion: 'anularFichada', fichadaId: firebaseKey, motivo: (motivo || '').trim() })
    });
    let data = {};
    try { data = await resp.json(); } catch (_) {}
    if (resp.ok && data && data.ok) {
      alert('Fichada anulada. Queda guardada como evidencia y no se contabiliza en los reportes.');
      cargarDatos();
    } else {
      alert('No se pudo anular la fichada: ' + ((data && data.error) || ('HTTP ' + resp.status)) + '.\n\nVerificá que el Worker esté desplegado y actualizado.');
    }
  } catch (err) {
    console.error(err);
    alert('Ocurrió un error al intentar anular la fichada. Revisá tu conexión.');
  }
}

function filtrarTabla() {
  const busqueda = document.getElementById('inputBusqueda').value.toLowerCase();
  const filtroTipo = document.getElementById('filtroTipo').value;
  const valDesde = document.getElementById('fechaDesde').value;
  const valHasta = document.getElementById('fechaHasta').value;
  const chkAnuladas = document.getElementById('chkMostrarAnuladas');
  const mostrarAnuladas = !!(chkAnuladas && chkAnuladas.checked);

  // Base: fichadas activas (no anuladas) siempre visibles.
  // Si el checkbox está tildado, se agregan las anuladas al final.
  let baseDatos = mostrarAnuladas ? [...datosLocales, ...datosAnuladasGlobal] : datosLocales;

  datosFiltradosActuales = baseDatos.filter(fila => {
    const textoFila = `${fila[1]} ${fila[2]} ${fila[3]}`.toLowerCase();
    const coincideBusqueda = textoFila.includes(busqueda);
    const coincideTipo = (filtroTipo === 'TODOS') || (fila[4] === filtroTipo);

    let coincideFecha = true;
    if (fila[0]) {
      const fechaObj = new Date(fila[0]);
      const fechaIsoFila = obtenerFechaLocalClave(fechaObj);
      
      if (valDesde && fechaIsoFila < valDesde) coincideFecha = false;
      if (valHasta && fechaIsoFila > valHasta) coincideFecha = false;
    }

    return coincideBusqueda && coincideTipo && coincideFecha;
  });

  // Orden REAL por fecha/hora (mas reciente primero) EN EL ORIGEN, para que la
  // tabla en pantalla Y los reportes detallados (Excel/PDF que recorren esta
  // misma lista) queden siempre en el mismo orden cronologico. Antes el orden
  // dependia de las claves internas de Firebase. Las filas sin fecha valida
  // quedan al final.
  datosFiltradosActuales.sort((a, b) => {
    const ta = a && a[0] ? new Date(a[0]).getTime() : NaN;
    const tb = b && b[0] ? new Date(b[0]).getTime() : NaN;
    const va = Number.isFinite(ta) ? ta : -Infinity;
    const vb = Number.isFinite(tb) ? tb : -Infinity;
    return vb - va;
  });

  renderizarTabla(datosFiltradosActuales);
  // Los KPI representan el estado GENERAL (dataset completo sin anuladas), no el subconjunto
  // filtrado. Asi los indicadores no cambian al aplicar busqueda/fecha/tipo.
  actualizarMetricasYGraficos(datosLocales);
}

// ==========================================
// CÁLCULO Y GESTIÓN DE HORAS DEL SUPERVISOR
// ==========================================

function minutosDesdeMedianoche(hora) {
  if (!hora || !/^\d{1,2}:\d{2}$/.test(String(hora))) return null;
  const [h, m] = String(hora).split(':').map(Number);
  if (h < 0 || h > 23 || m < 0 || m > 59) return null;
  return h * 60 + m;
}

function obtenerFechaLocalClave(fecha) {
  if (!(fecha instanceof Date) || isNaN(fecha)) return '';
  const y = fecha.getFullYear();
  const m = String(fecha.getMonth() + 1).padStart(2, '0');
  const d = String(fecha.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

// Clasifica una fichada según el horario programado y las tolerancias globales (misma lógica que Admin).
// Devuelve null si no hay horario suficiente para evaluar.
function calcularCumplimientoFichada(tipo, fechaFichadaStr, horarioProgramado) {
  const t = String(tipo || '').toUpperCase();
  const f = new Date(fechaFichadaStr);
  if (isNaN(f) || !horarioProgramado) return null;
  const minFichada = f.getHours() * 60 + f.getMinutes();
  const tolIng = Number(configGlobalPanel.toleranciaIngresoMin);
  const tolEgr = Number(configGlobalPanel.toleranciaEgresoMin);

  const normalizar = (diff) => {
    if (diff > 720) return diff - 1440;
    if (diff < -720) return diff + 1440;
    return diff;
  };

  if (t === 'ENTRADA') {
    const ini = minutosDesdeMedianoche(horarioProgramado.inicio);
    if (ini === null) return null;
    const diff = normalizar(minFichada - ini);
    if (diff <= 0) return { texto: 'A tiempo', clase: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25' };
    if (diff <= tolIng) return { texto: `Tolerancia (+${diff} min)`, clase: 'bg-amber-500/15 text-amber-300 border-amber-500/40' };
    return { texto: `Llegada tarde (+${diff} min)`, clase: 'bg-rose-500/15 text-rose-300 border-rose-500/40' };
  }

  if (t === 'SALIDA') {
    const fin = minutosDesdeMedianoche(horarioProgramado.fin);
    const ini = minutosDesdeMedianoche(horarioProgramado.inicio);
    if (fin === null) return null;
    // Turno nocturno: el fin del turno cae del dia siguiente (fin < inicio).
    // Si la fichada de SALIDA ocurrio de dia (minFichada >= fin) pero antes de
    // que termine el turno (minFichada < inicio), el fin real es fin+1440.
    // Ej. turno 19-07, salida 15:45: fin real = 420+1440 = 1860, diff = 945-1860 = -915
    //   -> "Salida anticipada". Sin este ajuste diff quedaba +525 -> "Horas extra".
    let finReal = fin;
    if (ini !== null && fin < ini && minFichada >= fin && minFichada < ini) {
      finReal = fin + 1440;
    }
    const diff = normalizar(minFichada - finReal);
    if (diff < 0) return { texto: `Salida anticipada (${Math.abs(diff)} min antes)`, clase: 'bg-rose-500/15 text-rose-300 border-rose-500/40' };
    if (diff <= tolEgr) return { texto: 'Salida en horario', clase: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25' };
    // REGLA DE NEGOCIO (Opcion B, ajustada): al superar la tolerancia se computan
    // como extra los minutos de tolerancia COMPLETOS mas cada minuto adicional; NO
    // se cuenta el minuto en que se cruza el umbral. Misma logica que Admin.
    // Formula: extra = diff - 1 (cuando diff > tolEgr).
    // Ej. fin 07:00, tol 30': 07:31 -> +30 min; 07:40 -> +39 min.
    const extra = diff - 1;
    return { texto: `Horas extra (+${extra} min)`, clase: 'bg-sky-500/15 text-sky-300 border-sky-500/40' };
  }
  return null;
}

function obtenerHorarioProgramado(entrada, legajo, objetivoNombre) {
  const fechaEntrada = new Date(entrada);
  if (isNaN(fechaEntrada)) return null;
  const fechaClave = obtenerFechaLocalClave(fechaEntrada);
  const legajoStr = String(legajo || '').trim();
  const objetivoStr = String(objetivoNombre || '').trim().toLowerCase();

  // Primero se busca un turno puntual cargado desde Admin para esa fecha.
  const turnosFecha = asignacionesTurnosPanel.filter(t =>
    mismoLegajo(t.legajo, legajoStr) && String(t.fecha || '') === fechaClave
  );

  let turno = null;
  if (turnosFecha.length) {
    // Si hay varios turnos ese día, priorizar el objetivo de la fichada.
    turno = turnosFecha.find(t => {
      const nombre = String(t.objetivoNombre || t.objetivo || '').trim().toLowerCase();
      return objetivoStr && nombre && (nombre === objetivoStr || nombre.includes(objetivoStr) || objetivoStr.includes(nombre));
    }) || turnosFecha[0];
  }

  if (turno && (turno.horaInicio || turno.horaFin)) {
    return {
      inicio: turno.horaInicio || '',
      fin: turno.horaFin || '',
      origen: 'Turno asignado'
    };
  }

  // Si no existe un turno puntual, usar el horario habitual configurado en Admin.
  const persona = Object.values(mapaConfiguracionPersonalPanel).find(p => mismoLegajo(p.legajo, legajoStr));
  const h = persona?.horarioHabitual || {};
  if (h.inicio || h.fin) {
    return {
      inicio: h.inicio || '',
      fin: h.fin || '',
      origen: 'Horario habitual'
    };
  }

  return null;
}

function calcularHoras(fechaInicioStr, fechaFinStr, horarioProgramado = null) {
  let inicio = new Date(fechaInicioStr);
  const fin = new Date(fechaFinStr);
  if (isNaN(inicio) || isNaN(fin) || fin <= inicio) return { d: 0, n: 0, t: 0, entradaComputable: inicio, ajusteMinutos: 0 };

  let entradaComputable = new Date(inicio.getTime());
  let ajusteMinutos = 0;

  // Regla laboral del sistema:
  // si el empleado llega ANTES del horario de inicio del turno, esos minutos
  // no forman parte de las horas computables ni se consideran horas extra.
  if (horarioProgramado?.inicio) {
    const minutosTurno = minutosDesdeMedianoche(horarioProgramado.inicio);
    if (minutosTurno !== null) {
      const fechaTurno = new Date(inicio.getTime());
      fechaTurno.setHours(Math.floor(minutosTurno / 60), minutosTurno % 60, 0, 0);

      // Para turnos nocturnos que comienzan tarde, la comparación sigue siendo
      // sobre la fecha de la ENTRADA. El punto importante es no contar llegada anticipada.
      if (fechaTurno > entradaComputable) {
        entradaComputable = fechaTurno;
        ajusteMinutos = Math.max(0, Math.round((entradaComputable - inicio) / 60000));
      }
    }
  }

  // Si por alguna configuración extraña el horario programado cae después de la salida,
  // no se computan horas de ese período.
  if (entradaComputable >= fin) {
    return { d: 0, n: 0, t: 0, entradaComputable, ajusteMinutos };
  }

  let horasDiurnas = 0;
  let horasNocturnas = 0;
  let actual = new Date(entradaComputable.getTime());

  while (actual < fin) {
    let siguiente = new Date(actual.getTime() + 60000);
    if (siguiente > fin) siguiente = new Date(fin.getTime());

    let hora = actual.getHours();
    if (hora >= 21 || hora < 6) {
      horasNocturnas += (siguiente - actual) / 3600000;
    } else {
      horasDiurnas += (siguiente - actual) / 3600000;
    }
    actual = siguiente;
  }

  return {
    d: horasDiurnas,
    n: horasNocturnas,
    t: horasDiurnas + horasNocturnas,
    entradaComputable,
    ajusteMinutos
  };
}

function formatearAHorasReloj(horasDecimales) {
  if (isNaN(horasDecimales) || horasDecimales <= 0) return "00:00 hs";
  const horas = Math.floor(horasDecimales);
  const minutos = Math.round((horasDecimales - horas) * 60);
  return `${String(horas).padStart(2, '0')}:${String(minutos).padStart(2, '0')} hs`;
}

function consultarHorasSupervisor() {
  const legajo = document.getElementById('legajoSupervisorInput').value.trim();
  if (!legajo) {
    return alert("Por favor ingresa un número de legajo para consultar.");
  }

  if (!datosLocales || datosLocales.length === 0) {
    return alert("Los datos aún se están cargando o no hay registros disponibles.");
  }

  const marcacionesVigilador = datosLocales.filter(f => mismoLegajo(f[1], legajo));
  
  if (marcacionesVigilador.length === 0) {
    alert("No se encontraron registros para el legajo especificado.");
    document.getElementById('resultadoSupervisor').classList.add('hidden');
    document.getElementById('controlesSupervisor').classList.add('hidden');
    return;
  }

  datosSupervisorGlobal = marcacionesVigilador;
  poblarSelectMesesSupervisor(datosSupervisorGlobal);
  aplicarFiltrosSupervisor();

  document.getElementById('resultadoSupervisor').classList.remove('hidden');
  document.getElementById('controlesSupervisor').classList.remove('hidden');
}

function poblarSelectMesesSupervisor(datos) {
  const selectMes = document.getElementById('supFiltroMes');
  const mesActualSeleccionado = selectMes.value;
  
  const mesesSet = new Set();
  datos.forEach(f => {
    if(f[0]) {
      const d = new Date(f[0]);
      if(!isNaN(d)) {
        const anio = d.getFullYear();
        const mes = String(d.getMonth() + 1).padStart(2, '0');
        mesesSet.add(`${anio}-${mes}`);
      }
    }
  });

  const mesesOrdenados = Array.from(mesesSet).sort().reverse();
  selectMes.innerHTML = `<option value="todos">Todos los meses</option>`;
  const nombresMeses = ["Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio", "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"];

  mesesOrdenados.forEach(m => {
    const [anio, mesNum] = m.split('-');
    const nombreMesTexto = `${nombresMeses[parseInt(mesNum) - 1]} ${anio}`;
    const opt = document.createElement('option');
    opt.value = m;
    opt.innerText = nombreMesTexto;
    selectMes.appendChild(opt);
  });

  if (mesesOrdenados.includes(mesActualSeleccionado)) {
    selectMes.value = mesActualSeleccionado;
  }
}

function aplicarFiltrosSupervisor() {
  const mesFiltro = document.getElementById('supFiltroMes').value;
  const valDesde = document.getElementById('supFechaDesde').value;
  const valHasta = document.getElementById('supFechaHasta').value;

  let filtrados = datosSupervisorGlobal;

  if (mesFiltro !== 'todos') {
    filtrados = filtrados.filter(f => {
      const d = new Date(f[0]);
      const anio = d.getFullYear();
      const mes = String(d.getMonth() + 1).padStart(2, '0');
      return `${anio}-${mes}` === mesFiltro;
    });
  }

  if (valDesde || valHasta) {
    filtrados = filtrados.filter(f => {
      if (!f[0]) return false;
      const fechaIsoFila = obtenerFechaLocalClave(new Date(f[0]));
      if (valDesde && fechaIsoFila < valDesde) return false;
      if (valHasta && fechaIsoFila > valHasta) return false;
      return true;
    });
  }

  procesarYRenderizarSupervisor(filtrados);
}

function procesarYRenderizarSupervisor(marcacionesVigilador) {
  marcacionesVigilador.sort((a, b) => new Date(a[0]) - new Date(b[0]));

  let totalD = 0, totalN = 0, totalT = 0;
  const tabla = document.getElementById('supCuerpoDetalle');
  tabla.innerHTML = "";

  for (let i = 0; i < marcacionesVigilador.length; i++) {
    if (marcacionesVigilador[i][4] === 'ENTRADA') {
      let entrada = marcacionesVigilador[i];
      let salida = marcacionesVigilador[i + 1] && marcacionesVigilador[i + 1][4] === 'SALIDA' ? marcacionesVigilador[i + 1] : null;

      let objetivoNombre = entrada[3] || (salida && salida[3]) || '-';
      const horarioProgramado = obtenerHorarioProgramado(entrada[0], entrada[1], objetivoNombre);
      let horas = salida ? calcularHoras(entrada[0], salida[0], horarioProgramado) : { d: 0, n: 0, t: 0, entradaComputable: new Date(entrada[0]), ajusteMinutos: 0 };

      totalD += horas.d;
      totalN += horas.n;
      totalT += horas.t;

      const tr = document.createElement('tr');
      tr.className = "hover:bg-slate-800/50 transition";
      tr.innerHTML = `
        <td class="p-3 text-xs font-mono">${new Date(entrada[0]).toLocaleString('es-AR', { hour12: false })}</td>
        <td class="p-3 text-xs font-mono">${salida ? new Date(salida[0]).toLocaleString('es-AR', { hour12: false }) : '<span class="text-amber-400">En Turno</span>'}</td>
        <td class="p-3 text-xs text-slate-300 font-medium">${escaparHtml(objetivoNombre)}<div class="text-[10px] text-slate-500 mt-1">${horarioProgramado ? `Turno ${escaparHtml(horarioProgramado.inicio || '--:--')} - ${escaparHtml(horarioProgramado.fin || '--:--')} · ${escaparHtml(horarioProgramado.origen)}` : 'Sin horario configurado'}${horas.ajusteMinutos > 0 ? ` · ${horas.ajusteMinutos} min anticipados no computados` : ''}</div></td>
        <td class="p-3 text-center text-xs font-semibold text-amber-400">${formatearAHorasReloj(horas.d)}</td>
        <td class="p-3 text-center text-xs font-semibold text-indigo-400">${formatearAHorasReloj(horas.n)}</td>
        <td class="p-3 text-center text-xs font-bold text-emerald-400">${formatearAHorasReloj(horas.t)}</td>
      `;
      tabla.appendChild(tr);
    }
  }

  document.getElementById('supHorasDiurnas').innerText = formatearAHorasReloj(totalD);
  document.getElementById('supHorasNocturnas').innerText = formatearAHorasReloj(totalN);
  document.getElementById('supHorasTotales').innerText = formatearAHorasReloj(totalT);
}

function exportarExcelSupervisor() {
  const legajo = document.getElementById('legajoSupervisorInput').value.trim();
  const filas = document.querySelectorAll('#supCuerpoDetalle tr');
  if (filas.length === 0) return alert("No hay datos para exportar.");

  let csv = "Entrada;Salida;Objetivo;Diurnas;Nocturnas;Total\n";
  filas.forEach(tr => {
    const cols = tr.querySelectorAll('td');
    const filaData = Array.from(cols).map(c => `"${c.innerText.replace(/[\n\r]+/g, "").trim()}"`).join(";");
    csv += filaData + "\n";
  });

  const blob = new Blob(["\ufeff" + csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `Reporte_Horas_Legajo_${legajo}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function exportarPdfSupervisor() {
  const legajo = document.getElementById('legajoSupervisorInput').value.trim();
  const filas = document.querySelectorAll('#supCuerpoDetalle tr');
  if (filas.length === 0) return alert("No hay datos para exportar.");

  let nombreApellido = "No especificado";
  if (datosSupervisorGlobal && datosSupervisorGlobal.length > 0) {
    nombreApellido = datosSupervisorGlobal[0][2] || "No especificado";
  }

  const horasDiurnasTotal = document.getElementById('supHorasDiurnas').innerText;
  const horasNocturnasTotal = document.getElementById('supHorasNocturnas').innerText;
  const horasTotalesGeneral = document.getElementById('supHorasTotales').innerText;

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  doc.setFontSize(14);
  doc.setTextColor(15, 23, 42);
  doc.text("vga security 24 - Control operativo y asistencia - Reporte de Horas por Empleado", 14, 15);

  doc.setFontSize(10);
  doc.setTextColor(71, 85, 105);
  doc.text(`Fecha de emisión: ${new Date().toLocaleString('es-AR', { hour12: false })}`, 14, 22);

  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  doc.text(`Legajo: ${legajo}`, 14, 31);
  doc.text(`Nombre y Apellido: ${nombreApellido}`, 14, 37);

  doc.text(`Total Horas Diurnas: ${horasDiurnasTotal}`, 120, 31);
  doc.text(`Total Horas Nocturnas: ${horasNocturnasTotal}`, 120, 37);
  doc.text(`Total General del Periodo: ${horasTotalesGeneral}`, 120, 43);

  const columnas = ["Entrada", "Salida", "Objetivo", "Diurnas", "Nocturnas", "Total"];
  const datosTabla = [];
  
  filas.forEach(tr => {
    const cols = tr.querySelectorAll('td');
    datosTabla.push([
      cols[0].innerText,
      cols[1].innerText,
      cols[2].innerText,
      cols[3].innerText,
      cols[4].innerText,
      cols[5].innerText
    ]);
  });

  doc.autoTable({
    head: [columnas],
    body: datosTabla,
    startY: 48,
    theme: 'grid',
    headStyles: { fillColor: [15, 23, 42] },
    styles: { fontSize: 8 }
  });

  doc.save(`Reporte_Horas_Legajo_${legajo}.pdf`);
}

function actualizarMetricasYGraficos(registros) {
  // Usa clave de fecha LOCAL (no UTC) para no descolocar el dia durante la noche.
  const hoyStr = obtenerFechaLocalClave(new Date());

  let entradasHoy = 0;
  let salidasHoy = 0;
  // Estado operativo real: ultima fichada HISTORICA por legajo (no solo la de hoy).
  // Asi una ENTRADA de la noche anterior sin SALIDA sigue contando "En Planta".
  const ultimaFichadaPorLegajo = {}; // legajo -> { ts, tipo }

  const diasUltimaSemana = [];
  const conteoPorDia = {};

  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const fechaKey = obtenerFechaLocalClave(d);
    diasUltimaSemana.push(fechaKey);
    conteoPorDia[fechaKey] = { entradas: 0, salidas: 0 };
  }

  registros.forEach(fila => {
    if (!fila[0]) return;
    
    const fechaObj = new Date(fila[0]);
    if (isNaN(fechaObj.getTime())) return;
    const fechaIso = obtenerFechaLocalClave(fechaObj);
    const legajo = fila[1];
    const tipo = fila[4];

    if (fechaIso === hoyStr) {
      if (tipo === 'ENTRADA') entradasHoy++;
      if (tipo === 'SALIDA') salidasHoy++;
    }

    if (conteoPorDia[fechaIso]) {
      if (tipo === 'ENTRADA') conteoPorDia[fechaIso].entradas++;
      if (tipo === 'SALIDA') conteoPorDia[fechaIso].salidas++;
    }

    // Rastrea la ultima fichada historica por legajo para el estado "En Planta".
    const ts = fechaObj.getTime();
    const prev = ultimaFichadaPorLegajo[legajo];
    if (!prev || ts >= prev.ts) {
      ultimaFichadaPorLegajo[legajo] = { ts, tipo };
    }
  });

  let enPlanta = 0;
  Object.values(ultimaFichadaPorLegajo).forEach(u => {
    if (u.tipo === 'ENTRADA') enPlanta++;
  });

  document.getElementById('kpiEntradasHoy').innerText = entradasHoy;
  document.getElementById('kpiSalidasHoy').innerText = salidasHoy;
  document.getElementById('kpiEnPlanta').innerText = enPlanta;
  document.getElementById('kpiTotalRegistros').innerText = registros.length;

  renderizarGraficoDona(enPlanta, salidasHoy);
  renderizarGraficoBarras(diasUltimaSemana, conteoPorDia);
}

async function renderizarGraficoDona(enPlanta, salidas) {
  await lazyChart();
  const ctx = document.getElementById('chartDonaHoy').getContext('2d');

  if (instChartDona) instChartDona.destroy();

  instChartDona = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['En Planta', 'Salidas Registradas'],
      datasets: [{
        data: [enPlanta, salidas],
        backgroundColor: ['#38bdf8', '#f43f5e'],
        borderWidth: 2,
        borderColor: '#1e293b'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#94a3b8', font: { size: 11 } }
        }
      }
    }
  });
}

async function renderizarGraficoBarras(diasKey, conteoPorDia) {
  await lazyChart();
  const ctx = document.getElementById('chartBarrasSemana').getContext('2d');

  const labels = diasKey.map(f => {
    const partes = f.split('-');
    return `${partes[2]}/${partes[1]}`;
  });

  const dataEntradas = diasKey.map(f => conteoPorDia[f].entradas);
  const dataSalidas = diasKey.map(f => conteoPorDia[f].salidas);

  if (instChartBarras) instChartBarras.destroy();

  instChartBarras = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Entradas',
          data: dataEntradas,
          backgroundColor: '#10b981',
          borderRadius: 6
        },
        {
          label: 'Salidas',
          data: dataSalidas,
          backgroundColor: '#f43f5e',
          borderRadius: 6
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: '#94a3b8' },
          grid: { display: false }
        },
        y: {
          ticks: { color: '#94a3b8', precision: 0 },
          grid: { color: '#334155' }
        }
      },
      plugins: {
        legend: {
          position: 'top',
          labels: { color: '#94a3b8', font: { size: 11 } }
        }
      }
    }
  });
}

function abrirFoto(url) {
  document.getElementById('imgModal').src = url;
  document.getElementById('modalFoto').classList.remove('hidden');
}

function cerrarModal() {
  document.getElementById('modalFoto').classList.add('hidden');
  document.getElementById('imgModal').src = "";
}

async function exportarExcel() {
  await lazyExport();
  if (!datosFiltradosActuales || datosFiltradosActuales.length === 0) {
    return alert("No hay datos visibles para exportar.");
  }

  const cabeceras = [["Fecha y Hora", "Legajo", "Nombre", "Objetivo", "Tipo", "Ubicación (Mapa)", "Foto URL"]];
  const filas = datosFiltradosActuales.map(f => [
    f[0] ? new Date(f[0]).toLocaleString('es-AR', { hour12: false }) : '',
    f[1] !== undefined ? String(f[1]) : '',
    f[2] || '',
    f[3] || '',
    f[4] || '',
    f[5] || '',
    f[6] || ''
  ]);

  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet([...cabeceras, ...filas]);
  XLSX.utils.book_append_sheet(wb, ws, "Marcaciones");
  XLSX.writeFile(wb, `Reporte_Marcaciones_${new Date().toISOString().slice(0,10)}.xlsx`);
}

async function exportarPDF() {
  await lazyExport();
  if (!datosFiltradosActuales || datosFiltradosActuales.length === 0) {
    return alert("No hay datos visibles para exportar.");
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  doc.setFontSize(16);
  doc.text("Reporte de Marcaciones de Asistencia", 14, 15);
  doc.setFontSize(10);
  doc.text(`Generado el: ${new Date().toLocaleString('es-AR', { hour12: false })}`, 14, 22);

  const columnas = ["Fecha y Hora", "Legajo", "Nombre", "Objetivo", "Tipo"];
  const filas = datosFiltradosActuales.map(f => [
    f[0] ? new Date(f[0]).toLocaleString('es-AR', { hour12: false }) : '',
    f[1] !== undefined ? String(f[1]) : '',
    f[2] || '',
    f[3] || '',
    f[4] || ''
  ]);

  doc.autoTable({
    head: [columnas],
    body: filas,
    startY: 28,
    theme: 'grid',
    headStyles: { fillColor: [15, 23, 42] },
    styles: { fontSize: 8 }
  });

  doc.save(`Reporte_Marcaciones_${new Date().toISOString().slice(0,10)}.pdf`);
}

// =============================================================================
//  [OPCIÓN A] ALERTAS DE RONDAS ATRASADAS (vigilancia del lado del cliente)
//  Lee objetivos + rondasRegistros (solo lectura) y detecta puntos de control
//  que debieron escanearse y aún no se marcaron dentro de su plazo
//  (frecuencia + tolerancia). Se evalúa en el navegador del supervisor mientras
//  el panel está abierto. El archivado queda en este dispositivo (localStorage).
//  NO escribe en Firebase ni toca el Worker SA-ONLY.
// =============================================================================
const CLAVE_ALERTAS_RONDAS_ARCHIVADAS = 'vigix_alertas_rondas_archivadas';
let alertasRondasDetectadas = [];

function leerArchivadasRondasLocal() {
  try { return JSON.parse(localStorage.getItem(CLAVE_ALERTAS_RONDAS_ARCHIVADAS) || '[]') || []; } catch (_) { return []; }
}
function guardarArchivadasRondasLocal(claves) {
  try { localStorage.setItem(CLAVE_ALERTAS_RONDAS_ARCHIVADAS, JSON.stringify(Array.from(new Set(claves)))); } catch (_) {}
}
function _rondaHhmmAMin(hhmm) {
  const m = /^(\d{1,2}):(\d{2})$/.exec(String(hhmm || '').trim());
  if (!m) return null;
  const h = parseInt(m[1], 10), mi = parseInt(m[2], 10);
  if (h < 0 || h > 23 || mi < 0 || mi > 59) return null;
  return h * 60 + mi;
}
// Devuelve {inicioMs, finMs} de la ventana de ronda ACTIVA ahora, o null.
// Soporta ventanas nocturnas que cruzan la medianoche (p. ej. 22:00 a 06:00).
function _ventanaRondaActiva(config, ahora) {
  const ini = _rondaHhmmAMin(config.horaInicio);
  const fin = _rondaHhmmAMin(config.horaFin);
  if (ini == null || fin == null || ini === fin) return null;
  const dias = Array.isArray(config.diasSemana) ? config.diasSemana.map(Number) : [];
  const nowMin = ahora.getHours() * 60 + ahora.getMinutes();
  const diaHoy = ahora.getDay();
  const base0 = new Date(ahora); base0.setHours(0, 0, 0, 0);
  const ms0 = base0.getTime();
  if (fin > ini) {
    if (dias.indexOf(diaHoy) !== -1 && nowMin >= ini && nowMin <= fin) {
      return { inicioMs: ms0 + ini * 60000, finMs: ms0 + fin * 60000 };
    }
    return null;
  }
  // Nocturna: tramo noche de HOY.
  if (dias.indexOf(diaHoy) !== -1 && nowMin >= ini) {
    return { inicioMs: ms0 + ini * 60000, finMs: ms0 + (24 * 60 + fin) * 60000 };
  }
  // Nocturna: tramo madrugada de HOY (la ronda empezó AYER).
  const diaAyer = (diaHoy + 6) % 7;
  if (dias.indexOf(diaAyer) !== -1 && nowMin <= fin) {
    return { inicioMs: ms0 - 24 * 60 * 60000 + ini * 60000, finMs: ms0 + fin * 60000 };
  }
  return null;
}

async function evaluarRondasAtrasadas() {
  const cont = document.getElementById('listaAlertasRondas');
  if (!cont) return;
  let objetivos = null, registros = null;
  try {
    [objetivos, registros] = await Promise.all([
      window.fetchConAuthPanel(`${URL_BASE_FIREBASE}/objetivos.json?ts=${Date.now()}`, { cache: 'no-store' }).then(r => r.ok ? r.json() : null).catch(() => null),
      window.fetchConAuthPanel(`${URL_BASE_FIREBASE}/rondasRegistros.json?ts=${Date.now()}`, { cache: 'no-store' }).then(r => r.ok ? r.json() : null).catch(() => null)
    ]);
  } catch (_) {}
  const ahora = new Date();
  const ahoraMs = ahora.getTime();
  // Último escaneo por objetivo+punto.
  const ultimoPorPunto = {};
  if (registros && typeof registros === 'object') {
    Object.values(registros).forEach(r => {
      if (!r || !r.idObjetivo || !r.idPunto || !r.timestamp) return;
      const t = new Date(r.timestamp).getTime();
      if (isNaN(t)) return;
      const k = `${r.idObjetivo}__${r.idPunto}`;
      if (!ultimoPorPunto[k] || t > ultimoPorPunto[k]) ultimoPorPunto[k] = t;
    });
  }
  const detectadas = [];
  if (objetivos && typeof objetivos === 'object') {
    const fechaClave = obtenerFechaLocalClave(ahora);
    Object.entries(objetivos).forEach(([idObj, obj]) => {
      if (!obj || !obj.rondas || !obj.rondas.config) return;
      const config = obj.rondas.config;
      if (config.activo !== true) return;
      const frecuencia = Number(config.frecuenciaMin) || 0;
      if (frecuencia <= 0) return; // sin cadencia definida: no se puede evaluar
      const tolerancia = Math.max(0, Number(config.toleranciaMin) || 0);
      const ventana = _ventanaRondaActiva(config, ahora);
      if (!ventana) return; // fuera de horario / día no activo: sin obligación
      const puntos = (obj.rondas.puntos && typeof obj.rondas.puntos === 'object') ? obj.rondas.puntos : {};
      const nombreObj = obj.nombre || idObj;
      Object.entries(puntos).forEach(([idPunto, punto]) => {
        if (!punto || punto.activo === false) return;
        const k = `${idObj}__${idPunto}`;
        let ultimo = ultimoPorPunto[k] || null;
        if (ultimo != null && ultimo < ventana.inicioMs) ultimo = null; // fuera de la ventana vigente
        const baseMs = ultimo != null ? ultimo : ventana.inicioMs;
        const limiteMs = baseMs + (frecuencia + tolerancia) * 60000;
        if (ahoraMs <= limiteMs) return; // dentro de plazo
        const atrasoMin = Math.round((ahoraMs - limiteMs) / 60000);
        const clave = [sanitizarClaveFirebase(idObj), sanitizarClaveFirebase(idPunto), sanitizarClaveFirebase(fechaClave)].join('__');
        detectadas.push({
          clave, idObjetivo: idObj, nombreObjetivo: nombreObj,
          idPunto, nombrePunto: punto.nombre || idPunto,
          nunca: ultimo == null, ultimoMs: ultimo, atrasoMin, frecuencia, tolerancia
        });
      });
    });
  }
  detectadas.sort((a, b) => b.atrasoMin - a.atrasoMin);
  alertasRondasDetectadas = detectadas;
  renderAlertasRondas();
}

function renderAlertasRondas() {
  const cont = document.getElementById('listaAlertasRondas');
  const contador = document.getElementById('contadorAlertasRondas');
  if (!cont) return;
  const chk = document.getElementById('chkMostrarArchivadasRondas');
  const mostrarArch = !!(chk && chk.checked);
  const archivadas = new Set(leerArchivadasRondasLocal());
  const visibles = alertasRondasDetectadas.filter(a => mostrarArch ? true : !archivadas.has(a.clave));
  const activas = alertasRondasDetectadas.filter(a => !archivadas.has(a.clave)).length;
  if (contador) {
    contador.textContent = String(activas);
    contador.classList.toggle('hidden', activas === 0);
  }
  if (!visibles.length) {
    cont.innerHTML = `<p class="text-sm text-slate-400 py-4 text-center"><i class="fa-solid fa-circle-check text-emerald-400"></i> No hay rondas atrasadas ${mostrarArch ? '' : 'pendientes '}en este momento.</p>`;
    return;
  }
  cont.innerHTML = '';
  visibles.forEach(a => {
    const estaArch = archivadas.has(a.clave);
    const colorBorde = estaArch ? 'border-slate-600' : (a.nunca ? 'border-rose-500/50' : 'border-amber-500/50');
    const ultimoTxt = a.ultimoMs ? new Date(a.ultimoMs).toLocaleString('es-AR', { hour12: false }) : 'Sin marcas en esta ronda';
    const estado = a.nunca
      ? '<span class="font-semibold text-rose-300">Nunca marcado en esta ronda</span>'
      : `<span class="font-semibold text-amber-300">Atrasado ${a.atrasoMin} min</span>`;
    const div = document.createElement('div');
    div.className = `flex flex-col md:flex-row md:items-center justify-between gap-2 bg-slate-900/70 border ${colorBorde} rounded-xl px-4 py-3 ${estaArch ? 'opacity-60' : ''}`;
    div.innerHTML = `
      <div class="flex items-start gap-3">
        <i class="fa-solid ${a.nunca ? 'fa-triangle-exclamation text-rose-400' : 'fa-hourglass-half text-amber-400'} mt-0.5"></i>
        <div class="text-xs">
          <p class="font-bold text-white">${escaparHtml(a.nombrePunto)} <span class="text-slate-400 font-normal">· ${escaparHtml(a.nombreObjetivo)}</span></p>
          <p class="text-slate-300">${estado} · Cada ${a.frecuencia} min (tol. ${a.tolerancia} min)</p>
          <p class="text-slate-400">Última marca: ${escaparHtml(ultimoTxt)}</p>
        </div>
      </div>
      <div class="flex-shrink-0">
        ${estaArch
          ? `<button type="button" data-accion-ronda="desarchivar" data-clave="${escaparHtml(a.clave)}" class="text-xs bg-slate-700 hover:bg-slate-600 text-slate-200 border border-slate-600 px-3 py-1.5 rounded-lg transition flex items-center gap-1.5"><i class="fa-solid fa-rotate-left"></i> Restaurar</button>`
          : `<button type="button" data-accion-ronda="archivar" data-clave="${escaparHtml(a.clave)}" class="text-xs bg-emerald-600/20 hover:bg-emerald-600/40 text-emerald-300 border border-emerald-500/40 px-3 py-1.5 rounded-lg transition flex items-center gap-1.5"><i class="fa-solid fa-box-archive"></i> Archivar</button>`}
      </div>`;
    cont.appendChild(div);
  });
}

function archivarAlertaRonda(clave) {
  const arch = new Set(leerArchivadasRondasLocal()); arch.add(clave);
  guardarArchivadasRondasLocal(Array.from(arch)); renderAlertasRondas();
}
function desarchivarAlertaRonda(clave) {
  const arch = new Set(leerArchivadasRondasLocal()); arch.delete(clave);
  guardarArchivadasRondasLocal(Array.from(arch)); renderAlertasRondas();
}
window.evaluarRondasAtrasadas = evaluarRondasAtrasadas;
window.renderAlertasRondas = renderAlertasRondas;
window.archivarAlertaRonda = archivarAlertaRonda;
window.desarchivarAlertaRonda = desarchivarAlertaRonda;

// =============================================================================
//  CABLEADO DE EVENTOS (CSP estricta: sin handlers inline en el HTML)
//  Reemplaza los antiguos onclick/onchange/onkeyup del panel.html por
//  addEventListener, y usa delegacion para los botones que se generan
//  dinamicamente dentro de las tablas / listas.
// =============================================================================
document.addEventListener('DOMContentLoaded', function () {
  const on = (id, evento, fn) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(evento, fn);
  };

  // --- Login supervisor ---
  const form = document.getElementById('formLoginSupervisor');
  if (form) form.addEventListener('submit', validarPassword);

  // --- Encabezado del panel ---
  on('btnActualizar', 'click', function () { cargarDatos(); });
  on('btnCerrarSesion', 'click', function () { cerrarSesion(); });

  // --- Alertas de supervision ---
  on('chkMostrarArchivadasSup', 'change', function () { renderAlertasSupervision(); });
  on('btnRefrescarAlertas', 'click', function () { cargarDatos(); });

  // --- Alertas de rondas atrasadas (Opcion A) ---
  on('chkMostrarArchivadasRondas', 'change', function () { renderAlertasRondas(); });
  on('btnRefrescarRondas', 'click', function () { evaluarRondasAtrasadas(); });

  // --- Auditoria de horas por empleado ---
  on('supFiltroMes', 'change', function () { aplicarFiltrosSupervisor(); });
  on('supFechaDesde', 'change', function () { aplicarFiltrosSupervisor(); });
  on('supFechaHasta', 'change', function () { aplicarFiltrosSupervisor(); });
  on('btnConsultarHoras', 'click', function () { consultarHorasSupervisor(); });
  on('btnExcelSupervisor', 'click', function () { exportarExcelSupervisor(); });
  on('btnPdfSupervisor', 'click', function () { exportarPdfSupervisor(); });

  // --- Filtros y exportacion general ---
  on('inputBusqueda', 'keyup', function () { filtrarTabla(); });
  on('fechaDesde', 'change', function () { filtrarTabla(); });
  on('fechaHasta', 'change', function () { filtrarTabla(); });
  on('filtroTipo', 'change', function () { filtrarTabla(); });
  on('chkMostrarAnuladas', 'change', function () { filtrarTabla(); });
  on('btnExcelGeneral', 'click', function () { exportarExcel(); });
  on('btnPdfGeneral', 'click', function () { exportarPDF(); });

  // --- Modal de foto ---
  on('btnCerrarModalFoto', 'click', function () { cerrarModal(); });

  // --- Delegacion: botones Archivar / Restaurar de las alertas ---
  const listaAlertas = document.getElementById('listaAlertasSupervision');
  if (listaAlertas) {
    listaAlertas.addEventListener('click', function (ev) {
      const btn = ev.target.closest('[data-accion-alerta]');
      if (!btn) return;
      const clave = btn.getAttribute('data-clave');
      if (btn.getAttribute('data-accion-alerta') === 'desarchivar') {
        desarchivarAlertaSupervision(clave);
      } else {
        archivarAlertaSupervision(clave);
      }
    });
  }

  // --- Delegacion: botones Archivar / Restaurar de las alertas de rondas ---
  const listaAlertasRondas = document.getElementById('listaAlertasRondas');
  if (listaAlertasRondas) {
    listaAlertasRondas.addEventListener('click', function (ev) {
      const btn = ev.target.closest('[data-accion-ronda]');
      if (!btn) return;
      const clave = btn.getAttribute('data-clave');
      if (btn.getAttribute('data-accion-ronda') === 'desarchivar') {
        desarchivarAlertaRonda(clave);
      } else {
        archivarAlertaRonda(clave);
      }
    });
  }

  // --- Delegacion: botones Ver Foto / Anular de la tabla de registros ---
  const cuerpoTabla = document.getElementById('cuerpoTabla');
  if (cuerpoTabla) {
    cuerpoTabla.addEventListener('click', function (ev) {
      const btn = ev.target.closest('[data-accion]');
      if (!btn) return;
      const accion = btn.getAttribute('data-accion');
      if (accion === 'ver-foto') {
        abrirFoto(btn.getAttribute('data-url'));
      } else if (accion === 'eliminar-fichada') {
        eliminarFichadaFirebase(btn.getAttribute('data-key'));
      }
    });
  }
});
