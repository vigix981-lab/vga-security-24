const URL_FIREBASE = "https://vga-security-24-default-rtdb.firebaseio.com";
// URL del Worker que sincroniza la clave de Firebase Auth al cambiar el PIN.
// Pegá acá la URL que te da Cloudflare (ej: https://vigix-auth-admin.TU-SUBDOMINIO.workers.dev).
// Si queda vacía, el cambio de PIN NO actualiza la clave de acceso (solo el hash local).
const URL_WORKER_AUTH = "https://vga-security-24.micasa27822024.workers.dev/";

// ============================================================================
//  [PLAN] TOPES POR PLAN CONTRATADO (indicadores + aviso de cupo en el panel)
//  El plan lo fija EL DUENO del servicio desde su panel exclusivo (super-admin
//  -> Worker, protegido por OWNER_KEY). Aqui el panel admin SOLO LEE el plan
//  (/config/plan, lectura permitida por Reglas) para: (a) mostrar "X / maximo"
//  y (b) avisar antes de intentar un alta. El candado DURO real vive en el
//  Worker (crearEmpleadoDatos + verificarCupo), no se puede saltear.
// ============================================================================
window.PLAN_VIGIX = null;

function nombreLegiblePlan(n) {
  var m = { esencial: 'Esencial', profesional: 'Profesional', empresa: 'Empresa', custom: 'A medida' };
  var k = String(n || '').toLowerCase();
  return m[k] || (n ? (String(n).charAt(0).toUpperCase() + String(n).slice(1)) : 'Esencial');
}

// Lee /config/plan + refresca indicadores. Nunca interrumpe la carga si falla.
async function cargarPlanApp() {
  try {
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/config/plan.json?ts=${Date.now()}`), { cache: 'no-store' });
    const p = await res.json();
    const maxVig = Number(p && p.maxVigiladores);
    const maxObj = Number(p && p.maxObjetivos);
    window.PLAN_VIGIX = {
      nombre: (p && p.nombre) ? String(p.nombre) : 'esencial',
      maxVigiladores: (Number.isFinite(maxVig) && maxVig >= 0) ? maxVig : 10,
      maxObjetivos: (Number.isFinite(maxObj) && maxObj >= 0) ? maxObj : 2,
      estado: (p && String(p.estado).toLowerCase() === 'suspendido') ? 'suspendido' : 'activo',
      funciones: (p && p.funciones && typeof p.funciones === 'object') ? p.funciones : {}
    };
  } catch (_) {
    window.PLAN_VIGIX = window.PLAN_VIGIX || { nombre: 'esencial', maxVigiladores: 10, maxObjetivos: 2, estado: 'activo', funciones: {} };
  }
  actualizarIndicadoresPlan();
  aplicarFuncionesUI();
}

// ¿El plan contratado incluye esta función opcional? (rondas, alertasIncidencias,
// rolesSupervision, exportarReportes, multiplesSedes, modoOffline).
function planTieneFuncion(nombre) {
  const fn = (window.PLAN_VIGIX && window.PLAN_VIGIX.funciones) || {};
  return !!fn[nombre];
}
window.planTieneFuncion = planTieneFuncion;

// Muestra u oculta en pantalla lo que depende de una función del plan.
// Convencion CSP-safe: cualquier elemento con data-plan-funcion="X" se oculta
// (clase 'hidden') si el plan no tiene la funcion X. Ademas, oculta el selector
// de rol cuando el plan no incluye "roles y supervision" (en Esencial todos los
// altas son vigiladores).
function aplicarFuncionesUI() {
  try {
    const marcados = document.querySelectorAll('[data-plan-funcion]');
    for (let i = 0; i < marcados.length; i++) {
      const el = marcados[i];
      const f = el.getAttribute('data-plan-funcion');
      el.classList.toggle('hidden', !planTieneFuncion(f));
    }
    // Selector de rol en el alta de empleados.
    const selRol = document.getElementById('altaRol');
    if (selRol) {
      const permite = planTieneFuncion('rolesSupervision');
      const cont = selRol.closest('div') || selRol.parentElement;
      if (cont) cont.classList.toggle('hidden', !permite);
      if (!permite) selRol.value = 'empleado';
    }
  } catch (_) {}
}
window.aplicarFuncionesUI = aplicarFuncionesUI;

// Pinta el badge del plan (encabezado) y los contadores "X / max" de los forms.
function actualizarIndicadoresPlan() {
  const plan = window.PLAN_VIGIX || { nombre: 'esencial', maxVigiladores: 10, maxObjetivos: 2, estado: 'activo' };
  const usadosVig = Array.isArray(datosPersonal) ? datosPersonal.length : 0;
  const usadosObj = Array.isArray(datosObjetivos) ? datosObjetivos.length : 0;
  const badge = document.getElementById('badgePlanApp');
  if (badge) {
    const sufijo = plan.estado === 'suspendido' ? ' · SUSPENDIDO' : '';
    badge.textContent = 'Plan ' + nombreLegiblePlan(plan.nombre) + sufijo;
    badge.classList.toggle('vigix-plan-suspendido', plan.estado === 'suspendido');
    badge.classList.remove('hidden');
  }
  const pintar = (idTxt, usados, max) => {
    const el = document.getElementById(idTxt);
    if (!el) return;
    const topeTxt = (max > 0) ? String(max) : '\u221E';
    el.textContent = usados + ' / ' + topeTxt;
    const lleno = (max > 0 && usados >= max);
    el.classList.toggle('vigix-cupo-lleno', lleno || plan.estado === 'suspendido');
    el.classList.remove('hidden');
  };
  pintar('cupoVigiladoresTxt', usadosVig, plan.maxVigiladores);
  pintar('cupoObjetivosTxt', usadosObj, plan.maxObjetivos);
}

// Consulta al Worker el cupo REAL (server-side) antes de un alta.
// tipo: 'vigilador' | 'objetivo'. Devuelve la respuesta del Worker o null si
// no se pudo consultar (en ese caso NO se bloquea: el candado duro del Worker
// sigue protegiendo el alta de vigiladores).
async function verificarCupoApp(tipo) {
  try {
    return await window.llamarWorkerAdmin({ accion: 'verificarCupo', tipo: tipo });
  } catch (e) {
    console.warn('No se pudo verificar el cupo del plan:', e);
    return null;
  }
}
window.cargarPlanApp = cargarPlanApp;
window.verificarCupoApp = verificarCupoApp;
window.actualizarIndicadoresPlan = actualizarIndicadoresPlan;

// --- REGISTRO DE AUDITORÍA (aditivo) ---
// Deja constancia inmutable en /auditoria de cada cambio crítico (borrado/edición) hecho por el admin.
// Usa el sello de tiempo del servidor y nunca interrumpe la operación principal si falla.

// ─────────────────────────────────────────────────────────────────────────────
//  CARGA BAJO DEMANDA DE LIBRERÍAS CDN PESADAS
//  Las librerías de exportación (xlsx ~600KB, jspdf+autotable ~350KB) y el
//  mapa (leaflet ~150KB) ya NO se cargan en el <head>. Se cargan recién
//  cuando el usuario hace clic en "Exportar" o abre el mapa.
//  Resultado: la página se muestra ~1.5MB más rápido.
// ─────────────────────────────────────────────────────────────────────────────

// CDN con SRI para carga bajo demanda (coinciden con los que estaban en <head>)
var LAZY_CDN = {
  leaflet:   { id:'leaflet',   src:'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js',                                 integrity:'sha512-BwHfrr4c9kmRkLw6iXFdzcdWV/PGkVgiIyIWLLlTSXzWQzxuSg4DiQUCpauz/EWjgk5TYQqX/kvn9pG1NpYfqg==' },
  xlsx:      { id:'xlsx',      src:'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js',             integrity:'sha512-r22gChDnGvBylk90+2e/ycr3RVrDi8DIOkIGNhJlKfuyQM4tIRAI062MaV8sfjQKYVGjOBaZBOA87z+IhZE9DA==' },
  jspdf:     { id:'jspdf',     src:'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',            integrity:'sha512-qZvrmS2ekKPF2mSznTQsxqPgnpkI4DNTlrdUmTzrDgektczlKNRRhy5X5AAOnx5S09ydFYWWNSfcEqDTTHgtNA==' },
  autotable: { id:'autotable', src:'https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.31/jspdf.plugin.autotable.min.js', integrity:'sha512-/cZZTKETbsuutvNXdPji/z8N+9e+LHq9D60JhcBCigq9I5a2VDEcLzml8PdVlVqzmWlVbhZCuTx+9CTi2xb30A==' }
};

// Carga leaflet bajo demanda. Devuelve una Promise.
function lazyLeaflet() {
  return window.cargarCDN(LAZY_CDN.leaflet.id, LAZY_CDN.leaflet.src, LAZY_CDN.leaflet.integrity);
}

// Carga xlsx+jspdf+autotable bajo demanda (en orden, autotable necesita jspdf).
var _lazyExportPromise = null;
function lazyExport() {
  if (_lazyExportPromise) return _lazyExportPromise;
  _lazyExportPromise = window.cargarLoteCDN([
    LAZY_CDN.xlsx,
    LAZY_CDN.jspdf,
    LAZY_CDN.autotable
  ]);
  return _lazyExportPromise;
}

async function registrarAuditoria(accion, entidad, detalle) {
  try {
    // MIGRADO A SERVER-SIDE: el Worker autoritativo valida el idToken + rol
    // admin y escribe en /auditoria con la service account. Ya no se hace
    // POST directo a Firebase (las reglas endurecidas lo impiden).
    // Se divide 'entidad' (puede venir como "coleccion/id") en entidad + id.
    const entidadStr = String(entidad || 'manual');
    const idx = entidadStr.indexOf('/');
    const entidadNombre = idx >= 0 ? entidadStr.slice(0, idx) : entidadStr;
    const entidadId = idx >= 0 ? entidadStr.slice(idx + 1) : '';
    await window.llamarWorkerAdmin({
      accion: 'auditarEvento',
      eventoAccion: String(accion || ''),
      entidad: entidadNombre,
      entidadId: entidadId,
      detalle: (detalle && typeof detalle === 'object') ? detalle : { texto: String(detalle || '') }
    });
  } catch (err) {
    console.warn('No se pudo registrar el evento de auditoría:', err);
    // Aviso visible, como maximo 1 vez por minuto, sin interrumpir la operacion en curso.
    const ahoraAud = Date.now();
    if (!window.__ultimoAvisoAuditoria || ahoraAud - window.__ultimoAvisoAuditoria > 60000) {
      window.__ultimoAvisoAuditoria = ahoraAud;
      setTimeout(() => alert('⚠️ La acción se realizó, pero NO quedó registrada en la auditoría. Avisá al responsable técnico.'), 0);
    }
  }
}

let datosMarcaciones = [];
let datosNovedades = [];
let datosPanicos = [];
let datosFiltradosNovedades = [];
let datosFiltradosMarcaciones = [];
// Estado de paginación de la tabla de marcaciones (aditivo).
let paginaActualMarcaciones = 1;
let filasPorPaginaMarcaciones = 25;
let datosPersonal = [];
let mapaRolesUsuarios = {};  // uid -> rol ('empleado' | 'supervisor' | 'admin'). Para separar la lista.
let datosObjetivos = [];
let mapaConfiguracionPersonal = {};
let asignacionesTurnosAdmin = [];
let asignacionesTurnosGlobalAdmin = [];
let personalConfigurandoId = null;
let registroFraudeSeleccionado = null;

// --- MÓDULO DE SONIDO Y ESCUCHA DE PÁNICO EN TIEMPO REAL ---
let audioCtxPanico = null;
let osc1 = null;
let osc2 = null;
let panicoInterval = null;
let panicoActivoActualId = null;
let intervaloPanicoPoll = null;
let intervaloAlertasFichadas = null;
let alertasFichadasCache = [];
let alertasFichadasConocidas = new Set();
let alertasFichadasInicializadas = false;
// Configuración global de reglas laborales y radio de fichaje (persistida en Firebase /configuracionGlobal).
let configGlobalAdmin = { toleranciaIngresoMin: 15, toleranciaEgresoMin: 30, radioFichajeMetros: 100, modoDispositivo: 'compartido', biometriaEstricta: false, precisionMaximaMetros: 0, offlineHabilitado: false, ventanaLoteOfflineHoras: 168, antiReplaySegundos: 90, skewRelojOfflineSegundos: 300 };

function iniciarSonidoSirena() {
  if (audioCtxPanico) return; 
  try {
    audioCtxPanico = new (window.AudioContext || window.webkitAudioContext)();
    
    osc1 = audioCtxPanico.createOscillator();
    osc2 = audioCtxPanico.createOscillator();
    const gain = audioCtxPanico.createGain();

    osc1.type = 'sawtooth';
    osc2.type = 'sine';

    osc1.frequency.setValueAtTime(800, audioCtxPanico.currentTime);
    osc2.frequency.setValueAtTime(600, audioCtxPanico.currentTime);

    gain.gain.setValueAtTime(0.3, audioCtxPanico.currentTime);

    osc1.connect(gain);
    osc2.connect(gain);
    gain.connect(audioCtxPanico.destination);

    osc1.start();
    osc2.start();

    let toggle = false;
    panicoInterval = setInterval(() => {
      if (!audioCtxPanico) return;
      toggle = !toggle;
      osc1.frequency.setValueAtTime(toggle ? 950 : 600, audioCtxPanico.currentTime);
      osc2.frequency.setValueAtTime(toggle ? 750 : 450, audioCtxPanico.currentTime);
    }, 400);
  } catch (e) {
    console.error("Error iniciando sonido de sirena:", e);
  }
}

function detenerSonidoSirena() {
  if (panicoInterval) clearInterval(panicoInterval);
  if (osc1) { try { osc1.stop(); } catch(e){} }
  if (osc2) { try { osc2.stop(); } catch(e){} }
  if (audioCtxPanico) { try { audioCtxPanico.close(); } catch(e){} }
  audioCtxPanico = null;
  osc1 = null;
  osc2 = null;
  panicoInterval = null;
}

// Sistema de sondeo por intervalos optimizado para GitHub Pages
function escucharAlertasPanicoSSE() {
  if (intervaloPanicoPoll) clearInterval(intervaloPanicoPoll);
  
  intervaloPanicoPoll = setInterval(async () => {
    try {
      const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/panicos.json`));
      const panicosObj = await res.json();
      
      if (!panicosObj) return;

      let keys = Object.keys(panicosObj);
      for (let id of keys) {
        let p = panicosObj[id];
        // Si hay un pánico pendiente o activo
        if (p && (p.estado === 'PENDIENTE' || p.estado === 'ACTIVO')) {
          if (panicoActivoActualId !== id) {
            activarModalPanico(id, p);
          }
          break; 
        }
      }
    } catch (err) {
      console.warn("Error consultando pánicos:", err);
    }
  }, 3000);
}

function activarModalPanico(id, datos) {
  panicoActivoActualId = id;
  document.getElementById('panicoNombre').innerText = datos.nombre || 'Vigilador No Especificado';
  document.getElementById('panicoDetalle').innerText = `Legajo: ${datos.legajo || '-'} | Objetivo: ${datos.objetivo || '-'}`;
  
  const horaStr = datos.fechaHora ? new Date(datos.fechaHora).toLocaleString('es-AR', { hour12: false }) : ((datos.timestampServidor || datos.timestampEstimadoDispositivo || datos.timestamp) ? new Date(datos.timestampServidor || datos.timestampEstimadoDispositivo || datos.timestamp).toLocaleString('es-AR', { hour12: false }) : new Date().toLocaleString('es-AR', { hour12: false }));
  document.getElementById('panicoHora').innerText = `Activado a las: ${horaStr}`;

  const linkGps = document.getElementById('panicoMapaUrl');
  if (datos.latitud && datos.longitud) {
    linkGps.href = `https://maps.google.com/?q=${datos.latitud},${datos.longitud}`;
    document.getElementById('panicoUbicacionBox').classList.remove('hidden');
  } else {
    document.getElementById('panicoUbicacionBox').classList.add('hidden');
  }

  document.getElementById('modalPanicoAdmin').classList.remove('hidden');
  iniciarSonidoSirena();
}

async function apagarAlertaPanico() {
  detenerSonidoSirena();
  document.getElementById('modalPanicoAdmin').classList.add('hidden');

  if (panicoActivoActualId) {
    try {
      // MIGRADO A SERVER-SIDE: el Worker marca el panico como ATENDIDO y
      // registra la auditoria atomicamente con la service account.
      await window.llamarWorkerAdmin({ accion: 'atenderPanico', panicoId: panicoActivoActualId, estado: 'ATENDIDO', nota: '' });
    } catch (e) {
      console.error("Error resolviendo pánico en el Worker:", e);
    }
    panicoActivoActualId = null;
    recargarDatosEfectivo();
  }
}

// --- ALERTAS DE FICHADAS BLOQUEADAS POR GEO-CERCA ---
function iniciarEscuchaAlertasFichadas() {
  if (intervaloAlertasFichadas) clearInterval(intervaloAlertasFichadas);
  cargarAlertasFichadas(true);
  intervaloAlertasFichadas = setInterval(() => cargarAlertasFichadas(false), 5000);
}

async function cargarAlertasFichadas(esCargaInicial = false) {
  try {
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/alertasFichadas.json?ts=${Date.now()}`), { cache: 'no-store' });
    if (!res.ok) throw new Error('No se pudieron consultar las alertas.');
    const data = await res.json();
    const lista = [];

    if (data) {
      Object.keys(data).forEach(id => {
        const a = data[id];
        if (a) lista.push({ id, ...a });
      });
    }

    lista.sort((a, b) => new Date(b.fechaHora || 0) - new Date(a.fechaHora || 0));
    alertasFichadasCache = lista;
    actualizarBadgeAlertasFichadas();
    renderizarAlertasFichadas(lista);

    if (!alertasFichadasInicializadas || esCargaInicial) {
      lista.forEach(a => alertasFichadasConocidas.add(a.id));
      alertasFichadasInicializadas = true;
      return;
    }

    const nuevas = lista.filter(a => !alertasFichadasConocidas.has(a.id));
    nuevas.forEach(a => {
      alertasFichadasConocidas.add(a.id);
      notificarNuevaAlertaFichada(a);
    });
  } catch (err) {
    console.warn('Error consultando alertas de fichadas:', err);
  }
}

function actualizarBadgeAlertasFichadas() {
  const badge = document.getElementById('badgeAlertasFichadas');
  if (!badge) return;
  const pendientes = alertasFichadasCache.filter(a => a.vistoAdmin !== true && a.estado !== 'ATENDIDA').length;
  badge.innerText = pendientes > 99 ? '99+' : String(pendientes);
  badge.classList.toggle('hidden', pendientes === 0);
  badge.classList.toggle('flex', pendientes > 0);
  const badgeTab = document.getElementById('badgeAlertasTab');
  if (badgeTab) {
    badgeTab.innerText = pendientes > 99 ? '99+' : String(pendientes);
    badgeTab.classList.toggle('hidden', pendientes === 0);
    badgeTab.classList.toggle('flex', pendientes > 0);
  }
}

function formatearFechaAlerta(fecha) {
  if (!fecha) return '-';
  const d = new Date(fecha);
  return isNaN(d.getTime()) ? '-' : d.toLocaleString('es-AR', { hour12: false });
}

function formatearDistanciaAlerta(metros) {
  const n = Number(metros);
  if (!Number.isFinite(n)) return '-';
  if (n < 1000) return `${Math.round(n)} m`;
  return `${(n / 1000).toFixed(2).replace('.', ',')} km (${Math.round(n).toLocaleString('es-AR')} m)`;
}

function renderizarAlertasFichadas(lista) {
  const cont = document.getElementById('listaAlertasFichadas');
  if (!cont) return;
  if (!lista.length) {
    cont.innerHTML = `<div class="p-6 text-center text-slate-400 text-sm">No hay alertas de fichadas bloqueadas.</div>`;
    return;
  }

  const htmlAlertas = lista.slice(0, 100).map(a => {
    const vista = a.vistoAdmin === true;
    const mapa = (Number.isFinite(Number(a.latitud)) && Number.isFinite(Number(a.longitud)))
      ? `https://maps.google.com/?q=${a.latitud},${a.longitud}` : '';
    return `<div class="p-3 rounded-xl border ${vista ? 'border-slate-700 bg-slate-800/60' : 'border-rose-500/40 bg-rose-950/20'}">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-2">
        <div>
          <div class="flex items-center gap-2">
            <span class="text-sm font-bold text-white">${escaparHtml(a.nombre || 'Sin nombre')}</span>
            ${vista ? '<span class="text-[10px] text-slate-500 uppercase">Vista</span>' : '<span class="text-[10px] font-black text-rose-400 uppercase">Nueva</span>'}
          </div>
          <p class="text-xs text-slate-400 mt-1">Legajo: ${escaparHtml(a.legajo || '-')} · ${escaparHtml(a.tipoFichada || '-')} · ${formatearFechaAlerta(a.fechaHora)}</p>
          <p class="text-xs text-slate-300 mt-1">Objetivo: <strong>${escaparHtml(a.objetivo || '-')}</strong></p>
        </div>
        <div class="text-left md:text-right">
          <p class="text-sm font-black text-rose-300">${formatearDistanciaAlerta(a.distanciaMetros)}</p>
          <p class="text-[11px] text-slate-400">Radio permitido: ${Math.round(Number(a.radioPermitidoMetros) || 100)} m</p>
        </div>
      </div>
      <div class="mt-2 flex flex-wrap gap-2">
        ${mapa ? `<a href="${escaparHtml(mapa)}" target="_blank" class="text-xs text-sky-400 hover:underline"><i class="fa-solid fa-map-location-dot"></i> Ver ubicación</a>` : ''}
        <span class="text-xs text-slate-500">${escaparHtml(a.mensaje || 'Fichada bloqueada por ubicación')}</span>
      </div>
    </div>`;
  }).join('');
  cont.innerHTML = htmlAlertas;
  const historial = document.getElementById('listaAlertasFichadasHistorial');
  if (historial) historial.innerHTML = htmlAlertas;
}

function abrirModalAlertasFichadas() {
  document.getElementById('modalAlertasFichadas').classList.remove('hidden');
  cargarAlertasFichadas(false);
}

function cerrarModalAlertasFichadas() {
  document.getElementById('modalAlertasFichadas').classList.add('hidden');
}

async function marcarTodasAlertasFichadasVistas() {
  const pendientes = alertasFichadasCache.filter(a => a.vistoAdmin !== true && a.estado !== 'ATENDIDA');
  if (!pendientes.length) return;
  try {
    await Promise.all(pendientes.map(async a => fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/alertasFichadas/${a.id}.json`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vistoAdmin: true, vistoEn: new Date().toISOString() })
    })));
    await cargarAlertasFichadas(false);
  } catch (err) {
    alert('No se pudieron actualizar todas las alertas.');
  }
}

async function solicitarNotificacionesNavegador() {
  if (!('Notification' in window)) {
    alert('Este navegador no admite notificaciones de escritorio.');
    return;
  }
  const permiso = await Notification.requestPermission();
  if (permiso === 'granted') {
    alert('Avisos del navegador activados.');
  } else {
    alert('El navegador no concedió permiso para mostrar avisos.');
  }
}

function notificarNuevaAlertaFichada(alerta) {
  const titulo = '🚨 Alerta de fichada';
  const cuerpo = `${alerta.nombre || 'Empleado'} está a ${formatearDistanciaAlerta(alerta.distanciaMetros)} de ${alerta.objetivo || 'su objetivo'}. Fichada bloqueada.`;

  const modal = document.getElementById('modalAlertasFichadas');
  if (modal && modal.classList.contains('hidden')) {
    const btn = document.getElementById('btnAlertasFichadas');
    if (btn) {
      btn.classList.add('animate-pulse');
      setTimeout(() => btn.classList.remove('animate-pulse'), 5000);
    }
  }

  if ('Notification' in window && Notification.permission === 'granted') {
    try {
      new Notification(titulo, { body: cuerpo, tag: `alerta-fichada-${alerta.id}` });
    } catch (e) {}
  }
}

window.onload = function() {
  generarPinEmpleado();
  initInlineHandlers();
  // La restauracion de sesion la decide Firebase Auth (onAuthStateChanged),
  // NO un flag editable en sessionStorage. Ver listener en el modulo Firebase.
};

// Genera un PIN aleatorio de 6 digitos para el alta de empleado con acceso.
// (Antes eran 4 digitos = 9000 combinaciones; ahora son 6 digitos reales =
// 900000 combinaciones, segun recomendacion de la auditoria A5.)
// Usa crypto.getRandomValues (CSPRNG) en vez de Math.random (no seguro,
// predecible). Muestreo por rechazo para eliminar el sesgo por modulo:
// se descartan los valores del tramo superior que no reparten parejo entre
// los 900000 PIN posibles (100000-999999), asi cada PIN es equiprobable.
// Compatibilidad: el login completa el PIN a 6 con padStart(6,'0'), por lo que
// los PIN viejos de 4 digitos (p.ej. 3456 -> 003456) siguen funcionando igual.
function generarPinEmpleado() {
  const RANGO = 900000; // 999999 - 100000 + 1
  const LIMITE = Math.floor(0x100000000 / RANGO) * RANGO; // umbral anti-sesgo
  const buf = new Uint32Array(1);
  let n, pin;
  // Reintenta hasta obtener un PIN que ademas pase el filtro de fortaleza
  // (descarta por azar 1234, 111111, 123456, etc.), manteniendo equiprobabilidad.
  do {
    do {
      crypto.getRandomValues(buf);
      n = buf[0];
    } while (n >= LIMITE);
    pin = String(100000 + (n % RANGO));
  } while (window.validarFortalezaPin && !window.validarFortalezaPin(pin).ok);
  const inputPin = document.getElementById('altaPin');
  if (inputPin) inputPin.value = pin;
}

// ────────────────────────────────────────────────────────────────────────────
//  COMPROBANTE DE CREDENCIALES (PIN) — patron "mostrar una sola vez".
//  El PIN NUNCA se guarda en texto plano. En el UNICO instante en que se
//  conoce (alta o cambio de PIN, dentro del navegador del admin) se muestra
//  este comprobante para descargarlo en PDF / imprimirlo / copiarlo y
//  entregarselo al empleado. No se persiste en ningun lado: si se pierde, se
//  resetea el PIN desde "Configurar" y se reemite. Asi se tiene un registro
//  entregable SIN crear la vulnerabilidad de almacenar PINs recuperables.
// ────────────────────────────────────────────────────────────────────────────
var _comprobantePinActual = null;

function etiquetaRolComprobante(rol) {
  return rol === 'admin' ? 'Administrador'
       : rol === 'supervisor' ? 'Supervisor'
       : 'Empleado (vigilador)';
}

// Abre el comprobante con los datos recien generados. 'modo': 'alta' | 'cambio'.
function mostrarComprobantePin(datos) {
  datos = datos || {};
  const pin = String(datos.pin || '').trim();
  const legajo = String(datos.legajo || '').trim();
  const nombre = String(datos.nombre || '').trim();
  const rol = String(datos.rol || 'empleado').trim();
  const modo = datos.modo === 'cambio' ? 'cambio' : 'alta';
  const fecha = new Date().toLocaleString('es-AR', { hour12: false });
  _comprobantePinActual = { pin, legajo, nombre, rol, modo, fecha };

  const modal = document.getElementById('modalComprobantePin');
  if (!modal) { // Fallback si esta version del HTML no tiene el modal.
    alert('PIN de ' + nombre + ' (legajo ' + legajo + '): ' + pin + '\n\nAnotalo AHORA: no se vuelve a mostrar.');
    return;
  }
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  set('comprobanteNombre', nombre || '—');
  set('comprobanteLegajo', legajo || '—');
  set('comprobantePin', pin || '—');
  set('comprobanteRol', etiquetaRolComprobante(rol));
  set('comprobanteFecha', fecha);
  const titulo = document.getElementById('comprobanteTitulo');
  if (titulo) titulo.textContent = modo === 'cambio' ? 'PIN actualizado' : 'Nuevo acceso creado';
  modal.classList.remove('hidden');
}
window.mostrarComprobantePin = mostrarComprobantePin;

function cerrarComprobantePin() {
  const modal = document.getElementById('modalComprobantePin');
  if (modal) modal.classList.add('hidden');
  _comprobantePinActual = null;
}

function copiarComprobantePin() {
  if (!_comprobantePinActual) return;
  const d = _comprobantePinActual;
  const texto = 'Acceso vga security 24 - Control operativo y asistencia\n'
    + 'Nombre: ' + d.nombre + '\n'
    + 'Legajo: ' + d.legajo + '\n'
    + 'PIN: ' + d.pin + '\n'
    + 'Rol: ' + etiquetaRolComprobante(d.rol) + '\n'
    + 'Emitido: ' + d.fecha;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(texto).then(function(){ avisarCopiaComprobante(true); }, function(){ avisarCopiaComprobante(false); });
  } else {
    avisarCopiaComprobante(false);
  }
}

function avisarCopiaComprobante(ok) {
  const btn = document.getElementById('btnComprobanteCopiar');
  if (!btn) return;
  if (!btn.dataset.orig) btn.dataset.orig = btn.innerHTML;
  btn.innerHTML = ok ? '<i class="fa-solid fa-check"></i> ¡Copiado!' : '<i class="fa-solid fa-triangle-exclamation"></i> Copialo a mano';
  setTimeout(function(){ btn.innerHTML = btn.dataset.orig; }, 2500);
}

// Imprime SOLO el comprobante (CSS @media print en styles.css lo aisla).
function imprimirComprobantePin() {
  document.body.classList.add('print-comprobante');
  const limpiar = function(){ document.body.classList.remove('print-comprobante'); window.removeEventListener('afterprint', limpiar); };
  window.addEventListener('afterprint', limpiar);
  setTimeout(function(){ try { window.print(); } catch (e) {} setTimeout(limpiar, 1500); }, 50);
}

// Genera un PDF descargable con jsPDF (ya se usa para los reportes).
async function descargarComprobantePinPDF() {
  if (!_comprobantePinActual) return;
  const d = _comprobantePinActual;
  const btn = document.getElementById('btnComprobantePDF');
  const original = btn ? btn.innerHTML : '';
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generando...'; }
  try {
    await lazyExport();
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.setDrawColor(16, 185, 129); doc.setLineWidth(0.8); doc.rect(14, 16, 182, 112);
    doc.setFontSize(10); doc.setTextColor(16, 185, 129);
    doc.text('DEMO ASISTENCIA S.A. · VIGIX', 20, 26);
    doc.setFontSize(18); doc.setTextColor(20, 20, 20);
    doc.text('Comprobante de acceso', 20, 38);
    doc.setFontSize(10); doc.setTextColor(90, 90, 90);
    doc.text('Entregar al empleado. Documento confidencial.', 20, 45);
    doc.setDrawColor(220); doc.line(20, 50, 190, 50);
    doc.setFontSize(12);
    let y = 62;
    const fila = function(etq, val){ doc.setTextColor(120,120,120); doc.text(etq, 20, y); doc.setTextColor(20,20,20); doc.text(String(val || '—'), 70, y); y += 11; };
    fila('Nombre:', d.nombre);
    fila('Legajo:', d.legajo);
    fila('Rol:', etiquetaRolComprobante(d.rol));
    doc.setTextColor(120,120,120); doc.text('PIN de acceso:', 20, y);
    doc.setFontSize(22); doc.setTextColor(16, 120, 80); doc.text(String(d.pin || '—'), 70, y + 1);
    doc.setFontSize(9); y += 14;
    doc.setTextColor(120,120,120); doc.text('Emitido: ' + d.fecha, 20, y);
    doc.setFontSize(8); doc.setTextColor(140,140,140);
    doc.text('El PIN no se almacena en texto plano. Si se extravia, el administrador puede resetearlo y', 20, 118);
    doc.text('reemitir este comprobante. Ingreso del empleado: legajo + PIN.', 20, 122);
    const nombreArch = ('Acceso_' + (d.legajo || 'empleado') + '_' + new Date().toISOString().slice(0,10) + '.pdf').replace(/[^\w.\-]+/g, '_');
    doc.save(nombreArch);
  } catch (e) {
    alert('No se pudo generar el PDF: ' + ((e && e.message) || e) + '\nPodes imprimir o copiar los datos como alternativa.');
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = original; }
  }
}

function validarPasswordAdmin(e) {
  e.preventDefault();
  let email = (document.getElementById('inputEmailAdmin') ? document.getElementById('inputEmailAdmin').value : '').trim();
  // Ingreso simplificado: si la persona escribio SOLO el legajo (sin "@"), le
  // agregamos el dominio sintetico que usan los usuarios creados desde el panel
  // ("legajo@vga.security24"). Si escribio un correo completo (ej: admin@vigix.com,
  // creados a mano en la base), se respeta tal cual. Asi conviven ambos.
  if (email && email.indexOf('@') === -1) email = email + '@vga.security24';
  const input = document.getElementById('inputPassAdmin').value;
  const errorMsg = document.getElementById('msgErrorPassAdmin');
  errorMsg.classList.add('hidden');

  // --- Login REAL con Firebase Auth (correo + contraseña) ---
  if (typeof window.loginAdminReal === 'function') {
    const btnLogin = e.target ? e.target.querySelector('button[type="submit"]') : null;
    if (btnLogin) btnLogin.disabled = true;
    // Watchdog: si por algún motivo (conexión trabada en el celular) el login
    // no responde, reactivamos el botón y avisamos, para que nunca quede
    // "sin hacer nada" sin poder reintentar.
    let resuelto = false;
    const watchdog = setTimeout(function () {
      if (resuelto) return;
      if (btnLogin) btnLogin.disabled = false;
      errorMsg.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Está tardando más de lo normal. Revisá tu conexión y volvé a intentar.';
      errorMsg.classList.remove('hidden');
    }, 20000);
    window.loginAdminReal(email, input).then(function(res) {
      resuelto = true;
      clearTimeout(watchdog);
      if (btnLogin) btnLogin.disabled = false;
      if (res && res.ok) {
        sessionStorage.setItem('auth_admin', 'true');
        if (res.rol) sessionStorage.setItem('rol_admin', res.rol);
        if (res.uid) sessionStorage.setItem('uid_admin', res.uid);
        if (email) sessionStorage.setItem('email_admin', email);
        mostrarAdmin();
      } else {
        // El Worker ya aplica el bloqueo y arma el mensaje (bloqueo o intentos
        // restantes). El cliente solo lo muestra.
        errorMsg.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> ' + ((res && res.mensaje) || 'Correo o contraseña incorrectos.');
        errorMsg.classList.remove('hidden');
        document.getElementById('inputPassAdmin').value = '';
        document.getElementById('inputPassAdmin').focus();
      }
    }).catch(function () {
      resuelto = true;
      clearTimeout(watchdog);
      if (btnLogin) btnLogin.disabled = false;
      errorMsg.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> No se pudo completar el acceso. Revisá tu conexión y reintentá.';
      errorMsg.classList.remove('hidden');
    });
    return;
  }

  // El sistema de login aún no terminó de cargar (sin conexión o CDN de Firebase no disponible)
  errorMsg.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> El sistema de acceso está cargando. Verificá tu conexión y reintentá en unos segundos.';
  errorMsg.classList.remove('hidden');
}

function mostrarAdmin() {
  document.getElementById('pantallaLoginAdmin').classList.add('hidden');
  document.getElementById('contenidoAdmin').classList.remove('hidden');
  recargarDatosEfectivo();
  escucharAlertasPanicoSSE();
  iniciarEscuchaAlertasFichadas();
}

function cerrarSesionAdmin() {
  sessionStorage.removeItem('auth_admin');
  sessionStorage.removeItem('rol_admin');
  sessionStorage.removeItem('uid_admin');
  sessionStorage.removeItem('email_admin');
  if (intervaloPanicoPoll) clearInterval(intervaloPanicoPoll);
  if (intervaloAlertasFichadas) clearInterval(intervaloAlertasFichadas);
  detenerSonidoSirena();
  // IMPORTANTE: esperamos a que Firebase cierre la sesion (signOut) ANTES de
  // recargar. Si recargaramos antes de que termine, la sesion podria quedar
  // a medio cerrar y el panel volveria a mostrarse (o quedaria en un estado
  // roto que obligaba a borrar el historial para poder reingresar).
  function finalizar() { location.reload(); }
  if (typeof window.logoutAdminReal === 'function') {
    try {
      const p = window.logoutAdminReal();
      if (p && typeof p.then === 'function') { p.then(finalizar).catch(finalizar); }
      else { finalizar(); }
    } catch (_) { finalizar(); }
  } else {
    finalizar();
  }
}

function cambiarTab(tab) {
  document.getElementById('tabMarcaciones').classList.add('hidden');
  document.getElementById('tabNovedades').classList.add('hidden');
  document.getElementById('tabAlertasUbicacion').classList.add('hidden');
  document.getElementById('tabPanicos').classList.add('hidden');
  document.getElementById('tabPersonal').classList.add('hidden');
  document.getElementById('tabObjetivos').classList.add('hidden');
  document.getElementById('tabDispositivos').classList.add('hidden');
  document.getElementById('tabConfiguracion').classList.add('hidden');
  { var _tRR = document.getElementById('tabRondasReporte'); if (_tRR) _tRR.classList.add('hidden'); }

  document.getElementById('tabBtnMarcaciones').className = "px-5 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition";
  document.getElementById('tabBtnAlertasUbicacion').className = "px-5 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition";
  document.getElementById('tabBtnNovedades').className = "px-5 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition";
  document.getElementById('tabBtnPanicos').className = "px-5 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition";
  document.getElementById('tabBtnPersonal').className = "px-5 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition";
  document.getElementById('tabBtnObjetivos').className = "px-5 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition";

  document.getElementById('tabBtnDispositivos').className = "px-5 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition";
  document.getElementById('tabBtnConfiguracion').className = "px-5 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition";
  { var _bRR = document.getElementById('tabBtnRondasReporte'); if (_bRR) _bRR.className = "px-5 py-3 font-semibold text-sm border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition"; }
  if (tab === 'marcaciones') {
    document.getElementById('tabMarcaciones').classList.remove('hidden');
    document.getElementById('tabBtnMarcaciones').className = "px-5 py-3 font-semibold text-sm border-b-2 border-emerald-500 text-emerald-400 flex items-center gap-2 transition";
  } else if (tab === 'alertasUbicacion') {
    document.getElementById('tabAlertasUbicacion').classList.remove('hidden');
    document.getElementById('tabBtnAlertasUbicacion').className = "px-5 py-3 font-semibold text-sm border-b-2 border-rose-500 text-rose-400 flex items-center gap-2 transition";
    cargarAlertasFichadas(false);
  } else if (tab === 'novedades') {
    document.getElementById('tabNovedades').classList.remove('hidden');
    document.getElementById('tabBtnNovedades').className = "px-5 py-3 font-semibold text-sm border-b-2 border-amber-500 text-amber-400 flex items-center gap-2 transition";
  } else if (tab === 'panicos') {
    document.getElementById('tabPanicos').classList.remove('hidden');
    document.getElementById('tabBtnPanicos').className = "px-5 py-3 font-semibold text-sm border-b-2 border-rose-500 text-rose-400 flex items-center gap-2 transition";
  } else if (tab === 'personal') {
    document.getElementById('tabPersonal').classList.remove('hidden');
    document.getElementById('tabBtnPersonal').className = "px-5 py-3 font-semibold text-sm border-b-2 border-amber-500 text-amber-400 flex items-center gap-2 transition";
  } else if (tab === 'objetivos') {
    document.getElementById('tabObjetivos').classList.remove('hidden');
    document.getElementById('tabBtnObjetivos').className = "px-5 py-3 font-semibold text-sm border-b-2 border-sky-500 text-sky-400 flex items-center gap-2 transition";
  } else if (tab === 'dispositivos') {
    document.getElementById('tabDispositivos').classList.remove('hidden');
    document.getElementById('tabBtnDispositivos').className = "px-5 py-3 font-semibold text-sm border-b-2 border-emerald-500 text-emerald-400 flex items-center gap-2 transition";
    aplicarConfigGlobalAInputs();
    cargarDispositivos();
  } else if (tab === 'configuracion') {
    document.getElementById('tabConfiguracion').classList.remove('hidden');
    document.getElementById('tabBtnConfiguracion').className = "px-5 py-3 font-semibold text-sm border-b-2 border-emerald-500 text-emerald-400 flex items-center gap-2 transition";
    aplicarConfigGlobalAInputs();
  } else if (tab === 'rondasReporte') {
    document.getElementById('tabRondasReporte').classList.remove('hidden');
    document.getElementById('tabBtnRondasReporte').className = "px-5 py-3 font-semibold text-sm border-b-2 border-emerald-500 text-emerald-400 flex items-center gap-2 transition";
    cargarReporteRondas();
  }
  // [PLAN] cambiarTab() reescribe por completo el className de cada boton de
  // pestana (para pintar la activa), lo que BORRA la clase 'hidden' que puso
  // aplicarFuncionesUI(). Por eso re-aplicamos las funciones del plan al final:
  // las pestanas no incluidas en el plan vuelven a ocultarse al cambiar de tab.
  aplicarFuncionesUI();
}

// ===================================================================
//  PASO 3 - REPORTE DE RONDAS (admin / supervisor)   [ADITIVO, SOLO LECTURA]
//  Lee el nodo rondasRegistros (append-only, lo que escanea el vigilador) y
//  lo cruza con objetivos (nombre legible) y personal (nombre del vigilador por
//  legajo). No escribe nada ni toca ninguna otra pestana. Admin y supervisor
//  pueden leer el nodo completo (ver database.rules.json -> rondasRegistros).
// ===================================================================
var _reporteRondasCache = [];
var _nombresObjetivosRonda = {};
var _nombresVigiladoresRonda = {};

async function cargarReporteRondas() {
  var estado = document.getElementById('estadoReporteRondas');
  if (estado) { estado.textContent = 'Cargando registros de rondas\u2026'; estado.className = 'text-xs text-slate-400'; }
  try {
    // Mapa idObjetivo -> nombre legible.
    try {
      var resObj = await fetch(await window.urlConAuthAdmin(URL_FIREBASE + '/objetivos.json?ts=' + Date.now()), { cache: 'no-store' });
      var dataObj = resObj.ok ? await resObj.json() : null;
      _nombresObjetivosRonda = {};
      if (dataObj) Object.keys(dataObj).forEach(function (id) {
        var d = dataObj[id];
        _nombresObjetivosRonda[id] = (typeof d === 'string') ? d : ((d && d.nombre) || id);
      });
    } catch (_) {}
    // Mapa legajo -> nombre del vigilador.
    try {
      var resPer = await fetch(await window.urlConAuthAdmin(URL_FIREBASE + '/personal.json?ts=' + Date.now()), { cache: 'no-store' });
      var dataPer = resPer.ok ? await resPer.json() : null;
      _nombresVigiladoresRonda = {};
      if (dataPer) Object.keys(dataPer).forEach(function (id) {
        var p = dataPer[id];
        if (p && p.legajo != null) _nombresVigiladoresRonda[String(p.legajo)] = p.nombre || '';
      });
    } catch (_) {}
    // Registros de rondas (nodo completo; admin/supervisor).
    var res = await fetch(await window.urlConAuthAdmin(URL_FIREBASE + '/rondasRegistros.json?ts=' + Date.now()), { cache: 'no-store' });
    if (!res.ok) {
      if (estado) {
        estado.textContent = (res.status === 401 || res.status === 403)
          ? 'Sin permiso para leer las rondas. Revis\u00e1 que las Reglas (nodo rondasRegistros) est\u00e9n desplegadas.'
          : ('No se pudieron cargar las rondas (error ' + res.status + ').');
        estado.className = 'text-xs text-rose-400';
      }
      _reporteRondasCache = [];
      renderReporteRondas();
      return;
    }
    var data = await res.json();
    var arr = [];
    if (data) Object.keys(data).forEach(function (id) {
      var r = data[id] || {};
      r._id = id;
      arr.push(r);
    });
    // Mas recientes primero.
    arr.sort(function (a, b) { return (Date.parse(b.timestamp) || 0) - (Date.parse(a.timestamp) || 0); });
    _reporteRondasCache = arr;
    poblarFiltroObjetivosRonda();
    renderReporteRondas();
  } catch (e) {
    if (estado) { estado.textContent = 'Error al cargar las rondas. Reintent\u00e1.'; estado.className = 'text-xs text-rose-400'; }
    _reporteRondasCache = [];
    renderReporteRondas();
  }
}

function fmtFechaHoraRonda(iso) {
  var ms = Date.parse(iso);
  if (!ms) return '-';
  try {
    return new Date(ms).toLocaleString('es-AR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch (_) { return new Date(ms).toISOString(); }
}

function fechaLocalISORonda(iso) {
  var ms = Date.parse(iso); if (!ms) return '';
  var d = new Date(ms);
  var mm = ('0' + (d.getMonth() + 1)).slice(-2);
  var dd = ('0' + d.getDate()).slice(-2);
  return d.getFullYear() + '-' + mm + '-' + dd;
}

function poblarFiltroObjetivosRonda() {
  var sel = document.getElementById('filtroObjetivoRonda');
  if (!sel) return;
  var prev = sel.value;
  var ids = {};
  _reporteRondasCache.forEach(function (r) { if (r.idObjetivo) ids[r.idObjetivo] = true; });
  var html = '<option value="">Todos los objetivos</option>';
  Object.keys(ids).forEach(function (id) {
    var nombre = _nombresObjetivosRonda[id] || id;
    html += '<option value="' + escaparHtml(id) + '">' + escaparHtml(nombre) + '</option>';
  });
  sel.innerHTML = html;
  if (prev) sel.value = prev;
}

function limpiarFiltrosRonda() {
  var fo = document.getElementById('filtroObjetivoRonda'); if (fo) fo.value = '';
  var ff = document.getElementById('filtroFechaRonda'); if (ff) ff.value = '';
  var fl = document.getElementById('filtroLegajoRonda'); if (fl) fl.value = '';
  renderReporteRondas();
}

function renderReporteRondas() {
  var cuerpo = document.getElementById('cuerpoReporteRondas');
  var estado = document.getElementById('estadoReporteRondas');
  if (!cuerpo) return;
  var fObj = (document.getElementById('filtroObjetivoRonda') || {}).value || '';
  var fFecha = (document.getElementById('filtroFechaRonda') || {}).value || '';
  var fLeg = ((document.getElementById('filtroLegajoRonda') || {}).value || '').trim();

  var filtrados = _reporteRondasCache.filter(function (r) {
    if (fObj && r.idObjetivo !== fObj) return false;
    if (fLeg && String(r.legajo || '') !== fLeg) return false;
    if (fFecha && fechaLocalISORonda(r.timestamp) !== fFecha) return false;
    return true;
  });

  var total = filtrados.length, fueraRadio = 0, sinGps = 0;
  filtrados.forEach(function (r) {
    if (!r.gpsDisponible) sinGps++;
    else if (!r.ubicacionValidada) fueraRadio++;
  });
  var elTot = document.getElementById('resumenRondasTotal'); if (elTot) elTot.textContent = total;
  var elFR = document.getElementById('resumenRondasFuera'); if (elFR) elFR.textContent = fueraRadio;
  var elSG = document.getElementById('resumenRondasSinGps'); if (elSG) elSG.textContent = sinGps;

  if (estado) {
    estado.textContent = total ? (total + ' paso(s) de ronda') : 'No hay pasos de ronda para los filtros elegidos.';
    estado.className = 'text-xs text-slate-400';
  }

  if (!total) {
    cuerpo.innerHTML = '<tr><td colspan="6" class="p-8 text-center text-slate-400">No hay pasos de ronda registrados.</td></tr>';
    return;
  }

  var html = '';
  filtrados.forEach(function (r) {
    var nombreObj = _nombresObjetivosRonda[r.idObjetivo] || r.idObjetivo || '-';
    var nombreVig = _nombresVigiladoresRonda[String(r.legajo)] || '';
    var ubicHtml;
    if (!r.gpsDisponible) {
      ubicHtml = '<span class="inline-block px-2 py-0.5 rounded-full text-xs font-bold border border-slate-500/30 text-slate-400 bg-slate-500/10">Sin GPS</span>';
    } else if (r.ubicacionValidada) {
      ubicHtml = '<span class="inline-block px-2 py-0.5 rounded-full text-xs font-bold border border-emerald-500/30 text-emerald-400 bg-emerald-500/10">En el punto' + (r.distanciaMetros != null ? ' \u00b7 ' + r.distanciaMetros + ' m' : '') + '</span>';
    } else {
      ubicHtml = '<span class="inline-block px-2 py-0.5 rounded-full text-xs font-bold border border-amber-500/30 text-amber-400 bg-amber-500/10">Fuera de radio' + (r.distanciaMetros != null ? ' \u00b7 ' + r.distanciaMetros + ' m' : '') + '</span>';
    }
    var mapaHtml = '';
    if (r.latitud != null && r.longitud != null) {
      var mapa = 'https://www.google.com/maps?q=' + encodeURIComponent(r.latitud + ',' + r.longitud);
      mapaHtml = '<a href="' + escaparHtml(mapa) + '" target="_blank" rel="noopener" class="text-xs text-sky-400 hover:underline"><i class="fa-solid fa-map-location-dot"></i> Ver mapa</a>';
    }
    html +=
      '<tr class="hover:bg-slate-800/40">' +
        '<td class="p-3 text-slate-300 whitespace-nowrap">' + escaparHtml(fmtFechaHoraRonda(r.timestamp)) + '</td>' +
        '<td class="p-3 text-slate-200">' + escaparHtml(nombreObj) + '</td>' +
        '<td class="p-3 font-medium text-white">' + escaparHtml(r.nombrePunto || r.idPunto || '-') + '</td>' +
        '<td class="p-3 text-slate-300">' + escaparHtml(nombreVig || '\u2014') + '<br><span class="text-xs text-slate-500">Leg: ' + escaparHtml(String(r.legajo || '-')) + '</span></td>' +
        '<td class="p-3">' + ubicHtml + '</td>' +
        '<td class="p-3 text-center">' + (mapaHtml || '<span class="text-slate-600 text-xs">\u2014</span>') + '</td>' +
      '</tr>';
  });
  cuerpo.innerHTML = html;
}

// ====== CONFIGURACIÓN GLOBAL (tolerancias + radio) Y CÁLCULO DE CUMPLIMIENTO ======
function minutosDesdeHHMM(hora) {
  if (!hora || !/^\d{1,2}:\d{2}$/.test(String(hora))) return null;
  const [h, m] = String(hora).split(':').map(Number);
  if (h < 0 || h > 23 || m < 0 || m > 59) return null;
  return h * 60 + m;
}

function aplicarConfigGlobalAInputs() {
  const i = document.getElementById('cfgToleranciaIngreso');
  const e = document.getElementById('cfgToleranciaEgreso');
  const r = document.getElementById('cfgRadioFichaje');
  const pr = document.getElementById('cfgPrecisionMaxima');
  if (i) i.value = configGlobalAdmin.toleranciaIngresoMin;
  if (e) e.value = configGlobalAdmin.toleranciaEgresoMin;
  if (r) r.value = configGlobalAdmin.radioFichajeMetros;
  if (pr) pr.value = configGlobalAdmin.precisionMaximaMetros;
  const modo = (configGlobalAdmin.modoDispositivo === 'individual') ? 'individual' : 'compartido';
  const rc = document.getElementById('modoCompartido');
  const ri = document.getElementById('modoIndividual');
  if (rc) rc.checked = (modo === 'compartido');
  if (ri) ri.checked = (modo === 'individual');
  const be = document.getElementById('cfgBiometriaEstricta');
  if (be) be.checked = (configGlobalAdmin.biometriaEstricta === true);
  const oh = document.getElementById('cfgOfflineHabilitado');
  if (oh) oh.checked = (configGlobalAdmin.offlineHabilitado === true);
  const vl = document.getElementById('cfgVentanaLoteOffline');
  if (vl) vl.value = configGlobalAdmin.ventanaLoteOfflineHoras;
  // Clave nueva (#7): ventana anti-repeticion de fichadas (seg). 0 = desactivado.
  const ar = document.getElementById('cfgAntiReplaySegundos');
  if (ar) ar.value = configGlobalAdmin.antiReplaySegundos;
  // Clave nueva (#5): tolerancia de reloj del dispositivo al sincronizar (seg).
  const sk = document.getElementById('cfgSkewRelojOffline');
  if (sk) sk.value = configGlobalAdmin.skewRelojOfflineSegundos;
}

async function cargarConfiguracionGlobal() {
  try {
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/configuracionGlobal.json?ts=${Date.now()}`), { cache: 'no-store' });
    const data = await res.json();
    if (data && typeof data === 'object') {
      if (Number.isFinite(Number(data.toleranciaIngresoMin))) configGlobalAdmin.toleranciaIngresoMin = Number(data.toleranciaIngresoMin);
      if (Number.isFinite(Number(data.toleranciaEgresoMin))) configGlobalAdmin.toleranciaEgresoMin = Number(data.toleranciaEgresoMin);
      if (Number.isFinite(Number(data.radioFichajeMetros)) && Number(data.radioFichajeMetros) > 0) configGlobalAdmin.radioFichajeMetros = Number(data.radioFichajeMetros);
      if (Number.isFinite(Number(data.precisionMaximaMetros)) && Number(data.precisionMaximaMetros) >= 0) configGlobalAdmin.precisionMaximaMetros = Number(data.precisionMaximaMetros);
      configGlobalAdmin.modoDispositivo = (String(data.modoDispositivo || '').trim() === 'individual') ? 'individual' : 'compartido';
      configGlobalAdmin.biometriaEstricta = (data.biometriaEstricta === true);
      configGlobalAdmin.offlineHabilitado = (data.offlineHabilitado === true);
      if (Number.isFinite(Number(data.ventanaLoteOfflineHoras)) && Number(data.ventanaLoteOfflineHoras) > 0) configGlobalAdmin.ventanaLoteOfflineHoras = Number(data.ventanaLoteOfflineHoras);
      // Clave nueva (#7): ventana anti-repeticion (seg). Se acepta 0 (desactivado).
      if (Number.isFinite(Number(data.antiReplaySegundos)) && Number(data.antiReplaySegundos) >= 0) configGlobalAdmin.antiReplaySegundos = Number(data.antiReplaySegundos);
      // Clave nueva (#5): tolerancia de reloj del dispositivo (seg). Se acepta 0.
      if (Number.isFinite(Number(data.skewRelojOfflineSegundos)) && Number(data.skewRelojOfflineSegundos) >= 0) configGlobalAdmin.skewRelojOfflineSegundos = Number(data.skewRelojOfflineSegundos);
    }
  } catch (err) {
    console.warn('No se pudo cargar la configuración global, se usan valores por defecto.', err);
  }
  aplicarConfigGlobalAInputs();
}

async function guardarConfiguracionGlobal() {
  const estado = document.getElementById('cfgEstadoGuardado');
  const tolIng = Math.max(0, Math.min(120, parseInt(document.getElementById('cfgToleranciaIngreso').value, 10) || 0));
  const tolEgr = Math.max(0, Math.min(120, parseInt(document.getElementById('cfgToleranciaEgreso').value, 10) || 0));
  const radio = Math.max(10, Math.min(5000, parseInt(document.getElementById('cfgRadioFichaje').value, 10) || 100));
  const precEl = document.getElementById('cfgPrecisionMaxima');
  const precisionMaxima = Math.max(0, Math.min(2000, parseInt(precEl ? precEl.value : 0, 10) || 0));
  const beEl = document.getElementById('cfgBiometriaEstricta');
  const biometriaEstricta = !!(beEl && beEl.checked);
  // Clave nueva (#7): ventana anti-repeticion de fichadas (seg). 0 = desactivado.
  const arEl = document.getElementById('cfgAntiReplaySegundos');
  const antiReplaySegundos = Math.max(0, Math.min(3600, parseInt(arEl ? arEl.value : 90, 10) || 0));
  const payload = { toleranciaIngresoMin: tolIng, toleranciaEgresoMin: tolEgr, radioFichajeMetros: radio, precisionMaximaMetros: precisionMaxima, modoDispositivo: (configGlobalAdmin.modoDispositivo === 'individual' ? 'individual' : 'compartido'), biometriaEstricta: biometriaEstricta, antiReplaySegundos: antiReplaySegundos, actualizado: new Date().toISOString() };
  if (estado) { estado.className = 'text-xs text-slate-400'; estado.innerText = 'Guardando...'; }
  try {
    // PATCH (merge) en lugar de PUT para NO pisar el resto de /configuracionGlobal
    // (flags offline, skew, etc. que se guardan desde otros botones).
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/configuracionGlobal.json`), {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Respuesta no OK');
    configGlobalAdmin.toleranciaIngresoMin = tolIng;
    configGlobalAdmin.toleranciaEgresoMin = tolEgr;
    configGlobalAdmin.radioFichajeMetros = radio;
    configGlobalAdmin.precisionMaximaMetros = precisionMaxima;
    configGlobalAdmin.biometriaEstricta = biometriaEstricta;
    configGlobalAdmin.antiReplaySegundos = antiReplaySegundos;
    if (estado) { estado.className = 'text-xs text-emerald-400 font-semibold'; estado.innerText = '✓ Configuración guardada.'; }
    filtrarTablaMarcaciones();
  } catch (err) {
    console.error('Error al guardar configuración global:', err);
    if (estado) { estado.className = 'text-xs text-rose-400 font-semibold'; estado.innerText = '❌ No se pudo guardar. Reintentá.'; }
  }
}

// Guarda SOLO el modo de dispositivo (individual/compartido) sin pisar el
// resto de la configuración global (PATCH). Lo lee la pantalla de fichaje
// en /configuracionGlobal/modoDispositivo.
async function guardarModoDispositivo() {
  const estado = document.getElementById('cfgEstadoModo');
  const sel = document.querySelector('input[name="modoDispositivo"]:checked');
  const modo = (sel && sel.value === 'individual') ? 'individual' : 'compartido';
  if (estado) { estado.className = 'text-xs text-slate-400'; estado.innerText = 'Guardando...'; }
  try {
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/configuracionGlobal.json`), {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ modoDispositivo: modo, modoDispositivoActualizado: new Date().toISOString() })
    });
    if (!res.ok) throw new Error('Respuesta no OK');
    configGlobalAdmin.modoDispositivo = modo;
    if (estado) {
      estado.className = 'text-xs text-emerald-400 font-semibold';
      estado.innerText = (modo === 'individual')
        ? '✓ Modo INDIVIDUAL guardado (la sesión se mantiene).'
        : '✓ Modo COMPARTIDO guardado (cierra sesión tras fichar).';
    }
  } catch (err) {
    console.error('Error al guardar el modo de dispositivo:', err);
    if (estado) { estado.className = 'text-xs text-rose-400 font-semibold'; estado.innerText = '❌ No se pudo guardar. Reintentá.'; }
  }
}
window.guardarModoDispositivo = guardarModoDispositivo;

// ====== FASE 3: FICHAJE OFFLINE + GESTION DE DISPOSITIVOS ======
// Persiste SOLO los flags de offline (PATCH, no pisa el resto de la config).
async function guardarConfigOffline() {
  const estado = document.getElementById('cfgEstadoOffline');
  const habilitado = !!document.getElementById('cfgOfflineHabilitado').checked;
  // [PLAN] Guia amable: el fichaje offline solo esta disponible si el plan
  // contratado incluye la funcion 'modoOffline'. Si se intenta ACTIVAR sin plan,
  // avisamos y revertimos el check (apagarlo siempre se permite). Aunque alguien
  // sortee esta guia, las Reglas de Firebase rechazan la escritura server-side.
  if (habilitado && !planTieneFuncion('modoOffline')) {
    const chk = document.getElementById('cfgOfflineHabilitado');
    if (chk) chk.checked = false;
    if (estado) {
      estado.className = 'text-xs text-amber-400 font-semibold';
      estado.innerText = 'El fichaje offline no esta incluido en tu plan actual. Escribinos para sumar esta funcion.';
    }
    return;
  }
  const ventana = Math.max(1, Math.min(720, parseInt(document.getElementById('cfgVentanaLoteOffline').value, 10) || 168));
  // Clave nueva (#5): tolerancia de reloj del dispositivo al sincronizar (seg).
  const skEl = document.getElementById('cfgSkewRelojOffline');
  const skewRelojOfflineSegundos = Math.max(0, Math.min(3600, parseInt(skEl ? skEl.value : 300, 10) || 0));
  if (estado) { estado.className = 'text-xs text-slate-400'; estado.innerText = 'Guardando...'; }
  try {
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/configuracionGlobal.json`), {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ offlineHabilitado: habilitado, ventanaLoteOfflineHoras: ventana, skewRelojOfflineSegundos: skewRelojOfflineSegundos, offlineActualizado: new Date().toISOString() })
    });
    if (!res.ok) throw new Error('Respuesta no OK');
    configGlobalAdmin.offlineHabilitado = habilitado;
    configGlobalAdmin.ventanaLoteOfflineHoras = ventana;
    configGlobalAdmin.skewRelojOfflineSegundos = skewRelojOfflineSegundos;
    if (estado) {
      estado.className = 'text-xs text-emerald-400 font-semibold';
      estado.innerText = habilitado ? '✓ Fichaje offline HABILITADO.' : '✓ Fichaje offline deshabilitado.';
    }
  } catch (err) {
    console.error('Error al guardar configuración offline:', err);
    if (estado) { estado.className = 'text-xs text-rose-400 font-semibold'; estado.innerText = '❌ No se pudo guardar. Reintentá.'; }
  }
}
window.guardarConfigOffline = guardarConfigOffline;

function escaparHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Lista los dispositivos registrados (via Worker, rol admin server-side).
async function cargarDispositivos() {
  const tbody = document.getElementById('tablaDispositivos');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="5" class="px-3 py-6 text-center text-slate-500">Cargando…</td></tr>';
  try {
    const data = await window.llamarWorkerAdmin({ accion: 'listarDispositivos' });
    const lista = Array.isArray(data.dispositivos) ? data.dispositivos : [];
    if (!lista.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="px-3 py-6 text-center text-slate-500">No hay dispositivos registrados todavía.</td></tr>';
      return;
    }
    tbody.innerHTML = lista.map(d => {
      const id = escaparHtml(d.deviceId);
      const idJs = JSON.stringify(d.deviceId);
      const nombre = escaparHtml(d.nombre || '(sin nombre)');
      const legajos = (Array.isArray(d.legajos) && d.legajos.length) ? escaparHtml(d.legajos.join(', ')) : '<span class="text-slate-500">Todos</span>';
      const badge = d.activo
        ? '<span class="bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-[11px] font-bold px-2 py-0.5 rounded-full">Activo</span>'
        : '<span class="bg-slate-600/30 text-slate-400 border border-slate-600/40 text-[11px] font-bold px-2 py-0.5 rounded-full">Inactivo</span>';
      const toggleTxt = d.activo ? 'Desactivar' : 'Activar';
      const toggleIcon = d.activo ? 'fa-ban' : 'fa-circle-check';
      return `<tr class="border-b border-slate-700/60">
        <td class="px-3 py-3 font-semibold text-white">${nombre}</td>
        <td class="px-3 py-3">${badge}</td>
        <td class="px-3 py-3 text-slate-300">${legajos}</td>
        <td class="px-3 py-3 font-mono text-[11px] text-slate-500 break-all">${id}</td>
        <td class="px-3 py-3 text-right whitespace-nowrap">
          <button type="button" data-accion="toggleDispositivo" data-a1="${escaparHtml(d.deviceId)}" data-a2="${d.activo ? 'false' : 'true'}" class="text-xs font-semibold text-sky-400 hover:text-sky-300 px-2 py-1"><i class="fa-solid ${toggleIcon}"></i> ${toggleTxt}</button>
          <button type="button" data-accion="rotarSecretoDispositivo" data-a1="${escaparHtml(d.deviceId)}" class="text-xs font-semibold text-amber-400 hover:text-amber-300 px-2 py-1"><i class="fa-solid fa-key"></i> Rotar secreto</button>
          <button type="button" data-accion="eliminarDispositivo" data-a1="${escaparHtml(d.deviceId)}" class="text-xs font-semibold text-rose-400 hover:text-rose-300 px-2 py-1"><i class="fa-solid fa-trash"></i> Eliminar</button>
        </td>
      </tr>`;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="px-3 py-6 text-center text-rose-400">No se pudieron cargar los dispositivos: ${escaparHtml(err.message)}</td></tr>`;
  }
}
window.cargarDispositivos = cargarDispositivos;

// ─── DELEGACIÓN DE EVENTOS (reemplaza los onclick="" bloqueados por el CSP) ───
// El Content-Security-Policy (script-src sin 'unsafe-inline') bloquea los
// manejadores inline onclick="". En lugar de debilitar el CSP, los botones
// generados dinámicamente llevan data-accion + data-a1/data-a2, y este ÚNICO
// listener global despacha cada click al handler correcto. La seguridad del
// CSP queda intacta (sin 'unsafe-inline' ni 'unsafe-hashes').
document.addEventListener('click', function (ev) {
  const el = ev.target.closest('[data-accion]');
  if (!el) return;
  const accion = el.getAttribute('data-accion');
  const a1 = el.getAttribute('data-a1');
  const a2 = el.getAttribute('data-a2');
  switch (accion) {
    case 'toggleDispositivo': toggleDispositivo(a1, a2 === 'true'); break;
    case 'rotarSecretoDispositivo': rotarSecretoDispositivo(a1); break;
    case 'eliminarDispositivo': eliminarDispositivo(a1); break;
    case 'abrirModalAuditoriaPorId': abrirModalAuditoriaPorId(a1); break;
    case 'abrirModalAccionFraudePorId': abrirModalAccionFraudePorId(a1); break;
    case 'abrirFoto': abrirFoto(a1); break;
    case 'eliminarPanico': eliminarPanico(a1); break;
    case 'cambiarEstadoPersonal': cambiarEstadoPersonal(a1, a2 === 'true'); break;
    case 'abrirModalEditar': abrirModalEditar(a1); break;
    case 'abrirModalTurnosPersonal': abrirModalTurnosPersonal(a1); break;
    case 'eliminarPersonal': eliminarPersonal(a1); break;
    case 'editarAsignacionTurno': editarAsignacionTurno(a1); break;
    case 'eliminarAsignacionTurno': eliminarAsignacionTurno(a1); break;
    case 'seleccionarResultadoNominatim': seleccionarResultadoNominatim(a1, parseInt(a2, 10)); break;
    case 'abrirModalEditarObjetivo': abrirModalEditarObjetivo(a1); break;
    case 'reintentarCargarRonda': cargarRondaObjetivo(a1); break;
    case 'eliminarObjetivo': eliminarObjetivo(a1); break;
    case 'toggleDiaRonda': toggleDiaRonda(a1); break;
    case 'editarPuntoRonda': editarPuntoRonda(a1); break;
    case 'eliminarPuntoRonda': eliminarPuntoRonda(a1); break;
    case 'mostrarQRPunto': mostrarQRPunto(a1); break;
  }
});

// Convierte {deviceId, secreto} en un codigo compacto para pegar en el dispositivo.
function armarCodigoVinculacion(deviceId, secreto) {
  try { return btoa(JSON.stringify({ v: 1, deviceId, secreto })); }
  catch (_) { return JSON.stringify({ v: 1, deviceId, secreto }); }
}

async function crearDispositivo() {
  const estado = document.getElementById('estadoCrearDispositivo');
  const nombre = document.getElementById('nuevoDispositivoNombre').value.trim();
  const legajosRaw = document.getElementById('nuevoDispositivoLegajos').value.trim();
  if (!nombre) { if (estado) { estado.className = 'text-xs text-rose-400 font-semibold'; estado.innerText = 'Indicá un nombre.'; } return; }
  const legajos = legajosRaw ? legajosRaw.split(',').map(x => x.trim()).filter(Boolean) : undefined;
  if (estado) { estado.className = 'text-xs text-slate-400'; estado.innerText = 'Creando...'; }
  try {
    const payload = { accion: 'crearDispositivo', nombre };
    if (legajos && legajos.length) payload.legajos = legajos;
    const data = await window.llamarWorkerAdmin(payload);
    const codigo = armarCodigoVinculacion(data.deviceId, data.secreto);
    document.getElementById('codigoVinculacionTexto').value = codigo;
    document.getElementById('codigoDeviceId').innerText = data.deviceId;
    document.getElementById('codigoSecreto').innerText = data.secreto;
    document.getElementById('boxCodigoVinculacion').classList.remove('hidden');
    document.getElementById('nuevoDispositivoNombre').value = '';
    document.getElementById('nuevoDispositivoLegajos').value = '';
    if (estado) { estado.className = 'text-xs text-emerald-400 font-semibold'; estado.innerText = '✓ Dispositivo creado.'; }
    cargarDispositivos();
  } catch (err) {
    if (estado) { estado.className = 'text-xs text-rose-400 font-semibold'; estado.innerText = '❌ ' + err.message; }
  }
}
window.crearDispositivo = crearDispositivo;

function copiarCodigoVinculacion() {
  const ta = document.getElementById('codigoVinculacionTexto');
  const aviso = document.getElementById('copiadoAviso');
  const ok = () => { if (aviso) { aviso.className = 'text-emerald-400 font-semibold'; aviso.innerText = '✓ Copiado'; setTimeout(() => { if (aviso) aviso.innerText = ''; }, 2500); } };
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(ta.value).then(ok, () => { ta.select(); document.execCommand('copy'); ok(); }); }
    else { ta.select(); document.execCommand('copy'); ok(); }
  } catch (_) { ta.select(); }
}
window.copiarCodigoVinculacion = copiarCodigoVinculacion;

async function toggleDispositivo(deviceId, activar) {
  try {
    await window.llamarWorkerAdmin({ accion: 'actualizarDispositivo', deviceId, activo: !!activar });
    cargarDispositivos();
  } catch (err) { alert('No se pudo actualizar el dispositivo: ' + err.message); }
}
window.toggleDispositivo = toggleDispositivo;

async function rotarSecretoDispositivo(deviceId) {
  if (!confirm('Al rotar el secreto, el dispositivo dejará de fichar hasta que pegues el NUEVO código de vinculación. ¿Continuar?')) return;
  try {
    const data = await window.llamarWorkerAdmin({ accion: 'actualizarDispositivo', deviceId, rotarSecreto: true });
    const codigo = armarCodigoVinculacion(deviceId, data.secreto);
    document.getElementById('codigoVinculacionTexto').value = codigo;
    document.getElementById('codigoDeviceId').innerText = deviceId;
    document.getElementById('codigoSecreto').innerText = data.secreto;
    document.getElementById('boxCodigoVinculacion').classList.remove('hidden');
    document.getElementById('boxCodigoVinculacion').scrollIntoView({ behavior: 'smooth', block: 'center' });
    cargarDispositivos();
  } catch (err) { alert('No se pudo rotar el secreto: ' + err.message); }
}
window.rotarSecretoDispositivo = rotarSecretoDispositivo;

async function eliminarDispositivo(deviceId) {
  if (!confirm('¿Eliminar este dispositivo? No podrá volver a fichar offline salvo que lo des de alta de nuevo.')) return;
  try {
    await window.llamarWorkerAdmin({ accion: 'eliminarDispositivo', deviceId });
    cargarDispositivos();
  } catch (err) { alert('No se pudo eliminar el dispositivo: ' + err.message); }
}
window.eliminarDispositivo = eliminarDispositivo;

// Clasifica una fichada según el horario programado y las tolerancias configuradas.
// Devuelve null si no hay datos suficientes para evaluar.
function calcularCumplimientoFichada(tipo, fechaFichadaStr, horaProgInicio, horaProgFin) {
  const t = String(tipo || '').toUpperCase();
  const f = new Date(fechaFichadaStr);
  if (isNaN(f)) return null;
  const minFichada = f.getHours() * 60 + f.getMinutes();
  const tolIng = Number(configGlobalAdmin.toleranciaIngresoMin);
  const tolEgr = Number(configGlobalAdmin.toleranciaEgresoMin);

  const normalizar = (diff) => {
    // Ajuste para turnos que cruzan la medianoche.
    if (diff > 720) return diff - 1440;
    if (diff < -720) return diff + 1440;
    return diff;
  };

  if (t === 'ENTRADA') {
    const ini = minutosDesdeHHMM(horaProgInicio);
    if (ini === null) return null;
    const diff = normalizar(minFichada - ini);
    if (diff <= 0) {
      return { estado: 'A_TIEMPO', texto: 'A tiempo', clase: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25', fila: '' };
    } else if (diff <= tolIng) {
      return { estado: 'TOLERANCIA', texto: `Tolerancia (+${diff} min)`, clase: 'bg-amber-500/15 text-amber-300 border-amber-500/40', fila: 'bg-amber-950/20 border-l-4 border-l-amber-500' };
    } else {
      return { estado: 'TARDE', texto: `Llegada tarde (+${diff} min)`, clase: 'bg-rose-500/15 text-rose-300 border-rose-500/40', fila: 'bg-rose-950/20 border-l-4 border-l-rose-500' };
    }
  }

  if (t === 'SALIDA') {
    const fin = minutosDesdeHHMM(horaProgFin);
    if (fin === null) return null;
    const diff = normalizar(minFichada - fin);
    if (diff < 0) {
      return { estado: 'ANTICIPADA', texto: `Salida anticipada (${Math.abs(diff)} min antes)`, clase: 'bg-rose-500/15 text-rose-300 border-rose-500/40', fila: 'bg-rose-950/20 border-l-4 border-l-rose-500' };
    } else if (diff <= tolEgr) {
      return { estado: 'EN_HORARIO', texto: 'Salida en horario', clase: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25', fila: '' };
    } else {
      // REGLA DE NEGOCIO (Opcion B, ajustada): al SUPERAR la tolerancia de egreso
      // se computan como extra los minutos de tolerancia COMPLETOS mas cada minuto
      // adicional; NO se cuenta el minuto en que se cruza el umbral por si mismo.
      // Formula: extra = diff - 1 (cuando diff > tolEgr).
      // Ej. fin 07:00, tol 30': 07:30 -> en horario; 07:31 -> +30 min; 07:40 -> +39 min.
      const extra = diff - 1;
      return { estado: 'EXTRA', texto: `Horas extra (+${extra} min)`, clase: 'bg-sky-500/15 text-sky-300 border-sky-500/40', fila: 'bg-sky-950/20 border-l-4 border-l-sky-500' };
    }
  }
  return null;
}

// Deriva el horario programado igual que el Panel: primero un turno puntual asignado
// para esa fecha, si no existe usa el horario habitual del legajo. Sirve como respaldo
// para fichadas antiguas que no tienen el horario guardado en el registro.
function obtenerFechaLocalClaveAdmin(fecha) {
  if (!(fecha instanceof Date) || isNaN(fecha)) return '';
  const y = fecha.getFullYear();
  const m = String(fecha.getMonth() + 1).padStart(2, '0');
  const d = String(fecha.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

// Comparación de legajos tolerante a formato (igual criterio que mis-horas.html):
// primero compara como texto normalizado y, de respaldo, como número, para que
// "007" y "7" (o con espacios) se consideren el mismo legajo.
function mismoLegajoAdmin(a, b) {
  const sa = String(a == null ? '' : a).trim();
  const sb = String(b == null ? '' : b).trim();
  // Guard de vacio UNIFICADO con index/panel/mis-horas: dos legajos vacios NO
  // se consideran el mismo (evita cruzar registros sin legajo entre si).
  if (sa === '' || sb === '') return false;
  if (sa === sb) return true;
  const na = parseInt(sa, 10);
  const nb = parseInt(sb, 10);
  return Number.isFinite(na) && Number.isFinite(nb) && na === nb;
}

function obtenerHorarioProgramadoAdmin(entrada, legajo, objetivoNombre) {
  const fechaEntrada = new Date(entrada);
  if (isNaN(fechaEntrada)) return null;
  const fechaClave = obtenerFechaLocalClaveAdmin(fechaEntrada);
  const legajoStr = String(legajo || '').trim();
  const objetivoStr = String(objetivoNombre || '').trim().toLowerCase();

  const turnosFecha = asignacionesTurnosGlobalAdmin.filter(t =>
    mismoLegajoAdmin(t.legajo, legajoStr) && String(t.fecha || '') === fechaClave
  );

  let turno = null;
  if (turnosFecha.length) {
    turno = turnosFecha.find(t => {
      const nombre = String(t.objetivoNombre || t.objetivo || '').trim().toLowerCase();
      return objetivoStr && nombre && (nombre === objetivoStr || nombre.includes(objetivoStr) || objetivoStr.includes(nombre));
    }) || turnosFecha[0];
  }

  if (turno && (turno.horaInicio || turno.horaFin)) {
    return { inicio: turno.horaInicio || '', fin: turno.horaFin || '' };
  }

  const persona = Object.values(mapaConfiguracionPersonal).find(p => mismoLegajoAdmin(p.legajo, legajoStr));
  const h = (persona && persona.horarioHabitual) || {};
  if (h.inicio || h.fin) {
    return { inicio: h.inicio || '', fin: h.fin || '' };
  }

  return null;
}

// Resuelve el horario de una fila: usa el guardado en la fichada y, si falta,
// lo deriva igual que el Panel. Devuelve la clasificación de cumplimiento.
function calcularCumplimientoFilaAdmin(fila) {
  let ini = fila[12];
  let fin = fila[13];
  if (!ini && !fin) {
    const derivado = obtenerHorarioProgramadoAdmin(fila[0], fila[1], fila[3]);
    if (derivado) { ini = derivado.inicio; fin = derivado.fin; }
  }
  return calcularCumplimientoFichada(fila[4], fila[0], ini, fin);
}

function convertirImagenBase64(file) {
  return new Promise((resolve, reject) => {
    if (!file) resolve(null);
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = () => resolve(reader.result);
    reader.onerror = error => reject(error);
  });
}

// CARGA DE DATOS DESDE FIREBASE REALTIME DATABASE
async function recargarDatosEfectivo() {
  const icono = document.getElementById('icono-reload');
  if (icono) icono.classList.add('fa-spin');

  try {
    // 0. Cargar configuración global (tolerancias + radio)
    await cargarConfiguracionGlobal();

    // 0b. [PLAN] Cargar el plan contratado para los indicadores "X / maximo".
    await cargarPlanApp();

    // 1. Cargar Personal primero
    const resPersonal = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/personal.json`));
    const dataPersonal = await resPersonal.json();
    datosPersonal = [];
    let mapaFotosMaster = {};

    if (dataPersonal) {
      Object.keys(dataPersonal).forEach(id => {
        const d = dataPersonal[id];
        if (d) {
          const legajoStr = d.legajo ? String(d.legajo).trim() : '';
          mapaConfiguracionPersonal[id] = d;
          datosPersonal.push([legajoStr, d.nombre || '', 'Personal', ((d.tienePin || d.pinHash || d.pinSalt) ? '••••' : (d.pin || '')), d.estado || 'ACTIVO', id, d.fotoMaster || '']);
          if (legajoStr && d.fotoMaster) {
            mapaFotosMaster[legajoStr] = d.fotoMaster;
          }
        }
      });
    }
    // 1a. Cargar el mapa de roles /usuarios (uid -> rol) para separar la lista.
    //     Lectura permitida al admin por Reglas (/usuarios .read = admin).
    mapaRolesUsuarios = {};
    try {
      const resUsuarios = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/usuarios.json`));
      const dataUsuarios = await resUsuarios.json();
      if (dataUsuarios) {
        Object.keys(dataUsuarios).forEach(uid => {
          const u = dataUsuarios[uid] || {};
          mapaRolesUsuarios[uid] = (u.rol || 'empleado');
        });
      }
    } catch (_) { /* si falla, todos se muestran como personal (comportamiento previo) */ }
    renderizarTablaPersonal(datosPersonal);

    // 1b. Cargar TODOS los cambios de turno (para derivar el horario programado
    //     en fichadas antiguas que no lo tienen guardado, igual que el Panel).
    try {
      const resTurnosGlobal = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/asignacionesTurnos.json?ts=${Date.now()}`), { cache: 'no-store' });
      const dataTurnosGlobal = await resTurnosGlobal.json();
      asignacionesTurnosGlobalAdmin = dataTurnosGlobal ? Object.entries(dataTurnosGlobal).map(([id, d]) => ({ ...d, id })) : [];
    } catch (err) {
      console.warn('No se pudieron cargar los turnos para el cálculo de cumplimiento.', err);
      asignacionesTurnosGlobalAdmin = [];
    }

    // 2. Cargar Marcaciones (sin cache: tras aprobar/anular debe reflejar el
    //    estado REAL de la base, no una copia cacheada por el navegador).
    const resMarcaciones = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/fichadas.json?ts=${Date.now()}`), { cache: 'no-store' });
    const dataMarcaciones = await resMarcaciones.json();
    datosMarcaciones = [];
    if (dataMarcaciones) {
      Object.keys(dataMarcaciones).forEach(id => {
        const d = dataMarcaciones[id];
        if (d) {
          // Fichada ANULADA: se conserva en la base como evidencia, pero NO se
          // muestra en la tabla ni se contabiliza en horas/alertas/reportes.
          if (d.anulada === true) return;
          // Hora OFICIAL para tabla y alertas de cumplimiento (notificarAlertasCumplimiento):
          // sello del servidor Firebase unificado (d.timestampServidor, .sv=timestamp, NO
          // manipulable) primero; 'timestamp' queda como compat de fichadas antiguas y el
          // reloj del dispositivo SOLO como fallback final para registros sin sello.
          // Evita que un telefono con la hora cambiada falsee llegada tarde / salida anticipada.
          const fecha = d.timestampServidor || d.timestampEstimadoDispositivo || d.timestamp || d.fechaHoraDispositivo || '';
          const mapaUrl = (d.latitud && d.longitud) ? `https://maps.google.com/?q=${d.latitud},${d.longitud}` : '';
          
          const legajoStr = d.legajo ? String(d.legajo).trim() : '';
          const alertaFraude = d.alertaFraude || false;
          const distanciaEuclidiana = (d.distanciaEuclidiana !== undefined && d.distanciaEuclidiana !== null) ? Number(d.distanciaEuclidiana) : null;
          const motivoFraude = d.motivoFraude || '';
          const motivoRevision = d.motivoRevision || '';
          const requiereRevisionManual = d.requiereRevisionManual === true;
          const origenOffline = (d.origenOffline === true || d.sincronizadoDesdeOffline === true);
          // Fichada sin conexión PENDIENTE DE VERIFICACIÓN: NO es fraude, solo no
          // se pudo cotejar la identidad en el momento. Se detecta por el origen
          // offline o el marcador de revisión; se incluye compatibilidad con
          // fichadas offline antiguas que usaban la leyenda previa de "fraude".
          const esOfflinePendiente = (requiereRevisionManual || origenOffline
            || d.validacionFacial === 'OFFLINE_PENDIENTE_VERIFICACION'
            || d.validacionFacial === 'OFFLINE_AUDITORIA_REQUERIDA'
            || /offline/i.test(motivoFraude))
            // ...salvo que el admin YA la haya validado manualmente. El origen
            // offline es un hecho permanente y no se borra; esta marca de
            // resolucion es lo que saca la fichada del estado "pendiente".
            && d.verificacionOfflineResuelta !== true;
          const fotoMaster = mapaFotosMaster[legajoStr] || '';

          datosMarcaciones.push([
            fecha, 
            legajoStr, 
            d.nombre || '', 
            d.objetivo || '', 
            d.tipo || '', 
            mapaUrl, 
            d.fotoBase64 || '',
            alertaFraude,
            distanciaEuclidiana,
            motivoFraude,
            fotoMaster,
            id,
            d.horarioProgramadoInicio || '',
            d.horarioProgramadoFin || '',
            esOfflinePendiente,
            motivoRevision
          ]);
        }
      });
    }
    filtrarTablaMarcaciones();
    notificarAlertasCumplimiento(datosMarcaciones);

    // 3. Cargar Novedades
    const resNovedades = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/novedades.json`));
    const dataNovedades = await resNovedades.json();
    datosNovedades = [];
    if (dataNovedades) {
      Object.keys(dataNovedades).forEach(id => {
        const d = dataNovedades[id];
        if (d) {
          const fecha = d.timestampServidor || d.timestampEstimadoDispositivo || d.fechaHoraDispositivo || d.timestamp || d.fechaHora || '';
          const mapaUrl = (d.latitud && d.longitud) ? `https://maps.google.com/?q=${d.latitud},${d.longitud}` : '';
          const fotoNovedad = d.fotoBase64 || d.foto || '';
          datosNovedades.push([fecha, d.legajo ? String(d.legajo) : '', d.nombre || '', d.objetivo || '', d.tipoIncidencia || 'General', d.descripcion || '', mapaUrl, fotoNovedad]);
        }
      });
    }
    filtrarTablaNovedades();

    // 4. Cargar Pánicos (dentro de recargarDatosEfectivo)
    const resPanicos = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/panicos.json`));
    const dataPanicos = await resPanicos.json();
    datosPanicos = [];
    if (dataPanicos) {
      Object.keys(dataPanicos).forEach(id => {
        const d = dataPanicos[id];
        if (d) {
          // Panico ANULADO: se conserva en la base como evidencia, pero NO se muestra.
          if (d.anulado === true) return;
          // Priorizamos el sello de servidor (timestampServidor, .sv) por ser hora oficial
          // NO manipulable; luego fechaHora/timestamp enviados desde mis-horas como fallback.
          const rawFecha = d.timestampServidor || d.timestampEstimadoDispositivo || d.fechaHora || d.timestamp || d.fecha || '';
          const mapaUrl = (d.latitud && d.longitud) ? `https://maps.google.com/?q=${d.latitud},${d.longitud}` : '';
          
          datosPanicos.push([
            id,
            rawFecha,
            d.legajo ? String(d.legajo) : '-',
            d.nombre || 'Sin Nombre',
            d.objetivo || 'Sin Objetivo',
            d.estado || 'PENDIENTE',
            mapaUrl
          ]);
        }
      });
    }
    renderizarTablaPanicos(datosPanicos);

    // 5. Cargar Objetivos
    const resObjetivos = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos.json`));
    const dataObjetivos = await resObjetivos.json();
    datosObjetivos = [];
    if (dataObjetivos) {
      Object.keys(dataObjetivos).forEach(id => {
        const d = dataObjetivos[id];
        if (d) {
          const nombreObj = typeof d === 'string' ? d : (d.nombre || id);
          const direccionObj = typeof d === 'string' ? '' : (d.direccion || '');
          const latitudObj = typeof d === 'string' ? '' : (d.latitud ?? '');
          const longitudObj = typeof d === 'string' ? '' : (d.longitud ?? '');
          const estadoObj = typeof d === 'string' ? 'ACTIVO' : (d.estado || 'ACTIVO');
          datosObjetivos.push([id, nombreObj, direccionObj, latitudObj, longitudObj, estadoObj]);
        }
      });
    }
    renderizarTablaObjetivos(datosObjetivos);

    // [PLAN] Repintar indicadores con los conteos reales ya cargados.
    try { actualizarIndicadoresPlan(); } catch (_) {}

  } catch (err) {
    console.error("Error al sincronizar con Firebase:", err);
  } finally {
    if (icono) icono.classList.remove('fa-spin');
  }
}

function renderizarTablaMarcaciones(registros) {
  const cuerpo = document.getElementById('cuerpoTablaMarcaciones');
  cuerpo.innerHTML = "";

  if (!registros || registros.length === 0) {
    cuerpo.innerHTML = `<tr><td colspan="9" class="p-8 text-center text-slate-400">No hay registros cargados aún en Firebase.</td></tr>`;
    actualizarResumenCumplimiento(registros || []);
    actualizarControlesPaginacion(0, 0, 0);
    return;
  }

  // Resumen de cumplimiento sobre el total filtrado (no solo la página visible).
  actualizarResumenCumplimiento(registros);

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

  // Paginación (aditivo): recorta el conjunto ordenado a la página actual.
  const totalRegistros = ordenados.length;
  const totalPaginas = Math.max(1, Math.ceil(totalRegistros / filasPorPaginaMarcaciones));
  if (paginaActualMarcaciones > totalPaginas) paginaActualMarcaciones = totalPaginas;
  if (paginaActualMarcaciones < 1) paginaActualMarcaciones = 1;
  const inicio = (paginaActualMarcaciones - 1) * filasPorPaginaMarcaciones;
  const fin = Math.min(inicio + filasPorPaginaMarcaciones, totalRegistros);
  const paginaRegistros = ordenados.slice(inicio, fin);
  actualizarControlesPaginacion(totalRegistros, inicio, fin);

  paginaRegistros.forEach(fila => {
    const fecha = fila[0] ? new Date(fila[0]).toLocaleString('es-AR', { hour12: false }) : '-';
    const legajo = fila[1] !== undefined ? String(fila[1]) : '-';
    const nombre = fila[2] || '-';
    const objetivo = fila[3] || '-';
    const tipo = fila[4] || '-';
    const urlMapa = fila[5] || '';
    const urlFoto = fila[6] || '';
    
    const alertaFraude = fila[7];
    const distanciaEuclidiana = fila[8];
    const firebaseId = fila[11];
    const esOfflinePendiente = fila[14] === true;
    // Fraude REAL: alerta que NO proviene de una fichada offline. Una fichada
    // sin conexión no es fraude; se trata como pendiente de verificación.
    const esFraudeReal = alertaFraude === true && !esOfflinePendiente;

    // Clasificación de cumplimiento (tolerancia / tarde / anticipada / extra) según el horario programado.
    const cumplimiento = calcularCumplimientoFilaAdmin(fila);
    const celdaCumplimiento = cumplimiento
      ? `<span class="inline-block px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${cumplimiento.clase}">${cumplimiento.texto}</span>`
      : `<span class="text-xs text-slate-500">Sin horario</span>`;

    const badgeTipo = tipo === 'ENTRADA' 
      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
      : 'bg-rose-500/10 text-rose-400 border-rose-500/20';

    let badgeIA = `<span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"><i class="fa-solid fa-circle-check"></i> OK</span>`;
    
    if (esFraudeReal) {
      badgeIA = `<button data-accion="abrirModalAuditoriaPorId" data-a1="${firebaseId}" class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-extrabold bg-rose-500/20 text-rose-400 border border-rose-500/40 animate-pulse hover:bg-rose-500/30 transition shadow-lg cursor-pointer">
                  <i class="fa-solid fa-triangle-exclamation"></i> SOSPECHA DE FRAUDE
                 </button>`;
    } else if (esOfflinePendiente) {
      badgeIA = `<button data-accion="abrirModalAccionFraudePorId" data-a1="${firebaseId}" class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold bg-amber-500/15 text-amber-300 border border-amber-500/40 hover:bg-amber-500/25 transition cursor-pointer">
                  <i class="fa-regular fa-clock"></i> Pendiente de verificación
                 </button>`;
    } else if (distanciaEuclidiana !== null) {
      badgeIA = `<button data-accion="abrirModalAuditoriaPorId" data-a1="${firebaseId}" class="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-slate-700/60 text-slate-300 hover:bg-slate-700 border border-slate-600 transition">
                  <i class="fa-solid fa-brain text-emerald-400"></i> Verificado (d: ${distanciaEuclidiana.toFixed(2)})
                 </button>`;
    }

    const btnMapa = (urlMapa && urlMapa.includes('http'))
      ? `<a href="${escaparHtml(urlMapa)}" target="_blank" class="inline-flex items-center gap-1 bg-sky-600/20 text-sky-400 hover:bg-sky-600/40 border border-sky-500/30 px-3 py-1 rounded-lg text-xs font-semibold transition">
          <i class="fa-solid fa-map-location-dot"></i> Mapa
         </a>`
      : `<span class="text-xs text-slate-500">Sin GPS</span>`;

    const btnFoto = (urlFoto && urlFoto.length > 50)
      ? `<button data-accion="abrirFoto" data-a1="${escaparHtml(urlFoto)}" class="inline-flex items-center gap-1 bg-amber-600/20 text-amber-400 hover:bg-amber-600/40 border border-amber-500/30 px-3 py-1 rounded-lg text-xs font-semibold transition">
          <i class="fa-solid fa-image"></i> Foto
         </button>`
      : `<span class="text-xs text-slate-500">Sin Foto</span>`;

    let btnAccionFraude = '';
    if (esFraudeReal) {
      btnAccionFraude = `<button data-accion="abrirModalAccionFraudePorId" data-a1="${firebaseId}" class="inline-flex items-center gap-1 bg-rose-600 hover:bg-rose-500 text-white font-bold px-2.5 py-1 rounded-lg text-xs transition shadow-md">
                          <i class="fa-solid fa-shield-cat"></i> 🚨 Resolver Fraude
                         </button>`;
    } else if (esOfflinePendiente) {
      btnAccionFraude = `<button data-accion="abrirModalAccionFraudePorId" data-a1="${firebaseId}" class="inline-flex items-center gap-1 bg-amber-600 hover:bg-amber-500 text-white font-bold px-2.5 py-1 rounded-lg text-xs transition shadow-md">
                          <i class="fa-solid fa-clipboard-check"></i> Revisar fichada
                         </button>`;
    }

    const tr = document.createElement('tr');
    let claseFilaCumpl = (cumplimiento && cumplimiento.fila) ? (' ' + cumplimiento.fila) : '';
    tr.className = esFraudeReal
      ? "bg-rose-950/20 hover:bg-rose-900/30 transition border-l-4 border-l-rose-500"
      : (esOfflinePendiente
          ? ("bg-amber-950/10 hover:bg-amber-900/20 transition border-l-4 border-l-amber-500" + claseFilaCumpl)
          : ("hover:bg-slate-700/30 transition" + claseFilaCumpl));
    tr.innerHTML = `
      <td class="p-4 font-mono text-xs text-slate-300">${fecha}</td>
      <td class="p-4 font-semibold text-white">${escaparHtml(legajo)}</td>
      <td class="p-4 font-medium text-slate-200">${escaparHtml(nombre)}</td>
      <td class="p-4 text-slate-400">${escaparHtml(objetivo)}</td>
      <td class="p-4 text-center">
        <span class="inline-block px-2.5 py-0.5 rounded-full text-xs font-bold border ${badgeTipo}">${escaparHtml(tipo)}</span>
      </td>
      <td class="p-4 text-center">${celdaCumplimiento}</td>
      <td class="p-4 text-center">${badgeIA}</td>
      <td class="p-4 text-center">${btnMapa}</td>
      <td class="p-4 text-center flex items-center justify-center gap-2">${btnFoto} ${btnAccionFraude}</td>
    `;
    cuerpo.appendChild(tr);
  });
}

function filtrarTablaMarcaciones() {
  const busqueda = document.getElementById('inputBusqueda').value.toLowerCase();
  const filtroTipo = document.getElementById('filtroTipo').value;
  const filtroAuditoria = document.getElementById('filtroAuditoria').value;

  datosFiltradosMarcaciones = datosMarcaciones.filter(fila => {
    const textoFila = `${fila[1]} ${fila[2]} ${fila[3]}`.toLowerCase();
    const coincideBusqueda = textoFila.includes(busqueda);
    const coincideTipo = (filtroTipo === 'TODOS') || (fila[4] === filtroTipo);
    
    let coincideAuditoria = true;
    const esOfflinePendienteFila = fila[14] === true;
    const esFraudeRealFila = fila[7] === true && !esOfflinePendienteFila;
    if (filtroAuditoria === 'FRAUDE') coincideAuditoria = esFraudeRealFila;
    if (filtroAuditoria === 'PENDIENTE') coincideAuditoria = esOfflinePendienteFila;
    if (filtroAuditoria === 'OK') coincideAuditoria = !esFraudeRealFila && !esOfflinePendienteFila;

    return coincideBusqueda && coincideTipo && coincideAuditoria;
  });

  // Orden REAL por fecha/hora (mas reciente primero) EN EL ORIGEN, para que la
  // tabla en pantalla Y los reportes detallados (Excel/PDF, que recorren esta
  // misma lista) queden siempre en el mismo orden cronologico. Antes el orden
  // dependia de las claves internas de Firebase, por eso una fichada podia
  // aparecer fuera de lugar. Las filas sin fecha valida quedan al final.
  datosFiltradosMarcaciones.sort((a, b) => {
    const ta = a && a[0] ? new Date(a[0]).getTime() : NaN;
    const tb = b && b[0] ? new Date(b[0]).getTime() : NaN;
    const va = Number.isFinite(ta) ? ta : -Infinity;
    const vb = Number.isFinite(tb) ? tb : -Infinity;
    return vb - va;
  });

  paginaActualMarcaciones = 1;
  renderizarTablaMarcaciones(datosFiltradosMarcaciones);
}

// --- PAGINACIÓN Y RESUMEN DE CUMPLIMIENTO (aditivo) ---
function actualizarControlesPaginacion(total, inicio, fin) {
  const totalPaginas = Math.max(1, Math.ceil(total / filasPorPaginaMarcaciones));
  const infoPagina = document.getElementById('infoPaginaMarcaciones');
  const infoRango = document.getElementById('infoRangoMarcaciones');
  if (infoPagina) infoPagina.innerText = `${paginaActualMarcaciones} / ${totalPaginas}`;
  if (infoRango) infoRango.innerText = total > 0 ? `Mostrando ${inicio + 1}-${fin} de ${total}` : 'Sin registros';
}

function irPaginaMarcaciones(delta) {
  const total = (datosFiltradosMarcaciones || []).length;
  const totalPaginas = Math.max(1, Math.ceil(total / filasPorPaginaMarcaciones));
  paginaActualMarcaciones = Math.min(totalPaginas, Math.max(1, paginaActualMarcaciones + delta));
  renderizarTablaMarcaciones(datosFiltradosMarcaciones);
}

function cambiarFilasPorPagina() {
  const sel = document.getElementById('selectFilasPorPagina');
  const val = parseInt(sel ? sel.value : '25', 10);
  filasPorPaginaMarcaciones = Number.isFinite(val) && val > 0 ? val : 25;
  paginaActualMarcaciones = 1;
  renderizarTablaMarcaciones(datosFiltradosMarcaciones);
}

// Cuenta los estados de cumplimiento sobre el conjunto filtrado y actualiza las tarjetas.
function actualizarResumenCumplimiento(registros) {
  let aTiempo = 0, tolerancia = 0, tarde = 0, anticipada = 0, extra = 0;
  (registros || []).forEach(fila => {
    const c = calcularCumplimientoFilaAdmin(fila);
    if (!c) return;
    if (c.estado === 'A_TIEMPO' || c.estado === 'EN_HORARIO') aTiempo++;
    else if (c.estado === 'TOLERANCIA') tolerancia++;
    else if (c.estado === 'TARDE') tarde++;
    else if (c.estado === 'ANTICIPADA') anticipada++;
    else if (c.estado === 'EXTRA') extra++;
  });
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.innerText = v; };
  set('resCumplATiempo', aTiempo);
  set('resCumplTolerancia', tolerancia);
  set('resCumplTarde', tarde);
  set('resCumplAnticipada', anticipada);
  set('resCumplExtra', extra);
}

function obtenerRegistroPorId(id) {
  return datosMarcaciones.find(f => f[11] === id);
}

function abrirModalAccionFraudePorId(id) {
  const registro = obtenerRegistroPorId(id);
  if (registro) abrirModalAccionFraude(registro);
}

function abrirModalAuditoriaPorId(id) {
  const registro = obtenerRegistroPorId(id);
  if (registro) abrirModalAuditoria(registro);
}

function abrirModalAccionFraude(registro) {
  registroFraudeSeleccionado = registro;
  document.getElementById('fraudeFirebaseId').value = registro[11];

  const esOfflinePendiente = registro[14] === true;
  const esFraudeReal = registro[7] === true && !esOfflinePendiente;

  const icono = document.getElementById('fraudeModalIcono');
  const titulo = document.getElementById('fraudeModalTitulo');
  const subtitulo = document.getElementById('fraudeModalSubtitulo');
  if (esFraudeReal) {
    icono.className = "w-10 h-10 bg-rose-500/20 border border-rose-500/40 rounded-xl flex items-center justify-center text-rose-400 text-lg";
    icono.innerHTML = '<i class="fa-solid fa-shield-cat"></i>';
    titulo.innerText = "Gestión de alerta de fraude";
    subtitulo.innerText = "Revisá la evidencia y decidí sobre esta marcación.";
  } else {
    // Fichada sin conexión: lenguaje conservador y profesional (no acusatorio).
    icono.className = "w-10 h-10 bg-amber-500/20 border border-amber-500/40 rounded-xl flex items-center justify-center text-amber-300 text-lg";
    icono.innerHTML = '<i class="fa-regular fa-clock"></i>';
    titulo.innerText = "Revisión de fichada sin conexión";
    subtitulo.innerText = "Se registró sin internet y no pudo verificarse en el momento. Revisala y decidí.";
  }

  const fecha = registro[0] ? new Date(registro[0]).toLocaleString('es-AR', { hour12: false }) : '-';
  const motivoTxt = registro[15] || registro[9] || '';
  document.getElementById('fraudeDetalleFichada').innerHTML = `
    <p><strong>Empleado:</strong> ${escaparHtml(registro[2])} (Legajo: ${escaparHtml(registro[1])})</p>
    <p><strong>Objetivo:</strong> ${escaparHtml(registro[3])} - <strong>Tipo:</strong> ${escaparHtml(registro[4])}</p>
    <p><strong>Fecha/Hora:</strong> ${fecha}</p>
    ${motivoTxt ? `<p><strong>Estado:</strong> ${escaparHtml(motivoTxt)}</p>` : ''}
  `;

  document.getElementById('modalAccionFraude').classList.remove('hidden');
}

function cerrarModalAccionFraude() {
  document.getElementById('modalAccionFraude').classList.add('hidden');
}

async function aprobarFraudeManual() {
  const id = document.getElementById('fraudeFirebaseId').value;
  if (!id) return;

  try {
    // MIGRADO A SERVER-SIDE (hallazgo #4): la validacion de la fichada la realiza
    // el Worker con la service account y escribe la auditoria FICHADA_APROBADA de
    // forma atomica (fail-closed). El cliente ya NO hace el PATCH por REST.
    await window.llamarWorkerAdmin({ accion: 'validarFichada', fichadaId: id, motivo: 'Validada manualmente por el administrador' });

    // VERIFICACION EN LA BASE: releemos ESTA fichada (sin cache) y confirmamos
    // que la marca de resolucion quedo realmente escrita antes de dar el OK.
    // Asi el cartel de exito refleja el estado REAL de la base, no la respuesta
    // del Worker a ciegas.
    const resCheck = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/fichadas/${id}.json?ts=${Date.now()}`), { cache: 'no-store' });
    const fichadaBase = resCheck.ok ? await resCheck.json().catch(() => null) : null;
    if (!fichadaBase || fichadaBase.verificacionOfflineResuelta !== true) {
      throw new Error('la base no confirmo el cambio (el estado no persistio). Reintenta.');
    }

    alert("Fichada validada correctamente (confirmado en la base de datos).");
    cerrarModalAccionFraude();
    recargarDatosEfectivo();
  } catch (e) {
    alert("Error al actualizar la marcación: " + e.toString());
  }
}

async function eliminarFraudeMarca() {
  const id = document.getElementById('fraudeFirebaseId').value;
  if (!id) return;

  // ANULACION LOGICA (no borra): la marcacion se conserva en la base como
  // evidencia laboral y queda marcada como anulada, con motivo, quien y cuando.
  // Deja de mostrarse en la tabla y de contar en reportes/horas/alertas.
  const motivo = prompt("Motivo de la anulación de esta fichada (queda registrado; la fichada NO se borra):", "");
  if (motivo === null) return; // el admin canceló
  if (!confirm("Se anulará esta fichada: queda guardada como evidencia, marcada como anulada y sin contar en los reportes. ¿Confirmás?")) return;

  try {
    // MIGRADO A SERVER-SIDE: el Worker realiza la anulacion logica de la
    // fichada (conserva evidencia) y escribe la auditoria atomicamente.
    await window.llamarWorkerAdmin({ accion: 'anularFichada', fichadaId: id, motivo: motivo || 'Anulada por el administrador' });
    alert("Fichada anulada. Queda guardada como evidencia y no se contabiliza en los reportes.");
    cerrarModalAccionFraude();
    recargarDatosEfectivo();
  } catch (e) {
    alert("Error al anular la marcación: " + e.toString());
  }
}

function verAuditoriaDesdeAccion() {
  if (registroFraudeSeleccionado) {
    const registroParaAuditoria = [...registroFraudeSeleccionado];
    cerrarModalAccionFraude();
    abrirModalAuditoria(registroParaAuditoria);
  } else {
    alert("No se pudo obtener la información de la evidencia para este registro.");
  }
}

function abrirModalAuditoria(registro) {
  const alertaFraude = registro[7];
  const esOfflinePendiente = registro[14] === true;
  const esFraudeReal = alertaFraude === true && !esOfflinePendiente;
  const distancia = registro[8];
  const motivo = registro[9];
  const fotoFichada = registro[6];
  const fotoMaster = registro[10];

  const box = document.getElementById('boxAlertaAuditoria');
  const lblTipo = document.getElementById('lblTipoAlerta');
  const lblDist = document.getElementById('lblDistanciaEuclidiana');
  const lblMotivo = document.getElementById('lblMotivoFraude');

  if (esFraudeReal) {
    box.className = "p-4 rounded-xl border flex flex-col gap-2 bg-rose-950/40 border-rose-500/50 text-rose-200";
    lblTipo.innerText = "🚨 ALERTA: Sospecha de Suplantación o Fraude";
    lblMotivo.innerText = motivo || "La coincidencia facial no alcanzó el umbral de seguridad requerido o se detectó uso de foto estática/pantalla.";
  } else if (esOfflinePendiente) {
    box.className = "p-4 rounded-xl border flex flex-col gap-2 bg-amber-950/40 border-amber-500/50 text-amber-200";
    lblTipo.innerText = "🕒 Pendiente de verificación (fichada sin conexión)";
    lblMotivo.innerText = registro[15] || motivo || "La identidad no pudo verificarse en el momento por falta de conexión. Revisá la evidencia disponible antes de validar o anular.";
  } else {
    box.className = "p-4 rounded-xl border flex flex-col gap-2 bg-emerald-950/40 border-emerald-500/50 text-emerald-200";
    lblTipo.innerText = "✅ Verificación Satisfactoria";
    lblMotivo.innerText = "La coincidencia de rasgos biométricos se encuentra dentro del rango de tolerancia permitido.";
  }

  lblDist.innerText = (distancia !== null && !isNaN(distancia)) ? `Distancia Euclidiana: ${distancia.toFixed(4)}` : "Distancia N/A";

  document.getElementById('imgAuditoriaFichada').src = fotoFichada || '';
  document.getElementById('imgAuditoriaMaster').src = fotoMaster || fotoFichada || '';

  document.getElementById('modalAuditoriaIA').classList.remove('hidden');
}

function cerrarModalAuditoria() {
  document.getElementById('modalAuditoriaIA').classList.add('hidden');
}

function renderizarTablaNovedades(registros) {
  const cuerpo = document.getElementById('cuerpoTablaNovedades');
  cuerpo.innerHTML = "";

  if (!registros || registros.length === 0) {
    cuerpo.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-slate-400">No hay novedades registradas.</td></tr>`;
    return;
  }

  // La lista ya llega ordenada por fecha desc desde filtrarTablaNovedades;
  // reordenamos aqui por robustez para dejar siempre la mas reciente arriba
  // (sin depender del orden interno de las claves de Firebase).
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
    const tipoIncidencia = fila[4] || '-';
    const descripcion = fila[5] || '-';
    const urlMapa = fila[6] || '';
    const urlFoto = fila[7] || '';

    const btnMapa = (urlMapa && urlMapa.includes('http'))
      ? `<a href="${escaparHtml(urlMapa)}" target="_blank" class="inline-flex items-center gap-1 bg-sky-600/20 text-sky-400 hover:bg-sky-600/40 border border-sky-500/30 px-3 py-1 rounded-lg text-xs font-semibold transition">
          <i class="fa-solid fa-map-location-dot"></i> Mapa
         </a>`
      : `<span class="text-xs text-slate-500">Sin GPS</span>`;

    const btnFoto = (urlFoto && urlFoto.length > 50)
      ? `<button data-accion="abrirFoto" data-a1="${escaparHtml(urlFoto)}" class="inline-flex items-center gap-1 bg-amber-600/20 text-amber-400 hover:bg-amber-600/40 border border-amber-500/30 px-3 py-1 rounded-lg text-xs font-semibold transition">
          <i class="fa-solid fa-image"></i> Foto
         </button>`
      : `<span class="text-xs text-slate-500">Sin Foto</span>`;

    const tr = document.createElement('tr');
    tr.className = "hover:bg-slate-700/30 transition";
    tr.innerHTML = `
      <td class="p-4 font-mono text-xs text-slate-300">${fecha}</td>
      <td class="p-4"><span class="font-bold text-white">${escaparHtml(nombre)}</span><br><span class="text-xs text-slate-400">Leg: ${escaparHtml(legajo)}</span></td>
      <td class="p-4 text-slate-300">${escaparHtml(objetivo)}</td>
      <td class="p-4"><span class="bg-amber-500/10 text-amber-400 border border-amber-500/20 px-2 py-0.5 rounded text-xs font-bold">${escaparHtml(tipoIncidencia)}</span></td>
      <td class="p-4 text-slate-200" style="max-width: 300px; white-space: normal; word-break: break-word;">${escaparHtml(descripcion)}</td>
      <td class="p-4 text-center">${btnMapa}</td>
      <td class="p-4 text-center">${btnFoto}</td>
    `;
    cuerpo.appendChild(tr);
  });
}

function renderizarTablaPanicos(registros) {
  const cuerpo = document.getElementById('cuerpoTablaPanicos');
  cuerpo.innerHTML = "";

  if (!registros || registros.length === 0) {
    cuerpo.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-slate-400">No hay alertas de pánico registradas.</td></tr>`;
    return;
  }

  // Ordenar del más reciente al más antiguo
  const ordenados = [...registros].reverse();

  ordenados.forEach(fila => {
    const id = fila[0];
    const rawFecha = fila[1];
    
    // Formateo seguro de la fecha y hora para Argentina (DD/MM/YYYY HH:mm:ss)
    let fechaFormateada = '-';
    if (rawFecha) {
      const fechaObj = !isNaN(rawFecha) ? new Date(Number(rawFecha)) : new Date(rawFecha);
      if (!isNaN(fechaObj.getTime())) {
        fechaFormateada = fechaObj.toLocaleString('es-AR', { hour12: false });
      } else {
        fechaFormateada = String(rawFecha);
      }
    }

    const legajo = fila[2];
    const nombre = fila[3];
    const objetivo = fila[4];
    const estado = fila[5];
    const urlMapa = fila[6];

    const badgeEstado = estado === 'ATENDIDO' 
      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
      : 'bg-rose-500/10 text-rose-400 border-rose-500/20 animate-pulse';

    const btnMapa = (urlMapa && urlMapa.includes('http'))
      ? `<a href="${escaparHtml(urlMapa)}" target="_blank" class="inline-flex items-center gap-1 bg-sky-600/20 text-sky-400 hover:bg-sky-600/40 border border-sky-500/30 px-3 py-1 rounded-lg text-xs font-semibold transition">
          <i class="fa-solid fa-map-location-dot"></i> Mapa
         </a>`
      : `<span class="text-xs text-slate-500">Sin GPS</span>`;

    const tr = document.createElement('tr');
    tr.className = "hover:bg-slate-700/30 transition";
    tr.innerHTML = `
      <td class="p-4 font-mono text-xs text-slate-300">${fechaFormateada}</td>
      <td class="p-4 font-bold text-white">${escaparHtml(legajo)}</td>
      <td class="p-4 font-medium text-slate-200">${escaparHtml(nombre)}</td>
      <td class="p-4 text-slate-400">${escaparHtml(objetivo)}</td>
      <td class="p-4 text-center">
        <span class="inline-block px-2.5 py-1 rounded-full text-xs font-bold border ${badgeEstado}">${escaparHtml(estado)}</span>
      </td>
      <td class="p-4 text-center">${btnMapa}</td>
      <td class="p-4 text-center">
        <button data-accion="eliminarPanico" data-a1="${escaparHtml(id)}" class="bg-rose-600/20 text-rose-400 hover:bg-rose-600/40 border border-rose-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1">
          <i class="fa-solid fa-ban"></i> Anular
        </button>
      </td>
    `;
    cuerpo.appendChild(tr);
  });
}

async function eliminarPanico(id) {
  // ANULACION LOGICA (no borra): el panico se conserva en la base como
  // evidencia y queda marcado como anulado, con motivo, quien y cuando.
  const motivo = prompt("Motivo de la ANULACIÓN de este pánico (queda registrado; el registro NO se borra):", "");
  if (motivo === null) return; // el admin canceló
  if (!confirm("Se ANULARÁ este registro de pánico: queda guardado como evidencia y marcado como anulado. ¿Confirmás?")) return;
  try {
    // MIGRADO A SERVER-SIDE: el Worker realiza la anulacion logica del panico
    // (estado ANULADO + anulado=true para compat con el filtro de la UI) y
    // escribe la auditoria atomicamente con la service account.
    await window.llamarWorkerAdmin({ accion: 'atenderPanico', panicoId: id, estado: 'ANULADO', nota: motivo || '' });
    alert("Registro de pánico anulado. Queda guardado como evidencia.");
    recargarDatosEfectivo();
  } catch (e) {
    alert("Error al anular el registro: " + e.toString());
  }
}

function filtrarTablaNovedades() {
  const busqueda = document.getElementById('inputBusquedaNovedades').value.toLowerCase();

  datosFiltradosNovedades = datosNovedades.filter(fila => {
    const textoFila = `${fila[1]} ${fila[2]} ${fila[3]} ${fila[4]} ${fila[5]}`.toLowerCase();
    return textoFila.includes(busqueda);
  });

  // Orden REAL por fecha/hora (mas reciente primero) EN EL ORIGEN, para que la
  // tabla de novedades en pantalla Y los reportes (Excel/PDF, que recorren esta
  // misma lista) queden en el mismo orden cronologico. Las filas sin fecha
  // valida quedan al final.
  datosFiltradosNovedades.sort((a, b) => {
    const ta = a && a[0] ? new Date(a[0]).getTime() : NaN;
    const tb = b && b[0] ? new Date(b[0]).getTime() : NaN;
    const va = Number.isFinite(ta) ? ta : -Infinity;
    const vb = Number.isFinite(tb) ? tb : -Infinity;
    return vb - va;
  });

  renderizarTablaNovedades(datosFiltradosNovedades);
}

function renderizarTablaPersonal(registros) {
  const cuerpo = document.getElementById('cuerpoTablaPersonal');
  const cuerpoRoles = document.getElementById('cuerpoTablaRoles');
  cuerpo.innerHTML = "";
  if (cuerpoRoles) cuerpoRoles.innerHTML = "";
  if (!registros || registros.length === 0) {
    cuerpo.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-slate-400">No hay personal registrado.</td></tr>`;
    if (cuerpoRoles) cuerpoRoles.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-slate-400">No hay supervisores ni administradores.</td></tr>`;
    return;
  }
  let nVig = 0, nRoles = 0;
  registros.forEach(fila => {
    const firebaseId = fila[5];
    const rol = mapaRolesUsuarios[firebaseId] || 'empleado';
    const esRol = (rol === 'supervisor' || rol === 'admin');
    const tr = construirFilaPersonal(fila, rol);
    if (esRol && cuerpoRoles) { cuerpoRoles.appendChild(tr); nRoles++; }
    else { cuerpo.appendChild(tr); nVig++; }
  });
  if (nVig === 0) cuerpo.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-slate-400">No hay vigiladores registrados.</td></tr>`;
  if (cuerpoRoles && nRoles === 0) cuerpoRoles.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-slate-400">No hay supervisores ni administradores.</td></tr>`;
}

// Construye una fila de la tabla de personal. Si el usuario es supervisor/admin
// se le agrega una etiqueta de rol junto al nombre (misma estructura de columnas).
function construirFilaPersonal(fila, rol) {
    const legajoStr = String(fila[0]);
    const nombreStr = fila[1] || '';
    const pinStr = fila[3] || '****';
    const estadoStr = fila[4] || 'ACTIVO';
    const firebaseId = fila[5];
    const fotoMaster = fila[6] || '';
    const cfg = mapaConfiguracionPersonal[firebaseId] || {};
    const h = cfg.horarioHabitual || {};
    const objetivos = Array.isArray(cfg.objetivosAsignados) ? cfg.objetivosAsignados : [];
    const horarioTexto = h.inicio && h.fin ? `${h.inicio} - ${h.fin}` : 'Sin horario habitual';
    const objetivosTexto = objetivos.length ? `${objetivos.length} autorizado(s)` : 'Sin objetivos asignados';
    const esRol = (rol === 'supervisor' || rol === 'admin');
    const badgeRol = esRol
      ? `<span class="ml-2 align-middle text-[10px] font-bold uppercase px-2 py-0.5 rounded ${rol === 'admin' ? 'bg-rose-500/15 text-rose-300 border border-rose-500/40' : 'bg-indigo-500/15 text-indigo-300 border border-indigo-500/40'}">${rol === 'admin' ? 'Administrador' : 'Supervisor'}</span>`
      : '';
    // Linea secundaria: para vigiladores el horario/objetivos; para roles, como ingresan al panel.
    const subLinea = esRol
      ? `Ingreso al panel: legajo ${escaparHtml(legajoStr)} + PIN`
      : `${escaparHtml(horarioTexto)} · ${escaparHtml(objetivosTexto)}`;
    const btnFotoMaster = (fotoMaster && fotoMaster.length > 50)
      ? `<button data-accion="abrirFoto" data-a1="${escaparHtml(fotoMaster)}" class="inline-flex items-center gap-1 bg-amber-600/20 text-amber-400 hover:bg-amber-600/40 border border-amber-500/30 px-3 py-1 rounded-lg text-xs font-semibold transition"><i class="fa-solid fa-id-card"></i> Ver Foto</button>`
      : `<span class="text-xs text-slate-500">Sin Foto</span>`;
    const esActivoVig = String(estadoStr).trim().toUpperCase() === 'ACTIVO';
    const claseEstadoVig = esActivoVig ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/15 text-rose-400 border border-rose-500/40';
    const btnEstadoVig = esActivoVig
      ? `<button data-accion="cambiarEstadoPersonal" data-a1="${escaparHtml(firebaseId)}" data-a2="true" class="bg-orange-600/20 text-orange-400 hover:bg-orange-600/40 border border-orange-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1"><i class="fa-solid fa-user-slash"></i> Dar de baja</button>`
      : `<button data-accion="cambiarEstadoPersonal" data-a1="${escaparHtml(firebaseId)}" data-a2="false" class="bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/40 border border-emerald-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1"><i class="fa-solid fa-user-check"></i> Reactivar</button>`;
    // El boton "Turnos" solo tiene sentido para vigiladores (fichan en un puesto).
    const btnTurnos = esRol ? '' : `<button data-accion="abrirModalTurnosPersonal" data-a1="${escaparHtml(firebaseId)}" class="bg-sky-600/20 text-sky-400 hover:bg-sky-600/40 border border-sky-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1"><i class="fa-solid fa-calendar-days"></i> Turnos</button>`;
    const tr = document.createElement('tr');
    tr.className = "hover:bg-slate-700/30 transition";
    tr.innerHTML = `
      <td class="p-4 font-bold text-amber-400">${escaparHtml(legajoStr)}</td>
      <td class="p-4 font-medium text-white">${escaparHtml(nombreStr)}${badgeRol}<div class="text-[11px] text-slate-500 mt-1">${subLinea}</div></td>
      <td class="p-4 text-center font-mono text-slate-400">${escaparHtml(pinStr)}</td>
      <td class="p-4 text-center">${btnFotoMaster}</td>
      <td class="p-4 text-center"><span class="${claseEstadoVig} px-2 py-1 rounded text-xs">${escaparHtml(estadoStr)}</span></td>
      <td class="p-4 text-center"><div class="flex flex-wrap justify-center gap-2">
        <button data-accion="abrirModalEditar" data-a1="${escaparHtml(firebaseId)}" class="bg-amber-600/20 text-amber-400 hover:bg-amber-600/40 border border-amber-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1"><i class="fa-solid fa-sliders"></i> Configurar</button>
        ${btnTurnos}
        ${btnEstadoVig}
        <button data-accion="eliminarPersonal" data-a1="${escaparHtml(firebaseId)}" class="bg-rose-600/20 text-rose-400 hover:bg-rose-600/40 border border-rose-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1"><i class="fa-solid fa-trash"></i> Eliminar</button>
      </div></td>`;
    return tr;
}

async function abrirModalEditar(id) {
  const cfg = mapaConfiguracionPersonal[id];
  if (!cfg) return alert('No se encontró el personal seleccionado. Actualizá los datos e intentá nuevamente.');
  document.getElementById('editFirebaseId').value = id;
  document.getElementById('editLegajo').value = cfg.legajo || '';
  document.getElementById('editNombre').value = cfg.nombre || '';
  document.getElementById('editPin').value = ''; // el PIN se guarda hasheado; vacío = no se cambia
  document.getElementById('editFotoMaster').value = '';
  const h = cfg.horarioHabitual || {};
  document.getElementById('editHorarioInicio').value = h.inicio || '';
  document.getElementById('editHorarioFin').value = h.fin || '';
  const preview = document.getElementById('previewFotoActual');
  preview.innerHTML = (cfg.fotoMaster && cfg.fotoMaster.length > 50)
    ? `<span class="text-emerald-400"><i class="fa-solid fa-check"></i> Posee foto máster cargada</span>`
    : `<span class="text-rose-400"><i class="fa-solid fa-xmark"></i> Sin foto máster</span>`;
  await cargarCheckboxObjetivosPersonal(cfg.objetivosAsignados || []);
  // Roles de control (supervisor/admin): NO se les asignan objetivos de fichada.
  // Se oculta el selector de objetivos y se muestra un aviso explicativo.
  const rolActual = mapaRolesUsuarios[id] || 'empleado';
  const esRolControl = (rolActual === 'supervisor' || rolActual === 'admin');
  const bloqueObj = document.getElementById('bloqueObjetivosEditar');
  const avisoRol = document.getElementById('avisoRolSinObjetivos');
  if (bloqueObj) bloqueObj.classList.toggle('hidden', esRolControl);
  if (avisoRol) avisoRol.classList.toggle('hidden', !esRolControl);
  document.getElementById('modalEditarPersonal').classList.remove('hidden');
}

async function cargarCheckboxObjetivosPersonal(asignados) {
  const cont = document.getElementById('editObjetivosAsignados');
  cont.innerHTML = '<span class="text-slate-400">Cargando objetivos...</span>';
  try {
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos.json?ts=${Date.now()}`), { cache: 'no-store' });
    const data = await res.json();
    cont.innerHTML = '';
    if (!data) { cont.innerHTML = '<span class="text-slate-500">No hay objetivos registrados.</span>'; return; }
    const arr = Object.entries(data).filter(([id,o]) => o && (o.nombre || o.codigo));
    if (!arr.length) { cont.innerHTML = '<span class="text-slate-500">No hay objetivos registrados.</span>'; return; }
    const idsAsignados = (Array.isArray(asignados) ? asignados : []).map(x => String(x.id || x.firebaseId || ''));
    arr.forEach(([id,o]) => {
      const checked = idsAsignados.includes(String(id));
      const label = document.createElement('label');
      label.className = 'flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg p-2 cursor-pointer hover:border-slate-600';
      label.innerHTML = `<input type="checkbox" class="objetivo-personal-checkbox accent-amber-500" value="${escaparHtml(id)}" data-nombre="${escaparHtml(o.nombre || o.codigo || '')}" ${checked ? 'checked' : ''}> <span class="text-slate-200">${escaparHtml(o.nombre || o.codigo || '')}</span>`;
      cont.appendChild(label);
    });
  } catch(e) {
    cont.innerHTML = '<span class="text-rose-400">No se pudieron cargar los objetivos.</span>';
  }
}

function cerrarModalEditar() { document.getElementById('modalEditarPersonal').classList.add('hidden'); }

async function guardarEdicionPersonal() {
  const id = document.getElementById('editFirebaseId').value;
  const legajo = document.getElementById('editLegajo').value.trim();
  const nombre = document.getElementById('editNombre').value.trim();
  const pin = document.getElementById('editPin').value.trim();
  const inputFoto = document.getElementById('editFotoMaster');
  const inicio = document.getElementById('editHorarioInicio').value;
  const fin = document.getElementById('editHorarioFin').value;
  const btn = document.getElementById('btnGuardarEdicion');
  if (!id || !legajo || !nombre) return alert('Completá legajo y nombre.');
  if ((inicio && !fin) || (!inicio && fin)) return alert('Completá ambos horarios habituales o dejalos vacíos.');
  // Si se escribió un PIN nuevo, exigimos que sea fuerte (sin secuencias ni
  // repeticiones ni PINs comunes). Vacío = se conserva el PIN actual.
  if (pin && window.validarFortalezaPin) {
    const _fp = window.validarFortalezaPin(pin);
    if (!_fp.ok) return alert('No se cambió el PIN: ' + _fp.mensaje + '\n\nDejá el campo PIN vacío para conservar el actual, o escribí uno más seguro.');
  }
  btn.disabled = true; btn.innerText = 'Guardando...';
  const objetivosAsignados = Array.from(document.querySelectorAll('.objetivo-personal-checkbox:checked')).map(cb => ({ id: cb.value, nombre: cb.dataset.nombre || '' }));
  // Blindaje: a los roles de control (supervisor/admin) nunca se les guardan
  // objetivos, aunque por algun motivo llegara a existir una seleccion previa.
  const rolGuardar = mapaRolesUsuarios[id] || 'empleado';
  const objetivosFinal = (rolGuardar === 'supervisor' || rolGuardar === 'admin') ? [] : objetivosAsignados;
  // El PIN nunca se guarda en texto plano: si se ingresó uno nuevo se deriva hash+salt;
  // si el campo queda vacío, se conserva el PIN actual.
  const fichaActual = mapaConfiguracionPersonal[id] || {};
  // Las Reglas FINALES exigen en /personal/<id>: legajo (STRING), nombre y estado.
  // Un PATCH que no reenvíe 'estado' (o con legajo numérico) es DENEGADO por .validate.
  // Por eso reenviamos estado (conservando el actual) y forzamos legajo como texto.
  const datosActualizados = { legajo: String(legajo).trim(), nombre, estado: (fichaActual.estado || 'activo'), horarioHabitual: { inicio: inicio || '', fin: fin || '' }, objetivosAsignados: objetivosFinal };
  // Las credenciales (pinHash/pinSalt) NO se guardan en /personal (nodo legible por
  // supervisores): se escriben en /credenciales/<id> (acceso solo admin/dueño por Reglas).
  let credencialNueva = null;
  if (pin) {
    const pinSaltEdit = window.generarSaltPin();
    credencialNueva = { pinHash: await window.hashPin(pin, pinSaltEdit), pinSalt: pinSaltEdit };
    datosActualizados.tienePin = true;
  } else {
    datosActualizados.tienePin = !!(fichaActual.tienePin || fichaActual.pinHash);
  }
  // Purga cualquier credencial vieja que hubiera quedado en /personal.
  datosActualizados.pin = null;
  datosActualizados.pinHash = null;
  datosActualizados.pinSalt = null;
  if (inputFoto.files && inputFoto.files[0]) datosActualizados.fotoMaster = await convertirImagenBase64(inputFoto.files[0]);
  // ================== INTENTO ATOMICO (server-side) ==================
  // Una sola llamada al Worker consolida ficha + credencial + Auth (PIN y/o
  // legajo/email) + identidad, con orden fail-fast (Auth primero). Evita el
  // estado "a medias" que producian las 4 escrituras sueltas de abajo.
  // Si el Worker es una version vieja que no conoce la accion, se cae con
  // gracia a la ruta clasica. Cualquier OTRO error (incluido 'inconsistente')
  // se informa y se ABORTA, para no duplicar escrituras por la ruta legacy.
  const legajoAnteriorAtom = String(fichaActual.legajo || '').trim();
  const legajoNuevoAtom = String(legajo).trim();
  const legajoCambioAtom = legajoAnteriorAtom !== '' && legajoAnteriorAtom !== legajoNuevoAtom;
  if (URL_WORKER_AUTH) {
    try {
      const payloadAtom = { accion: 'actualizarEmpleado', uid: id, personal: datosActualizados, usuario: { legajo: legajoNuevoAtom, nombre } };
      if (credencialNueva) { payloadAtom.credencial = credencialNueva; payloadAtom.nuevaClave = String(pin).trim().padStart(6, '0'); }
      if (legajoCambioAtom) payloadAtom.nuevoEmail = legajoNuevoAtom + '@vga.security24';
      await window.llamarWorkerAdmin(payloadAtom);
      // Exito atomico: el Worker ya audito. Refrescamos cache local y cerramos
      // SIN ejecutar las escrituras sueltas de abajo (ruta no atomica).
      mapaConfiguracionPersonal[id] = { ...(mapaConfiguracionPersonal[id] || {}), ...datosActualizados };
      cerrarModalEditar();
      recargarDatosEfectivo();
      btn.disabled = false; btn.innerText = 'Guardar Cambios';
      // Si se cambio el PIN, mostramos el comprobante (unica vez que se ve en claro).
      if (pin && typeof window.mostrarComprobantePin === 'function') {
        window.mostrarComprobantePin({ legajo: String(legajo).trim(), nombre, pin: String(pin).trim(), rol: rolGuardar, modo: 'cambio' });
      } else {
        alert('Personal actualizado con éxito.');
      }
      return;
    } catch (eAtom) {
      // [#4] El panel ya NO escribe /personal, /usuarios ni /credenciales de forma
      //      directa (las Reglas los tienen en .write:false). Toda la edicion pasa
      //      por el Worker; cualquier error se informa y se ABORTA, sin ruta legacy.
      const msgAtom = String((eAtom && eAtom.message) || eAtom);
      alert('No se pudo guardar los cambios: ' + msgAtom);
      btn.disabled = false; btn.innerText = 'Guardar Cambios';
      return;
    }
  } else {
    alert('No se puede guardar: el servicio de administración (Worker) no está configurado (URL_WORKER_AUTH vacío).');
    btn.disabled = false; btn.innerText = 'Guardar Cambios';
  }
}

// Activa / da de baja a un vigilador. Un legajo INACTIVO no puede fichar
// (el bloqueo se aplica del lado del portal de fichaje).
async function cambiarEstadoPersonal(firebaseId, estabaActivo) {
  const nuevoEstado = estabaActivo ? 'INACTIVO' : 'ACTIVO';
  const accion = estabaActivo ? 'dar de baja' : 'reactivar';
  if (!confirm(`¿Seguro que querés ${accion} a este vigilador? Un legajo dado de baja no podrá fichar.`)) return;
  try {
    // [#4] El estado ya NO se escribe directo en /personal (Reglas .write:false).
    //      Pasa por el Worker (actualizarEmpleado), que patchea /personal con la
    //      service account y audita el cambio server-side.
    await window.llamarWorkerAdmin({ accion: 'actualizarEmpleado', uid: firebaseId, personal: { estado: nuevoEstado } });
    if (mapaConfiguracionPersonal[firebaseId]) mapaConfiguracionPersonal[firebaseId].estado = nuevoEstado;
    alert(estabaActivo ? 'Vigilador dado de baja. Ya no podrá fichar.' : 'Vigilador reactivado.');
    recargarDatosEfectivo();
  } catch(err) { alert('No se pudo actualizar el estado: ' + ((err && err.message) || err)); }
}

async function eliminarPersonal(firebaseId) {
  if (!confirm(`¿Estás seguro de que deseas eliminar este registro? Se dará de baja su ficha, su identidad de acceso y sus credenciales.`)) return;
  const legajoElim = (mapaConfiguracionPersonal[firebaseId] || {}).legajo || '';
  // ================== INTENTO ATOMICO (server-side) ==================
  // Una sola llamada da de baja Auth PRIMERO (fail-fast) y luego limpia
  // credenciales/usuarios/personal con la service account, auditando una vez.
  // Evita el estado "ficha borrada pero cuenta de Auth viva". Si el Worker es
  // una version vieja que no conoce la accion, cae a la ruta clasica.
  if (URL_WORKER_AUTH) {
    try {
      await window.llamarWorkerAdmin({ accion: 'darDeBajaEmpleado', uid: firebaseId, modo: 'ELIMINAR' });
      delete mapaConfiguracionPersonal[firebaseId];
      alert('Registro eliminado con éxito (ficha, identidad, credenciales y acceso).');
      recargarDatosEfectivo();
      return;
    } catch (eAtomDel) {
      // [#4] El panel ya NO borra /personal, /usuarios ni /credenciales de forma
      //      directa (Reglas .write:false). Toda la baja pasa por el Worker;
      //      cualquier error se informa y se ABORTA, sin ruta legacy.
      const msgAtomDel = String((eAtomDel && eAtomDel.message) || eAtomDel);
      alert('No se pudo eliminar el registro: ' + msgAtomDel);
      return;
    }
  } else {
    alert('No se puede eliminar: el servicio de administración (Worker) no está configurado (URL_WORKER_AUTH vacío).');
  }
}

async function abrirModalTurnosPersonal(id) {
  const cfg = mapaConfiguracionPersonal[id];
  if (!cfg) return alert('No se encontró el vigilador.');
  personalConfigurandoId = id;
  document.getElementById('turnoFirebaseId').value = '';
  document.getElementById('turnoFecha').value = '';
  document.getElementById('turnoHoraInicio').value = '';
  document.getElementById('turnoHoraFin').value = '';
  document.getElementById('turnoObservacion').value = '';
  document.getElementById('turnosPersonalSubtitulo').innerText = `${cfg.nombre || ''} · Legajo ${cfg.legajo || ''}`;
  await cargarObjetivosTurno(cfg.objetivosAsignados || []);
  await cargarAsignacionesTurnoPersonal();
  document.getElementById('modalTurnosPersonal').classList.remove('hidden');
}

async function cargarObjetivosTurno(asignados) {
  const sel = document.getElementById('turnoObjetivo');
  sel.innerHTML = '<option value="">Cargando objetivos...</option>';
  try {
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos.json?ts=${Date.now()}`), { cache: 'no-store' });
    const data = await res.json();
    sel.innerHTML = '<option value="">Seleccione objetivo</option>';
    const lista = data ? Object.entries(data).filter(([id,o]) => o && (o.nombre || o.codigo)) : [];
    lista.forEach(([id,o]) => sel.insertAdjacentHTML('beforeend', `<option value="${escaparHtml(id)}">${escaparHtml(o.nombre || o.codigo || id)}</option>`));
    if (!lista.length) sel.innerHTML = '<option value="">No hay objetivos registrados</option>';
  } catch(e) {
    sel.innerHTML = '<option value="">No se pudieron cargar los objetivos</option>';
  }
}

async function cargarAsignacionesTurnoPersonal() {
  const cuerpo = document.getElementById('cuerpoTurnosPersonal');
  cuerpo.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-slate-500">Cargando turnos...</td></tr>';
  try {
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/asignacionesTurnos.json?ts=${Date.now()}`), { cache: 'no-store' });
    const data = await res.json();
    asignacionesTurnosAdmin = data ? Object.entries(data).map(([id,d]) => ({...d, id})).filter(d => mismoLegajoAdmin(d.legajo, mapaConfiguracionPersonal[personalConfigurandoId]?.legajo)) : [];
    asignacionesTurnosAdmin.sort((a,b) => String(a.fecha || '').localeCompare(String(b.fecha || '')));
    cuerpo.innerHTML = '';
    if (!asignacionesTurnosAdmin.length) { cuerpo.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-slate-500">No hay cambios de turno registrados.</td></tr>'; return; }
    asignacionesTurnosAdmin.forEach(t => {
      const tr=document.createElement('tr'); tr.className='border-t border-slate-800';
      tr.innerHTML=`<td class="p-3 text-slate-200">${escaparHtml(t.fecha||'')}</td><td class="p-3 text-slate-200">${escaparHtml(t.objetivoNombre||t.objetivo||'')}</td><td class="p-3 font-mono text-emerald-300">${escaparHtml(t.horaInicio||'')} - ${escaparHtml(t.horaFin||'')}</td><td class="p-3 text-slate-400">${escaparHtml(t.observacion||'')}</td><td class="p-3 text-center"><button data-accion="editarAsignacionTurno" data-a1="${escaparHtml(t.id)}" class="text-amber-400 hover:text-amber-300 mr-3"><i class="fa-solid fa-pen"></i></button><button data-accion="eliminarAsignacionTurno" data-a1="${escaparHtml(t.id)}" class="text-rose-400 hover:text-rose-300"><i class="fa-solid fa-trash"></i></button></td>`;
      cuerpo.appendChild(tr);
    });
  } catch(e) { cuerpo.innerHTML='<tr><td colspan="5" class="p-6 text-center text-rose-400">No se pudieron cargar los turnos.</td></tr>'; }
}

async function guardarAsignacionTurno(e) {
  e.preventDefault();
  const cfg=mapaConfiguracionPersonal[personalConfigurandoId]; if(!cfg) return;
  const id=document.getElementById('turnoFirebaseId').value;
  const fecha=document.getElementById('turnoFecha').value;
  const objetivoId=document.getElementById('turnoObjetivo').value;
  const objetivoNombre=document.getElementById('turnoObjetivo').selectedOptions[0]?.textContent || '';
  const horaInicio=document.getElementById('turnoHoraInicio').value;
  const horaFin=document.getElementById('turnoHoraFin').value;
  const observacion=document.getElementById('turnoObservacion').value.trim();
  if(!fecha||!objetivoId||!horaInicio||!horaFin) return alert('Completá fecha, objetivo, inicio y fin.');
  const payload={legajo:String(cfg.legajo||''), nombre:cfg.nombre||'', objetivoId, objetivoNombre, fecha, horaInicio, horaFin, observacion, actualizadoEn:new Date().toISOString()};
  const btn=document.getElementById('btnGuardarTurno'); btn.disabled=true; btn.innerText='Guardando...';
  try{
    const url=id?`${URL_FIREBASE}/asignacionesTurnos/${id}.json`:`${URL_FIREBASE}/asignacionesTurnos.json`;
    const res=await fetch(await window.urlConAuthAdmin(url),{method:id?'PATCH':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    if(!res.ok) throw new Error('Firebase rechazó el turno');
    registrarAuditoria(id?'TURNO_EDITADO':'TURNO_CREADO', id?`asignacionesTurnos/${id}`:'asignacionesTurnos', { legajo:String(cfg.legajo||''), fecha, objetivo:objetivoNombre, horaInicio, horaFin });
    alert(id?'Turno actualizado correctamente.':'Turno asignado correctamente.');
    document.getElementById('turnoFirebaseId').value=''; document.getElementById('turnoFecha').value=''; document.getElementById('turnoHoraInicio').value=''; document.getElementById('turnoHoraFin').value=''; document.getElementById('turnoObservacion').value='';
    cargarAsignacionesTurnoPersonal();
  }catch(e){alert('No se pudo guardar el turno: '+e.toString());}finally{btn.disabled=false;btn.innerHTML='<i class="fa-solid fa-save"></i> Guardar';}
}

function editarAsignacionTurno(id){
  const t=asignacionesTurnosAdmin.find(x=>String(x.id)===String(id)); if(!t)return;
  document.getElementById('turnoFirebaseId').value=t.id; document.getElementById('turnoFecha').value=t.fecha||''; document.getElementById('turnoObjetivo').value=t.objetivoId||''; document.getElementById('turnoHoraInicio').value=t.horaInicio||''; document.getElementById('turnoHoraFin').value=t.horaFin||''; document.getElementById('turnoObservacion').value=t.observacion||'';
  document.getElementById('btnGuardarTurno').innerHTML='<i class="fa-solid fa-save"></i> Actualizar';
}
async function eliminarAsignacionTurno(id){ if(!confirm('¿Eliminar esta asignación de turno?'))return; try{const r=await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/asignacionesTurnos/${id}.json`),{method:'DELETE'});if(!r.ok)throw new Error('Error');registrarAuditoria('TURNO_ELIMINADO', `asignacionesTurnos/${id}`, {});cargarAsignacionesTurnoPersonal();}catch(e){alert('No se pudo eliminar el turno.');} }
function cerrarModalTurnosPersonal(){document.getElementById('modalTurnosPersonal').classList.add('hidden');personalConfigurandoId=null;}

// =========================
// OBJETIVOS / UBICACIONES
// Geocodificación gratuita con OpenStreetMap + Nominatim.
// =========================
let mapaObjetivoNuevo = null;
let marcadorObjetivoNuevo = null;
let mapaObjetivoEditar = null;
let marcadorObjetivoEditar = null;
let objetivoEditandoId = null;
let ultimaBusquedaNominatim = 0;
let resultadosNominatim = { nuevo: [], editar: [] };

function escaparHtml(valor) {
  return String(valor ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function validarCoordenadas(lat, lon) {
  const latNum = Number(lat);
  const lonNum = Number(lon);
  return Number.isFinite(latNum) && Number.isFinite(lonNum) && latNum >= -90 && latNum <= 90 && lonNum >= -180 && lonNum <= 180;
}

function formatearCoordenada(valor) {
  const n = Number(valor);
  return Number.isFinite(n) ? n.toFixed(6) : '';
}

function mostrarInfoUbicacion(modo, texto, tipo = 'info') {
  const id = modo === 'nuevo' ? 'infoUbicacionNuevo' : 'infoUbicacionEditar';
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.remove('hidden');
  el.className = `rounded-xl p-3 text-xs border ${tipo === 'error' ? 'bg-rose-500/10 border-rose-500/20 text-rose-200' : tipo === 'success' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-200' : 'bg-sky-500/10 border-sky-500/20 text-sky-200'}`;
  el.innerHTML = texto;
}

function ocultarInfoUbicacion(modo) {
  const id = modo === 'nuevo' ? 'infoUbicacionNuevo' : 'infoUbicacionEditar';
  const el = document.getElementById(id);
  if (el) el.classList.add('hidden');
}

async function obtenerMapaObjetivo(modo) {
  await lazyLeaflet();
  const esNuevo = modo === 'nuevo';
  const contenedorId = esNuevo ? 'mapaObjetivoNuevo' : 'mapaObjetivoEditar';
  const mapaExistente = esNuevo ? mapaObjetivoNuevo : mapaObjetivoEditar;
  if (mapaExistente) return mapaExistente;

  const contenedor = document.getElementById(contenedorId);
  if (!contenedor) return null;
  contenedor.classList.remove('hidden');

  const mapa = L.map(contenedorId, { scrollWheelZoom: true }).setView([-34.545, -58.71], 13);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19,
    attribution: '&copy; OpenStreetMap contributors'
  }).addTo(mapa);

  if (esNuevo) mapaObjetivoNuevo = mapa;
  else mapaObjetivoEditar = mapa;
  setTimeout(() => mapa.invalidateSize(), 150);
  return mapa;
}

async function colocarMarcadorObjetivo(modo, lat, lon, zoom = 18, draggable = true) {
  if (!validarCoordenadas(lat, lon)) return;
  // Esperar a que Leaflet (lazy) termine de cargar ANTES de usar 'L'.
  // Antes esto era sincronico y usaba 'L' sin cargar -> 'L is not defined'.
  const mapa = await obtenerMapaObjetivo(modo);
  if (!mapa) return;

  const esNuevo = modo === 'nuevo';
  let marcador = esNuevo ? marcadorObjetivoNuevo : marcadorObjetivoEditar;
  if (marcador) mapa.removeLayer(marcador);

  marcador = L.marker([Number(lat), Number(lon)], { draggable }).addTo(mapa);
  marcador.bindPopup('<strong>Ubicación del objetivo</strong><br>Podés mover el marcador para ajustar el punto exacto.').openPopup();
  marcador.on('dragend', async function () {
    const pos = marcador.getLatLng();
    establecerCoordenadasObjetivo(modo, pos.lat, pos.lng, 'Ubicación ajustada manualmente en el mapa.');
    await reverseGeocodificarObjetivo(modo, pos.lat, pos.lng);
  });
  mapa.setView([Number(lat), Number(lon)], zoom);
  if (esNuevo) marcadorObjetivoNuevo = marcador;
  else marcadorObjetivoEditar = marcador;
  setTimeout(() => mapa.invalidateSize(), 150);
}

function establecerCoordenadasObjetivo(modo, lat, lon, mensaje = '') {
  if (!validarCoordenadas(lat, lon)) {
    mostrarInfoUbicacion(modo, 'Las coordenadas recibidas no son válidas.', 'error');
    return false;
  }
  const latId = modo === 'nuevo' ? 'newLatitudObjetivo' : 'editLatitudObjetivo';
  const lonId = modo === 'nuevo' ? 'newLongitudObjetivo' : 'editLongitudObjetivo';
  document.getElementById(latId).value = formatearCoordenada(lat);
  document.getElementById(lonId).value = formatearCoordenada(lon);
  Promise.resolve(colocarMarcadorObjetivo(modo, lat, lon)).catch(function (e) { console.warn('No se pudo colocar el marcador:', e); });
  if (mensaje) mostrarInfoUbicacion(modo, `${escaparHtml(mensaje)}<br><span class="font-mono">Lat: ${formatearCoordenada(lat)} &nbsp; Lon: ${formatearCoordenada(lon)}</span>`, 'success');
  return true;
}

function mostrarResultadosNominatim(modo, resultados) {
  const contenedorId = modo === 'nuevo' ? 'resultadoDireccionNuevo' : 'resultadoDireccionEditar';
  const contenedor = document.getElementById(contenedorId);
  resultadosNominatim[modo] = resultados || [];
  if (!resultados || resultados.length === 0) {
    contenedor.classList.remove('hidden');
    contenedor.innerHTML = `<div class="bg-amber-500/10 border border-amber-500/20 text-amber-200 rounded-xl p-3 text-xs">No se encontró una ubicación. Probá con calle, altura, localidad, partido y provincia.</div>`;
    return;
  }
  contenedor.classList.remove('hidden');
  contenedor.innerHTML = `
    <div class="bg-slate-950/60 border border-slate-700 rounded-xl p-3 space-y-2">
      <div class="text-xs text-slate-400 mb-2"><i class="fa-solid fa-list"></i> Seleccioná la dirección correcta:</div>
      ${resultados.map((r, i) => `
        <button type="button" data-accion="seleccionarResultadoNominatim" data-a1="${modo}" data-a2="${i}" class="w-full text-left bg-slate-900 hover:bg-slate-700 border border-slate-700 hover:border-sky-500/50 rounded-xl p-3 transition">
          <div class="text-sm font-semibold text-white">${escaparHtml(r.display_name || 'Ubicación encontrada')}</div>
          <div class="text-[11px] text-slate-500 mt-1 font-mono">${formatearCoordenada(r.lat)}, ${formatearCoordenada(r.lon)}</div>
        </button>
      `).join('')}
    </div>`;
}

async function buscarDireccionObjetivo(modo) {
  const inputId = modo === 'nuevo' ? 'newDireccionObjetivo' : 'editDireccionObjetivo';
  const btnId = modo === 'nuevo' ? 'btnBuscarDireccionNuevo' : 'btnBuscarDireccionEditar';
  const direccion = document.getElementById(inputId).value.trim();
  const btn = document.getElementById(btnId);
  if (direccion.length < 5) {
    mostrarInfoUbicacion(modo, 'Escribí una dirección más completa, por ejemplo: calle + altura + localidad + provincia.', 'error');
    return;
  }
  const ahora = Date.now();
  const espera = 1100 - (ahora - ultimaBusquedaNominatim);
  if (espera > 0) await new Promise(resolve => setTimeout(resolve, espera));
  ultimaBusquedaNominatim = Date.now();
  btn.disabled = true;
  const textoOriginal = btn.innerHTML;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Buscando...';
  ocultarInfoUbicacion(modo);
  try {
    const url = 'https://nominatim.openstreetmap.org/search?' + new URLSearchParams({
      format: 'jsonv2', addressdetails: '1', limit: '5', countrycodes: 'ar', 'accept-language': 'es', q: direccion
    }).toString();
    const respuesta = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!respuesta.ok) throw new Error(`Nominatim respondió con HTTP ${respuesta.status}`);
    const resultados = await respuesta.json();
    mostrarResultadosNominatim(modo, resultados);
    if (!resultados || resultados.length === 0) mostrarInfoUbicacion(modo, 'No encontramos esa dirección. Probá agregando localidad, partido y provincia.', 'error');
  } catch (error) {
    console.error('Error al geocodificar:', error);
    mostrarInfoUbicacion(modo, 'No se pudo consultar el servicio gratuito de mapas. Revisá tu conexión e intentá nuevamente.', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = textoOriginal;
  }
}

function seleccionarResultadoNominatim(modo, indice) {
  const resultado = resultadosNominatim[modo][indice];
  if (!resultado) return;
  const lat = Number(resultado.lat);
  const lon = Number(resultado.lon);
  if (!establecerCoordenadasObjetivo(modo, lat, lon, 'Ubicación seleccionada correctamente.')) return;
  const direccionId = modo === 'nuevo' ? 'newDireccionObjetivo' : 'editDireccionObjetivo';
  document.getElementById(direccionId).value = resultado.display_name || document.getElementById(direccionId).value;
  const contenedorId = modo === 'nuevo' ? 'resultadoDireccionNuevo' : 'resultadoDireccionEditar';
  document.getElementById(contenedorId).innerHTML = `<div class="bg-emerald-500/10 border border-emerald-500/20 text-emerald-200 rounded-xl p-3 text-xs"><i class="fa-solid fa-circle-check"></i> Ubicación seleccionada: <strong>${escaparHtml(resultado.display_name || '')}</strong><br><span class="text-[11px]">El marcador quedó en ${formatearCoordenada(lat)}, ${formatearCoordenada(lon)}. Podés arrastrarlo para corregir el punto.</span></div>`;
  obtenerMapaObjetivo(modo).then(function (mapa) {
    if (mapa) setTimeout(() => mapa.invalidateSize(), 100);
  }).catch(function (e) { console.warn('No se pudo preparar el mapa del objetivo:', e); });
}

function aplicarCoordenadasManualesObjetivo(modo) {
  const latId = modo === 'nuevo' ? 'newLatitudObjetivo' : 'editLatitudObjetivo';
  const lonId = modo === 'nuevo' ? 'newLongitudObjetivo' : 'editLongitudObjetivo';
  const lat = Number(String(document.getElementById(latId).value).replace(',', '.').trim());
  const lon = Number(String(document.getElementById(lonId).value).replace(',', '.').trim());

  if (!validarCoordenadas(lat, lon)) {
    mostrarInfoUbicacion(modo, 'Coordenadas inválidas. Latitud debe estar entre -90 y 90 y longitud entre -180 y 180.', 'error');
    return;
  }

  establecerCoordenadasObjetivo(modo, lat, lon, 'Coordenadas manuales aplicadas. Podés mover el marcador para ajustar el punto exacto.');
  reverseGeocodificarObjetivo(modo, lat, lon);
}

async function reverseGeocodificarObjetivo(modo, lat, lon) {
  try {
    const url = 'https://nominatim.openstreetmap.org/reverse?' + new URLSearchParams({
      format: 'jsonv2',
      lat: lat,
      lon: lon,
      zoom: '18',
      addressdetails: '1',
      'accept-language': 'es'
    }).toString();
    const respuesta = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!respuesta.ok) return;
    const resultado = await respuesta.json();
    const direccionId = modo === 'nuevo' ? 'newDireccionObjetivo' : 'editDireccionObjetivo';
    if (resultado && resultado.display_name) {
      document.getElementById(direccionId).value = resultado.display_name;
      mostrarInfoUbicacion(modo, `Dirección asociada al punto seleccionado:<br><strong>${escaparHtml(resultado.display_name)}</strong>`, 'success');
    }
  } catch (error) {
    console.warn('No se pudo obtener la dirección del punto:', error);
  }
}

function usarGPSObjetivo(modo) {
  if (!navigator.geolocation) {
    mostrarInfoUbicacion(modo, 'Este navegador no permite obtener la ubicación GPS.', 'error');
    return;
  }
  const btnId = modo === 'nuevo' ? 'btnGPSNuevo' : 'btnGPSEditar';
  const btn = document.getElementById(btnId);
  const textoOriginal = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Obteniendo GPS...';
  navigator.geolocation.getCurrentPosition(
    position => {
      establecerCoordenadasObjetivo(modo, position.coords.latitude, position.coords.longitude, `GPS actual obtenido. Precisión aproximada: ${Math.round(position.coords.accuracy)} m.`);
      btn.disabled = false;
      btn.innerHTML = textoOriginal;
    },
    error => {
      console.error('Error GPS:', error);
      let mensaje = 'No se pudo obtener la ubicación GPS.';
      if (error.code === 1) mensaje = 'El navegador bloqueó el acceso a la ubicación. Permití la ubicación para este sitio.';
      if (error.code === 2) mensaje = 'No se pudo determinar la ubicación actual.';
      if (error.code === 3) mensaje = 'La solicitud de ubicación tardó demasiado.';
      mostrarInfoUbicacion(modo, mensaje, 'error');
      btn.disabled = false;
      btn.innerHTML = textoOriginal;
    },
    { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
  );
}


function obtenerDireccionObjetivo(modo) {
  const id = modo === 'nuevo' ? 'newDireccionObjetivo' : 'editDireccionObjetivo';
  return (document.getElementById(id)?.value || '').trim();
}

function abrirGoogleMapsConsulta(consulta) {
  const texto = (consulta || '').trim();
  if (!texto) {
    alert('Primero escribí una dirección.');
    return;
  }
  const url = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(texto)}`;
  window.open(url, '_blank', 'noopener,noreferrer');
}

function buscarDireccionGoogleObjetivo(modo) {
  const direccion = obtenerDireccionObjetivo(modo);
  if (!direccion) {
    alert('Primero escribí la dirección exacta.');
    return;
  }
  abrirGoogleMapsConsulta(direccion);
  mostrarInfoUbicacion(
    modo,
    'Google Maps se abrió en una nueva pestaña. Si Google Maps muestra el domicilio exacto, podés hacer clic derecho sobre el punto, copiar las coordenadas y pegarlas abajo en <strong>Latitud</strong> y <strong>Longitud</strong>. Después presioná <strong>Aplicar coordenadas manuales</strong>.',
    'success'
  );
}

function renderizarTablaObjetivos(registros) {
  const cuerpo = document.getElementById('cuerpoTablaObjetivos');
  cuerpo.innerHTML = '';
  if (!registros || registros.length === 0) {
    cuerpo.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-slate-400">No hay objetivos registrados.</td></tr>`;
    return;
  }
  registros.forEach(fila => {
    const firebaseId = fila[0];
    const nombreObj = fila[1] || '';
    const direccionObj = fila[2] || '';
    const lat = fila[3];
    const lon = fila[4];
    const estado = fila[5] || 'ACTIVO';
    const tieneGPS = validarCoordenadas(lat, lon);
    const coordenadas = tieneGPS ? `${formatearCoordenada(lat)}, ${formatearCoordenada(lon)}` : 'Sin GPS';
    const mapaLink = tieneGPS ? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(Number(lat))},${encodeURIComponent(Number(lon))}` : '';
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-700/30 transition';
    tr.innerHTML = `
      <td class="p-4 font-mono text-xs text-slate-400">${escaparHtml(firebaseId)}</td>
      <td class="p-4 font-medium text-white">${escaparHtml(nombreObj)}</td>
      <td class="p-4 text-slate-300 max-w-xs" style="white-space:normal;">${escaparHtml(direccionObj || 'Sin dirección cargada')}</td>
      <td class="p-4 font-mono text-xs ${tieneGPS ? 'text-emerald-300' : 'text-rose-400'}">${tieneGPS ? `<a href="${mapaLink}" target="_blank" rel="noopener noreferrer" title="Abrir esta ubicación en Google Maps" class="hover:underline inline-flex items-center gap-1.5"><i class="fa-brands fa-google text-red-400"></i>${coordenadas}</a>` : coordenadas}</td>
      <td class="p-4 text-center"><span class="bg-emerald-500/10 text-emerald-400 px-2 py-1 rounded text-xs">${escaparHtml(estado)}</span></td>
      <td class="p-4 text-center whitespace-nowrap">
        <button data-accion="abrirModalEditarObjetivo" data-a1="${escaparHtml(firebaseId)}" class="bg-sky-600/20 text-sky-400 hover:bg-sky-600/40 border border-sky-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1 mr-1"><i class="fa-solid fa-pen-to-square"></i> Editar</button>
        <button data-accion="eliminarObjetivo" data-a1="${escaparHtml(firebaseId)}" class="bg-rose-600/20 text-rose-400 hover:bg-rose-600/40 border border-rose-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1"><i class="fa-solid fa-trash"></i> Eliminar</button>
      </td>`;
    cuerpo.appendChild(tr);
  });
}

async function guardarObjetivo(e) {
  e.preventDefault();
  const btn = document.getElementById('btnGuardarObj');
  btn.disabled = true; btn.innerText = 'Guardando...';
  const nombreObj = document.getElementById('newObjetivo').value.trim();
  const direccionObj = document.getElementById('newDireccionObjetivo').value.trim();
  const lat = Number(document.getElementById('newLatitudObjetivo').value);
  const lon = Number(document.getElementById('newLongitudObjetivo').value);
  if (!nombreObj || !direccionObj) {
    alert('Completá el nombre y la dirección del objetivo.');
    btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-plus"></i> Añadir Objetivo'; return;
  }
  if (!validarCoordenadas(lat, lon)) {
    alert('Primero buscá la dirección y seleccioná una ubicación válida. También podés usar el GPS actual.');
    btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-plus"></i> Añadir Objetivo'; return;
  }
  // [PLAN] Chequeo de cupo server-side ANTES de crear el objetivo. El Worker
  // cuenta los objetivos reales y aplica el tope del plan contratado.
  try {
    const cupo = await verificarCupoApp('objetivo');
    if (cupo && cupo.ok && cupo.disponible === false) {
      if (cupo.suspendido) {
        alert('La cuenta está suspendida por el proveedor del servicio. No se pueden crear objetivos. Contactá al proveedor.');
      } else {
        alert('Límite del plan alcanzado: tu plan "' + nombreLegiblePlan(cupo.plan && cupo.plan.nombre) + '" permite hasta ' + cupo.maximo + ' objetivos y ya hay ' + cupo.usados + '. Para sumar más, actualizá tu plan.');
      }
      btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-plus"></i> Añadir Objetivo'; return;
    }
  } catch (_) { /* si la verificación falla, se continúa: el POST a Firebase decide */ }
  try {
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos.json`), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nombre: nombreObj, direccion: direccionObj, latitud: lat, longitud: lon, estado: 'ACTIVO', timestamp: new Date().toISOString() })
    });
    if (!res.ok) throw new Error('Error al guardar en Firebase');
    alert('Objetivo registrado con éxito.');
    document.getElementById('newObjetivo').value = '';
    document.getElementById('newDireccionObjetivo').value = '';
    document.getElementById('newLatitudObjetivo').value = '';
    document.getElementById('newLongitudObjetivo').value = '';
    document.getElementById('resultadoDireccionNuevo').classList.add('hidden');
    document.getElementById('mapaObjetivoNuevo').classList.add('hidden');
    document.getElementById('infoUbicacionNuevo').classList.add('hidden');
    if (mapaObjetivoNuevo) { mapaObjetivoNuevo.remove(); mapaObjetivoNuevo = null; marcadorObjetivoNuevo = null; }
    recargarDatosEfectivo();
  } catch (err) {
    alert('Ocurrió un error al guardar el objetivo: ' + err.toString());
  } finally {
    btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-plus"></i> Añadir Objetivo';
  }
}

function abrirModalEditarObjetivo(firebaseId) {
  const fila = datosObjetivos.find(item => String(item[0]) === String(firebaseId));
  if (!fila) return alert('No se encontró el objetivo seleccionado. Actualizá los datos e intentá nuevamente.');
  objetivoEditandoId = firebaseId;
  document.getElementById('editObjetivoId').value = firebaseId;
  document.getElementById('editNombreObjetivo').value = fila[1] || '';
  document.getElementById('editDireccionObjetivo').value = fila[2] || '';
  document.getElementById('editLatitudObjetivo').value = validarCoordenadas(fila[3], fila[4]) ? formatearCoordenada(fila[3]) : '';
  document.getElementById('editLongitudObjetivo').value = validarCoordenadas(fila[3], fila[4]) ? formatearCoordenada(fila[4]) : '';
  document.getElementById('resultadoDireccionEditar').classList.add('hidden');
  ocultarInfoUbicacion('editar');
  document.getElementById('modalEditarObjetivo').classList.remove('hidden');
  document.body.classList.add('overflow-hidden');
  if (mapaObjetivoEditar) { mapaObjetivoEditar.remove(); mapaObjetivoEditar = null; marcadorObjetivoEditar = null; }
  // Cargar config + puntos de la ronda PRIMERO. Antes el mapa (Leaflet lazy)
  // se iniciaba de forma sincronica y lanzaba "L is not defined" al abrir el
  // objetivo, abortando esta funcion ANTES de llegar a cargar los puntos: por
  // eso la lista salia vacia hasta que se agregaba un punto nuevo. Ahora la
  // carga de puntos NO depende del mapa.
  cargarRondaObjetivo(firebaseId);
  // Mapa aislado: cualquier fallo del mapa queda contenido y nunca impide que
  // aparezca la lista de puntos.
  (async function () {
    try {
      const mapa = await obtenerMapaObjetivo('editar');
      if (validarCoordenadas(fila[3], fila[4])) await colocarMarcadorObjetivo('editar', fila[3], fila[4]);
      else if (mapa) setTimeout(() => mapa.invalidateSize(), 150);
    } catch (e) {
      console.warn('No se pudo inicializar el mapa del objetivo (no afecta a los puntos):', e);
    }
  })();
}

function cerrarModalEditarObjetivo() {
  document.getElementById('modalEditarObjetivo').classList.add('hidden');
  document.body.classList.remove('overflow-hidden');
  objetivoEditandoId = null;
  if (mapaObjetivoEditar) { mapaObjetivoEditar.remove(); mapaObjetivoEditar = null; marcadorObjetivoEditar = null; }
}

async function guardarEdicionObjetivo() {
  const id = document.getElementById('editObjetivoId').value || objetivoEditandoId;
  const nombreObj = document.getElementById('editNombreObjetivo').value.trim();
  const direccionObj = document.getElementById('editDireccionObjetivo').value.trim();
  const lat = Number(document.getElementById('editLatitudObjetivo').value);
  const lon = Number(document.getElementById('editLongitudObjetivo').value);
  const btn = document.getElementById('btnGuardarEdicionObjetivo');
  if (!id || !nombreObj || !direccionObj) return alert('Completá el nombre y la dirección.');
  if (!validarCoordenadas(lat, lon)) return alert('El objetivo debe tener coordenadas válidas. Buscá la dirección o usá el GPS actual.');
  btn.disabled = true; btn.innerText = 'Guardando...';
  try {
    const res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos/${id}.json`), {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nombre: nombreObj, direccion: direccionObj, latitud: lat, longitud: lon, estado: 'ACTIVO', fechaActualizacion: new Date().toISOString() })
    });
    if (!res.ok) throw new Error('Error al actualizar en Firebase');
    registrarAuditoria('OBJETIVO_EDITADO', `objetivos/${id}`, { nombre: nombreObj, direccion: direccionObj });
    alert('Objetivo actualizado correctamente.');
    cerrarModalEditarObjetivo();
    recargarDatosEfectivo();
  } catch (err) {
    alert('Ocurrió un error al actualizar el objetivo: ' + err.toString());
  } finally {
    btn.disabled = false; btn.innerText = 'Guardar Cambios';
  }
}

async function eliminarObjetivo(firebaseId) {
  if (!confirm('¿Estás seguro de que deseas eliminar este objetivo?')) return;
  try {
    await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos/${firebaseId}.json`), { method: 'DELETE' });
    registrarAuditoria('OBJETIVO_ELIMINADO', `objetivos/${firebaseId}`, {});
    alert('Objetivo eliminado con éxito.');
    recargarDatosEfectivo();
  } catch (err) {
    alert('Ocurrió un error al eliminar: ' + err.toString());
  }
}

function abrirFoto(base64) {
  document.getElementById('imgModal').src = base64;
  document.getElementById('modalFoto').classList.remove('hidden');
}

function cerrarModal() {
  document.getElementById('modalFoto').classList.add('hidden');
  document.getElementById('imgModal').src = "";
}

async function exportarExcel() {
  await lazyExport();
  if (!datosFiltradosMarcaciones || datosFiltradosMarcaciones.length === 0) {
    return alert("No hay datos visibles para exportar.");
  }

  const cabeceras = [["Fecha y Hora", "Legajo", "Nombre", "Objetivo", "Tipo", "Auditoría IA", "Distancia Euclidiana", "Motivo Fraude"]];
  const filas = datosFiltradosMarcaciones.map(f => [
    f[0] ? new Date(f[0]).toLocaleString('es-AR', { hour12: false }) : '',
    f[1] !== undefined ? String(f[1]) : '',
    f[2] || '',
    f[3] || '',
    f[4] || '',
    f[7] ? 'SOSPECHA DE FRAUDE' : 'VERIFICADO',
    f[8] !== null ? f[8] : '',
    f[9] || ''
  ]);

  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet([...cabeceras, ...filas]);
  XLSX.utils.book_append_sheet(wb, ws, "Marcaciones");
  XLSX.writeFile(wb, `Reporte_Marcaciones_${new Date().toISOString().slice(0,10)}.xlsx`);
}

async function exportarPDF() {
  await lazyExport();
  if (!datosFiltradosMarcaciones || datosFiltradosMarcaciones.length === 0) {
    return alert("No hay datos visibles para exportar.");
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  doc.setFontSize(16);
  doc.text("Reporte de Marcaciones y Auditoría IA", 14, 15);
  doc.setFontSize(10);
  doc.text(`Generado el: ${new Date().toLocaleString('es-AR', { hour12: false })}`, 14, 22);

  const columnas = ["Fecha y Hora", "Legajo", "Nombre", "Objetivo", "Tipo", "Auditoría IA"];
  const filas = datosFiltradosMarcaciones.map(f => [
    f[0] ? new Date(f[0]).toLocaleString('es-AR', { hour12: false }) : '',
    f[1] !== undefined ? String(f[1]) : '',
    f[2] || '',
    f[3] || '',
    f[4] || '',
    f[7] ? 'SOSPECHA FRAUDE' : 'VERIFICADO'
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

// --- REPORTE MENSUAL DE CUMPLIMIENTO EN PDF (aditivo) ---
async function exportarPDFCumplimientoMensual() {
  await lazyExport();
  if (!datosMarcaciones || datosMarcaciones.length === 0) {
    return alert('No hay marcaciones cargadas para generar el reporte.');
  }
  // Mes objetivo: el elegido en el selector o, si está vacío, el mes actual.
  const inputMes = document.getElementById('mesReporteCumpl');
  let anio, mes; // mes 0-11
  if (inputMes && inputMes.value && /^\d{4}-\d{2}$/.test(inputMes.value)) {
    const partes = inputMes.value.split('-');
    anio = parseInt(partes[0], 10);
    mes = parseInt(partes[1], 10) - 1;
  } else {
    const hoy = new Date();
    anio = hoy.getFullYear();
    mes = hoy.getMonth();
  }

  // Agrupar por empleado y contar estados de cumplimiento dentro del mes.
  const porEmpleado = {};
  let totalMes = 0;
  const tot = { aTiempo: 0, tolerancia: 0, tarde: 0, anticipada: 0, extra: 0 };
  datosMarcaciones.forEach(fila => {
    const f = new Date(fila[0]);
    if (isNaN(f) || f.getFullYear() !== anio || f.getMonth() !== mes) return;
    const c = calcularCumplimientoFilaAdmin(fila);
    if (!c) return;
    totalMes++;
    const legajo = fila[1] !== undefined ? String(fila[1]) : '-';
    const clave = legajo + '|' + (fila[2] || '');
    if (!porEmpleado[clave]) porEmpleado[clave] = { legajo, nombre: fila[2] || '', aTiempo: 0, tolerancia: 0, tarde: 0, anticipada: 0, extra: 0 };
    const e = porEmpleado[clave];
    if (c.estado === 'A_TIEMPO' || c.estado === 'EN_HORARIO') { e.aTiempo++; tot.aTiempo++; }
    else if (c.estado === 'TOLERANCIA') { e.tolerancia++; tot.tolerancia++; }
    else if (c.estado === 'TARDE') { e.tarde++; tot.tarde++; }
    else if (c.estado === 'ANTICIPADA') { e.anticipada++; tot.anticipada++; }
    else if (c.estado === 'EXTRA') { e.extra++; tot.extra++; }
  });

  if (totalMes === 0) {
    return alert('No hay marcaciones con horario evaluable en el mes seleccionado.');
  }

  const meses = ['Enero','Febrero','Marzo','Abril','Mayo','Junio','Julio','Agosto','Septiembre','Octubre','Noviembre','Diciembre'];
  const etiquetaMes = `${meses[mes]} ${anio}`;

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  doc.setFontSize(16);
  doc.text('Reporte Mensual de Cumplimiento', 14, 15);
  doc.setFontSize(11);
  doc.text(`Período: ${etiquetaMes}`, 14, 23);
  doc.setFontSize(9);
  doc.text(`Generado el: ${new Date().toLocaleString('es-AR', { hour12: false })}`, 14, 29);
  doc.text(`Total de marcaciones evaluadas: ${totalMes}  |  A tiempo: ${tot.aTiempo}  Tolerancia: ${tot.tolerancia}  Tarde: ${tot.tarde}  Anticipadas: ${tot.anticipada}  Extra: ${tot.extra}`, 14, 35);

  const columnas = ['Legajo', 'Nombre', 'A tiempo', 'Tolerancia', 'Tarde', 'Anticipada', 'Horas extra', 'Total'];
  const filas = Object.values(porEmpleado)
    .sort((a, b) => (b.tarde + b.anticipada) - (a.tarde + a.anticipada))
    .map(e => {
      const total = e.aTiempo + e.tolerancia + e.tarde + e.anticipada + e.extra;
      return [e.legajo, e.nombre, e.aTiempo, e.tolerancia, e.tarde, e.anticipada, e.extra, total];
    });

  doc.autoTable({
    head: [columnas],
    body: filas,
    startY: 40,
    theme: 'grid',
    headStyles: { fillColor: [49, 46, 129] },
    styles: { fontSize: 8 },
    didParseCell: function (data) {
      if (data.section === 'body') {
        if (data.column.index === 4 && Number(data.cell.raw) > 0) { data.cell.styles.textColor = [190, 18, 60]; data.cell.styles.fontStyle = 'bold'; }
        if (data.column.index === 5 && Number(data.cell.raw) > 0) { data.cell.styles.textColor = [190, 18, 60]; data.cell.styles.fontStyle = 'bold'; }
        if (data.column.index === 3 && Number(data.cell.raw) > 0) { data.cell.styles.textColor = [180, 120, 0]; }
      }
    }
  });

  doc.save(`Reporte_Cumplimiento_${anio}-${String(mes + 1).padStart(2, '0')}.pdf`);
}

// --- NOTIFICACIONES DE CUMPLIMIENTO (aditivo) ---
// Dispara un aviso del navegador por cada NUEVA llegada tarde / salida anticipada.
// Guarda los ids ya avisados en localStorage para no repetir al recargar la página.
// En la primera carga solo marca lo existente como visto (no spamea al abrir el panel).
function notificarAlertasCumplimiento(registros) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const primeraCarga = (localStorage.getItem('cumpl_notificadas') === null);
  let yaAvisadas = [];
  try { yaAvisadas = JSON.parse(localStorage.getItem('cumpl_notificadas') || '[]'); } catch (e) { yaAvisadas = []; }
  const setAvisadas = new Set(yaAvisadas);

  (registros || []).forEach(fila => {
    const id = fila[11];
    if (!id || setAvisadas.has(id)) return;
    const c = calcularCumplimientoFilaAdmin(fila);
    const esAlerta = c && (c.estado === 'TARDE' || c.estado === 'ANTICIPADA');

    if (primeraCarga) {
      // Sembrar lo existente sin avisar.
      if (esAlerta) setAvisadas.add(id);
      return;
    }
    if (!esAlerta) return;

    // Solo avisar de eventos de las últimas 24 h.
    const ts = fila[0] ? new Date(fila[0]).getTime() : 0;
    if (ts && (Date.now() - ts) > 86400000) { setAvisadas.add(id); return; }
    try {
      const titulo = c.estado === 'TARDE' ? '⏰ Llegada tarde' : '🚪 Salida anticipada';
      new Notification(titulo, { body: `${fila[2] || 'Empleado'} (Legajo ${fila[1]}) · ${fila[3] || ''} · ${c.texto}`, tag: `cumpl-${id}` });
    } catch (e) {}
    setAvisadas.add(id);
  });

  const arr = Array.from(setAvisadas).slice(-800);
  try { localStorage.setItem('cumpl_notificadas', JSON.stringify(arr)); } catch (e) {}
}

async function exportarExcelNovedades() {
  await lazyExport();
  const registrosAExportar = (datosFiltradosNovedades && datosFiltradosNovedades.length > 0) ? datosFiltradosNovedades : datosNovedades;
  if (!registrosAExportar || registrosAExportar.length === 0) {
    return alert("No hay datos visibles para exportar.");
  }

  const cabeceras = [["Fecha y Hora", "Legajo", "Nombre", "Objetivo", "Tipo Incidencia", "Descripción"]];
  const filas = registrosAExportar.map(f => [
    f[0] ? new Date(f[0]).toLocaleString('es-AR', { hour12: false }) : '',
    f[1] !== undefined ? String(f[1]) : '',
    f[2] || '',
    f[3] || '',
    f[4] || '',
    f[5] || ''
  ]);

  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet([...cabeceras, ...filas]);
  XLSX.utils.book_append_sheet(wb, ws, "Novedades");
  XLSX.writeFile(wb, `Reporte_Novedades_${new Date().toISOString().slice(0,10)}.xlsx`);
}

async function exportarPDFNovedades() {
  await lazyExport();
  const registrosAExportar = (datosFiltradosNovedades && datosFiltradosNovedades.length > 0) ? datosFiltradosNovedades : datosNovedades;
  if (!registrosAExportar || registrosAExportar.length === 0) {
    return alert("No hay datos visibles para exportar.");
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  doc.setFontSize(16);
  doc.text("Reporte de Novedades e Incidencias", 14, 15);
  doc.setFontSize(10);
  doc.text(`Generado el: ${new Date().toLocaleString('es-AR', { hour12: false })}`, 14, 22);

  const columnas = ["Fecha y Hora", "Legajo / Nombre", "Objetivo", "Tipo", "Descripción"];
  const filas = registrosAExportar.map(f => [
    f[0] ? new Date(f[0]).toLocaleString('es-AR', { hour12: false }) : '',
    `${f[2] || ''} (Leg: ${f[1] || ''})`,
    f[3] || '',
    f[4] || '',
    f[5] || ''
  ]);

  doc.autoTable({
    head: [columnas],
    body: filas,
    startY: 28,
    theme: 'grid',
    headStyles: { fillColor: [15, 23, 42] },
    styles: { fontSize: 8 }
  });

  doc.save(`Reporte_Novedades_${new Date().toISOString().slice(0,10)}.pdf`);
}

// ========== Inline Handler Migration (CSP hardening) ==========
// All former inline event handlers (onclick/onsubmit/onkeyup/onchange)
// moved here as addEventListener calls to allow removing 'unsafe-inline' from CSP.

// SISTEMA DE RONDAS CON QR - Paso 1 (panel admin). Aditivo. Carga/edita el
// horario de la ronda y los puntos de control de cada objetivo y genera/imprime/
// descarga el QR de cada punto. Todo via REST con ?auth de admin
// (window.urlConAuthAdmin). No toca el Worker ni la logica previa.
var DIAS_RONDA = [
  { n: 1, t: 'Lun' }, { n: 2, t: 'Mar' }, { n: 3, t: 'Mie' },
  { n: 4, t: 'Jue' }, { n: 5, t: 'Vie' }, { n: 6, t: 'Sab' }, { n: 0, t: 'Dom' }
];
var _puntosRondaActual = {};
var _diasRondaSel = [];
var _qrPuntoActual = null;

// Token aleatorio e irrepetible por punto (lo valida el vigilador al escanear).
function generarTokenPunto() {
  var buf = new Uint8Array(16);
  (window.crypto || window.msCrypto).getRandomValues(buf);
  var hex = '';
  for (var i = 0; i < buf.length; i++) hex += ('0' + buf[i].toString(16)).slice(-2);
  return hex;
}

// Carga qrcodejs bajo demanda (CDN con SRI), igual que el resto de librerias.
var _lazyQRPromise = null;
function lazyQR() {
  if (_lazyQRPromise) return _lazyQRPromise;
  _lazyQRPromise = window.cargarCDN(
    'qrcodejs',
    'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js',
    'sha512-CNgIRecGo7nphbeZ04Sc13ka07paqdeTu0WR1IM4kNcpmBAUSHSQX0FslNhTDadL4O5SAGapGt4FodqL8My0mA=='
  );
  return _lazyQRPromise;
}

function infoPuntoRonda(mensaje, tipo) {
  var el = document.getElementById('infoPuntoRonda');
  if (!el) return;
  if (!mensaje) { el.classList.add('hidden'); el.innerHTML = ''; return; }
  var color = tipo === 'error' ? 'text-rose-400' : (tipo === 'ok' ? 'text-emerald-400' : 'text-slate-400');
  el.className = 'text-xs ' + color;
  el.innerHTML = mensaje;
}

function renderDiasRonda() {
  var cont = document.getElementById('rondaDias');
  if (!cont) return;
  cont.innerHTML = '';
  DIAS_RONDA.forEach(function (d) {
    var on = _diasRondaSel.indexOf(d.n) >= 0;
    var b = document.createElement('button');
    b.type = 'button';
    b.setAttribute('data-accion', 'toggleDiaRonda');
    b.setAttribute('data-a1', String(d.n));
    b.className = on
      ? 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 text-white transition'
      : 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700 transition';
    b.textContent = d.t;
    cont.appendChild(b);
  });
}

function toggleDiaRonda(n) {
  n = parseInt(n, 10);
  var i = _diasRondaSel.indexOf(n);
  if (i >= 0) _diasRondaSel.splice(i, 1); else _diasRondaSel.push(n);
  renderDiasRonda();
}

function cancelarEdicionPunto() {
  var set = function (elid, val) { var e = document.getElementById(elid); if (e) e.value = val; };
  set('puntoEditandoId', ''); set('puntoNombre', ''); set('puntoLat', ''); set('puntoLng', ''); set('puntoRadio', ''); set('puntoPrecision', '');
  var f = document.getElementById('puntoFoto'); if (f) f.checked = false;
  var t = document.getElementById('btnAgregarPuntoTexto'); if (t) t.textContent = 'Agregar punto';
  var tit = document.getElementById('tituloFormPunto'); if (tit) tit.textContent = 'Agregar punto de control';
  var cancel = document.getElementById('btnCancelarEdicionPunto'); if (cancel) cancel.classList.add('hidden');
  infoPuntoRonda('', '');
}

// Carga config + puntos del objetivo abierto en el modal de edicion.
async function cargarRondaObjetivo(id) {
  _puntosRondaActual = {};
  _diasRondaSel = [];
  var set = function (elid, val) { var e = document.getElementById(elid); if (e) e.value = val; };
  set('rondaHoraInicio', ''); set('rondaHoraFin', ''); set('rondaFrecuencia', ''); set('rondaTolerancia', '');
  var chk = document.getElementById('rondaActiva'); if (chk) chk.checked = false;
  cancelarEdicionPunto();
  renderDiasRonda();
  renderPuntosRonda({});
  if (!id) return;
  // Lectura con auth fresca cada intento (token recalculado en urlConAuthAdmin).
  var leerRondas = async function () {
    var url = await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos/${id}/rondas.json?ts=${Date.now()}`);
    return fetch(url, { cache: 'no-store' });
  };
  try {
    var res = await leerRondas();
    // Reintento unico: si la 1a lectura falla (401 transitorio tras renovar el
    // token, o un corte de red), esperamos un instante y reintentamos ANTES de
    // decidir que no hay puntos. Asi evitamos la lista vacia enganosa.
    if (!res.ok) {
      await new Promise(function (r) { setTimeout(r, 450); });
      res = await leerRondas();
    }
    if (!res.ok) { renderErrorPuntosRonda(id); return; }
    var data = await res.json();
    if (data) {
      var cfg = data.config || {};
      set('rondaHoraInicio', cfg.horaInicio || '');
      set('rondaHoraFin', cfg.horaFin || '');
      set('rondaFrecuencia', (cfg.frecuenciaMin != null) ? cfg.frecuenciaMin : '');
      set('rondaTolerancia', (cfg.toleranciaMin != null) ? cfg.toleranciaMin : '');
      if (chk) chk.checked = cfg.activo === true;
      _diasRondaSel = Array.isArray(cfg.diasSemana) ? cfg.diasSemana.slice() : [];
      renderDiasRonda();
      _puntosRondaActual = data.puntos || {};
    }
    renderPuntosRonda(_puntosRondaActual);
  } catch (err) {
    console.warn('No se pudo cargar la ronda del objetivo:', err);
    renderErrorPuntosRonda(id);
  }
}

// Aviso visible (no silencioso) cuando la lectura de puntos falla, con boton
// para reintentar sin tener que cerrar y reabrir el objetivo.
function renderErrorPuntosRonda(id) {
  var cuerpo = document.getElementById('cuerpoPuntosRonda');
  if (!cuerpo) return;
  cuerpo.innerHTML = '<tr><td colspan="4" class="p-6 text-center">' +
    '<span class="text-rose-400 mr-1">No se pudieron cargar los puntos.</span>' +
    '<button data-accion="reintentarCargarRonda" data-a1="' + escaparHtml(String(id || '')) + '" class="bg-sky-600/20 text-sky-400 hover:bg-sky-600/40 border border-sky-500/30 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1"><i class="fa-solid fa-rotate-right"></i> Reintentar</button>' +
    '</td></tr>';
}

async function guardarConfigRonda() {
  var id = document.getElementById('editObjetivoId').value || objetivoEditandoId;
  if (!id) return alert('Primero guarda el objetivo.');
  // [PLAN] Guia amable: el control de rondas requiere la funcion 'rondas' del
  // plan. Si no esta incluida, avisamos y no intentamos escribir (las Reglas de
  // Firebase igualmente rechazan la config de rondas sin plan).
  if (!planTieneFuncion('rondas')) {
    alert('El control de rondas no esta incluido en tu plan actual. Escribinos para sumar esta funcion y configurar los recorridos.');
    return;
  }
  var btn = document.getElementById('btnGuardarConfigRonda');
  var horaInicio = (document.getElementById('rondaHoraInicio').value || '').trim();
  var horaFin = (document.getElementById('rondaHoraFin').value || '').trim();
  var frecuencia = parseInt(document.getElementById('rondaFrecuencia').value, 10);
  var tolerancia = parseInt(document.getElementById('rondaTolerancia').value, 10);
  var activo = !!document.getElementById('rondaActiva').checked;
  var payload = {
    activo: activo, horaInicio: horaInicio, horaFin: horaFin,
    frecuenciaMin: isNaN(frecuencia) ? 0 : frecuencia,
    toleranciaMin: isNaN(tolerancia) ? 0 : tolerancia,
    diasSemana: _diasRondaSel.slice().sort(function (a, b) { return a - b; }),
    fechaActualizacion: new Date().toISOString()
  };
  btn.disabled = true; var orig = btn.innerHTML; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Guardando...';
  try {
    var res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos/${id}/rondas/config.json`), {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Error al guardar el horario');
    registrarAuditoria('RONDA_CONFIG_EDITADA', `objetivos/${id}`, { activo: activo, horaInicio: horaInicio, horaFin: horaFin });
    alert('Horario de ronda guardado.');
  } catch (err) {
    alert('No se pudo guardar el horario: ' + err.toString());
  } finally {
    btn.disabled = false; btn.innerHTML = orig;
  }
}

function usarGPSPunto() {
  if (!navigator.geolocation) { infoPuntoRonda('Este navegador no permite obtener la ubicacion GPS.', 'error'); return; }
  var btn = document.getElementById('btnGPSPunto');
  var orig = btn.innerHTML; btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Obteniendo...';
  navigator.geolocation.getCurrentPosition(function (pos) {
    document.getElementById('puntoLat').value = pos.coords.latitude.toFixed(6);
    document.getElementById('puntoLng').value = pos.coords.longitude.toFixed(6);
    infoPuntoRonda('GPS actual tomado. Precision aprox: ' + Math.round(pos.coords.accuracy) + ' m.', 'ok');
    btn.disabled = false; btn.innerHTML = orig;
  }, function (err) {
    var m = 'No se pudo obtener la ubicacion GPS.';
    if (err.code === 1) m = 'El navegador bloqueo la ubicacion. Permiti el acceso para este sitio.';
    infoPuntoRonda(m, 'error');
    btn.disabled = false; btn.innerHTML = orig;
  }, { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 });
}

async function agregarPuntoRonda() {
  var id = document.getElementById('editObjetivoId').value || objetivoEditandoId;
  if (!id) return alert('Primero guarda el objetivo.');
  // [PLAN] Guia amable: agregar puntos de ronda requiere la funcion 'rondas'.
  // Si el plan no la incluye, avisamos y abortamos (las Reglas de Firebase
  // tambien bloquean la escritura del punto server-side).
  if (!planTieneFuncion('rondas')) {
    infoPuntoRonda('El control de rondas no esta incluido en tu plan actual. Escribinos para habilitar los recorridos.', 'error');
    return;
  }
  var idPunto = (document.getElementById('puntoEditandoId').value || '').trim();
  var nombre = (document.getElementById('puntoNombre').value || '').trim();
  var lat = Number(document.getElementById('puntoLat').value);
  var lng = Number(document.getElementById('puntoLng').value);
  var radio = parseInt(document.getElementById('puntoRadio').value, 10);
  var precision = parseInt(document.getElementById('puntoPrecision').value, 10);
  var foto = !!document.getElementById('puntoFoto').checked;
  if (!nombre) { infoPuntoRonda('Pone un nombre al punto.', 'error'); return; }
  if (!validarCoordenadas(lat, lng)) { infoPuntoRonda('El punto necesita coordenadas validas. Usa el GPS o cargalas a mano.', 'error'); return; }
  if (isNaN(radio) || radio < 5) radio = 30;
  if (isNaN(precision) || precision < 5) precision = 50;
  var btn = document.getElementById('btnAgregarPunto');
  btn.disabled = true; var orig = btn.innerHTML; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Guardando...';
  try {
    if (idPunto) {
      var prev = _puntosRondaActual[idPunto] || {};
      var cuerpoEdit = {
        nombre: nombre, lat: lat, lng: lng, radioMetros: radio, precisionGpsMin: precision,
        fotoObligatoria: foto, token: prev.token || generarTokenPunto(),
        orden: (prev.orden != null) ? prev.orden : (Object.keys(_puntosRondaActual).length + 1),
        activo: (prev.activo !== false), fechaActualizacion: new Date().toISOString()
      };
      var resE = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos/${id}/rondas/puntos/${idPunto}.json`), {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cuerpoEdit)
      });
      if (!resE.ok) throw new Error('Error al actualizar el punto');
      registrarAuditoria('RONDA_PUNTO_EDITADO', `objetivos/${id}`, { idPunto: idPunto, nombre: nombre });
    } else {
      var cuerpoNuevo = {
        nombre: nombre, lat: lat, lng: lng, radioMetros: radio, precisionGpsMin: precision,
        fotoObligatoria: foto, token: generarTokenPunto(),
        orden: Object.keys(_puntosRondaActual).length + 1,
        activo: true, timestamp: new Date().toISOString()
      };
      var resN = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos/${id}/rondas/puntos.json`), {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cuerpoNuevo)
      });
      if (!resN.ok) throw new Error('Error al guardar el punto');
      registrarAuditoria('RONDA_PUNTO_CREADO', `objetivos/${id}`, { nombre: nombre });
    }
    cancelarEdicionPunto();
    await cargarRondaObjetivo(id);
    infoPuntoRonda('Punto guardado. Ya podes generar su QR en la lista.', 'ok');
  } catch (err) {
    infoPuntoRonda('No se pudo guardar el punto: ' + err.toString(), 'error');
  } finally {
    btn.disabled = false; btn.innerHTML = orig;
  }
}

function editarPuntoRonda(idPunto) {
  var p = _puntosRondaActual[idPunto];
  if (!p) return;
  document.getElementById('puntoEditandoId').value = idPunto;
  document.getElementById('puntoNombre').value = p.nombre || '';
  document.getElementById('puntoLat').value = (p.lat != null) ? p.lat : '';
  document.getElementById('puntoLng').value = (p.lng != null) ? p.lng : '';
  document.getElementById('puntoRadio').value = (p.radioMetros != null) ? p.radioMetros : '';
  document.getElementById('puntoPrecision').value = (p.precisionGpsMin != null) ? p.precisionGpsMin : '';
  document.getElementById('puntoFoto').checked = p.fotoObligatoria === true;
  document.getElementById('btnAgregarPuntoTexto').textContent = 'Guardar cambios';
  document.getElementById('tituloFormPunto').textContent = 'Editar punto de control';
  document.getElementById('btnCancelarEdicionPunto').classList.remove('hidden');
  var sec = document.getElementById('seccionRondas'); if (sec) sec.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function eliminarPuntoRonda(idPunto) {
  var id = document.getElementById('editObjetivoId').value || objetivoEditandoId;
  if (!id || !idPunto) return;
  var p = _puntosRondaActual[idPunto] || {};
  if (!confirm('Eliminar el punto "' + (p.nombre || idPunto) + '"? El QR impreso dejara de servir.')) return;
  try {
    var res = await fetch(await window.urlConAuthAdmin(`${URL_FIREBASE}/objetivos/${id}/rondas/puntos/${idPunto}.json`), { method: 'DELETE' });
    if (!res.ok) throw new Error('Error al eliminar');
    registrarAuditoria('RONDA_PUNTO_ELIMINADO', `objetivos/${id}`, { idPunto: idPunto, nombre: p.nombre || '' });
    await cargarRondaObjetivo(id);
  } catch (err) {
    alert('No se pudo eliminar el punto: ' + err.toString());
  }
}

function renderPuntosRonda(puntos) {
  var cuerpo = document.getElementById('cuerpoPuntosRonda');
  if (!cuerpo) return;
  var ids = Object.keys(puntos || {});
  if (ids.length === 0) {
    cuerpo.innerHTML = '<tr><td colspan="4" class="p-6 text-center text-slate-500">Sin puntos cargados.</td></tr>';
    return;
  }
  ids.sort(function (a, b) { return (puntos[a].orden || 0) - (puntos[b].orden || 0); });
  cuerpo.innerHTML = '';
  ids.forEach(function (idPunto, i) {
    var p = puntos[idPunto];
    var tr = document.createElement('tr');
    tr.className = 'border-t border-slate-800 hover:bg-slate-800/40 transition';
    var foto = p.fotoObligatoria === true
      ? '<span class="text-amber-400"><i class="fa-solid fa-camera"></i> foto</span>'
      : '<span class="text-slate-500">sin foto</span>';
    tr.innerHTML =
      '<td class="p-3 text-slate-400 font-mono">' + (i + 1) + '</td>' +
      '<td class="p-3"><div class="font-medium text-white">' + escaparHtml(p.nombre || '') + '</div>' +
        '<div class="text-xs text-slate-500 font-mono">' + (p.lat != null ? formatearCoordenada(p.lat) : '?') + ', ' + (p.lng != null ? formatearCoordenada(p.lng) : '?') + '</div></td>' +
      '<td class="p-3 text-xs text-slate-300">' + (p.radioMetros || 30) + ' m &middot; ' + foto + '</td>' +
      '<td class="p-3 text-center whitespace-nowrap">' +
        '<button data-accion="mostrarQRPunto" data-a1="' + escaparHtml(idPunto) + '" class="bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/40 border border-emerald-500/30 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1 mr-1" title="Ver / imprimir QR"><i class="fa-solid fa-qrcode"></i> QR</button>' +
        '<button data-accion="editarPuntoRonda" data-a1="' + escaparHtml(idPunto) + '" class="bg-sky-600/20 text-sky-400 hover:bg-sky-600/40 border border-sky-500/30 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1 mr-1" title="Editar"><i class="fa-solid fa-pen-to-square"></i></button>' +
        '<button data-accion="eliminarPuntoRonda" data-a1="' + escaparHtml(idPunto) + '" class="bg-rose-600/20 text-rose-400 hover:bg-rose-600/40 border border-rose-500/30 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition inline-flex items-center gap-1" title="Eliminar"><i class="fa-solid fa-trash"></i></button>' +
      '</td>';
    cuerpo.appendChild(tr);
  });
}

// Contenido del QR: VIGIX1|idObjetivo|idPunto|token
function payloadQRPunto(idObjetivo, idPunto, token) {
  return 'VIGIX1|' + idObjetivo + '|' + idPunto + '|' + token;
}

async function mostrarQRPunto(idPunto) {
  var id = document.getElementById('editObjetivoId').value || objetivoEditandoId;
  var p = _puntosRondaActual[idPunto];
  if (!id || !p) return;
  var nombreObj = document.getElementById('editNombreObjetivo').value || 'Objetivo';
  var payload = payloadQRPunto(id, idPunto, p.token || '');
  _qrPuntoActual = { idPunto: idPunto, nombre: p.nombre || '', payload: payload };
  document.getElementById('qrObjetivoNombre').textContent = nombreObj;
  document.getElementById('qrPuntoNombre').textContent = p.nombre || '';
  document.getElementById('qrPayloadTexto').textContent = payload;
  var cont = document.getElementById('qrContenedor');
  cont.innerHTML = '<p class="text-xs">Generando QR...</p>';
  document.getElementById('modalQRPunto').classList.remove('hidden');
  try {
    await lazyQR();
    cont.innerHTML = '';
    new QRCode(cont, { text: payload, width: 240, height: 240, correctLevel: QRCode.CorrectLevel.M });
  } catch (err) {
    cont.innerHTML = '<p class="text-xs text-rose-500">No se pudo generar el QR. Revisa tu conexion.</p>';
  }
}

function cerrarModalQRPunto() {
  document.getElementById('modalQRPunto').classList.add('hidden');
  var cont = document.getElementById('qrContenedor'); if (cont) cont.innerHTML = '';
  _qrPuntoActual = null;
}

function _canvasQRActual() {
  var cont = document.getElementById('qrContenedor');
  return cont ? cont.querySelector('canvas') : null;
}

function descargarQRPunto() {
  var canvas = _canvasQRActual();
  if (!canvas || !_qrPuntoActual) { alert('Espera a que el QR termine de generarse.'); return; }
  try {
    var url = canvas.toDataURL('image/png');
    var a = document.createElement('a');
    var nombre = (_qrPuntoActual.nombre || 'punto').replace(/[^a-z0-9]+/gi, '_').toLowerCase();
    a.href = url; a.download = 'qr_' + nombre + '.png';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  } catch (err) {
    alert('No se pudo descargar el PNG: ' + err.toString());
  }
}

function imprimirQRPunto() {
  if (!_canvasQRActual()) { alert('Espera a que el QR termine de generarse.'); return; }
  document.body.classList.add('print-qr');
  var limpiar = function () { document.body.classList.remove('print-qr'); window.removeEventListener('afterprint', limpiar); };
  window.addEventListener('afterprint', limpiar);
  setTimeout(function () { try { window.print(); } catch (e) {} setTimeout(limpiar, 1500); }, 50);
}

function initInlineHandlers() {
  document.getElementById("formValidarPass").addEventListener("submit", function(e) { validarPasswordAdmin(e) });
  document.getElementById("btnRecargar").addEventListener("click", function(e) { recargarDatosEfectivo() });
  document.getElementById("btnAlertasFichadas").addEventListener("click", function(e) { abrirModalAlertasFichadas() });
  document.getElementById("btnCerrarSesion").addEventListener("click", function(e) { cerrarSesionAdmin() });
  document.getElementById("tabBtnMarcaciones").addEventListener("click", function(e) { cambiarTab('marcaciones') });
  document.getElementById("tabBtnAlertasUbicacion").addEventListener("click", function(e) { cambiarTab('alertasUbicacion') });
  document.getElementById("tabBtnNovedades").addEventListener("click", function(e) { cambiarTab('novedades') });
  document.getElementById("tabBtnPanicos").addEventListener("click", function(e) { cambiarTab('panicos') });
  document.getElementById("tabBtnPersonal").addEventListener("click", function(e) { cambiarTab('personal') });
  document.getElementById("tabBtnObjetivos").addEventListener("click", function(e) { cambiarTab('objetivos') });
  document.getElementById("tabBtnDispositivos").addEventListener("click", function(e) { cambiarTab('dispositivos') });
  document.getElementById("tabBtnConfiguracion").addEventListener("click", function(e) { cambiarTab('configuracion') });
  { var _b = document.getElementById("tabBtnRondasReporte"); if (_b) _b.addEventListener("click", function(e) { cambiarTab('rondasReporte') }); }
  { var _r = document.getElementById("btnActualizarReporteRondas"); if (_r) _r.addEventListener("click", function(e) { cargarReporteRondas() }); }
  { var _fo = document.getElementById("filtroObjetivoRonda"); if (_fo) _fo.addEventListener("change", function(e) { renderReporteRondas() }); }
  { var _ff = document.getElementById("filtroFechaRonda"); if (_ff) _ff.addEventListener("change", function(e) { renderReporteRondas() }); }
  { var _fl = document.getElementById("filtroLegajoRonda"); if (_fl) _fl.addEventListener("keyup", function(e) { renderReporteRondas() }); }
  { var _bl = document.getElementById("btnLimpiarFiltrosRonda"); if (_bl) _bl.addEventListener("click", function(e) { limpiarFiltrosRonda() }); }
  document.getElementById("inputBusqueda").addEventListener("keyup", function(e) { filtrarTablaMarcaciones() });
  document.getElementById("filtroAuditoria").addEventListener("change", function(e) { filtrarTablaMarcaciones() });
  document.getElementById("filtroTipo").addEventListener("change", function(e) { filtrarTablaMarcaciones() });
  document.getElementById("btnExcelMarc").addEventListener("click", function(e) { exportarExcel() });
  document.getElementById("btnPDFMarc").addEventListener("click", function(e) { exportarPDF() });
  document.getElementById("btnPDFCumpl").addEventListener("click", function(e) { exportarPDFCumplimientoMensual() });
  document.getElementById("selectFilasPorPagina").addEventListener("change", function(e) { cambiarFilasPorPagina() });
  document.getElementById("btnPagAnt").addEventListener("click", function(e) { irPaginaMarcaciones(-1) });
  document.getElementById("btnPagSig").addEventListener("click", function(e) { irPaginaMarcaciones(1) });
  document.getElementById("inputBusquedaNovedades").addEventListener("keyup", function(e) { filtrarTablaNovedades() });
  document.getElementById("btnExcelNov").addEventListener("click", function(e) { exportarExcelNovedades() });
  document.getElementById("btnPDFNov").addEventListener("click", function(e) { exportarPDFNovedades() });
  document.getElementById("btnCargarAlertas").addEventListener("click", function(e) { cargarAlertasFichadas(false) });
  document.getElementById("btnMarcarVistas").addEventListener("click", function(e) { marcarTodasAlertasFichadasVistas() });
  document.getElementById("btnGenPin").addEventListener("click", function(e) { generarPinEmpleado() });
  document.getElementById("formGuardarObj").addEventListener("submit", function(e) { guardarObjetivo(e) });
  document.getElementById("btnBuscarDireccionNuevo").addEventListener("click", function(e) { buscarDireccionObjetivo('nuevo') });
  document.getElementById("btnbuscarDirGogObj_nuevo").addEventListener("click", function(e) { buscarDireccionGoogleObjetivo('nuevo') });
  document.getElementById("btnaplicarCoordObj_nuevo").addEventListener("click", function(e) { aplicarCoordenadasManualesObjetivo('nuevo') });
  document.getElementById("btnGPSNuevo").addEventListener("click", function(e) { usarGPSObjetivo('nuevo') });
  document.getElementById("btnGuardarOffline").addEventListener("click", function(e) { guardarConfigOffline() });
  document.getElementById("btnCrearDispositivo").addEventListener("click", function(e) { crearDispositivo() });
  document.getElementById("btnCopiarVinc").addEventListener("click", function(e) { copiarCodigoVinculacion() });
  document.getElementById("btnCargarDisp").addEventListener("click", function(e) { cargarDispositivos() });
  document.getElementById("btnGuardarConfig").addEventListener("click", function(e) { guardarConfiguracionGlobal() });
  document.getElementById("btnGuardarModo").addEventListener("click", function(e) { guardarModoDispositivo() });
  document.getElementById("btnApagarPanico").addEventListener("click", function(e) { apagarAlertaPanico() });
  document.getElementById("btnCerrarModal").addEventListener("click", function(e) { cerrarModal() });
  document.getElementById("btnCerrarFraude").addEventListener("click", function(e) { cerrarModalAccionFraude() });
  document.getElementById("btnAprobarFichada").addEventListener("click", function(e) { aprobarFraudeManual() });
  document.getElementById("btnAnularFichada").addEventListener("click", function(e) { eliminarFraudeMarca() });
  document.getElementById("btnCotejarFichada").addEventListener("click", function(e) { verAuditoriaDesdeAccion() });
  document.getElementById("btnCerrarAud").addEventListener("click", function(e) { cerrarModalAuditoria() });
  document.getElementById("btnCerrarAud2").addEventListener("click", function(e) { cerrarModalAuditoria() });
  document.getElementById("btnCerrarEdit").addEventListener("click", function(e) { cerrarModalEditar() });
  document.getElementById("btnCerrarEdit2").addEventListener("click", function(e) { cerrarModalEditar() });
  document.getElementById("btnGuardarEdicion").addEventListener("click", function(e) { guardarEdicionPersonal() });
  document.getElementById("btnCerrarTurnos").addEventListener("click", function(e) { cerrarModalTurnosPersonal() });
  document.getElementById("formGuardarTurno").addEventListener("submit", function(e) { guardarAsignacionTurno(e) });
  document.getElementById("btnCerrarObj").addEventListener("click", function(e) { cerrarModalEditarObjetivo() });
  document.getElementById("btnBuscarDireccionEditar").addEventListener("click", function(e) { buscarDireccionObjetivo('editar') });
  document.getElementById("btnaplicarCoordObj_editar").addEventListener("click", function(e) { aplicarCoordenadasManualesObjetivo('editar') });
  document.getElementById("btnGPSEditar").addEventListener("click", function(e) { usarGPSObjetivo('editar') });
  document.getElementById("btnCerrarObj2").addEventListener("click", function(e) { cerrarModalEditarObjetivo() });
  document.getElementById("btnGuardarEdicionObjetivo").addEventListener("click", function(e) { guardarEdicionObjetivo() });
  // --- Sistema de Rondas con QR (Paso 1) ---
  var _bCfg = document.getElementById("btnGuardarConfigRonda"); if (_bCfg) _bCfg.addEventListener("click", function(e) { guardarConfigRonda() });
  var _bGPSp = document.getElementById("btnGPSPunto"); if (_bGPSp) _bGPSp.addEventListener("click", function(e) { usarGPSPunto() });
  var _bAddP = document.getElementById("btnAgregarPunto"); if (_bAddP) _bAddP.addEventListener("click", function(e) { agregarPuntoRonda() });
  var _bCanP = document.getElementById("btnCancelarEdicionPunto"); if (_bCanP) _bCanP.addEventListener("click", function(e) { cancelarEdicionPunto() });
  var _bCerQR = document.getElementById("btnCerrarQR"); if (_bCerQR) _bCerQR.addEventListener("click", function(e) { cerrarModalQRPunto() });
  var _bDescQR = document.getElementById("btnDescargarQR"); if (_bDescQR) _bDescQR.addEventListener("click", function(e) { descargarQRPunto() });
  var _bImpQR = document.getElementById("btnImprimirQR"); if (_bImpQR) _bImpQR.addEventListener("click", function(e) { imprimirQRPunto() });
  document.getElementById("btnCerrarAlertas").addEventListener("click", function(e) { cerrarModalAlertasFichadas() });
  document.getElementById("btnNotifNav").addEventListener("click", function(e) { solicitarNotificacionesNavegador() });
  document.getElementById("btnMarcarVistas2").addEventListener("click", function(e) { marcarTodasAlertasFichadasVistas() });
  // Comprobante de PIN (mostrar una sola vez): botones del modal.
  var _cbCerrar = document.getElementById("btnCerrarComprobante"); if (_cbCerrar) _cbCerrar.addEventListener("click", function(e) { cerrarComprobantePin() });
  var _cbCerrar2 = document.getElementById("btnCerrarComprobante2"); if (_cbCerrar2) _cbCerrar2.addEventListener("click", function(e) { cerrarComprobantePin() });
  var _cbPDF = document.getElementById("btnComprobantePDF"); if (_cbPDF) _cbPDF.addEventListener("click", function(e) { descargarComprobantePinPDF() });
  var _cbImp = document.getElementById("btnComprobanteImprimir"); if (_cbImp) _cbImp.addEventListener("click", function(e) { imprimirComprobantePin() });
  var _cbCop = document.getElementById("btnComprobanteCopiar"); if (_cbCop) _cbCop.addEventListener("click", function(e) { copiarComprobantePin() });
}
