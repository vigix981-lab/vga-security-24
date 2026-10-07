const URL_FIREBASE = "https://mercosur-seguridad-default-rtdb.firebaseio.com";
let temporizadorInactividad;
let datosVigiladorGlobal = [];
let mapaConfiguracionPersonalVigilador = {};
let asignacionesTurnosVigilador = [];

// ── Sesion autenticada (login-first) ─────────────────────────────────
// El acceso a "Mis Horas" mantiene la sesion de Firebase Auth y usa su
// idToken para leer SOLO los datos propios (?auth=). Sin sesion no se
// hace ningun fetch de personal/fichadas.
let idTokenVig = null;
let legajoSesionVig = null;

// Comparación de legajo ÚNICA y consistente (evita mezclar string y parseInt
// en distintos puntos). Normaliza con trim; si ambos son numéricos compara
// también por valor entero (tolera ceros a la izquierda). Legajo SIEMPRE string.
function mismoLegajoVig(a, b) {
  const x = String(a == null ? '' : a).trim();
  const y = String(b == null ? '' : b).trim();
  if (x === '' || y === '') return false;
  if (x === y) return true;
  const nx = parseInt(x, 10), ny = parseInt(y, 10);
  return Number.isFinite(nx) && Number.isFinite(ny) && nx === ny;
}

function urlAuth(url) {
  // Si el timer renovó el token, sincronizar antes de armar la URL
  if (window._forzarRefreshTokenMisHoras) {
    // nothing needed here, urlAuthFresca handles the refresh
  }
  if (!idTokenVig) return url;
  return url + (url.includes('?') ? '&' : '?') + 'auth=' + encodeURIComponent(idTokenVig);
}

// Refresca el idToken contra la sesion viva de Firebase Auth (el SDK lo
// renueva si esta vencido) y luego arma la URL con ?auth. Se usa en las
// ESCRITURAS criticas (panico / novedades) para que el token cacheado no
// caduque en turnos largos y la alerta no sea rechazada por las reglas.
async function urlAuthFresca(url) {
  try {
    if (typeof window.obtenerTokenVigilador === 'function') {
      // obtenerTokenVigilador ya fuerza refresh si el token tiene >50 min
      const t = await window.obtenerTokenVigilador(true);
      if (t) idTokenVig = t;
    }
  } catch (_) {}
  return urlAuth(url);
}

// Lee SOLO la ficha propia (query scoped por legajo, SIEMPRE string) en
// vez de descargar todo /personal. Requiere .indexOn:["legajo"] en reglas.
// El legajo se guarda y se compara SIEMPRE como string (tambien en las
// Reglas de Seguridad), por eso NO se hace variante numerica: un equalTo
// numerico contra un indice string nunca coincide (query denegado/vacio).
async function fetchPersonalScoped(legajo) {
  const base = `${URL_FIREBASE}/personal.json?orderBy=${encodeURIComponent('"legajo"')}`;
  const legajoStr = String(legajo == null ? '' : legajo).trim();
  const r = await fetch(urlAuth(base + '&equalTo=' + encodeURIComponent('"' + legajoStr + '"') + '&ts=' + Date.now()), { cache: 'no-store' }).then(x => x.json()).catch(() => null);
  return r || null;
}

// Variables para control del Botón de Pánico sostenido
let temporizadorPanico = null;
let intervaloProgresoPanico = null;
let tiempoPresionadoMs = 0;
let panicoEnEnvio = false;   // evita reenvío/duplicado de una alerta de pánico en curso
let novedadEnEnvio = false;  // evita reenvío/duplicado de una novedad en curso
const TIEMPO_REQUERIDO_MS = 3000; // 3 segundos

// ── Seguridad (anti-XSS) ─────────────────────────────────────────────
// Escapa caracteres peligrosos antes de insertar texto proveniente de la
// base de datos dentro de innerHTML. Evita inyección de código (XSS).
function escapeHtml(valor) {
  return String(valor == null ? '' : valor)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Sanitiza texto libre antes de guardarlo en Firebase: quita etiquetas HTML
// y esquemas peligrosos, y recorta el largo. El contenido se guarda como
// texto plano; el panel debe renderizarlo con textContent.
function sanitizarTextoLibre(valor, maxLargo = 2000) {
  let t = String(valor == null ? '' : valor);
  t = t.replace(/<[^>]*>/g, '');                 // elimina cualquier etiqueta
  t = t.replace(/javascript:/gi, '');            // elimina esquema javascript:
  t = t.replace(/on\w+\s*=/gi, '');               // elimina manejadores on*=
  t = t.replace(/[\u0000-\u001F\u007F]/g, ' ');   // caracteres de control
  return t.trim().slice(0, maxLargo);
}

// Identificador único de evento (clave de idempotencia) para pánicos e
// incidencias. Permite detectar/descartar retransmisiones duplicadas.
function generarIdEvento() {
  try {
    if (window.crypto && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    if (window.crypto && crypto.getRandomValues) {
      const b = crypto.getRandomValues(new Uint8Array(16));
      return Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
    }
  } catch (e) { /* fallback abajo */ }
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

// Registro de ids ya enviados en esta sesión para no retransmitir dos veces.
const eventosEnviados = new Set();

// Consulta SOLO las fichadas del legajo indicado usando el índice del
// servidor (orderBy="legajo"&equalTo="..."), en vez de descargar el nodo
// completo y filtrar en el cliente. El legajo se guarda y se compara
// SIEMPRE como string (tambien en las Reglas de Seguridad), por eso NO se
// hace variante numerica: un equalTo numerico contra un indice string
// nunca coincide (query denegado/vacio).
function fetchFichadasLegajo(legajo) {
  const legajoStr = String(legajo == null ? '' : legajo).trim();
  const urlScoped = urlAuth(`${URL_FIREBASE}/fichadas.json?orderBy=%22legajo%22&equalTo=%22${encodeURIComponent(legajoStr)}%22&ts=${Date.now()}`);
  return fetch(urlScoped, { cache: 'no-store' })
    .then(res => res.ok ? res.json() : null)
    .catch(() => null);
}

// Consulta SOLO los turnos asignados al legajo indicado usando el indice
// del servidor (orderBy="legajo"&equalTo="..."), en vez de descargar TODO
// el nodo asignacionesTurnos (turnos de todos los empleados) y filtrar en
// el cliente. El legajo se guarda y se compara SIEMPRE como string (tambien
// en las Reglas de Seguridad), por eso NO se hace variante numerica: un
// equalTo numerico contra un indice string nunca coincide (query vacio).
// Requiere .indexOn:["legajo"] en la regla de asignacionesTurnos.
function fetchTurnosLegajo(legajo) {
  const legajoStr = String(legajo == null ? '' : legajo).trim();
  const urlScoped = urlAuth(`${URL_FIREBASE}/asignacionesTurnos.json?orderBy=%22legajo%22&equalTo=%22${encodeURIComponent(legajoStr)}%22&ts=${Date.now()}`);
  return fetch(urlScoped, { cache: 'no-store' })
    .then(res => res.ok ? res.json() : null)
    .catch(() => null);
}

function parseFechaSegura(fechaStr) {
  if (!fechaStr) return new Date(NaN);
  let d = new Date(fechaStr);
  if (!isNaN(d.getTime())) return d;
  d = new Date(String(fechaStr).replace(/-/g, '/'));
  return d;
}

function minutosDesdeMedianoche(hora) {
  if (!hora || !/^\d{1,2}:\d{2}$/.test(String(hora))) return null;
  const [h, m] = String(hora).split(':').map(Number);
  if (h < 0 || h > 23 || m < 0 || m > 59) return null;
  return h * 60 + m;
}

function obtenerFechaLocalClave(fecha) {
  if (!(fecha instanceof Date) || isNaN(fecha.getTime())) return '';
  const y = fecha.getFullYear();
  const m = String(fecha.getMonth() + 1).padStart(2, '0');
  const d = String(fecha.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function obtenerHorarioProgramado(entrada, legajo, objetivoNombre) {
  const fechaEntrada = parseFechaSegura(entrada);
  if (isNaN(fechaEntrada.getTime())) return null;

  const fechaClave = obtenerFechaLocalClave(fechaEntrada);
  const legajoStr = String(legajo || '').trim();
  const objetivoStr = String(objetivoNombre || '').trim().toLowerCase();

  // Primero: turno puntual asignado desde ADMIN para esa fecha.
  const turnosFecha = asignacionesTurnosVigilador.filter(t =>
    mismoLegajoVig(t.legajo, legajoStr) && String(t.fecha || '') === fechaClave
  );

  let turno = null;
  if (turnosFecha.length) {
    // Si hay más de un turno, priorizar el objetivo de la fichada.
    turno = turnosFecha.find(t => {
      const nombre = String(t.objetivoNombre || t.objetivo || '').trim().toLowerCase();
      return objetivoStr && nombre && (
        nombre === objetivoStr ||
        nombre.includes(objetivoStr) ||
        objetivoStr.includes(nombre)
      );
    }) || turnosFecha[0];
  }

  if (turno && (turno.horaInicio || turno.horaFin)) {
    return {
      inicio: turno.horaInicio || '',
      fin: turno.horaFin || '',
      origen: 'Turno asignado'
    };
  }

  // Segundo: horario habitual configurado en ADMIN para ese vigilador.
  const persona = Object.values(mapaConfiguracionPersonalVigilador).find(p =>
    mismoLegajoVig(p.legajo, legajoStr)
  );
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

function calcularHoras(f1, f2, horarioProgramado = null) {
  const inicioReal = parseFechaSegura(f1);
  const fin = parseFechaSegura(f2);

  if (isNaN(inicioReal.getTime()) || isNaN(fin.getTime()) || fin <= inicioReal) {
    return { d: 0, n: 0, t: 0, entradaComputable: inicioReal, ajusteMinutos: 0 };
  }

  // La fichada real NO se modifica. Solo se modifica el punto desde el cual
  // se calculan las horas trabajadas cuando hubo llegada anticipada.
  let inicioComputable = new Date(inicioReal.getTime());
  let ajusteMinutos = 0;

  if (horarioProgramado?.inicio) {
    const minutosTurno = minutosDesdeMedianoche(horarioProgramado.inicio);

    if (minutosTurno !== null) {
      const inicioTurno = new Date(inicioReal.getTime());
      inicioTurno.setHours(
        Math.floor(minutosTurno / 60),
        minutosTurno % 60,
        0,
        0
      );

      // Ejemplo: turno 19:00, entrada 18:30 -> computar desde 19:00.
      // Si entra 19:20 -> se mantiene 19:20.
      if (inicioTurno > inicioComputable) {
        inicioComputable = inicioTurno;
        ajusteMinutos = Math.round((inicioComputable - inicioReal) / 60000);
      }
    }
  }

  if (inicioComputable >= fin) {
    return { d: 0, n: 0, t: 0, entradaComputable: inicioComputable, ajusteMinutos };
  }

  let diurnas = 0;
  let nocturnas = 0;
  let cur = new Date(inicioComputable.getTime());

  while (cur < fin) {
    let siguiente = new Date(cur.getTime() + 60000);
    if (siguiente > fin) siguiente = new Date(fin.getTime());

    const h = cur.getHours();
    const minutos = (siguiente - cur) / 60000;

    if (h >= 6 && h < 21) diurnas += minutos / 60;
    else nocturnas += minutos / 60;

    cur = siguiente;
  }

  return {
    d: diurnas,
    n: nocturnas,
    t: diurnas + nocturnas,
    entradaComputable: inicioComputable,
    ajusteMinutos
  };
}

function reiniciarTemporizador() {
  clearTimeout(temporizadorInactividad);
  temporizadorInactividad = setTimeout(() => {
    if (sessionStorage.getItem('vigilador_legajo')) {
      cerrarSesionVigilador();
      alert("Sesión cerrada automáticamente por 3 minutos de inactividad.");
    }
  }, 180000); 
}

window.onload = function() {
  // LOGIN-FIRST: NO auto-restauramos ninguna sesion previa. Sin token de
  // Firebase Auth valido no se puede leer nada, asi que siempre arrancamos
  // en la pantalla de login. Limpiamos cualquier rastro de sesion anterior.
  sessionStorage.removeItem('vigilador_legajo');
  sessionStorage.removeItem('vigilador_nombre');
  sessionStorage.removeItem('vigilador_token');
  idTokenVig = null;
  legajoSesionVig = null;

  const prev = document.getElementById('previewLegajoVigilador');
  if (prev) { prev.classList.add('hidden'); prev.innerHTML = ''; }
  document.getElementById('formLoginVigilador').classList.remove('hidden');
  document.getElementById('infoSesionActiva').classList.add('hidden');
  document.getElementById('btnCerrarSesion').classList.add('hidden');

  inicializarBotonPanicoSostenido();
  // Al abrir la app: mostrar avisos de alertas pendientes y reintentar la
  // cola de pánicos por si quedó algo sin enviar en una sesión anterior.
  actualizarAvisoPanicosPendientes();
  reenviarPanicosPendientes();
  // Idem para la cola de novedades (Punto 2).
  actualizarAvisoNovedadesPendientes();
  reenviarNovedadesPendientes();
};

function activarEscuchasInactividad() {
  window.addEventListener('mousemove', reiniciarTemporizador);
  window.addEventListener('mousedown', reiniciarTemporizador);
  window.addEventListener('keypress', reiniciarTemporizador);
  window.addEventListener('touchstart', reiniciarTemporizador);
}



function formatearAHorasReloj(horasDecimales) {
  if (isNaN(horasDecimales) || horasDecimales <= 0) return "00:00 hs";
  const horas = Math.floor(horasDecimales);
  const minutos = Math.round((horasDecimales - horas) * 60);
  return `${String(horas).padStart(2, '0')}:${String(minutos).padStart(2, '0')} hs`;
}

// Muestra (SOLO tras iniciar sesion) el resumen del legajo: nombre +
// ultima fichada + proxima accion esperada. Usa exclusivamente los datos
// ya cargados de la sesion; NO hace ninguna lectura previa al login.
function renderPreviewVigilador(nombreEmpleado, misFichadas) {
  const cont = document.getElementById('previewLegajoVigilador');
  if (!cont) return;
  const lista = Array.isArray(misFichadas) ? [...misFichadas] : [];
  lista.sort((a, b) => new Date(a.fecha) - new Date(b.fecha));
  const ultima = lista[lista.length - 1] || null;
  let ultimaTxt = 'Sin fichadas registradas';
  let proximaTxt = 'ENTRADA';
  if (ultima) {
    const fdt = new Date(ultima.fecha);
    const fechaFmt = isNaN(fdt.getTime()) ? String(ultima.fecha) : fdt.toLocaleString('es-AR');
    ultimaTxt = `${(ultima.tipo || 'FICHADA')} — ${fechaFmt}`;
    if (ultima.esOffline === true) {
      ultimaTxt += ultima.pendienteVerif === true
        ? ' (hora del dispositivo · pendiente de verificación)'
        : ' (hora del dispositivo)';
    }
    proximaTxt = (String(ultima.tipo || '').toUpperCase() === 'ENTRADA') ? 'SALIDA' : 'ENTRADA';
  }
  cont.classList.remove('hidden');
  cont.innerHTML =
    `<span><i class="fa-solid fa-user text-emerald-400"></i> <strong class="text-white">${escapeHtml(nombreEmpleado)}</strong></span>` +
    `<span><i class="fa-solid fa-clock-rotate-left text-emerald-400"></i> Última: ${escapeHtml(ultimaTxt)}</span>` +
    `<span><i class="fa-solid fa-arrow-right text-emerald-400"></i> Próxima acción esperada: <strong class="text-white">${escapeHtml(proximaTxt)}</strong></span>`;
}

async function buscarMisHoras() {
  const legajoIngresado = document.getElementById('legajoInput').value.trim();
  const pinIngresado = document.getElementById('pinInput').value.trim();

  if (!legajoIngresado || !pinIngresado) {
    return alert("Por favor ingresa tu número de legajo y tu PIN de seguridad.");
  }

  // 1) LOGIN REAL contra Firebase Auth (sesion persistente). Recien con un
  //    token valido se realiza CUALQUIER lectura; sin login no se baja nada.
  let loginOk = false;
  if (typeof window.loginVigilador === 'function') {
    try {
      const res = await window.loginVigilador(legajoIngresado, pinIngresado);
      if (res && res.ok && res.idToken) {
        idTokenVig = res.idToken;
        legajoSesionVig = legajoIngresado;
        loginOk = true;
      }
    } catch (_) {}
  }
  if (!loginOk) {
    alert('❌ Legajo o PIN incorrecto. No podés acceder a tus horas sin las credenciales reales de tu legajo.');
    return;
  }

  try {
    // 2) Lecturas SCOPED + ?auth: SOLO la ficha y las fichadas propias.
    const [personalData, fichadasData, turnosData] = await Promise.all([
      fetchPersonalScoped(legajoIngresado),
      fetchFichadasLegajo(legajoIngresado),
      fetchTurnosLegajo(legajoIngresado)
    ]);

    mapaConfiguracionPersonalVigilador = personalData || {};
    asignacionesTurnosVigilador = turnosData
      ? Object.entries(turnosData).map(([id, d]) => ({ ...d, id }))
      : [];

    let nombreEmpleado = `Legajo ${legajoIngresado}`;
    let estadoVigilador = 'ACTIVO';
    let fichaEncontrada = false;
    if (personalData) {
      Object.values(personalData).forEach(p => {
        const pLegajo = String(p.legajo || "").trim();
        if (mismoLegajoVig(pLegajo, legajoIngresado)) {
          fichaEncontrada = true;
          if (p.nombre) nombreEmpleado = p.nombre;
          estadoVigilador = String(p.estado || 'ACTIVO').trim().toUpperCase();
        }
      });
    }

    // Bloqueo por estado: un legajo INACTIVO / dado de baja NO puede consultar
    // su historial ni usar el botón de pánico desde Mis Horas (misma política que index.html).
    if (fichaEncontrada && estadoVigilador !== 'ACTIVO') {
      try { if (typeof window.logoutVigilador === 'function') await window.logoutVigilador(); } catch (_) {}
      idTokenVig = null; legajoSesionVig = null;
      alert('⛔ Tu legajo figura como INACTIVO / dado de baja. No podés acceder a tus horas. Contactá al administrador.');
      return;
    }

    let misFichadas = [];
    if (fichadasData) {
      Object.values(fichadasData).forEach(f => {
        const fLegajo = String(f.legajo || "").trim();
        const coincideLegajo = mismoLegajoVig(fLegajo, legajoIngresado);
        if (coincideLegajo) {
          misFichadas.push({
            // Se prioriza el sello de servidor unificado (timestampServidor, no
            // manipulable) y se convierte a texto ISO; 'timestamp' queda como compat
            // de fichadas antiguas y el reloj del dispositivo como fallback final.
            fecha: (typeof f.timestampServidor === 'number' ? new Date(f.timestampServidor).toISOString() : (typeof f.timestampEstimadoDispositivo === 'number' ? new Date(f.timestampEstimadoDispositivo).toISOString() : (typeof f.timestamp === 'number' ? new Date(f.timestamp).toISOString() : (f.fechaHoraDispositivo || f.fecha)))),
            legajo: f.legajo,
            objetivo: f.objetivo || 'Objetivo General',
            tipo: String(f.tipo || "").toUpperCase(),
            // Fichada registrada sin conexión: la hora es del dispositivo (no
            // sellada por el servidor) y puede estar pendiente de verificación.
            esOffline: (f.origenOffline === true || f.sincronizadoDesdeOffline === true || f.horaVerificadaServidor === false),
            pendienteVerif: ((f.origenOffline === true || f.sincronizadoDesdeOffline === true || f.horaVerificadaServidor === false) && f.verificacionOfflineResuelta !== true)
          });
        }
      });
    }

    if (misFichadas.length === 0) {
      alert("No se encontraron registros de fichadas para el legajo ingresado.");
      return;
    }

    sessionStorage.setItem('vigilador_legajo', legajoIngresado);
    sessionStorage.setItem('vigilador_nombre', nombreEmpleado);
    sessionStorage.setItem('vigilador_token', generarIdEvento());
    datosVigiladorGlobal = misFichadas;

    document.getElementById('formLoginVigilador').classList.add('hidden');
    document.getElementById('infoSesionActiva').classList.remove('hidden');
    document.getElementById('lblLegajoActivo').innerText = legajoIngresado;
    document.getElementById('lblNombreActivo').innerText = nombreEmpleado;
    document.getElementById('btnCerrarSesion').classList.remove('hidden');
    document.getElementById('seccionPanico').classList.remove('hidden');
    document.getElementById('seccionNovedades').classList.remove('hidden'); 

    // Recien AHORA (ya con sesion iniciada) mostramos el resumen del legajo:
    // nombre + ultima fichada + proxima accion esperada.
    renderPreviewVigilador(nombreEmpleado, misFichadas);

    poblarSelectMeses(datosVigiladorGlobal);
    procesarYRenderizar(datosVigiladorGlobal);
    activarEscuchasInactividad();
    reiniciarTemporizador();
    actualizarAvisoPanicosPendientes();
    reenviarPanicosPendientes();
    actualizarAvisoNovedadesPendientes();
    reenviarNovedadesPendientes();
  } catch (err) {
    console.error(err);
    alert("Ocurrió un error al consultar Firebase.");
  }
}

function poblarSelectMeses(datos) {
  const selectMes = document.getElementById('filtroMes');
  const mesActualSeleccionado = selectMes.value;
  
  const mesesSet = new Set();
  datos.forEach(f => {
    if(f.fecha) {
      const d = parseFechaSegura(f.fecha);
      if(!isNaN(d.getTime())) {
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
    const nombreMesTexto = `${nombresMeses[parseInt(mesNum, 10) - 1]} ${anio}`;
    const opt = document.createElement('option');
    opt.value = m;
    opt.innerText = nombreMesTexto;
    selectMes.appendChild(opt);
  });

  if (mesesOrdenados.includes(mesActualSeleccionado)) {
    selectMes.value = mesActualSeleccionado;
  }
}

function aplicarFiltros() {
  const mesFiltro = document.getElementById('filtroMes').value;
  const diaFiltro = document.getElementById('filtroDia').value;

  // Primero armamos los turnos completos (entrada + salida) sobre TODO el set,
  // para que un turno que cruza la medianoche (ej. 19:00 -> 07:00) conserve su
  // salida. Recién despues filtramos cada turno por la fecha de su ENTRADA.
  let turnos = construirTurnos(datosVigiladorGlobal);

  if (mesFiltro !== 'todos') {
    turnos = turnos.filter(t => {
      const d = parseFechaSegura(t.entrada.fecha);
      if (isNaN(d.getTime())) return false;
      const anio = d.getFullYear();
      const mes = String(d.getMonth() + 1).padStart(2, '0');
      return `${anio}-${mes}` === mesFiltro;
    });
  }

  if (diaFiltro) {
    turnos = turnos.filter(t => {
      const d = parseFechaSegura(t.entrada.fecha);
      if (isNaN(d.getTime())) return false;
      const anio = d.getFullYear();
      const mes = String(d.getMonth() + 1).padStart(2, '0');
      const dia = String(d.getDate()).padStart(2, '0');
      return `${anio}-${mes}-${dia}` === diaFiltro;
    });
  }

  renderizarTurnos(turnos);
}

function limpiarFiltros() {
  document.getElementById('filtroMes').value = 'todos';
  document.getElementById('filtroDia').value = '';
  procesarYRenderizar(datosVigiladorGlobal);
}

// Empareja cada ENTRADA con su SALIDA adyacente usando SIEMPRE el set completo
// de marcaciones (ordenado por fecha). De esta forma un turno que cruza la
// medianoche (ej. 19:00 -> 07:00) mantiene su salida aunque luego se filtre por
// dia/mes.
function construirTurnos(marcaciones) {
  const orden = [...marcaciones].sort((a, b) => parseFechaSegura(a.fecha) - parseFechaSegura(b.fecha));
  const turnos = [];
  for (let i = 0; i < orden.length; i++) {
    if (orden[i].tipo === 'ENTRADA') {
      const entrada = orden[i];
      const salida = orden[i + 1] && orden[i + 1].tipo === 'SALIDA' ? orden[i + 1] : null;
      turnos.push({ entrada, salida });
    }
  }
  return turnos;
}

function procesarYRenderizar(marcacionesVigilador) {
  renderizarTurnos(construirTurnos(marcacionesVigilador));
}

function renderizarTurnos(turnos) {
  let totalD = 0, totalN = 0, totalT = 0;
  const tabla = document.getElementById('cuerpoDetalle');
  tabla.innerHTML = "";

  for (const turnoPar of turnos) {
      let entrada = turnoPar.entrada;
      let salida = turnoPar.salida;

      let objetivoNombre = entrada.objetivo || (salida && salida.objetivo) || '-';
      const horarioProgramado = obtenerHorarioProgramado(entrada.fecha, entrada.legajo, objetivoNombre);
      let horas = salida
        ? calcularHoras(entrada.fecha, salida.fecha, horarioProgramado)
        : { d: 0, n: 0, t: 0, ajusteMinutos: 0 };

      totalD += horas.d;
      totalN += horas.n;
      totalT += horas.t;

      const fEntrada = parseFechaSegura(entrada.fecha);
      const fSalida = salida ? parseFechaSegura(salida.fecha) : null;

      // Marca de fichada offline: la hora mostrada es del dispositivo (no sellada
      // por el servidor). Se resalta en ámbar mientras esté pendiente de verificación.
      const algunOffline = (entrada && entrada.esOffline === true) || (salida && salida.esOffline === true);
      const algunPendiente = (entrada && entrada.pendienteVerif === true) || (salida && salida.pendienteVerif === true);
      const notaOffline = algunOffline
        ? `<div class="mt-1 inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold ${algunPendiente ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30' : 'bg-slate-500/15 text-slate-300 border border-slate-500/30'}" title="Fichada registrada sin conexión: la hora proviene del dispositivo y no fue sellada por el servidor${algunPendiente ? '. Pendiente de verificación por un administrador.' : ' (ya verificada manualmente).'}"><i class="fa-solid fa-clock-rotate-left"></i> hora del dispositivo${algunPendiente ? ' · pendiente de verificación' : ''}</div>`
        : '';

      const tr = document.createElement('tr');
      tr.className = "hover:bg-slate-700/30 transition";
      tr.innerHTML = `
        <td class="p-4 text-xs font-mono">${!isNaN(fEntrada.getTime()) ? fEntrada.toLocaleString('es-AR', { hour12: false }) : escapeHtml(entrada.fecha)}</td>
        <td class="p-4 text-xs font-mono">${salida ? (!isNaN(fSalida.getTime()) ? fSalida.toLocaleString('es-AR', { hour12: false }) : escapeHtml(salida.fecha)) : '<span class="text-amber-400">En Turno</span>'}</td>
        <td class="p-4 text-xs text-slate-300 font-medium">${escapeHtml(objetivoNombre)}
          <div class="text-[10px] text-slate-500 mt-1">${horarioProgramado ? `Turno ${escapeHtml(horarioProgramado.inicio || '--:--')} - ${escapeHtml(horarioProgramado.fin || '--:--')} · ${escapeHtml(horarioProgramado.origen)}` : 'Sin horario configurado'}${horas.ajusteMinutos > 0 ? ` · ${horas.ajusteMinutos} min anticipados no computados` : ''}</div>${notaOffline}
        </td>
        <td class="p-4 text-center text-xs font-semibold text-amber-400">${formatearAHorasReloj(horas.d)}</td>
        <td class="p-4 text-center text-xs font-semibold text-indigo-400">${formatearAHorasReloj(horas.n)}</td>
        <td class="p-4 text-center text-xs font-bold text-emerald-400">${formatearAHorasReloj(horas.t)}</td>
      `;
      tabla.appendChild(tr);
  }

  document.getElementById('horasDiurnas').innerText = formatearAHorasReloj(totalD);
  document.getElementById('horasNocturnas').innerText = formatearAHorasReloj(totalN);
  document.getElementById('horasTotales').innerText = formatearAHorasReloj(totalT);

  document.getElementById('seccionFiltros').classList.remove('hidden');
  document.getElementById('resumenHoras').classList.remove('hidden');
  document.getElementById('contenedorTabla').classList.remove('hidden');
}

// 🚨 CONFIGURACIÓN DEL BOTÓN DE PÁNICO SOSTENIDO (3 SEGUNDOS)
function inicializarBotonPanicoSostenido() {
  const btn = document.getElementById('btnPanico');
  
  const iniciarPresion = (e) => {
    e.preventDefault();
    tiempoPresionadoMs = 0;
    document.getElementById('textoPanico').innerText = "MANTÉN PRESIONADO...";
    
    intervaloProgresoPanico = setInterval(() => {
      tiempoPresionadoMs += 50;
      let porcentaje = Math.min((tiempoPresionadoMs / TIEMPO_REQUERIDO_MS) * 100, 100);
      document.getElementById('barraProgresoPanico').style.width = `${porcentaje}%`;
    }, 50);

    temporizadorPanico = setTimeout(() => {
      cancelarPresion();
      dispararAlertaPanico();
    }, TIEMPO_REQUERIDO_MS);
  };

  const cancelarPresion = () => {
    clearTimeout(temporizadorPanico);
    clearInterval(intervaloProgresoPanico);
    tiempoPresionadoMs = 0;
    document.getElementById('barraProgresoPanico').style.width = '0%';
    document.getElementById('textoPanico').innerText = "MANTÉN PRESIONADO (3s)";
  };

  // Eventos para Desktop y Mobile
  btn.addEventListener('mousedown', iniciarPresion);
  btn.addEventListener('mouseup', cancelarPresion);
  btn.addEventListener('mouseleave', cancelarPresion);

  btn.addEventListener('touchstart', iniciarPresion);
  btn.addEventListener('touchend', cancelarPresion);
  btn.addEventListener('touchcancel', cancelarPresion);
}

// 🚨 EJECUCIÓN DE LA ALERTA DE PÁNICO CORREGIDA
function dispararAlertaPanico() {
  if (panicoEnEnvio) return; // ya hay una alerta en curso: no duplicar
  const legajo = sessionStorage.getItem('vigilador_legajo');
  const nombreVigilador = sessionStorage.getItem('vigilador_nombre') || `Legajo ${legajo}`;

  if (!legajo) {
    alert("Debe iniciar sesión para emitir una alerta.");
    return;
  }

  let enServicio = false;
  let objetivoActual = "Objetivo Asignado";

  if (datosVigiladorGlobal.length > 0) {
    let ordenadas = [...datosVigiladorGlobal].sort((a, b) => parseFechaSegura(a.fecha) - parseFechaSegura(b.fecha));
    let ultimaMar = ordenadas[ordenadas.length - 1];
    
    if (ultimaMar && ultimaMar.tipo === 'ENTRADA') {
      enServicio = true;
      if (ultimaMar.objetivo) objetivoActual = ultimaMar.objetivo;
    }
  }

  if (!enServicio) {
    alert("❌ No se puede enviar la alerta de pánico: Se encuentra fuera de servicio (requiere tener una Entrada activa).");
    return;
  }

  if (!navigator.geolocation) {
    alert("Tu dispositivo no soporta geolocalización.");
    return;
  }

  navigator.geolocation.getCurrentPosition(
    async function(position) {
      const lat = position.coords.latitude;
      const lon = position.coords.longitude;
      const fechaActual = new Date().toISOString();
      const idEvento = generarIdEvento();

      // Payload estandarizado incluyendo 'fechaHora' para que el panel lo lea correctamente
      const payloadPanico = {
        tipo: "PANICO",
        legajo: String(legajo),
        nombre: nombreVigilador,
        objetivo: objetivoActual,
        latitud: lat,
        longitud: lon,
        mapa: `https://www.google.com/maps?q=${lat},${lon}`,
        fechaHora: fechaActual,
        fechaHoraDispositivo: fechaActual,
        // Sello de servidor Firebase (.sv=timestamp): hora oficial NO manipulable,
        // independiente del reloj del telefono. El admin/panel la leen con prioridad.
        timestampServidor: { ".sv": "timestamp" },
        estado: "PENDIENTE",
        atendido: false,
        // Clave de idempotencia + token de sesión: permiten al panel descartar
        // retransmisiones duplicadas y correlacionar el evento con la sesión activa.
        idEvento: idEvento,
        tokenSesion: sessionStorage.getItem('vigilador_token') || '',
        emitidoEnMs: Date.now()
      };

      if (eventosEnviados.has(idEvento)) { panicoEnEnvio = false; return; }
      eventosEnviados.add(idEvento);
      panicoEnEnvio = true;

      // Sin conexión: NO se pierde la alerta. Se guarda en la cola local y
      // se reenvía automáticamente al recuperar internet.
      if (!navigator.onLine) {
        encolarPanicoPendiente(payloadPanico);
        panicoEnEnvio = false;
        alert("⚠️ SIN CONEXIÓN. La alerta de pánico quedó guardada y se enviará automáticamente apenas se recupere internet. Mantené el teléfono encendido.");
        return;
      }

      // ENVÍO ONLINE con validación REAL de la respuesta del servidor.
      // Antes se informaba "ENVIADA" apenas respondía el servidor, sin mirar
      // el código HTTP: un rechazo (token vencido, reglas) se mostraba como
      // éxito y la alerta se perdía en silencio. Ahora decidimos según el
      // resultado real:
      //   - 2xx + payload (data.name)  -> ÉXITO confirmado.
      //   - 401 (token vencido)        -> refrescamos token y reintentamos 1 vez.
      //   - 403 / 422 (rechazo reglas) -> NO se encola (reintentar daría lo mismo):
      //                                    se avisa que la central NO la recibió.
      //   - red / 5xx (caída temporal) -> se encola con el MISMO idEvento para
      //                                    reintento automático (sin duplicar).
      async function postPanicoUnaVez() {
        const urlPanico = await urlAuthFresca(`${URL_FIREBASE}/panicos.json`);
        return fetch(urlPanico, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payloadPanico)
        });
      }

      try {
        let res = await postPanicoUnaVez();

        // 401: token vencido. Refrescamos (urlAuthFresca ya fuerza refresh)
        // y reintentamos una sola vez.
        if (res.status === 401) {
          res = await postPanicoUnaVez();
        }

        if (res.ok) {
          // Éxito confirmado: 2xx + payload del servidor (push-key en data.name).
          const data = await res.json().catch(() => null);
          if (data && data.name) {
            if (payloadPanico.idEvento) eventosEnviados.add(payloadPanico.idEvento);
            panicoEnEnvio = false;
            alert("🚨 ¡ALERTA DE PÁNICO ENVIADA A LA CENTRAL. EL PERSONAL OPERATIVO HA SIDO NOTIFICADO!");
          } else {
            // 2xx pero sin payload esperado: lo tratamos como ambiguo y lo
            // encolamos para reintento (no perdemos la alerta).
            panicoEnEnvio = false;
            encolarPanicoPendiente(payloadPanico);
            alert("⚠️ La central respondió de forma incompleta. La alerta quedó guardada y se reintentará automáticamente.");
          }
        } else if (res.status === 403 || res.status === 422) {
          // Rechazo definitivo (permisos / datos inválidos): reintentar daría
          // el mismo resultado, por eso NO se encola. Se avisa con claridad.
          panicoEnEnvio = false;
          alert("❌ La central RECHAZÓ la alerta de pánico (sesión o permisos). NO fue registrada. Volvé a iniciar sesión e intentá de nuevo.");
        } else {
          // 5xx u otro error temporal del servidor: se encola para reintento.
          panicoEnEnvio = false;
          encolarPanicoPendiente(payloadPanico);
          alert("⚠️ La central no pudo procesar la alerta en este momento. Quedó guardada y se reintentará automáticamente.");
        }
      } catch (error) {
        // Caída de red: no se pierde la alerta, se encola con el mismo idEvento.
        panicoEnEnvio = false;
        encolarPanicoPendiente(payloadPanico);
        alert("⚠️ No se pudo contactar a la central en este momento. La alerta quedó guardada y se reintentará automáticamente al recuperar la conexión.");
      }
    },
    function(error) {
      alert("Error: Es obligatorio permitir el acceso al GPS para activar la alerta de pánico.");
    },
    { enableHighAccuracy: true }
  );
}

// ---- Cola offline de pánicos: garantiza que ninguna alerta se pierda ----
const CLAVE_PANICOS_PENDIENTES = 'panicos_pendientes';
let reenviandoPanicos = false;

// Guarda una alerta de pánico en la cola local (idempotente por idEvento).
function encolarPanicoPendiente(payload) {
  try {
    let cola = JSON.parse(localStorage.getItem(CLAVE_PANICOS_PENDIENTES) || '[]');
    if (!cola.some(p => p && p.idEvento === payload.idEvento)) {
      cola.push(payload);
      localStorage.setItem(CLAVE_PANICOS_PENDIENTES, JSON.stringify(cola));
    }
    actualizarAvisoPanicosPendientes();
  } catch (e) { /* si falla localStorage no interrumpimos la operatoria */ }
}

// Reenvía en orden todas las alertas encoladas. Solo elimina de la cola las
// que confirmó el servidor; las que fallan quedan para el próximo intento.
function reenviarPanicosPendientes() {
  if (reenviandoPanicos || !navigator.onLine) return;
  let cola;
  try { cola = JSON.parse(localStorage.getItem(CLAVE_PANICOS_PENDIENTES) || '[]'); }
  catch (e) { cola = []; }
  if (!cola.length) return;

  reenviandoPanicos = true;
  const pendientes = [...cola];

  (async () => {
    const sobrevivientes = [];
    for (const payload of pendientes) {
      try {
        const urlP = await urlAuthFresca(`${URL_FIREBASE}/panicos.json`);
        let res = await fetch(urlP, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        await res.json();
        if (payload.idEvento) eventosEnviados.add(payload.idEvento);
      } catch (e) {
        sobrevivientes.push(payload); // sigue pendiente para reintentar luego
      }
    }
    try { localStorage.setItem(CLAVE_PANICOS_PENDIENTES, JSON.stringify(sobrevivientes)); }
    catch (e) { /* noop */ }
    reenviandoPanicos = false;
    actualizarAvisoPanicosPendientes();
    const enviadas = pendientes.length - sobrevivientes.length;
    if (enviadas > 0) {
      alert(`🚨 Se reenvi${enviadas === 1 ? 'ó' : 'eron'} ${enviadas} alerta${enviadas === 1 ? '' : 's'} de pánico pendiente${enviadas === 1 ? '' : 's'} a la central.`);
    }
  })();
}

// Muestra/actualiza el aviso visible de alertas de pánico aún sin confirmar.
function actualizarAvisoPanicosPendientes() {
  let cola;
  try { cola = JSON.parse(localStorage.getItem(CLAVE_PANICOS_PENDIENTES) || '[]'); }
  catch (e) { cola = []; }
  const aviso = document.getElementById('avisoPanicosPendientes');
  if (!aviso) return;
  if (cola.length > 0) {
    aviso.textContent = `⚠️ ${cola.length} alerta${cola.length === 1 ? '' : 's'} de pánico pendiente${cola.length === 1 ? '' : 's'} de envío (se reintentará al recuperar internet).`;
    aviso.classList.remove('hidden');
  } else {
    aviso.classList.add('hidden');
  }
}

// Al recuperar conexión reintentamos automáticamente la cola de pánicos.
window.addEventListener('online', reenviarPanicosPendientes);

// ---- Cola offline de novedades: espeja el patrón de pánicos (Punto 2) ----
// Misma decisión de diseño: POST con push-key + dedupe local por idEvento.
// Se prioriza "no perder la novedad" por sobre "no duplicar" (mismo tradeoff
// aceptado en pánicos). No usamos PUT-por-idEvento porque la regla de
// /novedades exige !data.exists() en la escritura: un reintento tras un
// éxito ambiguo daría 403 y quedaría encolado para siempre.
const CLAVE_NOVEDADES_PENDIENTES = 'novedades_pendientes';
let reenviandoNovedades = false;

// Guarda una novedad en la cola local (idempotente por idEvento). El foto
// en base64 puede ser grande (~MB): si localStorage se llena, el try/catch
// evita interrumpir la operatoria (no se rompe el flujo del usuario).
function encolarNovedadPendiente(payload) {
  try {
    let cola = JSON.parse(localStorage.getItem(CLAVE_NOVEDADES_PENDIENTES) || '[]');
    if (!cola.some(n => n && n.idEvento === payload.idEvento)) {
      cola.push(payload);
      localStorage.setItem(CLAVE_NOVEDADES_PENDIENTES, JSON.stringify(cola));
    }
    actualizarAvisoNovedadesPendientes();
  } catch (e) { /* si falla localStorage no interrumpimos la operatoria */ }
}

// Reenvía en orden todas las novedades encoladas. Solo elimina de la cola
// las que confirmó el servidor (res.ok + data.name); las que fallan quedan
// para el próximo intento. Requiere sesión activa (urlAuthFresca).
function reenviarNovedadesPendientes() {
  if (reenviandoNovedades || !navigator.onLine) return;
  let cola;
  try { cola = JSON.parse(localStorage.getItem(CLAVE_NOVEDADES_PENDIENTES) || '[]'); }
  catch (e) { cola = []; }
  if (!cola.length) return;

  reenviandoNovedades = true;
  const pendientes = [...cola];

  (async () => {
    const sobrevivientes = [];
    for (const payload of pendientes) {
      try {
        const urlN = await urlAuthFresca(`${URL_FIREBASE}/novedades.json`);
        let res = await fetch(urlN, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        let data = null;
        try { data = await res.json(); } catch (_) {}
        if (!res.ok || !data || data.error || !data.name) throw new Error('rechazada');
        if (payload.idEvento) eventosEnviados.add(payload.idEvento);
      } catch (e) {
        sobrevivientes.push(payload); // sigue pendiente para reintentar luego
      }
    }
    try { localStorage.setItem(CLAVE_NOVEDADES_PENDIENTES, JSON.stringify(sobrevivientes)); }
    catch (e) { /* noop */ }
    reenviandoNovedades = false;
    actualizarAvisoNovedadesPendientes();
    const enviadas = pendientes.length - sobrevivientes.length;
    if (enviadas > 0) {
      alert(`📝 Se reenvi${enviadas === 1 ? 'ó' : 'eron'} ${enviadas} novedad${enviadas === 1 ? '' : 'es'} pendiente${enviadas === 1 ? '' : 's'} a la central.`);
    }
  })();
}

// Muestra/actualiza el aviso visible de novedades aún sin confirmar.
function actualizarAvisoNovedadesPendientes() {
  let cola;
  try { cola = JSON.parse(localStorage.getItem(CLAVE_NOVEDADES_PENDIENTES) || '[]'); }
  catch (e) { cola = []; }
  const aviso = document.getElementById('avisoNovedadesPendientes');
  if (!aviso) return;
  if (cola.length > 0) {
    aviso.textContent = `⚠️ ${cola.length} novedad${cola.length === 1 ? '' : 'es'} pendiente${cola.length === 1 ? '' : 's'} de envío (se reintentará al recuperar internet).`;
    aviso.classList.remove('hidden');
  } else {
    aviso.classList.add('hidden');
  }
}

// Al recuperar conexión reintentamos automáticamente la cola de novedades.
window.addEventListener('online', reenviarNovedadesPendientes);

// 📝 ENVÍO DE NOVEDAD A FIREBASE
function enviarNovedadPortal() {
  const legajo = sessionStorage.getItem('vigilador_legajo');
  const nombreVigilador = sessionStorage.getItem('vigilador_nombre') || `Legajo ${legajo}`;
  const tipoIncidencia = document.getElementById('tipoIncidencia').value;
  const descripcion = sanitizarTextoLibre(document.getElementById('descNovedad').value);
  const inputArchivo = document.getElementById('fotoNovedadInput');

  if (!legajo) {
    alert("Debe iniciar sesión para enviar una novedad.");
    return;
  }

  let enServicio = false;
  let objetivoActual = "Objetivo Asignado";

  if (datosVigiladorGlobal.length > 0) {
    let ordenadas = [...datosVigiladorGlobal].sort((a, b) => parseFechaSegura(a.fecha) - parseFechaSegura(b.fecha));
    let ultimaMar = ordenadas[ordenadas.length - 1];
    
    if (ultimaMar && ultimaMar.tipo === 'ENTRADA') {
      enServicio = true;
      if (ultimaMar.objetivo) objetivoActual = ultimaMar.objetivo;
    }
  }

  if (!enServicio) {
    alert("❌ No se puede enviar el informe: Actualmente se encuentra fuera de servicio (debe tener una Entrada activa / En Turno).");
    return;
  }

  if (!descripcion) {
    alert("Por favor, escriba la descripción de la novedad o incidencia.");
    return;
  }

  if (!navigator.geolocation) {
    alert("Tu dispositivo no soporta geolocalización.");
    return;
  }

  navigator.geolocation.getCurrentPosition(
    function(position) {
      const lat = position.coords.latitude;
      const lon = position.coords.longitude;

      if (inputArchivo.files && inputArchivo.files[0]) {
        const lector = new FileReader();
        lector.onload = function(e) {
          enviarDatosFirebase(legajo, nombreVigilador, objetivoActual, tipoIncidencia, descripcion, lat, lon, e.target.result);
        };
        lector.readAsDataURL(inputArchivo.files[0]);
      } else {
        enviarDatosFirebase(legajo, nombreVigilador, objetivoActual, tipoIncidencia, descripcion, lat, lon, "");
      }
    },
    function(error) {
      alert("Error: Es necesario activar el GPS para enviar novedades.");
    },
    { enableHighAccuracy: true }
  );
}

async function enviarDatosFirebase(legajo, nombre, objetivo, tipoIncidencia, descripcion, lat, lon, fotoBase64) {
  if (novedadEnEnvio) return; // ya hay una novedad en curso: no duplicar
  const idEvento = generarIdEvento();
  if (eventosEnviados.has(idEvento)) return;
  const fechaNovedad = new Date().toISOString();
  const payload = {
    // Esquema unificado con Admin (nombres estandar) + compatibilidad con
    // los nombres antiguos (fechaHora / foto) que ya existen en Firebase.
    fechaHora: fechaNovedad,
    fechaHoraDispositivo: fechaNovedad,
    timestamp: fechaNovedad,
    // Sello de servidor Firebase (.sv=timestamp): hora oficial NO manipulable,
    // independiente del reloj del telefono. El admin la lee con prioridad.
    timestampServidor: { ".sv": "timestamp" },
    legajo: legajo,
    nombre: nombre,
    objetivo: objetivo,
    tipoIncidencia: sanitizarTextoLibre(tipoIncidencia, 120),
    descripcion: sanitizarTextoLibre(descripcion),
    latitud: lat,
    longitud: lon,
    foto: fotoBase64,
    fotoBase64: fotoBase64,
    // Clave de idempotencia + token de sesión para descartar duplicados.
    idEvento: idEvento,
    tokenSesion: sessionStorage.getItem('vigilador_token') || '',
    emitidoEnMs: Date.now()
  };

  eventosEnviados.add(idEvento);
  novedadEnEnvio = true;

  // SIN CONEXION (Punto 2): no se pierde la novedad. Se guarda en la cola
  // local y se reintenta automaticamente al recuperar internet. La
  // idempotencia por idEvento evita duplicar la MISMA novedad en la cola.
  if (!navigator.onLine) {
    encolarNovedadPendiente(payload);
    novedadEnEnvio = false;
    alert("📶 Sin conexión: la novedad quedó guardada y se enviará automáticamente al recuperar internet.");
    document.getElementById('descNovedad').value = "";
    document.getElementById('fotoNovedadInput').value = "";
    return;
  }

  // Token fresco antes de enviar la novedad (evita rechazo por token vencido).
  const urlNovedad = await urlAuthFresca(`${URL_FIREBASE}/novedades.json`);
  fetch(urlNovedad, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  })
  .then(async (res) => {
    // VALIDACION DE res.ok (Punto 3): Firebase puede devolver un cuerpo JSON
    // incluso ante un ERROR HTTP (401 token vencido, 403 reglas, 500). Sin
    // este control, un rechazo del servidor mostraba "enviada correctamente"
    // aunque la novedad NO se hubiera guardado. Ahora un POST exitoso debe:
    //   (a) tener res.ok (2xx), y (b) devolver la clave creada (data.name).
    // Cualquier otro caso se trata como FALLO y cae en el catch (que ademas
    // libera el idEvento para permitir reintento manual).
    let data = null;
    try { data = await res.json(); } catch (_) {}
    if (!res.ok || !data || data.error || !data.name) {
      const msg = (data && data.error) ? data.error : ('HTTP ' + res.status);
      throw new Error('el servidor rechazo la novedad (' + msg + ')');
    }
    return data;
  })
  .then(() => {
    novedadEnEnvio = false;
    alert("✅ Novedad enviada correctamente a la central.");
    document.getElementById('descNovedad').value = "";
    document.getElementById('fotoNovedadInput').value = "";
  })
  .catch(error => {
    // FALLO DE RED/servidor: en vez de perder la novedad, la ENCOLAMOS para
    // reintento automatico al volver la conexion (Punto 2). El idEvento se
    // conserva en la cola; NO se libera de eventosEnviados para no duplicar
    // en esta misma sesion.
    novedadEnEnvio = false;
    encolarNovedadPendiente(payload);
    alert("⚠️ No se pudo contactar a la central. La novedad quedó guardada y se reintentará automáticamente al recuperar la conexión.");
    document.getElementById('descNovedad').value = "";
    document.getElementById('fotoNovedadInput').value = "";
  });
}

function cerrarSesionVigilador() {
  clearTimeout(temporizadorInactividad);
  if (typeof window._detenerRenovacionToken === 'function') window._detenerRenovacionToken();
  sessionStorage.removeItem('vigilador_legajo');
  sessionStorage.removeItem('vigilador_nombre');
  sessionStorage.removeItem('vigilador_token');
  datosVigiladorGlobal = [];

  // Cerrar la sesion de Firebase Auth y descartar el token: sin token no se
  // puede volver a leer nada hasta iniciar sesion otra vez.
  idTokenVig = null;
  legajoSesionVig = null;
  if (typeof window.logoutVigilador === 'function') {
    try { window.logoutVigilador(); } catch (_) {}
  }

  document.getElementById('formLoginVigilador').classList.remove('hidden');
  document.getElementById('infoSesionActiva').classList.add('hidden');
  document.getElementById('btnCerrarSesion').classList.add('hidden');
  document.getElementById('seccionPanico').classList.add('hidden');
  document.getElementById('seccionFiltros').classList.add('hidden');
  document.getElementById('resumenHoras').classList.add('hidden');
  document.getElementById('seccionNovedades').classList.add('hidden'); 
  document.getElementById('contenedorTabla').classList.add('hidden');

  const prev = document.getElementById('previewLegajoVigilador');
  if (prev) { prev.classList.add('hidden'); prev.innerHTML = ''; }

  document.getElementById('legajoInput').value = '';
  document.getElementById('pinInput').value = '';
  document.getElementById('filtroMes').innerHTML = `<option value="todos">Todos los meses</option>`;
  document.getElementById('filtroDia').value = '';
}

// --- Cableado de eventos ---------------------------------------------------
// Reemplaza los antiguos onclick/onsubmit/onchange que estaban escritos
// dentro del HTML. Con el CSP endurecido (sin 'unsafe-inline' en script-src)
// esos handlers embebidos ya no se ejecutan, asi que aca se enganchan con
// addEventListener a los mismos ids/funciones de siempre. No cambia ninguna
// logica: solo la forma de conectar el boton/formulario con su funcion.
document.addEventListener("DOMContentLoaded", function(){
  var el;
  el=document.getElementById("formLoginVigilador"); if(el) el.addEventListener("submit", function(ev){ ev.preventDefault(); buscarMisHoras(); });
  el=document.getElementById("btnCerrarSesion");     if(el) el.addEventListener("click",  function(){ cerrarSesionVigilador(); });
  el=document.getElementById("filtroMes");           if(el) el.addEventListener("change", function(){ aplicarFiltros(); });
  el=document.getElementById("filtroDia");           if(el) el.addEventListener("change", function(){ aplicarFiltros(); });
  el=document.getElementById("btnLimpiarFiltros");   if(el) el.addEventListener("click",  function(){ limpiarFiltros(); });
  el=document.getElementById("btnEnviarNovedad");    if(el) el.addEventListener("click",  function(){ enviarNovedadPortal(); });
});
