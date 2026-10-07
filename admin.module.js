// ---- Módulos requeridos desde la CDN de Firebase (v10.8.0) ----
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAuth, createUserWithEmailAndPassword, signInWithCustomToken, signOut, onAuthStateChanged, setPersistence, browserSessionPersistence } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";
import { getDatabase, ref, set, get, remove } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-database.js";

// ---- Configuración de tu proyecto Firebase ----
const firebaseConfig = {
  apiKey: "AIzaSyAsJoHn9mH6-klN_4yN1lBrnw0bHTzEhTU",
  authDomain: "vga-security-24.firebaseapp.com",
  databaseURL: "https://vga-security-24-default-rtdb.firebaseio.com",
  projectId: "vga-security-24",
  storageBucket: "vga-security-24.firebasestorage.app",
  messagingSenderId: "972832448326",
  appId: "1:972832448326:web:60415215815b95142c4f47"
};

// ---- App PRINCIPAL (sesión del Administrador) ----
const mainApp = initializeApp(firebaseConfig);
const mainDb  = getDatabase(mainApp);
const mainAuth = getAuth(mainApp);

// La sesion del admin NO debe sobrevivir al cierre de la pestana/navegador.
// Con persistencia de SESION (no local), al salir y volver a entrar el panel
// arranca limpio en la pantalla de login, sin quedar 'pegado' a una sesion
// vieja (esto evita tener que borrar el historial para poder reingresar).
try { setPersistence(mainAuth, browserSessionPersistence).catch(function () {}); } catch (_) {}

/**
 * Login REAL de admin: valida credenciales en Firebase Auth
 * y lee el rol guardado en la base de datos: /usuarios/<uid>/rol.
 * Solo se permite entrar con rol 'admin' (los supervisores quedan excluidos).
 * @returns {Promise<{ok:boolean, uid?:string, rol?:string, mensaje?:string}>}
 */
// Utilidad: limita el tiempo de una promesa. Si supera el tiempo, resuelve
// con un valor de reserva (nunca deja el login colgado). Clave en celulares,
// donde ciertas operaciones de almacenamiento/persistencia pueden trabarse.
function conLimite(promesa, ms, valorReserva) {
  return Promise.race([
    Promise.resolve(promesa).catch(function () { return valorReserva; }),
    new Promise(function (res) { setTimeout(function () { res(valorReserva); }, ms); })
  ]);
}

// Endpoint del Worker que ahora INTERMEDIA el login (bloqueo anti fuerza bruta
// PERSISTENTE del lado del servidor). El login del admin ya NO va directo del
// navegador a Firebase: pasa por el Worker, que cuenta/limita los intentos en
// la base y, si la clave es correcta, emite un custom token.
const URL_WORKER_LOGIN_ADMIN = "https://vga-security-24.micasa27822024.workers.dev";

// Formatea segundos restantes como "X min YY s" (o "YY s" si es menos de 1 min).
function _fmtSegundos(seg) {
  seg = Math.max(0, Math.ceil(Number(seg) || 0));
  const m = Math.floor(seg / 60), s = seg % 60;
  if (m > 0) return m + ' min ' + (s < 10 ? '0' : '') + s + ' s';
  return s + ' s';
}

async function loginAdminReal(email, password) {
  if (!email || !password) {
    return { ok: false, mensaje: 'Ingresá el correo y la contraseña.' };
  }
  // Persistencia de SESION: se intenta, pero NO debe bloquear el login (en
  // algunos navegadores de celular puede trabarse; la limitamos en el tiempo).
  await conLimite(setPersistence(mainAuth, browserSessionPersistence), 1500, null);

  // 1) EL LOGIN PASA POR EL WORKER (unica puerta de entrada). El Worker lleva el
  //    conteo de intentos fallidos de forma PERSISTENTE (nodo /intentosLogin,
  //    solo accesible por la service account) y, superado el limite, BLOQUEA
  //    temporalmente SIN consultar a Firebase. El bloqueo ya NO vive en el
  //    navegador: sobrevive a recargas, a limpiar el storage y a cambiar de
  //    dispositivo. Si el PIN/clave es correcto, el Worker devuelve un CUSTOM
  //    TOKEN que canjeamos con signInWithCustomToken para abrir la sesion real.
  let data, httpStatus;
  try {
    const resp = await fetch(URL_WORKER_LOGIN_ADMIN, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accion: 'loginPin', email: email, password: password })
    });
    httpStatus = resp.status;
    data = await resp.json().catch(() => ({}));
  } catch (e) {
    return { ok: false, mensaje: 'No se pudo contactar el servicio de acceso. Revisá tu conexión y reintentá.' };
  }

  // 2) El Worker rechazo (bloqueo o credenciales invalidas).
  if (!data || !data.ok) {
    if (httpStatus === 429 || data.bloqueado) {
      const seg = Number(data.segundosRestantes) || 0;
      return { ok: false, bloqueado: true, segundosRestantes: seg,
               mensaje: 'Demasiados intentos fallidos. Por seguridad, el ingreso quedó bloqueado. Probá de nuevo en ' + _fmtSegundos(seg) + '.' };
    }
    let mensaje = 'Correo o contraseña incorrectos.';
    const quedan = (typeof data.intentosRestantes === 'number') ? data.intentosRestantes : null;
    if (quedan !== null && quedan > 0 && quedan <= 2) {
      mensaje += ' Te queda' + (quedan === 1 ? '' : 'n') + ' ' + quedan + ' intento' + (quedan === 1 ? '' : 's') + ' antes del bloqueo.';
    }
    return { ok: false, mensaje: mensaje, intentosRestantes: quedan };
  }

  // 3) Credenciales OK -> abrimos la sesion real del SDK con el custom token.
  let cred;
  try {
    cred = await signInWithCustomToken(mainAuth, data.customToken);
  } catch (e) {
    return { ok: false, mensaje: 'No se pudo abrir la sesión. Reintentá en unos segundos.' };
  }
  const uid = cred.user.uid;

  // 4) Leer el rol desde /usuarios/<uid> (con limite de tiempo).
  let rol = null, errorLectura = null;
  try {
    const snap = await conLimite(get(ref(mainDb, `usuarios/${uid}`)), 12000, '__TIMEOUT__');
    if (snap === '__TIMEOUT__') {
      errorLectura = 'tiempo de espera agotado al leer el rol';
    } else if (snap.exists()) {
      rol = (snap.val() || {}).rol || null;
    }
  } catch (e2) { errorLectura = (e2 && (e2.code || e2.message)) || 'desconocido'; }

  // 5) Separacion de roles: este panel es EXCLUSIVO de administradores.
  if (rol !== 'admin') {
    try { await signOut(mainAuth); } catch (_) {}
    // SEGURIDAD: el mensaje NUNCA debe exponer el UID, el rol real leido ni
    // rutas internas de la base. Solo un aviso generico (y, para supervisores,
    // una ayuda de "panel equivocado").
    let detalle;
    if (errorLectura) {
      detalle = 'No se pudieron verificar tus permisos en este momento. Reintentá en unos segundos.';
    } else if (rol === 'supervisor') {
      detalle = 'Tu cuenta es de supervisor; este panel es exclusivo de administradores.';
    } else {
      detalle = 'Esta cuenta no tiene permisos de administrador para ingresar a este panel.';
    }
    return { ok: false, mensaje: detalle };
  }

  // 6) Todo OK: marcar la hora del token e iniciar la renovacion automatica.
  _tokenTimestamp = Date.now();
  _iniciarRenovacionToken();
  return { ok: true, uid, rol };
}
window.loginAdminReal = loginAdminReal;

// --- Restauracion de sesion basada en Firebase Auth (no solo sessionStorage) ---
// El panel solo se muestra si Auth confirma un usuario REAL con rol admin.
// Asi un flag editable (sessionStorage.auth_admin) ya no alcanza para exponer la UI.
onAuthStateChanged(mainAuth, async (user) => {
  const contenido = document.getElementById('contenidoAdmin');
  const yaVisible = () => contenido && !contenido.classList.contains('hidden');
  if (!user) {
    // Sin sesion real: limpiar flags. El estado inicial del HTML ya muestra el login.
    sessionStorage.removeItem('auth_admin');
    sessionStorage.removeItem('rol_admin');
    sessionStorage.removeItem('uid_admin');
    sessionStorage.removeItem('email_admin');
    return;
  }
  // Hay usuario autenticado: validar rol admin contra /usuarios/<uid>/rol.
  let rol = null;
  try {
    const snap = await get(ref(mainDb, `usuarios/${user.uid}/rol`));
    rol = snap.exists() ? snap.val() : null;
  } catch (_) {}
  if (rol !== 'admin') {
    // Autenticado pero sin rol admin: no se expone el panel de administracion.
    sessionStorage.removeItem('auth_admin');
    return;
  }
  // Sesion admin confirmada: repoblar flags de sesion y mostrar la UI una sola vez.
  sessionStorage.setItem('auth_admin', 'true');
  sessionStorage.setItem('rol_admin', rol);
  sessionStorage.setItem('uid_admin', user.uid);
  if (user.email) sessionStorage.setItem('email_admin', user.email);
  // Iniciar la renovación automática del token (se refresca cada 50 min)
  _tokenTimestamp = Date.now();
  _iniciarRenovacionToken();
  if (!yaVisible() && typeof window.mostrarAdmin === 'function') window.mostrarAdmin();
});

// --- Token del admin/supervisor para autenticar escrituras REST (reglas .write endurecidas) ---
// Aditivo: no modifica ninguna lógica existente. Devuelve la URL con ?auth=<idToken> si hay sesión.
// ─────────────────────────────────────────────────────────────────────────────
//  RENOVACIÓN AUTOMÁTICA DEL TOKEN
//  Firebase Auth emite tokens de ~1h. El SDK los refresca solo si está
//  "activo", pero en una pestaña abierta sin tocar, el token se queda
//  vencido y la próxima lectura/escritura falla con 401.
//  Solución: refrescar proactivamente cada 50 min y también antes de
//  cada operación si el token tiene más de 50 min de antigüedad.
// ─────────────────────────────────────────────────────────────────────────────
const TOKEN_MAX_ANTIGUEDAD_MS = 50 * 60 * 1000; // 50 minutos
let _tokenTimestamp = 0;    // cuándo se emitió el último token (ms)
let _tokenRefreshing = null; // Promise en curso (evita refreshes simultáneos)

// Renueva el token del admin forzando la petición al servidor.
// Si ya hay un refresh en curso, espera ese en vez de lanzar otro.
async function _forzarRefreshToken() {
  if (_tokenRefreshing) return _tokenRefreshing;
  _tokenRefreshing = (async () => {
    try {
      const u = mainAuth.currentUser;
      if (!u) return null;
      const token = await u.getIdToken(true); // fuerza refresh contra Google
      _tokenTimestamp = Date.now();
      return token;
    } catch (e) {
      // Si falla el refresh, puede ser que la sesión se perdió
      console.warn('[Token Admin] Error al renovar:', e && (e.code || e.message));
      _tokenTimestamp = 0;
      return null;
    } finally {
      _tokenRefreshing = null;
    }
  })();
  return _tokenRefreshing;
}

// Arranca el timer que renueva el token cada 50 minutos, mientras haya sesión.
// Se apaga automáticamente si el usuario cierra sesión.
let _timerRenovacion = null;
function _iniciarRenovacionToken() {
  if (_timerRenovacion) return; // ya está corriendo
  _timerRenovacion = setInterval(() => {
    if (mainAuth.currentUser) {
      _forzarRefreshToken().catch(() => {});
    } else {
      // No hay sesión: detener el timer
      clearInterval(_timerRenovacion);
      _timerRenovacion = null;
    }
  }, TOKEN_MAX_ANTIGUEDAD_MS);
}
function _detenerRenovacionToken() {
  if (_timerRenovacion) { clearInterval(_timerRenovacion); _timerRenovacion = null; }
}

// Devuelve un idToken válido. Si el token tiene >50 min, lo renueva antes.
// Si no hay sesión, devuelve null.
window.obtenerTokenAdmin = async () => {
  try {
    const u = mainAuth.currentUser;
    if (!u) return null;
    // ¿El token actual tiene más de 50 minutos? Renovar primero.
    if (Date.now() - _tokenTimestamp > TOKEN_MAX_ANTIGUEDAD_MS) {
      const fresco = await _forzarRefreshToken();
      if (fresco) return fresco;
    }
    // Token dentro de la ventana de validez: usar cacheado.
    return await u.getIdToken();
  } catch (_) { return null; }
};
// Construye la URL con ?auth=<idToken>. Si el token puede estar
// vencido, obtenerTokenAdmin lo renueva automáticamente.
window.urlConAuthAdmin = async (url) => {
  let token = null;
  try { token = await window.obtenerTokenAdmin(); } catch (_) {}
  if (!token) return url;
  return url + (url.includes('?') ? '&' : '?') + 'auth=' + encodeURIComponent(token);
};

// --- LLAMADA UNIFICADA AL WORKER PARA ACCIONES ADMIN (server-side, autoritativo) ---
// Envia la accion al Worker, que valida el idToken + rol admin y escribe la
// AUDITORIA con la service account (las reglas de Firebase ya NO permiten
// escritura directa desde el panel para estas operaciones). Devuelve el JSON
// de respuesta o lanza Error con el mensaje del Worker.
// Llama al Worker con reintentos automáticos: si el token estaba
// vencido (401), lo renueva y reintenta UNA vez antes de fallar.
window.llamarWorkerAdmin = async (payload) => {
  const base = String(URL_WORKER_AUTH || '').trim();
  if (!base) throw new Error('El Worker de autenticacion no esta configurado (URL_WORKER_AUTH vacio).');
  const idToken = await window.obtenerTokenAdmin();
  if (!idToken) throw new Error('No hay sesion de administrador activa (falta idToken).');

  const hacerPeticion = async (token) => {
    const res = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, idToken: token })
    });
    let data = null;
    try { data = await res.json(); } catch (_) {}
    if (!res.ok || !data || data.error) {
      const msg = (data && data.error) ? data.error : ('HTTP ' + res.status);
      throw new Error(msg);
    }
    return data;
  };

  try {
    return await hacerPeticion(idToken);
  } catch (e1) {
    // Si fue error de auth (401/token vencido), renovar y reintentar UNA vez
    if (e1 && /401|Permission denied|token|auth/i.test(e1.message)) {
      const tokenFresco = await _forzarRefreshToken();
      if (tokenFresco) return await hacerPeticion(tokenFresco);
    }
    throw e1;
  }
};

async function logoutAdminReal() {
  _detenerRenovacionToken();
  try { await signOut(mainAuth); } catch (_) {}
}
window.logoutAdminReal = logoutAdminReal;

// ---- App SECUNDARIA (crea empleados SIN cerrar la sesión del admin) ----
const secondaryApp  = initializeApp(firebaseConfig, "SecondaryApp");
const secondaryAuth = getAuth(secondaryApp);

/**
 * Registra un empleado creando su credencial real de acceso en Firebase Auth
 * (usando la instancia secundaria) y guardando su ficha en Realtime Database.
 * @param {string} legajo  N° de legajo (ej: "0297")
 * @param {string} nombre  Nombre completo (ej: "Juan Pérez")
 * @param {string} pin     PIN numérico de 4+ dígitos (ej: "3456")
 * @param {string|null} fotoMaster  Foto máster en base64 (opcional)
 * @param {string} rol     Rol a asignar: 'empleado' (por defecto), 'supervisor' o 'admin'.
 */
async function registrarEmpleado(legajo, nombre, pin, fotoMaster = null, rol = 'empleado') {
  // a. Formateo de datos -> email y password sintéticos
  const legajoLimpio = String(legajo).trim();
  const nombreLimpio = String(nombre).trim();
  const pinLimpio    = String(pin).trim();

  // Rol: solo se aceptan los tres valores válidos. Cualquier otro -> 'empleado'.
  const rolesValidos = ['empleado', 'supervisor', 'admin'];
  const rolLimpio = rolesValidos.includes(String(rol).trim()) ? String(rol).trim() : 'empleado';

  const emailEmpleado    = `${legajoLimpio}@vga.security24`;
  const passwordEmpleado = pinLimpio.padStart(6, '0'); // "3456" -> "003456"

  try {
    // b. Crear la credencial en la instancia SECUNDARIA
    const credencial = await createUserWithEmailAndPassword(secondaryAuth, emailEmpleado, passwordEmpleado);
    const uid = credencial.user.uid;

    // c. [#4] La ESCRITURA de /personal + /credenciales + /usuarios la hace el
    //    Worker con la service account (las Reglas tienen esos nodos en
    //    .write:false para el cliente). Aqui solo preparamos los datos y
    //    delegamos: alta atomica + auditoria server-side.
    // El PIN no se guarda en texto plano: se deriva un hash con salt.
    const pinSaltNuevo = window.generarSaltPin();
    const pinHashNuevo = await window.hashPin(pinLimpio, pinSaltNuevo);
    const datosPersonal = {
      legajo: legajoLimpio,
      nombre: nombreLimpio,
      estado: "activo",
      authUid: uid,
      fechaAlta: new Date().toISOString(),
      // --- Campos adicionales para compatibilidad con el panel actual ---
      // (necesarios para que la tabla y "Configurar" sigan funcionando)
      // El hash/salt del PIN NO va en /personal (lo leen los supervisores):
      // se marca solo que tiene PIN y las credenciales van en /credenciales/<uid>.
      tienePin: true,
      fotoMaster: fotoMaster || null,
      horarioHabitual: { inicio: '', fin: '' },
      objetivosAsignados: []
    };

    // d. Cerrar de inmediato la sesión secundaria (el Worker usa el token del
    //    admin de la sesión principal, no esta).
    await signOut(secondaryAuth);

    // e. Alta atomica en el servidor. Si falla, el Worker revierte TODO (incluida
    //    la cuenta de Auth recien creada), asi que el legajo queda libre para
    //    reintentar sin colisiones.
    await window.llamarWorkerAdmin({
      accion: 'crearEmpleadoDatos',
      uid,
      personal: datosPersonal,
      credencial: { pinHash: pinHashNuevo, pinSalt: pinSaltNuevo },
      usuario: { legajo: legajoLimpio, rol: rolLimpio }
    });

    const etiquetaRol = rolLimpio === 'admin' ? 'Administrador'
                      : rolLimpio === 'supervisor' ? 'Supervisor'
                      : 'Empleado (vigilador)';
    // Comprobante "mostrar una sola vez": el PIN solo se conoce en claro ahora.
    // Se abre el modal para descargar/imprimir/copiar y entregarselo al empleado.
    if (typeof window.mostrarComprobantePin === 'function') {
      window.mostrarComprobantePin({ legajo: legajoLimpio, nombre: nombreLimpio, pin: pinLimpio, rol: rolLimpio, modo: 'alta' });
    } else {
      alert(`✅ Usuario registrado con éxito.\nLegajo: ${legajoLimpio}\nNombre: ${nombreLimpio}\nRol: ${etiquetaRol}\nPIN de acceso: ${pinLimpio}`);
    }
    return { ok: true, uid, rol: rolLimpio };
  } catch (error) {
    // e. Manejo claro de errores
    let mensaje;
    switch (error && error.code) {
      case 'auth/email-already-in-use':
        mensaje = `⚠️ El legajo "${legajoLimpio}" ya está registrado. Usá otro número de legajo.`;
        break;
      case 'auth/invalid-email':
        mensaje = '⚠️ El legajo genera un correo inválido. Revisá el dato ingresado.';
        break;
      case 'auth/weak-password':
        mensaje = '⚠️ El PIN es demasiado corto: la contraseña debe tener al menos 6 caracteres.';
        break;
      default:
        mensaje = '❌ Ocurrió un problema al registrar el empleado: ' + ((error && error.message) || (error && error.code) || error);
    }
    alert(mensaje);
    // Por seguridad, intentar cerrar la sesión secundaria si quedó abierta
    try { await signOut(secondaryAuth); } catch (_) {}
    return { ok: false, error };
  }
}

// Exponer la función por si querés invocarla desde otras partes del panel
window.registrarEmpleado = registrarEmpleado;

// ---- Listener del formulario de alta con acceso ----
const formAltaEmpleado = document.getElementById('formAltaEmpleado');
if (formAltaEmpleado) {
  formAltaEmpleado.addEventListener('submit', async (event) => {
    event.preventDefault();

    const btn    = document.getElementById('btnAltaEmpleado');
    const legajo = document.getElementById('altaLegajo').value;
    const nombre = document.getElementById('altaNombre').value;
    const pin    = document.getElementById('altaPin').value;
    const inputFoto = document.getElementById('altaFotoMaster');
    const selRol = document.getElementById('altaRol');
    const rol    = selRol ? selRol.value : 'empleado';

    // Confirmación extra al crear un usuario con permisos elevados: un admin o
    // supervisor NO es un vigilador más (puede ver/gestionar datos de todos).
    if (rol === 'admin' || rol === 'supervisor') {
      const etq = rol === 'admin' ? 'ADMINISTRADOR (acceso total al panel)' : 'SUPERVISOR (control operativo)';
      if (!confirm('Vas a crear un usuario con rol ' + etq + '.\n\nLegajo: ' + String(legajo).trim() + '\n\n¿Confirmás que querés darle estos permisos?')) {
        return;
      }
    }

    if (btn) {
      btn.disabled = true;
      btn.dataset.original = btn.innerHTML;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Creando...';
    }

    // Convertir la Foto Máster (IA) a base64 si el admin cargó una
    let fotoMasterBase64 = null;
    if (inputFoto && inputFoto.files && inputFoto.files[0] && typeof window.convertirImagenBase64 === 'function') {
      try { fotoMasterBase64 = await window.convertirImagenBase64(inputFoto.files[0]); } catch (_) { fotoMasterBase64 = null; }
    }

    const resultado = await registrarEmpleado(legajo, nombre, pin, fotoMasterBase64, rol);

    if (resultado && resultado.ok) {
      formAltaEmpleado.reset();
      // Tras reset, el selector vuelve a su valor por defecto ('empleado').
      if (selRol) selRol.value = 'empleado';
      // Generar un nuevo PIN para la próxima alta
      if (typeof window.generarPinEmpleado === 'function') window.generarPinEmpleado();
      // Refrescar la tabla de personal si la función del panel existe
      if (typeof window.recargarDatosEfectivo === 'function') {
        window.recargarDatosEfectivo();
      }
    }

    if (btn) {
      btn.disabled = false;
      btn.innerHTML = btn.dataset.original || '<i class="fa-solid fa-user-shield"></i> Crear empleado';
    }
  });
}
