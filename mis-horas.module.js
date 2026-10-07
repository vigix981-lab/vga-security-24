import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, signOut, setPersistence, browserSessionPersistence } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyAsJoHn9mH6-klN_4yN1lBrnw0bHTzEhTU",
  authDomain: "vga-security-24.firebaseapp.com",
  databaseURL: "https://vga-security-24-default-rtdb.firebaseio.com",
  projectId: "vga-security-24",
  storageBucket: "vga-security-24.firebasestorage.app",
  messagingSenderId: "972832448326",
  appId: "1:972832448326:web:60415215815b95142c4f47"
};

const vigApp  = initializeApp(firebaseConfig, "VigAuthApp");
const vigAuth = getAuth(vigApp);

/**
 * Inicia sesion REAL del vigilador (legajo + PIN) manteniendo la sesion en
 * Firebase Auth y devolviendo su idToken para autorizar las lecturas
 * (?auth=). Mantiene la sesion viva (no la cierra):
 * la mantiene viva durante la consulta de horas.
 * Persistencia de sesion (no sobrevive al cierre de pestana).
 * @returns {Promise<{ok:boolean, idToken?:string, uid?:string, razon?:string}>}
 */
async function loginVigilador(legajo, pin) {
  const legajoLimpio = String(legajo || '').trim();
  const pinLimpio    = String(pin || '').trim();
  if (!legajoLimpio || !pinLimpio) return { ok: false, razon: 'faltan_datos' };

  const email    = `${legajoLimpio}@vga.security24`;
  const password = pinLimpio.padStart(6, '0');
  try {
    try { await setPersistence(vigAuth, browserSessionPersistence); } catch (_) {}
    const cred = await signInWithEmailAndPassword(vigAuth, email, password);
    const idToken = await cred.user.getIdToken();
    _tokenTimestamp = Date.now();
    _iniciarRenovacionToken();
    return { ok: true, idToken, uid: cred.user.uid };
  } catch (e) {
    return { ok: false, razon: (e && e.code) || 'error' };
  }
}
window.loginVigilador = loginVigilador;

/** Cierra la sesion de Firebase Auth del vigilador. */
async function logoutVigilador() {
  _detenerRenovacionToken();
  try { await signOut(vigAuth); } catch (_) {}
}
window.logoutVigilador = logoutVigilador;

/**
 * Devuelve un idToken VIGENTE del vigilador logueado. El SDK refresca el
 * token automaticamente si esta vencido o proximo a vencer; con forzar=true
 * se pide uno nuevo si o si. Critico para el boton de panico en turnos
 * largos (el token cacheado al loguear caduca ~1h).
 * @returns {Promise<string|null>}
 */
// ─────────────────────────────────────────────────────────────────────────────
//  RENOVACIÓN AUTOMÁTICA DEL TOKEN (igual que admin/panel/index)
//  Cada 50 min se renueva proactivamente; obtenerTokenVigilador refresca
//  automáticamente si el token tiene >50 min de antigüedad.
// ─────────────────────────────────────────────────────────────────────────────
const TOKEN_MAX_ANTIGUEDAD_MS = 50 * 60 * 1000;
let _tokenTimestamp = 0;
let _tokenRefreshing = null;

async function _forzarRefreshToken() {
  if (_tokenRefreshing) return _tokenRefreshing;
  _tokenRefreshing = (async () => {
    try {
      if (vigAuth.currentUser) {
        const t = await vigAuth.currentUser.getIdToken(true);
        _tokenTimestamp = Date.now();
        return t;
      }
    } catch (e) {
      console.warn('[Token Mis-Horas] Error al renovar:', e && (e.code || e.message));
      _tokenTimestamp = 0;
    } finally {
      _tokenRefreshing = null;
    }
    return null;
  })();
  return _tokenRefreshing;
}

let _timerRenovacion = null;
function _iniciarRenovacionToken() {
  if (_timerRenovacion) return;
  _timerRenovacion = setInterval(() => {
    if (vigAuth.currentUser) {
      _forzarRefreshToken().catch(() => {});
    } else {
      clearInterval(_timerRenovacion);
      _timerRenovacion = null;
    }
  }, TOKEN_MAX_ANTIGUEDAD_MS);
}
function _detenerRenovacionToken() {
  if (_timerRenovacion) { clearInterval(_timerRenovacion); _timerRenovacion = null; }
}

async function obtenerTokenVigilador(forzar = false) {
  try {
    if (!vigAuth.currentUser) return null;
    if (forzar || Date.now() - _tokenTimestamp > TOKEN_MAX_ANTIGUEDAD_MS) {
      const fresco = await _forzarRefreshToken();
      if (fresco) return fresco;
    }
    const cacheado = await vigAuth.currentUser.getIdToken();
    return cacheado || null;
  } catch (_) { return null; }
}

window.obtenerTokenVigilador = obtenerTokenVigilador;
window._forzarRefreshTokenMisHoras = _forzarRefreshToken;
window._iniciarRenovacionToken = _iniciarRenovacionToken;
window._detenerRenovacionToken = _detenerRenovacionToken;
