// rondas.module.js — Sesion Firebase del vigilador para la pantalla de Rondas.
// Replica EXACTAMENTE el patron de index.module.js (login por Worker + custom
// token, renovacion automatica, hora oficial del servidor), en una instancia
// DEDICADA para no interferir con ninguna otra sesion de la app. Aditivo: no
// toca ningun otro archivo ni el Worker (que sigue SA-ONLY).

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAuth, signInWithCustomToken, signOut, setPersistence, browserSessionPersistence, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";
import { getDatabase, ref, get } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-database.js";

const firebaseConfig = {
  apiKey: "AIzaSyAsJoHn9mH6-klN_4yN1lBrnw0bHTzEhTU",
  authDomain: "vga-security-24.firebaseapp.com",
  databaseURL: "https://vga-security-24-default-rtdb.firebaseio.com",
  projectId: "vga-security-24",
  storageBucket: "vga-security-24.firebasestorage.app",
  messagingSenderId: "972832448326",
  appId: "1:972832448326:web:60415215815b95142c4f47"
};

// Instancia dedicada para NO interferir con otras sesiones (index/panel/admin).
const rondasApp  = initializeApp(firebaseConfig, "VigRondasApp");
const rondasAuth = getAuth(rondasApp);
const rondasDb   = getDatabase(rondasApp);
// La sesion vive mientras la pestana este abierta (dispositivo del vigilador).
try { setPersistence(rondasAuth, browserSessionPersistence); } catch (_) {}

// Worker que INTERMEDIA el login por PIN (bloqueo anti fuerza bruta). Igual que
// index/panel: el navegador NO va directo a Firebase; el Worker valida el PIN y
// devuelve un custom token que canjeamos con signInWithCustomToken.
const URL_WORKER_LOGIN = "https://vga-security-24.micasa27822024.workers.dev";

// Datos de la sesion vigente (legajo canonico + uid). Lo consume rondas.app.js.
window.sesionRondas = { legajo: null, uid: null, nombre: null };

// ---- HORA OFICIAL DEL SERVIDOR (sello de la ronda, igual que la fichada) ----
let offsetRelojServidorMs = null;
function decodificarPayloadJwt(token) {
  try {
    const parte = String(token).split('.')[1];
    if (!parte) return null;
    const base = parte.replace(/-/g, '+').replace(/_/g, '/');
    const relleno = base + '==='.slice((base.length + 3) % 4);
    return JSON.parse(atob(relleno));
  } catch (_) { return null; }
}
function sincronizarRelojDesdeToken(token) {
  const p = decodificarPayloadJwt(token);
  if (p && Number.isFinite(p.iat)) {
    offsetRelojServidorMs = (p.iat * 1000) - Date.now();
  }
}
function ahoraServidorMs() {
  return (typeof offsetRelojServidorMs === 'number') ? (Date.now() + offsetRelojServidorMs) : Date.now();
}
window.ahoraServidorRondasMs = ahoraServidorMs;

// ---- Renovacion automatica del token (igual que index/panel/admin) ----
const TOKEN_MAX_ANTIGUEDAD_MS = 50 * 60 * 1000;
let _tokenTimestamp = 0;
let _tokenRefreshing = null;
let idTokenGlobal = null;

async function _forzarRefreshToken() {
  if (_tokenRefreshing) return _tokenRefreshing;
  _tokenRefreshing = (async () => {
    try {
      if (rondasAuth.currentUser) {
        const t = await rondasAuth.currentUser.getIdToken(true);
        sincronizarRelojDesdeToken(t);
        _tokenTimestamp = Date.now();
        idTokenGlobal = t;
        return t;
      }
    } catch (e) {
      console.warn('[Token Rondas] Error al renovar:', e && (e.code || e.message));
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
    if (rondasAuth.currentUser) {
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

// Lee el legajo CANONICO del uid autenticado (root/usuarios/<uid>/legajo). Es el
// que las Reglas exigen al escribir rondasRegistros, asi que lo usamos SIEMPRE
// en vez del texto tecleado (que podria tener ceros/espacios distintos).
async function leerLegajoCanonico(uid) {
  try {
    const snap = await get(ref(rondasDb, `usuarios/${uid}`));
    if (snap && snap.exists()) {
      const v = snap.val() || {};
      return { legajo: (v.legajo != null) ? String(v.legajo) : null, rol: v.rol || null };
    }
  } catch (_) {}
  return { legajo: null, rol: null };
}

/**
 * Login del vigilador (legajo + PIN) via Worker. Devuelve el legajo canonico.
 * @returns {Promise<{ok:boolean, uid?:string, legajo?:string, razon?:string,
 *                     segundosRestantes?:number, intentosRestantes?:number}>}
 */
async function loginVigiladorRondas(legajo, pin) {
  const legajoLimpio = String(legajo || '').trim();
  const pinLimpio    = String(pin || '').trim();
  if (!legajoLimpio || !pinLimpio) return { ok: false, razon: 'faltan_datos' };
  let data, httpStatus;
  try {
    const resp = await fetch(URL_WORKER_LOGIN, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accion: 'loginPin', legajo: legajoLimpio, pin: pinLimpio })
    });
    httpStatus = resp.status;
    data = await resp.json().catch(() => ({}));
  } catch (e) {
    return { ok: false, razon: 'red' };
  }
  if (!resp_ok(httpStatus, data)) {
    if (httpStatus === 429 || (data && data.bloqueado)) {
      return { ok: false, razon: 'bloqueado', segundosRestantes: (data && data.segundosRestantes) || 0 };
    }
    return { ok: false, razon: 'credenciales', intentosRestantes: (data && data.intentosRestantes) };
  }
  let cred;
  try {
    cred = await signInWithCustomToken(rondasAuth, data.customToken);
  } catch (e) {
    return { ok: false, razon: 'sesion' };
  }
  const uid = cred.user.uid;
  const idToken = await cred.user.getIdToken();
  sincronizarRelojDesdeToken(idToken);
  _tokenTimestamp = Date.now();
  idTokenGlobal = idToken;
  _iniciarRenovacionToken();
  const info = await leerLegajoCanonico(uid);
  const legajoFinal = info.legajo || legajoLimpio;
  window.sesionRondas = { legajo: legajoFinal, uid: uid, nombre: null };
  return { ok: true, uid: uid, legajo: legajoFinal };
}
function resp_ok(status, data) { return status && status < 400 && data && data.ok; }
window.loginVigiladorRondas = loginVigiladorRondas;

async function logoutVigiladorRondas() {
  _detenerRenovacionToken();
  idTokenGlobal = null;
  window.sesionRondas = { legajo: null, uid: null, nombre: null };
  try { await signOut(rondasAuth); } catch (_) {}
}
window.logoutVigiladorRondas = logoutVigiladorRondas;

// Devuelve un idToken valido; si tiene mas de 50 min, lo renueva antes.
async function obtenerTokenRondas(forzar = false) {
  try {
    if (!rondasAuth.currentUser) return null;
    if (forzar || Date.now() - _tokenTimestamp > TOKEN_MAX_ANTIGUEDAD_MS) {
      const fresco = await _forzarRefreshToken();
      if (fresco) return fresco;
    }
    const cacheado = await rondasAuth.currentUser.getIdToken();
    if (cacheado) idTokenGlobal = cacheado;
    return cacheado;
  } catch (_) { return null; }
}
window.obtenerTokenRondas = obtenerTokenRondas;

// Agrega ?auth=<idToken> a una URL REST (reglas .read/.write endurecidas).
window.urlConAuthRondas = async (url) => {
  let token = null;
  try { token = await obtenerTokenRondas(); } catch (_) {}
  if (!token) return url;
  return url + (url.includes('?') ? '&' : '?') + 'auth=' + encodeURIComponent(token);
};

// fetch con reintento automatico en 401: renueva el token y reintenta UNA vez.
window.fetchConAuthRondas = async (url, options = {}) => {
  const u1 = await window.urlConAuthRondas(url);
  const res1 = await fetch(u1, options);
  if (res1.status === 401) {
    const fresco = await _forzarRefreshToken();
    if (fresco) {
      const u2 = url + (url.includes('?') ? '&' : '?') + 'auth=' + encodeURIComponent(fresco);
      return fetch(u2, options);
    }
  }
  return res1;
};

// Restauracion de sesion: si al recargar Firebase restaura la sesion, repoblamos
// window.sesionRondas y avisamos a la app para mostrar el escaner sin re-login.
onAuthStateChanged(rondasAuth, async (user) => {
  if (!user) { window.sesionRondas = { legajo: null, uid: null, nombre: null }; return; }
  try {
    const t = await user.getIdToken();
    sincronizarRelojDesdeToken(t);
    _tokenTimestamp = Date.now();
    idTokenGlobal = t;
    _iniciarRenovacionToken();
  } catch (_) {}
  const info = await leerLegajoCanonico(user.uid);
  window.sesionRondas = { legajo: info.legajo, uid: user.uid, nombre: null };
  if (typeof window.onSesionRondasLista === 'function') {
    try { window.onSesionRondasLista(window.sesionRondas); } catch (_) {}
  }
});
