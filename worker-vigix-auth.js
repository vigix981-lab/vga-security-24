/**
 * Worker vga security 24 — Cambia la contraseña de Firebase Auth de un empleado.
 *
 * ¿Por qué existe? Desde el navegador NO se puede forzar la contraseña de
 * otro usuario sin la clave vieja. Esta pieza de backend usa la service
 * account (con permisos de Auth Admin) para hacerlo de forma segura.
 *
 * SEGURIDAD (no tocar):
 *  - Solo acepta pedidos desde ALLOWED_ORIGIN (tu GitHub Pages).
 *  - Verifica criptográficamente el idToken de quien pide (Firebase RS256).
 *  - Exige que ese usuario tenga rol 'admin' en /usuarios/<uid>.
 *  - La clave de la service account vive SOLO como secreto (env), nunca en el código.
 *
 * VARIABLES DE ENTORNO a configurar en Cloudflare:
 *  - SERVICE_ACCOUNT  (SECRETO)  -> el JSON COMPLETO de la cuenta de servicio.
 *  - ALLOWED_ORIGIN              -> https://micasa27822024-netizen.github.io
 *  - RTDB_URL                    -> https://mercosur-seguridad-default-rtdb.firebaseio.com
 *  - FIREBASE_WEB_API_KEY        -> la Web API Key del proyecto (NO es secreto;
 *                                  es la misma clave publica del firebaseConfig
 *                                  del front). La usa SOLO el endpoint loginPin
 *                                  para validar el PIN contra Firebase Auth.
 */

const JWK_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPES = [
  'https://www.googleapis.com/auth/identitytoolkit',
  'https://www.googleapis.com/auth/firebase.database',
  'https://www.googleapis.com/auth/userinfo.email',
].join(' ');

function cors(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
    // HSTS: fuerza HTTPS durante 1 año; incluye subdominios y precarga.
    // Solo tiene efecto si el Worker se sirve sobre HTTPS (lo cual
    // Cloudflare garantiza automaticamente).
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  };
}
function json(obj, status, origin) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors(origin) },
  });
}

// ===================================================================
//  [PLAN] TOPES POR PLAN CONTRATADO (candado de cupo)
//  Piezas ADITIVAS: no tocan ningun flujo de Auth/fichaje existente.
//  El plan vive en /config/plan (CERRADO a escritura de clientes por las
//  Reglas; solo lo escribe el Worker con la service account via ownerFijarPlan).
//  Estructura: { nombre, maxVigiladores, maxObjetivos, estado, actualizado }.
// ===================================================================

// Plan por defecto si /config/plan aun NO fue configurado = Esencial.
const PLAN_DEFAULT = { nombre: 'esencial', maxVigiladores: 10, maxObjetivos: 2, estado: 'activo' };

// [PLAN] BANDERAS DE FUNCION. Interruptores on/off que habilitan funciones por
// plan. Las funciones base (fichadas GPS+foto, objetivos, panel basico, reportes
// esenciales) van SIEMPRE encendidas y no necesitan bandera. Estas son las
// opcionales que distinguen a cada plan.
const FUNCIONES_CLAVES = ['rondas', 'alertasIncidencias', 'rolesSupervision', 'exportarReportes', 'multiplesSedes', 'modoOffline'];

// Combos recomendados por plan (acumulativos). 'custom' no tiene preset: usa lo
// que mande el dueño explicitamente.
const FUNCIONES_PRESET = {
  esencial:    { rondas: false, alertasIncidencias: false, rolesSupervision: false, exportarReportes: false, multiplesSedes: false, modoOffline: false },
  profesional: { rondas: true,  alertasIncidencias: true,  rolesSupervision: true,  exportarReportes: true,  multiplesSedes: false, modoOffline: false },
  empresa:     { rondas: true,  alertasIncidencias: true,  rolesSupervision: true,  exportarReportes: true,  multiplesSedes: true,  modoOffline: true  }
};

// Normaliza el objeto de funciones: toma SOLO las claves conocidas, cada una
// como booleano. Si no viene nada, cae al preset del plan (o Esencial = todo off).
function normalizarFunciones(fuente, nombrePlan) {
  const base = FUNCIONES_PRESET[String(nombrePlan || '').toLowerCase()] || FUNCIONES_PRESET.esencial;
  const out = {};
  for (const k of FUNCIONES_CLAVES) {
    if (fuente && typeof fuente === 'object' && typeof fuente[k] !== 'undefined') out[k] = !!fuente[k];
    else out[k] = !!base[k];
  }
  return out;
}

// Comparacion de strings en tiempo ~constante (anti timing-attack sobre OWNER_KEY).
function comparaConstante(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Cuenta hijos de un nodo con una lectura SHALLOW (barata: solo las claves).
async function contarHijosSA(RTDB, accessToken, nodo) {
  const authGet = { headers: { Authorization: 'Bearer ' + accessToken } };
  const r = await fetch(`${RTDB}/${nodo}.json?shallow=true`, authGet).then(x => x.json()).catch(() => null);
  return (r && typeof r === 'object') ? Object.keys(r).length : 0;
}

// Lee /config/plan con la service account y lo normaliza (defaults = Esencial).
async function leerPlanSA(RTDB, accessToken) {
  const authGet = { headers: { Authorization: 'Bearer ' + accessToken } };
  const p = await fetch(`${RTDB}/config/plan.json`, authGet).then(x => x.json()).catch(() => null);
  const maxVig = Number(p && p.maxVigiladores);
  const maxObj = Number(p && p.maxObjetivos);
  return {
    nombre: (p && p.nombre) ? String(p.nombre) : PLAN_DEFAULT.nombre,
    maxVigiladores: (Number.isFinite(maxVig) && maxVig >= 0) ? maxVig : PLAN_DEFAULT.maxVigiladores,
    maxObjetivos: (Number.isFinite(maxObj) && maxObj >= 0) ? maxObj : PLAN_DEFAULT.maxObjetivos,
    estado: (p && String(p.estado).toLowerCase() === 'suspendido') ? 'suspendido' : 'activo',
    funciones: normalizarFunciones(p && p.funciones, (p && p.nombre) ? p.nombre : PLAN_DEFAULT.nombre),
    existe: !!p
  };
}

// Escribe /config/plan con la service account (PUT). Devuelve el fetch Response.
async function putPlanSA(RTDB, accessToken, plan) {
  return fetch(`${RTDB}/config/plan.json`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
    body: JSON.stringify(plan)
  });
}

// ===================================================================
//  [PLAN] PANEL EXCLUSIVO DEL DUENO (owner): leer / fijar / suspender plan.
//  NO usa idToken de Firebase ni rol admin: se autentica con OWNER_KEY (secreto
//  del Worker). Asi el dueno del servicio controla los topes de cada clon aun
//  sin ser admin de esa empresa; y la empresa cliente NO puede tocar su propio
//  tope (su admin no conoce OWNER_KEY y las Reglas bloquean la escritura).
// ===================================================================
async function manejarAccionOwner(accion, body, env, sa, projectId, origin) {
  const ownerKey = env.OWNER_KEY || '';
  if (!ownerKey) return json({ error: 'El servidor no tiene OWNER_KEY configurado. Crea el secreto en Cloudflare.' }, 500, origin);
  const provista = String((body && body.ownerKey) || '');
  if (!provista || !comparaConstante(provista, ownerKey)) {
    return json({ error: 'Clave de dueno incorrecta.' }, 403, origin);
  }

  let accessToken;
  try { accessToken = await obtenerAccessToken(sa); }
  catch (e) { return json({ error: 'no se pudo autenticar el servidor: ' + e.message }, 500, origin); }
  const RTDB = env.RTDB_URL;

  // LEER el plan actual + uso real (para el tablero del dueno).
  if (accion === 'ownerLeerPlan') {
    const plan = await leerPlanSA(RTDB, accessToken);
    const [vig, obj] = await Promise.all([
      contarHijosSA(RTDB, accessToken, 'personal'),
      contarHijosSA(RTDB, accessToken, 'objetivos')
    ]);
    return json({ ok: true, plan, uso: { vigiladores: vig, objetivos: obj } }, 200, origin);
  }

  // FIJAR / SUSPENDER el plan.
  if (accion === 'ownerFijarPlan') {
    const nombre = (String(body.nombre || '').trim().toLowerCase()) || 'custom';
    const estado = (String(body.estado || '').trim().toLowerCase() === 'suspendido') ? 'suspendido' : 'activo';
    const maxVig = Math.floor(Number(body.maxVigiladores));
    const maxObj = Math.floor(Number(body.maxObjetivos));
    if (!Number.isFinite(maxVig) || maxVig < 0 || !Number.isFinite(maxObj) || maxObj < 0) {
      return json({ error: 'Topes invalidos: deben ser numeros enteros >= 0.' }, 422, origin);
    }
    const plan = { nombre, maxVigiladores: maxVig, maxObjetivos: maxObj, estado, funciones: normalizarFunciones(body.funciones, nombre), actualizado: new Date().toISOString() };
    const r = await putPlanSA(RTDB, accessToken, plan);
    if (!r.ok) {
      const t = await r.text().catch(() => '');
      return json({ error: 'No se pudo guardar el plan (HTTP ' + r.status + ' ' + t + ').' }, 502, origin);
    }
    return json({ ok: true, plan }, 200, origin);
  }

  return json({ error: 'accion de dueno desconocida' }, 400, origin);
}

// ===================================================================
//  RATE LIMITING (memoria por instancia de Worker)
//  Ventana deslizante de 60 s con limpieza automatica de entradas viejas.
//  Limites:
//    - Por IP:                60 req/min (proteccion contra flood generico)
//    - Por UID (idToken):     30 req/min (brute force de credenciales)
//    - Acciones sensibles:    10 req/min por UID (cambio clave, baja, anular)
//  No usa KV ni Durable Objects; funciona con el plan gratis.
//  Nota: Cloudflare puede rotar instancias (los contadores se resetean),
//  pero eso no debilita la proteccion contra ataques sostenidos.
// ===================================================================
const RL_VENTANA_MS = 60_000;
const RL_MAX_POR_IP = 60;
const RL_MAX_POR_UID = 30;
const RL_MAX_SENSIBLE = 10;
const RL_ACCIONES_SENSIBLES = new Set([
  'eliminar', 'actualizarEmpleado', 'darDeBajaEmpleado',
  'anularFichada', 'atenderPanico', 'validarFichada'
]);

// Almacena { clave: [timestamp, ...] } por IP y por UID.
const rlContadores = new Map();

// Limpia entradas cuya ventana ya expiro (se llama de a ratos, no en cada req).
let rlUltimaLimpieza = 0;
function rlLimpiarSiCorresponde() {
  const ahora = Date.now();
  if (ahora - rlUltimaLimpieza < 10_000) return; // cada 10 s como mucho
  rlUltimaLimpieza = ahora;
  const corte = ahora - RL_VENTANA_MS;
  for (const [clave, timestamps] of rlContadores) {
    const vivos = timestamps.filter(t => t > corte);
    if (vivos.length === 0) rlContadores.delete(clave);
    else if (vivos.length !== timestamps.length) rlContadores.set(clave, vivos);
  }
}

// Registra un hit y devuelve cuantos lleva en la ventana actual.
function rlRegistrar(clave) {
  rlLimpiarSiCorresponde();
  const ahora = Date.now();
  const corte = ahora - RL_VENTANA_MS;
  let timestamps = rlContadores.get(clave) || [];
  timestamps = timestamps.filter(t => t > corte); // solo los de esta ventana
  timestamps.push(ahora);
  rlContadores.set(clave, timestamps);
  return timestamps.length;
}

// Verifica rate limit. Devuelve { ok } o { bloqueado, limite, clave }.
// Se llama DESPUES de parsear el body (para saber accion y uid)
// pero ANTES de cualquier logica de negocio.
function rlVerificar(ip, uid, accion) {
  // 1) Limite por IP
  const ipHits = rlRegistrar('ip:' + ip);
  if (ipHits > RL_MAX_POR_IP) {
    return { ok: false, bloqueado: true, motivo: 'RATE_LIMIT_IP',
             limite: RL_MAX_POR_IP, ventana: '60s', clave: 'ip:' + ip };
  }

  // 2) Limite por UID (si hay uid en el body)
  if (uid) {
    const uidHits = rlRegistrar('uid:' + uid);
    if (uidHits > RL_MAX_POR_UID) {
      return { ok: false, bloqueado: true, motivo: 'RATE_LIMIT_UID',
               limite: RL_MAX_POR_UID, ventana: '60s', clave: 'uid:' + uid };
    }

    // 3) Accion sensible: limite mas estricto por UID
    if (RL_ACCIONES_SENSIBLES.has(accion)) {
      const sensibleHits = rlRegistrar('sensible:' + uid + ':' + accion);
      if (sensibleHits > RL_MAX_SENSIBLE) {
        return { ok: false, bloqueado: true, motivo: 'RATE_LIMIT_SENSIBLE',
                 limite: RL_MAX_SENSIBLE, ventana: '60s',
                 clave: 'sensible:' + uid + ':' + accion };
      }
    }
  }

  return { ok: true };
}

// --- Helpers base64 ---
function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlFromBytes(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlFromString(str) {
  return b64urlFromBytes(new TextEncoder().encode(str));
}
function pemToPkcs8(pem) {
  const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return b64ToBytes(body);
}

// ===================================================================
//  VALIDACION DE OBJETIVO + GPS (fichaje autoritativo, server-side)
//  Estas piezas son ADITIVAS: no tocan los flujos de Auth existentes.
// ===================================================================

// Distancia entre dos coordenadas (formula del haversine), en metros.
// Igual que calcularDistanciaMetros() del cliente, pero aca es la version
// AUTORITATIVA: el cliente no puede saltearla ni falsear el resultado.
function distanciaMetros(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = g => g * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

// Radio permitido de un objetivo: usa el del objetivo (radioPermitido/radio/
// radioMetros) y, si no lo define, el radio global; por ultimo 100 m.
function radioObjetivoMetros(item, fallback) {
  const r = Number(item && (item.radioPermitido ?? item.radio ?? item.radioMetros));
  if (Number.isFinite(r) && r > 0) return r;
  const f = Number(fallback);
  return (Number.isFinite(f) && f > 0) ? f : 100;
}

// Normaliza personal.objetivosAsignados a una lista de IDs (string), tolerando
// tanto el formato array [{id,nombre}] como el de objeto {id:{...}}.
function idsObjetivosAsignados(personal) {
  const raw = personal && personal.objetivosAsignados;
  if (Array.isArray(raw)) {
    return raw.filter(x => x && (x.id || x.firebaseId || x.nombre))
              .map(x => String(x.id || x.firebaseId || ''));
  }
  if (raw && typeof raw === 'object') {
    return Object.entries(raw).map(([id, x]) => String((x && x.id) || id));
  }
  return [];
}

// Lee las coordenadas de un objetivo tolerando distintos nombres de campo.
function latObjetivo(item) { return Number(item && (item.latitud ?? item.lat ?? item.latitude)); }
function lngObjetivo(item) { return Number(item && (item.longitud ?? item.lng ?? item.lon ?? item.longitude)); }

// ===================================================================
//  [#1] CLAVE RTDB SEGURA (anti INYECCION DE RUTA).
//  Todo identificador controlado por el cliente (fichadaId / idEvento /
//  panicoId / uid) se interpola en la URL REST de la service account, que
//  BYPASSA las Reglas. Un valor con '/', '.', '..', '#', '$', '[' o ']' podria
//  desviar una escritura privilegiada FUERA del nodo previsto (p.ej. un
//  fichadaId = "../usuarios/<uid>" que, al normalizar la URL, termina
//  escribiendo en /usuarios). Se restringe el id al juego de caracteres de una
//  clave Firebase valida (letras, numeros, '_' y '-') y se RECHAZA cualquier
//  otro. Cubre push-ids, UIDs de Auth, legajos y los ids 'fch_<hex>' derivados.
// ===================================================================
function esClaveRtdbSegura(k) {
  return typeof k === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(k);
}

// ===================================================================
//  IDEMPOTENCIA + ATOMICIDAD DE FICHADAS (Capas A / B / C)
//  Cierra los Puntos 1 (idempotencia server-side) y 4 (anti-duplicado atomico).
//  La service account BYPASSA las reglas, por eso la atomicidad se logra con el
//  control de concurrencia optimista de la RTDB por ETag (X-Firebase-ETag +
//  if-match), no con reglas .write.
// ===================================================================

// --- Capa A: idEvento DETERMINISTICO ---
// Cuantiza el tiempo en ventanas: dos intentos del MISMO evento (legajo+tipo+
// objetivo) dentro de la ventana producen el MISMO id => misma ruta RTDB =>
// idempotencia por construccion, sin coordinacion entre dispositivos.
async function derivarIdEvento(legajo, tipo, objetivoId, epochMs, ventanaMs) {
  const v = (ventanaMs > 0) ? Math.floor(epochMs / ventanaMs) : epochMs;
  const clave = `${legajo}|${tipo}|${objetivoId}|${v}`;
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clave));
  const bytes = new Uint8Array(buf);
  let hex = '';
  for (let i = 0; i < 16; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return 'fch_' + hex;
}

// --- Capa B: create-once ATOMICO (compare-and-set por ETag) ---
// Garantiza UN solo registro por id, incluso con requests simultaneos:
//   - si el nodo ya existe => idempotente (no reescribe, devuelve el existente);
//   - si no existe => PUT condicionado al ETag observado; el que pierde la
//     carrera recibe 412 y devuelve el registro ganador.
async function crearFichadaAtomica(RTDB, accessToken, fichadaId, registro) {
  // [#1] Defensa de ultimo recurso: nunca interpolar una clave no segura en la
  // ruta REST (la SA bypassa las Reglas). Si algo llego hasta aca con un id
  // invalido, se corta antes de construir la URL.
  if (!esClaveRtdbSegura(fichadaId)) throw new Error('fichadaId invalido (clave RTDB no segura)');
  const url = `${RTDB}/fichadas/${fichadaId}.json`;
  const authH = { Authorization: 'Bearer ' + accessToken };

  // 1) GET con ETag del nodo destino.
  const getRes = await fetch(url, { headers: { ...authH, 'X-Firebase-ETag': 'true' } });
  const etag = getRes.headers.get('ETag');
  const actual = await getRes.json().catch(() => null);

  // 2) Ya existe => idempotente: NO reescribe.
  if (actual !== null && actual !== undefined) {
    return { creado: false, duplicado: true, registro: actual };
  }

  // 3) Crear condicionado al ETag observado (compare-and-set).
  const putRes = await fetch(url, {
    method: 'PUT',
    headers: { ...authH, 'Content-Type': 'application/json', 'if-match': etag || 'null_etag' },
    body: JSON.stringify(registro)
  });
  if (putRes.status === 412) {
    // Perdio la carrera: otro request creo el nodo entre el GET y el PUT.
    const ganador = await fetch(url, { headers: authH }).then(r => r.json()).catch(() => null);
    return { creado: false, duplicado: true, registro: ganador };
  }
  if (!putRes.ok) {
    const t = await putRes.text().catch(() => '');
    throw new Error('HTTP ' + putRes.status + ' ' + t);
  }
  return { creado: true, duplicado: false, registro };
}

// --- Capa C: lock ANTI-REPLAY por legajo (compare-and-set por ETag) ---
// Cierra el caso de dos idEvento DISTINTOS para el mismo evento fisico dentro de
// la ventana. Es OPT-IN: con ventanaMs <= 0 queda desactivado (no rompe fichajes
// legitimos). Un retry del MISMO idEvento NO se bloquea (lo maneja la Capa B).
async function verificarLockAntiReplay(RTDB, accessToken, legajo, tipo, idEvento, ahoraMs, ventanaMs) {
  if (!(ventanaMs > 0)) return { ok: true, desactivado: true };
  const url = `${RTDB}/locksFichada/${encodeURIComponent(legajo)}.json`;
  const authH = { Authorization: 'Bearer ' + accessToken };

  for (let intento = 0; intento < 2; intento++) {
    const getRes = await fetch(url, { headers: { ...authH, 'X-Firebase-ETag': 'true' } });
    const etag = getRes.headers.get('ETag');
    const lock = await getRes.json().catch(() => null);

    if (lock && lock.ultimoTipo === tipo && lock.ultimoIdEvento !== idEvento &&
        Number.isFinite(Number(lock.ultimoTimestampMs)) &&
        (ahoraMs - Number(lock.ultimoTimestampMs)) < ventanaMs) {
      return { ok: false, bloqueado: true, motivo: 'ventana_anti_replay' };
    }

    const nuevo = { ultimoTipo: tipo, ultimoIdEvento: idEvento, ultimoTimestampMs: ahoraMs };
    const putRes = await fetch(url, {
      method: 'PUT',
      headers: { ...authH, 'Content-Type': 'application/json', 'if-match': etag || 'null_etag' },
      body: JSON.stringify(nuevo)
    });
    if (putRes.ok) return { ok: true };
    if (putRes.status === 412) continue; // carrera en el lock: reintentar el chequeo
    return { ok: true, lockError: 'HTTP ' + putRes.status }; // fallo del lock: no bloquear el fichaje
  }
  // Conflicto persistente tras reintentos: tratar como duplicado (fail-closed).
  return { ok: false, bloqueado: true, motivo: 'conflicto_persistente_lock' };
}

// ===================================================================
//  MAQUINA DE ESTADOS ENTRADA -> SALIDA (autoritativa, server-side)
//  El estado de jornada de cada legajo se cachea en /estadoJornada/<legajo>
//  (nodo CERRADO a clientes por las Reglas -> root .read/.write:false; solo la
//  service account, que bypassa las Reglas, lo escribe). Si el cache aun no
//  existe (migracion / primer uso), se reconstruye leyendo la ULTIMA fichada
//  real del legajo en /fichadas. Objetivo: impedir server-side una SALIDA sin
//  ENTRADA activa y una ENTRADA con otra ENTRADA ya abierta, aunque el cliente
//  llame al Worker directamente saltando la interfaz.
//  NOTA: si un admin escribe /fichadas DIRECTO por REST (fuera del Worker) el
//  cache podria quedar desfasado; toda escritura via Worker (incluidas las del
//  admin) refresca el cache, y el bootstrap lo reconstruye si falta.
// ===================================================================
// [#7] Default POSITIVO del anti-replay: si configuracionGlobal.antiReplaySegundos
// NO esta definido, el anti-replay queda ACTIVO con esta ventana (segundos). El
// admin puede desactivarlo explicitamente poniendo antiReplaySegundos = 0.
const ANTI_REPLAY_DEFAULT_SEG = 90;

// [#6] Reconstruye el ultimo estado ENTRADA/SALIDA del legajo leyendo /fichadas,
// EXCLUYENDO las fichadas anuladas (anulada === true). Centralizado aqui para que
// tanto el bootstrap de cache como la reconciliacion post-anulacion apliquen el
// MISMO criterio (una fichada anulada no cuenta para la secuencia de jornada).
async function bootstrapEstadoDesdeFichadas(RTDB, accessToken, legajo) {
  const authGet = { headers: { Authorization: 'Bearer ' + accessToken } };
  const q = `${RTDB}/fichadas.json?orderBy=${encodeURIComponent('"legajo"')}&equalTo=${encodeURIComponent('"' + legajo + '"')}`;
  const mapa = await fetch(q, authGet).then(r => r.json()).catch(() => null);
  if (mapa && typeof mapa === 'object') {
    let mejor = null;
    for (const f of Object.values(mapa)) {
      if (f && f.anulada === true) continue; // [#6] una fichada anulada NO cuenta
      const t = String((f && f.tipo) || '').toUpperCase();
      if (t !== 'ENTRADA' && t !== 'SALIDA') continue;
      let ts = Number(f && f.timestampServidor);
      if (!Number.isFinite(ts)) ts = Number(f && f.timestampEstimadoDispositivo); // [#4] fichadas offline
      if (!Number.isFinite(ts)) ts = (f && f.fechaHoraDispositivo) ? Date.parse(f.fechaHoraDispositivo) : NaN;
      if (!Number.isFinite(ts)) ts = 0;
      if (!mejor || ts > mejor.ts) mejor = { tipo: t, ts, idEvento: String((f && (f.idEvento || f.fichadaId)) || '') };
    }
    if (mejor) return { tipo: mejor.tipo, idEvento: mejor.idEvento, ts: mejor.ts, origen: 'bootstrap' };
  }
  return { tipo: null, idEvento: '', ts: 0, origen: 'vacio' };
}

async function obtenerUltimoEstadoLegajo(RTDB, accessToken, legajo) {
  const authGet = { headers: { Authorization: 'Bearer ' + accessToken } };
  // 1) Cache rapido de estado (una lectura de un solo nodo).
  const cache = await fetch(`${RTDB}/estadoJornada/${encodeURIComponent(legajo)}.json`, authGet)
    .then(r => r.json()).catch(() => null);
  const tipoCache = cache && String(cache.ultimoTipo || '').toUpperCase();
  if (tipoCache === 'ENTRADA' || tipoCache === 'SALIDA') {
    return { tipo: tipoCache, idEvento: String(cache.ultimoIdEvento || ''), ts: Number(cache.ultimoTimestampMs) || 0, origen: 'cache' };
  }
  // 2) Bootstrap desde /fichadas del legajo (una sola vez; luego queda cacheado).
  return await bootstrapEstadoDesdeFichadas(RTDB, accessToken, legajo);
}

// Valida la transicion contra el estado actual. Un reintento del MISMO evento
// (mismo idEvento ya registrado) se PERMITE: lo resuelve la idempotencia (Capa B),
// para no romper reintentos legitimos que ya se habian confirmado.
function validarTransicionJornada(estadoActual, tipo, fichadaId) {
  if (fichadaId && estadoActual.idEvento && fichadaId === estadoActual.idEvento) {
    return { ok: true, retry: true };
  }
  if (tipo === 'ENTRADA') {
    if (estadoActual.tipo === 'ENTRADA') {
      return { ok: false, motivo: 'ENTRADA_YA_ACTIVA', mensaje: 'ya existe una ENTRADA activa sin SALIDA' };
    }
    return { ok: true };
  }
  // SALIDA
  if (estadoActual.tipo !== 'ENTRADA') {
    return { ok: false, motivo: 'SIN_ENTRADA_ACTIVA', mensaje: 'no hay una ENTRADA activa para registrar la SALIDA' };
  }
  return { ok: true };
}

// Persiste el nuevo estado de jornada. Best-effort: NUNCA debe romper el fichaje
// ya creado. No retrocede el estado con un evento mas viejo (p.ej. sync offline
// tardio que llega despues de una fichada online mas reciente).
async function actualizarEstadoJornada(RTDB, accessToken, legajo, tipo, fichadaId, tsMs) {
  try {
    const authH = { Authorization: 'Bearer ' + accessToken };
    const url = `${RTDB}/estadoJornada/${encodeURIComponent(legajo)}.json`;
    const tsNuevo = Number(tsMs) || Date.now();
    // [#6] Compare-and-set por ETag (misma defensa que reservarTransicionJornada
    // y reconciliarEstadoJornada). Esta ruta la usa la CORRECCION del ADMIN, que
    // queda exenta de la maquina de estados; sin condicionar al ETag, una fichada
    // concurrente del mismo legajo podria quedar pisada por este PUT. Se condiciona
    // al ETag observado y, si otro request gano la carrera (412), se reintenta
    // releyendo el estado. Sigue sin retroceder ante un evento mas viejo.
    for (let intento = 0; intento < 3; intento++) {
      const getRes = await fetch(url, { headers: { ...authH, 'X-Firebase-ETag': 'true' } });
      const etag = getRes.headers.get('ETag');
      const actual = await getRes.json().catch(() => null);
      const tsPrevio = Number(actual && actual.ultimoTimestampMs) || 0;
      if (actual && tsPrevio > tsNuevo) return;   // no retroceder el estado.
      const putRes = await fetch(url, {
        method: 'PUT',
        headers: { ...authH, 'Content-Type': 'application/json', 'if-match': etag || 'null_etag' },
        body: JSON.stringify({ ultimoTipo: tipo, ultimoIdEvento: String(fichadaId || ''), ultimoTimestampMs: tsNuevo })
      });
      if (putRes.ok || putRes.status === 404) return;
      if (putRes.status !== 412) return;          // otro error: best-effort, no insistir.
      // 412: perdio la carrera contra una fichada concurrente -> reintentar ciclo.
    }
  } catch (_) { /* best-effort: no romper el fichaje ya creado */ }
}

// [#7] RESERVA ATOMICA de la transicion de jornada (compare-and-set por ETag).
// Resuelve la condicion de carrera: antes se LEIA el estado, se VALIDABA y mas
// tarde se ESCRIBIA en pasos separados, de modo que dos fichadas concurrentes del
// mismo legajo podian pasar ambas la validacion (p.ej. dos ENTRADA sin SALIDA en
// medio). Ahora leer-validar-avanzar ocurre en UNA operacion condicionada al ETag
// del nodo /estadoJornada/<legajo> (mismo patron de compare-and-set que ya usa el
// create-once de fichadas y el lock anti-replay):
//   - lee el estado actual (cache o bootstrap desde /fichadas, excluyendo anuladas);
//   - valida la transicion ENTRADA->SALIDA;
//   - si es valida, ESCRIBE el nuevo estado condicionado al ETag observado;
//   - si otro request gano la carrera (412) reintenta todo el ciclo;
//   - no retrocede el estado ante un evento mas viejo (sync offline tardio).
// Debe invocarse ANTES de crear la fichada: es el candado que ordena la secuencia.
async function reservarTransicionJornada(RTDB, accessToken, legajo, tipo, fichadaId, tsMs) {
  const authH = { Authorization: 'Bearer ' + accessToken };
  const urlEstado = `${RTDB}/estadoJornada/${encodeURIComponent(legajo)}.json`;
  for (let intento = 0; intento < 4; intento++) {
    // 1) Estado actual + ETag (una sola lectura del nodo).
    const getRes = await fetch(urlEstado, { headers: { ...authH, 'X-Firebase-ETag': 'true' } });
    const etag = getRes.headers.get('ETag');
    const cache = await getRes.json().catch(() => null);
    let estadoActual;
    const tipoCache = cache && String(cache.ultimoTipo || '').toUpperCase();
    if (tipoCache === 'ENTRADA' || tipoCache === 'SALIDA') {
      estadoActual = { tipo: tipoCache, idEvento: String(cache.ultimoIdEvento || ''), ts: Number(cache.ultimoTimestampMs) || 0 };
    } else {
      // Cache ausente: bootstrap desde /fichadas (excluye anuladas). No usamos el
      // ETag para condicionar en este caso (el nodo estaba vacio): el PUT se
      // condiciona igual al ETag observado del nodo vacio (if-match null_etag).
      estadoActual = await bootstrapEstadoDesdeFichadas(RTDB, accessToken, legajo);
    }

    // 2) Validacion de la maquina de estados.
    const trans = validarTransicionJornada(estadoActual, tipo, fichadaId);
    if (!trans.ok) return { ok: false, motivo: trans.motivo, mensaje: trans.mensaje, estadoActual };
    // Reintento del MISMO idEvento ya registrado: no reavanza (idempotente).
    if (trans.retry) return { ok: true, retry: true, estadoActual };

    // 3) No retroceder el estado ante un evento mas viejo (p.ej. sync offline
    //    tardio que llega despues de una fichada online mas reciente). La
    //    transicion es valida pero NO se reescribe el cache.
    const tsNuevo = Number(tsMs) || Date.now();
    if (estadoActual.tipo && (estadoActual.ts || 0) > tsNuevo) {
      return { ok: true, sinAvance: true, estadoActual };
    }

    // 4) Avanzar el estado condicionado al ETag (compare-and-set).
    const nuevo = { ultimoTipo: tipo, ultimoIdEvento: String(fichadaId || ''), ultimoTimestampMs: tsNuevo };
    const putRes = await fetch(urlEstado, {
      method: 'PUT',
      headers: { ...authH, 'Content-Type': 'application/json', 'if-match': etag || 'null_etag' },
      body: JSON.stringify(nuevo)
    });
    if (putRes.ok) return { ok: true, avanzado: true, estadoActual };
    if (putRes.status === 412) continue; // perdio la carrera: reintentar el ciclo
    // Error del PUT (no de concurrencia): no romper el fichaje por un fallo de
    // cache; la validacion ya se hizo contra el estado leido.
    return { ok: true, cacheError: 'HTTP ' + putRes.status, estadoActual };
  }
  // Conflicto de concurrencia persistente: fail-closed (se rechaza y se reintenta).
  return { ok: false, motivo: 'CONFLICTO_SECUENCIA', mensaje: 'conflicto de concurrencia en la secuencia de jornada, reintenta en unos instantes' };
}

// [#6] Reconcilia /estadoJornada tras anular una fichada: recalcula el ultimo
// estado ENTRADA/SALIDA del legajo EXCLUYENDO las anuladas y lo reescribe (o lo
// borra si ya no quedan fichadas validas). Sin esto, el cache podia quedar
// apuntando a una fichada que acaba de anularse, bloqueando el siguiente fichaje
// legitimo (p.ej. una ENTRADA anulada que dejaba el estado como 'ENTRADA activa').
// Best-effort: no debe romper la anulacion ya aplicada.
async function reconciliarEstadoJornada(RTDB, accessToken, legajo) {
  try {
    if (!legajo) return;
    const authH = { Authorization: 'Bearer ' + accessToken };
    const url = `${RTDB}/estadoJornada/${encodeURIComponent(legajo)}.json`;
    // [#7] Compare-and-set por ETag: entre leer /fichadas y reescribir el cache,
    // una fichada CONCURRENTE del mismo legajo podria avanzar /estadoJornada. Sin
    // condicionar al ETag, este PUT pisaria ese avance con un estado reconstruido
    // ya viejo. Se condiciona al ETag observado y, si otro request gano la carrera
    // (412), se RECONSTRUYE de nuevo (leyendo tambien la fichada recien creada) y
    // se reintenta -> converge sin pisar escrituras concurrentes.
    for (let intento = 0; intento < 3; intento++) {
      const getRes = await fetch(url, { headers: { ...authH, 'X-Firebase-ETag': 'true' } });
      const etag = getRes.headers.get('ETag');
      const estado = await bootstrapEstadoDesdeFichadas(RTDB, accessToken, legajo);
      let putRes;
      if (estado && estado.tipo) {
        putRes = await fetch(url, {
          method: 'PUT',
          headers: { ...authH, 'Content-Type': 'application/json', 'if-match': etag || 'null_etag' },
          body: JSON.stringify({ ultimoTipo: estado.tipo, ultimoIdEvento: estado.idEvento, ultimoTimestampMs: estado.ts, reconciliadoEn: { '.sv': 'timestamp' } })
        });
      } else {
        // No quedan fichadas validas: se limpia el cache (condicionado al ETag).
        putRes = await fetch(url, { method: 'DELETE', headers: { ...authH, 'if-match': etag || 'null_etag' } });
      }
      if (putRes.ok || putRes.status === 404) return;   // aplicado (404 = el nodo ya no existia)
      if (putRes.status !== 412) return;                // otro error: best-effort, no insistir
      // 412: perdio la carrera contra una fichada concurrente -> reintentar el ciclo.
    }
  } catch (_) { /* best-effort: la anulacion ya quedo aplicada */ }
}

/**
 * FICHAJE AUTORITATIVO.
 * El vigilador (no admin) envia su idToken + la fichada. El servidor:
 *   1) Verifica criptograficamente quien pide (uid del token).
 *   2) Resuelve el legajo REAL desde /usuarios/<uid> (ignora el que mande el cliente).
 *   3) Comprueba que el objetivo este AUTORIZADO para ese legajo.
 *   4) Calcula la distancia GPS al objetivo y exige estar dentro del radio.
 *   5) Escribe la fichada con la service account (bypassa reglas), sellando
 *      legajo, authUid, coordenadas del objetivo, distancia y hora de servidor.
 * El admin queda exento de las validaciones de autorizacion y radio (correccion).
 */
async function manejarFichar(body, env, sa, projectId, origin) {
  const { idToken, fichada } = body || {};
  if (!idToken) return json({ error: 'falta idToken' }, 400, origin);
  if (!fichada || typeof fichada !== 'object') return json({ error: 'falta la fichada' }, 400, origin);

  // 1) Identidad del solicitante (verificacion de firma del idToken).
  let sol;
  try { sol = await verificarIdToken(idToken, projectId); }
  catch (e) { return json({ error: 'token invalido: ' + e.message }, 401, origin); }
  const uid = sol.sub;

  // 2) Access token de la service account (escritura autoritativa).
  let accessToken;
  try { accessToken = await obtenerAccessToken(sa); }
  catch (e) { return json({ error: 'no se pudo autenticar el servidor: ' + e.message }, 500, origin); }
  const authGet = { headers: { Authorization: 'Bearer ' + accessToken } };
  const RTDB = env.RTDB_URL;

  // 3) legajo REAL del uid (autoritativo, no el que mande el cliente).
  const usuario = await fetch(`${RTDB}/usuarios/${uid}.json`, authGet).then(r => r.json()).catch(() => null);
  const legajoReal = (usuario && usuario.legajo != null) ? String(usuario.legajo).trim() : '';
  const rol = usuario && usuario.rol;
  const esAdmin = rol === 'admin';
  if (!legajoReal) return json({ error: 'usuario sin legajo asignado' }, 403, origin);

  // 4) Campos criticos de la fichada.
  const tipo = String(fichada.tipo || '').trim().toUpperCase();
  const lat = Number(fichada.latitud);
  const lng = Number(fichada.longitud);
  const nombreObjetivo = String(fichada.objetivo || '').trim();
  const objetivoIdCliente = String(fichada.objetivoAutorizadoId || '').trim();
  if (tipo !== 'ENTRADA' && tipo !== 'SALIDA') return json({ error: 'tipo de fichada invalido' }, 422, origin);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || (lat === 0 && lng === 0)) return json({ error: 'coordenada GPS invalida' }, 422, origin);
  if (!nombreObjetivo) return json({ error: 'objetivo requerido' }, 422, origin);
  if (!fichada.fechaHoraDispositivo) return json({ error: 'fechaHoraDispositivo requerida' }, 422, origin);

  // 5) Ficha del vigilador (estado + objetivos autorizados) por legajo.
  const personalResp = await fetch(
    `${RTDB}/personal.json?orderBy=${encodeURIComponent('"legajo"')}&equalTo=${encodeURIComponent('"' + legajoReal + '"')}`,
    authGet
  ).then(r => r.json()).catch(() => null);
  const personal = (personalResp && typeof personalResp === 'object') ? Object.values(personalResp)[0] : null;
  if (!esAdmin) {
    if (!personal) return json({ error: 'vigilador inexistente' }, 403, origin);
    if (String(personal.estado || '').toUpperCase() === 'INACTIVO') return json({ error: 'vigilador inactivo / dado de baja' }, 403, origin);
  }
  const autorizados = personal ? idsObjetivosAsignados(personal) : [];

  // 6) Objetivo (por id declarado o por nombre) + sus coordenadas y radio.
  const objetivos = await fetch(`${RTDB}/objetivos.json`, authGet).then(r => r.json()).catch(() => null) || {};
  let entry = null;
  if (objetivoIdCliente && objetivos[objetivoIdCliente]) entry = [objetivoIdCliente, objetivos[objetivoIdCliente]];
  if (!entry) {
    const busc = nombreObjetivo.toLowerCase();
    entry = Object.entries(objetivos).find(([id, it]) =>
      String((it && (it.nombre || it.codigo)) || id).trim().toLowerCase() === busc) || null;
  }
  if (!entry) return json({ error: 'objetivo inexistente' }, 422, origin);
  const objIdReal = entry[0];
  const obj = entry[1];

  // Autorizacion: el objetivo debe estar asignado a ESTE vigilador (salvo admin).
  // IMPORTANTE: si el vigilador NO tiene objetivos asignados (lista vacia) NO puede
  // fichar contra ninguno. Antes se exigia 'autorizados.length' en la condicion, lo
  // que dejaba pasar el caso vacio (0 objetivos = sin restriccion). Eso contradecia
  // la interfaz ("No tiene objetivos autorizados"). El admin queda exento.
  if (!esAdmin && !autorizados.includes(String(objIdReal))) {
    return json({ error: 'objetivo no autorizado para este vigilador' }, 403, origin);
  }

  const laObj = latObjetivo(obj);
  const loObj = lngObjetivo(obj);
  if (!Number.isFinite(laObj) || !Number.isFinite(loObj) || (laObj === 0 && loObj === 0)) {
    return json({ error: 'el objetivo no tiene coordenadas GPS cargadas' }, 422, origin);
  }

  // Radio: objetivo -> configuracionGlobal.radioFichajeMetros -> 100 m.
  let radioGlobal = 100;
  const cfg = await fetch(`${RTDB}/configuracionGlobal.json`, authGet).then(r => r.json()).catch(() => null);
  const rg = Number(cfg && cfg.radioFichajeMetros);
  if (Number.isFinite(rg) && rg > 0) radioGlobal = rg;
  const radio = radioObjetivoMetros(obj, radioGlobal);
  const dist = distanciaMetros(lat, lng, laObj, loObj);

  // UMBRAL DE PRECISION GPS (autoritativo, fail-closed). Si la lectura del
  // dispositivo es demasiado imprecisa (accuracy alto), la ubicacion NO es
  // confiable para evaluar la geocerca => se RECHAZA la fichada (salvo admin).
  // El umbral se configura en configuracionGlobal.precisionMaximaMetros (metros).
  // Si no hay un valor > 0 configurado, el control queda DESACTIVADO y NO altera
  // el comportamiento actual (no rompe fichajes existentes). Solo se aplica
  // cuando el cliente reporta una precision numerica (precisionGPSMetros).
  const precisionGPS = Number(fichada.precisionGPSMetros);
  let precisionMax = 0;
  const pm = Number(cfg && cfg.precisionMaximaMetros);
  if (Number.isFinite(pm) && pm > 0) precisionMax = pm;
  if (!esAdmin && precisionMax > 0 && Number.isFinite(precisionGPS) && precisionGPS > precisionMax) {
    // AUDITORIA AUTORITATIVA: deja rastro del intento bloqueado por precision GPS.
    await auditarSA(RTDB, accessToken, {
      accion: 'FICHADA_BLOQUEADA_PRECISION', entidad: 'fichadas',
      entidadId: String(fichada.fichadaId || ''),
      actorUid: uid, actorLegajo: legajoReal, rol: rol || 'vigilador',
      detalle: {
        objetivo: String((obj && (obj.nombre || obj.codigo)) || nombreObjetivo),
        precisionGPSMetros: Math.round(precisionGPS),
        precisionMaximaMetros: Math.round(precisionMax)
      }
    });
    return json({
      error: 'precision GPS insuficiente para fichar (senal poco confiable)',
      bloqueado: true,
      motivo: 'PRECISION_GPS',
      precisionGPSMetros: Math.round(precisionGPS),
      precisionMaximaMetros: Math.round(precisionMax)
    }, 403, origin);
  }

  // Geocerca autoritativa (fail-closed): fuera de radio => BLOQUEADA.
  if (!esAdmin && dist > radio) {
    // AUDITORIA AUTORITATIVA: deja rastro del intento bloqueado por GPS.
    await auditarSA(RTDB, accessToken, {
      accion: 'FICHADA_BLOQUEADA_GPS', entidad: 'fichadas',
      entidadId: String(fichada.fichadaId || ''),
      actorUid: uid, actorLegajo: legajoReal, rol: rol || 'vigilador',
      detalle: {
        objetivo: String((obj && (obj.nombre || obj.codigo)) || nombreObjetivo),
        distanciaMetros: Math.round(dist), radioPermitidoMetros: Math.round(radio)
      }
    });
    return json({
      error: 'fuera del radio del objetivo',
      bloqueado: true,
      distanciaMetros: Math.round(dist),
      radioPermitidoMetros: Math.round(radio)
    }, 403, origin);
  }

  // 7) IDEMPOTENCIA + ATOMICIDAD (Capas A / B / C). --------------------------
  //    Capa A - idEvento ESTABLE. Prioridad:
  //      1) idEvento explicito del cliente (recomendado, estable entre reintentos),
  //      2) fichadaId legado (compat con el cliente actual, aun no migrado),
  //      3) hash deterministico legajo|tipo|objetivo|ventana (fallback autoritativo).
  const ventanaIdMs = (() => { const v = Number(cfg && cfg.ventanaIdEventoSegundos); return (Number.isFinite(v) && v > 0) ? v * 1000 : 120000; })();
  let fichadaId = String(fichada.idEvento || fichada.fichadaId || '').trim();
  if (!fichadaId) {
    fichadaId = await derivarIdEvento(legajoReal, tipo, String(objIdReal), Date.now(), ventanaIdMs);
  }
  // [#1] El idEvento/fichadaId puede venir del cliente: se valida como clave
  // RTDB segura ANTES de usarlo en cualquier ruta REST (anti path injection).
  if (!esClaveRtdbSegura(fichadaId)) {
    return json({ error: 'idEvento/fichadaId invalido (solo se permiten letras, numeros, guion y guion bajo)' }, 422, origin);
  }

  //    Capa C - lock anti-replay por legajo. [#7] AHORA ACTIVO POR DEFECTO: si el
  //    admin no configura antiReplaySegundos, se aplica una ventana por defecto
  //    (ANTI_REPLAY_DEFAULT_SEG). Solo se desactiva poniendo antiReplaySegundos = 0
  //    de forma EXPLICITA. Solo aplica a vigiladores; el admin queda exento.
  const ventanaReplayMs = (() => {
    const raw = cfg && cfg.antiReplaySegundos;
    if (raw === 0 || raw === '0') return 0;        // desactivado EXPLICITAMENTE por el admin
    const v = Number(raw);
    if (Number.isFinite(v) && v > 0) return v * 1000;
    return ANTI_REPLAY_DEFAULT_SEG * 1000;         // [#7] default POSITIVO si no esta configurado
  })();
  if (!esAdmin) {
    const lock = await verificarLockAntiReplay(RTDB, accessToken, legajoReal, tipo, fichadaId, Date.now(), ventanaReplayMs);
    if (lock.bloqueado) {
      await auditarSA(RTDB, accessToken, {
        accion: 'FICHADA_BLOQUEADA_ANTIREPLAY', entidad: 'fichadas', entidadId: fichadaId,
        actorUid: uid, actorLegajo: legajoReal, rol: rol || 'vigilador',
        detalle: {
          tipo, objetivo: String((obj && (obj.nombre || obj.codigo)) || nombreObjetivo),
          motivo: lock.motivo || 'ventana_anti_replay'
        }
      });
      return json({
        error: 'evento duplicado (anti-replay): ya se registro una fichada equivalente hace instantes',
        bloqueado: true, motivo: 'ANTI_REPLAY', duplicado: true
      }, 409, origin);
    }
  }

  //    Capa D - MAQUINA DE ESTADOS ENTRADA -> SALIDA. [#7] La validacion de la
  //    secuencia y el avance del estado se hacen de forma ATOMICA (compare-and-set
  //    por ETag) JUSTO ANTES de crear la fichada, mediante reservarTransicionJornada
  //    (ver mas abajo, antes de la Capa B). Esto cierra la condicion de carrera que
  //    tenia el esquema previo read-validate / write-separado.

  //    Registro AUTORITATIVO: se conservan los campos utiles del cliente (foto,
  //    validacionFacial, horarios) pero se SOBREESCRIBEN los criticos con los
  //    valores verificados en el servidor.
  const registro = Object.assign({}, fichada, {
    fichadaId,
    idEvento: fichadaId,
    legajo: legajoReal,
    authUid: uid,
    objetivo: String((obj && (obj.nombre || obj.codigo)) || nombreObjetivo),
    objetivoAutorizadoId: String(objIdReal),
    tipo,
    latitud: lat,
    longitud: lng,
    latitudObjetivo: laObj,
    longitudObjetivo: loObj,
    distanciaAlObjetivoMetros: Math.round(dist),
    radioPermitidoMetros: Math.round(radio),
    ubicacionValidada: true,
    ubicacionValidadaServidor: true,
    validadaPorWorker: true,
    // [#4] Procedencia del tiempo EXPLICITA: en el fichaje online el ancla es el
    // reloj del servidor (.sv timestamp), no el del dispositivo.
    origenTiempo: 'servidor',
    timestampServidor: { '.sv': 'timestamp' }
  });

  //    [#7] RESERVA ATOMICA de la transicion de jornada (compare-and-set por ETag)
  //    JUSTO ANTES de crear la fichada. Valida la secuencia ENTRADA->SALIDA y
  //    avanza el estado en una sola operacion condicionada al ETag, cerrando la
  //    carrera de dos fichadas concurrentes del mismo legajo. El admin queda EXENTO
  //    (correcciones); para el admin el cache se actualiza best-effort tras crear.
  if (!esAdmin) {
    const reserva = await reservarTransicionJornada(RTDB, accessToken, legajoReal, tipo, fichadaId, Date.now());
    if (!reserva.ok) {
      await auditarSA(RTDB, accessToken, {
        accion: 'FICHADA_BLOQUEADA_SECUENCIA', entidad: 'fichadas', entidadId: fichadaId,
        actorUid: uid, actorLegajo: legajoReal, rol: rol || 'vigilador',
        detalle: {
          tipo, objetivo: String((obj && (obj.nombre || obj.codigo)) || nombreObjetivo),
          motivo: reserva.motivo, estadoPrevio: (reserva.estadoActual && reserva.estadoActual.tipo) || null
        }
      });
      const code = reserva.motivo === 'CONFLICTO_SECUENCIA' ? 409 : 409;
      return json({
        error: reserva.mensaje, bloqueado: true, motivo: reserva.motivo,
        tipoRechazado: tipo, estadoActual: (reserva.estadoActual && reserva.estadoActual.tipo) || null
      }, code, origin);
    }
  }

  //    Capa B - create-once ATOMICO (ETag compare-and-set). Un solo registro por id.
  let resultado;
  try {
    resultado = await crearFichadaAtomica(RTDB, accessToken, fichadaId, registro);
  } catch (e) {
    return json({ error: 'no se pudo guardar la fichada: ' + String((e && e.message) || e) }, 502, origin);
  }

  //    Idempotente: el evento ya existia (reintento / carrera perdida). No se crea
  //    de nuevo. Se responde EXITO con duplicado:true para que el cliente lo trate
  //    como fichada aceptada (y NO la reencole).
  if (resultado.duplicado) {
    await auditarSA(RTDB, accessToken, {
      accion: 'FICHADA_DUPLICADA_IGNORADA', entidad: 'fichadas', entidadId: fichadaId,
      actorUid: uid, actorLegajo: legajoReal, rol: rol || 'vigilador',
      detalle: { tipo, objetivo: registro.objetivo, via: 'idempotencia_worker' }
    });
    return json({
      ok: true, duplicado: true, fichadaId,
      distanciaMetros: Math.round(dist), radioPermitidoMetros: Math.round(radio)
    }, 200, origin);
  }

  // [#7] El estado de jornada ya se reservo ATOMICAMENTE antes de crear la fichada
  // (reservarTransicionJornada) para los vigiladores. Para el ADMIN, que queda
  // exento de la reserva, se actualiza aqui el cache best-effort tras crear.
  if (esAdmin) {
    await actualizarEstadoJornada(RTDB, accessToken, legajoReal, tipo, fichadaId, Date.now());
  }

  // AUDITORIA AUTORITATIVA: la creacion de la fichada queda registrada por el
  // Worker (no depende de la UI). Solo se emite cuando REALMENTE se creo.
  await auditarSA(RTDB, accessToken, {
    accion: 'FICHADA_CREADA', entidad: 'fichadas', entidadId: fichadaId,
    actorUid: uid, actorLegajo: legajoReal, rol: rol || 'vigilador',
    detalle: {
      tipo, objetivo: registro.objetivo,
      distanciaMetros: Math.round(dist), radioPermitidoMetros: Math.round(radio),
      precisionGPSMetros: Number.isFinite(precisionGPS) ? Math.round(precisionGPS) : null,
      sincronizadoDesdeOffline: !!fichada.sincronizadoDesdeOffline
    }
  });

  return json({
    ok: true,
    creado: true,
    fichadaId,
    distanciaMetros: Math.round(dist),
    radioPermitidoMetros: Math.round(radio)
  }, 200, origin);
}

// ===================================================================
//  AUDITORIA AUTORITATIVA (server-side, service account)
//  auditarSA escribe UNA entrada append-only en /auditoria con la SA. Sella
//  timestampServidor y marca registradoPorWorker=true. Por si sola es best-effort
//  (usada en eventos secundarios). Para los HECHOS CRITICOS (anulacion de fichada
//  y de panico) se usa auditarSAConReintentos + REVERSION: si la bitacora no puede
//  registrarse, la operacion se deshace, de modo que NUNCA quede un hecho critico
//  aplicado sin su registro de auditoria (punto 5). La identidad (actorUid/
//  actorLegajo) la provee el llamador SIEMPRE derivada del idToken verificado,
//  nunca del cuerpo crudo del cliente.
// ===================================================================
async function auditarSA(RTDB, accessToken, entrada) {
  const registro = Object.assign({
    timestampServidor: { '.sv': 'timestamp' },
    registradoPorWorker: true
  }, entrada);
  try {
    const res = await fetch(`${RTDB}/auditoria.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
      body: JSON.stringify(registro)
    });
    if (!res.ok) return { ok: false, status: res.status };
    const data = await res.json().catch(() => ({}));
    return { ok: true, id: data && data.name };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
}

// Auditoria OBLIGATORIA con reintentos cortos: absorbe fallos transitorios de red
// antes de dar por perdida la bitacora. Se usa en los hechos criticos (anulacion
// de fichada / de panico); si tras los reintentos sigue fallando, el llamador
// REVIERTE la operacion para no dejar el hecho sin registro.
async function auditarSAConReintentos(RTDB, accessToken, entrada, intentos) {
  const max = intentos || 3;
  let ultimo = { ok: false };
  for (let i = 1; i <= max; i++) {
    ultimo = await auditarSA(RTDB, accessToken, entrada);
    if (ultimo.ok) return ultimo;
    if (i < max) await new Promise(r => setTimeout(r, 300 * i)); // 300ms, 600ms
  }
  return ultimo;
}

// ===================================================================
//  ACCIONES ADMINISTRATIVAS CON AUDITORIA ATOMICA (service account)
//  anularFichada / atenderPanico / auditarEvento. Cada una:
//   1) verifica el idToken del solicitante,
//   2) exige rol admin (leido server-side de /usuarios/<uid>),
//   3) ejecuta el PATCH con la SA (anulacion LOGICA, conserva evidencia),
//   4) escribe la entrada de /auditoria con la SA, sellando actor y hora.
//  El cliente ya no hace el PATCH ni el POST de auditoria por su cuenta: el
//  registro del hecho queda garantizado como efecto del Worker.
// ===================================================================
async function manejarAccionAdmin(accion, body, env, sa, projectId, origin) {
  const { idToken } = body || {};
  if (!idToken) return json({ error: 'falta idToken' }, 400, origin);

  // 1) Identidad del solicitante.
  let sol;
  try { sol = await verificarIdToken(idToken, projectId); }
  catch (e) { return json({ error: 'token invalido: ' + e.message }, 401, origin); }
  const adminUid = sol.sub;

  // 2) Access token de la service account.
  let accessToken;
  try { accessToken = await obtenerAccessToken(sa); }
  catch (e) { return json({ error: 'no se pudo autenticar el servidor: ' + e.message }, 500, origin); }
  const RTDB = env.RTDB_URL;
  const authGet = { headers: { Authorization: 'Bearer ' + accessToken } };

  // 3) El solicitante DEBE ser admin (rol + legajo reales, server-side).
  const usuario = await fetch(`${RTDB}/usuarios/${adminUid}.json`, authGet).then(r => r.json()).catch(() => null);
  const rol = usuario && usuario.rol;
  const adminLegajo = (usuario && usuario.legajo != null) ? String(usuario.legajo).trim() : '';
  if (rol !== 'admin') return json({ error: 'no autorizado (se requiere rol admin)' }, 403, origin);

  const patchSA = (path, patch) => fetch(`${RTDB}/${path}.json`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
    body: JSON.stringify(patch)
  });

  // --- ANULAR FICHADA (anulacion logica: conserva la evidencia) ---
  if (accion === 'anularFichada') {
    const fichadaId = String(body.fichadaId || '').trim();
    const motivo = String(body.motivo || '').trim();
    if (!fichadaId) return json({ error: 'falta fichadaId' }, 422, origin);
    if (!esClaveRtdbSegura(fichadaId)) return json({ error: 'fichadaId invalido (clave RTDB no segura)' }, 422, origin); // [#1] anti path injection
    const existente = await fetch(`${RTDB}/fichadas/${fichadaId}.json`, authGet).then(r => r.json()).catch(() => null);
    if (!existente) return json({ error: 'fichada inexistente' }, 404, origin);
    const patch = {
      anulada: true,
      motivoAnulacion: motivo || 'sin motivo',
      anuladaPor: adminLegajo || adminUid,
      anuladaPorUid: adminUid,
      timestampAnulacion: { '.sv': 'timestamp' }
    };
    // Punto 5: auditoria OBLIGATORIA. Capturamos el estado previo de las claves
    // que vamos a tocar para poder REVERTIR si la bitacora no llega a registrarse.
    const previoAnul = {};
    for (const k of Object.keys(patch)) previoAnul[k] = (existente && k in existente) ? existente[k] : null;
    const res = await patchSA(`fichadas/${fichadaId}`, patch);
    if (!res.ok) { const t = await res.text().catch(() => ''); return json({ error: 'no se pudo anular: HTTP ' + res.status + ' ' + t }, 502, origin); }
    const aud = await auditarSAConReintentos(RTDB, accessToken, {
      accion: 'FICHADA_ANULADA', entidad: 'fichadas', entidadId: fichadaId,
      actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
      detalle: { motivo: motivo || 'sin motivo', legajoAfectado: String(existente.legajo || '') }
    });
    if (!aud.ok) {
      // No se pudo auditar el hecho: se REVIERTE la anulacion (fail-closed) para
      // que NUNCA quede una fichada anulada sin su registro en la bitacora.
      let revertida = true;
      try { const rv = await patchSA(`fichadas/${fichadaId}`, previoAnul); revertida = rv.ok; } catch (_) { revertida = false; }
      return json({
        error: revertida
          ? 'La anulacion NO se aplico: no se pudo registrar la auditoria obligatoria. Reintenta en unos segundos.'
          : 'ATENCION: la auditoria fallo y ademas no se pudo revertir la anulacion. Revisa la fichada manualmente.',
        auditoria: aud, revertida
      }, 502, origin);
    }
    // [#6] Reconcilia el cache /estadoJornada del legajo afectado: una fichada
    // anulada NO debe seguir contando para la secuencia ENTRADA->SALIDA. Se
    // recalcula el ultimo estado excluyendo las anuladas (best-effort; la
    // anulacion y su auditoria ya quedaron aplicadas). Sin esto, p.ej. anular una
    // ENTRADA dejaba el estado como 'ENTRADA activa' y bloqueaba el siguiente
    // fichaje legitimo del vigilador.
    await reconciliarEstadoJornada(RTDB, accessToken, String(existente.legajo || '').trim());
    return json({ ok: true, fichadaId, anulada: true, auditoria: aud }, 200, origin);
  }

  // --- VALIDAR FICHADA (aprobacion manual de una fichada marcada como fraude/
  //     pendiente de verificacion). Mismo patron atomico que anularFichada:
  //     el PATCH lo hace la SA y la auditoria FICHADA_APROBADA es OBLIGATORIA
  //     (si no se puede registrar, se REVIERTE el cambio, fail-closed). El
  //     cliente ya no toca /fichadas por REST: la validacion pasa por aqui. ---
  if (accion === 'validarFichada') {
    const fichadaId = String(body.fichadaId || '').trim();
    const motivo = String(body.motivo || '').trim() || 'Validada manualmente por el administrador';
    if (!fichadaId) return json({ error: 'falta fichadaId' }, 422, origin);
    if (!esClaveRtdbSegura(fichadaId)) return json({ error: 'fichadaId invalido (clave RTDB no segura)' }, 422, origin); // [#1] anti path injection
    const existente = await fetch(`${RTDB}/fichadas/${fichadaId}.json`, authGet).then(r => r.json()).catch(() => null);
    if (!existente) return json({ error: 'fichada inexistente' }, 404, origin);
    const patch = {
      alertaFraude: false,
      requiereRevisionManual: false,
      verificacionOfflineResuelta: true,
      validacionFacial: 'VALIDADA_MANUAL',
      motivoFraude: motivo,
      motivoRevision: motivo
    };
    // Estado previo de las claves que vamos a tocar, para poder REVERTIR si la
    // bitacora no llega a registrarse.
    const previoVal = {};
    for (const k of Object.keys(patch)) previoVal[k] = (existente && k in existente) ? existente[k] : null;
    const res = await patchSA(`fichadas/${fichadaId}`, patch);
    if (!res.ok) { const t = await res.text().catch(() => ''); return json({ error: 'no se pudo validar: HTTP ' + res.status + ' ' + t }, 502, origin); }
    const aud = await auditarSAConReintentos(RTDB, accessToken, {
      accion: 'FICHADA_APROBADA', entidad: 'fichadas', entidadId: fichadaId,
      actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
      detalle: { motivo, legajoAfectado: String(existente.legajo || '') }
    });
    if (!aud.ok) {
      // No se pudo auditar: se REVIERTE la validacion (fail-closed) para que
      // NUNCA quede una fichada validada sin su registro en la bitacora.
      let revertida = true;
      try { const rv = await patchSA(`fichadas/${fichadaId}`, previoVal); revertida = rv.ok; } catch (_) { revertida = false; }
      return json({
        error: revertida
          ? 'La validacion NO se aplico: no se pudo registrar la auditoria obligatoria. Reintenta en unos segundos.'
          : 'ATENCION: la auditoria fallo y ademas no se pudo revertir la validacion. Revisa la fichada manualmente.',
        auditoria: aud, revertida
      }, 502, origin);
    }
    return json({ ok: true, fichadaId, validada: true, auditoria: aud }, 200, origin);
  }

  // --- ATENDER / ANULAR PANICO ---
  if (accion === 'atenderPanico') {
    const panicoId = String(body.panicoId || '').trim();
    if (panicoId && !esClaveRtdbSegura(panicoId)) return json({ error: 'panicoId invalido (clave RTDB no segura)' }, 422, origin); // [#1] anti path injection
    const estado = String(body.estado || 'ATENDIDO').trim().toUpperCase();
    const nota = String(body.nota || '').trim();
    if (!panicoId) return json({ error: 'falta panicoId' }, 422, origin);
    if (estado !== 'ATENDIDO' && estado !== 'ANULADO') return json({ error: 'estado invalido (ATENDIDO|ANULADO)' }, 422, origin);
    const existente = await fetch(`${RTDB}/panicos/${panicoId}.json`, authGet).then(r => r.json()).catch(() => null);
    if (!existente) return json({ error: 'panico inexistente' }, 404, origin);
    const patch = {
      estado,
      notaAtencion: nota,
      atendidoPor: adminLegajo || adminUid,
      atendidoPorUid: adminUid,
      timestampAtencion: { '.sv': 'timestamp' }
    };
    // Anulacion LOGICA: se marca anulado=true (ademas del estado) para que la UI
    // del panel siga ocultando el panico anulado (compat con admin.html, que
    // filtra por d.anulado === true). La evidencia se conserva en la base.
    if (estado === 'ANULADO') {
      patch.anulado = true;
      patch.motivoAnulacion = nota;
      patch.anuladoPor = adminLegajo || adminUid;
      patch.anuladoPorUid = adminUid;
      patch.timestampAnulacion = { '.sv': 'timestamp' };
    }
    // Punto 5: auditoria OBLIGATORIA tambien para el panico. Estado previo para revertir.
    const previoPan = {};
    for (const k of Object.keys(patch)) previoPan[k] = (existente && k in existente) ? existente[k] : null;
    const res = await patchSA(`panicos/${panicoId}`, patch);
    if (!res.ok) { const t = await res.text().catch(() => ''); return json({ error: 'no se pudo actualizar el panico: HTTP ' + res.status + ' ' + t }, 502, origin); }
    const aud = await auditarSAConReintentos(RTDB, accessToken, {
      accion: estado === 'ANULADO' ? 'PANICO_ANULADO' : 'PANICO_ATENDIDO', entidad: 'panicos', entidadId: panicoId,
      actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
      detalle: { estado, nota, legajoAfectado: String(existente.legajo || '') }
    });
    if (!aud.ok) {
      // No se pudo auditar: se REVIERTE el cambio de estado del panico (fail-closed).
      let revertido = true;
      try { const rv = await patchSA(`panicos/${panicoId}`, previoPan); revertido = rv.ok; } catch (_) { revertido = false; }
      return json({
        error: revertido
          ? 'La accion sobre el panico NO se aplico: no se pudo registrar la auditoria obligatoria. Reintenta en unos segundos.'
          : 'ATENCION: la auditoria fallo y ademas no se pudo revertir el cambio del panico. Revisa el registro manualmente.',
        auditoria: aud, revertido
      }, 502, origin);
    }
    return json({ ok: true, panicoId, estado, auditoria: aud }, 200, origin);
  }

  // --- AUDITAR EVENTO MANUAL (admin registra un evento en la bitacora) ---
  if (accion === 'auditarEvento') {
    const evAccion = String(body.eventoAccion || '').trim();
    if (!evAccion) return json({ error: 'falta eventoAccion' }, 422, origin);
    const aud = await auditarSA(RTDB, accessToken, {
      accion: evAccion,
      entidad: String(body.entidad || 'manual'),
      entidadId: String(body.entidadId || ''),
      actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
      detalle: (body.detalle && typeof body.detalle === 'object') ? body.detalle : { texto: String(body.detalle || '') }
    });
    if (!aud.ok) return json({ error: 'no se pudo registrar la auditoria', detalle: aud }, 502, origin);
    return json({ ok: true, auditoria: aud }, 200, origin);
  }

  // ============================================================================
  //  GESTION DE DISPOSITIVOS OFFLINE (Fase 3, aditivo)
  //  El padron dispositivos/{deviceId} = { activo, secreto, nombre, legajos[] }
  //  vive bajo reglas SA-only; el panel NUNCA escribe/lee directo. Todo pasa
  //  por aca (idToken + rol admin ya verificados arriba). El 'secreto' HMAC se
  //  genera en el servidor y se DEVUELVE al operador UNA sola vez (alta/rotacion)
  //  para provisionarlo en el dispositivo; nunca se expone en el listado ni se
  //  registra en la auditoria.
  // ----------------------------------------------------------------------------
  const putSA = (path, valor) => fetch(`${RTDB}/${path}.json`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
    body: JSON.stringify(valor)
  });
  const deleteSA = (path) => fetch(`${RTDB}/${path}.json`, {
    method: 'DELETE', headers: { Authorization: 'Bearer ' + accessToken }
  });
  const generarSecretoHex = () => {
    const b = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
  };
  const normalizarLegajos = (v) => {
    if (!Array.isArray(v)) return null;
    const out = v.map(x => String(x).trim()).filter(Boolean);
    return out.length ? Array.from(new Set(out)) : null;
  };

  // --- LISTAR DISPOSITIVOS (nunca devuelve el secreto) ---
  if (accion === 'listarDispositivos') {
    const todos = await fetch(`${RTDB}/dispositivos.json`, authGet).then(r => r.json()).catch(() => null);
    const lista = [];
    if (todos && typeof todos === 'object') {
      for (const [id, d] of Object.entries(todos)) {
        if (!d || typeof d !== 'object') continue;
        lista.push({
          deviceId: id,
          nombre: d.nombre || '',
          activo: d.activo === true,
          legajos: Array.isArray(d.legajos) ? d.legajos.map(String) : null,
          tieneSecreto: !!d.secreto,
          creado: d.creado || null,
          actualizado: d.actualizado || null
        });
      }
    }
    lista.sort((a, b) => String(b.creado || '').localeCompare(String(a.creado || '')));
    return json({ ok: true, dispositivos: lista }, 200, origin);
  }

  // --- CREAR DISPOSITIVO (genera deviceId + secreto; devuelve el secreto UNA vez) ---
  if (accion === 'crearDispositivo') {
    const nombre = String(body.nombre || '').trim();
    if (!nombre) return json({ error: 'falta nombre del dispositivo' }, 422, origin);
    const legajos = normalizarLegajos(body.legajos);
    const deviceId = (typeof crypto.randomUUID === 'function')
      ? crypto.randomUUID()
      : generarSecretoHex().slice(0, 32);
    const secreto = generarSecretoHex();
    const nowIso = new Date().toISOString();
    const registro = { activo: true, secreto, nombre, creado: nowIso, actualizado: nowIso, creadoPor: adminLegajo || adminUid };
    if (legajos) registro.legajos = legajos;
    const res = await putSA(`dispositivos/${encodeURIComponent(deviceId)}`, registro);
    if (!res.ok) { const t = await res.text().catch(() => ''); return json({ error: 'no se pudo crear el dispositivo: HTTP ' + res.status + ' ' + t }, 502, origin); }
    await auditarSA(RTDB, accessToken, {
      accion: 'DISPOSITIVO_CREADO', entidad: 'dispositivos', entidadId: deviceId,
      actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
      detalle: { nombre, legajos: legajos || 'todos' } // NUNCA el secreto
    });
    return json({ ok: true, deviceId, secreto, nombre, activo: true, legajos: legajos || null }, 200, origin);
  }

  // --- ACTUALIZAR DISPOSITIVO (nombre/activo/legajos; opcional rotar secreto) ---
  if (accion === 'actualizarDispositivo') {
    const deviceId = String(body.deviceId || '').trim();
    if (!deviceId) return json({ error: 'falta deviceId' }, 422, origin);
    const existente = await fetch(`${RTDB}/dispositivos/${encodeURIComponent(deviceId)}.json`, authGet).then(r => r.json()).catch(() => null);
    if (!existente || typeof existente !== 'object') return json({ error: 'dispositivo inexistente' }, 404, origin);
    const patch = { actualizado: new Date().toISOString() };
    if (typeof body.nombre === 'string' && body.nombre.trim()) patch.nombre = body.nombre.trim();
    if (typeof body.activo === 'boolean') patch.activo = body.activo;
    if (body.legajos !== undefined) {
      const legajos = normalizarLegajos(body.legajos);
      patch.legajos = legajos; // null => elimina la restriccion de padron
    }
    let secretoNuevo = null;
    if (body.rotarSecreto === true) { secretoNuevo = generarSecretoHex(); patch.secreto = secretoNuevo; }
    const res = await patchSA(`dispositivos/${encodeURIComponent(deviceId)}`, patch);
    if (!res.ok) { const t = await res.text().catch(() => ''); return json({ error: 'no se pudo actualizar: HTTP ' + res.status + ' ' + t }, 502, origin); }
    await auditarSA(RTDB, accessToken, {
      accion: secretoNuevo ? 'DISPOSITIVO_SECRETO_ROTADO' : 'DISPOSITIVO_ACTUALIZADO', entidad: 'dispositivos', entidadId: deviceId,
      actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
      detalle: { cambioNombre: patch.nombre !== undefined, cambioActivo: patch.activo !== undefined, cambioLegajos: body.legajos !== undefined, rotoSecreto: !!secretoNuevo } // NUNCA el secreto
    });
    const out = { ok: true, deviceId };
    if (secretoNuevo) out.secreto = secretoNuevo;
    return json(out, 200, origin);
  }

  // --- ELIMINAR DISPOSITIVO ---
  if (accion === 'eliminarDispositivo') {
    const deviceId = String(body.deviceId || '').trim();
    if (!deviceId) return json({ error: 'falta deviceId' }, 422, origin);
    const existente = await fetch(`${RTDB}/dispositivos/${encodeURIComponent(deviceId)}.json`, authGet).then(r => r.json()).catch(() => null);
    if (!existente) return json({ error: 'dispositivo inexistente' }, 404, origin);
    const res = await deleteSA(`dispositivos/${encodeURIComponent(deviceId)}`);
    if (!res.ok) { const t = await res.text().catch(() => ''); return json({ error: 'no se pudo eliminar: HTTP ' + res.status + ' ' + t }, 502, origin); }
    await auditarSA(RTDB, accessToken, {
      accion: 'DISPOSITIVO_ELIMINADO', entidad: 'dispositivos', entidadId: deviceId,
      actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
      detalle: { nombre: existente.nombre || '' }
    });
    return json({ ok: true, deviceId, eliminado: true }, 200, origin);
  }

  // --- ACTUALIZAR EMPLEADO (ATOMICO server-side): PIN + Auth + legajo + ficha ---
  // Consolida en UNA sola operacion lo que el panel hacia en 4 escrituras sueltas
  // (personal + credenciales + Auth + usuarios), cada una capaz de fallar por su
  // cuenta y dejar el acceso DESINCRONIZADO (PIN online != PIN offline, o legajo
  // de Auth != legajo de la ficha). Orden FAIL-FAST: primero Auth (lo mas dificil
  // de reconciliar); si Auth falla NO se toca la base y todo queda como estaba.
  // Si Auth queda OK, se aplican los PATCH a la RTDB (mismo proyecto, muy fiables)
  // y se REPORTA cualquier divergencia. El PIN/clave/email NUNCA se registra en
  // la auditoria: solo banderas booleanas + legajo anterior/nuevo.
  if (accion === 'actualizarEmpleado') {
    const uid = String(body.uid || '').trim();
    if (!uid) return json({ error: 'falta uid' }, 422, origin);
    if (!esClaveRtdbSegura(uid)) return json({ error: 'uid invalido (clave RTDB no segura)' }, 422, origin); // [#1] anti path injection
    const nuevaClave = body.nuevaClave;
    const nuevoEmail = body.nuevoEmail;
    if (nuevaClave !== undefined && (typeof nuevaClave !== 'string' || nuevaClave.length < 6)) return json({ error: 'la clave debe tener al menos 6 caracteres' }, 422, origin);
    if (nuevoEmail !== undefined && (typeof nuevoEmail !== 'string' || !/^[^@\s]+@[^@\s]+$/.test(nuevoEmail))) return json({ error: 'email invalido' }, 422, origin);

    // Estado anterior (para auditar el legajo previo sin depender del cliente).
    const personalPrev = await fetch(`${RTDB}/personal/${uid}.json`, authGet).then(r => r.json()).catch(() => null);
    const legajoPrev = personalPrev ? String(personalPrev.legajo || '').trim() : '';

    // 1) AUTH PRIMERO (fail-fast). Si falla, no se modifica NADA en la base.
    if (nuevaClave !== undefined || nuevoEmail !== undefined) {
      const payloadAuth = { localId: uid };
      if (nuevaClave !== undefined) payloadAuth.password = nuevaClave;
      if (nuevoEmail !== undefined) payloadAuth.email = nuevoEmail;
      const upd = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
        body: JSON.stringify(payloadAuth)
      });
      const updData = await upd.json().catch(() => ({}));
      if (!upd.ok) return json({ error: 'no se pudo actualizar el acceso (Auth): ' + ((updData.error && updData.error.message) || ('HTTP ' + upd.status)) + '. No se modifico ningun dato.' }, 502, origin);
    }

    // 2) PATCH a la RTDB (Auth ya quedo OK). Se acumulan las fallas para reportar.
    const fallas = [];

    // 2a) Ficha /personal: se fusionan los campos provistos y se PURGA cualquier
    //     credencial (texto/hash) que pudiera colarse en el nodo legible.
    if (body.personal && typeof body.personal === 'object') {
      const p = Object.assign({}, body.personal);
      if (p.legajo !== undefined) p.legajo = String(p.legajo).trim(); // legajo SIEMPRE string
      p.pin = null; p.pinHash = null; p.pinSalt = null; // la credencial nunca vive en /personal
      const rp = await patchSA(`personal/${uid}`, p);
      if (!rp.ok) { const t = await rp.text().catch(() => ''); fallas.push({ nodo: 'personal', status: rp.status, detalle: t }); }
    }

    // 2b) Credencial hasheada (PIN offline) en /credenciales (nodo protegido).
    //     El Worker NO recomputa el hash: usa el pinHash/pinSalt que envia el
    //     cliente (PBKDF2 identico), evitando divergencias de algoritmo.
    if (body.credencial && typeof body.credencial === 'object' && body.credencial.pinHash && body.credencial.pinSalt) {
      const rc = await patchSA(`credenciales/${uid}`, { pinHash: String(body.credencial.pinHash), pinSalt: String(body.credencial.pinSalt) });
      if (!rc.ok) { const t = await rc.text().catch(() => ''); fallas.push({ nodo: 'credenciales', status: rc.status, detalle: t }); }
    }

    // 2c) Identidad de acceso /usuarios (legajo + nombre; jamas toca el rol).
    if (body.usuario && typeof body.usuario === 'object') {
      const u = {};
      if (body.usuario.legajo !== undefined) u.legajo = String(body.usuario.legajo).trim();
      if (body.usuario.nombre !== undefined) u.nombre = String(body.usuario.nombre);
      if (Object.keys(u).length) {
        const ru = await patchSA(`usuarios/${uid}`, u);
        if (!ru.ok) { const t = await ru.text().catch(() => ''); fallas.push({ nodo: 'usuarios', status: ru.status, detalle: t }); }
      }
    }

    // 3) Auditoria (una sola entrada; SOLO banderas, jamas PIN ni email nuevo).
    const legajoNuevo = (body.personal && body.personal.legajo != null) ? String(body.personal.legajo).trim() : legajoPrev;
    //    [#5] Auditoria OBLIGATORIA con reintentos (absorbe fallos transitorios
    //    de red). Si aun asi NO se registra, el cambio queda marcado como
    //    inconsistente para que el admin lo revise, nunca se oculta.
    const aud = await auditarSAConReintentos(RTDB, accessToken, {
      accion: (nuevaClave !== undefined) ? ((nuevoEmail !== undefined) ? 'EMPLEADO_PIN_Y_LEGAJO_ACTUALIZADOS' : 'EMPLEADO_PIN_RESETEADO') : ((nuevoEmail !== undefined) ? 'EMPLEADO_LEGAJO_CAMBIADO' : 'EMPLEADO_EDITADO'),
      entidad: 'usuarios', entidadId: uid, actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
      detalle: {
        cambioPin: nuevaClave !== undefined,
        cambioEmail: nuevoEmail !== undefined,
        cambioCredencialOffline: !!(body.credencial && body.credencial.pinHash),
        legajoAnterior: legajoPrev, legajoNuevo,
        nodosConError: fallas.map(f => f.nodo)
      }
    }, 3);

    // 4) Resultado. Auth ya se aplico OK; si algun PATCH fallo o la auditoria no
    //    pudo registrarse, el estado quedo PARCIALMENTE aplicado -> se avisa
    //    (207) para reintentar, sin ocultarlo.
    const auditFallo = !aud.ok;
    if (fallas.length || auditFallo) {
      const motivos = [];
      if (fallas.length) motivos.push('fallaron escrituras en la base: ' + fallas.map(f => f.nodo).join(', '));
      if (auditFallo) motivos.push('no se pudo registrar la auditoria del cambio');
      return json({ ok: false, uid, inconsistente: true, error: 'El acceso (Auth) se actualizo, pero ' + motivos.join('; ') + '. Reintenta la edicion.', fallas, auditoria: aud }, 207, origin);
    }
    return json({ ok: true, uid, auditoria: aud }, 200, origin);
  }

  // --- DAR DE BAJA EMPLEADO (ATOMICO server-side): Auth + ficha + credenciales ---
  // Reemplaza la baja en 4 pasos del panel por UNA operacion. Orden FAIL-FAST:
  // primero se elimina la cuenta de Auth (si esto falla se ABORTA, para no dejar
  // una ficha borrada junto a una cuenta capaz de seguir autenticandose). Luego
  // se limpian /credenciales, /usuarios y /personal con la SA. modo:'INACTIVAR'
  // conserva la ficha marcandola INACTIVO (baja logica); por defecto la elimina.
  if (accion === 'darDeBajaEmpleado') {
    const uid = String(body.uid || '').trim();
    if (!uid) return json({ error: 'falta uid' }, 422, origin);
    if (!esClaveRtdbSegura(uid)) return json({ error: 'uid invalido (clave RTDB no segura)' }, 422, origin); // [#1] anti path injection
    const modo = String(body.modo || 'ELIMINAR').trim().toUpperCase();
    const personalPrev = await fetch(`${RTDB}/personal/${uid}.json`, authGet).then(r => r.json()).catch(() => null);
    const legajoAfectado = personalPrev ? String(personalPrev.legajo || '').trim() : '';

    // 1) [#5] AUDITORIA PRIMERO (hecho critico IRREVERSIBLE). Una baja no se
    //    puede deshacer, asi que la bitacora se escribe ANTES de tocar nada:
    //    si tras los reintentos no se registra, se ABORTA sin eliminar Auth ni
    //    datos (nunca se destruye un empleado sin su registro de auditoria).
    const aud = await auditarSAConReintentos(RTDB, accessToken, {
      accion: modo === 'INACTIVAR' ? 'EMPLEADO_INACTIVADO' : 'EMPLEADO_ELIMINADO',
      entidad: 'usuarios', entidadId: uid, actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
      detalle: { modo, legajoAfectado, authEliminada: true }
    }, 3);
    if (!aud.ok) {
      return json({ error: 'No se pudo registrar la auditoria de la baja tras varios intentos; no se elimino ni modifico nada. Reintenta en un momento.' }, 502, origin);
    }

    // 2) AUTH: eliminar la cuenta (fail-fast). Se TOLERA "cuenta inexistente"
    //    (ya borrada): en ese caso se sigue con la limpieza de la base.
    const del = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
      body: JSON.stringify({ localId: uid })
    });
    const delData = await del.json().catch(() => ({}));
    const msgDel = (delData.error && delData.error.message) || '';
    if (!del.ok && !/USER_NOT_FOUND|EMAIL_NOT_FOUND/i.test(msgDel)) {
      // La baja NO ocurrio: compensamos la bitacora para no dejar un registro de
      // eliminacion que en realidad no se aplico (best-effort).
      await auditarSAConReintentos(RTDB, accessToken, {
        accion: 'EMPLEADO_BAJA_ABORTADA', entidad: 'usuarios', entidadId: uid,
        actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
        detalle: { modo, legajoAfectado, motivo: 'fallo al eliminar la cuenta de Auth' }
      }, 2);
      return json({ error: 'no se pudo eliminar el acceso (Auth): ' + (msgDel || ('HTTP ' + del.status)) + '. No se modifico la ficha.' }, 502, origin);
    }

    // 3) Limpieza en la base (Auth ya no puede autenticar). Best-effort + reporte.
    //    Un 404 se considera exito (el nodo ya no existia).
    const fallas = [];
    const rc = await deleteSA(`credenciales/${uid}`);
    if (!rc.ok && rc.status !== 404) fallas.push('credenciales');
    const ru = await deleteSA(`usuarios/${uid}`);
    if (!ru.ok && ru.status !== 404) fallas.push('usuarios');
    if (modo === 'INACTIVAR') {
      const rp = await patchSA(`personal/${uid}`, { estado: 'INACTIVO', bajaEn: { '.sv': 'timestamp' }, pin: null, pinHash: null, pinSalt: null });
      if (!rp.ok) fallas.push('personal');
    } else {
      const rp = await deleteSA(`personal/${uid}`);
      if (!rp.ok && rp.status !== 404) fallas.push('personal');
    }

    if (fallas.length) {
      return json({ ok: false, uid, inconsistente: true, error: 'El acceso (Auth) se dio de baja, pero fallaron limpiezas en: ' + fallas.join(', ') + '. Reintenta.', fallas, auditoria: aud }, 207, origin);
    }
    return json({ ok: true, uid, baja: true, modo, auditoria: aud }, 200, origin);
  }

  // --- CREAR DATOS DE EMPLEADO (ALTA ATOMICA server-side) [#4] ---
  // El panel crea la cuenta de Auth (app secundaria) y delega AQUI la escritura
  // de /personal + /credenciales + /usuarios (con rol) para el uid recien creado.
  // El cliente ya NO escribe esos nodos (las Reglas los tienen en .write:false).
  // Orden ATOMICO con auditoria obligatoria: se escriben los 3 nodos, se audita
  // con reintentos y, si algo falla (nodo o bitacora), se REVIERTE TODO -incluida
  // la cuenta de Auth- para no dejar ni un alta a medias ni un acceso sin ficha.
  if (accion === 'crearEmpleadoDatos') {
    const uid = String(body.uid || '').trim();
    if (!uid) return json({ error: 'falta uid' }, 422, origin);
    if (!esClaveRtdbSegura(uid)) return json({ error: 'uid invalido (clave RTDB no segura)' }, 422, origin); // [#1] anti path injection
    const pIn = (body.personal && typeof body.personal === 'object') ? body.personal : null;
    const uIn = (body.usuario && typeof body.usuario === 'object') ? body.usuario : null;
    const cIn = (body.credencial && typeof body.credencial === 'object') ? body.credencial : null;
    if (!pIn) return json({ error: 'falta la ficha de personal' }, 422, origin);
    if (!uIn || uIn.legajo === undefined) return json({ error: 'falta la identidad (usuario.legajo)' }, 422, origin);

    const legajo = String(uIn.legajo).trim();
    const rolesValidos = ['empleado', 'supervisor', 'admin'];
    const rolNuevo = rolesValidos.includes(String(uIn.rol || '').trim()) ? String(uIn.rol).trim() : 'empleado';

    // Ficha /personal saneada: legajo SIEMPRE string y SIN credencial en el nodo
    // legible (el PIN hasheado vive solo en /credenciales).
    const ficha = Object.assign({}, pIn);
    ficha.legajo = legajo;
    ficha.pin = null; ficha.pinHash = null; ficha.pinSalt = null;

    // Deshace TODO (datos + cuenta de Auth) para que el alta sea 'todo o nada' y
    // el legajo quede libre para reintentar sin colisiones.
    const revertirAlta = async (motivo) => {
      try { await deleteSA(`personal/${uid}`); } catch (_) {}
      try { await deleteSA(`credenciales/${uid}`); } catch (_) {}
      try { await deleteSA(`usuarios/${uid}`); } catch (_) {}
      try {
        await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:delete`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
          body: JSON.stringify({ localId: uid })
        });
      } catch (_) {}
      return json({ error: motivo + ' Se revirtio el alta por completo (cuenta y datos); podes volver a intentarlo.' }, 502, origin);
    };

    // [PLAN] CANDADO DURO DE CUPO DE VIGILADORES (backstop autoritativo).
    //   El cliente ya crea la cuenta de Auth (app secundaria) ANTES de llamar
    //   aqui; por eso, si el plan no permite el alta, se BORRA esa cuenta recien
    //   creada para no dejar un acceso huerfano, y se rechaza. Los 3 nodos de
    //   datos todavia NO se escribieron en este punto, asi que solo hay que
    //   limpiar Auth. Este chequeo NO se puede saltear desde el navegador.
    const rechazarPorPlan = async (msg) => {
      try {
        await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:delete`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
          body: JSON.stringify({ localId: uid })
        });
      } catch (_) {}
      return json({ error: msg, limite: true }, 409, origin);
    };
    const planAlta = await leerPlanSA(RTDB, accessToken);
    if (planAlta.estado === 'suspendido') {
      return await rechazarPorPlan('La cuenta esta suspendida por el proveedor del servicio. No se pueden dar de alta vigiladores. Contacta al proveedor.');
    }
    if (planAlta.maxVigiladores > 0) {
      const usadosVig = await contarHijosSA(RTDB, accessToken, 'personal');
      if (usadosVig >= planAlta.maxVigiladores) {
        return await rechazarPorPlan('Limite del plan alcanzado: tu plan "' + planAlta.nombre + '" permite hasta ' + planAlta.maxVigiladores + ' vigiladores y ya hay ' + usadosVig + '. Para sumar mas, actualiza tu plan.');
      }
    }

    // [PLAN] CANDADO DURO DE FUNCION "roles y supervision". Si el plan no la
    // incluye, solo se permiten vigiladores (rol 'empleado'); crear admin o
    // supervisor queda bloqueado en el servidor (no se puede saltear).
    if ((rolNuevo === 'admin' || rolNuevo === 'supervisor') && !(planAlta.funciones && planAlta.funciones.rolesSupervision)) {
      return await rechazarPorPlan('Tu plan "' + planAlta.nombre + '" no incluye "Roles y supervision". Solo podes dar de alta vigiladores. Para crear administradores o supervisores, actualiza tu plan.');
    }

    // 1) Escritura de los 3 nodos (PUT: alta limpia, sin restos previos).
    const fallas = [];
    const rp = await putSA(`personal/${uid}`, ficha);
    if (!rp.ok) fallas.push('personal');
    if (cIn && cIn.pinHash && cIn.pinSalt) {
      const rc = await putSA(`credenciales/${uid}`, { pinHash: String(cIn.pinHash), pinSalt: String(cIn.pinSalt) });
      if (!rc.ok) fallas.push('credenciales');
    }
    const ru = await putSA(`usuarios/${uid}`, { legajo, rol: rolNuevo });
    if (!ru.ok) fallas.push('usuarios');
    if (fallas.length) {
      return await revertirAlta('No se pudieron escribir los datos del empleado (' + fallas.join(', ') + ').');
    }

    // 2) [#5] Auditoria OBLIGATORIA con reintentos. Si no se registra, se revierte
    //    el alta: nunca queda un empleado creado sin su registro en la bitacora.
    const aud = await auditarSAConReintentos(RTDB, accessToken, {
      accion: 'EMPLEADO_CREADO', entidad: 'usuarios', entidadId: uid,
      actorUid: adminUid, actorLegajo: adminLegajo, rol: 'admin',
      detalle: { legajo, rolAsignado: rolNuevo, tienePin: !!(cIn && cIn.pinHash) }
    }, 3);
    if (!aud.ok) {
      return await revertirAlta('El alta no pudo registrarse en la auditoria.');
    }

    return json({ ok: true, uid, legajo, rol: rolNuevo, auditoria: aud }, 200, origin);
  }

  // ----------------------------------------------------------------
  //  [PLAN] VERIFICAR CUPO antes de un alta (vigilador u objetivo).
  //  Lo usa el panel admin para avisar ANTES de intentar crear y para pintar
  //  los indicadores "X / maximo". El candado DURO vive en crearEmpleadoDatos
  //  (vigiladores) y aqui mismo via la cuenta real (los objetivos se chequean
  //  tambien server-side desde el cliente con esta misma accion antes del POST).
  // ----------------------------------------------------------------
  if (accion === 'verificarCupo') {
    const plan = await leerPlanSA(RTDB, accessToken);
    const [vig, obj] = await Promise.all([
      contarHijosSA(RTDB, accessToken, 'personal'),
      contarHijosSA(RTDB, accessToken, 'objetivos')
    ]);
    const tipo = String(body.tipo || '').trim().toLowerCase();
    const suspendido = plan.estado === 'suspendido';
    let disponible = true, usados = 0, maximo = 0;
    if (tipo === 'objetivo') { usados = obj; maximo = plan.maxObjetivos; }
    else { usados = vig; maximo = plan.maxVigiladores; } // 'empleado'/'vigilador' por defecto
    if (suspendido) disponible = false;
    else if (maximo > 0 && usados >= maximo) disponible = false;
    return json({
      ok: true,
      disponible,
      suspendido,
      tipo: (tipo === 'objetivo') ? 'objetivo' : 'vigilador',
      usados, maximo,
      plan: { nombre: plan.nombre, maxVigiladores: plan.maxVigiladores, maxObjetivos: plan.maxObjetivos, estado: plan.estado, funciones: plan.funciones },
      uso: { vigiladores: vig, objetivos: obj }
    }, 200, origin);
  }

  return json({ error: 'accion administrativa desconocida' }, 400, origin);
}

// --- Verifica el idToken de Firebase del solicitante (firma + iss/aud/exp) ---
async function verificarIdToken(idToken, projectId) {
  const [h, p, s] = String(idToken).split('.');
  if (!h || !p || !s) throw new Error('token malformado');
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));
  const now = Math.floor(Date.now() / 1000);
  if (payload.aud !== projectId) throw new Error('aud inválido');
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) throw new Error('iss inválido');
  if (!payload.exp || payload.exp < now) throw new Error('token expirado');
  if (!payload.sub) throw new Error('sin sub');
  const jwks = await (await fetch(JWK_URL)).json();
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid);
  if (!jwk) throw new Error('clave pública no encontrada');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(s), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) throw new Error('firma inválida');
  return payload; // payload.sub = uid del solicitante
}

// --- Firma un JWT con la service account y obtiene un access token OAuth2 ---
async function obtenerAccessToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT', kid: sa.private_key_id };
  const claim = { iss: sa.client_email, scope: SCOPES, aud: TOKEN_URL, iat: now, exp: now + 3600 };
  const unsigned = `${b64urlFromString(JSON.stringify(header))}.${b64urlFromString(JSON.stringify(claim))}`;
  const key = await crypto.subtle.importKey('pkcs8', pemToPkcs8(sa.private_key), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(unsigned)));
  const jwt = `${unsigned}.${b64urlFromBytes(sig)}`;
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: jwt }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error_description || data.error || ('HTTP ' + res.status));
  return data.access_token;
}

// --- Emite un CUSTOM TOKEN de Firebase firmado con la service account ---
// Lo consume el navegador con signInWithCustomToken(): asi, tras validar el PIN
// en el Worker, el cliente establece una sesion REAL del SDK (currentUser queda
// seteado) y la renovacion automatica de token sigue funcionando sin cambios.
// El custom token NO es el idToken: es un JWT de corta vida que el SDK canjea
// por un idToken/refreshToken propios.
async function crearCustomToken(sa, uid) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT', kid: sa.private_key_id };
  const claim = {
    iss: sa.client_email,
    sub: sa.client_email,
    aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat: now,
    exp: now + 3600,
    uid: String(uid)
  };
  const unsigned = `${b64urlFromString(JSON.stringify(header))}.${b64urlFromString(JSON.stringify(claim))}`;
  const key = await crypto.subtle.importKey('pkcs8', pemToPkcs8(sa.private_key), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(unsigned)));
  return `${unsigned}.${b64urlFromBytes(sig)}`;
}

// ===================================================================
//  FASE 1 - LOTE OFFLINE FIRMADO POR DISPOSITIVO (opt-in)
//  Permite subir fichadas creadas SIN conexion (login offline validado en el
//  dispositivo con hash local de PIN, se implementa en Fase 2/3). El Worker NO
//  confia en identidad autoafirmada: exige (a) que el modo offline este
//  habilitado globalmente, (b) una credencial de dispositivo (HMAC), y (c) para
//  cada fichada, que el authUid resuelva a un legajo real, que el legajo
//  pertenezca al padron del dispositivo y que pase objetivo + geocerca + GPS.
//
//  Contrato del request (accion:'ficharLoteOffline'):
//    {
//      accion: 'ficharLoteOffline',
//      deviceId:  '<id del dispositivo registrado>',
//      timestamp: <epoch ms del armado del lote>,
//      fichadas:  '<STRING JSON del array de fichadas, EXACTAMENTE lo firmado>',
//      firma:     '<HMAC-SHA256 hex de `${deviceId}.${timestamp}.${fichadas}`>'
//    }
//  La firma se computa sobre el STRING 'fichadas' tal cual viaja (sin re-serializar)
//  para evitar desajustes de canonicalizacion.
//
//  Registro del dispositivo en RTDB (lo provisiona el admin en Fase 3):
//    dispositivos/{deviceId} = {
//      activo:  true,
//      secreto: '<clave HMAC aleatoria>',      // solo la conoce el dispositivo
//      nombre:  'Tablet Objetivo X',
//      legajos: ['123','456']                   // opcional: padron permitido
//    }
//  Flag global (configuracionGlobal): offlineHabilitado === true. Por defecto
//  DESACTIVADO: si no esta en true, este endpoint responde 403.
// ===================================================================

// Verifica una firma HMAC-SHA256 (hex) en tiempo casi constante.
async function verificarFirmaDispositivo(secreto, mensaje, firmaHex) {
  try {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(secreto)),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(mensaje)));
    let hex = '';
    for (let i = 0; i < mac.length; i++) hex += mac[i].toString(16).padStart(2, '0');
    const a = hex.toLowerCase();
    const b = String(firmaHex || '').toLowerCase();
    if (!b || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  } catch (_) { return false; }
}

// Procesa UNA fichada offline: re-valida identidad, objetivo y geocerca y la crea
// de forma idempotente (Capa A/B). Nunca lanza: devuelve un resultado por fichada.
async function procesarFichadaOffline(f, ctx) {
  const { RTDB, accessToken, authGet, objetivos, radioGlobal, precisionMax, ventanaIdMs, legajosDispositivo, deviceId, ahoraRecepcionMs, ventanaLoteMs, skewFuturoMs } = ctx;
  const refCliente = String((f && (f.idEvento || f.fichadaId)) || '');
  try {
    const authUid = String((f && f.authUid) || '').trim();
    const legajoDeclarado = String((f && f.legajo) || '').trim();
    const tipo = String((f && f.tipo) || '').trim().toUpperCase();
    const lat = Number(f && f.latitud);
    const lng = Number(f && f.longitud);
    const nombreObjetivo = String((f && f.objetivo) || '').trim();
    const objetivoIdCliente = String((f && f.objetivoAutorizadoId) || '').trim();

    if (!authUid) return { ref: refCliente, rechazada: true, motivo: 'sin authUid' };
    if (tipo !== 'ENTRADA' && tipo !== 'SALIDA') return { ref: refCliente, rechazada: true, motivo: 'tipo invalido' };
    if (!Number.isFinite(lat) || !Number.isFinite(lng) || (lat === 0 && lng === 0)) return { ref: refCliente, rechazada: true, motivo: 'GPS invalido' };
    if (!nombreObjetivo) return { ref: refCliente, rechazada: true, motivo: 'objetivo requerido' };

    // Binding de identidad: el authUid DEBE existir y su legajo es el autoritativo.
    const usuario = await fetch(`${RTDB}/usuarios/${authUid}.json`, authGet).then(r => r.json()).catch(() => null);
    const legajoReal = (usuario && usuario.legajo != null) ? String(usuario.legajo).trim() : '';
    if (!legajoReal) return { ref: refCliente, rechazada: true, motivo: 'authUid sin legajo' };
    if (legajoDeclarado && legajoDeclarado !== legajoReal) return { ref: refCliente, rechazada: true, motivo: 'legajo no coincide con authUid' };

    // El legajo debe pertenecer al padron del dispositivo (si esta definido).
    if (legajosDispositivo && !legajosDispositivo.includes(legajoReal)) {
      return { ref: refCliente, rechazada: true, motivo: 'legajo fuera del padron del dispositivo' };
    }

    // Ficha del vigilador (estado + objetivos autorizados).
    const personalResp = await fetch(`${RTDB}/personal.json?orderBy=${encodeURIComponent('"legajo"')}&equalTo=${encodeURIComponent('"' + legajoReal + '"')}`, authGet).then(r => r.json()).catch(() => null);
    const personal = (personalResp && typeof personalResp === 'object') ? Object.values(personalResp)[0] : null;
    if (!personal) return { ref: refCliente, rechazada: true, motivo: 'vigilador inexistente' };
    if (String(personal.estado || '').toUpperCase() === 'INACTIVO') return { ref: refCliente, rechazada: true, motivo: 'vigilador inactivo' };
    const autorizados = idsObjetivosAsignados(personal);

    // Objetivo (por id o por nombre) + coordenadas + radio.
    let entry = null;
    if (objetivoIdCliente && objetivos[objetivoIdCliente]) entry = [objetivoIdCliente, objetivos[objetivoIdCliente]];
    if (!entry) {
      const busc = nombreObjetivo.toLowerCase();
      entry = Object.entries(objetivos).find(([id, it]) => String((it && (it.nombre || it.codigo)) || id).trim().toLowerCase() === busc) || null;
    }
    if (!entry) return { ref: refCliente, rechazada: true, motivo: 'objetivo inexistente' };
    const objIdReal = entry[0];
    const obj = entry[1];
    if (!autorizados.includes(String(objIdReal))) return { ref: refCliente, rechazada: true, motivo: 'objetivo no autorizado' };
    const laObj = latObjetivo(obj);
    const loObj = lngObjetivo(obj);
    if (!Number.isFinite(laObj) || !Number.isFinite(loObj) || (laObj === 0 && loObj === 0)) return { ref: refCliente, rechazada: true, motivo: 'objetivo sin coordenadas' };
    const radio = radioObjetivoMetros(obj, radioGlobal);
    const dist = distanciaMetros(lat, lng, laObj, loObj);

    // Precision GPS (si esta configurada).
    const precisionGPS = Number(f.precisionGPSMetros);
    if (precisionMax > 0 && Number.isFinite(precisionGPS) && precisionGPS > precisionMax) {
      await auditarSA(RTDB, accessToken, { accion: 'FICHADA_OFFLINE_RECHAZADA', entidad: 'fichadas', entidadId: refCliente, actorUid: authUid, actorLegajo: legajoReal, rol: 'vigilador', detalle: { motivo: 'PRECISION_GPS', deviceId, precisionGPSMetros: Math.round(precisionGPS), precisionMaximaMetros: Math.round(precisionMax) } });
      return { ref: refCliente, rechazada: true, motivo: 'precision GPS insuficiente' };
    }
    // Geocerca (fail-closed).
    if (dist > radio) {
      await auditarSA(RTDB, accessToken, { accion: 'FICHADA_OFFLINE_RECHAZADA', entidad: 'fichadas', entidadId: refCliente, actorUid: authUid, actorLegajo: legajoReal, rol: 'vigilador', detalle: { motivo: 'FUERA_DE_RADIO', deviceId, distanciaMetros: Math.round(dist), radioPermitidoMetros: Math.round(radio) } });
      return { ref: refCliente, rechazada: true, motivo: 'fuera del radio' };
    }

    // idEvento estable (Capa A). Fallback deterministico si no viene.
    let fichadaId = String(f.idEvento || f.fichadaId || '').trim();
    if (!fichadaId) fichadaId = await derivarIdEvento(legajoReal, tipo, String(objIdReal), Date.now(), ventanaIdMs);
    if (!esClaveRtdbSegura(fichadaId)) return { ref: refCliente, rechazada: true, motivo: 'idEvento/fichadaId invalido (clave RTDB no segura)' }; // [#1] anti path injection

    // [#5] Hora del FICHAJE offline (estimacion del dispositivo). El reloj del
    // dispositivo NO es confiable: el ancla temporal real es la RECEPCION del lote
    // en el servidor. Se clampea cada marca a la ventana
    // [recepcion - ventanaLote, recepcion + skew] y se RECHAZAN las que caen fuera:
    // ni futuras (reloj adelantado / manipulado) ni mas viejas que la ventana de
    // lote permitida. Asi una marca con fecha arbitraria no puede alterar la
    // cronologia (y, con ella, la secuencia de jornada).
    let tFichaje = Number(f.timestampServidorEstimado) || Number(f.timestampLocal) || (f.fechaHoraDispositivo ? Date.parse(f.fechaHoraDispositivo) : NaN);
    const limiteViejo = ahoraRecepcionMs - ventanaLoteMs;
    const limiteFuturo = ahoraRecepcionMs + skewFuturoMs;
    if (Number.isFinite(tFichaje)) {
      if (tFichaje > limiteFuturo) {
        await auditarSA(RTDB, accessToken, { accion: 'FICHADA_OFFLINE_RECHAZADA', entidad: 'fichadas', entidadId: refCliente, actorUid: authUid, actorLegajo: legajoReal, rol: 'vigilador', detalle: { motivo: 'MARCA_FUTURA', tipo, deviceId, marcaMs: tFichaje, limiteFuturoMs: limiteFuturo } });
        return { ref: refCliente, rechazada: true, motivo: 'marca con fecha futura (reloj del dispositivo)' };
      }
      if (tFichaje < limiteViejo) {
        await auditarSA(RTDB, accessToken, { accion: 'FICHADA_OFFLINE_RECHAZADA', entidad: 'fichadas', entidadId: refCliente, actorUid: authUid, actorLegajo: legajoReal, rol: 'vigilador', detalle: { motivo: 'MARCA_VENCIDA', tipo, deviceId, marcaMs: tFichaje, limiteViejoMs: limiteViejo } });
        return { ref: refCliente, rechazada: true, motivo: 'marca mas vieja que la ventana de lote permitida' };
      }
    } else {
      // Sin hora utilizable del dispositivo: se ancla a la recepcion del lote.
      tFichaje = ahoraRecepcionMs;
    }

    // [#7] Maquina de estados ENTRADA -> SALIDA tambien en el lote offline, con
    // RESERVA ATOMICA (compare-and-set por ETag) ANTES de crear la fichada: un
    // dispositivo firmado no puede sincronizar una SALIDA sin ENTRADA activa ni una
    // ENTRADA duplicada, y validacion + avance ocurren sin ventana de carrera. El
    // lote se procesa en orden cronologico (ver manejarLoteOffline) y la reserva no
    // retrocede el estado ante marcas mas viejas, preservando la monotonia.
    const reserva = await reservarTransicionJornada(RTDB, accessToken, legajoReal, tipo, fichadaId, tFichaje);
    if (!reserva.ok) {
      await auditarSA(RTDB, accessToken, { accion: 'FICHADA_OFFLINE_RECHAZADA', entidad: 'fichadas', entidadId: refCliente, actorUid: authUid, actorLegajo: legajoReal, rol: 'vigilador', detalle: { motivo: reserva.motivo, tipo, deviceId } });
      return { ref: refCliente, rechazada: true, motivo: reserva.mensaje };
    }

    const registro = Object.assign({}, f, {
      fichadaId, idEvento: fichadaId, legajo: legajoReal, authUid,
      objetivo: String((obj && (obj.nombre || obj.codigo)) || nombreObjetivo),
      objetivoAutorizadoId: String(objIdReal),
      tipo, latitud: lat, longitud: lng, latitudObjetivo: laObj, longitudObjetivo: loObj,
      distanciaAlObjetivoMetros: Math.round(dist), radioPermitidoMetros: Math.round(radio),
      ubicacionValidada: true, ubicacionValidadaServidor: true, validadaPorWorker: true,
      origenOffline: true, dispositivoOrigen: deviceId, sincronizadoDesdeOffline: true,
      requiereRevisionManual: true,          // la identidad facial no se cotejo online
      horaVerificadaServidor: false,
      // [#4] Procedencia del tiempo EXPLICITA y con NOMBRE HONESTO. En una fichada
      // offline NO existe hora de servidor del momento del fichaje: lo que hay es
      // la ESTIMACION del dispositivo, ya CLAMPEADA a la ventana del lote. Se guarda
      // en 'timestampEstimadoDispositivo' (no 'timestampServidor'). El unico sello
      // de SERVIDOR real en una fichada offline es 'timestampArriboServidor' (hora
      // de RECEPCION). 'horaVerificadaServidor' = false lo refuerza.
      origenTiempo: 'dispositivo-clampeado',
      timestampServidor: null,                      // [#4] jamas un valor de dispositivo bajo este nombre
      timestampEstimadoDispositivo: tFichaje,       // estimacion del dispositivo, clampeada a la ventana del lote
      timestampArriboServidor: { '.sv': 'timestamp' } // unico sello de servidor real (hora de recepcion)
    });

    const resultado = await crearFichadaAtomica(RTDB, accessToken, fichadaId, registro);
    if (resultado.duplicado) return { ref: refCliente, fichadaId, duplicada: true };

    await auditarSA(RTDB, accessToken, {
      accion: 'FICHADA_CREADA_OFFLINE', entidad: 'fichadas', entidadId: fichadaId,
      actorUid: authUid, actorLegajo: legajoReal, rol: 'vigilador',
      detalle: { tipo, objetivo: registro.objetivo, deviceId, distanciaMetros: Math.round(dist), radioPermitidoMetros: Math.round(radio), fechaHoraDispositivo: f.fechaHoraDispositivo || null }
    });
    return { ref: refCliente, fichadaId, creada: true };
  } catch (e) {
    return { ref: refCliente, rechazada: true, motivo: 'error interno: ' + String((e && e.message) || e) };
  }
}

async function manejarLoteOffline(body, env, sa, projectId, origin) {
  const deviceId = String((body && body.deviceId) || '').trim();
  const timestamp = Number(body && body.timestamp);
  const fichadasStr = (body && typeof body.fichadas === 'string') ? body.fichadas : '';
  const firma = String((body && body.firma) || '').trim();
  if (!deviceId || !Number.isFinite(timestamp) || !fichadasStr || !firma) {
    return json({ error: 'lote offline invalido (faltan deviceId/timestamp/fichadas/firma)' }, 400, origin);
  }

  let accessToken;
  try { accessToken = await obtenerAccessToken(sa); }
  catch (e) { return json({ error: 'no se pudo autenticar el servidor: ' + e.message }, 500, origin); }
  const RTDB = env.RTDB_URL;
  const authGet = { headers: { Authorization: 'Bearer ' + accessToken } };

  // (a) Flag global de modo offline (opt-in por cliente). Default: DESACTIVADO.
  const cfg = await fetch(`${RTDB}/configuracionGlobal.json`, authGet).then(r => r.json()).catch(() => null);
  if (!(cfg && cfg.offlineHabilitado === true)) {
    return json({ error: 'modo offline no habilitado', motivo: 'OFFLINE_DESHABILITADO' }, 403, origin);
  }

  // (a-plan) [PLAN] CANDADO DURO DE FUNCION "modo offline": aunque el flag local
  // este encendido, si el plan contratado no incluye modoOffline el servidor
  // rechaza el lote. No se puede saltear desde el dispositivo.
  const planOffline = await leerPlanSA(RTDB, accessToken);
  if (planOffline.estado === 'suspendido' || !(planOffline.funciones && planOffline.funciones.modoOffline)) {
    return json({ error: 'tu plan no incluye el modo offline autorizado', motivo: 'OFFLINE_NO_EN_PLAN' }, 403, origin);
  }

  // (b) Dispositivo registrado + credencial HMAC.
  const disp = await fetch(`${RTDB}/dispositivos/${encodeURIComponent(deviceId)}.json`, authGet).then(r => r.json()).catch(() => null);
  if (!disp || disp.activo !== true || !disp.secreto) {
    return json({ error: 'dispositivo no autorizado o inactivo', motivo: 'DISPOSITIVO_INVALIDO' }, 403, origin);
  }
  const mensaje = `${deviceId}.${timestamp}.${fichadasStr}`;
  if (!(await verificarFirmaDispositivo(disp.secreto, mensaje, firma))) {
    return json({ error: 'firma del lote invalida', motivo: 'FIRMA_INVALIDA' }, 401, origin);
  }

  // Frescura del lote (anti-replay de lotes viejos). Ventana configurable (horas).
  const ventanaLoteMs = (() => { const v = Number(cfg.ventanaLoteOfflineHoras); return (Number.isFinite(v) && v > 0) ? v * 3600000 : 7 * 24 * 3600000; })();
  if (Math.abs(Date.now() - timestamp) > ventanaLoteMs) {
    return json({ error: 'lote offline vencido', motivo: 'LOTE_VENCIDO' }, 401, origin);
  }

  // Fichadas firmadas.
  let fichadas;
  try { fichadas = JSON.parse(fichadasStr); } catch (_) { return json({ error: 'fichadas del lote ilegibles' }, 400, origin); }
  if (!Array.isArray(fichadas) || fichadas.length === 0) return json({ error: 'lote sin fichadas' }, 400, origin);
  if (fichadas.length > 200) return json({ error: 'lote demasiado grande (max 200)' }, 413, origin);

  // Contexto compartido (se lee una sola vez).
  const legajosDispositivo = Array.isArray(disp.legajos) ? disp.legajos.map(x => String(x).trim()) : null;
  const objetivos = await fetch(`${RTDB}/objetivos.json`, authGet).then(r => r.json()).catch(() => null) || {};
  let radioGlobal = 100; { const rg = Number(cfg.radioFichajeMetros); if (Number.isFinite(rg) && rg > 0) radioGlobal = rg; }
  let precisionMax = 0; { const pm = Number(cfg.precisionMaximaMetros); if (Number.isFinite(pm) && pm > 0) precisionMax = pm; }
  const ventanaIdMs = (() => { const v = Number(cfg.ventanaIdEventoSegundos); return (Number.isFinite(v) && v > 0) ? v * 1000 : 120000; })();
  // [#5] Tolerancia de adelanto de reloj del dispositivo (clock skew) al clampear
  // las marcas offline. Configurable; default 5 minutos.
  const skewFuturoMs = (() => { const v = Number(cfg.skewRelojOfflineSegundos); return (Number.isFinite(v) && v >= 0) ? v * 1000 : 5 * 60000; })();
  // [#5] Momento de recepcion del lote en el servidor: es el ancla temporal real.
  // Cada marca offline se clampea a la ventana [recepcion - ventanaLote, recepcion + skew].
  const ahoraRecepcionMs = Date.now();
  const ctx = { RTDB, accessToken, authGet, objetivos, radioGlobal, precisionMax, ventanaIdMs, legajosDispositivo, deviceId, ahoraRecepcionMs, ventanaLoteMs, skewFuturoMs };

  // Orden cronologico del lote: garantiza que la ENTRADA se procese antes que su
  // SALIDA para que la maquina de estados valide la secuencia correctamente aun
  // si el cliente envio las fichadas desordenadas.
  fichadas.sort((a, b) => {
    const ta = Number((a && (a.timestampServidorEstimado || a.timestampLocal))) || ((a && a.fechaHoraDispositivo) ? Date.parse(a.fechaHoraDispositivo) : 0) || 0;
    const tb = Number((b && (b.timestampServidorEstimado || b.timestampLocal))) || ((b && b.fechaHoraDispositivo) ? Date.parse(b.fechaHoraDispositivo) : 0) || 0;
    return ta - tb;
  });

  const resultados = [];
  for (const f of fichadas) resultados.push(await procesarFichadaOffline(f, ctx));

  const creadas = resultados.filter(r => r.creada).length;
  const duplicadas = resultados.filter(r => r.duplicada).length;
  const rechazadas = resultados.filter(r => r.rechazada).length;
  return json({ ok: true, procesadas: resultados.length, creadas, duplicadas, rechazadas, resultados }, 200, origin);
}

// ===================================================================
//  LOGIN POR PIN CON BLOQUEO PERSISTENTE (anti fuerza bruta)
//  El login por PIN del vigilador antes iba DIRECTO del navegador a Firebase
//  Auth, salteando este Worker: por eso el rate-limit de arriba NO frenaba la
//  fuerza bruta al PIN (6 digitos = 1.000.000 de combinaciones). Este endpoint
//  convierte al Worker en el UNICO punto de entrada del login: cuenta los fallos
//  por legajo y por IP en /intentosLogin (nodo SA-only) y, superado el limite,
//  BLOQUEA temporalmente sin siquiera consultar a Firebase. El conteo vive en la
//  base (NO en memoria) para que sobreviva a la rotacion de instancias.
// ===================================================================
const LOGIN_MAX_FALLOS_LEGAJO = 5;              // fallos por legajo antes de bloquear
const LOGIN_MAX_FALLOS_IP     = 20;             // fallos por IP (varios legajos) antes de bloquear
const LOGIN_VENTANA_MS        = 15 * 60 * 1000; // ventana para contar fallos
const LOGIN_BLOQUEO_MS        = 15 * 60 * 1000; // duracion del bloqueo temporal

// Las claves de RTDB no admiten . # $ [ ] /  -> se sanitizan (la IP trae puntos).
function sanitizarClaveRTDB(s) { return String(s).replace(/[.#$\[\]\/]/g, '_'); }

// Lee el contador de intentos de una clave (legajo o ip) + su ETag (para CAS).
async function leerIntentoLogin(RTDB, token, clave) {
  const url = `${RTDB}/intentosLogin/${encodeURIComponent(sanitizarClaveRTDB(clave))}.json`;
  const res = await fetch(url, { headers: { Authorization: 'Bearer ' + token, 'X-Firebase-ETag': 'true' } });
  const etag = res.headers.get('ETag');
  const data = await res.json().catch(() => null);
  return { url, etag, data };
}

// Devuelve ms restantes de bloqueo (0 si no esta bloqueada la clave).
function estaBloqueado(data, ahoraMs) {
  const hasta = Number(data && data.bloqueadoHastaMs) || 0;
  return (hasta > ahoraMs) ? { bloqueado: true, restanteMs: hasta - ahoraMs } : { bloqueado: false, restanteMs: 0 };
}

// Registra UN fallo (compare-and-set por ETag). Reinicia la ventana si expiro;
// al alcanzar el maximo fija bloqueadoHastaMs. Reintenta ante carrera (412).
// Best-effort: un fallo del PUT no debe romper el flujo de login.
async function registrarFalloLogin(RTDB, token, clave, maxFallos, ahoraMs) {
  for (let i = 0; i < 3; i++) {
    const { url, etag, data } = await leerIntentoLogin(RTDB, token, clave);
    const ventanaViva = !!(data && Number(data.ventanaInicioMs) && (ahoraMs - Number(data.ventanaInicioMs) < LOGIN_VENTANA_MS));
    const fallos = (ventanaViva ? Number(data.fallos) || 0 : 0) + 1;
    const nuevo = {
      fallos,
      ventanaInicioMs: ventanaViva ? Number(data.ventanaInicioMs) : ahoraMs,
      ultimoFalloMs: ahoraMs
    };
    if (fallos >= maxFallos) nuevo.bloqueadoHastaMs = ahoraMs + LOGIN_BLOQUEO_MS;
    const put = await fetch(url, {
      method: 'PUT',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', 'if-match': etag || 'null_etag' },
      body: JSON.stringify(nuevo)
    });
    if (put.ok) return nuevo;
    if (put.status === 412) continue; // carrera: releer y reintentar
    return nuevo; // fallo del PUT: no romper el login por el contador
  }
  return null;
}

// Borra el contador de una clave (se llama tras un login exitoso).
async function resetearIntentoLogin(RTDB, token, clave) {
  try {
    await fetch(`${RTDB}/intentosLogin/${encodeURIComponent(sanitizarClaveRTDB(clave))}.json`,
      { method: 'DELETE', headers: { Authorization: 'Bearer ' + token } });
  } catch (_) { /* best-effort */ }
}

/**
 * LOGIN POR PIN (vigiladores) con bloqueo anti fuerza bruta.
 * El cliente ya NO inicia sesion directo contra Firebase: llama aqui con
 *   { accion:'loginPin', legajo, pin }   (o { email, pin|password }).
 * Flujo:
 *   1) Arma email/clave con la convencion de la app
 *      (legajo@vga.security24 / pin.padStart(6,'0')).
 *   2) Revisa el BLOQUEO persistente por legajo y por IP. Si esta bloqueado,
 *      responde 429 SIN consultar a Firebase (esto es lo que frena la fuerza
 *      bruta: el atacante no llega a Firebase).
 *   3) Valida el PIN contra Firebase Auth (REST signInWithPassword, Web API Key).
 *   4) Exito  -> resetea contadores y DEVUELVE un CUSTOM TOKEN de Firebase; el
 *                navegador lo canjea con signInWithCustomToken() para abrir una
 *                sesion real del SDK (currentUser) y la renovacion sigue igual.
 *   5) Fallo  -> suma un fallo a legajo e IP y responde 401 con intentos restantes
 *                (o 429 si ese fallo activo el bloqueo).
 * Nunca revela si el error fue "no existe" vs "PIN incorrecto": mensaje generico.
 * NOTA: este endpoint es la UNICA puerta de login de toda la app. Lo usan el
 *       vigilador (legajo + PIN) y tambien los paneles de admin y supervisor
 *       (correo/legajo + clave): todos pasan por aqui para heredar el bloqueo
 *       persistente. La separacion de roles se resuelve en el cliente DESPUES
 *       de abrir la sesion con el custom token.
 */
async function manejarLoginPin(body, env, sa, origin, ip) {
  const RTDB = env.RTDB_URL;
  const apiKey = env.FIREBASE_WEB_API_KEY;
  if (!apiKey) return json({ error: 'config del servidor incompleta (falta FIREBASE_WEB_API_KEY)' }, 500, origin);

  // 1) Email + clave segun la convencion de la app.
  const legajo = String((body && body.legajo) || '').trim();
  let email = String((body && body.email) || '').trim().toLowerCase();
  if (!email && legajo) email = `${legajo}@vga.security24`;
  const password = (body && typeof body.pin === 'string') ? body.pin.padStart(6, '0')
                 : (body && typeof body.password === 'string') ? body.password : '';
  if (!email || !password) return json({ error: 'faltan datos de acceso (legajo/pin)' }, 400, origin);

  const claveLegajo = 'legajo:' + (legajo || email);
  const claveIp = 'ip:' + (ip || 'desconocida');
  const ahora = Date.now();

  // 2) Access token de la service account (leer/escribir /intentosLogin).
  let saToken;
  try { saToken = await obtenerAccessToken(sa); }
  catch (e) { return json({ error: 'no se pudo autenticar el servidor: ' + e.message }, 500, origin); }

  // 2a) ¿Bloqueado por legajo o por IP? Si lo esta, NO se consulta a Firebase.
  const [regLeg, regIp] = await Promise.all([
    leerIntentoLogin(RTDB, saToken, claveLegajo),
    leerIntentoLogin(RTDB, saToken, claveIp)
  ]);
  const bLeg = estaBloqueado(regLeg.data, ahora);
  const bIp = estaBloqueado(regIp.data, ahora);
  if (bLeg.bloqueado || bIp.bloqueado) {
    const restanteMs = Math.max(bLeg.restanteMs, bIp.restanteMs);
    await auditarSA(RTDB, saToken, {
      accion: 'LOGIN_BLOQUEADO', entidad: 'usuarios', entidadId: legajo || email,
      actorLegajo: legajo, rol: 'vigilador',
      detalle: { motivo: bLeg.bloqueado ? 'DEMASIADOS_FALLOS_LEGAJO' : 'DEMASIADOS_FALLOS_IP', ip: ip || 'desconocida' }
    });
    return json({
      error: 'cuenta temporalmente bloqueada por demasiados intentos fallidos. Reintenta mas tarde.',
      bloqueado: true, motivo: 'LOGIN_BLOQUEADO',
      segundosRestantes: Math.ceil(restanteMs / 1000)
    }, 429, origin);
  }

  // 3) Validar el PIN contra Firebase Auth (REST, Web API Key publica).
  let fb, fbData;
  try {
    fb = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, returnSecureToken: true })
    });
    fbData = await fb.json().catch(() => ({}));
  } catch (e) {
    return json({ error: 'no se pudo validar el acceso: ' + String((e && e.message) || e) }, 502, origin);
  }

  // 4) FALLO -> suma fallo a legajo e IP; responde generico (sin filtrar causa).
  if (!fb.ok) {
    const [nLeg] = await Promise.all([
      registrarFalloLogin(RTDB, saToken, claveLegajo, LOGIN_MAX_FALLOS_LEGAJO, ahora),
      registrarFalloLogin(RTDB, saToken, claveIp, LOGIN_MAX_FALLOS_IP, ahora)
    ]);
    const fallosLeg = (nLeg && nLeg.fallos) || 0;
    const quedan = Math.max(0, LOGIN_MAX_FALLOS_LEGAJO - fallosLeg);
    const recienBloqueado = !!(nLeg && nLeg.bloqueadoHastaMs);
    return json({
      error: 'credenciales invalidas',
      bloqueado: recienBloqueado,
      intentosRestantes: quedan,
      segundosRestantes: recienBloqueado ? Math.ceil(LOGIN_BLOQUEO_MS / 1000) : undefined
    }, recienBloqueado ? 429 : 401, origin);
  }

  // 5) EXITO -> resetear contadores y emitir el custom token de sesion.
  await Promise.all([
    resetearIntentoLogin(RTDB, saToken, claveLegajo),
    resetearIntentoLogin(RTDB, saToken, claveIp)
  ]);
  // El Worker NO devuelve el idToken crudo: emite un CUSTOM TOKEN para que el
  // navegador abra una sesion real del SDK (signInWithCustomToken). Asi todo el
  // manejo de sesion/renovacion del cliente sigue igual que antes.
  let customToken;
  try { customToken = await crearCustomToken(sa, fbData.localId); }
  catch (e) { return json({ error: 'no se pudo emitir el token de sesion: ' + String((e && e.message) || e) }, 500, origin); }
  return json({
    ok: true,
    customToken,
    uid: fbData.localId,
    email: fbData.email
  }, 200, origin);
}

export default {
  async fetch(request, env) {
    const origin = env.ALLOWED_ORIGIN || '';
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(origin) });
    const reqOrigin = request.headers.get('Origin');
    if (reqOrigin && reqOrigin !== origin) return json({ error: 'origen no permitido' }, 403, origin);
    if (request.method !== 'POST') return json({ error: 'método no permitido' }, 405, origin);

    let sa;
    try { sa = JSON.parse(env.SERVICE_ACCOUNT); } catch (_) { return json({ error: 'config del servidor inválida' }, 500, origin); }
    const projectId = sa.project_id;

    let body;
    try { body = await request.json(); } catch (_) { return json({ error: 'JSON inválido' }, 400, origin); }
    const { idToken, uid, nuevaClave, nuevoEmail, accion } = body || {};

    // --- RATE LIMITING (primera barrera: antes de cualquier logica de negocio) ---
    const ip = request.headers.get('CF-Connecting-IP')
            || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()
            || 'desconocida';
    const rl = rlVerificar(ip, uid || '', accion || '');
    if (!rl.ok) {
      return json({
        error: 'demasiadas solicitudes, espera un momento antes de reintentar',
        bloqueado: true, motivo: rl.motivo,
        limite: rl.limite, ventana: rl.ventana
      }, 429, origin);
    }

    // NUEVO (aditivo): fichaje con validacion autoritativa de objetivo + GPS.
    // No requiere 'uid' (el servidor usa el uid del propio token). Se resuelve
    // ANTES del control de admin porque quien ficha es el vigilador, no el admin.
    if (accion === 'fichar') return manejarFichar(body, env, sa, projectId, origin);

    // NUEVO (Fase 1, aditivo): lote de fichadas OFFLINE firmado por dispositivo.
    // No usa idToken de Firebase (el vigilador ficho sin conexion); se autentica
    // con la credencial del dispositivo (HMAC) y revalida todo server-side.
    if (accion === 'ficharLoteOffline') return manejarLoteOffline(body, env, sa, projectId, origin);

    // NUEVO (aditivo): login por PIN con BLOQUEO persistente anti fuerza bruta.
    // No usa idToken (es el propio login): el Worker valida el PIN contra Firebase
    // y cuenta/limita los intentos. Se despacha ANTES del guard de idToken/uid.
    if (accion === 'loginPin') return manejarLoginPin(body, env, sa, origin, ip);

    // NUEVO [PLAN] (aditivo): panel EXCLUSIVO del dueno del servicio. Se autentica
    // con OWNER_KEY (secreto del Worker), NO con idToken/rol admin. Se despacha
    // ANTES del guard de idToken/uid porque no usa credenciales de Firebase.
    if (accion === 'ownerLeerPlan' || accion === 'ownerFijarPlan') {
      return manejarAccionOwner(accion, body, env, sa, projectId, origin);
    }

    // NUEVO (aditivo): acciones administrativas con AUDITORIA ATOMICA. Cada una
    // verifica el idToken y exige rol admin dentro de manejarAccionAdmin; no
    // requieren 'uid' en el cuerpo, por eso se despachan ANTES del guard de abajo.
    if (accion === 'anularFichada' || accion === 'atenderPanico' || accion === 'auditarEvento' ||
        accion === 'validarFichada' ||
        accion === 'listarDispositivos' || accion === 'crearDispositivo' ||
        accion === 'actualizarDispositivo' || accion === 'eliminarDispositivo' ||
        accion === 'actualizarEmpleado' || accion === 'darDeBajaEmpleado' ||
        accion === 'crearEmpleadoDatos' || accion === 'verificarCupo') {
      return manejarAccionAdmin(accion, body, env, sa, projectId, origin);
    }

    if (!idToken || !uid) return json({ error: 'faltan datos (idToken, uid)' }, 400, origin);
    if (uid && !esClaveRtdbSegura(uid)) return json({ error: 'uid invalido (clave RTDB no segura)' }, 422, origin); // [#1] anti path injection
    if (accion !== 'eliminar' && !nuevaClave && !nuevoEmail) return json({ error: 'nada para actualizar (falta nuevaClave o nuevoEmail)' }, 400, origin);
    if (nuevaClave !== undefined && (typeof nuevaClave !== 'string' || nuevaClave.length < 6)) return json({ error: 'la clave debe tener al menos 6 caracteres' }, 400, origin);
    if (nuevoEmail !== undefined && (typeof nuevoEmail !== 'string' || !/^[^@\s]+@[^@\s]+$/.test(nuevoEmail))) return json({ error: 'email inválido' }, 400, origin);

    // 1) ¿Quién pide? Verificación criptográfica del idToken.
    let solicitante;
    try { solicitante = await verificarIdToken(idToken, projectId); }
    catch (e) { return json({ error: 'token inválido: ' + e.message }, 401, origin); }

    // 2) Access token de la service account.
    let accessToken;
    try { accessToken = await obtenerAccessToken(sa); }
    catch (e) { return json({ error: 'no se pudo autenticar el servidor: ' + e.message }, 500, origin); }

    // 3) El solicitante DEBE ser admin.
    let rol = null;
    try {
      const r = await fetch(`${env.RTDB_URL}/usuarios/${solicitante.sub}/rol.json`, { headers: { Authorization: 'Bearer ' + accessToken } });
      rol = await r.json();
    } catch (_) {}
    if (rol !== 'admin') return json({ error: 'no autorizado (se requiere rol admin)' }, 403, origin);

    // 4) [#2] BAJA TOTAL del empleado (no solo Auth). Antes esta ruta borraba
    //    UNICAMENTE la cuenta de Auth y dejaba huerfanos /usuarios/<uid>,
    //    /personal/<uid> y /credenciales/<uid>: la ficha seguia existiendo y el PIN
    //    offline hasheado permanecia utilizable. Ahora se limpia TODO como en
    //    darDeBajaEmpleado. Al eliminar la cuenta de Auth se invalidan ademas sus
    //    idTokens (revocacion efectiva): ningun token viejo vuelve a autenticar.
    if (accion === 'eliminar') {
      const RTDB = env.RTDB_URL;
      const authH = { Authorization: 'Bearer ' + accessToken };
      const authGet = { headers: authH };

      // Legajo capturado ANTES de borrar (para la auditoria).
      const personalPrev = await fetch(`${RTDB}/personal/${uid}.json`, authGet).then(r => r.json()).catch(() => null);
      const legajoAfectado = personalPrev ? String(personalPrev.legajo || '').trim() : '';

      // [#5] AUDITORIA PRIMERO (baja total IRREVERSIBLE): se registra ANTES de
      // borrar nada; si tras los reintentos no se puede registrar, se ABORTA sin
      // eliminar Auth ni datos (nunca una baja sin bitacora).
      const aud = await auditarSAConReintentos(RTDB, accessToken, {
        accion: 'USUARIO_DADO_DE_BAJA', entidad: 'usuarios', entidadId: uid,
        actorUid: solicitante.sub, rol: 'admin',
        detalle: { via: 'eliminar', legajoAfectado, authEliminada: true, nodosLimpiados: ['credenciales', 'usuarios', 'personal'] }
      }, 3);
      if (!aud.ok) {
        return json({ error: 'No se pudo registrar la auditoria de la baja tras varios intentos; no se elimino nada. Reintenta.' }, 502, origin);
      }

      // 4a) AUTH: eliminar la cuenta (fail-fast). Se TOLERA "cuenta inexistente"
      //     (ya borrada) para poder completar igualmente la limpieza de la base.
      const del = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
        body: JSON.stringify({ localId: uid }),
      });
      const delData = await del.json().catch(() => ({}));
      const msgDel = (delData.error && delData.error.message) || '';
      if (!del.ok && !/USER_NOT_FOUND|EMAIL_NOT_FOUND/i.test(msgDel)) {
        // La baja NO ocurrio: compensamos la bitacora (best-effort) para no dejar
        // un registro de baja que en realidad no se aplico.
        await auditarSAConReintentos(RTDB, accessToken, {
          accion: 'USUARIO_BAJA_ABORTADA', entidad: 'usuarios', entidadId: uid,
          actorUid: solicitante.sub, rol: 'admin',
          detalle: { via: 'eliminar', legajoAfectado, motivo: 'fallo al eliminar la cuenta de Auth' }
        }, 2);
        return json({ error: 'no se pudo eliminar el acceso: ' + (msgDel || ('HTTP ' + del.status)) + '. No se modifico la ficha.' }, 502, origin);
      }

      // 4b) Limpieza en la base (Auth ya no puede autenticar). Best-effort +
      //     reporte. Un 404 se considera exito (el nodo ya no existia).
      const borrarNodo = (ruta) => fetch(`${RTDB}/${ruta}.json`, { method: 'DELETE', headers: authH });
      const fallas = [];
      const rc = await borrarNodo(`credenciales/${uid}`);
      if (!rc.ok && rc.status !== 404) fallas.push('credenciales');
      const ru = await borrarNodo(`usuarios/${uid}`);
      if (!ru.ok && ru.status !== 404) fallas.push('usuarios');
      const rp = await borrarNodo(`personal/${uid}`);
      if (!rp.ok && rp.status !== 404) fallas.push('personal');

      if (fallas.length) {
        return json({ ok: false, uid, inconsistente: true, error: 'El acceso (Auth) se dio de baja, pero fallaron limpiezas en: ' + fallas.join(', ') + '. Reintenta la eliminacion.', fallas, auditoria: aud }, 207, origin);
      }
      return json({ ok: true, uid, eliminado: true, auditoria: aud }, 200, origin);
    }

    // 5) Forzar los cambios pedidos en el empleado destino (endpoint admin de Identity Toolkit).
    const payload = { localId: uid };
    if (nuevaClave) payload.password = nuevaClave;
    if (nuevoEmail) payload.email = nuevoEmail;
    const upd = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + accessToken },
      body: JSON.stringify(payload),
    });
    const updData = await upd.json().catch(() => ({}));
    if (!upd.ok) return json({ error: 'no se pudo actualizar el acceso: ' + ((updData.error && updData.error.message) || ('HTTP ' + upd.status)) }, 502, origin);

    // AUDITORIA: cambio de credencial/legajo (SOLO booleanos, jamas el valor del
    // PIN o del email nuevo -> no se filtra ninguna credencial en la bitacora).
    await auditarSA(env.RTDB_URL, accessToken, {
      accion: nuevaClave ? (nuevoEmail ? 'PIN_Y_LEGAJO_ACTUALIZADOS' : 'PIN_RESETEADO') : 'LEGAJO_CAMBIADO',
      entidad: 'usuarios', entidadId: uid, actorUid: solicitante.sub, rol: 'admin',
      detalle: { cambioPin: !!nuevaClave, cambioEmail: !!nuevoEmail }
    });

    return json({ ok: true, uid }, 200, origin);
  },
};
