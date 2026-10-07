    const URL_FIREBASE = "https://mercosur-seguridad-default-rtdb.firebaseio.com";
    // Endpoint del Cloudflare Worker (fichaje AUTORITATIVO con service account).
    // Las Reglas endurecidas (SA-ONLY) impiden que el vigilador cree /fichadas por
    // REST; la fichada se envia al Worker (accion 'fichar'), que revalida objetivo
    // + geocerca GPS y persiste con la service account (bypassa Reglas). Debe
    // coincidir con el connect-src del CSP de index.html.
    const URL_WORKER = "https://vga-security-24.micasa27822024.workers.dev";

    // Escapa texto para insertarlo de forma segura en HTML (evita XSS almacenado
    // desde datos de terceros, p.ej. el nombre de un objetivo cargado por el
    // admin). Cubre atributos y nodos de texto: & < > " '.
    function escHtmlIdx(valor) {
      return String(valor == null ? '' : valor).replace(/[&<>"']/g,
        c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

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

    // --- ANTI-DUPLICADO DE FICHAJES (aditivo) ---
    // Ventana de tiempo dentro de la cual una misma persona no puede repetir el mismo tipo de fichada.
    const VENTANA_ANTIDUPLICADO_MS = 120000; // 2 minutos
    // --- ID IDEMPOTENTE DE FICHADA (aditivo) ---
    // Genera un identificador único UNA sola vez por fichada. Ese ID viaja con
    // la fichada (online y en la cola offline) y se usa como CLAVE en Firebase.
    // Al guardar con PUT sobre esa clave, reintentar la sincronización
    // SOBRESCRIBE el mismo registro en lugar de crear un duplicado.
    function generarIdFichada() {
      const rnd = (self.crypto && typeof crypto.randomUUID === 'function')
        ? crypto.randomUUID()
        : (Date.now().toString(36) + Math.random().toString(36).slice(2, 12));
      return 'fch_' + rnd;
    }
    // Consulta las fichadas recientes del legajo y detecta un duplicado (mismo tipo dentro de la ventana).
    // Ante cualquier error de red devuelve false para no bloquear una fichada legítima.
    async function existeFichadaReciente(legajo, tipo) {
      try {
        const url = `${URL_FIREBASE}/fichadas.json?orderBy=%22legajo%22&equalTo=%22${encodeURIComponent(String(legajo))}%22`;
        const res = await fetch(urlAuth(url), { cache: 'no-store' });
        if (!res.ok) return false;
        const data = await res.json();
        if (!data) return false;
        const ahora = Date.now();
        const tipoBuscado = String(tipo || '').toUpperCase();
        return Object.values(data).some(f => {
          if (!f || String(f.tipo || '').toUpperCase() !== tipoBuscado) return false;
          // Hora OFICIAL: sello de servidor unificado (timestampServidor). Se mantiene
          // compatibilidad con fichadas antiguas que usaban 'timestamp' / 'timestampLocal'.
          let ts = (typeof f.timestampServidor === 'number') ? f.timestampServidor
                 : (typeof f.timestampEstimadoDispositivo === 'number') ? f.timestampEstimadoDispositivo
                 : (typeof f.timestamp === 'number') ? f.timestamp
                 : (typeof f.timestampLocal === 'number' ? f.timestampLocal
                 : (f.fechaHoraDispositivo ? new Date(f.fechaHoraDispositivo).getTime() : 0));
          return ts && (ahora - ts) >= 0 && (ahora - ts) < VENTANA_ANTIDUPLICADO_MS;
        });
      } catch (e) {
        console.warn('No se pudo verificar duplicados de fichada:', e);
        return false;
      }
    }

    let fotoBase64Global = "";
    let estaSincronizando = false;
    let ultimoTipoFichadaGlobal = "";
    // Turno/horario de la ENTRADA activa (si la hay). Permite ligar la SALIDA
    // al turno con el que se abrio el servicio, aunque cruce la medianoche.
    let ultimaEntradaActivaGlobal = null;
    // Marca si el legajo validado figura como INACTIVO / dado de baja. Si es
    // asi, se bloquea toda posibilidad de fichar.
    let vigiladorInactivoGlobal = false;
    let fotoMasterGuardada = null;
    let modelosCargados = false;
    let resultadoSimilitudGlobal = "NO_EVALUADO";
    // Modo biométrico estricto (lo define el Admin en configuración global).
    // Si está activo, NO se permite fichar sin una COINCIDENCIA facial real
    // contra la Foto Master (bloquea IA no disponible, sin master, master
    // ilegible, error de evaluación o rostro no evaluado).
    let biometriaEstrictaGlobal = false;
    let sospechaFraudeGlobal = false;
    let motivoSospechaGlobal = "";
    let personalActualGlobal = null;
    let turnoProgramadoGlobal = null;
    let objetivoAutorizadoIdsGlobal = [];

    // ===================================================================
    //  SESION AUTENTICADA DEL VIGILADOR (login-first)
    //  El vigilador inicia sesion con legajo + PIN contra Firebase Auth y
    //  la sesion se MANTIENE (no signOut inmediato). Con ese idToken se
    //  leen SOLO sus propios datos (query scoped) en vez de bajar toda la
    //  base de PII. Sin sesion no se muestra el panel ni se hace ningun
    //  fetch de personal/fichadas.
    // ===================================================================
    let idTokenVig = null;                 // idToken de la sesion Auth activa
    let sesionEsOffline = false;           // true = sesion iniciada SIN conexion (login por hash local del PIN, sin idToken). Distingue "sesion offline legitima" de "token vencido".
    let uidSesion = null;                  // uid de Firebase Auth de la sesion activa (para sellar authUid)
    let legajoSesion = null;               // legajo logueado
    let modoDispositivo = 'compartido';    // 'individual' mantiene sesion; 'compartido' cierra tras fichar
    let timerInactividad = null;
    const MS_INACTIVIDAD = 2 * 60 * 1000;  // auto-logout por inactividad (~2 min) en modo compartido

    // ===================================================================
    //  FASE 2 - COLA OFFLINE OPT-IN (login local + lote firmado por dispositivo)
    //  Habilita que un vigilador inicie sesion y fiche SIN conexion, y que esas
    //  fichadas se suban despues por una via AUTONOMA de la sesion: un lote
    //  firmado con la credencial HMAC del dispositivo (endpoint 'ficharLoteOffline'
    //  del Worker). Todo es OPT-IN: solo actua si el modo offline esta habilitado
    //  globalmente (cfg.offlineHabilitado) y si el dispositivo esta provisionado.
    //  El PIN NUNCA se guarda en claro: se cachea su hash PBKDF2+salt.
    // ===================================================================
    const URL_WORKER_FICHAJE = URL_WORKER;           // alias: la sincronizacion del lote offline usa el mismo Worker
    const LS_OFFLINE_CFG   = 'vigix_offline_cfg';    // { offlineHabilitado, ventanaLoteOfflineHoras }
    const LS_CRED_OFFLINE  = 'vigix_cred_offline';   // { <legajo>: { version, salt, hashHex|macHex, uid, personal, guardadoEn, ... } }
    const LS_DISPOSITIVO   = 'vigix_dispositivo';     // { deviceId, secreto } (lo provisiona el Admin en Fase 3)
    const LS_OFFLINE_INTENTOS = 'vigix_offline_intentos'; // M1: { <legajo>: { fallos, bloqueadoHasta } } anti fuerza-bruta offline
    const PBKDF2_ITER      = 150000;
    const OFFLINE_CRED_TTL_MS     = 14 * 24 * 60 * 60 * 1000; // M3: la credencial offline cacheada caduca a los 14 dias
    const OFFLINE_MAX_FALLOS_BASE = 5;                        // M1: fallos antes de iniciar el bloqueo escalonado
    const PIN_BIND_PREFIJO        = 'offline-pin-bind:v2:';   // M2: namespace del HMAC que ata el hash del PIN al dispositivo

    // Agrega ?auth=<idToken> a una URL de la RTDB si hay sesion activa.
    function urlAuth(url) {
      // Antes de construir la URL, actualizar idTokenVig si el timer lo renovó
      if (window._getIdTokenGlobal && window._getIdTokenGlobal()) {
        idTokenVig = window._getIdTokenGlobal();
      }
      if (!idTokenVig) return url;
      return url + (url.includes('?') ? '&' : '?') + 'auth=' + encodeURIComponent(idTokenVig);
    }

    // Lee SOLO los registros propios (query scoped por legajo, string y numero)
    // para no descargar toda la coleccion. Requiere en las Reglas de Seguridad
    // el indice .indexOn: ["legajo"] sobre /personal y /fichadas.
    async function fetchScoped(path, legajo) {
      const base = `${URL_FIREBASE}/${path}.json?orderBy=${encodeURIComponent('"legajo"')}`;
      // El legajo es SIEMPRE string (tambien en las Reglas): no hay variante numerica,
      // las Reglas la deniegan. Una respuesta {error:...} no es dato: se descarta.
      const r = await fetch(urlAuth(base + '&equalTo=' + encodeURIComponent('"' + String(legajo).trim() + '"')), { cache: 'no-store' }).then(x => x.json()).catch(() => null);
      if (r && typeof r === 'object' && !r.error && Object.keys(r).length) return r;
      return null;
    }

    function reiniciarInactividad() {
      if (modoDispositivo !== 'compartido') { if (timerInactividad) { clearTimeout(timerInactividad); timerInactividad = null; } return; }
      if (!legajoSesion) return;
      if (timerInactividad) clearTimeout(timerInactividad);
      timerInactividad = setTimeout(() => {
        alert('Sesion cerrada por inactividad. Volve a ingresar tu legajo y PIN.');
        cerrarSesionVigilador();
      }, MS_INACTIVIDAD);
    }
    ['click', 'keydown', 'touchstart'].forEach(ev =>
      document.addEventListener(ev, () => { if (legajoSesion) reiniciarInactividad(); }, { passive: true })
    );

    async function cargarModoDispositivo() {
      try {
        const res = await fetch(urlAuth(`${URL_FIREBASE}/configuracionGlobal/modoDispositivo.json?ts=${Date.now()}`), { cache: 'no-store' });
        const m = await res.json();
        modoDispositivo = (String(m || '').trim() === 'individual') ? 'individual' : 'compartido';
      } catch (_) { modoDispositivo = 'compartido'; }
    }

    // --- Timeout acotado para las llamadas al Worker (AbortController) ---
    function fetchConLimite(url, opciones, msTimeout) {
      const ctrl = new AbortController();
      const t = setTimeout(() => { try { ctrl.abort(); } catch (_) {} }, msTimeout || 20000);
      return fetch(url, Object.assign({}, opciones || {}, { signal: ctrl.signal })).finally(() => clearTimeout(t));
    }

    // --- Config offline cacheada (para saber, estando offline, si se permite) ---
    function offlineHabilitadoLocal() {
      try { const c = JSON.parse(localStorage.getItem(LS_OFFLINE_CFG) || '{}'); return !!(c && c.offlineHabilitado === true); } catch (_) { return false; }
    }
    function ventanaLoteOfflineHorasLocal() {
      try { const c = JSON.parse(localStorage.getItem(LS_OFFLINE_CFG) || '{}'); const v = Number(c && c.ventanaLoteOfflineHoras); return (Number.isFinite(v) && v > 0) ? v : 168; } catch (_) { return 168; }
    }
    // Persiste el flag desde /configuracionGlobal cuando hay conexion.
    function guardarOfflineCfg(cfg) {
      try { localStorage.setItem(LS_OFFLINE_CFG, JSON.stringify({ offlineHabilitado: !!(cfg && cfg.offlineHabilitado === true), ventanaLoteOfflineHoras: Number(cfg && cfg.ventanaLoteOfflineHoras) || 168 })); } catch (_) {}
    }
    // Lee /configuracionGlobal AHORA (con conexion) y persiste el flag offline de
    // forma AWAITABLE, para GARANTIZAR que el flag este cacheado ANTES de cachear
    // la credencial offline (evita la carrera del primer login online).
    async function asegurarOfflineCfg() {
      if (!navigator.onLine) return;
      try {
        const res = await fetch(urlAuth(`${URL_FIREBASE}/configuracionGlobal.json?ts=${Date.now()}`), { cache: 'no-store' });
        const cfg = await res.json();
        guardarOfflineCfg(cfg);
      } catch (_) {}
    }

    // --- Utilidades cripto (WebCrypto) ---
    function _b64FromBytes(bytes) { let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
    function _bytesFromB64(b64) { const s = atob(String(b64 || '')); const a = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; }
    // Comparacion de hex en tiempo casi constante (no cortocircuita por caracter).
    function _igualHex(a, b) { a = String(a || '').toLowerCase(); b = String(b || '').toLowerCase(); if (!a || a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }
    async function _pbkdf2Hex(pin, saltBytes, iteraciones) {
      const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: iteraciones, hash: 'SHA-256' }, baseKey, 256);
      const b = new Uint8Array(bits); let h = ''; for (let i = 0; i < b.length; i++) h += b[i].toString(16).padStart(2, '0'); return h;
    }
    async function firmarHmacHex(secreto, mensaje) {
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(secreto)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(mensaje)));
      let h = ''; for (let i = 0; i < mac.length; i++) h += mac[i].toString(16).padStart(2, '0'); return h;
    }

    // ===================================================================
    //  ALMACEN SEGURO DE LA CLAVE HMAC DEL DISPOSITIVO (IndexedDB)
    //  El secreto se importa como CryptoKey con extractable:false: se puede USAR
    //  para firmar los lotes offline, pero su material NUNCA vuelve a leerse desde
    //  JavaScript (defensa ante XSS, a diferencia de guardarlo en localStorage).
    // ===================================================================
    const IDB_NOMBRE   = 'vigix_seguro';
    const IDB_STORE    = 'claves';
    const IDB_KEY_HMAC = 'hmac_dispositivo';
    const IDB_KEY_AES  = 'aes_cifrado_local';   // M4: clave AES-GCM no extraible para cifrar datos sensibles en reposo
    function _idbAbrir() {
      return new Promise((resolve, reject) => {
        let req;
        try { req = indexedDB.open(IDB_NOMBRE, 1); } catch (e) { return reject(e); }
        req.onupgradeneeded = () => { const db = req.result; if (!db.objectStoreNames.contains(IDB_STORE)) db.createObjectStore(IDB_STORE); };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
    function _idbGuardar(clave, valor) {
      return _idbAbrir().then(db => new Promise((resolve, reject) => {
        const tx = db.transaction(IDB_STORE, 'readwrite');
        tx.objectStore(IDB_STORE).put(valor, clave);
        tx.oncomplete = () => { db.close(); resolve(true); };
        tx.onerror = () => { db.close(); reject(tx.error); };
      }));
    }
    function _idbLeer(clave) {
      return _idbAbrir().then(db => new Promise((resolve, reject) => {
        const tx = db.transaction(IDB_STORE, 'readonly');
        const rq = tx.objectStore(IDB_STORE).get(clave);
        rq.onsuccess = () => { db.close(); resolve(rq.result || null); };
        rq.onerror = () => { db.close(); reject(rq.error); };
      }));
    }
    function _idbBorrar(clave) {
      return _idbAbrir().then(db => new Promise((resolve) => {
        const tx = db.transaction(IDB_STORE, 'readwrite');
        tx.objectStore(IDB_STORE).delete(clave);
        tx.oncomplete = () => { db.close(); resolve(true); };
        tx.onerror = () => { db.close(); resolve(false); };
      })).catch(() => false);
    }
    async function _importarClaveHmacNoExtraible(secreto) {
      return crypto.subtle.importKey('raw', new TextEncoder().encode(String(secreto)), { name: 'HMAC', hash: 'SHA-256' }, false /* NO extraible */, ['sign']);
    }
    async function _persistirClaveHmac(secreto) {
      try { const key = await _importarClaveHmacNoExtraible(secreto); await _idbGuardar(IDB_KEY_HMAC, key); return true; }
      catch (e) { console.warn('No se pudo guardar la clave del dispositivo de forma segura:', e); return false; }
    }
    // ===================================================================
    //  M4: CIFRADO LOCAL EN REPOSO (AES-GCM, clave NO extraible en IndexedDB)
    //  Protege la foto master (biometrico) y la config personal (PII) frente a
    //  robo del dispositivo o volcado del almacenamiento: el dato queda como
    //  texto cifrado y la clave para descifrarlo nunca sale del navegador.
    // ===================================================================
    async function _obtenerClaveCifradoLocal() {
      if (!(self.crypto && crypto.subtle)) return null;
      try { const k = await _idbLeer(IDB_KEY_AES); if (k) return k; } catch (_) {}
      try {
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false /* NO extraible */, ['encrypt', 'decrypt']);
        await _idbGuardar(IDB_KEY_AES, key);
        return key;
      } catch (e) { console.warn('No se pudo preparar el cifrado local:', e); return null; }
    }
    async function _cifrarTextoLocal(texto) {
      if (texto == null) return null;
      const key = await _obtenerClaveCifradoLocal();
      if (!key) return null;
      try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(String(texto))));
        return { iv: _b64FromBytes(iv), ct: _b64FromBytes(ct) };
      } catch (e) { console.warn('Fallo el cifrado local:', e); return null; }
    }
    async function _descifrarTextoLocal(payload) {
      if (!payload || !payload.iv || !payload.ct) return null;
      const key = await _obtenerClaveCifradoLocal();
      if (!key) return null;
      try {
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: _bytesFromB64(payload.iv) }, key, _bytesFromB64(payload.ct));
        return new TextDecoder().decode(pt);
      } catch (_) { return null; }
    }
    // M5: migra proactivamente al arranque el secreto HMAC que pudiera haber
    // quedado en claro en localStorage hacia IndexedDB (clave no extraible) y
    // BORRA la copia del localStorage. Antes esto solo ocurria de forma perezosa
    // en la primera firma, dejando una ventana de exposicion.
    async function _migrarSecretoHmacASeguro() {
      try {
        const d = JSON.parse(localStorage.getItem(LS_DISPOSITIVO) || 'null');
        if (!d || !d.deviceId || !d.secreto) return;    // nada que migrar
        const ok = await _persistirClaveHmac(d.secreto);
        if (ok) localStorage.setItem(LS_DISPOSITIVO, JSON.stringify({ deviceId: d.deviceId, provisionado: true }));
      } catch (_) {}
    }
    async function _obtenerClaveHmacDispositivo() {
      try { const k = await _idbLeer(IDB_KEY_HMAC); if (k) return k; } catch (_) {}
      try {
        const d = JSON.parse(localStorage.getItem(LS_DISPOSITIVO) || 'null');
        if (d && d.deviceId && d.secreto) {
          const ok = await _persistirClaveHmac(d.secreto);
          if (ok) {
            localStorage.setItem(LS_DISPOSITIVO, JSON.stringify({ deviceId: d.deviceId, provisionado: true }));
            const k2 = await _idbLeer(IDB_KEY_HMAC); if (k2) return k2;
          }
          return await _importarClaveHmacNoExtraible(d.secreto);
        }
      } catch (_) {}
      return null;
    }
    async function firmarLoteDispositivo(mensaje) {
      const key = await _obtenerClaveHmacDispositivo();
      if (!key) return null;
      const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(mensaje)));
      let h = ''; for (let i = 0; i < mac.length; i++) h += mac[i].toString(16).padStart(2, '0'); return h;
    }

    // --- Credencial del dispositivo (deviceId + secreto HMAC) ---
    function obtenerCredencialDispositivo() {
      try { const d = JSON.parse(localStorage.getItem(LS_DISPOSITIVO) || 'null'); return (d && d.deviceId && (d.secreto || d.provisionado)) ? d : null; } catch (_) { return null; }
    }

    // --- Vinculacion del dispositivo (Fase 3): el operador pega el codigo que
    //     genero el Admin. Se decodifica y se guarda {deviceId} + clave HMAC no
    //     extraible en IndexedDB. El secreto NUNCA sale de este dispositivo salvo
    //     dentro de la firma HMAC de cada lote.
    function _parsearCodigoVinculacion(codigo) {
      const raw = String(codigo || '').trim();
      if (!raw) return null;
      let obj = null;
      try { obj = JSON.parse(atob(raw)); } catch (_) { obj = null; }
      if (!obj) { try { obj = JSON.parse(raw); } catch (_) { obj = null; } }
      if (obj && typeof obj.deviceId === 'string' && typeof obj.secreto === 'string' && obj.deviceId && obj.secreto) {
        return { deviceId: obj.deviceId, secreto: obj.secreto };
      }
      return null;
    }
    function vincularDispositivo() {
      const estado = document.getElementById('estadoVincular');
      const ya = obtenerCredencialDispositivo();
      const msgInicial = ya ? 'Este dispositivo YA está vinculado. Pegar un código nuevo lo reemplaza.\n\nCódigo de vinculación:' : 'Pegá el código de vinculación que te dio el administrador:';
      const codigo = prompt(msgInicial);
      if (codigo === null) return; // cancelado
      const cred = _parsearCodigoVinculacion(codigo);
      if (!cred) {
        if (estado) { estado.className = 'text-[11px] mt-1 text-rose-400 font-semibold'; estado.innerText = '❌ Código inválido. Verificá que lo hayas copiado completo.'; }
        return;
      }
      (async () => {
      try {
        const guardado = await _persistirClaveHmac(cred.secreto);
        if (guardado) {
          localStorage.setItem(LS_DISPOSITIVO, JSON.stringify({ deviceId: cred.deviceId, provisionado: true }));
        } else {
          localStorage.setItem(LS_DISPOSITIVO, JSON.stringify({ deviceId: cred.deviceId, secreto: cred.secreto }));
        }
        if (estado) { estado.className = 'text-[11px] mt-1 text-emerald-400 font-semibold'; estado.innerText = '✓ Dispositivo vinculado. Ya puede fichar sin conexión.'; }
        const lbl = document.getElementById('lblVincular');
        if (lbl) lbl.innerText = 'Dispositivo vinculado — volver a vincular';
      } catch (_) {
        if (estado) { estado.className = 'text-[11px] mt-1 text-rose-400 font-semibold'; estado.innerText = '❌ No se pudo guardar en este navegador.'; }
      }
      })();
    }
    window.vincularDispositivo = vincularDispositivo;

    // Refleja en la pantalla de login si este telefono YA esta vinculado.
    function refrescarEstadoVinculacion() {
      const lbl = document.getElementById('lblVincular');
      const estado = document.getElementById('estadoVincular');
      const ya = obtenerCredencialDispositivo();
      if (ya) {
        if (lbl) lbl.innerText = 'Dispositivo vinculado — volver a vincular';
        if (estado) { estado.className = 'text-[11px] mt-1 text-emerald-400 font-semibold'; estado.innerText = '✓ Dispositivo vinculado. Puede fichar sin conexión.'; }
      } else {
        if (lbl) lbl.innerText = 'Vincular dispositivo para fichaje offline';
        if (estado) { estado.className = 'text-[11px] mt-1'; estado.innerText = ''; }
      }
    }
    window.refrescarEstadoVinculacion = refrescarEstadoVinculacion;

    // Muestra cuantas fichadas offline quedan por sincronizar y, si alguna fue
    // rechazada por el servidor, el motivo. El estado se refleja en la linea
    // dentro de la tarjeta de login (#estadoOfflinePend).
    function refrescarEstadoOfflinePendientes() {
      let pend = [], rech = [];
      try { pend = JSON.parse(localStorage.getItem('fichadas_pendientes') || '[]'); } catch (_) {}
      try { rech = JSON.parse(localStorage.getItem('fichadas_rechazadas') || '[]'); } catch (_) {}
      const offPend = (pend || []).filter(f => f && (f.creadaOffline === true || f.origenOffline === true));

      let tipo = 'oculto', texto = '';
      if (offPend.length > 0) {
        if (!obtenerCredencialDispositivo()) {
          tipo = 'error';
          texto = '⚠️ ' + offPend.length + ' fichada(s) offline sin enviar: este teléfono no tiene un dispositivo vinculado. Volvé a vincularlo y conectate a internet.';
        } else {
          tipo = 'pendiente';
          texto = '⏳ ' + offPend.length + ' fichada(s) offline pendiente(s) de sincronizar. Conectate a internet para enviarlas.';
        }
      } else {
        const recientes = (rech || []).filter(f => f && f.viaLoteOffline === true);
        if (recientes.length > 0) {
          const ultima = recientes[recientes.length - 1];
          tipo = 'error';
          texto = '⚠️ Una fichada offline fue rechazada por el servidor: ' + (ultima.motivoRechazo || 'validación fallida') + '. Avisá al administrador.';
        }
      }

      // Linea de estado dentro de la tarjeta de login (notificacion original).
      const el = document.getElementById('estadoOfflinePend');
      if (el) {
        if (tipo === 'oculto') { el.classList.add('hidden'); el.innerText = ''; }
        else {
          el.className = 'text-[11px] mt-1 font-semibold ' + (tipo === 'error' ? 'text-rose-400' : 'text-amber-400');
          el.innerText = texto;
          el.classList.remove('hidden');
        }
      }
    }
    window.refrescarEstadoOfflinePendientes = refrescarEstadoOfflinePendientes;

    // --- Credencial de login OFFLINE (hash PBKDF2 del PIN + snapshot del vigilador) ---
    function _leerCredsOffline() { try { return JSON.parse(localStorage.getItem(LS_CRED_OFFLINE) || '{}') || {}; } catch (_) { return {}; } }

    // --- M1: contador de intentos + bloqueo escalonado del login OFFLINE ---
    // El login online ya esta protegido por el Worker; esto replica ese freno
    // del lado del dispositivo, donde el ataque de fuerza bruta es local.
    function _leerIntentosOffline() { try { return JSON.parse(localStorage.getItem(LS_OFFLINE_INTENTOS) || '{}') || {}; } catch (_) { return {}; } }
    function _guardarIntentosOffline(m) { try { localStorage.setItem(LS_OFFLINE_INTENTOS, JSON.stringify(m || {})); } catch (_) {} }
    function _calcularBloqueoOfflineMs(fallos) {
      if (fallos < OFFLINE_MAX_FALLOS_BASE) return 0; // < 5  -> sin bloqueo
      if (fallos < 10) return 60 * 1000;              // 5-9  -> 1 min
      if (fallos < 15) return 5 * 60 * 1000;          // 10-14-> 5 min
      return 15 * 60 * 1000;                          // 15+  -> 15 min
    }
    function estadoBloqueoOffline(legajo) {
      const r = _leerIntentosOffline()[String(legajo).trim()];
      if (!r) return { bloqueado: false, fallos: 0, segundosRestantes: 0 };
      const ahora = Date.now();
      const hasta = Number(r.bloqueadoHasta) || 0;
      if (hasta > ahora) return { bloqueado: true, fallos: Number(r.fallos) || 0, segundosRestantes: Math.ceil((hasta - ahora) / 1000) };
      return { bloqueado: false, fallos: Number(r.fallos) || 0, segundosRestantes: 0 };
    }
    function _registrarFalloOffline(legajo) {
      const m = _leerIntentosOffline(); const k = String(legajo).trim();
      const r = m[k] || { fallos: 0, bloqueadoHasta: 0 };
      r.fallos = (Number(r.fallos) || 0) + 1;
      const ms = _calcularBloqueoOfflineMs(r.fallos);
      if (ms > 0) r.bloqueadoHasta = Date.now() + ms;
      m[k] = r; _guardarIntentosOffline(m);
      return r;
    }
    function _limpiarFallosOffline(legajo) {
      const m = _leerIntentosOffline(); const k = String(legajo).trim();
      if (m[k]) { delete m[k]; _guardarIntentosOffline(m); }
    }
    // M2: calcula el HMAC (atado al dispositivo) del hash del PIN. Devuelve null
    // si este telefono no tiene clave de dispositivo (no vinculado).
    async function _macPinDispositivo(hashHex) {
      return await firmarLoteDispositivo(PIN_BIND_PREFIJO + String(hashHex));
    }
    // Se llama tras un login ONLINE exitoso. Guarda el hash del PIN (nunca el PIN)
    // y una copia de la config del vigilador para poder operar sin red mas tarde.
    // Se cachea si el modo offline esta habilitado globalmente O si este telefono
    // ya fue VINCULADO por el admin (provisionado para offline). El servidor igual
    // revalida el lote al sincronizar, por lo que cachear el hash local es seguro.
    async function cachearCredencialOffline(legajo, pin, uid, nombre, personal, fotoMaster) {
      if (!offlineHabilitadoLocal() && !obtenerCredencialDispositivo()) return;
      if (!(self.crypto && crypto.subtle)) return;
      try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const hashHex = await _pbkdf2Hex(String(pin).padStart(6, '0'), salt, PBKDF2_ITER);
        // M2: si el dispositivo esta vinculado, atamos el hash a su clave HMAC NO
        // extraible (IndexedDB). Asi, aunque alguien copie esta credencial del
        // localStorage, NO puede verificar ni crackear el PIN fuera de este
        // telefono: necesitaria la clave del dispositivo, que nunca sale de aca.
        const macHex = await _macPinDispositivo(hashHex); // null si el device no esta vinculado
        // M4: la foto master (biometrico) y la config personal (PII) se guardan
        // CIFRADAS en reposo con una clave AES-GCM no extraible. Si el cifrado no
        // esta disponible, se degrada a texto plano (compatibilidad).
        const fotoEnc = fotoMaster ? await _cifrarTextoLocal(String(fotoMaster)) : null;
        const persEnc = personal ? await _cifrarTextoLocal(JSON.stringify(personal)) : null;
        const creds = _leerCredsOffline();
        const registro = {
          legajo: String(legajo).trim(), uid: uid || null, nombre: nombre || null,
          salt: _b64FromBytes(salt), iteraciones: PBKDF2_ITER,
          guardadoEn: new Date().toISOString()
        };
        if (fotoEnc) registro.fotoMasterEnc = fotoEnc; else if (fotoMaster) registro.fotoMaster = fotoMaster; // cifrado o legacy plano
        if (persEnc) registro.personalEnc   = persEnc; else if (personal)   registro.personal   = personal;   // cifrado o legacy plano
        if (macHex) { registro.version = 2; registro.macHex = macHex; }   // atada al dispositivo (fuerte)
        else        { registro.version = 1; registro.hashHex = hashHex; } // legacy: hash plano (sin device)
        creds[String(legajo).trim()] = registro;
        localStorage.setItem(LS_CRED_OFFLINE, JSON.stringify(creds));
      } catch (e) { console.warn('No se pudo cachear la credencial offline:', e); }
    }
    // Verifica el PIN contra la credencial local. Devuelve { cred, motivo } con
    // motivo in {'ok','sin_credencial','pin_invalido','expirada','device_requerido'}.
    async function verificarCredencialOffline(legajo, pin) {
      const c = _leerCredsOffline()[String(legajo).trim()];
      if (!c || !c.salt || (!c.hashHex && !c.macHex)) return { cred: null, motivo: 'sin_credencial' };
      // M3: caducidad. Una credencial vieja (PIN cambiado o baja del empleado)
      // deja de valer sin conexion; el proximo login online la renueva.
      const guardado = c.guardadoEn ? Date.parse(c.guardadoEn) : 0;
      if (guardado && (Date.now() - guardado) > OFFLINE_CRED_TTL_MS) return { cred: null, motivo: 'expirada' };
      try {
        const hashHex = await _pbkdf2Hex(String(pin).padStart(6, '0'), _bytesFromB64(c.salt), c.iteraciones || PBKDF2_ITER);
        if (c.version === 2 && c.macHex) {
          // M2: credencial atada al dispositivo -> recalculamos el HMAC local.
          const mac = await _macPinDispositivo(hashHex);
          if (!mac) return { cred: null, motivo: 'device_requerido' };
          return _igualHex(mac, c.macHex) ? { cred: c, motivo: 'ok' } : { cred: null, motivo: 'pin_invalido' };
        }
        // Legacy (version 1 / sin version): hash plano. Backward-compatible.
        return _igualHex(hashHex, c.hashHex) ? { cred: c, motivo: 'ok' } : { cred: null, motivo: 'pin_invalido' };
      } catch (_) { return { cred: null, motivo: 'pin_invalido' }; }
    }
    // M4: devuelve una copia del registro con fotoMaster/personal EN CLARO,
    // descifrando los campos cifrados (o usando el texto plano legacy).
    async function _descifrarCamposCred(c) {
      if (!c) return c;
      const out = Object.assign({}, c);
      if (c.fotoMasterEnc) out.fotoMaster = await _descifrarTextoLocal(c.fotoMasterEnc);
      if (c.personalEnc) {
        const s = await _descifrarTextoLocal(c.personalEnc);
        try { out.personal = s ? JSON.parse(s) : null; } catch (_) { out.personal = null; }
      }
      return out;
    }

    // --- Login OFFLINE (sin idToken; identidad probada por hash local del PIN) ---
    async function iniciarSesionOffline(legajo, pin, st, btn) {
      const legajoNorm = String(legajo).trim();
      // M1: freno anti fuerza-bruta. Si esta bloqueado, ni siquiera verificamos.
      const bloqueo = estadoBloqueoOffline(legajoNorm);
      if (bloqueo.bloqueado) {
        st.className = 'text-xs mt-1 text-center text-rose-400 block';
        const min = Math.max(1, Math.ceil(bloqueo.segundosRestantes / 60));
        st.innerText = `Demasiados intentos sin conexión. Esperá ${min} min antes de reintentar.`;
        if (btn) btn.disabled = false; return;
      }
      const res = await verificarCredencialOffline(legajoNorm, pin);
      if (!res || res.motivo !== 'ok') {
        st.className = 'text-xs mt-1 text-center text-rose-400 block';
        if (res && res.motivo === 'expirada') {
          st.innerText = 'Tu acceso sin conexión caducó por seguridad. Conectate a internet e iniciá sesión una vez con tu legajo y PIN en este mismo teléfono para renovarlo.';
        } else if (res && res.motivo === 'device_requerido') {
          st.innerText = 'Tu acceso sin conexión está atado a este teléfono y no se puede verificar porque el dispositivo no está vinculado. Volvé a vincularlo y, con internet, iniciá sesión una vez en este mismo teléfono.';
        } else if (res && res.motivo === 'sin_credencial') {
          if (obtenerCredencialDispositivo()) {
            st.innerText = 'Este teléfono ya está vinculado, pero todavía no guardó tu acceso para fichar sin conexión. Con internet, iniciá sesión una vez con tu legajo y PIN en este mismo teléfono; después vas a poder fichar offline.';
          } else if (!offlineHabilitadoLocal()) {
            st.innerText = 'Sin conexión: este teléfono todavía no está habilitado para uso offline. Pedile al administrador que active el modo offline y, con internet, iniciá sesión una vez en este mismo teléfono.';
          } else {
            st.innerText = 'Sin conexión: legajo/PIN no verificados en este dispositivo. Conectate a internet e iniciá sesión al menos una vez en este teléfono.';
          }
        } else {
          // pin_invalido: contamos el fallo (M1) y avisamos los intentos restantes.
          const r = _registrarFalloOffline(legajoNorm);
          const restantes = OFFLINE_MAX_FALLOS_BASE - (Number(r.fallos) || 0);
          const nb = estadoBloqueoOffline(legajoNorm);
          if (nb.bloqueado) {
            const min = Math.max(1, Math.ceil(nb.segundosRestantes / 60));
            st.innerText = `Demasiados intentos sin conexión. Esperá ${min} min antes de reintentar.`;
          } else if (restantes > 0 && restantes <= 2) {
            st.innerText = `PIN incorrecto. Te queda${restantes === 1 ? '' : 'n'} ${restantes} intento${restantes === 1 ? '' : 's'} antes del bloqueo temporal.`;
          } else {
            st.innerText = 'Sin conexión: legajo o PIN incorrectos.';
          }
        }
        if (btn) btn.disabled = false; return;
      }
      const cred = await _descifrarCamposCred(res.cred);
      // M1: login correcto -> se reinicia el contador de fallos de este legajo.
      _limpiarFallosOffline(legajoNorm);
      // M2 (migracion en caliente): si la credencial es legacy (v1, hash plano) y
      // ahora el dispositivo esta vinculado, la re-guardamos ATADA al device (v2).
      if (cred && cred.version !== 2 && obtenerCredencialDispositivo()) {
        try { await cachearCredencialOffline(legajoNorm, pin, cred.uid, cred.nombre, cred.personal, cred.fotoMaster); } catch (_) {}
      }
      // Sesion OFFLINE: NO hay idToken. La identidad se ata luego, al sincronizar,
      // via el authUid cacheado + la credencial firmada del dispositivo (Worker).
      idTokenVig = null;
      sesionEsOffline = true;   // marca de sesion offline legitima: el fichaje NO debe exigir idToken
      uidSesion = cred.uid || null;
      legajoSesion = legajoNorm;
      document.getElementById('loginPin').value = '';
      document.getElementById('pantallaLogin').classList.add('hidden');
      document.getElementById('panelFichaje').classList.remove('hidden');
      document.getElementById('legajo').value = legajoSesion;
      st.className = 'text-xs mt-1 text-center hidden'; st.innerText = '';
      iniciarCamaraSegura();
      cargarModelosIA();
      cargarObjetivos();                 // usa la cache local de objetivos
      modoDispositivo = 'compartido';    // offline: no se pudo leer config -> por defecto compartido
      document.getElementById('nombre').value = cred.nombre || '';
      const lblNom = document.getElementById('lblSesionNombre'); if (lblNom) lblNom.innerText = cred.nombre || legajoSesion;
      fotoMasterGuardada = cred.fotoMaster || null;
      vigiladorInactivoGlobal = false;
      let personalOffline = cred.personal || null;
      if (!personalOffline || !personalOffline.objetivosAsignados) {
        try {
          const cache = JSON.parse(localStorage.getItem('personal_config_fichada') || 'null');
          if (cache && String(cache.legajo || '').trim() === legajoSesion) personalOffline = cache;
        } catch (_) {}
      }
      if (personalOffline) { try { await aplicarConfiguracionVigilador(personalOffline); } catch (_) {} }
      verificarUltimoEstadoLocal(legajoSesion);
      reiniciarInactividad();
    }

    // --- Sincronizacion del LOTE OFFLINE firmado por dispositivo ---
    // Sube por 'ficharLoteOffline' las fichadas creadas realmente sin conexion.
    // No requiere idToken. El Worker revalida identidad + objetivo + geocerca y es
    // idempotente por idEvento.
    let estaSincronizandoLote = false;
    async function sincronizarLoteOffline() {
      if (estaSincronizandoLote) return;
      if (!navigator.onLine) return;
      if (!URL_WORKER_FICHAJE) return;
      const disp = obtenerCredencialDispositivo();
      if (!disp) return;                                    // sin dispositivo provisionado no hay via firmada
      // NO se bloquea por el flag local 'offlineHabilitado': es solo una cache y, si
      // el ultimo login fue offline, puede faltar o estar desactualizada, lo que
      // dejaria las fichadas VARADAS para siempre (pendientes que nunca se envian).
      // El Worker es la autoridad: si el modo offline esta deshabilitado devuelve
      // OFFLINE_DESHABILITADO (403) y se conserva la cola; si esta habilitado, sube.
      const pendientes = JSON.parse(localStorage.getItem('fichadas_pendientes') || '[]');
      const loteItems = pendientes.filter(f => f && (f.creadaOffline === true || f.origenOffline === true));
      if (loteItems.length === 0) return;
      estaSincronizandoLote = true;
      try {
        const envio = loteItems.slice(0, 200).map(f => Object.assign({}, f, {
          timestampServidorEstimado: (typeof f.timestampServidorEstimado === 'number') ? f.timestampServidorEstimado
            : (f.horaServidorFichaje ? Date.parse(f.horaServidorFichaje) : (f.timestampLocal || null))
        }));
        const fichadasStr = JSON.stringify(envio);
        const timestamp = Date.now();
        const firma = await firmarLoteDispositivo(`${disp.deviceId}.${timestamp}.${fichadasStr}`);
        if (!firma) return; // sin clave utilizable: se conserva la cola (finally resetea el flag)
        const resp = await fetchConLimite(URL_WORKER_FICHAJE, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ accion: 'ficharLoteOffline', deviceId: disp.deviceId, timestamp, fichadas: fichadasStr, firma })
        }, 25000);
        let data = {}; try { data = await resp.json(); } catch (_) {}
        if (resp.status === 403 && data && data.motivo === 'OFFLINE_DESHABILITADO') { estaSincronizandoLote = false; return; }
        if (!resp.ok || !data || !data.ok) throw new Error('Lote offline respondió ' + resp.status);

        const porRef = {}; (data.resultados || []).forEach(r => { if (r && r.ref) porRef[String(r.ref)] = r; });
        const rechazadasArch = JSON.parse(localStorage.getItem('fichadas_rechazadas') || '[]');
        let restantes = JSON.parse(localStorage.getItem('fichadas_pendientes') || '[]');
        restantes = restantes.filter(f => {
          if (!(f && (f.creadaOffline === true || f.origenOffline === true))) return true; // ajenas al lote: no se tocan
          const r = porRef[String(f.idEvento || f.fichadaId || '')];
          if (!r) return true;                       // sin resultado: se conserva para reintentar
          if (r.creada || r.duplicada) return false; // aceptada: sale de la cola
          if (r.rechazada) {                         // invalida server-side: se archiva y sale
            rechazadasArch.push(Object.assign({}, f, { motivoRechazo: r.motivo || 'validación del servidor fallida', rechazadaEn: new Date().toISOString(), viaLoteOffline: true }));
            return false;
          }
          return true;
        });
        localStorage.setItem('fichadas_rechazadas', JSON.stringify(rechazadasArch));
        localStorage.setItem('fichadas_pendientes', JSON.stringify(restantes));
        console.log(`🔒 Lote offline sincronizado: creadas ${data.creadas || 0}, duplicadas ${data.duplicadas || 0}, rechazadas ${data.rechazadas || 0}.`);
      } catch (err) {
        console.warn('No se pudo sincronizar el lote offline (se reintentará):', err);
      } finally {
        estaSincronizandoLote = false;
        try { if (typeof refrescarEstadoOfflinePendientes === 'function') refrescarEstadoOfflinePendientes(); } catch (_) {}
      }
    }

    // ===================================================================
    //  CADUCIDAD Y LIMPIEZA DE DATOS SENSIBLES OFFLINE
    // ===================================================================
    const MAX_RETENCION_OFFLINE_MS = 30 * 24 * 3600 * 1000; // 30 dias
    function _tsDesdeISO(iso) { const t = Date.parse(iso || ''); return Number.isFinite(t) ? t : 0; }
    function purgarCacheOfflineVencido() {
      const ahora = Date.now();
      try {
        const creds = _leerCredsOffline(); let cambio = false;
        for (const k of Object.keys(creds)) {
          const g = _tsDesdeISO(creds[k] && creds[k].guardadoEn);
          if (!g || (ahora - g) > MAX_RETENCION_OFFLINE_MS) { delete creds[k]; cambio = true; }
        }
        if (cambio) localStorage.setItem(LS_CRED_OFFLINE, JSON.stringify(creds));
      } catch (_) {}
      try {
        const cache = JSON.parse(localStorage.getItem('vigix_turnos_cache') || '{}') || {}; let cambio = false;
        for (const k of Object.keys(cache)) {
          const g = _tsDesdeISO(cache[k] && cache[k].guardadoEn);
          if (!g || (ahora - g) > MAX_RETENCION_OFFLINE_MS) { delete cache[k]; cambio = true; }
        }
        if (cambio) localStorage.setItem('vigix_turnos_cache', JSON.stringify(cache));
      } catch (_) {}
    }
    function limpiarDatosSensiblesAlSalir() {
      try { fotoBase64Global = ''; fotoMasterGuardada = null; } catch (_) {}
      const offlineActivo = offlineHabilitadoLocal() || !!obtenerCredencialDispositivo();
      if (!offlineActivo) { try { localStorage.removeItem(LS_CRED_OFFLINE); } catch (_) {} }
      purgarCacheOfflineVencido();
    }

    async function iniciarSesionVigilador(e) {
      if (e && e.preventDefault) e.preventDefault();
      const legajo = document.getElementById('loginLegajo').value.trim();
      const pin = document.getElementById('loginPin').value.trim();
      const st = document.getElementById('login-status');
      const btn = document.getElementById('btnIngresar');
      if (!legajo || !pin) { st.className = 'text-xs mt-1 text-center text-rose-400 block'; st.innerText = 'Ingresá tu legajo y PIN.'; return; }
      if (!navigator.onLine) {
        // Sin conexión: intento de login OFFLINE contra el hash local del PIN
        // (solo si el modo offline esta habilitado y la credencial fue cacheada).
        if (btn) btn.disabled = true;
        st.className = 'text-xs mt-1 text-center text-amber-400 block'; st.innerText = 'Verificando credencial local...';
        await iniciarSesionOffline(legajo, pin, st, btn);
        return;
      }
      st.className = 'text-xs mt-1 text-center text-amber-400 block'; st.innerText = 'Verificando...';
      if (btn) btn.disabled = true;
      try {
        const r = (typeof window.loginVigilador === 'function') ? await window.loginVigilador(legajo, pin) : { ok: false, razon: 'sin_auth' };
        if (!r || !r.ok) {
          const cod = r && r.razon;
          st.className = 'text-xs mt-1 text-center text-rose-400 block';
          if (cod === 'bloqueado' || cod === 'auth/too-many-requests') {
            // Bloqueo temporal por fuerza bruta (lo aplica el Worker).
            const seg = Number(r && r.segundosRestantes) || 0;
            const min = Math.ceil(seg / 60);
            st.innerText = seg
              ? `Demasiados intentos. Esperá ${min} min antes de reintentar.`
              : 'Demasiados intentos. Esperá unos minutos.';
          } else {
            // Credenciales invalidas. Avisamos los intentos restantes si quedan pocos.
            const quedan = Number(r && r.intentosRestantes);
            st.innerText = (Number.isFinite(quedan) && quedan > 0 && quedan <= 3)
              ? `Legajo o PIN incorrectos. Te quedan ${quedan} intento(s).`
              : 'Legajo o PIN incorrectos.';
          }
          if (btn) btn.disabled = false;
          return;
        }
        idTokenVig = r.idToken;
        sesionEsOffline = false;   // sesion ONLINE autenticada con idToken
        uidSesion = r.uid || null;
        legajoSesion = String(legajo).trim();
        document.getElementById('loginPin').value = '';
        document.getElementById('pantallaLogin').classList.add('hidden');
        document.getElementById('panelFichaje').classList.remove('hidden');
        document.getElementById('legajo').value = legajoSesion;
        st.className = 'text-xs mt-1 text-center hidden'; st.innerText = '';
        // Recursos del panel: recien ahora, ya autenticado.
        iniciarCamaraSegura();
        cargarModelosIA();
        cargarObjetivos();
        await cargarModoDispositivo();
        await validarLegajo();   // lee SOLO el registro propio, con token
        // Fase 2 (opt-in): si el modo offline esta habilitado o el dispositivo esta
        // vinculado, cacheamos el hash del PIN (PBKDF2+salt) y la config del vigilador
        // para permitir un login OFFLINE posterior. Nunca se guarda el PIN en claro.
        try { await asegurarOfflineCfg(); } catch (_) {}
        try { await cachearCredencialOffline(legajoSesion, pin, uidSesion, (personalActualGlobal && personalActualGlobal.nombre) || document.getElementById('nombre').value, personalActualGlobal, fotoMasterGuardada); } catch (_) {}
        reiniciarInactividad();
        // Ya con sesion activa (idToken + legajo propio), intenta subir las
        // fichadas/alertas offline que pertenezcan a ESTE legajo. Las Reglas de
        // Seguridad atan cada fichada al legajo del uid autenticado, por eso la
        // sincronizacion debe ocurrir con la sesion del propio vigilador.
        if (navigator.onLine) { sincronizarFichadasPendientes(); sincronizarAlertasFichadasPendientes(); sincronizarLoteOffline(); }
      } catch (err) {
        st.className = 'text-xs mt-1 text-center text-rose-400 block';
        st.innerText = 'Error al iniciar sesión.';
        if (btn) btn.disabled = false;
      }
    }

    async function cerrarSesionVigilador() {
      try { if (typeof window._detenerRenovacionToken === 'function') window._detenerRenovacionToken(); } catch (_) {}
      try { if (typeof window.logoutVigilador === 'function') await window.logoutVigilador(); } catch (_) {}
      idTokenVig = null; sesionEsOffline = false; legajoSesion = null; uidSesion = null;
      if (timerInactividad) { clearTimeout(timerInactividad); timerInactividad = null; }
      personalActualGlobal = null; turnoProgramadoGlobal = null; fotoMasterGuardada = null;
      vigiladorInactivoGlobal = false; ultimoTipoFichadaGlobal = '';
      try { limpiarDatosSensiblesAlSalir(); } catch (_) {}
      const panel = document.getElementById('panelFichaje'); if (panel) panel.classList.add('hidden');
      const login = document.getElementById('pantallaLogin'); if (login) login.classList.remove('hidden');
      const st = document.getElementById('login-status'); if (st) { st.className = 'text-xs mt-1 text-center hidden'; st.innerText = ''; }
      const btn = document.getElementById('btnIngresar'); if (btn) btn.disabled = false;
      const ll = document.getElementById('loginLegajo'); if (ll) ll.value = '';
      const lp = document.getElementById('loginPin'); if (lp) lp.value = '';
      const nom = document.getElementById('lblSesionNombre'); if (nom) nom.innerText = '—';
    }
    window.iniciarSesionVigilador = iniciarSesionVigilador;
    window.cerrarSesionVigilador = cerrarSesionVigilador;

    window.onload = async function() {
      actualizarEstadoRed();
      const f = document.getElementById('formLogin');
      if (f) f.addEventListener('submit', iniciarSesionVigilador);

      // Estado offline en la pantalla de login: vinculacion y cola pendiente.
      try { await _migrarSecretoHmacASeguro(); } catch (_) {}   // M5: saca el secreto HMAC del localStorage
      try { purgarCacheOfflineVencido(); } catch (_) {}
      try { refrescarEstadoVinculacion(); } catch (_) {}
      try { refrescarEstadoOfflinePendientes(); } catch (_) {}

      if (navigator.onLine) {
        sincronizarFichadasPendientes();
        sincronizarAlertasFichadasPendientes();
        sincronizarLoteOffline();
      }
    };

    // CARGAR MODELOS DESDE LA CARPETA LOCAL /models
    async function cargarModelosIA() {
      const status = document.getElementById('foto-status');
      status.innerText = "⏳ Cargando modelos de Inteligencia Artificial...";
      status.className = "text-xs text-amber-400 text-center font-semibold";
      
      try {
        const MODEL_URL = './models';

        await faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL);
        await faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL);
        await faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL);

        modelosCargados = true;
        status.innerText = "⚠️ Foto no capturada (IA Lista)";
        status.className = "text-xs text-rose-400 text-center font-semibold";
        console.log("✅ Modelos de IA cargados con éxito desde la carpeta local.");
      } catch (err) {
        console.error("Error al cargar modelos de la IA:", err);
        modelosCargados = false;
        status.innerText = "⚠️ Modo IA no disponible (Error al cargar modelos)";
        status.className = "text-xs text-amber-400 text-center font-semibold";
      }
    }

    window.addEventListener('online', () => {
      actualizarEstadoRed();
      sincronizarFichadasPendientes();
      sincronizarAlertasFichadasPendientes();
      sincronizarLoteOffline();
      try { refrescarEstadoOfflinePendientes(); } catch (_) {}
    });
    
    window.addEventListener('offline', actualizarEstadoRed);

    function iniciarCamaraSegura() {
      const status = document.getElementById('foto-status');
      
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" } })
          .then(stream => { 
            document.getElementById('webcam').srcObject = stream; 
          })
          .catch(err => {
            console.warn("No se pudo iniciar la cámara automáticamente: ", err);
            status.innerText = "⚠️ Cámara pausada o sin permisos (pulse Capturar Foto)";
          });
      } else {
        status.innerText = "⚠️ Su navegador no soporta el acceso a la cámara";
      }
    }

    function actualizarEstadoRed() {
      const indicador = document.getElementById('estadoRed');
      if (!indicador) return;
      if (navigator.onLine) {
        indicador.className = "text-[11px] font-semibold px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30";
        indicador.innerText = "🟢 Online";
      } else {
        indicador.className = "text-[11px] font-semibold px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-500/30";
        indicador.innerText = "⚠️ Modo Offline";
      }
    }

    // RADIO DE SEGURIDAD POR DEFECTO: 100 METROS.
    // Si el objetivo tiene radioPermitido, radio o radioMetros, se usa ese valor.
    const RADIO_OBJETIVO_DEFAULT_METROS = 100;
    // Radio por defecto configurable desde Admin (/configuracionGlobal). Se usa como respaldo
    // cuando el objetivo no define su propio radio.
    let radioGlobalConfigMetros = RADIO_OBJETIVO_DEFAULT_METROS;
    let objetivosDetalleGlobal = [];

    function obtenerDatosObjetivoSeleccionado(nombreObjetivo) {
      return objetivosDetalleGlobal.find(o =>
        String(o.nombre || o.codigo || '').trim() === String(nombreObjetivo || '').trim()
      ) || null;
    }

    function normalizarRadioObjetivo(objetivo) {
      const radio = Number(
        objetivo?.radioPermitido ??
        objetivo?.radio ??
        objetivo?.radioMetros ??
        radioGlobalConfigMetros
      );
      return Number.isFinite(radio) && radio > 0 ? radio : RADIO_OBJETIVO_DEFAULT_METROS;
    }

    function cargarObjetivos() {
      // Radio por defecto configurable desde el panel Admin.
      if (navigator.onLine) {
        fetch(urlAuth(`${URL_FIREBASE}/configuracionGlobal.json?ts=${Date.now()}`), { cache: 'no-store' })
          .then(res => res.json())
          .then(cfg => {
            const r = Number(cfg && cfg.radioFichajeMetros);
            if (Number.isFinite(r) && r > 0) radioGlobalConfigMetros = r;
            biometriaEstrictaGlobal = (cfg && cfg.biometriaEstricta === true);
          }).catch(() => {});
      }
      const objetivosGuardados = JSON.parse(localStorage.getItem('demo_lista_objetivos') || '[]');
      if (objetivosGuardados.length > 0) objetivosDetalleGlobal = objetivosGuardados.map(item => typeof item === 'string' ? { nombre: item } : item);
      if (navigator.onLine) {
        fetch(urlAuth(`${URL_FIREBASE}/objetivos.json?ts=${Date.now()}`), { cache: 'no-store' })
          .then(res => res.json())
          .then(data => {
            if (!data) return;
            const listaNuevos = Object.entries(data).filter(([id,item]) => item && (item.nombre || item.codigo)).map(([id,item]) => ({
              id, nombre:item.nombre||item.codigo, codigo:item.codigo||'', latitud:item.latitud??item.lat??item.latitude??null, longitud:item.longitud??item.lng??item.lon??item.longitude??null, radioPermitido:normalizarRadioObjetivo(item)
            }));
            if (listaNuevos.length) { localStorage.setItem('demo_lista_objetivos',JSON.stringify(listaNuevos)); objetivosDetalleGlobal=listaNuevos; if(personalActualGlobal) aplicarConfiguracionVigilador(personalActualGlobal); }
          }).catch(err=>console.warn('No se pudieron actualizar los objetivos desde Firebase:',err));
      }
    }

    function normalizarObjetivosAsignados(personal) {
      const raw = personal?.objetivosAsignados;
      if (Array.isArray(raw)) return raw.filter(x => x && (x.id || x.firebaseId || x.nombre)).map(x => ({ id:String(x.id||x.firebaseId||''), nombre:String(x.nombre||'') }));
      if (raw && typeof raw === 'object') return Object.entries(raw).map(([id,x]) => ({id:String(x?.id||id),nombre:String(x?.nombre||x||'')}));
      return [];
    }

    function formatearHorarioTurno(inicio, fin) { return inicio && fin ? `${inicio} → ${fin}` : 'Sin horario programado'; }

    function obtenerFechaLocalISO() {
      const d = new Date();
      const y = d.getFullYear();
      const m = String(d.getMonth()+1).padStart(2,'0');
      const day = String(d.getDate()).padStart(2,'0');
      return `${y}-${m}-${day}`;
    }

    async function obtenerTurnoProgramadoParaFecha(legajo, fecha) {
      if (!navigator.onLine) return null;
      try {
        // Consulta ACOTADA por legajo (string): las Reglas solo permiten al vigilador leer su propio legajo.
        const legajoQ=String((typeof legajoSesion!=='undefined'&&legajoSesion)?legajoSesion:legajo).trim();
        const res=await fetch(urlAuth(`${URL_FIREBASE}/asignacionesTurnos.json?orderBy=%22legajo%22&equalTo=%22${encodeURIComponent(legajoQ)}%22&ts=${Date.now()}`),{cache:'no-store'});
        if(!res.ok)return null;
        const data=await res.json();
        if(!data||data.error)return null;
        const lista=Object.entries(data).map(([id,d])=>({...d,id})).filter(d=>mismoLegajo(d.legajo, legajo) && String(d.fecha||'')===String(fecha));
        lista.sort((a,b)=>String(b.actualizadoEn||'').localeCompare(String(a.actualizadoEn||'')));
        return lista[0]||null;
      }catch(e){console.warn('No se pudo obtener la asignación del turno:',e);return null;}
    }

    async function aplicarConfiguracionVigilador(personal) {
      personalActualGlobal=personal||null;
      if(!personal)return;
      localStorage.setItem('personal_config_fichada',JSON.stringify(personal));
      const asignadosRaw=normalizarObjetivosAsignados(personal);
      const asignados=asignadosRaw.map(x=>{
        const detalle=objetivosDetalleGlobal.find(o=>String(o.id||'')===String(x.id||''));
        return { ...x, nombre: detalle?.nombre || x.nombre };
      });
      objetivoAutorizadoIdsGlobal=asignados.map(x=>x.id).filter(Boolean);
      const fecha=obtenerFechaLocalISO();
      turnoProgramadoGlobal=await obtenerTurnoProgramadoParaFecha(personal.legajo,fecha);
      let permitidos=asignados;
      if(turnoProgramadoGlobal?.objetivoId){
        const objetivoTurno = objetivosDetalleGlobal.find(o=>String(o.id||'')===String(turnoProgramadoGlobal.objetivoId));
        permitidos = [{ id:String(turnoProgramadoGlobal.objetivoId), nombre:objetivoTurno?.nombre || turnoProgramadoGlobal.objetivoNombre || '' }];
        objetivoAutorizadoIdsGlobal = permitidos.map(x=>x.id);
      }
      const select=document.getElementById('objetivo'); select.innerHTML='<option value="">Seleccione su puesto asignado</option>';
      permitidos.forEach(o=>select.insertAdjacentHTML('beforeend',`<option value="${escHtmlIdx(o.nombre||'')}" data-objetivo-id="${escHtmlIdx(o.id||'')}">${escHtmlIdx(o.nombre||o.id||'')}</option>`));
      const objStatus=document.getElementById('objetivo-status'); const turnoStatus=document.getElementById('turno-status');
      objStatus.className='text-[11px] mt-1 text-slate-500'; objStatus.innerText=permitidos.length ? `✓ ${permitidos.length} objetivo(s) autorizado(s) para este vigilador.` : '⚠️ No tiene objetivos autorizados. Debe configurarlos el administrador.';
      turnoStatus.classList.remove('hidden'); turnoStatus.className='text-[11px] mt-1 '+(turnoProgramadoGlobal?'text-sky-300':'text-slate-400');
      turnoStatus.innerText=turnoProgramadoGlobal ? `📅 Turno asignado para hoy: ${formatearHorarioTurno(turnoProgramadoGlobal.horaInicio,turnoProgramadoGlobal.horaFin)} · ${turnoProgramadoGlobal.objetivoNombre||''}` : (personal.horarioHabitual?.inicio&&personal.horarioHabitual?.fin ? `🕒 Horario habitual: ${formatearHorarioTurno(personal.horarioHabitual.inicio,personal.horarioHabitual.fin)}` : '⚠️ No hay horario programado para hoy.');
      if(permitidos.length===1) select.value=permitidos[0].nombre||'';
    }



    function calcularDistanciaMetros(lat1, lon1, lat2, lon2) {
      const R = 6371000;
      const toRad = grados => grados * Math.PI / 180;
      const dLat = toRad(lat2 - lat1);
      const dLon = toRad(lon2 - lon1);
      const a =
        Math.sin(dLat / 2) ** 2 +
        Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
        Math.sin(dLon / 2) ** 2;
      return 2 * R * Math.asin(Math.sqrt(a));
    }

    function mostrarErrorUbicacion(mensaje) {
      const divResultado = document.getElementById('resultado');
      divResultado.className = "p-3 rounded-xl text-xs text-center bg-rose-950 text-rose-200 border border-rose-500";
      divResultado.innerText = mensaje;
      divResultado.classList.remove('hidden');
    }

    function formatearDistanciaObjetivo(distanciaMetros) {
      const metros = Math.max(0, Number(distanciaMetros) || 0);
      if (metros < 1000) {
        return `${Math.round(metros)} m`;
      }
      return `${(metros / 1000).toFixed(2).replace('.', ',')} km (${Math.round(metros).toLocaleString('es-AR')} m)`;
    }

    async function obtenerDatosObjetivoParaFichada(nombreObjetivo) {
      let detalle = obtenerDatosObjetivoSeleccionado(nombreObjetivo);
      const tieneCoordenadas = detalle &&
        Number.isFinite(Number(detalle.latitud)) &&
        Number.isFinite(Number(detalle.longitud)) &&
        !(Number(detalle.latitud) === 0 && Number(detalle.longitud) === 0);

      if (tieneCoordenadas) return detalle;

      // Refresco puntual: evita depender de que la carga inicial haya terminado.
      if (!navigator.onLine) return detalle;

      try {
        const res = await fetch(urlAuth(`${URL_FIREBASE}/objetivos.json?ts=${Date.now()}`), { cache: 'no-store' });
        if (!res.ok) throw new Error(`Firebase respondió ${res.status}`);
        const data = await res.json();
        const buscado = String(nombreObjetivo || '').trim().toLowerCase();
        const encontrado = Object.entries(data || {}).find(([id, item]) => {
          const nombre = String(item?.nombre || item?.codigo || id || '').trim().toLowerCase();
          return nombre === buscado;
        });

        if (encontrado) {
          const [id, item] = encontrado;
          detalle = {
            id,
            ...item,
            nombre: item?.nombre || item?.codigo || id,
            latitud: item?.latitud ?? item?.lat ?? item?.latitude ?? null,
            longitud: item?.longitud ?? item?.lng ?? item?.lon ?? item?.longitude ?? null,
            radioPermitido: normalizarRadioObjetivo(item)
          };

          // Actualizamos la caché para las siguientes fichadas.
          const indice = objetivosDetalleGlobal.findIndex(o =>
            String(o.nombre || o.codigo || '').trim().toLowerCase() === buscado
          );
          if (indice >= 0) objetivosDetalleGlobal[indice] = detalle;
          else objetivosDetalleGlobal.push(detalle);
          localStorage.setItem('demo_lista_objetivos', JSON.stringify(objetivosDetalleGlobal));
          return detalle;
        }
      } catch (err) {
        console.warn('No se pudieron recuperar las coordenadas del objetivo desde Firebase:', err);
      }

      return detalle;
    }

    async function validarUbicacionObjetivo(lat, lng, objetivo, contexto = {}) {
      const detalle = await obtenerDatosObjetivoParaFichada(objetivo);
      const latObjetivo = Number(detalle?.latitud);
      const lngObjetivo = Number(detalle?.longitud);
      const radioPermitido = normalizarRadioObjetivo(detalle);

      if (!Number.isFinite(latObjetivo) || !Number.isFinite(lngObjetivo) ||
          (latObjetivo === 0 && lngObjetivo === 0)) {
        mostrarErrorUbicacion(
          `❌ No se puede validar la ubicación de "${objetivo}". No se pudieron obtener sus coordenadas GPS desde Firebase.`
        );
        return null;
      }

      const distancia = calcularDistanciaMetros(lat, lng, latObjetivo, lngObjetivo);
      const distanciaTexto = formatearDistanciaObjetivo(distancia);

      if (distancia > radioPermitido) {
        const alerta = {
          tipoAlerta: "FICHADA_BLOQUEADA_UBICACION",
          estado: "NUEVA",
          legajo: contexto.legajo || "",
          nombre: contexto.nombre || (contexto.legajo ? `Legajo ${contexto.legajo}` : "Sin nombre"),
          objetivo: objetivo || "Sin objetivo",
          tipoFichada: contexto.tipo || "",
          distanciaMetros: Math.round(distancia),
          distanciaTexto,
          radioPermitidoMetros: Math.round(radioPermitido),
          precisionGPSMetros: Number.isFinite(contexto.precisionGPS) ? Math.round(contexto.precisionGPS) : null,
          latitud: lat,
          longitud: lng,
          latitudObjetivo: latObjetivo,
          longitudObjetivo: lngObjetivo,
          fechaHora: new Date().toISOString(),
          mensaje: `Intento de fichada bloqueado: distancia ${distanciaTexto} del objetivo.`
        };

        registrarAlertaFichadaBloqueada(alerta);

        mostrarErrorUbicacion(
          `❌ FICHADA BLOQUEADA. Estás a ${distanciaTexto} del objetivo. Radio permitido: ${Math.round(radioPermitido)} m. Debes encontrarte dentro del radio del objetivo.`
        );
        return null;
      }

      return {
        distanciaMetros: Math.round(distancia),
        distanciaTexto,
        radioPermitido: Math.round(radioPermitido),
        latObjetivo,
        lngObjetivo
      };
    }


    async function registrarAlertaFichadaBloqueada(alerta) {
      if (!alerta) return;

      if (!navigator.onLine) {
        const pendientes = JSON.parse(localStorage.getItem('alertas_fichadas_pendientes') || '[]');
        pendientes.push(alerta);
        localStorage.setItem('alertas_fichadas_pendientes', JSON.stringify(pendientes));
        return;
      }

      try {
        const res = await fetch(urlAuth(`${URL_FIREBASE}/alertasFichadas.json`), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(alerta)
        });
        if (!res.ok) throw new Error("No se pudo registrar la alerta de fichada.");
      } catch (err) {
        console.warn("No se pudo enviar la alerta de fichada. Se guardará para sincronizar luego.", err);
        const pendientes = JSON.parse(localStorage.getItem('alertas_fichadas_pendientes') || '[]');
        pendientes.push(alerta);
        localStorage.setItem('alertas_fichadas_pendientes', JSON.stringify(pendientes));
      }
    }

    function sincronizarAlertasFichadasPendientes() {
      if (!navigator.onLine) return;
      const pendientes = JSON.parse(localStorage.getItem('alertas_fichadas_pendientes') || '[]');
      if (!pendientes.length) return;

      const alerta = pendientes[0];
      fetch(urlAuth(`${URL_FIREBASE}/alertasFichadas.json`), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(alerta)
      })
      .then(res => {
        if (!res.ok) throw new Error("Firebase rechazó la alerta pendiente.");
        return res.json();
      })
      .then(() => {
        const restantes = JSON.parse(localStorage.getItem('alertas_fichadas_pendientes') || '[]');
        restantes.shift();
        localStorage.setItem('alertas_fichadas_pendientes', JSON.stringify(restantes));
        if (restantes.length) sincronizarAlertasFichadasPendientes();
      })
      .catch(err => console.warn("La alerta pendiente seguirá en cola:", err));
    }

    function validarLegajo() {
      const legajoInput = (legajoSesion || document.getElementById('legajo').value).trim();
      const statusLbl = document.getElementById('legajo-status');
      const badgeEstado = document.getElementById('ultimo-estado-badge');
      fotoMasterGuardada = null;
      
      if (!legajoInput) {
        badgeEstado.classList.add('hidden');
        ultimoTipoFichadaGlobal = "";
        return;
      }

      if (!navigator.onLine) {
        statusLbl.className = "text-xs mt-1 text-slate-400 block";
        statusLbl.innerText = "Modo Offline: Verificación en servidor omitida.";
        verificarUltimoEstadoLocal(legajoInput);
        return;
      }

      statusLbl.className = "text-xs mt-1 text-amber-400 block";
      statusLbl.innerText = "Buscando legajo y foto oficial...";

      Promise.all([
        fetchScoped('personal', legajoInput),
        fetchScoped('fichadas', legajoInput)
      ])
      .then(([dataPersonal, dataFichadas]) => {
        let encontrado = null;
        if (dataPersonal) {
          if (dataPersonal[legajoInput]) {
            encontrado = dataPersonal[legajoInput];
          } else {
            Object.values(dataPersonal).forEach(personal => {
              if (mismoLegajo(personal.legajo, legajoInput)) {
                encontrado = personal;
              }
            });
          }
        }

        if (encontrado) {
          const estadoVigilador = String(encontrado.estado || 'ACTIVO').trim().toUpperCase();
          vigiladorInactivoGlobal = (estadoVigilador !== 'ACTIVO');
          document.getElementById('nombre').value = encontrado.nombre || "";
          const lblNom = document.getElementById('lblSesionNombre'); if (lblNom) lblNom.innerText = encontrado.nombre || legajoInput;
          fotoMasterGuardada = encontrado.fotoMaster || null;
          if (vigiladorInactivoGlobal) {
            statusLbl.className = "text-xs mt-1 text-rose-400 block";
            statusLbl.innerText = `⛔ Legajo INACTIVO / dado de baja. No podés fichar. Contactá al administrador.`;
          } else {
            statusLbl.className = "text-xs mt-1 text-emerald-400 block";
            statusLbl.innerText = `✓ ${encontrado.nombre || 'Legajo Encontrado'} ${fotoMasterGuardada ? '📸 (Foto Master OK)' : '⚠️ (Sin Foto Master)'}`;
          }
        } else {
          vigiladorInactivoGlobal = false;
          document.getElementById('nombre').value = "";
          statusLbl.className = "text-xs mt-1 text-rose-400 block";
          statusLbl.innerText = "❌ Legajo no encontrado en el sistema.";
        }

        if (encontrado && !vigiladorInactivoGlobal) { aplicarConfiguracionVigilador(encontrado); }
        else { personalActualGlobal = null; turnoProgramadoGlobal = null; document.getElementById('objetivo').innerHTML = '<option value="">' + (vigiladorInactivoGlobal ? 'Legajo inactivo' : 'Legajo no autorizado') + '</option>'; document.getElementById('objetivo-status').innerText = ''; document.getElementById('turno-status').classList.add('hidden'); }

        let ultimaFichadaTipo = "";
        let timestampUltimo = 0;
        let ultimaFichadaObj = null;

        if (dataFichadas) {
          Object.values(dataFichadas).forEach(f => {
            if (mismoLegajo(f.legajo, legajoInput)) {
              // Fichada ANULADA/DESAPROBADA por el administrador: se conserva en la
              // base como evidencia (marca 'anulada' o estado 'ANULADA'), pero NO
              // debe contar como el ultimo estado valido del vigilador. Si no la
              // descartamos, una ENTRADA anulada seguiria habilitando una SALIDA.
              const estadoF = String(f.estado || '').trim().toUpperCase();
              if (f.anulada === true || estadoF === 'ANULADA' || estadoF === 'DESAPROBADA') return;
              // Hora OFICIAL para determinar la ultima fichada (ENTRADA/SALIDA): sello del
              // servidor Firebase unificado (timestampServidor, .sv=timestamp, NO manipulable)
              // primero; 'timestamp' queda como compat de fichadas antiguas y el reloj del
              // dispositivo SOLO como fallback final.
              const refTiempo = f.timestampServidor || f.timestampEstimadoDispositivo || f.timestamp || f.fechaHoraDispositivo;
              let tiempoFichada = refTiempo ? new Date(refTiempo).getTime() : 0;
              if (tiempoFichada >= timestampUltimo) {
                timestampUltimo = tiempoFichada;
                ultimaFichadaTipo = String(f.tipo || "").trim().toUpperCase();
                ultimaFichadaObj = f;
              }
            }
          });
        }

        let pendientes = JSON.parse(localStorage.getItem('fichadas_pendientes') || '[]');
        pendientes.forEach(p => {
          if (mismoLegajo(p.legajo, legajoInput)) {
            let tiempoP = p.fechaHoraDispositivo ? new Date(p.fechaHoraDispositivo).getTime() : 0;
            if (tiempoP >= timestampUltimo) {
              timestampUltimo = tiempoP;
              ultimaFichadaTipo = String(p.tipo || "").trim().toUpperCase();
              ultimaFichadaObj = p;
            }
          }
        });

        ultimoTipoFichadaGlobal = ultimaFichadaTipo;
        ultimaEntradaActivaGlobal = capturarEntradaActiva(ultimaFichadaTipo, ultimaFichadaObj);
        actualizarBotonSalidaSegunObjetivo();
        // Persistimos el estado REAL leido del servidor para que, si despues se
        // corta internet, el modo offline conozca la ultima ENTRADA/SALIDA.
        guardarUltimoEstadoConocido(legajoInput, ultimaFichadaTipo, timestampUltimo, ultimaEntradaActivaGlobal);

        if (ultimaFichadaTipo) {
          badgeEstado.classList.remove('hidden');
          if (ultimaFichadaTipo === 'ENTRADA') {
            badgeEstado.className = "text-xs mt-1.5 font-semibold text-emerald-400 block";
            badgeEstado.innerText = "ℹ️ Estado actual: Ya registraste una ENTRADA. Tu próxima acción debe ser SALIDA.";
          } else {
            badgeEstado.className = "text-xs mt-1.5 font-semibold text-slate-400 block";
            badgeEstado.innerText = "ℹ️ Estado actual: Última fichada fue SALIDA. Puedes marcar ENTRADA.";
          }
        } else {
          badgeEstado.classList.add('hidden');
        }

      })
      .catch(() => {
        statusLbl.className = "text-xs mt-1 text-slate-400 block";
        statusLbl.innerText = "Error de conexión al validar legajo.";
      });
    }

    // Devuelve el turno/horario de la ENTRADA activa para que la SALIDA lo
    // herede (turnos nocturnos que cruzan la medianoche). null si no hay
    // ENTRADA abierta.
    function capturarEntradaActiva(tipo, obj) {
      if (tipo !== 'ENTRADA' || !obj) return null;
      return {
        horarioProgramadoInicio: obj.horarioProgramadoInicio || null,
        horarioProgramadoFin: obj.horarioProgramadoFin || null,
        horarioProgramadoOrigen: obj.horarioProgramadoOrigen || null,
        asignacionTurnoId: obj.asignacionTurnoId || null,
        objetivo: obj.objetivo || null,
        objetivoAutorizadoId: obj.objetivoAutorizadoId || null,
        fechaHoraDispositivo: obj.fechaHoraDispositivo || null
      };
    }

    // ===================================================================
    //  ULTIMO ESTADO CONOCIDO (snapshot local del estado ENTRADA/SALIDA)
    // ===================================================================
    // Cuando se ficha CON internet, el estado real (ultima ENTRADA/SALIDA) vive
    // en Firebase, pero el telefono no lo recordaba. Al quedarse sin conexion no
    // "veia" la ENTRADA hecha online y bloqueaba la SALIDA offline. Aca cacheamos
    // el ultimo estado conocido por legajo para que el modo offline lo respete.
    // Es SOLO logica de cliente: el servidor sigue siendo la autoridad final.
    const LS_ULTIMO_ESTADO = 'vigix_ultimo_estado';
    function guardarUltimoEstadoConocido(legajo, tipo, tsMs, entradaActiva) {
      try {
        const k = String(legajo || '').trim();
        if (!k) return;
        const all = JSON.parse(localStorage.getItem(LS_ULTIMO_ESTADO) || '{}') || {};
        all[k] = {
          tipo: String(tipo || '').trim().toUpperCase(),
          ts: Number(tsMs) || Date.now(),
          entradaActiva: entradaActiva || null,
          guardadoEn: new Date().toISOString()
        };
        localStorage.setItem(LS_ULTIMO_ESTADO, JSON.stringify(all));
      } catch (_) {}
    }
    // Lectura tolerante: compara por legajo normalizado (mismoLegajo) para no
    // fallar por ceros a la izquierda u otras variantes de tipeo.
    function leerUltimoEstadoConocido(legajo) {
      try {
        const all = JSON.parse(localStorage.getItem(LS_ULTIMO_ESTADO) || '{}') || {};
        if (all[String(legajo || '').trim()]) return all[String(legajo || '').trim()];
        for (const k of Object.keys(all)) {
          if (mismoLegajo(k, legajo)) return all[k];
        }
        return null;
      } catch (_) { return null; }
    }

    function verificarUltimoEstadoLocal(legajoInput) {
      let ultimaFichadaTipo = "";
      let timestampUltimo = 0;
      let ultimaFichadaObj = null;

      // 1) Punto de partida: el ULTIMO ESTADO CONOCIDO online, cacheado en este
      //    telefono la ultima vez que hubo internet. Asi una ENTRADA fichada
      //    online se "ve" aunque ahora estemos sin conexion.
      const snap = leerUltimoEstadoConocido(legajoInput);
      if (snap && snap.tipo) {
        timestampUltimo = Number(snap.ts) || 0;
        ultimaFichadaTipo = String(snap.tipo).trim().toUpperCase();
        ultimaFichadaObj = snap.entradaActiva
          ? Object.assign({ tipo: ultimaFichadaTipo }, snap.entradaActiva)
          : null;
      }

      // 2) La cola offline puede tener fichadas mas nuevas que el snapshot: gana
      //    siempre la mas reciente por fecha/hora del dispositivo.
      let pendientes = JSON.parse(localStorage.getItem('fichadas_pendientes') || '[]');
      pendientes.forEach(p => {
        if (mismoLegajo(p.legajo, legajoInput)) {
          let tiempoP = p.fechaHoraDispositivo ? new Date(p.fechaHoraDispositivo).getTime() : 0;
          if (tiempoP >= timestampUltimo) {
            timestampUltimo = tiempoP;
            ultimaFichadaTipo = String(p.tipo || "").trim().toUpperCase();
            ultimaFichadaObj = p;
          }
        }
      });

      ultimoTipoFichadaGlobal = ultimaFichadaTipo;
      ultimaEntradaActivaGlobal = capturarEntradaActiva(ultimaFichadaTipo, ultimaFichadaObj);
      actualizarBotonSalidaSegunObjetivo();
      const badgeEstado = document.getElementById('ultimo-estado-badge');

      if (ultimaFichadaTipo) {
        badgeEstado.classList.remove('hidden');
        if (ultimaFichadaTipo === 'ENTRADA') {
          badgeEstado.className = "text-xs mt-1.5 font-semibold text-emerald-400 block";
          badgeEstado.innerText = "ℹ️ Estado actual (Offline): Tienes una ENTRADA pendiente.";
        } else {
          badgeEstado.className = "text-xs mt-1.5 font-semibold text-slate-400 block";
          badgeEstado.innerText = "ℹ️ Estado actual (Offline): Última fichada fue SALIDA.";
        }
      } else {
        badgeEstado.classList.add('hidden');
      }
    }

    async function capturarFoto() {
      const video = document.getElementById('webcam');
      const canvas = document.getElementById('canvas');
      const preview = document.getElementById('preview');
      const status = document.getElementById('foto-status');
      const btn = document.getElementById('btnCapturar');

      if (!video.srcObject && navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        try {
          const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" } });
          video.srcObject = stream;
        } catch(err) {
          alert("No se pudo acceder a la cámara. Verifique los permisos del navegador.");
          return;
        }
      }

      btn.disabled = true;
      status.innerText = "🔍 Analizando rostro e identidad con IA...";
      status.className = "text-xs text-amber-400 text-center font-semibold";

      setTimeout(async () => {
        await realizarCapturaIA(video, canvas, preview, status);
        btn.disabled = false;
      }, 200);
    }

    // INSPECCIÓN PRECISA DE TEXTURA PARA DETECTAR PANTALLAS HD
    function analizarTexturaSuperficial(ctx, box) {
      const margen = 15;
      const x = Math.max(0, Math.floor(box.x - margen));
      const y = Math.max(0, Math.floor(box.y - margen));
      const w = Math.min(ctx.canvas.width - x, Math.floor(box.width + (margen * 2)));
      const h = Math.min(ctx.canvas.height - y, Math.floor(box.height + (margen * 2)));

      if (w <= 0 || h <= 0) return { esSospechoso: false, motivo: "" };

      const imageData = ctx.getImageData(x, y, w, h);
      const data = imageData.data;
      
      let sumaGris = 0;
      let totalPixeles = data.length / 4;
      let pixelesSaturadosBrillo = 0;

      const valoresGris = new Uint8Array(totalPixeles);
      for (let i = 0; i < data.length; i += 4) {
        const r = data[i];
        const g = data[i+1];
        const b = data[i+2];
        
        const gris = 0.299 * r + 0.587 * g + 0.114 * b;
        valoresGris[i / 4] = gris;
        sumaGris += gris;

        if (r > 245 && g > 245 && b > 245) {
          pixelesSaturadosBrillo++;
        }
      }

      const promedio = sumaGris / totalPixeles;

      let sumaDiferenciasCuadradas = 0;
      for (let i = 0; i < totalPixeles; i++) {
        sumaDiferenciasCuadradas += Math.pow(valoresGris[i] - promedio, 2);
      }
      
      const desviacionEstandard = Math.sqrt(sumaDiferenciasCuadradas / totalPixeles);
      const porcentajeBrillo = (pixelesSaturadosBrillo / totalPixeles) * 100;

      if (desviacionEstandard < 8.0 && porcentajeBrillo > 12.0) {
        return {
          esSospechoso: true,
          motivo: `Patrón liso detectado en segundo plano (Posible imagen en pantalla HD - Desv: ${desviacionEstandard.toFixed(1)}, Brillo: ${porcentajeBrillo.toFixed(1)}%)`
        };
      }

      return { esSospechoso: false, motivo: "" };
    }

    async function realizarCapturaIA(video, canvas, preview, status) {
      sospechaFraudeGlobal = false;
      motivoSospechaGlobal = "";

      const MAX_WIDTH = 320;
      const originalWidth = video.videoWidth || 640;
      const originalHeight = video.videoHeight || 480;

      let targetWidth = MAX_WIDTH;
      let targetHeight = Math.round((originalHeight * MAX_WIDTH) / originalWidth);

      canvas.width = targetWidth;
      canvas.height = targetHeight;
      
      const ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, targetWidth, targetHeight);

      if (!modelosCargados) {
        fotoBase64Global = canvas.toDataURL('image/jpeg', 0.35);
        preview.src = fotoBase64Global;
        preview.classList.remove('hidden');
        resultadoSimilitudGlobal = "IA_NO_DISPONIBLE";
        status.innerText = "⚠️ Foto capturada sin análisis facial de IA.";
        status.className = "text-xs text-amber-400 text-center font-semibold";
        return;
      }

      // 1. DETECTAR ROSTRO Y EXTRAER VECTOR MATEMÁTICO DE LA SELFIE
      const deteccionSelfie = await faceapi.detectSingleFace(canvas, new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.25 }))
                                          .withFaceLandmarks()
                                          .withFaceDescriptor();

      if (!deteccionSelfie) {
        status.innerText = "❌ Rechazado: No se detecta un rostro humano claro.";
        status.className = "text-xs text-rose-400 text-center font-semibold";
        preview.classList.add('hidden');
        fotoBase64Global = "";
        return;
      }

      const box = deteccionSelfie.detection.box;

      // 2. FILTRO DE TAMAÑO RELATIVO (Evita fotos lejanas/papeles en miniatura)
      const altoRelativo = box.height / canvas.height;
      if (altoRelativo < 0.25) {
        status.innerText = "❌ Rechazado: Acerque la cara a la cámara (rostro muy pequeño).";
        status.className = "text-xs text-rose-400 text-center font-semibold";
        preview.classList.add('hidden');
        fotoBase64Global = "";
        return;
      }

      // 3. FILTRO ANÁLISIS BORDES DE PAPEL/HOJA SATURADA
      const startX = Math.max(0, box.x - 20);
      const startY = Math.max(0, box.y - 20);
      const width = Math.min(canvas.width - startX, box.width + 40);
      const height = Math.min(canvas.height - startY, box.height + 40);
      
      const imgData = ctx.getImageData(startX, startY, width, height);
      let pixelesSaturados = 0;
      for (let i = 0; i < imgData.data.length; i += 4) {
        if (imgData.data[i] > 240 && imgData.data[i+1] > 240 && imgData.data[i+2] > 240) {
          pixelesSaturados++;
        }
      }
      if ((pixelesSaturados / (imgData.data.length / 4)) > 0.20) {
        status.innerText = "❌ Rechazado: Se identificaron bordes de marco o papel alrededor del rostro.";
        status.className = "text-xs text-rose-400 text-center font-semibold";
        preview.classList.add('hidden');
        fotoBase64Global = "";
        return;
      }

      // 4. COMPARAR CON FOTO MASTER CON UMBRAL MÍNIMO DEL 55%
      if (fotoMasterGuardada) {
        try {
          const imgMaster = new Image();
          imgMaster.crossOrigin = "anonymous";
          imgMaster.src = fotoMasterGuardada;
          await imgMaster.decode();

          const deteccionMaster = await faceapi.detectSingleFace(imgMaster, new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.25 }))
                                               .withFaceLandmarks()
                                               .withFaceDescriptor();

          if (deteccionMaster) {
            const distancia = faceapi.euclideanDistance(deteccionSelfie.descriptor, deteccionMaster.descriptor);
            const porcentajeSimilitud = Math.round((1 - distancia) * 100);

            // UMBRAL DEL 55% COINCIDENCIA MÍNIMA (Distancia > 0.45 rechaza)
            if (distancia > 0.45) {
              status.innerText = `❌ Rechazado: Coincidencia insuficiente (${porcentajeSimilitud}%). Requerido: 55%.`;
              status.className = "text-xs text-rose-400 text-center font-semibold";
              preview.classList.add('hidden');
              fotoBase64Global = "";
              return;
            }

            // ANÁLISIS EN SEGUNDO PLANO DE TEXTURA PIEL VS PANTALLAS
            const analisisTextura = analizarTexturaSuperficial(ctx, box);
            if (analisisTextura.esSospechoso) {
              sospechaFraudeGlobal = true;
              motivoSospechaGlobal = analisisTextura.motivo;
            }

            resultadoSimilitudGlobal = `${porcentajeSimilitud}% COINCIDENCIA`;
            status.innerText = `✓ Rostro Validado (${porcentajeSimilitud}% Coincidencia)`;
            status.className = "text-xs text-emerald-400 text-center font-semibold";
          } else {
            resultadoSimilitudGlobal = "MASTER_SIN_ROSTRO";
            status.innerText = "✓ Rostro Humano OK (Master ilegible)";
            status.className = "text-xs text-emerald-400 text-center font-semibold";
          }
        } catch (e) {
          console.warn("Error evaluando Foto Master:", e);
          resultadoSimilitudGlobal = "ERROR_EVALUACION";
        }
      } else {
        resultadoSimilitudGlobal = "SIN_MASTER";
        status.innerText = "✓ Rostro Humano Detectado (Sin foto master de cotejo)";
        status.className = "text-xs text-emerald-400 text-center font-semibold";
      }

      fotoBase64Global = canvas.toDataURL('image/jpeg', 0.35);
      preview.src = fotoBase64Global;
      preview.classList.remove('hidden');
    }

    async function procesarEnvio(tipoRecibido) {
      const tipo = String(tipoRecibido).trim().toUpperCase();
      const legajo = document.getElementById('legajo').value.trim();
      const nombre = document.getElementById('nombre').value.trim();
      const objetivo = document.getElementById('objetivo').value;

      // Guarda de sesion. IMPORTANTE: debe permitir la sesion OFFLINE.
      // En modo offline NO existe idToken (idTokenVig === null): la identidad ya
      // quedo probada por el hash local del PIN al iniciar sesion, y la fichada se
      // guardara en la cola offline firmada por el dispositivo (no usa idToken).
      // Se usa 'sesionEsOffline' (no navigator.onLine, que es poco fiable) para
      // solo forzar re-login si (a) no hay sesion, o (b) es una sesion ONLINE que
      // perdio su idToken (token realmente vencido).
      if (!legajoSesion) {
        alert('Tu sesión expiró. Volvé a ingresar tu legajo y PIN.');
        cerrarSesionVigilador();
        return;
      }
      if (!idTokenVig && !sesionEsOffline) {
        alert('Tu sesión expiró. Volvé a ingresar tu legajo y PIN.');
        cerrarSesionVigilador();
        return;
      }

      if (!legajo || !objetivo) {
        alert("Por favor seleccione un Objetivo.");
        return;
      }

      const opcionObjetivo = document.getElementById('objetivo').selectedOptions[0];
      const objetivoIdSeleccionado = opcionObjetivo ? opcionObjetivo.dataset.objetivoId : '';
      if (!personalActualGlobal || String(personalActualGlobal.legajo||'').trim() !== String(legajo).trim()) {
        alert('❌ No se pudo validar la configuración del vigilador. Ingrese nuevamente su legajo.'); return;
      }
      // Bloqueo por estado: un legajo INACTIVO / dado de baja no puede fichar.
      if (vigiladorInactivoGlobal) {
        alert('⛔ FICHADA BLOQUEADA. Tu legajo figura como INACTIVO / dado de baja. Contactá al administrador.'); return;
      }
      // El PIN ya fue validado contra Firebase Auth al iniciar sesión; no se
      // vuelve a pedir en cada fichada. La sesión autenticada (idToken) es la
      // prueba de identidad para leer/escribir en la base.
      if (!objetivoIdSeleccionado || !objetivoAutorizadoIdsGlobal.includes(String(objetivoIdSeleccionado))) {
        alert('❌ FICHADA BLOQUEADA. Ese objetivo no está autorizado para este vigilador.'); return;
      }
      // Turno nocturno: una SALIDA que cierra una ENTRADA activa NO exige que
      // haya un turno programado para HOY (la entrada pudo abrirse ayer y cruzar
      // la medianoche). En ese caso el horario se hereda de la ENTRADA (ver mas
      // abajo, override del payload). Para ENTRADA si se exige horario vigente.
      const cerrandoEntradaActiva = (tipo === "SALIDA" && ultimoTipoFichadaGlobal === "ENTRADA");
      if (!cerrandoEntradaActiva && !turnoProgramadoGlobal && (!personalActualGlobal.horarioHabitual?.inicio || !personalActualGlobal.horarioHabitual?.fin)) {
        alert('❌ FICHADA BLOQUEADA. No hay un horario programado para este vigilador. El administrador debe asignar un horario.'); return;
      }

      if (ultimoTipoFichadaGlobal === "ENTRADA" && tipo === "ENTRADA") {
        alert("⚠️ Acción bloqueada: Ya registraste una ENTRADA previa. No puedes volver a fichar entrada hasta registrar tu SALIDA.");
        const divRes = document.getElementById('resultado');
        divRes.className = "p-3 rounded-xl text-xs text-center bg-rose-950 text-rose-200 border border-rose-500";
        divRes.innerText = "❌ Bloqueado: Ya registraste una entrada anterior.";
        divRes.classList.remove('hidden');
        return;
      }

      // Maquina de estados: SIN_SERVICIO -> ENTRADA -> SALIDA -> ENTRADA.
      // Bloquea una SALIDA cuando no hay una ENTRADA activa (sin fichada previa
      // o cuando la ultima fichada valida ya fue una SALIDA).
      if (tipo === "SALIDA" && ultimoTipoFichadaGlobal !== "ENTRADA") {
        const motivo = (ultimoTipoFichadaGlobal === "SALIDA")
          ? "Tu última fichada válida ya fue una SALIDA. Tu próxima acción debe ser una ENTRADA."
          : "No tenés una ENTRADA activa. Primero recordá tu ENTRADA antes de marcar SALIDA.";
        alert("⚠️ Acción bloqueada: " + motivo);
        const divRes = document.getElementById('resultado');
        divRes.className = "p-3 rounded-xl text-xs text-center bg-rose-950 text-rose-200 border border-rose-500";
        divRes.innerText = "❌ Bloqueado: SALIDA sin una ENTRADA activa.";
        divRes.classList.remove('hidden');
        return;
      }

      // Coherencia de OBJETIVO: una SALIDA debe cerrarse en el MISMO objetivo
      // donde se abrio la ENTRADA activa. Sin esto, un vigilador podia tomar
      // servicio en el objetivo A y marcar la SALIDA en el objetivo B, dejando
      // la ENTRADA de A abierta y ensuciando los reportes. Solo validamos si
      // conocemos el objetivo de la ENTRADA (fichadas viejas podrian no tenerlo
      // guardado; en ese caso no bloqueamos, por compatibilidad).
      if (tipo === "SALIDA" && ultimoTipoFichadaGlobal === "ENTRADA" && ultimaEntradaActivaGlobal) {
        const idObjetivoEntrada = String(ultimaEntradaActivaGlobal.objetivoAutorizadoId || '').trim();
        const idObjetivoSalida = String(objetivoIdSeleccionado || '').trim();
        if (idObjetivoEntrada && idObjetivoSalida && idObjetivoEntrada !== idObjetivoSalida) {
          const nombreObjEntrada = ultimaEntradaActivaGlobal.objetivo || 'el objetivo donde tomaste servicio';
          alert("⚠️ Acción bloqueada: tomaste servicio en \"" + nombreObjEntrada + "\". La SALIDA tenés que darla en ESE mismo objetivo, no en otro. Seleccioná \"" + nombreObjEntrada + "\" para poder marcar tu salida.");
          const divRes = document.getElementById('resultado');
          divRes.className = "p-3 rounded-xl text-xs text-center bg-rose-950 text-rose-200 border border-rose-500";
          divRes.innerText = "❌ Bloqueado: la SALIDA debe ser en el mismo objetivo de la ENTRADA (" + nombreObjEntrada + ").";
          divRes.classList.remove('hidden');
          // Alerta VISUAL: resaltamos el selector de objetivo en rojo con una
          // sacudida breve y lo enfocamos, para que se vea claro cual hay que
          // elegir. Es aditivo (clase 'objetivo-error' de styles.css): no cambia
          // las clases base del select. La marca se quita sola a los 4 seg o en
          // cuanto el vigilador cambia de opcion.
          const selObjetivo = document.getElementById('objetivo');
          if (selObjetivo) {
            selObjetivo.classList.add('objetivo-error');
            try { selObjetivo.focus(); selObjetivo.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (e) {}
            setTimeout(() => selObjetivo.classList.remove('objetivo-error'), 4000);
            const limpiarMarcaObjetivo = function () {
              selObjetivo.classList.remove('objetivo-error');
              selObjetivo.removeEventListener('change', limpiarMarcaObjetivo);
            };
            selObjetivo.addEventListener('change', limpiarMarcaObjetivo);
          }
          return;
        }
      }

      localStorage.setItem('demo_ultimo_objetivo', objetivo);

      if (!fotoBase64Global) {
        alert("Primero capture una selfie válida haciendo clic en 'CAPTURAR Y VALIDAR ROSTRO'.");
        return;
      }

      // 🛡️ MODO BIOMÉTRICO ESTRICTO (fail-closed): si el Admin lo activó, solo se
      // permite fichar cuando hubo una COINCIDENCIA facial real contra la Foto
      // Master. Cualquier otro estado (IA no disponible, sin master, master
      // ilegible, error o rostro no evaluado) BLOQUEA la fichada en vez de
      // dejarla pasar marcada para revisión.
      if (biometriaEstrictaGlobal && !/COINCIDENCIA/.test(String(resultadoSimilitudGlobal))) {
        const divRes = document.getElementById('resultado');
        divRes.className = "p-3 rounded-xl text-xs text-center bg-rose-950 text-rose-200 border border-rose-500";
        divRes.innerText = "❌ FICHADA BLOQUEADA (modo estricto): no se validó tu rostro contra la Foto Master. Reintentá con buena luz y de frente; si no tenés Foto Master cargada, contactá al administrador.";
        divRes.classList.remove('hidden');
        return;
      }

      const divResultado = document.getElementById('resultado');
      divResultado.className = "p-3 rounded-xl text-xs text-center bg-slate-700 text-white";
      divResultado.innerText = "📍 Verificando ubicación GPS y distancia al objetivo...";
      divResultado.classList.remove('hidden');

      if (!navigator.geolocation) {
        mostrarErrorUbicacion("❌ El dispositivo/navegador no soporta localización GPS.");
        return;
      }

      navigator.geolocation.getCurrentPosition(
        pos => {
          const lat = pos.coords.latitude;
          const lng = pos.coords.longitude;
          const precisionGPS = Number(pos.coords.accuracy);

          if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat === 0 || lng === 0) {
            mostrarErrorUbicacion("❌ No se obtuvo una coordenada GPS válida. Activa la ubicación para fichar.");
            return;
          }

          // 🛡️ Detección de ubicación simulada / Fake GPS ANTES de permitir el guardado.
          const esGpsFalso = (pos.coords.isFromMockProvider === true) || (pos.mocked === true);
          const precisionSospechosa = (precisionGPS === 0);
          if (esGpsFalso || precisionSospechosa) {
            mostrarErrorUbicacion("❌ Se detectó una ubicación simulada o Fake GPS. La fichada fue bloqueada por seguridad.");
            return;
          }

          // La validación ocurre ANTES de enviar/guardar la fichada.
          validarUbicacionObjetivo(lat, lng, objetivo, { legajo, nombre, tipo, precisionGPS }).then(validacionUbicacion => {
            if (!validacionUbicacion) return;

            divResultado.className = "p-3 rounded-xl text-xs text-center bg-emerald-950 text-emerald-200 border border-emerald-500";
            divResultado.innerText =
              `✅ Ubicación verificada. Distancia al objetivo: ${validacionUbicacion.distanciaTexto}. ` +
              `Radio permitido: ${validacionUbicacion.radioPermitido} m. ` +
              `Precisión GPS: ${Number.isFinite(precisionGPS) ? Math.round(precisionGPS) + ' m' : 'no disponible'}.`;

            ejecutarPeticionFichada(
              tipo, lat, lng, legajo, '', nombre, objetivo,
              validacionUbicacion, precisionGPS
            );
          }).catch(err => {
            console.error('Error validando geocerca:', err);
            mostrarErrorUbicacion('❌ No se pudo verificar la distancia al objetivo. La fichada fue bloqueada.');
          });
          return;
        },
        err => {
          mostrarErrorUbicacion("❌ Permiso de GPS denegado o no disponible. Activa la ubicación en tu dispositivo.");
        },
        { timeout: 15000, enableHighAccuracy: true, maximumAge: 0 }
      );
    }

    async function ejecutarPeticionFichada(tipo, lat, lng, legajo, pin, nombre, objetivo, validacionUbicacion, precisionGPS) {
      const datos = {
        // ID idempotente: identifica de forma única ESTA fichada. Se genera una
        // sola vez acá y se reutiliza en cada reintento de guardado/sincronización,
        // por lo que nunca se crea un duplicado (se guarda con PUT sobre esta clave).
        fichadaId: generarIdFichada(),
        // Legajo de la sesion autenticada (string): las Reglas exigen que coincida con /usuarios/<uid>/legajo.
        legajo: String((typeof legajoSesion !== 'undefined' && legajoSesion) ? legajoSesion : legajo).trim(),
        // El PIN ya se validó antes de fichar (Firebase Auth / hash con salt), así que
        // NO se guarda dentro de la fichada: evitamos exponer PIN en /fichadas.
        nombre: nombre || ("Legajo " + legajo),
        objetivo: objetivo,
        tipo: tipo,  
        latitud: lat,
        longitud: lng,
        mapa: `https://www.google.com/maps?q=${lat},${lng}`,
        fotoBase64: fotoBase64Global,
        validacionFacial: resultadoSimilitudGlobal,
        alertaFraude: sospechaFraudeGlobal,
        motivoFraude: motivoSospechaGlobal,
        fechaHoraDispositivo: new Date().toISOString(),
        // Reloj local del dispositivo (solo referencia / uso offline). El sello oficial lo pone el servidor.
        timestampLocal: Date.now(),

        // Auditoría de geolocalización: solo se llega aquí si pasó el radio.
        ubicacionValidada: true,
        distanciaAlObjetivoMetros: validacionUbicacion ? validacionUbicacion.distanciaMetros : null,
        radioPermitidoMetros: validacionUbicacion ? validacionUbicacion.radioPermitido : RADIO_OBJETIVO_DEFAULT_METROS,
        precisionGPSMetros: Number.isFinite(precisionGPS) ? Math.round(precisionGPS) : null,
        latitudObjetivo: validacionUbicacion ? validacionUbicacion.latObjetivo : null,
        longitudObjetivo: validacionUbicacion ? validacionUbicacion.lngObjetivo : null,

        // Configuración laboral vigente al momento de la fichada.
        horarioProgramadoInicio: turnoProgramadoGlobal?.horaInicio || personalActualGlobal?.horarioHabitual?.inicio || null,
        horarioProgramadoFin: turnoProgramadoGlobal?.horaFin || personalActualGlobal?.horarioHabitual?.fin || null,
        horarioProgramadoOrigen: turnoProgramadoGlobal ? 'ASIGNACION_FECHA' : 'HORARIO_HABITUAL',
        asignacionTurnoId: turnoProgramadoGlobal?.id || null,
        objetivoAutorizadoId: document.getElementById('objetivo').selectedOptions[0]?.dataset?.objetivoId || null
      };

      // Turno nocturno: si es SALIDA y hay una ENTRADA activa (que pudo abrirse
      // el dia anterior y cruzar la medianoche), la SALIDA hereda el turno/horario
      // de esa ENTRADA en lugar del turno resuelto para la fecha de HOY.
      if (tipo === 'SALIDA' && ultimaEntradaActivaGlobal) {
        if (ultimaEntradaActivaGlobal.horarioProgramadoInicio) datos.horarioProgramadoInicio = ultimaEntradaActivaGlobal.horarioProgramadoInicio;
        if (ultimaEntradaActivaGlobal.horarioProgramadoFin) datos.horarioProgramadoFin = ultimaEntradaActivaGlobal.horarioProgramadoFin;
        if (ultimaEntradaActivaGlobal.horarioProgramadoOrigen) datos.horarioProgramadoOrigen = ultimaEntradaActivaGlobal.horarioProgramadoOrigen;
        if (ultimaEntradaActivaGlobal.asignacionTurnoId) datos.asignacionTurnoId = ultimaEntradaActivaGlobal.asignacionTurnoId;

        // Respaldo de integridad: si la ENTRADA no dejó guardado su horario, lo
        // resolvemos por la FECHA en que se abrió esa entrada (no por la fecha de
        // hoy), para que el turno nocturno quede íntegro en el registro de la SALIDA.
        if ((!datos.horarioProgramadoInicio || !datos.horarioProgramadoFin) && ultimaEntradaActivaGlobal.fechaHoraDispositivo && navigator.onLine) {
          try {
            const fEntrada = new Date(ultimaEntradaActivaGlobal.fechaHoraDispositivo);
            const claveEntrada = `${fEntrada.getFullYear()}-${String(fEntrada.getMonth()+1).padStart(2,'0')}-${String(fEntrada.getDate()).padStart(2,'0')}`;
            const turnoEntrada = await obtenerTurnoProgramadoParaFecha(legajo, claveEntrada);
            if (turnoEntrada) {
              datos.horarioProgramadoInicio = turnoEntrada.horaInicio || datos.horarioProgramadoInicio;
              datos.horarioProgramadoFin = turnoEntrada.horaFin || datos.horarioProgramadoFin;
              datos.horarioProgramadoOrigen = 'ASIGNACION_FECHA_ENTRADA';
              datos.asignacionTurnoId = turnoEntrada.id || datos.asignacionTurnoId;
            }
          } catch (e) { /* si no se puede resolver, se conserva el fallback previo */ }
        }
      }

      const divResultado = document.getElementById('resultado');

      // Enrutado por TIPO DE SESION, no por navigator.onLine (poco fiable): una
      // sesion OFFLINE no tiene idToken, por lo que la via online (Worker 'fichar')
      // la rechazaria y la fichada quedaria en un limbo (ni online ni lote firmado).
      // Toda sesion offline -o falta real de conexion- va a la cola offline firmada
      // por el dispositivo, que se sincroniza luego via 'ficharLoteOffline'.
      if (sesionEsOffline || !idTokenVig || !navigator.onLine) {
        // Offline: no se puede validar contra el servidor en este momento. Se sella con
        // la hora local disponible; al sincronizar, el servidor pone el sello oficial (.sv).
        aplicarHoraServidor(datos, false);
        guardarFichadaOffline(datos, tipo, legajo);
        return;
      }

      // Sesion individual larga: renovar el idToken antes de las operaciones REST
      // para no fichar con un token vencido (evita 401 y perdida de la fichada).
      const tokenFresco = await refrescarTokenVigilador();
      if (tokenFresco) idTokenVig = tokenFresco;

      // VALIDACION DE HORA POR SERVIDOR: con el token recien renovado ya tenemos la
      // hora oficial. Sellamos la fichada con esa hora y detectamos si el reloj del
      // telefono esta manipulado (queda marcada para revision del admin).
      aplicarHoraServidor(datos, !!tokenFresco);

      divResultado.className = "p-3 rounded-xl text-xs text-center bg-slate-700 text-white";
      divResultado.innerText = "Verificando duplicados...";
      divResultado.classList.remove('hidden');

      existeFichadaReciente(legajo, tipo).then(async esDuplicada => {
        if (esDuplicada) {
          divResultado.className = "p-3 rounded-xl text-xs text-center bg-rose-950 text-rose-200 border border-rose-500";
          divResultado.innerText = `❌ Ya registraste una fichada de ${tipo} hace instantes. Espera unos minutos antes de volver a fichar.`;
          return;
        }
        divResultado.className = "p-3 rounded-xl text-xs text-center bg-slate-700 text-white";
        divResultado.innerText = "Registrando fichada...";

        // FICHAJE AUTORITATIVO VIA WORKER (service account) con REINTENTO acotado.
        // Reglas SA-ONLY: el PUT directo del vigilador esta DENEGADO (401 Permission
        // denied). La unica via valida es el Worker (accion 'fichar'), que verifica el
        // idToken, revalida objetivo + geocerca GPS y escribe con la service account.
        // Ante un fallo TRANSITORIO (red/5xx) se reintenta una vez antes de encolar;
        // un rechazo de VALIDACION (403/422/bloqueado) NO se reintenta.
        const MAX_INTENTOS_WORKER = 2;
        for (let intento = 1; intento <= MAX_INTENTOS_WORKER; intento++) {
          const ctrl = new AbortController();
          const tAbort = setTimeout(() => ctrl.abort(), 20000);
          try {
            const resp = await fetch(URL_WORKER, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                accion: "fichar",
                idToken: idTokenVig,
                fichada: Object.assign({}, datos, { idEvento: datos.fichadaId })
              }),
              signal: ctrl.signal
            });
            clearTimeout(tAbort);
            let data = {};
            try { data = await resp.json(); } catch (_) {}

            // 401 = token vencido: renovar y reintentar con el token fresco
            if (resp.status === 401) {
              const fresco = await (window._forzarRefreshTokenVig ? window._forzarRefreshTokenVig() : window.refrescarTokenVigilador());
              if (fresco) { idTokenVig = fresco; if (window._setIdTokenGlobal) window._setIdTokenGlobal(fresco); }
              throw new Error('Token vencido (401), reintentando con token renovado');
            }

            // Exito: el Worker confirma ok:true (fichada creada o duplicada idempotente).
            if (resp.ok && data && data.ok) {
              if (data.fichadaId) datos.fichadaId = data.fichadaId;
              divResultado.className = "p-3 rounded-xl text-xs text-center bg-emerald-950 text-emerald-200 border border-emerald-500";
              divResultado.innerText = `✓ ¡Fichada de ${tipo} registrada y validada por el servidor!`;
              ultimoTipoFichadaGlobal = tipo;
              guardarUltimoEstadoConocido(legajo, tipo, Date.now(), (tipo === 'ENTRADA') ? capturarEntradaActiva('ENTRADA', datos) : null);
              limpiarFormularioExitoso();
              finalizarSesionTrasFichada();
              return; // Guardado online confirmado: NO encolar copia offline.
            }

            // Rechazo de VALIDACION (no de red): fail-closed. No se encola ni se
            // reintenta (el resultado seria el mismo). Se muestra el motivo real.
            if (resp.status === 403 || resp.status === 422 || (data && data.bloqueado)) {
              const detalle = (data && data.distanciaMetros != null)
                ? ` Estás a ${data.distanciaMetros} m del objetivo (radio permitido: ${data.radioPermitidoMetros} m).`
                : '';
              divResultado.className = "p-3 rounded-xl text-xs text-center bg-rose-950 text-rose-200 border border-rose-500";
              divResultado.innerText = `❌ FICHADA BLOQUEADA por el servidor: ${(data && (data.error || data.motivo)) || 'validación fallida'}.${detalle}`;
              return;
            }

            // Cualquier otro estado (500/502/token) -> fallo transitorio: reintentar.
            throw new Error('El servidor respondió ' + resp.status);
          } catch (err) {
            clearTimeout(tAbort);
            console.warn(`Worker de fichaje no disponible (intento ${intento}/${MAX_INTENTOS_WORKER}):`, err);
            if (intento < MAX_INTENTOS_WORKER) {
              await new Promise(r => setTimeout(r, 1500)); // pausa corta antes de reintentar
              continue;
            }
            // Agotados los reintentos: la fichada YA se valido online (rostro cotejado)
            // pero el Worker no respondio por un fallo transitorio. Se encola SIN la
            // bandera de fraude/revision manual y se reintenta por la via autoritativa.
            encolarParaReintentoWorker(datos, tipo, legajo, divResultado);
            return;
          }
        }
      });
    }

    // Encola una fichada YA VALIDADA online cuando el Worker tuvo un fallo
    // TRANSITORIO (red/5xx) tras agotar los reintentos. A diferencia de la cola
    // offline "pura", NO fuerza la bandera de fraude/revision manual (el rostro SI
    // se cotejo online); marca la fichada como generada online y dispara de
    // inmediato la sincronizacion por la via autoritativa (Worker).
    function encolarParaReintentoWorker(datos, tipo, legajo, divResultado) {
      let pendientes = JSON.parse(localStorage.getItem('fichadas_pendientes') || '[]');
      // Anti-duplicado: no encolar dos veces el mismo evento (misma fichadaId).
      const yaEnCola = datos.fichadaId && pendientes.some(f => f && f.fichadaId === datos.fichadaId);
      if (!yaEnCola) {
        datos.creadaOffline = false; // se genero ONLINE: sincroniza por Worker con idToken
        pendientes.push(datos);
        localStorage.setItem('fichadas_pendientes', JSON.stringify(pendientes));
      }
      ultimoTipoFichadaGlobal = tipo;
      guardarUltimoEstadoConocido(legajo, tipo, Date.now(), (tipo === 'ENTRADA') ? capturarEntradaActiva('ENTRADA', datos) : null);
      const div = divResultado || document.getElementById('resultado');
      if (div) {
        div.className = "p-3 rounded-xl text-xs text-center bg-amber-950 text-amber-200 border border-amber-500";
        div.innerText = `⏳ Fichada de ${tipo} registrada. El servidor no respondió en este momento; se sincronizará automáticamente en cuanto se restablezca la conexión.`;
      }
      limpiarFormularioExitoso();
      finalizarSesionTrasFichada();
      // Reintento inmediato por la via autoritativa (Worker).
      if (navigator.onLine) sincronizarFichadasPendientes();
    }

    function guardarFichadaOffline(datos, tipo, legajo) {
      let pendientes = JSON.parse(localStorage.getItem('fichadas_pendientes') || '[]');

      if (pendientes.length > 0) {
        let ultimaPendiente = pendientes[pendientes.length - 1];
        if (ultimaPendiente.legajo === legajo && ultimaPendiente.tipo === tipo) {
          const divResultado = document.getElementById('resultado');
          divResultado.className = "p-3 rounded-xl text-xs text-center bg-rose-950 text-rose-200 border border-rose-500";
          divResultado.innerText = `❌ Ya tienes una fichada de ${tipo} pendiente de sincronización. No puedes repetirla dos veces seguidas.`;
          return; 
        }
      }

      // Fichada sin cotejo de identidad en el momento (tipico caso offline: no
      // hubo servidor para verificar el rostro). NO es fraude: se marca como
      // PENDIENTE DE VERIFICACION para que RRHH la revise con criterio, sin acusar
      // al vigilador. La alerta de fraude REAL (rostro sospechoso o foto de pantalla
      // detectada por el analisis local) se conserva aparte en datos.alertaFraude
      // y NO se pisa aqui.
      if (resultadoSimilitudGlobal === "SIN_MASTER" || resultadoSimilitudGlobal === "IA_NO_DISPONIBLE" || resultadoSimilitudGlobal === "NO_EVALUADO") {
        datos.requiereRevisionManual = true;
        datos.motivoRevision = "Fichada registrada sin conexión: la identidad no pudo verificarse en el momento y queda pendiente de revisión.";
        datos.validacionFacial = "OFFLINE_PENDIENTE_VERIFICACION";
      }

      // Fase 2: marca de origen. Solo las creadas REALMENTE sin conexion viajan por
      // la via firmada por dispositivo (lote offline), que no depende del idToken.
      // Se marca por TIPO DE SESION (sin idToken) y no solo por navigator.onLine:
      // si la sesion es offline y la red reaparecio, la fichada IGUAL debe viajar
      // por el lote firmado (no por la via online, que exige idToken).
      datos.creadaOffline = (sesionEsOffline || !idTokenVig || !navigator.onLine);
      // authUid de la sesion (online u offline desde cache): el Worker lo exige para
      // atar la fichada a un legajo real al sincronizar el lote.
      if (!datos.authUid && typeof uidSesion !== 'undefined' && uidSesion) datos.authUid = uidSesion;

      pendientes.push(datos);
      localStorage.setItem('fichadas_pendientes', JSON.stringify(pendientes));

      ultimoTipoFichadaGlobal = tipo;
      guardarUltimoEstadoConocido(legajo, tipo, Date.now(), (tipo === 'ENTRADA') ? capturarEntradaActiva('ENTRADA', datos) : null);
      const divResultado = document.getElementById('resultado');
      divResultado.className = "p-3 rounded-xl text-xs text-center bg-amber-950 text-amber-200 border border-amber-500";
      const notaCopiaTurno = (typeof turnoProgramadoGlobal!=='undefined' && turnoProgramadoGlobal && turnoProgramadoGlobal._origenCache) ? ' Tu turno se tomó de la copia guardada en este teléfono.' : '';
      divResultado.innerText = `✅ Fichada de ${tipo} registrada sin conexión.${notaCopiaTurno} Se sincronizará automáticamente al recuperar internet y quedará pendiente de verificación por RRHH.`;

      limpiarFormularioExitoso();
      finalizarSesionTrasFichada();
      // Aviso visual inmediato: refleja la nueva fichada pendiente en el banner
      // global y en la tarjeta de login (aunque la sesion se cierre en modo compartido).
      try { refrescarEstadoOfflinePendientes(); } catch (_) {}
      // Si en este momento hay conexion (fallo puntual del Worker/RTDB), se intenta
      // subir de inmediato por el lote firmado; si estamos offline, quedara para el
      // evento 'online'. Solo actua sobre fichadas creadas offline.
      if (navigator.onLine) sincronizarLoteOffline();
    }

    // Tras una fichada exitosa: en modo COMPARTIDO se cierra la sesion (para
    // que el proximo empleado deba loguearse); en modo INDIVIDUAL se mantiene
    // la sesion y solo se reinicia el temporizador de inactividad.
    function finalizarSesionTrasFichada() {
      if (modoDispositivo === 'compartido') {
        setTimeout(() => { cerrarSesionVigilador(); }, 1800);
      } else {
        reiniciarInactividad();
      }
    }

    function limpiarFormularioExitoso() {
      document.getElementById('legajo-status').className = "text-xs mt-1 hidden";
      document.getElementById('legajo-status').innerText = "";
      document.getElementById('ultimo-estado-badge').classList.add('hidden');
      
      fotoBase64Global = "";
      fotoMasterGuardada = null;
      resultadoSimilitudGlobal = "NO_EVALUADO";
      sospechaFraudeGlobal = false;
      motivoSospechaGlobal = "";
      
      const preview = document.getElementById('preview');
      preview.src = "";
      preview.classList.add('hidden');
      
      const statusFoto = document.getElementById('foto-status');
      statusFoto.innerText = "⚠️ Foto no capturada";
      statusFoto.className = "text-xs text-rose-400 text-center font-semibold";

      iniciarCamaraSegura();
    }

    function sincronizarFichadasPendientes() {
      if (estaSincronizando) return; 
      if (!navigator.onLine) return;
      // Seguridad ENFORCED server-side: las Reglas atan newData.legajo al legajo
      // del uid autenticado. Por eso SOLO se puede sincronizar CON una sesion
      // activa y SOLO las fichadas del propio legajo logueado; una fichada de
      // otro legajo seria rechazada por las Reglas, asi que se conserva en la
      // cola hasta que su verdadero dueno inicie sesion en este dispositivo.
      if (!idTokenVig || !legajoSesion) return;
      let pendientes = JSON.parse(localStorage.getItem('fichadas_pendientes') || '[]');
      if (pendientes.length === 0) return;

      // Reparto de responsabilidades (Fase 2): si el dispositivo esta provisionado,
      // las fichadas creadas OFFLINE se suben por la via firmada (sincronizarLoteOffline),
      // no por aqui. Sin dispositivo provisionado, esta sync (con sesion activa) sigue
      // siendo el respaldo para no perderlas.
      const hayDispositivo = !!obtenerCredencialDispositivo();
      const idx = pendientes.findIndex(f => f && mismoLegajo(f.legajo, legajoSesion) && !(hayDispositivo && (f.creadaOffline === true || f.origenOffline === true)));
      if (idx === -1) return; // ninguna pendiente corresponde a esta via

      estaSincronizando = true;
      let datos = pendientes.splice(idx, 1)[0];
      localStorage.setItem('fichadas_pendientes', JSON.stringify(pendientes));

      // Retrocompatibilidad: si una fichada quedo en cola ANTES de esta version
      // (sin fichadaId), le asignamos uno ahora para poder guardarla idempotente.
      if (!datos.fichadaId) datos.fichadaId = generarIdFichada();

      // Sincronizacion VIA WORKER (service account). Igual que el fichaje online:
      // las Reglas SA-ONLY no permiten crear /fichadas por REST, asi que la cola
      // offline tambien se sube por el Worker (accion 'fichar'), que revalida todo
      // server-side. Si el servidor la RECHAZA, se devuelve a la cola.
      // Antes de sincronizar, asegurar que el token no esté vencido
      if (window._getIdTokenGlobal && window._getIdTokenGlobal()) {
        idTokenVig = window._getIdTokenGlobal();
      }
      fetch(URL_WORKER, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          accion: "fichar",
          idToken: idTokenVig,
          fichada: Object.assign({}, datos, { idEvento: datos.fichadaId, sincronizadoDesdeOffline: true })
        })
      })
      .then(async res => {
        const cuerpo = await res.json().catch(() => null);
        // Rechazo de VALIDACION (no de red): la fichada es invalida (fuera de radio,
        // objetivo no autorizado, datos incompletos). No puede sincronizar nunca; se
        // retira de la cola y se ARCHIVA como rechazada para auditoria (NO se descarta
        // en silencio ni se reintenta en bucle).
        if (res.status === 403 || res.status === 422 || (cuerpo && cuerpo.bloqueado)) {
          const rechazadas = JSON.parse(localStorage.getItem('fichadas_rechazadas') || '[]');
          rechazadas.push(Object.assign({}, datos, {
            motivoRechazo: (cuerpo && (cuerpo.error || cuerpo.motivo)) || 'validacion del servidor fallida',
            distanciaMetros: (cuerpo && cuerpo.distanciaMetros != null) ? cuerpo.distanciaMetros : null,
            rechazadaEn: new Date().toISOString()
          }));
          localStorage.setItem('fichadas_rechazadas', JSON.stringify(rechazadas));
          console.warn("⛔ Fichada pendiente RECHAZADA por el servidor y archivada:", (cuerpo && cuerpo.error));
          return { _rechazada: true };
        }
        // 401 = token vencido: renovar y reintentar una vez
        if (res.status === 401) {
          const fresco = await (window._forzarRefreshTokenVig ? window._forzarRefreshTokenVig() : window.refrescarTokenVigilador());
          if (fresco) { idTokenVig = fresco; if (window._setIdTokenGlobal) window._setIdTokenGlobal(fresco); }
          // Reintentar con token fresco
          try {
            const res2 = await fetch(URL_WORKER, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ accion: "fichar", idToken: fresco, fichada: Object.assign({}, datos, { idEvento: datos.fichadaId, sincronizadoDesdeOffline: true }) })
            });
            const cuerpo2 = await res2.json().catch(() => null);
            if (res2.ok && cuerpo2 && cuerpo2.ok) return { ok: true };
            if (res2.status === 403 || res2.status === 422 || (cuerpo2 && cuerpo2.bloqueado)) {
              // Rechazo de validación en reintento: archivar
              const rechazadas = JSON.parse(localStorage.getItem('fichadas_rechazadas') || '[]');
              rechazadas.push(Object.assign({}, datos, { motivoRechazo: (cuerpo2 && (cuerpo2.error || cuerpo2.motivo)) || 'validacion del servidor fallida', rechazadaEn: new Date().toISOString() }));
              localStorage.setItem('fichadas_rechazadas', JSON.stringify(rechazadas));
              return { _rechazada: true };
            }
            throw new Error((cuerpo2 && cuerpo2.error) || ('HTTP ' + res2.status));
          } catch (retryErr) {
            throw new Error('Token renovado pero reintento falló: ' + retryErr.message);
          }
        }
        // Solo se da por sincronizada si el Worker confirma ok:true (creada o
        // duplicada idempotente). Cualquier otro estado (red/5xx) la devuelve a la cola.
        if (!res.ok || !cuerpo || !cuerpo.ok) {
          throw new Error((cuerpo && cuerpo.error) || ('El servidor rechazo la fichada pendiente (HTTP ' + res.status + ').'));
        }
        return cuerpo;
      })
      .then(respuesta => {
        estaSincronizando = false;
        console.log("🔄 Fichada pendiente sincronizada con Firebase.");
        
        const restantes = JSON.parse(localStorage.getItem('fichadas_pendientes') || '[]');
        if (restantes.some(f => f && mismoLegajo(f.legajo, legajoSesion))) {
          sincronizarFichadasPendientes();
        }
      })
      .catch(err => {
        console.error("Error al sincronizar fichada pendiente, devolviéndola a la cola...", err);
        let actualizadas = JSON.parse(localStorage.getItem('fichadas_pendientes') || '[]');
        actualizadas.unshift(datos);
        localStorage.setItem('fichadas_pendientes', JSON.stringify(actualizadas));
        estaSincronizando = false;
      });
    }

// Habilita o BLOQUEA el boton SALIDA segun el objetivo elegido. Si hay una
// ENTRADA activa y el objetivo seleccionado NO coincide con el de esa entrada,
// el boton SALIDA queda deshabilitado (no se puede fichar salida) hasta que el
// vigilador corrija el objetivo. Es preventivo; la validacion dentro de
// procesarEnvio sigue como respaldo. Solo actua si conocemos el objetivo de la
// ENTRADA (fichadas viejas sin ese dato no bloquean, por compatibilidad).
function actualizarBotonSalidaSegunObjetivo(){
  var btnSalida = document.getElementById("btnSalida");
  var selObjetivo = document.getElementById("objetivo");
  if(!btnSalida || !selObjetivo) return;
  var opcion = selObjetivo.selectedOptions && selObjetivo.selectedOptions[0];
  var idSeleccionado = opcion ? String(opcion.dataset.objetivoId || "").trim() : "";
  var idEntrada = (ultimaEntradaActivaGlobal && ultimaEntradaActivaGlobal.objetivoAutorizadoId)
    ? String(ultimaEntradaActivaGlobal.objetivoAutorizadoId).trim() : "";
  var hayEntradaActiva = (ultimoTipoFichadaGlobal === "ENTRADA");
  var objetivoIncorrecto = hayEntradaActiva && idEntrada && idSeleccionado && idEntrada !== idSeleccionado;
  if(objetivoIncorrecto){
    var nombreObj = ultimaEntradaActivaGlobal.objetivo || "el objetivo donde tomaste servicio";
    btnSalida.disabled = true;
    btnSalida.classList.add("btn-bloqueado");
    btnSalida.setAttribute("aria-disabled", "true");
    btnSalida.title = 'Para dar la SALIDA eleg\u00ed el objetivo "' + nombreObj + '", donde tomaste servicio.';
    selObjetivo.classList.add("objetivo-error");
  } else {
    btnSalida.disabled = false;
    btnSalida.classList.remove("btn-bloqueado");
    btnSalida.removeAttribute("aria-disabled");
    btnSalida.title = "";
    selObjetivo.classList.remove("objetivo-error");
  }
}

// --- Cableado de eventos (antes onclick en el HTML) ---
document.addEventListener("DOMContentLoaded", function(){
  var b;
  b=document.getElementById("btnCerrarSesionVig"); if(b) b.addEventListener("click", function(){ cerrarSesionVigilador(); });
  b=document.getElementById("btnCapturar"); if(b) b.addEventListener("click", function(){ capturarFoto(); });
  b=document.getElementById("btnEntrada"); if(b) b.addEventListener("click", function(){ procesarEnvio("ENTRADA"); });
  b=document.getElementById("btnSalida"); if(b) b.addEventListener("click", function(){ procesarEnvio("SALIDA"); });
  b=document.getElementById("btnVincular"); if(b) b.addEventListener("click", function(){ vincularDispositivo(); });
  var selObjetivoBtn=document.getElementById("objetivo"); if(selObjetivoBtn) selObjetivoBtn.addEventListener("change", actualizarBotonSalidaSegunObjetivo);
  actualizarBotonSalidaSegunObjetivo();
});
