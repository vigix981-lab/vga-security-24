(function () {
  // Genera un salt aleatorio (16 bytes) en hexadecimal.
  function generarSaltPin() {
    const a = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  // Deriva el hash del PIN con PBKDF2-SHA256 (100k iteraciones) y el salt dado.
  async function hashPin(pin, saltHex) {
    const enc = new TextEncoder();
    const salt = Uint8Array.from((String(saltHex).match(/.{1,2}/g) || []).map(b => parseInt(b, 16)));
    const km = await crypto.subtle.importKey('raw', enc.encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, km, 256);
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  // Verifica un PIN contra una ficha que tenga pinHash + pinSalt.
  async function verificarPinHash(pin, ficha) {
    if (!ficha) return false;
    const h = String(ficha.pinHash || '').trim();
    const s = String(ficha.pinSalt || '').trim();
    if (!h || !s) return false;
    try { return (await hashPin(pin, s)) === h; } catch (_) { return false; }
  }
  window.generarSaltPin = generarSaltPin;
  window.hashPin = hashPin;
  window.verificarPinHash = verificarPinHash;
})();
