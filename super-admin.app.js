'use strict';
// Panel EXCLUSIVO del dueño. Se autentica con OWNER_KEY (secreto del Worker),
// NO con Firebase. La clave NO se guarda: se lee del input en cada operación.
var URL_WORKER = 'https://vga-security-24.micasa27822024.workers.dev';

// Combos de funciones recomendados por plan (igual que en el Worker).
var FUNCIONES_PRESET = {
  esencial:    { rondas:false, alertasIncidencias:false, rolesSupervision:false, exportarReportes:false, multiplesSedes:false, modoOffline:false },
  profesional: { rondas:true,  alertasIncidencias:true,  rolesSupervision:true,  exportarReportes:true,  multiplesSedes:false, modoOffline:false },
  empresa:     { rondas:true,  alertasIncidencias:true,  rolesSupervision:true,  exportarReportes:true,  multiplesSedes:true,  modoOffline:true  }
};
var FN_IDS = { rondas:'fnRondas', alertasIncidencias:'fnAlertas', rolesSupervision:'fnRoles', exportarReportes:'fnExport', multiplesSedes:'fnSedes', modoOffline:'fnOffline' };

function leerFuncionesForm(){
  var out = {};
  for (var k in FN_IDS){ var el = $(FN_IDS[k]); out[k] = !!(el && el.checked); }
  return out;
}
function pintarFuncionesForm(fn){
  fn = fn || {};
  for (var k in FN_IDS){ var el = $(FN_IDS[k]); if (el) el.checked = !!fn[k]; }
}

function $(id){ return document.getElementById(id); }
function mostrarMsg(txt, tipo){
  var m = $('msg');
  m.textContent = txt;
  m.className = 'msg ' + (tipo === 'error' ? 'msg-error' : 'msg-ok');
}
function leerClave(){
  var k = ($('ownerKey').value || '').trim();
  if (!k){ mostrarMsg('Poné la clave de dueño para continuar.', 'error'); return null; }
  return k;
}
async function llamar(payload){
  var res = await fetch(URL_WORKER, {
    method:'POST',
    headers:{ 'Content-Type':'application/json' },
    body: JSON.stringify(payload)
  });
  var data = {};
  try { data = await res.json(); } catch(_){ data = {}; }
  return { status: res.status, data: data };
}

function pintarEstado(plan, uso){
  var e = $('estado');
  var nombre = plan && plan.nombre ? plan.nombre : 'esencial';
  var topeV = (plan && plan.maxVigiladores > 0) ? plan.maxVigiladores : '∞';
  var topeO = (plan && plan.maxObjetivos > 0) ? plan.maxObjetivos : '∞';
  var susp = (plan && plan.estado === 'suspendido');
  e.className = 'card estado' + (susp ? ' estado-susp' : '');
  e.textContent = '';
  var h = document.createElement('h2'); h.textContent = 'Plan actual: ' + nombre + (susp ? ' (SUSPENDIDO)' : '');
  var p1 = document.createElement('p'); p1.textContent = 'Vigiladores: ' + (uso ? uso.vigiladores : '?') + ' / ' + topeV;
  var p2 = document.createElement('p'); p2.textContent = 'Objetivos: ' + (uso ? uso.objetivos : '?') + ' / ' + topeO;
  e.appendChild(h); e.appendChild(p1); e.appendChild(p2);
}

function cargarFormDesde(plan){
  if (!plan) return;
  $('inpNombre').value = plan.nombre || 'esencial';
  $('inpEstado').value = (plan.estado === 'suspendido') ? 'suspendido' : 'activo';
  $('inpVig').value = Number.isFinite(plan.maxVigiladores) ? plan.maxVigiladores : 10;
  $('inpObj').value = Number.isFinite(plan.maxObjetivos) ? plan.maxObjetivos : 2;
  pintarFuncionesForm(plan.funciones);
}

async function onLeer(){
  var k = leerClave(); if (!k) return;
  mostrarMsg('Consultando el servidor…', 'ok');
  try {
    var r = await llamar({ accion:'ownerLeerPlan', ownerKey:k });
    if (r.data && r.data.ok){
      pintarEstado(r.data.plan, r.data.uso);
      cargarFormDesde(r.data.plan);
      $('estado').classList.remove('hidden');
      mostrarMsg('Plan leído correctamente.', 'ok');
    } else {
      mostrarMsg((r.data && r.data.error) || ('Error (HTTP ' + r.status + ')'), 'error');
    }
  } catch(e){ mostrarMsg('No se pudo conectar con el servidor.', 'error'); }
}

async function aplicar(estadoForzado){
  var k = leerClave(); if (!k) return;
  var nombre = ($('inpNombre').value || '').trim().toLowerCase() || 'custom';
  var estado = estadoForzado || $('inpEstado').value;
  var maxVig = Math.floor(Number($('inpVig').value));
  var maxObj = Math.floor(Number($('inpObj').value));
  if (!Number.isFinite(maxVig) || maxVig < 0 || !Number.isFinite(maxObj) || maxObj < 0){
    mostrarMsg('Los topes deben ser números enteros mayores o iguales a 0.', 'error'); return;
  }
  var funciones = leerFuncionesForm();
  var etiqueta = (estado === 'suspendido') ? 'SUSPENDER la cuenta' : ('aplicar el plan “' + nombre + '” (' + maxVig + ' vig / ' + maxObj + ' obj)');
  if (!confirm('¿Confirmás ' + etiqueta + '?')) return;
  mostrarMsg('Guardando…', 'ok');
  try {
    var r = await llamar({ accion:'ownerFijarPlan', ownerKey:k, nombre:nombre, estado:estado, maxVigiladores:maxVig, maxObjetivos:maxObj, funciones:funciones });
    if (r.data && r.data.ok){
      cargarFormDesde(r.data.plan);
      mostrarMsg('Plan guardado. Volvé a “Leer plan actual” para ver el uso en vivo.', 'ok');
    } else {
      mostrarMsg((r.data && r.data.error) || ('Error (HTTP ' + r.status + ')'), 'error');
    }
  } catch(e){ mostrarMsg('No se pudo conectar con el servidor.', 'error'); }
}

function seleccionarPlan(ev){
  var b = ev.currentTarget;
  var nombre = b.getAttribute('data-nombre');
  var vig = b.getAttribute('data-vig');
  var obj = b.getAttribute('data-obj');
  $('inpNombre').value = nombre;
  if (vig !== '') $('inpVig').value = vig;
  if (obj !== '') $('inpObj').value = obj;
  $('inpEstado').value = 'activo';
  if (nombre !== 'custom' && FUNCIONES_PRESET[nombre]) pintarFuncionesForm(FUNCIONES_PRESET[nombre]);
  var all = document.querySelectorAll('.plan');
  for (var i=0;i<all.length;i++) all[i].classList.remove('plan-sel');
  b.classList.add('plan-sel');
}

document.addEventListener('DOMContentLoaded', function(){
  $('btnLeer').addEventListener('click', onLeer);
  $('btnAplicar').addEventListener('click', function(){ aplicar(null); });
  $('btnSuspender').addEventListener('click', function(){ aplicar('suspendido'); });
  var planes = document.querySelectorAll('.plan');
  for (var i=0;i<planes.length;i++) planes[i].addEventListener('click', seleccionarPlan);
});
