"""
Advance Orders module (event bookings: fiesta, kasal, binyag, atbp.)

WHY THIS EXISTS: regular orders in this app assume a walk-in/reseller
buying ice for the SAME day. Event bookings are different - a customer
books WEEKS ahead, for a SPECIFIC delivery date/time and venue, often
with a deposit paid upfront. Cramming that into the normal daily_sales
flow (which has no venue, no event type, no deposit tracking, and no
"this hasn't happened yet" state) would either lose that data or force
staff to remember it outside the app. This module gives event bookings
their own home, while still handing off into the SAME daily_sales table
once the event is actually delivered - so it shows up in the reseller's
sales trend/history/points like any other order, with zero double-entry.

Firebase data model (new):
  advance_orders/<id> = {
    order_source: "staff" | "customer",
    reseller_id: str | None,          # linked reseller account, if any
    reseller_name: str,               # snapshot at booking time
    contact_name: str,                # who to coordinate with for the event
    contact_number: str,
    event_type: str,                  # Fiesta / Kasal / Binyag / Reunion / Iba pa
    event_type_other: str,            # only used when event_type == "Iba pa"
    venue_address: str,
    delivery_date: "YYYY-MM-DD",
    delivery_time: "HH:MM" | "",
    quantity: float,
    kg_size: str,
    unit_price: float,
    total_amount: float,
    deposit_amount: float,
    special_instructions: str,
    status: "Pending" | "Confirmed" | "Delivered" | "Cancelled",
    created_by: str,
    created_at: str,
    updated_at: str,
    fulfilled_sale_id: str | None,    # set once converted into daily_sales
  }

Routes:
  STAFF SIDE
  GET    /advance-orders                          - list/manage page
  GET    /api/advance_orders                       - JSON list (optional ?status=)
  POST   /api/advance_orders                       - staff creates a booking
  PATCH  /api/advance_orders/<id>                  - edit fields / change status
  POST   /api/advance_orders/<id>/deliver          - mark Delivered + create the actual daily_sales row
  DELETE /api/advance_orders/<id>                  - ISESMO only: cancel/remove a booking

  RESELLER SIDE
  GET    /customer/<reseller_id>/advance-order      - booking form + "my bookings" page
  POST   /api/customer/<reseller_id>/advance_order  - reseller books their own event
  GET    /api/customer/<reseller_id>/advance_orders - reseller's own bookings only

Converting to an actual sale (mark Delivered) deliberately tags the new
daily_sales row with order_source="advance_order" (NOT "customer") so it
is never mistaken for a normal online reseller restock order elsewhere in
the app (e.g. the online-orders-only points-earning logic, which checks
specifically for order_source=="customer") - a one-off event bulk order
is a different kind of transaction. It still carries reseller_id/
reseller_name, so it DOES show up correctly in that reseller's Sales
Trend/History, since those already match on reseller_id/reseller_name
alone, not order_source.
"""
from datetime import datetime

from flask import Blueprint, request, jsonify, session, render_template_string, redirect, url_for

from modules.shared import fb_get, fb_post, fb_patch, fb_delete, login_required, isesmo_only, now_str, today_str, log_customer_activity

advance_orders_bp = Blueprint("advance_orders", __name__)

EVENT_TYPES = ["Fiesta", "Kasal", "Binyag", "Reunion", "Birthday", "Iba pa"]
KG_SIZES = ["1Kg", "5Kg", "10Kg", "25Kg"]
STATUSES = ["Pending", "Confirmed", "Delivered", "Cancelled"]

# Same fallback selling prices used by the customer self-order endpoint
# (api_customer_place_order in app.py) - kept as an exact copy here for
# the same circular-import reason documented in modules/shared.py.
FALLBACK_PRICES = {"1Kg": 10, "5Kg": 50, "10Kg": 100, "25Kg": 250}


def _get_price(kg_size):
    """Look up the live selling price the same way app.py's get_price()
    does (price_settings/REGULAR first, fallback prices second), so an
    event booking is priced the same as a normal DELIVER order."""
    try:
        data = fb_get("price_settings/REGULAR")
        col_map = {"1Kg": "kg1", "5Kg": "kg5", "10Kg": "kg10", "25Kg": "kg25"}
        col = col_map.get(kg_size, "kg1")
        if data and data.get(col):
            return float(data[col])
    except Exception:
        pass
    return float(FALLBACK_PRICES.get(kg_size, 10))


def _serialize(key, val):
    row = dict(val)
    row["id"] = key
    row.setdefault("deposit_amount", 0)
    row["balance_due"] = round((row.get("total_amount") or 0) - (row.get("deposit_amount") or 0), 2)
    return row


def _kg_val(kg_size):
    """'10Kg' -> 10.0. Same tiny parsing convention already used
    elsewhere in this app for kg_size strings."""
    try:
        return float(str(kg_size).lower().replace("kg", "").strip())
    except (TypeError, ValueError):
        return 0.0


def _compute_leaderboard(year, month, top_n=5):
    """Ranks resellers by TOTAL KG booked this calendar month (boss's
    call, Sept 22: 'total kg, monthly reset' - fair across resellers of
    different sizes and resets the excitement every month instead of
    the same big reseller sitting on top forever).

    Ranked on delivery_date's month (the event's own month), not when
    it was booked - this is meant to answer "sino may pinaka-maraming
    inevent this month", which is what a reseller actually sees/feels
    competing over. Counts every non-Cancelled booking (Pending,
    Confirmed, AND Delivered) so a reseller's rank updates the moment
    they book, not only after the event is fulfilled - that immediate
    feedback is the whole point of a leaderboard as a booking incentive.
    Walk-in bookings (no reseller_id) never appear here - the point is
    to reward RESELLERS specifically.
    """
    month_prefix = f"{year:04d}-{month:02d}"
    data = fb_get("advance_orders") or {}
    totals = {}  # reseller_id -> {"reseller_name": ..., "kg": ...}
    for val in data.values():
        if not val or not val.get("reseller_id"):
            continue
        if val.get("status") == "Cancelled":
            continue
        if not (val.get("delivery_date") or "").startswith(month_prefix):
            continue
        rid = val["reseller_id"]
        kg = _kg_val(val.get("kg_size")) * float(val.get("quantity") or 0)
        entry = totals.setdefault(rid, {"reseller_id": rid, "reseller_name": val.get("reseller_name") or "", "total_kg": 0.0})
        entry["total_kg"] += kg
        if val.get("reseller_name"):
            entry["reseller_name"] = val.get("reseller_name")

    ranked = sorted(totals.values(), key=lambda e: e["total_kg"], reverse=True)
    for i, entry in enumerate(ranked):
        entry["rank"] = i + 1
        entry["total_kg"] = round(entry["total_kg"], 2)
    return ranked[:top_n]


# =================================================================
# STAFF-SIDE HTML PAGE
# =================================================================
ADVANCE_ORDERS_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Advance Orders - Omega Ice</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0;font-weight:700}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600}
.menu-wrap{position:relative}
.menu-btn{padding:7px 14px;border-radius:20px;font-size:15px;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600;cursor:pointer;line-height:1}
.menu-btn.open{background:#00609C;color:#fff;border-color:#00609C}
.menu-dropdown{display:none;position:absolute;top:calc(100% + 6px);right:0;background:#fff;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,.18);min-width:190px;z-index:60;overflow:hidden;border:1px solid #e5e7eb}
.menu-dropdown.show{display:block}
.menu-dropdown a{display:flex;align-items:center;gap:10px;padding:13px 16px;font-size:13px;color:#333;text-decoration:none;border-bottom:1px solid #f0f4f8;font-weight:600}
.menu-dropdown a:last-child{border-bottom:none}
.menu-dropdown a:hover,.menu-dropdown a:active{background:#eef7ff;color:#00609C}
.menu-dropdown a.active{background:#eef7ff;color:#00609C}
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.add-btn{width:100%;padding:12px;border-radius:10px;border:none;background:#00609C;color:#fff;font-weight:700;font-size:13px;margin-bottom:12px}
.filter-row{display:flex;gap:6px;overflow-x:auto;margin-bottom:12px;padding-bottom:2px}
.filter-pill{flex-shrink:0;padding:8px 14px;border-radius:20px;font-size:11px;font-weight:700;border:1px solid #cde;background:#fff;color:#00609C;cursor:pointer;white-space:nowrap}
.filter-pill.active{background:#00609C;color:#fff;border-color:#00609C}
.evt-card{background:#fff;border-left:4px solid #00609C;border-radius:8px;padding:12px;margin-bottom:10px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.evt-card.soon{border-left-color:#f59e0b}
.evt-head{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
.evt-title{font-weight:700;font-size:13px;color:#0f2942}
.evt-sub{font-size:11px;color:#888;margin-top:2px}
.status-pill{padding:4px 10px;border-radius:12px;font-size:9px;font-weight:700;white-space:nowrap}
.status-pending{background:#fef3c7;color:#92400e}.status-confirmed{background:#dbeafe;color:#1e40af}
.status-delivered{background:#dcfce7;color:#166534}.status-cancelled{background:#fee2e2;color:#991b1b}
.evt-body{font-size:12px;color:#444;margin-top:8px;line-height:1.6}
.evt-money{display:flex;gap:14px;margin-top:8px;font-size:11px}
.evt-money b{color:#00609C}
.soon-tag{background:#fef3c7;color:#92400e;font-size:9px;font-weight:700;padding:3px 8px;border-radius:10px;margin-left:6px}
.evt-actions{display:flex;gap:6px;margin-top:10px;flex-wrap:wrap}
.evt-actions button{padding:8px 12px;border-radius:8px;border:none;font-size:11px;font-weight:700}
.btn-confirm{background:#dbeafe;color:#1e40af}.btn-deliver{background:#dcfce7;color:#166534}
.btn-edit{background:#f0f4f8;color:#555}.btn-cancel{background:#fee2e2;color:#991b1b}.btn-del{background:#fee2e2;color:#991b1b}
.empty{color:#888;text-align:center;padding:30px 10px;font-size:13px}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:100;align-items:center;justify-content:center;padding:16px}
.overlay.show{display:flex}
.modal{background:#fff;border-radius:14px;padding:20px;width:100%;max-width:420px;max-height:90vh;overflow-y:auto}
.modal h3{margin:0 0 12px;font-size:16px;color:#00609C}
.modal label{font-size:12px;color:#666;display:block;margin:10px 0 4px;font-weight:600}
.modal input,.modal select,.modal textarea{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:14px;font-family:inherit}
.two-col-input{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.modal .btn-row{display:flex;gap:8px;margin-top:16px}
.modal .btn-row button{flex:1;padding:11px;border-radius:9px;border:none;font-size:13px;font-weight:700}
.modal .btn-cancel2{background:#eee;color:#555}.modal .btn-confirm2{background:#00609C;color:#fff}
.status{font-size:12px;text-align:center;margin-top:8px;min-height:16px}.status.err{color:#c0392b}.status.ok{color:#1a8a4a}
.estimate{background:#eef4fb;border-radius:8px;padding:8px 10px;margin-top:10px;font-size:12px;color:#00609C;font-weight:600}
</style></head>
<body>
<div class="topbar">
  <h1>🎉 Advance Orders</h1>
  <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
    <a href="/cashier" class="nav-pill">Sales</a>
    <div class="menu-wrap">
      <button type="button" class="menu-btn" id="navMenuBtn" onclick="toggleNavMenu()" title="Menu">☰</button>
      <div class="menu-dropdown" id="navMenuDropdown">
        <a href="/home">🏠 Home</a>
        <a href="/machines">🏭 Machines</a>
        <a href="/credit">💳 Utang</a>
        <a href="/credit/history">🧾 Utang History</a>
        <a href="/expenses">💸 Expenses</a>
        <a href="/plastic">📦 Plastic</a>
        <a href="/assets">🏗️ Fixed Assets</a>
        <a href="/advance-orders" class="active">🎉 Advance Orders</a>
        <a href="/admin/duplicates">🔍 Duplicate Finder</a>
<a href="/prices">💰 Price Manager</a>
        <a href="/dashboard">📊 Dashboard</a>
      </div>
    </div>
  </div>
</div>

<div class="card" id="leaderboardCard" style="background:linear-gradient(135deg,#00609C,#0f2942);color:#fff">
  <h3 style="color:#fff;margin:0 0 4px;font-size:13px">🏆 Top Bookers Ngayong Buwan</h3>
  <div id="leaderboardList" style="font-size:12px">Loading...</div>
</div>

<button class="add-btn" onclick="openAddModal()">➕ Bagong Advance Order</button>

<div class="filter-row" id="filterRow"></div>

<div id="listWrap">Loading...</div>

<div class="overlay" id="formOverlay">
  <div class="modal">
    <h3 id="formTitle">Bagong Advance Order</h3>
    <input type="hidden" id="f_id">

    <label>Reseller (optional)</label>
    <select id="f_reseller"><option value="">— Walk-in / walang account —</option></select>

    <label>Contact Person</label>
    <input type="text" id="f_contact_name" placeholder="Pangalan ng may-ari ng event">
    <label>Contact Number</label>
    <input type="text" id="f_contact_number" placeholder="09XXXXXXXXX">

    <label>Uri ng Event</label>
    <select id="f_event_type"></select>
    <div id="f_event_other_wrap" style="display:none">
      <label>Anong event?</label>
      <input type="text" id="f_event_other" placeholder="Ilagay ang event">
    </div>

    <label>Venue / Address</label>
    <textarea id="f_venue" rows="2" placeholder="Saan ide-deliver"></textarea>

    <div class="two-col-input">
      <div><label>Delivery Date</label><input type="date" id="f_date"></div>
      <div><label>Delivery Time (optional)</label><input type="time" id="f_time"></div>
    </div>

    <div class="two-col-input">
      <div><label>Quantity (bags)</label><input type="number" id="f_qty" placeholder="0" step="1" min="1"></div>
      <div><label>Kg Size</label><select id="f_kg_size"></select></div>
    </div>

    <label>Deposit na binayad na (₱, optional)</label>
    <input type="number" id="f_deposit" placeholder="0.00" step="0.01" min="0">

    <div class="estimate" id="estimateBox">Tinatayang Halaga: ₱0.00</div>

    <label>Special Instructions (optional)</label>
    <textarea id="f_notes" rows="2" placeholder="Hal: dalhin sa likod, i-deliver bago mag-alas 6"></textarea>

    <p class="status" id="formStatus"></p>
    <div class="btn-row">
      <button class="btn-cancel2" onclick="closeFormModal()">Cancel</button>
      <button class="btn-confirm2" onclick="submitForm()">✅ I-save</button>
    </div>
  </div>
</div>

<script>
function toggleNavMenu(e){
  if(e) e.stopPropagation();
  const dd = document.getElementById('navMenuDropdown');
  const btn = document.getElementById('navMenuBtn');
  if(!dd || !btn) return;
  const willShow = !dd.classList.contains('show');
  dd.classList.toggle('show', willShow);
  btn.classList.toggle('open', willShow);
}
document.addEventListener('click', function(e){
  const wrap = document.querySelector('.menu-wrap');
  if(wrap && !wrap.contains(e.target)){
    const dd = document.getElementById('navMenuDropdown');
    const btn = document.getElementById('navMenuBtn');
    if(dd) dd.classList.remove('show');
    if(btn) btn.classList.remove('open');
  }
});

const EVENT_TYPES = {{ event_types|tojson }};
const KG_SIZES = {{ kg_sizes|tojson }};
const IS_ISESMO = {{ 'true' if is_isesmo else 'false' }};
const FALLBACK_PRICES = {{ fallback_prices|tojson }};
let currentFilter = 'All';
let allOrders = [];
let resellerCache = [];

function escapeHtmlA(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }
function daysUntil(dateStr){
  if(!dateStr) return null;
  const today = new Date(); today.setHours(0,0,0,0);
  const d = new Date(dateStr + 'T00:00:00');
  return Math.round((d - today) / 86400000);
}

function renderFilters(){
  const wrap = document.getElementById('filterRow');
  const tabs = ['All', 'Pending', 'Confirmed', 'Delivered', 'Cancelled'];
  wrap.innerHTML = tabs.map(t => `<div class="filter-pill ${t===currentFilter?'active':''}" onclick="setFilter('${t}')">${t}</div>`).join('');
}
function setFilter(t){ currentFilter = t; renderFilters(); renderList(); }

function renderList(){
  const wrap = document.getElementById('listWrap');
  let rows = allOrders.slice();
  if(currentFilter !== 'All') rows = rows.filter(r => r.status === currentFilter);
  rows.sort((a,b) => (a.delivery_date||'').localeCompare(b.delivery_date||''));
  if(!rows.length){ wrap.innerHTML = '<div class="empty">Walang advance order dito.</div>'; return; }
  wrap.innerHTML = rows.map(r => {
    const dLeft = daysUntil(r.delivery_date);
    const soon = (r.status==='Pending' || r.status==='Confirmed') && dLeft!==null && dLeft>=0 && dLeft<=3;
    const evtLabel = (r.event_type==='Iba pa' && r.event_type_other) ? r.event_type_other : r.event_type;
    const who = r.reseller_name || r.contact_name || 'Walk-in';
    let actions = '';
    if(r.status==='Pending') actions += `<button class="btn-confirm" onclick="setStatus('${r.id}','Confirmed')">✔️ Confirm</button>`;
    if(r.status==='Pending' || r.status==='Confirmed') actions += `<button class="btn-deliver" onclick="deliverOrder('${r.id}')">🚚 Mark Delivered</button>`;
    if(r.status!=='Delivered' && r.status!=='Cancelled') actions += `<button class="btn-edit" onclick="openEditModal('${r.id}')">✏️ Edit</button>`;
    if(r.status!=='Delivered' && r.status!=='Cancelled') actions += `<button class="btn-cancel" onclick="setStatus('${r.id}','Cancelled')">🚫 Cancel</button>`;
    if(IS_ISESMO) actions += `<button class="btn-del" onclick="deleteOrder('${r.id}')">🗑️ Delete</button>`;
    return `
      <div class="evt-card ${soon?'soon':''}">
        <div class="evt-head">
          <div>
            <div class="evt-title">🎊 ${escapeHtmlA(evtLabel)} - ${escapeHtmlA(who)}${soon?`<span class="soon-tag">${dLeft===0?'NGAYON':dLeft+'d na lang'}</span>`:''}</div>
            <div class="evt-sub">📅 ${escapeHtmlA(r.delivery_date||'-')}${r.delivery_time?' • '+escapeHtmlA(r.delivery_time):''}</div>
          </div>
          <span class="status-pill status-${(r.status||'pending').toLowerCase()}">${escapeHtmlA(r.status)}</span>
        </div>
        <div class="evt-body">
          📍 ${escapeHtmlA(r.venue_address||'-')}<br>
          📞 ${escapeHtmlA(r.contact_name||'-')} ${r.contact_number?'('+escapeHtmlA(r.contact_number)+')':''}<br>
          🧊 ${r.quantity} x ${escapeHtmlA(r.kg_size)}
          ${r.special_instructions ? '<br>📝 '+escapeHtmlA(r.special_instructions) : ''}
        </div>
        <div class="evt-money">
          <span>Total: <b>${peso(r.total_amount)}</b></span>
          <span>Deposit: <b>${peso(r.deposit_amount)}</b></span>
          <span>Balance: <b>${peso(r.balance_due)}</b></span>
        </div>
        <div class="evt-actions">${actions}</div>
      </div>
    `;
  }).join('');
}

async function loadOrders(){
  try{
    const res = await fetch('/api/advance_orders');
    if(res.status===401){ window.location.href='/login'; return; }
    const data = await res.json();
    if(!data.ok){ document.getElementById('listWrap').innerHTML = `<div class="empty">${escapeHtmlA(data.error||'Error')}</div>`; return; }
    allOrders = data.orders || [];
    renderList();
  }catch(e){
    document.getElementById('listWrap').innerHTML = `<div class="empty">Error: ${escapeHtmlA(e.message)}</div>`;
  }
}

async function loadResellers(){
  try{
    const res = await fetch('/api/resellers');
    const data = await res.json();
    resellerCache = data.resellers || data || [];
    const sel = document.getElementById('f_reseller');
    const opts = ['<option value="">— Walk-in / walang account —</option>'];
    resellerCache.forEach(r => opts.push(`<option value="${escapeHtmlA(r.id)}">${escapeHtmlA(r.store_name)}</option>`));
    sel.innerHTML = opts.join('');
  }catch(e){ /* non-fatal - walk-in booking still works without the list */ }
}

function populateStaticSelects(){
  document.getElementById('f_event_type').innerHTML = EVENT_TYPES.map(t => `<option value="${t}">${t}</option>`).join('');
  document.getElementById('f_kg_size').innerHTML = KG_SIZES.map(t => `<option value="${t}">${t}</option>`).join('');
}

function updateEstimate(){
  const qty = parseFloat(document.getElementById('f_qty').value) || 0;
  const kgSize = document.getElementById('f_kg_size').value;
  const price = FALLBACK_PRICES[kgSize] || 10;
  document.getElementById('estimateBox').textContent = `Tinatayang Halaga: ${peso(price*qty)} (₱${price}/${kgSize})`;
}

function openAddModal(){
  document.getElementById('formTitle').textContent = 'Bagong Advance Order';
  document.getElementById('f_id').value = '';
  document.getElementById('f_reseller').value = '';
  document.getElementById('f_contact_name').value = '';
  document.getElementById('f_contact_number').value = '';
  document.getElementById('f_event_type').value = EVENT_TYPES[0];
  document.getElementById('f_event_other').value = '';
  document.getElementById('f_event_other_wrap').style.display = (EVENT_TYPES[0]==='Iba pa') ? 'block' : 'none';
  document.getElementById('f_venue').value = '';
  document.getElementById('f_date').value = '';
  document.getElementById('f_time').value = '';
  document.getElementById('f_qty').value = '';
  document.getElementById('f_kg_size').value = KG_SIZES[0];
  document.getElementById('f_deposit').value = '';
  document.getElementById('f_notes').value = '';
  document.getElementById('formStatus').textContent = '';
  updateEstimate();
  document.getElementById('formOverlay').classList.add('show');
}

function openEditModal(id){
  const r = allOrders.find(x => x.id === id);
  if(!r) return;
  document.getElementById('formTitle').textContent = 'I-edit ang Advance Order';
  document.getElementById('f_id').value = r.id;
  document.getElementById('f_reseller').value = r.reseller_id || '';
  document.getElementById('f_contact_name').value = r.contact_name || '';
  document.getElementById('f_contact_number').value = r.contact_number || '';
  document.getElementById('f_event_type').value = r.event_type || EVENT_TYPES[0];
  document.getElementById('f_event_other').value = r.event_type_other || '';
  document.getElementById('f_event_other_wrap').style.display = (r.event_type==='Iba pa') ? 'block' : 'none';
  document.getElementById('f_venue').value = r.venue_address || '';
  document.getElementById('f_date').value = r.delivery_date || '';
  document.getElementById('f_time').value = r.delivery_time || '';
  document.getElementById('f_qty').value = r.quantity || '';
  document.getElementById('f_kg_size').value = r.kg_size || KG_SIZES[0];
  document.getElementById('f_deposit').value = r.deposit_amount || '';
  document.getElementById('f_notes').value = r.special_instructions || '';
  document.getElementById('formStatus').textContent = '';
  updateEstimate();
  document.getElementById('formOverlay').classList.add('show');
}
function closeFormModal(){ document.getElementById('formOverlay').classList.remove('show'); }

document.addEventListener('DOMContentLoaded', function(){
  document.getElementById('f_event_type').addEventListener('change', function(){
    document.getElementById('f_event_other_wrap').style.display = (this.value==='Iba pa') ? 'block' : 'none';
  });
  document.getElementById('f_qty').addEventListener('input', updateEstimate);
  document.getElementById('f_kg_size').addEventListener('change', updateEstimate);
});

async function submitForm(){
  const id = document.getElementById('f_id').value;
  const selReseller = document.getElementById('f_reseller');
  const resellerName = selReseller.value ? (selReseller.options[selReseller.selectedIndex].textContent) : '';
  const body = {
    reseller_id: selReseller.value || null,
    reseller_name: resellerName,
    contact_name: document.getElementById('f_contact_name').value.trim(),
    contact_number: document.getElementById('f_contact_number').value.trim(),
    event_type: document.getElementById('f_event_type').value,
    event_type_other: document.getElementById('f_event_other').value.trim(),
    venue_address: document.getElementById('f_venue').value.trim(),
    delivery_date: document.getElementById('f_date').value,
    delivery_time: document.getElementById('f_time').value,
    quantity: parseFloat(document.getElementById('f_qty').value) || 0,
    kg_size: document.getElementById('f_kg_size').value,
    deposit_amount: parseFloat(document.getElementById('f_deposit').value) || 0,
    special_instructions: document.getElementById('f_notes').value.trim(),
  };
  const st = document.getElementById('formStatus');
  if(!body.delivery_date){ st.textContent = 'Pumili ng delivery date.'; st.className = 'status err'; return; }
  if(!body.quantity || body.quantity <= 0){ st.textContent = 'Ilagay ang valid na quantity.'; st.className = 'status err'; return; }
  if(!body.venue_address){ st.textContent = 'Ilagay ang venue/address.'; st.className = 'status err'; return; }
  st.textContent = 'Saving...'; st.className = 'status';
  try{
    const url = id ? `/api/advance_orders/${id}` : '/api/advance_orders';
    const method = id ? 'PATCH' : 'POST';
    const res = await fetch(url, {method, headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const data = await res.json();
    if(data.ok){
      st.textContent = 'Na-save!'; st.className = 'status ok';
      setTimeout(() => { closeFormModal(); loadOrders(); }, 400);
    } else {
      st.textContent = data.error || 'May error.'; st.className = 'status err';
    }
  }catch(e){
    st.textContent = 'Error: ' + e.message; st.className = 'status err';
  }
}

async function setStatus(id, status){
  if(status==='Cancelled' && !confirm('I-cancel ang advance order na ito?')) return;
  try{
    const res = await fetch(`/api/advance_orders/${id}`, {method:'PATCH', headers:{'Content-Type':'application/json'}, body: JSON.stringify({status})});
    const data = await res.json();
    if(data.ok) loadOrders(); else alert(data.error || 'Hindi na-update.');
  }catch(e){ alert('Error: ' + e.message); }
}

async function deliverOrder(id){
  if(!confirm('I-mark bilang Delivered? Isang sale record ang gagawin nito.')) return;
  try{
    const res = await fetch(`/api/advance_orders/${id}/deliver`, {method:'POST'});
    const data = await res.json();
    if(data.ok) loadOrders(); else alert(data.error || 'Hindi na-mark bilang delivered.');
  }catch(e){ alert('Error: ' + e.message); }
}

async function deleteOrder(id){
  if(!confirm('Permanenteng tanggalin ang advance order na ito?')) return;
  try{
    const res = await fetch(`/api/advance_orders/${id}`, {method:'DELETE'});
    const data = await res.json();
    if(data.ok) loadOrders(); else alert(data.error || 'Hindi na-delete.');
  }catch(e){ alert('Error: ' + e.message); }
}

async function loadLeaderboard(){
  const wrap = document.getElementById('leaderboardList');
  const card = document.getElementById('leaderboardCard');
  try{
    const res = await fetch('/api/advance_orders/leaderboard');
    const data = await res.json();
    if(!data.ok){ if(card) card.style.display = 'none'; return; }
    const rows = data.leaderboard || [];
    if(!rows.length){ wrap.innerHTML = '<div style="opacity:.85">Wala pang na-book ngayong buwan.</div>'; return; }
    const medals = ['🥇','🥈','🥉'];
    wrap.innerHTML = rows.map((r, idx) => `
      <div style="display:flex;justify-content:space-between;padding:4px 0">
        <span>${medals[idx] || '#'+r.rank} ${escapeHtmlA(r.reseller_name)}</span>
        <span>${r.total_kg} kg</span>
      </div>
    `).join('');
  }catch(e){
    if(card) card.style.display = 'none';
  }
}

populateStaticSelects();
renderFilters();
loadResellers();
loadOrders();
loadLeaderboard();
</script>
</body></html>
"""


@advance_orders_bp.route("/advance-orders")
@login_required
def advance_orders_page():
    staff = (session.get("staff_name") or "").strip().lower()
    is_isesmo = staff in ["isesmo", "isesmo gamboa"]
    return render_template_string(
        ADVANCE_ORDERS_HTML,
        event_types=EVENT_TYPES,
        kg_sizes=KG_SIZES,
        is_isesmo=is_isesmo,
        fallback_prices=FALLBACK_PRICES,
    )


@advance_orders_bp.route("/api/advance_orders")
@login_required
def api_advance_orders_list():
    try:
        status_filter = (request.args.get("status") or "").strip()
        data = fb_get("advance_orders") or {}
        orders = []
        for key, val in data.items():
            if not val:
                continue
            if status_filter and (val.get("status") or "Pending") != status_filter:
                continue
            orders.append(_serialize(key, val))
        orders.sort(key=lambda r: r.get("delivery_date") or "9999-99-99")
        return jsonify({"ok": True, "orders": orders})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@advance_orders_bp.route("/api/advance_orders/leaderboard")
def api_advance_orders_leaderboard():
    """Top-5 resellers by total kg booked this month. Reachable by
    EITHER a logged-in reseller or staff (not staff-only, unlike most
    routes in this module) since the whole point is for resellers
    themselves to see it on their own booking page and feel the
    competition - it never exposes anything beyond store name + kg,
    the same info already visible to any staff member anyway."""
    try:
        if not session.get("customer_id") and not session.get("staff_name"):
            return jsonify({"ok": False, "error": "Login required"}), 401
        now = datetime.now()
        top = _compute_leaderboard(now.year, now.month, top_n=5)
        return jsonify({"ok": True, "year": now.year, "month": now.month, "leaderboard": top})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def _validate_and_build(data, existing=None):
    """Shared validation/normalization for create + edit. Returns
    (entry_dict, error_response_or_None)."""
    quantity = data.get("quantity")
    try:
        quantity = float(quantity)
    except (TypeError, ValueError):
        quantity = 0
    if quantity <= 0:
        return None, (jsonify({"ok": False, "error": "Invalid quantity"}), 400)

    kg_size = data.get("kg_size") or "1Kg"
    if kg_size not in KG_SIZES:
        kg_size = "1Kg"

    event_type = data.get("event_type") or "Iba pa"
    if event_type not in EVENT_TYPES:
        event_type = "Iba pa"

    delivery_date = (data.get("delivery_date") or "").strip()
    if not delivery_date:
        return None, (jsonify({"ok": False, "error": "Delivery date is required"}), 400)
    try:
        datetime.strptime(delivery_date, "%Y-%m-%d")
    except ValueError:
        return None, (jsonify({"ok": False, "error": "Invalid delivery date format (YYYY-MM-DD)"}), 400)

    venue_address = (data.get("venue_address") or "").strip()
    if not venue_address:
        return None, (jsonify({"ok": False, "error": "Venue/address is required"}), 400)

    try:
        deposit_amount = round(float(data.get("deposit_amount") or 0), 2)
    except (TypeError, ValueError):
        deposit_amount = 0
    if deposit_amount < 0:
        deposit_amount = 0

    unit_price = _get_price(kg_size)
    total_amount = round(unit_price * quantity, 2)

    entry = {
        "reseller_id": data.get("reseller_id") or None,
        "reseller_name": (data.get("reseller_name") or "").strip(),
        "contact_name": (data.get("contact_name") or "").strip(),
        "contact_number": (data.get("contact_number") or "").strip(),
        "event_type": event_type,
        "event_type_other": (data.get("event_type_other") or "").strip() if event_type == "Iba pa" else "",
        "venue_address": venue_address,
        "delivery_date": delivery_date,
        "delivery_time": (data.get("delivery_time") or "").strip(),
        "quantity": quantity,
        "kg_size": kg_size,
        "unit_price": unit_price,
        "total_amount": total_amount,
        "deposit_amount": deposit_amount,
        "special_instructions": (data.get("special_instructions") or "").strip(),
        "updated_at": now_str(),
    }
    if existing is None:
        entry["status"] = "Pending"
        entry["created_at"] = now_str()
        entry["fulfilled_sale_id"] = None
    return entry, None


@advance_orders_bp.route("/api/advance_orders", methods=["POST"])
@login_required
def api_advance_orders_create():
    try:
        data = request.json or {}
        entry, err = _validate_and_build(data)
        if err:
            return err
        entry["order_source"] = "staff"
        entry["created_by"] = session.get("staff_name")
        fb_post("advance_orders", entry)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@advance_orders_bp.route("/api/advance_orders/<order_id>", methods=["PATCH"])
@login_required
def api_advance_orders_update(order_id):
    try:
        existing = fb_get(f"advance_orders/{order_id}")
        if not existing:
            return jsonify({"ok": False, "error": "Advance order not found"}), 404
        if existing.get("status") in ("Delivered", "Cancelled") and not request.json.get("status"):
            # already finalized - block edits to line items, but still
            # allow an explicit status change (e.g. un-cancel isn't
            # offered in the UI, but this keeps the API honest either way)
            return jsonify({"ok": False, "error": "Hindi na pwedeng i-edit ang isang Delivered/Cancelled na order."}), 400

        data = request.json or {}
        # A pure status-change request (e.g. Confirm/Cancel from the list
        # view) only sends {"status": "..."} - don't run full validation
        # in that case, since venue/qty/etc. weren't resent.
        if set(data.keys()) <= {"status"}:
            status = data.get("status")
            if status not in STATUSES:
                return jsonify({"ok": False, "error": "Invalid status"}), 400
            fb_patch(f"advance_orders/{order_id}", {"status": status, "updated_at": now_str()})
            return jsonify({"ok": True})

        entry, err = _validate_and_build(data, existing=existing)
        if err:
            return err
        fb_patch(f"advance_orders/{order_id}", entry)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@advance_orders_bp.route("/api/advance_orders/<order_id>/deliver", methods=["POST"])
@login_required
def api_advance_orders_deliver(order_id):
    try:
        existing = fb_get(f"advance_orders/{order_id}")
        if not existing:
            return jsonify({"ok": False, "error": "Advance order not found"}), 404
        if existing.get("status") == "Delivered" and existing.get("fulfilled_sale_id"):
            # Already converted - don't create a second daily_sales row
            # (e.g. a double-tap on "Mark Delivered").
            return jsonify({"ok": True, "already_delivered": True})
        if existing.get("status") == "Cancelled":
            return jsonify({"ok": False, "error": "Cancelled na ang booking na ito."}), 400

        sale = {
            "reseller_id": existing.get("reseller_id"),
            "reseller_name": existing.get("reseller_name") or existing.get("contact_name") or "",
            "quantity": existing.get("quantity"),
            "kg_size": existing.get("kg_size"),
            "unit_price": existing.get("unit_price"),
            "total_sales": existing.get("total_amount"),
            "mode": "DELIVER",
            "payment": "Cash",
            "sales_date": existing.get("delivery_date"),
            "created_at": now_str(),
            "staff_name": session.get("staff_name"),
            "order_status": "Delivered",
            # Deliberately NOT "customer" - see module docstring: this is
            # a one-off event booking, not a normal reseller restock
            # order, and "customer" gates the online-orders points logic
            # elsewhere in app.py.
            "order_source": "advance_order",
            "notes": f"Advance order ({existing.get('event_type')}) - {existing.get('venue_address','')}".strip(),
        }
        sale_result = fb_post("daily_sales", sale)
        sale_id = sale_result.get("name") if sale_result else None
        fb_patch(f"advance_orders/{order_id}", {
            "status": "Delivered",
            "fulfilled_sale_id": sale_id,
            "updated_at": now_str(),
        })
        return jsonify({"ok": True, "sale_id": sale_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@advance_orders_bp.route("/api/advance_orders/<order_id>", methods=["DELETE"])
@isesmo_only
def api_advance_orders_delete(order_id):
    try:
        fb_delete(f"advance_orders/{order_id}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# =================================================================
# RESELLER-SIDE BOOKING PAGE
# =================================================================
ADVANCE_ORDER_CUSTOMER_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Book an Event - Omega Ice</title>
<link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.topbar h1{font-size:15px;color:#00609C;margin:0}
.btn{padding:10px 14px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;text-decoration:none}
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.card h3{margin:0 0 10px;font-size:13px;color:#00609C}
label{font-size:12px;color:#666;display:block;margin:10px 0 4px;font-weight:600}
input,select,textarea{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:14px;font-family:inherit}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.estimate{background:#eef4fb;border-radius:8px;padding:10px;margin-top:12px;font-size:13px;color:#00609C;font-weight:700;text-align:center}
.submit-btn{width:100%;padding:13px;border-radius:10px;border:none;background:#00609C;color:#fff;font-weight:700;font-size:14px;margin-top:14px}
.status{font-size:12px;text-align:center;margin-top:8px;min-height:16px}.status.err{color:#c0392b}.status.ok{color:#1a8a4a}
.evt-card{border-left:4px solid #0096D6;padding:10px 12px;margin:8px 0;background:#f9fbfd;border-radius:8px;font-size:12px}
.status-pill{padding:3px 9px;border-radius:12px;font-size:9px;font-weight:700}
.status-pending{background:#fef3c7;color:#92400e}.status-confirmed{background:#dbeafe;color:#1e40af}
.status-delivered{background:#dcfce7;color:#166534}.status-cancelled{background:#fee2e2;color:#991b1b}
.empty{color:#888;text-align:center;padding:16px;font-size:12px}
</style></head>
<body>
<div class="topbar"><h1>🎉 Book an Event Order</h1><a href="/customer/{{ reseller_id }}/dashboard" class="btn">← Back</a></div>

<div class="card" id="leaderboardCard" style="background:linear-gradient(135deg,#00609C,#0f2942);color:#fff">
  <h3 style="color:#fff;margin:0 0 4px">🏆 Top Bookers Ngayong Buwan</h3>
  <p style="font-size:11px;opacity:.85;margin:0 0 10px">Ranggo base sa total kg ng events na na-book — nag-re-reset bawat buwan.</p>
  <div id="leaderboardList">Loading...</div>
</div>

<div class="card">
  <h3>Bagong Event Booking</h3>
  <p style="font-size:11px;color:#888;margin-top:-4px">Para sa fiesta, kasal, binyag, at iba pang malaking bilihan na may specific delivery date.</p>

  <label>Uri ng Event</label>
  <select id="f_event_type"></select>
  <div id="f_event_other_wrap" style="display:none">
    <label>Anong event?</label>
    <input type="text" id="f_event_other" placeholder="Ilagay ang event">
  </div>

  <label>Contact Person</label>
  <input type="text" id="f_contact_name" placeholder="Pangalan ng may-ari ng event">
  <label>Contact Number</label>
  <input type="text" id="f_contact_number" placeholder="09XXXXXXXXX">

  <label>Venue / Delivery Address</label>
  <textarea id="f_venue" rows="2" placeholder="Saan ide-deliver"></textarea>

  <div class="two-col">
    <div><label>Delivery Date</label><input type="date" id="f_date"></div>
    <div><label>Delivery Time (optional)</label><input type="time" id="f_time"></div>
  </div>

  <div class="two-col">
    <div><label>Quantity (bags)</label><input type="number" id="f_qty" placeholder="0" step="1" min="1"></div>
    <div><label>Kg Size</label><select id="f_kg_size"></select></div>
  </div>

  <label>Special Instructions (optional)</label>
  <textarea id="f_notes" rows="2" placeholder="Hal: i-deliver bago mag-alas 6 ng umaga"></textarea>

  <div class="estimate" id="estimateBox">Tinatayang Halaga: ₱0.00</div>
  <button class="submit-btn" onclick="submitBooking()">✅ I-book ang Event</button>
  <p class="status" id="formStatus"></p>
</div>

<div class="card">
  <h3>Aking mga Naka-book na Event</h3>
  <div id="myBookingsList">Loading...</div>
</div>

<script>
const resellerId = "{{ reseller_id }}";
const EVENT_TYPES = {{ event_types|tojson }};
const KG_SIZES = {{ kg_sizes|tojson }};
const FALLBACK_PRICES = {{ fallback_prices|tojson }};

function escapeHtmlAC(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }

document.getElementById('f_event_type').innerHTML = EVENT_TYPES.map(t => `<option value="${t}">${t}</option>`).join('');
document.getElementById('f_kg_size').innerHTML = KG_SIZES.map(t => `<option value="${t}">${t}</option>`).join('');

function updateEstimate(){
  const qty = parseFloat(document.getElementById('f_qty').value) || 0;
  const kgSize = document.getElementById('f_kg_size').value;
  const price = FALLBACK_PRICES[kgSize] || 10;
  document.getElementById('estimateBox').textContent = `Tinatayang Halaga: ${peso(price*qty)} (₱${price}/${kgSize})`;
}
document.getElementById('f_qty').addEventListener('input', updateEstimate);
document.getElementById('f_kg_size').addEventListener('change', updateEstimate);
document.getElementById('f_event_type').addEventListener('change', function(){
  document.getElementById('f_event_other_wrap').style.display = (this.value==='Iba pa') ? 'block' : 'none';
});
updateEstimate();

async function submitBooking(){
  const body = {
    contact_name: document.getElementById('f_contact_name').value.trim(),
    contact_number: document.getElementById('f_contact_number').value.trim(),
    event_type: document.getElementById('f_event_type').value,
    event_type_other: document.getElementById('f_event_other').value.trim(),
    venue_address: document.getElementById('f_venue').value.trim(),
    delivery_date: document.getElementById('f_date').value,
    delivery_time: document.getElementById('f_time').value,
    quantity: parseFloat(document.getElementById('f_qty').value) || 0,
    kg_size: document.getElementById('f_kg_size').value,
    special_instructions: document.getElementById('f_notes').value.trim(),
  };
  const st = document.getElementById('formStatus');
  if(!body.delivery_date){ st.textContent = 'Pumili ng delivery date.'; st.className='status err'; return; }
  if(!body.quantity || body.quantity<=0){ st.textContent = 'Ilagay ang valid na quantity.'; st.className='status err'; return; }
  if(!body.venue_address){ st.textContent = 'Ilagay ang venue/address.'; st.className='status err'; return; }
  st.textContent = 'Saving...'; st.className='status';
  try{
    const res = await fetch(`/api/customer/${resellerId}/advance_order`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)
    });
    const data = await res.json();
    if(data.ok){
      st.textContent = 'Na-book na! Kukumpirmahin ito ng staff.'; st.className='status ok';
      ['f_contact_name','f_contact_number','f_venue','f_date','f_time','f_qty','f_notes'].forEach(id => document.getElementById(id).value='');
      updateEstimate();
      loadMyBookings();
    } else {
      st.textContent = data.error || 'May error.'; st.className='status err';
    }
  }catch(e){
    st.textContent = 'Error: ' + e.message; st.className='status err';
  }
}

async function loadMyBookings(){
  const wrap = document.getElementById('myBookingsList');
  try{
    const res = await fetch(`/api/customer/${resellerId}/advance_orders`);
    const data = await res.json();
    if(!data.ok){ wrap.innerHTML = `<div class="empty">${escapeHtmlAC(data.error||'Error')}</div>`; return; }
    const rows = data.orders || [];
    if(!rows.length){ wrap.innerHTML = '<div class="empty">Wala ka pang na-book na event.</div>'; return; }
    wrap.innerHTML = rows.map(r => {
      const evtLabel = (r.event_type==='Iba pa' && r.event_type_other) ? r.event_type_other : r.event_type;
      return `
        <div class="evt-card">
          <div style="display:flex;justify-content:space-between"><b>🎊 ${escapeHtmlAC(evtLabel)}</b><span class="status-pill status-${(r.status||'pending').toLowerCase()}">${escapeHtmlAC(r.status)}</span></div>
          <div style="margin-top:4px">📅 ${escapeHtmlAC(r.delivery_date)}${r.delivery_time?' • '+escapeHtmlAC(r.delivery_time):''}</div>
          <div>🧊 ${r.quantity} x ${escapeHtmlAC(r.kg_size)} = ${peso(r.total_amount)}</div>
          <div>💰 Deposit: ${peso(r.deposit_amount)} • Balance: ${peso(r.balance_due)}</div>
        </div>
      `;
    }).join('');
  }catch(e){
    wrap.innerHTML = `<div class="empty">Error: ${escapeHtmlAC(e.message)}</div>`;
  }
}

async function loadLeaderboard(){
  const wrap = document.getElementById('leaderboardList');
  const card = document.getElementById('leaderboardCard');
  try{
    const res = await fetch('/api/advance_orders/leaderboard');
    const data = await res.json();
    if(!data.ok){ card.style.display = 'none'; return; }
    const rows = data.leaderboard || [];
    if(!rows.length){ wrap.innerHTML = `<div style="font-size:12px;opacity:.85">Wala pang na-book ngayong buwan — ikaw pwedeng maging una! 🎉</div>`; return; }
    const medals = ['🥇','🥈','🥉'];
    wrap.innerHTML = rows.map((r, idx) => {
      const isMe = r.reseller_id === resellerId;
      const medal = medals[idx] || `#${r.rank}`;
      return `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;${isMe?'font-weight:800':''};border-bottom:${idx<rows.length-1?'1px solid rgba(255,255,255,.15)':'none'}">
          <span>${medal} ${escapeHtmlAC(r.reseller_name)}${isMe?' (ikaw!)':''}</span>
          <span>${r.total_kg} kg</span>
        </div>
      `;
    }).join('');
  }catch(e){
    if(card) card.style.display = 'none';
  }
}

loadMyBookings();
loadLeaderboard();
</script>
</body></html>
"""


@advance_orders_bp.route("/customer/<reseller_id>/advance-order")
def customer_advance_order_page(reseller_id):
    if not session.get("customer_id") and not session.get("staff_name"):
        return redirect(url_for("customer_login_page"))
    if session.get("customer_id") and session.get("customer_id") != reseller_id and not session.get("staff_name"):
        return redirect(f"/customer/{session.get('customer_id')}/advance-order")
    return render_template_string(
        ADVANCE_ORDER_CUSTOMER_HTML,
        reseller_id=reseller_id,
        event_types=EVENT_TYPES,
        kg_sizes=KG_SIZES,
        fallback_prices=FALLBACK_PRICES,
    )


@advance_orders_bp.route("/api/customer/<reseller_id>/advance_order", methods=["POST"])
def api_customer_advance_order_create(reseller_id):
    try:
        # Same access pattern as api_customer_place_order in app.py: must
        # be logged in as this exact reseller, OR be staff.
        if session.get("customer_id") and session.get("customer_id") != reseller_id:
            return jsonify({"ok": False, "error": "Not allowed"}), 403
        if not session.get("customer_id") and not session.get("staff_name"):
            return jsonify({"ok": False, "error": "Login required"}), 401

        reseller = fb_get(f"resellers/{reseller_id}") or {}
        if not reseller:
            return jsonify({"ok": False, "error": "Reseller not found"}), 404

        data = request.json or {}
        entry, err = _validate_and_build(data)
        if err:
            return err
        entry["reseller_id"] = reseller_id
        entry["reseller_name"] = reseller.get("store_name", "")
        entry["order_source"] = "customer"
        entry["created_by"] = f"reseller:{reseller_id}"
        fb_post("advance_orders", entry)
        if session.get("customer_id") == reseller_id:
            log_customer_activity(reseller_id, reseller.get("store_name"), "Nag-book ng event",
                                   f"{entry.get('event_type','')} - {entry.get('quantity','')}x {entry.get('kg_size','')} on {entry.get('delivery_date','')}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@advance_orders_bp.route("/api/customer/<reseller_id>/advance_orders")
def api_customer_advance_orders_list(reseller_id):
    try:
        if session.get("customer_id") and session.get("customer_id") != reseller_id:
            return jsonify({"ok": False, "error": "Not allowed"}), 403
        if not session.get("customer_id") and not session.get("staff_name"):
            return jsonify({"ok": False, "error": "Login required"}), 401

        data = fb_get("advance_orders") or {}
        orders = []
        for key, val in data.items():
            if not val or val.get("reseller_id") != reseller_id:
                continue
            orders.append(_serialize(key, val))
        orders.sort(key=lambda r: r.get("delivery_date") or "9999-99-99")
        return jsonify({"ok": True, "orders": orders})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
