"""
Utang / Credit Collection module.

Ported from the "UtangScreen" + "CreditCollectionHistoryScreen" ideas in
the user's separate Kivy desktop app (OMEGA_PURIFIED.py), rewritten from
scratch for the web app: that version drew its own buttons/cards with
Kivy widgets and read/wrote a local SQLite `payments` table. Here it's a
normal Flask page + JSON API, and it reads/writes Firebase instead - the
SAME `resellers/<id>/credit_balance` field the rest of app.py already
uses (customer orders bump it up), plus a NEW `credit_payments` node
that is this module's own addition (a payment history log which nothing
in app.py wrote before this).

Routes:
  GET    /credit                            - Utang page: resellers with outstanding balance + Collect button
  GET    /credit/history                    - Collection History page (filters: All/Today/Date/Search)
  GET    /api/credit/outstanding            - JSON: resellers with credit_balance > 0
  POST   /api/credit/collect                - JSON: record a payment, decrement credit_balance
  GET    /api/credit/history                - JSON: payment log, filterable
  DELETE /api/credit/payment/<payment_id>   - ISESMO only: undo/delete a payment (e.g. a test entry
                                               or a mistake) - restores the reversed amount back onto
                                               the reseller's credit_balance so the books stay correct
"""
from datetime import datetime

from flask import Blueprint, request, jsonify, session, render_template_string

from modules.shared import fb_get, fb_post, fb_patch, fb_delete, login_required, isesmo_only, now_str, today_str

credit_bp = Blueprint("credit", __name__)


# ---------- Page: /credit ----------

CREDIT_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Utang / Credit - Omega Ice</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0;font-weight:700}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C}
.menu-wrap{position:relative}
.menu-btn{padding:7px 14px;border-radius:20px;font-size:15px;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600;cursor:pointer;line-height:1}
.menu-btn.open{background:#00609C;color:#fff;border-color:#00609C}
.menu-dropdown{display:none;position:absolute;top:calc(100% + 6px);right:0;background:#fff;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,.18);min-width:190px;z-index:60;overflow:hidden;border:1px solid #e5e7eb}
.menu-dropdown.show{display:block}
.menu-dropdown a{display:flex;align-items:center;gap:10px;padding:13px 16px;font-size:13px;color:#333;text-decoration:none;border-bottom:1px solid #f0f4f8;font-weight:600}
.menu-dropdown a:last-child{border-bottom:none}
.menu-dropdown a:hover,.menu-dropdown a:active{background:#eef7ff;color:#00609C}
.menu-dropdown a.active{background:#eef7ff;color:#00609C}
.total-card{background:linear-gradient(135deg,#c0392b,#e74c3c);color:#fff;border-radius:12px;padding:16px;margin-bottom:12px;text-align:center}
.total-card .amt{font-size:26px;font-weight:700}.total-card .lbl{font-size:11px;opacity:.9}
.card{background:#fff;border-radius:12px;padding:12px 14px;margin-bottom:10px;box-shadow:0 1px 4px rgba(0,0,0,.05);display:flex;justify-content:space-between;align-items:center;gap:10px}
.card .name{font-weight:600;font-size:14px}.card .bal{font-size:12px;color:#c0392b;font-weight:600}
.collect-btn{padding:9px 16px;border-radius:10px;border:none;background:#22c55e;color:#fff;font-size:12px;font-weight:700;white-space:nowrap}
input#searchInp{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px;margin-bottom:10px}
.empty{color:#888;text-align:center;padding:30px 10px;font-size:13px}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:100;align-items:center;justify-content:center;padding:16px}
.overlay.show{display:flex}
.modal{background:#fff;border-radius:14px;padding:20px;width:100%;max-width:360px}
.modal h3{margin:0 0 4px;font-size:16px;color:#00609C}
.modal .sub{font-size:12px;color:#888;margin-bottom:14px}
.modal label{font-size:12px;color:#666;display:block;margin:10px 0 4px}
.modal input,.modal textarea{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:14px;font-family:inherit}
.modal .btn-row{display:flex;gap:8px;margin-top:16px}
.modal .btn-row button{flex:1;padding:11px;border-radius:9px;border:none;font-size:13px;font-weight:700}
.modal .btn-cancel{background:#eee;color:#555}.modal .btn-confirm{background:#22c55e;color:#fff}
.status{font-size:12px;text-align:center;margin-top:8px;min-height:16px}.status.err{color:#c0392b}.status.ok{color:#1a8a4a}
</style></head>
<body>
<div class="topbar">
  <h1>💳 Utang / Credit Collection</h1>
  <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
    <a href="/orders" class="nav-pill" style="background:#ff4444;color:#fff;border-color:#ff4444">🔴 Live Orders</a>
    <a href="/cashier" class="nav-pill">Sales</a>
    <div class="menu-wrap">
      <button type="button" class="menu-btn" id="navMenuBtn" onclick="toggleNavMenu()" title="Menu">☰</button>
      <div class="menu-dropdown" id="navMenuDropdown">
        <a href="/home">🏠 Home</a>
        <a href="/machines">🏭 Machines</a>
        <a href="/credit" class="active">💳 Utang</a>
        <a href="/credit/history">🧾 Utang History</a>
        <a href="/expenses">💸 Expenses</a>
        <a href="/plastic">📦 Plastic</a>
        <a href="/assets">🏗️ Fixed Assets</a>
        <a href="/dashboard">📊 Dashboard</a>
      </div>
    </div>
  </div>
</div>

<div class="total-card"><div class="amt" id="totalOutstanding">₱0</div><div class="lbl">TOTAL OUTSTANDING UTANG</div></div>

<input type="text" id="searchInp" placeholder="Search store name..." oninput="renderList()">
<div id="listWrap">Loading...</div>

<div class="overlay" id="collectOverlay">
  <div class="modal">
    <h3>Collect Payment</h3>
    <div class="sub" id="collectStoreLabel"></div>
    <label>Amount (₱)</label>
    <input type="number" id="collectAmount" placeholder="0.00" step="0.01" min="0.01">
    <label>Note (optional)</label>
    <textarea id="collectNote" rows="2" placeholder="hal. bayad kalahati, weekly arrangement..."></textarea>
    <p class="status" id="collectStatus"></p>
    <div class="btn-row">
      <button class="btn-cancel" onclick="closeCollect()">Cancel</button>
      <button class="btn-confirm" onclick="submitCollect()">✅ Confirm</button>
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

let allResellers = [];
let activeReseller = null;

function escapeHtmlU(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }

async function loadOutstanding(){
  const wrap = document.getElementById('listWrap');
  try{
    const res = await fetch('/api/credit/outstanding');
    if(res.status===401){ window.location.href='/login'; return; }
    const data = await res.json();
    if(!data.ok){ wrap.innerHTML = `<div class="empty">${escapeHtmlU(data.error||'Error')}</div>`; return; }
    allResellers = data.rows || [];
    document.getElementById('totalOutstanding').textContent = peso(data.total || 0);
    renderList();
  }catch(e){
    wrap.innerHTML = `<div class="empty">Error: ${escapeHtmlU(e.message)}</div>`;
  }
}

function renderList(){
  const q = (document.getElementById('searchInp').value || '').toLowerCase().trim();
  let rows = allResellers;
  if(q) rows = rows.filter(r => (r.store_name||'').toLowerCase().includes(q));
  const wrap = document.getElementById('listWrap');
  if(!rows.length){
    wrap.innerHTML = '<div class="empty">Walang natitirang utang na customer. 🎉</div>';
    return;
  }
  wrap.innerHTML = rows.map(r => `
    <div class="card">
      <div>
        <div class="name">${escapeHtmlU(r.store_name)}</div>
        <div class="bal">${peso(r.credit_balance)} outstanding</div>
      </div>
      <button class="collect-btn" data-id="${escapeHtmlU(r.id)}" onclick="openCollectByIdx(this)">💵 Collect</button>
    </div>
  `).join('');
}
// Looks the reseller up in allResellers by id (read from the button's
// own data-id, set via a normal HTML attribute - never re-injects
// store_name into an inline onclick string). That's the fix for a store
// name with an apostrophe (e.g. "Tsong's Canteen"): JSON.stringify()
// does NOT escape single quotes, so embedding it straight into an
// onclick='...' attribute let the apostrophe close the attribute early
// and broke the whole button - looking it up by id sidesteps the
// problem entirely instead of trying to escape every special character.
function openCollectByIdx(btn){
  const id = btn.getAttribute('data-id');
  const r = allResellers.find(x => String(x.id) === id);
  if(!r) return;
  openCollect(r.id, r.store_name, r.credit_balance);
}

function openCollect(id, storeName, balance){
  activeReseller = {id, storeName, balance};
  document.getElementById('collectStoreLabel').textContent = `${storeName} - Outstanding: ${peso(balance)}`;
  document.getElementById('collectAmount').value = '';
  document.getElementById('collectNote').value = '';
  document.getElementById('collectStatus').textContent = '';
  document.getElementById('collectOverlay').classList.add('show');
}
function closeCollect(){
  document.getElementById('collectOverlay').classList.remove('show');
  activeReseller = null;
}
async function submitCollect(){
  if(!activeReseller) return;
  const amt = parseFloat(document.getElementById('collectAmount').value);
  const note = document.getElementById('collectNote').value.trim();
  const st = document.getElementById('collectStatus');
  if(!amt || amt <= 0){ st.textContent = 'Ilagay ang valid na amount.'; st.className = 'status err'; return; }
  st.textContent = 'Saving...'; st.className = 'status';
  try{
    const res = await fetch('/api/credit/collect', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({reseller_id: activeReseller.id, amount: amt, note: note})
    });
    const data = await res.json();
    if(data.ok){
      st.textContent = 'Na-record na ang payment!'; st.className = 'status ok';
      setTimeout(() => { closeCollect(); loadOutstanding(); }, 700);
    } else {
      st.textContent = data.error || 'May error.'; st.className = 'status err';
    }
  }catch(e){
    st.textContent = 'Error: ' + e.message; st.className = 'status err';
  }
}
loadOutstanding();
</script>
</body></html>
"""

CREDIT_HISTORY_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Collection History - Omega Ice</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0;font-weight:700}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C}
.menu-wrap{position:relative}
.menu-btn{padding:7px 14px;border-radius:20px;font-size:15px;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600;cursor:pointer;line-height:1}
.menu-btn.open{background:#00609C;color:#fff;border-color:#00609C}
.menu-dropdown{display:none;position:absolute;top:calc(100% + 6px);right:0;background:#fff;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,.18);min-width:190px;z-index:60;overflow:hidden;border:1px solid #e5e7eb}
.menu-dropdown.show{display:block}
.menu-dropdown a{display:flex;align-items:center;gap:10px;padding:13px 16px;font-size:13px;color:#333;text-decoration:none;border-bottom:1px solid #f0f4f8;font-weight:600}
.menu-dropdown a:last-child{border-bottom:none}
.menu-dropdown a:hover,.menu-dropdown a:active{background:#eef7ff;color:#00609C}
.menu-dropdown a.active{background:#eef7ff;color:#00609C}
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:10px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.filter-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.filter-btn{padding:7px 12px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px}
.filter-btn.active{background:#00609C;color:#fff}
input#dateInp,input#searchInp2{padding:9px;border-radius:8px;border:1px solid #ccd;font-size:12px}
.total-card{background:linear-gradient(135deg,#22c55e,#16a34a);color:#fff;border-radius:12px;padding:14px;margin-bottom:10px;text-align:center}
.total-card .amt{font-size:22px;font-weight:700}.total-card .lbl{font-size:11px;opacity:.9}
.log-row{display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid #f0f4f8}
.log-meta{font-size:9px;color:#aaa;margin-top:2px}
.amt-pill{font-weight:700;color:#1a8a4a;white-space:nowrap}
.empty{color:#888;text-align:center;padding:30px 10px;font-size:13px}
.del-btn{background:none;border:none;color:#c0392b;font-size:16px;padding:2px 4px}
</style></head>
<body>
<div class="topbar">
  <h1>📜 Collection History</h1>
  <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
    <a href="/cashier" class="nav-pill">Sales</a>
    <div class="menu-wrap">
      <button type="button" class="menu-btn" id="navMenuBtn" onclick="toggleNavMenu()" title="Menu">☰</button>
      <div class="menu-dropdown" id="navMenuDropdown">
        <a href="/home">🏠 Home</a>
        <a href="/machines">🏭 Machines</a>
        <a href="/credit">💳 Utang</a>
        <a href="/credit/history" class="active">🧾 Utang History</a>
        <a href="/expenses">💸 Expenses</a>
        <a href="/plastic">📦 Plastic</a>
        <a href="/assets">🏗️ Fixed Assets</a>
        <a href="/dashboard">📊 Dashboard</a>
      </div>
    </div>
  </div>
</div>

<div class="card">
  <div class="filter-row">
    <button class="filter-btn active" data-m="ALL" onclick="setMode('ALL')">ALL</button>
    <button class="filter-btn" data-m="TODAY" onclick="setMode('TODAY')">TODAY</button>
    <button class="filter-btn" data-m="DATE" onclick="setMode('DATE')">DATE</button>
  </div>
  <div class="filter-row">
    <input type="date" id="dateInp" style="display:none" onchange="setMode('DATE')">
    <input type="text" id="searchInp2" placeholder="Search store name..." style="flex:1" oninput="renderHistory()">
  </div>
</div>

<div class="total-card"><div class="amt" id="totalCollected">₱0</div><div class="lbl">TOTAL COLLECTED (this view)</div></div>

<div class="card" id="listWrap2">Loading...</div>

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

let currentMode = 'ALL';
let allPayments = [];
const IS_ISESMO = {{ 'true' if is_isesmo else 'false' }};

function escapeHtmlH(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso2(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }

function setMode(m){
  currentMode = m;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.m===m));
  document.getElementById('dateInp').style.display = (m==='DATE') ? 'block' : 'none';
  loadHistory();
}

async function loadHistory(){
  const wrap = document.getElementById('listWrap2');
  wrap.textContent = 'Loading...';
  try{
    let url = `/api/credit/history?mode=${currentMode}`;
    if(currentMode === 'DATE'){
      const d = document.getElementById('dateInp').value;
      if(!d){ wrap.innerHTML = '<div class="empty">Pumili ng date.</div>'; return; }
      url += `&date=${d}`;
    }
    const res = await fetch(url);
    if(res.status===401){ window.location.href='/login'; return; }
    const data = await res.json();
    if(!data.ok){ wrap.innerHTML = `<div class="empty">${escapeHtmlH(data.error||'Error')}</div>`; return; }
    allPayments = data.rows || [];
    renderHistory();
  }catch(e){
    wrap.innerHTML = `<div class="empty">Error: ${escapeHtmlH(e.message)}</div>`;
  }
}

function renderHistory(){
  const q = (document.getElementById('searchInp2').value || '').toLowerCase().trim();
  let rows = allPayments;
  if(q) rows = rows.filter(r => (r.store_name||'').toLowerCase().includes(q));
  const total = rows.reduce((s,r) => s + (Number(r.amount)||0), 0);
  document.getElementById('totalCollected').textContent = peso2(total);
  const wrap = document.getElementById('listWrap2');
  if(!rows.length){
    wrap.innerHTML = '<div class="empty">Walang payment na nakita.</div>';
    return;
  }
  wrap.innerHTML = rows.map(r => `
    <div class="log-row">
      <div>
        <div style="font-weight:600">${escapeHtmlH(r.store_name)}</div>
        ${r.note ? `<div class="log-meta">${escapeHtmlH(r.note)}</div>` : ''}
        <div class="log-meta">${escapeHtmlH(r.collected_at)} • ni ${escapeHtmlH(r.collected_by||'-')}</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <div class="amt-pill">${peso2(r.amount)}</div>
        ${IS_ISESMO ? `<button class="del-btn" data-id="${escapeHtmlH(r.id)}" onclick="deletePaymentByIdx(this)">🗑️</button>` : ''}
      </div>
    </div>
  `).join('');
}
// Same fix as openCollectByIdx() above: look the payment up in
// allPayments by id (read from a normal data-id attribute) instead of
// re-injecting store_name into an inline onclick='...' string, which
// broke on any store name containing an apostrophe.
function deletePaymentByIdx(btn){
  const id = btn.getAttribute('data-id');
  const r = allPayments.find(x => String(x.id) === id);
  if(!r) return;
  deletePayment(r.id, r.store_name, r.amount);
}

async function deletePayment(id, storeName, amount){
  if(!confirm(`Tanggalin ang payment na ${peso2(amount)} para kay ${storeName}?\\n\\nMababawi ito pabalik sa utang niya (credit_balance).`)) return;
  try{
    const res = await fetch(`/api/credit/payment/${id}`, {method:'DELETE'});
    const data = await res.json();
    if(data.ok){
      loadHistory();
    } else {
      alert(data.error || 'Hindi na-delete.');
    }
  }catch(e){
    alert('Error: ' + e.message);
  }
}
loadHistory();
</script>
</body></html>
"""


# ---------- Routes ----------

@credit_bp.route("/credit")
@login_required
def credit_page():
    return render_template_string(CREDIT_HTML)


@credit_bp.route("/credit/history")
@login_required
def credit_history_page():
    staff = (session.get("staff_name") or "").strip().lower()
    is_isesmo = staff in ["isesmo", "isesmo gamboa"]
    return render_template_string(CREDIT_HISTORY_HTML, is_isesmo=is_isesmo)


@credit_bp.route("/api/credit/outstanding")
@login_required
def api_credit_outstanding():
    try:
        resellers = fb_get("resellers") or {}
        rows = []
        total = 0.0
        for key, val in resellers.items():
            if not val:
                continue
            bal = float(val.get("credit_balance") or 0)
            if bal > 0:
                rows.append({"id": key, "store_name": val.get("store_name") or "(unnamed)", "credit_balance": bal})
                total += bal
        rows.sort(key=lambda r: r["credit_balance"], reverse=True)
        return jsonify({"ok": True, "rows": rows, "total": total})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@credit_bp.route("/api/credit/collect", methods=["POST"])
@login_required
def api_credit_collect():
    try:
        data = request.json or {}
        reseller_id = data.get("reseller_id")
        try:
            amount = float(data.get("amount"))
        except (TypeError, ValueError):
            amount = 0
        note = (data.get("note") or "").strip()
        if not reseller_id:
            return jsonify({"ok": False, "error": "Missing reseller_id"}), 400
        if amount <= 0:
            return jsonify({"ok": False, "error": "Invalid amount"}), 400
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        if not reseller:
            return jsonify({"ok": False, "error": "Customer not found"}), 404
        current_balance = float(reseller.get("credit_balance") or 0)
        # Allowed to go to 0 or below (an overpayment becomes an advance
        # credit for next time) rather than hard-capping at the current
        # balance - simplest behavior, matches how small stores actually
        # handle "sobra ang bayad" in practice.
        new_balance = round(current_balance - amount, 2)
        fb_patch(f"resellers/{reseller_id}", {"credit_balance": new_balance})
        payment = {
            "reseller_id": reseller_id,
            "store_name": reseller.get("store_name") or "(unnamed)",
            "amount": amount,
            "note": note,
            "balance_before": current_balance,
            "balance_after": new_balance,
            "collected_by": session.get("staff_name"),
            "collected_at": today_str(),
            "timestamp": now_str(),
        }
        fb_post("credit_payments", payment)
        return jsonify({"ok": True, "new_balance": new_balance})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@credit_bp.route("/api/credit/history")
@login_required
def api_credit_history():
    try:
        mode = (request.args.get("mode") or "ALL").upper()
        date_filter = request.args.get("date") or ""
        payments = fb_get("credit_payments") or {}
        rows = []
        for key, val in payments.items():
            if not val:
                continue
            row = dict(val)
            row["id"] = key
            rows.append(row)
        if mode == "TODAY":
            today = today_str()
            rows = [r for r in rows if (r.get("collected_at") or "").startswith(today)]
        elif mode == "DATE" and date_filter:
            rows = [r for r in rows if (r.get("collected_at") or "").startswith(date_filter)]
        # Newest first
        rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
        return jsonify({"ok": True, "rows": rows})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@credit_bp.route("/api/credit/payment/<payment_id>", methods=["DELETE"])
@isesmo_only
def api_credit_delete_payment(payment_id):
    """Undo a payment (e.g. a test entry made while trying out the
    feature, or a mistake) - restricted to Isesmo since this reverses
    money already recorded as collected, which the rest of the staff
    shouldn't be able to quietly undo."""
    try:
        payment = fb_get(f"credit_payments/{payment_id}")
        if not payment:
            return jsonify({"ok": False, "error": "Payment not found"}), 404
        reseller_id = payment.get("reseller_id")
        amount = float(payment.get("amount") or 0)
        if reseller_id:
            reseller = fb_get(f"resellers/{reseller_id}") or {}
            current_balance = float(reseller.get("credit_balance") or 0)
            # Give the amount back to the outstanding balance - deleting a
            # payment means it never happened, so the utang is restored.
            fb_patch(f"resellers/{reseller_id}", {"credit_balance": round(current_balance + amount, 2)})
        fb_delete(f"credit_payments/{payment_id}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
