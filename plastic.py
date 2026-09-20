"""
Plastic / Packaging Inventory module.

Ported from the plastic_* functions in the user's separate Kivy desktop
app (OMEGA_PURIFIED.py): update_plastic_purchase, deduct_plastic_usage,
log_plastic_loss, get_plastic_summary, etc. That version tracked stock
per plastic type across 3 separate local SQLite tables. Rebuilt here on
Firebase with the same 3-way split (purchase / usage / loss), since that
split is what makes "how much did we lose to breakage/damage this month"
answerable on its own instead of buried inside general usage.

Design choice: this does NOT auto-deduct plastic when a sale/order is
recorded elsewhere in app.py - that would require assuming a fixed
"1 order = 1 bag of a specific type" rule that isn't actually true here
(mode, kg size, and packaging don't map 1:1 in a way this module can see
safely). Usage stays a deliberate manual entry, same as the Kivy
version's own `deduct_plastic_usage` was a separate call, not something
wired automatically into the sale flow either.

Firebase data model (all new):
  plastic_purchases/<id> = {date, plastic_type, qty, unit_price, total, recorded_by, created_at}
  plastic_usage/<id>     = {date, plastic_type, qty, note, recorded_by, created_at}
  plastic_losses/<id>    = {date, plastic_type, qty, reason, recorded_by, created_at}

Current stock per type = sum(purchases) - sum(usage) - sum(losses)

Routes:
  GET    /plastic                      - Plastic Inventory page (stock per type + Buy/Use/Loss actions + log)
  GET    /api/plastic/summary          - JSON: stock summary per type
  GET    /api/plastic/log              - JSON: combined recent log (purchases+usage+losses)
  POST   /api/plastic/purchase         - JSON: log a purchase (adds to stock)
  POST   /api/plastic/usage            - JSON: log usage (subtracts from stock)
  POST   /api/plastic/loss             - JSON: log a loss/damage (subtracts from stock)
  DELETE /api/plastic/<kind>/<id>      - ISESMO only: undo an entry (kind: purchase|usage|loss)
"""
from datetime import datetime

from flask import Blueprint, request, jsonify, session, render_template_string

from modules.shared import fb_get, fb_post, fb_delete, login_required, isesmo_only, now_str, today_str

plastic_bp = Blueprint("plastic", __name__)

PLASTIC_TYPES = ["1Kg bag", "5Kg bag", "10Kg bag", "25Kg bag", "Other"]

_KIND_TO_NODE = {
    "purchase": "plastic_purchases",
    "usage": "plastic_usage",
    "loss": "plastic_losses",
}


PLASTIC_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Plastic Inventory - Omega Ice</title>
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
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.stock-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-bottom:12px}
.stock-tile{background:#fff;border-radius:12px;padding:12px 8px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.stock-tile .qty{font-size:20px;font-weight:700;color:#00609C}
.stock-tile .qty.low{color:#c0392b}
.stock-tile .lbl{font-size:10px;color:#888;margin-top:2px}
.action-row{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px}
.action-row button{padding:12px 6px;border-radius:10px;border:none;color:#fff;font-size:12px;font-weight:700}
.btn-buy{background:#22c55e}.btn-use{background:#f59e0b}.btn-loss{background:#ef4444}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:100;align-items:center;justify-content:center;padding:16px}
.overlay.show{display:flex}
.modal{background:#fff;border-radius:14px;padding:20px;width:100%;max-width:360px}
.modal h3{margin:0 0 12px;font-size:16px;color:#00609C}
.modal label{font-size:12px;color:#666;display:block;margin:10px 0 4px}
.modal input,.modal select,.modal textarea{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:14px;font-family:inherit}
.modal .btn-row{display:flex;gap:8px;margin-top:16px}
.modal .btn-row button{flex:1;padding:11px;border-radius:9px;border:none;font-size:13px;font-weight:700}
.modal .btn-cancel{background:#eee;color:#555}.modal .btn-confirm{background:#00609C;color:#fff}
.status{font-size:12px;text-align:center;margin-top:8px;min-height:16px}.status.err{color:#c0392b}.status.ok{color:#1a8a4a}
.log-row{display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid #f0f4f8}
.log-meta{font-size:9px;color:#aaa;margin-top:2px}
.log-badge{padding:3px 9px;border-radius:12px;font-size:9px;font-weight:700;white-space:nowrap;height:fit-content}
.log-badge.purchase{background:#dcfce7;color:#166534}.log-badge.usage{background:#fef3c7;color:#92400e}.log-badge.loss{background:#fee2e2;color:#991b1b}
.del-btn{background:none;border:none;color:#c0392b;font-size:16px;padding:2px 4px}
.empty{color:#888;text-align:center;padding:20px 10px;font-size:13px}
</style></head>
<body>
<div class="topbar">
  <h1>📦 Plastic Inventory</h1>
  <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
    <a href="/cashier" class="nav-pill">Sales</a>
    <div class="menu-wrap">
      <button type="button" class="menu-btn" id="navMenuBtn" onclick="toggleNavMenu()" title="Menu">☰</button>
      <div class="menu-dropdown" id="navMenuDropdown">
        <a href="/machines">🏭 Machines</a>
        <a href="/credit">💳 Utang</a>
        <a href="/credit/history">🧾 Utang History</a>
        <a href="/expenses">💸 Expenses</a>
        <a href="/plastic" class="active">📦 Plastic</a>
        <a href="/assets">🏗️ Fixed Assets</a>
        <a href="/dashboard">📊 Dashboard</a>
      </div>
    </div>
  </div>
</div>

<div class="stock-grid" id="stockGrid">Loading...</div>

<div class="action-row">
  <button class="btn-buy" onclick="openModal('purchase')">➕ Buy</button>
  <button class="btn-use" onclick="openModal('usage')">📤 Use</button>
  <button class="btn-loss" onclick="openModal('loss')">⚠️ Loss</button>
</div>

<div class="card">
  <h3 style="margin:0 0 10px;font-size:13px;color:#00609C">Recent Log</h3>
  <div id="logWrap">Loading...</div>
</div>

<div class="overlay" id="modalOverlay">
  <div class="modal">
    <h3 id="modalTitle">Add</h3>
    <label>Plastic Type</label>
    <select id="modalType"></select>
    <label>Date</label>
    <input type="date" id="modalDate">
    <label>Quantity</label>
    <input type="number" id="modalQty" placeholder="0" step="1" min="1">
    <div id="unitPriceWrap" style="display:none">
      <label>Unit Price (₱, optional)</label>
      <input type="number" id="modalUnitPrice" placeholder="0.00" step="0.01" min="0">
    </div>
    <label id="noteLabel">Note (optional)</label>
    <textarea id="modalNote" rows="2"></textarea>
    <p class="status" id="modalStatus"></p>
    <div class="btn-row">
      <button class="btn-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-confirm" onclick="submitModal()">✅ Save</button>
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

const PLASTIC_TYPES = {{ plastic_types|tojson }};
const IS_ISESMO = {{ 'true' if is_isesmo else 'false' }};
let currentKind = 'purchase';

function escapeHtmlP(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }

async function loadSummary(){
  const wrap = document.getElementById('stockGrid');
  try{
    const res = await fetch('/api/plastic/summary');
    if(res.status===401){ window.location.href='/login'; return; }
    const data = await res.json();
    if(!data.ok){ wrap.innerHTML = `<div class="empty">${escapeHtmlP(data.error||'Error')}</div>`; return; }
    wrap.innerHTML = PLASTIC_TYPES.map(t => {
      const s = (data.summary && data.summary[t]) || {stock:0};
      const low = s.stock <= 10;
      return `<div class="stock-tile"><div class="qty ${low?'low':''}">${s.stock}</div><div class="lbl">${escapeHtmlP(t)}</div></div>`;
    }).join('');
  }catch(e){
    wrap.innerHTML = `<div class="empty">Error: ${escapeHtmlP(e.message)}</div>`;
  }
}

async function loadLog(){
  const wrap = document.getElementById('logWrap');
  try{
    const res = await fetch('/api/plastic/log');
    const data = await res.json();
    if(!data.ok){ wrap.innerHTML = `<div class="empty">${escapeHtmlP(data.error||'Error')}</div>`; return; }
    const rows = data.rows || [];
    if(!rows.length){ wrap.innerHTML = '<div class="empty">Wala pang log.</div>'; return; }
    const badgeLbl = {purchase:'BUY', usage:'USE', loss:'LOSS'};
    wrap.innerHTML = rows.map(r => `
      <div class="log-row">
        <div>
          <div style="font-weight:600">${escapeHtmlP(r.plastic_type)} - ${r.qty} pcs</div>
          ${r.note || r.reason ? `<div class="log-meta">${escapeHtmlP(r.note || r.reason)}</div>` : ''}
          <div class="log-meta">${escapeHtmlP(r.date)} • ni ${escapeHtmlP(r.recorded_by||'-')}</div>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <span class="log-badge ${r.kind}">${badgeLbl[r.kind]}</span>
          ${IS_ISESMO ? `<button class="del-btn" onclick="deleteEntry('${r.kind}','${r.id}')">🗑️</button>` : ''}
        </div>
      </div>
    `).join('');
  }catch(e){
    wrap.innerHTML = `<div class="empty">Error: ${escapeHtmlP(e.message)}</div>`;
  }
}

function openModal(kind){
  currentKind = kind;
  const titles = {purchase:'➕ Log Purchase', usage:'📤 Log Usage', loss:'⚠️ Log Loss/Damage'};
  document.getElementById('modalTitle').textContent = titles[kind];
  document.getElementById('modalType').innerHTML = PLASTIC_TYPES.map(t => `<option value="${escapeHtmlP(t)}">${escapeHtmlP(t)}</option>`).join('');
  document.getElementById('modalDate').value = new Date().toISOString().slice(0,10);
  document.getElementById('modalQty').value = '';
  document.getElementById('modalUnitPrice').value = '';
  document.getElementById('modalNote').value = '';
  document.getElementById('modalStatus').textContent = '';
  document.getElementById('unitPriceWrap').style.display = (kind==='purchase') ? 'block' : 'none';
  document.getElementById('noteLabel').textContent = (kind==='loss') ? 'Reason' : 'Note (optional)';
  document.getElementById('modalOverlay').classList.add('show');
}
function closeModal(){
  document.getElementById('modalOverlay').classList.remove('show');
}

async function submitModal(){
  const plastic_type = document.getElementById('modalType').value;
  const date = document.getElementById('modalDate').value;
  const qty = parseInt(document.getElementById('modalQty').value, 10);
  const unit_price = parseFloat(document.getElementById('modalUnitPrice').value) || 0;
  const noteVal = document.getElementById('modalNote').value.trim();
  const st = document.getElementById('modalStatus');
  if(!date){ st.textContent = 'Pumili ng date.'; st.className = 'status err'; return; }
  if(!qty || qty <= 0){ st.textContent = 'Ilagay ang valid na quantity.'; st.className = 'status err'; return; }
  if(currentKind === 'loss' && !noteVal){ st.textContent = 'Ilagay ang reason.'; st.className = 'status err'; return; }
  st.textContent = 'Saving...'; st.className = 'status';
  const body = {plastic_type, date, qty};
  if(currentKind === 'purchase') body.unit_price = unit_price;
  if(currentKind === 'loss') body.reason = noteVal; else body.note = noteVal;
  try{
    const res = await fetch(`/api/plastic/${currentKind}`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if(data.ok){
      st.textContent = 'Na-save!'; st.className = 'status ok';
      setTimeout(() => { closeModal(); loadSummary(); loadLog(); }, 500);
    } else {
      st.textContent = data.error || 'May error.'; st.className = 'status err';
    }
  }catch(e){
    st.textContent = 'Error: ' + e.message; st.className = 'status err';
  }
}

async function deleteEntry(kind, id){
  if(!confirm('Tanggalin ang entry na ito?')) return;
  try{
    const res = await fetch(`/api/plastic/${kind}/${id}`, {method:'DELETE'});
    const data = await res.json();
    if(data.ok){ loadSummary(); loadLog(); }
    else alert(data.error || 'Hindi na-delete.');
  }catch(e){
    alert('Error: ' + e.message);
  }
}

loadSummary();
loadLog();
</script>
</body></html>
"""


def _compute_summary():
    """Stock per plastic type = purchases - usage - losses."""
    summary = {t: {"purchased": 0, "used": 0, "lost": 0, "stock": 0} for t in PLASTIC_TYPES}

    def _accumulate(node, field):
        data = fb_get(node) or {}
        for val in data.values():
            if not val:
                continue
            t = val.get("plastic_type") or "Other"
            if t not in summary:
                summary[t] = {"purchased": 0, "used": 0, "lost": 0, "stock": 0}
            summary[t][field] += float(val.get("qty") or 0)

    _accumulate("plastic_purchases", "purchased")
    _accumulate("plastic_usage", "used")
    _accumulate("plastic_losses", "lost")
    for t, s in summary.items():
        s["stock"] = round(s["purchased"] - s["used"] - s["lost"], 2)
    return summary


@plastic_bp.route("/plastic")
@login_required
def plastic_page():
    staff = (session.get("staff_name") or "").strip().lower()
    is_isesmo = staff in ["isesmo", "isesmo gamboa"]
    return render_template_string(PLASTIC_HTML, plastic_types=PLASTIC_TYPES, is_isesmo=is_isesmo)


@plastic_bp.route("/api/plastic/summary")
@login_required
def api_plastic_summary():
    try:
        return jsonify({"ok": True, "summary": _compute_summary()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@plastic_bp.route("/api/plastic/log")
@login_required
def api_plastic_log():
    try:
        rows = []
        for kind, node in _KIND_TO_NODE.items():
            data = fb_get(node) or {}
            for key, val in data.items():
                if not val:
                    continue
                row = dict(val)
                row["id"] = key
                row["kind"] = kind
                rows.append(row)
        rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
        return jsonify({"ok": True, "rows": rows[:200]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def _add_entry(node, extra_fields=None):
    data = request.json or {}
    plastic_type = (data.get("plastic_type") or "Other").strip()
    date = (data.get("date") or "").strip() or today_str()
    try:
        qty = float(data.get("qty"))
    except (TypeError, ValueError):
        qty = 0
    if qty <= 0:
        return None, (jsonify({"ok": False, "error": "Invalid quantity"}), 400)
    entry = {
        "plastic_type": plastic_type,
        "date": date,
        "qty": qty,
        "recorded_by": session.get("staff_name"),
        "created_at": now_str(),
    }
    if extra_fields:
        entry.update(extra_fields(data))
    fb_post(node, entry)
    return entry, None


@plastic_bp.route("/api/plastic/purchase", methods=["POST"])
@login_required
def api_plastic_purchase():
    try:
        def extra(data):
            try:
                unit_price = float(data.get("unit_price") or 0)
            except (TypeError, ValueError):
                unit_price = 0
            qty = float(data.get("qty") or 0)
            return {"unit_price": unit_price, "total": round(unit_price * qty, 2), "note": (data.get("note") or "").strip()}
        entry, err = _add_entry("plastic_purchases", extra)
        if err:
            return err
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@plastic_bp.route("/api/plastic/usage", methods=["POST"])
@login_required
def api_plastic_usage():
    try:
        def extra(data):
            return {"note": (data.get("note") or "").strip()}
        entry, err = _add_entry("plastic_usage", extra)
        if err:
            return err
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@plastic_bp.route("/api/plastic/loss", methods=["POST"])
@login_required
def api_plastic_loss():
    try:
        data = request.json or {}
        reason = (data.get("reason") or "").strip()
        if not reason:
            return jsonify({"ok": False, "error": "Reason is required for a loss entry"}), 400

        def extra(_data):
            return {"reason": reason}
        entry, err = _add_entry("plastic_losses", extra)
        if err:
            return err
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@plastic_bp.route("/api/plastic/<kind>/<entry_id>", methods=["DELETE"])
@isesmo_only
def api_plastic_delete(kind, entry_id):
    try:
        node = _KIND_TO_NODE.get(kind)
        if not node:
            return jsonify({"ok": False, "error": "Invalid kind"}), 400
        fb_delete(f"{node}/{entry_id}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
