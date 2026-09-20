"""
Fixed Assets module.

Ported from ensure_fixed_assets_tables / sell_fixed_asset / unsell_fixed_asset
in the user's separate Kivy desktop app (OMEGA_PURIFIED.py) - capital
equipment (machines, freezers, delivery vehicles, etc.) tracked as
assets you bought and may later sell, separate from day-to-day expenses.

Firebase data model (all new):
  fixed_assets/<id> = {
    name, category, purchase_date, purchase_price,
    sold (bool), sale_date, sale_price, buyer, notes,
    recorded_by, created_at
  }

Routes:
  GET    /assets                 - Fixed Assets page: add form + active/sold lists + totals
  GET    /api/assets             - JSON: all assets
  POST   /api/assets             - JSON: add a new asset
  POST   /api/assets/<id>/sell   - JSON: mark sold {sale_date, sale_price, buyer}
  POST   /api/assets/<id>/unsell - JSON: revert a sale (e.g. recorded by mistake)
  DELETE /api/assets/<id>        - ISESMO only: remove an asset entirely
"""
from datetime import datetime

from flask import Blueprint, request, jsonify, session, render_template_string

from modules.shared import fb_get, fb_post, fb_patch, fb_delete, login_required, isesmo_only, now_str, today_str

assets_bp = Blueprint("assets", __name__)

ASSET_CATEGORIES = ["Machine", "Freezer", "Vehicle", "Equipment", "Other"]


ASSETS_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Fixed Assets - Omega Ice</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0;font-weight:700}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C}
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.stat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-bottom:12px}
.stat-card{border-radius:12px;padding:14px;text-align:center;color:#fff}
.stat-card.invested{background:linear-gradient(135deg,#00609C,#0096D6)}
.stat-card.recovered{background:linear-gradient(135deg,#22c55e,#16a34a)}
.stat-card .amt{font-size:19px;font-weight:700}.stat-card .lbl{font-size:10px;opacity:.9}
label{font-size:12px;color:#666;display:block;margin:10px 0 4px}
input,select,textarea{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:14px;font-family:inherit}
.save-btn{width:100%;padding:13px;margin-top:14px;background:#00609C;color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:600}
.status{font-size:12px;text-align:center;margin-top:8px;min-height:16px}.status.err{color:#c0392b}.status.ok{color:#1a8a4a}
.tabs{display:flex;gap:6px;margin-bottom:10px}
.tabs button{flex:1;padding:9px;border-radius:8px;border:1px solid #cde;background:#fff;color:#00609C;font-size:12px;font-weight:600}
.tabs button.active{background:#00609C;color:#fff}
.asset-row{padding:10px 0;border-bottom:1px solid #f0f4f8}
.asset-row .name{font-weight:600;font-size:14px}
.asset-row .meta{font-size:11px;color:#888;margin-top:2px}
.asset-row .btns{display:flex;gap:6px;margin-top:8px}
.asset-row .btns button{padding:6px 12px;border-radius:8px;border:none;font-size:11px;font-weight:600}
.btn-sell{background:#f59e0b;color:#fff}.btn-unsell{background:#94a3b8;color:#fff}.btn-del{background:#fee2e2;color:#c0392b}
.sold-tag{display:inline-block;padding:2px 8px;border-radius:10px;background:#dcfce7;color:#166534;font-size:9px;font-weight:700;margin-left:6px}
.empty{color:#888;text-align:center;padding:20px 10px;font-size:13px}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:100;align-items:center;justify-content:center;padding:16px}
.overlay.show{display:flex}
.modal{background:#fff;border-radius:14px;padding:20px;width:100%;max-width:360px}
.modal h3{margin:0 0 12px;font-size:16px;color:#00609C}
.modal .btn-row{display:flex;gap:8px;margin-top:16px}
.modal .btn-row button{flex:1;padding:11px;border-radius:9px;border:none;font-size:13px;font-weight:700}
.modal .btn-cancel{background:#eee;color:#555}.modal .btn-confirm{background:#f59e0b;color:#fff}
</style></head>
<body>
<div class="topbar">
  <h1>🏭 Fixed Assets</h1>
  <div style="display:flex;gap:6px;flex-wrap:wrap">
    <a href="/cashier" class="nav-pill">Sales</a>
    <a href="/credit" class="nav-pill">💳 Utang</a>
    <a href="/expenses" class="nav-pill">Expenses</a>
    <a href="/plastic" class="nav-pill">Plastic</a>
    <a href="/assets" class="nav-pill active">Assets</a>
  </div>
</div>

<div class="stat-grid">
  <div class="stat-card invested"><div class="amt" id="totalInvested">₱0</div><div class="lbl">TOTAL INVESTED</div></div>
  <div class="stat-card recovered"><div class="amt" id="totalRecovered">₱0</div><div class="lbl">RECOVERED FROM SALES</div></div>
</div>

<div class="card">
  <h3 style="margin:0 0 10px;font-size:13px;color:#00609C">Add Asset</h3>
  <label>Name</label>
  <input type="text" id="assetName" placeholder="hal. Ice Machine #2, Delivery Motor...">
  <label>Category</label>
  <select id="assetCategory"></select>
  <label>Purchase Date</label>
  <input type="date" id="assetDate">
  <label>Purchase Price (₱)</label>
  <input type="number" id="assetPrice" placeholder="0.00" step="0.01" min="0.01">
  <label>Notes (optional)</label>
  <textarea id="assetNotes" rows="2"></textarea>
  <button class="save-btn" onclick="submitAsset()">💾 Save Asset</button>
  <p class="status" id="assetStatus"></p>
</div>

<div class="tabs">
  <button class="active" data-t="active" onclick="setTab('active')">Active</button>
  <button data-t="sold" onclick="setTab('sold')">Sold</button>
</div>
<div class="card" id="listWrap">Loading...</div>

<div class="overlay" id="sellOverlay">
  <div class="modal">
    <h3>Mark as Sold</h3>
    <label>Sale Date</label>
    <input type="date" id="sellDate">
    <label>Sale Price (₱)</label>
    <input type="number" id="sellPrice" placeholder="0.00" step="0.01" min="0">
    <label>Buyer (optional)</label>
    <input type="text" id="sellBuyer">
    <p class="status" id="sellStatus"></p>
    <div class="btn-row">
      <button class="btn-cancel" onclick="closeSellModal()">Cancel</button>
      <button class="btn-confirm" onclick="submitSell()">✅ Confirm Sale</button>
    </div>
  </div>
</div>

<script>
const CATEGORIES = {{ categories|tojson }};
const IS_ISESMO = {{ 'true' if is_isesmo else 'false' }};
let allAssets = [];
let currentTab = 'active';
let sellingAssetId = null;

function escapeHtmlA2(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }

document.getElementById('assetCategory').innerHTML = CATEGORIES.map(c => `<option value="${escapeHtmlA2(c)}">${escapeHtmlA2(c)}</option>`).join('');
document.getElementById('assetDate').value = new Date().toISOString().slice(0,10);

async function submitAsset(){
  const name = document.getElementById('assetName').value.trim();
  const category = document.getElementById('assetCategory').value;
  const purchase_date = document.getElementById('assetDate').value;
  const purchase_price = parseFloat(document.getElementById('assetPrice').value);
  const notes = document.getElementById('assetNotes').value.trim();
  const st = document.getElementById('assetStatus');
  if(!name){ st.textContent = 'Ilagay ang pangalan.'; st.className = 'status err'; return; }
  if(!purchase_date){ st.textContent = 'Pumili ng date.'; st.className = 'status err'; return; }
  if(!purchase_price || purchase_price <= 0){ st.textContent = 'Ilagay ang valid na price.'; st.className = 'status err'; return; }
  st.textContent = 'Saving...'; st.className = 'status';
  try{
    const res = await fetch('/api/assets', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({name, category, purchase_date, purchase_price, notes})
    });
    const data = await res.json();
    if(data.ok){
      st.textContent = 'Na-save!'; st.className = 'status ok';
      document.getElementById('assetName').value = '';
      document.getElementById('assetPrice').value = '';
      document.getElementById('assetNotes').value = '';
      loadAssets();
    } else {
      st.textContent = data.error || 'May error.'; st.className = 'status err';
    }
  }catch(e){
    st.textContent = 'Error: ' + e.message; st.className = 'status err';
  }
}

function setTab(t){
  currentTab = t;
  document.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('active', b.dataset.t===t));
  renderList();
}

async function loadAssets(){
  const wrap = document.getElementById('listWrap');
  try{
    const res = await fetch('/api/assets');
    if(res.status===401){ window.location.href='/login'; return; }
    const data = await res.json();
    if(!data.ok){ wrap.innerHTML = `<div class="empty">${escapeHtmlA2(data.error||'Error')}</div>`; return; }
    allAssets = data.rows || [];
    let invested = 0, recovered = 0;
    allAssets.forEach(a => {
      invested += Number(a.purchase_price) || 0;
      if(a.sold) recovered += Number(a.sale_price) || 0;
    });
    document.getElementById('totalInvested').textContent = peso(invested);
    document.getElementById('totalRecovered').textContent = peso(recovered);
    renderList();
  }catch(e){
    wrap.innerHTML = `<div class="empty">Error: ${escapeHtmlA2(e.message)}</div>`;
  }
}

function renderList(){
  const wrap = document.getElementById('listWrap');
  const rows = allAssets.filter(a => currentTab === 'sold' ? a.sold : !a.sold);
  if(!rows.length){
    wrap.innerHTML = `<div class="empty">Walang ${currentTab==='sold'?'nabentang':'active na'} asset.</div>`;
    return;
  }
  wrap.innerHTML = rows.map(a => `
    <div class="asset-row">
      <div class="name">${escapeHtmlA2(a.name)}${a.sold ? '<span class="sold-tag">SOLD</span>' : ''}</div>
      <div class="meta">${escapeHtmlA2(a.category)} • Bought ${escapeHtmlA2(a.purchase_date)} for ${peso(a.purchase_price)}</div>
      ${a.sold ? `<div class="meta">Sold ${escapeHtmlA2(a.sale_date)} for ${peso(a.sale_price)}${a.buyer ? ' to '+escapeHtmlA2(a.buyer) : ''}</div>` : ''}
      ${a.notes ? `<div class="meta">${escapeHtmlA2(a.notes)}</div>` : ''}
      <div class="btns">
        ${!a.sold ? `<button class="btn-sell" onclick="openSellModal('${a.id}')">💰 Mark Sold</button>` : `<button class="btn-unsell" onclick="unsellAsset('${a.id}')">↩️ Undo Sale</button>`}
        ${IS_ISESMO ? `<button class="btn-del" onclick="deleteAsset('${a.id}')">🗑️ Delete</button>` : ''}
      </div>
    </div>
  `).join('');
}

function openSellModal(id){
  sellingAssetId = id;
  document.getElementById('sellDate').value = new Date().toISOString().slice(0,10);
  document.getElementById('sellPrice').value = '';
  document.getElementById('sellBuyer').value = '';
  document.getElementById('sellStatus').textContent = '';
  document.getElementById('sellOverlay').classList.add('show');
}
function closeSellModal(){
  document.getElementById('sellOverlay').classList.remove('show');
  sellingAssetId = null;
}
async function submitSell(){
  if(!sellingAssetId) return;
  const sale_date = document.getElementById('sellDate').value;
  const sale_price = parseFloat(document.getElementById('sellPrice').value);
  const buyer = document.getElementById('sellBuyer').value.trim();
  const st = document.getElementById('sellStatus');
  if(!sale_date){ st.textContent = 'Pumili ng date.'; st.className = 'status err'; return; }
  if(!sale_price || sale_price < 0){ st.textContent = 'Ilagay ang valid na price.'; st.className = 'status err'; return; }
  st.textContent = 'Saving...'; st.className = 'status';
  try{
    const res = await fetch(`/api/assets/${sellingAssetId}/sell`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({sale_date, sale_price, buyer})
    });
    const data = await res.json();
    if(data.ok){
      st.textContent = 'Na-record!'; st.className = 'status ok';
      setTimeout(() => { closeSellModal(); loadAssets(); }, 500);
    } else {
      st.textContent = data.error || 'May error.'; st.className = 'status err';
    }
  }catch(e){
    st.textContent = 'Error: ' + e.message; st.className = 'status err';
  }
}

async function unsellAsset(id){
  if(!confirm('I-undo ang sale record na ito? Babalik itong Active.')) return;
  try{
    const res = await fetch(`/api/assets/${id}/unsell`, {method:'POST'});
    const data = await res.json();
    if(data.ok) loadAssets();
    else alert(data.error || 'Hindi na-undo.');
  }catch(e){
    alert('Error: ' + e.message);
  }
}

async function deleteAsset(id){
  if(!confirm('Permanenteng tanggalin ang asset na ito?')) return;
  try{
    const res = await fetch(`/api/assets/${id}`, {method:'DELETE'});
    const data = await res.json();
    if(data.ok) loadAssets();
    else alert(data.error || 'Hindi na-delete.');
  }catch(e){
    alert('Error: ' + e.message);
  }
}

loadAssets();
</script>
</body></html>
"""


@assets_bp.route("/assets")
@login_required
def assets_page():
    staff = (session.get("staff_name") or "").strip().lower()
    is_isesmo = staff in ["isesmo", "isesmo gamboa"]
    return render_template_string(ASSETS_HTML, categories=ASSET_CATEGORIES, is_isesmo=is_isesmo)


@assets_bp.route("/api/assets")
@login_required
def api_assets_list():
    try:
        assets = fb_get("fixed_assets") or {}
        rows = []
        for key, val in assets.items():
            if not val:
                continue
            row = dict(val)
            row["id"] = key
            rows.append(row)
        rows.sort(key=lambda r: r.get("purchase_date") or "", reverse=True)
        return jsonify({"ok": True, "rows": rows})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@assets_bp.route("/api/assets", methods=["POST"])
@login_required
def api_assets_add():
    try:
        data = request.json or {}
        name = (data.get("name") or "").strip()
        category = (data.get("category") or "Other").strip()
        purchase_date = (data.get("purchase_date") or "").strip() or today_str()
        try:
            purchase_price = float(data.get("purchase_price"))
        except (TypeError, ValueError):
            purchase_price = 0
        notes = (data.get("notes") or "").strip()
        if not name:
            return jsonify({"ok": False, "error": "Name is required"}), 400
        if purchase_price <= 0:
            return jsonify({"ok": False, "error": "Invalid purchase price"}), 400
        entry = {
            "name": name,
            "category": category,
            "purchase_date": purchase_date,
            "purchase_price": purchase_price,
            "sold": False,
            "sale_date": None,
            "sale_price": None,
            "buyer": None,
            "notes": notes,
            "recorded_by": session.get("staff_name"),
            "created_at": now_str(),
        }
        fb_post("fixed_assets", entry)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@assets_bp.route("/api/assets/<asset_id>/sell", methods=["POST"])
@login_required
def api_assets_sell(asset_id):
    try:
        asset = fb_get(f"fixed_assets/{asset_id}")
        if not asset:
            return jsonify({"ok": False, "error": "Asset not found"}), 404
        data = request.json or {}
        sale_date = (data.get("sale_date") or "").strip() or today_str()
        try:
            sale_price = float(data.get("sale_price"))
        except (TypeError, ValueError):
            sale_price = 0
        buyer = (data.get("buyer") or "").strip()
        if sale_price < 0:
            return jsonify({"ok": False, "error": "Invalid sale price"}), 400
        fb_patch(f"fixed_assets/{asset_id}", {
            "sold": True,
            "sale_date": sale_date,
            "sale_price": sale_price,
            "buyer": buyer,
            "sold_by": session.get("staff_name"),
            "sold_at": now_str(),
        })
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@assets_bp.route("/api/assets/<asset_id>/unsell", methods=["POST"])
@login_required
def api_assets_unsell(asset_id):
    """Undo a sale record - e.g. it was logged by mistake. Reverts the
    asset back to Active without deleting its purchase history."""
    try:
        asset = fb_get(f"fixed_assets/{asset_id}")
        if not asset:
            return jsonify({"ok": False, "error": "Asset not found"}), 404
        fb_patch(f"fixed_assets/{asset_id}", {
            "sold": False,
            "sale_date": None,
            "sale_price": None,
            "buyer": None,
        })
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@assets_bp.route("/api/assets/<asset_id>", methods=["DELETE"])
@isesmo_only
def api_assets_delete(asset_id):
    try:
        fb_delete(f"fixed_assets/{asset_id}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
