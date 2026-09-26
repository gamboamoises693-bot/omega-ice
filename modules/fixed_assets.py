"""
Fixed Assets module.

REWRITTEN (v2) - the first version invented a "category" field and a
plain sold/not-sold flag that don't actually exist in the original app.
This version replicates the REAL logic from the Kivy source
(ensure_fixed_assets_tables / sell_fixed_asset / unsell_fixed_asset /
ExpensesScreen.show_fix_inventory, all in OMEGA_PURIFIED.py) and the
real columns in omega_ice.db's `fixed_assets` table:

    id, asset_name, purchase_date, price, depreciation,
    monthly_depreciation, total_months, status, sale_date,
    sale_price, buyer, created_at

Ground truth from the 4 real rows in the user's DB: there is NO
category column at all - assets are just named freely ("Ice
Machine(Princeton)", "Freezer Fujidenzo", ...), and `total_months`
varies per asset (60 for the ice machines, 36 for the freezers) - the
user types it in per-asset, it's not a fixed constant. So this version
drops the invented category field and adds what actually matters in
the original: a MONTHLY STRAIGHT-LINE DEPRECIATION SCHEDULE with a
live "book value" (Original - accumulated depreciation), computed the
exact same way ExpensesScreen.show_fix_inventory() does it:

    months_elapsed = (ref_year - purchase_year)*12 + (ref_month - purchase_month) + 1
    (clamped to [0, total_months]; ref date = today, or sale_date once sold)
    accumulated = monthly_depreciation * months_elapsed
    book_value  = max(0, price - accumulated)

Selling is NOT tied to book value - same as the original ("Pwede
ibenta hindi base sa Book - lagay mo sale price"): staff can type any
sale price, and the app just shows the resulting gain/loss
(sale_price - book_value at the sale date) for their own reference.

INTENTIONALLY NOT replicated: the original also auto-inserts 60 rows
into a `fixed_asset_depreciation` table AND mirrors them into
`expenses` (category "Fix Asset") every time an asset is added or
un-sold - that's why the real omega_ice.db has 192 "Fix Asset" rows in
`expenses` for just 4 assets. We compute book value live from the
purchase date + monthly rate instead of storing a 60-row schedule, so
the Expenses module (modules/expenses.py) stays free of that spam
while this module still shows the exact same numbers the schedule
would have produced.

Firebase data model:
  fixed_assets/<id> = {
    name, purchase_date, price, total_months, monthly_depreciation,
    status ("active" | "sold"), sale_date, sale_price, buyer,
    book_value_at_sale, gain_loss_at_sale,
    recorded_by, created_at, sold_by, sold_at
  }

Routes:
  GET    /assets                 - Fixed Assets page: add form + active/sold lists + book values
  GET    /api/assets             - JSON: all assets, each with live-computed book_value/months_elapsed/remaining_months
  POST   /api/assets             - JSON: add a new asset {name, purchase_date, price, total_months}
  POST   /api/assets/<id>/sell   - JSON: mark sold {sale_date, sale_price, buyer} - any price allowed, gain/loss just informational
  POST   /api/assets/<id>/unsell - JSON: revert a sale (e.g. recorded by mistake)
  DELETE /api/assets/<id>        - ISESMO only: remove an asset entirely
"""
from calendar import monthrange
from datetime import datetime

from flask import Blueprint, request, jsonify, session, render_template_string

from modules.shared import fb_get, fb_post, fb_patch, fb_delete, login_required, isesmo_only, now_str, today_str

assets_bp = Blueprint("assets", __name__)

DEFAULT_TOTAL_MONTHS = 60


def _parse_date(s):
    try:
        return datetime.strptime((s or "").strip(), "%Y-%m-%d")
    except (TypeError, ValueError):
        return None


def _months_elapsed(purchase_dt, ref_dt, total_months):
    """Matches show_fix_inventory()'s month-count exactly: whole calendar
    months between purchase and ref date, +1 (the purchase month itself
    counts as month 1), clamped to [0, total_months]."""
    if not purchase_dt or not ref_dt:
        return 0
    elapsed = (ref_dt.year - purchase_dt.year) * 12 + (ref_dt.month - purchase_dt.month) + 1
    return max(0, min(elapsed, total_months))


def _asset_metrics(asset):
    """Live book-value computation, same formula as the original's
    show_fix_inventory(). Never trusts stored numbers for this - always
    recomputed from price/total_months/purchase_date so it's always
    accurate as of "now" (or as of sale_date, once sold)."""
    price = float(asset.get("price") or 0)
    total_months = int(asset.get("total_months") or DEFAULT_TOTAL_MONTHS) or DEFAULT_TOTAL_MONTHS
    monthly = float(asset.get("monthly_depreciation") or (price / total_months if total_months else 0))
    purchase_dt = _parse_date(asset.get("purchase_date"))

    if asset.get("status") == "sold" and asset.get("sale_date"):
        ref_dt = _parse_date(asset.get("sale_date")) or datetime.now()
    else:
        ref_dt = datetime.now()

    months_elapsed = _months_elapsed(purchase_dt, ref_dt, total_months)
    accumulated = round(monthly * months_elapsed, 2)
    book_value = round(max(0.0, price - accumulated), 2)
    remaining_months = max(0, total_months - months_elapsed)

    return {
        "monthly_depreciation": round(monthly, 2),
        "months_elapsed": months_elapsed,
        "remaining_months": remaining_months,
        "accumulated_depreciation": accumulated,
        "book_value": book_value,
    }


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
.stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px}
.stat-card{border-radius:12px;padding:10px 6px;text-align:center;color:#fff}
.stat-card.invested{background:linear-gradient(135deg,#00609C,#0096D6)}
.stat-card.book{background:linear-gradient(135deg,#7c3aed,#a855f7)}
.stat-card.recovered{background:linear-gradient(135deg,#22c55e,#16a34a)}
.stat-card .amt{font-size:15px;font-weight:700}.stat-card .lbl{font-size:8.5px;opacity:.9}
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
.asset-row .book{font-size:13px;font-weight:700;color:#7c3aed;margin-top:4px}
.asset-row .btns{display:flex;gap:6px;margin-top:8px}
.asset-row .btns button{padding:6px 12px;border-radius:8px;border:none;font-size:11px;font-weight:600}
.btn-sell{background:#f59e0b;color:#fff}.btn-unsell{background:#94a3b8;color:#fff}.btn-del{background:#fee2e2;color:#c0392b}
.sold-tag{display:inline-block;padding:2px 8px;border-radius:10px;background:#dcfce7;color:#166534;font-size:9px;font-weight:700;margin-left:6px}
.empty{color:#888;text-align:center;padding:20px 10px;font-size:13px}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:100;align-items:center;justify-content:center;padding:16px}
.overlay.show{display:flex}
.modal{background:#fff;border-radius:14px;padding:20px;width:100%;max-width:360px}
.modal h3{margin:0 0 4px;font-size:16px;color:#00609C}
.modal .hint{font-size:11px;color:#888;margin-bottom:10px}
.modal .gainloss{font-size:13px;font-weight:700;text-align:center;margin-top:8px;min-height:18px}
.modal .gainloss.gain{color:#16a34a}.modal .gainloss.loss{color:#c0392b}
.modal .btn-row{display:flex;gap:8px;margin-top:16px}
.modal .btn-row button{flex:1;padding:11px;border-radius:9px;border:none;font-size:13px;font-weight:700}
.modal .btn-cancel{background:#eee;color:#555}.modal .btn-confirm{background:#f59e0b;color:#fff}
</style></head>
<body>
<div class="topbar">
  <h1>🏭 Fixed Assets</h1>
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
        <a href="/assets" class="active">🏗️ Fixed Assets</a>
        <a href="/advance-orders">🎉 Advance Orders</a>
        <a href="/admin/duplicates">🔍 Duplicate Finder</a>
<a href="/prices">💰 Price Manager</a>
<a href="/ai-sales">🤖 Ask AI</a>
        <a href="/dashboard">📊 Dashboard</a>
      </div>
    </div>
  </div>
</div>

<div class="stat-grid">
  <div class="stat-card invested"><div class="amt" id="totalInvested">₱0</div><div class="lbl">TOTAL INVESTED</div></div>
  <div class="stat-card book"><div class="amt" id="totalBookValue">₱0</div><div class="lbl">ACTIVE BOOK VALUE NOW</div></div>
  <div class="stat-card recovered"><div class="amt" id="totalRecovered">₱0</div><div class="lbl">RECOVERED FROM SALES</div></div>
</div>

<div class="card">
  <h3 style="margin:0 0 10px;font-size:13px;color:#00609C">Add Asset</h3>
  <label>Asset Name</label>
  <input type="text" id="assetName" placeholder="hal. Ice Machine(Princeton), Freezer Fujidenzo...">
  <label>Purchase Date</label>
  <input type="date" id="assetDate">
  <label>Price (₱)</label>
  <input type="number" id="assetPrice" placeholder="0.00" step="0.01" min="0.01">
  <label>Depreciation Months (default 60)</label>
  <input type="number" id="assetMonths" value="60" min="1" step="1">
  <div class="status" id="assetPreview" style="color:#00609C;font-weight:600"></div>
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
    <div class="hint" id="sellBookHint">Book Value = Original - (Monthly x Months Paid)<br>Pwede ibenta hindi base sa Book - lagay mo sale price.</div>
    <label>Sale Date</label>
    <input type="date" id="sellDate" onchange="previewGainLoss()">
    <label>Sale Price (₱)</label>
    <input type="number" id="sellPrice" placeholder="0.00" step="0.01" min="0" oninput="previewGainLoss()">
    <label>Buyer (optional)</label>
    <input type="text" id="sellBuyer">
    <div class="gainloss" id="gainLossPreview"></div>
    <p class="status" id="sellStatus"></p>
    <div class="btn-row">
      <button class="btn-cancel" onclick="closeSellModal()">Cancel</button>
      <button class="btn-confirm" onclick="submitSell()">✅ Confirm Sale</button>
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

const IS_ISESMO = {{ 'true' if is_isesmo else 'false' }};
let allAssets = [];
let currentTab = 'active';
let sellingAssetId = null;
let sellingBookValue = 0;

function escapeHtmlA2(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }

document.getElementById('assetDate').value = new Date().toISOString().slice(0,10);

function updateAssetPreview(){
  const price = parseFloat(document.getElementById('assetPrice').value) || 0;
  const months = parseInt(document.getElementById('assetMonths').value) || 60;
  const prev = document.getElementById('assetPreview');
  if(price && months){
    const monthly = price / months;
    prev.textContent = `${peso(price)} / ${months} = ${peso(monthly)}/month`;
  } else {
    prev.textContent = '';
  }
}
document.getElementById('assetPrice').addEventListener('input', updateAssetPreview);
document.getElementById('assetMonths').addEventListener('input', updateAssetPreview);

async function submitAsset(){
  const name = document.getElementById('assetName').value.trim();
  const purchase_date = document.getElementById('assetDate').value;
  const price = parseFloat(document.getElementById('assetPrice').value);
  const total_months = parseInt(document.getElementById('assetMonths').value) || 60;
  const st = document.getElementById('assetStatus');
  if(!name){ st.textContent = 'Ilagay ang pangalan.'; st.className = 'status err'; return; }
  if(!purchase_date){ st.textContent = 'Pumili ng date.'; st.className = 'status err'; return; }
  if(!price || price <= 0){ st.textContent = 'Ilagay ang valid na price.'; st.className = 'status err'; return; }
  if(total_months <= 0){ st.textContent = 'Invalid months.'; st.className = 'status err'; return; }
  st.textContent = 'Saving...'; st.className = 'status';
  try{
    const res = await fetch('/api/assets', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({name, purchase_date, price, total_months})
    });
    const data = await res.json();
    if(data.ok){
      st.textContent = 'Na-save!'; st.className = 'status ok';
      document.getElementById('assetName').value = '';
      document.getElementById('assetPrice').value = '';
      document.getElementById('assetMonths').value = '60';
      document.getElementById('assetPreview').textContent = '';
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
    let invested = 0, bookValueNow = 0, recovered = 0;
    allAssets.forEach(a => {
      invested += Number(a.price) || 0;
      if(a.status === 'sold') recovered += Number(a.sale_price) || 0;
      else bookValueNow += Number(a.book_value) || 0;
    });
    document.getElementById('totalInvested').textContent = peso(invested);
    document.getElementById('totalBookValue').textContent = peso(bookValueNow);
    document.getElementById('totalRecovered').textContent = peso(recovered);
    renderList();
  }catch(e){
    wrap.innerHTML = `<div class="empty">Error: ${escapeHtmlA2(e.message)}</div>`;
  }
}

function renderList(){
  const wrap = document.getElementById('listWrap');
  const rows = allAssets.filter(a => currentTab === 'sold' ? a.status === 'sold' : a.status !== 'sold');
  if(!rows.length){
    wrap.innerHTML = `<div class="empty">Walang ${currentTab==='sold'?'nabentang':'active na'} asset.</div>`;
    return;
  }
  wrap.innerHTML = rows.map(a => `
    <div class="asset-row">
      <div class="name">${escapeHtmlA2(a.name)}${a.status==='sold' ? '<span class="sold-tag">SOLD</span>' : ''}</div>
      <div class="meta">Bought ${escapeHtmlA2(a.purchase_date)} for ${peso(a.price)} • ${peso(a.monthly_depreciation)}/mo</div>
      <div class="meta">Paid ${a.months_elapsed}/${a.total_months} months${a.status!=='sold' ? ` (${a.remaining_months} left)` : ''}</div>
      ${a.status === 'sold'
        ? `<div class="meta">Sold ${escapeHtmlA2(a.sale_date)} for ${peso(a.sale_price)}${a.buyer ? ' to '+escapeHtmlA2(a.buyer) : ''}</div>
           <div class="book">Book noon: ${peso(a.book_value)} • ${(a.sale_price - a.book_value) >= 0 ? 'TUBO' : 'LUGI'} ${peso(Math.abs(a.sale_price - a.book_value))}</div>`
        : `<div class="book">Book Value Now: ${peso(a.book_value)}</div>`}
      <div class="btns">
        ${a.status!=='sold' ? `<button class="btn-sell" onclick='openSellModal(${JSON.stringify(a)})'>💰 Mark Sold</button>` : `<button class="btn-unsell" onclick="unsellAsset('${a.id}')">↩️ Undo Sale</button>`}
        ${IS_ISESMO ? `<button class="btn-del" onclick="deleteAsset('${a.id}')">🗑️ Delete</button>` : ''}
      </div>
    </div>
  `).join('');
}

function openSellModal(asset){
  sellingAssetId = asset.id;
  sellingBookValue = Number(asset.book_value) || 0;
  document.getElementById('sellDate').value = new Date().toISOString().slice(0,10);
  document.getElementById('sellPrice').value = '';
  document.getElementById('sellBuyer').value = '';
  document.getElementById('sellStatus').textContent = '';
  document.getElementById('sellBookHint').innerHTML = `Book Value Now: <b>${peso(sellingBookValue)}</b> (Original ${peso(asset.price)})<br>Pwede ibenta hindi base sa Book - lagay mo sale price.`;
  document.getElementById('gainLossPreview').textContent = '';
  document.getElementById('sellOverlay').classList.add('show');
}
function closeSellModal(){
  document.getElementById('sellOverlay').classList.remove('show');
  sellingAssetId = null;
}
function previewGainLoss(){
  const sp = parseFloat(document.getElementById('sellPrice').value) || 0;
  const el = document.getElementById('gainLossPreview');
  if(!sp){ el.textContent = ''; el.className = 'gainloss'; return; }
  const gain = sp - sellingBookValue;
  if(gain >= 0){
    el.textContent = `TUBO ka ${peso(gain)} (Sale ${peso(sp)} - Book ${peso(sellingBookValue)})`;
    el.className = 'gainloss gain';
  } else {
    el.textContent = `LUGI ka ${peso(Math.abs(gain))} (Sale ${peso(sp)} - Book ${peso(sellingBookValue)})`;
    el.className = 'gainloss loss';
  }
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
    return render_template_string(ASSETS_HTML, is_isesmo=is_isesmo)


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
            row["total_months"] = int(row.get("total_months") or DEFAULT_TOTAL_MONTHS)
            row.update(_asset_metrics(row))
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
        purchase_date = (data.get("purchase_date") or "").strip() or today_str()
        try:
            price = float(data.get("price"))
        except (TypeError, ValueError):
            price = 0
        try:
            total_months = int(data.get("total_months") or DEFAULT_TOTAL_MONTHS)
        except (TypeError, ValueError):
            total_months = DEFAULT_TOTAL_MONTHS
        if total_months <= 0:
            total_months = DEFAULT_TOTAL_MONTHS
        if not name:
            return jsonify({"ok": False, "error": "Name is required"}), 400
        if price <= 0:
            return jsonify({"ok": False, "error": "Invalid price"}), 400
        monthly_depreciation = round(price / total_months, 4)
        entry = {
            "name": name,
            "purchase_date": purchase_date,
            "price": price,
            "total_months": total_months,
            "monthly_depreciation": monthly_depreciation,
            "status": "active",
            "sale_date": None,
            "sale_price": None,
            "buyer": None,
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

        # Compute book value AS OF the sale date (same formula as show_fix_inventory),
        # so the gain/loss we record is accurate to the moment of sale, not "now".
        asset_with_id = dict(asset)
        asset_with_id["status"] = "sold"
        asset_with_id["sale_date"] = sale_date
        metrics = _asset_metrics(asset_with_id)
        gain_loss = round(sale_price - metrics["book_value"], 2)

        fb_patch(f"fixed_assets/{asset_id}", {
            "status": "sold",
            "sale_date": sale_date,
            "sale_price": sale_price,
            "buyer": buyer,
            "book_value_at_sale": metrics["book_value"],
            "gain_loss_at_sale": gain_loss,
            "sold_by": session.get("staff_name"),
            "sold_at": now_str(),
        })
        return jsonify({"ok": True, "book_value": metrics["book_value"], "gain_loss": gain_loss})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@assets_bp.route("/api/assets/<asset_id>/unsell", methods=["POST"])
@login_required
def api_assets_unsell(asset_id):
    """Undo a sale record - e.g. it was logged by mistake. Reverts the
    asset back to Active. Book value simply recomputes live from
    purchase_date again - no stored depreciation schedule to regenerate,
    unlike the original's regenerate-60-rows approach."""
    try:
        asset = fb_get(f"fixed_assets/{asset_id}")
        if not asset:
            return jsonify({"ok": False, "error": "Asset not found"}), 404
        fb_patch(f"fixed_assets/{asset_id}", {
            "status": "active",
            "sale_date": None,
            "sale_price": None,
            "buyer": None,
            "book_value_at_sale": None,
            "gain_loss_at_sale": None,
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
