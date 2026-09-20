"""
Expense Tracking module.

REWRITTEN (v2) to faithfully port the real "ExpensesScreen" logic and
fields from the user's original Kivy app (OMEGA_PURIFIED.py), verified
against BOTH the Kivy source AND the actual production SQLite database
(omega_ice.db) the user exported from that app. The first version of
this module was a rough placeholder (single generic amount+note field) -
this version replicates the real per-category field sets and the
auto-computed values the original app calculated live as you typed.

What the real `expenses` SQLite table actually stores (ground truth,
read from omega_ice.db):
  id, date, category, item, quantity, price, unit_price, supplier,
  staff_id, created_at, description, cubic, kwh, kwph, base,
  final_bill, current_bill, real_kwph, bill_start, bill_end

Only 5 categories exist in real data: Consumables, Fuel, Electricity,
Maintenance, Fix Asset (+ an unrelated "STAFF SALARY" bucket that's
auto-written by a different screen entirely - not part of this UI).

Design decisions made after reading the source (ExpensesScreen class,
~line 5327 of the Kivy file) and the real rows in the DB:

  - "Fix Asset" is INTENTIONALLY NOT a category here. In the Kivy app,
    picking "Fix Asset" in the expense form actually creates a row in a
    separate `fixed_assets` table plus 60 auto-generated monthly
    depreciation rows mirrored into `expenses` (that's why the DB is
    full of "Dep 1/60, Dep 2/60..." rows). We already have a dedicated,
    better-designed `modules/fixed_assets.py` (active/sold tracking,
    sell/unsell) that covers this same need without the monthly-row
    spam. Don't duplicate it here.

  - `expense_categories` table (with icon/color per category) exists in
    the schema but `get_all_expense_categories()` is dead code - it's
    never called from ExpensesScreen. The UI hardcodes exactly 4
    category buttons (Consumables/Fuel/Electricity/Maintenance/+FixAsset
    handled above). So categories stay a fixed list here too - no need
    for a category-admin screen.

  - The "AUTO HATIIN BILL" (bill-splitting-across-2-months) button in
    the original only ever showed a preview label - `_hatiin_cache` is
    computed but nothing in save_new_expense() ever reads it, so it
    never actually saved a split. It's dead functionality. We replicate
    the same *preview* (days spanned + per-day rate) client-side purely
    as a helpful readout, since it's cheap - but there's no "apply
    split" because the original never had one either.

  - Per-category fields & auto-computed values (server recomputes all
    of these itself - never trusts client math, same principle as the
    original always recalculating from raw inputs):
      Consumables : item, quantity, price(total)   -> unit_price = price/quantity
      Fuel        : item, liters(quantity), price  -> unit_price = price/quantity
      Electricity : bill_start, bill_end, kwh, base(subtotal), current_bill(final)
                    -> kwph = base/kwh ; real_kwph = current_bill/kwh
                    -> the "amount" used for totals is current_bill if set,
                       else base (matches the original's CASE WHEN in
                       MonthlyExpensesSummaryScreen.load_data())
      Maintenance : item, price

Firebase data model:
  expenses/<auto_id> = {
    date, category, description, quantity, unit_price, price,
    bill_start, bill_end, kwh, base, current_bill, kwph, real_kwph,
    recorded_by, created_at, updated_by, updated_at
  }
  (fields not relevant to a category are simply omitted/null)

Routes:
  GET    /expenses                    - Expenses page (category-specific form + month list)
  GET    /api/expenses?month=YYYY-MM  - JSON: rows for that month + total + by_category
  POST   /api/expenses                - JSON: add an expense entry
  PUT    /api/expenses/<id>           - JSON: edit an entry (any logged-in staff, like the original)
  DELETE /api/expenses/<id>           - ISESMO only: remove an entry (e.g. a mistake/test entry)
"""
from datetime import datetime

from flask import Blueprint, request, jsonify, session, render_template_string

from modules.shared import fb_get, fb_post, fb_put, fb_delete, login_required, isesmo_only, now_str, today_str

expenses_bp = Blueprint("expenses", __name__)

EXPENSE_CATEGORIES = ["Consumables", "Fuel", "Electricity", "Maintenance"]


def _safe_float(v, default=0.0):
    try:
        if v is None or v == "":
            return default
        return float(v)
    except (TypeError, ValueError):
        return default


def _compute_fields(category, data):
    """
    Recompute every derived field server-side, mirroring
    ExpensesScreen.update_computation() / save_new_expense() in the
    original Kivy app. Returns (entry_dict, error_string_or_None).
    """
    date = (data.get("date") or "").strip() or today_str()
    entry = {
        "date": date,
        "category": category,
        "description": None,
        "quantity": None,
        "unit_price": None,
        "price": None,
        "bill_start": None,
        "bill_end": None,
        "kwh": None,
        "base": None,
        "current_bill": None,
        "kwph": None,
        "real_kwph": None,
    }

    if category == "Consumables":
        item = (data.get("description") or "").strip() or "Consumables"
        qty = _safe_float(data.get("quantity"))
        price = _safe_float(data.get("price"))
        if price <= 0:
            return None, "Ilagay ang valid na PRICE."
        unit = round(price / qty, 4) if qty else 0
        entry.update({"description": item, "quantity": qty, "price": price, "unit_price": unit})

    elif category == "Fuel":
        item = (data.get("description") or "").strip() or "Fuel"
        liters = _safe_float(data.get("quantity"))
        price = _safe_float(data.get("price"))
        if price <= 0:
            return None, "Ilagay ang valid na PRICE."
        unit = round(price / liters, 4) if liters else 0
        entry.update({"description": item, "quantity": liters, "price": price, "unit_price": unit})

    elif category == "Electricity":
        bill_start = (data.get("bill_start") or "").strip() or None
        bill_end = (data.get("bill_end") or "").strip() or None
        kwh = _safe_float(data.get("kwh"))
        base = _safe_float(data.get("base"))
        current_bill = _safe_float(data.get("current_bill"))
        if kwh <= 0:
            return None, "Ilagay ang valid na KWH USED."
        if base <= 0 and current_bill <= 0:
            return None, "Ilagay ang BILL SUB TOTAL o CURRENT BILL."
        kwph = round(base / kwh, 4) if kwh and base else 0
        real_kwph = round(current_bill / kwh, 4) if kwh and current_bill else 0
        price = current_bill if current_bill > 0 else base
        desc = "Elec %s KWH" % int(kwh)
        entry.update({
            "description": desc, "price": price, "kwh": kwh, "base": base,
            "current_bill": current_bill, "kwph": kwph, "real_kwph": real_kwph,
            "bill_start": bill_start, "bill_end": bill_end,
        })

    elif category == "Maintenance":
        item = (data.get("description") or "").strip() or "Maintenance"
        price = _safe_float(data.get("price"))
        if price <= 0:
            return None, "Ilagay ang valid na PRICE."
        entry.update({"description": item, "price": price})

    else:
        return None, "Invalid category."

    return entry, None


def _effective_amount(row):
    """Matches the original's CASE WHEN category='Electricity' AND current_bill>0 THEN current_bill ELSE price END."""
    if row.get("category") == "Electricity" and _safe_float(row.get("current_bill")) > 0:
        return _safe_float(row.get("current_bill"))
    return _safe_float(row.get("price"))


EXPENSES_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Expenses - Omega Ice</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0;font-weight:700}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C}
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.total-card{background:linear-gradient(135deg,#c0392b,#e67e22);color:#fff;border-radius:12px;padding:16px;margin-bottom:12px;text-align:center}
.total-card .amt{font-size:26px;font-weight:700}.total-card .lbl{font-size:11px;opacity:.9}
label{font-size:12px;color:#666;display:block;margin:10px 0 4px}
input,select,textarea{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:14px;font-family:inherit}
input:disabled{background:#f4f6f8;color:#888}
.cat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-top:4px}
.cat-row button{padding:9px 4px;border-radius:8px;border:1px solid #ccd;background:#f5f5f5;font-size:11px}
.cat-row button.active{background:#00609C;color:#fff;border-color:#00609C}
.save-btn{width:100%;padding:13px;margin-top:14px;background:#00609C;color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:600}
.save-btn.editing{background:#1a8a4a}
.cancel-btn{width:100%;padding:10px;margin-top:8px;background:#fff;color:#888;border:1px solid #ccd;border-radius:10px;font-size:13px}
.status{font-size:12px;text-align:center;margin-top:8px;min-height:16px}.status.err{color:#c0392b}.status.ok{color:#1a8a4a}
.month-nav{display:flex;align-items:center;justify-content:center;gap:14px;margin-bottom:10px}
.month-nav button{padding:8px 14px;border-radius:8px;border:1px solid #cde;background:#fff;color:#00609C;font-weight:700}
.month-nav .label{font-weight:700;color:#00609C;font-size:14px;min-width:120px;text-align:center}
.breakdown{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px}
.chip{padding:5px 10px;border-radius:14px;background:#eef4fb;color:#00609C;font-size:11px;font-weight:600}
.log-row{display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid #f0f4f8}
.log-meta{font-size:9px;color:#aaa;margin-top:2px}
.amt-pill{font-weight:700;color:#c0392b;white-space:nowrap}
.edit-btn,.del-btn{background:none;border:none;font-size:15px;padding:2px 4px}
.edit-btn{color:#00609C}.del-btn{color:#c0392b}
.empty{color:#888;text-align:center;padding:20px 10px;font-size:13px}
.auto-hint{font-size:10px;color:#1a8a4a;margin-top:2px}
.hatiin-hint{font-size:11px;color:#1a8a4a;background:#eafaf0;border-radius:8px;padding:8px;margin-top:6px;text-align:center}
.edit-banner{background:#fff3cd;color:#8a6d1a;border-radius:8px;padding:8px 10px;font-size:12px;margin-bottom:8px;font-weight:600;text-align:center}
</style></head>
<body>
<div class="topbar">
  <h1>💸 Expenses</h1>
  <div style="display:flex;gap:6px;flex-wrap:wrap">
    <a href="/cashier" class="nav-pill">Sales</a>
    <a href="/credit" class="nav-pill">💳 Utang</a>
    <a href="/expenses" class="nav-pill active">Expenses</a>
    <a href="/plastic" class="nav-pill">📦 Plastic</a>
    <a href="/assets" class="nav-pill">🏭 Assets</a>
  </div>
</div>

<div class="card">
  <div class="edit-banner" id="editBanner" style="display:none">✏️ Ina-edit ang entry #<span id="editIdLbl"></span></div>
  <label>Category</label>
  <div class="cat-row" id="catRow"></div>
  <div id="formFields"></div>
  <button class="save-btn" id="saveBtn" onclick="submitExpense()">💾 Save Expense</button>
  <button class="cancel-btn" id="cancelBtn" style="display:none" onclick="cancelEdit()">Cancel Edit</button>
  <p class="status" id="expStatus"></p>
</div>

<div class="month-nav">
  <button onclick="shiftMonth(-1)">◀</button>
  <div class="label" id="monthLabel"></div>
  <button onclick="shiftMonth(1)">▶</button>
</div>

<div class="total-card"><div class="amt" id="monthTotal">₱0</div><div class="lbl">TOTAL EXPENSES THIS MONTH</div></div>

<div class="card">
  <div class="breakdown" id="breakdownWrap"></div>
</div>

<div class="card" id="listWrap">Loading...</div>

<script>
const CATEGORIES = {{ categories|tojson }};
const IS_ISESMO = {{ 'true' if is_isesmo else 'false' }};
let selectedCategory = CATEGORIES[0];
let viewMonth = new Date();
let editId = null;

function escapeHtmlE(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }
function monthKey(d){ return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0'); }
function monthLabelText(d){ return d.toLocaleString('en-PH',{month:'long', year:'numeric'}); }
function todayStr(){ return new Date().toISOString().slice(0,10); }

function initCatRow(){
  const row = document.getElementById('catRow');
  row.innerHTML = CATEGORIES.map(c => `<button type="button" data-c="${escapeHtmlE(c)}" onclick="selectCategory('${escapeHtmlE(c)}')" class="${c===selectedCategory?'active':''}">${escapeHtmlE(c)}</button>`).join('');
}

function selectCategory(c){
  selectedCategory = c;
  document.querySelectorAll('#catRow button').forEach(b => b.classList.toggle('active', b.dataset.c===c));
  renderForm();
}

// Renders the category-specific fields, mirroring ExpensesScreen.rebuild_form()
function renderForm(prefill){
  prefill = prefill || {};
  const f = document.getElementById('formFields');
  const date = prefill.date || todayStr();
  if(selectedCategory === 'Consumables'){
    f.innerHTML = `
      <label>Date</label><input type="date" id="f_date" value="${date}">
      <label>Item Name (hal. Sako, Tape)</label><input type="text" id="f_desc" value="${escapeHtmlE(prefill.description||'')}" placeholder="Consumables">
      <label>Quantity</label><input type="number" id="f_qty" step="0.01" value="${prefill.quantity ?? ''}" oninput="updateComputation()">
      <label>Price (total ₱)</label><input type="number" id="f_price" step="0.01" value="${prefill.price ?? ''}" oninput="updateComputation()">
      <label>Unit Price (auto)</label><input type="text" id="f_unit" disabled>
    `;
  } else if(selectedCategory === 'Fuel'){
    f.innerHTML = `
      <label>Date</label><input type="date" id="f_date" value="${date}">
      <label>Item Name (hal. Diesel)</label><input type="text" id="f_desc" value="${escapeHtmlE(prefill.description||'')}" placeholder="Fuel">
      <label>Liters</label><input type="number" id="f_qty" step="0.01" value="${prefill.quantity ?? ''}" oninput="updateComputation()">
      <label>Price (total ₱)</label><input type="number" id="f_price" step="0.01" value="${prefill.price ?? ''}" oninput="updateComputation()">
      <label>Unit Price (auto)</label><input type="text" id="f_unit" disabled>
    `;
  } else if(selectedCategory === 'Electricity'){
    f.innerHTML = `
      <label>Bill Start</label><input type="date" id="f_bill_start" value="${prefill.bill_start || ''}" oninput="updateComputation()">
      <label>Bill End</label><input type="date" id="f_bill_end" value="${prefill.bill_end || ''}" oninput="updateComputation()">
      <label>KWH Used</label><input type="number" id="f_kwh" step="0.01" value="${prefill.kwh ?? ''}" oninput="updateComputation()">
      <label>Bill Sub Total (₱)</label><input type="number" id="f_base" step="0.01" value="${prefill.base ?? ''}" oninput="updateComputation()">
      <label>Current Bill / Final (₱)</label><input type="number" id="f_current_bill" step="0.01" value="${prefill.current_bill ?? ''}" oninput="updateComputation()">
      <label>₱/KWH from sub total (auto)</label><input type="text" id="f_kwph" disabled>
      <label>Real ₱/KWH from final bill (auto)</label><input type="text" id="f_real_kwph" disabled>
      <div class="hatiin-hint" id="hatiinHint">Lagay Bill Start, End, KWH at Current Bill para makita ang days span.</div>
    `;
  } else if(selectedCategory === 'Maintenance'){
    f.innerHTML = `
      <label>Date</label><input type="date" id="f_date" value="${date}">
      <label>Job Order (hal. Repair motor)</label><input type="text" id="f_desc" value="${escapeHtmlE(prefill.description||'')}" placeholder="Maintenance">
      <label>Price (₱)</label><input type="number" id="f_price" step="0.01" value="${prefill.price ?? ''}" oninput="updateComputation()">
    `;
  }
  updateComputation();
}

// Mirrors ExpensesScreen.update_computation() - purely a live preview, server always recomputes for real
function updateComputation(){
  if(selectedCategory === 'Consumables' || selectedCategory === 'Fuel'){
    const qty = parseFloat(document.getElementById('f_qty').value) || 0;
    const price = parseFloat(document.getElementById('f_price').value) || 0;
    const unit = qty ? (price/qty) : 0;
    document.getElementById('f_unit').value = (qty && price) ? unit.toFixed(2) : '';
  } else if(selectedCategory === 'Electricity'){
    const kwh = parseFloat(document.getElementById('f_kwh').value) || 0;
    const base = parseFloat(document.getElementById('f_base').value) || 0;
    const curr = parseFloat(document.getElementById('f_current_bill').value) || 0;
    const kwph = (kwh && base) ? (base/kwh) : 0;
    const real = (kwh && curr) ? (curr/kwh) : 0;
    document.getElementById('f_kwph').value = kwph ? kwph.toFixed(2) : '';
    document.getElementById('f_real_kwph').value = real ? real.toFixed(2) : '';
    // "Hatiin" preview: days spanned + per-day rate (informational only, same as original)
    const startS = document.getElementById('f_bill_start').value;
    const endS = document.getElementById('f_bill_end').value;
    const hint = document.getElementById('hatiinHint');
    if(startS && endS && curr){
      const sd = new Date(startS), ed = new Date(endS);
      let days = Math.round((ed - sd) / 86400000);
      if(days <= 0) days = 1;
      const perDay = curr / days;
      hint.textContent = `${days} days span • ₱${perDay.toFixed(0)}/day`;
    } else {
      hint.textContent = 'Lagay Bill Start, End, KWH at Current Bill para makita ang days span.';
    }
  }
}

function startEdit(row){
  editId = row.id;
  selectedCategory = CATEGORIES.includes(row.category) ? row.category : CATEGORIES[0];
  document.querySelectorAll('#catRow button').forEach(b => b.classList.toggle('active', b.dataset.c===selectedCategory));
  renderForm(row);
  document.getElementById('editBanner').style.display = 'block';
  document.getElementById('editIdLbl').textContent = row.id;
  document.getElementById('saveBtn').textContent = '✏️ Update Expense';
  document.getElementById('saveBtn').classList.add('editing');
  document.getElementById('cancelBtn').style.display = 'block';
  window.scrollTo({top:0, behavior:'smooth'});
}

function cancelEdit(){
  editId = null;
  document.getElementById('editBanner').style.display = 'none';
  document.getElementById('saveBtn').textContent = '💾 Save Expense';
  document.getElementById('saveBtn').classList.remove('editing');
  document.getElementById('cancelBtn').style.display = 'none';
  renderForm();
}

function collectFormPayload(){
  const payload = {category: selectedCategory};
  if(selectedCategory === 'Consumables' || selectedCategory === 'Fuel'){
    payload.date = document.getElementById('f_date').value;
    payload.description = document.getElementById('f_desc').value.trim();
    payload.quantity = document.getElementById('f_qty').value;
    payload.price = document.getElementById('f_price').value;
  } else if(selectedCategory === 'Electricity'){
    payload.date = document.getElementById('f_bill_end').value || todayStr();
    payload.bill_start = document.getElementById('f_bill_start').value;
    payload.bill_end = document.getElementById('f_bill_end').value;
    payload.kwh = document.getElementById('f_kwh').value;
    payload.base = document.getElementById('f_base').value;
    payload.current_bill = document.getElementById('f_current_bill').value;
  } else if(selectedCategory === 'Maintenance'){
    payload.date = document.getElementById('f_date').value;
    payload.description = document.getElementById('f_desc').value.trim();
    payload.price = document.getElementById('f_price').value;
  }
  return payload;
}

async function submitExpense(){
  const st = document.getElementById('expStatus');
  const payload = collectFormPayload();
  st.textContent = 'Saving...'; st.className = 'status';
  try{
    const url = editId ? `/api/expenses/${editId}` : '/api/expenses';
    const method = editId ? 'PUT' : 'POST';
    const res = await fetch(url, {
      method,
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if(data.ok){
      st.textContent = editId ? 'Na-update!' : 'Na-save!'; st.className = 'status ok';
      cancelEdit();
      loadMonth();
    } else {
      st.textContent = data.error || 'May error.'; st.className = 'status err';
    }
  }catch(e){
    st.textContent = 'Error: ' + e.message; st.className = 'status err';
  }
}

function shiftMonth(delta){
  viewMonth.setMonth(viewMonth.getMonth() + delta);
  loadMonth();
}

let lastRows = {};

async function loadMonth(){
  document.getElementById('monthLabel').textContent = monthLabelText(viewMonth);
  const wrap = document.getElementById('listWrap');
  wrap.textContent = 'Loading...';
  try{
    const res = await fetch(`/api/expenses?month=${monthKey(viewMonth)}`);
    if(res.status===401){ window.location.href='/login'; return; }
    const data = await res.json();
    if(!data.ok){ wrap.innerHTML = `<div class="empty">${escapeHtmlE(data.error||'Error')}</div>`; return; }
    document.getElementById('monthTotal').textContent = peso(data.total || 0);
    const bd = document.getElementById('breakdownWrap');
    const byCat = data.by_category || {};
    const cats = Object.keys(byCat);
    bd.innerHTML = cats.length ? cats.map(c => `<span class="chip">${escapeHtmlE(c)}: ${peso(byCat[c])}</span>`).join('') : '<span style="color:#aaa;font-size:11px">Wala pang expense sa buwan na ito.</span>';
    const rows = data.rows || [];
    lastRows = {};
    rows.forEach(r => lastRows[r.id] = r);
    if(!rows.length){
      wrap.innerHTML = '<div class="empty">Walang expense na naka-record sa buwan na ito.</div>';
      return;
    }
    wrap.innerHTML = rows.map(r => {
      const amt = (r.category === 'Electricity' && Number(r.current_bill) > 0) ? r.current_bill : r.price;
      return `
      <div class="log-row">
        <div>
          <div style="font-weight:600">${escapeHtmlE(r.category)} - ${escapeHtmlE(r.description||'')}</div>
          <div class="log-meta">${escapeHtmlE(r.date)} • ni ${escapeHtmlE(r.recorded_by||'-')}</div>
        </div>
        <div style="display:flex;align-items:center;gap:6px">
          <div class="amt-pill">${peso(amt)}</div>
          <button class="edit-btn" onclick='startEdit(${JSON.stringify(r)})'>✏️</button>
          ${IS_ISESMO ? `<button class="del-btn" onclick="deleteExpense('${r.id}')">🗑️</button>` : ''}
        </div>
      </div>
    `;
    }).join('');
  }catch(e){
    wrap.innerHTML = `<div class="empty">Error: ${escapeHtmlE(e.message)}</div>`;
  }
}

async function deleteExpense(id){
  if(!confirm('Tanggalin ang expense entry na ito?')) return;
  try{
    const res = await fetch(`/api/expenses/${id}`, {method:'DELETE'});
    const data = await res.json();
    if(data.ok) loadMonth();
    else alert(data.error || 'Hindi na-delete.');
  }catch(e){
    alert('Error: ' + e.message);
  }
}

initCatRow();
renderForm();
loadMonth();
</script>
</body></html>
"""


@expenses_bp.route("/expenses")
@login_required
def expenses_page():
    staff = (session.get("staff_name") or "").strip().lower()
    is_isesmo = staff in ["isesmo", "isesmo gamboa"]
    return render_template_string(EXPENSES_HTML, categories=EXPENSE_CATEGORIES, is_isesmo=is_isesmo)


@expenses_bp.route("/api/expenses")
@login_required
def api_expenses_list():
    try:
        month = request.args.get("month") or datetime.now().strftime("%Y-%m")
        expenses = fb_get("expenses") or {}
        rows = []
        for key, val in expenses.items():
            if not val:
                continue
            if not (val.get("date") or "").startswith(month):
                continue
            row = dict(val)
            row["id"] = key
            rows.append(row)
        rows.sort(key=lambda r: r.get("date") or "", reverse=True)
        total = sum(_effective_amount(r) for r in rows)
        by_category = {}
        for r in rows:
            cat = r.get("category") or "Other"
            by_category[cat] = round(by_category.get(cat, 0) + _effective_amount(r), 2)
        return jsonify({"ok": True, "rows": rows, "total": round(total, 2), "by_category": by_category})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@expenses_bp.route("/api/expenses", methods=["POST"])
@login_required
def api_expenses_add():
    try:
        data = request.json or {}
        category = (data.get("category") or "").strip()
        if category not in EXPENSE_CATEGORIES:
            return jsonify({"ok": False, "error": "Invalid category"}), 400
        entry, err = _compute_fields(category, data)
        if err:
            return jsonify({"ok": False, "error": err}), 400
        entry["recorded_by"] = session.get("staff_name")
        entry["created_at"] = now_str()
        fb_post("expenses", entry)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@expenses_bp.route("/api/expenses/<expense_id>", methods=["PUT"])
@login_required
def api_expenses_update(expense_id):
    try:
        existing = fb_get(f"expenses/{expense_id}")
        if not existing:
            return jsonify({"ok": False, "error": "Not found"}), 404
        data = request.json or {}
        category = (data.get("category") or "").strip()
        if category not in EXPENSE_CATEGORIES:
            return jsonify({"ok": False, "error": "Invalid category"}), 400
        entry, err = _compute_fields(category, data)
        if err:
            return jsonify({"ok": False, "error": err}), 400
        entry["recorded_by"] = existing.get("recorded_by")
        entry["created_at"] = existing.get("created_at")
        entry["updated_by"] = session.get("staff_name")
        entry["updated_at"] = now_str()
        fb_put(f"expenses/{expense_id}", entry)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@expenses_bp.route("/api/expenses/<expense_id>", methods=["DELETE"])
@isesmo_only
def api_expenses_delete(expense_id):
    try:
        fb_delete(f"expenses/{expense_id}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
