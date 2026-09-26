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

  - UPDATE: "AUTO HATIIN BILL" (bill-splitting-across-2-months) was
    dead functionality in the original - `_hatiin_cache` was computed
    but nothing in save_new_expense() ever read it, so a bill spanning
    e.g. Aug 12 - Sep 9 was always recorded as ONE lump entry, in
    whichever month it happened to get saved. The user asked for this
    to actually work here, since it throws off monthly totals (a bill
    covering mostly August was landing entirely in September, etc).
    So when bill_start and bill_end fall in two different (adjacent)
    calendar months, we now really do split it: the same day-count
    formula the dead preview used (days remaining in the start month
    vs days elapsed in the end month) is applied to kwh/base/
    current_bill, producing TWO Firebase entries - one dated at the
    end of the start month, one dated at bill_end - so each month's
    total only carries its own share of the bill. See
    _split_electricity_portions() below.

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
from calendar import monthrange
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
        # Electricity is special-cased in the route handlers instead
        # (it can produce ONE or TWO entries - see
        # _split_electricity_portions()). _compute_fields() still
        # validates the raw inputs here so both POST and PUT share the
        # same validation, but the caller must use
        # _split_electricity_portions() to actually build the entry/ies.
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


def _parse_date(s):
    try:
        return datetime.strptime((s or "").strip(), "%Y-%m-%d")
    except (TypeError, ValueError):
        return None


def _split_electricity_portions(electricity_entry):
    """
    Given a validated Electricity entry (from _compute_fields), returns a
    LIST of 1 or 2 entry dicts ready to save:

      - If bill_start/bill_end are missing, invalid, or fall in the SAME
        calendar month -> returns the entry unchanged, as a list of 1.

      - If they fall in two ADJACENT calendar months (the normal case for
        a ~30-day billing cycle, e.g. Aug 12 -> Sep 9) -> splits kwh,
        base and current_bill proportionally by day count between the
        two months, same formula the original's dead "hatiin" preview
        used:
            days_in_start_month = days from bill_start to the end of
                                   its month (inclusive)
            days_in_end_month   = bill_end's day-of-month
            ratio = each month's day count / total days
        Each portion becomes its own entry, dated inside its own month
        (so /api/expenses?month=YYYY-MM buckets each portion into the
        right month), tagged with a shared bill_ref so they can be
        traced back to the same original bill.

      - If they span MORE than two calendar months (not a normal
        billing cycle - almost certainly a typo), we don't guess: falls
        back to a single entry dated at bill_end, same as before.
    """
    start_dt = _parse_date(electricity_entry.get("bill_start"))
    end_dt = _parse_date(electricity_entry.get("bill_end"))

    if not start_dt or not end_dt or end_dt <= start_dt:
        return [electricity_entry]

    same_month = (start_dt.year, start_dt.month) == (end_dt.year, end_dt.month)
    months_apart = (end_dt.year - start_dt.year) * 12 + (end_dt.month - start_dt.month)

    if same_month or months_apart != 1:
        return [electricity_entry]

    days_in_start_month = monthrange(start_dt.year, start_dt.month)[1]
    days_start_month = days_in_start_month - start_dt.day + 1
    days_end_month = end_dt.day
    total_days = days_start_month + days_end_month
    if total_days <= 0:
        return [electricity_entry]

    kwh = _safe_float(electricity_entry.get("kwh"))
    base = _safe_float(electricity_entry.get("base"))
    current_bill = _safe_float(electricity_entry.get("current_bill"))
    bill_start = electricity_entry.get("bill_start")
    bill_end = electricity_entry.get("bill_end")
    bill_ref = "%s_to_%s" % (bill_start, bill_end)

    end_of_start_month = "%04d-%02d-%02d" % (start_dt.year, start_dt.month, days_in_start_month)

    portions = []
    for label, ratio, portion_date, days in (
        ("1/2", days_start_month / total_days, end_of_start_month, days_start_month),
        ("2/2", days_end_month / total_days, bill_end, days_end_month),
    ):
        p_kwh = round(kwh * ratio, 4)
        p_base = round(base * ratio, 2)
        p_current = round(current_bill * ratio, 2)
        p_kwph = round(p_base / p_kwh, 4) if p_kwh and p_base else 0
        p_real_kwph = round(p_current / p_kwh, 4) if p_kwh and p_current else 0
        p_price = p_current if p_current > 0 else p_base
        portion = dict(electricity_entry)
        portion.update({
            "date": portion_date,
            "description": "Elec %s KWH (hinati %s, %s araw ng %s-%s)" % (
                round(p_kwh, 1), label, days, bill_start, bill_end
            ),
            "kwh": p_kwh, "base": p_base, "current_bill": p_current,
            "kwph": p_kwph, "real_kwph": p_real_kwph, "price": p_price,
            "bill_start": bill_start, "bill_end": bill_end,
            "split_part": label, "split_days": days, "split_of_bill": bill_ref,
        })
        portions.append(portion)

    return portions


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
  <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
    <a href="/cashier" class="nav-pill">Sales</a>
    <div class="menu-wrap">
      <button type="button" class="menu-btn" id="navMenuBtn" onclick="toggleNavMenu()" title="Menu">☰</button>
      <div class="menu-dropdown" id="navMenuDropdown">
        <a href="/home">🏠 Home</a>
        <a href="/machines">🏭 Machines</a>
        <a href="/credit">💳 Utang</a>
        <a href="/credit/history">🧾 Utang History</a>
        <a href="/expenses" class="active">💸 Expenses</a>
        <a href="/expenses/trend">📈 Expense Trends</a>
        <a href="/plastic">📦 Plastic</a>
        <a href="/assets">🏗️ Fixed Assets</a>
        <a href="/advance-orders">🎉 Advance Orders</a>
        <a href="/admin/duplicates">🔍 Duplicate Finder</a>
<a href="/prices">💰 Price Manager</a>
<a href="/ai-sales">🤖 Ask AI</a>
        <a href="/dashboard">📊 Dashboard</a>
      </div>
    </div>
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
      <div class="hatiin-hint" id="hatiinHint">Lagay Bill Start, End, KWH at Current Bill. Kung magkaiba ang buwan ng Start at End, AWTOMATIKONG mahahati ang bill sa dalawang buwan base sa bilang ng araw.</div>
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
    // Live preview of the REAL auto-split the server will do, so staff
    // sees the per-month breakdown before saving - mirrors
    // _split_electricity_portions() in expenses.py exactly.
    const startS = document.getElementById('f_bill_start').value;
    const endS = document.getElementById('f_bill_end').value;
    const hint = document.getElementById('hatiinHint');
    if(!startS || !endS || !curr){
      hint.textContent = 'Lagay Bill Start, End, KWH at Current Bill. Kung magkaiba ang buwan ng Start at End, AWTOMATIKONG mahahati ang bill sa dalawang buwan base sa bilang ng araw.';
    } else {
      const [sy, sm, sd] = startS.split('-').map(Number);
      const [ey, em, ed] = endS.split('-').map(Number);
      if(sy === ey && sm === em){
        hint.textContent = `Iisang buwan lang (${startS} - ${endS}) - hindi hahatiin, ${peso2(curr)} sa buwan na iyon.`;
      } else {
        const monthsApart = (ey - sy) * 12 + (em - sm);
        if(monthsApart !== 1){
          hint.textContent = `⚠️ Sobrang layo ng Start at End (${startS} - ${endS}) - hindi ito normal na 1-buwan na bill, kaya HINDI hahatiin. I-double check mo yung dates.`;
        } else {
          const daysInStartMonth = new Date(sy, sm, 0).getDate();
          const daysStart = daysInStartMonth - sd + 1;
          const daysEnd = ed;
          const totalDays = daysStart + daysEnd;
          const amtStart = curr * daysStart / totalDays;
          const amtEnd = curr * daysEnd / totalDays;
          hint.textContent = `Mahahati: ${sy}-${String(sm).padStart(2,'0')} (${daysStart}d) = ${peso2(amtStart)} • ${ey}-${String(em).padStart(2,'0')} (${daysEnd}d) = ${peso2(amtEnd)}`;
        }
      }
    }
  }
}
function peso2(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{maximumFractionDigits:0}); }

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
      st.textContent = editId ? 'Na-update!' : (data.split ? `Na-save! Nahati sa ${data.count} buwan.` : 'Na-save!');
      st.className = 'status ok';
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


# Bar chart is hand-built with plain flexbox divs (bar height as a % of
# the tallest month) rather than a charting library - consistent with
# the rest of this app's no-external-JS-dependency approach (same
# reasoning as the inline SVG reward icon in app.py). Each bar carries
# its own peso value as a label printed right above it (ISESMO's
# request, Sept 22: "lagyan mo na din ng data labels") so the number is
# always visible without needing to hover/tap.
EXPENSES_TREND_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Expense Trends - Omega Ice</title>
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
.filter-row{display:grid;grid-template-columns:1fr 1fr;gap:8px}
label{font-size:12px;color:#666;display:block;margin:0 0 4px}
select{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:14px;font-family:inherit;background:#fff}
.total-card{background:linear-gradient(135deg,#00609C,#0f2942);color:#fff;border-radius:12px;padding:16px;margin-bottom:12px;text-align:center}
.total-card .amt{font-size:26px;font-weight:700}.total-card .lbl{font-size:11px;opacity:.9}
.chart-wrap{display:flex;align-items:flex-end;gap:4px;height:220px;padding:20px 4px 0;border-bottom:2px solid #e5e7eb}
.bar-col{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%;min-width:0}
.bar-label{font-size:9px;font-weight:700;color:#0f2942;margin-bottom:3px;white-space:nowrap;transform:rotate(0deg)}
.bar{width:70%;background:linear-gradient(180deg,#0096D6,#00609C);border-radius:4px 4px 0 0;min-height:2px;transition:height .3s ease}
.bar.zero{background:#e5e7eb}
.month-labels{display:flex;gap:4px;padding:6px 4px 0}
.month-labels span{flex:1;text-align:center;font-size:10px;color:#666;font-weight:600;min-width:0}
.empty{color:#888;text-align:center;padding:30px 10px;font-size:13px}
.status{font-size:12px;text-align:center;margin-top:8px;min-height:16px}.status.err{color:#c0392b}
</style></head>
<body>
<div class="topbar">
  <h1>📈 Expense Trends</h1>
  <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
    <a href="/expenses" class="nav-pill">← Expenses</a>
    <div class="menu-wrap">
      <button type="button" class="menu-btn" id="navMenuBtn" onclick="toggleNavMenu()" title="Menu">☰</button>
      <div class="menu-dropdown" id="navMenuDropdown">
        <a href="/home">🏠 Home</a>
        <a href="/machines">🏭 Machines</a>
        <a href="/credit">💳 Utang</a>
        <a href="/credit/history">🧾 Utang History</a>
        <a href="/expenses">💸 Expenses</a>
        <a href="/expenses/trend" class="active">📈 Expense Trends</a>
        <a href="/plastic">📦 Plastic</a>
        <a href="/assets">🏗️ Fixed Assets</a>
        <a href="/advance-orders">🎉 Advance Orders</a>
        <a href="/admin/duplicates">🔍 Duplicate Finder</a>
<a href="/prices">💰 Price Manager</a>
<a href="/ai-sales">🤖 Ask AI</a>
        <a href="/dashboard">📊 Dashboard</a>
      </div>
    </div>
  </div>
</div>

<div class="card">
  <div class="filter-row">
    <div>
      <label>Category</label>
      <select id="catSelect" onchange="loadTrend()">
        <option value="__all__">Lahat (All Categories)</option>
        {% for c in categories %}<option value="{{ c }}">{{ c }}</option>{% endfor %}
      </select>
    </div>
    <div>
      <label>Year</label>
      <select id="yearSelect" onchange="loadTrend()"></select>
    </div>
  </div>
</div>

<div class="total-card"><div class="amt" id="yearTotal">₱0</div><div class="lbl" id="yearTotalLbl">TOTAL FOR SELECTED YEAR</div></div>

<div class="card">
  <div id="chartArea">Loading...</div>
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

const START_YEAR = {{ start_year }};
const CURRENT_YEAR = {{ current_year }};

function escapeHtmlT(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }
function pesoShort(n){
  // Compact form for the small data-label above each bar - full centavos
  // there would crowd 12 bars on a phone screen; the total card above
  // the chart still shows the exact peso-and-centavos figure.
  n = Number(n) || 0;
  if(n >= 1000) return '₱' + (n/1000).toLocaleString('en-PH',{maximumFractionDigits:1}) + 'k';
  return '₱' + n.toLocaleString('en-PH',{maximumFractionDigits:0});
}

function initYearSelect(){
  const sel = document.getElementById('yearSelect');
  let opts = '';
  // Newest year first (most likely what ISESMO wants to check), but
  // never below START_YEAR (2025) - "2025 lang start ng business ko so
  // sa selection mag start ng 2025".
  for(let y = CURRENT_YEAR; y >= START_YEAR; y--){
    opts += `<option value="${y}" ${y===CURRENT_YEAR?'selected':''}>${y}</option>`;
  }
  sel.innerHTML = opts;
}

async function loadTrend(){
  const chartArea = document.getElementById('chartArea');
  const category = document.getElementById('catSelect').value;
  const year = document.getElementById('yearSelect').value;
  chartArea.innerHTML = 'Loading...';
  try{
    const res = await fetch(`/api/expenses/yearly_trend?category=${encodeURIComponent(category)}&year=${encodeURIComponent(year)}`);
    const data = await res.json();
    if(!data.ok){ chartArea.innerHTML = `<div class="empty">${escapeHtmlT(data.error||'Error')}</div>`; return; }

    document.getElementById('yearTotal').textContent = peso(data.year_total);
    document.getElementById('yearTotalLbl').textContent = `TOTAL - ${escapeHtmlT(data.category_label)} (${data.year})`;

    const months = data.months || [];
    const maxVal = Math.max(1, ...months.map(m => m.total));
    if(!months.some(m => m.total > 0)){
      chartArea.innerHTML = `<div class="empty">Walang na-record na expense para sa ${escapeHtmlT(data.category_label)} noong ${data.year}.</div>`;
      return;
    }

    let bars = '<div class="chart-wrap">';
    let labels = '<div class="month-labels">';
    months.forEach(m => {
      const pct = m.total > 0 ? Math.max(4, Math.round((m.total / maxVal) * 100)) : 0;
      bars += `<div class="bar-col" title="${escapeHtmlT(m.label)} ${data.year}: ${escapeHtmlT(peso(m.total))}">
        <div class="bar-label">${m.total > 0 ? escapeHtmlT(pesoShort(m.total)) : ''}</div>
        <div class="bar ${m.total===0?'zero':''}" style="height:${pct}%"></div>
      </div>`;
      labels += `<span>${escapeHtmlT(m.label)}</span>`;
    });
    bars += '</div>';
    labels += '</div>';
    chartArea.innerHTML = bars + labels;
  }catch(e){ chartArea.innerHTML = `<div class="empty">Error: ${escapeHtmlT(e.message)}</div>`; }
}

initYearSelect();
loadTrend();
</script>
</body></html>
"""


@expenses_bp.route("/expenses")
@login_required
def expenses_page():
    staff = (session.get("staff_name") or "").strip().lower()
    is_isesmo = staff in ["isesmo", "isesmo gamboa"]
    return render_template_string(EXPENSES_HTML, categories=EXPENSE_CATEGORIES, is_isesmo=is_isesmo)


TREND_START_YEAR = 2025  # business started 2025 - year dropdown never goes below this


@expenses_bp.route("/expenses/trend")
@login_required
def expenses_trend_page():
    current_year = max(datetime.now().year, TREND_START_YEAR)
    return render_template_string(
        EXPENSES_TREND_HTML,
        categories=EXPENSE_CATEGORIES,
        start_year=TREND_START_YEAR,
        current_year=current_year,
    )


MONTH_LABELS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


@expenses_bp.route("/api/expenses/yearly_trend")
@login_required
def api_expenses_yearly_trend():
    try:
        category = (request.args.get("category") or "").strip()
        if category != "__all__" and category not in EXPENSE_CATEGORIES:
            return jsonify({"ok": False, "error": "Invalid category"}), 400

        year_raw = (request.args.get("year") or "").strip()
        try:
            year = int(year_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid year"}), 400
        if year < TREND_START_YEAR or year > datetime.now().year:
            return jsonify({"ok": False, "error": "Year out of range"}), 400

        expenses = fb_get("expenses") or {}
        month_totals = [0.0] * 12
        for val in expenses.values():
            if not val:
                continue
            date_str = val.get("date") or ""
            # Expect "YYYY-MM-DD" - guard against malformed/partial dates
            if len(date_str) < 7 or not date_str.startswith(f"{year}-"):
                continue
            if category != "__all__" and val.get("category") != category:
                continue
            try:
                month_idx = int(date_str[5:7]) - 1
            except ValueError:
                continue
            if 0 <= month_idx < 12:
                month_totals[month_idx] += _effective_amount(val)

        months = [
            {"month": i + 1, "label": MONTH_LABELS[i], "total": round(month_totals[i], 2)}
            for i in range(12)
        ]
        year_total = round(sum(month_totals), 2)
        category_label = "Lahat (All Categories)" if category == "__all__" else category

        return jsonify({
            "ok": True,
            "category_label": category_label,
            "year": year,
            "months": months,
            "year_total": year_total,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


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

        entries = _split_electricity_portions(entry) if category == "Electricity" else [entry]
        recorded_by = session.get("staff_name")
        created_at = now_str()
        for e in entries:
            e["recorded_by"] = recorded_by
            e["created_at"] = created_at
            fb_post("expenses", e)

        return jsonify({"ok": True, "split": len(entries) > 1, "count": len(entries)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@expenses_bp.route("/api/expenses/<expense_id>", methods=["PUT"])
@login_required
def api_expenses_update(expense_id):
    """Edits exactly the one record being edited - it never re-splits
    across months. If a bill's date range is edited such that it now
    should be split differently, delete it and add it again instead so
    the split logic in POST runs fresh (safer than silently turning one
    edited record into two, or deleting its sibling automatically)."""
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
