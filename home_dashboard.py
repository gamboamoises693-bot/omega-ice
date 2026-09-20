"""
modules/home_dashboard.py

New "Main Form" / home landing page for Omega Ice - a dashboard-style
page shown right after login (app.py's "/" route now redirects here
instead of straight to /cashier), kept SEPARATE from the Sales entry
page (/cashier stays its own dedicated page, reachable from the
hamburger dropdown / a "Go to Sales" button here).

Boss's request (verbatim): "Gawa nalang kaya tayo ng bagong main form
boss na nakahiwalay din ang sales. S main form ay parang sa
pangatlong image. check mo yung pgm ko dati para may reference ka."

Reference material checked before building this:
  - OMEGA_PURIFIED.py -> class DashboardScreen (the Kivy screen this
    page is modeled after - same FILTER DASHBOARD control, same
    SALES DATA / NET PROFIT / EXPENSES / CREDIT cards, same
    "Include Fixed Asset" toggle, same EXPENSES BREAKDOWN list).
  - MY_DASHBOARD.html / Montly_Dash.html - these turned out to be
    rendered EXPORTS of a Claude-made React artifact (a bundled,
    minified JS build, not editable source), not hand-written
    reference code. The 3rd screenshot the user showed IS a
    screenshot of that exported page. Since the bundle isn't
    meaningfully readable, this page was built to match what the
    screenshot actually shows, using the *real* formulas from the
    Kivy DashboardScreen.on_enter() (which the screenshot's numbers
    ultimately come from anyway).

WHAT WAS KEPT vs DROPPED from the original Kivy screen, and why:

KEPT (same formulas/fields as DashboardScreen.on_enter()):
  - FILTER DASHBOARD: same 3 search modes -
      "%" (or blank/"all"/"all time"/etc) -> ALL TIME
      "YYYY"                              -> one YEAR
      "YYYY-MM" (default: current month)  -> one MONTH
    See _resolve_period() below - same rules as the original's
    load_dashboard_month()/on_enter() mode-detection block.
  - SALES DATA card: total pesos + qty + transaction count for the
    period, plus 1/5/10/25kg breakdown. Pulled from the same
    `daily_sales` Firebase node the rest of the app already uses
    (mirrors /api/sales/month/<month_str>'s own filtering rules:
    skip archived-and-not-include_in_all_time rows, only count
    Delivered/Out for Delivery orders).
  - NET PROFIT / EXPENSES / CREDIT KPI row - identical formulas to
    the original's update_ui(): `net = total_sales - total_exp`,
    `margin = net/total_sales*100`.
  - EXPENSES BREAKDOWN by category with % and peso amount, same idea
    as load_expense_breakdown() (SUM grouped by category, sorted
    descending, with a TOTAL row at the bottom).
  - "Include Fixed Asset (Machine + Freezer)" ON/OFF toggle - same
    idea as the original's toggle_dash_fixed(). IMPORTANT DIFFERENCE:
    in the ORIGINAL, fixed-asset depreciation was written as literal
    rows straight into the `expenses` table (category LIKE '%Fix%'),
    so the toggle just added `AND category NOT LIKE '%Fix%'` to a
    plain SQL SUM. Our modules/expenses.py deliberately does NOT do
    that (see that module's own docstring - it would spam 60+ rows
    per asset into Firebase for no reason). So here, the fixed-asset
    amount for the selected period is instead computed LIVE from the
    `fixed_assets` node using the exact same monthly_depreciation
    math modules/fixed_assets.py already uses (_asset_metrics), and
    it's added on top of the Consumables/Fuel/Electricity/
    Maintenance total only when the toggle is ON. See
    `_fixed_asset_expense_for_period()` below - it recognizes exactly
    one monthly_depreciation "hit" per calendar month an asset was in
    service (from its purchase month up to total_months later, or up
    to its sale month if it was sold), which is the correct accrual
    version of what the original's pre-generated 60-row schedule
    was approximating.
  - Credit total = SUM of every reseller's credit_balance, with NO
    date filter - matches the original exactly (its SQL has no WHERE
    clause on that query in any of the 3 modes, so "Utang" is always
    an as-of-today snapshot regardless of which period is selected).

DROPPED (Android/Kivy-only, doesn't apply to a web app):
  - The "CONNECT TO DASHBOARD / MY DASHBOARD.html / SELECT / OPEN
    CHROME" widget. In the original this spun up a local HTTP server
    on the phone and opened a separate HTML file the user picked from
    phone storage via a Chrome intent - a workaround for Kivy not
    being able to render rich web content itself. None of that
    applies here: this Flask page IS the dashboard, so there's
    nothing external to "connect" to.
"""
import re
from datetime import datetime

from flask import Blueprint, request, jsonify, session, render_template_string

from modules.shared import fb_get, login_required, today_str
from modules.expenses import _effective_amount
from modules.fixed_assets import _asset_metrics, DEFAULT_TOTAL_MONTHS

home_bp = Blueprint("home_dashboard", __name__)


# ---------- Period resolution (mirrors DashboardScreen's mode rules) ----------

def _resolve_period(raw):
    """Returns (mode, prefix, display).

    mode:    "all" | "year" | "month"
    prefix:  string to match a YYYY-MM-DD date against with
             .startswith() - "" for all-time, "YYYY" for a year,
             "YYYY-MM" for a month.
    display: what to show the user (e.g. "2026-09", "2026", "ALL TIME").
    """
    raw = (raw or "").strip()
    low = raw.lower()
    if "%" in raw or low in ["", "all", "all%", "%%", "*", "all time", "all db"]:
        return "all", "", "ALL TIME"
    if re.match(r"^\d{4}$", raw):
        return "year", raw, raw
    if raw.endswith("-%"):
        year = raw.split("-")[0]
        return "year", year, year
    if len(raw) >= 7 and "-" in raw:
        month = raw[:7]
        return "month", month, month
    # Anything unrecognized falls back to the current month, same as
    # the original defaulting to self.selected_dashboard_month.
    month = today_str()[:7]
    return "month", month, month


def _parse_date(s):
    try:
        return datetime.strptime((s or "").strip(), "%Y-%m-%d")
    except (TypeError, ValueError):
        return None


# ---------- Sales ----------

def _sales_totals(mode, prefix):
    sales = fb_get("daily_sales") or {}
    total_sales = 0.0
    total_qty = 0
    total_trans = 0
    kg_map = {"1Kg": 0, "5Kg": 0, "10Kg": 0, "25Kg": 0}
    for _, v in sales.items():
        if not v:
            continue
        if v.get("archived") and not v.get("include_in_all_time"):
            continue
        sd = (v.get("sales_date") or "")[:10]
        if mode != "all" and not sd.startswith(prefix):
            continue
        status = v.get("order_status") or "Delivered"
        if status not in ["Delivered", "Out for Delivery"]:
            continue
        qty = int(v.get("quantity") or 0)
        kg_size = v.get("kg_size") or "1Kg"
        peso = float(v.get("total_sales") or 0)
        total_sales += peso
        total_qty += qty
        total_trans += 1
        if kg_size in kg_map:
            kg_map[kg_size] += qty
    return round(total_sales, 2), total_qty, total_trans, kg_map


# ---------- Operating expenses (Consumables/Fuel/Electricity/Maintenance) ----------

def _expense_breakdown(mode, prefix):
    expenses = fb_get("expenses") or {}
    by_cat = {}
    for _, v in expenses.items():
        if not v:
            continue
        d = (v.get("date") or "")[:10]
        if mode != "all" and not d.startswith(prefix):
            continue
        cat = v.get("category") or "Other"
        by_cat[cat] = round(by_cat.get(cat, 0) + _effective_amount(v), 2)
    return by_cat


# ---------- Fixed-asset depreciation, recomputed live for the period ----------

def _month_in_service(asset, ym):
    """True if `asset` recognizes one month of depreciation in
    calendar month `ym` ("YYYY-MM"): from its purchase month through
    total_months later, stopping early at its sale month if sold."""
    purchase_dt = _parse_date(asset.get("purchase_date"))
    if not purchase_dt:
        return False
    total_months = int(asset.get("total_months") or DEFAULT_TOTAL_MONTHS) or DEFAULT_TOTAL_MONTHS
    try:
        y, m = int(ym[:4]), int(ym[5:7])
    except (ValueError, IndexError):
        return False
    month_index = (y - purchase_dt.year) * 12 + (m - purchase_dt.month) + 1
    if month_index < 1 or month_index > total_months:
        return False
    if asset.get("status") == "sold" and asset.get("sale_date"):
        sale_dt = _parse_date(asset.get("sale_date"))
        if sale_dt and (y, m) > (sale_dt.year, sale_dt.month):
            return False
    return True


def _fixed_asset_expense_for_period(mode, prefix):
    assets = fb_get("fixed_assets") or {}
    total = 0.0
    if mode == "all":
        # All-time = every asset's accumulated depreciation as of now
        # (or as of sale date, once sold) - same live formula
        # modules/fixed_assets.py already uses for book value.
        for a in assets.values():
            if not a:
                continue
            total += _asset_metrics(a)["accumulated_depreciation"]
        return round(total, 2)

    if mode == "month":
        months_to_check = [prefix]
    else:  # year
        months_to_check = ["%s-%02d" % (prefix, m) for m in range(1, 13)]

    for a in assets.values():
        if not a:
            continue
        monthly = _asset_metrics(a)["monthly_depreciation"]
        for ym in months_to_check:
            if _month_in_service(a, ym):
                total += monthly
    return round(total, 2)


# ---------- Credit (no date filter - always an as-of-today snapshot) ----------

def _credit_total():
    resellers = fb_get("resellers") or {}
    return round(sum(float(v.get("credit_balance") or 0) for v in resellers.values() if v), 2)


@home_bp.route("/home")
@login_required
def home_page():
    return render_template_string(HOME_HTML, default_period=today_str()[:7])


@home_bp.route("/api/home/summary")
@login_required
def api_home_summary():
    raw = (request.args.get("period") or today_str()[:7]).strip()
    include_fixed = request.args.get("include_fixed", "1") != "0"
    mode, prefix, display = _resolve_period(raw)

    total_sales, total_qty, total_trans, kg_map = _sales_totals(mode, prefix)
    by_cat = _expense_breakdown(mode, prefix)
    operating_exp = round(sum(by_cat.values()), 2)
    fixed_amt = _fixed_asset_expense_for_period(mode, prefix) if include_fixed else 0.0
    if fixed_amt > 0:
        by_cat = dict(by_cat)
        by_cat["Fixed Asset Depreciation"] = fixed_amt
    total_exp = round(operating_exp + fixed_amt, 2)

    total_credit = _credit_total()

    net = round(total_sales - total_exp, 2)
    margin = round((net / total_sales * 100), 1) if total_sales > 0 else 0.0

    cat_rows = sorted(by_cat.items(), key=lambda kv: kv[1], reverse=True)
    pct_base = sum(v for _, v in cat_rows) or 1
    breakdown = [
        {"category": c, "amount": round(v, 2), "pct": round(v / pct_base * 100, 1)}
        for c, v in cat_rows
    ]

    return jsonify({
        "ok": True,
        "mode": mode,
        "period": raw,
        "display": display,
        "sales": {
            "total": total_sales,
            "qty": total_qty,
            "transactions": total_trans,
            "kg": kg_map,
        },
        "net_profit": net,
        "margin": margin,
        "expenses": {
            "total": total_exp,
            "operating": operating_exp,
            "fixed_asset": fixed_amt,
            "breakdown": breakdown,
        },
        "credit": total_credit,
    })


HOME_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Home - Omega Ice</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:0 12px 16px}
.menu-wrap{position:relative}
.menu-btn{width:44px;height:44px;border-radius:12px;font-size:18px;border:1px solid rgba(255,255,255,.35);background:rgba(255,255,255,.15);color:#fff;display:flex;align-items:center;justify-content:center;cursor:pointer}
.menu-btn.open{background:#fff;color:#00609C}
.menu-dropdown{display:none;position:absolute;top:calc(100% + 6px);left:0;background:#fff;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,.18);min-width:190px;z-index:60;overflow:hidden;border:1px solid #e5e7eb}
.menu-dropdown.show{display:block}
.menu-dropdown a{display:flex;align-items:center;gap:10px;padding:13px 16px;font-size:13px;color:#333;text-decoration:none;border-bottom:1px solid #f0f4f8;font-weight:600}
.menu-dropdown a:last-child{border-bottom:none}
.menu-dropdown a:hover,.menu-dropdown a:active{background:#eef7ff;color:#00609C}
.menu-dropdown a.active{background:#eef7ff;color:#00609C}
.header-card{background:linear-gradient(135deg,#00609C,#0a7fc7);border-radius:0 0 20px 20px;padding:16px;margin:0 -12px 14px;color:#fff}
.header-top{display:flex;gap:14px;align-items:flex-start}
.header-text{display:flex;flex-direction:column;gap:2px}
.app-title{font-size:17px;font-weight:700}
.app-tagline{font-size:12px;opacity:.9}
.header-date{font-size:10px;opacity:.75;margin-top:4px}
.header-time{font-size:11px;font-weight:700;opacity:1}
.header-dev{font-size:9px;opacity:.5;margin-top:2px}
.card{background:#fff;border-radius:16px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.card-title-row{display:flex;align-items:center;gap:6px;margin-bottom:6px}
.card-title{font-size:10px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.02em}
.hint{font-size:8px;color:#999;margin-bottom:8px}
.filter-row{display:flex;gap:6px;flex-wrap:wrap}
.filter-row input{flex:1 1 70px;min-width:0;padding:10px 6px;border-radius:8px;border:1px solid #ccd;font-size:15px;text-align:center}
.filter-row button{flex:0 0 auto;border:none;border-radius:8px;font-weight:700;font-size:11px;color:#fff;cursor:pointer;padding:10px 12px;white-space:nowrap}
.btn-search{background:#00609C}
.btn-today{background:#26a34a}
.sales-btn-row{margin-bottom:12px}
.go-sales-btn{display:block;width:100%;text-align:center;text-decoration:none;background:#fff;color:#00609C;border:2px dashed #9cc9ea;border-radius:14px;padding:12px;font-weight:700;font-size:13px}
.toggle-card{background:#e9fcef;border-radius:12px;padding:10px 12px;display:flex;align-items:center;gap:10px;margin-bottom:12px;cursor:pointer;font-weight:700;font-size:11px;color:#111}
.toggle-card.off{background:#fdeaea}
.toggle-dot{width:18px;height:18px;border-radius:50%;background:#1a8a4a;flex:0 0 auto}
.toggle-card.off .toggle-dot{background:#c0392b}
.perf-label{font-size:10px;font-weight:700;color:#666;margin:4px 0 8px}
.sales-card{background:linear-gradient(135deg,#13a0ec,#0a7fc7);border-radius:18px;padding:16px;color:#fff;margin-bottom:12px}
.sales-top{font-size:10px;font-weight:700;opacity:.95;margin-bottom:4px}
.sales-val{font-size:28px;font-weight:700}
.sales-sub{font-size:9px;opacity:.85;margin-top:4px}
.sales-breakdown{font-size:9px;font-weight:700;margin-top:6px}
.sales-margin{font-size:10px;font-weight:700;color:#fff9c4;margin-top:6px}
.kpi-row{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px}
.kpi-card{border-radius:14px;padding:10px;text-align:left}
.kpi-card.net{background:#f2fdf5}
.kpi-card.exp{background:#fff5ef}
.kpi-card.credit{background:#fdf0f0}
.kpi-head{font-size:8px;font-weight:700;color:#888;margin-bottom:4px}
.kpi-val{font-size:15px;font-weight:700}
.kpi-card.net .kpi-val{color:#166534}
.kpi-card.exp .kpi-val{color:#c2410c}
.kpi-card.credit .kpi-val{color:#b91c1c}
.kpi-sub{font-size:9px;font-weight:700;margin-top:2px}
.kpi-card.net .kpi-sub{color:#1a8a4a}
.break-row{display:flex;justify-content:space-between;align-items:center;background:#f7f8fa;border-radius:10px;padding:9px 10px;margin-bottom:6px;font-size:11px}
.break-cat{font-weight:700;flex:1}
.break-pct{color:#666;font-weight:700;width:44px;text-align:center}
.break-amt{font-weight:700;width:80px;text-align:right}
.break-total-row{display:flex;justify-content:space-between;background:#fde8e8;border-radius:10px;padding:9px 10px;font-weight:700;font-size:12px;color:#c0392b}
.empty{color:#888;text-align:center;padding:16px;font-size:12px}
</style></head>
<body>

<div class="header-card">
  <div class="header-top">
    <div class="menu-wrap">
      <button type="button" class="menu-btn" id="navMenuBtn" onclick="toggleNavMenu()" title="Menu">☰</button>
      <div class="menu-dropdown" id="navMenuDropdown">
        <a href="/home" class="active">🏠 Home</a>
        <a href="/cashier">🧊 Sales</a>
        <a href="/machines">🏭 Machines</a>
        <a href="/credit">💳 Utang</a>
        <a href="/credit/history">🧾 Utang History</a>
        <a href="/expenses">💸 Expenses</a>
        <a href="/plastic">📦 Plastic</a>
        <a href="/assets">🏗️ Fixed Assets</a>
        <a href="/dashboard">📊 Dashboard</a>
      </div>
    </div>
    <div class="header-text">
      <div class="app-title">OMEGA PURIFIED ICE CUBES</div>
      <div class="app-tagline">The Pure Choice. OMEGA ICE.</div>
      <div class="header-date" id="headerDate"></div>
      <div class="header-time" id="headerTime"></div>
      <div class="header-dev">Developed by: Moises Gamboa</div>
    </div>
  </div>
</div>

<div class="sales-btn-row"><a href="/cashier" class="go-sales-btn">🧊 GO TO SALES ENTRY →</a></div>

<div class="card">
  <div class="card-title-row">🔎 <span class="card-title">Filter Dashboard</span></div>
  <div class="hint">Type: % = ALL | YYYY = Year | YYYY-MM = Month</div>
  <div class="filter-row">
    <input id="periodInput" value="{{ default_period }}">
    <button class="btn-search" onclick="searchPeriod()">SEARCH</button>
    <button class="btn-today" onclick="setToday()">TODAY</button>
  </div>
</div>

<div class="toggle-card" id="fixedToggleBox" onclick="toggleFixedAsset()">
  <div class="toggle-dot"></div>
  <span id="fixedToggleLbl">Include Fixed Asset (Machine + Freezer) - ON</span>
</div>

<div class="perf-label" id="perfLabel">{{ default_period }} PERFORMANCE - MONTH MODE</div>

<div class="sales-card">
  <div class="sales-top">📟 SALES DATA</div>
  <div class="sales-val" id="salesVal">₱0</div>
  <div class="sales-sub" id="salesDays">0 transactions • 0kg</div>
  <div class="sales-breakdown" id="salesBreakdown">1kg:0 | 5kg:0 | 10kg:0 | 25kg:0</div>
  <div class="sales-margin" id="profitMarginLbl">Margin: 0% - ₱0 Net</div>
</div>

<div class="kpi-row">
  <div class="kpi-card net">
    <div class="kpi-head">NET PROFIT</div>
    <div class="kpi-val" id="netVal">₱0</div>
    <div class="kpi-sub" id="marginVal">0% Margin</div>
  </div>
  <div class="kpi-card exp">
    <div class="kpi-head">EXPENSES</div>
    <div class="kpi-val" id="expVal">₱0</div>
    <div class="kpi-sub">&nbsp;</div>
  </div>
  <div class="kpi-card credit">
    <div class="kpi-head">CREDIT</div>
    <div class="kpi-val" id="creditVal">₱0</div>
    <div class="kpi-sub">&nbsp;</div>
  </div>
</div>

<div class="card">
  <div class="card-title-row">
    <span class="card-title">📊 Expenses Breakdown</span>
    <span style="margin-left:auto;font-weight:700;color:#c0392b;font-size:11px" id="expBreakTotal">₱0</span>
  </div>
  <div class="hint">Category • Percentage • Amount</div>
  <div id="expBreakList"><div class="empty">Loading...</div></div>
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

const DEFAULT_PERIOD = {{ default_period|tojson }};
let currentPeriod = DEFAULT_PERIOD;
let includeFixed = true;

function updateClock(){
  const now = new Date();
  document.getElementById('headerDate').textContent = now.toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'});
  document.getElementById('headerTime').textContent = now.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'}) + ' - Real Time';
}
setInterval(updateClock, 1000);
updateClock();

function peso(n){
  return '₱' + Number(n||0).toLocaleString('en-US',{maximumFractionDigits:0});
}
function escapeHtml(s){
  return String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function loadSummary(){
  document.getElementById('perfLabel').textContent = 'Loading...';
  try{
    const res = await fetch(`/api/home/summary?period=${encodeURIComponent(currentPeriod)}&include_fixed=${includeFixed?1:0}`);
    const data = await res.json();
    if(!data.ok){ document.getElementById('perfLabel').textContent = 'Error loading data'; return; }
    document.getElementById('perfLabel').textContent = `${data.display} PERFORMANCE - ${data.mode.toUpperCase()} MODE`;
    document.getElementById('salesVal').textContent = peso(data.sales.total);
    document.getElementById('salesDays').textContent = `${data.sales.transactions} transactions • ${data.sales.qty}kg`;
    const kg = data.sales.kg || {};
    document.getElementById('salesBreakdown').textContent = `1kg:${kg['1Kg']||0} | 5kg:${kg['5Kg']||0} | 10kg:${kg['10Kg']||0} | 25kg:${kg['25Kg']||0}`;
    document.getElementById('netVal').textContent = peso(data.net_profit);
    document.getElementById('marginVal').textContent = `${data.margin}% Margin`;
    document.getElementById('expVal').textContent = peso(data.expenses.total);
    document.getElementById('creditVal').textContent = peso(data.credit);
    document.getElementById('profitMarginLbl').textContent = `Margin: ${data.margin}% - ${peso(data.net_profit)} Net`;
    document.getElementById('expBreakTotal').textContent = `${peso(data.expenses.total)} • ${data.mode.toUpperCase()}`;
    renderBreakdown(data.expenses.breakdown, data.expenses.total);
  }catch(e){
    document.getElementById('perfLabel').textContent = 'Error: ' + e.message;
  }
}

function renderBreakdown(rows, total){
  const wrap = document.getElementById('expBreakList');
  if(!rows || !rows.length){
    wrap.innerHTML = '<div class="empty">No expenses found</div>';
    return;
  }
  let html = rows.map(r => `
    <div class="break-row">
      <span class="break-cat">${escapeHtml(r.category)}</span>
      <span class="break-pct">${r.pct}%</span>
      <span class="break-amt">${peso(r.amount)}</span>
    </div>`).join('');
  html += `<div class="break-total-row"><span>TOTAL EXPENSES</span><span>${peso(total)}</span></div>`;
  wrap.innerHTML = html;
}

function searchPeriod(){
  const v = document.getElementById('periodInput').value.trim();
  currentPeriod = v || DEFAULT_PERIOD;
  loadSummary();
}
function setToday(){
  currentPeriod = DEFAULT_PERIOD;
  document.getElementById('periodInput').value = currentPeriod;
  loadSummary();
}
function toggleFixedAsset(){
  includeFixed = !includeFixed;
  const box = document.getElementById('fixedToggleBox');
  const lbl = document.getElementById('fixedToggleLbl');
  if(includeFixed){
    box.classList.remove('off');
    lbl.textContent = 'Include Fixed Asset (Machine + Freezer) - ON';
  } else {
    box.classList.add('off');
    lbl.textContent = 'Include Fixed Asset (Machine + Freezer) - OFF';
  }
  loadSummary();
}

loadSummary();
</script>
</body></html>
"""
