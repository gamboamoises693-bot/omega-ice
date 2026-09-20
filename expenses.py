"""
Expense Tracking module.

Ported from the "ExpensesScreen" / "MonthlyExpensesSummaryScreen" +
expense_categories table idea in the user's separate Kivy desktop app
(OMEGA_PURIFIED.py). That version let the categories themselves be
edited (name/icon/color) in a whole extra table - simplified here to a
fixed preset list (still covers the same categories it defaulted to),
since a configurable-category-admin screen is a lot of extra surface
for very little real benefit on a small operation like this one.

Firebase data model (all new - nothing existing in app.py touches this):
  expenses/<auto_id> = {date, category, amount, note, recorded_by, created_at}

Routes:
  GET    /expenses                 - Expenses page: add form + this month's list + category totals
  GET    /api/expenses?month=YYYY-MM  - JSON: list for that month (default: current month) + totals
  POST   /api/expenses             - JSON: add an expense entry
  DELETE /api/expenses/<id>        - ISESMO only: remove an entry (e.g. a mistake/test entry)
"""
from datetime import datetime

from flask import Blueprint, request, jsonify, session, render_template_string

from modules.shared import fb_get, fb_post, fb_delete, login_required, isesmo_only, now_str, today_str

expenses_bp = Blueprint("expenses", __name__)

EXPENSE_CATEGORIES = ["Consumables", "Fuel", "Electricity", "Maintenance", "Fixed Asset", "Other"]


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
.cat-row{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-top:4px}
.cat-row button{padding:9px 4px;border-radius:8px;border:1px solid #ccd;background:#f5f5f5;font-size:11px}
.cat-row button.active{background:#00609C;color:#fff;border-color:#00609C}
.save-btn{width:100%;padding:13px;margin-top:14px;background:#00609C;color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:600}
.status{font-size:12px;text-align:center;margin-top:8px;min-height:16px}.status.err{color:#c0392b}.status.ok{color:#1a8a4a}
.month-nav{display:flex;align-items:center;justify-content:center;gap:14px;margin-bottom:10px}
.month-nav button{padding:8px 14px;border-radius:8px;border:1px solid #cde;background:#fff;color:#00609C;font-weight:700}
.month-nav .label{font-weight:700;color:#00609C;font-size:14px;min-width:120px;text-align:center}
.breakdown{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px}
.chip{padding:5px 10px;border-radius:14px;background:#eef4fb;color:#00609C;font-size:11px;font-weight:600}
.log-row{display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid #f0f4f8}
.log-meta{font-size:9px;color:#aaa;margin-top:2px}
.amt-pill{font-weight:700;color:#c0392b;white-space:nowrap}
.del-btn{background:none;border:none;color:#c0392b;font-size:16px;padding:2px 4px}
.empty{color:#888;text-align:center;padding:20px 10px;font-size:13px}
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
  <label>Date</label>
  <input type="date" id="expDate">
  <label>Category</label>
  <div class="cat-row" id="catRow"></div>
  <label>Amount (₱)</label>
  <input type="number" id="expAmount" placeholder="0.00" step="0.01" min="0.01">
  <label>Note (optional)</label>
  <textarea id="expNote" rows="2" placeholder="hal. gasolina delivery van..."></textarea>
  <button class="save-btn" onclick="submitExpense()">💾 Save Expense</button>
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

function escapeHtmlE(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }
function monthKey(d){ return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0'); }
function monthLabelText(d){ return d.toLocaleString('en-PH',{month:'long', year:'numeric'}); }

function initCatRow(){
  const row = document.getElementById('catRow');
  row.innerHTML = CATEGORIES.map(c => `<button type="button" data-c="${escapeHtmlE(c)}" onclick="selectCategory('${escapeHtmlE(c)}')" class="${c===selectedCategory?'active':''}">${escapeHtmlE(c)}</button>`).join('');
}
function selectCategory(c){
  selectedCategory = c;
  document.querySelectorAll('#catRow button').forEach(b => b.classList.toggle('active', b.dataset.c===c));
}

async function submitExpense(){
  const date = document.getElementById('expDate').value;
  const amount = parseFloat(document.getElementById('expAmount').value);
  const note = document.getElementById('expNote').value.trim();
  const st = document.getElementById('expStatus');
  if(!date){ st.textContent = 'Pumili ng date.'; st.className = 'status err'; return; }
  if(!amount || amount <= 0){ st.textContent = 'Ilagay ang valid na amount.'; st.className = 'status err'; return; }
  st.textContent = 'Saving...'; st.className = 'status';
  try{
    const res = await fetch('/api/expenses', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({date, category: selectedCategory, amount, note})
    });
    const data = await res.json();
    if(data.ok){
      st.textContent = 'Na-save!'; st.className = 'status ok';
      document.getElementById('expAmount').value = '';
      document.getElementById('expNote').value = '';
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
    if(!rows.length){
      wrap.innerHTML = '<div class="empty">Walang expense na naka-record sa buwan na ito.</div>';
      return;
    }
    wrap.innerHTML = rows.map(r => `
      <div class="log-row">
        <div>
          <div style="font-weight:600">${escapeHtmlE(r.category)}</div>
          ${r.note ? `<div class="log-meta">${escapeHtmlE(r.note)}</div>` : ''}
          <div class="log-meta">${escapeHtmlE(r.date)} • ni ${escapeHtmlE(r.recorded_by||'-')}</div>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="amt-pill">${peso(r.amount)}</div>
          ${IS_ISESMO ? `<button class="del-btn" onclick="deleteExpense('${r.id}')">🗑️</button>` : ''}
        </div>
      </div>
    `).join('');
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

document.getElementById('expDate').value = new Date().toISOString().slice(0,10);
initCatRow();
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
        total = sum(float(r.get("amount") or 0) for r in rows)
        by_category = {}
        for r in rows:
            cat = r.get("category") or "Other"
            by_category[cat] = round(by_category.get(cat, 0) + float(r.get("amount") or 0), 2)
        return jsonify({"ok": True, "rows": rows, "total": round(total, 2), "by_category": by_category})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@expenses_bp.route("/api/expenses", methods=["POST"])
@login_required
def api_expenses_add():
    try:
        data = request.json or {}
        date = (data.get("date") or "").strip() or today_str()
        category = (data.get("category") or "Other").strip()
        try:
            amount = float(data.get("amount"))
        except (TypeError, ValueError):
            amount = 0
        note = (data.get("note") or "").strip()
        if amount <= 0:
            return jsonify({"ok": False, "error": "Invalid amount"}), 400
        entry = {
            "date": date,
            "category": category,
            "amount": amount,
            "note": note,
            "recorded_by": session.get("staff_name"),
            "created_at": now_str(),
        }
        fb_post("expenses", entry)
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
