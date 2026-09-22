"""
Duplicate Order Finder module.

WHY THIS EXISTS: the Sept 22 fix (10-second same-reseller/qty/kg_size/
mode/payment/sales_date guard in api_customer_place_order) only stops
NEW duplicate orders from being created going forward. It does nothing
for duplicate rows that were already sitting in daily_sales BEFORE that
fix shipped - like the Sept 6 batch ISESMO first reported, and possibly
similar batches for other resellers/dates that were never individually
checked. This module is a reusable admin tool to find and clean up
THAT kind of pre-existing duplicate data, any time it's needed again -
not a one-off script, since there is no guarantee Sept 6 is the only
date this ever happened on.

DETECTION APPROACH: group daily_sales rows (excluding already
soft-deleted ones) by (reseller_id-or-name, quantity, kg_size, mode,
payment, sales_date). Any group with more than one row is a
"candidate" duplicate - NOT auto-deleted, because a reseller placing
the same qty/kg_size twice in one day can be perfectly legitimate (e.g.
a morning restock and an afternoon top-up). To help staff judge which
groups are real accidents vs real repeat orders, each group is flagged
"high_confidence" when the gap between two of its orders' created_at
timestamps is under 60 seconds - that gap is what a double-tap/retry
actually looks like, while a real second order later in the day won't
have it. Staff still make the final call and pick exactly which rows
to delete.

Firebase data model (new):
  daily_sales_dup_ignore/<hash-of-group-key> = {
    group_key: str, dismissed_by: str, dismissed_at: str
  }
  Lets staff mark a group "not actually a duplicate" so it stops
  showing up on every future scan (e.g. a reseller who legitimately
  orders the same 10Kg twice a day, every day).

Routes:
  GET    /admin/duplicates                    - Duplicate Finder page
  GET    /api/admin/duplicates                - JSON: candidate duplicate groups
  POST   /api/admin/duplicates/dismiss         - mark a group as "not a duplicate"
  DELETE /api/admin/duplicates/dismiss/<hash>  - undo a dismiss
  POST   /api/admin/duplicates/delete          - ISESMO only: delete specific sale rows
"""
import hashlib
from datetime import datetime

from flask import Blueprint, request, jsonify, session, render_template_string

from modules.shared import fb_get, fb_post, fb_patch, fb_delete, login_required, isesmo_only, now_str

duplicate_finder_bp = Blueprint("duplicate_finder", __name__)


def _group_key_hash(group_key):
    return hashlib.md5(group_key.encode("utf-8")).hexdigest()


def _find_duplicate_groups(include_dismissed=False):
    ignored = fb_get("daily_sales_dup_ignore") or {}
    # NOTE: the mock/real Firebase delete leaves a None placeholder at
    # the path rather than removing the key outright in some SDK paths,
    # so filter on truthy VALUES, not just key presence - same pattern
    # every other loop over Firebase data in this app already follows
    # ("if not val: continue").
    ignored_hashes = {k for k, v in ignored.items() if v}

    sales = fb_get("daily_sales") or {}
    buckets = {}
    for key, val in sales.items():
        if not val or val.get("deleted"):
            continue
        rid = val.get("reseller_id") or ""
        rname = (val.get("reseller_name") or "").strip().lower()
        group_key = "|".join([
            str(rid or rname),
            str(val.get("quantity")),
            str(val.get("kg_size")),
            str(val.get("mode") or ""),
            str(val.get("payment") or ""),
            str(val.get("sales_date") or ""),
        ])
        row = dict(val)
        row["id"] = key
        buckets.setdefault(group_key, []).append(row)

    results = []
    for group_key, rows in buckets.items():
        if len(rows) < 2:
            continue
        gk_hash = _group_key_hash(group_key)
        is_dismissed = gk_hash in ignored_hashes
        if is_dismissed and not include_dismissed:
            continue

        rows.sort(key=lambda r: r.get("created_at") or "")
        gaps = []
        for i in range(1, len(rows)):
            try:
                t1 = datetime.strptime(rows[i - 1].get("created_at") or "", "%Y-%m-%d %H:%M:%S")
                t2 = datetime.strptime(rows[i].get("created_at") or "", "%Y-%m-%d %H:%M:%S")
                gaps.append((t2 - t1).total_seconds())
            except (TypeError, ValueError):
                continue
        min_gap = min(gaps) if gaps else None
        high_confidence = min_gap is not None and min_gap < 60

        extras_total = round(sum(float(r.get("total_sales") or 0) for r in rows[1:]), 2)
        results.append({
            "group_key": group_key,
            "group_hash": gk_hash,
            "is_dismissed": is_dismissed,
            "reseller_id": rows[0].get("reseller_id"),
            "reseller_name": rows[0].get("reseller_name") or "(walang pangalan)",
            "sales_date": rows[0].get("sales_date"),
            "quantity": rows[0].get("quantity"),
            "kg_size": rows[0].get("kg_size"),
            "mode": rows[0].get("mode"),
            "payment": rows[0].get("payment"),
            "count": len(rows),
            "high_confidence": high_confidence,
            "min_gap_seconds": min_gap,
            "extras_total": extras_total,
            "orders": rows,
        })

    # High-confidence groups first, then most recent sales_date first.
    results.sort(key=lambda g: (g["high_confidence"], g["sales_date"] or ""), reverse=True)
    return results


# =================================================================
# STAFF PAGE
# =================================================================
DUPLICATE_FINDER_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Duplicate Finder - Omega Ice</title>
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
.summary-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}
.summary-tile{text-align:center;padding:10px}
.summary-val{font-size:20px;font-weight:800;color:#00609C}.summary-val.warn{color:#c0392b}
.summary-lbl{font-size:9px;color:#888;margin-top:2px}
.opt-row{display:flex;gap:14px;font-size:12px;color:#444;flex-wrap:wrap;margin-bottom:4px}
.opt-row label{display:flex;align-items:center;gap:6px;cursor:pointer}
.grp-card{background:#fff;border-left:4px solid #c0392b;border-radius:8px;padding:12px;margin-bottom:10px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.grp-card.review{border-left-color:#f59e0b}
.grp-card.dismissed{border-left-color:#aaa;opacity:.6}
.grp-head{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
.grp-title{font-weight:700;font-size:13px;color:#0f2942}
.grp-sub{font-size:11px;color:#888;margin-top:2px}
.badge{padding:3px 9px;border-radius:12px;font-size:9px;font-weight:700;white-space:nowrap}
.badge.high{background:#fee2e2;color:#991b1b}.badge.review{background:#fef3c7;color:#92400e}.badge.dismissed{background:#eee;color:#666}
.order-row{display:flex;align-items:center;gap:8px;padding:8px 0;border-top:1px solid #f0f4f8;font-size:12px}
.order-row .tag-keep{background:#dcfce7;color:#166534;font-size:9px;font-weight:700;padding:2px 7px;border-radius:8px}
.order-row .tag-extra{background:#fee2e2;color:#991b1b;font-size:9px;font-weight:700;padding:2px 7px;border-radius:8px}
.grp-actions{display:flex;gap:6px;margin-top:10px;flex-wrap:wrap}
.grp-actions button{padding:8px 12px;border-radius:8px;border:none;font-size:11px;font-weight:700}
.btn-del{background:#fee2e2;color:#991b1b}.btn-dismiss{background:#f0f4f8;color:#555}.btn-undismiss{background:#dbeafe;color:#1e40af}
.empty{color:#888;text-align:center;padding:30px 10px;font-size:13px}
.hint{font-size:11px;color:#888;margin-top:-4px;margin-bottom:10px}
</style></head>
<body>
<div class="topbar">
  <h1>🔍 Duplicate Finder</h1>
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
        <a href="/advance-orders">🎉 Advance Orders</a>
        <a href="/admin/duplicates" class="active">🔍 Duplicate Finder</a>
        <a href="/dashboard">📊 Dashboard</a>
      </div>
    </div>
  </div>
</div>

<div class="card">
  <div class="summary-grid">
    <div class="summary-tile"><div class="summary-val" id="sumGroups">0</div><div class="summary-lbl">DUPLICATE GROUPS</div></div>
    <div class="summary-tile"><div class="summary-val warn" id="sumImpact">₱0</div><div class="summary-lbl">HALAGA NG POSIBLENG SOBRA</div></div>
  </div>
</div>

<div class="card">
  <div class="opt-row">
    <label><input type="checkbox" id="optHighOnly" checked onchange="renderGroups()"> Ipakita lang HIGH CONFIDENCE (within 60 sec)</label>
    <label><input type="checkbox" id="optShowDismissed" onchange="loadGroups()"> Ipakita rin ang mga na-dismiss</label>
  </div>
  <p class="hint">HIGH CONFIDENCE = dalawang order na sunod-sunod (loob ng 60 segundo) - mukhang double-tap talaga. Ang iba ay "Review" - baka totoong hiwalay na order lang (hal. umaga at hapon parehong 10Kg).</p>
</div>

<div id="listWrap">Loading...</div>

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
let allGroups = [];

function escapeHtmlD(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }

async function loadGroups(){
  const showDismissed = document.getElementById('optShowDismissed').checked;
  try{
    const res = await fetch(`/api/admin/duplicates?include_dismissed=${showDismissed ? 1 : 0}`);
    if(res.status===401){ window.location.href='/login'; return; }
    const data = await res.json();
    if(!data.ok){ document.getElementById('listWrap').innerHTML = `<div class="empty">${escapeHtmlD(data.error||'Error')}</div>`; return; }
    allGroups = data.groups || [];
    const activeOnes = allGroups.filter(g => !g.is_dismissed);
    document.getElementById('sumGroups').textContent = activeOnes.length;
    document.getElementById('sumImpact').textContent = peso(activeOnes.reduce((s,g) => s + (g.extras_total||0), 0));
    renderGroups();
  }catch(e){
    document.getElementById('listWrap').innerHTML = `<div class="empty">Error: ${escapeHtmlD(e.message)}</div>`;
  }
}

function renderGroups(){
  const wrap = document.getElementById('listWrap');
  const highOnly = document.getElementById('optHighOnly').checked;
  let rows = allGroups.slice();
  if(highOnly) rows = rows.filter(g => g.high_confidence || g.is_dismissed);
  if(!rows.length){ wrap.innerHTML = '<div class="empty">Walang nakitang duplicate. 🎉</div>'; return; }

  wrap.innerHTML = rows.map(g => {
    const cls = g.is_dismissed ? 'dismissed' : (g.high_confidence ? '' : 'review');
    const badge = g.is_dismissed
      ? '<span class="badge dismissed">DISMISSED</span>'
      : (g.high_confidence ? '<span class="badge high">HIGH CONFIDENCE</span>' : '<span class="badge review">REVIEW</span>');
    const ordersHtml = g.orders.map((o, idx) => {
      const tag = idx === 0 ? '<span class="tag-keep">UNANG ORDER</span>' : '<span class="tag-extra">POSIBLENG SOBRA</span>';
      const checked = (idx > 0 && !g.is_dismissed) ? 'checked' : '';
      return `
        <div class="order-row">
          ${IS_ISESMO && !g.is_dismissed ? `<input type="checkbox" class="del-check" data-id="${escapeHtmlD(o.id)}" ${checked}>` : ''}
          <div style="flex:1">
            <div>${tag} • ${escapeHtmlD(o.created_at||'-')}</div>
            <div style="color:#888;font-size:10px">ID: ${escapeHtmlD(o.id)} • ${peso(o.total_sales)}</div>
          </div>
        </div>
      `;
    }).join('');
    let actions = '';
    if(!g.is_dismissed){
      if(IS_ISESMO) actions += `<button class="btn-del" onclick="deleteSelected('${g.group_hash}')">🗑️ Delete Selected</button>`;
      actions += `<button class="btn-dismiss" onclick="dismissGroup('${g.group_hash}', \`${escapeHtmlD(g.group_key)}\`)">✔️ Hindi ito duplicate</button>`;
    } else {
      actions += `<button class="btn-undismiss" onclick="undismissGroup('${g.group_hash}')">↩️ I-review ulit</button>`;
    }
    return `
      <div class="grp-card ${cls}" data-hash="${escapeHtmlD(g.group_hash)}">
        <div class="grp-head">
          <div>
            <div class="grp-title">${escapeHtmlD(g.reseller_name)} - ${g.quantity} x ${escapeHtmlD(g.kg_size)}</div>
            <div class="grp-sub">📅 ${escapeHtmlD(g.sales_date||'-')} • ${escapeHtmlD(g.mode||'-')} / ${escapeHtmlD(g.payment||'-')} • ${g.count} orders</div>
          </div>
          ${badge}
        </div>
        <div>${ordersHtml}</div>
        <div class="grp-actions">${actions}</div>
      </div>
    `;
  }).join('');
}

async function deleteSelected(groupHash){
  const card = document.querySelector(`.grp-card[data-hash="${groupHash}"]`);
  if(!card) return;
  const ids = Array.from(card.querySelectorAll('.del-check:checked')).map(cb => cb.dataset.id);
  if(!ids.length){ alert('Walang napiling order na tatanggalin.'); return; }
  if(!confirm(`Tanggalin ang ${ids.length} order(s)? Hindi na ito mababawi.`)) return;
  try{
    const res = await fetch('/api/admin/duplicates/delete', {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({sale_ids: ids})
    });
    const data = await res.json();
    if(data.ok) loadGroups(); else alert(data.error || 'Hindi na-delete.');
  }catch(e){ alert('Error: ' + e.message); }
}

async function dismissGroup(groupHash, groupKey){
  try{
    const res = await fetch('/api/admin/duplicates/dismiss', {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({group_key: groupKey})
    });
    const data = await res.json();
    if(data.ok) loadGroups(); else alert(data.error || 'Hindi na-dismiss.');
  }catch(e){ alert('Error: ' + e.message); }
}

async function undismissGroup(groupHash){
  try{
    const res = await fetch(`/api/admin/duplicates/dismiss/${groupHash}`, {method:'DELETE'});
    const data = await res.json();
    if(data.ok) loadGroups(); else alert(data.error || 'Hindi na-undo.');
  }catch(e){ alert('Error: ' + e.message); }
}

loadGroups();
</script>
</body></html>
"""


@duplicate_finder_bp.route("/admin/duplicates")
@login_required
def duplicate_finder_page():
    staff = (session.get("staff_name") or "").strip().lower()
    is_isesmo = staff in ["isesmo", "isesmo gamboa"]
    return render_template_string(DUPLICATE_FINDER_HTML, is_isesmo=is_isesmo)


@duplicate_finder_bp.route("/api/admin/duplicates")
@login_required
def api_duplicate_finder_list():
    try:
        include_dismissed = request.args.get("include_dismissed") == "1"
        groups = _find_duplicate_groups(include_dismissed=include_dismissed)
        return jsonify({"ok": True, "groups": groups})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@duplicate_finder_bp.route("/api/admin/duplicates/dismiss", methods=["POST"])
@login_required
def api_duplicate_finder_dismiss():
    try:
        data = request.json or {}
        group_key = (data.get("group_key") or "").strip()
        if not group_key:
            return jsonify({"ok": False, "error": "Missing group_key"}), 400
        gk_hash = _group_key_hash(group_key)
        fb_post_result = fb_patch(f"daily_sales_dup_ignore/{gk_hash}", {
            "group_key": group_key,
            "dismissed_by": session.get("staff_name"),
            "dismissed_at": now_str(),
        })
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@duplicate_finder_bp.route("/api/admin/duplicates/dismiss/<gk_hash>", methods=["DELETE"])
@login_required
def api_duplicate_finder_undismiss(gk_hash):
    try:
        fb_delete(f"daily_sales_dup_ignore/{gk_hash}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@duplicate_finder_bp.route("/api/admin/duplicates/delete", methods=["POST"])
@isesmo_only
def api_duplicate_finder_delete():
    try:
        data = request.json or {}
        sale_ids = data.get("sale_ids") or []
        if not isinstance(sale_ids, list) or not sale_ids:
            return jsonify({"ok": False, "error": "Walang napiling order"}), 400
        deleted = 0
        for sid in sale_ids:
            if not sid or not isinstance(sid, str):
                continue
            if fb_delete(f"daily_sales/{sid}"):
                deleted += 1
        return jsonify({"ok": True, "deleted": deleted})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
