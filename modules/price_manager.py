"""
modules/price_manager.py
----------------------------------------------------------------------------
Price Manager - lets ISESMO set the price per kg used across the whole
system, instead of that number only ever being set once (at /api/setup,
app.py) and never editable again from the UI.

This does NOT introduce a new pricing model - it's a UI + a couple of API
routes layered directly on top of the SAME `price_settings/REGULAR` and
`price_settings/PICKUP` Firebase nodes app.py's own `get_price(kg_label,
mode)` already reads from (see app.py, search for `def get_price`). So a
price saved here takes effect immediately on the very next sale recorded
anywhere in the system - no other file needs to change.

Two "kinds" of price, matching app.py's own `get_price()` exactly:
    REGULAR - normal delivery price
    PICKUP  - discounted price when the customer picks up themselves
Each kind has 4 sizes: 1Kg, 5Kg, 10Kg, 25Kg (same as app.py's `col_map`).

If `price_settings/{REGULAR,PICKUP}` was never written in Firebase (e.g. a
fresh deploy that skipped /api/setup, or a Firebase node that got wiped),
this page shows the exact same FALLBACK values app.py's own `get_price()`
would silently fall back to at sale time - so what ISESMO sees here is
always the CURRENT EFFECTIVE price, never a misleading blank/zero.

Every save is logged to `price_change_log` (who changed it, old values,
new values, when) - the same audit-trail pattern already used elsewhere
in this app (staff login log, credit payment history, etc.), since a
wrong price change is exactly the kind of thing ISESMO will want to trace
back later ("bakit nagbago yung presyo, sino nag-edit").

Routes:
    GET  /prices               - Price Manager page (ISESMO only)
    GET  /api/prices           - JSON: current effective REGULAR + PICKUP prices
    POST /api/prices           - JSON: save new prices (ISESMO only)
    GET  /api/prices/history   - JSON: price change log, newest first (ISESMO only)

Integration in app.py (2 lines, alongside the other `from modules.*`
imports / register_blueprint calls):
    from modules.price_manager import price_manager_bp
    app.register_blueprint(price_manager_bp)
----------------------------------------------------------------------------
"""
from flask import Blueprint, request, jsonify, session, render_template_string

from modules.shared import fb_get, fb_patch, fb_post, login_required, isesmo_only, now_str

price_manager_bp = Blueprint("price_manager", __name__)

# Same 4 sizes, same Firebase column names, and the SAME fallback numbers
# as app.py's own get_price()/FALLBACK_PRICES - kept as an exact mirror
# here (not imported from app.py) to avoid a circular import, exactly the
# same reasoning modules/shared.py's own docstring gives for its fb_get
# copy. If app.py's FALLBACK_PRICES ever changes, update this dict too.
KG_SIZES = ["1Kg", "5Kg", "10Kg", "25Kg"]
COL_MAP = {"1Kg": "kg1", "5Kg": "kg5", "10Kg": "kg10", "25Kg": "kg25"}
FALLBACK_REGULAR = {"1Kg": 10.0, "5Kg": 50.0, "10Kg": 100.0, "25Kg": 250.0}


def _pickup_fallback(kg_label):
    """Mirrors app.py's get_price() PICKUP discount rule exactly:
    1Kg gets -1 (floor 1), every other size gets -5 (floor 5)."""
    base = FALLBACK_REGULAR.get(kg_label, 10.0)
    return max(1.0, base - 1) if kg_label == "1Kg" else max(5.0, base - 5)


FALLBACK_PICKUP = {kg: _pickup_fallback(kg) for kg in KG_SIZES}


def _get_current_prices():
    """Returns (regular_dict, pickup_dict), each {"1Kg": 10.0, "5Kg": 50.0, ...} -
    always the CURRENT EFFECTIVE price (Firebase value if set, otherwise the
    same fallback app.py's get_price() would use), never a blank."""
    regular_raw = fb_get("price_settings/REGULAR") or {}
    pickup_raw = fb_get("price_settings/PICKUP") or {}
    regular = {}
    pickup = {}
    for kg in KG_SIZES:
        col = COL_MAP[kg]
        try:
            regular[kg] = float(regular_raw[col]) if regular_raw.get(col) is not None else FALLBACK_REGULAR[kg]
        except (TypeError, ValueError):
            regular[kg] = FALLBACK_REGULAR[kg]
        try:
            pickup[kg] = float(pickup_raw[col]) if pickup_raw.get(col) is not None else FALLBACK_PICKUP[kg]
        except (TypeError, ValueError):
            pickup[kg] = FALLBACK_PICKUP[kg]
    return regular, pickup


# ---------- Page: /prices ----------

PRICE_MANAGER_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Price Manager - Omega Ice</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0;font-weight:700}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.card h2{font-size:14px;color:#00609C;margin:0 0 12px;font-weight:700}
.price-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.price-field label{display:block;font-size:11px;color:#666;font-weight:600;margin-bottom:4px}
.price-input-wrap{position:relative}
.price-input-wrap .peso{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#888;font-size:14px;pointer-events:none}
.price-input-wrap input{width:100%;padding:10px 10px 10px 24px;border-radius:8px;border:1px solid #ccd;font-size:14px}
.save-row{display:flex;gap:10px;align-items:center;margin-top:16px}
.save-btn{flex:1;padding:12px;border-radius:10px;border:none;background:#00609C;color:#fff;font-weight:700;font-size:14px;cursor:pointer}
.save-btn:disabled{opacity:.6;cursor:not-allowed}
.status{font-size:12px;text-align:center;margin-top:10px;min-height:16px}.status.err{color:#c0392b}.status.ok{color:#1a8a4a}
.hist-toggle{display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none}
.hist-toggle span.icon{font-size:12px;color:#00609C}
.hist-body{display:none;margin-top:10px}
.hist-row{padding:10px 0;border-bottom:1px solid #f0f4f8;font-size:12px}
.hist-row .who{font-weight:600;color:#333}
.hist-row .when{color:#999;font-size:10px;margin-top:2px}
.hist-diff{margin-top:4px;color:#555}
.hist-diff .old{color:#c0392b;text-decoration:line-through;margin-right:4px}
.hist-diff .new{color:#1a8a4a;font-weight:600}
.empty{color:#888;text-align:center;padding:20px 10px;font-size:13px}
</style></head>
<body>
<div class="topbar">
  <h1>Price Manager (ISESMO Only)</h1>
  <a href="/cashier" class="nav-pill">Back to Sales</a>
</div>

<div class="card">
  <h2>Delivery Prices</h2>
  <div class="price-grid" id="regularGrid"></div>
</div>

<div class="card">
  <h2>Pickup Prices</h2>
  <div class="price-grid" id="pickupGrid"></div>
</div>

<div class="card">
  <div class="save-row">
    <button class="save-btn" id="saveBtn" onclick="savePrices()">Save Prices</button>
  </div>
  <p class="status" id="saveStatus"></p>
</div>

<div class="card">
  <div class="hist-toggle" onclick="toggleHistory()">
    <h2 style="margin:0">Price Change History</h2>
    <span class="icon" id="histIcon">Show &#9660;</span>
  </div>
  <div class="hist-body" id="histBody">
    <div id="histList" class="empty">Loading...</div>
  </div>
</div>

<script>
const KG_SIZES = ["1Kg", "5Kg", "10Kg", "25Kg"];
let historyLoadedOnce = false;

function pesoNum(n){ return Number(n || 0); }

function renderGrid(containerId, prefix, values){
  const el = document.getElementById(containerId);
  el.innerHTML = KG_SIZES.map(kg => `
    <div class="price-field">
      <label>${kg}</label>
      <div class="price-input-wrap">
        <span class="peso">&#8369;</span>
        <input type="number" id="${prefix}_${kg}" step="0.01" min="0" value="${pesoNum(values[kg]).toFixed(2)}">
      </div>
    </div>
  `).join('');
}

async function loadPrices(){
  try{
    const res = await fetch('/api/prices');
    if(res.status===401){ window.location.href='/login'; return; }
    if(res.status===403){ document.body.innerHTML = '<div class="empty">Access denied. ISESMO only.</div>'; return; }
    const data = await res.json();
    if(!data.ok){ document.getElementById('saveStatus').textContent = data.error || 'Failed to load prices.'; return; }
    renderGrid('regularGrid', 'reg', data.regular);
    renderGrid('pickupGrid', 'pk', data.pickup);
  }catch(e){
    document.getElementById('saveStatus').textContent = 'Error: ' + e.message;
    document.getElementById('saveStatus').className = 'status err';
  }
}

async function savePrices(){
  const btn = document.getElementById('saveBtn');
  const st = document.getElementById('saveStatus');
  const regular = {};
  const pickup = {};
  for(const kg of KG_SIZES){
    const regVal = parseFloat(document.getElementById(`reg_${kg}`).value);
    const pkVal = parseFloat(document.getElementById(`pk_${kg}`).value);
    if(isNaN(regVal) || regVal < 0 || isNaN(pkVal) || pkVal < 0){
      st.textContent = `Please enter a valid price for ${kg}.`;
      st.className = 'status err';
      return;
    }
    regular[kg] = regVal;
    pickup[kg] = pkVal;
  }
  btn.disabled = true;
  st.textContent = 'Saving...';
  st.className = 'status';
  try{
    const res = await fetch('/api/prices', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({regular, pickup})
    });
    const data = await res.json();
    if(data.ok){
      st.textContent = 'Prices saved. New sales will use these prices right away.';
      st.className = 'status ok';
      if(historyLoadedOnce){ historyLoadedOnce = false; loadHistory(); }
    } else {
      st.textContent = data.error || 'Could not save.';
      st.className = 'status err';
    }
  }catch(e){
    st.textContent = 'Error: ' + e.message;
    st.className = 'status err';
  }finally{
    btn.disabled = false;
  }
}

function toggleHistory(){
  const body = document.getElementById('histBody');
  const icon = document.getElementById('histIcon');
  const willShow = body.style.display !== 'block';
  body.style.display = willShow ? 'block' : 'none';
  icon.innerHTML = willShow ? 'Hide &#9650;' : 'Show &#9660;';
  if(willShow && !historyLoadedOnce){
    historyLoadedOnce = true;
    loadHistory();
  }
}

function escapeHtmlP(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}

async function loadHistory(){
  const list = document.getElementById('histList');
  list.innerHTML = 'Loading...';
  try{
    const res = await fetch('/api/prices/history');
    const data = await res.json();
    if(!data.ok){ list.innerHTML = `<div class="empty">${escapeHtmlP(data.error || 'Failed to load history.')}</div>`; return; }
    const rows = data.rows || [];
    if(!rows.length){ list.innerHTML = '<div class="empty">No price changes recorded yet.</div>'; return; }
    list.innerHTML = rows.map(r => `
      <div class="hist-row">
        <div class="who">${escapeHtmlP(r.changed_by || 'Unknown')}</div>
        <div class="when">${escapeHtmlP(r.timestamp || '')}</div>
        ${(r.changes || []).map(c => `
          <div class="hist-diff">${escapeHtmlP(c.label)}: <span class="old">&#8369;${pesoNum(c.old).toFixed(2)}</span><span class="new">&#8369;${pesoNum(c.new_val).toFixed(2)}</span></div>
        `).join('')}
      </div>
    `).join('');
  }catch(e){
    list.innerHTML = `<div class="empty">Error: ${escapeHtmlP(e.message)}</div>`;
  }
}

loadPrices();
</script>
</body></html>
"""


# ---------- Routes ----------

@price_manager_bp.route("/prices")
@isesmo_only
def price_manager_page():
    return render_template_string(PRICE_MANAGER_HTML)


@price_manager_bp.route("/api/prices")
@login_required
def api_get_prices():
    """Read-only for any logged-in staff member (so e.g. the cashier
    screen could show "today's price" somewhere later if ever needed) -
    only SAVING a price change is restricted to ISESMO (see the POST
    route below)."""
    try:
        regular, pickup = _get_current_prices()
        return jsonify({"ok": True, "regular": regular, "pickup": pickup})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@price_manager_bp.route("/api/prices", methods=["POST"])
@isesmo_only
def api_save_prices():
    try:
        data = request.json or {}
        new_regular_raw = data.get("regular") or {}
        new_pickup_raw = data.get("pickup") or {}

        # Validate every size is present and a non-negative number BEFORE
        # writing anything - a half-applied save (e.g. REGULAR written but
        # PICKUP rejected) would leave the two price tables inconsistent,
        # so this all-or-nothing check happens first.
        new_regular = {}
        new_pickup = {}
        for kg in KG_SIZES:
            for label, src, dest in (("regular", new_regular_raw, new_regular), ("pickup", new_pickup_raw, new_pickup)):
                if kg not in src:
                    return jsonify({"ok": False, "error": f"Missing {label} price for {kg}"}), 400
                try:
                    val = float(src[kg])
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "error": f"Invalid {label} price for {kg}"}), 400
                if val < 0:
                    return jsonify({"ok": False, "error": f"{label.title()} price for {kg} cannot be negative"}), 400
                dest[kg] = val

        old_regular, old_pickup = _get_current_prices()

        # Build the audit-log diff BEFORE overwriting anything, and only
        # include sizes that actually changed - a save where nothing
        # actually moved (ISESMO just tapped Save without editing) still
        # writes a log entry with an empty "changes" list, which is fine
        # and harmless, but keeps the log focused on real changes when
        # something DID move.
        changes = []
        for kg in KG_SIZES:
            if old_regular[kg] != new_regular[kg]:
                changes.append({"label": f"Delivery {kg}", "old": old_regular[kg], "new_val": new_regular[kg]})
            if old_pickup[kg] != new_pickup[kg]:
                changes.append({"label": f"Pickup {kg}", "old": old_pickup[kg], "new_val": new_pickup[kg]})

        regular_patch = {COL_MAP[kg]: new_regular[kg] for kg in KG_SIZES}
        regular_patch["type"] = "REGULAR"
        pickup_patch = {COL_MAP[kg]: new_pickup[kg] for kg in KG_SIZES}
        pickup_patch["type"] = "PICKUP"

        fb_patch("price_settings/REGULAR", regular_patch)
        fb_patch("price_settings/PICKUP", pickup_patch)

        if changes:
            fb_post("price_change_log", {
                "changed_by": session.get("staff_name"),
                "changes": changes,
                "timestamp": now_str(),
            })

        return jsonify({"ok": True, "regular": new_regular, "pickup": new_pickup, "changed": len(changes)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@price_manager_bp.route("/api/prices/history")
@isesmo_only
def api_price_history():
    try:
        logs = fb_get("price_change_log") or {}
        rows = []
        for key, val in logs.items():
            if not val:
                continue
            row = dict(val)
            row["id"] = key
            rows.append(row)
        rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
        return jsonify({"ok": True, "rows": rows[:100]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
