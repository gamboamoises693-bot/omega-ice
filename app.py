
"""
Omega Ice - OFFLINE FIRST - Firebase + Local SQLite backup
- If internet: saves to Firebase instantly
- If NO internet: saves to phone (omega_local.db) and shows pending badge
- When internet returns: tap badge or go to /api/offline/sync to upload

Firebase: https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app
"""

import os, sqlite3, json, requests, time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "omega-ice-realtime-2026")
FIREBASE_URL = "https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app".rstrip("/")

KG_OPTIONS = ["1Kg", "5Kg", "10Kg", "25Kg"]
FALLBACK_PRICES = {"1Kg": 10, "5Kg": 50, "10Kg": 100, "25Kg": 250}

LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"><title>Omega Ice - Login</title>
<style>*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;background:#eef7ff;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#fff;border-radius:16px;padding:28px 24px;width:100%;max-width:340px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.06)}h1{font-size:20px;color:#00609C;margin:0 0 4px}.subtitle{font-size:13px;color:#333;margin:0 0 4px;font-weight:600}.tagline{font-size:11px;color:#888;margin:0 0 24px}.dots{font-size:28px;letter-spacing:8px;margin:12px 0;color:#222;min-height:36px}.msg{font-size:12px;color:#888;min-height:18px;margin-bottom:16px}.keypad{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px}.keypad button{padding:20px 0;font-size:24px;border-radius:12px;border:none;background:#f0f0f0;cursor:pointer;touch-action:manipulation}.keypad button:active{background:#ddd;transform:scale(0.97)}.keypad button.clear{background:#e5433d;color:#fff}.keypad button.back{background:#999;color:#fff}.footer{font-size:10px;color:#aaa;margin-top:10px}</style>
</head><body>
<div class="card"><h1>OMEGA PURIFIED ICE</h1><p class="subtitle">STAFF LOGIN</p><p class="tagline">Sales quick access</p><div class="dots" id="dots">o o o o</div><p class="msg" id="msg">Enter PIN</p>
<div class="keypad">
<button type="button" onclick="addDigit('1')">1</button>
<button type="button" onclick="addDigit('2')">2</button>
<button type="button" onclick="addDigit('3')">3</button>
<button type="button" onclick="addDigit('4')">4</button>
<button type="button" onclick="addDigit('5')">5</button>
<button type="button" onclick="addDigit('6')">6</button>
<button type="button" onclick="addDigit('7')">7</button>
<button type="button" onclick="addDigit('8')">8</button>
<button type="button" onclick="addDigit('9')">9</button>
<button type="button" class="clear" onclick="clearPin()">C</button>
<button type="button" onclick="addDigit('0')">0</button>
<button type="button" class="back" onclick="backspace()">&lt;</button>
</div><p class="footer">Omega Ice System</p></div>
<script>
let pin="";
function updateDots(){let out="";for(let i=0;i<4;i++)out+=(i<pin.length?"*":"o")+" ";document.getElementById("dots").innerText=out.trim()}
function addDigit(d){if(pin.length<4){pin+=d;updateDots();if(pin.length==4)setTimeout(doLogin,200)}}
function backspace(){pin=pin.slice(0,-1);updateDots()}
function clearPin(){pin="";updateDots();document.getElementById("msg").textContent="Enter PIN"}
async function doLogin(){document.getElementById("msg").textContent="Checking...";try{const res=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({pin})});const data=await res.json();if(data.ok){document.getElementById("msg").textContent="OK "+data.name+"! Loading...";window.location.href="/cashier"}else{document.getElementById("msg").textContent=data.error||"Wrong PIN";setTimeout(clearPin,1200)}}catch(e){document.getElementById("msg").textContent="Network error - retry";setTimeout(clearPin,1500)}}
</script>
</body></html>
"""
CASHIER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Omega Ice - Cashier</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    background: #eef7ff;
    margin: 0;
    padding: 12px 12px 40px;
    color: #1a1a1a;
  }
  .topbar {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 8px;
  }
  .topbar h1 { font-size: 18px; color: #00609C; margin: 0; font-weight:700; }
  .topbar .staff { font-size: 12px; color: #555; }
  .logout { font-size: 12px; color: #c0392b; background: #fff; border: 1px solid #e0c0c0; padding:6px 10px; border-radius:8px; }
  .cloud-badge{display:inline-flex;align-items:center;gap:4px;padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;margin-bottom:8px}
  .cloud-badge.online{background:#22c55e;color:#fff}
  .cloud-badge.offline{background:#ef4444;color:#fff}
  .cloud-badge.pending{background:#f59e0b;color:#fff;cursor:pointer}
  .topbar-wrap{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
  .nav-links{display:flex;gap:8px;margin-bottom:6px}
  .nav-links a{padding:8px 14px;background:#fff;border-radius:20px;font-size:12px;text-decoration:none;color:#00609C;border:1px solid #cde;}
  .nav-links a.active{background:#00609C;color:#fff}
  .card {
    background: #fff; border-radius: 12px; padding: 16px;
    margin-bottom: 14px; box-shadow: 0 1px 4px rgba(0,0,0,0.05);
  }
  label { display: block; font-size: 12px; color: #666; margin: 10px 0 4px; }
  input, select {
    width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #ccd;
    font-size: 14px;
  }
  .toggle-row { display: flex; gap: 8px; margin-top: 4px; }
  .toggle-row button {
    flex: 1; padding: 10px; border-radius: 8px; border: 1px solid #ccd;
    background: #f5f5f5; font-size: 13px;
  }
  .toggle-row button.active { background: #0096D6; color: #fff; border-color: #0096D6; }
  .kg-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-top: 4px; }
  .kg-row button {
    padding: 10px 0; border-radius: 8px; border: 1px solid #ccd; background: #f5f5f5; font-size: 13px;
  }
  .kg-row button.active { background: #0096D6; color: #fff; border-color: #0096D6; }
  .total-row {
    display: flex; justify-content: space-between; align-items: baseline;
    margin: 16px 0 4px; font-size: 14px; color: #444;
  }
  .total-row .amount { font-size: 24px; font-weight: 600; color: #00609C; }
  .save-btn {
    width: 100%; padding: 14px; margin-top: 12px; background: #00609C; color: #fff;
    border: none; border-radius: 10px; font-size: 15px; font-weight: 600;
  }
  #resellerResults {
    border: 1px solid #ddd; border-radius: 8px; margin-top: 4px; max-height: 160px;
    overflow-y: auto; display: none; background: #fff;
  }
  #resellerResults div { padding: 8px 10px; font-size: 13px; border-bottom: 1px solid #eee; }
  #resellerResults div:last-child { border-bottom: none; }
  .status { font-size: 13px; text-align: center; margin-top: 8px; min-height: 18px; }
  .status.ok { color: #1a8a4a; }
  .status.err { color: #c73333; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 6px 4px; border-bottom: 1px solid #eee; }
  th { color: #888; font-weight: 500; }
  .del-btn { background: none; border: none; color: #c0392b; font-size: 12px; }
  .edit-btn { background: none; border: none; color: #0096D6; font-size: 12px; margin-right:6px; font-weight:700; }
</style>
</head>
<body>

<div class="topbar-wrap">
<div class="topbar">
  <h1>OMEGA ICE</h1>
  <div style="display:flex;align-items:center;gap:10px"><span class="staff">{{ staff_name }}</span><button class="logout" onclick="logout()">Logout</button></div>
</div>
<div style="display:flex;gap:8px;flex-wrap:wrap">
  <span class="cloud-badge online" id="onlineBadge">● Online - Cloud Live</span>
  <span class="cloud-badge pending" id="pendingBadge" style="display:none" onclick="syncOffline()">0 Pending - Tap to sync</span>
</div>
<div class="nav-links"><a href="/cashier" class="active">Sales</a><a href="/machines">Machines</a></div>
</div>

<div class="card">
  <label>Reseller / customer</label>
  <input type="text" id="resellerInput" placeholder="Type to search or add new" autocomplete="off">
  <div id="resellerResults"></div>

  <label>Delivery mode</label>
  <div class="toggle-row">
    <button id="modeDeliver" class="active" onclick="setMode('DELIVER')">Deliver</button>
    <button id="modePickup" onclick="setMode('PICKUP')">Pickup</button>
  </div>

  <label>Payment</label>
  <div class="toggle-row">
    <button id="payCash" class="active" onclick="setPayment('Cash')">Cash</button>
    <button id="payCredit" onclick="setPayment('Credit')">Credit</button>
  </div>

  <label>Size</label>
  <div class="kg-row">
    {% for kg in kg_options %}
    <button data-kg="{{ kg }}" onclick="setKg('{{ kg }}')" class="{{ 'active' if loop.first else '' }}">{{ kg }}</button>
    {% endfor %}
  </div>

  <label>Quantity</label>
  <input type="number" id="qtyInput" value="1" min="1" oninput="updateTotal()">

  <div class="total-row">
    <span>Total</span>
    <span class="amount" id="totalAmount">₱0</span>
  </div>

  <button class="save-btn" id="saveBtn" onclick="saveSale()">Save sale</button>
  <button class="save-btn" id="cancelEditBtn" style="display:none; background:#999; margin-top:6px;" onclick="cancelEdit()">Cancel edit</button>
  <p class="status" id="statusMsg"></p>
</div>

<div class="card">
  <label style="font-weight:600;margin-bottom:8px;display:block">Recent sales</label>
  <table>
    <thead><tr><th>Date</th><th>Reseller</th><th>Qty</th><th>Size</th><th>Total</th><th></th></tr></thead>
    <tbody id="recentBody"></tbody>
  </table>
</div>

<script>
let mode = 'DELIVER';
let payment = 'Cash';
let kg = '{{ kg_options[0] }}';
let selectedReseller = null;
let unitPrice = 0;
let editingSaleId = null;

function setMode(m) {
  mode = m;
  document.getElementById('modeDeliver').classList.toggle('active', m === 'DELIVER');
  document.getElementById('modePickup').classList.toggle('active', m === 'PICKUP');
  updateTotal();
}

function setPayment(p) {
  payment = p;
  document.getElementById('payCash').classList.toggle('active', p === 'Cash');
  document.getElementById('payCredit').classList.toggle('active', p === 'Credit');
}

function setKg(k) {
  kg = k;
  document.querySelectorAll('.kg-row button').forEach(b => b.classList.toggle('active', b.dataset.kg === k));
  updateTotal();
}

async function updateTotal() {
  try {
    const res = await fetch(`/api/price?kg=${kg}&mode=${mode}`);
    const data = await res.json();
    unitPrice = data.price;
  } catch(e) { unitPrice = 10; }
  const qty = parseInt(document.getElementById('qtyInput').value) || 0;
  document.getElementById('totalAmount').textContent = '₱' + (unitPrice * qty).toLocaleString();
}

const resellerInput = document.getElementById('resellerInput');
const resultsBox = document.getElementById('resellerResults');

resellerInput.addEventListener('input', async () => {
  selectedReseller = null;
  const q = resellerInput.value.trim();
  if (!q) { resultsBox.style.display = 'none'; return; }
  try {
    const res = await fetch(`/api/resellers?q=${encodeURIComponent(q)}`);
    const rows = await res.json();
    if (!rows.length) { resultsBox.style.display = 'none'; return; }
    resultsBox.innerHTML = rows.map(r => `<div class="res-item" data-id="${r.id}" data-name="${r.store_name.replace(/"/g,'&quot;')}">${r.store_name}</div>`).join('');
    resultsBox.style.display = 'block';
      resultsBox.querySelectorAll('.res-item').forEach(el => {
        el.addEventListener('click', () => {
          pickReseller(el.getAttribute('data-id'), el.getAttribute('data-name'));
        });
      });
  } catch(e) { resultsBox.style.display='none'; }
});

function pickReseller(id, name) {
  selectedReseller = { id, name };
  resellerInput.value = name;
  resultsBox.style.display = 'none';
}

async function saveSale() {
  const qty = parseInt(document.getElementById('qtyInput').value) || 0;
  const name = resellerInput.value.trim();
  const statusEl = document.getElementById('statusMsg');
  if (!name || qty <= 0) {
    statusEl.textContent = 'Enter a reseller name and quantity';
    statusEl.className = 'status err';
    return;
  }
  const payload = {
    reseller_id: selectedReseller ? selectedReseller.id : null,
    reseller_name: name,
    quantity: qty,
    kg_size: kg,
    mode: mode,
    payment: payment
  };

  const url = editingSaleId ? `/api/sale/${editingSaleId}` : '/api/sale';
  const method = editingSaleId ? 'PUT' : 'POST';

  statusEl.textContent = editingSaleId ? 'Updating...' : 'Saving...';
  statusEl.className = 'status';
  try {
    const res = await fetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.ok) {
      statusEl.textContent = data.offline ? `Saved offline ₱${data.total} - will sync when online` : `Saved ₱${data.total}`;
      statusEl.className = 'status ok';
      resellerInput.value = '';
      selectedReseller = null;
      document.getElementById('qtyInput').value = 1;
      editingSaleId = null;
      document.getElementById('saveBtn').textContent = 'Save sale';
      document.getElementById('cancelEditBtn').style.display = 'none';
      updateTotal();
      loadRecent();
      checkOnline();
    } else {
      statusEl.textContent = data.error || 'Error';
      statusEl.className = 'status err';
    }
  } catch(e) {
    statusEl.textContent = 'Network error - saved? Check recent';
    statusEl.className = 'status err';
    loadRecent();
  }
}

function editSale(id) {
  fetch(`/api/sale/${id}`).then(r=>r.json()).then(data=>{
    if (!data.ok) return;
    const s = data.sale;
    editingSaleId = id;
    resellerInput.value = s.reseller_name;
    selectedReseller = s.reseller_id ? {id: s.reseller_id, name: s.reseller_name} : null;
    document.getElementById('qtyInput').value = s.quantity;
    setKg(s.kg_size);
    setMode(s.mode);
    setPayment(s.payment);
    document.getElementById('saveBtn').textContent = 'Update sale';
    document.getElementById('cancelEditBtn').style.display = 'block';
    window.scrollTo({top:0, behavior:'smooth'});
  });
}

function cancelEdit() {
  editingSaleId = null;
  resellerInput.value = '';
  selectedReseller = null;
  document.getElementById('qtyInput').value = 1;
  document.getElementById('saveBtn').textContent = 'Save sale';
  document.getElementById('cancelEditBtn').style.display = 'none';
  updateTotal();
}

async function loadRecent() {
  try {
    const res = await fetch('/api/sales/recent');
    const rows = await res.json();
    const tbody = document.getElementById('recentBody');
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td>${r.sales_date || r.created_at?.slice(0,10) || ''}</td>
        <td>${r.reseller_name}</td>
        <td>${r.quantity}</td>
        <td>${r.kg_size}</td>
        <td>₱${r.total_sales}</td>
        <td>
          <button class="edit-btn" onclick="editSale('${r.id}')">Edit</button>
          <button class="del-btn" onclick="deleteSale('${r.id}')">Del</button>
        </td>
      </tr>
    `).join('');
  } catch(e) {}
}

async function deleteSale(id) {
  if (!confirm('Delete this sale?')) return;
  await fetch(`/api/sale/${id}`, {method:'DELETE'});
  loadRecent();
  checkOnline();
}

async function checkOnline() {
  try {
    const res = await fetch('/api/offline/pending');
    const data = await res.json();
    const onlineBadge = document.getElementById('onlineBadge');
    const pendingBadge = document.getElementById('pendingBadge');
    if (data.offline) {
      onlineBadge.textContent = '● Offline - Saved locally';
      onlineBadge.className = 'cloud-badge offline';
    } else {
      onlineBadge.textContent = '● Online - Cloud Live';
      onlineBadge.className = 'cloud-badge online';
    }
    if (data.pending_count > 0) {
      pendingBadge.textContent = `${data.pending_count} Pending - Tap to sync`;
      pendingBadge.style.display = 'inline-flex';
    } else {
      pendingBadge.style.display = 'none';
    }
  } catch(e) {
    document.getElementById('onlineBadge').textContent = '● Offline';
    document.getElementById('onlineBadge').className = 'cloud-badge offline';
  }
}

async function syncOffline() {
  if (!confirm('Sync pending sales to cloud?')) return;
  const res = await fetch('/api/offline/sync', {method:'POST'});
  const data = await res.json();
  if (data.ok) {
    alert(`Synced ${data.synced} sales!`);
    loadRecent();
    checkOnline();
  } else {
    alert(data.error || 'Sync failed - no internet');
  }
}

async function logout(){await fetch('/api/logout',{method:'POST'});window.location.href='/login'}
updateTotal();loadRecent();checkOnline();setInterval(checkOnline,5000);setInterval(loadRecent,10000);
</script>

</body>
</html>
"""

# ---------- Local offline DB ----------
LOCAL_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "omega_local.db")

def init_local_db():
    conn = sqlite3.connect(LOCAL_DB)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS pending_sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data TEXT,
        created_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS cached_resellers (
        firebase_id TEXT,
        store_name TEXT,
        credit_balance REAL,
        updated_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS cached_sales (
        firebase_id TEXT,
        sales_date TEXT,
        reseller_name TEXT,
        quantity INTEGER,
        kg_size TEXT,
        total_sales REAL,
        mode TEXT,
        payment TEXT,
        created_at TEXT
    )""")
    conn.commit()
    conn.close()

init_local_db()

def is_online():
    try:
        r = requests.get(f"{FIREBASE_URL}/.json", timeout=3)
        return r.status_code in [200, 401, 403]
    except:
        return False

def save_local_pending(sale_dict):
    conn = sqlite3.connect(LOCAL_DB)
    c = conn.cursor()
    c.execute("INSERT INTO pending_sales (data, created_at) VALUES (?,?)", (json.dumps(sale_dict), datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_pending_count():
    conn = sqlite3.connect(LOCAL_DB)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM pending_sales")
    count = c.fetchone()[0]
    conn.close()
    return count

def save_cached_resellers(fb_data):
    if not fb_data:
        return
    conn = sqlite3.connect(LOCAL_DB)
    c = conn.cursor()
    c.execute("DELETE FROM cached_resellers")
    for fid, val in fb_data.items():
        if val and val.get("store_name"):
            c.execute("INSERT INTO cached_resellers VALUES (?,?,?,?)", (fid, val.get("store_name"), float(val.get("credit_balance",0) or 0), datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_cached_resellers(q=""):
    conn = sqlite3.connect(LOCAL_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    q = q.lower()
    if q:
        c.execute("SELECT * FROM cached_resellers WHERE lower(store_name) LIKE ? ORDER BY store_name LIMIT 50", (f"%{q}%",))
    else:
        c.execute("SELECT * FROM cached_resellers ORDER BY store_name LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return [{"id": r["firebase_id"], "store_name": r["store_name"], "credit_balance": r["credit_balance"]} for r in rows]

# ---------- Firebase helpers ----------
def fb_get(path):
    try:
        r = requests.get(f"{FIREBASE_URL}/{path}.json", timeout=7)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"GET {path} error: {e}")
    return None

def fb_post(path, data):
    try:
        r = requests.post(f"{FIREBASE_URL}/{path}.json", json=data, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"POST {path} error: {e}")
    return None

def fb_put(path, data):
    try:
        r = requests.put(f"{FIREBASE_URL}/{path}.json", json=data, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"PUT {path} error: {e}")
    return None

def fb_patch(path, data):
    try:
        r = requests.patch(f"{FIREBASE_URL}/{path}.json", json=data, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"PATCH {path} error: {e}")
    return None

def get_price(kg_label, mode):
    ptype = "PICKUP" if mode == "PICKUP" else "REGULAR"
    col_map = {"1Kg": "kg1", "5Kg": "kg5", "10Kg": "kg10", "25Kg": "kg25"}
    col = col_map.get(kg_label, "kg1")
    try:
        data = fb_get(f"price_settings/{ptype}")
        if data and data.get(col):
            return float(data[col])
    except:
        pass
    price = FALLBACK_PRICES.get(kg_label, 10)
    if mode == "PICKUP":
        price = max(1, price - 1) if kg_label == "1Kg" else max(5, price - 5)
    return float(price)

# ---------- Machine monitoring helpers ----------

def get_electricity_rate():
    """₱ per kWh, used to compute electricity cost of a machine run."""
    try:
        data = fb_get("settings/electricity_rate")
        if data:
            return float(data)
    except:
        pass
    return 12.0  # fallback default rate

def calc_machine_age(date_purchase):
    if not date_purchase:
        return "N/A"
    try:
        d = datetime.strptime(date_purchase, "%Y-%m-%d")
        days = (datetime.now() - d).days
        years, rem_days = divmod(days, 365)
        months = rem_days // 30
        if years > 0:
            return f"{years}y {months}m"
        elif months > 0:
            return f"{months}m"
        return f"{days}d"
    except:
        return "N/A"

def is_pm_overdue(pm_date):
    if not pm_date:
        return False
    try:
        d = datetime.strptime(pm_date, "%Y-%m-%d")
        return d.date() < datetime.now().date()
    except:
        return False

def login_required(view):
    def wrapped(*args, **kwargs):
        if not session.get("staff_name"):
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped

@app.route("/")
def root():
    if session.get("staff_name"):
        return redirect(url_for("cashier_page"))
    return redirect(url_for("login_page"))

@app.route("/login")
def login_page():
    return render_template_string(LOGIN_HTML)

@app.route("/debug")
def debug_page():
    import os
    info = []
    info.append(f"FIREBASE_URL: {FIREBASE_URL}")
    info.append(f"Online: {is_online()}")
    info.append(f"CWD: {os.getcwd()}")
    info.append(f"Local DB: {LOCAL_DB} exists={os.path.exists(LOCAL_DB)}")
    info.append(f"Pending offline sales: {get_pending_count()}")
    try:
        r = requests.get(f"{FIREBASE_URL}/.json", timeout=5)
        info.append(f"Firebase status: {r.status_code}")
    except Exception as e:
        info.append(f"Firebase failed: {e}")
    return "<br>".join(info)

@app.route("/api/login", methods=["POST"])
def api_login():
    pin = (request.json or {}).get("pin", "").strip()
    if len(pin) != 4:
        return jsonify({"ok": False, "error": "Enter 4-digit PIN"}), 400
    # Try online first
    staff_data = fb_get("staff")
    # If offline, allow login with cached PINs (fallback)
    if not staff_data:
        # offline fallback PINs
        offline_pins = {"1928":"Tatay/Nanay","0615":"Yhel","0519":"OMEGA","0712":"ISESMO"}
        if pin in offline_pins:
            session["staff_id"] = f"offline-{pin}"
            session["staff_name"] = offline_pins[pin]
            session["staff_position"] = "Offline"
            return jsonify({"ok": True, "name": offline_pins[pin], "position": "Offline Mode"})
        return jsonify({"ok": False, "error": "No internet + no cached staff. Connect once to login."}), 404
    for key, val in staff_data.items():
        if val and val.get("pin") == pin and val.get("status") == "Active":
            session["staff_id"] = key
            session["staff_name"] = val.get("name")
            session["staff_position"] = val.get("position", "Staff")
            return jsonify({"ok": True, "name": val.get("name"), "position": val.get("position")})
    return jsonify({"ok": False, "error": "Wrong PIN"}), 401

@app.route("/api/setup")
def api_setup():
    existing = fb_get("staff")
    if existing:
        return jsonify({"ok": False, "message": "Already setup", "staff_count": len(existing)})
    staff = {
        "staff1": {"name": "Tatay/Nanay", "position": "Co-Owner", "pin": "1928", "status": "Active"},
        "staff2": {"name": "Yhel", "position": "Staff", "pin": "0615", "status": "Active"},
        "staff3": {"name": "OMEGA", "position": "ADMIN", "pin": "0519", "status": "Active"},
        "staff4": {"name": "ISESMO", "position": "Manager/Owner", "pin": "0712", "status": "Active"},
    }
    fb_put("staff", staff)
    fb_put("price_settings/REGULAR", {"kg1": 10, "kg5": 50, "kg10": 100, "kg25": 250, "type": "REGULAR"})
    fb_put("price_settings/PICKUP", {"kg1": 9, "kg5": 45, "kg10": 90, "kg25": 230, "type": "PICKUP"})
    return jsonify({"ok": True, "message": "Setup done! PIN 1928"})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/cashier")
@login_required
def cashier_page():
    return render_template_string(CASHIER_HTML, staff_name=session.get("staff_name"), staff_position=session.get("staff_position"), kg_options=KG_OPTIONS)

@app.route("/api/resellers")
@login_required
def api_resellers():
    q = request.args.get("q", "").strip().lower()
    # Try online
    data = fb_get("resellers")
    if data:
        save_cached_resellers(data)
        resellers = []
        for key, val in data.items():
            if val:
                name = val.get("store_name", "")
                if not q or q in name.lower():
                    resellers.append({"id": key, "store_name": name, "credit_balance": val.get("credit_balance", 0)})
        resellers.sort(key=lambda x: x["store_name"])
        return jsonify(resellers[:50] if not q else resellers[:20])
    else:
        # offline fallback - use cached
        cached = get_cached_resellers(q)
        return jsonify(cached)

@app.route("/api/price")
@login_required
def api_price():
    kg = request.args.get("kg", "1Kg")
    mode = request.args.get("mode", "DELIVER")
    return jsonify({"price": get_price(kg, mode)})

@app.route("/api/sale", methods=["POST"])
@login_required
def api_create_sale():
    data = request.json or {}
    reseller_id = data.get("reseller_id")
    reseller_name = data.get("reseller_name", "").strip()
    qty = int(data.get("quantity", 1))
    kg_size = data.get("kg_size", "1Kg")
    mode = data.get("mode", "DELIVER")
    payment = data.get("payment", "Cash")
    notes = data.get("notes", "")

    if not reseller_name or qty <= 0:
        return jsonify({"ok": False, "error": "Reseller and quantity required"}), 400

    unit_price = get_price(kg_size, mode)
    total = round(unit_price * qty, 2)

    sale = {
        "sales_date": datetime.now().strftime("%Y-%m-%d"),
        "reseller_id": reseller_id,
        "reseller_name": reseller_name,
        "quantity": qty,
        "kg_size": kg_size,
        "total_sales": total,
        "unit_price": unit_price,
        "mode": mode,
        "payment": payment,
        "payment_mode": payment,
        "delivery_mode": mode,
        "notes": notes,
        "staff_name": session.get("staff_name"),
        "created_at": datetime.now().isoformat()
    }

    # Try online
    result = fb_post("daily_sales", sale)
    if result:
        # online success - ALSO cache locally for instant Recent display
        try:
            conn = sqlite3.connect(LOCAL_DB)
            c = conn.cursor()
            c.execute("INSERT INTO cached_sales (sales_date, reseller_name, quantity, kg_size, total_sales, mode, payment, created_at) VALUES (?,?,?,?,?,?,?,?)",
                      (sale["sales_date"], sale["reseller_name"], sale["quantity"], sale["kg_size"], sale["total_sales"], sale["mode"], sale["payment"], sale["created_at"]))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Cache error: {e}")
        if payment == "Credit" and reseller_id:
            reseller = fb_get(f"resellers/{reseller_id}")
            if reseller:
                cur = float(reseller.get("credit_balance", 0) or 0)
                fb_patch(f"resellers/{reseller_id}", {"credit_balance": cur + total})
        fb_post("staff_logs", {
            "log_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "staff_name": session.get("staff_name"),
            "action": "SALE",
            "reseller_name": reseller_name,
            "qty": qty,
            "total": total,
            "notes": notes
        })
        return jsonify({"ok": True, "total": total, "unit_price": unit_price, "offline": False, "firebase_key": result.get("name")})
    else:
        # OFFLINE - save locally
        save_local_pending(sale)
        # Also save to cached_sales for recent list
        conn = sqlite3.connect(LOCAL_DB)
        c = conn.cursor()
        c.execute("INSERT INTO cached_sales (sales_date, reseller_name, quantity, kg_size, total_sales, mode, payment, created_at) VALUES (?,?,?,?,?,?,?,?)",
                  (sale["sales_date"], sale["reseller_name"], sale["quantity"], sale["kg_size"], sale["total_sales"], sale["mode"], sale["payment"], sale["created_at"]))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "total": total, "unit_price": unit_price, "offline": True, "pending_count": get_pending_count(), "message": "Saved offline - will sync when online"})

@app.route("/api/sales/recent")
@login_required
def api_recent_sales():
    # Try online first
    data = fb_get("daily_sales")
    sales = []
    recent = []
    if data:
        for key, val in data.items():
            if val:
                sales.append({
                    "id": key,
                    "sales_date": val.get("sales_date"),
                    "reseller_name": val.get("reseller_name"),
                    "quantity": val.get("quantity"),
                    "kg_size": val.get("kg_size"),
                    "total_sales": val.get("total_sales"),
                    "mode": val.get("mode"),
                    "payment": val.get("payment"),
                    "created_at": val.get("created_at","")
                })
        # sort by created_at desc for newest first
        sales.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        recent = sales[:20]
    
    # Also include cached local sales (for instant display + offline)
    try:
        conn = sqlite3.connect(LOCAL_DB)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM cached_sales ORDER BY id DESC LIMIT 20")
        for r in c.fetchall():
            # Avoid duplicates if already in recent (check by created_at)
            recent.append({
                "id": f"offline-{r['id']}",
                "sales_date": r["sales_date"],
                "reseller_name": r["reseller_name"],
                "quantity": r["quantity"],
                "kg_size": r["kg_size"],
                "total_sales": r["total_sales"],
                "mode": r["mode"],
                "payment": r["payment"],
                "created_at": r["created_at"]
            })
        conn.close()
    except Exception as e:
        print(f"Recent local read error: {e}")
    
    # Sort combined by created_at
    recent.sort(key=lambda x: x.get("created_at",""), reverse=True)
    return jsonify(recent[:20])

@app.route("/api/debug/sales")
@login_required
def api_debug_sales():
    import os
    data = fb_get("daily_sales")
    fb_count = len(data) if data else 0
    local_count = 0
    try:
        conn = sqlite3.connect(LOCAL_DB)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM cached_sales")
        local_count = c.fetchone()[0]
        conn.close()
    except:
        pass
    return jsonify({"firebase_daily_sales_count": fb_count, "local_cached_count": local_count, "firebase_raw": str(data)[:1000] if data else None, "online": is_online()})

@app.route("/api/offline/pending")
@login_required
def api_offline_pending():
    return jsonify({"pending_count": get_pending_count(), "offline": not is_online()})

@app.route("/api/offline/sync", methods=["POST"])
@login_required
def api_offline_sync():
    if not is_online():
        return jsonify({"ok": False, "error": "Still offline - no internet"}), 400
    conn = sqlite3.connect(LOCAL_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM pending_sales")
    rows = c.fetchall()
    synced = 0
    failed = 0
    for r in rows:
        try:
            sale = json.loads(r["data"])
            result = fb_post("daily_sales", sale)
            if result:
                c.execute("DELETE FROM pending_sales WHERE id=?", (r["id"],))
                synced += 1
                time.sleep(0.2)
            else:
                failed += 1
        except Exception as e:
            failed += 1
    conn.commit()
    # clear cached_sales after sync
    if synced>0:
        c.execute("DELETE FROM cached_sales")
        conn.commit()
    conn.close()
    return jsonify({"ok": True, "synced": synced, "failed": failed, "remaining": get_pending_count()})

@app.route("/api/sale/<sale_id>", methods=["DELETE"])
@login_required
def api_delete_sale(sale_id):
    if str(sale_id).startswith("offline-"):
        # delete local
        try:
            oid = int(str(sale_id).replace("offline-",""))
            conn = sqlite3.connect(LOCAL_DB)
            c = conn.cursor()
            c.execute("DELETE FROM cached_sales WHERE id=?", (oid,))
            conn.commit()
            conn.close()
            return jsonify({"ok": True})
        except:
            return jsonify({"ok": False}), 400
    try:
        requests.delete(f"{FIREBASE_URL}/daily_sales/{sale_id}.json", timeout=10)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

MACHINES_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Omega Ice - Machines</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    background: #eef7ff; margin: 0; padding: 12px 12px 40px; color: #1a1a1a;
  }
  .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
  .topbar h1 { font-size: 16px; color: #00609C; margin: 0; }
  .topbar a { font-size: 12px; color: #00609C; text-decoration: none; }
  .card { background: #fff; border-radius: 12px; padding: 16px; margin-bottom: 14px; box-shadow: 0 1px 4px rgba(0,0,0,0.05); }
  input { width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #ccd; font-size: 14px; margin-bottom: 8px; }
  label { display: block; font-size: 12px; color: #666; margin: 8px 0 4px; }
  .add-btn { width: 100%; padding: 12px; background: #0096D6; color: #fff; border: none; border-radius: 10px; font-size: 14px; font-weight: 600; }
  .m-card { background: #fff; border-radius: 12px; padding: 14px; margin-bottom: 10px; box-shadow: 0 1px 4px rgba(0,0,0,0.05); }
  .m-name { font-size: 15px; font-weight: 600; margin: 0 0 2px; }
  .m-meta { font-size: 12px; color: #777; margin: 0 0 2px; }
  .m-actions { display: flex; gap: 6px; margin-top: 10px; flex-wrap: wrap; }
  .m-actions button { flex: 1; min-width: 70px; padding: 8px 0; font-size: 12px; border-radius: 8px; border: 1px solid #ccd; background: #f5f5f5; }
  .m-actions button.monitor { background: #0096D6; color: #fff; border-color: #0096D6; }
  .m-actions button.pm { background: #1a8a4a; color: #fff; border-color: #1a8a4a; }
  .m-actions button.delete { color: #c0392b; }
  .pm-overdue { color: #c73333; font-weight: 600; }
  #formPanel { display: none; }
  .form-actions { display: flex; gap: 8px; margin-top: 10px; }
  .form-actions button { flex: 1; padding: 10px; border-radius: 8px; border: none; font-size: 13px; }
  .form-actions .save { background: #00609C; color: #fff; }
  .form-actions .cancel { background: #ddd; }
  .status { font-size: 13px; text-align: center; margin-top: 8px; min-height: 18px; }
  .status.ok { color: #1a8a4a; }
  .status.err { color: #c73333; }
</style>
</head>
<body>

<div class="topbar">
  <h1>Machines</h1>
  <a href="/cashier">&larr; Cashier</a>
</div>

<div class="card">
  <input type="text" id="searchInput" placeholder="Search machine or vendor..." oninput="loadMachines()">
  <button class="add-btn" onclick="openAddForm()">+ Add machine</button>
</div>

<div class="card" id="formPanel">
  <h3 id="formTitle" style="margin:0 0 8px; font-size:14px;">Add machine</h3>
  <label>Machine name *</label>
  <input type="text" id="f_name">
  <label>Date purchased</label>
  <input type="date" id="f_date_purchase">
  <label>Unit price (₱)</label>
  <input type="number" id="f_unit_price">
  <label>Power rating (e.g. 220V / 2HP)</label>
  <input type="text" id="f_power_rating">
  <label>Wattage (W)</label>
  <input type="number" id="f_wattage">
  <label>Vendor</label>
  <input type="text" id="f_vendor">
  <label>Capacity (kg/day)</label>
  <input type="number" id="f_capacity">
  <label>PM (maintenance) date</label>
  <input type="date" id="f_pm_date">
  <label>Filter change date</label>
  <input type="date" id="f_filter_change_date">
  <label>Notes</label>
  <input type="text" id="f_notes">
  <div class="form-actions">
    <button class="save" onclick="saveMachine()">Save</button>
    <button class="cancel" onclick="closeForm()">Cancel</button>
  </div>
  <p class="status" id="formStatus"></p>
</div>

<div id="machineList"></div>

<script>
let editingId = null;

function openAddForm() {
  editingId = null;
  document.getElementById('formTitle').textContent = 'Add machine';
  ['f_name','f_date_purchase','f_unit_price','f_power_rating','f_wattage','f_vendor','f_capacity','f_pm_date','f_filter_change_date','f_notes']
    .forEach(id => document.getElementById(id).value = '');
  document.getElementById('formPanel').style.display = 'block';
  window.scrollTo({top:0, behavior:'smooth'});
}

function closeForm() {
  document.getElementById('formPanel').style.display = 'none';
}

async function saveMachine() {
  const payload = {
    machine_name: document.getElementById('f_name').value.trim(),
    date_purchase: document.getElementById('f_date_purchase').value,
    unit_price: parseFloat(document.getElementById('f_unit_price').value) || 0,
    power_rating: document.getElementById('f_power_rating').value.trim(),
    wattage: parseFloat(document.getElementById('f_wattage').value) || 0,
    vendor: document.getElementById('f_vendor').value.trim(),
    capacity: parseFloat(document.getElementById('f_capacity').value) || 0,
    pm_date: document.getElementById('f_pm_date').value,
    filter_change_date: document.getElementById('f_filter_change_date').value,
    notes: document.getElementById('f_notes').value.trim()
  };
  const statusEl = document.getElementById('formStatus');
  if (!payload.machine_name) {
    statusEl.textContent = 'Machine name is required';
    statusEl.className = 'status err';
    return;
  }
  const url = editingId ? `/api/machine/${editingId}` : '/api/machines';
  const method = editingId ? 'PUT' : 'POST';
  const res = await fetch(url, { method, headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  const data = await res.json();
  if (data.ok) {
    statusEl.textContent = 'Saved';
    statusEl.className = 'status ok';
    closeForm();
    loadMachines();
  } else {
    statusEl.textContent = data.error || 'Error saving';
    statusEl.className = 'status err';
  }
}

async function editMachine(id) {
  const res = await fetch(`/api/machine/${id}`);
  const data = await res.json();
  if (!data.ok) return;
  const m = data.machine;
  editingId = id;
  document.getElementById('formTitle').textContent = 'Edit machine';
  document.getElementById('f_name').value = m.machine_name || '';
  document.getElementById('f_date_purchase').value = m.date_purchase || '';
  document.getElementById('f_unit_price').value = m.unit_price || '';
  document.getElementById('f_power_rating').value = m.power_rating || '';
  document.getElementById('f_wattage').value = m.wattage || '';
  document.getElementById('f_vendor').value = m.vendor || '';
  document.getElementById('f_capacity').value = m.capacity || '';
  document.getElementById('f_pm_date').value = m.pm_date || '';
  document.getElementById('f_filter_change_date').value = m.filter_change_date || '';
  document.getElementById('f_notes').value = m.notes || '';
  document.getElementById('formPanel').style.display = 'block';
  window.scrollTo({top:0, behavior:'smooth'});
}

async function deleteMachine(id) {
  if (!confirm('Delete this machine? Its logs will also be removed.')) return;
  await fetch(`/api/machine/${id}`, { method: 'DELETE' });
  loadMachines();
}

async function loadMachines() {
  const q = document.getElementById('searchInput').value;
  const res = await fetch(`/api/machines?q=${encodeURIComponent(q)}`);
  const machines = await res.json();
  const listEl = document.getElementById('machineList');
  if (!machines.length) {
    listEl.innerHTML = '<div class="card">No machines yet — tap "+ Add machine" above.</div>';
    return;
  }
  listEl.innerHTML = machines.map(m => `
    <div class="m-card">
      <p class="m-name">${m.machine_name}</p>
      <p class="m-meta">${m.wattage || 0}W · ${m.vendor || 'No vendor'} · Age: ${m.age}</p>
      <p class="m-meta ${m.pm_overdue ? 'pm-overdue' : ''}">PM due: ${m.pm_date || 'N/A'}${m.pm_overdue ? ' (OVERDUE)' : ''}</p>
      <div class="m-actions">
        <button class="monitor" onclick="location.href='/machine/${m.id}/monitor'">Monitor</button>
        <button class="pm" onclick="markPmDone('${m.id}', '${m.machine_name.replace(/'/g,"\\'")}')">PM Done +30d</button>
        <button onclick="location.href='/machine/${m.id}/pm-history'">History</button>
        <button onclick="editMachine('${m.id}')">Edit</button>
        <button class="delete" onclick="deleteMachine('${m.id}')">Delete</button>
      </div>
    </div>
  `).join('');
}

async function markPmDone(id, name) {
  if (!confirm(`Mark PM (maintenance) + filter change done today for "${name}"? This sets the next due date to 30 days from now.`)) return;
  const res = await fetch(`/api/machine/${id}/pm_done`, { method: 'POST' });
  const data = await res.json();
  if (data.ok) {
    alert(`PM marked done. Next due: ${data.next_pm}`);
    loadMachines();
  } else {
    alert(data.error || 'Error marking PM done');
  }
}

loadMachines();
</script>

</body>
</html>
"""

MACHINE_MONITOR_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Omega Ice - Monitor</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    background: #eef7ff; margin: 0; padding: 12px 12px 40px; color: #1a1a1a;
  }
  .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
  .topbar h1 { font-size: 16px; color: #00609C; margin: 0; }
  .topbar a { font-size: 12px; color: #00609C; text-decoration: none; }
  .card { background: #fff; border-radius: 12px; padding: 14px; margin-bottom: 12px; box-shadow: 0 1px 4px rgba(0,0,0,0.05); }
  .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-bottom: 12px; }
  .summary div { background: #fff; border-radius: 10px; padding: 10px 4px; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,0.05); }
  .summary .val { font-size: 14px; font-weight: 600; color: #00609C; }
  .summary .lbl { font-size: 9px; color: #888; margin-top: 2px; }
  input { padding: 8px; border-radius: 8px; border: 1px solid #ccd; font-size: 13px; }
  .start-btn { width: 100%; padding: 14px; background: #0096D6; color: #fff; border: none; border-radius: 10px; font-size: 14px; font-weight: 600; margin-bottom: 12px; }
  .start-btn.running { background: #888; }
  .log-card { background: #fff; border-radius: 10px; padding: 10px 12px; margin-bottom: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.05); }
  .log-card.running { background: #fff7e0; }
  .log-top { font-size: 13px; font-weight: 500; }
  .log-sub { font-size: 11px; color: #888; margin-top: 2px; }
  .log-actions { display: flex; gap: 6px; margin-top: 8px; }
  .log-actions button { flex: 1; padding: 6px 0; font-size: 12px; border-radius: 6px; border: none; }
  .log-actions .add { background: #0096D6; color: #fff; }
  .log-actions .stop { background: #c0392b; color: #fff; }
  .status { font-size: 13px; text-align: center; margin-top: 8px; min-height: 18px; }
  .status.ok { color: #1a8a4a; }
  .status.err { color: #c73333; }
</style>
</head>
<body>

<div class="topbar">
  <h1 id="machineTitle">Machine</h1>
  <a href="/machines">&larr; Machines</a>
</div>

<div class="card">
  <label style="font-size:12px; color:#666;">Date</label>
  <div style="display:flex; gap:6px; margin-top:4px;">
    <input type="date" id="dateInput" style="flex:1;">
    <button onclick="loadLogs()" style="padding:8px 14px; border-radius:8px; border:none; background:#0096D6; color:#fff; font-size:13px;">Load</button>
  </div>
</div>

<div class="summary">
  <div><div class="val" id="sumHours">0h</div><div class="lbl">HOURS</div></div>
  <div><div class="val" id="sumOutput">0kg</div><div class="lbl">OUTPUT</div></div>
  <div><div class="val" id="sumCost">₱0</div><div class="lbl">ELEC COST</div></div>
  <div><div class="val" id="sumCpk">₱0/kg</div><div class="lbl">COST/KG</div></div>
</div>

<button class="start-btn" id="startBtn" onclick="startMachine()">Start machine — save start time</button>
<p class="status" id="statusMsg"></p>

<div id="logsList"></div>

<script>
const machineId = "{{ machine_id }}";
document.getElementById('machineTitle').textContent = "{{ machine_name }} \u2022 {{ wattage }}W";
document.getElementById('dateInput').value = new Date().toISOString().slice(0,10);

// Wraps fetch so failures are always visible instead of silent:
// - session expired (redirected to login) shows a clear message
// - network errors show a clear message
// - non-OK HTTP status shows the status code
async function safeFetchJson(url, options) {
  const statusEl = document.getElementById('statusMsg');
  try {
    const res = await fetch(url, options);
    if (res.redirected && res.url.includes('/login')) {
      statusEl.textContent = 'Session expired — please log in again';
      statusEl.className = 'status err';
      return null;
    }
    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      statusEl.textContent = `Unexpected response (status ${res.status}) — try logging in again`;
      statusEl.className = 'status err';
      return null;
    }
    const data = await res.json();
    if (!res.ok && !('ok' in data)) {
      statusEl.textContent = data.error || `Server error (status ${res.status})`;
      statusEl.className = 'status err';
      return null;
    }
    return data;
  } catch (err) {
    statusEl.textContent = 'Network error — check your connection: ' + err.message;
    statusEl.className = 'status err';
    return null;
  }
}

async function startMachine() {
  const data = await safeFetchJson(`/api/machine/${machineId}/start`, { method: 'POST' });
  if (!data) return;
  const statusEl = document.getElementById('statusMsg');
  if (data.ok) {
    statusEl.textContent = 'Machine started';
    statusEl.className = 'status ok';
    loadLogs();
  } else {
    statusEl.textContent = data.error || 'Error starting machine';
    statusEl.className = 'status err';
  }
}

async function addHarvest(logId) {
  const kg = prompt('Enter harvested kg for this batch:');
  if (!kg || isNaN(parseFloat(kg))) return;
  const data = await safeFetchJson(`/api/machine/${machineId}/harvest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ log_id: logId, kg: parseFloat(kg) })
  });
  if (!data) return;
  const statusEl = document.getElementById('statusMsg');
  if (data.ok) {
    statusEl.textContent = `Harvest of ${kg}kg added`;
    statusEl.className = 'status ok';
  } else {
    statusEl.textContent = data.error || 'Error adding harvest';
    statusEl.className = 'status err';
  }
  loadLogs();
}

async function stopMachine(logId) {
  if (!confirm('Stop this machine run? This will compute total output and electricity cost.')) return;
  const data = await safeFetchJson(`/api/machine/${machineId}/stop`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ log_id: logId })
  });
  if (!data) return;
  const statusEl = document.getElementById('statusMsg');
  if (data.ok) {
    statusEl.textContent = `Stopped — ${data.output_kg}kg, ₱${data.expense} electricity`;
    statusEl.className = 'status ok';
  } else {
    statusEl.textContent = data.error || 'Error stopping machine';
    statusEl.className = 'status err';
  }
  loadLogs();
}

async function loadLogs() {
  const date = document.getElementById('dateInput').value;
  const data = await safeFetchJson(`/api/machine/${machineId}/logs?date=${date}`);
  if (!data) return;

  document.getElementById('sumHours').textContent = (data.total_hours || 0).toFixed(1) + 'h';
  document.getElementById('sumOutput').textContent = (data.total_output || 0).toFixed(0) + 'kg';
  document.getElementById('sumCost').textContent = '₱' + (data.total_expense || 0).toFixed(0);
  document.getElementById('sumCpk').textContent = '₱' + (data.avg_cost_per_kg || 0).toFixed(2) + '/kg';

  const startBtn = document.getElementById('startBtn');
  startBtn.classList.toggle('running', data.has_running);
  startBtn.textContent = data.has_running ? 'Machine running...' : 'Start machine — save start time';
  startBtn.disabled = data.has_running;

  const listEl = document.getElementById('logsList');
  if (!data.logs || !data.logs.length) {
    listEl.innerHTML = '<div class="card">No logs for this date yet.</div>';
    return;
  }
  listEl.innerHTML = data.logs.map(lg => {
    if (lg.status === 'RUNNING') {
      return `
        <div class="log-card running">
          <div class="log-top">${lg.start_time} - RUNNING</div>
          <div class="log-sub">Harvest so far: ${lg.harvest_kg || 0}kg (${lg.harvest_count || 0}x)</div>
          <div class="log-actions">
            <button class="add" onclick="addHarvest('${lg.id}')">Add harvest</button>
            <button class="stop" onclick="stopMachine('${lg.id}')">Stop</button>
          </div>
        </div>`;
    } else {
      return `
        <div class="log-card">
          <div class="log-top">${lg.start_time} - ${lg.end_time} = ${(lg.operating_hours||0).toFixed(1)}h</div>
          <div class="log-sub">Output ${(lg.output_kg||0).toFixed(0)}kg | ₱${(lg.expense||0).toFixed(0)} | ₱${(lg.cost_per_kg||0).toFixed(2)}/kg</div>
        </div>`;
    }
  }).join('');
}

loadLogs();
</script>

</body>
</html>
"""


# ---------- Machine routes ----------

@app.route("/debug/machines")
def debug_machines():
    raw = fb_get("machines")
    return jsonify({
        "firebase_url": FIREBASE_URL,
        "online": is_online(),
        "raw_machines_node": raw,
        "count": len(raw) if isinstance(raw, dict) else (0 if raw is None else "not a dict - see raw_machines_node")
    })

@app.route("/debug/resellers")
def debug_resellers():
    raw = fb_get("resellers") or {}
    # group by store_name to surface duplicates clearly
    by_name = {}
    for key, val in raw.items():
        if not val:
            continue
        name = (val.get("store_name") or "").strip()
        by_name.setdefault(name, []).append({"firebase_key": key, **val})
    duplicates = {name: entries for name, entries in by_name.items() if len(entries) > 1}
    return jsonify({
        "total_resellers": len(raw),
        "duplicate_names": duplicates,
        "duplicate_count": len(duplicates)
    })


@app.route("/debug/fix_reseller_duplicates")
def fix_reseller_duplicates():
    """
    One-time cleanup: the migration script created a second, sparse
    reseller entry (keyed by old numeric SQLite id) for every reseller
    that already existed in Firebase (keyed by a real push-id, with
    full address/contact/GPS data).

    This keeps the RICH entry (push-id key, more fields filled in),
    re-points any daily_sales that reference the SPARSE entry's key
    over to the rich entry's key, merges credit_balance if needed,
    then deletes the sparse duplicate.

    Safe to run more than once - if there are no more duplicates,
    it does nothing.
    """
    resellers = fb_get("resellers") or {}
    sales = fb_get("daily_sales") or {}

    by_name = {}
    for key, val in resellers.items():
        if not val:
            continue
        name = (val.get("store_name") or "").strip()
        by_name.setdefault(name, []).append((key, val))

    report = []

    for name, entries in by_name.items():
        if len(entries) < 2:
            continue

        # Prefer the entry with a real Firebase push-key (starts with "-")
        # and more populated fields as the one to KEEP.
        def richness(entry):
            key, val = entry
            score = 1 if key.startswith("-") else 0
            score += sum(1 for f in ("address", "contact_no", "owner_name", "latitude") if val.get(f))
            return score

        entries_sorted = sorted(entries, key=richness, reverse=True)
        keep_key, keep_val = entries_sorted[0]
        remove_entries = entries_sorted[1:]

        merged_sales = 0
        for remove_key, remove_val in remove_entries:
            # re-point any sales referencing the sparse entry
            for sale_id, sale in sales.items():
                if sale and str(sale.get("reseller_id")) == str(remove_key):
                    fb_patch(f"daily_sales/{sale_id}", {"reseller_id": keep_key})
                    merged_sales += 1

            # merge credit balance if the removed entry had one
            remove_bal = remove_val.get("credit_balance") or 0
            if remove_bal:
                keep_bal = keep_val.get("credit_balance") or 0
                fb_patch(f"resellers/{keep_key}", {"credit_balance": keep_bal + remove_bal})

            # delete the sparse duplicate
            requests.delete(f"{FIREBASE_URL}/resellers/{remove_key}.json", timeout=10)

            report.append({
                "store_name": name,
                "kept_key": keep_key,
                "removed_key": remove_key,
                "sales_repointed": merged_sales,
            })

    return jsonify({"merged": report, "duplicates_fixed": len(report)})

@app.route("/machines")
@login_required
def machines_page():
    return render_template_string(MACHINES_HTML)


@app.route("/api/machines")
@login_required
def api_machines():
    q = request.args.get("q", "").strip().lower()
    data = fb_get("machines") or {}
    machines = []
    for key, val in data.items():
        if not val:
            continue
        name = val.get("machine_name", "")
        vendor = val.get("vendor", "")
        if q and q not in name.lower() and q not in vendor.lower():
            continue
        m = dict(val)
        m["id"] = key
        m["age"] = calc_machine_age(val.get("date_purchase"))
        m["pm_overdue"] = is_pm_overdue(val.get("pm_date"))
        machines.append(m)
    machines.sort(key=lambda x: x.get("machine_name", ""))
    return jsonify(machines)


@app.route("/api/machines", methods=["POST"])
@login_required
def api_create_machine():
    data = request.json or {}
    name = data.get("machine_name", "").strip()
    if not name:
        return jsonify({"ok": False, "error": "Machine name is required"}), 400
    machine = {
        "machine_name": name,
        "date_purchase": data.get("date_purchase", ""),
        "unit_price": float(data.get("unit_price") or 0),
        "power_rating": data.get("power_rating", ""),
        "wattage": float(data.get("wattage") or 0),
        "vendor": data.get("vendor", ""),
        "capacity": float(data.get("capacity") or 0),
        "pm_date": data.get("pm_date", ""),
        "filter_change_date": data.get("filter_change_date", ""),
        "notes": data.get("notes", ""),
    }
    result = fb_post("machines", machine)
    if result:
        return jsonify({"ok": True, "id": result.get("name")})
    return jsonify({"ok": False, "error": "Could not save — check internet connection"}), 503


@app.route("/api/machine/<machine_id>", methods=["GET"])
@login_required
def api_get_machine(machine_id):
    data = fb_get(f"machines/{machine_id}")
    if not data:
        return jsonify({"ok": False, "error": "Machine not found"}), 404
    return jsonify({"ok": True, "machine": data})


@app.route("/api/machine/<machine_id>", methods=["PUT"])
@login_required
def api_update_machine(machine_id):
    data = request.json or {}
    name = data.get("machine_name", "").strip()
    if not name:
        return jsonify({"ok": False, "error": "Machine name is required"}), 400
    machine = {
        "machine_name": name,
        "date_purchase": data.get("date_purchase", ""),
        "unit_price": float(data.get("unit_price") or 0),
        "power_rating": data.get("power_rating", ""),
        "wattage": float(data.get("wattage") or 0),
        "vendor": data.get("vendor", ""),
        "capacity": float(data.get("capacity") or 0),
        "pm_date": data.get("pm_date", ""),
        "filter_change_date": data.get("filter_change_date", ""),
        "notes": data.get("notes", ""),
    }
    result = fb_put(f"machines/{machine_id}", machine)
    if result is not None:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Could not update — check internet connection"}), 503


@app.route("/api/machine/<machine_id>", methods=["DELETE"])
@login_required
def api_delete_machine(machine_id):
    try:
        requests.delete(f"{FIREBASE_URL}/machines/{machine_id}.json", timeout=10)
        # also remove its logs
        logs = fb_get("machine_logs") or {}
        for lid, lg in logs.items():
            if lg and lg.get("machine_id") == machine_id:
                requests.delete(f"{FIREBASE_URL}/machine_logs/{lid}.json", timeout=10)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/machine/<machine_id>/monitor")
@login_required
def machine_monitor_page(machine_id):
    m = fb_get(f"machines/{machine_id}") or {}
    return render_template_string(
        MACHINE_MONITOR_HTML,
        machine_id=machine_id,
        machine_name=m.get("machine_name", "Machine"),
        wattage=m.get("wattage", 0),
    )


@app.route("/api/machine/<machine_id>/start", methods=["POST"])
@login_required
def api_start_machine(machine_id):
    # Prevent starting if already running today
    logs = fb_get("machine_logs") or {}
    today = datetime.now().strftime("%Y-%m-%d")
    for lg in logs.values():
        if lg and lg.get("machine_id") == machine_id and lg.get("status") == "RUNNING":
            return jsonify({"ok": False, "error": "Machine is already running"}), 400
    log = {
        "machine_id": machine_id,
        "log_date": today,
        "start_time": datetime.now().strftime("%H:%M"),
        "end_time": None,
        "output_kg": 0,
        "operating_hours": 0,
        "rate_per_kwh": get_electricity_rate(),
        "expense": 0,
        "cost_per_kg": 0,
        "status": "RUNNING",
        "started_at": datetime.now().isoformat(),
        "staff_name": session.get("staff_name"),
    }
    result = fb_post("machine_logs", log)
    if result:
        return jsonify({"ok": True, "log_id": result.get("name")})
    return jsonify({"ok": False, "error": "Could not start — check internet connection"}), 503


@app.route("/api/machine/<machine_id>/harvest", methods=["POST"])
@login_required
def api_add_harvest(machine_id):
    data = request.json or {}
    log_id = data.get("log_id")
    kg = float(data.get("kg") or 0)
    if not log_id or kg <= 0:
        return jsonify({"ok": False, "error": "Valid log and kg amount required"}), 400
    harvest = {"log_id": log_id, "kg": kg, "timestamp": datetime.now().isoformat()}
    result = fb_post("machine_harvests", harvest)
    if result:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Could not save harvest — check internet connection"}), 503


@app.route("/api/machine/<machine_id>/stop", methods=["POST"])
@login_required
def api_stop_machine(machine_id):
    data = request.json or {}
    log_id = data.get("log_id")
    log = fb_get(f"machine_logs/{log_id}")
    if not log:
        return jsonify({"ok": False, "error": "Log not found"}), 404

    # sum harvests for this log
    harvests = fb_get("machine_harvests") or {}
    total_kg = sum(h.get("kg", 0) for h in harvests.values() if h and h.get("log_id") == log_id)

    started_at = log.get("started_at")
    operating_hours = 0
    if started_at:
        try:
            start_dt = datetime.fromisoformat(started_at)
            operating_hours = (datetime.now() - start_dt).total_seconds() / 3600
        except:
            pass

    machine = fb_get(f"machines/{machine_id}") or {}
    wattage = float(machine.get("wattage") or 0)
    rate = log.get("rate_per_kwh") or get_electricity_rate()
    kwh_used = (wattage / 1000) * operating_hours
    expense = round(kwh_used * rate, 2)
    cost_per_kg = round(expense / total_kg, 2) if total_kg > 0 else 0

    update = {
        "end_time": datetime.now().strftime("%H:%M"),
        "output_kg": total_kg,
        "operating_hours": round(operating_hours, 2),
        "expense": expense,
        "cost_per_kg": cost_per_kg,
        "status": "STOPPED",
    }
    fb_patch(f"machine_logs/{log_id}", update)
    return jsonify({"ok": True, "output_kg": total_kg, "expense": expense, "cost_per_kg": cost_per_kg})


@app.route("/api/machine/<machine_id>/logs")
@login_required
def api_machine_logs(machine_id):
    log_date = request.args.get("date") or datetime.now().strftime("%Y-%m-%d")
    all_logs = fb_get("machine_logs") or {}
    harvests = fb_get("machine_harvests") or {}

    logs = []
    total_hours = total_output = total_expense = 0
    has_running = False

    for lid, lg in all_logs.items():
        if not lg or lg.get("machine_id") != machine_id or lg.get("log_date") != log_date:
            continue
        entry = dict(lg)
        entry["id"] = lid
        if lg.get("status") == "RUNNING":
            has_running = True
            hs = [h for h in harvests.values() if h and h.get("log_id") == lid]
            entry["harvest_kg"] = sum(h.get("kg", 0) for h in hs)
            entry["harvest_count"] = len(hs)
        else:
            total_hours += lg.get("operating_hours", 0) or 0
            total_output += lg.get("output_kg", 0) or 0
            total_expense += lg.get("expense", 0) or 0
        logs.append(entry)

    logs.sort(key=lambda x: x.get("start_time", ""))
    avg_cpk = round(total_expense / total_output, 2) if total_output > 0 else 0

    return jsonify({
        "logs": logs,
        "total_hours": total_hours,
        "total_output": total_output,
        "total_expense": total_expense,
        "avg_cost_per_kg": avg_cpk,
        "has_running": has_running,
    })


PM_HISTORY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PM History</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    background: #eef7ff; margin: 0; padding: 12px 12px 40px; color: #1a1a1a;
  }
  .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
  .topbar h1 { font-size: 16px; color: #00609C; margin: 0; }
  .topbar a { font-size: 12px; color: #00609C; text-decoration: none; }
  .card { background: #fff; border-radius: 12px; padding: 14px; margin-bottom: 10px; box-shadow: 0 1px 4px rgba(0,0,0,0.05); }
  .pm-top { font-size: 13px; font-weight: 500; }
  .pm-sub { font-size: 12px; color: #888; margin-top: 3px; }
  .pm-notes { font-size: 11px; color: #aaa; margin-top: 4px; }
</style>
</head>
<body>

<div class="topbar">
  <h1 id="pageTitle">PM History</h1>
  <a href="/machines">&larr; Machines</a>
</div>

<div id="historyList">Loading...</div>

<script>
const machineId = "{{ machine_id }}";
document.getElementById('pageTitle').textContent = "{{ machine_name }} \u2022 PM History";

async function loadHistory() {
  const res = await fetch(`/api/machine/${machineId}/pm_history`);
  const rows = await res.json();
  const listEl = document.getElementById('historyList');
  if (!rows.length) {
    listEl.innerHTML = '<div class="card">No PM history yet — use "PM Done +30d" on the Machines page to create one.</div>';
    return;
  }
  listEl.innerHTML = rows.map(r => `
    <div class="card">
      <div class="pm-top">PM done: ${r.pm_done_date} &rarr; Next: ${r.next_pm_due || 'N/A'}</div>
      <div class="pm-sub">Filter: ${r.filter_done_date || '-'} &rarr; Next: ${r.next_filter_due || 'N/A'}</div>
      <div class="pm-notes">${r.notes || ''} | ${r.created_at || ''}</div>
    </div>
  `).join('');
}

loadHistory();
</script>

</body>
</html>
"""



@app.route("/api/sale/<sale_id>", methods=["GET"])
@login_required
def api_get_sale(sale_id):
    if str(sale_id).startswith("offline-"):
        try:
            oid = int(str(sale_id).replace("offline-",""))
            conn = sqlite3.connect(LOCAL_DB)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM cached_sales WHERE id=?", (oid,))
            r = c.fetchone()
            conn.close()
            if r:
                return jsonify({"ok": True, "sale": {"id": sale_id, "reseller_id": None, "reseller_name": r["reseller_name"], "quantity": r["quantity"], "kg_size": r["kg_size"], "mode": r["mode"], "payment": r["payment"]}})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 404
    data = fb_get(f"daily_sales/{sale_id}")
    if data:
        return jsonify({"ok": True, "sale": {"id": sale_id, "reseller_id": data.get("reseller_id"), "reseller_name": data.get("reseller_name"), "quantity": data.get("quantity"), "kg_size": data.get("kg_size"), "mode": data.get("mode","DELIVER"), "payment": data.get("payment","Cash")}})
    return jsonify({"ok": False, "error": "Not found"}), 404

@app.route("/api/sale/<sale_id>", methods=["PUT"])
@login_required
def api_update_sale(sale_id):
    d = request.json or {}
    qty = int(d.get("quantity",1))
    kg_size = d.get("kg_size","1Kg")
    mode = d.get("mode","DELIVER")
    payment = d.get("payment","Cash")
    reseller_name = d.get("reseller_name","").strip()
    reseller_id = d.get("reseller_id")
    if not reseller_name or qty<=0:
        return jsonify({"ok": False, "error": "Missing"}), 400
    unit_price = get_price(kg_size, mode)
    total = round(unit_price*qty,2)
    if str(sale_id).startswith("offline-"):
        try:
            oid = int(str(sale_id).replace("offline-",""))
            conn = sqlite3.connect(LOCAL_DB)
            c = conn.cursor()
            c.execute("UPDATE cached_sales SET reseller_name=?, quantity=?, kg_size=?, total_sales=?, mode=?, payment=? WHERE id=?", (reseller_name, qty, kg_size, total, mode, payment, oid))
            conn.commit()
            conn.close()
            return jsonify({"ok": True, "total": total, "unit_price": unit_price})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
    existing = fb_get(f"daily_sales/{sale_id}")
    if not existing:
        return jsonify({"ok": False, "error": "Not found"}), 404
    fb_patch(f"daily_sales/{sale_id}", {"reseller_name": reseller_name, "reseller_id": reseller_id, "quantity": qty, "kg_size": kg_size, "mode": mode, "payment": payment, "payment_mode": payment, "delivery_mode": mode, "total_sales": total, "unit_price": unit_price})
    return jsonify({"ok": True, "total": total, "unit_price": unit_price})

# ---------- PM (preventive maintenance) routes ----------

@app.route("/api/machine/<machine_id>/pm_done", methods=["POST"])
@login_required
def api_pm_done(machine_id):
    machine = fb_get(f"machines/{machine_id}")
    if not machine:
        return jsonify({"ok": False, "error": "Machine not found"}), 404

    today = datetime.now().strftime("%Y-%m-%d")
    next_pm = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")

    # update the machine's due dates
    fb_patch(f"machines/{machine_id}", {"pm_date": next_pm, "filter_change_date": next_pm})

    # record the history entry
    entry = {
        "machine_id": machine_id,
        "pm_done_date": today,
        "next_pm_due": next_pm,
        "filter_done_date": today,
        "next_filter_due": next_pm,
        "notes": "Monthly PM + Filter Done",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "staff_name": session.get("staff_name"),
    }
    result = fb_post("pm_history", entry)
    if result:
        return jsonify({"ok": True, "next_pm": next_pm})
    return jsonify({"ok": False, "error": "Could not save — check internet connection"}), 503


@app.route("/api/machine/<machine_id>/pm_history")
@login_required
def api_pm_history(machine_id):
    all_history = fb_get("pm_history") or {}
    rows = [dict(v, id=k) for k, v in all_history.items() if v and v.get("machine_id") == machine_id]
    rows.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify(rows)


@app.route("/machine/<machine_id>/pm-history")
@login_required
def pm_history_page(machine_id):
    m = fb_get(f"machines/{machine_id}") or {}
    return render_template_string(
        PM_HISTORY_HTML,
        machine_id=machine_id,
        machine_name=m.get("machine_name", "Machine"),
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Omega Purified Ice OFFLINE MODE ready")
    print(f"Firebase: {FIREBASE_URL}")
    print(f"Local DB: {LOCAL_DB}")
    print(f"Pending offline: {get_pending_count()}")
    print(f"Listening on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
