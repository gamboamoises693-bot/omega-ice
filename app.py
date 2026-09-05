
"""
Omega Ice - Cloud Website Version (Render.com)
Free hosting - no Pydroid3 needed
Firebase: https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app
"""

import os, requests
from datetime import datetime
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "omega-ice-2026-free-website")

FIREBASE_URL = "https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app".rstrip("/")

KG_OPTIONS = ["1Kg", "5Kg", "10Kg", "25Kg"]
FALLBACK_PRICES = {"1Kg": 10, "5Kg": 50, "10Kg": 100, "25Kg": 250}

# --- Firebase helpers ---
def fb_get(path):
    try:
        r = requests.get(f"{FIREBASE_URL}/{path}.json", timeout=10)
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
        return r.json()
    except Exception as e:
        print(f"PUT {path} error: {e}")
        return None

def fb_patch(path, data):
    try:
        r = requests.patch(f"{FIREBASE_URL}/{path}.json", json=data, timeout=10)
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

def login_required(view):
    def wrapped(*args, **kwargs):
        if not session.get("staff_name"):
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Omega Ice - Login</title>
<style>
  *{box-sizing:border-box} body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;background:#eef7ff;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
  .card{background:#fff;border-radius:16px;padding:28px 24px;width:100%;max-width:340px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,0.06)}
  h1{font-size:20px;color:#00609C;margin:0 0 4px} .subtitle{font-size:13px;color:#333;margin:0 0 4px;font-weight:600} .tagline{font-size:11px;color:#888;margin:0 0 24px}
  .dots{font-size:28px;letter-spacing:6px;margin-bottom:8px;color:#222} .msg{font-size:12px;color:#888;min-height:18px;margin-bottom:16px}
  .keypad{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px}
  .keypad button{padding:16px 0;font-size:20px;border-radius:10px;border:none;background:#f2f2f2;color:#111}
  .keypad button.clear{background:#e5433d;color:#fff} .keypad button.back{background:#999;color:#fff}
  .footer{font-size:10px;color:#aaa;margin-top:10px}
</style>
</head>
<body>
<div class="card">
  <h1>OMEGA PURIFIED ICE</h1><p class="subtitle">STAFF LOGIN</p><p class="tagline">Sales quick access - Cloud</p>
  <div class="dots" id="dots">o&nbsp;&nbsp;&nbsp;o&nbsp;&nbsp;&nbsp;o&nbsp;&nbsp;&nbsp;o</div><p class="msg" id="msg">Enter 4-digit PIN</p>
  <div class="keypad">
    <button onclick="addDigit('1')">1</button><button onclick="addDigit('2')">2</button><button onclick="addDigit('3')">3</button>
    <button onclick="addDigit('4')">4</button><button onclick="addDigit('5')">5</button><button onclick="addDigit('6')">6</button>
    <button onclick="addDigit('7')">7</button><button onclick="addDigit('8')">8</button><button onclick="addDigit('9')">9</button>
    <button class="clear" onclick="clearPin()">C</button><button onclick="addDigit('0')">0</button><button class="back" onclick="backspace()">&lt;</button>
  </div>
  <p class="footer">Cloud Version - Free Hosting</p>
</div>
<script>
let pin="";
function updateDots(){const dots=document.getElementById('dots');let out="";for(let i=0;i<4;i++)out+=(i<pin.length?"*":"o")+"&nbsp;&nbsp;&nbsp;";dots.innerHTML=out;}
function addDigit(d){if(pin.length<4){pin+=d;updateDots();if(pin.length===4)setTimeout(doLogin,200);}}
function backspace(){pin=pin.slice(0,-1);updateDots();}
function clearPin(){pin="";updateDots();document.getElementById('msg').textContent="Enter 4-digit PIN";}
async function doLogin(){const res=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin})});const data=await res.json();if(data.ok){window.location.href='/cashier';}else{document.getElementById('msg').textContent=data.error||'Wrong PIN';setTimeout(clearPin,800);}}
</script>
</body>
</html>
"""

CASHIER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Omega Ice - Cashier</title>
<style>
  *{box-sizing:border-box} body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;background:#eef7ff;margin:0;padding:12px 12px 40px;color:#1a1a1a}
  .topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px} .topbar h1{font-size:16px;color:#00609C;margin:0} .topbar .staff{font-size:12px;color:#555} .logout{font-size:12px;color:#c0392b;background:none;border:none}
  .card{background:#fff;border-radius:12px;padding:16px;margin-bottom:14px;box-shadow:0 1px 4px rgba(0,0,0,0.05)}
  label{display:block;font-size:12px;color:#666;margin:10px 0 4px} input,select{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:14px}
  .toggle-row{display:flex;gap:8px;margin-top:4px} .toggle-row button{flex:1;padding:10px;border-radius:8px;border:1px solid #ccd;background:#f5f5f5;font-size:13px} .toggle-row button.active{background:#0096D6;color:#fff;border-color:#0096D6}
  .kg-row{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-top:4px} .kg-row button{padding:10px 0;border-radius:8px;border:1px solid #ccd;background:#f5f5f5;font-size:13px} .kg-row button.active{background:#0096D6;color:#fff;border-color:#0096D6}
  .total-row{display:flex;justify-content:space-between;align-items:baseline;margin:16px 0 4px;font-size:14px;color:#444} .total-row .amount{font-size:24px;font-weight:600;color:#00609C}
  .save-btn{width:100%;padding:14px;margin-top:12px;background:#00609C;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600}
  #resellerResults{border:1px solid #ddd;border-radius:8px;margin-top:4px;max-height:160px;overflow-y:auto;display:none;background:#fff;position:relative;z-index:10}
  #resellerResults div{padding:10px;font-size:14px;border-bottom:1px solid #eee;cursor:pointer} #resellerResults div:hover{background:#f0f8ff}
  .status{font-size:13px;text-align:center;margin-top:8px;min-height:18px} .status.ok{color:#1a8a4a} .status.err{color:#c73333}
  table{width:100%;border-collapse:collapse;font-size:12px} th,td{text-align:left;padding:6px 4px;border-bottom:1px solid #eee} th{color:#888;font-weight:500} .del-btn{background:none;border:none;color:#c0392b;font-size:12px}
  .cloud-badge{position:fixed;top:10px;right:10px;z-index:9999;padding:6px 10px;border-radius:20px;font-size:11px;background:#00aa44;color:white}
</style>
</head>
<body>
<div class="cloud-badge">☁️ Cloud - Live</div>
<div class="topbar"><h1>OMEGA ICE - Cashier ☁️</h1><div><span class="staff">{{ staff_name }} ({{ staff_position }})</span><button class="logout" onclick="logout()">Logout</button></div></div>
<div class="card">
  <label>Reseller / customer</label><input type="text" id="resellerInput" placeholder="Type to search or add new" autocomplete="off"><div id="resellerResults"></div>
  <label>Delivery mode</label><div class="toggle-row"><button id="modeDeliver" class="active" onclick="setMode('DELIVER')">Deliver</button><button id="modePickup" onclick="setMode('PICKUP')">Pickup</button></div>
  <label>Payment</label><div class="toggle-row"><button id="payCash" class="active" onclick="setPayment('Cash')">Cash</button><button id="payCredit" onclick="setPayment('Credit')">Credit</button></div>
  <label>Size</label><div class="kg-row">{% for kg in kg_options %}<button data-kg="{{ kg }}" onclick="setKg('{{ kg }}')" class="{{ 'active' if loop.first else '' }}">{{ kg }}</button>{% endfor %}</div>
  <label>Quantity</label><input type="number" id="qtyInput" value="1" min="1" oninput="updateTotal()">
  <div class="total-row"><span>Total</span><span class="amount" id="totalAmount">₱0</span></div>
  <button class="save-btn" id="saveBtn" onclick="saveSale()">Save sale</button><p class="status" id="statusMsg"></p>
</div>
<div class="card"><label style="margin-top:0;">Recent sales (Live from Cloud)</label><table><thead><tr><th>Date</th><th>Reseller</th><th>Qty</th><th>Size</th><th>Total</th><th></th></tr></thead><tbody id="recentBody"></tbody></table></div>
<script>
let mode='DELIVER'; let payment='Cash'; let kg='{{ kg_options[0] }}'; let selectedReseller=null; let unitPrice=0;
function setMode(m){mode=m; document.getElementById('modeDeliver').classList.toggle('active',m==='DELIVER'); document.getElementById('modePickup').classList.toggle('active',m==='PICKUP'); updateTotal();}
function setPayment(p){payment=p; document.getElementById('payCash').classList.toggle('active',p==='Cash'); document.getElementById('payCredit').classList.toggle('active',p==='Credit');}
function setKg(k){kg=k; document.querySelectorAll('.kg-row button').forEach(b=>b.classList.toggle('active',b.dataset.kg===k)); updateTotal();}
async function updateTotal(){const res=await fetch(`/api/price?kg=${kg}&mode=${mode}`); const data=await res.json(); unitPrice=data.price; const qty=parseInt(document.getElementById('qtyInput').value)||0; document.getElementById('totalAmount').textContent='₱'+(unitPrice*qty).toLocaleString();}
const resellerInput=document.getElementById('resellerInput'); const resultsBox=document.getElementById('resellerResults');
resellerInput.addEventListener('input', async ()=>{
  selectedReseller=null; const q=resellerInput.value.trim(); if(!q){resultsBox.style.display='none';return;}
  try{const res=await fetch(`/api/resellers?q=${encodeURIComponent(q)}`); const rows=await res.json(); if(!rows.length){resultsBox.style.display='none';return;}
  resultsBox.innerHTML=rows.map(r=>`<div class="res-item" data-id="${r.id}" data-name="${r.store_name.replace(/"/g,'&quot;')}">${r.store_name}</div>`).join(''); resultsBox.style.display='block';
  resultsBox.querySelectorAll('.res-item').forEach(el=>{el.addEventListener('click',()=>{pickReseller(el.getAttribute('data-id'),el.getAttribute('data-name'));});});}catch(e){resultsBox.style.display='none';}
});
document.addEventListener('click',(e)=>{if(!resellerInput.contains(e.target)&&!resultsBox.contains(e.target)){resultsBox.style.display='none';}});
function pickReseller(id,name){selectedReseller={id,name}; resellerInput.value=name; resultsBox.style.display='none';}
async function saveSale(){
  const qty=parseInt(document.getElementById('qtyInput').value)||0; const name=resellerInput.value.trim(); const statusEl=document.getElementById('statusMsg');
  if(!name||qty<=0){statusEl.textContent='Enter reseller name and quantity'; statusEl.className='status err'; return;}
  const payload={reseller_id:selectedReseller?selectedReseller.id:null,reseller_name:name,quantity:qty,kg_size:kg,mode:mode,payment:payment};
  statusEl.textContent='Saving...'; statusEl.className='status';
  const res=await fetch('/api/sale',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await res.json();
  if(data.ok){statusEl.textContent=`Saved — total ₱${data.total} ☁️`; statusEl.className='status ok'; resellerInput.value=''; selectedReseller=null; document.getElementById('qtyInput').value=1; updateTotal(); loadRecent();}
  else{statusEl.textContent=data.error||'Error saving'; statusEl.className='status err';}
}
async function loadRecent(){
  const res=await fetch('/api/sales/recent'); const rows=await res.json();
  document.getElementById('recentBody').innerHTML=rows.map(r=>{
    let dateStr=r.sales_date||''; if(dateStr.includes('-')){let parts=dateStr.split(' ')[0].split('-'); if(parts.length>=3) dateStr=parts[1]+'/'+parts[2];}
    return `<tr><td style="font-size:11px;color:#666;white-space:nowrap;">${dateStr}</td><td>${r.reseller_name}</td><td>${r.quantity}</td><td>${r.kg_size}</td><td>₱${r.total_sales}</td><td><button class="del-btn" onclick="deleteSale('${r.id}')">Del</button></td></tr>`;
  }).join('');
}
async function deleteSale(id){if(!confirm('Delete this sale?'))return; await fetch(`/api/sale/${id}`,{method:'DELETE'}); loadRecent();}
async function logout(){await fetch('/api/logout',{method:'POST'}); window.location.href='/login';}
updateTotal(); loadRecent(); setInterval(loadRecent,5000);
</script>
</body>
</html>
"""

@app.route("/")
def root():
    if session.get("staff_name"):
        return redirect(url_for("cashier_page"))
    return redirect(url_for("login_page"))

@app.route("/login")
def login_page():
    return render_template_string(LOGIN_HTML)

@app.route("/api/login", methods=["POST"])
def api_login():
    pin = (request.json or {}).get("pin", "").strip()
    if len(pin) != 4:
        return jsonify({"ok": False, "error": "Enter 4-digit PIN"}), 400
    staff_data = fb_get("staff")
    if not staff_data:
        return jsonify({"ok": False, "error": "No staff found"}), 404
    for key, val in staff_data.items():
        if val and val.get("pin") == pin and val.get("status") == "Active":
            session["staff_id"] = key
            session["staff_name"] = val.get("name")
            session["staff_position"] = val.get("position", "Staff")
            return jsonify({"ok": True, "name": val.get("name"), "position": val.get("position")})
    return jsonify({"ok": False, "error": "Wrong PIN"}), 401

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
    data = fb_get("resellers")
    if not data:
        return jsonify([])
    resellers = []
    for key, val in data.items():
        if val:
            name = val.get("store_name", "")
            if not q or q in name.lower():
                resellers.append({"id": key, "store_name": name, "credit_balance": val.get("credit_balance", 0)})
    resellers.sort(key=lambda x: x["store_name"])
    return jsonify(resellers[:50] if not q else resellers[:20])

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
        "staff_name": session.get("staff_name"),
        "created_at": datetime.now().isoformat()
    }
    result = fb_post("daily_sales", sale)
    if payment == "Credit" and reseller_id:
        reseller = fb_get(f"resellers/{reseller_id}")
        if reseller:
            cur = float(reseller.get("credit_balance", 0) or 0)
            fb_patch(f"resellers/{reseller_id}", {"credit_balance": cur + total})
    fb_post("staff_logs", {"log_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "staff_name": session.get("staff_name"), "action": "SALE", "reseller_name": reseller_name, "qty": qty, "total": total})
    return jsonify({"ok": True, "total": total, "unit_price": unit_price, "firebase_key": result.get("name") if result else None})

@app.route("/api/sales/recent")
@login_required
def api_recent_sales():
    data = fb_get("daily_sales")
    sales = []
    if not data:
        return jsonify([])
    for key, val in data.items():
        if val:
            sales.append({"id": key, "sales_date": val.get("sales_date"), "reseller_name": val.get("reseller_name"), "quantity": val.get("quantity"), "kg_size": val.get("kg_size"), "total_sales": val.get("total_sales"), "mode": val.get("mode"), "payment": val.get("payment"), "created_at": val.get("created_at","")})
    sales.sort(key=lambda x: x.get("created_at",""), reverse=True)
    return jsonify(sales[:20])

@app.route("/api/sale/<sale_id>", methods=["DELETE"])
@login_required
def api_delete_sale(sale_id):
    try:
        requests.delete(f"{FIREBASE_URL}/daily_sales/{sale_id}.json", timeout=10)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({"ok": True, "firebase": FIREBASE_URL})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Omega Ice Cloud running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
