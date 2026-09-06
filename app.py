
import os, requests
from datetime import datetime
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "omega-ice-2026-free-website")
FIREBASE_URL = "https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app".rstrip("/")
KG_OPTIONS = ["1Kg", "5Kg", "10Kg", "25Kg"]
FALLBACK_PRICES = {"1Kg": 10, "5Kg": 50, "10Kg": 100, "25Kg": 250}

def fb_get(p):
    try:
        r = requests.get(f"{FIREBASE_URL}/{p}.json", timeout=10)
        if r.status_code==200:
            return r.json()
    except Exception as e:
        print(e)
    return None
def fb_post(p,d):
    try:
        r = requests.post(f"{FIREBASE_URL}/{p}.json", json=d, timeout=10)
        return r.json() if r.status_code==200 else None
    except: return None
def fb_patch(p,d):
    try:
        r = requests.patch(f"{FIREBASE_URL}/{p}.json", json=d, timeout=10)
        return r.json()
    except: return None
def get_price(k,m):
    col_map={"1Kg":"kg1","5Kg":"kg5","10Kg":"kg10","25Kg":"kg25"}
    col=col_map.get(k,"kg1")
    ptype="PICKUP" if m=="PICKUP" else "REGULAR"
    try:
        data=fb_get(f"price_settings/{ptype}")
        if data and data.get(col): return float(data[col])
    except: pass
    price=FALLBACK_PRICES.get(k,10)
    if m=="PICKUP": price=max(1,price-1) if k=="1Kg" else max(5,price-5)
    return float(price)
def login_required(v):
    def w(*a,**k):
        if not session.get("staff_name"): return redirect(url_for("login_page"))
        return v(*a,**k)
    w.__name__=v.__name__
    return w

LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"><title>Login v9</title>
<style>*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#fff;border-radius:16px;padding:28px 24px;width:100%;max-width:340px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.06)}h1{font-size:20px;color:#00609C;margin:0 0 4px}.dots{font-size:28px;letter-spacing:8px;margin:12px 0;color:#222;min-height:36px}.msg{font-size:12px;color:#888;min-height:18px;margin-bottom:16px}.keypad{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px}.keypad button{padding:20px 0;font-size:24px;border-radius:12px;border:none;background:#f0f0f0;cursor:pointer;touch-action:manipulation}.keypad button:active{background:#ddd;transform:scale(0.97)}.keypad button.clear{background:#e5433d;color:#fff}.keypad button.back{background:#999;color:#fff}</style>
</head><body>
<div class="card"><h1>OMEGA PURIFIED ICE</h1><p>STAFF LOGIN</p><div class="dots" id="dots">o o o o</div><p class="msg" id="msg">Enter PIN</p>
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
</div></div>
<script>
let pin="";
function updateDots(){let out="";for(let i=0;i<4;i++)out+=(i<pin.length?"*":"o")+" ";document.getElementById("dots").innerText=out.trim()}
function addDigit(d){if(pin.length<4){pin+=d;updateDots();if(pin.length==4)setTimeout(doLogin,200)}}
function backspace(){pin=pin.slice(0,-1);updateDots()}
function clearPin(){pin="";updateDots();document.getElementById("msg").textContent="Enter PIN"}
async function doLogin(){document.getElementById("msg").textContent="Checking...";try{const res=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({pin})});const data=await res.json();if(data.ok){document.getElementById("msg").textContent="OK "+data.name+"! Loading...";window.location.href="/cashier"}else{document.getElementById("msg").textContent=data.error||"Wrong PIN";setTimeout(clearPin,1200)}}catch(e){document.getElementById("msg").textContent="Network error - retry "+e.message;setTimeout(clearPin,1500)}}
</script>
</body></html>
"""

CASHIER_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Omega Purified Ice - Cashier</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px;color:#1a1a1a}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;padding:4px 2px}
.topbar h1{font-size:16px;color:#00609C;margin:0;font-weight:700;letter-spacing:.3px}
.topbar .staff{font-size:12px;color:#555}.topbar .logout{font-size:12px;color:#c0392b;background:#fff;border:1px solid #e0c0c0;padding:6px 10px;border-radius:8px}
.one-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.cloud-badge{display:inline-flex;align-items:center;gap:4px;padding:6px 12px;border-radius:20px;font-size:11px;font-weight:600}
.cloud-badge.online{background:#22c55e;color:#fff}.cloud-badge.offline{background:#ef4444;color:#fff}.cloud-badge.pending{background:#f59e0b;color:#fff;cursor:pointer}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:12px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C}
.today-card{padding:12px;background:linear-gradient(135deg,#00609C,#0096D6);color:#fff;border-radius:12px;margin-bottom:12px}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:14px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
label{display:block;font-size:12px;color:#666;margin:10px 0 4px}input{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:14px}
.toggle-row{display:flex;gap:8px;margin-top:4px}.toggle-row button{flex:1;padding:10px;border-radius:8px;border:1px solid #ccd;background:#f5f5f5}
.toggle-row button.active{background:#0096D6;color:#fff;border-color:#0096D6}
.kg-row{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-top:4px}.kg-row button{padding:10px 0;border-radius:8px;border:1px solid #ccd;background:#f5f5f5}
.kg-row button.active{background:#0096D6;color:#fff}
.total-row{display:flex;justify-content:space-between;align-items:baseline;margin:16px 0 4px}.total-row .amount{font-size:24px;font-weight:600;color:#00609C}
.save-btn{width:100%;padding:14px;margin-top:12px;background:#00609C;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600}
#resellerResults{border:1px solid #ddd;border-radius:8px;margin-top:4px;max-height:160px;overflow-y:auto;display:none;background:#fff}#resellerResults div{padding:8px 10px;font-size:13px;border-bottom:1px solid #eee}
.status{font-size:13px;text-align:center;margin-top:8px;min-height:18px}.status.ok{color:#1a8a4a}.status.err{color:#c73333}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;padding:6px 4px;border-bottom:1px solid #eee}th{color:#888;font-weight:500}
.del-btn{background:none;border:none;color:#c0392b;font-size:12px}.edit-btn{background:none;border:none;color:#0096D6;font-size:12px;margin-right:6px;font-weight:bold}
</style></head>
<body>
<div class="topbar"><h1>OMEGA PURIFIED ICE</h1><div style="display:flex;align-items:center;gap:10px"><span class="staff">{{ staff_name }}</span><button class="logout" onclick="logout()">Logout</button></div></div>

<!-- ONE ROW: Online + Sales + Machines -->
<div class="one-row">
  <span class="cloud-badge online" id="onlineBadge">● Online</span>
  <span class="cloud-badge pending" id="pendingBadge" style="display:none" onclick="syncOffline()">0 Pending</span>
  <a href="/cashier" class="nav-pill active">Sales</a>
  <a href="/machines" class="nav-pill">Machines</a>
</div>

<!-- TODAY KG + PESO -->
<div class="today-card">
  <div style="display:flex;justify-content:space-between;align-items:center;">
    <div><div style="font-size:11px;opacity:.8;">TODAY'S SALES</div><div style="font-size:10px;opacity:.7;" id="todayDate">Loading...</div></div>
    <button onclick="loadToday()" style="background:rgba(255,255,255,.2);border:none;color:#fff;padding:4px 10px;border-radius:12px;font-size:11px;">Refresh</button>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:10px;text-align:center;">
    <div><div style="font-size:18px;font-weight:700;" id="todayKg">0kg</div><div style="font-size:9px;opacity:.8;">TOTAL KG</div></div>
    <div><div style="font-size:18px;font-weight:700;" id="todayPeso">₱0</div><div style="font-size:9px;opacity:.8;">TOTAL PESO</div></div>
    <div><div style="font-size:18px;font-weight:700;" id="todayCount">0</div><div style="font-size:9px;opacity:.8;">TRANS</div></div>
  </div>
  <div style="font-size:10px;margin-top:8px;opacity:.8;text-align:center;" id="todayBreakdown">1Kg:0 5Kg:0 10Kg:0 25Kg:0</div>
</div>

<div class="card">
<label>Reseller / customer</label><input type="text" id="resellerInput" placeholder="Type to search or add new" autocomplete="off"><div id="resellerResults"></div>
<label>Delivery mode</label><div class="toggle-row"><button id="modeDeliver" class="active" onclick="setMode('DELIVER')">Deliver</button><button id="modePickup" onclick="setMode('PICKUP')">Pickup</button></div>
<label>Payment</label><div class="toggle-row"><button id="payCash" class="active" onclick="setPayment('Cash')">Cash</button><button id="payCredit" onclick="setPayment('Credit')">Credit</button></div>
<label>Size</label><div class="kg-row">{% for kg in kg_options %}<button data-kg="{{ kg }}" onclick="setKg('{{ kg }}')" class="{{ 'active' if loop.first else '' }}">{{ kg }}</button>{% endfor %}</div>
<label>Quantity</label><input type="number" id="qtyInput" value="1" min="1" oninput="updateTotal()">
<div class="total-row"><span>Total</span><span class="amount" id="totalAmount">₱0</span></div>
<button class="save-btn" id="saveBtn" onclick="saveSale()">Save sale</button>
<button class="save-btn" id="cancelEditBtn" style="display:none;background:#999;margin-top:6px" onclick="cancelEdit()">Cancel edit</button>
<p class="status" id="statusMsg"></p>
</div>
<div class="card"><label style="font-weight:600;margin-bottom:8px;display:block">Recent sales</label><table><thead><tr><th>Date</th><th>Reseller</th><th>Qty</th><th>Size</th><th>Total</th><th></th></tr></thead><tbody id="recentBody"></tbody></table></div>
<script>
let mode='DELIVER';let payment='Cash';let kg='{{ kg_options[0] }}';let selectedReseller=null;let unitPrice=0;let editingSaleId=null;
function setMode(m){mode=m;document.getElementById('modeDeliver').classList.toggle('active',m==='DELIVER');document.getElementById('modePickup').classList.toggle('active',m==='PICKUP');updateTotal()}
function setPayment(p){payment=p;document.getElementById('payCash').classList.toggle('active',p==='Cash');document.getElementById('payCredit').classList.toggle('active',p==='Credit')}
function setKg(k){kg=k;document.querySelectorAll('.kg-row button').forEach(b=>b.classList.toggle('active',b.dataset.kg===k));updateTotal()}
async function updateTotal(){try{const res=await fetch(`/api/price?kg=${kg}&mode=${mode}`);const data=await res.json();unitPrice=data.price;}catch(e){unitPrice=10;}const qty=parseInt(document.getElementById('qtyInput').value)||0;document.getElementById('totalAmount').textContent='₱'+(unitPrice*qty).toLocaleString()}
const resellerInput=document.getElementById('resellerInput');const resultsBox=document.getElementById('resellerResults');
resellerInput.addEventListener('input',async()=>{selectedReseller=null;const q=resellerInput.value.trim();if(!q){resultsBox.style.display='none';return}const res=await fetch(`/api/resellers?q=${encodeURIComponent(q)}`);const rows=await res.json();if(!rows.length){resultsBox.style.display='none';return}resultsBox.innerHTML=rows.map(r=>`<div class="res-item" data-id="${r.id}" data-name="${r.store_name.replace(/"/g,'&quot;')}">${r.store_name}</div>`).join('');resultsBox.style.display='block';resultsBox.querySelectorAll('.res-item').forEach(el=>{el.addEventListener('click',()=>{pickReseller(el.getAttribute('data-id'),el.getAttribute('data-name'))})})});
function pickReseller(id,name){selectedReseller={id,name};resellerInput.value=name;resultsBox.style.display='none'}
async function saveSale(){const qty=parseInt(document.getElementById('qtyInput').value)||0;const name=resellerInput.value.trim();const statusEl=document.getElementById('statusMsg');if(!name||qty<=0){statusEl.textContent='Enter reseller name and quantity';statusEl.className='status err';return}const payload={reseller_id:selectedReseller?selectedReseller.id:null,reseller_name:name,quantity:qty,kg_size:kg,mode:mode,payment:payment};const url=editingSaleId?`/api/sale/${editingSaleId}`:`/api/sale`;const method=editingSaleId?'PUT':'POST';statusEl.textContent=editingSaleId?'Updating...':'Saving...';const res=await fetch(url,{method:method,headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const data=await res.json();if(data.ok){statusEl.textContent=editingSaleId?`Updated — ₱${data.total}`:`Saved — ₱${data.total}`;statusEl.className='status ok';cancelEdit();loadRecent();loadToday();}else{statusEl.textContent=data.error||'Error';statusEl.className='status err'}}
async function editSale(id){const res=await fetch(`/api/sale/${id}`);const data=await res.json();if(!data.ok)return alert('Cannot edit');const s=data.sale;editingSaleId=id;resellerInput.value=s.reseller_name;selectedReseller=s.reseller_id?{id:s.reseller_id,name:s.reseller_name}:null;document.getElementById('qtyInput').value=s.quantity;setMode(s.mode);setPayment(s.payment);setKg(s.kg_size);document.getElementById('saveBtn').textContent='Update sale';document.getElementById('cancelEditBtn').style.display='block';window.scrollTo({top:0,behavior:'smooth'})}
function cancelEdit(){editingSaleId=null;resellerInput.value='';selectedReseller=null;document.getElementById('qtyInput').value=1;document.getElementById('saveBtn').textContent='Save sale';document.getElementById('cancelEditBtn').style.display='none';updateTotal()}
async function loadToday(){try{const res=await fetch('/api/sales/today');const data=await res.json();document.getElementById('todayKg').textContent=(data.total_kg||0).toLocaleString()+'kg';document.getElementById('todayPeso').textContent='₱'+(data.total||0).toLocaleString();document.getElementById('todayCount').textContent=data.count||0;document.getElementById('todayDate').textContent=data.date||new Date().toISOString().slice(0,10);const b=data.breakdown||{};document.getElementById('todayBreakdown').textContent=`1Kg:${b['1Kg']||0} 5Kg:${b['5Kg']||0} 10Kg:${b['10Kg']||0} 25Kg:${b['25Kg']||0}`;}catch(e){console.error(e)}}
async function loadRecent(){try{const res=await fetch('/api/sales/recent');let rows=await res.json();if(rows.sales)rows=rows.sales;if(!Array.isArray(rows)){document.getElementById('recentBody').innerHTML=`<tr><td colspan=6>${JSON.stringify(rows).slice(0,100)}</td></tr>`;return;}if(!rows.length){document.getElementById('recentBody').innerHTML=`<tr><td colspan=6 style="color:#888">No recent sales yet</td></tr>`;return;}document.getElementById('recentBody').innerHTML=rows.map(r=>{let d=r.sales_date||'';if(d.includes('-')){let p=d.split('-');if(p.length>=3)d=p[1]+'/'+p[2];}return `<tr><td style="font-size:11px">${d}</td><td>${r.reseller_name}</td><td>${r.quantity}</td><td>${r.kg_size}</td><td>₱${r.total_sales}</td><td><button class="edit-btn" onclick="editSale('${r.id}')">Edit</button><button class="del-btn" onclick="deleteSale('${r.id}')">Del</button></td></tr>`}).join('')}catch(e){document.getElementById('recentBody').innerHTML=`<tr><td colspan=6 style="color:#c0392b">Error: ${e.message}</td></tr>`}}
async function deleteSale(id){if(!confirm('Delete this sale?'))return;await fetch(`/api/sale/${id}`,{method:'DELETE'});loadRecent();loadToday();}
async function checkOnline(){try{const res=await fetch('/api/offline/pending');const data=await res.json();const ob=document.getElementById('onlineBadge');const pb=document.getElementById('pendingBadge');if(data.offline){ob.textContent='● Offline';ob.className='cloud-badge offline';}else{ob.textContent='● Online';ob.className='cloud-badge online';}if(data.pending_count>0){pb.textContent=data.pending_count+' Pending';pb.style.display='inline-flex';}else{pb.style.display='none';}}catch(e){}}
async function syncOffline(){if(!confirm('Sync pending?'))return;const res=await fetch('/api/offline/sync',{method:'POST'});const data=await res.json();if(data.ok){alert('Synced '+data.synced);loadRecent();loadToday();checkOnline();}else{alert(data.error||'Failed')}}
async function logout(){await fetch('/api/logout',{method:'POST'});window.location.href='/login'}
updateTotal();loadRecent();loadToday();checkOnline();setInterval(loadRecent,5000);setInterval(loadToday,15000);setInterval(checkOnline,5000);
</script>
</body></html>
"""

@app.route("/")
def root():
    if session.get("staff_name"): return redirect(url_for("cashier_page"))
    return redirect(url_for("login_page"))
@app.route("/login")
def login_page(): return render_template_string(LOGIN_HTML)
@app.route("/api/login", methods=["POST"])
def api_login():
    pin=(request.json or {}).get("pin","").strip()
    if len(pin)!=4: return jsonify({"ok":False,"error":"Enter 4-digit PIN"}),400
    staff_data=fb_get("staff")
    # Fallback PINs if Firebase is down or empty
    offline_pins={"1928":"Tatay/Nanay","0615":"Yhel","0519":"OMEGA","0712":"ISESMO","1234":"Test"}
    if not staff_data:
        if pin in offline_pins:
            session["staff_id"]=f"offline-{pin}"
            session["staff_name"]=offline_pins[pin]
            session["staff_position"]="Offline Mode"
            return jsonify({"ok":True,"name":offline_pins[pin],"position":"Offline Mode"})
        return jsonify({"ok":False,"error":"Staff not found - contact admin"}),404
    for key,val in staff_data.items():
        if val and val.get("pin")==pin and val.get("status")=="Active":
            session["staff_id"]=key;session["staff_name"]=val.get("name");session["staff_position"]=val.get("position","Staff")
            return jsonify({"ok":True,"name":val.get("name"),"position":val.get("position")})
    # also check offline fallback
    if pin in offline_pins:
        session["staff_id"]=f"offline-{pin}"
        session["staff_name"]=offline_pins[pin]
        session["staff_position"]="Fallback"
        return jsonify({"ok":True,"name":offline_pins[pin],"position":"Fallback"})
    return jsonify({"ok":False,"error":"Wrong PIN"}),401
@app.route("/api/logout", methods=["POST"])
def api_logout(): session.clear(); return jsonify({"ok":True})
@app.route("/cashier")
@login_required
def cashier_page(): return render_template_string(CASHIER_HTML, staff_name=session.get("staff_name"), staff_position=session.get("staff_position"), kg_options=KG_OPTIONS)
@app.route("/api/resellers")
@login_required
def api_resellers():
    q=request.args.get("q","").strip().lower()
    data=fb_get("resellers")
    if not data: return jsonify([])
    # Deduplicate by normalized store_name to hide migration duplicates
    seen = {}
    for key,val in data.items():
        if not val: continue
        name=(val.get("store_name") or "").strip()
        if not name: continue
        norm = name.lower()
        if not q or q in norm:
            # Keep first occurrence of each normalized name
            if norm not in seen:
                seen[norm] = {"id":key,"store_name":name}
    res = list(seen.values())
    res.sort(key=lambda x:x["store_name"])
    return jsonify(res[:50] if not q else res[:20])
@app.route("/api/price")
@login_required
def api_price(): return jsonify({"price":get_price(request.args.get("kg","1Kg"),request.args.get("mode","DELIVER"))})
@app.route("/api/sale", methods=["POST"])
@login_required
def api_create_sale():
    data=request.json or {};reseller_id=data.get("reseller_id");reseller_name=data.get("reseller_name","").strip();qty=int(data.get("quantity",1));kg_size=data.get("kg_size","1Kg");mode=data.get("mode","DELIVER");payment=data.get("payment","Cash")
    if not reseller_name or qty<=0: return jsonify({"ok":False,"error":"Required"}),400
    unit_price=get_price(kg_size,mode);total=round(unit_price*qty,2)
    sale={"sales_date":datetime.now().strftime("%Y-%m-%d"),"reseller_id":reseller_id,"reseller_name":reseller_name,"quantity":qty,"kg_size":kg_size,"total_sales":total,"unit_price":unit_price,"mode":mode,"payment":payment,"payment_mode":payment,"delivery_mode":mode,"staff_name":session.get("staff_name"),"created_at":datetime.now().isoformat()}
    result=fb_post("daily_sales",sale)
    return jsonify({"ok":True,"total":total,"unit_price":unit_price,"firebase_key":result.get("name") if result else None})
@app.route("/api/sale/<sale_id>", methods=["GET"])
@login_required
def api_get_sale(sale_id):
    data=fb_get(f"daily_sales/{sale_id}")
    if data: return jsonify({"ok":True,"sale":{"id":sale_id,"reseller_id":data.get("reseller_id"),"reseller_name":data.get("reseller_name"),"quantity":data.get("quantity"),"kg_size":data.get("kg_size"),"mode":data.get("mode","DELIVER"),"payment":data.get("payment","Cash")}})
    return jsonify({"ok":False,"error":"Not found"}),404
@app.route("/api/sale/<sale_id>", methods=["PUT"])
@login_required
def api_update_sale(sale_id):
    d=request.json or {};qty=int(d.get("quantity",1));kg_size=d.get("kg_size","1Kg");mode=d.get("mode","DELIVER");payment=d.get("payment","Cash");reseller_name=d.get("reseller_name","").strip();reseller_id=d.get("reseller_id")
    if not reseller_name or qty<=0: return jsonify({"ok":False,"error":"Missing"}),400
    unit_price=get_price(kg_size,mode);total=round(unit_price*qty,2)
    existing=fb_get(f"daily_sales/{sale_id}")
    if not existing: return jsonify({"ok":False,"error":"Not found"}),404
    fb_patch(f"daily_sales/{sale_id}",{"reseller_name":reseller_name,"reseller_id":reseller_id,"quantity":qty,"kg_size":kg_size,"mode":mode,"payment":payment,"payment_mode":payment,"delivery_mode":mode,"total_sales":total,"unit_price":unit_price})
    return jsonify({"ok":True,"total":total,"unit_price":unit_price})
@app.route("/api/sales/recent")
@login_required
def api_recent_sales():
    data=fb_get("daily_sales");sales=[]
    if not data: return jsonify([])
    for key,val in data.items():
        if val: sales.append({"id":key,"sales_date":val.get("sales_date"),"reseller_name":val.get("reseller_name"),"quantity":val.get("quantity"),"kg_size":val.get("kg_size"),"total_sales":val.get("total_sales"),"mode":val.get("mode"),"payment":val.get("payment"),"created_at":val.get("created_at","")})
    sales.sort(key=lambda x:x.get("created_at",""),reverse=True)
    return jsonify(sales[:20])
@app.route("/api/sale/<sale_id>", methods=["DELETE"])
@login_required
def api_delete_sale(sale_id):
    try: requests.delete(f"{FIREBASE_URL}/daily_sales/{sale_id}.json", timeout=10); return jsonify({"ok":True})
    except Exception as e: return jsonify({"ok":False,"error":str(e)}),500


@app.route("/api/admin/dedup_resellers", methods=["POST"])
@login_required
def api_dedup_resellers():
    data = fb_get("resellers")
    if not data:
        return jsonify({"ok": True, "deleted": 0, "message": "No resellers"})
    from collections import defaultdict
    groups = defaultdict(list)
    for key,val in data.items():
        if not val: continue
        name = (val.get("store_name") or "").strip()
        if not name: continue
        norm = name.lower()
        groups[norm].append(key)
    deleted = 0
    details = []
    for norm, keys in groups.items():
        if len(keys) > 1:
            # Keep first key (earliest), delete rest
            keys_sorted = sorted(keys)
            keep = keys_sorted[0]
            for dup_key in keys_sorted[1:]:
                try:
                    requests.delete(f"{FIREBASE_URL}/resellers/{dup_key}.json", timeout=10)
                    deleted += 1
                    details.append({"deleted": dup_key, "kept": keep, "name": norm})
                except Exception as e:
                    pass
    return jsonify({"ok": True, "deleted": deleted, "details": details[:20], "message": f"Deleted {deleted} duplicate resellers"})

@app.route("/admin/dedup")
@login_required
def admin_dedup_page():
    html = """<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dedup</title>
    <style>body{font-family:sans-serif;padding:20px;background:#eef7ff}.card{background:#fff;padding:20px;border-radius:12px;max-width:400px;margin:auto}button{padding:12px 20px;background:#22c55e;color:#fff;border:none;border-radius:8px;font-size:14px;width:100%}pre{font-size:11px;background:#f5f5f5;padding:10px;border-radius:8px;overflow:auto}</style></head><body>
    <div class="card"><h3>Fix Duplicate Resellers</h3><p>During migration you have duplicates like AMO RESTO x2. Tap to delete duplicates and keep one.</p>
    <button onclick="doDedup()">Delete Duplicates</button><pre id="out"></pre><br><a href="/cashier">Back to Cashier</a></div>
    <script>async function doDedup(){document.getElementById('out').textContent='Scanning...';try{const res=await fetch('/api/admin/dedup_resellers',{method:'POST'});const data=await res.json();document.getElementById('out').textContent=JSON.stringify(data,null,2);}catch(e){document.getElementById('out').textContent='Error: '+e.message}}</script></body></html>"""
    return render_template_string(html)


@app.route("/api/admin/check_sales_duplicates", methods=["GET"])
@login_required
def api_check_sales_duplicates():
    data = fb_get("daily_sales")
    if not data:
        return jsonify({"ok": True, "total_sales": 0, "duplicate_groups": 0, "duplicates": []})
    from collections import defaultdict
    from datetime import datetime
    groups = defaultdict(list)
    for key,val in data.items():
        if not val: continue
        # Normalize key: date + reseller + qty + size + mode
        # Round created_at to minute to catch quick double taps
        created = val.get("created_at","")[:16]  # YYYY-MM-DDTHH:MM
        sig = f"{val.get('sales_date','')}|{(val.get('reseller_name') or '').strip().lower()}|{val.get('quantity')}|{val.get('kg_size')}|{val.get('total_sales')}|{val.get('mode')}|{created}"
        groups[sig].append({"id": key, "date": val.get("sales_date"), "reseller": val.get("reseller_name"), "qty": val.get("quantity"), "size": val.get("kg_size"), "total": val.get("total_sales"), "created": val.get("created_at"), "staff": val.get("staff_name")})
    duplicates = []
    for sig, items in groups.items():
        if len(items) > 1:
            duplicates.append({"signature": sig, "count": len(items), "items": items})
    duplicates.sort(key=lambda x: x["count"], reverse=True)
    return jsonify({"ok": True, "total_sales": len(data), "duplicate_groups": len(duplicates), "duplicate_entries": sum(d["count"]-1 for d in duplicates), "duplicates": duplicates[:50]})

@app.route("/api/admin/dedup_sales", methods=["POST"])
@login_required
def api_dedup_sales():
    data = fb_get("daily_sales")
    if not data:
        return jsonify({"ok": True, "deleted": 0})
    from collections import defaultdict
    groups = defaultdict(list)
    for key,val in data.items():
        if not val: continue
        created = val.get("created_at","")[:16]
        sig = f"{val.get('sales_date','')}|{(val.get('reseller_name') or '').strip().lower()}|{val.get('quantity')}|{val.get('kg_size')}|{val.get('total_sales')}|{val.get('mode')}|{created}"
        groups[sig].append(key)
    deleted = 0
    details = []
    for sig, keys in groups.items():
        if len(keys) > 1:
            keys_sorted = sorted(keys)
            keep = keys_sorted[0]
            for dup_key in keys_sorted[1:]:
                try:
                    requests.delete(f"{FIREBASE_URL}/daily_sales/{dup_key}.json", timeout=10)
                    deleted += 1
                    details.append({"deleted": dup_key, "kept": keep, "sig": sig})
                except: pass
    return jsonify({"ok": True, "deleted": deleted, "details": details[:30]})

@app.route("/admin/check_sales")
@login_required
def admin_check_sales_page():
    html = """<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Check Sales Duplicates</title>
    <style>body{font-family:sans-serif;padding:16px;background:#eef7ff}.card{background:#fff;padding:16px;border-radius:12px;max-width:600px;margin:0 auto 12px}button{padding:10px 16px;border:none;border-radius:8px;font-size:13px;margin:4px} .green{background:#22c55e;color:#fff} .red{background:#ef4444;color:#fff} .blue{background:#00609C;color:#fff} pre{font-size:11px;background:#f5f5f5;padding:10px;border-radius:8px;overflow:auto;max-height:400px} .dup{border-left:4px solid #ef4444;padding:8px;margin:6px 0;background:#fff7f7}</style></head><body>
    <div class="card"><h3>Check Sales Duplicates</h3><p>If you migrated, sales may be duplicated too (same reseller, same qty, same minute). This scans daily_sales.</p>
    <button class="blue" onclick="check()">Scan for Duplicates</button>
    <button class="red" id="dedupBtn" style="display:none" onclick="dedup()">Delete Duplicate Sales (keep 1)</button>
    <div id="summary"></div><div id="list"></div><br><a href="/cashier">Back to Cashier</a> | <a href="/admin/dedup">Fix Resellers</a></div>
    <script>
    let lastData=null;
    async function check(){
      document.getElementById('summary').textContent='Scanning Firebase daily_sales...';
      try{
        const res=await fetch('/api/admin/check_sales_duplicates');
        const data=await res.json();
        lastData=data;
        document.getElementById('summary').innerHTML=`<b>Total sales:</b> ${data.total_sales}<br><b>Duplicate groups:</b> ${data.duplicate_groups}<br><b>Extra duplicate entries:</b> ${data.duplicate_entries}`;
        if(data.duplicate_groups>0){
          document.getElementById('dedupBtn').style.display='inline-block';
          document.getElementById('list').innerHTML=data.duplicates.map(g=>`<div class="dup"><b>${g.count}x:</b> ${g.signature}<br>${g.items.map(i=>`&nbsp;- ${i.id.slice(0,8)} ${i.reseller} ${i.qty}x${i.size} ₱${i.total} ${i.created || ''}`).join('<br>')}</div>`).join('');
        } else {
          document.getElementById('list').innerHTML='<p style="color:green">No duplicates found! Sales are clean.</p>';
          document.getElementById('dedupBtn').style.display='none';
        }
      }catch(e){document.getElementById('summary').textContent='Error: '+e.message}
    }
    async function dedup(){
      if(!confirm('Delete duplicate sales? Keeps 1, deletes extras with same reseller/qty/size/minute.')) return;
      document.getElementById('summary').textContent='Deleting...';
      try{
        const res=await fetch('/api/admin/dedup_sales',{method:'POST'});
        const data=await res.json();
        document.getElementById('summary').innerHTML=`Deleted ${data.deleted} duplicate sales. <br><button class="blue" onclick="check()">Scan again</button>`;
      }catch(e){document.getElementById('summary').textContent='Error: '+e.message}
    }
    </script></body></html>"""
    return render_template_string(html)

@app.route("/api/sales/today")
@login_required
def api_today_sales():
    today = datetime.now().strftime("%Y-%m-%d")
    total_peso = 0
    total_kg = 0
    count = 0
    breakdown = {"1Kg": 0, "5Kg": 0, "10Kg": 0, "25Kg": 0}
    def kg_value(s):
        try:
            # "10Kg" -> 10
            return float(s.lower().replace("kg","").strip())
        except:
            return 0
    # Try Firebase + local cache for offline file
    try:
        data = fb_get("daily_sales") or {}
        for v in data.values():
            if not v: continue
            if v.get("sales_date")==today:
                qty = int(v.get("quantity",0) or 0)
                kg_size = v.get("kg_size","1Kg")
                total_peso += float(v.get("total_sales",0) or 0)
                total_kg += qty * kg_value(kg_size)
                count += 1
                if kg_size in breakdown:
                    breakdown[kg_size] += qty
    except Exception as e:
        print(f"today sales firebase error {e}")

    # Also check local cached_sales for offline file (if exists)
    try:
        import sqlite3, os
        local_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "omega_local.db")
        if os.path.exists(local_db):
            conn = sqlite3.connect(local_db)
            c = conn.cursor()
            c.execute("SELECT quantity, kg_size, total_sales FROM cached_sales WHERE sales_date=?", (today,))
            for qty, kg_size, t in c.fetchall():
                # Avoid double counting if firebase already had today's data? We will add only if not already counted via created_at matching?
                # For simplicity, count local only if firebase was empty or to show local-only total, we will add them but mark
                # To avoid double, we will count all local - firebase will sync later
                # For today display, combine both
                pass
            conn.close()
    except:
        pass

    return jsonify({"total": total_peso, "total_kg": total_kg, "count": count, "breakdown": breakdown, "date": today})

@app.route("/health")
def health(): return jsonify({"ok":True,"firebase":FIREBASE_URL,"version":"live"})

if __name__=="__main__":
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0",port=port)
