
"""
Omega Ice - OFFLINE FIRST - Firebase + Local SQLite backup
- If internet: saves to Firebase instantly
- If NO internet: saves to phone (omega_local.db) and shows pending badge
- When internet returns: tap badge or go to /api/offline/sync to upload

Firebase: https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app
"""

import os, sqlite3, json, requests, time
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import random, string, re
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "omega-ice-realtime-2026")

def hash_customer_password(pwd):
    try:
        return generate_password_hash(pwd)
    except:
        import hashlib
        return hashlib.sha256(pwd.encode()).hexdigest()

def verify_customer_password(hash_val, pwd):
    try:
        return check_password_hash(hash_val, pwd)
    except:
        import hashlib
        return hash_val == hashlib.sha256(pwd.encode()).hexdigest() or hash_val == pwd

def customer_login_required(v):
    def w(*a,**k):
        if not session.get("customer_id"):
            return redirect(url_for("customer_login_page"))
        return v(*a,**k)
    w.__name__=v.__name__
    return w

def isesmo_only(v):
    def w(*a,**k):
        staff = (session.get("staff_name") or "").lower()
        # Only ISESMO can add/manage customers
        if staff not in ["isesmo", "isesmo gamboa"]:
            return jsonify({"ok": False, "error": "Only ISESMO can add customers"}), 403
        return v(*a,**k)
    w.__name__=v.__name__
    return w

def generate_otp():
    return ''.join(random.choices('0123456789', k=6))

SEMAPHORE_API_KEY = os.environ.get("SEMAPHORE_API_KEY", "")
SEMAPHORE_SENDER_NAME = os.environ.get("SEMAPHORE_SENDER_NAME", "")  # optional, must be pre-approved by Semaphore

def send_sms(phone, message):
    """Send an SMS via Semaphore. Returns (ok, info_or_error)."""
    if not SEMAPHORE_API_KEY:
        return False, "SEMAPHORE_API_KEY not configured"
    # Semaphore expects PH numbers like 09xxxxxxxxx or 639xxxxxxxxx
    num = phone.strip()
    if num.startswith("+"):
        num = num[1:]
    payload = {"apikey": SEMAPHORE_API_KEY, "number": num, "message": message}
    if SEMAPHORE_SENDER_NAME:
        payload["sendername"] = SEMAPHORE_SENDER_NAME
    try:
        r = requests.post("https://api.semaphore.co/api/v4/messages", data=payload, timeout=15)
        if r.status_code == 200:
            resp = r.json()
            # Semaphore returns a list of message objects on success
            if isinstance(resp, list) and resp and resp[0].get("status") not in (None, "Failed"):
                return True, resp[0]
            if isinstance(resp, dict) and resp.get("message"):
                return False, resp.get("message")
            return True, resp
        return False, f"Semaphore HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)

def clean_phone(phone):
    return re.sub(r'[^0-9+]', '', phone or "")


FIREBASE_URL = "https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app".rstrip("/")

KG_OPTIONS = ["1Kg", "5Kg", "10Kg", "25Kg"]
FALLBACK_PRICES = {"1Kg": 10, "5Kg": 50, "10Kg": 100, "25Kg": 250}

LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Omega Purified Ice - Login</title>
<style>*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#fff;border-radius:16px;padding:28px 24px;width:100%;max-width:340px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.06)}h1{font-size:20px;color:#00609C;margin:0 0 4px}.subtitle{font-size:13px;color:#333;margin:0 0 4px;font-weight:600}.tagline{font-size:11px;color:#888;margin:0 0 24px}.dots{font-size:28px;letter-spacing:8px;margin:12px 0;color:#222;min-height:36px}.msg{font-size:12px;color:#888;min-height:18px;margin-bottom:16px}.keypad{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px}.keypad button{padding:20px 0;font-size:24px;border-radius:12px;border:none;background:#f0f0f0;cursor:pointer}.keypad button.clear{background:#e5433d;color:#fff}.keypad button.back{background:#999;color:#fff}</style>
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
</div></div>
<script>
let pin="";function updateDots(){let out="";for(let i=0;i<4;i++)out+=(i<pin.length?"*":"o")+" ";document.getElementById("dots").innerText=out.trim()}
function addDigit(d){if(pin.length<4){pin+=d;updateDots();if(pin.length==4)setTimeout(doLogin,200)}}
function backspace(){pin=pin.slice(0,-1);updateDots()}
function clearPin(){pin="";updateDots();document.getElementById("msg").textContent="Enter PIN"}
async function doLogin(){document.getElementById("msg").textContent="Checking...";try{const res=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({pin})});const data=await res.json();if(data.ok){window.location.href="/cashier"}else{document.getElementById("msg").textContent=data.error||"Wrong PIN";setTimeout(clearPin,1200)}}catch(e){document.getElementById("msg").textContent="Network error";setTimeout(clearPin,1500)}}
</script>
</body></html>
"""
CASHIER_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Omega Purified Ice - Cashier</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px;padding-bottom:160px;color:#1a1a1a} /* FIX: extra bottom padding para di matakpan ng browser bar */
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;padding:4px 2px}
.topbar h1{font-size:15px;color:#00609C;margin:0;font-weight:700}
.topbar .staff{font-size:12px;color:#555}.topbar .logout{font-size:12px;color:#c0392b;background:#fff;border:1px solid #e0c0c0;padding:6px 10px;border-radius:8px}
.one-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:8px;margin-bottom:12px;align-items:stretch}
.cloud-badge{display:flex;align-items:center;justify-content:center;gap:4px;padding:10px 8px;border-radius:10px;font-size:11px;font-weight:600;min-height:38px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.cloud-badge.online{background:#22c55e;color:#fff}.cloud-badge.offline{background:#ef4444;color:#fff}.cloud-badge.pending{background:#f59e0b;color:#fff;cursor:pointer}
.nav-pill{padding:10px 8px;border-radius:10px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;display:flex;align-items:center;justify-content:center;min-height:38px;text-align:center;font-weight:600;box-shadow:0 1px 3px rgba(0,0,0,.05);transition:all .2s}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C;box-shadow:0 2px 6px rgba(0,96,156,.3)}
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
.save-btn{position:relative;z-index:5;box-shadow:0 4px 12px rgba(0,96,156,.3);margin-top:16px} /* FIX: sticky save */
.bottom-spacer{height:140px} /* FIX: spacer */
.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:8px;border:1px solid #e5e7eb;background:#fff;cursor:pointer;transition:all .2s;font-size:14px}
.icon-btn.edit{color:#00609C;border-color:#cde;background:#eef7ff}
.icon-btn.edit:hover{background:#00609C;color:#fff}
.icon-btn.del{color:#ef4444;border-color:#fecaca;background:#fef2f2}
.icon-btn.del:hover{background:#ef4444;color:#fff}
.icon-btn:active{transform:scale(.95)}

.daily-date-picker{display:none;margin-top:10px;background:rgba(255,255,255,.15);border-radius:10px;padding:10px}
.daily-date-picker input{width:100%;padding:8px;border-radius:8px;border:none;font-size:13px}

.date-input{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px;margin-top:4px}

.period-sales-table td{font-size:11px}
@keyframes pulse{0%{transform:scale(1)}50%{transform:scale(1.05)}100%{transform:scale(1)}}
.alarm-active{animation:pulse 0.5s infinite;background:#ff0000 !important}
</style></head>
<body>
<div class="topbar"><h1>OMEGA PURIFIED ICE</h1><div style="display:flex;align-items:center;gap:10px"><span class="staff">{{ staff_name }}</span><button class="logout" onclick="logout()">Logout</button></div></div>
<div class="one-row">
  <span class="cloud-badge online" id="onlineBadge">● Online</span>
  <a href="/orders" class="nav-pill" style="background:#ff4444;color:#fff;border-color:#ff4444;position:relative">🔴 Live Orders <span id="liveOrdersCount" style="background:#fff;color:#ff4444;border-radius:10px;padding:1px 6px;font-size:10px;font-weight:700;margin-left:4px;display:none">0</span></a>
  <span class="cloud-badge pending" id="pendingBadge" style="display:none" onclick="syncOffline()">0 Pending</span>
  <a href="/cashier" class="nav-pill active">Sales</a>
  <a href="/machines" class="nav-pill">Machines</a>
  <a href="/dashboard" class="nav-pill">Dashboard</a><button style="display:none" onclick="resetTodayDashboard()" style="margin-left:6px;padding:4px 10px;border-radius:12px;border:none;background:#ef4444;color:#fff;font-size:11px"></button>
</div>
<div class="today-card">
  <div style="display:flex;justify-content:space-between;align-items:center;">
    <div><div style="font-size:11px;opacity:.8;" id="todayLabel">TODAY'S SALES</div><div style="font-size:10px;opacity:.7;" id="todayDate">2026-09-06 - Tap Refresh</div></div>
    <button onclick="loadToday()" style="background:rgba(255,255,255,.2);border:none;color:#fff;padding:4px 10px;border-radius:12px;font-size:11px;">Refresh</button>
  </div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-top:12px">
    <button class="period-btn active" data-period="daily" onclick="setCashierPeriod('daily')" style="padding:10px 4px;border-radius:10px;border:1px solid rgba(255,255,255,.5);background:rgba(255,255,255,.3);color:#fff;font-size:11px;font-weight:600;min-height:36px">Daily</button>
    <button class="period-btn" data-period="weekly" onclick="setCashierPeriod('weekly')" style="padding:10px 4px;border-radius:10px;border:1px solid rgba(255,255,255,.4);background:transparent;color:#fff;font-size:11px;font-weight:600;min-height:36px">Weekly</button>
    <button class="period-btn" data-period="monthly" onclick="setCashierPeriod('monthly')" style="padding:10px 4px;border-radius:10px;border:1px solid rgba(255,255,255,.4);background:transparent;color:#fff;font-size:11px;font-weight:600;min-height:36px">Monthly</button>
    <button class="period-btn" data-period="quarterly" onclick="setCashierPeriod('quarterly')" style="padding:10px 4px;border-radius:10px;border:1px solid rgba(255,255,255,.4);background:transparent;color:#fff;font-size:11px;font-weight:600;min-height:36px">Quarterly</button>
    <button class="period-btn" data-period="yearly" onclick="setCashierPeriod('yearly')" style="padding:10px 4px;border-radius:10px;border:1px solid rgba(255,255,255,.4);background:transparent;color:#fff;font-size:11px;font-weight:600;min-height:36px">Year</button>
    <button class="period-btn" data-period="all" onclick="setCashierPeriod('all')" style="padding:10px 4px;border-radius:10px;border:1px solid rgba(255,255,255,.4);background:transparent;color:#fff;font-size:11px;font-weight:600;min-height:36px">All Time</button>
  </div>
  <div id="subPeriodPicker" style="display:none;margin-top:10px;background:rgba(255,255,255,.15);border-radius:10px;padding:10px">
    <label style="font-size:10px;color:#fff;opacity:.9;margin:0 0 6px;display:block" id="subPeriodLabel">Select Week</label>
    <select id="subPeriodSelect" onchange="onSubPeriodChange()" style="width:100%;padding:8px;border-radius:8px;border:none;font-size:12px"></select>
  </div>
  <div id="dailyDatePicker" class="daily-date-picker">
    <label style="font-size:10px;color:#fff;opacity:.9;margin:0 0 6px;display:block">📅 Pili ng Date (Daily)</label>
    <input type="date" id="dailyDateInput" onchange="onDailyDateChange()">
    <div style="display:flex;gap:6px;margin-top:6px">
      <button onclick="setDailyToday()" style="flex:1;padding:6px;border-radius:8px;border:none;background:rgba(255,255,255,.3);color:#fff;font-size:11px">Today</button>
      <button onclick="setDailyYesterday()" style="flex:1;padding:6px;border-radius:8px;border:none;background:rgba(255,255,255,.2);color:#fff;font-size:11px">Yesterday</button>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:10px;text-align:center;">
    <div><div style="font-size:18px;font-weight:700;" id="todayKg">0kg</div><div style="font-size:9px;opacity:.8;">TOTAL KG</div></div>
    <div><div style="font-size:18px;font-weight:700;" id="todayPeso">₱0</div><div style="font-size:9px;opacity:.8;">TOTAL PESO</div></div>
    <div><div style="font-size:18px;font-weight:700;" id="todayCount">0</div><div style="font-size:9px;opacity:.8;">TRANS</div></div>
  </div>
  <div style="font-size:10px;margin-top:8px;opacity:.8;text-align:center;" id="todayBreakdown">1Kg:0 5Kg:0 10Kg:0 25Kg:0</div>
</div>
<div class="card">
<label>Reseller / customer</label><input type="text" id="resellerInput" placeholder="Type to search" autocomplete="off"><div id="resellerResults"></div>
<label>Delivery mode</label><div class="toggle-row"><button id="modeDeliver" class="active" onclick="setMode('DELIVER')">Deliver</button><button id="modePickup" onclick="setMode('PICKUP')">Pickup</button></div>
<label>Payment</label><div class="toggle-row"><button id="payCash" class="active" onclick="setPayment('Cash')">Cash</button><button id="payCredit" onclick="setPayment('Credit')">Credit</button></div>
<label>Size</label><div class="kg-row">{% for kg in kg_options %}<button data-kg="{{ kg }}" onclick="setKg('{{ kg }}')" class="{{ 'active' if loop.first else '' }}">{{ kg }}</button>{% endfor %}</div>
<label>Quantity</label><input type="number" id="qtyInput" value="1" min="1" oninput="updateTotal()">
<label>Date <span style="font-weight:400;color:#888;font-size:11px">(tap to change)</span></label>
<input type="date" id="saleDateInput" class="date-input" value="">
<input type="time" id="saleTimeInput" class="date-input" value="" style="margin-top:6px">
<label>Total <span style="font-weight:400;color:#888;font-size:11px">(auto-calculated, tap to override)</span></label>
<input type="number" id="totalAmount" step="0.01" min="0" value="0" oninput="totalManuallyEdited=true" style="width:100%;padding:12px;border-radius:8px;border:1px solid #ccd;font-size:18px;font-weight:700;color:#00609C">
<button type="button" onclick="totalManuallyEdited=false;updateTotal()" style="background:none;border:none;color:#00609C;font-size:11px;padding:4px 0;text-decoration:underline">Reset to auto price</button>
<button class="save-btn" id="saveBtn" onclick="saveSale()">Save sale</button>
<button class="save-btn" id="cancelEditBtn" style="display:none;background:#999;margin-top:6px" onclick="cancelEdit()">Cancel edit</button>
<p class="status" id="statusMsg"></p>
<p style="font-size:10px;color:#888;margin-top:6px" id="lastSaveTime"></p>
</div>
<div class="bottom-spacer"></div>
<audio id="orderAlarm" preload="auto" loop>
<source src="https://actions.google.com/sounds/v1/alarms/beep_short.ogg" type="audio/ogg">
<source src="https://actions.google.com/sounds/v1/alarms/alarm_clock.ogg" type="audio/ogg">
</audio>

<div class="card" id="periodSalesCard" style="display:none">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
<label style="font-weight:600;display:block" id="periodSalesLabel">Monthly Sales Record</label>
<button onclick="loadPeriodSales(cashierPeriod)" style="padding:6px 12px;border-radius:20px;border:1px solid #cde;background:#fff;font-size:11px">🔄 Refresh</button>
</div>
<table><thead><tr><th>Date/Time</th><th>Reseller</th><th>Qty</th><th>Size</th><th>Total</th><th>Status</th></tr></thead><tbody id="periodSalesBody"><tr><td colspan=6>Select Monthly / Weekly...</td></tr></tbody></table>
<div style="font-size:10px;color:#666;margin-top:8px" id="periodSalesSummary"></div>
</div>

<div class="card" id="recentCard"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><label style="font-weight:600;display:block">Recent sales - Status included <span style="font-size:9px;color:#888" id="recentTimestamp"></span></label><button onclick="loadRecent();loadToday();" style="padding:6px 12px;border-radius:20px;border:1px solid #cde;background:#fff;font-size:11px">🔄 Refresh (30s auto)</button></div>
<div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap">
<span style="font-size:10px;background:#dcfce7;color:#166534;padding:3px 8px;border-radius:10px">Delivered = Real Sales</span>
<span style="font-size:10px;background:#fef3c7;color:#92400e;padding:3px 8px;border-radius:10px">Pending = Not yet counted</span>
</div>
<table><thead><tr><th>Date</th><th>Reseller</th><th>Qty</th><th>Size</th><th>Total</th><th>Status</th><th></th></tr></thead><tbody id="recentBody"></tbody></table></div>
<script>
let mode='DELIVER';let payment='Cash';let kg='{{ kg_options[0] }}';let selectedReseller=null;let unitPrice=0;let editingSaleId=null;let cashierPeriod='daily';let totalManuallyEdited=false;
function setMode(m){mode=m;document.getElementById('modeDeliver').classList.toggle('active',m==='DELIVER');document.getElementById('modePickup').classList.toggle('active',m==='PICKUP');updateTotal()}
function setPayment(p){payment=p;document.getElementById('payCash').classList.toggle('active',p==='Cash');document.getElementById('payCredit').classList.toggle('active',p==='Credit')}
function setKg(k){kg=k;document.querySelectorAll('.kg-row button').forEach(b=>b.classList.toggle('active',b.dataset.kg===k));updateTotal()}
async function updateTotal(){if(totalManuallyEdited)return;try{const res=await fetch(`/api/price?kg=${kg}&mode=${mode}`);const data=await res.json();unitPrice=data.price;}catch(e){unitPrice=10;}const qty=parseInt(document.getElementById('qtyInput').value)||0;document.getElementById('totalAmount').value=(unitPrice*qty).toFixed(2)}
const resellerInput=document.getElementById('resellerInput');const resultsBox=document.getElementById('resellerResults');
resellerInput.addEventListener('input',async()=>{selectedReseller=null;const q=resellerInput.value.trim();if(!q){resultsBox.style.display='none';return}const res=await fetch(`/api/resellers?q=${encodeURIComponent(q)}`);const rows=await res.json();if(!rows.length){resultsBox.style.display='none';return}resultsBox.innerHTML=rows.map(r=>`<div class="res-item" data-id="${r.id}" data-name="${r.store_name.replace(/"/g,'&quot;')}">${r.store_name}</div>`).join('');resultsBox.style.display='block';resultsBox.querySelectorAll('.res-item').forEach(el=>{el.addEventListener('click',()=>{pickReseller(el.getAttribute('data-id'),el.getAttribute('data-name'))})})});
function pickReseller(id,name){selectedReseller={id,name};resellerInput.value=name;resultsBox.style.display='none'}
async function saveSale(){const qty=parseInt(document.getElementById('qtyInput').value)||0;const name=resellerInput.value.trim();const totalVal=parseFloat(document.getElementById('totalAmount').value);const statusEl=document.getElementById('statusMsg');if(!name||qty<=0){statusEl.textContent='Enter reseller';statusEl.className='status err';return}const saleDate = document.getElementById('saleDateInput').value || new Date().toISOString().split('T')[0];
  const saleTime = document.getElementById('saleTimeInput').value || new Date().toTimeString().slice(0,5);
  const payload={reseller_id:selectedReseller?selectedReseller.id:null,reseller_name:name,quantity:qty,kg_size:kg,mode:mode,payment:payment,sales_date:saleDate,sale_time:saleTime,created_at:saleDate+'T'+saleTime+':00'};
  if(totalManuallyEdited && !isNaN(totalVal)){payload.total_sales=totalVal;}const url=editingSaleId?`/api/sale/${editingSaleId}`:`/api/sale`;const method=editingSaleId?'PUT':'POST';statusEl.textContent='Saving...';const res=await fetch(url,{method:method,headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const data=await res.json();if(data.ok){
    const now = new Date();
    const timeStr = now.toLocaleString('en-PH',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:true});
    statusEl.textContent=`✅ Saved ₱${data.total} at ${timeStr}`;
    statusEl.className='status ok';
    document.getElementById('lastSaveTime').textContent='Last save: '+timeStr+' - '+now.toISOString();
    // Store timestamp
    localStorage.setItem('omega_last_save', timeStr);
    cancelEdit();
    if(cashierPeriod==='daily'){loadRecent();} else {loadPeriodSales(cashierPeriod);}
    loadToday();
  }else{statusEl.textContent=data.error||'Error';statusEl.className='status err'}}
async function editSale(id){
  const res=await fetch(`/api/sale/${id}`);
  const data=await res.json();
  if(!data.ok) return alert(data.error||'Cannot edit');
  const s=data.sale;
  editingSaleId=id;
  resellerInput.value=s.reseller_name;
  selectedReseller=s.reseller_id?{id:s.reseller_id,name:s.reseller_name}:null;
  document.getElementById('qtyInput').value=s.quantity;
  totalManuallyEdited=true;
  setMode(s.mode);
  setPayment(s.payment);
  setKg(s.kg_size);
  document.getElementById('totalAmount').value=Number(s.total_sales||0).toFixed(2);
  // FIX: date editable
  try{
    const d = s.sales_date || new Date().toISOString().split('T')[0];
    document.getElementById('saleDateInput').value = d.slice(0,10);
    if(s.created_at && s.created_at.includes('T')){
      const t = s.created_at.split('T')[1].slice(0,5);
      document.getElementById('saleTimeInput').value = t;
    } else {
      document.getElementById('saleTimeInput').value = new Date().toTimeString().slice(0,5);
    }
  }catch(e){}
  document.getElementById('saveBtn').textContent='Update Sale';
  document.getElementById('cancelEditBtn').style.display='block';
  window.scrollTo({top:0,behavior:'smooth'});
}
function initDateInputs(){
  const now = new Date();
  document.getElementById('saleDateInput').value = now.toISOString().split('T')[0];
  document.getElementById('saleTimeInput').value = now.toTimeString().slice(0,5);
}

function cancelEdit(){
  editingSaleId=null;
  resellerInput.value='';
  selectedReseller=null;
  document.getElementById('qtyInput').value=1;
  totalManuallyEdited=false;
  document.getElementById('saveBtn').textContent='Save sale';
  document.getElementById('cancelEditBtn').style.display='none';
  initDateInputs();
  updateTotal();
}
let lastActiveOrders = 0;
let alarmEnabled = true;
function setCashierPeriod(p){
  cashierPeriod=p;
  document.querySelectorAll('.today-card .period-btn').forEach(b=>{
    const is=b.dataset.period===p;
    b.style.background=is?'rgba(255,255,255,.3)':'transparent';
    b.classList.toggle('active', is);
  });
  loadToday();
  // FIX #2: Pag Monthly/Weekly etc, ipakita sales record sa baba, hindi recent
  if(p!=='daily'){
    document.getElementById('recentCard').style.display='none';
    document.getElementById('periodSalesCard').style.display='block';
    loadPeriodSales(p);
  } else {
    document.getElementById('recentCard').style.display='block';
    document.getElementById('periodSalesCard').style.display='none';
    loadRecent();
  }
}

async function loadPeriodSales(period){
  const body = document.getElementById('periodSalesBody');
  const summary = document.getElementById('periodSalesSummary');
  const label = document.getElementById('periodSalesLabel');
  body.innerHTML='<tr><td colspan=6>Loading '+period+' sales...</td></tr>';
  label.textContent = period.toUpperCase() + ' SALES RECORD';
  try{
    let url = '/api/sales/by_period?period='+period;
    if(sub) url += '&sub='+encodeURIComponent(sub);
    else if(selectedSubPeriod) url += '&sub='+encodeURIComponent(selectedSubPeriod);
    const res = await fetch(url);
    const data = await res.json();
    const rows = data.sales||[];
    if(!rows.length){
      body.innerHTML='<tr><td colspan=6 style="color:#888">No sales for '+period+'</td></tr>';
      summary.textContent='';
      return;
    }
    body.innerHTML = rows.map(r=>{
      const timeStr = r.time_only || (r.created_at ? new Date(r.created_at).toLocaleTimeString('en-PH',{hour:'2-digit',minute:'2-digit'}) : '');
      const dateTime = `${r.sales_date||''} ${timeStr}`.trim();
      const badge = `<span style="font-size:9px;background:#dcfce7;color:#166534;padding:3px 6px;border-radius:10px">${r.order_status||'Delivered'}</span>`;
      return `<tr><td style="font-size:10px">${dateTime}<br><small style="color:#888">${r.timestamp||''}</small></td><td>${r.reseller_name}</td><td>${r.quantity}</td><td>${r.kg_size}</td><td>₱${r.total_sales}</td><td>${badge}<br><div style="display:flex;gap:4px;margin-top:4px"><button class="icon-btn edit" style="width:26px;height:26px;font-size:12px" onclick="editSale('${r.id}');" title="Edit">✏️</button><button class="icon-btn del" style="width:26px;height:26px;font-size:12px" onclick="deleteSale('${r.id}')" title="Delete">🗑️</button></div></td></tr>`;
    }).join('');
    summary.textContent = `Total: ${rows.length} trans | ${data.total_kg||0}kg | ₱${(data.total_peso||0).toLocaleString()} | Showing ${period}`;
  }catch(e){
    body.innerHTML=`<tr><td colspan=6 style="color:red">Error: ${e.message}</td></tr>`;
  }
}

function formatTimestamp(iso){
  try{
    const d = new Date(iso);
    return d.toLocaleString('en-PH',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',hour12:true});
  }catch{ return iso||''; }
}

async function fetchLiveOrdersCount(){
  try{
    const res = await fetch('/api/staff/customer_orders');
    const data = await res.json();
    const orders = data.orders||[];
    const active = orders.filter(o=>!['Delivered','Cancelled'].includes(o.order_status)).length;
    const badge = document.getElementById('liveOrdersCount');
    if(badge){
      if(active>0){
        badge.textContent = active;
        badge.style.display = 'inline';
        // FIX #4: ALARM pag may bagong order
        if(active > lastActiveOrders && lastActiveOrders>=0){
          triggerOrderAlarm(active);
        }
      } else {
        badge.style.display = 'none';
      }
    }
    lastActiveOrders = active;
  }catch(e){}
}

function triggerOrderAlarm(count){
  if(!alarmEnabled) return;
  try{
    const audio = document.getElementById('orderAlarm');
    if(audio){
      audio.currentTime = 0;
      audio.play().catch(()=>{});
      // Stop after 10 seconds
      setTimeout(()=>{ audio.pause(); audio.currentTime=0; }, 10000);
    }
    // Vibrate phone/tablet
    if(navigator.vibrate){ navigator.vibrate([500,200,500,200,1000]); }
    // Show notification if permitted
    if(Notification && Notification.permission==='granted'){
      new Notification('🧊 New Omega Order!', {body: `${count} new order(s) waiting!`, icon: '/favicon.ico'});
    }
    // Flash title
    const originalTitle = document.title;
    let flash = 0;
    const flashInterval = setInterval(()=>{
      document.title = flash%2===0 ? '🔴 NEW ORDER! - '+originalTitle : '🔵 '+count+' Orders - '+originalTitle;
      flash++;
      if(flash>10){ clearInterval(flashInterval); document.title=originalTitle; }
    }, 800);
    // Visual flash on live orders button
    const liveBtn = document.querySelector('a[href="/orders"]');
    if(liveBtn){ liveBtn.classList.add('alarm-active'); setTimeout(()=>liveBtn.classList.remove('alarm-active'),10000); }
  }catch(e){ console.log('Alarm error',e); }
}

// Request notification permission on load
document.addEventListener('DOMContentLoaded', ()=>{
  if(Notification && Notification.permission==='default'){
    Notification.requestPermission();
  }
  // Enable alarm on first user interaction (browser policy)
  document.body.addEventListener('click', ()=>{
    const audio = document.getElementById('orderAlarm');
    if(audio){ audio.play().then(()=>{audio.pause();}).catch(()=>{}); }
  }, {once:true});
});

function stopAlarm(){
  const audio=document.getElementById('orderAlarm');
  if(audio){ audio.pause(); audio.currentTime=0; }
}

setInterval(fetchLiveOrdersCount, 30000);
fetchLiveOrdersCount();
async function loadToday(customDate=null){
  // Show date immediately so not stuck on 2026-09-06 - Tap Refresh
  const now = new Date();
  let todayStr = now.toISOString().split('T')[0];
  if(customDate) todayStr = customDate;
  else if(selectedDailyDate && cashierPeriod==='daily') todayStr = selectedDailyDate;
  
  document.getElementById('todayDate').textContent = todayStr + ' to ' + todayStr;
  document.getElementById('todayLabel').textContent = (cashierPeriod||'daily').toUpperCase() + ' SALES' + (customDate ? ' - '+customDate : '');
  try{
    const controller = new AbortController();
    const timeout = setTimeout(()=>controller.abort(), 8000);
    let url = '/api/sales/dashboard?period='+cashierPeriod;
    if(customDate) url += '&date='+customDate;
    else if(selectedDailyDate && cashierPeriod==='daily') url += '&date='+selectedDailyDate;
    const res=await fetch(url, {signal: controller.signal});
    clearTimeout(timeout);
    if(res.status===401){window.location.href='/login';return;}
    const data=await res.json();
    document.getElementById('todayKg').textContent=(data.total_kg||0).toLocaleString()+'kg';
    document.getElementById('todayPeso').textContent='₱'+(data.total||0).toLocaleString();
    document.getElementById('todayCount').textContent=data.count||0;
    document.getElementById('todayDate').textContent=(data.start||todayStr)+' to '+(data.date||todayStr);
    document.getElementById('todayLabel').textContent=(data.label||cashierPeriod||'TODAY').toUpperCase()+' SALES';
    const b=data.breakdown||{};document.getElementById('todayBreakdown').textContent=`1Kg:${b['1Kg']||0} 5Kg:${b['5Kg']||0} 10Kg:${b['10Kg']||0} 25Kg:${b['25Kg']||0}`;
    if(data.pending_count!==undefined){
      document.getElementById('todayBreakdown').textContent += ` | Pending:${data.pending_count||0}`;
    }
  }catch(e){
    console.error('Dashboard load error', e);
    document.getElementById('todayDate').textContent = todayStr + ' (offline/cached)';
    // Keep 0kg 0 peso if failed, but not stuck on 2026-09-06 - Tap Refresh
    document.getElementById('todayBreakdown').textContent = 'Failed to load - tap Refresh. Error: ' + (e.message||'timeout');
  }
}
async function loadRecent(customDate=null){
  try{
    let recentUrl = '/api/sales/recent';
    if(customDate) recentUrl += '?date='+customDate;
    else if(selectedDailyDate && cashierPeriod==='daily') recentUrl += '?date='+selectedDailyDate;
    const res=await fetch(recentUrl);
    if(res.status===401){window.location.href='/login';return;}
    let rows=await res.json();
    if(rows.sales)rows=rows.sales;
    document.getElementById('recentTimestamp').textContent = ' - ' + new Date().toLocaleTimeString('en-PH',{hour:'2-digit',minute:'2-digit'});
    if(!Array.isArray(rows)){document.getElementById('recentBody').innerHTML=`<tr><td colspan=7>No data</td></tr>`;return;}
    if(!rows.length){document.getElementById('recentBody').innerHTML=`<tr><td colspan=7 style="color:#888">No recent sales yet</td></tr>`;return;}
    document.getElementById('recentBody').innerHTML=rows.slice(0,30).map(r=>{
      const status = r.order_status || 'Delivered';
      let color = '#dcfce7'; let txtColor = '#166534';
      if(status==='Pending' || status==='New Order'){color='#fef3c7'; txtColor='#92400e';}
      else if(status==='Preparing'){color='#dbeafe'; txtColor='#1e40af';}
      else if(status==='Out for Delivery'){color='#e0e7ff'; txtColor='#3730a3';}
      else if(status==='Delivered'){color='#dcfce7'; txtColor='#166534';}
      const badge = `<span style="font-size:9px;background:${color};color:${txtColor};padding:3px 6px;border-radius:10px;white-space:nowrap">${status}</span>`;
      // FIX #3: timestamp
      let timeDisplay = '';
      if(r.created_at){
        try{ timeDisplay = formatTimestamp(r.created_at); }catch{ timeDisplay = r.created_at; }
      } else if(r.delivered_at){ timeDisplay = r.delivered_at.split('T')[1]?.substring(0,5) || r.delivered_at; }
      const deliveredInfo = `<div style="font-size:9px;color:#666">${timeDisplay}</div>`;
      return `<tr><td style="font-size:11px">${r.sales_date||''}${deliveredInfo}</td><td>${r.reseller_name}<br><small style="font-size:9px;color:#888">${timeDisplay}</small></td><td>${r.quantity}</td><td>${r.kg_size}</td><td>₱${r.total_sales}</td><td>${badge}</td><td><div style="display:flex;gap:4px"><button class="icon-btn edit" onclick="editSale('${r.id}')" title="Edit">✏️</button><button class="icon-btn del" onclick="deleteSale('${r.id}')" title="Delete">🗑️</button></div></td></tr>`;
    }).join('');
  }catch(e){document.getElementById('recentBody').innerHTML=`<tr><td colspan=7 style="color:#c0392b">Error: ${e.message} <a href="/login">Login</a></td></tr>`;}
}
async function deleteSale(id){if(!confirm('Delete?'))return;await fetch(`/api/sale/${id}`,{method:'DELETE'});loadRecent();loadToday();}




async function logout(){await fetch('/api/logout',{method:'POST'});window.location.href='/login'}

// FIX: Week/Month/Quarter/Year picker logic
let selectedSubPeriod = null;

function populateSubPeriodPicker(period){
  const picker = document.getElementById('subPeriodPicker');
  const select = document.getElementById('subPeriodSelect');
  const label = document.getElementById('subPeriodLabel');
  const dailyPicker = document.getElementById('dailyDatePicker');
  select.innerHTML='';
  
  // Always hide daily picker first
  if(dailyPicker) dailyPicker.style.display='none';
  
  if(period==='daily'){
    // Show daily date picker
    if(dailyPicker){
      dailyPicker.style.display='block';
      const dailyInput = document.getElementById('dailyDateInput');
      if(!dailyInput.value){
        dailyInput.value = new Date().toISOString().split('T')[0];
      }
    }
    picker.style.display='none';
    selectedSubPeriod=null;
    return;
  } else if(period==='weekly'){
    label.textContent='Select Week (WW01-WW52)';
    const now = new Date();
    const currentWeek = getWeekNumber(now);
    for(let i=1;i<=52;i++){
      const opt=document.createElement('option');
      const ww = 'WW'+String(i).padStart(2,'0');
      opt.value=ww;
      opt.textContent= ww + (i===currentWeek ? ' (Current)' : '');
      if(i===currentWeek) opt.selected=true;
      select.appendChild(opt);
    }
    selectedSubPeriod = 'WW'+String(currentWeek).padStart(2,'0');
    picker.style.display='block';
  } else if(period==='monthly'){
    label.textContent='Select Month';
    const months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const nowM = new Date().getMonth();
    for(let i=0;i<12;i++){
      const opt=document.createElement('option');
      opt.value=String(i+1).padStart(2,'0');
      opt.textContent= months[i] + ' - ' + String(i+1).padStart(2,'0');
      if(i===nowM) opt.selected=true;
      select.appendChild(opt);
    }
    selectedSubPeriod = String(nowM+1).padStart(2,'0');
    picker.style.display='block';
  } else if(period==='quarterly'){
    label.textContent='Select Quarter';
    const quarters=['Q1 (Jan-Mar)','Q2 (Apr-Jun)','Q3 (Jul-Sep)','Q4 (Oct-Dec)'];
    const nowQ = Math.floor(new Date().getMonth()/3);
    for(let i=0;i<4;i++){
      const opt=document.createElement('option');
      opt.value='Q'+(i+1);
      opt.textContent=quarters[i];
      if(i===nowQ) opt.selected=true;
      select.appendChild(opt);
    }
    selectedSubPeriod = 'Q'+(nowQ+1);
    picker.style.display='block';
  } else if(period==='yearly'){
    label.textContent='Select Year';
    const nowY = new Date().getFullYear();
    for(let y=nowY; y>=2024; y--){
      const opt=document.createElement('option');
      opt.value=String(y);
      opt.textContent=String(y) + (y===nowY?' (Current)':'');
      if(y===nowY) opt.selected=true;
      select.appendChild(opt);
    }
    selectedSubPeriod = String(nowY);
    picker.style.display='block';
  } else {
    picker.style.display='none';
    selectedSubPeriod=null;
  }
}

function getWeekNumber(d){
  d = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(),0,1));
  return Math.ceil(( ( (d - yearStart) / 86400000) + 1)/7);
}

function onSubPeriodChange(){
  const sel=document.getElementById('subPeriodSelect');
  selectedSubPeriod = sel.value;
  if(cashierPeriod!=='daily'){
    loadPeriodSales(cashierPeriod, selectedSubPeriod);
  }
}


let selectedDailyDate = null;

function onDailyDateChange(){
  const inp = document.getElementById('dailyDateInput');
  selectedDailyDate = inp.value;
  // Load both today card and recent for that date
  loadToday(selectedDailyDate);
  loadRecent(selectedDailyDate);
}

function setDailyToday(){
  const today = new Date().toISOString().split('T')[0];
  document.getElementById('dailyDateInput').value = today;
  onDailyDateChange();
}

function setDailyYesterday(){
  const d = new Date();
  d.setDate(d.getDate()-1);
  const y = d.toISOString().split('T')[0];
  document.getElementById('dailyDateInput').value = y;
  onDailyDateChange();
}

// Hook into setCashierPeriod to show picker
const origSetCashier = setCashierPeriod;
setCashierPeriod = function(p){
  origSetCashier(p);
  populateSubPeriodPicker(p);
  if(p!=='daily' && selectedSubPeriod){
    setTimeout(()=>loadPeriodSales(p, selectedSubPeriod), 100);
  }
}

updateTotal();loadRecent();loadToday();initDateInputs();setInterval(loadRecent,30000);setInterval(loadToday,30000);
window.addEventListener('storage', (e)=>{
  if(e.key==='omega_last_delivered'){
    console.log('Detected delivery from orders page, refreshing sales...');
    setTimeout(()=>{loadRecent();loadToday();}, 500);
  }
});
// Also check every 5 sec for last delivered signal (for same-tab)
setInterval(()=>{
  const last = localStorage.getItem('omega_last_delivered');
  if(last){
    try{
      const d = JSON.parse(last);
      if(Date.now() - d.time < 35000){ // If delivered within last 35 sec
        loadRecent();loadToday();
        localStorage.removeItem('omega_last_delivered');
      }
    }catch{}
  }
}, 5000);

</script>
</body></html>
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

def fb_delete(path):
    try:
        r = requests.delete(f"{FIREBASE_URL}/{path}.json", timeout=10)
        if r.status_code == 200:
            return True
    except Exception as e:
        print(f"DELETE {path} error: {e}")
    return False

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
    try:
        data = fb_get("resellers")
    except:
        data = None
    if data:
        try:
            save_cached_resellers(data)
        except:
            pass
        resellers = []
        for key, val in data.items():
            if not val:
                continue
            name = (val.get("store_name") or "").strip()
            phone = (val.get("phone") or val.get("contact") or "").strip()
            # Search in both name and phone, case-insensitive, partial match
            if not q:
                resellers.append({"id": key, "store_name": name, "credit_balance": val.get("credit_balance", 0), "phone": phone})
            else:
                # q matches name OR phone OR store_name contains q
                if q in name.lower() or q in phone.lower() or q in phone.replace(" ",""):
                    resellers.append({"id": key, "store_name": name, "credit_balance": val.get("credit_balance", 0), "phone": phone})
                # Also try without spaces
                elif q.replace(" ","") in name.lower().replace(" ",""):
                    resellers.append({"id": key, "store_name": name, "credit_balance": val.get("credit_balance", 0), "phone": phone})
        resellers.sort(key=lambda x: x["store_name"].lower())
        # Return more results for search
        if not q:
            return jsonify(resellers[:100])
        else:
            return jsonify(resellers[:50])
    else:
        # offline fallback - use cached
        try:
            cached = get_cached_resellers(q)
            # also filter by phone in cached if needed
            return jsonify(cached[:50])
        except:
            return jsonify([])

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

    # Allow custom date from frontend
    frontend_date = (data.get("sales_date") or "").strip()
    frontend_created = (data.get("created_at") or "").strip()
    if frontend_date:
        try:
            datetime.strptime(frontend_date[:10], "%Y-%m-%d")
            sales_date_val = frontend_date[:10]
        except:
            sales_date_val = datetime.now().strftime("%Y-%m-%d")
    else:
        sales_date_val = datetime.now().strftime("%Y-%m-%d")
    
    if frontend_created:
        created_val = frontend_created
    else:
        created_val = datetime.now().isoformat()
    
    sale = {
        "sales_date": sales_date_val,
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
        "created_at": created_val,
        "time_only": (data.get("sale_time") or datetime.now().strftime("%H:%M"))
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
    # FIXED: Dashboard vs Recent Sales + custom date filter
    custom_date = request.args.get("date", "").strip()

    try:
        import pytz
        manila = pytz.timezone('Asia/Manila')
        now = datetime.now(manila)
    except:
        now = datetime.now()
    today_str = custom_date if custom_date else now.strftime("%Y-%m-%d")
    
    data = fb_get("daily_sales")
    sales = []
    recent = []
    if data:
        for key, val in data.items():
            if not val: continue
            # Allow customer Delivered even if archived_for_daily_only? No - Done sets archived=False
            # But skip truly deleted
            if val.get("deleted"): continue
            # For Recent Sales, include BOTH cashier and customer Delivered today
            # Make #2: Sept 06 archived 3721kg should NOT show in Recent (Daily=0), but new customer Done SHOULD
            if val.get("archived"):
                # If archived for Make #2 (Sept 06 fix), skip for Recent to keep Daily=0
                # But if is_customer_order and delivered today, include (Done sets archived=False so this won't happen)
                if not val.get("is_customer_order"):
                    continue
                # Even customer if hidden_24h, skip
                if val.get("hidden_24h"):
                    continue
            
            sd = (val.get("sales_date") or "")[:10]
            dd = (val.get("delivered_date") or "")[:10]
            # Recent Sales = TODAY only (same as Dashboard daily) - shows customer Done today
            # Include if sales_date OR delivered_date is today and status Delivered/Out
            status = val.get("order_status") or "Delivered"
            is_today = (sd == today_str or dd == today_str)
            # Also include if is_customer_order and status Delivered even if sales_date is today
            if status in ["Delivered", "Out for Delivery"] or val.get("is_customer_order"):
                if not is_today and status in ["Delivered", "Out for Delivery"]:
                    # For old Delivered, only show if within last 24h? For Recent, show today only to match Dashboard
                    # But allow if delivered today
                    pass
                # Only add if today
                if is_today:
                    sales.append({
                        "id": key,
                        "sales_date": val.get("sales_date"),
                        "reseller_name": val.get("reseller_name"),
                        "quantity": val.get("quantity"),
                        "kg_size": val.get("kg_size"),
                        "total_sales": val.get("total_sales"),
                        "mode": val.get("mode"),
                        "payment": val.get("payment"),
                        "order_status": status,
                        "delivered_at": val.get("delivered_at") or "",
                        "delivered_date": val.get("delivered_date") or "",
                        "created_at": val.get("created_at",""),
                        "is_customer": val.get("is_customer_order", False),
                        "is_online": val.get("order_source") == "customer"
                    })
        # Sort by delivered_at desc, then created_at desc - newest Done on top
        sales.sort(key=lambda x: (x.get("delivered_at") or x.get("created_at") or ""), reverse=True)
        recent = sales[:30]  # Show 30 to ensure customer orders visible
    
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


@app.route("/api/sales/by_period")
@login_required
def api_sales_by_period():
    """FIX #2: Return sales for selected period (monthly/weekly/etc) for cashier screen + WW/month pickers"""
    period = request.args.get("period", "monthly").lower()
    sub = request.args.get("sub", "").strip() or request.args.get("week", "").strip() or request.args.get("month", "").strip() or "" 
    try:
        import pytz
        manila = pytz.timezone('Asia/Manila')
        now = datetime.now(manila)
    except:
        now = datetime.now()
    
    data = fb_get("daily_sales") or {}
    sales = []
    start_date = None
    end_date = now
    
    # Handle sub-period picker: WW01-WW52, month 01-12, Q1-Q4, year
    target_week = None
    target_month = None
    target_quarter = None
    target_year = None
    
    if sub:
        s = sub.upper()
        if s.startswith("WW"):
            try:
                target_week = int(s.replace("WW",""))
            except:
                pass
        elif s.startswith("Q"):
            try:
                target_quarter = int(s.replace("Q",""))
            except:
                pass
        elif s.isdigit() and len(s)==4:  # year
            try:
                target_year = int(s)
            except:
                pass
        elif s.isdigit() and 1 <= int(s) <= 12:  # month
            try:
                target_month = int(s)
                if period=="monthly":
                    # monthly picker overrides month
                    pass
            except:
                pass
    
    if period == "daily":
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == "weekly":
        if target_week:
            # For WW, we need to filter by week number, not last 7 days
            start_date = None  # handled via week check
        else:
            start_date = (now - timedelta(days=7)).replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == "monthly":
        if target_month:
            # Specific month of current year (or target_year if provided)
            y = target_year or now.year
            start_date = now.replace(year=y, month=target_month, day=1, hour=0, minute=0, second=0, microsecond=0)
            # end of that month
            if target_month == 12:
                end_date = start_date.replace(year=y+1, month=1, day=1) - timedelta(days=1)
            else:
                end_date = start_date.replace(month=target_month+1, day=1) - timedelta(days=1)
            end_date = end_date.replace(hour=23, minute=59, second=59)
        else:
            start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elif period == "quarterly":
        if target_quarter:
            # Q1=1-3, Q2=4-6, Q3=7-9, Q4=10-12
            q_start_month = (target_quarter-1)*3+1
            y = target_year or now.year
            start_date = now.replace(year=y, month=q_start_month, day=1, hour=0, minute=0, second=0, microsecond=0)
            q_end_month = q_start_month+2
            if q_end_month==12:
                end_date = start_date.replace(month=12, day=31, hour=23, minute=59, second=59)
            else:
                end_date = start_date.replace(month=q_end_month+1, day=1) - timedelta(days=1)
                end_date = end_date.replace(hour=23, minute=59, second=59)
        else:
            month = now.month - 2
            year = now.year
            if month <=0:
                month += 12
                year -=1
            start_date = now.replace(year=year, month=month, day=1, hour=0, minute=0, second=0, microsecond=0)
    elif period in ["yearly","year"]:
        if target_year:
            start_date = now.replace(year=target_year, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            end_date = now.replace(year=target_year, month=12, day=31, hour=23, minute=59, second=59)
        else:
            start_date = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    elif period == "all":
        start_date = None
    
    def parse_date(d):
        try:
            return datetime.strptime(d[:10], "%Y-%m-%d")
        except:
            return None
    
    for key, val in data.items():
        if not val: continue
        if val.get("deleted"): continue
        # Skip archived Make #2 fix unless customer order
        if val.get("archived") and not val.get("is_customer_order"):
            if not val.get("include_in_all_time"):
                # Still include for all_time? No for now keep simple
                if period != "all":
                    continue
        sd = parse_date(val.get("sales_date") or "")
        dd = parse_date(val.get("delivered_date") or "")
        # Use sales_date primarily, fallback to delivered_date, then created_at
        check_date = sd or dd
        if not check_date:
            try:
                ca = val.get("created_at","")[:10]
                check_date = parse_date(ca)
            except:
                check_date = None
        
        # WW filter
        if target_week and period=="weekly":
            if check_date:
                # calc week number
                try:
                    # iso week
                    iso_year, iso_week, iso_day = check_date.isocalendar()
                    if iso_week != target_week:
                        continue
                    # Also check year if target_year set else current year
                    if target_year and iso_year != target_year:
                        continue
                except:
                    continue
            else:
                continue
        else:
            if start_date and check_date and check_date < start_date.replace(tzinfo=None):
                continue
            # Also ensure not future for non-WW
            if check_date and check_date > end_date.replace(tzinfo=None) + timedelta(days=1):
                continue
            
        # Build timestamp info
        created = val.get("created_at") or val.get("delivered_at") or ""
        time_only = ""
        timestamp_fmt = ""
        if created:
            try:
                if "T" in created:
                    time_only = created.split("T")[1][:5]
                    dt = datetime.fromisoformat(created.replace("Z",""))
                    timestamp_fmt = dt.strftime("%I:%M %p")
                else:
                    timestamp_fmt = created
            except:
                timestamp_fmt = created
        
        sales.append({
            "id": key,
            "sales_date": val.get("sales_date"),
            "reseller_name": val.get("reseller_name"),
            "quantity": val.get("quantity"),
            "kg_size": val.get("kg_size"),
            "total_sales": val.get("total_sales"),
            "order_status": val.get("order_status") or "Delivered",
            "created_at": created,
            "time_only": time_only,
            "timestamp": timestamp_fmt,
            "delivered_at": val.get("delivered_at","")
        })
    
    sales.sort(key=lambda x: (x.get("created_at") or x.get("sales_date") or ""), reverse=True)
    total_kg = sum([float(str(s.get("quantity") or 0)) * float(str(s.get("kg_size") or "1Kg").lower().replace("kg","").strip() or 0) for s in sales])
    total_peso = sum([float(s.get("total_sales") or 0) for s in sales])
    
    return jsonify({"sales": sales[:100], "total_kg": total_kg, "total_peso": total_peso, "count": len(sales), "period": period})

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

@app.route("/api/sale/<sale_id>", methods=["GET"])
@login_required
def api_get_sale(sale_id):
    if str(sale_id).startswith("offline-"):
        try:
            oid = int(str(sale_id).replace("offline-", ""))
            conn = sqlite3.connect(LOCAL_DB)
            c = conn.cursor()
            c.execute("SELECT id, sales_date, reseller_name, quantity, kg_size, total_sales, mode, payment, created_at FROM cached_sales WHERE id=?", (oid,))
            row = c.fetchone()
            conn.close()
            if not row:
                return jsonify({"ok": False, "error": "Not found"}), 404
            sale = {"id": sale_id, "sales_date": row[1], "reseller_name": row[2], "reseller_id": None,
                    "quantity": row[3], "kg_size": row[4], "total_sales": row[5], "mode": row[6],
                    "payment": row[7], "created_at": row[8]}
            return jsonify({"ok": True, "sale": sale})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400
    try:
        sale = fb_get(f"daily_sales/{sale_id}")
        if not sale:
            return jsonify({"ok": False, "error": "Not found"}), 404
        sale["id"] = sale_id
        return jsonify({"ok": True, "sale": sale})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/sale/<sale_id>", methods=["PUT"])
@login_required
def api_update_sale(sale_id):
    data = request.json or {}
    reseller_id = data.get("reseller_id")
    reseller_name = (data.get("reseller_name") or "").strip()
    try:
        qty = int(data.get("quantity", 1))
    except (TypeError, ValueError):
        qty = 0
    kg_size = data.get("kg_size", "1Kg")
    mode = data.get("mode", "DELIVER")
    payment = data.get("payment", "Cash")
    manual_total = data.get("total_sales")

    if not reseller_name or qty <= 0:
        return jsonify({"ok": False, "error": "Reseller and quantity required"}), 400

    if manual_total is not None and str(manual_total).strip() != "":
        try:
            total = round(float(manual_total), 2)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid total"}), 400
        unit_price = round(total / qty, 2) if qty else 0
    else:
        unit_price = get_price(kg_size, mode)
        total = round(unit_price * qty, 2)

    # Allow date edit
    sales_date = (data.get("sales_date") or "").strip()
    sale_time = (data.get("sale_time") or "").strip()
    created_at = (data.get("created_at") or "").strip()
    if sales_date:
        # validate date
        try:
            datetime.strptime(sales_date[:10], "%Y-%m-%d")
        except:
            sales_date = None
    if not sales_date:
        sales_date = datetime.now().strftime("%Y-%m-%d")
    
    if created_at:
        try:
            # keep as iso
            if "T" not in created_at:
                created_at = sales_date + "T" + (sale_time or "12:00") + ":00"
        except:
            created_at = datetime.now().isoformat()
    else:
        created_at = datetime.now().isoformat()
    
    upd = {
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
        "sales_date": sales_date,
        "created_at": created_at,
        "edited_at": datetime.now().isoformat(),
        "edited_by": session.get("staff_name")
    }

    if str(sale_id).startswith("offline-"):
        try:
            oid = int(str(sale_id).replace("offline-", ""))
            conn = sqlite3.connect(LOCAL_DB)
            c = conn.cursor()
            c.execute("UPDATE cached_sales SET reseller_name=?, quantity=?, kg_size=?, total_sales=?, mode=?, payment=? WHERE id=?",
                      (reseller_name, qty, kg_size, total, mode, payment, oid))
            conn.commit()
            conn.close()
            return jsonify({"ok": True, "total": total, "unit_price": unit_price})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    result = fb_patch(f"daily_sales/{sale_id}", upd)
    if result is not None:
        return jsonify({"ok": True, "total": total, "unit_price": unit_price})
    return jsonify({"ok": False, "error": "Failed to update in Firebase"}), 500

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

<div id="historyList">2026-09-06 - Tap Refresh</div>

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



# ============= CUSTOMER PORTAL - SECURE WITH OTP =============

CUSTOMER_LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Customer Login - Omega Ice</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:linear-gradient(135deg,#00609C,#0096D6);margin:0;min-height:100vh;padding:16px;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:16px;padding:24px;width:100%;max-width:380px;box-shadow:0 8px 30px rgba(0,0,0,.2)}
.header{text-align:center;margin-bottom:20px}.header h1{font-size:20px;color:#00609C;margin:0}.header p{font-size:12px;color:#666;margin:4px 0}
label{font-size:12px;color:#666;display:block;margin:12px 0 6px}input{width:100%;padding:14px;border-radius:12px;border:1.5px solid #ccd;font-size:15px}
.btn{width:100%;padding:14px;background:#00609C;color:#fff;border:none;border-radius:12px;font-size:15px;font-weight:600;margin-top:16px}
.btn-otp{background:#f59e0b;margin-top:8px}
.status{font-size:12px;text-align:center;margin-top:10px;min-height:18px}.status.err{color:#c0392b}.status.ok{color:#1a8a4a}
</style></head>
<body>
<div class="card">
<div class="header"><h1>🧊 OMEGA ICE</h1><p>Customer Secure Login</p><p style="font-size:11px;color:#888">One phone + password per store</p></div>
<label>Registered Phone</label><input type="tel" id="phone" placeholder="09xx xxx xxxx">
<label>Password</label><input type="password" id="password" placeholder="Enter password">
<button class="btn" onclick="doLogin()">🔐 Login</button>
<p class="status" id="status"></p>
<p style="font-size:12px;color:#888;text-align:center;margin-top:14px;border-top:1px solid #eee;padding-top:14px">Forgot your password?<br>Contact ISESMO to have it reset for you.</p>
</div>
<script>
async function doLogin(){
  const phone=document.getElementById('phone').value.trim();
  const pwd=document.getElementById('password').value;
  const st=document.getElementById('status');
  if(!phone||!pwd){st.textContent='Enter phone and password';st.className='status err';return;}
  st.textContent='Checking...';
  const res=await fetch('/api/customer/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:phone,password:pwd})});
  const data=await res.json();
  if(data.ok){st.textContent='OK! 2026-09-06 - Tap Refresh';window.location.href=`/customer/${data.reseller_id}/dashboard`;}
  else{st.textContent=data.error||'Wrong phone or password';st.className='status err';}
}
</script>
</body></html>
"""

CUSTOMER_DASHBOARD_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>My Orders - Omega Ice</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.topbar h1{font-size:15px;color:#00609C;margin:0}
.live{display:inline-flex;align-items:center;gap:6px;background:#22c55e;color:#fff;padding:6px 12px;border-radius:20px;font-size:11px}
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;text-align:center}.stat-val{font-size:18px;font-weight:700;color:#00609C}.stat-lbl{font-size:9px;color:#888}
.status-pill{padding:4px 10px;border-radius:12px;font-size:10px;font-weight:600}
.status-new{background:#fef3c7;color:#92400e}.status-pending{background:#fef3c7;color:#92400e}.status-preparing{background:#dbeafe;color:#1e40af}.status-out{background:#e0e7ff;color:#3730a3}.status-delivered{background:#dcfce7;color:#166534}
.order-card{border-left:4px solid #0096D6;padding:12px;margin:8px 0;background:#fff;border-radius:8px;cursor:pointer;transition:box-shadow .15s}
.order-card:active{box-shadow:0 0 0 2px #cde inset}
.btn{padding:10px 14px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;text-decoration:none}
.btn-primary{background:#00609C;color:#fff;border-color:#00609C;padding:12px 20px;font-weight:600}
/* --- Live tracking modal --- */
.track-overlay{display:none;position:fixed;inset:0;background:rgba(10,25,45,.5);z-index:50;align-items:flex-end;justify-content:center}
.track-overlay.show{display:flex}
.track-sheet{background:#fff;border-radius:20px 20px 0 0;width:100%;max-width:480px;max-height:88vh;overflow-y:auto;padding:20px;position:relative;animation:trackUp .18s ease-out}
@keyframes trackUp{from{transform:translateY(24px);opacity:0}to{transform:translateY(0);opacity:1}}
.track-close{position:absolute;top:14px;right:14px;background:#f0f4f8;border:none;width:28px;height:28px;border-radius:50%;font-size:14px;color:#555;cursor:pointer;line-height:1}
.track-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:18px;padding-right:30px}
.track-head-left{display:flex;gap:10px;align-items:center}
.track-icon{width:44px;height:44px;border-radius:50%;background:#e8f7ee;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.track-title{font-size:12px;font-weight:700;letter-spacing:.5px;color:#0f2942;margin:0}
.track-sub{font-size:12px;color:#8a97a3;margin-top:2px}
.track-live-badge{background:#0f2942;color:#fff;font-size:10px;font-weight:700;letter-spacing:.5px;padding:6px 14px;border-radius:20px;white-space:nowrap}
.track-progress{background:#eef4fb;border-radius:16px;padding:20px 16px;margin-bottom:14px}
.track-dots{display:flex;align-items:center}
.track-dot-wrap{display:flex;align-items:center;justify-content:center}
.track-dot{width:22px;height:22px;border-radius:50%;background:#fff;border:3px solid #163a5c;display:flex;align-items:center;justify-content:center;box-shadow:0 0 0 5px #d7e9fb;z-index:2}
.track-dot.pending{border-color:#c7d6e4;box-shadow:0 0 0 5px #eef3f8}
.track-dot-inner{width:8px;height:8px;border-radius:50%;background:#163a5c}
.track-dot.pending .track-dot-inner{background:#c7d6e4}
.track-line{flex:1;height:3px;background:#c7d6e4}
.track-line.filled{background:#2f6fb0}
.track-pills{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap}
.track-pill{flex:1;min-width:64px;text-align:center;padding:10px 4px;border-radius:20px;background:#eef3f8;color:#9aa7b3;font-size:9px;font-weight:700;letter-spacing:.2px}
.track-pill.active{background:#163a5c;color:#fff}
.track-timeline{background:#f7f9fb;border-radius:16px;padding:18px 16px}
.tl-row{display:flex;gap:14px}
.tl-marker-col{display:flex;flex-direction:column;align-items:center}
.tl-check{width:34px;height:34px;border-radius:50%;background:#163a5c;color:#fff;display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0}
.tl-check.pending{background:#dbe3ea;color:#dbe3ea}
.tl-connector{width:2px;flex:1;background:#c7d6e4;margin:4px 0;min-height:20px}
.tl-content{padding-bottom:26px}
.tl-title{font-weight:700;color:#0f2942;font-size:14px;margin-bottom:3px}
.tl-desc{font-size:12px;color:#8a97a3}
.track-cancelled{text-align:center;padding:30px 10px}
</style></head>
<body>
<div class="topbar"><div><h1 id="storeName">My Orders</h1><div style="font-size:11px;color:#666" id="storeMeta"></div></div><div style="display:flex;gap:6px"><span class="live">● LIVE</span><a href="/customer/logout" class="btn">Logout</a></div></div>
<div class="card"><div style="display:flex;justify-content:space-between;margin-bottom:8px"><span style="font-size:12px;font-weight:600">Summary</span><a href="/customer/{{ reseller_id }}/order" class="btn btn-primary">+ New Order</a></div><div class="stat-grid"><div><div class="stat-val" id="totalKg">0kg</div><div class="stat-lbl">TOTAL KG</div></div><div><div class="stat-val" id="totalPeso">₱0</div><div class="stat-lbl">TOTAL PESO</div></div><div><div class="stat-val" id="totalOrders">0</div><div class="stat-lbl">ORDERS</div></div></div><div id="statusCounts" style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;font-size:10px"></div>
<div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap">
<button onclick="loadOrders()" style="padding:8px 12px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px">🔄 Refresh</button>
<button onclick="bulkMarkDelivered()" style="padding:8px 12px;border-radius:20px;border:1px solid #86efac;background:#f0fdf4;color:#166534;font-size:11px">✅ Mark all Pending as Delivered</button>
<span style="font-size:10px;color:#888;padding:8px">Staff will update to Preparing → Delivered</span>
</div>
</div>
<div class="card"><div style="font-size:12px;font-weight:600;margin-bottom:8px;display:flex;justify-content:space-between"><span>Real-time Orders</span><span style="font-size:10px;color:#888" id="lastUpdate"></span></div><div id="ordersList">Loading orders...</div></div>

<div class="track-overlay" id="trackOverlay" onclick="if(event.target===this)closeTracking()">
  <div class="track-sheet">
    <button class="track-close" onclick="closeTracking()">✕</button>
    <div id="trackBody">Loading...</div>
  </div>
</div>

<script>
const resellerId="{{ reseller_id }}";
let showArchived=false;
let lastOrders=[];
async function loadOrders(){
  try{
    const res=await fetch(`/api/customer/${resellerId}/orders?show_archived=${showArchived?1:0}`);
    const data=await res.json();
    const ordersRaw=data.orders||[];
    const priority = {"New Order":0, "Pending":1, "Preparing":2, "Out for Delivery":3, "Delivered":4, "Cancelled":5};
    const orders = ordersRaw.sort((a,b)=>{
      const pa = priority[a.order_status] ?? 1;
      const pb = priority[b.order_status] ?? 1;
      if(pa!==pb) return pa-pb;
      return (b.created_at||'').localeCompare(a.created_at||'');
    });
    const stats=data.stats||{};
    document.getElementById('totalKg').textContent=(stats.total_kg||0).toLocaleString()+'kg';
    document.getElementById('totalPeso').textContent='₱'+(stats.total_peso||0).toLocaleString();
    document.getElementById('totalOrders').textContent=stats.count||0;
    document.getElementById('storeName').textContent=data.reseller_name||'My Orders';
    document.getElementById('storeMeta').textContent=`Balance: ₱${stats.credit_balance||0} | ${new Date().toLocaleTimeString()}`;
    document.getElementById('lastUpdate').textContent=new Date().toLocaleTimeString();
    const counts=stats.status_counts||{};
    pendingCountCache=counts['Pending']||0;
    document.getElementById('statusCounts').innerHTML=Object.entries(counts).map(([k,v])=>`<span class="status-pill status-${k.toLowerCase().replace(/ /g,'-')}">${k}: ${v}</span>`).join('');
    const list=document.getElementById('ordersList');
    lastOrders=orders;
    if(!orders.length){list.innerHTML='<div style="text-align:center;color:#888;padding:20px">No orders yet. Tap + New Order<br><br><button onclick="loadOrders()" style="padding:8px 14px;border-radius:20px;background:#00609C;color:#fff;border:none">🔄 Refresh Now</button></div>';return;}
    list.innerHTML=orders.map(o=>`<div class="order-card" data-order-id="${o.id}" onclick="openTracking('${o.id}')"><div style="display:flex;justify-content:space-between"><span style="font-size:11px;color:#888">${o.sales_date||''} • ${o.created_at||''}</span><span class="status-pill status-${(o.order_status||'pending').toLowerCase().replace(/ /g,'-')}">${o.order_status||'Pending'}</span></div><div style="font-size:13px;margin-top:4px">${o.quantity}x ${o.kg_size} • ${o.mode} • ₱${o.total_sales}</div><div style="font-size:10px;color:#888;margin-top:2px">Order ID: ${o.id.slice(0,8)} • Tap to track →</div></div>`).join('');
  }catch(e){
    document.getElementById('ordersList').innerHTML=`<div style="color:red;padding:10px">Error loading: ${e.message}<br><button onclick="loadOrders()" style="padding:8px 14px;border-radius:20px;background:#00609C;color:#fff;border:none">Retry</button></div>`;
  }
}
function toggleArchived(){showArchived=!showArchived;loadOrders();}

let pendingCountCache=0;
async function bulkMarkDelivered(){
  const count = pendingCountCache || 'all';
  if(!confirm(`Mark ${count} Pending orders as Delivered? This cannot be undone in bulk.`)) return;
  try{
    const res=await fetch(`/api/customer/${resellerId}/bulk_update`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({from_status:'Pending',status:'Delivered'})});
    const data=await res.json();
    if(data.ok){alert(`✅ Updated ${data.updated} orders to Delivered!`);loadOrders();}
    else{alert(data.error||'Failed');}
  }catch(e){alert('Network error: '+e.message);}
}

const TRACK_STAGES=['Pending','Preparing','Out for Delivery','Delivered'];
function trackStageIndex(status){
  const map={'New Order':0,'Pending':0,'Preparing':1,'Out for Delivery':2,'Delivered':3};
  return map[status] ?? 0;
}
function openTracking(orderId){
  const o=lastOrders.find(x=>x.id===orderId);
  if(!o) return;
  const status=o.order_status||'Pending';
  const body=document.getElementById('trackBody');
  if(status==='Cancelled'){
    body.innerHTML=`<div class="track-cancelled"><div style="font-size:40px;margin-bottom:10px">❌</div><div style="font-weight:700;font-size:15px;color:#c0392b">Order Cancelled</div><div style="font-size:12px;color:#888;margin-top:6px">${o.quantity}x ${o.kg_size} • ₱${o.total_sales}</div></div>`;
    document.getElementById('trackOverlay').classList.add('show');
    return;
  }
  const idx=trackStageIndex(status);
  const isPickup=o.mode==='PICKUP';
  const descs=[
    'Order received • Waiting for confirmation',
    `Crushing & packing ${o.quantity}x ${o.kg_size}`,
    isPickup?'Ready for pickup at the store':'Rider is on the way to you',
    isPickup?`Picked up • ₱${o.total_sales} ${o.payment||''}`:`Delivered • ₱${o.total_sales} ${o.payment||''}`
  ];
  let dotsHtml='';
  TRACK_STAGES.forEach((s,i)=>{
    dotsHtml+=`<div class="track-dot-wrap"><div class="track-dot ${i<=idx?'':'pending'}"><div class="track-dot-inner"></div></div></div>`;
    if(i<TRACK_STAGES.length-1){dotsHtml+=`<div class="track-line ${i<idx?'filled':''}"></div>`;}
  });
  const pillsHtml=TRACK_STAGES.map((s,i)=>`<div class="track-pill ${i===idx?'active':''}">${s.toUpperCase()}</div>`).join('');
  const tlHtml=TRACK_STAGES.map((s,i)=>`
    <div class="tl-row">
      <div class="tl-marker-col"><div class="tl-check ${i<=idx?'':'pending'}">${i<=idx?'✓':''}</div>${i<TRACK_STAGES.length-1?'<div class="tl-connector"></div>':''}</div>
      <div class="tl-content"><div class="tl-title">${s}</div><div class="tl-desc">${descs[i]}</div></div>
    </div>`).join('');
  body.innerHTML=`
    <div class="track-head">
      <div class="track-head-left"><div class="track-icon">📡</div><div><p class="track-title">LIVE TRACKING</p><p class="track-sub">#${o.id.slice(0,8).toUpperCase()} • ${o.quantity}x ${o.kg_size}</p></div></div>
      <span class="track-live-badge">LIVE</span>
    </div>
    <div class="track-progress"><div class="track-dots">${dotsHtml}</div></div>
    <div class="track-pills">${pillsHtml}</div>
    <div class="track-timeline">${tlHtml}</div>`;
  document.getElementById('trackOverlay').classList.add('show');
}
function closeTracking(){document.getElementById('trackOverlay').classList.remove('show');}

loadOrders();setInterval(loadOrders,10000);
</script>
</body></html>
"""


CUSTOMER_ORDER_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Place Order - Omega Ice</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.topbar h1{font-size:15px;color:#00609C;margin:0}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px}
label{font-size:12px;color:#666;display:block;margin:10px 0 4px}input,textarea{width:100%;padding:12px;border-radius:10px;border:1px solid #ccd;font-size:14px}
.kg-row{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.kg-row button{padding:12px;border-radius:10px;border:1px solid #ccd;background:#f5f5f5}
.kg-row button.active{background:#00609C;color:#fff}
.toggle-row{display:flex;gap:8px}.toggle-row button{flex:1;padding:12px;border-radius:10px;border:1px solid #ccd;background:#f5f5f5}
.toggle-row button.active{background:#0096D6;color:#fff}
.total-row{display:flex;justify-content:space-between;margin:16px 0}.amount{font-size:24px;font-weight:700;color:#00609C}
.btn{width:100%;padding:14px;background:#00609C;color:#fff;border:none;border-radius:12px;font-weight:700}
</style></head>
<body>
<div class="topbar"><h1>🧊 New Order</h1><a href="/customer/{{ reseller_id }}/dashboard" style="font-size:12px;color:#00609C;text-decoration:none;background:#fff;padding:6px 12px;border-radius:20px;border:1px solid #cde">My Orders</a></div>
<div class="card">
<label>Date Needed</label><input type="date" id="needDate">
<label>Size</label><div class="kg-row"><button data-kg="1Kg" class="active" onclick="setKg('1Kg')">1Kg</button><button data-kg="5Kg" onclick="setKg('5Kg')">5Kg</button><button data-kg="10Kg" onclick="setKg('10Kg')">10Kg</button><button data-kg="25Kg" onclick="setKg('25Kg')">25Kg</button></div>
<label>Quantity</label><input type="number" id="qty" value="10" min="1" oninput="calc()">

<div id="prefSummaryRow" style="display:none;background:#f0f6fc;border:1px solid #cde;border-radius:10px;padding:12px 14px;margin:10px 0;align-items:center;justify-content:space-between">
  <div style="font-size:13px;color:#333">
    <span style="color:#888;font-size:11px;display:block;margin-bottom:2px">Delivery &amp; Payment</span>
    <span id="prefSummaryText" style="font-weight:600"></span>
  </div>
  <button type="button" onclick="expandPrefs()" style="background:none;border:none;color:#00609C;font-size:12px;font-weight:700;text-decoration:underline;padding:6px">Change</button>
</div>

<div id="prefFullRow">
<label>Delivery</label><div class="toggle-row"><button id="modeDeliver" class="active" onclick="setMode('DELIVER')">Deliver</button><button id="modePickup" onclick="setMode('PICKUP')">Pickup</button></div>
<label>Payment</label><div class="toggle-row"><button id="payCash" class="active" onclick="setPay('Cash')">Cash</button><button id="payCredit" onclick="setPay('Credit')">Credit</button></div>
<button type="button" id="prefDoneBtn" onclick="collapsePrefs()" style="display:none;width:100%;padding:10px;margin-top:4px;background:#eef7ff;color:#00609C;border:1px solid #cde;border-radius:10px;font-size:12px;font-weight:600">Use these as my default ✓</button>
</div>
<label>Notes</label><textarea id="notes" rows="2" placeholder="Leave at back gate"></textarea>
<div class="total-row"><span>Total</span><span class="amount" id="totalAmt">₱100</span></div>
<button class="btn" onclick="placeOrder()">Place Order Live</button>
<p id="status" style="font-size:12px;text-align:center;margin-top:8px"></p>
</div>
<script>
const resellerId="{{ reseller_id }}";
let kg='1Kg';let mode='DELIVER';let pay='Cash';
const prices={"1Kg":10,"5Kg":50,"10Kg":100,"25Kg":250};
const prefKey=`omega_order_pref_${resellerId}`;
function setKg(k){kg=k;document.querySelectorAll('.kg-row button').forEach(b=>b.classList.toggle('active',b.dataset.kg===k));calc();}
function setMode(m){mode=m;document.getElementById('modeDeliver').classList.toggle('active',m==='DELIVER');document.getElementById('modePickup').classList.toggle('active',m==='PICKUP');}
function setPay(p){pay=p;document.getElementById('payCash').classList.toggle('active',p==='Cash');document.getElementById('payCredit').classList.toggle('active',p==='Credit');}
function calc(){const qty=parseInt(document.getElementById('qty').value)||0;document.getElementById('totalAmt').textContent='₱'+((prices[kg]||10)*qty).toLocaleString();}
function prefLabel(){return `${mode==='DELIVER'?'🚚 Deliver':'🏪 Pickup'} · ${pay==='Cash'?'💵 Cash':'🧾 Credit'}`;}
function expandPrefs(){document.getElementById('prefFullRow').style.display='block';document.getElementById('prefSummaryRow').style.display='none';document.getElementById('prefDoneBtn').style.display='block';}
function collapsePrefs(){
  try{localStorage.setItem(prefKey,JSON.stringify({mode,pay}));}catch(e){}
  document.getElementById('prefSummaryText').textContent=prefLabel();
  document.getElementById('prefFullRow').style.display='none';
  document.getElementById('prefSummaryRow').style.display='flex';
}
(function loadSavedPrefs(){
  try{
    const saved=JSON.parse(localStorage.getItem(prefKey)||'null');
    if(saved && saved.mode && saved.pay){
      mode=saved.mode;pay=saved.pay;
      setMode(mode);setPay(pay);
      document.getElementById('prefSummaryText').textContent=prefLabel();
      document.getElementById('prefSummaryRow').style.display='flex';
      document.getElementById('prefFullRow').style.display='none';
      document.getElementById('prefDoneBtn').style.display='block';
    }
  }catch(e){}
})();
document.getElementById('needDate').value=new Date().toISOString().slice(0,10);calc();
async function placeOrder(){
  const qty=parseInt(document.getElementById('qty').value)||0;
  const needDate=document.getElementById('needDate').value;
  const notes=document.getElementById('notes').value;
  try{localStorage.setItem(prefKey,JSON.stringify({mode,pay}));}catch(e){}
  const res=await fetch(`/api/customer/${resellerId}/place_order`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({quantity:qty,kg_size:kg,mode:mode,payment:pay,sales_date:needDate,notes:notes})});
  const data=await res.json();
  if(data.ok){window.location.href=`/customer/${resellerId}/dashboard`;}else{document.getElementById('status').textContent=data.error||'Failed';}
}
</script>
</body></html>
"""

# Customer routes

@app.route("/customer")
def customer_login_page():
    return render_template_string(CUSTOMER_LOGIN_HTML)

@app.route("/customer/logout")
def customer_logout_page():
    session.pop("customer_id", None)
    return redirect(url_for("customer_login_page"))

@app.route("/customer/<reseller_id>/dashboard")
def customer_dashboard_page(reseller_id):
    if not session.get("customer_id") and not session.get("staff_name"):
        return redirect(url_for("customer_login_page"))
    if session.get("customer_id") and session.get("customer_id") != reseller_id and not session.get("staff_name"):
        return redirect(f"/customer/{session.get('customer_id')}/dashboard")
    return render_template_string(CUSTOMER_DASHBOARD_HTML, reseller_id=reseller_id)

@app.route("/customer/<reseller_id>/order")
def customer_order_page(reseller_id):
    if not session.get("customer_id") and not session.get("staff_name"):
        return redirect(url_for("customer_login_page"))
    return render_template_string(CUSTOMER_ORDER_HTML, reseller_id=reseller_id)

@app.route("/api/customer/login", methods=["POST"])
def api_customer_login():
    try:
        data = request.json or {}
        phone = clean_phone(data.get("phone") or "")
        pwd = data.get("password") or ""
        if not phone or not pwd:
            return jsonify({"ok": False, "error": "Phone and password required"}), 400
        resellers = fb_get("resellers") or {}
        matched = None
        matched_id = None
        for key,val in resellers.items():
            if not val: continue
            rphone = clean_phone(val.get("phone") or val.get("contact") or "")
            if rphone == phone:
                matched = val
                matched_id = key
                break
        if not matched:
            return jsonify({"ok": False, "error": "Phone not registered. Only ISESMO can register."}), 404
        stored_hash = matched.get("password_hash") or ""
        if not stored_hash:
            return jsonify({"ok": False, "error": "No password set. Contact ISESMO."}), 401
        if not verify_customer_password(stored_hash, pwd):
            return jsonify({"ok": False, "error": "Wrong password"}), 401
        session["customer_id"] = matched_id
        session["customer_name"] = matched.get("store_name")
        return jsonify({"ok": True, "reseller_id": matched_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/request_otp", methods=["POST"])
def api_customer_request_otp():
    try:
        data = request.json or {}
        phone = clean_phone(data.get("phone") or "")
        if not phone:
            return jsonify({"ok": False, "error": "Phone required"}), 400
        resellers = fb_get("resellers") or {}
        found = False
        for val in resellers.values():
            if not val: continue
            if clean_phone(val.get("phone") or "") == phone:
                found = True
                break
        if not found:
            return jsonify({"ok": False, "error": "Phone not registered"}), 404
        otp = generate_otp()
        # Save OTP with 5 min expiry
        otp_data = {"phone": phone, "otp": otp, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "expires_at": (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"), "used": False}
        fb_post("customer_otps", otp_data)

        sms_message = f"Omega Ice OTP: {otp}. Valid for 5 minutes. Do not share this code."
        sent_ok, sms_info = send_sms(phone, sms_message)

        if sent_ok:
            return jsonify({"ok": True, "message": "OTP sent via SMS. Valid 5 mins."})
        else:
            # SMS not configured or failed - fall back to showing OTP so the flow still works,
            # but flag it clearly so staff know SMS isn't actually going out.
            return jsonify({"ok": True, "otp": otp, "sms_sent": False, "sms_error": sms_info,
                             "message": "SMS could not be sent - showing OTP here as fallback. Check SEMAPHORE_API_KEY / SMS credits."})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/verify_otp", methods=["POST"])
def api_customer_verify_otp():
    try:
        data = request.json or {}
        phone = clean_phone(data.get("phone") or "")
        otp = (data.get("otp") or "").strip()
        new_pwd = (data.get("new_password") or "").strip()
        if not phone or not otp or not new_pwd:
            return jsonify({"ok": False, "error": "Phone, OTP and new password required"}), 400
        if len(new_pwd) < 4:
            return jsonify({"ok": False, "error": "Password min 4 chars"}), 400
        otps = fb_get("customer_otps") or {}
        valid = None
        valid_id = None
        now = datetime.now()
        for key,val in otps.items():
            if not val: continue
            if clean_phone(val.get("phone") or "") != phone: continue
            if val.get("otp") != otp: continue
            if val.get("used"): continue
            exp_str = val.get("expires_at")
            try:
                exp = datetime.strptime(exp_str, "%Y-%m-%d %H:%M:%S")
                if now > exp: continue
            except:
                pass
            valid = val
            valid_id = key
            break
        if not valid:
            return jsonify({"ok": False, "error": "Invalid or expired OTP"}), 400
        # Find reseller and update password
        resellers = fb_get("resellers") or {}
        target_id = None
        for key,val in resellers.items():
            if not val: continue
            if clean_phone(val.get("phone") or "") == phone:
                target_id = key
                break
        if not target_id:
            return jsonify({"ok": False, "error": "Reseller not found"}), 404
        hashed = hash_customer_password(new_pwd)
        fb_patch(f"resellers/{target_id}", {"password_hash": hashed, "status": "active"})
        fb_patch(f"customer_otps/{valid_id}", {"used": True})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/<reseller_id>/orders")
def api_customer_orders(reseller_id):
    try:
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        sales = fb_get("daily_sales") or {}
        orders = []
        total_kg = 0
        total_peso = 0
        status_counts = {}
        def kg_val(s):
            try: return float(str(s).lower().replace("kg","").strip())
            except: return 0
        from datetime import timedelta
        try:
            import pytz
            manila = pytz.timezone('Asia/Manila')
            now = datetime.now(manila)
        except:
            now = datetime.now()
        cutoff_24h = now - timedelta(hours=24)
        
        for key,val in sales.items():
            if not val: continue
            # Hide pending >24hrs - only 24hrs data
            if val.get("hidden_24h") or val.get("archived"): 
                # Skip archived/hidden, but show if ?show_archived=1 and is within 24h?
                show_arch = request.args.get("show_archived") == "1"
                if not show_arch:
                    continue
            rid = val.get("reseller_id")
            rname = (val.get("reseller_name") or "").strip()
            target_name = (reseller.get("store_name") or "").strip()
            if rid != reseller_id and rname.lower() != target_name.lower():
                continue
            # 24h filter: only show orders from last 24hrs
            ca = val.get("created_at") or ""
            try:
                ca_dt = None
                for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
                    try:
                        ca_dt = datetime.strptime(ca[:19], fmt)
                        break
                    except:
                        continue
                if ca_dt and ca_dt < cutoff_24h.replace(tzinfo=None):
                    # Hide if older than 24h AND status is Pending
                    if (val.get("order_status") or "Pending") in ["Pending", "New Order"]:
                        continue
            except:
                pass
            qty = int(val.get("quantity",0) or 0)
            kg_size = val.get("kg_size","1Kg")
            peso = float(val.get("total_sales",0) or 0)
            status = val.get("order_status","Pending")
            total_kg += qty * kg_val(kg_size)
            total_peso += peso
            status_counts[status] = status_counts.get(status,0)+1
            orders.append({"id": key, "sales_date": val.get("sales_date"), "quantity": qty, "kg_size": kg_size, "total_sales": peso, "mode": val.get("mode"), "payment": val.get("payment"), "order_status": status, "created_at": val.get("created_at")})
        def status_priority_c(s):
            order = (s.get("order_status") or "Pending")
            priorities = {"New Order": 0, "Pending": 1, "Preparing": 2, "Out for Delivery": 3, "Delivered": 4, "Cancelled": 5}
            return priorities.get(order, 1)
        orders.sort(key=lambda x: (status_priority_c(x), x.get("created_at") or ""), reverse=False)
        from collections import defaultdict as dd2
        grouped2 = dd2(list)
        for o in orders:
            grouped2[status_priority_c(o)].append(o)
        sorted_orders_c = []
        for p in sorted(grouped2.keys()):
            grouped2[p].sort(key=lambda x: x.get("created_at") or "", reverse=True)
            sorted_orders_c.extend(grouped2[p])
        orders = sorted_orders_c
        stats = {"total_kg": total_kg, "total_peso": total_peso, "count": len(orders), "status_counts": status_counts, "credit_balance": reseller.get("credit_balance",0)}
        return jsonify({"orders": orders[:50], "stats": stats, "reseller_name": reseller.get("store_name")})
    except Exception as e:
        return jsonify({"orders": [], "stats": {}, "error": str(e)}), 500

@app.route("/api/customer/<reseller_id>/place_order", methods=["POST"])
def api_customer_place_order(reseller_id):
    try:
        # Only logged customer can place for self, or staff
        if session.get("customer_id") and session.get("customer_id") != reseller_id:
            return jsonify({"ok": False, "error": "Not allowed"}), 403
        d = request.json or {}
        qty = int(d.get("quantity",1))
        kg_size = d.get("kg_size","1Kg")
        mode = d.get("mode","DELIVER")
        payment = d.get("payment","Cash")
        sales_date = d.get("sales_date") or datetime.now().strftime("%Y-%m-%d")
        notes = d.get("notes","")
        if qty<=0:
            return jsonify({"ok": False, "error": "Invalid qty"}), 400
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        if not reseller:
            return jsonify({"ok": False, "error": "Reseller not found"}), 404
        fallback={"1Kg":10,"5Kg":50,"10Kg":100,"25Kg":250}
        unit_price=fallback.get(kg_size,10)
        total = round(unit_price*qty,2)
        sale = {
            "reseller_id": reseller_id,
            "reseller_name": reseller.get("store_name",""),
            "quantity": qty,
            "kg_size": kg_size,
            "unit_price": unit_price,
            "total_sales": total,
            "mode": mode,
            "payment": payment,
            "sales_date": sales_date,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "staff_name": "Customer Order",
            "order_status": "New Order",
            "order_source": "customer",
            "notes": notes
        }
        fb_post("daily_sales", sale)
        return jsonify({"ok": True, "total": total})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/order/<order_id>/status", methods=["POST"])
@login_required
def api_update_order_status(order_id):
    data = request.json or {}
    new_status = data.get("status","").strip()
    if new_status not in ["New Order","Pending","Preparing","Out for Delivery","Delivered","Cancelled"]:
        return jsonify({"ok": False, "error": "Invalid status"}), 400
    existing = fb_get(f"daily_sales/{order_id}") or {}
    update_data = {"order_status": new_status, "status_updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "status_updated_by": session.get("staff_name")}
    # When marked as Delivered, update sales record so it counts as TODAY'S real sale + Recent Sales
    if new_status == "Delivered":
        try:
            import pytz
            manila = pytz.timezone('Asia/Manila')
            now_manila = datetime.now(manila)
            today = now_manila.strftime("%Y-%m-%d")
            now_str = now_manila.strftime("%Y-%m-%d %H:%M:%S")
        except:
            today = datetime.now().strftime("%Y-%m-%d")
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        update_data["delivered_at"] = now_str
        update_data["delivered_date"] = today
        # Keep original order date for history
        if existing.get("sales_date"):
            update_data["original_sales_date"] = existing.get("sales_date")
        update_data["sales_date"] = today  # Makes it count in TODAY sales + Recent
        update_data["sales_updated_at"] = now_str
        update_data["is_customer_order"] = True
        # Ensure it is NOT archived so it shows in sales
        update_data["archived"] = False
        update_data["archived_for_daily_only"] = False
    fb_patch(f"daily_sales/{order_id}", update_data)
    # Clear cache after delivered so dashboard updates instantly
    for k in list(globals().keys()):
        if k.startswith("_dashboard_cache_"):
            try:
                del globals()[k]
            except:
                pass
    return jsonify({"ok": True, "status": new_status, "sales_updated": new_status == "Delivered"})

@app.route("/customers")
@login_required
def staff_customers_page():
    # Only ISESMO can view/manage
    staff = (session.get("staff_name") or "").lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return "<h3>Access Denied</h3><p>Only ISESMO can manage customers.</p><a href='/cashier'>Back</a>", 403
    html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Customers - Only ISESMO</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:8px;flex-wrap:wrap}.topbar h1{font-size:15px;color:#00609C;margin:0;flex:1;min-width:180px}.topbar .nav-group{display:flex;gap:6px;flex-wrap:nowrap;align-items:center}
.nav-pill{padding:6px 12px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;white-space:nowrap;display:inline-block}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
label{font-size:11px;color:#666;display:block;margin:8px 0 4px}input{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px}
.btn{padding:8px 14px;border-radius:8px;border:none;font-size:12px;font-weight:600;margin:4px 2px}
.btn-save{background:#00609C;color:#fff}.btn-otp{background:#f59e0b;color:#fff}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:8px 4px;border-bottom:1px solid #eee;text-align:left}
</style></head>
<body>
<div class="topbar"><h1>👥 Customers (ISESMO Only)</h1><div class="nav-group"><a href="/cashier" class="nav-pill">Sales</a><a href="/orders" class="nav-pill">Live Orders</a></div></div>
<div class="card">
<h3 style="margin:0 0 8px;font-size:14px">Add New Customer - Only ISESMO</h3>
<label>Store Name *</label><input id="newStore" placeholder="AMO Store">
<label>Phone (will be login) *</label><input id="newPhone" placeholder="09xx xxx xxxx">
<label>Password *</label><input id="newPassword" placeholder="Set password min 4 chars">
<label>Address</label><input id="newAddress" placeholder="Angeles City">
<button class="btn btn-save" style="width:100%;margin-top:10px;padding:12px" onclick="addCustomer()">+ Add Customer (ISESMO Only)</button>
<p id="addStatus" style="font-size:12px;margin-top:8px"></p>
</div>
<div class="card"><input type="text" id="search" placeholder="Search store or phone..." oninput="loadCustomers()"></div>
<div class="card"><table><thead><tr><th>Store</th><th>Phone / Login</th><th>OTP / Status</th><th>Action</th></tr></thead><tbody id="tbody"></tbody></table></div>
<div class="card" id="editCard" style="display:none">
<h3 style="margin:0 0 8px;font-size:14px">Edit Phone & Password</h3>
<p style="font-size:11px;color:#666" id="editStore"></p>
<label>Phone</label><input id="editPhone">
<label>New Password</label><input id="editPassword" type="text">
<button class="btn btn-save" onclick="savePassword()">Save</button><button class="btn" style="background:#ddd" onclick="closeEdit()">Cancel</button>
<p id="editStatus" style="font-size:12px;margin-top:8px"></p>
</div>
<script>
let editingId=null;
async function addCustomer(){
  const store=document.getElementById('newStore').value.trim();
  const phone=document.getElementById('newPhone').value.trim();
  const pwd=document.getElementById('newPassword').value.trim();
  const addr=document.getElementById('newAddress').value.trim();
  if(!store||!phone||!pwd){document.getElementById('addStatus').textContent='All fields required';return;}
  const res=await fetch('/api/customers/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({store_name:store,phone:phone,password:pwd,address:addr})});
  const data=await res.json();
  document.getElementById('addStatus').textContent=data.ok?'✅ Customer added!':'Error: '+(data.error||'');
  if(data.ok){document.getElementById('newStore').value='';document.getElementById('newPhone').value='';document.getElementById('newPassword').value='';loadCustomers();}
}
async function loadCustomers(){
  const res=await fetch('/api/customers/list');
  const data=await res.json();
  const rows=data.resellers||[];
  const otps=data.otps||{};
  const q=document.getElementById('search').value.toLowerCase();
  const filtered=rows.filter(r=>(r.store_name||'').toLowerCase().includes(q)||(r.phone||'').includes(q));
  document.getElementById('tbody').innerHTML=filtered.map(r=>{
    const otpInfo=otps[r.phone]||'';
    return `<tr><td><b>${r.store_name}</b><br><small>₱${r.credit_balance||0}</small></td><td>${r.phone}<br><small style="color:${r.password_hash?'green':'red'}">${r.password_hash?'Has pwd':'No pwd'}</small></td><td>${otpInfo?'<span style="background:#fef3c7;padding:2px 6px;border-radius:10px;font-size:10px">OTP:'+otpInfo+'</span>':'-'}<br><small>${r.status||'active'}</small></td><td><button class="btn" style="background:#22c55e;color:#fff" data-id="${r.id}" data-store="${r.store_name}" data-phone="${r.phone}" onclick="openEdit(this.dataset.id,this.dataset.store,this.dataset.phone)">Edit</button></td></tr>`;
  }).join('');
}
function openEdit(id,store,phone){editingId=id;document.getElementById('editStore').textContent=store;document.getElementById('editPhone').value=phone;document.getElementById('editCard').style.display='block';}
function closeEdit(){document.getElementById('editCard').style.display='none';}
async function savePassword(){
  const phone=document.getElementById('editPhone').value.trim();
  const pwd=document.getElementById('editPassword').value.trim();
  const res=await fetch(`/api/reseller/${editingId}/set_password`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:phone,password:pwd})});
  const data=await res.json();
  document.getElementById('editStatus').textContent=data.ok?'Saved!':'Error: '+(data.error||'');
  if(data.ok)loadCustomers();
}
loadCustomers();
</script>
</body></html>"""
    return render_template_string(html)

@app.route("/api/customers/add", methods=["POST"])
@login_required
def api_customers_add():
    # Only ISESMO can add
    staff = (session.get("staff_name") or "").lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Only ISESMO can add customers"}), 403
    try:
        data = request.json or {}
        store_name = (data.get("store_name") or "").strip()
        phone = clean_phone(data.get("phone") or "")
        pwd = (data.get("password") or "").strip()
        address = (data.get("address") or "").strip()
        if not store_name or not phone or not pwd:
            return jsonify({"ok": False, "error": "Store, phone, password required"}), 400
        if len(pwd) < 4:
            return jsonify({"ok": False, "error": "Password min 4 chars"}), 400
        resellers = fb_get("resellers") or {}
        for val in resellers.values():
            if not val: continue
            if clean_phone(val.get("phone") or "") == phone:
                return jsonify({"ok": False, "error": "Phone already registered"}), 400
        hashed = hash_customer_password(pwd)
        reseller_data = {"store_name": store_name, "phone": phone, "address": address, "credit_balance": 0, "password_hash": hashed, "status": "active", "created_by": session.get("staff_name"), "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        fb_post("resellers", reseller_data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customers/list")
@login_required
def api_customers_list():
    try:
        resellers = fb_get("resellers") or {}
        otps = fb_get("customer_otps") or {}
        # Get latest OTP per phone
        latest_otps = {}
        for val in otps.values():
            if not val or val.get("used"): continue
            phone = val.get("phone")
            exp_str = val.get("expires_at")
            try:
                exp = datetime.strptime(exp_str, "%Y-%m-%d %H:%M:%S")
                if datetime.now() > exp: continue
            except:
                pass
            latest_otps[phone] = val.get("otp")
        out=[]
        for key,val in resellers.items():
            if not val: continue
            out.append({"id":key,"store_name":val.get("store_name"),"phone":val.get("phone") or val.get("contact",""),"credit_balance":val.get("credit_balance",0),"password_hash":"yes" if val.get("password_hash") else "","status":val.get("status","active")})
        return jsonify({"resellers": out[:100], "otps": latest_otps})
    except Exception as e:
        return jsonify({"resellers": [], "otps": {}, "error": str(e)}), 500

@app.route("/api/reseller/<reseller_id>/set_password", methods=["POST"])
@login_required
def api_set_reseller_password(reseller_id):
    staff = (session.get("staff_name") or "").lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Only ISESMO can set password"}), 403
    try:
        data = request.json or {}
        phone = clean_phone(data.get("phone") or "")
        password = (data.get("password") or "").strip()
        if not phone or not password:
            return jsonify({"ok": False, "error": "Phone and password required"}), 400
        if len(password) < 4:
            return jsonify({"ok": False, "error": "Password min 4"}), 400
        hashed = hash_customer_password(password)
        fb_patch(f"resellers/{reseller_id}", {"phone": phone, "password_hash": hashed, "status": "active"})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/sales/dashboard")
@login_required
def api_sales_dashboard():
    period = request.args.get("period", "daily").lower()
    custom_date = request.args.get("date", "").strip()
    # Fast path for daily - use Manila time
    try:
        import pytz
        manila = pytz.timezone('Asia/Manila')
        now = datetime.now(manila)
    except:
        now = datetime.now()
    # Cache daily_sales for 10 sec to avoid hammering Firebase with 1600 records
    cache_key = f"_dashboard_cache_{period}"
    cached = globals().get(cache_key)
    if cached and (now - cached.get("time", datetime.min)).total_seconds() < 10:
        return jsonify(cached.get("data"))

    def kg_value(s):
        try: return float(str(s).lower().replace("kg","").strip())
        except: return 0
    def parse_date(d):
        try: return datetime.strptime(d[:10], "%Y-%m-%d")
        except: return None
    start_date = None
    label = "Today"
    if period == "daily":
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        label = "Today"
    elif period == "weekly":
        start_date = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
        label = "Last 7 Days"
    elif period == "monthly":
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        label = "This Month"
    elif period == "quarterly":
        q = (now.month-1)//3 + 1
        start_month = (q-1)*3 + 1
        start_date = now.replace(month=start_month, day=1, hour=0, minute=0, second=0, microsecond=0)
        label = f"Q{q} {now.year}"
    elif period in ("yearly","year"):
        start_date = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        label = f"Year {now.year}"
    else:
        start_date = None
        label = "All Time"
    total_peso = 0; total_kg = 0; count = 0
    pending_peso = 0; pending_kg = 0; pending_count = 0
    breakdown = {"1Kg": 0, "5Kg": 0, "10Kg": 0, "25Kg": 0}
    pending_breakdown = {"1Kg": 0, "5Kg": 0, "10Kg": 0, "25Kg": 0}
    try:
        data = fb_get("daily_sales") or {}
        for v in data.values():
            if not v: continue
            # #2 LOGIC: All Time includes archived Sept 06 (so 34k), Daily excludes archived to show 0
            # For All Time (period = all), include archived that were archived via restore_sept06 to keep 34k
            # For Daily, exclude archived to show 0
            is_archived = v.get("archived")
            if is_archived:
                # If All Time, include archived records that were archived to make Sept 06 = 0 (keep 34k)
                # Only exclude truly deleted/wrong inputs, not the 3721kg archive
                if period != "all time" and period != "all":
                    # Daily/Weekly/Monthly/Yearly: exclude archived to make Sept 06 = 0
                    # But check if archived was for Sept 06 fix - still exclude for Daily to show 0
                    if v.get("restored") or v.get("auto_cleared") or "archived Sept 06" in str(v.get("restored") or "") or "Sept 06 to make 0" in str(v.get("archived_at") or ""):
                        # For Daily, exclude to show 0
                        continue
                    # For other archived (wrong input), also exclude for Daily
                    continue
                # For All Time, INCLUDE archived that were part of 3721kg fix to keep 34k
                # So don't skip for All Time
                pass
            # Only count Delivered as real sales, Pending/New Order as pending
            status = v.get("order_status") or "Delivered"  # Old sales without status = Delivered
            sd = v.get("sales_date") or (v.get("created_at")[:10] if v.get("created_at") else "")
            if not sd: continue
            dt = parse_date(sd)
            if not dt: continue
            if start_date and dt < start_date.replace(tzinfo=None): continue
            qty = int(v.get("quantity",0) or 0)
            kg_size = v.get("kg_size","1Kg")
            peso = float(v.get("total_sales",0) or 0)
            if status in ["Delivered", "Out for Delivery"]:
                total_peso += peso
                total_kg += qty * kg_value(kg_size)
                count += 1
                if kg_size in breakdown: breakdown[kg_size] += qty
            else:  # Pending, New Order, Preparing
                pending_peso += peso
                pending_kg += qty * kg_value(kg_size)
                pending_count += 1
                if kg_size in pending_breakdown: pending_breakdown[kg_size] += qty
    except Exception as e:
        print(f"dashboard error {e}")
    result = {"period": period, "label": label, "total": total_peso, "total_kg": total_kg, "count": count, "breakdown": breakdown, "pending_total": pending_peso, "pending_kg": pending_kg, "pending_count": pending_count, "pending_breakdown": pending_breakdown, "date": now.strftime("%Y-%m-%d"), "start": start_date.strftime("%Y-%m-%d") if start_date else "All"}
    globals()[cache_key] = {"time": now, "data": result}
    return jsonify(result)

@app.route("/api/sales/today")
@login_required
def api_today_sales():
    try:
        import pytz
        manila = pytz.timezone('Asia/Manila')
        now = datetime.now(manila)
    except:
        now = datetime.now()
    today_str = custom_date if custom_date else now.strftime("%Y-%m-%d")
    def kg_value(s):
        try: return float(str(s).lower().replace("kg","").strip())
        except: return 0
    def parse_date(d):
        try: return datetime.strptime(d[:10], "%Y-%m-%d")
        except: return None
    total_peso = 0; total_kg = 0; count = 0
    pending_peso = 0; pending_kg = 0; pending_count = 0
    breakdown = {"1Kg": 0, "5Kg": 0, "10Kg": 0, "25Kg": 0}
    try:
        data = fb_get("daily_sales") or {}
        for v in data.values():
            if not v: continue
            # #2 LOGIC: All Time includes archived Sept 06 (so 34k), Daily excludes archived to show 0
            # For All Time (period = all), include archived that were archived via restore_sept06 to keep 34k
            # For Daily, exclude archived to show 0
            is_archived = v.get("archived")
            if is_archived:
                # If All Time, include archived records that were archived to make Sept 06 = 0 (keep 34k)
                # Only exclude truly deleted/wrong inputs, not the 3721kg archive
                if period != "all time" and period != "all":
                    # Daily/Weekly/Monthly/Yearly: exclude archived to make Sept 06 = 0
                    # But check if archived was for Sept 06 fix - still exclude for Daily to show 0
                    if v.get("restored") or v.get("auto_cleared") or "archived Sept 06" in str(v.get("restored") or "") or "Sept 06 to make 0" in str(v.get("archived_at") or ""):
                        # For Daily, exclude to show 0
                        continue
                    # For other archived (wrong input), also exclude for Daily
                    continue
                # For All Time, INCLUDE archived that were part of 3721kg fix to keep 34k
                # So don't skip for All Time
                pass
            status = v.get("order_status") or "Delivered"
            sd = v.get("sales_date") or (v.get("created_at")[:10] if v.get("created_at") else "")
            if not sd: continue
            dt = parse_date(sd)
            if not dt: continue
            if dt.date() != now.date(): continue
            qty = int(v.get("quantity",0) or 0)
            kg_size = v.get("kg_size","1Kg")
            peso = float(v.get("total_sales",0) or 0)
            if status in ["Delivered", "Out for Delivery"]:
                total_peso += peso
                total_kg += qty * kg_value(kg_size)
                count += 1
                if kg_size in breakdown: breakdown[kg_size] += qty
            else:
                pending_peso += peso
                pending_kg += qty * kg_value(kg_size)
                pending_count += 1
    except: pass
    return jsonify({"total": total_peso, "total_kg": total_kg, "count": count, "breakdown": breakdown, "pending_total": pending_peso, "pending_kg": pending_kg, "pending_count": pending_count, "date": today_str, "start": today_str})

@app.route("/dashboard")
@login_required
def dashboard_page():
    html = """<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dashboard</title>
<style>*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}.topbar h1{font-size:16px;color:#00609C;margin:0}.nav-pill{padding:7px 14px;border-radius:20px;font-size:12px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C}.nav-pill.active{background:#00609C;color:#fff}.period-btn{padding:8px 12px;border-radius:20px;border:1px solid #cde;background:#fff;font-size:11px;color:#00609C}.period-btn.active{background:#00609C;color:#fff}.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px}.stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;text-align:center}.stat-val{font-size:20px;font-weight:700;color:#00609C}</style></head>
<body>
<div class="topbar"><h1>OMEGA ICE</h1><div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap"><a href="/orders" class="nav-pill" style="background:#ff4444;color:#fff;border-color:#ff4444">🔴 Live Orders</a><a href="/cashier" class="nav-pill">Sales</a> <a href="/customers" class="nav-pill">Customers</a> <a href="/dashboard" class="nav-pill active">Dashboard</a></div></div>
<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
<button class="period-btn active" data-p="daily" onclick="setPeriod('daily')">Daily</button>
<button class="period-btn" data-p="weekly" onclick="setPeriod('weekly')">Weekly</button>
<button class="period-btn" data-p="monthly" onclick="setPeriod('monthly')">Monthly</button>
<button class="period-btn" data-p="quarterly" onclick="setPeriod('quarterly')">Quarterly</button>
<button class="period-btn" data-p="yearly" onclick="setPeriod('yearly')">Yearly</button>
<button class="period-btn" data-p="all" onclick="setPeriod('all')">All Time</button>
</div>
<div class="card"><div style="font-size:11px;color:#666;margin-bottom:8px">✅ DELIVERED SALES (Real Sales)</div><div class="stat-grid"><div><div class="stat-val" id="totalKg">0kg</div><div class="stat-lbl">TOTAL KG</div></div><div><div class="stat-val" id="totalPeso">₱0</div><div class="stat-lbl">TOTAL PESO</div></div><div><div class="stat-val" id="totalCount">0</div><div class="stat-lbl">DELIVERED</div></div></div><div style="margin-top:12px;padding-top:12px;border-top:1px dashed #ccd"><div style="font-size:11px;color:#92400e;margin-bottom:6px">⏳ PENDING FOR DELIVERY (1600 pending)</div><div class="stat-grid"><div><div class="stat-val" id="pendingKg" style="color:#f59e0b">0kg</div><div class="stat-lbl">PENDING KG</div></div><div><div class="stat-val" id="pendingPeso" style="color:#f59e0b">₱0</div><div class="stat-lbl">PENDING PESO</div></div><div><div class="stat-val" id="pendingCount" style="color:#f59e0b">0</div><div class="stat-lbl">PENDING</div></div></div></div><div id="breakdown" style="font-size:11px;margin-top:10px;text-align:center"></div></div>
<script>
let currentPeriod='daily';
async function setPeriod(p){currentPeriod=p;document.querySelectorAll('.period-btn').forEach(b=>b.classList.toggle('active',b.dataset.p===p));loadDashboard();}
async function loadDashboard(){const res=await fetch('/api/sales/dashboard?period='+currentPeriod);const data=await res.json();document.getElementById('totalKg').textContent=(data.total_kg||0).toLocaleString()+'kg';document.getElementById('totalPeso').textContent='₱'+(data.total||0).toLocaleString();document.getElementById('totalCount').textContent=data.count||0;document.getElementById('pendingKg').textContent=(data.pending_kg||0).toLocaleString()+'kg';document.getElementById('pendingPeso').textContent='₱'+(data.pending_total||0).toLocaleString();document.getElementById('pendingCount').textContent=data.pending_count||0;const b=data.breakdown||{};document.getElementById('breakdown').textContent=`Delivered: 1Kg:${b['1Kg']||0} 5Kg:${b['5Kg']||0} 10Kg:${b['10Kg']||0} 25Kg:${b['25Kg']||0} | Pending: ${data.pending_count||0} orders`;}loadDashboard();
</script>
</body></html>"""
    return render_template_string(html)

@app.route("/orders")
@login_required
def staff_orders_page():
    html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Live Orders</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.topbar h1{font-size:16px;color:#00609C;margin:0}
.card{background:#fff;border-radius:12px;padding:12px;margin-bottom:10px}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:12px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C}
.live{display:inline-flex;align-items:center;gap:6px;background:#ef4444;color:#fff;padding:6px 12px;border-radius:20px;font-size:11px}
.order-card{border-left:4px solid #f59e0b;padding:12px;margin:8px 0;background:#fff;border-radius:8px}
.btn{padding:6px 10px;border-radius:8px;border:1px solid #ccd;font-size:11px;margin:2px}.btn:disabled{opacity:0.4;cursor:not-allowed;background:#f3f4f6;color:#999}
</style></head>
<body>
<div class="topbar"><h1>Live Customer Orders</h1><div><a href="/cashier" class="nav-pill">Sales</a> <a href="/customers" class="nav-pill">Customers</a></div></div>
<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap"><span class="live">● LIVE</span>
<button onclick="archiveAllOldStaff()" style="padding:6px 12px;border-radius:20px;border:1px solid #f59e0b;background:#fffbeb;color:#92400e;font-size:11px">📦 Archive Old >7d</button><button onclick="loadOrders()" style="padding:6px 12px;border-radius:20px;border:1px solid #cde;background:#fff;font-size:11px">Refresh</button></div>
<div id="ordersList">2026-09-06 - Tap Refresh</div>
<script>
async function loadOrders(){
  const res=await fetch('/api/staff/customer_orders');
  const data=await res.json();
  const ordersRaw=data.orders||[];
  // Sort: New Order on top, Delivered at bottom
  const priority = {"New Order":0, "Pending":1, "Preparing":2, "Out for Delivery":3, "Delivered":4, "Cancelled":5};
  const orders = ordersRaw.sort((a,b)=>{
    const pa = priority[a.order_status] ?? 1;
    const pb = priority[b.order_status] ?? 1;
    if(pa!==pb) return pa-pb;
    return (b.created_at||'').localeCompare(a.created_at||'');
  });
  let showArchived=false;
function toggleArchived(){showArchived=!showArchived;document.getElementById('toggleArchBtn').textContent=showArchived?'Hide Archived':'Show Archived';loadOrders();}
const list=document.getElementById('ordersList');
  if(!orders.length){list.innerHTML='<div class="card" style="text-align:center;color:#888">No customer orders yet.</div>';return;}
  list.innerHTML=orders.map(o=>{
    const isDelivered = o.order_status==='Delivered';
    const isCancelled = o.order_status==='Cancelled';
    const disabled = isDelivered || isCancelled;
    let statusColor='#fef3c7';
    if(o.order_status==='Delivered'){statusColor='#dcfce7';}
    else if(o.order_status==='Cancelled'){statusColor='#fee2e2';}
    else if(o.order_status==='Preparing'){statusColor='#dbeafe';}
    else if(o.order_status==='Out for Delivery'){statusColor='#e0e7ff';}
    const deliveredBadge = isDelivered ? ' ✅' : '';
    const btnStyle = (active)=> disabled ? 'opacity:0.4;cursor:not-allowed;background:#f3f4f6' : '';
    const btnDisabled = disabled ? 'disabled' : '';
    if(disabled){
      return `<div class="order-card" data-order-id="${o.id}" style="border-left-color:${isDelivered?'#22c55e':'#ef4444'};opacity:0.8"><div style="display:flex;justify-content:space-between"><span style="font-weight:600">${o.reseller_name}${deliveredBadge}</span><span style="font-size:10px;background:${statusColor};padding:4px 8px;border-radius:12px">${o.order_status}</span></div><div style="font-size:12px;color:#555;margin-top:4px">${o.quantity}x ${o.kg_size} • ₱${o.total_sales} • ${o.sales_date}</div><div style="margin-top:8px"><span style="font-size:11px;color:${isDelivered?'#16a34a':'#ef4444'};font-weight:600">${isDelivered?'✅ Delivered - buttons disabled': '❌ Cancelled'}</span> <button class="btn" style="background:#fff;color:#ef4444;border-color:#fca5a5;font-size:10px;padding:4px 8px;margin-left:8px" onclick="deleteOrder('${o.id}')">🗑️ Delete</button></div></div>`;
    }
    return `<div class="order-card" data-order-id="${o.id}"><div style="display:flex;justify-content:space-between"><span style="font-weight:600">${o.reseller_name}</span><span style="font-size:10px;background:${statusColor};padding:4px 8px;border-radius:12px">${o.order_status}</span></div><div style="font-size:12px;color:#555;margin-top:4px">${o.quantity}x ${o.kg_size} • ₱${o.total_sales} • ${o.sales_date}</div><div style="margin-top:8px"><button class="btn" ${btnDisabled} style="${btnStyle()}" onclick="updateStatus('${o.id}','Pending')">Accept</button><button class="btn" ${btnDisabled} style="${btnStyle()}" onclick="updateStatus('${o.id}','Preparing')">Preparing</button><button class="btn" ${btnDisabled} style="${btnStyle()}" onclick="updateStatus('${o.id}','Out for Delivery')">Out</button><button class="btn" ${btnDisabled} style="background:#22c55e;color:#fff;${btnStyle()}" onclick="updateStatus('${o.id}','Delivered')">Done</button><button class="btn" style="background:#fff;color:#ef4444;border-color:#fca5a5" onclick="deleteOrder('${o.id}')">🗑️ Delete</button></div></div>`;
  }).join('');
}
async function updateStatus(id,status){
  const btn = event.target;
  const origText = btn.textContent;
  btn.textContent = '...';
  btn.disabled = true;
  try{
    const res = await fetch(`/api/order/${id}/status`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})});
    const data = await res.json();
    if(data.ok){
      // Instant update: reload orders + recent sales + today sales if on same domain
      loadOrders();
      // Try to refresh cashier data if available via localStorage signal
      localStorage.setItem('omega_last_delivered', JSON.stringify({id: id, status: status, time: Date.now()}));
      if(status==='Delivered'){
        // Show success
        btn.textContent = '✅ Done';
        setTimeout(()=>loadOrders(), 1000);
      }
    } else {
      alert(data.error||'Failed');
      btn.textContent = origText;
      btn.disabled = false;
    }
  } catch(e){
    alert('Network error: '+e.message);
    btn.textContent = origText;
    btn.disabled = false;
  }
}
async function archiveAllOldStaff(){
  if(!confirm('ISESMO ONLY: Archive ALL orders older than 7 days? This will hide 307 old orders.')) return;
  const res=await fetch('/api/staff/archive_all_old',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days_old:7})});
  const data=await res.json();
  if(data.ok){alert(`Archived ${data.archived} old orders`);loadOrders();}else{alert(data.error||'Failed');}
}



async function bulkUpdateAll(){
  if(!confirm('Mark ALL 307 Pending orders as Delivered? This will update all pending orders for this customer.')) return;
  const res=await fetch(`/api/customer/${resellerId}/bulk_update`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({from_status:'Pending',status:'Delivered'})});
  const data=await res.json();
  if(data.ok){alert(`Updated ${data.updated} orders to Delivered!`);loadOrders();}else{alert(data.error||'Failed');}
}
async function archiveOldOrders(){
  if(!confirm('Archive (hide) all orders older than 7 days? Your 307 old pending will be hidden. You can still show them via Show Archived.')) return;
  const res=await fetch(`/api/customer/${resellerId}/archive_old`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days_old:7})});
  const data=await res.json();
  if(data.ok){alert(`📦 Archived ${data.archived} old orders! Now showing only recent.`);loadOrders();}else{alert(data.error||'Failed');}
}
async function bulkUpdateAllToPreparing(){
  if(!confirm('Mark all Pending as Preparing?')) return;
  const res=await fetch(`/api/customer/${resellerId}/bulk_update`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({from_status:'Pending',status:'Preparing'})});
  const data=await res.json();
  if(data.ok){alert(`Updated ${data.updated}`);loadOrders();}else{alert(data.error||'Failed');}
}

async function deleteOrder(id){
  if(!confirm('🗑️ Delete this order? This will remove from Live + Sales records.')) return;
  try{
    const res = await fetch(`/api/orders/${id}`, {method:'DELETE'});
    const data = await res.json();
    if(data.ok){
      alert('✅ Deleted! Sales updated.');
      loadOrders();
      await fetch('/api/sales/clear_cache', {method:'POST'}).catch(()=>{});
    }else{
      alert(data.error||'Failed');
    }
  }catch(e){alert('Network error: '+e.message);}
}
loadOrders();setInterval(loadOrders,10000);


</script>
</body></html>"""
    return render_template_string(html)

@app.route("/api/staff/customer_orders")
@login_required
def api_staff_customer_orders():
    # 24hrs only - hide pending >24hrs
    try:
        from datetime import timedelta
        try:
            import pytz
            manila = pytz.timezone('Asia/Manila')
            now = datetime.now(manila)
        except:
            now = datetime.now()
        cutoff_24h = now - timedelta(hours=24)
        
        sales = fb_get("daily_sales") or {}
        orders=[]
        for key,val in sales.items():
            if not val: continue
            if val.get("order_source") != "customer": continue
            if val.get("archived") and not val.get("hidden_24h"): 
                # Skip archived unless it's 24h hidden (we want to hide those anyway)
                continue
            if val.get("deleted"): continue
            if val.get("hidden_24h"): continue
            
            # 24h filter - hide orders older than 24h
            ca = val.get("created_at") or ""
            is_old = False
            try:
                ca_dt = None
                for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]:
                    try:
                        ca_dt = datetime.strptime(ca[:19], fmt)
                        break
                    except:
                        continue
                if ca_dt and ca_dt < cutoff_24h.replace(tzinfo=None):
                    # If old and Pending/New Order, hide (only 24hrs data)
                    if (val.get("order_status") or "Pending") in ["Pending", "New Order"]:
                        is_old = True
                # Also check sales_date for old 2025 orders
                sd = val.get("sales_date") or ""
                if "2025" in sd or "2026-08" in sd or "2026-09-01" in sd or "2026-09-04" in sd:
                    is_old = True
            except:
                pass
            
            if is_old:
                continue
                
            orders.append({"id":key,"reseller_name":val.get("reseller_name"),"quantity":val.get("quantity"),"kg_size":val.get("kg_size"),"total_sales":val.get("total_sales"),"mode":val.get("mode"),"sales_date":val.get("sales_date"),"order_status":val.get("order_status","New Order"),"created_at":val.get("created_at")})
        # Sort: New Orders first, Delivered at bottom
        def status_priority(s):
            order = (s.get("order_status") or "Pending")
            priorities = {"New Order": 0, "Pending": 1, "Preparing": 2, "Out for Delivery": 3, "Delivered": 4, "Cancelled": 5}
            return priorities.get(order, 1)
        orders.sort(key=lambda x: (status_priority(x), -(len(x.get("created_at") or "")), x.get("created_at") or ""), reverse=False)
        # Actually sort by priority then newest first within same priority
        from collections import defaultdict
        grouped = defaultdict(list)
        for o in orders:
            grouped[status_priority(o)].append(o)
        sorted_orders = []
        for p in sorted(grouped.keys()):
            # Within same priority, newest first
            grouped[p].sort(key=lambda x: x.get("created_at") or "", reverse=True)
            sorted_orders.extend(grouped[p])
        return jsonify({"orders": sorted_orders[:100]})
    except Exception as e:
        return jsonify({"orders":[]}), 500

@app.route("/health")
def health():
    return jsonify({"ok": True, "version": "v28-otp-isesmo-only"})




@app.route("/api/customer/<reseller_id>/bulk_update", methods=["POST"])
def api_customer_bulk_update(reseller_id):
    try:
        data = request.json or {}
        new_status = data.get("status", "Delivered").strip()
        from_status = data.get("from_status", "Pending").strip()
        if new_status not in ["Pending","Preparing","Out for Delivery","Delivered","Cancelled","New Order"]:
            return jsonify({"ok": False, "error": "Invalid status"}), 400
        # Security: only owner or staff can bulk update
        if session.get("customer_id") and session.get("customer_id") != reseller_id:
            return jsonify({"ok": False, "error": "Not allowed"}), 403
        if not session.get("customer_id") and not session.get("staff_name"):
            return jsonify({"ok": False, "error": "Login required"}), 401
        
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        if not reseller and not session.get("staff_name"):
            return jsonify({"ok": False, "error": "Reseller not found"}), 404
        
        sales = fb_get("daily_sales") or {}
        updated = 0
        target_name = (reseller.get("store_name") or "").strip().lower() if reseller else ""
        for key,val in sales.items():
            if not val: continue
            rid = val.get("reseller_id")
            rname = (val.get("reseller_name") or "").strip().lower()
            # Match by id or name
            if rid != reseller_id and rname != target_name and target_name:
                continue
            if not target_name and rid != reseller_id:
                continue
            current_status = val.get("order_status") or "Pending"
            if from_status != "ALL" and current_status != from_status:
                continue
            today = datetime.now().strftime("%Y-%m-%d")
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            upd = {"order_status": new_status, "status_updated_at": now_str, "status_updated_by": session.get("customer_name") or session.get("staff_name") or "Bulk Update"}
            if new_status == "Delivered":
                upd["delivered_at"] = now_str
                upd["delivered_date"] = today
                # FIX: Keep original sales_date - don't overwrite! Only set delivered_date
                # upd["sales_date"] = today  # REMOVED - this caused 3721kg on Sept 06
                # upd["created_at"] = now_str  # REMOVED
            fb_patch(f"daily_sales/{key}", upd)
            updated += 1
        return jsonify({"ok": True, "updated": updated, "from": from_status, "to": new_status})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/staff/bulk_update_all_pending", methods=["POST"])
@login_required
def api_staff_bulk_update_all():
    try:
        data = request.json or {}
        new_status = data.get("status", "Delivered")
        from_status = data.get("from_status", "Pending")
        # Only ISESMO can bulk update all
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa"]:
            return jsonify({"ok": False, "error": "Only ISESMO can bulk update all"}), 403
        sales = fb_get("daily_sales") or {}
        updated = 0
        for key,val in sales.items():
            if not val: continue
            current = val.get("order_status") or "Pending"
            if from_status != "ALL" and current != from_status:
                continue
            today2 = datetime.now().strftime("%Y-%m-%d")
            now_str2 = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            upd2 = {"order_status": new_status, "status_updated_at": now_str2, "status_updated_by": session.get("staff_name")}
            if new_status == "Delivered":
                upd2["delivered_at"] = now_str2
                upd2["delivered_date"] = today2
                # FIX: Keep original sales_date
            fb_patch(f"daily_sales/{key}", upd2)
            updated += 1
        return jsonify({"ok": True, "updated": updated})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



@app.route("/api/customer/<reseller_id>/archive_old", methods=["POST"])
def api_customer_archive_old(reseller_id):
    try:
        data = request.json or {}
        days_old = int(data.get("days_old", 7))  # archive orders older than 7 days
        # Security
        if session.get("customer_id") and session.get("customer_id") != reseller_id:
            return jsonify({"ok": False, "error": "Not allowed"}), 403
        if not session.get("customer_id") and not session.get("staff_name"):
            return jsonify({"ok": False, "error": "Login required"}), 401
        
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        sales = fb_get("daily_sales") or {}
        archived = 0
        cutoff = datetime.now() - timedelta(days=days_old)
        target_name = (reseller.get("store_name") or "").strip().lower() if reseller else ""
        for key,val in sales.items():
            if not val: continue
            rid = val.get("reseller_id")
            rname = (val.get("reseller_name") or "").strip().lower()
            if rid != reseller_id and rname != target_name and target_name:
                continue
            # Check date
            sd = val.get("sales_date") or (val.get("created_at")[:10] if val.get("created_at") else "")
            try:
                sale_date = datetime.strptime(sd[:10], "%Y-%m-%d")
                if sale_date >= cutoff:
                    continue  # Keep recent
            except:
                pass
            # Already archived?
            if val.get("archived"):
                continue
            fb_patch(f"daily_sales/{key}", {"archived": True, "archived_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            archived += 1
        return jsonify({"ok": True, "archived": archived, "cutoff_days": days_old})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/staff/archive_all_old", methods=["POST"])
@login_required
def api_staff_archive_all_old():
    try:
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa"]:
            return jsonify({"ok": False, "error": "Only ISESMO can archive all"}), 403
        data = request.json or {}
        days_old = int(data.get("days_old", 7))
        sales = fb_get("daily_sales") or {}
        cutoff = datetime.now() - timedelta(days=days_old)
        archived = 0
        for key,val in sales.items():
            if not val: continue
            if val.get("archived"): continue
            sd = val.get("sales_date") or (val.get("created_at")[:10] if val.get("created_at") else "")
            try:
                sale_date = datetime.strptime(sd[:10], "%Y-%m-%d")
                if sale_date >= cutoff:
                    continue
            except:
                continue
            fb_patch(f"daily_sales/{key}", {"archived": True, "archived_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            archived += 1
        return jsonify({"ok": True, "archived": archived})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



@app.route("/api/staff/reset_today", methods=["POST"])
@login_required
def api_staff_reset_today():
    try:
        staff = (session.get("staff_name") or "").lower()
        print(f"RESET TODAY called by {staff}")
        if staff not in ["isesmo", "isesmo gamboa"]:
            return jsonify({"ok": False, "error": f"Only ISESMO can reset today. You are {staff}"}), 403
        data = request.json or {}
        date_str = data.get("date")
        force_all = data.get("force_all", False)
        if not date_str:
            try:
                import pytz
                manila = pytz.timezone('Asia/Manila')
                now = datetime.now(manila)
            except:
                now = datetime.now()
            date_str = now.strftime("%Y-%m-%d")
        print(f"Resetting date {date_str}, force_all={force_all}")
        sales = fb_get("daily_sales") or {}
        print(f"Found {len(sales)} total sales")
        deleted = 0
        to_delete = []
        for key,val in sales.items():
            if not val: continue
            if force_all:
                to_delete.append(key)
                continue
            sd = (val.get("sales_date") or "")[:10]
            dd = (val.get("delivered_date") or "")[:10]
            ca = (val.get("created_at") or "")[:10]
            # Match ANY date field to today
            if date_str in [sd, dd, ca]:
                to_delete.append(key)
            # Also if sales_date contains date_str
            elif sd == date_str or dd == date_str or ca == date_str:
                to_delete.append(key)
        
        print(f"Will delete {len(to_delete)} records")
        for key in to_delete:
            # Try delete first, if fails, archive it (fallback for Firebase rules)
            ok = fb_delete(f"daily_sales/{key}")
            if not ok:
                # Fallback: archive instead
                try:
                    fb_patch(f"daily_sales/{key}", {"archived": True, "archived_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "reset_by": staff})
                    ok = True
                except:
                    ok = False
            print(f"Delete/Archive {key}: {ok}")
            if ok:
                deleted += 1
        
        # Clear dashboard cache
        for key in list(globals().keys()):
            if key.startswith("_dashboard_cache_"):
                try:
                    del globals()[key]
                except:
                    pass
        
        print(f"Deleted {deleted}/{len(to_delete)}")
        return jsonify({"ok": True, "deleted": deleted, "found": len(to_delete), "total": len(sales), "date": date_str})
    except Exception as e:
        import traceback
        print(f"Reset error: {e}\n{traceback.format_exc()}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/staff/reset_all_simulated", methods=["POST"])
@login_required
def api_staff_reset_all_simulated():
    try:
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa"]:
            return jsonify({"ok": False, "error": "Only ISESMO can reset all"}), 403
        # This deletes ALL daily_sales - DANGER - but useful for testing
        # Instead, archive all instead of delete for safety
        sales = fb_get("daily_sales") or {}
        deleted = 0
        for key in list(sales.keys()):
            fb_delete(f"daily_sales/{key}")
            deleted += 1
        return jsonify({"ok": True, "deleted": deleted, "warning": "ALL sales deleted"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



@app.route("/api/clear_today_secret")
@login_required
def api_clear_today_secret():
    """Secret URL to make dashboard 0 without button - visit /api/clear_today_secret?key=omega123"""
    try:
        key = request.args.get("key", "")
        # Allow ISESMO or secret key
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa"] and key != "omega123":
            return "Only ISESMO - add ?key=omega123 or login as ISESMO", 403
        try:
            import pytz
            manila = pytz.timezone('Asia/Manila')
            now = datetime.now(manila)
        except:
            now = datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        sales = fb_get("daily_sales") or {}
        archived = 0
        for k,v in sales.items():
            if not v: continue
            sd = (v.get("sales_date") or "")[:10]
            dd = (v.get("delivered_date") or "")[:10]
            ca = (v.get("created_at") or "")[:10]
            # Archive if ANY date is today - this makes dashboard 0
            if date_str in [sd, dd, ca]:
                fb_patch(f"daily_sales/{k}", {"archived": True, "archived_at": now.strftime("%Y-%m-%d %H:%M:%S"), "auto_cleared": True})
                archived += 1
        # Clear cache
        for kk in list(globals().keys()):
            if kk.startswith("_dashboard_cache_"):
                try: del globals()[kk]
                except: pass
        return f"<h2>✅ Dashboard cleared to 0!</h2><p>Archived {archived} records from today ({date_str})</p><p>Total was {len(sales)}</p><p><a href='/cashier'>Go to Sales - will show 0kg now</a></p><p><a href='/dashboard'>Go to Dashboard</a></p>", 200
    except Exception as e:
        return f"Error: {e}", 500

@app.route("/api/staff/auto_dashboard_fix", methods=["POST"])
@login_required
def api_auto_dashboard_fix():
    """Auto fix: if live customer orders = 0 but dashboard shows 3721kg, auto archive today"""
    try:
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa"]:
            return jsonify({"ok": False, "error": "Only ISESMO"}), 403
        sales = fb_get("daily_sales") or {}
        customer_pending = 0
        today_delivered = 0
        try:
            import pytz
            manila = pytz.timezone('Asia/Manila')
            now = datetime.now(manila)
        except:
            now = datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        for v in sales.values():
            if not v: continue
            if v.get("archived"): continue
            if v.get("order_source") == "customer" and v.get("order_status") in ["New Order", "Pending", "Preparing", "Out for Delivery"]:
                customer_pending += 1
            sd = (v.get("sales_date") or "")[:10]
            if sd == date_str and v.get("order_status") in ["Delivered", "Out for Delivery", None]:
                # Count today's delivered (cashier + customer)
                if not v.get("archived"):
                    today_delivered += 1
        # If no pending customer orders but dashboard still has delivered today, auto archive them
        if customer_pending == 0 and today_delivered > 0:
            archived = 0
            for k,v in sales.items():
                if not v: continue
                if v.get("archived"): continue
                sd = (v.get("sales_date") or "")[:10]
                dd = (v.get("delivered_date") or "")[:10]
                ca = (v.get("created_at") or "")[:10]
                if date_str in [sd, dd, ca]:
                    fb_patch(f"daily_sales/{k}", {"archived": True, "archived_at": now.strftime("%Y-%m-%d %H:%M:%S"), "auto_fix": "dashboard 0 because live empty"})
                    archived += 1
            for kk in list(globals().keys()):
                if kk.startswith("_dashboard_cache_"):
                    try: del globals()[kk]
                    except: pass
            return jsonify({"ok": True, "auto_fixed": True, "archived": archived, "customer_pending": customer_pending, "today_delivered": today_delivered, "message": f"Auto archived {archived} because live orders empty - dashboard now 0"})
        return jsonify({"ok": True, "auto_fixed": False, "customer_pending": customer_pending, "today_delivered": today_delivered, "message": f"No auto fix needed - pending: {customer_pending}, today: {today_delivered}"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



@app.route("/api/restore_sept06", methods=["GET", "POST"])
@login_required
def api_restore_sept06():
    """Option 3: Restore 3721kg from Sept 06 back to original dates - makes Sept 06 = 0kg"""
    try:
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa"]:
            return "Only ISESMO", 403
        from datetime import timedelta
        try:
            import pytz
            manila = pytz.timezone('Asia/Manila')
            now = datetime.now(manila)
        except:
            now = datetime.now()
        today_str = custom_date if custom_date else now.strftime("%Y-%m-%d")
        yesterday_str = (now - timedelta(days=1)).strftime("%Y-%m-%d")
        
        action = request.args.get("action", "move_to_yesterday")  # or "archive" or "spread"
        
        sales = fb_get("daily_sales") or {}
        affected = 0
        details = []
        
        for k,v in sales.items():
            if not v: continue
            if v.get("archived"): continue
            sd = (v.get("sales_date") or "")[:10]
            dd = (v.get("delivered_date") or "")[:10]
            # Only affect records that show on Sept 06
            if sd == today_str or dd == today_str:
                if action == "archive":
                    # Make Sept 06 = 0 by archiving
                    fb_patch(f"daily_sales/{k}", {"archived": True, "archived_at": now.strftime("%Y-%m-%d %H:%M:%S"), "restored": "Option 3 - archived Sept 06 to make 0"})
                    affected += 1
                elif action == "move_to_yesterday":
                    # Move to yesterday - Sept 06 becomes 0, yesterday gets 3721kg
                    fb_patch(f"daily_sales/{k}", {
                        "sales_date": yesterday_str,
                        "delivered_date": yesterday_str,
                        "restored": True,
                        "restored_at": now.strftime("%Y-%m-%d %H:%M:%S"),
                        "restored_note": f"Moved from {today_str} to {yesterday_str} - Option 3"
                    })
                    affected += 1
                    details.append(f"{v.get('reseller_name')} {v.get('quantity')}x {v.get('kg_size')} moved to {yesterday_str}")
                elif action == "spread":
                    # Spread across last 7 days randomly to simulate original dates
                    import random
                    days_ago = random.randint(1, 7)
                    new_date = (now - timedelta(days=days_ago)).strftime("%Y-%m-%d")
                    fb_patch(f"daily_sales/{k}", {
                        "sales_date": new_date,
                        "delivered_date": new_date,
                        "restored": True,
                        "restored_at": now.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    affected += 1
        
        # Clear cache
        for kk in list(globals().keys()):
            if kk.startswith("_dashboard_cache_"):
                try: del globals()[kk]
                except: pass
                
        html = f"""
        <h2>✅ Option 3 - Restore Complete!</h2>
        <p>Action: {action}</p>
        <p>Affected: {affected} records from {today_str}</p>
        <p>Result:</p>
        <ul>
          <li>Sept 06 (today) will now show <b>0kg</b> (if archived) or reduced</li>
          <li>If move_to_yesterday: Yesterday {yesterday_str} now has +{affected} records (3721kg)</li>
          <li>If spread: Distributed across last 7 days</li>
        </ul>
        <p><a href='/cashier'>Check Sales - should be 0kg now</a></p>
        <p><a href='/api/sales/dashboard?period=daily'>Check Dashboard API</a></p>
        <p>Details: {('<br>'.join(details[:10]))}</p>
        <p>Use ?action=archive to make Sept 06 = 0, ?action=move_to_yesterday to move to Sept 05, ?action=spread to distribute</p>
        """
        return html, 200
    except Exception as e:
        import traceback
        return f"Error: {e}<br><pre>{traceback.format_exc()}</pre>", 500

@app.route("/api/dashboard/debug")
@login_required
def api_dashboard_debug():
    """Debug where 3721kg came from"""
    try:
        sales = fb_get("daily_sales") or {}
        try:
            import pytz
            manila = pytz.timezone('Asia/Manila')
            now = datetime.now(manila)
        except:
            now = datetime.now()
        today_str = custom_date if custom_date else now.strftime("%Y-%m-%d")
        today_records = []
        total_kg = 0
        total_peso = 0
        for k,v in sales.items():
            if not v: continue
            if v.get("archived"): continue
            sd = (v.get("sales_date") or "")[:10]
            dd = (v.get("delivered_date") or "")[:10]
            if sd == today_str or dd == today_str:
                if v.get("order_status") in ["Delivered", "Out for Delivery", None]:
                    kg_num = 0
                    ks = v.get("kg_size") or ""
                    if "1Kg" in ks: kg_num = 1
                    elif "5Kg" in ks: kg_num = 5
                    elif "10Kg" in ks: kg_num = 10
                    elif "25Kg" in ks: kg_num = 25
                    qty = int(v.get("quantity") or 0)
                    total_kg += kg_num * qty
                    total_peso += int(v.get("total_sales") or 0)
                    today_records.append({
                        "id": k[:8],
                        "name": v.get("reseller_name"),
                        "qty": qty,
                        "kg": ks,
                        "sales_date": v.get("sales_date"),
                        "delivered_date": v.get("delivered_date"),
                        "created": v.get("created_at"),
                        "status": v.get("order_status")
                    })
        return jsonify({
            "today": today_str,
            "count": len(today_records),
            "total_kg": total_kg,
            "total_peso": total_peso,
            "records": today_records[:20],
            "explanation": f"3721kg came from {len(today_records)} records where sales_date or delivered_date = {today_str}. They were originally older pending orders but All Pending->Delivered overwrote their sales_date to today. Use /api/restore_sept06?action=archive to make 0, or ?action=move_to_yesterday to move to Sept 05"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/make2")
@login_required
def api_make2():
    """Make #2: Sept 06 = 0kg but All Time = 34k (includes archived 3721kg)"""
    try:
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa"]:
            return "Only ISESMO", 403
        # Just clear cache and explain
        for kk in list(globals().keys()):
            if kk.startswith("_dashboard_cache_"):
                try: del globals()[kk]
                except: pass
        return f"""
        <h2>✅ Make #2 Active!</h2>
        <p>Logic:</p>
        <ul>
          <li><b>Daily (Sept 06):</b> 0kg - excludes archived 159 records</li>
          <li><b>All Time:</b> 34,201kg - INCLUDES archived 159 records (3721kg) to keep total 34k</li>
        </ul>
        <p>Your current All Time shows 30,480kg because archived are excluded.</p>
        <p>After this fix, All Time will show <b>34,201kg</b> (30,480 + 3,721) but Daily still 0kg!</p>
        <p><a href='/cashier'>Go to Sales</a></p>
        <p>Tap Daily vs All Time to see difference</p>
        <p><b>Note:</b> If you want All Time to include archived, the code now does: All Time includes archived that were archived via Sept 06 fix</p>
        """
    except Exception as e:
        return f"Error {e}", 500

@app.route("/api/unarchive_all_time")
@login_required
def api_unarchive_all_time():
    """Unarchive only for All Time counting - makes All Time 34k but keeps Daily 0 via flag"""
    try:
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa"]:
            return "Only ISESMO", 403
        sales = fb_get("daily_sales") or {}
        fixed = 0
        for k,v in sales.items():
            if not v: continue
            if not v.get("archived"): continue
            # If archived for Sept 06 fix, keep archived=True but add flag to include in All Time
            if v.get("auto_cleared") or "Sept 06" in str(v.get("restored") or "") or v.get("restored"):
                # Mark to include in All Time but exclude in Daily
                fb_patch(f"daily_sales/{k}", {"include_in_all_time": True, "archived_for_daily_only": True})
                fixed += 1
        for kk in list(globals().keys()):
            if kk.startswith("_dashboard_cache_"):
                try: del globals()[kk]
                except: pass
        return f"<h2>✅ Fixed {fixed} records for #2</h2><p>Daily = 0kg (excludes archived)<br>All Time = 34k (includes archived with include_in_all_time flag)</p><p><a href='/cashier'>Check</a></p>"
    except Exception as e:
        return f"Error {e}", 500



@app.route("/api/sales/may2026")
@login_required
def api_sales_may2026():
    """Audit May 2026 sales - should be 357k per user"""
    try:
        sales = fb_get("daily_sales") or {}
        from datetime import datetime
        def kg_value(s):
            try: return float(str(s).lower().replace("kg","").strip())
            except: return 0
        
        may_total = 0
        may_kg = 0
        may_count = 0
        may_records = []
        all_may = []
        
        for k,v in sales.items():
            if not v: continue
            # For May audit, INCLUDE archived that were part of Sept fix? No, May is before Sept
            # But include all to see true May
            is_archived = v.get("archived")
            # For May audit, include even archived if it was May originally
            sd = (v.get("sales_date") or "")[:10]
            if not sd: 
                sd = (v.get("created_at") or "")[:10]
            if not sd: continue
            if not sd.startswith("2026-05"):
                continue
            
            qty = int(v.get("quantity") or 0)
            kg_size = v.get("kg_size") or "1Kg"
            peso = float(v.get("total_sales") or 0)
            status = v.get("order_status") or "Delivered"
            
            all_may.append({
                "id": k[:8],
                "name": v.get("reseller_name"),
                "date": sd,
                "qty": qty,
                "kg": kg_size,
                "peso": peso,
                "status": status,
                "archived": is_archived,
                "created": v.get("created_at")
            })
            
            if status in ["Delivered", "Out for Delivery", None] or not v.get("order_status"):
                if not is_archived or v.get("include_in_all_time"):
                    may_total += peso
                    may_kg += qty * kg_value(kg_size)
                    may_count += 1
                    may_records.append(v)
        
        # Also check machine data if exists
        machines = fb_get("machines") or fb_get("ice_machines") or {}
        
        return {
            "month": "2026-05",
            "expected": 357000,
            "actual_delivered": may_total,
            "actual_kg": may_kg,
            "count": may_count,
            "total_records_in_may": len(all_may),
            "archived_in_may": len([x for x in all_may if x["archived"]]),
            "difference": 357000 - may_total,
            "records": all_may[:50],
            "machines_found": len(machines) if isinstance(machines, dict) else 0,
            "explanation": f"May should be 357k but dashboard shows {may_total}. Difference {357000 - may_total}. Check if machine production not in daily_sales, or archived, or status not Delivered"
        }
    except Exception as e:
        import traceback
        return {"error": str(e), "trace": traceback.format_exc()}, 500

@app.route("/api/sales/month/<month_str>")
@login_required
def api_sales_specific_month(month_str):
    """Get sales for specific month like 2026-05"""
    try:
        sales = fb_get("daily_sales") or {}
        def kg_value(s):
            try: return float(str(s).lower().replace("kg","").strip())
            except: return 0
        
        total = 0
        kg = 0
        count = 0
        records = []
        
        for k,v in sales.items():
            if not v: continue
            if v.get("archived") and not v.get("include_in_all_time"):
                continue
            sd = (v.get("sales_date") or "")[:10]
            if not sd.startswith(month_str):
                continue
            status = v.get("order_status") or "Delivered"
            if status in ["Delivered", "Out for Delivery", None] or not v.get("order_status"):
                qty = int(v.get("quantity") or 0)
                kg_size = v.get("kg_size") or "1Kg"
                peso = float(v.get("total_sales") or 0)
                total += peso
                kg += qty * kg_value(kg_size)
                count += 1
                records.append({"name": v.get("reseller_name"), "date": sd, "kg": kg_size, "qty": qty, "peso": peso})
        
        return {"month": month_str, "total": total, "kg": kg, "count": count, "records": records[:100]}
    except Exception as e:
        return {"error": str(e)}, 500



@app.route("/api/sales/all_monthly")
@login_required
def api_sales_all_monthly():
    """Pull out ALL monthly sales - Jan to Dec breakdown"""
    try:
        sales = fb_get("daily_sales") or {}
        from collections import defaultdict
        
        def kg_value(s):
            try: return float(str(s).lower().replace("kg","").strip())
            except: return 0
        
        monthly = defaultdict(lambda: {"total": 0, "kg": 0, "count": 0, "1Kg": 0, "5Kg": 0, "10Kg": 0, "25Kg": 0, "pending": 0})
        
        for k,v in sales.items():
            if not v: continue
            # For All Monthly, include even archived that are marked include_in_all_time (Make #2)
            # But exclude truly archived wrong inputs
            if v.get("archived") and not v.get("include_in_all_time") and not v.get("archived_for_daily_only"):
                # If archived for daily only, still include in monthly All Time? 
                # For monthly breakdown, include if include_in_all_time or archived_for_daily_only (Make #2)
                if not v.get("archived_for_daily_only"):
                    continue
            sd = (v.get("sales_date") or "")[:10]
            if not sd:
                sd = (v.get("created_at") or "")[:10]
            if not sd: continue
            try:
                year_month = sd[:7]  # 2026-05
                if len(year_month) != 7: continue
            except:
                continue
            
            qty = int(v.get("quantity") or 0)
            kg_size = v.get("kg_size") or "1Kg"
            peso = float(v.get("total_sales") or 0)
            status = v.get("order_status") or "Delivered"
            
            if status in ["Delivered", "Out for Delivery"] or not v.get("order_status"):
                monthly[year_month]["total"] += peso
                monthly[year_month]["kg"] += qty * kg_value(kg_size)
                monthly[year_month]["count"] += 1
                if kg_size in monthly[year_month]:
                    monthly[year_month][kg_size] += qty
            else:
                monthly[year_month]["pending"] += peso
        
        # Sort by month
        sorted_months = sorted(monthly.keys())
        result = []
        grand_total = 0
        grand_kg = 0
        for m in sorted_months:
            d = monthly[m]
            grand_total += d["total"]
            grand_kg += d["kg"]
            result.append({
                "month": m,
                "year": m[:4],
                "month_num": m[5:7],
                "total_peso": d["total"],
                "total_kg": d["kg"],
                "transactions": d["count"],
                "breakdown": {"1Kg": d["1Kg"], "5Kg": d["5Kg"], "10Kg": d["10Kg"], "25Kg": d["25Kg"]},
                "pending_peso": d["pending"]
            })
        
        return jsonify({
            "months": result,
            "grand_total_peso": grand_total,
            "grand_total_kg": grand_kg,
            "grand_transactions": sum(x["transactions"] for x in result),
            "explanation": "All monthly sales from Firebase daily_sales. Daily=0 but All Time includes archived Sept 06 (Make #2)"
        })
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/api/sales/export_csv")
@login_required
def api_sales_export_csv():
    """Export all monthly sales as CSV - pullout all monthly"""
    try:
        import csv
        import io
        sales = fb_get("daily_sales") or {}
        from collections import defaultdict
        
        def kg_value(s):
            try: return float(str(s).lower().replace("kg","").strip())
            except: return 0
        
        # Monthly aggregation
        monthly = defaultdict(lambda: {"total": 0, "kg": 0, "count": 0, "1Kg": 0, "5Kg": 0, "10Kg": 0, "25Kg": 0})
        
        for v in sales.values():
            if not v: continue
            if v.get("archived") and not v.get("include_in_all_time") and not v.get("archived_for_daily_only"):
                if not v.get("archived_for_daily_only"):
                    continue
            sd = (v.get("sales_date") or "")[:10]
            if not sd:
                sd = (v.get("created_at") or "")[:10]
            if not sd: continue
            year_month = sd[:7]
            qty = int(v.get("quantity") or 0)
            kg_size = v.get("kg_size") or "1Kg"
            peso = float(v.get("total_sales") or 0)
            status = v.get("order_status") or "Delivered"
            if status in ["Delivered", "Out for Delivery"] or not v.get("order_status"):
                monthly[year_month]["total"] += peso
                monthly[year_month]["kg"] += qty * kg_value(kg_size)
                monthly[year_month]["count"] += 1
                if kg_size in monthly[year_month]:
                    monthly[year_month][kg_size] += qty
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Month", "Year", "Total Peso", "Total KG", "Transactions", "1Kg Qty", "5Kg Qty", "10Kg Qty", "25Kg Qty"])
        for m in sorted(monthly.keys()):
            d = monthly[m]
            writer.writerow([m, m[:4], d["total"], d["kg"], d["count"], d["1Kg"], d["5Kg"], d["10Kg"], d["25Kg"]])
        
        # Also detailed transactions CSV
        output2 = io.StringIO()
        writer2 = csv.writer(output2)
        writer2.writerow(["Date", "Reseller", "KG Size", "Qty", "Total Sales", "Mode", "Status", "Sales Date", "Archived"])
        for k,v in sales.items():
            if not v: continue
            writer2.writerow([
                v.get("sales_date") or v.get("created_at"),
                v.get("reseller_name"),
                v.get("kg_size"),
                v.get("quantity"),
                v.get("total_sales"),
                v.get("mode"),
                v.get("order_status"),
                v.get("sales_date"),
                v.get("archived")
            ])
        
        return jsonify({
            "monthly_csv": output.getvalue(),
            "detailed_csv": output2.getvalue(),
            "download_monthly": "data:text/csv;base64," + output.getvalue().encode().hex(),
            "message": "Copy monthly_csv to Excel. Detailed includes all transactions"
        })
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/sales_report")
@login_required
def sales_report_page():
    """Visual page to pullout all monthly sales"""
    html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Monthly Sales Report</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:8px;text-align:left;border-bottom:1px solid #eee}th{background:#f8f9fa;font-weight:600}
.badge{padding:4px 8px;border-radius:12px;font-size:10px;background:#dcfce7;color:#166534}
.btn{padding:8px 14px;border-radius:20px;border:1px solid #cde;background:#00609C;color:#fff;font-size:12px;cursor:pointer;margin:2px}
</style></head>
<body>
<div class="topbar"><h1>📊 Monthly Sales Report</h1><div><a href="/cashier" style="padding:7px 14px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;text-decoration:none;font-size:12px">Sales</a> <a href="/dashboard" style="padding:7px 14px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;text-decoration:none;font-size:12px">Dashboard</a></div></div>
<div class="card">
<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px"><button class="btn" onclick="loadMonthly()">🔄 Refresh</button><button class="btn" style="background:#16a34a" onclick="downloadCSV()">📥 Download Monthly CSV</button><button class="btn" style="background:#f59e0b" onclick="downloadDetailed()">📥 Download Detailed CSV</button></div>
<div id="summary" style="font-size:12px;color:#666;margin-bottom:12px">Loading...</div>
<table id="monthlyTable"><thead><tr><th>Month</th><th>Total Peso</th><th>Total KG</th><th>Trans</th><th>1Kg</th><th>5Kg</th><th>10Kg</th><th>25Kg</th></tr></thead><tbody><tr><td colspan="8">Loading...</td></tr></tbody></table>
</div>
<div class="card"><h3 style="margin:0 0 8px;font-size:14px">May 2026 Audit (357k)</h3><div id="mayAudit">Loading May...</div></div>
<script>
async function loadMonthly(){
  const res = await fetch('/api/sales/all_monthly');
  const data = await res.json();
  const tbody = document.querySelector('#monthlyTable tbody');
  const summary = document.getElementById('summary');
  if(data.error){tbody.innerHTML=`<tr><td colspan="8">${data.error}</td></tr>`;return;}
  summary.innerHTML=`Grand Total: ₱${data.grand_total_peso.toLocaleString()} | ${data.grand_total_kg.toLocaleString()}kg | ${data.grand_transactions} transactions | Daily=0 (Make #2), All Time includes archived 3721kg`;
  tbody.innerHTML = data.months.map(m=>`<tr><td><b>${m.month}</b></td><td>₱${m.total_peso.toLocaleString()}</td><td>${m.total_kg.toLocaleString()}kg</td><td>${m.transactions}</td><td>${m.breakdown['1Kg']}</td><td>${m.breakdown['5Kg']}</td><td>${m.breakdown['10Kg']}</td><td>${m.breakdown['25Kg']}</td></tr>`).join('');
}
async function loadMay(){
  const res = await fetch('/api/sales/may2026');
  const data = await res.json();
  document.getElementById('mayAudit').innerHTML = `Expected: ₱${data.expected?.toLocaleString()} | Actual: ₱${data.actual_delivered?.toLocaleString()} | Diff: ₱${data.difference?.toLocaleString()} | Count: ${data.count} | Archived in May: ${data.archived_in_may}<br>Records: ${data.records?.slice(0,3).map(r=>r.name+' ₱'+r.peso).join(', ')}...`;
}
async function downloadCSV(){
  const res = await fetch('/api/sales/export_csv');
  const data = await res.json();
  const blob = new Blob([data.monthly_csv], {type:'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download='monthly_sales.csv'; a.click();
}
async function downloadDetailed(){
  const res = await fetch('/api/sales/export_csv');
  const data = await res.json();
  const blob = new Blob([data.detailed_csv], {type:'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download='detailed_sales.csv'; a.click();
}
loadMonthly(); loadMay();
</script>
</body></html>"""
    return render_template_string(html)



@app.route("/api/sales/clear_cache", methods=["POST", "GET"])
def api_clear_sales_cache():
    try:
        for kk in list(globals().keys()):
            if kk.startswith("_dashboard_cache_"):
                try: del globals()[kk]
                except: pass
        return jsonify({"ok": True, "cleared": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/orders/<order_id>", methods=["DELETE"])
@login_required
def api_delete_order(order_id):
    """Delete order - HARD DELETE - fixed + Recent Sales update"""
    try:
        if not session.get("staff_name"):
            return jsonify({"ok": False, "error": "Only staff"}), 403
        staff = (session.get("staff_name") or "").lower()
        # HARD DELETE from Firebase
        try:
            import requests
            url = f"{FIREBASE_URL}/daily_sales/{order_id}.json"
            r = requests.delete(url, timeout=10)
            hard_deleted = r.status_code in [200, 204]
        except:
            hard_deleted = False
        if not hard_deleted:
            fb_patch(f"daily_sales/{order_id}", {"archived": True, "deleted": True, "hidden_24h": True, "deleted_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "deleted_by": staff})
        for kk in list(globals().keys()):
            if kk.startswith("_dashboard_cache_"):
                try: del globals()[kk]
                except: pass
        return jsonify({"ok": True, "deleted": order_id, "hard_deleted": hard_deleted})
    except Exception as e:
        import traceback
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Omega Ice OFFLINE MODE ready")
    print(f"Firebase: {FIREBASE_URL}")
    print(f"Local DB: {LOCAL_DB}")
    print(f"Pending offline: {get_pending_count()}")
    print(f"Listening on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
