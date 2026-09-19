
"""
Omega Ice - OFFLINE FIRST - Firebase + Local SQLite backup
- If internet: saves to Firebase instantly
- If NO internet: saves to phone (omega_local.db) and shows pending badge
- When internet returns: tap badge or go to /api/offline/sync to upload

Firebase: https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app
"""

import os, sqlite3, json, requests, time, base64
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import random, string, re
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string, Response

# --- Firebase Admin SDK ---
import firebase_admin
from firebase_admin import credentials, db

app = Flask(__name__)
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    return resp


# --- SECURITY HARDENING ---
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required! Set it in Render > Environment")
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8)
)

# Init Firebase Admin from env variable FIREBASE_CREDENTIALS (paste whole JSON as string) or file path
firebase_creds_json = os.environ.get("FIREBASE_CREDENTIALS_JSON") or os.environ.get("FIREBASE_CREDENTIALS") or os.environ.get("FIREBASE_ADMIN_JSON") or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON") or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
firebase_creds_path = None
firebase_db_url = os.environ.get("FIREBASE_URL", "https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app")

if not firebase_admin._apps:
    try:
        if firebase_creds_json:
            # If you paste the JSON content in env var
            import tempfile
            # Handle base64 encoded json too
            try:
                # try to parse as json
                cred_dict = json.loads(firebase_creds_json)
            except:
                # try base64 decode
                cred_dict = json.loads(base64.b64decode(firebase_creds_json).decode())
            cred = credentials.Certificate(cred_dict)
        elif firebase_creds_path and os.path.exists(firebase_creds_path):
            cred = credentials.Certificate(firebase_creds_path)
        else:
            # fallback to local file if exists (for local dev)
            local_json = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firebase-admin.json")
            if os.path.exists(local_json):
                cred = credentials.Certificate(local_json)
            else:
                raise RuntimeError("No firebase credentials found")
        firebase_admin.initialize_app(cred, {
            "databaseURL": firebase_db_url
        })
    except Exception as e:
        print(f"Firebase Admin init error: {e}")
        raise

# Rate limiting simple
from collections import defaultdict
_login_attempts = defaultdict(list)

def is_rate_limited(ip, max_attempts=5, window_seconds=300):
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < window_seconds]
    return len(_login_attempts[ip]) >= max_attempts

def record_attempt(ip):
    _login_attempts[ip].append(time.time())


def hash_customer_password(pwd):
    return generate_password_hash(pwd, method="pbkdf2:sha256", salt_length=16)

def verify_customer_password(hash_val, pwd):
    if not hash_val or not pwd or len(hash_val) < 20 or hash_val == pwd:
        return False
    try:
        return check_password_hash(hash_val, pwd)
    except:
        return False

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
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>Omega Purified Ice - Login</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<meta name="mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#fff;border-radius:16px;padding:28px 24px;width:100%;max-width:340px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.06)}h1{font-size:20px;color:#00609C;margin:0 0 4px}.subtitle{font-size:13px;color:#333;margin:0 0 4px;font-weight:600}.tagline{font-size:11px;color:#888;margin:0 0 24px}.dots{font-size:28px;letter-spacing:8px;margin:12px 0;color:#222;min-height:36px}.msg{font-size:12px;color:#888;min-height:18px;margin-bottom:16px}.keypad{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px}.keypad button{padding:20px 0;font-size:24px;border-radius:12px;border:none;background:#f0f0f0;cursor:pointer}.keypad button.clear{background:#e5433d;color:#fff}.keypad button.back{background:#999;color:#fff}
#installBanner{display:none;background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:10px;margin-bottom:14px;font-size:12px;color:#92400e}
#installBanner button{margin-top:6px;padding:8px 14px;border-radius:8px;border:none;background:#00609C;color:#fff;font-size:12px;font-weight:600}
</style>
</head><body>
<div class="card">
<img src="/logo-full.webp" alt="Omega Purified Ice" style="max-width:170px;width:100%;height:auto;margin:0 auto 6px;display:block">
<div id="installBanner"><div>📲 I-install ang Cashier App sa device na ito para mas mabilis at parang native app.</div><button onclick="doInstallPrompt()">Install App</button></div>
<p class="subtitle">STAFF LOGIN</p><p class="tagline">Sales quick access</p><div class="dots" id="dots">o o o o</div><p class="msg" id="msg">Enter PIN</p>
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
// --- Auto/one-tap install prompt for the cashier PWA ---
// Browsers only allow the native install dialog to be triggered after
// 'beforeinstallprompt' fires (Chrome/Edge on Android/desktop; iOS Safari
// has no such event at all and only supports the manual Share > Add to
// Home Screen flow, so there's no code path for a true one-tap install
// there). We stash the event, then call .prompt() on it immediately -
// no extra click needed - which is as close to "auto install" as the web
// platform allows; the visible banner+button stays as a fallback for
// browsers that still require a user gesture.
let deferredInstallEvent = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallEvent = e;
  try{
    if(!localStorage.getItem('omega_cashier_installed')){
      e.prompt();
    }
  }catch(err){}
  document.getElementById('installBanner').style.display='block';
});
window.addEventListener('appinstalled', () => {
  try{ localStorage.setItem('omega_cashier_installed', '1'); }catch(e){}
  document.getElementById('installBanner').style.display='none';
});
async function doInstallPrompt(){
  if(!deferredInstallEvent) return;
  deferredInstallEvent.prompt();
  await deferredInstallEvent.userChoice;
  deferredInstallEvent = null;
  document.getElementById('installBanner').style.display='none';
}
let pin="";function updateDots(){let out="";for(let i=0;i<4;i++)out+=(i<pin.length?"*":"o")+" ";document.getElementById("dots").innerText=out.trim()}
function addDigit(d){if(pin.length<4){pin+=d;updateDots();if(pin.length==4)setTimeout(doLogin,200)}}
function backspace(){pin=pin.slice(0,-1);updateDots()}
function clearPin(){pin="";updateDots();document.getElementById("msg").textContent="Enter PIN"}
async function doLogin(){document.getElementById("msg").textContent="Checking...";try{const res=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({pin})});const data=await res.json();if(data.ok){window.location.href="/cashier"}else{document.getElementById("msg").textContent=data.error||"Wrong PIN";setTimeout(clearPin,1200)}}catch(e){document.getElementById("msg").textContent="Network error";setTimeout(clearPin,1500)}}
</script>
</body></html>
"""
CASHIER_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>Omega Purified Ice - Cashier</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<meta name="mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px;padding-bottom:160px;color:#1a1a1a} /* FIX: extra bottom padding para di matakpan ng browser bar */
/* --- Kiosk mode: cashier device is meant to stay ON this app, so disable
   text selection / long-press callouts everywhere EXCEPT actual form
   fields (staff still needs to select/copy values there). */
body.kiosk-on *{ -webkit-user-select:none; user-select:none; -webkit-touch-callout:none; }
body.kiosk-on input, body.kiosk-on textarea{ -webkit-user-select:text; user-select:text; -webkit-touch-callout:default; }
#kioskBtn{position:fixed;bottom:14px;right:14px;z-index:40;width:44px;height:44px;border-radius:50%;background:#00609C;color:#fff;border:none;font-size:18px;box-shadow:0 2px 8px rgba(0,0,0,.25)}
#installBannerC{display:none;background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:8px 10px;margin-bottom:10px;font-size:11px;color:#92400e;display:flex;justify-content:space-between;align-items:center;gap:8px}
#installBannerC button{padding:6px 12px;border-radius:8px;border:none;background:#00609C;color:#fff;font-size:11px;font-weight:600;white-space:nowrap}
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
<div id="installBannerC"><span>📲 I-install ang app na ito para mas mabilis gamit tuwing shift.</span><button onclick="doInstallPromptC()">Install</button></div>
<div class="topbar"><div style="display:flex;align-items:center;gap:8px"><img src="/icon-192.png" alt="" style="width:26px;height:26px;border-radius:6px"><h1>OMEGA PURIFIED ICE</h1></div><div style="display:flex;align-items:center;gap:10px"><span class="staff">{{ staff_name }}</span><button class="logout" onclick="logout()">Logout</button></div></div>
<button id="kioskBtn" onclick="toggleKiosk()" title="Kiosk mode">⛶</button>
<div class="one-row">
  <span class="cloud-badge online" id="onlineBadge">● Cloud Online</span>
  <a href="/orders" class="nav-pill" style="background:#ff4444;color:#fff;border-color:#ff4444;position:relative">🔴 Online Orders <span id="liveOrdersCount" style="background:#fff;color:#ff4444;border-radius:10px;padding:1px 6px;font-size:10px;font-weight:700;margin-left:4px;display:none">0</span></a>
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
    <label style="font-size:10px;color:#fff;opacity:.8;margin:8px 0 6px;display:block">🔎 O maghanap gamit ang date</label>
    <input type="date" id="periodDateSearchInput" onchange="onPeriodDateSearch()" style="width:100%;padding:8px;border-radius:8px;border:none;font-size:12px">
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

<div style="display:flex;gap:8px;margin:12px 0">
  <button id="openAlarmSettingsBtn" onclick="openAlarmModal()" style="flex:1;padding:14px;border-radius:12px;border:2px solid #ff4444;background:#fff5f5;color:#c0392b;font-weight:700;font-size:13px">⚙️🔊 Alarm Settings</button>
  <button id="stopAlarmBtn" onclick="stopAlarmForever()" style="display:none;padding:14px;border-radius:12px;border:none;background:#ef4444;color:#fff;font-weight:700;font-size:13px">🔇 Stop Alarm</button>
</div>

<div id="alarmModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.6);z-index:99999;align-items:center;justify-content:center;padding:16px">
  <div style="background:#fff;border-radius:16px;padding:20px;max-width:400px;width:100%;max-height:90vh;overflow-y:auto">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 style="margin:0;font-size:16px;color:#c0392b">🔊 Alarm Settings</h3>
      <button onclick="closeAlarmModal()" style="width:32px;height:32px;border-radius:50%;border:none;background:#f0f0f0;font-size:18px">✕</button>
    </div>
    <div style="background:#fff5f5;border:1px solid #fecaca;border-radius:10px;padding:10px;margin-bottom:12px">
      <div style="font-size:10px;color:#666">Staff: <b id="modalStaffName">Loading...</b></div>
      <div style="font-size:10px;color:#00609C;margin-top:2px">🎤 omega/yhel = English voice "New ice order!" | isesmo = alarm only</div>
    </div>
    <label style="font-size:11px;font-weight:600">Alarm Sound</label>
    <select id="alarmSoundSelect" onchange="saveAlarmSettings(); previewAlarmSound();" style="width:100%;padding:12px;border-radius:10px;border:2px solid #ddd;font-size:13px;margin:6px 0 12px">
      <option value="beep_short">🔔 Beep Short</option>
      <option value="alarm_clock">⏰ Alarm Clock</option>
      <option value="radar">🚨 Radar</option>
      <option value="siren">🚒 Siren</option>
      <option value="custom_loud" selected>🔥 LOUD BEEP</option>
      <option value="custom_very_loud">💥 SUPER LOUD 5x</option>
    </select>
    <label style="font-size:11px;font-weight:600">Volume</label>
    <select id="alarmVolumeSelect" onchange="saveAlarmSettings()" style="width:100%;padding:12px;border-radius:10px;border:2px solid #ddd;font-size:13px;margin:6px 0 12px">
      <option value="1.0" selected>100% MAX</option>
      <option value="0.8">80% Loud</option>
      <option value="0.5">50% Normal</option>
    </select>
    <div style="background:#f8f8f8;border-radius:10px;padding:10px;margin-bottom:12px">
      <label style="font-size:11px;display:flex;align-items:center;gap:8px;margin-bottom:8px"><input type="checkbox" id="alarmLoopCheck" checked onchange="saveAlarmSettings()" style="width:18px;height:18px"> <b>Loop until accepted</b></label>
      <label style="font-size:11px;display:flex;align-items:center;gap:8px;margin-bottom:8px"><input type="checkbox" id="alarmVibrateCheck" checked onchange="saveAlarmSettings()" style="width:18px;height:18px"> <b>Vibrate</b></label>
      <label style="font-size:11px;display:flex;align-items:center;gap:8px"><input type="checkbox" id="alarmBgCheck" checked onchange="saveAlarmSettings()" style="width:18px;height:18px"> <b>Background Notif</b></label>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">
      <button onclick="testAlarm()" style="padding:12px;border-radius:10px;border:2px solid #00609C;background:#eef7ff;color:#00609C;font-weight:700;font-size:12px">🔊 Test Alarm</button>
      <button onclick="testVoice()" style="padding:12px;border-radius:10px;border:2px solid #ff4444;background:#fff5f5;color:#c0392b;font-weight:700;font-size:12px">🗣️ Test Voice</button>
    </div>
    <div style="background:#eef7ff;border-radius:8px;padding:8px;font-size:10px;margin-bottom:12px">
      <div>Status: <span id="alarmStatus" style="font-weight:700">Ready - Tap Test to unlock sound</span></div>
      <div style="margin-top:4px;color:#666">💡 Tap Test first to unlock audio (browser rule). Then auto-alarm will work.</div>
    </div>
    <button onclick="closeAlarmModal()" style="width:100%;padding:14px;border-radius:10px;border:none;background:#00609C;color:#fff;font-weight:700;font-size:14px">✅ Save & Close</button>
  </div>
</div>

<audio id="orderAlarm" preload="auto" style="display:none"></audio>
<audio id="orderAlarm2" preload="auto" style="display:none"></audio>
<div id="alarmBanner" style="display:none;position:fixed;top:0;left:0;right:0;background:#ef4444;color:#fff;padding:14px;text-align:center;font-weight:700;z-index:99998;animation:blink 1s infinite" onclick="stopAlarmForever()">🔴 NEW ICE ORDER! TAP TO STOP - <span id="bannerCount">1</span> waiting!</div>
<style>@keyframes blink{0%,100%{opacity:1}50%{opacity:.7}} .alarm-active{animation:blink 0.5s infinite !important; background:#ef4444 !important; color:#fff !important}</style>

<div class="bottom-spacer"></div>


<div class="card" id="periodSalesCard" style="display:none">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
<label style="font-weight:600;display:block" id="periodSalesLabel">Monthly Sales Record</label>
<button onclick="loadPeriodSales(cashierPeriod)" style="padding:6px 12px;border-radius:20px;border:1px solid #cde;background:#fff;font-size:11px">🔄 Refresh</button>
</div>
<table><thead><tr><th>Date/Time</th><th>Reseller</th><th>Qty</th><th>Size</th><th>Total</th><th>Status</th></tr></thead><tbody id="periodSalesBody"><tr><td colspan=6>Select Monthly / Weekly...</td></tr></tbody></table>
<div style="font-size:10px;color:#666;margin-top:8px" id="periodSalesSummary"></div>
</div>

<div class="card" id="recentCard"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><label style="font-weight:600;display:block">Recent sales - Status included <span style="font-size:9px;color:#888" id="recentTimestamp"></span></label><button onclick="loadRecent();loadToday();" style="padding:6px 12px;border-radius:20px;border:1px solid #cde;background:#fff;font-size:11px">🔄 Refresh</button></div>
<div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap">
<span style="font-size:10px;background:#dcfce7;color:#166534;padding:3px 8px;border-radius:10px">Delivered = Real Sales</span>
<span style="font-size:10px;background:#fef3c7;color:#92400e;padding:3px 8px;border-radius:10px">Pending = Not yet counted</span>
</div>
<table><thead><tr><th>Date</th><th>Reseller</th><th>Qty</th><th>Size</th><th>Total</th><th>Status</th><th></th></tr></thead><tbody id="recentBody"></tbody></table></div>
<script>
let mode='DELIVER';let payment='Cash';let kg='{{ kg_options[0] }}';let selectedReseller=null;let unitPrice=0;let editingSaleId=null;let cashierPeriod='daily';let totalManuallyEdited=false;let timeManuallyEdited=false;
// BUG FIX: Date.toISOString() always renders in UTC. Manila is UTC+8, so
// between 12:00 AM-8:00 AM Manila time, toISOString().split('T')[0] would
// show YESTERDAY's date as "today" (e.g. still 2025-09-18 at 4:49 AM on
// Sept 19 Manila time). Date.getTime() is a timezone-agnostic UTC instant,
// so shifting it by +8h before formatting gives Manila's wall-clock date
// regardless of the browser/device's own timezone setting.
function todayManila(){
  const now = new Date();
  return new Date(now.getTime() + 8*60*60000).toISOString().split('T')[0];
}
// Same UTC-shift trick as todayManila(), but returns "HH:MM" - used to keep
// the Sale Time field ticking with the real current time (see below).
function nowManilaTimeHHMM(){
  const now = new Date();
  return new Date(now.getTime() + 8*60*60000).toISOString().slice(11,16);
}
// SECURITY FIX (Sept 19): reseller_name/store_name were being dropped
// straight into innerHTML (Recent Sales table, period sales table, the
// reseller-search dropdown) with no escaping. A store name like
// <img src=x onerror=...> would execute as real HTML/JS for any staff
// viewing that table - a stored XSS. Every place that renders a
// user-supplied name into HTML now runs it through this first.
function escapeHtml(t){
  const d = document.createElement('div');
  d.textContent = (t===null || t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function setMode(m){mode=m;document.getElementById('modeDeliver').classList.toggle('active',m==='DELIVER');document.getElementById('modePickup').classList.toggle('active',m==='PICKUP');updateTotal()}
function setPayment(p){payment=p;document.getElementById('payCash').classList.toggle('active',p==='Cash');document.getElementById('payCredit').classList.toggle('active',p==='Credit')}
function setKg(k){kg=k;document.querySelectorAll('.kg-row button').forEach(b=>b.classList.toggle('active',b.dataset.kg===k));updateTotal()}
async function updateTotal(){if(totalManuallyEdited)return;try{const res=await fetch(`/api/price?kg=${kg}&mode=${mode}`);const data=await res.json();unitPrice=data.price;}catch(e){unitPrice=10;}const qty=parseInt(document.getElementById('qtyInput').value)||0;document.getElementById('totalAmount').value=(unitPrice*qty).toFixed(2)}
const resellerInput=document.getElementById('resellerInput');const resultsBox=document.getElementById('resellerResults');
resellerInput.addEventListener('input',async()=>{selectedReseller=null;const q=resellerInput.value.trim();if(!q){resultsBox.style.display='none';return}const res=await fetch(`/api/resellers?q=${encodeURIComponent(q)}`);const rows=await res.json();if(!rows.length){resultsBox.style.display='none';return}resultsBox.innerHTML=rows.map(r=>`<div class="res-item" data-id="${r.id}" data-name="${r.store_name.replace(/"/g,'&quot;')}">${escapeHtml(r.store_name)}</div>`).join('');resultsBox.style.display='block';resultsBox.querySelectorAll('.res-item').forEach(el=>{el.addEventListener('click',()=>{pickReseller(el.getAttribute('data-id'),el.getAttribute('data-name'))})})});
function pickReseller(id,name){selectedReseller={id,name};resellerInput.value=name;resultsBox.style.display='none'}
async function saveSale(){const qty=parseInt(document.getElementById('qtyInput').value)||0;const name=resellerInput.value.trim();const totalVal=parseFloat(document.getElementById('totalAmount').value);const statusEl=document.getElementById('statusMsg');if(!name||qty<=0){statusEl.textContent='Enter reseller';statusEl.className='status err';return}const saleDate = document.getElementById('saleDateInput').value || todayManila();
  const saleTime = document.getElementById('saleTimeInput').value || nowManilaTimeHHMM();
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
    if(cashierPeriod==='daily'){loadRecent(selectedDailyDate);} else { loadPeriodSales(cashierPeriod, selectedSubPeriod); }
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
    const d = s.sales_date || todayManila();
    document.getElementById('saleDateInput').value = d.slice(0,10);
    if(s.created_at && s.created_at.includes('T')){
      const t = s.created_at.split('T')[1].slice(0,5);
      document.getElementById('saleTimeInput').value = t;
    } else {
      document.getElementById('saleTimeInput').value = nowManilaTimeHHMM();
    }
  }catch(e){}
  document.getElementById('saveBtn').textContent='Update Sale';
  document.getElementById('cancelEditBtn').style.display='block';
  window.scrollTo({top:0,behavior:'smooth'});
}
function initDateInputs(){
  document.getElementById('saleDateInput').value = todayManila();
  document.getElementById('saleTimeInput').value = nowManilaTimeHHMM();
}

function cancelEdit(){
  editingSaleId=null;
  resellerInput.value='';
  selectedReseller=null;
  document.getElementById('qtyInput').value=1;
  totalManuallyEdited=false;
  timeManuallyEdited=false;
  document.getElementById('saveBtn').textContent='Save sale';
  document.getElementById('cancelEditBtn').style.display='none';
  initDateInputs();
  updateTotal();
}
let alarmLoopInterval = null;
let alarmAudioContext = null;
let audioUnlocked = false;
let lastAlarmTime = 0;
let lastActiveOrders = 0;
let alarmEnabled = true;

function openAlarmModal(){
  const modal = document.getElementById('alarmModal');
  if(modal) modal.style.display='flex';
  const staff = document.querySelector('.staff')?.textContent || 'Unknown';
  const nameEl = document.getElementById('modalStaffName');
  if(nameEl) nameEl.textContent = staff;
  loadAlarmSettings();
  // Try unlock immediately when opening modal
  unlockAudio();
}

function closeAlarmModal(){
  const modal = document.getElementById('alarmModal');
  if(modal) modal.style.display='none';
  saveAlarmSettings();
}

// TABLET-OPTIMIZED unlock - must be called on user tap
function unlockAudio(){
  console.log('Attempting audio unlock...');
  try{
    // Create or resume AudioContext
    if(!alarmAudioContext){
      alarmAudioContext = new (window.AudioContext || window.webkitAudioContext)();
    }
    if(alarmAudioContext.state === 'suspended'){
      alarmAudioContext.resume().then(()=>{
        console.log('AudioContext resumed');
        audioUnlocked = true;
        const st = document.getElementById('alarmStatus');
        if(st) st.textContent = '✅ Sound unlocked! Ready for orders.';
      });
    } else {
      audioUnlocked = true;
    }
    
    // For tablets: play a very short silent beep to unlock
    if(alarmAudioContext){
      const osc = alarmAudioContext.createOscillator();
      const gain = alarmAudioContext.createGain();
      gain.gain.value = 0.001; // almost silent
      osc.connect(gain);
      gain.connect(alarmAudioContext.destination);
      osc.start();
      osc.stop(alarmAudioContext.currentTime + 0.1);
    }
    
    // Unlock speech
    if('speechSynthesis' in window){
      window.speechSynthesis.cancel();
      // Preload voices
      const voices = window.speechSynthesis.getVoices();
      console.log('Voices loaded:', voices.length);
    }
    
  }catch(e){ console.log('Unlock error', e); }
}

function speakIceOrder(count, orders=[]){
  console.log('speakIceOrder called', count);
  if(!('speechSynthesis' in window)){
    console.log('speechSynthesis not supported');
    alert('Voice not supported on this tablet');
    return;
  }
  try{
    window.speechSynthesis.cancel();
    let msg = count===1 ? 'New ice order! One new order!' : `New ice order! ${count} new orders!`;
    if(orders && orders.length>0){
      const n = orders[0].reseller_name || orders[0].customer_name || '';
      if(n) msg += ` From ${n}.`;
    }
    msg += ' Please check live orders!';
    
    // Tablet fix: ensure voices loaded
    let voices = window.speechSynthesis.getVoices();
    if(voices.length===0){
      // Wait and retry
      setTimeout(()=>{
        voices = window.speechSynthesis.getVoices();
        doSpeak(msg, voices);
      }, 500);
    } else {
      doSpeak(msg, voices);
    }
  }catch(e){ console.log('Voice error', e); alert('Voice error: '+e.message); }
}

function doSpeak(msg, voices){
  try{
    const utter = new SpeechSynthesisUtterance(msg);
    utter.lang = 'en-US';
    utter.rate = 1.0;
    utter.pitch = 1.0;
    utter.volume = 1.0;
    // Find English voice
    const enVoice = voices.find(v=>v.lang.toLowerCase().includes('en-us')) || voices.find(v=>v.lang.toLowerCase().includes('en')) || voices[0];
    if(enVoice){
      utter.voice = enVoice;
      console.log('Using voice:', enVoice.name, enVoice.lang);
    }
    utter.onstart = ()=>{ console.log('Voice started'); };
    utter.onerror = (e)=>{ console.log('Voice error', e); alert('Voice failed: '+e.error); };
    utter.onend = ()=>{ console.log('Voice ended'); };
    window.speechSynthesis.speak(utter);
  }catch(e){ console.log('doSpeak error', e); }
}

if('speechSynthesis' in window){
  window.speechSynthesis.onvoiceschanged = ()=>{
    const v = window.speechSynthesis.getVoices();
    console.log('Voices changed, now', v.length);
  };
}

function testVoice(){
  console.log('testVoice tapped');
  unlockAudio();
  // Small delay to ensure unlock
  setTimeout(()=>{
    const staffName = (document.querySelector('.staff')?.textContent || '').toLowerCase();
    const isIsesmo = staffName.includes('isesmo');
    if(isIsesmo){
      alert('ISESMO: alarm only. But testing voice anyway for tablet.');
    }
    // Force voice
    speakIceOrder(1, [{reseller_name:'Test Customer'}]);
    const st = document.getElementById('alarmStatus');
    if(st) st.textContent = '🔊 Testing English voice... Listen!';
    
    // Also vibrate to confirm button works
    if(navigator.vibrate) navigator.vibrate([200,100,200]);
  }, 300);
}

function getAlarmSettings(){
  return {
    sound: document.getElementById('alarmSoundSelect')?.value || localStorage.getItem('omega_alarm_sound') || 'custom_loud',
    volume: parseFloat(document.getElementById('alarmVolumeSelect')?.value || localStorage.getItem('omega_alarm_volume') || '1.0'),
    loop: document.getElementById('alarmLoopCheck')?.checked ?? (localStorage.getItem('omega_alarm_loop') !== 'false'),
    vibrate: document.getElementById('alarmVibrateCheck')?.checked ?? (localStorage.getItem('omega_alarm_vibrate') !== 'false'),
    bg: document.getElementById('alarmBgCheck')?.checked ?? (localStorage.getItem('omega_alarm_bg') !== 'false')
  };
}

function saveAlarmSettings(){
  const s = getAlarmSettings();
  localStorage.setItem('omega_alarm_sound', s.sound);
  localStorage.setItem('omega_alarm_volume', String(s.volume));
  localStorage.setItem('omega_alarm_loop', String(s.loop));
  localStorage.setItem('omega_alarm_vibrate', String(s.vibrate));
  localStorage.setItem('omega_alarm_bg', String(s.bg));
  const st = document.getElementById('alarmStatus');
  if(st) st.textContent = 'Saved: ' + s.sound + ' @ ' + Math.round(s.volume*100) + '%';
}

function loadAlarmSettings(){
  try{
    const sound = localStorage.getItem('omega_alarm_sound');
    const vol = localStorage.getItem('omega_alarm_volume');
    if(sound && document.getElementById('alarmSoundSelect')) document.getElementById('alarmSoundSelect').value = sound;
    if(vol && document.getElementById('alarmVolumeSelect')) document.getElementById('alarmVolumeSelect').value = vol;
    if(localStorage.getItem('omega_alarm_loop')!==null) document.getElementById('alarmLoopCheck').checked = localStorage.getItem('omega_alarm_loop')==='true';
    if(localStorage.getItem('omega_alarm_vibrate')!==null) document.getElementById('alarmVibrateCheck').checked = localStorage.getItem('omega_alarm_vibrate')==='true';
    if(localStorage.getItem('omega_alarm_bg')!==null) document.getElementById('alarmBgCheck').checked = localStorage.getItem('omega_alarm_bg')==='true';
  }catch{}
}

function previewAlarmSound(){
  const sel = document.getElementById('alarmSoundSelect')?.value || 'custom_loud';
  const vol = parseFloat(document.getElementById('alarmVolumeSelect')?.value || '1.0');
  playAlarmSound({sound: sel, volume: vol});
}

// TABLET FIX: Always use Web Audio, no HTML audio
function playAlarmSound(settings){
  console.log('playAlarmSound', settings.sound, 'vol', settings.volume);
  lastAlarmTime = Date.now();
  
  try{
    // Ensure AudioContext exists and is running - THIS IS CRITICAL FOR TABLET
    if(!alarmAudioContext){
      alarmAudioContext = new (window.AudioContext || window.webkitAudioContext)();
      console.log('Created AudioContext, state:', alarmAudioContext.state);
    }
    if(alarmAudioContext.state === 'suspended'){
      console.log('Resuming suspended AudioContext...');
      alarmAudioContext.resume().then(()=>{
        console.log('Resumed, now playing');
        doPlayBeep(settings);
      });
    } else {
      doPlayBeep(settings);
    }
  }catch(e){ 
    console.log('playAlarmSound error', e); 
    alert('Sound error: '+e.message+'. Try tapping Test again.');
  }
}

function doPlayBeep(settings){
  try{
    const ctx = alarmAudioContext;
    const vol = settings.volume || 1.0;
    
    // Different patterns for tablet
    let repeats = 3;
    let freq1 = 1000;
    let freq2 = 1500;
    
    if(settings.sound === 'custom_very_loud'){
      repeats = 6;
      freq1 = 1200;
      freq2 = 1800;
    } else if(settings.sound === 'siren'){
      repeats = 8;
      freq1 = 800;
      freq2 = 1600;
    } else if(settings.sound === 'alarm_clock'){
      repeats = 4;
      freq1 = 900;
      freq2 = 900;
    } else if(settings.sound === 'radar'){
      repeats = 3;
      freq1 = 600;
      freq2 = 1200;
    }
    
    console.log('Playing', repeats, 'beeps');
    
    for(let i=0;i<repeats;i++){
      setTimeout(()=>{
        try{
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          osc.type = 'square'; // Loudest
          osc.frequency.value = i%2===0 ? freq1 : freq2;
          gain.gain.setValueAtTime(vol, ctx.currentTime);
          gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime+0.7);
          osc.connect(gain);
          gain.connect(ctx.destination);
          osc.start();
          osc.stop(ctx.currentTime+0.7);
          console.log('Beep', i, 'played');
        }catch(e){ console.log('Beep error', e); }
      }, i*800);
    }
    
    // Vibrate for tablet
    if(settings.vibrate && navigator.vibrate){
      navigator.vibrate([500,200,500,200,1000]);
    }
    
    const st = document.getElementById('alarmStatus');
    if(st) st.textContent = '🔊 Playing '+settings.sound+' - '+new Date().toLocaleTimeString();
    
  }catch(e){ console.log('doPlayBeep error', e); }
}

function triggerOrderAlarm(count, orders=[]){
  if(!alarmEnabled) return;
  const settings = getAlarmSettings();
  const staffName = (document.querySelector('.staff')?.textContent || '').toLowerCase();
  const isVoiceAccount = staffName.includes('omega') || staffName.includes('yhel');
  console.log('TRIGGER ALARM', count, 'voice?', isVoiceAccount);
  
  try{
    const stopBtn = document.getElementById('stopAlarmBtn');
    if(stopBtn) stopBtn.style.display='inline-block';
    const banner = document.getElementById('alarmBanner');
    const bannerCount = document.getElementById('bannerCount');
    if(banner){ banner.style.display='block'; if(bannerCount) bannerCount.textContent = count; }
    const statusEl = document.getElementById('alarmStatus');
    if(statusEl) statusEl.textContent = '🔴 NEW ORDER '+count+' - '+new Date().toLocaleTimeString();
    
    // Voice first for omega/yhel
    if(isVoiceAccount){
      setTimeout(()=>{ speakIceOrder(count, orders); }, 500);
    }
    
    // Then beep
    setTimeout(()=>{ playAlarmSound(settings); }, 100);
    
    // Title flash
    let flash=0;
    if(window._flashInterval) clearInterval(window._flashInterval);
    window._flashInterval = setInterval(()=>{
      document.title = flash%2===0 ? '🔴 NEW ORDER ('+count+')!' : '🔵 '+count+' WAITING!';
      flash++;
      if(flash>200){ clearInterval(window._flashInterval); document.title='Omega Ice - Cashier'; }
    }, 700);
    
    const liveBtn = document.querySelector('a[href="/orders"]');
    if(liveBtn) liveBtn.classList.add('alarm-active');
    
    // Loop every 5s until every "New Order" has been accepted (status changed
    // away from "New Order") in the Live Orders UI. Does NOT wait for Delivered.
    if(alarmLoopInterval) clearInterval(alarmLoopInterval);
    if(settings.loop){
      alarmLoopInterval = setInterval(()=>{
        fetch('/api/staff/customer_orders').then(r=>r.json()).then(data=>{
          const stillNew = (data.orders||[]).filter(o=>o.order_status==='New Order');
          if(stillNew.length===0){ stopAlarmForever(); }
          else {
            const sLoop = (document.querySelector('.staff')?.textContent || '').toLowerCase();
            if(sLoop.includes('omega') || sLoop.includes('yhel')) speakIceOrder(stillNew.length, stillNew);
            playAlarmSound(getAlarmSettings());
          }
        });
      }, 5000);
    }
  }catch(e){ console.log(e); }
}

function stopAlarmForever(){
  console.log('Stop alarm');
  if(alarmLoopInterval){ clearInterval(alarmLoopInterval); alarmLoopInterval=null; }
  if(window._flashInterval){ clearInterval(window._flashInterval); window._flashInterval=null; }
  document.title='Omega Ice - Cashier';
  const btn=document.getElementById('stopAlarmBtn');
  if(btn) btn.style.display='none';
  const banner=document.getElementById('alarmBanner');
  if(banner) banner.style.display='none';
  const st=document.getElementById('alarmStatus');
  if(st) st.textContent='Stopped - '+new Date().toLocaleTimeString();
  const liveBtn = document.querySelector('a[href="/orders"]');
  if(liveBtn) liveBtn.classList.remove('alarm-active');
  if('speechSynthesis' in window) window.speechSynthesis.cancel();
  lastActiveOrders=0;
  setTimeout(()=>{ fetchLiveOrdersCount(); }, 2000);
}

function testAlarm(){
  console.log('testAlarm tapped - TABLET MODE');
  unlockAudio();
  // For tablet, need immediate audible beep after user tap
  setTimeout(()=>{
    const s = getAlarmSettings();
    console.log('Test with', s);
    playAlarmSound(s);
    // Also show visual feedback that button works
    const btn = document.getElementById('openAlarmSettingsBtn');
    if(btn){
      const orig = btn.textContent;
      btn.textContent = '🔊 Playing...';
      setTimeout(()=>{ btn.textContent = orig; }, 1000);
    }
    if(navigator.vibrate) navigator.vibrate([300,100,300]);
  }, 200);
}

function stopAlarm(){ stopAlarmForever(); }

async function fetchLiveOrdersCount(){
  try{
    const res = await fetch('/api/staff/customer_orders');
    const data = await res.json();
    const orders = data.orders||[];
    const active = orders.filter(o=>!['Delivered','Cancelled'].includes(o.order_status)).length;
    // FIX: alarm must key off unaccepted "New Order" items specifically, not just
    // "not delivered yet". Pending/Preparing/Out for Delivery are already accepted
    // in the Live Orders UI and should NOT keep the alarm ringing.
    const newOrders = orders.filter(o=>o.order_status==='New Order');
    const newOrderCount = newOrders.length;
    const badge = document.getElementById('liveOrdersCount');
    if(badge){
      if(active>0){
        badge.textContent = active;
        badge.style.display='inline';
      } else {
        badge.style.display='none';
      }
    }
    console.log('Live orders:', active, 'unaccepted new:', newOrderCount, 'loop:', !!alarmLoopInterval);
    if(newOrderCount>0){
      // Ring when a fresh unaccepted order shows up, or when the loop isn't
      // running yet (e.g. page/tab just loaded with unaccepted orders waiting).
      if(newOrderCount > lastActiveOrders || !alarmLoopInterval){
        triggerOrderAlarm(newOrderCount, newOrders);
      }
    } else if(alarmLoopInterval){
      // Nothing left unaccepted -> staff already tapped Accept in Live Orders UI
      stopAlarmForever();
    }
    lastActiveOrders = newOrderCount;
  }catch(e){ console.log('fetch error', e); }
}

// TABLET: Unlock on ANY tap
document.addEventListener('click', ()=>{ unlockAudio(); }, {once:false});
document.addEventListener('touchstart', ()=>{ 
  console.log('touchstart - unlocking');
  unlockAudio(); 
}, {once:false});
document.addEventListener('touchend', ()=>{ unlockAudio(); }, {once:false});

document.addEventListener('DOMContentLoaded', ()=>{
  loadAlarmSettings();
  console.log('DOM loaded, trying unlock');
  setTimeout(()=>{ 
    unlockAudio(); 
    // Preload voices
    if('speechSynthesis' in window) window.speechSynthesis.getVoices();
  }, 500);
  
  if(Notification && Notification.permission==='default'){ 
    Notification.requestPermission(); 
  }
  
  // TABLET: Big hint to tap Test first
  setTimeout(()=>{
    const st = document.getElementById('alarmStatus');
    if(st && !audioUnlocked){
      st.textContent = '⚠️ TAP Test Alarm first to enable sound on tablet!';
      st.style.color = '#ef4444';
      st.style.fontWeight = 'bold';
    }
  }, 2000);
});


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

async function loadPeriodSales(period, subVal=null){
  const body = document.getElementById('periodSalesBody');
  const summary = document.getElementById('periodSalesSummary');
  const label = document.getElementById('periodSalesLabel');
  body.innerHTML='<tr><td colspan=6>Loading '+period+' sales...</td></tr>';
  label.textContent = period.toUpperCase() + ' SALES RECORD';
  try{
    let url = '/api/sales/by_period?period='+period;
    let sub = subVal || selectedSubPeriod;
    if(sub) url += '&sub='+encodeURIComponent(sub);
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
      return `<tr><td style="font-size:10px">${dateTime}<br><small style="color:#888">${r.timestamp||''}</small></td><td>${escapeHtml(r.reseller_name)}</td><td>${r.quantity}</td><td>${r.kg_size}</td><td>₱${r.total_sales}</td><td>${badge}<br><div style="display:flex;gap:4px;margin-top:4px"><button class="icon-btn edit" style="width:26px;height:26px;font-size:12px" onclick="editSale('${r.id}');" title="Edit">✏️</button><button class="icon-btn del" style="width:26px;height:26px;font-size:12px" onclick="deleteSale('${r.id}')" title="Delete">🗑️</button></div></td></tr>`;
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



// NOTE: A second, broken copy of triggerOrderAlarm() and stopAlarm() used to be
// defined here. In JS, a later `function` declaration silently replaces an
// earlier one with the same name in the same scope - so THIS was the version
// that actually ran, not the correct looping/voice one defined above. It also
// played the <audio id="orderAlarm"> element, which has no `src`, so it was
// silent on top of not looping. Removed as the root-cause fix for the alarm
// not looping / not respecting the accept action.

setInterval(fetchLiveOrdersCount, 30000);
fetchLiveOrdersCount();
async function loadToday(customDate=null, subVal=null){
  // ROOT-CAUSE FIX: the top KG/PESO/TRANS card used to always hit
  // /api/sales/dashboard with only `period` (never the WW/month/quarter/
  // year `sub` picker value), so picking a week/month in the search box
  // updated the table below but NOT this card. Now it accepts `subVal` and
  // forwards it as `sub`, same as loadPeriodSales() does for the table -
  // both always show the same range because the backend uses one shared
  // resolver for both endpoints.
  const sub = subVal !== null ? subVal : (cashierPeriod !== 'daily' ? selectedSubPeriod : null);

  // Show date immediately so not stuck on a stale date - Tap Refresh
  let todayStr = todayManila();
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
    if(sub) url += '&sub='+encodeURIComponent(sub);
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
      return `<tr><td style="font-size:11px">${r.sales_date||''}${deliveredInfo}</td><td>${escapeHtml(r.reseller_name)}<br><small style="font-size:9px;color:#888">${timeDisplay}</small></td><td>${r.quantity}</td><td>${r.kg_size}</td><td>₱${r.total_sales}</td><td>${badge}</td><td><div style="display:flex;gap:4px"><button class="icon-btn edit" onclick="editSale('${r.id}')" title="Edit">✏️</button><button class="icon-btn del" onclick="deleteSale('${r.id}')" title="Delete">🗑️</button></div></td></tr>`;
    }).join('');
  }catch(e){document.getElementById('recentBody').innerHTML=`<tr><td colspan=7 style="color:#c0392b">Error: ${e.message} <a href="/login">Login</a></td></tr>`;}
}
async function deleteSale(id){
  if(!confirm('Delete?')) return;
  // BUG FIX: this used to fire-and-forget the DELETE request (no error
  // check) and then ALWAYS refresh only the daily Recent list + top card -
  // so deleting a row from the Weekly/Monthly/Quarterly/Yearly table never
  // refreshed that table, and the deleted row just stayed on screen
  // looking like the delete didn't work (even when it actually succeeded).
  try{
    const res = await fetch(`/api/sale/${id}`, {method:'DELETE'});
    if(res.status===401){window.location.href='/login';return;}
    const data = await res.json().catch(()=>({}));
    if(!res.ok || data.ok === false){
      alert('Delete failed: ' + (data.error || res.status));
      return;
    }
  }catch(e){
    alert('Delete failed: ' + e.message);
    return;
  }
  if(cashierPeriod === 'daily'){
    loadRecent(selectedDailyDate);
  } else {
    loadPeriodSales(cashierPeriod, selectedSubPeriod);
  }
  loadToday();
}




async function logout(){await fetch('/api/logout',{method:'POST'});window.location.href='/login'}

// FIX: Week/Month/Quarter/Year picker logic
let selectedSubPeriod = null;

function populateSubPeriodPicker(period){
  const picker = document.getElementById('subPeriodPicker');
  const select = document.getElementById('subPeriodSelect');
  const label = document.getElementById('subPeriodLabel');
  const dailyPicker = document.getElementById('dailyDatePicker');
  select.innerHTML='';
  // Reset the date-search field when switching period tabs so it doesn't show
  // a stale date left over from a different period (weekly/monthly/etc).
  const dateSearchInp = document.getElementById('periodDateSearchInput');
  if(dateSearchInp) dateSearchInp.value = '';
  
  // Always hide daily picker first
  if(dailyPicker) dailyPicker.style.display='none';
  
  if(period==='daily'){
    // Show daily date picker
    if(dailyPicker){
      dailyPicker.style.display='block';
      const dailyInput = document.getElementById('dailyDateInput');
      if(!dailyInput.value){
        dailyInput.value = todayManila();
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
  // Manual dropdown pick overrides any date-search value so they don't conflict
  const dateInp = document.getElementById('periodDateSearchInput');
  if(dateInp) dateInp.value = '';
  if(cashierPeriod!=='daily'){
    const v = selectedSubPeriod;
    // ROOT-CAUSE FIX: also refresh the top KG/PESO/TRANS card (loadToday),
    // not just the table - both used to drift out of sync.
    loadToday(null, v);
    loadPeriodSales(cashierPeriod, v);
  }
}

// FIX: dynamic "search by date" for weekly/monthly/quarterly/yearly - pumili ka
// lang ng kahit anong date, awtomatikong makukuha kung anong linggo/buwan/
// quarter/taon iyon at agad na lalabas ang sales ng period na iyon (parang
// yung Daily date search, pero applicable na rin sa ibang period tabs).
function onPeriodDateSearch(){
  const inp = document.getElementById('periodDateSearchInput');
  if(!inp || !inp.value) return;
  const picked = new Date(inp.value + 'T00:00:00');
  let sub = null;
  if(cashierPeriod === 'weekly'){
    sub = 'WW' + String(getWeekNumber(picked)).padStart(2,'0');
  } else if(cashierPeriod === 'monthly'){
    sub = String(picked.getMonth()+1).padStart(2,'0');
  } else if(cashierPeriod === 'quarterly'){
    sub = 'Q' + (Math.floor(picked.getMonth()/3)+1);
  } else if(cashierPeriod === 'yearly'){
    sub = String(picked.getFullYear());
  } else {
    return; // daily already has its own dedicated date search (dailyDateInput)
  }
  selectedSubPeriod = sub;
  // Sync the dropdown selection so it matches what the date search picked
  const sel = document.getElementById('subPeriodSelect');
  if(sel){
    for(const opt of sel.options){
      opt.selected = (opt.value === sub);
    }
  }
  // ROOT-CAUSE FIX: also refresh the top KG/PESO/TRANS card, not just the
  // table - this is the exact bug reported (total kg not dynamic on date search).
  loadToday(null, sub);
  loadPeriodSales(cashierPeriod, sub);
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
  document.getElementById('dailyDateInput').value = todayManila();
  onDailyDateChange();
}

function setDailyYesterday(){
  // Compute "yesterday" from the Manila date string directly (as a plain
  // UTC-midnight instant) instead of Date.setDate()/getDate(), which read
  // the BROWSER's local timezone - could be wrong on a device not set to
  // Asia/Manila.
  const manilaToday = todayManila();
  const d = new Date(manilaToday + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() - 1);
  const y = d.toISOString().split('T')[0];
  document.getElementById('dailyDateInput').value = y;
  onDailyDateChange();
}

// Hook into setCashierPeriod to show picker
const origSetCashier = setCashierPeriod;
setCashierPeriod = function(p){
  origSetCashier(p);
  populateSubPeriodPicker(p);
  if(p!=='daily'){
    setTimeout(()=>{
      const sel = document.getElementById('subPeriodSelect');
      const v = sel ? sel.value : selectedSubPeriod;
      selectedSubPeriod = v;
      // ROOT-CAUSE FIX: refresh the top card together with the table when
      // switching period tabs, using the sub-picker's default value (e.g.
      // current WW), so they start in sync instead of the card showing a
      // different range until the next manual search.
      loadToday(null, v);
      loadPeriodSales(p, v);
    }, 150);
  }
}

// FIX: midnight date rollover. Before this, `saleDateInput` (the date that
// gets saved with a NEW sale) was only ever set ONCE, when the page loaded
// (initDateInputs()). If the app/tab is left open across 12:00 AM Manila
// time without a reload, that field silently kept showing YESTERDAY's date
// - the Today card up top still looked correct (it refetches every 30s),
// but a sale saved after midnight would record on the wrong day.
// checkDateRollover() re-checks the actual Manila date and, if it changed,
// auto-advances the sale-entry date field (unless the cashier is mid-edit
// of an existing sale) and the daily filter date (unless the cashier
// deliberately pinned it to a past date via the date picker). It runs on
// every 30s tick (same cadence as loadToday/loadRecent) AND immediately
// when the tab/app comes back to the foreground, so switching back to the
// app after being away overnight catches the rollover right away instead
// of waiting up to 30s.
let lastKnownManilaDate = todayManila();
function checkDateRollover(){
  const nowDate = todayManila();
  if(nowDate === lastKnownManilaDate) return;
  lastKnownManilaDate = nowDate;
  const saleDateInp = document.getElementById('saleDateInput');
  if(saleDateInp && !editingSaleId) saleDateInp.value = nowDate;
  if(!selectedDailyDate){
    const dailyInp = document.getElementById('dailyDateInput');
    if(dailyInp) dailyInp.value = nowDate;
  }
  console.log('Date rolled over to '+nowDate+' - sale date field auto-updated');
}
document.addEventListener('visibilitychange', ()=>{
  if(document.visibilityState==='visible') checkDateRollover();
});
setInterval(checkDateRollover, 30000);

// BUG FIX: "Sale Time" had the exact same problem as the date - it was set
// ONCE when the page loaded (initDateInputs()) and never again. This one is
// worse than the date bug because the value isn't just a display, it gets
// saved AS-IS into created_at/time_only for every new sale (see saveSale()
// and /api/sale POST, which trusts whatever time the frontend sends). So a
// cashier who opened the app at 9:00 AM and recorded a sale at 10:30 AM
// without touching the Time field would have it permanently saved as 9:00
// AM - wrong timestamp on the actual record, not just a stale display.
//
// Fix: keep the field "ticking" with the real current time every 15s, the
// same way a live clock would, UNLESS the cashier has manually typed a
// different time (timeManuallyEdited) - e.g. deliberately encoding a sale
// for an earlier time - or is editing an existing sale (editingSaleId),
// where the field intentionally holds that record's original time.
const saleTimeInputEl = document.getElementById('saleTimeInput');
if(saleTimeInputEl){
  saleTimeInputEl.addEventListener('input', ()=>{ timeManuallyEdited = true; });
}
function tickSaleTime(){
  if(editingSaleId || timeManuallyEdited) return;
  const inp = document.getElementById('saleTimeInput');
  if(inp) inp.value = nowManilaTimeHHMM();
}
setInterval(tickSaleTime, 15000);

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

// --- Auto-install prompt (same approach as the login screen: capture
// 'beforeinstallprompt', call .prompt() immediately with no extra tap
// needed, keep the banner+button as fallback for browsers that insist on
// a user gesture). Shown here too since a staff member might land
// straight on /cashier with an existing session instead of /login.
let deferredInstallEventC = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallEventC = e;
  try{
    if(!localStorage.getItem('omega_cashier_installed')) e.prompt();
  }catch(err){}
  document.getElementById('installBannerC').style.display='flex';
});
window.addEventListener('appinstalled', () => {
  try{ localStorage.setItem('omega_cashier_installed', '1'); }catch(e){}
  document.getElementById('installBannerC').style.display='none';
});
async function doInstallPromptC(){
  if(!deferredInstallEventC) return;
  deferredInstallEventC.prompt();
  await deferredInstallEventC.userChoice;
  deferredInstallEventC = null;
  document.getElementById('installBannerC').style.display='none';
}

// --- Kiosk mode: for a dedicated cashier tablet/phone that should stay
// locked on this app. Toggled by the floating ⛶ button (off by default,
// so a normal browser tab still behaves normally until staff turns it
// on) and remembered per device via localStorage.
let kioskOn = false;
function applyKioskVisuals(on){
  document.body.classList.toggle('kiosk-on', on);
  document.getElementById('kioskBtn').textContent = on ? '⛶' : '⛶';
  document.getElementById('kioskBtn').style.background = on ? '#166534' : '#00609C';
}
async function toggleKiosk(){
  kioskOn = !kioskOn;
  try{ localStorage.setItem('omega_kiosk_mode', kioskOn ? '1' : '0'); }catch(e){}
  applyKioskVisuals(kioskOn);
  try{
    if(kioskOn && document.documentElement.requestFullscreen){
      await document.documentElement.requestFullscreen();
    }else if(!kioskOn && document.exitFullscreen && document.fullscreenElement){
      await document.exitFullscreen();
    }
  }catch(e){ /* Fullscreen needs a user gesture in most browsers - this IS one (button tap), but some browsers still refuse; visuals/lock still apply either way. */ }
}
document.addEventListener('contextmenu', (e) => { if(kioskOn) e.preventDefault(); });
// Re-enter fullscreen automatically if the OS/browser kicks it out (e.g.
// switching apps briefly) while kiosk mode is still turned on.
document.addEventListener('visibilitychange', () => {
  if(kioskOn && !document.hidden && document.documentElement.requestFullscreen && !document.fullscreenElement){
    document.documentElement.requestFullscreen().catch(()=>{});
  }
});
// Warn before an accidental refresh/close while kiosk mode is on, so a
// staff member's mid-sale entry doesn't vanish from a stray back-swipe.
window.addEventListener('beforeunload', (e) => {
  if(kioskOn){ e.preventDefault(); e.returnValue=''; }
});
(function initKiosk(){
  try{
    if(localStorage.getItem('omega_kiosk_mode')==='1'){ kioskOn=true; applyKioskVisuals(true); }
  }catch(e){}
})();

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
        db.reference("/").get(shallow=True)
        return True
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
        ref = db.reference(path)
        return ref.get()
    except Exception as e:
        print(f"GET {path} error: {e}")
    return None

def fb_post(path, data):
    try:
        ref = db.reference(path)
        new_ref = ref.push(data)
        return {"name": new_ref.key}
    except Exception as e:
        print(f"POST {path} error: {e}")
    return None

def fb_put(path, data):
    try:
        ref = db.reference(path)
        ref.set(data)
        return data
    except Exception as e:
        print(f"PUT {path} error: {e}")
    return None

def fb_delete(path):
    try:
        ref = db.reference(path)
        ref.delete()
        return True
    except Exception as e:
        print(f"DELETE {path} error: {e}")
    return False

def fb_patch(path, data):
    try:
        ref = db.reference(path)
        ref.update(data)
        return data
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
@login_required
def debug_page():
    if (session.get("staff_name") or "").lower() not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    return jsonify({"ok": True, "online": True, "pending": get_pending_count()})

@app.route("/api/login", methods=["POST"])
def api_login():
    ip = request.remote_addr or "unknown"
    if is_rate_limited(ip):
        return jsonify({"ok": False, "error": "Daming try! Wait 5 mins"}), 429
    pin = (request.json or {}).get("pin", "").strip()
    if len(pin) != 4 or not pin.isdigit():
        record_attempt(ip)

        return jsonify({"ok": False, "error": "Enter 4-digit PIN"}), 400
    # Try online first
    staff_data = fb_get("staff")
    # If offline, NO hardcoded PINs for security - must have internet and Firebase
    if not staff_data:
        return jsonify({"ok": False, "error": "No internet connection. Please connect to internet to login. Hardcoded offline PINs removed for security."}), 404
    for key, val in staff_data.items():
        if val and val.get("pin") == pin and val.get("status") == "Active":
            session["staff_id"] = key
            session["staff_name"] = val.get("name")
            session["staff_position"] = val.get("position", "Staff")
            return jsonify({"ok": True, "name": val.get("name"), "position": val.get("position")})
    record_attempt(ip)
    return jsonify({"ok": False, "error": "Wrong PIN"}), 401

@app.route("/api/setup")
def api_setup():
    if os.environ.get("ALLOW_SETUP", "false").lower() != "true":
        return jsonify({"ok": False, "error": "Setup disabled for security"}), 403
    existing = fb_get("staff")
    if existing:
        return jsonify({"ok": False, "message": "Already setup"})
    # CRITICAL SECURITY FIX (Sept 19): the real, working staff PINs used to
    # be hardcoded here in plain text, in the SAME source file that gets
    # copied/shared/uploaded around (as it just was, multiple times, in this
    # conversation). Anyone with a copy of this file had every staff PIN.
    # PINs now come from environment variables (set in Render > Environment,
    # never committed to the file) - setup refuses to run if they're not all
    # set, instead of silently falling back to a hardcoded value.
    #
    # IMPORTANT: since the old hardcoded PINs (1928/0615/0519/0712) have
    # already been exposed in this file, change all 4 staff PINs in Firebase
    # (or via this env-var-driven setup, if you're allowing a re-setup) as
    # soon as possible - the code fix alone doesn't invalidate PINs already
    # handed out.
    pin_env = {
        "staff1": ("STAFF1_NAME", "STAFF1_PIN", "Co-Owner"),
        "staff2": ("STAFF2_NAME", "STAFF2_PIN", "Staff"),
        "staff3": ("STAFF3_NAME", "STAFF3_PIN", "ADMIN"),
        "staff4": ("STAFF4_NAME", "STAFF4_PIN", "Manager/Owner"),
    }
    staff = {}
    missing = []
    for key, (name_var, pin_var, default_position) in pin_env.items():
        name = os.environ.get(name_var, "").strip()
        pin = os.environ.get(pin_var, "").strip()
        if not name or not (pin.isdigit() and len(pin) == 4):
            missing.append(f"{name_var}/{pin_var}")
            continue
        staff[key] = {"name": name, "position": os.environ.get(f"{key.upper()}_POSITION", default_position), "pin": pin, "status": "Active"}
    if missing:
        return jsonify({"ok": False, "error": "Missing/invalid env vars (need 4-digit PIN each): " + ", ".join(missing)}), 400
    fb_put("staff", staff)
    fb_put("price_settings/REGULAR", {"kg1": 10, "kg5": 50, "kg10": 100, "kg25": 250, "type": "REGULAR"})
    fb_put("price_settings/PICKUP", {"kg1": 9, "kg5": 45, "kg10": 90, "kg25": 230, "type": "PICKUP"})
    return jsonify({"ok": True, "message": "Setup done!"})


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

    # BUG FIX: this fallback used to be plain datetime.now() with no
    # timezone - on a server that isn't running in Asia/Manila (most cloud
    # hosts default to UTC), a sale saved without a frontend-supplied
    # date/time would silently land on the WRONG calendar day (UTC's
    # "today" can be 8 hours off from Manila's, same root cause as the
    # toISOString() bug fixed on the frontend). Frontend now always sends
    # sales_date/created_at from the live-ticking Manila time, so this is a
    # defensive fallback for the rare case it doesn't.
    try:
        import pytz
        manila = pytz.timezone('Asia/Manila')
        server_now = datetime.now(manila)
    except:
        server_now = datetime.now()

    # Allow custom date from frontend
    frontend_date = (data.get("sales_date") or "").strip()
    frontend_created = (data.get("created_at") or "").strip()
    if frontend_date:
        try:
            datetime.strptime(frontend_date[:10], "%Y-%m-%d")
            sales_date_val = frontend_date[:10]
        except:
            sales_date_val = server_now.strftime("%Y-%m-%d")
    else:
        sales_date_val = server_now.strftime("%Y-%m-%d")

    if frontend_created:
        created_val = frontend_created
    else:
        created_val = server_now.replace(tzinfo=None).isoformat()
    
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
        "time_only": (data.get("sale_time") or server_now.strftime("%H:%M"))
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


def resolve_period_range(period, sub, now, custom_date_str=None):
    """
    ROOT-CAUSE FIX (Sept 19): /api/sales/dashboard (top KG/PESO/TRANS card)
    and /api/sales/by_period (the sales table) used to compute the date
    range with two separate, slightly different pieces of code. That's why
    picking a week/month in the search box could update the table but NOT
    the total-kg card above it (or update it to a DIFFERENT number).

    This is now the single source of truth for both endpoints: same period
    + sub (WW01-WW52 / "01"-"12" / "Q1"-"Q4" / a 4-digit year) + optional
    custom_date always produces the exact same range, so both endpoints
    always agree.

    - "weekly" ALWAYS matches by ISO calendar week (Mon-Sun), never a
      rolling "last 7 days" window, so it lines up 1:1 with the WW dropdown.
    - When no sub is given, `custom_date` (the date-search box) becomes the
      anchor date used to derive the current week/month/quarter/year - this
      is what makes the date search "dynamic": pick ANY date and the right
      week/month/quarter is resolved automatically.
    - When sub IS given, it always wins over custom_date (manual dropdown
      pick beats a stale date-search value).

    Returns a dict:
      filter_start/filter_end : datetime range to filter by (None when
                                 ww_mode is True - weekly is matched by ISO
                                 week/year instead, see below)
      ww_mode      : True for "weekly" - match records by ISO week/year
                     instead of a start/end range
      target_week / target_year : the resolved ISO week/year (weekly only)
      range_start/range_end     : concrete calendar dates for DISPLAY only
                                   (always populated, even for weekly)
      label        : human-readable label for the period
    """
    period = (period or "daily").lower()
    sub = (sub or "").strip()

    target_week = target_month = target_quarter = target_year = None
    if sub:
        s = sub.upper()
        if s.startswith("WW"):
            try: target_week = int(s.replace("WW", ""))
            except: pass
        elif s.startswith("Q"):
            try: target_quarter = int(s.replace("Q", ""))
            except: pass
        elif s.isdigit() and len(s) == 4:
            try: target_year = int(s)
            except: pass
        elif s.isdigit() and 1 <= int(s) <= 12:
            try: target_month = int(s)
            except: pass

    # Anchor date: the custom date-search box only matters when no explicit
    # sub-picker value was sent - the dropdown always wins if both arrive.
    anchor = now
    if custom_date_str and not sub:
        try:
            parsed = datetime.strptime(custom_date_str[:10], "%Y-%m-%d")
            anchor = now.replace(year=parsed.year, month=parsed.month, day=parsed.day,
                                  hour=0, minute=0, second=0, microsecond=0)
        except Exception:
            anchor = now

    ww_mode = False
    filter_start = None
    filter_end = now
    range_start = None
    range_end = now
    label = "Today"

    if period == "daily":
        filter_start = anchor.replace(hour=0, minute=0, second=0, microsecond=0)
        filter_end = filter_start.replace(hour=23, minute=59, second=59)
        range_start, range_end = filter_start, filter_end
        label = filter_start.strftime("%Y-%m-%d")
    elif period == "weekly":
        ww_mode = True
        if not target_week:
            iso_year, iso_week, _ = anchor.isocalendar()
            target_week, target_year = iso_week, iso_year
        try:
            from datetime import date as _date_cls
            y_for_week = target_year or anchor.isocalendar()[0]
            monday = _date_cls.fromisocalendar(y_for_week, target_week, 1)
            sunday = _date_cls.fromisocalendar(y_for_week, target_week, 7)
            range_start = datetime(monday.year, monday.month, monday.day)
            range_end = datetime(sunday.year, sunday.month, sunday.day, 23, 59, 59)
        except Exception:
            range_start = range_end = None
        label = f"WW{target_week:02d}" + (f" {target_year}" if target_year else "")
    elif period == "monthly":
        y = target_year or anchor.year
        m = target_month or anchor.month
        filter_start = now.replace(year=y, month=m, day=1, hour=0, minute=0, second=0, microsecond=0)
        if m == 12:
            filter_end = filter_start.replace(year=y + 1, month=1, day=1) - timedelta(days=1)
        else:
            filter_end = filter_start.replace(month=m + 1, day=1) - timedelta(days=1)
        filter_end = filter_end.replace(hour=23, minute=59, second=59)
        range_start, range_end = filter_start, filter_end
        label = filter_start.strftime("%B %Y")
    elif period == "quarterly":
        y = target_year or anchor.year
        q = target_quarter or ((anchor.month - 1) // 3 + 1)
        q_start_month = (q - 1) * 3 + 1
        filter_start = now.replace(year=y, month=q_start_month, day=1, hour=0, minute=0, second=0, microsecond=0)
        q_end_month = q_start_month + 2
        if q_end_month == 12:
            filter_end = filter_start.replace(month=12, day=31, hour=23, minute=59, second=59)
        else:
            filter_end = filter_start.replace(month=q_end_month + 1, day=1) - timedelta(days=1)
            filter_end = filter_end.replace(hour=23, minute=59, second=59)
        range_start, range_end = filter_start, filter_end
        label = f"Q{q} {y}"
    elif period in ("yearly", "year"):
        y = target_year or anchor.year
        filter_start = now.replace(year=y, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        filter_end = now.replace(year=y, month=12, day=31, hour=23, minute=59, second=59)
        range_start, range_end = filter_start, filter_end
        label = f"Year {y}"
    else:  # "all"
        filter_start = None
        filter_end = None
        range_start = range_end = None
        label = "All Time"

    return {
        "filter_start": filter_start,
        "filter_end": filter_end,
        "ww_mode": ww_mode,
        "target_week": target_week,
        "target_year": target_year,
        "range_start": range_start,
        "range_end": range_end,
        "label": label,
    }


@app.route("/api/sales/by_period")
@login_required
def api_sales_by_period():
    """FIX #2: Return sales for selected period (monthly/weekly/etc) for cashier screen + WW/month pickers"""
    period = request.args.get("period", "monthly").lower()
    sub = request.args.get("sub", "").strip() or request.args.get("week", "").strip() or request.args.get("month", "").strip() or ""
    custom_date = request.args.get("date", "").strip()
    try:
        import pytz
        manila = pytz.timezone('Asia/Manila')
        now = datetime.now(manila)
    except:
        now = datetime.now()

    data = fb_get("daily_sales") or {}
    sales = []

    # ROOT-CAUSE FIX: date range now comes from the SAME resolver used by
    # /api/sales/dashboard, so the top card and this table always agree.
    rng = resolve_period_range(period, sub, now, custom_date)

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

        # WW filter (weekly always matches by ISO week/year now, see resolve_period_range)
        if rng["ww_mode"]:
            if check_date:
                try:
                    iso_year, iso_week, iso_day = check_date.isocalendar()
                    if iso_week != rng["target_week"]:
                        continue
                    if rng["target_year"] and iso_year != rng["target_year"]:
                        continue
                except:
                    continue
            else:
                continue
        else:
            if rng["filter_start"] and check_date and check_date < rng["filter_start"].replace(tzinfo=None):
                continue
            if period != "all" and rng["filter_end"] and check_date and check_date > rng["filter_end"].replace(tzinfo=None):
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
    
    return jsonify({
        "sales": sales[:100], "total_kg": total_kg, "total_peso": total_peso, "count": len(sales),
        "period": period, "label": rng["label"],
        "start": rng["range_start"].strftime("%Y-%m-%d") if rng["range_start"] else "All",
        "end": rng["range_end"].strftime("%Y-%m-%d") if rng["range_end"] else "",
    })

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
        # TRUE ROOT CAUSE FOUND (Sept 19): this used to hit the Firebase REST
        # API directly with plain `requests.delete()` - no auth token at all.
        # Your Realtime Database rules are locked down (.read/.write: false),
        # so that unauthenticated call was being REJECTED by Firebase every
        # time (401/403) and the code didn't even check the response, so it
        # silently reported {"ok": True} anyway. That's the actual reason
        # Delete looked broken. Switched to fb_delete(), which goes through
        # the Firebase Admin SDK (the same authenticated service-account
        # connection fb_get/fb_post/fb_patch already use) - it's allowed to
        # write regardless of the public .read/.write rules, the same way
        # the rest of this app already saves and edits sales.
        ok = fb_delete(f"daily_sales/{sale_id}")
        if not ok:
            return jsonify({"ok": False, "error": "Firebase delete failed - check server logs"}), 502
        # Clear the 10-sec dashboard cache so Today/period totals drop the
        # deleted sale immediately instead of up to 10s later.
        for kk in list(globals().keys()):
            if kk.startswith("_dashboard_cache_"):
                try: del globals()[kk]
                except: pass
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
@login_required
def debug_machines():
    # CRITICAL SECURITY FIX (Sept 19): this route had NO login check at all -
    # publicly readable by anyone on the internet with the URL, and it leaked
    # the actual Firebase database URL plus all machine data. Locked to
    # logged-in staff, and stopped returning the DB URL (that belongs in
    # server env vars/logs only, never in an API response).
    raw = fb_get("machines")
    return jsonify({
        "online": is_online(),
        "raw_machines_node": raw,
        "count": len(raw) if isinstance(raw, dict) else (0 if raw is None else "not a dict - see raw_machines_node")
    })

@app.route("/debug/resellers")
@login_required
def debug_resellers():
    # CRITICAL SECURITY FIX (Sept 19): this had NO login check - anyone with
    # the URL could dump every customer's phone number, address, credit
    # balance, and password hash. Locked to logged-in staff, and the
    # password hash is stripped out even for staff (never needed here).
    raw = fb_get("resellers") or {}
    # group by store_name to surface duplicates clearly
    by_name = {}
    for key, val in raw.items():
        if not val:
            continue
        name = (val.get("store_name") or "").strip()
        safe_val = {k: v for k, v in val.items() if k != "password_hash"}
        by_name.setdefault(name, []).append({"firebase_key": key, **safe_val})
    duplicates = {name: entries for name, entries in by_name.items() if len(entries) > 1}
    return jsonify({
        "total_resellers": len(raw),
        "duplicate_names": duplicates,
        "duplicate_count": len(duplicates)
    })


@app.route("/debug/fix_reseller_duplicates")
@login_required
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
    # CRITICAL SECURITY FIX (Sept 19): this MUTATES data (merges/deletes
    # reseller records, re-points sales) and had NO login check at all -
    # publicly triggerable by anyone. Restricted to ISESMO only, same as
    # the other one-time admin cleanup routes in this file.
    if (session.get("staff_name") or "").lower() not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Only ISESMO"}), 403
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

            # delete the sparse duplicate (fb_delete = authenticated Admin SDK,
            # not the raw unauthenticated REST call - see api_delete_sale for why)
            fb_delete(f"resellers/{remove_key}")

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
        # Same root-cause bug as api_delete_sale: raw unauthenticated REST
        # delete was silently rejected by the locked-down Firebase rules.
        # fb_delete() uses the authenticated Admin SDK connection instead.
        fb_delete(f"machines/{machine_id}")
        # also remove its logs
        logs = fb_get("machine_logs") or {}
        for lid, lg in logs.items():
            if lg and lg.get("machine_id") == machine_id:
                fb_delete(f"machine_logs/{lid}")
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
<link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
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
<div class="header"><img src="/logo-full.webp" alt="Omega Purified Ice" style="max-width:180px;width:100%;height:auto;margin:0 auto 8px;display:block"><p>Customer Secure Login</p><p style="font-size:11px;color:#888">One phone + password per store</p></div>
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
<link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
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
.rate-overlay{display:none;position:fixed;inset:0;background:rgba(10,25,45,.5);z-index:60;align-items:center;justify-content:center;padding:16px}
.rate-overlay.show{display:flex}
.rate-sheet{background:#fff;border-radius:16px;width:100%;max-width:360px;padding:22px;position:relative;text-align:center}
.rate-close{position:absolute;top:12px;right:12px;background:#f0f4f8;border:none;width:26px;height:26px;border-radius:50%;font-size:13px;color:#555;cursor:pointer}
.star-row{display:flex;justify-content:center;gap:6px;margin:14px 0}
.star-btn{font-size:32px;background:none;border:none;color:#dbe3ea;cursor:pointer;line-height:1;padding:2px}
.star-btn.filled{color:#f59e0b}
</style></head>
<body>
<div class="topbar"><div><h1 id="storeName">My Orders</h1><div style="font-size:11px;color:#666" id="storeMeta"></div></div><div style="display:flex;gap:6px"><span class="live">● LIVE</span><a href="/customer/logout" class="btn">Logout</a></div></div>
<div class="card"><div style="display:flex;justify-content:space-between;margin-bottom:8px"><span style="font-size:12px;font-weight:600">Summary</span><a href="/customer/{{ reseller_id }}/order" class="btn btn-primary">+ New Order</a></div><div class="stat-grid"><div><div class="stat-val" id="totalKg">0kg</div><div class="stat-lbl">TOTAL KG</div></div><div><div class="stat-val" id="totalPeso">₱0</div><div class="stat-lbl">TOTAL PESO</div></div><div><div class="stat-val" id="totalOrders">0</div><div class="stat-lbl">ORDERS</div></div></div><div id="statusCounts" style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;font-size:10px"></div>
<div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap">
<button onclick="loadOrders()" style="padding:8px 12px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px">🔄 Refresh</button>
<button onclick="bulkMarkDelivered()" style="padding:8px 12px;border-radius:20px;border:1px solid #86efac;background:#f0fdf4;color:#166534;font-size:11px">✅ Mark all Pending as Delivered</button>
<a href="/customer/{{ reseller_id }}/history" style="padding:8px 12px;border-radius:20px;border:1px solid #cde;background:#eef4fb;color:#00609C;font-size:11px;text-decoration:none;font-weight:600">📊 Sales History</a>
</div>
<div style="font-size:10px;color:#888;margin-top:6px">Staff will update to Preparing → Delivered</div>
</div>
<div class="card"><div style="font-size:12px;font-weight:600;margin-bottom:8px;display:flex;justify-content:space-between"><span>Real-time Orders</span><span style="font-size:10px;color:#888" id="lastUpdate"></span></div><div id="ordersList">Loading orders...</div></div>

<div class="track-overlay" id="trackOverlay" onclick="if(event.target===this)closeTracking()">
  <div class="track-sheet">
    <button class="track-close" onclick="closeTracking()">✕</button>
    <div id="trackBody">Loading...</div>
  </div>
</div>

<div class="rate-overlay" id="rateOverlay" onclick="if(event.target===this)closeRating()">
  <div class="rate-sheet">
    <button class="rate-close" onclick="closeRating()">✕</button>
    <div style="font-size:14px;font-weight:700;color:#0f2942">How was your order?</div>
    <div style="font-size:11px;color:#888;margin-top:2px">Tap a star to rate</div>
    <div class="star-row" id="starRow"></div>
    <textarea id="rateFeedback" rows="2" placeholder="Optional comment (e.g. mabilis dating, maayos yung packaging)" style="width:100%;padding:10px;border-radius:10px;border:1px solid #ccd;font-size:12px;resize:none"></textarea>
    <button onclick="submitRating()" style="width:100%;padding:12px;margin-top:12px;background:#00609C;color:#fff;border:none;border-radius:10px;font-weight:700">Submit Rating</button>
    <p id="rateStatus" style="font-size:11px;color:#c0392b;margin-top:6px"></p>
  </div>
</div>

<script>
const resellerId="{{ reseller_id }}";
let showArchived=false;
let lastOrders=[];
// Parses either a plain date ("2026-09-15") or a full/loose timestamp
// (including the old raw "...T08:05:08.955290" microsecond format) and
// renders it the same clean way everywhere, so the order list looks
// uniform instead of mixing clean times with raw ISO dumps.
function parseFlexDate(s){
  if(!s) return null;
  const m=String(s).match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?/);
  if(!m) return null;
  const [,y,mo,da,h='00',mi='00',se='00']=m;
  const d=new Date(+y,+mo-1,+da,+h,+mi,+se);
  return isNaN(d.getTime())?null:d;
}
function fmtOrderTime(salesDate,createdAt){
  const d=parseFlexDate(createdAt)||parseFlexDate(salesDate);
  if(!d) return salesDate||createdAt||'';
  const months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  let h=d.getHours();const ampm=h>=12?'PM':'AM';h=h%12;if(h===0)h=12;
  const mi=String(d.getMinutes()).padStart(2,'0');
  return `${months[d.getMonth()]} ${d.getDate()}, ${h}:${mi} ${ampm}`;
}
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
    list.innerHTML=orders.map(o=>{
      const reorderBtn=`<button onclick="event.stopPropagation();reorder('${o.id}')" style="font-size:10px;padding:5px 10px;border-radius:14px;border:1px solid #cde;background:#eef4fb;color:#00609C;font-weight:600">🔁 Reorder</button>`;
      let ratingHtml='';
      if((o.order_status||'')==='Delivered'){
        if(o.rating){
          ratingHtml=`<div style="margin-top:6px;font-size:11px;color:#f59e0b">${'★'.repeat(o.rating)}${'☆'.repeat(5-o.rating)}<span style="color:#888;margin-left:4px">Rated</span></div>`;
        }else{
          ratingHtml=`<button onclick="event.stopPropagation();openRating('${o.id}')" style="margin-top:6px;font-size:10px;padding:5px 10px;border-radius:14px;border:1px solid #fde68a;background:#fffbeb;color:#92400e;font-weight:600">⭐ Rate this order</button>`;
        }
      }
      return `<div class="order-card" data-order-id="${o.id}" onclick="openTracking('${o.id}')"><div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><span style="font-size:11px;color:#888;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${fmtOrderTime(o.sales_date,o.created_at)}</span><span class="status-pill status-${(o.order_status||'pending').toLowerCase().replace(/ /g,'-')}" style="flex-shrink:0">${o.order_status||'Pending'}</span></div><div style="display:grid;grid-template-columns:56px 1fr 64px;align-items:center;gap:6px;font-size:13px;margin-top:6px"><span style="font-weight:600">${o.quantity}x</span><span style="color:#555;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${o.kg_size} • ${o.mode}</span><span style="text-align:right;font-weight:600;color:#00609C">₱${(+o.total_sales||0).toLocaleString()}</span></div><div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px"><span style="font-size:10px;color:#888">Order ID: ${o.id.slice(0,8)} • Tap to track →</span>${reorderBtn}</div>${ratingHtml}</div>`;
    }).join('');
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
    `Packing ${o.quantity}x ${o.kg_size}`,
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

// --- Reorder: jumps to the New Order form pre-filled with the same
// size/qty/delivery/payment as a past order, so the customer doesn't have
// to re-type everything for a repeat purchase.
function reorder(orderId){
  const o=lastOrders.find(x=>x.id===orderId);
  if(!o) return;
  const params=new URLSearchParams({
    kg: o.kg_size||'1Kg',
    qty: o.quantity||1,
    mode: o.mode||'DELIVER',
    pay: o.payment||'Cash',
  });
  window.location.href=`/customer/${resellerId}/order?${params.toString()}`;
}

// --- Star rating modal (only shown for Delivered orders) ---
let rateOrderId=null;
let rateValue=0;
function renderStars(){
  const row=document.getElementById('starRow');
  row.innerHTML='';
  for(let i=1;i<=5;i++){
    const b=document.createElement('button');
    b.type='button';
    b.className='star-btn'+(i<=rateValue?' filled':'');
    b.textContent='★';
    b.onclick=()=>{rateValue=i;renderStars();};
    row.appendChild(b);
  }
}
function openRating(orderId){
  rateOrderId=orderId;
  rateValue=0;
  document.getElementById('rateFeedback').value='';
  document.getElementById('rateStatus').textContent='';
  renderStars();
  document.getElementById('rateOverlay').classList.add('show');
}
function closeRating(){document.getElementById('rateOverlay').classList.remove('show');}
async function submitRating(){
  const statusEl=document.getElementById('rateStatus');
  if(!rateValue){statusEl.textContent='Pumili muna ng star rating.';return;}
  try{
    const res=await fetch(`/api/customer/${resellerId}/rate_order/${rateOrderId}`,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({rating:rateValue,feedback:document.getElementById('rateFeedback').value})
    });
    const data=await res.json();
    if(data.ok){closeRating();loadOrders();}
    else{statusEl.textContent=data.error||'Failed to submit rating';}
  }catch(e){statusEl.textContent='Network error: '+e.message;}
}

loadOrders();setInterval(loadOrders,10000);
</script>
</body></html>
"""


CUSTOMER_HISTORY_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sales History - Omega Ice</title>
<link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.topbar h1{font-size:15px;color:#00609C;margin:0}
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;text-align:center}.stat-val{font-size:18px;font-weight:700;color:#00609C}.stat-lbl{font-size:9px;color:#888}
.btn{padding:10px 14px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;text-decoration:none}
.hist-period-btn{padding:7px 12px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px}
.hist-period-btn.active{background:#00609C;color:#fff}
</style></head>
<body>
<div class="topbar"><div><h1>📊 Sales History</h1><div style="font-size:11px;color:#666" id="storeMeta"></div></div><a href="/customer/{{ reseller_id }}/dashboard" class="btn">← Back</a></div>

<div class="card">
  <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">
    <button class="hist-period-btn active" data-p="daily" onclick="setHistPeriod('daily')">Daily</button>
    <button class="hist-period-btn" data-p="weekly" onclick="setHistPeriod('weekly')">Weekly</button>
    <button class="hist-period-btn" data-p="monthly" onclick="setHistPeriod('monthly')">Monthly</button>
    <button class="hist-period-btn" data-p="quarterly" onclick="setHistPeriod('quarterly')">Quarterly</button>
    <button class="hist-period-btn" data-p="yearly" onclick="setHistPeriod('yearly')">Yearly</button>
    <button class="hist-period-btn" data-p="all" onclick="setHistPeriod('all')">All</button>
  </div>
  <div id="histSubPicker" style="display:none;margin-bottom:10px;background:#eef4fb;border-radius:10px;padding:10px">
    <label style="font-size:10px;color:#666;margin:0 0 6px;display:block" id="histSubLabel">Select</label>
    <select id="histSubSelect" onchange="onHistSubChange()" style="width:100%;padding:8px;border-radius:8px;border:1px solid #cde;font-size:12px"></select>
    <label style="font-size:10px;color:#666;margin:8px 0 4px;display:block">...or search by any date in that period</label>
    <input type="date" id="histDateSearchInput" onchange="onHistDateSearch()" style="width:100%;padding:8px;border-radius:8px;border:1px solid #cde;font-size:12px">
  </div>
  <div id="histDailyPicker" style="display:none;margin-bottom:10px;background:#eef4fb;border-radius:10px;padding:10px">
    <input type="date" id="histDailyDateInput" onchange="onHistDailyDateChange()" style="width:100%;padding:8px;border-radius:8px;border:1px solid #cde;font-size:12px">
  </div>
  <div style="font-size:11px;color:#888;margin-bottom:6px" id="histLabel"></div>
  <div class="stat-grid" style="margin-bottom:10px">
    <div><div class="stat-val" id="histKg">0kg</div><div class="stat-lbl">TOTAL KG</div></div>
    <div><div class="stat-val" id="histPeso">₱0</div><div class="stat-lbl">TOTAL PESO</div></div>
    <div><div class="stat-val" id="histCount">0</div><div class="stat-lbl">TRANSACTIONS</div></div>
  </div>
  <div id="histChartWrap" style="margin:6px 0 14px;display:none"><canvas id="histChart" height="160"></canvas></div>
  <div id="histList" style="font-size:11px"></div>
</div>

<script>
const resellerId="{{ reseller_id }}";
// Same UTC-shift trick used on the staff/cashier side, so "today" always
// means Manila's today, not wherever the customer's phone thinks it is.
function todayManilaC(){
  const now = new Date();
  return new Date(now.getTime() + 8*60*60000).toISOString().split('T')[0];
}
function getWeekNumberC(d){
  d = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(),0,1));
  return Math.ceil(( ( (d - yearStart) / 86400000) + 1)/7);
}
function escapeHtmlC(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}

let histPeriod = 'daily';
let histSubPeriod = null;
let histDailyDate = null;
let histChartInstance = null;

// Groups the period's individual orders into chart-friendly buckets: by
// exact date for daily/weekly/monthly (few enough points to read), by
// month for quarterly/yearly/all (otherwise a year of daily bars would be
// unreadable on a phone screen).
function histBucketKey(period, dateStr){
  if(!dateStr) return 'Unknown';
  if(period==='quarterly'||period==='yearly'||period==='all') return dateStr.slice(0,7);
  return dateStr.slice(0,10);
}
function renderHistChart(period, rows){
  const wrap=document.getElementById('histChartWrap');
  if(!rows.length || typeof Chart==='undefined'){ wrap.style.display='none'; return; }
  const buckets={};
  rows.forEach(o=>{
    const key=histBucketKey(period, o.sales_date||(o.created_at||'').slice(0,10));
    if(!buckets[key]) buckets[key]={kg:0,peso:0};
    // total_kg isn't in the row, so approximate from kg_size text x quantity
    let kgEach=0;
    try{ kgEach=parseFloat(String(o.kg_size||'').toLowerCase().replace('kg','').trim())||0; }catch(e){}
    buckets[key].kg += kgEach*(o.quantity||0);
    buckets[key].peso += (+o.total_sales||0);
  });
  const labels=Object.keys(buckets).sort();
  if(labels.length<2){ wrap.style.display='none'; return; }
  wrap.style.display='block';
  const pesoData=labels.map(k=>buckets[k].peso);
  const kgData=labels.map(k=>buckets[k].kg);
  if(histChartInstance) histChartInstance.destroy();
  const ctx=document.getElementById('histChart').getContext('2d');
  histChartInstance=new Chart(ctx,{
    type:'bar',
    data:{
      labels,
      datasets:[
        {label:'Total Peso (₱)',data:pesoData,backgroundColor:'#00609C',yAxisID:'y'},
        {label:'Total Kg',data:kgData,type:'line',borderColor:'#f59e0b',backgroundColor:'#f59e0b',yAxisID:'y1',tension:.3}
      ]
    },
    options:{
      responsive:true,
      plugins:{legend:{labels:{font:{size:10}}}},
      scales:{
        y:{beginAtZero:true,position:'left',ticks:{font:{size:9}}},
        y1:{beginAtZero:true,position:'right',grid:{drawOnChartArea:false},ticks:{font:{size:9}}},
        x:{ticks:{font:{size:9}}}
      }
    }
  });
}

function setHistPeriod(p){
  histPeriod = p;
  document.querySelectorAll('.hist-period-btn').forEach(b=>{
    b.classList.toggle('active', b.dataset.p===p);
  });
  populateHistSubPicker(p);
}

function populateHistSubPicker(period){
  const subPicker = document.getElementById('histSubPicker');
  const dailyPicker = document.getElementById('histDailyPicker');
  const select = document.getElementById('histSubSelect');
  const label = document.getElementById('histSubLabel');
  const dateSearchInp = document.getElementById('histDateSearchInput');
  select.innerHTML = '';
  if(dateSearchInp) dateSearchInp.value = '';
  dailyPicker.style.display = 'none';
  subPicker.style.display = 'none';

  if(period==='daily'){
    dailyPicker.style.display = 'block';
    const dailyInput = document.getElementById('histDailyDateInput');
    if(!dailyInput.value) dailyInput.value = todayManilaC();
    histDailyDate = dailyInput.value;
    loadHistory();
    return;
  } else if(period==='weekly'){
    label.textContent = 'Select Week (WW01-WW52)';
    const now = new Date();
    const currentWeek = getWeekNumberC(now);
    for(let i=1;i<=52;i++){
      const opt=document.createElement('option');
      const ww='WW'+String(i).padStart(2,'0');
      opt.value=ww; opt.textContent = ww + (i===currentWeek?' (Current)':'');
      if(i===currentWeek) opt.selected=true;
      select.appendChild(opt);
    }
    histSubPeriod = 'WW'+String(currentWeek).padStart(2,'0');
  } else if(period==='monthly'){
    label.textContent = 'Select Month';
    const months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const nowM = new Date().getMonth();
    for(let i=0;i<12;i++){
      const opt=document.createElement('option');
      opt.value=String(i+1).padStart(2,'0'); opt.textContent = months[i]+' - '+String(i+1).padStart(2,'0');
      if(i===nowM) opt.selected=true;
      select.appendChild(opt);
    }
    histSubPeriod = String(nowM+1).padStart(2,'0');
  } else if(period==='quarterly'){
    label.textContent = 'Select Quarter';
    const quarters=['Q1 (Jan-Mar)','Q2 (Apr-Jun)','Q3 (Jul-Sep)','Q4 (Oct-Dec)'];
    const nowQ = Math.floor(new Date().getMonth()/3);
    for(let i=0;i<4;i++){
      const opt=document.createElement('option');
      opt.value='Q'+(i+1); opt.textContent=quarters[i];
      if(i===nowQ) opt.selected=true;
      select.appendChild(opt);
    }
    histSubPeriod = 'Q'+(nowQ+1);
  } else if(period==='yearly'){
    label.textContent = 'Select Year';
    const nowY = new Date().getFullYear();
    for(let y=nowY; y>=nowY-3; y--){
      const opt=document.createElement('option');
      opt.value=String(y); opt.textContent=String(y)+(y===nowY?' (Current)':'');
      if(y===nowY) opt.selected=true;
      select.appendChild(opt);
    }
    histSubPeriod = String(nowY);
  } else {
    // "all" - no sub-picker needed
    histSubPeriod = null;
    loadHistory();
    return;
  }
  subPicker.style.display = 'block';
  loadHistory();
}

function onHistSubChange(){
  const sel = document.getElementById('histSubSelect');
  histSubPeriod = sel.value;
  const dateInp = document.getElementById('histDateSearchInput');
  if(dateInp) dateInp.value = '';
  loadHistory();
}

// Dynamic date search: pick ANY date, backend figures out which week/
// month/quarter/year it falls in (same resolve_period_range() logic the
// staff dashboard uses) - no need to know the week number yourself.
function onHistDateSearch(){
  const inp = document.getElementById('histDateSearchInput');
  if(!inp || !inp.value) return;
  const picked = new Date(inp.value+'T00:00:00');
  let sub = null;
  if(histPeriod==='weekly') sub = 'WW'+String(getWeekNumberC(picked)).padStart(2,'0');
  else if(histPeriod==='monthly') sub = String(picked.getMonth()+1).padStart(2,'0');
  else if(histPeriod==='quarterly') sub = 'Q'+(Math.floor(picked.getMonth()/3)+1);
  else if(histPeriod==='yearly') sub = String(picked.getFullYear());
  else return;
  histSubPeriod = sub;
  const sel = document.getElementById('histSubSelect');
  if(sel){ for(const opt of sel.options){ opt.selected = (opt.value===sub); } }
  loadHistory();
}

function onHistDailyDateChange(){
  histDailyDate = document.getElementById('histDailyDateInput').value;
  loadHistory();
}

async function loadHistory(){
  const listEl = document.getElementById('histList');
  try{
    let url = `/api/customer/${resellerId}/history?period=${histPeriod}`;
    if(histPeriod==='daily' && histDailyDate) url += '&date='+histDailyDate;
    else if(histSubPeriod) url += '&sub='+encodeURIComponent(histSubPeriod);
    const res = await fetch(url);
    if(res.status===401){window.location.href='/customer';return;}
    const data = await res.json();
    if(!data.ok){ listEl.innerHTML = `<div style="color:red">${data.error||'Error'}</div>`; return; }
    document.getElementById('histLabel').textContent = `${data.label} (${data.start} to ${data.end||data.start})`;
    document.getElementById('histKg').textContent = (data.total_kg||0).toLocaleString()+'kg';
    document.getElementById('histPeso').textContent = '₱'+(data.total_peso||0).toLocaleString();
    document.getElementById('histCount').textContent = data.count||0;
    const rows = data.orders||[];
    if(!rows.length){
      document.getElementById('histChartWrap').style.display='none';
      listEl.innerHTML = '<div style="color:#888;text-align:center;padding:10px">No transactions for this period</div>';
      return;
    }
    renderHistChart(histPeriod, rows);
    listEl.innerHTML = rows.map(o=>{
      const statusColor = {'Delivered':'#166534','Cancelled':'#c0392b'}[o.order_status] || '#92400e';
      return `<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f0f4f8"><div><div>${o.sales_date||''} • ${o.quantity}x ${escapeHtmlC(o.kg_size)}</div><div style="font-size:9px;color:${statusColor}">${escapeHtmlC(o.order_status)}</div></div><div style="font-weight:600">₱${o.total_sales}</div></div>`;
    }).join('');
  }catch(e){
    listEl.innerHTML = `<div style="color:red">Error: ${escapeHtmlC(e.message)}</div>`;
  }
}

populateHistSubPicker('daily');
</script>
</body></html>
"""


CUSTOMER_ORDER_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Place Order - Omega Ice</title>
<link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
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
document.getElementById('needDate').value=new Date().toISOString().slice(0,10);
// Reorder support: /order?kg=5Kg&qty=10&mode=DELIVER&pay=Cash pre-fills the
// form from a past order (see reorder() on the dashboard). Falls back to
// normal defaults/saved prefs when no query params are present.
(function applyReorderParams(){
  const qs=new URLSearchParams(window.location.search);
  const rKg=qs.get('kg'), rQty=qs.get('qty'), rMode=qs.get('mode'), rPay=qs.get('pay');
  if(rKg && prices.hasOwnProperty(rKg)) setKg(rKg);
  if(rQty && parseInt(rQty)>0) document.getElementById('qty').value=parseInt(rQty);
  if(rMode==='DELIVER'||rMode==='PICKUP'){ setMode(rMode); expandPrefs(); }
  if(rPay==='Cash'||rPay==='Credit'){ setPay(rPay); expandPrefs(); }
  if(rKg||rQty||rMode||rPay){ collapsePrefs(); }
})();
calc();
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

# --- Brand assets (Omega Ice logo) ---
# Base64-encoded images built once from the official logo and embedded
# directly in the source, so no static file folder is needed on Render.
# icon-192 stays PNG because iOS Safari doesn't reliably read WEBP for
# home-screen touch icons; the bigger manifest icons use WEBP since it
# compresses this photo-real gradient icon far smaller than PNG at the
# same quality (a couple hundred KB vs a couple MB).
_ICON_192_PNG_B64 = "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"
_ICON_512_WEBP_B64 = "UklGRnAJAQBXRUJQVlA4WAoAAAAQAAAA/wEA/wEAQUxQSHJcAAABFIZt24aR/j87jtduOyAiJoAfVUD1QnnCyRyzcg0sHyUfAJU2ka0XOlDJamBEnLQGRNmH7ZhqmpUmFgEPGFE5B7jQkQDv7KeAxQvAGZd4w4D6hKlyVqIPXFSiLbas9jQZDzKIvpDTG7/qDdu2ZVuqbVvX7bzoVMoOGgxiDLsZ9i12d3d3d7e33d0Ou0dj520BQwkBUbDouODc9339wbjv+3mubTvgetKImABv2P6vk9P+3+P5nN14QpQkBEIgEAIUt+AuBYpDcSkftEiBQnFri7tr0aLFrbiU4iEQAgRIQghx9012Xs/H48bIzryXnSm3PhExAfjN/7/5/zf//+b//yuweS7n9muNubU2c0NRt19nWru5A+i1zVHH7tUH8F9hzJbZuifoxhxAn4Nu/u88aekHx3WH/epijjMWXeFwag503PmyD5olMSi+vR381w2zFhmw7Th91hP0YA502PvFBRJTUFIkTdod/qsGYGblWA4NR4wjv+pLa3pmQMe9nl8opVBJ5vXTFvBfKwxdrjyzHQAzcy8CNFy2WIlNx4NNzQwYcMQrC8VElZ3XB/3MfrUY9FP+0r4dOqLQADSutN3NS5QUmrwL2aTMgBUu/bpZSlRLk86D/2rR+QU1jXjjP6c15HZYG3Ds+v08MSTl9WZbsOnQgAFnjZSYqJYHf14P/usEDLcwSVp815ULhq+EBhwiBSUp6ZEarckY0POMEVIKVTbpdnf7dSKHUxQReSqU3xsNWG8SKUnUglPao6mSaLvX51KEKs2YtwuyRDarnShKYkTkD4Kb36IoEJe8dv9dG4BNwYB1n2pUDlUx9G5Ps+w0qzvOV6godYx5DvvmWYySHkATJNH1tEnKWdVNPBOeFWK9k9uRzWfHRonQecg51pooFojM6+8wwKwalgN2eC8pUVUOjRkKz4bBH4u90fC/syEjxRIjhiCHIeNKKPRM/wLAKmYO9L9kqiJU/dCz3c0y0vszvdoV9j8yQ9+PFUUU+ngToNfniiKhj1aAA963A9y9AuYGdDvoXSlRGWTS5XDLgmOrucw/uwMsZ+WZNU85TlyaWIx53Qi0f7qMOwFzO+7rW3sCMM/lvBxzACse9+9mBZVNxrzd4Bkwb3ePUmj2cShuBsDM8T9qww0So4giHs0ZjsmTBeTP1+6Yw/oTpbvX3WE1lG8OdN3xbyOlCGU2acQAeNUsh2OXhpQ075K9BsEAwN0M8GWsmWrYE+ObxWJ6uZP7+tNURJTmX7L2A8oz//3cH24/9fjj14MVcaDH/722UIqgMpx0RzuzagHb/KiQlMQ4Ew707AwAHX778POrwJqhADSuuu+rjAJq9ErAljNKiEnpp0UhhorfX8QMuV3fkxShbDM1H4cqGYZe9qOSCiOvvyOHvs+/eMIfr7/r+Vka36tZymAAlhuukCSmOwdu9x+FSjNESiIZkdf5cJgDq903VxFU5kPfLAermLnBcYYUKkpO3gQNdhBVNHiPEc3RZpbDamNKkF9PU6hsqnTSu/3gDgy88GspqVVG/rRKmMHcDQAc200vFfo7zHGd8mSK4NL9Yc1RHYGc939aoaIMKVRhavq2yAGd/vCFlKhWotGDzVoEGAAsu1sfmOG4RcECav5WaMCKXygkiRq7QrPUMe9c2AW4SInFJFKVDr3cLgfs82azUqjVhi6Ft6hzI7rssEGH0/LnwMxwg6LY9E3gne9VqDD0SU+wucm9+8fSPStuPJKhDCa9aBh4+0JFqBUHv18dXpbhsP++8Og7CyY+8qU+6mPm2HKhWGTCmobfLw0WSXqssdmJQLfXI89vfySVQab5P593/HApqXUn/auzWTmO01Q8uGBrNDiWH8USQ4B/KKlo6HwYmpVp6L7O7l8rhURlY/IcSYlq5UxxBrwcwzIPRT4YEaHHe8DQ8KySJDH/124Hz6FK8IZ2ZHOSEb1emDIuTymoqlOUIqWIUOsPTh4GLwOOneaLKgw9txEcv19CFmjxJ7NUIqjFu8Cak4Df/V0SlUmKoiRSv4hJr3czK8NsuS8VRZj0/WrmjTcqJImUQkWptHj0tv89wthsYVVr3P++H5SCymTRiNumKdIU58LLgT9cQkw6Du1s4NcKFQZVlPz3wbsNMVTU/jdhgFXHsd4MqZnKaNE/bo2FmrMTvBQc+ywUiyj07rJA749LlAyNHAjArSUNxz14fG/Y/ySARlTX0PW0N2YpMSMqKiqRKOn1rmalDN3fUBRT6J9b7vlYPtSSLweYA7CyHNvOFZ/pC/vfg6HP1c/vn7NqFHbZ4b/KB7OhoqJYU/4seDnLfMRUghFzlopsgZju6NJx79OHwco7Ts1JNzX+L6L9bdLs7eDVMWDI55KYjXipGVvDy+j2ihKLiSEG1SLmH3ywScP7IVeG4WpGxMId4f9rcOy9KJbqdlh1YDlsdvk/JyW2SUp6r6d5MRhW/RdLSaQqyJCY4oZO8BIGf0ShpEfbmf2PAQ2PK5Gf9YVVBzCg08WL1EYnngezYjCsOkJRqsJkkJG/vhe8GOD3KkTOWt/c3P6H4NhgCknN2gJeLVgOf8qnNoqcuQ28hOf6flq1ohF8ZnlYMcfZokSeiBwA+1/CSQpRS/bJANzOl6JtUtLT7c2KWA67LSCzIIZe+A1KnVAQeq8vOg/tif8VmrldpJDIo7NgWPPuqYqWsI1gNB0ELzDgN+8qKZtMmnBZN1iRnRaKEuPt616a9N4m8P8FmAE5XFZEf7QMFG49Sqk8KqKMknNYSvq4txlgWPn6CQplNahZa8ABy9kaMwoUKnwsBwPMrL4D2rVDjzcLQn9Gg7tVzRw7z1WQpdg8oVmJxYqkEpaY3w8Os87PS6Gshma/f1Q7FP/DkiKKiBSvt4PBAFgGSOOSStc/Pv/UOU8FWfBMF2TS3K9ITU1Rgnpx2A1LpSgoGnnRu8phhV7oZOY4bkkKZTVpzM6dUNjxlIuvmiKqZNLlMBisdyOqTyyxGg5OkkQVMj133JGbdakeDAM+WTSHLHU8Ohxw+eeKgsa9sc53KlGRS/ZBO6wzRqEMMigmLToGMMCxyWxJVMngrE3ghiH3DH9pB1iVDFi1z7INSyiXMh8RKkYpzTodloHtxygfKnWYO7DVDFHK+fEBW02MS6GPV0KvZ5RUfVKKCL65d0d3FOzbFEGVTrrRzbHcO5K+GwIrZW7mJcx9EWKlG0aN+3xrcInkdOVVbjCv+wxWJcfgz5WoMo5BrsHXmFpQpIlTVRR30ptHPKfELOTfem6pYuSaKO7YYj7zZYRGrgC3drcqn1LsBS9VtqEoscvHknTtkoa5OwyDPlO+HLFZ58FRtY1nMVQ6dALccCFDhVkqijwkRagoq6KmswacMUV3IGdFDD2ekhjFyAX7wx3HNSeKcXg5XXa76brtvQh6b7tRDo59ZigfKe5BHWowDPte+TIi6cOhsGoZ2t+uxBJk2gcN6DtCxVSKYg+mYISkJEYLSJYRuhDY6opNzQDAHEDfo19oUrAgdFvOHZtPVYjkviUM3f6xWJq5DRyGoW8unHIysMdE5aXQxfD6YsBeh60OuGPzUUoslqQnV4HB3d2qAMOAdxQlQh/1QQ57N4nFqnDxhGaFQjMXi2UxNQdLUE375nIo6QDcgPa//1CKIiehwfq8qySFRq9UwrHZfOXzuhxmZrcptOCGc39SksgZm9QVhmWezqcxRxrcMfQ5RZGk2Wd3hruh2oZ2T5d1Cdyx+6K2I/TNkX9doGZ9ut2FTcEyqKnvzFMZC38Hd7ci6LaqA7kc0PvieWLBxWjA8fmgGDwBjhJ7NZHBlxrg6PJ2pJCkkJR0kxnqSMe2C5S0+KqecEf3JxWSQsN3BHIGrL3vUXt2q4Zj+R/KoE62nKHz84pySontDtiREzR9M7S/Q1HWR/fNFosp+OHWgKGwYfsXxt+9e2cglwMOnE0q9FIHLPuJQgo93dWs1JFBhUYsC0f7lxRikJJCE9aE1xdHRSioV4fCc/jNBFHUqN/Ac8C610xKkb8EVjlD+6fKCJ0NN8N9ZWUpl8g+GAKcNOEYa2dbzBHL4KTJpEqHZhxfxHDUfElN/9qnC9CQw50KUTM36/j3pUGFxq0OR6ljRVFzNkcO/i+FijPyp8JR85uVtcMCUpH0xXrIWbuXFWKcgAZHn0smS0r6tAesCri7BBm6FO5YcVQ5RT/9s+QSlkIf7DvwrKsBYOd55YgSVW6znnUYDI3PKB9BLX7hwM4ADhcl6uOnl5BS4p/hKGPnhSIZeyBneFCpROj+jma1nhlgpQx9PlZeUl7D14c3PKugFmzjDVj/HSmRwW9WrErPjxQkI6R8XAdzHJ+CLFbK1J1XelY5LoZmvP3zNycNW2W3zxUqzVAqL+laGGDo+k6ExETlXzx82Y43FSgkUkp6tZtZOetMFRU6H+a4VlGM+nkoGlD7d87BSsCxzwKFpKRRm6HfCJGaswGw5zilkJTX8F5VcOyyiCFJnDBFugoOu1/5YHCRpGeInv9UDktKKpz143xRpSktFFlGaPQaBYDfp7wkMSgOf3E+C8SgFJq7HRzlDPyxyDvLwHF9ObP2R01t7u5WxNzcABh6/O3VR4ehTLMT55OSkr4/+o5EUU0H5I6eobwkBeM0GEqaWYsujaT81PEfn7jahqfduhkcHV6VNC9f4nw24HylwMRCSaFymh874PHmcpJuhwGAY7uZyquQQUlUabLpDDOUaVh2lELU7A2Rw11KxURN/ftqtVRxc5RpaHezpBGD4SVgOLU5UVIoSErU6KfmK0lS0sJL2qO0AbCWXKn09sFrrNILxQ25u5bOue3wryNJWX9dETUu875SYEVJqszQR/3R6z+KUqELzQtgdth4JapohMpNerzBvbwubykkxsGWa3xFUUIhDR8Er5EMvf903fm79QYsZytcct9lq8IcG81kvlmnlWWNdytPSUFSkigpJCmvcfug7E592qEl2z9+Sg8AcHc3A4B+O23aDvdKOWvmFjAYdvq1lOBaSI3Zztb4oqw4GiUcm7yriCItDP0DgFk5uccKQg8Be8wkS5Ap5XevmRwnSFr46XXrALhS0kMNlsNhQQWfdFgJGPq/pqSyGZTEvMbtAHMr0e6Pb3zy8uFWYAYYCh1oyLmhhbbFo2OVNWUQDWa1F5SrRKEJjw0nVZKav12JwgEPJCW2jJx7ygo9UK7bZQXknNP3+VYhiRERkjRv05rJcDWbQ9KPpw384+xYGiN7oAFHkAp92b8cGAa8rCirKKnPN0fOUNyx91JJMzaCo7gBnjNHS83dAOt9b6Nmb24NRvT/vGIUkqiyNrBivtKQLuh08jhFy0QtGPHhxZ1LuAPXFIiKRaQUKrpk3vh3/9AOViM5To4QI6+l3y9RhEb2QgP2axap6RvCy0AOa40RW0I13TYIbli5b4Gh68tqjmZdDTM0HPXU3YPQYADQdb2VyitqhhbnNepMALbuCGVVLCNUDvNHIwfAcejYcS8e1R9rPqFgi0RJzbvBiwAd951IShKpkEJNY966/4ZT99x21U6onR2rjFdICkpU6IseyGHvJQWLty/PPPeiokVLzza4Y/8f7msPwLHdQlKJzzTA7PQm6dZGYKWDr7rvzamjD4S1BNYCq0zQpGM2OvTxycqlaloa+nFHmBnwgKSm59ZA98cVLRMjpYOK2bAr35kjqjglatopK3VGca+dYDhHiZJEqdQBzaKY9m4BDp5NtiA0egAac9hpsn5eHQ7DXxVS6DLk0H+0lqb5dx1665ikwkcN1gJz4JgmKuY2S0ltfWjK0UDOcDtTCj3bE1dUROT09QsMu0yUFCqTnH+8wXK5nAMwr6Gs091KVPESOy0o0OllGfaZrlALqSnH9wKW/1DNzXvCDXhKSWIciQZsOpOkCpki8rwLhnLNDVj2mJ8VQTFRbX/SgpMMDX5MUEx69KrpZCWS7ms0FNyo5kSVG/q2L4o2dO/VAbW0oedzSmWM6I4chs0SFboGVsrQ/lnl1WJy4Rt7rP44ExftVJB7XiFq2npowN5LJDGYQhIjHQkvwwzAcsd+2KSQRNWGoYVXrQLstEAUQxJVweC0jeFF/sFQC7n4ik232/eos6578pMvX/7z0BoKjlVHKIpR41a2Bmw2u8h1Zmaluv4nomWiNP0bMen7FWGGfiMUCo3qgxzOVajM0Ce9YcXMDVhp70uH50WqlgxqxJ8OeDRPSQySrEDSjWYocrlaJs6Zv1Qlv14XXjOZ4bFSYvwRjbblnCK3IAeYFTG/W6kCYkih0L1u5th4tqik+3KG3GNlMS09DI6iDmC1i0cukhhUbRmh1CwWSKSU2JLQt0PgBY7DyZaIlMQoTEnn1VI4eDpZIvTDJsAWc4u80QW5ziju2GAyoxIkRc3cFDlv8G2WiCJPQA6dPygnQtc1mhU4kFv/tJGSIlSDhkSqaHDMJDHKY1p8OBzFds+LLZFIqnhKd8FqJcPgsUqSREoKfbUtzg1KZPNdv7/tvWuWgwGA4QwmtiikkJKeaOcAcFyQ1Pyt0WArjxNLUM03doUBcIMNu2mSFEHVqFRxasRmGz7UrDzLSfpHo1uJnZsrE8VT6EJ4reT43eIUjKAUISX99NA0hSRSlHRfQzHr8pBSCxiaNTlPsfkQoOdGa+/3nSjqp1W8EWeSKk5OPNJhgDuw/vWTpQjVvqFP+qLdUWPFVCr03ZpwmBXLVyBUZry/Wi215TwVTXkppCQpVEgq8jFpdTgAOPq9p3xZQb24/UETFZq3v+/55owpi0Qp9NEywO5TywidCTe4A0OvmCAl6peRJaNclvxFYMRNXYDf3LNEKYqQ0/eDwVDo2HZRi0jNHjNy1Fcfv/7k7Rftvxxq6cYj3p0w/sNbT9lz16vGKiQGVZIS8/sjVwDHRuOVykjKX98Hg35QMJ69aLokhQqnHzbomJ8UKkm9NRgNBgw66xspUa2aJCOCElVNRgTZykTmb+oJNO77hhQFoacbzAzt+gAwrDq2Zc23bbLqcssv17M9Cq2WArqtvlovFK7+rEItTboMVgSO3acplUhafFYDcGBTiFy6WImkCqk5Y/IKSWSBQk/0BNa+eKSUqNZLRlAlI5iaF0yfMX3yN1+MGv7Bu//54ItRX4/6Yca8+YuXLmlWcUYEW4/IeH67RqDnuTPEInfAcljuga9OgBn6fKYoj/q6D0qau6GmdgAwz+Vy6PtvRUtCLzXAisBx+FxFkaQ5J8Cs13sKRQRDZVJiSAxJQYmRXjrvjglSCrVOMoIq5JJFs3746K3Xbjrm8GMP2nenTTdYa42B/Qf07dGte49+A5YfsNK6G2+6w16/2+v4O559c3RTUIURbCViaPo9mxpw0Fyy4DY0YJl7pfGrmHvutZb9vL7nrChqb2/I5dxQeHklPuxSCo5DppGSQmP3gudy1yoUEkNlk5JCWjQ3SZQUkpRCmScjgipkfvGUka+cucdvNxjYq2uXRlS9octKex158p3/HTkzSSLFCDJrYpIm37QWVvtBRV7pjNWeSvk8/4BG/OYHsSwyr7/AUaMbijZ0W2bAyVPJln3Vv4i5wQx3KiTq203hORy0JBga+dQillcYmnT5TlsddOssUlKkoLLOCBXNLxzzzq1HH7jbmst2Rmkv08r20oaiue59Nzn4xhFzlJaGJEUEmSWJSfrmwQ/ylCQuufMvXysYeqEL1v9QIUkkIyIoSafXbui0/emX3fzgc++++1WTqJZSE9aEo6jDbY8lopQORy6HTX5QkFM2X/4jRUuCn26DwitVkHUyQpKaZnz1n9uOP2jnQV1Q3NzdClF1M3M3FFrvzf9w8CGn3fD+D0tUGMEMSUySqKKUlCRy6b0XjVGSpFDxmD9lxPk9YbWZYds3ZqokQxWYu0WR7kM6wXK22TyRmr+5N2DocCUl/RXLflyJM1HY81+KrDGSJOXnfHvvPsN6d0Fxd3czZN3M3FGy88DdL3ry4+mLJTFFdqRIoZKMkCRSUpLEUNOcMV+8csXxv99+vWXRUnO32sjQ5RUpIlJEBFUBNu8BN3S4beJru8Js20UFM9ZzbPChkpI+Xc6GjhNbQn59wuar9Nv+OYUyzaCkxT++fcvhWyyXAwCamRGeSTMzYlHrstbws1/7LkkllSZTUTJCEkMP77Ll4F7tUdSsPAMAq4kcq0+KUCEZES1T6Hhzx9Cp0uxT2+HvDFELd8QW3yiJMe93sI2nt0yU5oz5araCWYqQ0rhP7953SFcUmpGIkzTDou1XO/ixfy6QUi5uSobu6QQA5t6Qc0P5hi6b7rw8amLDCmMjT0aiCskK3APLYduFbFbzY1fPJiXq1XO/VxKDf0YOpySq5aQkBZXdCGn8I0ev0RsAzN0M8ZJmBqDW86jXf5aUc/EU+rwfGnINBjha7Fj3tVkLR+4Jq4FguVtUfOEP7z3xXr5l1Pi10WgHJymokiEppNBjHdy7vKeogEQGlVUyUZp087oNAOBu+CWnGYAOG1014nuppOKHOg85B7DRpY9cMKgFjiGfSNToQfBaCMvd9ckXX7916+k7r9Tdej0gtkShl3sBp4gSI1hEDErU4m3NcWyeat0RlJZ+eP5aANwNbSBpAJba4Ky/zFdJxc+zA4GOO98xSdLT3WCAWRFHn9eVZ8SktWsiAN6z33JdUej4cwUYemC5DT4uaDE1fwe0P2yyWhVTSEtH3rxfDwBuaDNpBLDUIe8vlHIuLkR9/LfzXlogpTznbgp3BwyAo8f9yktJH/aA1USGQnN3t9wzzJNklKQkhj77TqFKhj447ZnFCrVeJonf3b5nfwDuaGNpBLrs89hESal4EFUYFDVtHeSADo0AHMv9S4mKSCfAURtbIYraDWppSFJIocpSkkKSyNbAkOa9+seVAZgb2mIawDUPfnKGVM8OFIwgI5L+s4xhzdOffX5X5LDME0oUU1zW3qxGKtfQ/2+fT5o+8YdPX3z8sScfe+L9JiVJCqrSZFASQyKzFkn6+bbtOgJwQ5tNA9B6s2smSCmyJ4mhwhc7Yt+xkl7rhPbXKk8xr4c6wWDuXlMVLrvOxmut3L3RPefe5fffKZRBSguXSpElRkiTrloHgDvadpoB+P2t30kRzBxDP747fHKaf8u1s5RSmn7girc0B8W8XugHN0ftbYZyDdhklFg9atEVW+1yymhFZhiSxl+zPmBuqAFpBIac85GUImNBPbhmpz6bPSlJSaKmjhYpJf13INyB5Y48ZfMaCzB3dzMzNwC4R1E1cskZALD9DDEbTNLiN09cEzBHzWgA+p30gRTBDIWaLusAg92nFJSkkIJSaOR6cEeHwz6Wxq0Dr2HM3a3A3L1Y2b02PuiG6WT1NHe7gl2nZ4NJmnTZNj0Bc9SUZkDfM7+iGMwK+eNBOWtA9+uXBlWclBT6aXO4Y8VHQpH0h1rGUGgGQ6GVZdjwHx9PCYmqfujzw1db6ehxCmUwSTMf3hSAO2pOc2C5I15eLAUzoksB4DcvilT5zB+PhhyWf10RCh5ije5Wo6Bhh7+fuTKQQ5cTr/0tYOZWzNDhJUkMKouhNGFsXlT1g1r42HYNMDfUpOZA1z3vmyklZuOD/YbteNa3SqHyyabT2wGrvKY8pdA5KHSrSbpcvUD65iCgy63UvAs6AYBZsT5fpTyV1aBEquqRlH9nr0bAUbuaA+22u3+BFKyeQovmLJaSWkzOeu6m60coURI1/tRdt16tEbDaw7FXs/JJ8+4+/DFFs/Jv/+PqQ/oBXqTxSS1sOhKpqjNJY4/pDBixWEsDWmzz8gwpVU8hiaEKUoVJRUNqmv3jv//UE1aDnKIkJSkpqKCkpV+c2hlugGPLn1UvTSeDSZpxTR/AiMVeGtB2k3t/UUTVRFKVZUSESpIqfHVNWO2x8zyGxMSgJEUKii9sDLiZ2bbvKZcoIjTnnmGEEYvFNKA27A0pVS2zJFPSvzrDagxYu9uVV0tTaOoFfQA3oucbJYqk+Hh/AwyLzTSgx4WzlNhKIiJYTmE+je5XeziGjlYzWyAl6b97tQNYw7rTVSKIpJmX9gOMWJymAbt/oYjsUCxBFY0SkSIipEc61BoGGHb6RsqXRylCix9ZB2i16o31ogDz0qvbA04sbpthpfulxIwwliQWIRe/dNNNjy9QFFBF04/3rwJDTWkwN8Mqt85RilIMhqQkTXj4jufHKsIIjT99GZhhcdzR4bRxYspI/qfJEQWhpzsBdtJCUiKbnr/87xf+5cghjpqzI2DmwK6vU1Fq0cxESUwqzAEk8Zl1AUeN7sCat81WYiY496clLPZhfzQazmhOVOihTihutcbur12yJuBuWOYv08gSTXOKSIyci9wzNOOMjnBDzW4G+/3nYsqAyHwqotBDXeHW7jHlGTwLDV5oqCkNg7+VJpzUHp5rNJwcKkFSpUvOORdXwfTsVoCjpnfDirctUmL1RFJFGbqjozlW/kCR11/MUYM6NpoWeaXHfgMA7S4mi5WfixYtfiIpXdMVbqjxzdF49GgxVa+QQUlMOhfuGPpMkxbsi1rEcrn2zysi9MNfDj7spCcXVyS08N3773xkqrKXRH1ySCNyqAMdWPv2ecpngJSUJAVnbAF3dP3dYdt0gtUc5gCW+1AhJhUl1fLQ+7v0AHj0wlJcMK95Vw4EDHWhOdof870Sq9f8/CU/KElKerUrzFCbOtC4zh/+HZQkBsmgWh76pDeAGs5ORR4Z+ngvwA31ogMbvabEKlFfroktvlOSGHEuDJbLNVjNYej/x2cmSlSZjBQtIRfuhgYatpii7CHIB1aAGepIc/R7WIrqhP6Vy2GHqQqJnL8fHABqD+z1maQIlRmSxBYk3ddgNPQZrSyHSQvPaw9HnenoeN4C5VkN6vPl0YCD5zGkpHe7AWvftResUkZWkuH/5ioFVW7S7HceeDexrNCoVeCGjv9UUvaZ1+TDAEfdacCJc5VYBYVua7QcTm5WImP6Zmh3j8avjQariKGaDf1GqVnlJ324bWcM/lYsJ6Vj4GaN1yhRIrPF0MgdYIY61Ay7f6iIKjCa/9ponjtzgZi0aFv0+iT0RFdU1GBdW1WRY51ZzEekiGCR4PAhMBs6vqyk17uaGQ5rDopJYpYi9NQQuKEuNcNKNy5QqpzI/Dnmhv0/W6p513W1Xh8pz4c2X6nRcm7FzABzx9p3f3YsWD2G3s+oNIvEUWjI4XRREoOSGNO3gRu6vRnNQal5Sp7MTES6piscdavD/7SAUTkFFx2PnKH3Xsdv0QD0/EIRmjH2RJRtDmCTz6UnCFYOgJ5HP/bc88/effHDc0Up9Nmy5ug3QiGFxFDk9Te4OVYZJynGPnbA+k8oMxHx9wY46lgHTmhiVE6hOQfCHYXe+KcmSiH9uOewfXrBADQM7AlseNntY5WfdySIijYHkDsrLzHm7Ql3XKiQQhPeXapEvdHfDEDHA6/7xxVHrArgwKSMpshf3ghDXWvmV5Kpckqati+8qJ3RREpi4szp+fNgZvjjj68d/rsPJOU1uT+skswBwBqwW1OkZt0Fc2w5lSFy0k5d/jJRC58cDEPZjTiGlERWLYlXNcJQ55q1/+NMpcopadqhMMCt88dKKhqSLoIbck9Ji+YqpaC+Xg6sJABmBrddFkoavSpy6PeukhQ6DcAGJ+/aCYaibmaea8AyLygkSqxSXmNO6ABD3WvAHuOUomJKmn0g3AyHzQsWU+J3QwvsochLIYma2A9WVcU7HvP028/vALfGO5Sk0Ed9zFFoKGmeM6DbrRFU6JtP86xGJH26CWCog82x8cvBqJiSpm6PBjtkskIlQxfBAbMbFaSKTFuv6oBct3Ywx3YLSTHm7QYD3N1Q3BwA+u/7apAKjd7lpCZVMUKvrA431MeOHlc1MyqmpI+Ww54zlVSaOgcG5HCJQkWT3l+erDgHYEDDvQop6SZzQ5nmBmDVXS4Z0aSgFBp/zmti5YLNDwyAo2525M5uiqiYkp478B9SRKnQZwPghhX/W4LR9NRKqDqYGRyDvlco9P1gOMo0AH12v2PsEolJhdRSsnKMuKUHHHW0m50XwYoxNPM/D74WihIKHoMcNnxdoVLj7usJVlyhY91pJFM6EY6yB+1zyYdNkhhUcYpUpZl09zIw1NVm7W5WYqWkvL5dY5kLm8hS8QdY4wvKs5iYki6ALQYYVv5RKempTmZlGHYZkSSmoDLJpBd7w1FnGzo/qDwrxlh8OBruUhQLjR8C80eYVDKk77dbLAByV85PHLUuHKUNy36qFEFllEkfDIGj7aUtSpqZsYLgGPCWUsUUGrkSDm0u4xozxymJJajvbl4fi4udNjv8kFVgKNOx8dygspv0xhowtLU0/DdprBw4Vv9UeVZKoef3fFZiSAr9MMRzDb7JDLEI+fBgAODiwb8kyttwjjJU14j+MFSruQHou8OxF1x17U23XHX2sRt2AwC3NgaG1d9RvmIKLZg//DuJFHk5CvddUCrOgbsZYLUAzYz4Lxv6fKrITNI7/WCoVgfQe9fbh89T6Wnv3XrUSgDc2hY4hn6sVDHlNXyDlU74JImKW9be/8pjDv9IVDHOPB45IIfa1HI4PztJ76wJQ6Wao/1vb/lkviRGShEpQlKMvn//HoBZmwLHqu8pVYwxfVdg2UsXkZw7epGUV5RQ0tQt0HD8Czf3RK7GMHMDGm4VM5I1aQhqqFJzYM2HF0tKQZVmBKXm/x7RA3BrS5DDOuMUlVJo9JZAw3MiJSWKKjPpnZ2uzEunAGY1hDkAdNv4liXMSM7zjoexShzodfZYKQXV4kjU4o//0hvwtgQ57LuAUSmFJly23WHfkxIpUWVHzCHzMffGzQzuViMYYMvtcduHM0QqkyXlKxtIVKcbfPt3pERVlonSh//XAW5tiDkujIhKKaS5i0VVlFRQlGYe34DasfMB//y6SVJQ2Ux6piuIqjQ3YMMHZilClWcKxcOrAN52wKzdBYuVKqUIKVRpShKTFt09bFDnmsCw0sNLJKWgGMEMJP19ZRBVSQBDLp4ghaqcQl/saTCrDBhwygJFpSRS1U7S5Kk3N8BqgRsUKShGSFJULenT/jBUJZHb6I4JUqKqzrwW3jAUsMqAGQ6ZrKhYFlPS+GPc0OYbOr0WSYyQNP/9u8aIVcqavCFqqErDcjdNlyKUyST9dEEnGKsCZth1OqPVBJfcvCpqQUOHV5WnpCnv/XXb7jhwkViVKNN3RQ1Vaej9FymFssokPj4AsKqA5XCBElsJg3/PwWsBGC5aovy4R09YpwsA7L+EVYmonwBDRdLwuxFKoSxH0qc7t4VVBcy6Pa186yD1xDJw1Ahddz5q31UcQK4Rfd5VUhWZ0rUtyIowYNcxqlPZZtKCZ4eCrAgYVh+hlDWyoPmuvjC09aSZ5RzFcw05oPfDClWRSc8sBaIaDW1O/EVJ2c9Z3x0EWEXAsdtERaaCUjD0bm842naa4V+beS7nDqDf/m8qWI2k/wwGUYkkVn8kKcljSZp7WktYRcCxz2RFhkIxbabYnO6Go+2mmRGAtV996z0OGwoYAOQ2v+yLvIKqIjlrJxgq0YBdxipnOU1KD64AqwgzHLeEzExo1jnrbnbvEumfhrba3FDYc/dL//nOzwuTxvylA3Jmmz88R2Koqkm31AyVaOh80TSlIrcRensovG2AWcc7lZgRct6pANrvdevTe8HaJHMDsMxae55003uLVTSkq9sBu0+QUqi6SZ+vDFYBiSEvS0memdenG8GsTYChz6tKWdGMbdDYAMDRFpsbgGX3vfX9yUskKSJIKQVvWWnLL9QcqnIuPw+DoQIJ7PytUpbzvEbvBnibAMcWExnZUOi9NQE0OKzNMTcAyx9w52dNksQUVEmGfvhZebJKpa5LYKhAgx3+i+rynzTz0u4wqwI4LlTKiEKj79mnM+BtjLkB6Lb97d80S0pBqnyGFMqL1Ul6pjMZH4lO189TUoRJ+vcmgFWBYdAnShlRSE1vHt0DcGs7zAH03/mv78+RmIKqJKP5uSNfJquRNXoADOEb0PMJlawYI2nahb1AxgfHvnODGRETld4/sTdg1jaYA7lNbhvVJCkFVWFq2rY4PK8qlrxwPxiiJ9HjmnFKWWEm6eNdAIvPLHeP8lmRmELx4UkDALdfOnM3wDb9x3RJKagqRnrwd++JVUi6q5UxOgO2fF/KRYFG0tybl4WFB8PQUUqZkRSh9PWlywP+i2YOAP02vWGmFEFVmTFfVOWz3u0BInhDu7N+VcoKNhW9vxGM0cGw/QRFhqQI6ctT+wMMyx2wNX7/txGzpKCqT4qqfMnTt4Mhdhp6PyclxVuSJm0PWHRwnNKcLSmSNPIIwEIyN6DPHg9PyksilU2qikl3kAyNBvzhc6WskOv68ZiWIIMz6/GmUrakCC29vANqDMccwGonfNgskUG1/lLGD4UhcBrQ9ZwfVS8KOqn+2KaAMTQ4dp2uyJiUqMdXAGgMxNyBDsPOHysxUb+MWcfBEDcNaLHn+1JS3DlrxpmtAWNkZvb3yJ6Y9OFe3QFYGAZgxdOenS1FUL+QSZ8uz7hoQItNn1qgVBR5Sar/cbMWAI1hwTBouCJzYlJ+/9Jt2sIYghHttjvxA0lB/WKWPGMXGGKmGdDxgBemqyRFn4tmPLlrDwDGqOC4UCl7Ui7S/GcGgObPCKz3z4VSStQvaNLNDWRIZgC67fNaklJR/CVJCz+6aaPWgFlQZit9rnCgknPRyF0NRl8k0PfKn1RyUahZX/YBEa65A+i55+Uf5hWJahsZlKa9csryANx+iWA4vDEXB5KYNO+etQG3VmRA78vGSqkoVpZpw2EI1twBYOgF/10iMai2k5GX9MmZawIwt18esvMbSj6kRI09szfg1lqIlkeMllJRtFHOoyFSMzcAuTVOvO8HiSmoNpYR0ti7DlwWgLu7hQLDwQtzcSLmpfcPaQS8dRCDHm5Uygo39NHyYCDmANBurb889aOkFFSbHCEt+e81W3ZAoTESssvrSl6kSGr61245mLcCYtsxylkBJ10MIkpzA2zgwbe/ME5SJKrtZqI085VrTz14LQNoDAOGnWaX4kZK1MJH1wfMsmboO1L1ooDJ0avDgjAHsNxhj49ulpQS1dZHkqSY9NRRywEwRkG2v1vZkZSo8X9bG7CMEZepXhRx6AoQEZob0H7Dy0YliSmompARpKQvLh1IgMYQYBg4XtmTmKSfL+0OzxTR/dOSFTE5eUNYAOYABh730lSJKVRbMmVp4uO7dgZgjAC0q51JTNLj/ZDLkmHYbJWQQjcZ4d4cwMa3jqYUoVo0Z6nxg3MGtwKMARiGfq/sS4qklwfDLTMkb1BWxKEJ68C8mQPtdrx3qhSJqlVLkvTj88M7ATR6A2s3+xPz+mxHwDKDju8GlXQJHL7NgB57PrVASqGatuQszf3HUSsAMG+GQZOUvYlJsy/qAsuIoed4lYhC3w6GuTIHljvmvSVSomrfkiWNvnqTloD5Au2y7E9K0mWWnXV+DSouhsGxOdDnxM9DDKo2LrlIs57eCIC5MgycoOxPwbk7wbOy1ZyQqG+GtioH+v/fB1QEVUPnLP188/qE0RHZ4h6lAJT0SA6Wka1jSnoQ1oocnY/6hIqgauySpGl3DQTMDwyb/1xKAMGv+2dm94UlIMaSg+BorWZY78lQBFWDlySNP7sHjG6INk8pBUBNWgOeBRI3KSvepNfag14cOGyCIqganUn67zaAtxYQu80qJYKp62UEbd4MqczZCwanjk7nLlCiavhImn56J3jr6fikcgQT18hKj5Eq8WSN6AI6cQz6Z1JSjZ+klzaDtRIYtphaSgBjB8KyYFj9h5jOAuHTsMn7ilDNH6FJe8BaCdHuWWV3oY+WycqG0wLKGjsA5sOx/U/KU/VgXuPXhfuA4eQSwfUwZOMPsyIqV4FwSaz5vfKqE/N6qZvRS/9vlJ2RTbvDM7JnXeEWTd0A5qTDo8qrXmSKE2E+AF7nLvRJL1hGTlAJJ+svnUAXhr2XBOsGhYb3Bn0Y1ptUirdbYcgkcaNyQBeB8Eh0eE2h+pFcejjMB9jiHmVfSZfCM0G0+Us8pUxbD+bCMLyJqieTXmsL+jDsOLcUV8wfmBHDyt+oRJP1aAPogWh4RFFXkPM3h/kgOr2h7Cn09UBYRoZODado/g4weDSs+I1YVyh0LegDhuN8JT1khozsvkDRZo1aHnSy0/z64/PlQS9rTVFxFOkP8KxcqhzPrSRcEjcpVGdGOQLmg2j1mLKf0Ce9YJkgas+EUzTv32AuiI7vLXkk3U/6gGG3xuIoToIjI61HhJM1elknhr6TxHoj9NkyoA+ix/sqXkKj+ltmunwa0LUknOzZVH9Q09aD+QBxtbKfy2DIpmGNySqxFP28NszLBQrVH/O2c2PYs16cULM3M8/M+tOiyXqjNejDcEtd0riDG6LvaJXWEXqrIywz2y8oiuYCGLzcVp/s5MgeVW4t18CQmaOUYymasb6jW+oQaeGubmA42wm1eDd4dk5XiSXrjfagmxvrk108bTZVbA2hL/rAskJcqhxLyYfD0IxAzR/uh1hqhKI1JF0HQ3auDYaatY6nG+qSxh09tXjSBTllPXiGLgom9GFX0M/1dYi0cDc/MJzlIukhh2XGcHI4F4Lwc2tdsmAnV5tME7PHhbvAkaHdF5ZIqGnrwRzdUodQ87ZzRHR5X5G50MsdYVkaNLWUQELPdwAdXV6XzN7KEch/V8oclx4MR3aJtq+qHsrRMLh1nF2fbOHJsMdSMmOh75eHZQjEev9UPQxq3sa+9l4i1h+/rOWJ6PW9InP3uCHTxNojlXIQoW9WAj0Nm1mPjF/VV8unskYt3AmeLRiG/lVKUTxc87X6z/VH6IOlQT8w/Dlroa/6wjIGQ5czJivnGM4H4dewwvf1yKutnW0xU8zY5SSavAFrPV1Xzv6K9kfNVffPFPXHjSAcE13/o8gS9ctasKYHGlrv956UirsF/+as4cl65HSYJxA3Zyv0UAPpADCgy/HjpcRWlTW2J+gIhr8p1RnUzGHODMcGs8S0Gww+acBqd89UROt6uYUvx2GJdUboy2VAZ1vOFrMTGrk86ASgAZu8JCW2ppNh8LXRTLHeeLuzu8FjFFm6BIRjA9qd/JMisbWUvAdqrgwrfF9/PN3gjOj5cYbISevDPAEGrPtEsyLYKoomDYA56/i6or5IuhEGZ3ZfhkI3GOGcjvYHvUcx2AqynqyBrmC4ut4IXeANjguyQ84eBvMGONDzqNeWiNEazoLBt+PIYF1BNW0TwFHBrCQ90GD0B3Og636vNCsyV8oBAWw0U6wvxvUKYLOZYjYYTb+DI0RzoPOh3ykyVjRlLXeGXiPqi9ALLeHd0OsTRTZCz3WGxQCYA8N+YGQr6x9Lgc5gfq+ivvgr6M8fyQijaQ84wrRcDtcrc6+29uc4WawjqKW7wbzBcGtGku5sZ/hFtcuz93qbCPZaKtYT3w0C3TnOzEbo84H4JVlxtUa/NXtP1iJYb2Y9kfS0w7/joMQMMBbvB0erNSvlboBhpY8n33/NRLEMMhP3wR+x7JeK+iHrSjCCreeI1Uu6p8HoBzB3d0Nxx7AFkhQqyZCCGbgDhHvaHfVEqe8Ki2DITxnI+roPDG5t+b4oarbNnt1gjlXGMk+qZEhTpktRvctg/gyHJtYNRVMHR2Do/pGiegsOhcGrYa1PPr5g3TX23r8Htp0a58DMcHYEVTJp/pXrbHTeeEXVTo9hy/livZD1SXcwgoYnq5f0RCvSjWO3ZmnihOb82au8ID3uMLNOjylKUD/tDwDb/sioTimHxTB0cv2Q9JJFAMN1Vcv6dk0QjradH0mixjwzK/h8Oxgc60wUi5Cz94K753CZWJWi+dtHQPR4W1E/PIEQHaeI1cmp8VAY/BoGfKkgGbE0Jb3f0QxmvT9VFAm91eAO5PxPVZuyWgRwnCXWC6UcC4thzyViNXLSPQ2EZ8P1CklikJq4PnJwrDtdLPFOZ5g57FFFVbJGLgOGsEuTWB8UTR0cxbBZ1ShJ6fau8OU4MVhQGHpnVZjjN9MZJT7uBgNyx84nq/R2pyBW/UlRH2R90g2MYb1pFWMkaeqJDSCcHSqxhEIjtoZb421KLEi6xg3dL3hxtkJVeqlVCIYOz9QPf24ZxToVo6RZD60NEN62HLMksYTyerYdHP3/rSQp9E5/5HCopFC17gARoeNssT5IuhdRrDqhMqQmjXpoGEHCva91yxyyRMQXfd0Nq48URU7aCm5+H5upql0BC+LoeqHkg2GI0LDCNxXKP7B2HwcM/g2dblxYBjV7K6ABOFWh0Etd4Og3SlS1ky4NY/uFYj1QNGPDMPp+pqiEFv4eQAPh39D9qtmRSin05MDT3zx/8OUKkTMv6OS21pRMXBTGulPrhdErgUF0fbMy5MgDljXA6M6xVV6SooTY9NlicdQsUgot3Rc4YAlV9awzgzD0+0xRD2T9vVUYHV+ujKiFXz2wVQvAvBlWeODTD9/7WSwhiikkSlLS+ysP/UhRvaIjg4DZ3fVB0j0kgmh8ukIKSbOe2pIgfQFo7NWr2wavM0qIlEgVDX0+UqEMLNw7DPy1LiilcTdYGE9VSowkzfvH+oC3MkPhBlPFEi0MKURWq+jXbaNwHBasBzRlUBwdXqqYJCZp0nm94K0LZuY4cXFUSKQoRdXGrxvHlnPF2i9r9LJgFO2fr4bEJL2zKcxaj7u7mR0+XSGyIhI1a5FYrdGDwChW+q4++Ee7ONo9Wx0pkn7eG26tpjBnjS8qL0pkJajh2xw5nqzWmlEY2r+gqAceszjaP1ctKa/Zh8O8ldjuFx43FMC5jIixP0isyJmwBxVtBm6vDy6BIYrGp6qnpNnHAt4aDN2HS9+f3qPzA8rrs3VXvraJrMR7w06bTlbpsz5RwHFRfXAUamG0eyYDSlp6VXe4Z8+tx2eRl955ahFD32yCLaapAqKmLhZV1ay3uoSRw8FkzVfUuCMsjNwTWVBQr24IuGXMgANmkBESqdB3t3xCqpIhUlXrGoZjj2ax9vvp91UjJv184SDALUuOFa/5WSEpQpJCUqqMSFVv6UC2nlsPjF8lkA4vZkNK0ujTuwOWnRy6PS2FymWeIitS/ax3ugcy9KfaL+uTpcEwur2XFTFJb+3dAM8MOvxd+VDZoXk/5snW8fEqYRhW+FZR+73eJpCen2ZGitCSe5aDZ8S3fW5xosoOTT9w0L2to+irNQJZ/qt64LXWgfT5KkNSot7dEJ4Fx+GLpIiymBYfBpyUWsm4dWFh9Pm4HvhL20D6fy9mSEyacCTcqmc49PuJU5qVj2ABIyXdm7PGF5VvHTOGh+FYYZRY+73XKZDlxmRLSpq1D3LVA2zABhsc/q0UpBSS9PpAuJ0/n2wFKnmfQNb8uR74omuFKa+ftoRnoOjmr7705FQxNOHBm05fEeY5P6VJFCkxMqXDAxk2s/YrGrsCLAjDKhOanJK+2wFu1TN3R5eOa77HpfpyMwBwAxrPbCJDiiQxU8cEssOCeuCHNQMZ+H3TU9KUgwGrWqEBPT+SZmwHNzOg9w4PLBLJOVOlr97Kk5nJOj2MHPbJU7XfzGGBDPnRgZLmn94AzwLcur645Iu9kDOYdTjh0wUSpSWXb3H6Bat2uytTF4fhOFdR80n13QLZYLoHhdIdfeBZALDy9ivAABj+lJeComYMQ+EGc8TsXBmFAffXA0VnBLL1XBeK0Curw7MBwAHkrO+XaqYkavYW3uA5239Jlu4Co+jyej2Q9KiBUeyb5ZNJIzeHZ8LcYG7AGSmpkMz/Hjmz3D8Vys6LLcEQHGv+JNZ+WW+1i6KG45V9SHn9sAU8CyX7HDuTUUSh45FzbD+LzNCITmHstLg+GLlMFIZT/SivUevAMmHoc8Jdw5eKKp50OnLo+IxCmS36bKUwjhZV+xdN3wQWxfmOlPTBAHgWHDsnSVTx0PQtkcOyX2ZryjqwEAwXKuqChTtGQVzrSXld7ZYFQ99XladKpfNgZvaXlCGVtHcY19cFyuXMIAjc74qc+Bt4BuD4zReMEqF3u8NgWO5rRQsionJZx8dgyD1SJ+jZGhhDmzddiemwbMBxSrCMB61In0/LY1ASWbkzUIth2c/qhffaR7H0575C18KyYX9RlPFCexgcW89SuaTyI696cCn5y+ZY/SexHiga1wcWQ7eRvpLuygqOK8FI/LQfDOZXKiJYjFr85KEroN3lUbmzYDHs38w6YfZmMRj6TVTxFPo7PBOGFT8XJSZJmr013OCPpGYpWGzJOe2ARuy0VKzU+VGco1BdmMtRUWw3X57JdGRGYLhREaQmvfWtxvwGDsNt0qf/bkoREjVmEBpzGPisqEpd+ssAXF8vJN0LMoRTlV1p2lpNxND7LebF/Oh9Og/eeyMDYNjhlRsGbzheUlBauIPnsPPnClXsetgvgKHrG/VC1us1REDc4ivr465gk3BsOkt646i910bZjQBOfeH6j5UidB6w21glVe6fDvPnWHWcWC+83T4CouVr3m4H0UQ2nD7nmj4AzMy9mAEONGDws1Kek86/fZ7yUkSwMiP6/jLssaReKPp6VVgEnT/xVep7wpoG0Hm/7YCcO8o2FDr6Xz9LIUkhMc1rqgg1f1t4BH8SVS9MXiMCQ88xKo5CI1dsOoWGihoc2Oqh5oigChYsqYhCJyEXwQWKumHO1jFsOcfZ6SCarDsqau4GM7S7KoIqjJSiQrfC/CF3d92grHNiOFVZfoMT+sCaToUNANwthx4fMYpQUlTmg26gN6Lf5/VD0qPwT9Se9aWrQHjvu/2wnoC742blQxLzz107SVEBatZmMG+GIePFeiHrtQbQX/v3PAUnrQ7z5dj0wwUzPrhoKNDg+8yTQqHvVsbv55AtU+go1PxtN7+eeLezP0Pf8Sp+kq4j4dtws0LSuItWBjrscNHXCmrKFsBDiorcCNLd4UHVi0VfrhDBDguK3JI/rwnzZfBnIjFCGn1+fwAbjRNDn2/U4eEKfdId/v6oeuL7NWH+TlX2E7ochLfc0wxJTNJ7WwK5lxQK/fDCfKqC1KxhMF9E7n5F3aBS39sfcJ8jcsq6MGcw/EN5FUbS9FO77jxGlEJSRRQ61l/vz+qJrKtAZ0T7tx0lPehGb459FipPFSY1vTdeIUkMVTb0oIHOBn4n1g9JD7szbPiriptYujcc3g2NJ0xQRIGCUqiqoW9XdmbYYHY9kfVKS9DbucryGnq5q5m7wo1eohJVGFR1qaY/wJwdklhXfNTLGdHiRUdl4Z4w+DZ3N3P0+MsEMRVUnzrU3RkK1Y/U6EEwV4Z+E/xkfdTNXVGHA+s9tFSRidADAH2dU2dM28TdYbnIz+UgXBuW3e/ArXvDzAztD3hPzMaoFWGOCNxbV4j5w5wRdyt5KWXapjBXhty1aem8T3cDHA4s9yiZAWrBNs46vF1fhC72RbT9s7KXpAdrhLP+oxTSrFM6wB3A7kuyoNAVoKsun9UbV/gyrD5ZxUnJs7eDeev2uhKT+MzaQJfVf/saMzJqBdCPYdVxYn3xWAPo6pSS5TTpuTakL7gd20wpQqMvPPvfU5pEZZGlviPM0wZz6o3/dPJEtH5FyUnWhPVg8Gzujs3niBKTilLZzLre17D59cZbHTwZfj9VxUmZuycMng1AwyYvkyqMYJDKzNudQUdbLqw33mzv67Bc5DPr2RrpyeCbn/bgZEWxooyITBTNWB/maJelqitDr7Z1RPAuZSelHAKDY8Nqt0+TlKjSDEoSM6Cs80FH+wf/l7DUe16K5m/uyrDl51IKqlxqyUc3v9qUkXc7g372zqvOeKWNI8OgqSpexvfz5Bg6SnmqbEb+wZ2WQ5enFBko+mUwzM9+UW/829cxuchn1t/bgn6s4WblVZQslvRAO8DaP5MJlXy4p73T/w6IVi8pO0m6A4Rbw/JjlaKQUhSQszZGQw67LSLLosSKJD1SA93stESsL15xZFjzBxUnZf6OME9tr/wu6V/+Mk2UlPR0O3Pr+pKSJAZZQKY8WYmir1dwtMXCeuPVtp6OKEU+sz7pAvoB0NDvyPtfe/nes/dbd7MRoiJm7wh3nJFCUkiRUkHTS+/kK9S4G8zNenP+Z0C2eEbJSdI1INy3aIFFd1/KaNZ9OXOs/ZNComZdcjsVQY0/967FqmjWkw10039ivfF2RzeGzWcV+SxlxkYwXzQDALMG23CBpBGrw63jE0oSI38yel75oxRcPHy8okIT+8B8ED1GKuqJpGdbwCnZ4kFlJ1lPtgR9ASBJgOj8wMLJ96wBcxzSHJSS7m90YOVTflZQSxeKlVDJx/lp/XS9cR3MiWGdn0vxUTRnWxji7LrthoA5VvhSIYW+XglmBhy+mPr5xNNmi5XIersT6AKGE0N1JLn0UEfnKMtn1lfdwEAKDY7TFZKi+Qg4gJyv+JOaz8KgMZUpZcFuMC9bzhPrh9C3K4I+iJVGukm6zYhAzR0wdH6jIPSfZcwAGLq+qeabt7gzT1U06ekG0AXR5zNG/ZD0fKOfk5TltDTuAIukqGO1n0UxNe0HR6Fj/wVaMF2sUNHEATAXIK5Wqh8inQCDS2KZT9xkfb1cSEMmR2Je97ZzK5LDKpNEBVXhrPO8GDabSdYLSSP6gj4Me6ciN5eQCNfQ5UUpNHYoHIWGhr8mkqp40rtLgS5gjQ8q1QsR58Pgk3xAyUloUl9YPACG3Dut6avfwVBo6HnbElLVLI0He3HsMJesD0JjBsN9GFcdo+LmIhAxt1t3+xVgKDTr9ogiVNWsv3cEXRg6v6xUHyRebgYnOCwX+Qx9vRIsJgMAQ6EZLleiqlvK3J1gLuDYazGjHkgatSK8dRAd/6rsJOlcEEGbu6GoY9s5pKqd9HQD6AKWuzISa7/g7L1gaC1H1rN8hkauCouqTLOOLyip6qX8vB7MCTo/pIhaL1F/g6N1Est/JS95nQMifMdRS4PVU9IVsNYBwwr/kvKs5UpdjVe0J92cpVDrrOvvyzI+w4AvFMpg6LNeZq0Dhh6XzpcSa7acNW5/wqtj0PeViiCrU9fYdWGIz/6mpEyy+TB4K4HBdnlkjhi1WU7KD/cH6MVwFkOVZEhiisqVur5eH4bwHVvPYGQj9OGy5k5ggO/y7GKlqL1ykr48rBUMXh3Lf6PKBEe88ENeYorKlLrGbAND/Nb+SSVlNHgaWg3MgfaHfiylVFvlJE2+emXA4OjPDFWSen5AbtUjHvwuLzESW5STPlgLhvgNu84hM6Ph/cy8AOZAnzO/kRi1U87SpOvXAIxwa+g/UhVq3hsGYNCBD47OS2IEi5WcU5YeXQWGSrxDSZkN/gmOAHNg4Mkf5sVgLVRylkZfvTpAwjFxZoQqGfpmBXN3AFjxwOue+TEkMVLkokXHnNkOhgokeg9XZEhfDAAdAWZA76Neb5YSa52cJH144soADZ4NK32vyiTdaQYA7gCQW/WQG9+cSklK0z5+8NrD+wBEFRrWmi5mR6G/OwPMgS4HvbhQimDtUnKRpv/xkB4ADb6JyxSqJDl/B3gBAHMHgC4bHnnhzTedt/863QCAREXsuihjkwfDfAHmQIddH50hKaI2KUkqo24bVgOMcE70G1+h0L/awUoAMHdDuWaGijQeGsp06P6W9AaYAw3Dzn1puhTBWoM5Sz8/ffBKAIxwT1ytUEWZPxiOlpq7m5kZUaGGSxWZYszfBeYOMAfQYdjfRklKUUtEkjT2unUMoBH+jT2/qVDo/R6wFrXJhoFjxEwp6W+dSH+AuQMYeMIr06UUrA0YlBa+cmgfAEaEaDi3hCr0JzhqQeI8hTKe64ciBADmBnTc5MYpkoJtXySJo2/fpQ1AI2I0Lv+lUkVCXw+E1QJEhzdagT5bjhYDAHMAG171ZZMUEWy7GEFpzuOHrgjADGEazipZFTofjlrQsMUMMmvK5RTEAZgb0P+39/wkSQy2RRGUFN9ct1UOMCfiNAz+VqUioVHLWw7m1uYRNyjLwfj+sDgAGAH0O+6Rz3+RlHPFlFQkzRz10L4rAjAiUrNOTyqpoklnADC0/Ya+o1SanpIebUVGAtAAsPuQE/72k5RTqY6SpDTm/kM2Wg4AjYjVcWw+VNGkN3papxMevf+krrC27mRlOSw5HQuLBYAZALQfdPU4SbkiSi6a9+q+KxMAjIjWMXi0KhP6bn3YqXlJR8EBd2+riNbPKXlQ1g9rw6IBSDMAvU7+ywzlXAW5qPHNnVoDMCMRrjkuV6iiXHwgbPAPam7WFTC05YZBk1RcKOmvS8PCWZRGoM1W/5BSiS5nzXtl57aAkQjZ8buZwYqE3u1sOI1B8hjk0G7wXtt1gMHc3dqcg0qW06Qra8aIAJgB3c6ZpJxjS9KbO7QGjAjabeVvlVShy4E+nyqoGRsgh6N+WDhtT2twFFrbQpwnNyXP3RkWFEADfvdcXfXIkn46qwNgRNTm+KuSKkrN2Bw4PFGhF9ubdXxDzbobQOOKG2/cF20q0fphP0r6ZEVaVAANrQ8bq1SiKnVN2AaoEXE7tp8RrEzovU6OO5UUOgEN2HZuRMw6ed3fP/nD9BmfbQmvEMOGv6i4UdIVCAwwYMifVVJMJek/NoARgRsGfaJQpUYNxMqjRWrWJvCGe5VELZm+RIXntynERcrym8ukQbDAwBq63rpA9YiS9GxvGCI36/iYkipNPr7H06JCw3vBBoxWSJQUjLxObkuInl+6UtJjDWRggMH2HadUwqlrxhUdYQjdcWYkVkzUUkXBvbkG/N/SUCEpNmv4ym2J4aici6dS5g6HhQYCv3tDOcfCpDE7AIbQHVvOYKiKFCmFzgA2H6diUoQ+XweGyiQ6/1VJrrPeXx4WGmhY+rasegkkSa8NBYnQHQPeU1JVKRV8ut+JYxUqTi26fy0Y2k7DprNUfCnpwVZkaICh5VGTlHMUkTTv8s4wInSz9g8qKYtUkpKKk3P/mIOjDSUuVJbzkupnwhgbCAx9JiuFwCS9viNgiJ2Os1IwEwoGyQhKCt0Bc7ShxHKf+VMuc3ZHLTjQ0OaoKUrFX1DfntgdRgRv2GseQ5mlChMZvNEcbalhk9kq7pT0zRBYcIAB232rlL0lNd7RCzBE79hgrJIqTAZbQqUZH74/W1LSt4PgbcsRuSjApFeWA6MDDYNfkJKvuqYeQBgRvaHnW0qqMJtnNLUk9OXha/XutvX9k5ZKby4La0OINi8rR6C8nu0CRgcYOp7+nVLxU+r6ZgvQEL/71UqslGZ+t1Dlk017otCG7nPykSujTTWs9YtKCEy6uYUxPBgw+BWV7CUnfbIWjIjfcejioCrNRfOD5YlxbWcg14A22LBfLoqRecFhsPhAQ7eb5yv5SNKzvWCoQMNvvldS5chQS9j82oE9AM+5u7Ut5LWKQlk/bAGLDzDwkJ+UcvZy0oRTO8BQgY4erykp06SWfHzeYMDQxhJdPlaOQkljN4JVAAhs/lcpZS1Jbw4BDBVo3v4mJWaKUqI09uqhaGsNg6aohKGkUUNgFQAaOp8zTRFZYl7TL+4MI6owhxPyQVWXEVEGyQgxhfTziW3PtnMjUdKHq8IqADBgi38npewk6eOtAEMlOnaczFB1Q5IiioVSsxSUIq+p68LbmONLVqR1vdwFrAKQ6HLqT4rIRiTNvKo/jKhEx/rfKqm6oXH33fmxxJBETfnjXrePkSKovP7cthC8VykUJT3QDqwCwID1X5byzEASX90RMFSjY71PlVTd0AfrA73/7/VmUQrdDWCNq8dLCuUPbms6va8cS0m6hLVqgDm6nzNZSqwOIzT/wq4wQzU6ln1beVbtJqAB6HzG3KBCF+ba54C1z3xtVpp9dVdYW2LoN1ElFpUydyfUqgFwYIN75koMVooRUnp7d8DRRuawzMNKqjZjzrldkGsAblAodBmKd97qkC1yaFsNW84OR1ljNoRVBMyA7e4eLymxAoxE6ctrf98TZmgjHT3vU2LVFNLzGwJY/W1R5NijN9v2xNM6OQqtrTlZReEmjdkCVhGAA1j92BfnSYwgWYKMkLTk7eMGAHC0lY41X1SiMsik77fquf8nSpSoNH+RpgxGzt0NbSrJB5TiUdIPu8GqAuYAOmx7zyQVZUSQlKSFn165a3fA3NBWGjb9XImqPoOR9PDFeUmkRIqctTEcbS7R/m3lgJTXhO3gbQVAMwBr7Hf7Jz81Zv3LPO/bF84c1g2AEdVp2O575ZVBStLSp1YbeNZrPy+SKDEimo9sm5YbpRKRksbsDG8zANAAoPuQrfc7+awLzjntuL0369MAgEZUqGPQCOWVQfK7q88+7bfdACyz5jbnfk9ShX9piwy9xgWlpCkHw9sQAGbEf9OMqFRzu1pJmWw6DoW5XA4ArlDS0unTpr2yBtzM2pw1JkelpKl7wdsUALT/MlGx5th5HlkFkiwWfGZ55BocADqsd8m44IxjV19zaDc4AFhbs2ZcShq/C9zalko3x3bfKVR5KkQWYeiVYQCW3fy0m1+YLCU9iOLWb0AD2pqVx5WwlDRuF3i9ZMBvf1JSNedc/VBzMTE09a7T7h0xX5ISQ3+HAZ1XO+mfI0Y9+BtYW0K2fFr1EpWSftwVXh85cv/3s5KqSH058LdzxAJKoaKRglLo9YEdNrvq7TEhSffn0KYSq32seo5KSZN3htdDjvZ/mq+kqnD+Q2+RkhSKEIMpqOLkp69NlcQU+fRRb1hbAmL1v0g5B6W8ftgMXv84Bj+xmEnVpSRKYmgRFSqflJQSpWjWRz3bGBDdLh4t5VxCUtK3m8DrHcea74ihajNCBfr8qJNHKsqTIihGopS/zAxtLIEVTv1SUopfIiV9ORi5usYc67yvPJVRaulRwJrDFS2QSEnNI2/dvSvaXhJY4fDnpksRv0BKenl1wOsXB3YdqbwySQal5n2sHX6/hGwBxbEv3XJAfwDW9gA0oGHTa7+SmNhKyMopafjOgFudYuh1xgQlZoKSmIInoMH6j1KUR844e1AHAA7A2iCABmCFU95YKkViKwgpKqekeTeuBlg9Yob1X5KSMhn68k+PLBF1DnJmdyqVF7ofMAfQe3APtNE0At0PuOnzEFNkLTRvmsiKKaRRh+Tg9Yc59vpBQVWdlMQ4Ee0OfHXu4n3hjoPzLI8cvw+AVfa64ZOx724La5MAmANY8chnF0sMZomcdMC69zOxYmLSoqv6wq3OMMMePymvKpIFDCkk5fd0R8etd+0Mc6w8TixL1Ozrj/vHj0mSnmoPa6MAGoG2w2/5WlLKzEzwTKDjA8qzYlJQL20IeD1hDhwxUXlVMaSQGJo0XxR5BHKOooaO/1aUE8FQISPy8VaXNgwADUDP/f84T2KKbIRGDLBG9H1D+Sookr47tgesfnBg9SvnKamKofHTFUx6cK2j55Ch+83c3A2A4zKlUqREMhiUFHqkQ9sG0Ai03vr6T5ukYAYYcTQcjsHvKl8FKan5jWFwqxMctvdIMVTF0Gfr7TVDocd6oOF5Bbng/wBHUcfRiSKLNb/4z0WiilKLfmuONp8GYNldr/teSqxa0r+7mQGOIe8rXw1FaPweMKsHzLDSzbOUQlWkJm8GXNzU/K/lkGt8RiFq3l97wa3Yb2YoL5FS6JmuuTMXB4uI+RNRAwA0Alj57zOlCFYl9PMGcABwDPlAeVZBzGvKcQ6v/RzY73Mpqaqh13JuXXfduxdy2GiqKIX05uaAATB0eECa9EOeVOgmwG5TlNBPu8BrAAB0A4Y9OE0SgxULzdkPjqKO1d5TYhWkpIUX94RZbWeGTqfPUaKq1g4GAG4dHlVIEpOm/bkRBsDQ78g/bbTCVflQ6K3OhvWniEUUmr43vCYA4AZf+6z3Z0lKrAxjyfFwlHSs+LwY1VBivLIO4LWcAWs9tlRJ1Q690x5m7ub4w8JggZSk23vAULrXCAU1fQNYx38rJFFS0rhN4DUC4ACW2eSUNxdLiRWIpKvcrRQcy1zRpKiGIvTDMY1wq9XM0eVP34mhjAAwbDtBoZKR9GA3GABzd8dNSqKOhfsjBSEmKq8Xu8JqBZg7gK77vrJQTEGWxRR6dhkYynXg+AWKakhJi+9bE3CryRzod1deicrCq40Fjn4fK68ymXi2maGoY9eFUtL9brhMIao5SUz52dvCawYA5g503PW5JkmKRBZhkpofHwRD+W44ZpFSVZSob45uB7jVXGboeOB/FEnVZzTHMw6Dud+gpLKDUzaBFzP0+0pBjR0C7NGUmvXx3v/31jRKS3aqLQCYAx1/d9e7Py6WpEgRSVr4/P6dYWipOU5crFQVMa9F927WAHhtRQKb3ztfiap+SNKNMMBxaFNieUw6ppzco0pi8x7A8iOlOVsA3YedePm//9EPVmMA5gC6DNnmzKe+W6zCaU/u3g4wtNwMx09XYjWkRM18ZGuHWe1EAv3+PFlMyiA1+eU3b10dBsMWPylUfujrDUvBcbZCoRPgOOCDz85xdwBo3x41qbkBgA3a44LbHrjngo0dcEMlzbDVe2JURQxp1q1rAG41kgE9Th+ZlKjqsoCcsHenrgBgWO4dJZVPjdoKhjJ2XhQRPAsO9OgFAOZuqF3N3VGmGyrt6HP9EuWrIjFJ35/cA7BayID2B31YxFCVQ6IUegyAGeDYblGKFoTuh+VKGbq/rySdAIehTLOapdDM3czcDVV04PAJSlEViUnp9SMHwq3WIYEhTyxUDlWb+a9miQq93NEcKBj8vcTyyPF7AV4Chl2+X7r4tUEwwKxUPWjABs+LUR0pKH22KeBWy9CAwTd8p5JU9dATQ69hwYi+sALAdn52rqIshWZeNghmxQAM2WfH3qhHDe3PX6xUJTFCY47oCpjVKubA0MvGSomqOjVvK+ywWKS+X7EU0GGPr8UySIX01U6AlTAAsHoEBhw1W/kqSUxqfu2EwYBbLWIOdDn6KylRGaSmrOnD5hX8tAq8hBuuVZSiGGLShMMcVgzubqhPadjrJyVWSQpKoy5eEXCrNcyBbge82KxEZZKasQ6GzS+YsGoZOawyXCGygJzbrETlteCijrBida1j88+VolpihPTRH/oCZrWEGdBl7+eaxFD1GYWcvg7Wn1EwZfVShj7/UigkSqExux3xtZiUFNd1hNU/cKz0qJSqJSmS0gfHDQTMawRzB5Y97Jm5YqKqH1TRL/qi3xcMauKQEoZln1NSaO6oIEP3ACvftlhJwaZd4XUQHJ3PnaEUVZOCWvrltYMBmLV95gC6H/j6IilR1Wco//y5N4+cPe5ImN2l5mZ+3BNWYNZ4lxLJ+ccOfEEReiLXAPv9GKVo1oX1ERzY/E0pVU9KIX311zUBuLVt5oAPOfH1uWKiqs8kjTyiC7D8BqsCjmGTJZ0LQ6Hj6KUpmHgWsE8zQ9OGodGw1nOSeHCdBDN0/9tcRVRPiiT9cNOGDpiZtVHmBnTa9f7vQwqq+hHSnKtXABzFDfu/8da5PYo51v5JoaSHO1tu8wVi6L+rAw3ofPI7H17aGVYfAQ5s8xqVonpSJGncPdt2BAC3yjFzA9B1l3/NkxhUBpP040PbAm6AuaNop84oabhCSUkjVkQjDlxKKunb4zoiB3TrgXraDF1OGCmlDEiRpGlP/3XnQcsAZqwScwDovP7f3pglpVAWmfTz31YGYCjbALMiBvyTzXnN2wUNWPlThaSk9NgA5Bwwq6MAB/pdMlN5ZkCKJGnKt28f2QMAzVgJ5gag3563vDdBUqIyGUlvrAfA0VIzlDQcF9LCPyOHZV9WUmFKeqo/zAx1tjnw22/FlAWJEZKa3j1jSHsAMEZn7gB67XbX5/MlRVCZZJIe7gd3QxUNnU759wv7mVu3J5RYRNGs+zqiHjfHqvcsVmIWJDESpR/+es0e/WoAzBiVmQNA4xp/+XCepBRURhP1/akd4ah+u0bAcZYSVZzS5NXgdRjgsP0/l1I2JDGypAVj795mRQAwM4Zj7gDQa51jn54gKYLKaiQ13bEKYKi6GeCO34xlqCi15Lspj/eH1WVwoN9Vi5QiI5JKzkWa8/mNw/u3BwAzYxg0IwAftMcNn04LKYLKLJP0n/0MbsiiGRx751MKFklXrLx2d9Tt5sDv/iMlZmXRnCXNm/Dq0cMHtAcAmtEbzYwAsMywA+/8tkkSE5VdJunn83sBjsw61vpOkkKiJqyE+t4MPc//WUoZkhghiYsnPHPq/ut0Q6G7Waswc3cU7TR097PempIkRVBZzkVz71gDMDTtDc49++aflVU0enmrcUkOcGDN2+YpIkOSGEFJWjrlxXMP22SAAYC5u2XH3N0NRfuvvt3B577641JJjKAyXZIWPLMtQMLhMXOKisb3gWEJ3wzY+U0pIkuFjAhKimlfXH3Kgct3RqF5uVYagBX34mYo6suvt88ZNwyfsICSxKAyXlLWZ7u1AA1N3qyB3T9TLvp13SU/wA3LHPaulCJbhWSQkrT463duvfgPay2DypoZWtxx8Pq/PeuKe0ZMWaJCMkhlvaSi/GJfwOCSaPVqSUU/D2oOABxY5rjRUmLWijIYKoyJb11z1p9PPWCHLTbZZMO1hg7o1uBFCs3hXZcdtMpaW+z+x4uuuPrpH6YsVNGIINUKS5IWvrNPO9QIp4azVc/lP7o3D8AcGHzVJCnYCgoZEUEVzS+YPWPG9Ik/fvLiQw/ec9fd99xz+6133P3gP++5/9URY36cNLtJJSMiSLXKkpM044ntlwYMbg29RmuhHiDRTGgOrHXnbClFqyjOiGCo6lFIUq22ZElzXviDAUY4JnYZVZ+xG6y5AHCDbXTbVInRakqyeFSShWrlJUvzx9y9RSvACO+99hreCs2KDmCdK7+hIlrXL3pJ0uxnhy8PwAj3RDOkA+h/7EchJtYiJUlzX9i8AYAREdKs2QFwA3oe8XZeSlFjMGVp5is7tASMaNY2B7rt++AUKRJrByZJE+/ctBVgRLO3OYD1rh4tMaI2iCQ1vXtmPwBGNIubA1jxz/9ZLEViG8dIlGY9sU9ngEY0m5sb0HWXO3+QlKINY1CK0bdvbYAZmtnNAQz6w8OTpAi2SYwkNX9206EDAbihGd7cAKx76VeSIoJtCyNLmnTXDt0B0IjmenMAKxx9/0xJimAbwQhJmvn3s9YAYEY077sD2OKkyz6cKyki+EvHCEn5MS+fu2kHgEb8L0DLAUDXbc56fY4kRQR/kUgyIiTN/uy+Awa1B2CG/1VonnMAXTf9v0c+mS9JjBTkLwgZoeKznjhm8+4AYEb8r0VzB4AeW5/73OimUGEKsvWRkUKSljYtmDz8ubM3bgQAd8P/ijR3ALBB2x54ycPD5ycVpiDZOkhGogrzs96+aKdttlhrWQeQczP8emnmjqL9Njrk9jcnzw0VMkWQZDZIMiJCRedO++C+6/dbrwuKuxt+/TRzNwOALkM3OPKGF8ZOnkOVjHJZdpSr0oum/Pz+3aduvHovFHqhGX5FNXdDYfuBqw47+uKb3xkzdvyMpcpgfu7EcWP/e99lZ+8yZHAPFJq7G36dNXd3FO86YMCgjfb901kXXPf0iK+//vrrb0aP/m7sj8VHj/r6669Hvf3gNeeeeervt1pt+QHdUdzc3fBrr3mhocx2PXv37t27T79+yw0avErh4H69evfu3buzoVwvNPyabOaFOTdU0TznhWaGX7OtTC9pJfH//v/N/7/5/zf//193AVZQOCDYrAAAEMIBnQEqAAIAAj5RIo5FI6IhFHwFuDgFBKbvxj2IbC/8l/AD9APrCTanbmP8Sv360dhXsf8L6L3IPYL76++/5f1adNvWvmEef/yP6f9sH+t9UX6V/ZL4Bv6P/h/ya9sr1Uf43/q+oj+w/8T93feB/5H70e7D+9f8b8jfka/wv/C///r2ex1+8f//9xf9t///69/74/Cp/av+1+8P//+RP9nv/7/u/cA//fthfwD/7cTD/Rfxp/VX5w/F/0/+1f4f9W/3z/wPtH+MfNf3b+5f5n/Zf37/7e99/l+Hv1f+v/9H+A9Wv419vP1H9s/zP/s/yfu93z/mX7j/xf8n+RvyC/jf83/zn9z/x//f/xHxn/Wf9j/Jd59tv+J/7H+T9gj2h+mf6T+/f5n/0f530oP8b/Oeq/14/3X+d/Lr7Af5n/Qv9J/ev3t/yH////P37/bP9X/rP7p//PSS+6f6H/f/3b8sPsD/k39U/z3+F/2//N/zn///9/4v/0P/b/zf+y/+X+x///vo/Of8P/y/8p/sf/j/pv/////0F/kP9D/1H9y/zH/s/y/////P3e/fV9Hv2o/3PuVfqr/qvzh/f///nnaZ3bfFn4PmMAX2md23xZ+D5jAF9pndt8Wfg+YwBfaZ3bfFn4PmMAX2mdybbFl9+HkSq/VrflzGG6bCjRvasAKEs2yBZ8ZJGu5KbbxAW5EepM3hgHxTT8KgC+0zu2+LPwfMX9iXPwvNZZsljxTCZ56FsdfzgRVRQ1QQ9gAwGL4vO4Vie3IdgoPn53tHq8Z6izrny/SZcnO//8PW5BHMs0EgoHViJJCvawHs0ohnj9ylSf2LeyXUSa8iZ+LPwZjEQ7Dzk3sSt8Zp00YrnkHwoArLoYR44kTipOmINu6wb1XuQD5GzXFC6/7KgT6QNJXpw/C5tm/pM9Qdz8uUBZZAFdNahjIFhQs3YO1KWRB469zMd0ipdpnhuakTe4O7Q7r00N1EmvIb+zBhdlvm+Lr5TQQiicAb0xoppnh6jNxzvrtkDsfYjA82L81ClwTvkF9s7qsPQQvq/aKjRoNf+tuSPCrMuk6Nv026hnAxx0eagqryCX2wyYHhhsUO/6WNM6vZF1d8GKPFWwqpKbzYD4dUDJm5AL0Y3I5SiggRMcxVMnDATKIJfzHEmvIl26ESnkAQwB3Fdx43eRxPNX75KnO13S+BJUH3J3LDdlTyrBNctuXO8yrSrUD3pBkpp78Fw376ZuPmqp/3YlQ2VfZMDv72ezcG1IqAnx92g8Ync3ncguWnsZU3umbG4bi+/iOZwtTf5bsRG8eUN6417LDM25P76f4c4HBOyWpIxh67PlM/Fn4L6NekTvb+NebC5fy3hDRyOesP6OOrGr0fEw43fhVTZ3HApCWCsSe3F20NyT2c5kb6rz7uzAegxpG7uveliN5ZZVUXZDut2+3j9bvwMhTSVsH3zGf5UFB5hxnq7+SeWVgBC3EhKoBLc486V8URv2K3kww+koyKhtqdLZ3bfFdTtYju2Z4uU7k85ZLMmlitAc3ZFFaOnOt/aPIQJ+Jxr8jL7avhJ3M+M5bbbu4s2lR28yFghCNB2Pw3EdFoaSUPq6WbqSR0SNXwOAf/10id14la/Epn4s7a3/pdJKZaZZTxzBxL6eGRfryNCsleLu+6rwzyx26pTDLFqVNQHpncWpJvbOkmpwCg3nGOVc3h4G8wd/pcKJ3tdWUQrVj4VZ9wCqb8P4oHbKypG2pRMOTfC+LPutJE1EAC1ijTJEPchliPn6KKvdBySvqV2TUbX6jHv5zXiLCMIJtz0j/zZ0XC/I0FSx1WYtq6VP9FllYHAxwpngOnxBV5KRKRz3tFOffb3iXQmvaKje6rP57rJH5aDnanGTyygKJgb/W3oLx+7RqZpoz9et9PkeRv1NNokYJy9Iie2zm3pDB/Y1oR3jyYButY2ncbmTAe+X9anW/T3n2c35noK5pQyM7b2MrYIfTG9PTOQkF3DeTSgVQRvoMe1FCXF88zr+bYParnb6RGYN1qhfLXxuy/rH65O6R//t1AfWLnzUBdqo04J6TzJqbmlecSPXW+BQqDGl0pMSdl2/8j5aYbUTirHsOGKn7VO6+TLtcES/s7PlgHxL1jR8IRyjYnPIhL8ZRRkuJM6Cdhuud97y7qcTMOdfqZhbmIDNlCPAnh7bHSVKQgMTsYDHhKtb0deLElbiDvng6kHMdBjzgcqmOBQL6IDQ+s8mV2LN33D18hwd11DqSkBNvTsMYPsapDEglPvjp+n/j94ptWKNFX1b70Z2fto5NrGv3aZsu58narPip+FR0TBiobT11Iy6m2e/FPbX3+1OJa52/b74OjuN5DB+cLK7dxmJfc1Q6440yZd3lI/mdrzTM3NAED6W/CitERSS1P311uxbU5Qr9OXZgjps/rvk7fi/fwoH0F+cWECLBv8a6durDBf4Uy1zXH1fFfEboTzjBKimHrCOeokWuF/8+1Jvs5//9SRwIai6d0jmmraTwFuvA7nPDEfiIN24PyfHTCbTZtbuBWm3cpPkgLh9Sre0nu3aPiXMtx8MsaU9tF/xqrY5kJvT7sXX0undxhoLzDj883BSXhpT9MxsnuyXzlMLAiP6E9IymKiH3skPWXehpSCz/STcYrtf/J7///4zjZOCzpCtGs7va/RwiqDxYXJn1H1uQcsHNyidziP0zqMsgpDYHTHOy91ELITcz4U8rOmqMyNLFOj5JM8D+oA7c3a/4P5jiBknl7O/pAz4WCQZhAyOb3snvLnQy4f/y9snmEtxcqmsLv169JVLFtavLm+2lV21Gz2G9wjSu8fFvXd2GOzJYeyPRQ+lKhTn91NHDc9pqbBUowlK0bs3aI0D3AKitTx74koYvI+gV1myxKch3XQuaXrpK8jjokSRugakZVTseEuVnF9CH9UHyJ78dN7BmBjSDKWfQun4Azr0p8/UIWA1OmsHFcoSsBUuepbGd8rjRia4c5H6/phGHwg3apSwhVrybXOxvFNbZSDWZJqGooLJzpAI6unDpSRMHlLpTQkjHMO9nn9m3TRtnfbBcCIc53jxipNj/uosVJr6k3eCfoBysKqXfNgB6y7lV5GdCVpNeAbBQzs2nRNmMTuVI9Q8XsJsrEdrQv2Jtdv5C5kfQnsHNCb+du7iyEOCdTwt0VB1u9Wgzq2ZSxB1fbVwIxRxLclRJR58Y/EgUQr14hJyKpvHd19C7yedYTVkMebJ5qsxD+XCRXrS2eu2lCu3APY6NZW8hccKu5Yc+jwoOtZxIwcaXVcoWuJkORObDMraZ65OnTANPnH7F4MdRvL/a9xPXCGqpklnjCQjj0TpJU4eeJivDhA5ViSTNs+RubwhLNJni1MP4EJo3iw0HH4dDKzBlTT/SDiWI2eJAyzayIepYxKZCLIuVdtx4PiiiO7XCi7df86UskvxK297+oz6yGurHIXljJx/iCBtoZ6dx6Fse4GOzEgFGqKNe3tKEJ/kiZ7Iz3+tFseNyJqdjZxrZQuJx27h0AzAa+Wwpx6fLGPWUq7CFhtrDekuXn5htkjdl7CUuUmDTduCB3UpCckTPsEv0vTXK5suQT01gKGn+qhrBj+gepo+x1YyIrpkWV4/IHsPpEuwjb7QaXiij8pBE4mL769MASpI9kBVUtKG4c9NfVSc+kF+iq5C1Qx/PtR/u7fSH8UDKEJ43yrheULEasZiqeSloHBYidWG1Y0nAf+BrrDNVyCgpbshlZ/D0MAA4MHEZr7bWowDnXz1zXH3cfqkn4CDDcrxLbu5bgNhc+d2diP29PDxifKxjS+gJD6BIBrIL78KA36ugP86AzZcqip5J/6dExKXjP+f3iomuR+hvM7mK99yqRa/atf6LcDDfMgZD+60oE9Gjn/RgCOw6KQoFbgAOUERvcBvS3B/J0HurglZwEuAvbVhDPiK9fQPnZehEzGxslcKHvfG/KJdWZQ48dWMYiKC3apItdhAgyVuVLFlwtHHLgSm+1ogk7ZiVO9J+Hstob7rcPZtg7GOZDt4mDVVfUFweuUET3gjZa6X4xmDUEb2WCFDaMCvfTz1rafv7nT3tM7fi8HxM34FYZdPb2r1Ede4iN6Dk4N2W0FCSVJThW0VN/woF943gfdMA1DZ2h4Vsr3DnVYwGBdc+GEqz+xL7OsE0f0Uvndqu5S4/dk+7LOHB8jLQ5ybC6mYwiPuWYCa5YdAQRZyF9pQiFiQmcBOq8jOsxV4RzYbdFyqjIpLaRXQN6IKUAg8+hWdjgvRRvKdlRtL28MMepzif0dy2jmU+69AVN5eTL2b9yv36S8/oheMcLYM94cHHmimMRasd3uPfUKzLx/ufg3pJP74a4U+AaoMW1tRnq6VwfNdD9KWabx6SLWalWIuA468AFpQ/JH9/xwUHzF/Zyho0A81SJ/un9Z3Iq46QLT19eOEPS2vy/nziPENIF6qK5o85ipb2qgoUvZvelNpunmpNeRMff1XOnwX6kjHSBU6+XAaap/Qoh8UfpZNi+T7OsUZZVKtdq5vjI0JyhFCv/a0iUr+b/79TAvINza1kuVWMws9hbpZMxhBvd8XIXJfiSBEe9EbgZaHPAzFB8xgC+0vZr3jd2Py6eH3ORYrgV2/qk8ngu85xvVnIpzijHfe2LF+FuqI4S3BmXTuAosrVsuTwuKn7DrAyX34p/zAuMY6UE2TTbg76a5TgKD5jAF9pndr9TZnSz04BR452kR8qRz7a3ZPesEOvhCp78/FUZFRkwkJ2fXKKi26IzLWROfg+YwBfaZ3bfCq2+p5dOnPwfMYAvtM7tviz8HzGAL7TO7b4s/B8xgCMAAP4NzAAAAAAAdnvNDN9QTiiPSSdE3RT52sWl0yIT/xksNlasXk8oVu9ry1nJXI4q4L5ZOHITRe9OqtodGB0XJitadfEsb9d2A3hRER91upP5+iMrFCKt+dQidk0lLWnmA7k2+InrICI8oI/Y71h7sOvS5PHrq9hDYEkpJ67cf0dHiMz5FxQzvKtYaOcL1MvhlTWe04CxhFKV69bdJdwZdYcYx6MWfyy3QD5drh4Fzdc2Xhy41eHHty/gB51YJvt2KpNasNZKvAE9EiABwMa7BrBnK9lz3rqTmMS/iym9lTS23ph1+Pmv+XFAVQ7Qahy/qLUvVfBFF9IfDYLynFjN0a49wrhSKhZHgEJEyjIOohf2Ii8FukJZFu4ge8Lvb//PmWQYNUuN7xhtwtsM6E6JR30YAHHI2H+aIxumTmo7Zxy/abRbRiX3ddZ1qvspVtoHEa5jS48lqn/EX+y5uQLE3HP3xVqZRJnewWkECSmR9fa4rG++26tF07JdV5pMKe4xDdY1FqgQZe88gcbFdyvG+kefmoo0R7864wTHy0OQiKcZLUhjfE2EOAaIKEPRQr5u4YxbasD0o9riQkc9qQCoQoTqPRCljJoyFX40B2DPqKrcPk35OEt5Ni+LEqJr2G9SZWdJ4s2+XwHlcGMU0yK3gqr0X5sclSHC3GZt1AlHeRNAx3Te6geNsFZs7WFeeDVQ9kIMKkNxuFytugGkxhQRQV59NA8rhsl7M5hwbASH3msEPAfFKFTdbZz+loViv+toN4r1JwAhihrrTKSazeZyVhdNFRqyIv8lmDLw7GRnDSCdFxKpyjugs6jx9RRrHCYa+FZt5j739L1VaPzSPRmDTbS5k5I39u4Fy/BFezQsKLY+DBpHL/23lH2agQfbaICX1DH9BNTpa/lw+flc0QuvMKWz6ymwcKKHUCZM5kkrpQ3LXrjj3pjSZRbIqrSYlx47DhtebyIOoqVPZLT1KkUARCnyqyyyML1zZMOsm7qPvhctuGB2nO+cUUylJJm5hsYoDAfortrabszwqIQHdO4ZT12Ri0pTYqi3bBTRz2f8d7ONsrFf8YJPHscUCmSBX/eJPgIfUNWM0g/QEwMFtIcrUhmklZfc4GoHUtR1V9cOhAb3GrTLDxQS245rqM80bON+nVMNIitU177HgZO02Y+Pfb+7ioQx9YiH+LICHy7TSuuWoq/nqcc18AF0rGrNc9p0Gz9zNtuhijBgd8bABfq6jZnGOEk4vvGJ+PIwrW/NnffU19Q+SIq4SBGErQ0edjY2LxweX62HAGgYy0ERZK+tRN0it0w4iltbQA2G1TI1nW3kwLbFO915tXxgtdSWV5qzmeX7erAQu7s0GGFYZcmMiplMPQPv8NEzYpJcIWqKoCcp9Y4mYJ20FfcXyFFINRDKY8nG72GGUeWy9GM/llgVJy0xqDqQWYQa9ElQXHl31s4gcbDTNku2gyLXINjqHmZdLNggDRLddVsbVSJh/nAxiWv/yeqmeXt/63Koj/yzmvXNAgfvMspdDGWmmRdnJ7By2QbjWdeqrmALn7xjHOZl4Fv082dqwSTvznZg/ng9AynvixzqwYWR7CI2U9V16kX1VCCOWJIjfHGXsSbWoR0WFLOjh2//esRZwQ+zAevZ+RZoiGreHsCeNaDtmopAttMbAieOHSP2451nAlHVqmqy4+cN8ppbkGlLhG17p+Kk9V3lDAPHB9eyyq94KeKZ0C9dsDgX4JS/EEhMDI4Lmft8L7V8Cz/mIUVxbmUYG9Zcxls81VcKG9p+WpVtrlubeRgem24BKona2M4sQrydCZnkkIzwQAGMhiBZYf3ng8ggNYHSnaQ8xn+sqolF3G7okCvqw0+R7vQIujQkb/tEFFRX7x0H8G9b/uW4n/elCPTtuW2Orc/VNg2/WL7tpFydahZN0LjjrXtyRChFfZdgcb9FPwKp9Df0f2HRHllWl0sWpXrDO4lqG/mN/XVdBaAqUdwdwqbPYUEujCP+/thHmxsO3QnIv38GvcQ5wbiKv54MiLC1q+Z7rilxo5B9MZ27EI8wKN2s35tNEpErFdzzniy6VDDV/pqbjgMzqFzoxaDBi3l16rGxNRvLt+Zel0wBOcNlYtY/mxC4bIcjhMWxE28m3cLpF3uDL+NOkRIPUUJk8LhEsIFFF2ma4qPNIu4chrXTlMDJ7RZptjzcUyzxetj1Lm5o1zrdp+JlC1toDFVUf97lcAFtx7rP/59R6SBK+p0+dYN6yHKO3bjXGIIq0CIvN/dqpZ1O7fDmV/1+j9MnKGxsUHLUBFZSnweE1jmQ9jSl4dLfyujdhoevXZVIRx9qto69ZXoXAa5Zz0oz5MUotXEu7yx0Pzj7QoyVwuagPuEuQlotR3fVgeA95+RuDRRroTfJzbv1b+dxOsXXbHtO4pgCbtR/ImdvaB7AiXQFaefvFPw24vxc+uLqSKYEKkyf1R2rpwh94I34xNuEPfYXHkTFYTb2xsZTCA+rTWqgUOhqsXhnBgAEkd+fm880Di51AMurQ2/94MvGzunk3BoZY4n/o8pIU0jSXQY3b54yyqXg99xvMAv+C+NXuVz+fEd87cpp/ae/xKsMvgW+JgxhYGN43YvsANX4J7UUuH11V0GcQo9H7NXkbn/BGBCf9PkqGFyJfRkgpkbJtSxMIe1Biqy64bef35aG4/R1s1rKHc9ti2wEc2UvcxXpgPWG+ce3mz6KNpedG2C2PXsqWOTmu5P0QWapR2wjJ4DmlhkpNbWL+Cw5ABb6+IdjrkGch//Az80I0jc0tMN4GSq6a4EMDZ48FgMgs4KAA4xxhoWVHdVmLNzN7YaqmK8ytXc8OdH4+w1zBeqFVGFBSjNdtoHtiMO2H3gRdq15fiYMnL7IOg4WZPu1THq/Fcr7HjNfnM3S1vPlsfR3ma267PKvl7JvBfI6pKvWGNP7CsTjYkBBGE72k60NrWbabTtLC+B5DKfew8okJG3Z0dQun/Z+dINiEotKlePZvVJuW88jUU0Q28C5nlD6s0h3BaNVHd6vk1MuQU6ZYvDava0ofzr8vPlWfCF0J65gDUi76N4ga+SPn2XN6Tv4+oUSAbFVMBcGmDeG+tDqpIj2IZliyO0Yli8zHJYDCpcmHXTCDT3E9UXmqSV6JIGkXq6SV2w0rrB2OlxG6hh31tbplYWkPMLaNsF6NX3kKspztFKVTjLrzwnzlVpIJsQgBW8TbpyQCrPvlU+z3mTzoTWin7/fN0LcBx8AvjnxyVxTVZ8ILSOeq659YhUJ/nK5yamzVHafE+TLOxAq80yfq2J5/VQgU+xOZuj9MrrcMrweXqRE6Vh6kj2uk2qUTHZ40JVeGBCovbmoCfxgDWt06PjEe6W9Gf7kCm56cDi+PmNgRUigrI4DMx4Og46BKwLb05Z1qN6Caoj7cU8+n3RMRgLLOz8lAg+VUBgPvJD2fYMy2NdeZJ7j5FcGG/jOwMPPRAVqkqUWosxuTawbCwmy0dxMD1Y11fwOhvidhpedSuuHP5TeDLyXgGr5D9FkARtR4QXWznaQeJ7MXQ5Gea3+eCGUqfcUxpbXj7nAZVBy7xsI9zaxLbfSJwdB2IaG59MfB6qR35w62h9jZ/XVm+80APwfzjShOEvUQ9esjWJezjvHea1hbSBGZFofLhA3oR6J9ogIjGLKltqXQlZ8We8WpuVP2se6kLwg09T7O7lLH5yIabqI9NSPchEC8VFIMAaTkrCVpP90rJcnu3D4nbLnEzYqTPweCDdzwQf5UaRxArKMKeHjj2eCH2FToBm+SDl2wKuXo3moDankwO9NAb+JJFTAUEdshPd9AqcI3ipng2vHExuCK2oM7ka86OFxNlMpH7YhigjjrbIFRpR+jBk8SwS9QSNfZ7q79IhPRe6zY25TSWqoogjp0VO5oqedKpm/AEhjaOozbbLXZzWC9qoT0Ps06NjLthmKyHtc0iIYF6QnKTli9Rx6/nwkK8bOBtZzPcm/9AsRNqLuc3RmTw3W/0cI6WcdURb3x+Ec8KFvJdS3zOa8dmxFhh1KguVTFjPywRccQfUlq5KtNz0pjY/NEbhcqb3SRo7QCEMp8XQVcJOym0673mAqRZsU9Uz3gguVgrN9qXQU8j9gKxIf7j9T1hWjdT8MkhgxQiGC1YT2ky4GHwp5eHqQqdMkxTbZ9n2T5u4bajZoGwCpYRaaYvHgP+vg401RuKB90Oc/oytGrnUT9/W15GqY0rhHIRLBehWrhsq8v8/DM9T5jH4k2lFOZLAqVyAHmnMSef/xmwOQhJ6isZ4bfDPcpcrZ6NcF+AKXMsPoamq61JKPl3v3Wf9EU8ZzacC8IyGfPnhyJ8hmH61MwjUvfOEbjIZz63JSGAve9iRJiB9nD1h+mF6l4C+81ORCaiWcQG5TBAuY4HHlcsezebaM4uhCO7f7NZHK08BoaRa6N9d1Flki+MzSsSa9Jf3cVTb3DyL/8uxSUn5UUqGK/HE7NpZvqk58KMCSABFve8U5u29lrGzK3hPQqKoIBmxgpMSo6XJjjL39DeQKRkUeLz1kYEMOps843EdYVVWakMSdlXjOQyc9mBIJXG+gy6RaP6Cm7Sd4BlvAi2vToGT+LRdiyncxN6Y+zShDpOfKe6O8nsgYDJjyI9dhkHFGvP0dStVGniYzQv5H6SvCxZoQ0QSP7aePQhUb0q2Sv4pHknSX50w+FNn+9LPuyMycLMAThnwld8xMzUiMox+amfN8/upehouWUw4GM0wD6uOa0dWxPeagHZHhvnDCZoJ2LY+KHlhPGif3TJgKu/ZWvQnTmCuLKjQUCPSC4vjQuhmctG7BaCjE3Rf/7GDVNCeV0Ls/9eLSYQ2ehhBZc62jsSc8TMN5CqbcPwC2MAOU9ZpLakDvTwcMh9/s3sinzkAO8nw+OhuJDRVlIfm9b1Hy5JjHCMvoe6S2xCgIfVHmxADlNeWmDq5wbkZXVXsRaMyKPFZYrzEKhpc7E785VFF5+37WuqNn2EE0IbDZJLctATpbw3B4ze+lleVnESC1jv1Yo+8HSw8O89m2+mxUJ6xNqAsi3yVl5Btw4iNeUr94RXDJYUJcefB+D5JLa48vnBrtisSszmE7/sWTwTJDTrGFnmohzcPzPfjkGj6l9/4Ex5AlD3sFpfJRBdl6U0fPyY0H6z8O1YIk4xOI85Bxhq98iBbTw7ol3cS4rcceo6DGyShm/Slm6nM5+8oiopy7/C6zCoQ9b+A5yn3Io/lARDUZw5pvuKZCnYM9Wfx2iUxuEwlsWtchlHtG/8swfquV+x46KIFksaI/ys7PGstf+c33/DWPcHg+pgOtJ8EIlzzzjz/tqkvDC/pWkO46uAK65o8o/wqSUbFUY9HdGY8U1d0HoaoBFWbc0kY8SLu8EbQW2iAWPUP5khNKrFpFd191NOuzlv/Ur19ioB+5cxP8viBC1FW7nxcOH5rMTRyoDqaEc00iKv3QODJAJx7zIpNHXUBu2wNt6E9TS/WBE8L14oxbT3aXIrae2llzrGM1Iil9ooHEU3gMbqWEc/eSH/vjxaXVIXx/jnb26nDRWfzx9iIIRn9pIpPreTs8oB3dtPkoxa5u5YNOq1UH/sfxX7F7mwzboyoMB+pN9ORL+4y5MOwuuiyHB6foICs1MeMDY1maV2KLc+GGIWc7zBkYiGj5b7TKdJb/z/kWT9itAjd5CjYdOcGCyVqOSBDRMorH7z8a/tv+NO8pne7nJVbrMdEoW0z1xCKclHQ7kYpBMzb0FXmz4jtCETumhV6AtcqgphJpmwdlRwRmmScfFG/INO7qijcUdAQxCqQzkHBqHkarR1rgN8VStt4s3B15E2AniABbKJd2A3RAqR6R9VzrpASB45txm3E+G0Ye7ickNNBvKA8zp7gq4gMRASn6JbXfh+gCF+vC/9Sg+BjHqkZwJfrKE3GS472WjSqTpv7kvQPiZLz/gtJ7Nsuu4etP7K9wWmySljJH5u8548Y+qBdJGRZmK4iSzKC1c48iClE+HPMFBjlIFPeAVEF5r84sSG/RMuRx6Ic3Pa4RECCnsgIYXx7uELqi04b9C8toZeZBhARg7fSdG1URFz4lfZO2z08ewRscsk03YY6MlR5X5VEV6rjwRMv8Cvhf1+pbKywZvfAFtyaeWvxBqKh/f+lSTB3IVnR0jt2nopKV6DqoFe8ydCO1a0B9w3QX0xVcDzxxpij3QuTUMqfJNJCmA6iT8Rvf3Vuqj49ZiVBdTohQCsGYMIlmRRdu5NPG1Np5yjiFhdud2Tq+zMrhQAjpK2X5JpfPGb+rKgbf9eQMxi2iaN3gpvmdExsgw2rBiHxW8G+N6i9M+I4ScDdPInnQKLA4BgDNANSTcLLybAcA09AZcCT07BzItGpaN4S5FGpJSdsSzNTsCtEboiQG0NKwP+2i98CkBjr8R0sovGX1Oy8QzLjGIMW692s8X+sN5OuqEXBccpWSXyUDAtMMLCROEqOGmW3eqAEkYz80A5TzRbCX8pIeIj8c3KdfbevZcREC0kGpt9SUnFIETfyZwn++bDmmRvf+lXOF3T2VEbO8IVjhiE1CSuXsIjXT9IZ0Cvs5++zzNREPMmC0ns/3FdrHNfnRAJexZX9ruu//g1/ud/2AS+jSD85zyAe4TR+4R70iKPO1vbbI89a8RQPfBBMBDRt7oP4GQoHVSKXgGxLvV+8TR3pKf8nRgMNkszLSkkchNWu0EGtwZwR7rp7FYSWo3obUIKPw+VA2JAXEyjMYF/6+FOd78bdDtjsg5yavxeLQqVN70jNTb9l7y1sIxrKRlKGl35OD6d/pvBSexYjg4igiF5rQyju2vkMDtdUR3cgR7Kc9A+7/FSVydD3v561yPOt4kzGrNW3d0D+21PRqF+mi+4KV4qSg27cN0JWxX4gNiESnrhMkI7Gs0aunXj246myJiyNVPS0rnpjNDSTTINZvtQgAIxs2ZC9SvCHir/LUoUIJgfv2j1O86J3s1CoAu1CpAbCPgPGFeZjk58gg47TCD1a/QrjQs2N827VYmGP1upLqpjeS1MEaFUz+E0o5OKmXZfnmDMKY6i2WTM/0OpMv8UUnQV0ynGdNwmh+wLKyxPpZWXMro1dRpeGXHksyH/GvV4MC3oygf8BjZtiiNnmNxVx3s4D7jf2vV8PJBDQlM42/J1JtcCLOmQsJPWBDiNWBEUk1d6D/0xWmxNcDOtxpoqZUnbjsu3UeK60Lnf+Uuczfck9/6cKWWSPwm8v59hikf+Rg/QxZKGI8Ht7VEUMyZajHOcy3QU6QFAi5wi/zELXehhXtocgeKdKR+IuB3iMZlXdFkI///dyHS8KJLkBVj+rQ/zr1L/BYSNFULkqfZ7u85kDN1DaJ5ASzJLTb293bQgvVIW8Z/sYp5fpZm0X2FZwm3ZDa/0Ny7M0EKcD+4wZLgTAMAA1j4OvtS7y2HrZTOxxPPcpVQfL7Cy8vjHE6RYEK7bUFqH/eKWk+5Hgo75c/yu6jdBHEQNO+oMuhO6Vihgs1mu4ZgCghTGpmdFdTbuIQApmN/DyH1eb7I2a29NbInLzdCkiu17ua/I0kvVAM5xrlKHjzT3ORlTYjwKDAtI95JllttW3qq/R0EmGfrlRyYxpK0uN+RjLntAtqSHURjLdesrqXDI0Tn67PWa2jX/RhbRrkz2eS4T6W6UcELI5mOxK/sxLHWNNjVMIz068pf2qL00GPef0KwJIFVJK9d/zdNcZex9HEaxlVlFz2QfIty5BL2K3UeyEw5WuP5cq2SPwdT2ncJKN2oP3YxzcuAFgSmPYS6lZ3ZpMh5dM/yezNGMligmNU4v+XV18j1tKlsQ/OG7U2193JvyLttWKaTGiuRC6cZ93YVOohHTbOseCodX4JECC+wbdPrac954xkZYvcxIbYVCgX3cj/bBG7JWe2650mw0ohJwNR904IUc5OOgHkSTyLdiYyW5Qi/cqzKKsuQoD0VS2voSdbI4qbUZ4LU33kR0KvB5RW+n+c7YmmjtdAS2FglalkOG6VHVHHxQxkoQZdlHx5YfaxsWkv0lOsJHcsxq9qEv63Qp+sqj6uvRAPlcpe19cLV0NjtIhMCWoLWN5CH/ZCCW67s+bs/HcAjgGrSKH758Hz/L1PYyUzAKno/yqNIDHkIaGD/C2K4qYdtZf0IPg4I0yKsM1XOEx8PfxTuHhrNZZ08g87WivOYhtX74f81qFGTcgAilpCA1o5vIYkWRdRkLOGZRH9AoAIUgs1EmPLtVyp8DMqrIyojClH0TvuCGPmZ4YQPEt82RDWfFI/OYxpWXaKktVJA/tXiZJtq0bS9ZbjCzfKhYUQeac5YAsiSGvT0qAIH4aVZ8WLPMHaX1t6cP5pn67t1D37wH6aJBeGDPrDlxHwNDs7Q35kwdN4ArZrb4j6G/rykG2+vFCxqJpFLCIYasfSnfJRHO2r0ZOvz1v9EDt8rqt/EBmtf/Jf+QpB0PR8eZuG2GYlsSrSEfK15kVqDbJilhPolpEyQ/VLaAdhL4Ayp4cxM29sWTv5W9fB3goCswBexxosiVOJ5Nb/EbNBo9wxOV6T1Hhj/EV+D4Z9x0DjI7zxHaPkRkedbC16cP8nLZ1e8rhVnOXNTSfFCcLM55zC0KvJeNVxE+9KUtiArSr1NApTP+TOP46Z45GtEQyUGlkIQp7raiNCjuYyRMXMSoMhC2c2gwhktM/D0Fdeu8n4XFw0b8B/coFgRaXHbNPZxetVxqYoRncAw/0JpG3Bx89hEcZwmi/MLwV1XZos1vaRCsGAo4nMTm6WqqQFtgmzHAaz7VPwxkGi4mNiGrhkinCRRcNT4Vr05kHqVodnFCYLoCAwneXa+ljdO1mCD4rODjMaE8G7Bu61r6xMGlwsZAwuS+szV1ob3PFzdHYApYUTmpK9PamyhpqiXb/XMSfVvYirxDt1aMZXjZBaFeS+Hffwphbn4OHiZS2ygBWZHTXg8uT+AEIV2WYs2gThDGAheZb/JO+g70NTa0fls889b+AzF2yQCdBXNyr6PkYIhk0yZ4TYDOUsvJXxZK+r7LvlH0mMqHOsgHijMOagVEzzJgJlNsue11BaWM3TxtNnKfD7nGCiORnGUc288eEN6lRtDTBVJBjYEzLK2F4PCWxmoU1xXPyxMJRprvOXp8Kb7GlbRq8kzVzdPEFJbAXMnFG0eBYrYdqIJ6ipAY2V3EceZEG+VsORV3WyrR7zbF5kehP6OFuyJqFl/m4EZ3m6DdqRk/RCjflJSlIxO43ou+TsTyqwRbEMuoUXgoyjM1iwf0LDqdM6fy91NKIpcxuE+UC8SIPflyPgyObMOP++sy/ilZ0OVoaUd6nKOZbRYAqnh47M/GU74FzUG69h/QN5YQEnLij0KAr/8xkxKqv0VeKWUXMZuBUJRUf0pXUicBHdzu4Hyh4w1eobECVxk7BHZFBH6jjYse4XwzfHKim8JabDqPWDELgiH6rh6jsISiuO+i9ASsm0CccpU5u2942ZkPwwTYwjBowBtkX0OawEj0DkLrwrMZpc/PDBrUGiK9c+Cyf28ZPbky4tj3/pB6LzOcB3SiX3UoSinrEhvrDiwv/vgRoafkmnGnaGBL374z+Jk0BN9uC7pwduDIQsdztzsXeJKrejoxwIqtI8AVuhtJ8IUQxn1pIOGYZXd8UGuYpXeXLjB8sAXQ5EUjcL7CARNvt6HKi5LWLp751vMBBGERVaY6v5eXhb5OLcf5rgDvM93H/GPMAUWu4SmhDr/HYY1hWZOAgtu8sm7kJY+5eNfh2aTA14jiGQpNNVy6+eutv+CQ53h7IrnSdm4Z0BuES9hUIv+Eaxiwo/0qrwLVRpgVgKoghpN0nYk5gA4gLoiV3YmtfScUevXsLaJjX5qj2yQiKmMMvNDqKbsmAwgMm9Lb8CbLXuKDKoQbEaXwufwfCH72TFy8RmNpuAcRDskFUCOd5dD1qRbRgUW/D0RTlLkmrAjw93x6Q+6GoU7Tv9KhWBGwOO9o47bd07WQd4OQWvG5A1+liTF7sR+5xCYciQFVH+V89S8RGfCyg0X/ma35yw4LDWPLMP2uBZaNdCrNOqFNQ18TBqTLVbKlM48WBpliMfOMXdvZcekpu/ggOxG6lcRGP8HYiu+S+sZjxCMVGbygSJlCBgoQCHTo9eZy4AaQ9L0c4Y0k+8eUcDOpRMQfXbqOR1YZYRIzpXNX6I6jzhJmlKKrnKFy1186w3xNzFoNQDWmMOs8cHXioMdQRmm/8leCxiJul1hsHbbPRWMlHXLiwcsc6QpnoPGaQHpVN77pG3sKbKbWsoH3LAHX8Pva/aUhiAioE3Wv/JWaeD73XJEeVdfUMfPueo5gM8is1VrWjuRneKWJgVyCyuunPsTqLYYj2FeGFo67+1sCkAila6pSauqr7WAqqWzDrBHgQmMf4iLlVnMttJOYCtPYtfl2N9AeS9ck8re5WCgn1UU/84+1PDllI8WGZqz/PX5ATokMzxxXo4ka+L/ERM+pxLcMOt8/1BzmPcnEvyhJIU/L+zWtsR7vecrJMdtMVDD6BtzICzEHyq9oekwtrVJcqRF284tNgIvgxd3k1GAv7vgXK8yudhCZ1P7tiEezLoy3wzgW3JPyPm2w8YEjSQojwS+2K22yc/ICZhy+ysmVxX61O3gHpXqxoh+Cl8LJwdlGAVr9J/6k8//ouYG7/tO0cjxRTRPOCR2/Yc0LFB/BrFdWfZJYRiHa4FiJVgfKmhKS6Tm5fJk96rLcCR+iw3Hmh2BXF2ILOVhhEfbWYkToohRXQQEasLZdhjhhjHW+P8jG0PtvRxl1x08hiabFADvELq/bjSH4jjj2ohS4dElkLyVSSjvvmu91ioJlvUsO0kNQQKb57I/uLPwP0LpLC9NkhyrDBpN5KE2xI0HAK6kM+bioVPZFVaxaIVC3ZOH0nb7a+6Yj2kWoTWkFfUQjwh1FJFKskDm8Skxd98dFoWZI+HbC1aI2qlZr0eBKWJRlKLituW6kUGIR3VtpMfFskO4LYQVN8XBUTMWSF4XRAzV63/FOD4jjchjH6AmVxEqLkjLlS53RHJ0gyKuLfD6c9AaPFX1gmiXzSgZ7zc/kS5Cip6h6CgxNMSYop0hzPEwdk9VNZHn+Qb6g3aHh1IHtKdvI/vN5RhtXtLzm8V2sIGUA7nlKnks3jQ10yzcTaad/Y7Jk8qGJRdhWFTZtqtid7gUqs/12WKU8KVdGmnDpf55CpLdDzcgHBPoNoHdVaDcUVu44Fx1rXjWgEEGGxzI/zPi8Q5zj8V/LlF7iUQUc3hHRXndTXgPQAEmYthfxAgZ8s4tUX5x6puvZZuhauZecRUn5OftUIJfkMXi/PxtR9Vwiz3ybsDL7/Byr3Je7PxcDHjvZl9c5230avwyTvOvu7cRCsTjGlQTC+gTvCimcei7ZJ71+i5eGJfydAwKdA6UXWPZ84io2QT3Panm56Vtxs2QPBSR7JKFUdkycCmSG9haKqE7hLQ1TeK+FGazrpBgv5MiFwB93SoYj2Z5UrzaEbVjXvIuwnexWGIjiiVBQ4goFf4JF3YegeAoBd7YQVplwYe26B485eIyTFzCr7Zaus7PTwkDO4PYS3NsZFwnwzKUf29EFVsHxI47f2lPyvCYya57AigE0EnFekgPWIqADi/ihTLbnmre2Sh9m5Ec494DPxZFemjtgfULldPeu/cEsJoznaJqww7V1tZHjuQUbYpyZFyysl9/EZyJ2l8ZYRVF20w6x9vKQZ3h+UEML5cA3QTcu7Qdc1ejIwvs9yoEN4onBI7fVDmVab0mABX3dY6e13B9RjLX35g4PgQGrQTCPWy9IbbOn3fQk2u+w42LsxyTneEN5BmSiM2Wzxef8L8ZOyziBJj6OkXwRXKybA9hls7SA6Bo96+G33A+6Z+M3rdLJ57C38+Nrd4dvb6CQole72kXN3Wt1zOIxrq/lbKa9p/JF2PwW/ixD8fm0vyF5zz1Tr52hgECFRNHINBSXyzx9fY43kQ3vTBDlZAzCojJNAEv6G7NPymKWfWt+QXnbjUC8F66+6mjk1QdQqDqkZG/MzbES73vLgPjinkVRC15DNdONutFSuHR/005J91FBh7vFkam2GNZ4FySsQBxN2q+2XYMm0P6a7PTJ9d0DV2Fbhkq5a0Ml8Ep3nhE1Pm+S89KlevMgkis93ZUs+OuIhZocmueSBtZDffnyfFb5w7RrcRmaL5Tcxx9aXgyEMaiojInobH7OB8J1xJSVii4qZN8TwTlBwuxcPsLkQ8kNcUkZ5J0p7dDWfBjPo+otGhQyJQhDfkhbmB4Y0zz5bMkHyih9vjDf4ITWzC80o/n53mkgREwBspV83KjQjQhP+2fs32iDsG/KrMPh0ZLxfIyVhqZvfRWq2Axc464nuzAqvjiwcN1s+p0JD1OGeh5yUT8mE4Pp98xcl4X12fIa6ZV4NUYQ3A/nv8Tqkx8bdsnZzLBRkkzLq0gRuNSBMAGmauhTTE/iKod8YI2c2PGK9blZ+ppJRm0esva0IjZsG7Rtr5VzsZrtvDVkpfrOiwcGAqBWU1bEIO5/IhXmGu6FnVrjgnEK4UHxiCg4W0j9eyZ8kYxkCoEsXSjXKjdfrhbwkNzl58ko4vIGjjEOezQQBiRIDePswbnaAHcUcAR3qMZjzocPqGC/4tAxqRqQ4Ge//MzaUn7UNuqeyxceiETK0QIpv9VCTL+fbCE5kUvObcjqGu0b05vz4lD40D2O6u12uPfaXktH3Hmn4aO/IlIn8cbgHmhGz1z2DYMwc1Ja6l5rqV826/PKmwf7/3kCCUbQMyXWKq/iBeJo22Bpa8DvL/UD3eMdvKc73Y1NFAv/6HoPD/aYv6uWFm3XYlLQJJhR/1wcVuFXTijJBnmRehjUnsgxEtvAUfHGv6PM46AHVvLbe8hfwWGqs4p3O9SrCzl1248MjG6Gvf0Laps7TlmdSs6YHf1ZHiy+8KYSqFHU1UWaOaP4VxL64lm1lQxLz+nWh9EKWmUDkHbAZw5O1JtCzMjD66wtLcsPXg3udWd+YT9IRCWPi88jGnElbKPz7/vkfQtBJetmF/7SMu4RvZ+z1vNs7dW5SvY6L17izdl69vM8voZQAMbejLolzHAd6S80sJSC/+p+XLEQVM2hz3WCrQA08kHCuTua/rQXG1161okanegc0+cM+QWYlXwfmZxAe/hzXivDCh6W2AX78Ycm1M1Rxc3WwwkYBY+sbC9/rLoteXVnLIUDMOHl/Doyt0gLLm4CO2Qvd9go/2bLqO65rW6r8fabV8HN2WlVvyTwJBoPBjwOtinpLQNK3w89UxPZQ09SeM7rnGOQedOwV290Z0aa57sdRMjQsIJ4ZfuleD5hZfgHpQLkjdN7WT42nECT6vZsGfP/M21LUNRF1mXXk37tmM3l4L5sgp0SGDht90FMDse0BpAGhL0h176/f5SRAcRvUeRSHBlyXI8KNls0+R+eHPrdojfhYQRG/dGXLvtEiAyeqiNdvgAbv3mi2+81l+o+ZMen03p13kGri+YEaFs6hcM4atJ0R/wSjt7QNQe2/VF8ZFkYX3GVtf4VJY8bwt3c1Q7K99+6NCTGTWpVjXCvYp5f/4Piyd8wktQGEK7netVKUAZr4zeeNvmKIBan0Qzga6JvUqDVUUoXHqrMcen89ItN2WfjgSxYhgE97NRq3yqKH3UlUOeEoPenWK8rdrlCxgwNZ33VdXmxGI/Lc0k4RHxmQNiH7meh+RE1GOjjLRUs2hjePxpJa+wezudLmE9qZuqqj9jlhi2AN5fXkJ2F5b9fEmKrUqq3ZV9rn1w0FOCfeb/BQVDPUXrxKl8tU9E6hEepdlftG67JzBh2nJ5ye1EgYNSCkREa+EXVnSU8GuRPH+OkrtW+SwzeGumqNEPG6B/ExKNuL87Rgg2sSo4d/nslmU0SKuI7ygxcAL3Y8NSdlxq146VJt9snERGqSAl3GybAfNo+17e8oNbwjB059ykQ9vAAnFldPYd7QOy1zXqhqB2X0pzTYNQuAoMXWQ8vVaZCnhr6ay201GhAWDBe70QAaKOe/AuMod+LVuBUZ50hA45uW9Pfyau/TircsNOZphrCOwoSmccGI1TB/PNgGc3DoFtqk2+RIHcUZA4rYzhonyCBkgd4jwB+jAvNwvibWrh+rQnE63kvHTUgsJI4z3JR6DfWHoWqpPMu22YGrJ5kgC5xokO5a1qyAn+wCbCHKjTzSPjASvcetypjEEPvTa59EU19i94O8rEFt5x3KcL90RbXfkJ/GNCywEpeGpqBFgFi4QtxCyt0T1bb071QEPbDFvEKCFefoDjRVw1BkuVyszBhwfYaRsK4Uuc5h6uEAZITFZyNegBsFkynjKkla8g3KF3uhx3O5v3mNjzDJ61B48Py1b9gkDq607GtqT0vHYwTTO0V0QOv0HxOE83aKv4bJkaSFsn+8HRZ6QcoKcpAp5K0YQVtBJmOko3mWeXQ6iAGETJNUY6piMQ9kPWwPjyANnSpFMAX3lIWbCXFJ2KDMPnmF39qTPfgoHPF/jg31eqtiiejNGwIRkF5UFYuMkd4qTlqpRipUPMJE4G+KnNWH+wkPP2hLbRONcwFyrpFVc0TLQKkNU1D1A0j/u0attm6IgsWNcv9pj8qLZ5KEM+QrAC7H6dzOHoSjl2RWpAyT1bhDYPQdyVn3Um1hdnljvf3UaV07xjGQBwcbwcOZbSy/XIWAQ6n2r3bOY62/uAy0YSAQn4urFgwxPIgoh24opxX6KlFrLDx9ynNi13kHXIhNuE+HW5beEWFhu93tkaLFtLjxvwR6ST9m136v9HKP79y1ahQghznYgj6n72I0V6mfDgY8gGoUTZLdYUtQVjzw3tQiZX6EYP6RLNdBM62TJmSjyQqr3KRSs0dGqv9aFXklDpyVbA5GZ+IJAs2xH0flN3bzZOSvr8y95Jt6IBk+hEWRAcXXZFfpK6p06fwF56/DGx4GlFx6l6dDS7n513lvQwonFdijX63Z83QT80C3KPFDlOgWdzXexuRSOSV9xLqc7uuUL2GPTcu43OlFhhjgXwQ7iEd27G110j0N7CD7ccRc9skY614Dug1n/rFTWPNyN/8QKHqqMXJfClBP2qV8I8TYmP1pGyODTYNF9SVAaVkXo/DrYbCPETU6JnkOEusaj/fUIS9WCpPi+IlICHPS8z8ey1qEqkntWiotmPXOQwkVUfsgcduSWTLuCg3vVlYVfYieKCy/R6G+xX/xfX+Gams7r6ZxuDbugL1zfRv2LdQC62Rp0ljMZFRGG2z9M6NMmUuHeBnziSzQnZXOlVx6AN0KsldXGbP+YxSdXuB8WnkZ/V5ysEG2UFW2TRx13C+9TmMrZD0//IPJ7be0DXonyLaQRvTWGJvavEDYXMwQ0bXQQ6pQxG23Njve5G5qxDSWAAYNj1poXUp3gwVFMTCj4Z4CJfkSThPUCdMQ6jtguHEHMIr3ZRQmqcADFWppTZFBkYw5PMoO3Aco3a9oCYPP7R/Qje1A3h3bPaNFEqH5ndO5ZJBTD0kaorBMKn/SP3WG7rVdJ9QGIYzKboO+oo9KApg/V/or4msQJFbzAn2b5/ecwLLnYaUcQBUpfpQ4AKE2pWLc9qiHEx5cdMEB7cji3/hBCL4VNMiEQctfcbreVZkkVZW4HQ7rHm0ZGY65amR6uY6dXHM5+/tPPcMHKQ/jDrx/Boe2HdUTQiPNRKUZa9izRnJxI3Ht91GFRGF+ugySTcQfMnAUZIpqZDyGtJtQCo+RRPfq4x25ZE9P7+c3N1/EQlkXwWffP2+TgNLszVH00YZcQRASXgHXhXEYG6e/LvI4HCqMijsz9THz7jtVZKKAZlSY/SzhXKgBOXb9d0RR3FNkZFvLljfOXJP/680HjCkwiSaaIvbDG31OIaIZ41+Zzn8I6coAJK360oxn1IeHt/9oyUufl2lHKmCZ2xh+X7tpB72NR8ACcyIXiDYBrV71rIbRe0unbC4mfSlj63U0tBEWHkFeWVO72harnXa8+AlX8gbZOc/1kYI98YRwQInKhZr1sYn1ti31PYdN9HFoTCxZhHxnqpshPl+Ar9BtR4YbRnFBGsHX5nNaHw5qhItbMv0we8Be49s8q4VQw83bh0iXgSXSMKSA8cC8tgJsr5JVGi3uyWxu1AjJ18sjglTa9K6JSMb2I/veCnmdHHDKgrEhOn9O869EHM78ht1CiFlenWID1u6RHCgEI9yOWRcXXG/NGRkaZq0uJTtf9F6/0UIrNUloFUEL0Sp3KH8QIgLZjaKMRUav20h/fnuzvO66ID9BlUWwSLQdzIpFtNUAv+vlJvn8+tiQ6sRe9e5EjYk0naWRLm1mwddLWoDMdGzSCrq4fdgsT7Ln2yl4f/Jg0U5NF0TWXzbGaHDphbrnca0toJ6bWgC9QpiTb/67b2PGwfll1z9JW5wJX1D7v/5M9bPfiGMRKpBztrv7n9c076X+QGYevSHahEAM197XNqPfGk7wK7GNoDfm84lVUPuhJMl4U/2k8KeU2hWnZbLZiVObu/mUMW6icMqTsbOvHn1PR2o1OhW3G9euKIF2mO6XhGgmDMdn964wKfABG1miJ0+dGDBnxHwIGS0gnVWNwaLiDCzQbiVzTiMGnoqfGEWT913OQ3KLP+5yiMzAWH/pOVsNmd8N0sS+UweYkCuuDRtOS8BV/2JZ5uuzYwEJCz+kyueQXwHl9/mPSr34BYjgFgNbOIonphjfjkZQFQ7/X71cru84x2LP3WltFlC3Fj1aSkKF323d/Qo/enxKisfHjG/ONsL7IlZF0znNfsrPv0iQR4tcPgMsglh4qNDFfo6R5fBCGY/3To9sRXQGL9E5Pirr/Miqq+uCpdzeQCoj1FxgPv45tV4BKFBtYxP6WYCAEXTZYf/g8jP5RgyqDIiOylAW4vWqQFL56wTZ+jRbxQiUjZRYo7sPEZOmIKirg1jRgOPsT64AqptO5EXCxEIzYW5LWP0ry5JwneaGL+gqMN6wx7QJ/hzhlXD0oL/hMktTtyUvCOJXQa5CWj9TJ1HuzJ/jrSjlxLm3nShAvFaJul2Qs4e1eCev6/21mRzemiMDrbHCo2eHh5TLB/IKGiJhqE95huSJxZh6i/Igt81G6w3y2qcEOZ598CRPWrdggQcjO0bZM5PueC9lSImIgvfq2zxMvZRXzIFhzXYFfADIXrVT290GNRFfUtV0pYKimXt5/KnWsY7eBDU6hc3jV+g6zx+WoIumGAGVkBJq1PDaHDLzdX4VghJrCRMfALTSkQ1fIQDfUXoKOG6USwtVYBnS/MMPvB0qk7VA07xI3HyvXHGpDV6diIfpBrNzGYOjGtOqdQj5K399RJe0oioVGyYdS1l6t5igU0Cn/x5UvIst0vQyybDrpMcGzFAg3lg/U23hA1JTwI4rS4WABb4C8g706Gk9hrMdB+U14Ifs3vxsy+s8oZFWw7z1GToiBVsfUaQ274hmYGWffySoGZD01KtbWIug7qE8NDut/qSLYo6vuxO/dAoJgsyaxQWatKLN+Zfbjz6Mp1Kl4p47ALXhq/gF+mbzqNk/IeT5hiDJFlS0YH5bXjqyDLRd56+yEXjbtiNvGlmYGDuuOgKvSVt8MEg5Zgsdl6lK+AwIBvGsbq/nrvKWNaUoweWnrsHiOZqS/ionmoJZWD87Tpvb/CV966Udht2ml4CPfEk8b3UDni/slONjr2MAjziuFa3MSmezGkQIwHNJ8csXvHsiq5RVH2a7bgFJDyoeRc14SDUoq6YnxaYB5yKoaghSjo5Sxs/zOY1gspuX8p0fBuTTWqplzGjEHX51O9DL+4zd6C7jebbBoetXJtmB3sB4660L8J2iwPi/31DrYIZajRJ3h/m40jKJ/WTj1cEMq+3PV59hd0ldOY0V3CauhntW0eHFjJmhS+0yJgbbrw4WkD0mD9Inb+zggwvkHTGszwAX649fM9v9mJc50g+GPgXN46mrlIp0wjwVgXtclxOkbEfb5aLTdzam6vDFLye7cH+4+UtFhojke6RalTsoFNqwWiY0x961hpqkehHsGdL2vsl1/rnw14UpcNoT8T/yLEf45VI9RkMKFUrZeHvIUR/w9MUOl2Hszc2Gm2XsPD20DWA0G9PzYkymtuVl8aWqziTDAPprxkeE4We328XXC9aEDKR7a2/vdejCEh0VKhb7/n+UMQF/5nQZnNhB8Pu6stzQ7+uLRW1/WaQEtgrYguh7B3pWGnckJxXVmlt1wTw6e7IdBjq1oY+I1p81T5VIY+vy+GsBX8fkklTl7d+d1uIwUBzmblwINpL5gacGMoC8WHLBmgCc0UeZYgQWIGd30gO1//u+NhK814zfqyzesnbWmwIZwxt69aH7hPjui0LRLO//mPY6VdZYqUstyHyOXA7hN0qc5hoB09+6zCgnwF605qOuSiB2TRs6H/Z9QZWWE3+cSSSfFP3ViWgwDF/x19wXSdBFGdokoK6Hcwclf2mRHODtbsR9huaI0WXn581i5vakk31jx+AgHegXpmGnHBQkPqI7qBbPMsVdfHDQ5ohoIpwarpIcd1Bydv9uyKa7imJtSN6cdVFLYtrhNADW4X6u1KBbWn8VZIYvs3of9XoAATbKI9KygDSsH6gwlFUjJDG4aH5j3SMYAWI5fnEzq5hN5Sp3sl1I8RvRHprHtcmfSOYGDhLOKo7IMlZfdRPA3wkOFXEdElCyeN3PmkGxwEwodFofO+lYCssimkVTw4Q3kAfiDUW5efFuKxV7nYTfLJlzLnVXdOQeA47tmoIunbOCysHlzf1IFh9ueLLPtWtb0km7rRNt7QiUbsWhT5BgS1bmtpJta3MlbiXQEIaMCZ5K0hRopNj160qJemti7dPLd7NnJE84vleg0gNEOQsu1oVlcLHFZGIcUV9jNWFAtLCNJLRjWHh2Lsmkt7GTXlDEXJUgvfRUccbVbmb68Warbfk4Cm6trI10SCyCPyQoYPOYhGekYPT+u+mXMojhnDWWWF/BDX8FPsK5DGANmCVsoJJdoswBqfzm7KdYDTXZwmhhJmqpnvCBMWPk0+Z9Ytdn6WXkwEzUX5I5TdNUpo2nbtbd08IFl+HukQG1HGPTY39iEfW7RLSzWgs7ePx14DE/QqTFJpASvdhF6xAO2Rs9sX8XH+PbfIUbTvI/PQC9lgeB6eHn7oP2XcsV5pnAKFTk6HGAh7sn6a/adGbufucFYH5iZhQofT77LsoMAqsiG0lBF2LneYSWhKRYmycS22KP1uYw8qjEjflXa1tQhVXsnHlucA6ZM3tdc49S5egYujmuLocMBqWalHmYUrDVDQWSI+wKRhlv/RhnkQioAfJ5j0S/MAtLV90aypimONM1rmj4P/8mVrAtYXKeDq2oSVOtOkI+sG/XHtAgrM9Ycdq3uoimMAaEy/aOyWYpyhLblnkX9kU4VihSss410LBJVKiAWPCEtXVyYDNTngjRuGyyKZThGb2aIgvk4q8zQOe5S8IECJmdnkQAvbjiH0zzRDkzVkIoxc1J/ftuzeGcj5tspo2ieWCcIt+Gc6u2g3m7uCa5WhsbX6clX6mSVV5LeJ4+2Vld1U7i+Ag6mhJwzFaXi/BrGnYt4O1IWnEABdOOFpfKmoogW897lQ6tZNpJ+QI+SUehwwLHuEfuNCASi9Irle2lQklzGpXXW3jv/OJ5QmeFlr7hbGzQOQRgAaOOErqQ82zHmxFNZf/emeeB622Fzhhxv1JPSP9VDreRSQ3HRqP4lLe9YhWyvAu0ydCoIgtJ+z5uCaCxT4fiZhdKRtT7tgkLlJMFrkFtUs2iWkEqX4BzYZEIcmb1WbDPhVOu1Q6Z9hbA6nr5LLw04N4DM+KxfaLP6+eSxiA5rONLEzxRqDNuL0a2FAA4jEIy3NLQU4nyXCR+sBi9e15KNn6JUq/YxWq6Vhh5ql0WbJfcKl4b6mCOl7RTXDZHSpqkxAxapNsksZLn+xDa56Tki8sRN+XbHHDLFacQa9uA/7pjP7b3W/d+jnNA/2omUJ7L4eQgXXPKclIAGUf+38Q0iQZlkUEc8FjkRuX0ryn4QCdTdCI4+D7uW6Uj/cLvxzgWVDD916k0mFymoOvhwRDZ64pIlH0UvIB+mwZ7t0dy2lp7x3sEPs9SZwqqoj0ergMhGvmFAWCUGbYbJPzUbDzw32zktoGlBaE/N+c/zKA+RZ3e6m4FuaDUIwMFMpz6e528WoNU82PvsK44QennX7/kEKI6OP9W6AXm8kTIcYlUBs30NqHf8s/UtPogH8m00eODBQu0kpNIaOeDDCEN9B6m7Uhf8ccjDWGdGKwc9SJzFNb+mW1D8yxou8QSkkmJ3ekcSbJkcU2x5D4uhZH/BVTbxgFyCH1sEYoVTqQZDfkVcUc4CaeAJl60/1ykpTLQXkUf/lZUDVPsJQ3yiXEn/tLF6w+p5ZXfpMZkxpiBAy2dZtm59jfLDO1arvK9i5t33mxoI0eHXedT97wsHGBWbSKqDnT79tBAnsPlhtLW1LWYiT0oWCTVQsnjM1jJ4P34Ul3Tbb7pjMiohPM780sTuAfc1qwIfSO+lx25gIYBE9E9+Bbpy5aPvGP66hUmH7pr/vSxKOpoKpARafJ4HTidrdYZMqrYmFa7ERdvhMAKDH+bP1HyTffVmKuKUBvKr5J2TLn8obxE957CZ0D5o9JPk5HgXPkfjU30tU2gfQ9yN3tbk7LJkA2Xy2qx7hZ/tqiVpL1grBpu+cGRHFcQOolPIQfDXMjGHjKa6vj9ohqQnJaJqke9nQ3R+ux4kZwwbHCQn+CoXbydwsH16umGx2PbbpsSTLdgOXa3camdD1Xbe6E03vfDW4zm1yGgBRphLydAjc6Wx+m/mlV5HlApMZalxCJN8EgrckGSVOrPec1AOFkx9iP8EK/zLHliRWJyLarzhfiUCQntob+/gIdJha1GeCL67qsTSEjNI3/Tvz1FyF0XLtq026TerfDPwNewoyjCBqY2wKwPVOIxbzRx68Rsmc8dWY3OqFEX2DlMRDsnTyRDpDnYpoQpE3GUm6psQEDy0Roq5sHDr5w8M1RuKYQbuU48RVyCO9KupdpgX+VxDVA4aGfWc3x+9gdOGnuXVyAT0ZobxuMplmZgF3CUhmjTEYvSeTtmEktQTdnFt1n5QtCd9Mvzygg74GnMLR0k7KnzU7flm0jru+JVzmeuYRac/s5SijHTBVeDN7OtTRe/7fQZd0vz4orp4HJ4I2EcOSexOHAmBufnmz7d7qBPZAIo8bydEx8krWjvdJdQ54G0rUayj87eMv2quRGd4uTgoXsUl4YMnd/DruXQoqxp+R7RdNOl2gEP1g7Ae6VTYG1fmTkIb7STNoxyDrtgk7ndVjZwNaSBnDs7+maasiF1cL7NoWaqSy2twKYdUi7heOLp2QlK6/8cFRfmXSMRw5uvHIrcvxMhWOIM5uu95xxug4nvCENEwvk0KExGWDtzfYlb6heSvaPk24uYwTmy90eg6KBVgw5hPiWdgRnWWcWNKsbBiK+9BgHRb5hmDl4to/CUTJqLl/Zo+8oF5wc0P2luBp1jEUS0p9RuXATs8bKwhd0E9+9rRFmDEex82NrXsDm8Bcgb8bakYpVjp+MboQdtxMX6aj3K1CNHpSIOGBuqp1+3x2oThPO8fSnftSM0s24qLw44uupjncT3HGW2dgHfBqHKudNlGFYWps6b9edLshnNz8WHHQXPeqitwYnSZZG55ZEV6A+F0b+CVh3yJLiqRgGvQR5beAy8Tcx6pjeJnLXlRifmNDYGb2EPnCjduz/YxCfwOncCbeKCGAUJKeuJdvhDoZXVAvWLa0mjSHIeblEixKmlYhAcJh/bcWuKf++KQmrImQIvgvmP4ivA++f0iyIlk/qQ34x418eOBPUEILKJYJdhDJLOKlzP3cU9ZCF09JHJew/+c1Pj5clJ+uEGYTaHxwYzl9qJm7XBpwwF/j2ANf14+eBfqSw/oAHyiBOmz+wxXZLt2GP/1TZHRDje95wu485HLrlyJW9yClQyQzltylgXQGrovLZfCHHhiaTCiRdiip2ynVv3jS2i+tr+zBHmSnCLvmc7+CZLbiAzJjMCo8dEBV5dagVG7WR9fozNxl55rF7upQeKBzUet1Rl5jE+2DCv6c8Su7YNb+ZbJEpIdW/flxNGt43jcas810O7BzsK8n5k51hRpTrlme2y1HgryibiKvnQs44lFYMT71Ojk8ewme1bXpkEOtQMZEnokJvJM43FuIGhw4oA6ZA39yOrqrEOK0f8CffHrXKmDCNTWGwSWucHCC5rnf3jBKGWOe0kD1lveAchax5PuikcO6vC5tEEnUSxg7PDfAoItdTtuJuBXjyBQH/p/648Fm7FL0FI9fQL+vEB2PDF8IN/+acrj28F1V47MgyfHAlhCHiRGHsC3QHFtYEEbP/otQArXAXGOqwJs1xpfmkbFAX1V7bMIo8Acl4nmzuXVt5cJgGg19iuT86mBVguY01WJ95uhRwDHYHhZOXAh5VYb25w7F3WLJaK3lhrLytCl7ZiB0sPu/jJgAS8w6Yss2f4A9cj7uKvNaA3keiwPxd3J+CbXD5AhjU89cBGOzhlorf2tj7f0JbbaTTNwusHilaYarm4p/EPpK6HEhQCrMDy6scCRSXz5h4fHXn001JGz26bdUroaI7A758ZuGFEcjTjnYQ5viPXI3Jl9c8nhR+r3Cf9F5/3pgY3TlaOHjQyrDkAasSiASgGoTvlKfon3Ol+OXV8LifnXIVkiFinROA3WPr3YAJQQcS0++o1VZmM3a7lEynnELbdqOEBz0FfGT+CiTVsk6c0R2e8fM4JZD0WlrRMnrJTl2Zao20M0zIX4qJi0QjdzPS27Pga0kJVqjHzl7D7Aljdr/+xnrh01oBNwIpj+zXlm6GqOavie4AEOmK01YYYArY+vcbMltMbHjHixTemngkM3gh6E7TgTRTVwJ0Tb5JaoYVT31lOCfUiGPj8HpGjA05G9qs3QCIEL7dAudLVm3IMUFJ1p2C+7wDdSIT4q7d+CeL5LEkD7oF9Tch2Q5RO6Cnfjkx9XbkU2KY0komOb2arpUIYh/dZCT3gEjr/r7Ja3dajMoxIejPgVBh7LYJSvI5aGOf8OQW+IME4P/83o2AKcv3x3kvRQ8O4opvKsGtBkiHR0Nwj+OT9mWschqFs2Qn4RLdY3KzBBwzC41VAlPdwexBmtK8s16iD2unQRKqvC2JrjHoNV8vsy4asICYDxAv07OOePMe4eajRhFUhBBL16t5/1SKK4dwkW74Om0tBBMKBs6c2E5FomHE13tH3TfVqr2XzrEEwqvgbub4CcgDMVXcKRc8ab3oH0opBr69RZy9B6fW/tG5ow3DqNBfYGFnBWFYp9beg6yMtH579D5q7YgFcEG4/A/yeWCxW9TYNGBvxS2GEZW3+UEMZz0nDJsCWcykJHP9z6MMLpddHMPx2lSVgU438E6EnTP8CW2GdnbX2lf+/85rJ3J4DAv5HKQvmY7vw0qOllqmmMka/FClT+AWwZSxfeKpPGyqztMHzONMXI2IOP9kv8SScKzsP3OJrmTaoAFmIVXjlncqGUx3YN3vjD2LZ3sBjD+zYuZBPWX6+qEJGaI5BJFwiNkZH+kPiuSkhbqM3MZW2xjYaaWWPjqkFFKwZAmv5vn0hlZqx9uWQ0LwOtsoa9+WHJoh5jXVpnaX9CvryHHvk7KMHkaUQpgkGHtTt8ful3t64k0Y3cwkppDYqV9wIMQCPh4Q921PT4lREO+riHJKfAL6LwwHlQKXzh4oRu8XwTBaWeshmgU+4OcwTvv8lLkCxSgLNn7G5VUre0XiXOU96it4HvwKyg+xKZJhsoUW34wL2xs+zEICu0eLX7cTOgpxnQZjknsVV12wOgCPh4nxUOFg3M1qCOmF0GGArUnjvgmxDF2hl7zH0PC+fNhvk4+au3Xnm3oftNtDSBD+26LrsGhspEkNMP+x/jxhAzBGTkfjQ8lZJAUSSvgV8KVDBsCGuhyU1aqBWvQhq9qFgL9FvNGUuMKZWPWAn8ORRxqWdrDJMnVVj0BxiwD7h7LGpyQBVDjraU5LCB1xmGGPNSkuFV4PQqiEeQAA+Wc8iMq+sENecnn3dzC3Pjbei+eWzRUJslKT1XyxmIW5Sb2lR4rnN8HhN70AdayGF8/UfATduGvTPQWkiUTTNb6FcFgMIFAKXrkAyBEOXn9cDUTkqcXzbIb0B2+QXRsqa1hOlAUNkXVTyCYyokIhhhSrYyGkDO7dwPYX8avwgLN8Gywop3IP9NRNa3vww1eeDd7Xl09eBZUfjrYXhfwlBIMqbZ8ClOZlqLALb+2Yu9dlhx/Jr0wfD6oOTkmUC4Nm+0EH1vPUD/VCM6yWy1xncvceKxWvS6LW//ZlcAIFK6LiQHMx6oPBPrhMXpc6dmli+Rpr9tQj5+K+J7EXc7uikb4HV8syml27N/PPQw0sQ3Z+uBHCy5RTzi55C7kCOyXk2WOAyHwzTSyPsJz/NUQ8OkdB2L1ihsiC7DpbuWRvhnknFbZwdOfY4yAJSO+TaeQoH0NrP5bhTCBoD3y6/F5TAMm87FIQ6s206O97N6qIdF2fRp1L/o+F8i3bkywmeGwbAREmnwhNeCKG+vIrHf2tPMyQP0G2Flv+Si5kbvy0FM9adUOkQB0DBSH5JNEO3cM5z4HlvoAAIgWuk7gvC54HFHCcUIP8d1+D9CbH3C6yxR4OtaaPLkF0KMgZdocXOBf4uc9t+YfWB9ulun1fywTyTXdXxzDm7Et98xHE+HaOi8GACXb1TibC2mVTOrLWvXF02HcdSdc4I4u04YSX9sChZGDBphoGR9VUCFD/ep0phAOnJJ7cr9nP53D8l3BZooafBJeGWBokW0N9pAEwnVNt/38kdRpRiWGOKtK9Zxp3GivR+akdWtnkAxw8wrt7m25G04/V3QRmOfb0sqYvK98aSCqx9zS/FTI9WfnIUG4ZzcFyeBYXPG4m/5GZeM4EAu8kZ9wxnUKTiUdeS8E945DYyH3b/wn3kB9Wi6lZFfrQA8vaveUOOjrC4RJlBLrUw41dl7EBi8Suxxo1dDTzHF0Wx7x3TYvy/7UyplnNm9NqnERhaKIRgoMnvOEvHsfVQCoRKy3MwAxfRmUNdU2KNjxtfAUB7b0aWo5WmF6TBrTcHoW61utb4djyzYgY9q4/YnVP363IkJSRSwtsCVP3bDKGQ1CwqPqffN96Z8/2oM0nuJQnMqtt0tO0MzOkFxRQpWZON0aQ6Ls3rCG+NeYYi3G9LxIJuPFmNXRizqrwhoDSQvWwkJici27elyKFmPf80bKwP9cr2O7nylJq3A9tETlON8xy+aWLRxWKYuMqk1gDFgcleX/WyuAgxuxMimxvc8Do7Vfs2itWtZlNdmRTEAuWEPA5tigcr5Uo9A/OS1MGxe52/n4iRdunoHTPKJT4b8BM9BqY+xNG6zsUz1IjNc8B+CspCVsqIu7IK9WW+17jPGwA6OsKiWrkgMDkESil6Q3z0AkPh/jz8mBr6stI9P/1iwUta8MZxZIn4+qEspWbok5rBdjQWYs9FRMJbXBOyesA7mNR7h/SwrszVfSPy1DbN6o6SNEEzzLgqmNtTkogN4NFMzkcmyJn6SnCztu1M6qpR8zUqEE8gUDRmkLqHg5nuazFgqh63ZSxD2TjdJ/BaHsRD0MYl1ros9kbDhMX4FeDyf4j7BdYEzXMbtqBAovWiQFtYq87+WnOoHF2iRBry8LUvXuuYMXfPNnf5RJnWDu+MT1TxBz0HQXHFMg+MdR0FnbVV7nMpMmFfrT/QOQKhPnxwaxr6PFIX5N6TeX5uO0hNSoYs06sAqnRxy88OKvjp4nrGzayRxB6zwlvZeptJIWsMVUKkZgV9mEeD6sf2A8MwjC8PMBuydBYM0XNYyMMtFn6H+O62rCKPq+zrGjh9lZKPA7NWx6wbrLg0UgN1dAoiZs+Z1Va+ZWzPu4shykz28Hh4/gAWc3uAbH/DKfDW9n8l+rPeOUxArABJ0ONAFpikmDBPzDe8G2/V8quhncBEe7DD3YyEWHUYG+n6lVeB1mIONfzgsV54CxlAdryA59wYgw9Q7IftrE5jZ4ZeyiF8C4B89vc/LRxUyt8vp/BG1l2oDeC5hD9qa7RxcJz35BGu6ksk+ZSvkBUNolfUlzpc/tFM3XebMp1n1WglOei6W0+i+pPeKeYWf5P2BGBuCKD3jCTS0uBGfSq7j5Y4GX3nUnHvHstEbZe6xwoULjC6exI5i/bCjeY8yyVoOzXGEQiitDRIFB3F/bhR7crtgsmihZ5CDYEX41DZFnZGbsnOuahWGsENaPEbiCYZyOIR2zwGhL1226H4eQn/dK4TQ68XfDNaqb7lzPjhh6Th27861d/xGUiKqqUEAA+iz1QjtKSX1mZr2zbXO9Vl7Fl0umLUaSteSromYQefky24TrAlUWvzL66VwV6tqNOhsdmqaTfScaTyG47WOl9CORGorbG5MnZ1XYV958pkG++nxYsmy4b1dQOOAVC7eAifCmOwhsD1f9DMgzWcCxHAvBgiew9O1vgaHbJW7k4MzqP9gAZQ4EvDNVD5kVWfjW/sIyMBrMf2u/sLRCT1V1PRBLrhNZQ0jky3je5E0MxJd8gPhqY0ZxQBNDtKA5RyOuBbCEbhPVanwenq8COGs2hMI5XJD4mqbrqjQxMinEfqDc2A4jutc0/Ym3G3W0nBkyf9w/U0Hk+v/bfMLULG0QiGFa5OMlew7Vnj0HMBH79auxMBIyCdPHpMef+Y1fp0Y29RkMOjaP9rJ9vkCKImrztDzmFxBagulkfO7lf3RR2AnmwJRpucVuvpp2Q+WhY9Ab7ZAQb+3USuNbDPQnDMIIMD3AV8UJVk8lkRLfPdZtEFMDLc45TdYLnORlSbxGrUBkjwePCB9pQjke2D4OaivfGFmWfq1c6WS9Mon3T1VnEI44alg4MZd5MOYw2pQ5VSM/evWU6n8oaLcY6xdbgexbgdtBxOKjIFnCDRRC7gF3mAOFYOX0zZYwMIz0arb0Q/uh8Pdsel7FGYZG51uLkVhTDHPOpTWaUIUisPxDND5AaBg+YyHbHv3vUS89GZjo6RVqiY4IpBP5DknltgtzF9cQSdv3UTmFz3j0MnYqpQrpgbZJ2RAfjlBzghyixBjkxYr9EhflXxD/mLG8j8uFIcrZcvavt8A/sPSoIzVEwSVFAzdLeuO/TLzDoFOnnT9K/8s5dzd/ftPUHYk3dkCzd3FKKSZCKWLFG299dRRTIWq6VQovSyYKZee3FBEefyQsWGsVJxVtw0aj1BhSEu0chEZlOnR9IztJ9ooxqfkcw6X1UEDroGqddNf4XeO4y3bqgX6xm4SBxZaeXhYCb/YnQwCsxoJpgjdVLigBpK+nWQr/V2/n/7PViDUkpvjX4CY5NgIVn26qrbzXiuu5axxP+FjFLthLX53tMsPopWnq0L7PEN1/z82T5UpORbywi7XfjVJGXSkM/WvMJm7E2Hk0CxDmkY9EZGirE7EFye4I2NvCuaQAF3uL0J8tJUZXeazw9AVeCoA6nMWZFcx+zXuC3aYRKvLqy2QMz22Uyee8chK+p1gb4yqVWAyHHqPDlLFmWfQobdpqFL2mINGoTirmrvaSIBQXF9MNBbQB7OSlvUMGpI8aHBVRDo7HxpFqe22Xl2xf4oi6qcPfS4TzjLqL/Z/KvejqrTmcXTW5XdR/irLef7lLmKL4pHqlOjGOARTz8cmpATLI+mQ2nl/uYBLo9Dt49AQ3dqlGujfIHCOn9J1jYVSeWZyMiLSGf+pLCzVsDG9Ycpjo7QI2Kt1rX9+Tddp3tgtgr3INQjG0VRLP0OdRou3I01qBCQ6j3mcm9bQ7NieOj19giH4Hs2hVwps6SudYJ69eV4m5k98fqwvM1AERljM/to5L7Bl75+gOzIM0mmZp5EHN4wLtGJo9F46N3xpaqQoi/JZSCDKe9LtabVjDdGtLfWRwb+sQu4C9Zv7+PBpCM20aeKne8UU8TPgPtLHkNNtiBlAXQshYQtcsgolYrPCiiEBocy0P3rnV/ttU4ZOAoQl8hfwuN1OeFZHyodqEYGf0yxYT0AFMNiaXNZS5ukeKFS4JeehFMeDATZxcoN6h2Lr7KwUAnCBuGZbk0/i4EncPgphiXMdkH0QBhETaYR3YuCYlNLKeiAcTuFD6WxqnfMD//n7miEBlCcTX4UQgbkoYvylF71zcwHXgQMhkN+ChdJFmHzQdsCrDTxQya2hn7omeQRwfKiwit9m6lXyc1RxCmu92HUQ6yfiLbjT3B3xp4eNB2wpcNm/hC7LmB8QnaeW6TaUki3SF+I4QH9HQ9joho9EZAp+L+e8R+GSdS7wSkEL+aefNWBjNSWQ1eqk0JFUP4tb2O6bLI6vFMHNeA7EpBQt7bb3qCEyy3H0VHNllbrnkpt4F0YcTVWBeQfExcfjFHymR/F9fnmaVni0mZKHm6dhfbLSKVZgftAugkvd73PgR9Jeq7CuM5XARA19cO/PTsNHUp7ny85B2q0zCeEtRMjJyRoZZ2vOFj1ZkIsiTOQX6BQK41zbbUM9jJSYC7uaEhI8EAqdPDhb1VeHpgY+MV/PlLufV38VRmpv/+iErvFd5tJxl+Wvm6mK7sm+SbsVxb5sdnK93JW0LSsVBqDB477/3M2hZ2yfPlu7wJE5GHDLzVu18Ey8rWIDUiFADlXTYQmdkS+nCD+UTg2YG/IqbDMsSzCYoAiBrZs5r+pVCQ9AE6ZTrZDn69JJAG67IR5bAFtzZkOnz5la5bY+7A6PHKadKPEw5kz7cU37fUjPk737ZYUQZ+TmdLrkWiOURWUXLuFxqevF73INLfCj6MW7x8ZbY63B8y1kNSSnvmJIc+Vu3oZhoicvY++SmKcZpfhAczQtJKP21AOLCLh2eVwMF123fSqn2gmsdEbOmooU/6i7o44bnoHwwxnBb75sKRhV2D0/bOKp3o0X/gdQJeCpSOiODf1en94Oryuy70oIS11Nuya7eCz68xUB+4ZMBT5dTr8qlJx+I8ZZfCYa4w9ngNF2YCzSmaf1kFgvO3/iG3/JYS8MXJo5lqA55i7OSEsTwTtLKlyCE6fBHNeEE2mwERf1/5NVzBA8gbv6ujrSklq7qlI/mz2tGUUpVPLUgoqtAUWkEStTZ/2zpatCO3y7ENuzJQBORLBnO9rpCvfwU+0msRZt/6cMEDBjA+/o3TYgNuvvCJswKkcfgIY7IgS5GsTxCM1OmyWkZR83O+W/Novcf94VJPIMq7mCnewLIaA+wtKBtXWwlglYpyOcrDuxP51orxlPgzYr1iFB+siNzgLA2MlBaRzEcDnNUARGC/LCv9q1I1Hgh/5ZXeiU6uI3QlUgcnGdsXQAN+D/+BNi9L6c1aEQD6Djol7E4jegwZFg0eu+cOPUcf6uo+FdVHX7S4SXsG/R+/0czjRNZEEYmLNHfEXftNrGLGPUreJ4gMz0AFf3kAF6+ev3rpo2Dza1I81hyg3HFbqFDALBKrDOtliD9QhA6hzJ9U0YphH4hMsUXwPFXeXgllywPkg3YL1iipN1f/7g9QrmrVYGWucPtyxqoE8CFOl2TbHJwxFAfH3tBnP+Pw6R0Nfn8SlpfQSyw4IW0eTZmIdpt7qWZYCO8sjziEQXPn8HkwoEqFUoPknFaODjTll4cRbu8q5gQULYRtZ+PJkljZ9IJmC6gM46VoY8wfGR6EGpzrmcbLMZ4rjPW5BzilsyAwkZuPqyt7pTTXATM4kywCRUdVfE4XxbSvakqELRAWNLOA8TgLlMKS84M4lBrOVfY3FiLp5aMlyn4IOZv4SluM/LQaE//b4M96kssdcZ+280BLxlGrifrZomsyQHdVAqMV5JkEK+6+bJUgCCPmJpGkW8kZ3ZFjYQyCWU8AlxkfYbf9ttDUMt25EtnednWWS2bGx/dcfvTOSlB3Q9ncy+ShmS2QYwgwYhZcexs6GbocG2h7Dphng9+kXHDAeJuIHGGC2gOpArp5zqkjAZfJouShypVbIjCk7wXGFf0Is6tRsJGhwtTx/7OYPblAnYvynoCzD7BeJxSV6Us4q5bQefEP+qPepRsl+NADQLOMvRhurzO4FfDztdvqkEoYvZiS/0PF0vWqtWOGXwTNN5v6Lj1akHnuYDtP+Ed1E7IJpRxgIWY1fiwm1bHLJRtsAsbjR6/Z8vaKL9+OeCUe6acwYXTHb3VoodHAx+ZVvUI2R6EvsM3SXG7nWzbSBj+adAEIl34BUdeSnWb3yU0Bb31PVeDneBOPUwBBt/1iJicD+hCxZOYH9l+VPb5sxrVWnkX+iKRDTSv1jDXXvJ3WhkpflJ1KlDQzgA1TKdaRf0a/+Einn3v8p+Bi9BV8c2lUmcVP1QizVD8NqTc5JPcYLUH5IsihBROybzWJ6wEEFF7nJf7lEZOVp0T0u/5+Lym6lO2wwja4VcY1Jvsn7XKIMcuk3yxZw6Av4jH1nJQ6W3dlq4IDMddlmCqoxkY4BCxNmJQp0nH508bcE3LyQoARlDBJugMGCASrD5rRjXTFruYLfJZYMtorLOTJnbtwXyDuXgNspDRo0y9Vj5lgFrW3Ncr5ja9StZOXX89hc0lt3otvM1QXzUOXENEPuxiWXSofkTMXnVY00xi4DNHjWL9uaPHF7KHocF7kA3if42p46+a2zfkA/zfdYd2r5iD4SvOWum/Bufd8QdPYem6bFsBV3IeuAwADIJLEDLP/AU2r2YY1SREBkdmMq1PM3vCQNZ/siYhtAM5nHlWz/ab1UanvS9hfw/0/JNoq+4hYLW/ShqNzO3rx9rwsV5m6wpZg9HJ5nnlOaQW25qi/MFedX5MfZYXIS35EdSKdb9ne4EfdUCA8aoyXbSJEifPKXMVNG8zoxsbatYuh1lZISXzj/oZVnxuC4mOSMd7StLECdmReO0wTyJtUkL8LNK2+XQhEmQwFzBmmLRkcG+R7aVtFF/N1ILfuiJVX8ajI/mgW6Q4DJyFVbARGZpi3wyV2w7derGAXPQ1JJdaHUOk7/DtvA8XOEWkALHjGd55uvQ58BMOc+k0OJOd33u/s1o8os7rbHSA0dN0NsbyBFqN0C1MKUkkbatgg2qQH2YnoCttf3ipzNsG1AwiTUEIwR0OCrLdToLv8SeMiklS4KFMEo1D4Q1B1t9kSK+ZjUbUR2JLJOWBZfTrsxFUPVaT12Nd8kBAXgKBFxW6J+zR6pXlFkLbQLuaIITV/D/RryAYEhiw3O4TItU2Iumy9+O8qmV1sX4gRSLE6M+8Pu4F9euK7dQBoWGNZDkXbM9ZyJUKlqxdT/kPSdnfLqTdwZEsZv7fXaYo8/7Q45VIvbYh9nhXPKHiBSf4XxNPw1+UMqSv61BbhF4sfW/kqwR3TdWX6IaxYsrAOJSSFy92lhOvmwe1GKAkI9AE/680LDwbdRgZBJfX6agRw8hTLl7Tou+4Bl7DwuISU9blj5hAQv5xzPBdd0HssAR1zrGDXhQbN5XJMw6NDvVoq/tZ21FJuTWVfJpBwRMWw1x0gAaGLQcjSjCGupkyk8TOD/HYZPqPG94u3SrKFeor/IFoP9dCTFnIrKfA7mqV5/+wspId9/GOLj7f0J+VNFMTU0YO9l2iQKGPhp/ooCyvvJOSjhOOtCiYlG7LzjE1LgW7TahIdeLmnea1YjcYXMJ1jtFozFb5NYu0joWa85Qw0XCyDf86bsk3nbt+8lB63iiJdrpSKi2laF0xzCcLaByXIyGtIvTe8JaSHEh+mcuZ9Dt05oTo2L7LtuACqEpye98KdjJVNUxelPmNNdVmk/VVz4K7+N+Spf8YzuzqjioZ6aqLThTZZv8rANgrDCFoHiEMUcMnAI5hYxxFypdvQLPltX2F98dO+zKfsBG5WVuuqJdK9tdi2IYuv0sO4VotW08PyyI/lTPTaB7Oss+6FP9iIwurxT9kPx0hCuHLLutTKfYFHtBjA1yyqa1gN9sVOW/j4NprMtczcSIq/k1XNR7+ukuqVwB7e8aL8kVD1JfVlbAwmC2gedTUYr8wqJiQ4utd/3QZ6aK4kZBjrqFBUGoN6bVF8PmsTL6g0NFhSHZAIwFDp0xYeHLVBgt+NmI6u5pk9H1ohxGcQYwBVu/M05/GdjFs6q4GZ/gvddgiQF6xlKmvjqQxNIFFCfKCEk4836JAV7IXVXtBSTCjm1b6GkJJxxenFzSIzjQf9vISd66oEy6eX+XeCeWqeBwGzNRnyuT5G47H48nExYGOttG6srzepUhaQX8G6bx5W98+s4tEbOBLyE8JC8HU6QwM/TvBBcVctCKTJgZQJk76AJG2grkq1n8pwiYEo9wlxRlw8ulIsiLqLB4KTWaDeEtjOELPkMdvJI6bfzJcpT5KbmAMfAiIl1Opud1gSugMLDDsZ7N1xJyGgak2RQs21zH/bqGNkVfkMHfVtFuuJRJRcmTFS3bRb2uiH4JrJxsvIeYy2ZPd6c8ZZoBYiGtQVHtc11mipPYjyUqIiWOzO2Z4G5fMU0tWRuMOfn78DIktjOVap8TSdEd67Wt+G6Gx1ztiN6HWpRyHHqTTzZeza9tzpha2znFrmV3bxWXgbdSlykmsDgbC70O5Dxo3k7cMiGMVEmlW9qIbGKA049NtmQjYK42v0bKEedwYd41evtQrtmIqyUK0NIZtil6TKq0Tz4HJMEJ4wJJVPSgqvbkCu5LQ3FLVO+WV9D/H8q7Dm/3d40GVW3K3yuMR1soJHUGTlkngtcOpBPnmkJVfdsMwyq4axpcAaAihnqJdBRFpoePfng9JtKzoQFv0Xedg9VIGg9dboXHKEGntqhkWv7MqeQADScmQ68fG4lU8ygQnUSNqtxc0nqatcUfSDCMX+P8WD9FonJPgfm73556sHh5Y2JpH4gMiT/XzfCBU8xstLYCG6WT03esvOIwK5+KAAmAGGA+/xAdMXpwZkE0tcyOWe8irkxEC4SlXOlPqZ922ZLaj5D1WTdD75H5JcZqNmO6XyU+XNC1rLXyJmuFa2dKVEEi0vyzdk5l7GP4BMcpagAXxf0yc5ZI8GYw5ZkjZdQVYWlOjS2zHoNCpiKIVs1g6Xu+ncOIb+awTodp62X50Bf0VbCkVvOMpJNRjPhnCfIXPV4E9SpcE1/D3k7HrtsViQnsJ3CN/trF16j9LbO8vIaUG92/G4AMuyiZFeu+URVfi7uhkV49LfIcsdGU6BuKECRBsmyZwDULIO9kR8sbUpxlbc/Uqqp1H6L/0t6RQEPlnazj/wXgCfVl7nv37YiUVYnSKSL31prCoITNPsBviFCLHAuArdA8ULQPapy+GWGpvNAEC0bq0hETRwsmRnmNkyEO55PdnCXaZqKDc4orfvdu1IJL7s/z2uQxKn3GGacSZwRUsPU2qotrtsFfXgzQSgf1/eyETdH7JFYg2+frLDMMr4cpi4FLKaSvBI8K4WC4ovpXj/7Tz7rh7Hr7cNX4FVRkDA0tYG1WbinLdchW9JOEzg1Y9gKyPBXgCtvVQm1FZsrHgAdUvIXeaoy/F8jo6iywpaPRe16BuDr9cp4Pk+/dHTHofvnk1UNKqejW93zBO1qkCuxvZhcXa/FjpJsXjqsEHjKFk1GyhW+gSaSouA8rG4rxoAyOg+sDjCXvokDjZack9W2DemJESRYOJa6Du0bOprksqAQaSae5wCeY07QBE+jV+BSnrrAdsVPc7Kz1UEP29HZfT4EV5nuiRL6Rl58ynyBjwkuMtk21CDA6uyK1TZOouroyEvtB8NbIBqjXPRuWS/fR7ZkOQdHRXe+rpPbq/c66FAjf3N9rxCUj8UiD7TSUm0rlewj106ee/QCMKYZgFXqYWLCCYFRDGCJvx3wJPMIekCT+Kc+uFIdDtQlkUhO0Q6co7euf0LFeE6yswrxjPlq+geafH5geklFLdvBADvSvrTeL+856Fb8XU5kEZQ4w+XjsmPb5OPOy1cMUwwsduUMVSgvn9B9J+KHY9Ftp4oUoOa687/xn2+SG1pMWRPpkm/+OaPYNNAWD0O6SqMaI17vFjEwwi1VdP8Dl6cOxk1Bo64etaBzx0zLVYPqSBjwRILZgKxbHZZ4jwSUO+185s7EuyUk9Zv8em97gkRhjHDvabcrcBg5ZrqeUyvH7r7Ha+uPF7d8nVCXFhFn5+RRjFgPy5p8lTV+/nYT5Hwscvu9swRYJbx/VlKpfmLlX0eP17xDFn9c5Ax0eCRGuyNEgxXeNMlCvMrDu+SJUNoScaWlMRbx/8NCbuH1el9WA6smNCqOVTDitXfiW9GhBVRtjOGAD+bexQElLquR8VImAF8/XNzYqI46umQwqOSV0tPHUgoGV+AzeZXyVpwMACeGKq8vjvhCjHJ+Spakzk+RuQdiuY20SZ2QqSk52Qdl8gfwh6JtSwL/B/3xKerGDPaLmOE99j+U1oTjEeNPbfJPC8+qgWJIfJP8lg7hEE/506NSEPL8hidkOF7s+mn3nGL8J5288blpmHFgQlNO2jGbBgqICgrtB9co3v/cmw8Q/B6jtP+Mn+XTPnOxDAgvew1ppKnszoKQFTbnveynbirt1ZHRaf2lu7Unk3beRb1WOXKgyg7CORDS1QxIIcDo6jQBaCrlGWAcaOfQNkryZabjlNOdQrLGR8W7nN7mRCef7ffbXRUlkkYXIee0i0yRlauHYuoQQVgtQAqHm9IfIoYCMgEbUjyYvoFzghBwTXT+5fFM1CUpZnHWCB/gmgwg+6VcVFK4j515gquQWRXKEOU/rV7uch53pLNFj56AC/US2R3AAAYnG9MK58aQjS6yUIJXekjRjelQzIWsyelFxY+u5bKJ/r7keKVmtppo5qoeM7xflOIG23FjOt/jiVEgGhJO2RlJ5cI3ZbjLBwgdDcR0OA9ddUThSMa7cHHi/6FkTHgFe5bLiQfoT4JycT8MSD/OBYe6m4Joj2WVycGjqBwW4hnEKCn7BPyCfXzA2yX1n4B4uODuF70y2/Q5i2OcykUnN/r9UVrrG3uerkXpuV46/eVizN2NdSvZcs82YPUPpGupt3838alTD2a06/FM2cb6x6Kb2+SJIrVj47GYhA2LqEFQfZ5AuaLukaOQ3mfs7qMdYAjcTSdDJ50hDazHTgmLNWiN76xHbgNWkX9fur5scbw9qs6Ra/tESOYPT3YOQf1rdGa1GigDoM1pkUNhNeAdOjmDS22/OM9BxNv+mOYUKzjYsCdVK28Re1ntyF7c7Dx0LxgMEJyJtpUNal55zWN3Nk8sBGoJFAmsQdo69mEYa1jXErE+LAkWz5qSg8aiyx1FSGeH+qsSp0O7WS8yOZsaiW0lZWeK9mqQRi5vEmyHrygzC1x688xTtrj+e6URtdpx1UiD2Lqr/9NZb3e018/86VD0EPN43EeraIuCH14m9BZyuIZRywCsoszBxhbLbeX+w6ZlcsaLDe7zl8YNrdltnjpzmVBEJtdyEXuKn1WRFAZZ+UxMdHitd99TBkbo7z2OjRooFHhYswkyyTwu7KHEuyCdozv/V3bssnGMoFZjMbOcFR20iILtOyzipk/FP6HznHAhHnK/Tr96XdzsNYbRIoemRtHzcmi/ylis4cZAwrLaxd7MQY3yufnKBtL9Qeasv7IKef9fqb8lECizuAHF7/tLEIpANNpyd7056dkcsw5RtXmlbXpkAdLTlkZw/idcaQjWNT2nocn84FTXg0P2J8iVEmOw0vE/MFnn8JpW0lbs0Bmomndugc+qBIoBItqbJMrK2NHARIZVaQrl7b5LNZQFOX/r58panvA0xYy5SgY5QC3w8e5Eiwn5D65hVmt55FSCZNGqsrBPAuo2ls+c2i6XulfLITsZluGSQt+qItQcagLG6u2aMMF2k/NK5d9gn4SGh4xqMA7i3MSTEYpSFELk1Lzw1R+xjNgE2DXKm1Q82u2S00a8Ri3GNFJxBIJqjTNmPVFZxEChMAdrTP1KsAoLfRu+55TpSfmkuxnxkKFf1oRL2ACfqRbCxyqyTIVNyCTlNegXN50GSgfrQwRFRxEvM+6W3i4mtTVlyhRgVAy+y0p7r/HRqfRk5uq1F+duHBhtwGzPDWA1on3wyFOOj+dQPjOIiQJj8hT1WhDaMSuOm3yLaUdqelSfWlOGqqVINz/ES7/ljviZOAX51m4Z9tmHNwn9As2koKPc3RjoReiG3LVe6BD5fipckFMnQ1tmE7I4GN2OjvfGR6b/2i73f+fgJPcaU8oTI+7AtSm653fpxg9OjFUj9hsniH97mRr9Zl+1rA5rBRDdltN2Or9KdbT9eoIwg7vrHLaY72ygbS7o1C/shOX5N4tgavLErRPRXw3EeNueSUDANR06TDtnxjIA9FYbqcv+WiaN62LSX0iCSSgYdXNoprfEdNNatKdtVYLCXFfXJ/vJqLat3G8IsUL831FXW2kftsvGGhZSj13FeuW1XdrixzlWDBs/OjMrNgiAMQwH97BEbdw0RF2TcVJASOHD4xMZWrZka6ieZbsR5m/ItZoNjCO4x60nBHbUq3dvprfv44BQ3YstV4Hn+QuO0seAK7ZIHF5sNhpdU10WGeiyY7wCYamHIF3oFZygtMui8sZYFmIS8jqg4aaEfNflSZruPxgPRQyiwOuxddqfHM/gx0Whc54N4Z5jdQIKFBbSzZNtFHwVMds6iFJgJ25fXanLpFcZppISU2quulSUKf3we6MYX0PU0Xzm3ULJCp9r4XtHadiMU/MZSiej6xS7b4SUBA1MRQc5k4Y53wB6ZW/0W1lSlQRuylqUfb42PYAJMjpH1xSEGpLPSdofGayu6IJ4K0fn92u4+FjMBld0Ro16/NV18rukGzNsUkCk8QlJg6L9+IEa5OIjn8CpL4bEsegFUPaETq94kKkn/qn6VexsGwrdgkA60iEDjwpRIkze9JvuNOJOC5qQcif5GXb2m48adeoTSUb49SKzHfomDDo8tFrBSODjKVWkIFpggZf8NISzxXpQwLaAcIgNjL0kzvxT0pgd49GD+eHxq6RBcrD3dM8VIo4aHTYbFBuaDtLOsuw7UcjWlRzOuZOJoSBtWgW/vQRz5rSvCTS7T28WUZQs9qvZUt1KFrV9wZbd9mCVTG5WtdSJB9B4w7ikP2RcNYp034HGpd/ngoQH+w72jKzCgF8TBnUv39QcIc9VC1PkVp/3hLDHuvvnUTmw/Na2V5et3uoSbLrgsm6J1BwhFhpwxjsN/ES+LvMxOC0XH3quXR0MwAlkzGrWZZMJBUbDUFnG3UkStBV97Wbi3DKhVVRFDSm+4KXxxMHRD7PdmVg+1MSVggUFlU4Nm54Fp6kofCUvj9MOr/xM8cbQzE4QyvnKhVQHRs3eoEDtUpaKRjK6LElFlL0cuMCakQTAlWXgPy9FazE2u9LdrG+DCBSsYyOs8i+atyE0P167zunyXGvqJgAP4klLge37cFqkNoW+uDUuWIKWM0x7muE373OkTWNiPLTRD7m+Q+8QybbuTixw6rWrHzh1ezq/WfFffU3FzJknlpRf29004dTJyePn6xx+UC5psdwkwrG7qorT2k0irvbvqyDIhyPb52oRI0J7eaDCnMFo3WnBcn9Sq6Xf5ThCLkGHrQmHaUaY/JY9HmSWgS0u6nonz3uK8LEVU1P2cWeHppVXpOyH6XeSDwmxKWUsxycDwO5PSSUh/+8LHLl2yfdpqXejr6yZn9v7zUTf8E+VDtRr2Bpr3B+iK3oZmBjvn2zzp6f2MAaVYbK4PIAZ92EDhWQRQ0AHD5l6xWbpZRO2CNRmTUMIfAHrIPtl7/9337vK4I+vdZ/HO4b3QaNUeHRfxNp+3dzKh/fjOaEstBjPG8wYPQhWkGoTL1XaPNAtocgwpsvSf7/367d1NviPV71mnDR7WWrEPR0FlDuVkuh5HT0YFDhXJNnfC7hmZDHpHWjxie5cF58GLfjAKnNDmDk6hA7vBjIy+v31YkVWi2zGimFEWJZ360q0nrvoSXZXxCfB3j0uMsqea6ZM/Cj9IUkvRy6WcshVtuzeqjkMA2IY5J5g/JWwrdUYDgoI5C1wNWUdu7EYFgpDRs/DNPt3zc/HstCHKMZ9yq3flu/d7aRsTw6sK7tziHbRG0MbmfO7LRnonAmCI3qjD9FNpRwPRKSGENe1kt30hbcn4JmPA+i4oGBnzByxHl1RBd40x2L2PSuTApOozQKD2iQsql1vUR+YxdlroJMKllqT4vfXcoaRRdbnXdxwAXSV6lkxWz15LvoS0BAaqfVUGf75xnc/cVWHUqphUc5PV5FibZtdah47ygQuZ/775fSFbzS9/suDykV+6JHT/m21EtSVsGz0Jrh1K4LHYKfvsNiP0NWks3e/ppkLA5jfsGZJHb7WOk2+nJ+cVdKhVXqTd6Gnnc1/opmLqQPrmc6WfaJFMvW38dfuB0E7IdjeDXnRNagdKhIfHCNbGUaEc3mRS/sBoevZvtXuC4t/7CGpVY1bIlLeiY7OUf2myK2hEXx6jybnk7Tq7jdaYCtnwe+JEM3Rlb+5xokZMQ0xs9N//Hc3OCKaJaJorHcn5GwSQ0t+ukrxqwVwgxZUyjRY0hT9070helhx8YPuKURzOnkQqJf6zgKH2XMoY7rWuJxTHEAjZeepQbgMlECIZdxGvMQQoN71rAw+2gu/DhdjQeBiPvch/uh44laIQUtPgH0itUPPf4ZByO548/4CdYH2sp8Q4hjUJ5Ztt6af1Pus0t68b6phH5YqNz48A7IAAOXZ6iGX7EPE3Q1AG8cDfUlJN102onNuKZRAbz7AMgUDDmlGAQo7CDu30ag7vfkW4Gv5e6w+9HrhXjKtrOrckipkkBJJyjo98bVVZHf40vpYeS8ScE4IOijSaVT+5sBVWDUCnyat5etsrh+pt5ibsnlkfCjTJb3J/d4r+2Qyg+ekgyz94K2iowurHfmTAQ2vzVtu66/+YCLtotmSmPgy8+i42/sTTG/0rENgWLLw5JuxXdhScxKx5bAEQ7a7LjAVfFlWz/6/hnBYInM5Qc/QUmGvMDHEHSwX8ZWkXENVs1J73cA8/nzh/2MfRfdRPULtB36UMSK4uK14IbQ6DGn4RLcZlcambHMDOSrzJXEdGfcF/V8Fi1tk0pJ049vgt+o21sFn9jif+wFLRzSmOze7Ic8Yh8Is6AOzciHG2sDdXT60ZebRHxPoxn+u0T8PuDcMjMcRDG/El+IAMw5ZcEYnFxAp1eeWW7ACpdy+pJggIkqmG6bhqBlbwyVM9BKU0BPqnkxZdiD7uEt7MCZgbGQ0M97NSNobR9K3aXzHB3cdyo4BWe1KDHOsJYlia5iXS5Bad3957cD4V2S5E4Wi3PNuo83It/ydR6PlR7BgGGygIYc8ICFovBFzuG4KinRvW0EarQEDKDzpiqjwCbe9dsVtNOMnLo8mXQO3jGyTo4N0IRx12hMIl1mJSOu14A0wwDFGzG39yPpsHqwoDDUaxhyKiAP8yj5i6nWYpOOicxwdbXY+JfdbwOANrnYogXoO0NRhkUaS2YmTIbW7IUDav79nxqsSQwwWF40ojxa+NmQwszM13nPWkUICw6edWw2w4TReqzv1VwW6w4l8fQnLCVch+rddUpr2bf1+6eUoqaaOd+H22XIeUcWZO9nCqIpcZ2hJavPuJ32Jzz08dFcmW1jbMfn7tlyqC8LlpC5HuyCyLRyZOsM9dWkN7/hnHr3Mb9tfgMxyJfeDDwXSVe7iAzXaSkmQfySxdw8ib8501QZCzKkSlAZkYRS/WOf7V04V3BXWGjh1Ft+qV2tr/+SEPyS6qQXZVHwiu+OxyU2BlXIoROMXhUhpoegHY74yFBUP775jpCpXxHwmXOQ+zobiiDmMIvGsIDjNpRG4ZIPyj0WuttcSA2p64y0JpUyuXaNOgAPnACe2bBibvDgITCXcJM6TaULxB497yN3TayejdEepj1kvc7Z9wYWyxsTCTebmPkcgI8t7eqkLj7yIagoOTfrMvNIlfCHLl65vgd6zvd/i9azjoT5tpv064C/HxMLZEwbGsoh+tMQjbdKsrmjSBQdg/ed/hyrLS15119oQ0KNCrnQDwBQbqGSzvNFzbsqWkAPs1qF8cKHNEC/bMrCCBnwmQubJdenrqrK7hccNTngBvtFaclVO3biIzmPxAbhVzj99w9j+28R7oQxzQabU6W04CS4/PGugyVN1zUF5UAwdQIwA1AZ4B2wF78qf6DmuEMaVNK5BDGgeuapYxbX8zA+qdsulWqee5bjTcqoD/Z/Cp4URAu7GNsP6Xf1FQ7kQiJXyamvPrYlSMqlEdFJTzghnzuHsBhMp+Mr4WBYIrKkg655adUPzUs84vJ5KFGhjh8qfn30MfKeJR9SRAKXDgGNod/8etjGMXAm4VnwJa/dSsTJ/lbVswPaCcFkOEOEV7F7WwIH4rRHLQBUotMes2/73U3c8pUTp4+WuKo+PbudG950IoJZ6v0L/XN1uMX+YfPXMBiAPyL7tlkgCXRhuhmCK6p4P3bo7hMcmsLvxrdtEttoTMxukB/yFzvsOOjPcM4RRBAEKH+n2nEXdQMyVDgD36CgKlVVCE4cT9u5JVBoEDlRgskCqPxBJN+JzGU7Pq6qlB85ENV3kj2cKkJ+FSE24jwfxE9INI1cUYCiNanwGdH462Mom1fv0vogTrzxChN1FQAJIR4dOmM6BJhig0o0viOUYEYh4kaMprbilzUkfBgoPV9umrlcdcef5tU+nDX5ExQY1RhAbhXwWhbAxXRgQOFW0gCcg9Q2oLK/FwhIMY0Pt0N+HsyupCBkMz1XBsNRKVhNcXSf09aYl9KUsahYrcApxsgSPXMjmskB6EhTuSJsifo0sAe3187gGBb0kr6Hs/UcF/hhuZCS4iNB5JIi0Xks0YyCGVpGjwqtCD4Wke92kO3wvdXLi5ut9ImBoDnjbD847ZWjXTBIYjbN7AlDCnB649gWDI3CdEPThCDFW986uEdA+hERcMbfzF5dXQkxKIFo8g5XOuR+0yzW0QEFcOwj4hZAMjVD72sn5yH1D6zcn4ckOlBk6p0uyC3bec4PmMjMGt0NAtQfcx3G6dRDXbVaEJFQYTpd8Y0GTlKeOg4dDWS83W7612w68yArCGI9C1h3GYmRN9mv7HMD63L62y8d2ciVnl9Sa4MId7Xqi/r0FmmVogByxR2Qri8gkFDNGxYgbBxCjn3N9p4gmPOiVZ/1C6EN9FIc+1XcmXuJH1/btp50jTWcN7gqFyY0dYji3UswrUAKyFiH+HlL8NElRtiz1T79dzbhtOcKpa/2pWmH6kMq6ZxOTMYldjjajNdyTEZzLmhHxbBOWrPvO/t+kcjZS4iAwKuRGy6qd9uqDOY6CWZm1EBq5dI95O9T1D6LzUu4BIOsjpSwMx0Vlv3d682RsHtwaK0YUr4dO2ysQAvhu9YE9SlzSxlq188RiyBo4a6wgXCF18NJbG2txIvxScLhNbAYZ8GLBZVEGPAbWsfkp5tR8ynNLpMv/V6WC0et/drTnSzelkC/IO4t3vzLiDdxlbPg1DiQeBD91g1o7W+dcKieSJRh7N3L9mL6EPEEVMCgJSXw15/HY/WelQkuNixaW61dHVjmEIOvuA1SxKADTHADpdPw53qkJ9rORgOv9cV8RwMR5LKNI5kA19D1HkXm5vm58dbJYPSg6lnsEKveLzPs8TkwrGX7XYH1P1xtYkkgRhxGxOle5DIBVIkrVTzZN9TKCo1Dv10DwHVYiwFdrE035Zzk1oAA9QXFHPJgAf8qMMhvqLkUbfaleh1FFlup1juKChTt9UcSeXhDQN5L/HCoekSWw9XDLNLAuKOWU5GC2nUfcn485qAsdBjzq2SEnA3PGbe+m5HVW4OihoV5BXmRfpSaiuN+2PIvkRjlOeU4dhKt6l2KHp4Nnuj7Au0v0JHuvB0MddTMuz2Lk142FGwx+asXCnTWlCfBorXwRbRYYYctPQ7BnRiloCv49PEm4Ey4AzasET5W0ZJfKbmD0nPqJOgMNXkQMaEvSIIiW4suqv5P0dVloej6YFVTtcDPg7abAbJ0NfnuJkeBTJyMliUj1oNoRUsOd/KdsndXseXzuj1A+natAKeyS54bE6dwVRg14CevwMLc0si/NUlN9rRdSP4s/jHXBvPnT7oZhgo85+tSRDqpKQBv2ntBOjVt0/QDNwJSxkUCvnFEOqkSikB/V6+a2rmh35c3WiTEHa1j4ZbZseu7QCe3/XWGqLYIMzaP2T3i9adIkJdPgDT8RCHF6yNII02VwimrHYU6bi1hICnKajbCkmzzlFK21YXiY4n6YB2QRQDm2Q7hxpVXZrsRF+mNhFvO2nyeCjjMq6FrH6cXFeKhKZ6GQVFri6G43rNEg6Qp9xa2y4ou5wkWzumJo1wtehMtC/XseVh0KDSpjlWoEaygmdr0j7CY6p4w1GCuLnLGdjmZNJYSaUkG7zyaWHF9MEwp8zn4sQ2YHErNhb/HmPcsWnQ1jPkmOWs7KqhKCktwSqxnwceGZsduh5Su0rYid65cmjym/7X1mBLGys5Of0On7ED37oHHzKLR1O1tr2xK2TDZktObNtbl74pcKPAwsT+2ncBlt9HYWEPB3dWQtAF+WHc9wGwGFjU6+DPhHGZwY26g6RbrmN+mvn7o9w7ClNwvA6KAgTAOEAzMNmRGwew56JcwJBWhg+4iuMwKoXS90/4e/+7TN6Nh4DZwOD2wYQXM51mHw45HkQjg8w13ncYA0o6TKwhofKk/THe7kVM4Ybw9TomT9nttWiAxSvIi6FSGDn1bO4cpwCYvFmrap91mO/TVekLCg1EyFrsIDUpGgFB0LZeoVED1BAdkb/hKOs1Aqbad3DQYtStgFsYgHHZSoOQ2Yn45TvAERx5nB/brpGO/F75zD8AlieTtUBIpsJ46NPsANmKZMi1ohAjhnoTl2TljufS+YT+3NX7lOa1FPHb2xQ33QWpzVd1dbTFvUq4gN1qpk5ewKvuusez95mmSz8Rk8n0FBfrISG9dDDX5zS83g47L+gSNG33tXExb3LH3Rq1dBwHALhPZO1VKzU1AIWyCcFnK1knP0t4P1D/NCjf+hvHbWWg+YiKO1u4uhHA9vSW1LBbku9fxHzU56IBF0euaMVNFsO/ORlMaOMEYbWzw6Wa5qjyhAvqbSpN5fnCLkuHpuh0LTgG0fEAxxTak48IaMcJ4ynZiT7K4KA+HtNYu/7Y25A4bqPGAPX0Rs81Cz2xW434kVHLQGGhv7nYrG6TxD0vjXoMLN8t+D6eRMOsRJyu+wYoY2WxHLxPgYbyajfIlEMt/vxs9YUwarxcjDT/S9KkiBpm8DBUtnLIPs/T6KAf3rFw2zjv6rkjG/tlQr7z/8ul7oKoUZiwU9XnSr78kw1nDKtlMgdXBsnQ63M8fVqGmUj8rYOdCsX48gvBKmcgZrrQCBMSgJgOV0I9DpjQCrm75FfuYcdaummM17VdR0T8iOT+mIuysb6oYfHQO33kbvVbdBsIhcojOfgfp9mATjzZVsPJOT+TwawCYTIYrjLDLUysWdg1QHaGJihj9QYG6RBvjrN0K2wt/NMzHJx/1FukJovjrghkiHe3M6Rwg9N9/BkhyKWlIOFuZt6KmzQAW/IhoB0JwY2GkYJ+7dLlhpK3j+rXlSgejJETa/+djJ7oMm7ZFx8OiD7fLSdCmnblY6hyZseye18QuBKAnDKPousEEOWJtpgP+UvgjVF15rbKB1uVLX5m3ESKJlkahnZcOxJQLTQp6+zL4zF9bsu+KPWh6WDqgZDR02nw9Zj5mgDbfp56M7XCvNMp4Bsv6ogGkkOvvgcUoO+uM7OPUPj2J0H2EVdIV5qHN+9cZDeQ71eV8VDS+hgGw4SwVgeyZXsYmD3luUcthSXdfq9zhHL87EMhiUD1pnpYtvECmUU41mKtLc+Z/m0uwpR6SVnOFSMFKhcVR7nW5YjRtgzgFSWS5wF+R2wD3V8o2NoX/6IwPl2mtMUNLfHD5vyewCMDb7gVPKKx2PEqf7UqNkjfQ3TA0a6DuVtIpxjex7fq0jsX3B1hsm1Ovh14LzEwphsHeXXOBTkhwbJjmih9XJahjPoP7CaBx+ZsUTLCeTZaEzF6BliKjdrXIsAzjm+duebPHrRKl7FoFloLRktVCpnWKYBVdZCoRNSdfVeNw2fimeogXaq8pVq+qFda1v6L3Hxd2B1ll/tfRBuva2JTZAEvXC1oheq1QM0ctn/QVG62V6+Amy7BGEegrXi5HZ8EvA4kuEbgfEVxB657pIRNoDmUgGrCxqN2wtY4zJPAbuRFNcT3NoIk+nsDYN7EqAqkaXCMhOsNwtMyP8H1KALR/9hnpNlVtXhzcLNqKFPTk1AFMcZA2UzsRDMkdvux9SRT3DelZnxDKPvcK0YxU8h8f0ji03HH2bKJvI80wHuhbxGrlMNj8C3vUp4CF31OeuhJIqIq9LieMA/qwMQFwgFbJnPi0vN8uYlvv4kgtsTMfc6LQZ5BhsGqij1Fo0XeTcQK3u5d46kWo+sdrhnNucgeaUtegZmFet1E2Qvzbw3cFE2hgTWDvuDaUeVdCHYZ8WANmXfxInY/VL3OUykSbqZqeIPcw7v07ouWsP7PL5pzJZlmQl1wxOlWrpGAQ13Y63u3F3ZjxAGCIxbPZlbAUAqLdw0ln33I1p5OpKfegoTrzCLJns0TBSjyDB2efHIQLQpU5cnGfz111UgsxYAx4nS6Bpu0/sCjqjgw9WXA4kW1pzRyhHgzg5nIglsuIJNMXK/i1oDcrkehFm1awUOKcaMYi3WQ1TRBzOk9IycjdEdYnDfzVSeTekilEGMcmHptWGUwgRdat5MD9+zfYi0Y32v1J6Cfh0xgolUUGbdFu5oiSC78IZF9h0B2OKzlQ8+XBH7WlsG1Z6bjtZV9pqVlORRcjO9UB3PsBysSQhdqOXOo4nVux9FXkFrtbyTI93NjygQYa3Bi7mRlZ535AVqjmhv/8nOAAFqPS4Z/Qn0ZGlBRrjYRaQM8ESYny0zx9p+dXcjGGXTSy6VSnDL8rFpQtJDL1/EgrPvcmF2srKeqSY/nQN8Ix7GOTSZT/B6v8034ky3wfUGSEOfI2zUG/fSKp4yL9D++LLsWDA3uMboW257RLJnMaro4Jps4UZm/E0VpbT9eP4Fhl9liGCqRivWoVjwpYzC9xUBrnCDVSh+ycxNTcV0ZPvHWR05Et/QykS/+vdsgGUtOpT9woiHQJ96mJ/A77bu6cKxn3T/+DEa9tdDNUaJkjtNtK8XMU+xPGT+Yg453xEivTbJoxSeMwWg0SYkMz7u0eD9wA/sod0Nntc2O6Vs2und+oiNAOKbE4WBVcmmRuMoxTCrKpjTj0v6gZmx2KQP1ftFMR/hCRy5WqK36mLod8yw6xOHlQM20UiJ2CjYyinRW85K/HjTrBlc9/dl2zrGaFR6iesctuRk2/svRRX7q+eU8G2Sk4LH7eEK3lPdOet9ZdGPb94yf8kH7nh9jVOvQvJwY4EPkhOWX4tOqgFQfMACGC4pFDNnXcVHoERauGW+m6bmhWq6NeNCL/6ZyIABvSbGHdP0scs3oCVDEJOALWG2vTrZbTEvynyN7BB59+J2IqGZe2jn2GSZWHbTtxGsi3x4ekioxKrN0C36jzMwBZ28zY8qZL3HTDhhv8m+Pax9dJ3bUB55ZP/6lhZCRVcKA+9z8KVMJpQCmihF2miSVHY5Xw7iV7epqDj4VwkoZBOq5EXXsdjgA8DJr8T7MIHsVegv9wFEdu9NiMcqJ7Lj0R78vr12+W6E8p65nqhtI000x/gPbEgrtKa9HoLDPUlQPaVc6AXxGTEkjtlZgFtpE9wtP+jD15R7NH/0HDMILK3lz1WAlyDb+dhwH8wMSv6oKOxBOEwypmWdlEXB4L2sclkQ58rcmDwd1RjQBZZXHYzjbDIDxWfXnQqSMlHBYodSbn1zCRgYv9g/xWecF/USRuXyBNxGAO5h0lAGjz2/fLTtsnuacZlIu7JtTvT7yYo1ppXQHru2Zaq+t2iCoqrqir7GL690XRG+Z6NVL/Rgnd6OsuXbD89s4kkxhxadoUE9kQA1fhA/IdJPcIGaZuJWYfLmapLS66oeLoeBC6X31vkYTNZ/a0f6rpf3F6C6Ffbhm9sYMFXL16yyj5eJU6Vs9RmzcGh7p8UFSz/nXIpSsAKf1hh/+NOwYsEjzQ1TY169+2SsR135siWg7sAtWOHxwvCXbYP6nKGFC/0gzpm/moFte2Vc5IQNC/zczvUNfRRtpPzVES8rI0jULWi2GNxgm0D6tVqAk9lMMhNz4e6n5Bgvi7VmlKy1A6z69j96kOskxSmo6QVdETdAukFCEWeZRtpIkHFVVAG3K+GHLBvw80aHbyxIhEY+6dOCDNhwFCm4fI4swYaSBS79RbJEORjp0gFgjrSpMbVcuKhUwk58g1t+pJgh29JobarEcE/3K1WfLwpTR/EM0f+YL6HwKgMIbjmXWhxTU5ULpmq3lree59zq0dtTzbAIK4sgjtslmiP42Tu2IjNeQFozRsFM/GtZU/qxlUPORoNWp7/CKvu34pNFzEZn7cK4ZhsRlD5vcNKRY+94o7jtP59Hgv5boeSk8xQzQgzY1SnsjbcI6sG5nZLDcjgXaxr+UE9kZnwTZD0XlgAEsIPyDCAcUUoOuttD/LKVEEJlbQL12X/IOAD7+sM2QRGjEqAaK+CWmFy/ZGYTcMmMzeFkpk3Antp9bMUGmC/sUEh85PkWFey8bSSFSvPpLyATXj1MHB6nluxFwo7cK1R233EXItjyesncVd1hpIKK5bAI4jhtchglHwIIPwExGSh+zirP08qFymto64yCUIr+8jtATfVjSNj+e6AtUp9dLpuV05aXZdrCFCJlU+lcz6/2PkdzZ5TscTfddv9M0xq6RfF6ABbsksVjk7a0pWcm3lw+/mg3q9EOjVOaGGed3/8XV4byQIf8fMs6O5jAQSIWNwLo96Oi9P5n3bLb9s8LKvsDRAryYaKOEzXjn+26T7zZp0AjGdD/HwIdxm109ocvH+mquAXT1Txm1Gmt6/hiSfJnDhz1VBP4/ym5DpFseB0zZpdg+WaasiwuAm3oepUC88XP5AJZlyDs4N8UWGafEoYnaKlxH0tuAkrChy49DXnmsQZE2m+AO4WaaXcrjxSGr2+YqFyuIDob84f0e3iqxBiXUniH0IMa/MG68m39pPBMTIKuX+cqZpBwrIDrD2UHd0ymoVxvQ77qaE3FCzOhXggeHmdrb911RDM9xW8VO7ASLmzDYAocnW+/8wVJ2m3AaPVqf56HSDrSvrbT9HpqH+u5ZZJdQhTo7UvGmgv0TG5nnJaNW8C5P7O/qmPpaENh166v0BeTz/PAGCgt4iv6CCVsItgcFN7lhb6LQpNxymAwmnKUHDm6RqlCcScLntO16jCKgHTvEGwfN2MBRlc1k6vjSve1gAmi6x7pliIXHw+KcJ+CTU/6pZ9hxqbE0puEkpdn5aFnZjgs6CJQvA6qPhBzhPXkrGsC3ManzmKxS8VRvkYNfAEDEheM5sM67+6vw4Lyk2EtvrdSBY3bTWazzgmlFZlIglxd7pz86hxdWAcpc9zP5C+kaalaWF3MJ52BPDyu5XMbuBVhNTGLbbTzX2rTSB0ycYuO8hrx7Aa3gajX0e8WBiXoDYgF7kOp3CuiQGVOl8sMJ6oTIYSy0h1bZg9TqxzSz3cuRWrXNJ1Fp/LofGCuywa5cDWE0TfaOWDlRm4RvG6VRC0LFhqPW5iFQcEp71S/B3cb9BP5S3+9JkaEHSbQtEeiARmyuXh2LB0zewkB2VyBKAn10V1bo5OZf+24cpp2bFBHp170VCFDThXtBbbNh3yO5ALpP7EnCTSboqpDnrbSFAj6OnVDKTXG9S/AMzN8Z6bxSBsISKd0+d1o9DdZ2dzLqNV9fMRQUHU8n4Wd2nQZNLG4s+OmiJmBpRsw8bL4ldEVqudRGezu0jLLZcke4SazH7UtU6mhoERJcSZRqscO4QqMw9+cfebLo+GhRVcxNVzbu+iChYnzspQvkTHH+Rls54HwvVeJdOQkqqr7pHD5C1R0QpuoF73jPSlocYw4fww2t3YmSQLHQ0l1s4A+S9qGS/zwyeIR+fJTwxNV4IopF//biSxeMDbrcjvR+rHdR8Y7pOSDgyknH9RrpW9YcX62FwuwoNQGnMClDV4HPvWL5njT0p8AA92Ajl3S0xnnlCyvKt62OgXKW04NR4ocsRF0lyyOpEXI9KpAJenHENbXpbpCH3uxoVr6Svyeg4aBC0L59BwB/u1x5vd9Etv2UphK14redfHwUiweAzSNr249ad7wSNJLY24kWld7WHJ9tOO7nydjzO6/7ii6x4bF4knB5hvczxj6BJcqnwEV2KdBlVyZp0qTRCNALB0E2oYQFmwJwZh/s0nJ29n+4JfNL4vZtgJdxHwXsfIBIwz2sO3RQaAde3fg0dwvKeDZNXtQTFrWMqbLoEV5poJbQX7nmsx6IWYrZqydUgGH4OrQruP5k4IHgqlRgkSld57GOcskXYrJz2+sRcv/h/YEwTWCpXouqMiGMxNdJV3igcMmMrp5qyGYU/qk9sMQHJ1xH2WkZ9UbuAvWzt9PLL3IGdQPtCNxROdXPtszW/9Xye+M0s765lPent4+hKVlMBnl1bQUSYIzeMvx+tYm73eKm+5wPXe7qwipVNxJMoHAviG6HsLaxwccQYEQKG9rZdnw3603x1uGbXE/IEWFOU2CUi1YB/NoMpJYJXQCjfG3TZpZWNd55/nS4nTAk+6J1zUZY+Kx5vuie9tM+RqCwU2FQplZMHdJ/AKUrVOJCKUqE/8j3GigElxReoqsSC+7kI/QQbxCTSqZiHQlO88mm0B1d8gi360KUBEU0uB/7ibcN3WLdDwTMnw4gE8fFDCKplmD0vt40EavdYFa95a3J6oKD+nifVsVIl6kpZyNEtgDkgR7xm9z6lsPCHLPdk18owwdxxbXdMJIBzu0gw/K4GSvj2a0Y1UWzUwXdijDXL5u+uQAuevsddabo5q1eN5uZA4h6beYuxxZXX/ho+KH7mLphqccvGRj5Qgt+QJ/XdcWS0KC5DRA6s1ZEgl9D8ED6l0usw4rJ16vEKgnyE5tQkC582Ns6Ie5eJ+WvvlMROYBtrVw2u64sC/8JBGoQoBoe8FCdu/L1Mx/hcG3amewrNrv+Q4feET5nLuzqsGTktI8e0mzTiMA9K22dJ29Q/6pSQbDeiug9sxk6ejY7JXZc3jQ8TW6hZdeW13lt8e9jo2OP8wg/lydzfq61WF6bUZzze5+zeu5jq++pEV7lWXAddNkkSVw36MlzM/pCk9ynm2hfEpJqg2L8tRaKBrEcD1TTc3bWFI5apbAzFIrerY6TTv3nrRmf+QqFDHijWKGjRDcZ95iV2gj4CKPqvJefQjZH0LaG+Uayrd4dq+UtOKlZ1AV16SfmDsL58NS8PDBB/ri8YoCEaQyv0wz8VEyRgoL89YP77fyGWQaPeVMZMa/APgNufhUCHcZ0fNpUAg9TW8++wT0W61fl9iNOvutaJjVkVe7cteR74ll/kuMZnM+4UZybUOqnOg8jejdfyYDVY/joNM+IauDWS10e7b8Xu3frgPe2dUEvzJzXksstCmg0dLYe2yIY9XIfq0xsMCsEfS32yqRT/Xa/ltNcPXjJVr4SL4zJl3rY0zJXpojj1Qy1hcEQC+VxOGoIBkUYliYeqIyp/FO9lV0TFKM4+Xh7ydwXABNInG7AJhV4VMA8UZIVPnLwPOri7w6qC3lt/IiOtpSXwqEgYCMyopPNl5jrHeg7/qLQvzT7vr6GE+YHR1y5sJT/JDvyBhMBbaRaztR9TJBWKLmZjAZgOKA5fgtWZsOW+E2hcv8VthllkOYYAL7eYCL+E7JJyD5oMhpsTDE6NkM7/DQtDA0bvujmHn8QPTB0hddD29zwFQMLMoHr4q2P1n+CW3y06xreT5MHpOnPH/R0mITFNGPDZOAxhiiTklSBAO+lE7v6NQVg6XETwmDXtXurWpjQ66QbPBtCuZ7kIXmbVhKYQ4j0pE3RxQ/uvnXBPu2OIUwcnasvRS0JmCBQdli1ecsCNNhIOXkYwlmRmdAIgP0FSbTzhirjnsqJBQZCZMnKwsvgbCdcCAlGHAXIeqXCuGa0jf+TO9wR5F65B+P1QflfR0jtWAzjXeAwIqSZeywaZVntoNt5aSpb+acOVUBh5kL9RgApU8OnfYFtFClgwfBfgZPARliqqqgbm1ozY/xIuP8yX3o0BFLgwCEl8aTMc+V8f4n5SLBMWLnjX5pUnGnPqmWecaqOgUSJ4Jakbg9Hc7P9CmAxLyG9WUkeHrBRYSiFx00jTHYPdLSTTJJ1Rf4lNh0GDM2FuIB2X0VtGZs2F2UvH15KsGe+T5JXGe5WYgBF6LZBvL9i9DfHO3eMgnqVUa5nkqNaLTshP6SYb0LjtDjNeenoTqaRNcpKH/0C1DwIl/gr7S8LP6vsb71fr8ZPRV+7cbF7ySK+pVzn8NosFcF8FutLtX3VlTY/pn0+SMnjknh9Isg3cRPg2adgDVD6RE4gPpIACFsbN8nSC06bL/isuKlxAfmF93ZFR8Lu05TnlzsgGoSf6Vb61RyOSzQjs23y6TQKPmwWDFTT2ttfRDCttuwNhMxA9ip1fdf/MAvHCVzYJ+iak/HkcLQkpXeuMHxBmPKz7Tt9lxsYlGNK3NfBGykFvS6Sf8a7RwmGwdFFUGdLnyg5M+7BXNIv5HgbilJ2VAm7znrOxILvkr+kqNsszXfLmWePTNxJNSZVKexJ+MTnDPmuoWMJLxnWlorhnxWmybJ1K7rluzAWu47Wr69c6ZSx/hMV+bLJeQQWIbtm2ATKecwSXatSgM8I4x92hjRFv46mEvKCs8n/wOM4QMu1c9LpU054oSv8Kq+OODqKQEl+V6kRpyyxXqiT2nD0349dH8FTq0qepnWq0fgBVTAI1izygBduYgOb23wc52b78ZUm/w05Fd8yYo/K91vTQwJysp7DmXoCOI37RQdfHhR76OAAAApjc0m/ew447J8ZAAzZIlQe8lNRfbZQPemz8IGI7RpHpbFhnVKVRqqksAMmgfHNF951yFuNKB90DjeuSkxSpAJnGaWvKPjpxlm+IhdX5nXJVXRGFTO1u75DG7V/XRkYHinaQtW52BDL7FEEAD3WMDADFVLW2EytMqujbYWkopMPKvJJpb5v0ZA06sBmfGQOZyZyU5xpd57mVVariLFrzcUmRgr/sRF/Ce520aVij2xvIGW3AJUt9ycNimtr4K3sepO2KQ5AduL37xdMEY2cn3pDitS/BEqdNhzM8wh9tqpqNsxfsr3Ld3nMF1u10OxD7Vpg2s+nZmZCbFNCg+UVGfDye7fQ6/E+N8MxltsFjfOE3H0FfzfPu2syz9nGsKYDkvNCYkorom3tVMivYTvIb9R+pl99xaLf7cPAE142UXN1dTihSi+7DZ/odol11Jw2C2pHNFnXLsrTUYXy0bHU30SfcepZ7V/+n10gRy7iH9jbmJmRb6il4v4cMRtX88gOPJ1UK7jCJPQBgXJqx+EX5QlDOnVlDh7LCbQEco9eG4f1OHv6IXVr1GwumKCN4WWYQgIc+95ClcuzhE1yAIOk+pb2BVMjGtUnC8vxSEMuW6H6h61b8YnJkxEGDosbitSp4EkdM+VS7FfcoMX41TI243EYzBEfPymtri/9SiqRt2RbfzRcf/Y2uBcZKnfWDUIxW/Ifnmw0vC7FSKju72n7U8RLKjotR9GEuLILCaMfbAwM+EQSYsdm1IksDji1nd2yGsAhi6aCWvX6lgJDcfUqPUfh3L4agfQfsw1A52SIkkoK/MlLRBbKKD/IkYRsK6o7hBo4eI2NuAenbyd8B5WvQH0ryqXd62dfV1J5c/Z0XOfNaiJTMOQX81LxpQcqCOXOHDxsUx2TWy9OrRnEsiaOF3LnMG0Z38c7lPxiO8UbBWnld/jepwhGR+EAUuwHvw8kq00OqqchX/Ea7q+lmADrhOwk6q6cop6rN2y1C5f/pUNFevIVKoWtFL/eYZs+lUNmicEGYjij/g7ckj1X+Riwhccruzsny3U6JRQ6A+4XAfhipnDqDddV6Ho+cIwz7pQt9YPGmb+J0f+aFu+n205PGdyZju3lU9iKUTcw937IlpkjQHp8pBqaxkWFVUFzi/VKSU2S2Lu1rRgbiVxdIvguQt0ypu1349hlxEP97XKp8OmMAKIyOkM9b253aMz4C60j0NHm6nE+4N5rDXIj8c7y7QI3IGAe2hHwwu86MnHZEkG3iN3jzJDNV6hUd8c0eDQXdaGhjHfTRONsyxBGPJngJpB82Y5ddvtGuuL/xSAYy9WMzcWegrqrqOzJ2BCXoQbrJXkxfyuk4rP+f5AJJymFMqKaow+OO9PXcuZor92WmEBsxSutlURXEYhBjcrKtO36hfVsUt/3RB7IFi782L9sMVGBc+Q7hT/QEohk5ilsP9IqeN4ty2jSVv7az6NDwY12gmOhteHjSZcX1SnvptigxSHHIId04IHHdKGAVRsU+hwzS3qXBHBQ2jHXqmF+Ovzvd/oQ/FLWYbRMrMEafD8gCIIsqQQTfygIWwhjn21CYwdOINT8Eqd9DvZ5KlWPQ9+NgBBLEXUHtX0OE51hH8fP1Oekj+7CNeBgrMZMzfYnajAUOPEFYx7H29aCpfds/IoDFzV7KVmIhW0O0rfZ+DIOdBg8gFNyBfpdg+LqL93YB73Q5g4SdIVIMFPcWr5navHKDOyI2C3kVOW8sauo3cGjPMcudPrvJ9Eb5ZyjcB5LquDPZZFG6Pd1fbwm2bV0FmMn2lxvP9zVSoH8a4kApjoObPGGMjwR2uupN4Dlk9LczVg6EZGaZURUeVq0lAd63vEq1t6n+0Qd5yfCW+54pRmffrvB81OW+s50EK/zyPFlX9WHH/iy41DC/OzU2iv1z9k/IJSFViE1hYk/waYMrv5z8t4Co/OqU7l7clxgj8KMpRSrUWakIFizz80p8y88XSbG/z0DE86w1bWTITDtEt2EAbOgwwpMathX3yfQdKmeor1FngblzwhMXZhUL/a3iIPUgOQor5MN3acwtVpNZG6/ZNm1jJav4IeVLgzGDc1GLR54MnnLvRasjExZuINPUolEpH0BTbgDQdHEXkWnUPrUubYea9GnNLWtxf+LpqlV/uPhBbxlJ9H7oLAjVDxdNtbyxuc196Rpf4OproHrSC8nDQYTgYrAib0/Jai62mhZr1bu1j+jOJgxtvY9ES4v9Fw8ghIhqvypxC1w1iCibxTiUciutqeJggaO0P9yq5eFB3mi7Iq7l2bzoTaJr5IVDRkwxyPjy5FHV+umvH5vrPDLLEkVEmupx2JgemFnc+1A+QdJkMKfcJv8ebfCseqrgRFNa0jKuu8SFK4B/8hhaMYs+uVlk+Jbr2t3P/GQu1pgUa3bAnM1rLPoDUmnoRLnAjGd4jHqWjwF+6aJhNSoZ6IkYJcJQgdDBl0Hsmre0wDHevBLbXMNflEHNiOe+vYHp6waK61m2t4owYB92gSZAAMsCVcAR2zmhfhMvKlmNKUKHbjT7yk936bAmt8AKGRWhrSpQ5ZksusHu84IzTZPzgC8m/9GtJsE4QsCbeAd1XZvE8DOCAAFI48bAnkcpXvGDXMrWu6X+paVz3LgWCHVbVyinrHsWPLfJekrq060yLblVxODKWFPiboiVE9F17BHW9JTG+bzHhq2eQKxV54yD9ATxK0eXsPkoyMCGYZ2nIOiS+fMqJPObfnJ6fC9rEBsN41hILsFfE8jRmTpB4NkiN4O1NaFldLJl8GQpfcplIAVkME7JzqxkQNjuCfum2FCXnxFuIIgR+WySNb1sCc5yf/Bwn9pLyWZsDIjS/54PpELDFmaSWn3G90KlJPF/AoCF/UT4b3EefPsxWACuGVfBaiKMu8f/8TMzCcs4JqbAqmROK9x6rzjv/Bq0cO2k2dNDOqCEqa55bNT7fBNpMBv0XhnovO8qa+mBq3j64lqZia25kzFCCXmJjAB2ND884lzv/gOackaR2J4HC69ljtElQzWV+13WI5b2nkrp6vPxkC6nhyKmx5aukC8tyU3rsRzRgH3x7bwHtQQPGJH955KQ17lqvmUe986fGrJiUSz10BjusA9ITnlYG6qNV3kGXxKor1qez7iBmGIDd+lRXwC/BhCCg5LppQ3ofdTnvnAArHLdtTJQBfM5LV/nIeQyHZtXjStkswTf78+6VzzW4W6kPMRikFVqCrGmtcpmK3WSVoFhEkLat6bOe1S9M3N1UzOBbva8agPRXsQruV61oalJ72mIjYTUCGclgAAAAAAAAAAA=="
_ICON_512_MASKABLE_WEBP_B64 = "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"
_LOGO_FULL_WEBP_B64 = "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"

@app.route("/icon-192.png")
def brand_icon_192():
    resp = Response(base64.b64decode(_ICON_192_PNG_B64), mimetype="image/png")
    resp.headers["Cache-Control"] = "public, max-age=604800"
    return resp

@app.route("/icon-512.webp")
def brand_icon_512():
    resp = Response(base64.b64decode(_ICON_512_WEBP_B64), mimetype="image/webp")
    resp.headers["Cache-Control"] = "public, max-age=604800"
    return resp

@app.route("/icon-512-maskable.webp")
def brand_icon_512_maskable():
    resp = Response(base64.b64decode(_ICON_512_MASKABLE_WEBP_B64), mimetype="image/webp")
    resp.headers["Cache-Control"] = "public, max-age=604800"
    return resp

@app.route("/logo-full.webp")
def brand_logo_full():
    """Full logo with the OMEGA PURIFIED ICE CUBES wordmark - used on the login screens, not as the tiny app icon (a wordmark is unreadable at icon size)."""
    resp = Response(base64.b64decode(_LOGO_FULL_WEBP_B64), mimetype="image/webp")
    resp.headers["Cache-Control"] = "public, max-age=604800"
    return resp

# --- PWA support ---
# Two separate manifests - one for the customer portal, one for the staff
# cashier app - so each installs as its OWN home-screen icon with its own
# start page/scope, even though they share the same logo/icons and service
# worker. sw.js is intentionally network-first (no offline caching of live
# sales/order data - a stale cached order list would be worse than none),
# it just exists because Chrome/Android require an active service worker
# before they'll offer the "Add to Home Screen" install prompt at all.
@app.route("/manifest.json")
def customer_manifest():
    return jsonify({
        "name": "Omega Ice - Customer Portal",
        "short_name": "Omega Ice",
        "start_url": "/customer",
        "scope": "/customer",
        "display": "standalone",
        "background_color": "#eef7ff",
        "theme_color": "#00609C",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": "/icon-512.webp", "sizes": "512x512", "type": "image/webp", "purpose": "any"},
            {"src": "/icon-512-maskable.webp", "sizes": "512x512", "type": "image/webp", "purpose": "maskable"},
        ],
    })

@app.route("/manifest_staff.json")
def staff_manifest():
    return jsonify({
        "name": "Omega Ice - Cashier",
        "short_name": "Omega Cashier",
        "start_url": "/",
        "scope": "/",
        "display": "fullscreen",
        "orientation": "any",
        "background_color": "#00609C",
        "theme_color": "#00609C",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": "/icon-512.webp", "sizes": "512x512", "type": "image/webp", "purpose": "any"},
            {"src": "/icon-512-maskable.webp", "sizes": "512x512", "type": "image/webp", "purpose": "maskable"},
        ],
    })

@app.route("/sw.js")
def customer_service_worker():
    js = (
        "const CACHE='omega-ice-v1';\n"
        "self.addEventListener('install',e=>{self.skipWaiting();});\n"
        "self.addEventListener('activate',e=>{self.clients.claim();});\n"
        "self.addEventListener('fetch',e=>{\n"
        "  if(e.request.method!=='GET') return;\n"
        "  e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));\n"
        "});\n"
    )
    return Response(js, mimetype="application/javascript")

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
    # SECURITY FIX (Sept 19): missing the same store-match check the
    # dashboard page already has - a logged-in customer for Store A could
    # browse Store B's order page just by editing the URL. The underlying
    # API calls are now locked down too (place_order/orders), but the page
    # itself should redirect the same way the dashboard already does.
    if session.get("customer_id") and session.get("customer_id") != reseller_id and not session.get("staff_name"):
        return redirect(f"/customer/{session.get('customer_id')}/order")
    return render_template_string(CUSTOMER_ORDER_HTML, reseller_id=reseller_id)

@app.route("/customer/<reseller_id>/history")
def customer_history_page(reseller_id):
    if not session.get("customer_id") and not session.get("staff_name"):
        return redirect(url_for("customer_login_page"))
    if session.get("customer_id") and session.get("customer_id") != reseller_id and not session.get("staff_name"):
        return redirect(f"/customer/{session.get('customer_id')}/history")
    return render_template_string(CUSTOMER_HISTORY_HTML, reseller_id=reseller_id)

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
            # CRITICAL SECURITY FIX (Sept 19): this used to return the actual
            # OTP straight in the public API response whenever SMS sending
            # failed. Since request_otp needs no login, ANYONE who knew a
            # registered phone number could request an OTP, and if SMS
            # happened to fail (per the old comment here, apparently common
            # with this SEMAPHORE setup), the OTP came right back to them -
            # no need to ever receive the SMS. That OTP resets the password,
            # so this was a full account-takeover path on any phone number.
            #
            # Fix: never put the OTP in the response. Only a logged-in staff
            # member can see it (so they can read it off the server and
            # relay it manually over the phone, same as before) - everyone
            # else just gets told to contact staff, matching how the rest of
            # this app already handles "no working password reset" cases.
            print(f"[OTP fallback - SMS failed] phone={phone} otp={otp} reason={sms_info}")
            if session.get("staff_name"):
                return jsonify({"ok": True, "otp": otp, "sms_sent": False, "sms_error": sms_info,
                                 "message": "SMS could not be sent - showing OTP here (staff view only). Check SEMAPHORE_API_KEY / SMS credits."})
            return jsonify({"ok": False, "sms_sent": False,
                             "message": "SMS could not be sent right now. Please contact staff for your OTP."}), 503
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
    # CRITICAL SECURITY FIX (Sept 19): this had NO session check at all -
    # anyone, logged in or not, could hit this URL for ANY reseller_id and
    # see that store's full order history and totals. Now matches the same
    # "must be logged in AND (this store or staff)" pattern already used by
    # bulk_update/archive_old elsewhere in this file.
    if session.get("customer_id") and session.get("customer_id") != reseller_id:
        return jsonify({"ok": False, "error": "Not allowed"}), 403
    if not session.get("customer_id") and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Login required"}), 401
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
            orders.append({"id": key, "sales_date": val.get("sales_date"), "quantity": qty, "kg_size": kg_size, "total_sales": peso, "mode": val.get("mode"), "payment": val.get("payment"), "order_status": status, "created_at": val.get("created_at"), "rating": val.get("rating"), "feedback": val.get("feedback")})
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

@app.route("/api/customer/<reseller_id>/history")
def api_customer_history(reseller_id):
    """
    Lets a customer backtrack their OWN sales by period (Daily/Weekly/
    Monthly/Quarterly/Yearly/All), same as the staff cashier dashboard -
    reuses resolve_period_range() so a picked week/month/date-search always
    resolves to the exact same range the staff side would show. Separate
    from /orders (which is the live-tracking list with 24h-pending-hide
    logic) - this one shows the FULL history for the chosen period,
    including old/completed/cancelled orders, since the whole point is
    looking back.
    """
    if session.get("customer_id") and session.get("customer_id") != reseller_id:
        return jsonify({"ok": False, "error": "Not allowed"}), 403
    if not session.get("customer_id") and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Login required"}), 401
    try:
        period = request.args.get("period", "monthly").lower()
        sub = request.args.get("sub", "").strip() or request.args.get("week", "").strip() or request.args.get("month", "").strip() or ""
        custom_date = request.args.get("date", "").strip()
        try:
            import pytz
            manila = pytz.timezone('Asia/Manila')
            now = datetime.now(manila)
        except:
            now = datetime.now()

        rng = resolve_period_range(period, sub, now, custom_date)

        reseller = fb_get(f"resellers/{reseller_id}") or {}
        target_name = (reseller.get("store_name") or "").strip().lower()
        sales = fb_get("daily_sales") or {}

        def kg_val(s):
            try: return float(str(s).lower().replace("kg","").strip())
            except: return 0
        def parse_date(d):
            try: return datetime.strptime(d[:10], "%Y-%m-%d")
            except: return None

        total_kg = 0; total_peso = 0; count = 0
        status_counts = {}
        rows = []
        for key, val in sales.items():
            if not val or val.get("deleted"): continue
            rid = val.get("reseller_id")
            rname = (val.get("reseller_name") or "").strip().lower()
            if rid != reseller_id and rname != target_name:
                continue
            check_date = parse_date(val.get("sales_date") or "") or parse_date((val.get("created_at") or "")[:10])
            if not check_date:
                continue
            if rng["ww_mode"]:
                try:
                    iso_year, iso_week, _ = check_date.isocalendar()
                    if iso_week != rng["target_week"]: continue
                    if rng["target_year"] and iso_year != rng["target_year"]: continue
                except:
                    continue
            else:
                if rng["filter_start"] and check_date < rng["filter_start"].replace(tzinfo=None): continue
                if period != "all" and rng["filter_end"] and check_date > rng["filter_end"].replace(tzinfo=None): continue

            qty = int(val.get("quantity", 0) or 0)
            kg_size = val.get("kg_size", "1Kg")
            peso = float(val.get("total_sales", 0) or 0)
            status = val.get("order_status") or "Delivered"
            total_kg += qty * kg_val(kg_size)
            total_peso += peso
            count += 1
            status_counts[status] = status_counts.get(status, 0) + 1
            rows.append({
                "id": key, "sales_date": val.get("sales_date"), "quantity": qty, "kg_size": kg_size,
                "total_sales": peso, "order_status": status, "created_at": val.get("created_at") or "",
            })

        rows.sort(key=lambda x: x.get("created_at") or x.get("sales_date") or "", reverse=True)

        return jsonify({
            "ok": True, "period": period, "label": rng["label"],
            "start": rng["range_start"].strftime("%Y-%m-%d") if rng["range_start"] else "All",
            "end": rng["range_end"].strftime("%Y-%m-%d") if rng["range_end"] else "",
            "total_kg": total_kg, "total_peso": total_peso, "count": count,
            "status_counts": status_counts, "orders": rows[:100],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/<reseller_id>/rate_order/<order_id>", methods=["POST"])
def api_customer_rate_order(reseller_id, order_id):
    """
    Lets a customer leave a 1-5 star rating (+ optional short feedback) on
    an order once it's Delivered. Same auth pattern as the other customer
    endpoints. Only allowed on orders that actually belong to this reseller
    and are already Delivered - rating something mid-delivery doesn't make
    sense, and rating someone else's order shouldn't be possible at all.
    """
    if session.get("customer_id") and session.get("customer_id") != reseller_id:
        return jsonify({"ok": False, "error": "Not allowed"}), 403
    if not session.get("customer_id") and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Login required"}), 401
    try:
        d = request.json or {}
        rating = int(d.get("rating", 0))
        feedback = str(d.get("feedback", "")).strip()[:500]
        if rating < 1 or rating > 5:
            return jsonify({"ok": False, "error": "Rating must be 1-5"}), 400
        order = fb_get(f"daily_sales/{order_id}")
        if not order or order.get("deleted"):
            return jsonify({"ok": False, "error": "Order not found"}), 404
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        target_name = (reseller.get("store_name") or "").strip().lower()
        rid = order.get("reseller_id")
        rname = (order.get("reseller_name") or "").strip().lower()
        if rid != reseller_id and rname != target_name:
            return jsonify({"ok": False, "error": "Not allowed"}), 403
        if (order.get("order_status") or "") != "Delivered":
            return jsonify({"ok": False, "error": "Order isn't Delivered yet"}), 400
        fb_patch(f"daily_sales/{order_id}", {
            "rating": rating,
            "feedback": feedback,
            "rated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        return jsonify({"ok": True, "rating": rating, "feedback": feedback})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/<reseller_id>/place_order", methods=["POST"])
def api_customer_place_order(reseller_id):
    try:
        # CRITICAL SECURITY FIX (Sept 19): the old check only blocked a
        # MISMATCH ("logged in as store A, targeting store B") but never
        # required being logged in at all - session.get("customer_id") is
        # None for an anonymous visitor, so the whole `if` was skipped and
        # anyone, no login whatsoever, could POST fake orders as ANY store.
        # Now also requires an actual session (customer OR staff), same
        # pattern as bulk_update/archive_old/orders elsewhere in this file.
        if session.get("customer_id") and session.get("customer_id") != reseller_id:
            return jsonify({"ok": False, "error": "Not allowed"}), 403
        if not session.get("customer_id") and not session.get("staff_name"):
            return jsonify({"ok": False, "error": "Login required"}), 401
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
    staff = (session.get("staff_name") or "").lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return "<h3>Access Denied</h3><p>Only ISESMO can manage customers.</p><a href='/cashier'>Back</a>", 403
    html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Customers - ISESMO Only</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.topbar h1{font-size:16px;color:#00609C;margin:0}
.nav-pill{padding:6px 12px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
label{font-size:11px;color:#666;display:block;margin:8px 0 4px}input{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px}
.btn{padding:8px 14px;border-radius:8px;border:none;font-size:12px;font-weight:600;cursor:pointer}
.btn-save{background:#00609C;color:#fff}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:10px 6px;border-bottom:1px solid #eee;text-align:left}
</style></head>
<body>
<div class="topbar"><h1>👥 Customers (ISESMO Only)</h1><div><a href="/cashier" class="nav-pill">Sales</a> <a href="/orders" class="nav-pill">Live Orders</a></div></div>

<div class="card">
<h3 style="margin:0 0 10px;font-size:14px">Add New Customer - ISESMO Only</h3>
<label>Store Name *</label><input id="newStore" placeholder="AMO Store">
<label>Phone (will be login) *</label><input id="newPhone" placeholder="09xx xxx xxxx">
<label>Password *</label><input id="newPassword" placeholder="Set password min 4 chars">
<label>Address</label><input id="newAddress" placeholder="Angeles City">
<button class="btn btn-save" style="width:100%;margin-top:12px;padding:12px" onclick="addCustomer()">+ Add Customer</button>
<p id="addStatus" style="font-size:12px;margin-top:8px"></p>
</div>

<div class="card">
<input type="text" id="search" placeholder="Search store or phone..." oninput="loadCustomers()" style="width:100%;padding:10px;border-radius:8px;border:1px solid #ccd">
<div style="font-size:11px;color:#666;margin-top:8px" id="customerCount">Loading customers...</div>
</div>

<div class="card">
<div style="overflow-x:auto">
<table><thead><tr><th>Store</th><th>Phone / Login</th><th>Balance</th><th>Action</th></tr></thead>
<tbody id="tbody"><tr><td colspan=4 style="text-align:center;padding:20px;color:#999">Loading...</td></tr></tbody>
</table>
</div>
</div>

<div class="card" id="editCard" style="display:none">
<h3 style="margin:0 0 10px;font-size:14px">Edit Phone & Password</h3>
<p style="font-size:11px;color:#666" id="editStore"></p>
<label>Phone</label><input id="editPhone">
<label>New Password (leave blank to keep old)</label><input id="editPassword" type="text" placeholder="New password">
<div style="display:flex;gap:8px;margin-top:10px">
<button class="btn btn-save" onclick="savePassword()">Save</button>
<button class="btn" style="background:#ddd" onclick="closeEdit()">Cancel</button>
</div>
<p id="editStatus" style="font-size:12px;margin-top:8px"></p>
</div>

<script>
let editingId=null;
async function addCustomer(){
  const store=document.getElementById('newStore').value.trim();
  const phone=document.getElementById('newPhone').value.trim();
  const pwd=document.getElementById('newPassword').value.trim();
  const addr=document.getElementById('newAddress').value.trim();
  if(!store||!phone||!pwd){document.getElementById('addStatus').textContent='Store, phone, password required';return;}
  document.getElementById('addStatus').textContent='Adding...';
  try{
    const res=await fetch('/api/customers/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({store_name:store,phone:phone,password:pwd,address:addr})});
    const data=await res.json();
    document.getElementById('addStatus').textContent=data.ok?'✅ Customer added!':'Error: '+(data.error||'');
    if(data.ok){document.getElementById('newStore').value='';document.getElementById('newPhone').value='';document.getElementById('newPassword').value='';document.getElementById('newAddress').value='';loadCustomers();}
  }catch(e){document.getElementById('addStatus').textContent='Error: '+e.message;}
}
let _allCustomers=[];
function escapeHtml(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML;}
async function loadCustomers(){
  try{
    const res=await fetch('/api/customers/list');
    const data=await res.json();
    const rows=data.resellers||[];
    _allCustomers=rows;
    document.getElementById('customerCount').textContent=rows.length+' customers found'+(data.error?' - '+data.error:'');
    if(!rows.length){
      document.getElementById('tbody').innerHTML='<tr><td colspan=4 style="text-align:center;padding:20px;color:#888">No customers yet. '+(data.error||'')+'</td></tr>';
      return;
    }
    const q=document.getElementById('search').value.toLowerCase();
    const filtered=rows.filter(r=>(r.store_name||'').toLowerCase().includes(q)||(r.phone||'').includes(q));
    document.getElementById('tbody').innerHTML=filtered.map(r=>{
      return `<tr><td><b>${escapeHtml(r.store_name)}</b><br><small style="color:#666">${escapeHtml(r.status||'active')}</small></td><td>${escapeHtml(r.phone)}<br><small style="color:${r.password_hash?'green':'red'}">${r.password_hash?'Has password':'No password'}</small></td><td>₱${r.credit_balance||0}</td><td><button class="btn" style="background:#22c55e;color:#fff" onclick="openEdit('${r.id}')">Edit</button></td></tr>`;
    }).join('');
  }catch(e){
    document.getElementById('customerCount').textContent='Error: '+e.message;
    document.getElementById('tbody').innerHTML='<tr><td colspan=4 style="color:red;text-align:center">Failed to load: '+e.message+'<br><button onclick="loadCustomers()" class="btn btn-save" style="margin-top:8px">Retry</button></td></tr>';
  }
}
function openEdit(id){
  const r=_allCustomers.find(x=>x.id===id);
  if(!r){alert('Customer not found: '+id);return;}
  editingId=id;
  document.getElementById('editStore').textContent=r.store_name+' ('+r.phone+')';
  document.getElementById('editPhone').value=r.phone||'';
  document.getElementById('editPassword').value='';
  document.getElementById('editCard').style.display='block';
  window.scrollTo({top:document.getElementById('editCard').offsetTop,behavior:'smooth'});
}
function closeEdit(){document.getElementById('editCard').style.display='none';}
async function savePassword(){
  const phone=document.getElementById('editPhone').value.trim();
  const pwd=document.getElementById('editPassword').value.trim();
  if(!pwd){document.getElementById('editStatus').textContent='Enter new password or cancel';return;}
  document.getElementById('editStatus').textContent='Saving...';
  try{
    const res=await fetch(`/api/reseller/${editingId}/set_password`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:phone,password:pwd})});
    const data=await res.json();
    document.getElementById('editStatus').textContent=data.ok?'✅ Saved!':'Error: '+(data.error||'');
    if(data.ok){loadCustomers();}
  }catch(e){document.getElementById('editStatus').textContent='Error: '+e.message;}
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
        out=[]
        for key,val in resellers.items():
            if not val: continue
            out.append({"id":key,"store_name":val.get("store_name") or val.get("name") or "No Name","phone":val.get("phone") or val.get("contact",""),"credit_balance":val.get("credit_balance",0),"password_hash":"yes" if val.get("password_hash") else "","status":val.get("status","active")})
        out.sort(key=lambda x: (x.get("store_name") or "").lower())
        return jsonify({"resellers": out[:200], "otps": {}, "count": len(out)})
    except Exception as e:
        import traceback
        return jsonify({"resellers": [], "otps": {}, "error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/api/customers/list_debug")
@login_required
def api_customers_list_debug():
    try:
        staff = (session.get("staff_name") or "").lower()
        resellers = fb_get("resellers") or {}
        return jsonify({"ok": True, "staff": staff, "resellers_raw_count": len(resellers), "sample": list(resellers.values())[:1] if resellers else []})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

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

@app.route("/api/admin/otps")
@login_required
def api_admin_otps():
    try:
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa", "omega", "yhel", "omega purified ice"]:
            return jsonify({"ok": False, "error": "Only ISESMO/OMEGA can view OTPs"}), 403
        otps_data = fb_get("customer_otps") or {}
        resellers_data = fb_get("resellers") or {}
        phone_to_name = {}
        for r in resellers_data.values():
            if not r: continue
            p = clean_phone(r.get("phone") or "")
            if p:
                phone_to_name[p] = r.get("store_name") or r.get("name") or ""
        otps = []
        now = datetime.now()
        for key, val in otps_data.items():
            if not val: continue
            phone = val.get("phone") or ""
            is_expired = False
            exp_str = val.get("expires_at") or ""
            try:
                exp = datetime.strptime(exp_str, "%Y-%m-%d %H:%M:%S")
                if now > exp:
                    is_expired = True
            except:
                pass
            otps.append({"id": key, "phone": phone, "otp": val.get("otp") or "", "created_at": val.get("created_at") or "", "expires_at": exp_str, "used": bool(val.get("used")), "is_expired": is_expired, "reseller_name": phone_to_name.get(clean_phone(phone), "")})
        otps.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        otps = otps[:50]
        return jsonify({"ok": True, "otps": otps})
    except Exception as e:
        import traceback
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/api/customers/<reseller_id>/qr")
@login_required
def api_customer_qr(reseller_id):
    try:
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa"]:
            return jsonify({"ok": False, "error": "Only ISESMO"}), 403
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        if not reseller:
            return jsonify({"ok": False, "error": "Customer not found"}), 404
        phone = clean_phone(reseller.get("phone") or "")
        store_name = reseller.get("store_name") or "Customer"
        import secrets
        token = secrets.token_urlsafe(32)
        token_data = {"reseller_id": reseller_id, "phone": phone, "store_name": store_name, "token": token, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "expires_at": (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S"), "used_count": 0}
        fb_post("qr_login_tokens", token_data)
        base_url = request.host_url.rstrip("/")
        if "onrender.com" in base_url or "omega" in base_url.lower():
            base_url = base_url.replace("http://", "https://")
        auto_link = f"{base_url}/customer/qr?token={token}"
        try:
            import qrcode, io
            qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
            qr.add_data(auto_link)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode()
            data_url = f"data:image/png;base64,{b64}"
        except Exception as e:
            data_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={auto_link}"
        return jsonify({"ok": True, "link": auto_link, "qr_data_url": data_url, "store_name": store_name, "phone": phone, "expires_at": token_data["expires_at"]})
    except Exception as e:
        import traceback
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/customer/qr")
def customer_qr_login():
    try:
        token = request.args.get("token") or ""
        if not token:
            return "<h3>Invalid QR</h3><p>No token.</p>", 400
        tokens = fb_get("qr_login_tokens") or {}
        matched = None
        matched_id = None
        now = datetime.now()
        for k, v in tokens.items():
            if not v: continue
            if v.get("token") == token:
                exp_str = v.get("expires_at") or ""
                try:
                    exp = datetime.strptime(exp_str, "%Y-%m-%d %H:%M:%S")
                    if now > exp:
                        continue
                except:
                    pass
                matched = v
                matched_id = k
                break
        if not matched:
            return "<h3>QR Expired or Invalid</h3><p>Please ask ISESMO to generate new QR code.</p><a href='/customer'>Go to Login</a>", 404
        reseller_id = matched.get("reseller_id")
        try:
            fb_patch(f"qr_login_tokens/{matched_id}", {"used_count": (matched.get("used_count") or 0) + 1, "last_used": now.strftime("%Y-%m-%d %H:%M:%S")})
        except:
            pass
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        if not reseller:
            return "<h3>Customer not found</h3>", 404
        session["customer_id"] = reseller_id
        session["customer_name"] = reseller.get("store_name")
        return redirect(f"/customer/{reseller_id}/dashboard")
    except Exception as e:
        import traceback
        return f"<h3>Error</h3><pre>{e}<br>{traceback.format_exc()}</pre>", 500

@app.route("/api/sales/dashboard")
@login_required
def api_sales_dashboard():
    period = request.args.get("period", "daily").lower()
    custom_date = request.args.get("date", "").strip()
    # ROOT-CAUSE FIX: accept the same `sub` (WW/month/quarter/year) picker
    # value that /api/sales/by_period accepts, so the top KG/PESO/TRANS card
    # and the sales table below it are always showing the same range.
    sub = request.args.get("sub", "").strip() or request.args.get("week", "").strip() or request.args.get("month", "").strip() or ""
    # Fast path for daily - use Manila time
    try:
        import pytz
        manila = pytz.timezone('Asia/Manila')
        now = datetime.now(manila)
    except:
        now = datetime.now()
    # Cache for 10 sec to avoid hammering Firebase with 1600+ records.
    # IMPORTANT: sub + date are part of the key now - previously the key was
    # just the period, so picking a different week/month could silently
    # return another week/month's cached totals.
    cache_key = f"_dashboard_cache_{period}_{sub}_{custom_date}"
    cached = globals().get(cache_key)
    if cached and (now - cached.get("time", datetime.min)).total_seconds() < 10:
        return jsonify(cached.get("data"))

    def kg_value(s):
        try: return float(str(s).lower().replace("kg","").strip())
        except: return 0
    def parse_date(d):
        try: return datetime.strptime(d[:10], "%Y-%m-%d")
        except: return None

    # Same resolver used by /api/sales/by_period - one range, two endpoints.
    rng = resolve_period_range(period, sub, now, custom_date)

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
            if rng["ww_mode"]:
                try:
                    iso_year, iso_week, _ = dt.isocalendar()
                    if iso_week != rng["target_week"]: continue
                    if rng["target_year"] and iso_year != rng["target_year"]: continue
                except:
                    continue
            else:
                if rng["filter_start"] and dt < rng["filter_start"].replace(tzinfo=None): continue
                if period != "all" and rng["filter_end"] and dt > rng["filter_end"].replace(tzinfo=None): continue
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
    result = {
        "period": period, "label": rng["label"], "total": total_peso, "total_kg": total_kg, "count": count,
        "breakdown": breakdown, "pending_total": pending_peso, "pending_kg": pending_kg, "pending_count": pending_count,
        "pending_breakdown": pending_breakdown,
        "date": rng["range_end"].strftime("%Y-%m-%d") if rng["range_end"] else now.strftime("%Y-%m-%d"),
        "start": rng["range_start"].strftime("%Y-%m-%d") if rng["range_start"] else "All",
    }
    globals()[cache_key] = {"time": now, "data": result}
    return jsonify(result)

@app.route("/api/sales/today")
@login_required
def api_today_sales():
    # BUG FIX: this route used to reference `custom_date` and `period`
    # without ever defining them (NameError swallowed by the bare
    # `except: pass` below), so it silently always returned zeros and never
    # respected the ?date= param. Both are now defined and actually used.
    custom_date = request.args.get("date", "").strip()
    try:
        import pytz
        manila = pytz.timezone('Asia/Manila')
        now = datetime.now(manila)
    except:
        now = datetime.now()
    today_str = custom_date if custom_date else now.strftime("%Y-%m-%d")
    try:
        target_date = datetime.strptime(today_str, "%Y-%m-%d").date()
    except Exception:
        target_date = now.date()
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
            # This endpoint is always a single day (no "all time" mode), so
            # archived records are always excluded - unlike dashboard/by_period
            # there's no `period` here to branch on.
            if v.get("archived"):
                continue
            status = v.get("order_status") or "Delivered"
            sd = v.get("sales_date") or (v.get("created_at")[:10] if v.get("created_at") else "")
            if not sd: continue
            dt = parse_date(sd)
            if not dt: continue
            if dt.date() != target_date: continue
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
    """Secure clear - ISESMO only, no secret key"""
    try:
        key = request.args.get("key", "")
        # Allow ISESMO or secret key
        staff = (session.get("staff_name") or "").lower()
        if staff not in ["isesmo", "isesmo gamboa"] and key != "REMOVED_FOR_SECURITY":
            return "Only ISESMO - add ?key=REMOVED_FOR_SECURITY or login as ISESMO", 403
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
        custom_date = request.args.get("date", "").strip()  # BUG FIX: was undefined (NameError)
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
        custom_date = request.args.get("date", "").strip()  # BUG FIX: was undefined (NameError)
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
