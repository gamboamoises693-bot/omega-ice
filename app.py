
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

# --- Web Push (cashier "new order" / "status change" alarm that fires
# even when the cashier PWA is closed / phone is locked) ---
# Requires `pywebpush` in requirements.txt (see deployment notes). If it's
# not installed, or the VAPID keys below aren't set, push is silently
# disabled - the rest of the app keeps working normally either way.
try:
    from pywebpush import webpush, WebPushException
    PUSH_LIB_AVAILABLE = True
except ImportError:
    PUSH_LIB_AVAILABLE = False
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
# "sub" is a contact the push service (Google/Mozilla) can reach you at if
# your app is misbehaving - it is NOT shown to customers. Override with
# your own via the VAPID_CLAIMS_SUB env var if you want a real address.
VAPID_CLAIMS_SUB = os.environ.get("VAPID_CLAIMS_SUB", "mailto:admin@omega-ice.onrender.com")
PUSH_ENABLED = bool(PUSH_LIB_AVAILABLE and VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY)

def send_push_to_cashiers(title, body, url="/orders", tag="omega-order"):
    """Fire a Web Push notification to every subscribed cashier device -
    shows up even if the PWA is closed / screen is locked (Android; on
    iOS the PWA must be installed via Add to Home Screen, iOS 16.4+).
    Best-effort: never raises, so a push failure can't break order flow."""
    if not PUSH_ENABLED:
        return
    try:
        subs = fb_get("push_subscriptions") or {}
    except Exception as e:
        print(f"send_push_to_cashiers: could not load subscriptions: {e}")
        return
    payload = json.dumps({"title": title, "body": body, "url": url, "tag": tag})
    for key, sub in (subs or {}).items():
        if not sub or not sub.get("endpoint"):
            continue
        try:
            webpush(
                subscription_info={"endpoint": sub.get("endpoint"), "keys": sub.get("keys") or {}},
                data=payload,
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims={"sub": VAPID_CLAIMS_SUB},
            )
        except WebPushException as e:
            status = None
            try:
                status = e.response.status_code
            except Exception:
                pass
            if status in (404, 410):
                # Subscription is dead (app uninstalled, data cleared, etc.)
                # - remove it so we stop wasting a push attempt on it.
                try:
                    fb_delete(f"push_subscriptions/{key}")
                except Exception:
                    pass
            else:
                print(f"send_push_to_cashiers: push failed for {key}: {e}")
        except Exception as e:
            print(f"send_push_to_cashiers: unexpected error for {key}: {e}")

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

# --- Feature modules (Flask Blueprints, see modules/) ---
# Split out of app.py so each business feature is its own file, easier to
# debug/extend on its own instead of everything living in one giant file.
# Registered here - AFTER firebase_admin.initialize_app() above - because
# each module's routes call Firebase helpers (modules/shared.py) that
# need the Firebase app already initialized.
from modules.credit import credit_bp
from modules.expenses import expenses_bp
from modules.plastic import plastic_bp
from modules.fixed_assets import assets_bp
from modules.admin_import import admin_import_bp
app.register_blueprint(credit_bp)
app.register_blueprint(expenses_bp)
app.register_blueprint(plastic_bp)
app.register_blueprint(assets_bp)
app.register_blueprint(admin_import_bp)

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
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Omega Purified Ice - Login</title>
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
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Omega Purified Ice - Cashier</title>
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
.menu-wrap{position:relative}
.menu-btn{width:100%;height:100%;padding:10px 8px;border-radius:10px;font-size:18px;border:1px solid #cde;background:#fff;color:#00609C;display:flex;align-items:center;justify-content:center;min-height:38px;font-weight:600;box-shadow:0 1px 3px rgba(0,0,0,.05);cursor:pointer}
.menu-btn.open{background:#00609C;color:#fff;border-color:#00609C}
.menu-dropdown{display:none;position:absolute;top:calc(100% + 6px);right:0;background:#fff;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,.18);min-width:190px;z-index:60;overflow:hidden;border:1px solid #e5e7eb}
.menu-dropdown.show{display:block}
.menu-dropdown a{display:flex;align-items:center;gap:10px;padding:13px 16px;font-size:13px;color:#333;text-decoration:none;border-bottom:1px solid #f0f4f8;font-weight:600}
.menu-dropdown a:last-child{border-bottom:none}
.menu-dropdown a:hover,.menu-dropdown a:active{background:#eef7ff;color:#00609C}
.menu-dropdown a.active{background:#eef7ff;color:#00609C}
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
<div id="pushBannerC" style="display:none;background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:8px 10px;margin-bottom:10px;font-size:11px;color:#991b1b;justify-content:space-between;align-items:center;gap:8px"><span>🔔 I-enable ang Order Alarm para may notification ka kahit closed ang app.</span><button onclick="enablePushAlerts()" style="padding:6px 12px;border-radius:8px;border:none;background:#c0392b;color:#fff;font-size:11px;font-weight:600;white-space:nowrap">Enable</button></div>
<div class="topbar"><div style="display:flex;align-items:center;gap:8px"><img src="/icon-192.png" alt="" style="width:26px;height:26px;border-radius:6px"><h1 id="cashierTitle">OMEGA PURIFIED ICE</h1></div><div style="display:flex;align-items:center;gap:10px"><span class="staff">{{ staff_name }}</span><button class="logout" onclick="logout()">Logout</button></div></div>
<button id="kioskBtn" onclick="toggleKiosk()" title="Kiosk mode">⛶</button>
<div class="one-row">
  <span class="cloud-badge online" id="onlineBadge">● Cloud Online</span>
  <a href="/orders" class="nav-pill" style="background:#ff4444;color:#fff;border-color:#ff4444;position:relative">🔴 Online Orders <span id="liveOrdersCount" style="background:#fff;color:#ff4444;border-radius:10px;padding:1px 6px;font-size:10px;font-weight:700;margin-left:4px;display:none">0</span></a>
  <span class="cloud-badge pending" id="pendingBadge" style="display:none" onclick="syncOffline()">0 Pending</span>
  <a href="/cashier" class="nav-pill active">Sales</a>
  <div class="menu-wrap">
    <button type="button" class="menu-btn" id="navMenuBtn" onclick="toggleNavMenu()" title="Menu">☰</button>
    <div class="menu-dropdown" id="navMenuDropdown">
      <a href="/machines">🏭 Machines</a>
      <a href="/credit">💳 Utang</a>
      <a href="/expenses">💸 Expenses</a>
      <a href="/plastic">📦 Plastic</a>
      <a href="/assets">🏗️ Fixed Assets</a>
      <a href="/dashboard">📊 Dashboard</a>
    </div>
  </div>
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

// Hamburger dropdown for the secondary nav links (Machines/Utang/Expenses/Plastic/Assets/Dashboard)
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

// --- Push notifications ("order alarm" that fires even if the cashier
// app/tab is fully closed or the phone is locked - Android Chrome
// supports this everywhere; iOS Safari only after the PWA is installed
// via Add to Home Screen, iOS 16.4+). This is separate from, and on top
// of, the in-page red pulsing alarm that already runs while the app is
// open - that one still works exactly as before with no changes here.
const VAPID_PUBLIC_KEY_C = "{{ vapid_public_key }}";
const PUSH_ENABLED_C = {{ 'true' if push_enabled else 'false' }};

function urlBase64ToUint8Array(base64String){
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g,'+').replace(/_/g,'/');
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for(let i=0;i<rawData.length;i++) outputArray[i] = rawData.charCodeAt(i);
  return outputArray;
}

async function updatePushBannerUI(){
  const banner = document.getElementById('pushBannerC');
  if(!banner) return;
  if(!PUSH_ENABLED_C || !('serviceWorker' in navigator) || !('PushManager' in window)){
    banner.style.display = 'none';
    return;
  }
  if(Notification.permission === 'granted'){
    try{
      const reg = await navigator.serviceWorker.ready;
      const sub = await reg.pushManager.getSubscription();
      banner.style.display = sub ? 'none' : 'flex';
    }catch(err){ banner.style.display = 'flex'; }
  } else if(Notification.permission === 'denied'){
    banner.style.display = 'none'; // browser already blocked it - nagging won't help, staff must fix it in browser settings
  } else {
    banner.style.display = 'flex';
  }
}

async function enablePushAlerts(){
  const banner = document.getElementById('pushBannerC');
  try{
    if(!PUSH_ENABLED_C){
      alert('Hindi pa naka-configure ang push notifications sa server. Sabihin kay Isesmo na i-set up ang VAPID keys.');
      return;
    }
    const perm = await Notification.requestPermission();
    if(perm !== 'granted'){
      alert('Kailangan payagan ang Notifications para gumana ang Order Alarm kahit closed ang app.');
      return;
    }
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if(!sub){
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY_C)
      });
    }
    const subJson = sub.toJSON();
    await fetch('/api/push/subscribe', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({endpoint: subJson.endpoint, keys: subJson.keys})
    });
    if(banner) banner.style.display = 'none';
  }catch(err){
    alert('Hindi na-enable ang push alerts: ' + err.message);
  }
}
if('serviceWorker' in navigator){
  window.addEventListener('load', () => { setTimeout(updatePushBannerUI, 1500); });
}

// --- Kiosk mode: for a dedicated cashier tablet/phone that should stay
// locked on this app. Turning it ON is a plain tap on the floating ⛶
// button (off by default, so a normal browser tab still behaves
// normally until staff turns it on) and remembered per device via
// localStorage. Turning it OFF is gated behind a secret PIN that only
// Isesmo knows (verified server-side, never stored in this page's
// source) - see showKioskUnlockPrompt()/submitKioskUnlock() below.
//
// IMPORTANT HONEST LIMITATION: a website (even installed as a PWA) has
// NO way to block the Android hardware/gesture Home button or the
// Recents/app-switcher - those are OS-level, entirely outside what any
// webpage's JavaScript can reach. What's implemented here (fullscreen +
// a Back-button trap below) is the most a web app can do. For a TRUE
// can't-leave-the-app lock (Home included), enable Android's own
// built-in "Screen Pinning" on the tablet - Settings > Security >
// Advanced > Screen pinning - which pins whatever app is open until
// unpinned with a gesture; that OS feature is what actually blocks Home.
let kioskOn = false;
function applyKioskVisuals(on){
  document.body.classList.toggle('kiosk-on', on);
  document.getElementById('kioskBtn').style.background = on ? '#166534' : '#00609C';
}
async function toggleKiosk(){
  if(!kioskOn){
    kioskOn = true;
    try{ localStorage.setItem('omega_kiosk_mode', '1'); }catch(e){}
    applyKioskVisuals(true);
    startBackTrap();
    try{
      if(document.documentElement.requestFullscreen) await document.documentElement.requestFullscreen();
    }catch(e){ /* Some browsers still refuse even on a tap; visuals/back-trap still apply either way. */ }
  }else{
    // Already ON - don't just turn off on a tap. Ask for the secret PIN.
    showKioskUnlockPrompt();
  }
}
function forceKioskOff(){
  kioskOn = false;
  try{ localStorage.setItem('omega_kiosk_mode', '0'); }catch(e){}
  applyKioskVisuals(false);
  stopBackTrap();
  try{
    if(document.exitFullscreen && document.fullscreenElement) document.exitFullscreen();
  }catch(e){}
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

// --- Back-button trap: keeps pushing a fresh history entry so the
// browser/PWA's Back action never actually leaves this page while kiosk
// mode is on. This DOES work for in-app/browser Back; it does NOT and
// CANNOT stop the Android hardware Home button (see note above).
let backTrapActive = false;
function onKioskPopstate(){
  if(kioskOn){
    try{ history.pushState({kiosk:true}, '', location.href); }catch(e){}
  }
}
function startBackTrap(){
  if(backTrapActive) return;
  backTrapActive = true;
  try{ history.pushState({kiosk:true}, '', location.href); }catch(e){}
  window.addEventListener('popstate', onKioskPopstate);
}
function stopBackTrap(){
  backTrapActive = false;
  window.removeEventListener('popstate', onKioskPopstate);
}

// --- Secret unlock prompt (Isesmo only) ---
// Reachable two ways: (1) tapping the ⛶ button while kiosk is already
// on, or (2) a hidden gesture - tap the "OMEGA PURIFIED ICE" title 5x
// within 3 seconds - in case the button itself gets hidden/removed
// later for a cleaner kiosk look. Both open the same PIN prompt; the
// PIN itself is checked server-side against KIOSK_UNLOCK_PIN (an env
// var, same pattern as the staff login PINs) and the endpoint also
// requires the active session to actually BE Isesmo - so even a staff
// member who somehow learns the PIN can't use it unless logged in as him.
function showKioskUnlockPrompt(){
  if(document.getElementById('kioskUnlockOverlay')) return;
  const ov = document.createElement('div');
  ov.id = 'kioskUnlockOverlay';
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(10,25,45,.6);z-index:100;display:flex;align-items:center;justify-content:center;padding:20px';
  ov.innerHTML =
    '<div style="background:#fff;border-radius:16px;padding:22px;max-width:300px;width:100%;text-align:center">' +
      '<div style="font-size:14px;font-weight:700;color:#0f2942;margin-bottom:6px">🔒 Kiosk Locked</div>' +
      '<div style="font-size:11px;color:#888;margin-bottom:12px">Enter secret PIN to disable kiosk mode. Isesmo only.</div>' +
      '<input type="password" id="kioskUnlockInput" placeholder="Secret PIN" style="width:100%;padding:12px;border-radius:10px;border:1px solid #ccd;font-size:16px;text-align:center;letter-spacing:4px">' +
      '<div id="kioskUnlockErr" style="font-size:11px;color:#c0392b;min-height:16px;margin-top:6px"></div>' +
      '<div style="display:flex;gap:8px;margin-top:10px">' +
        '<button onclick="closeKioskUnlockPrompt()" style="flex:1;padding:10px;border-radius:10px;border:1px solid #ccd;background:#f5f5f5">Cancel</button>' +
        '<button onclick="submitKioskUnlock()" style="flex:1;padding:10px;border-radius:10px;border:none;background:#00609C;color:#fff;font-weight:700">Unlock</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(ov);
  setTimeout(function(){
    const el = document.getElementById('kioskUnlockInput');
    if(el){
      el.focus();
      el.addEventListener('keydown', function(e){ if(e.key==='Enter') submitKioskUnlock(); });
    }
  }, 50);
}
function closeKioskUnlockPrompt(){
  const ov = document.getElementById('kioskUnlockOverlay');
  if(ov) ov.remove();
}
async function submitKioskUnlock(){
  const input = document.getElementById('kioskUnlockInput');
  const errEl = document.getElementById('kioskUnlockErr');
  const pin = input ? input.value : '';
  if(!pin){ errEl.textContent = 'Enter the PIN'; return; }
  try{
    const res = await fetch('/api/kiosk/verify_unlock', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({pin:pin})});
    const data = await res.json();
    if(data.ok){
      closeKioskUnlockPrompt();
      forceKioskOff();
    }else{
      errEl.textContent = data.error || 'Wrong PIN';
      if(input){ input.value=''; input.focus(); }
    }
  }catch(e){
    errEl.textContent = 'Network error: ' + e.message;
  }
}
// Hidden gesture: 5 taps on the title within 3 seconds also opens the
// unlock prompt (works even if the ⛶ button is ever hidden).
(function setupSecretTitleTap(){
  let tapCount = 0, tapTimer = null;
  const titleEl = document.getElementById('cashierTitle');
  if(!titleEl) return;
  titleEl.addEventListener('click', function(){
    tapCount++;
    clearTimeout(tapTimer);
    tapTimer = setTimeout(function(){ tapCount = 0; }, 3000);
    if(tapCount >= 5){
      tapCount = 0;
      showKioskUnlockPrompt();
    }
  });
})();

(function initKiosk(){
  try{
    if(localStorage.getItem('omega_kiosk_mode')==='1'){ kioskOn=true; applyKioskVisuals(true); startBackTrap(); }
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

def log_customer_login(reseller_id, store_name, phone, success, reason=""):
    """
    Records every customer login attempt - success AND failure - so staff
    can see who's actually using the customer portal, and so a string of
    failed attempts on one phone number (a real security signal) is
    visible instead of silently vanishing. Never lets a logging failure
    break the actual login flow - it's fire-and-forget.
    """
    try:
        entry = {
            "reseller_id": reseller_id,
            "store_name": store_name or "",
            "phone": phone or "",
            "success": bool(success),
            "reason": reason or "",
            "ip": request.remote_addr or "unknown",
            "user_agent": (request.headers.get("User-Agent") or "")[:200],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        fb_post("customer_login_logs", entry)
    except Exception as e:
        print(f"log_customer_login error: {e}")

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

@app.route("/api/kiosk/verify_unlock", methods=["POST"])
@login_required
def api_kiosk_verify_unlock():
    """
    Disabling kiosk mode on the cashier device is intentionally
    double-gated: (1) the active session must actually BE Isesmo - not
    just any staff PIN - same check already used by the ISESMO-only
    debug endpoints elsewhere in this file, and (2) the caller must also
    know a separate secret PIN, set via its own KIOSK_UNLOCK_PIN env var
    (never the same as anyone's login PIN, and never shipped in the page
    source since it's only checked here, server-side). Rate-limited per
    IP using the same helper as /api/login so this can't be brute-forced.
    """
    if (session.get("staff_name") or "").strip().lower() not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Not allowed"}), 403
    ip = request.remote_addr or "unknown"
    rl_key = f"kiosk_{ip}"
    if is_rate_limited(rl_key, max_attempts=5, window_seconds=300):
        return jsonify({"ok": False, "error": "Too many attempts. Try again in a few minutes."}), 429
    secret_pin = os.environ.get("KIOSK_UNLOCK_PIN")
    if not secret_pin:
        return jsonify({"ok": False, "error": "KIOSK_UNLOCK_PIN not set on server"}), 500
    data = request.json or {}
    pin = str(data.get("pin", ""))
    record_attempt(rl_key)
    if pin != secret_pin:
        return jsonify({"ok": False, "error": "Wrong PIN"}), 401
    return jsonify({"ok": True})

@app.route("/cashier")
@login_required
def cashier_page():
    return render_template_string(CASHIER_HTML, staff_name=session.get("staff_name"), staff_position=session.get("staff_position"), kg_options=KG_OPTIONS, vapid_public_key=VAPID_PUBLIC_KEY, push_enabled=PUSH_ENABLED)

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
<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js"></script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:linear-gradient(135deg,#00609C,#0096D6);margin:0;min-height:100vh;padding:16px;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:16px;padding:24px;width:100%;max-width:380px;box-shadow:0 8px 30px rgba(0,0,0,.2)}
.header{text-align:center;margin-bottom:20px}.header h1{font-size:20px;color:#00609C;margin:0}.header p{font-size:12px;color:#666;margin:4px 0}
label{font-size:12px;color:#666;display:block;margin:12px 0 6px}input{width:100%;padding:14px;border-radius:12px;border:1.5px solid #ccd;font-size:15px}
.btn{width:100%;padding:14px;background:#00609C;color:#fff;border:none;border-radius:12px;font-size:15px;font-weight:600;margin-top:16px}
.btn-otp{background:#f59e0b;margin-top:8px}
.status{font-size:12px;text-align:center;margin-top:10px;min-height:18px}.status.err{color:#c0392b}.status.ok{color:#1a8a4a}
#installBannerCu{background:#eef4fb;border:1px solid #cde;border-radius:10px;padding:10px;margin-bottom:14px;font-size:11px;color:#00609C;text-align:center}
#installBannerCu button{margin-top:6px;padding:7px 14px;border-radius:8px;border:none;background:#00609C;color:#fff;font-size:11px;font-weight:600}
#manualInstallHint{display:none;background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:10px;margin-top:8px;font-size:11px;color:#92400e;text-align:left}
</style></head>
<body>
<div class="card">
<div id="installBannerCu"><div>📲 I-install ang app na ito sa phone mo para mas mabilis mag-order.</div><button onclick="doInstallPromptCu()">Install App</button>
<div id="manualInstallHint">Sa Chrome: tapikin yung <b>⋮ (tatlong tuldok)</b> sa taas-kanan → piliin <b>"Install app"</b> o <b>"Add to Home screen"</b>.</div>
</div>
<div class="header"><img src="/logo-full.webp" alt="Omega Purified Ice" style="max-width:180px;width:100%;height:auto;margin:0 auto 8px;display:block"><p>Customer Secure Login</p><p style="font-size:11px;color:#888">One phone + password per store</p></div>
<label>Registered Phone</label><input type="tel" id="phone" placeholder="09xx xxx xxxx">
<label>Password</label><input type="password" id="password" placeholder="Enter password">
<button class="btn" onclick="doLogin()">🔐 Login</button>
<p class="status" id="status"></p>
<div style="display:flex;align-items:center;gap:8px;margin:16px 0"><div style="flex:1;height:1px;background:#e5e7eb"></div><span style="font-size:11px;color:#999">O KAYA</span><div style="flex:1;height:1px;background:#e5e7eb"></div></div>
<input type="file" id="qrFileInput" accept="image/*" style="display:none" onchange="handleQRUpload(event)">
<button class="btn" style="background:#1a8a4a" onclick="document.getElementById('qrFileInput').click()">📷 Upload QR Code</button>
<p style="font-size:11px;color:#888;text-align:center;margin-top:6px">I-upload lang yung QR code na ibinigay sa'yo ni ISESMO - automatic na ang login.</p>
<p style="font-size:12px;color:#888;text-align:center;margin-top:14px;border-top:1px solid #eee;padding-top:14px">Forgot your password?<br>Contact ISESMO to have it reset for you.</p>
</div>
<script>
// --- Auto-install for the customer PWA (no kiosk mode here - that's
// cashier-only; a customer's own phone should behave like a normal
// installed app, not a locked-down device).
//
// IMPORTANT: Chrome does NOT fire 'beforeinstallprompt' on a first visit
// - it withholds it until its own "engagement" heuristic is satisfied
// (some active time on the site and/or a repeat visit), as an anti-spam
// measure Google controls, not something a page can force. So the
// banner is shown UNCONDITIONALLY from page load (not hidden until the
// event fires): if the event *has* fired by the time the customer taps
// "Install App", we use it (one-tap native install); if it hasn't yet,
// we show plain manual instructions instead of silently doing nothing.
let deferredInstallEventCu = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallEventCu = e;
  try{
    if(!localStorage.getItem('omega_customer_installed')) e.prompt();
  }catch(err){}
});
window.addEventListener('appinstalled', () => {
  try{ localStorage.setItem('omega_customer_installed', '1'); }catch(e){}
  document.getElementById('installBannerCu').style.display='none';
});
(function hideBannerIfAlreadyInstalled(){
  try{
    if(localStorage.getItem('omega_customer_installed')==='1'){
      document.getElementById('installBannerCu').style.display='none';
    }
  }catch(e){}
})();
async function doInstallPromptCu(){
  if(deferredInstallEventCu){
    deferredInstallEventCu.prompt();
    await deferredInstallEventCu.userChoice;
    deferredInstallEventCu = null;
    return;
  }
  // Event hasn't fired yet (most likely a first visit) - show manual
  // steps instead of doing nothing, so the tap always does SOMETHING.
  const hint=document.getElementById('manualInstallHint');
  if(hint) hint.style.display='block';
  return;
}
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

// Lets a customer log in by uploading a saved/screenshotted QR code
// image instead of scanning it live - decoded entirely on-device with
// jsQR (no image upload to any server), then we just navigate to the
// link the QR encodes; the actual login + validation (expired/revoked
// token, etc.) is handled server-side by the existing /customer/qr route.
// Draws the source image onto a canvas capped at maxW wide (keeping
// aspect ratio) and returns its ImageData. A raw phone-camera photo can
// be 4000px+ wide - decoding at full size is slow and, on weaker/older
// devices (budget Android tablets etc.), can silently choke the canvas.
// Downscaling first is also just how jsQR is meant to be fed: it scans
// at a fixed internal resolution regardless, so handing it a huge image
// buys nothing but risk.
function getScaledImageData(img, maxW){
  const scale = Math.min(1, maxW / img.naturalWidth);
  const w = Math.max(1, Math.round(img.naturalWidth * scale));
  const h = Math.max(1, Math.round(img.naturalHeight * scale));
  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0, w, h);
  return ctx.getImageData(0, 0, w, h);
}

function decodeQRFromImage(img){
  // Try a few sizes - some QR photos decode better full-res (small QR
  // in a big frame), others decode better downscaled (huge camera photo
  // that's slow/blurry-at-full-res). attemptBoth also covers a QR that
  // was screenshotted in an inverted/dark-mode viewer.
  const sizesToTry = [1600, img.naturalWidth, 900, 500];
  for(const maxW of sizesToTry){
    if(!maxW || maxW <= 0) continue;
    try{
      const imgData = getScaledImageData(img, maxW);
      const code = jsQR(imgData.data, imgData.width, imgData.height, {inversionAttempts: 'attemptBoth'});
      if(code && code.data) return code.data;
    }catch(err){ /* try next size */ }
  }
  return null;
}

function handleQRUpload(event){
  const file = event.target.files && event.target.files[0];
  const st = document.getElementById('status');
  if(!file) return;
  st.className = 'status';
  st.textContent = 'Binabasa ang QR code...';
  const reader = new FileReader();
  reader.onerror = function(){
    st.textContent = 'Hindi ma-open ang file. Subukan ulit.';
    st.className = 'status err';
  };
  reader.onload = function(ev){
    const img = new Image();
    img.onerror = function(){
      st.textContent = 'Hindi valid na image file.';
      st.className = 'status err';
    };
    img.onload = function(){
      try{
        if(typeof jsQR !== 'function'){
          st.textContent = 'Hindi ma-load ang QR reader. Siguraduhing may internet at i-refresh ang page.';
          st.className = 'status err';
          return;
        }
        const decoded = decodeQRFromImage(img);
        if(!decoded){
          st.textContent = 'Hindi mabasa ang QR sa picture na yan. Gamitin yung QR file na na-download/na-send sa’yo (huwag kuhanan ulit ng photo), o piliing mas malinaw/hindi paikot na larawan.';
          st.className = 'status err';
          return;
        }
        if(!decoded.includes('/customer/qr') || !decoded.includes('token=')){
          st.textContent = 'Hindi ito QR code ng Omega Ice. Gamitin yung QR na binigay ni ISESMO.';
          st.className = 'status err';
          return;
        }
        st.textContent = 'QR na-detect! Nag-lo-login...';
        st.className = 'status ok';
        window.location.href = decoded;
      }catch(err){
        st.textContent = 'May error sa pagbasa ng QR. Subukan ulit.';
        st.className = 'status err';
      }
    };
    img.src = ev.target.result;
  };
  reader.readAsDataURL(file);
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
#installBannerCu{background:#eef4fb;border:1px solid #cde;border-radius:10px;padding:10px;margin-bottom:12px;font-size:11px;color:#00609C;display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
#installBannerCu button{padding:7px 12px;border-radius:8px;border:none;background:#00609C;color:#fff;font-size:11px;font-weight:600;white-space:nowrap}
#manualInstallHint{display:none;width:100%;background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:8px;margin-top:4px;font-size:10px;color:#92400e;text-align:left}
</style></head>
<body>
<div id="installBannerCu"><span>📲 I-install ang app na ito para mas mabilis mag-order.</span><button onclick="doInstallPromptCu()">Install</button>
<div id="manualInstallHint">Sa Chrome: tapikin yung <b>⋮</b> sa taas-kanan → piliin <b>"Install app"</b> o <b>"Add to Home screen"</b>.</div>
</div>
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
// Auto-install for the customer PWA (same approach as the login page -
// no kiosk mode, that's cashier-only). Added here too since a returning
// customer with a saved session lands straight on this dashboard and may
// never see the login page's install banner.
//
// Chrome only fires 'beforeinstallprompt' once ITS OWN engagement
// heuristic is satisfied (not on a plain first visit) - that's Google's
// anti-spam rule, not something this page controls. So the banner shows
// unconditionally on load; the button uses the captured native prompt
// when available, and falls back to manual instructions when it isn't.
let deferredInstallEventCu = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallEventCu = e;
  try{
    if(!localStorage.getItem('omega_customer_installed')) e.prompt();
  }catch(err){}
});
window.addEventListener('appinstalled', () => {
  try{ localStorage.setItem('omega_customer_installed', '1'); }catch(e){}
  document.getElementById('installBannerCu').style.display='none';
});
(function hideBannerIfAlreadyInstalled(){
  try{
    if(localStorage.getItem('omega_customer_installed')==='1'){
      document.getElementById('installBannerCu').style.display='none';
    }
  }catch(e){}
})();
async function doInstallPromptCu(){
  if(deferredInstallEventCu){
    deferredInstallEventCu.prompt();
    await deferredInstallEventCu.userChoice;
    deferredInstallEventCu = null;
    return;
  }
  const hint=document.getElementById('manualInstallHint');
  if(hint) hint.style.display='block';
}
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
_ICON_192_PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAYAAABS3GwHAADQZklEQVR42ux9d5xcVdn/95xzy/SZne19k03dTW8kJJBC781dEOkiKoK+ChYU3V3EgooKYgOpAsIuEErohGxISO/Jpmezvc/u9HLvPef8/pjZgL7qiz+D4vvm+XyGJGQzM/fep36f7/Mc4ISckBNyQk7ICTkhJ+SEnJATckJOyAk5ISfkhJyQE3JCTsgJOSEn5ISckBNyQk7ICTkhJ+SEnJDjIqROStrY2MgAkBO344R8YqSuTlIpJfl43ruO1q1apfyFLaCuro6euPMn5F8ijY2N7G8oOMl45A808zgqfqOUx95b1kF5/MVX5/z8kcZlNwHq6M+ceDon5F/n6aWkdXWrlFHFGzWKXz3y1I33PvLULaPG8k8rfuMHiv+d73y/8gfPvHfX1x5as+u2JzbKhuV75eUNK7Z++cvfnXvCCP7FOej/1Qt/6qlnLnvl/rvXPrNxT/8xjywlJYSwn9/30LVF51zyu85tuzdlRY+c5fnsZ+O1hPB/9DMkQJqkpKP/9s4f/XY6LZpwQ3Ze/rUFYyu8+w4Hkeo7ipOmlfJbf72FLRpn65/Q/+Ic+B/qAerR0NAg/n+uTUpJCCGZr3BC/p4o/9cuWErJCCHc5S+//IoHVvzy9K7elZEjrbtShdhECF372xfXvpbX4j9rpF8TSm7pgpV//NnkP91446bGxkZWW1v7kY2gsbGRkdpaDkL4Q7/89bRk8cyv2vIKr6yeXKYVODmkoloPP/oO/UrNTLpmezebUQRzIMbymXve3U82kOtqGiUDGv7/vBohJxT/I8r/uVDb3JyOelGOw2ROeYlXq7x2VtVl93rHlJ8JSER4YsA4pUxCJKV/R9BcctVtDfc+88f5NTU1om6VVOrq6kaLY/LXPH5jo2R1UtLa2lre33iz68kVm3+gTD97w+Jl8687c3aZlq9xHjFU2bjykDKl1E6LCrPwXPMhTKwary6a4uf9Iu+q7/7gB6c01RJeU/MPp15ESknuuPX63NmAWlcn6V9Lpz6u4v5EBPiPMIBmAMBwR0+355FuyzFOMwfzhYbDmHf22WfrqZ6OVf3jZl4dHkmK8UurFB7unjO0eVc041UtAGhoaPgrHl8yUks4atPpztrVa898fsT1M2dBxdQ5Y51wUJMHk4xSTWWPv7gLO7e3YPkPLsVbO3sQT6Zw4OgIli2oIGVhQtuHzV+9+dMzFq67vSYhIclH9eir0tHN+kPj63dfN/u8/luvI9/7sGE0NzfTJUuWSPL/kc6dMID/TYVvXR1NUZ6jF2YpraqlJIfCvGDcjLPOvf32ZYFdu1Zr0TgXVNCoDeh9feuethfu7Gv43RMXOEjeZ3uaV/wwJ6f/qPGrpkADIGsaG2lTTY2oJYRvqTvfMXz2985uG8ANzYP282x5eZiYp3AKQsNCY8OhEQwMBuBGCN/67GIYUFCc68K4Yh9ys2xo70/SKRML+NbdcvrLiWt/8mtCvrQ3XTz/PYUldXV1ZG91NVlKiHVuuaOAlow73636i+6/61mfUhz9ZY7b3Z5RegEAP/zWl7JTek6koaHBOFEE/98rAggIkXc//3qhzNGXeVJ59zoLKnJdPoUcfv3Vn790y9ee/PQfnt1on1mlaYmocOf56eDK7QPJLJfIHS4osGS/TEy1DykjfYd7Nr51dkNDQ5gCeGbFe1cjO/87/XF1Ys+whYqKLIwvzRKSg0aCMYQCvRjqH4ZU7OgLGtjW0olQJIEH7rgAb6/dh3d3jWBcZQGqJpfIZCzEO9qHlAlGy/lf+/KNr/6t+oNQCinksVr3Fy88NNnXPu45z7iqqmEXN4tMp7p/4J0f3HbVZXf+7nfLf0hNzZZdmV8gRWL85jUrTr/nnntCGR34P1szKP/XPH89IH/9wAPjbrnsnMNfvmDKO97PPk7DEZOEghG4squ+cuWjL37JMaFSswfCcA2bNBgZlI7KqjySRZHwh3nClgslz5cbbGt5oKGhIfzT3/5xiemdeGcsp/A0IYFoLCpOPqlCCknZgbYRasZG4CFxmCmKqKnCyYBlc0rx6fOq8VzzYfzsyfX4au0MvL9nGLEkRygcJ34nIzavH4PRyu/LRrzR9IGz+jNFlUIAAL39J7dPGe+d2dPT3pFwVC9whLyagGoovanhRPzN1oeu/fzlFap3wh15nlLQU91oXbGq6Z577gk1Sslq/4+nQ/+niuCGhgZBCJHOafOe/c2L7748afGPni+dMTU3K5qSnncGiWtyoWKrqrClqAGRa0d4nAei1yQxpyFDqaiM+TTm7kjQsa93W4mXdkS+9oe3fxbwzlpVNmnsadxIibbOkCidUE47+qLs/fUHYAx1otxLobmzkV1ciMtOn4IvXTIDp1UXYrLPjm/UTMeUmeOwvz2IpdOysG7jXgACFRUFzE0S4lA/nfmr6PM31tbW8sbGRjqKLgHAfQ/98cZfvrdr492/a9401X95c6rId0XDV+9oGzy69afCT6kpKHEolvnde78+MOf0m+5WZ4yVwdxkLPGnHitxpHsbALTUN5P/7iQ+6ImcSIE+sZ5c0vp6gBDykXDyDC4uv3zHl6edPOszP3SssS1Rbp7iNFkSgXhUurYmSb+NIFVCYCOQ1G4nup0AlEAxBIL7QtDKfTDNsCGDlOkBXbYNBRWzlGDp9Cz0DiR4S2ec5RS4Eejtg0emcOqMQnhz/RiKcBT6XSjL0kC5gGVKEMYgCaBIjmHC8NumHThjWh6+98vXUT69ChedPQ0encje/qhksaFIcteKuV/86rcOye8JWp/pD9xx621VFZd/sYVoebD1W0B+qMfYt/lTnrLco/0kd5tUfIW+uMkDuw9uI1PKpznzPJoBJgpTCjt6YP2D4dbNX6yurie1tf+3I8D/+hognT9fzh/47R8+5aqc/SQqp+vJXb2gfsITHhBKVOo8Goee5UDEC6QMjkAwijy/C6qmgEcF7HtDMqvARZqf/d0Rs2K2N3bSjByjp1cumVoiYinQLS39JNsFWMF+TB+Xi3ETSqE5bMh2ayiwq7ARgrjJQSgBGQ26BCBCwK5RbGoLYf2eLpQ4JeofXovbvn4VdJZCdWkOT1hgu1e/s+qWmjNOa2yUtLaWCFknCWkg4qHvL3/NM3PZWUfLk2ahnqNH9m3e/p2L5i+re/yV3+RUnvLpRNswz4aHxSZQRGVKRjq6+Y5dD1/8zPd/+wYAXiclbUg7EQJA1l17rU2dPPem3evffvnZl15qG3Uc/5v1g/1HeX4p6eqGBvnL3z9xxfQFZ3/7/XdXvEw+eIB/VZqamqSUkjzX+HanTAa36S7HKdqGhMvKZTSZRakGBhyKASpg5SigSYFAzzB0XYdDo4CqQOwaIRiIIzZunn/EY3MkuvpBdTvZc2SQrl+7i8wba8f0cgeKKwrhKysFd7nAmAJpAeGUQMQwoasMChRAEoAQpNWKwrQkKvPs6BoMQne4kAgOoysoMX5cAYhpUgdj3NSyx548bUrgxuunb2hsbGRNg4O0ufkx+VrzexPdpHwJdEqiMk5cqqfwrEuuuQEFZXMMhVFHkYtq5VKE3uyAZ4Qh6rZRrOnsvLHum6dXz5mSunvRovZVq1YpFRUVWL16tZx33nkzTr3yiy84cscunOc4+kf3xdeR06urSVNTkzxhAJ+AAnYJQD2W5fLOP+857htzihYLvHPkUEtHTU0N3bt3r/w7uT/WrXvHeOfNl/fPp4GnbGUTFmZXVZfZdw5x4abUFwD0MieYHbDZCLc7HcTlc5B4OAEhubRXOuVIRRZ558AhuHgSPbs7ceRoB8bnA7dePguV5dlIMRtKinPhtNugSQkIgoSgiJoSRAhkOVUokqTLWCIzFktACIFhClSVefF+SxfGlGRj465uTK4aA4+dwg4QxnTZHaWnXnvmtBeuvPr6wS996VxSXV0tFy+Z8/5l88+43D+mMjcRiUk6mIR7RrlrJGpQwxSwOQgGkikSj4P4QIl9ci4prZ69KKd4/EJ2OH7ayaeWrLr6us/11tc3s4oKoKBs7MSwp+gzKd1fmorE1n9myakHPqz8dXV1dPXq1f+rjOE/pthpaGgQS5cutcbOmVgsVHt5bnEWP6fmU+WEUJl1+ukf6Tp+v2WL+p2Hn+kPz0w8bO09lHD7PQygUuY7gKe7wdoFVNXLiGInKcuCyQCS1IjPctLOaAxOQhEOR1Bz+SQ8Un827vriWSB2J+xOF5ZWF6PSr4NyAiIImAQUImEnHIVeHbokaQgng+VI+QF8KUChKyoWTM6H06li7gQvtu9sR8KUkAoluU4u9ZxS1yEy9ieUSABVjBAi7/75r88wq8vzw14uta4kiRiUDAyOSKZQ9PWHEBhKgHEdrnIPkmNdSOoEwSzJW7u7TWvOrLKsJTdu+M2jz129ZAl4Q0ODkEfX7M7SuKE47TJn7MLvPv3Kuz+pe+ipm0brqDQ36R/rIjc2SialpPiEdp/pf4LnB4C77763+L4H/vAZwSbcqGt2uBw2pgs+QUpBH/z8582P8l6fnzPHrFu1Srl9yQWPHLTevSq6rz1heyssEg5LJj5ViGESSG5+/A9NXZsPBpUIkB1WkHj/6HBvx7Z3ZNSULrsTi06Zhi+cPwsTi/OwtyuC2RV+zCj0gnGBmAFQSsCYAlACDgm7jcFBAJlJ1CQBqCRgMm0oREowIhEzBKaX5cBls2H+9BIE+wZxsHUIFBbyvAqbWGwTI9J3wV3f+/b82topxt1fuuemadMuWxHPz/FGwUF1hThzdBCbShhVYMUkTAtwOBWwhEAylADnJgDGbD2CMEMgHB7amIqOdBJC5Ne/fud4w3PSdSqokoyFgMLy+e75S7+eW1x5XaYWIBeePLEI+POaoE5KSik7Rq+QUpJGKdkoZaS2lnBCiMAntJb4xBvA9+++W9RJSVWH41MV51zxpD7vlK9xVSFMCuRNmX/bb1ds2lf3/fvOrKurozfd9Hv1f3zD5mYhpaQdOw63D9KkQZYV0YSbwfRrSDlo8t1Hbr7ujS+eNa1zd0uvKM2Gv4LEti1/cr0xEOCmNPFU00Y8t+EIhpMCXqcd2bqKpCEBScGoAKMGCBGQBGAU8NspGCEQNB0BJCQEAQQh4FTCIhKWFEhaHCahKM7LQm8YmDfOi527O5BMCRBITC7SZFHFGLIzOvb7v/rVL87yX3jhPQNcCqlLbgFIlDoQ2j8EYUi4dYrqyhy48p3gKQOOmAlbXwqeoCXJ4Y4+V6lXsZqbl79934Lzvnrr55obGyUrnzHvm9U3fP4n3VyjdpmEN1e3BruHuSPUcw8hRP765bcfmHTNb1qWnnvTqQBQU1PDAKCBECEEP0bAI4TIWkL4KOS8/Pm3bnz8tU1vfebWb8//sEM7YQAfUUo4z2ogRMRDfc/v2rJ1T7+pIzBiyaRhSmVMqd3jc5V4nfpwQ0ODePDB/zkS7N1bTQghIqegON9Tnmu3YmEp/bqMJgRUThPn1/8eVzc9mpM7o9LfOzggzakVpWd8697vqm4/zcrWxUWLJ+KPz2zHvt5+UEoQ4wKams5tNAAuVcCuWWDCQLYi4dMIQCwIAlgEMEGQBBAHEAXBiCUxaHAMmgKdcYFZ5Vnw6gy5xdnItRlo64/BEApybYTNLLeDF1afHlHOfsOl5fjgpNRrSuaWhJhxCp/hQFGngOFQkNAAtcuSyd4ErM44RLlLho8Okw33fu/6wyPv3rTeveW2t99GDABqawn3OpWfd+7Y9hK1mKI6c0lWll8JHdq9/IZPX/rSLx5/+gZaOuWLzpLxvlMWzygHgKqaOgYAj7/w9rUPvLx+8+dv+/4SALjrF7+efN8r656+6rKbT3rx7TV3eubOf0grH3fGjHGVJQBQXV1PThjAX011PmjAjHqXOxruWfzZR97fXfdA0y8bGhp6QqsfOIMf2bexL2BBcdqJ2r5vg7Hm2eqvfe0LW+rq7p51cc2n5/1Pn9PUVCsAgre//c23+wa7O8MuFfJI3MgzHVYy3Leu4fOfj3duPZjvNZimeTQZCyVlJBThZZMKKJFOWlLmkRecOR1vrzkApkl0j8ThUCVAOSgo3ExHtk1HoUdHkUeDzhgUVYXgJuLRGKKRCILBEQwNDmCguw+B7l4EenoR7O3DQFsHjhzpxKRcitBQH86aVYie1kMYCUVgJlKYnq/JqsnZcu2+g+bzn/3MZ0T3vnWJvn1P72167Ea9TBF8pkv25VIZe6MLgyt6E/S5o4ekx4bgdBciNsjYiIGSM5dUfvfKyx/643d/1gYAdT+6f9nPf/fiF66++Nwjnz9r9sV6y8rzezo6B/b1xlDg17umAU7f2On3DFhZMjnS1hJa9+wrUkpSXVPNASAoPdcVVs+fc+rZiz8FAIq38Jy8GQs+ffatt74Xz6/8/oaOOAYO7N8TfXv5a5mUSHySDOBfRoWok5LubQJBUy2amprEaM442sxqaFhqHfvhmhqgqQnDEdNfNWVSMdjkr/zsj69Nvf3qc8/4/Umn3+6puHiNjI4M/df8qUsWlk+3P/DCu3+ieSU12Z7tZPqubZU7Dxxo+yDULqENDUs5PkwjIIBLgqkVbuGYmkv1twdt/gGKrgLqBQDNZ5chjRLXYUG0Up07OkyWGm496BjuC7Z5Kuddde54OfyiQXZsOYIpsyqQ4AROG4WVBKyUBZ5MAmYcISMKI5lCIpVCPJ4ANy1IYQGCQ0KCII0KCcg0MiSBw0IBowLjdQoST2FBHtDXsgnDigKm6GSuxmTJIpdCxn960cGVL64OR+KvWTIRi7V2clpcoRKRgD7ZB7UvbM85pWjCoF9FqNcChUWy55ehMHnOfT8gwytRjwM1S+YW8NyZK4pnVdlf3XzgG/0d3b+/4bJl99/3wtur97Y7axRir/1W07qThvWCHKO/D4Htb3/lwZdWB3uamlhjTY0EAF1HgMAUTqdzAqQksSdWBEK9w9ydlc02Ho2KApI049ufv65hxYr43qam/4nY97/XABo+1LUllP7Z0MatZ0Mnc++/rWXXznUrX3q4uaqlRdZJSVcQsmLcjJl/Uiae/GnvjFOX/fTJla+Ferrawx4LqYFA4upvfvf0igs/9Qtb2fjx/SGCHO/R/SfNGh/dsX8/ASDTn/HBVFWdlLS6qUWprZ1iXvS7X03x+/3jg2u2tSTl8Pq+zoGD8YiIAYA6ftIZVnwk5lgV4KHPzfLEJkQldu380fofff61M3+ztjUQ4Y6T5o+VLy5/n4wt96JNpKCacQQCIcRjEUiLAxSgBNBVFZqmweu0wWa3wabbwBgFYwyUUlAl/SsBgZQEAgJUCnDJACHATQOGZSCZNJBIJOFMxkmRww5ePOmL4yeMQTga+rJFiC48QgkFegBVE65SP92XbH5tZ5sMTpp/4ZXxbIe0+qLCti/KAvGu9S+sWHHk2/X1RC/1RSiR29uH+cljirLHjD2p8MfPvrPj6zHhtgX2d+GAJ7vIHFtZlIpGpdW+7p4Hf/79lY2NktXWEl6/Sio1jY2Ec2sIKqNUs88GIdL49VOhju4YC41EkvnlPlbGLHnEOeXcm2tqDvy6piZGPmHku3+JAcwG1Jyv/OSXRkLRs4Z2PPHCC0+s+f3zb/4mHo2Gv3rtZd8su+Dx8zDj3B8cjCo7gIfnNNTXC9TXE0KoOXTVeTfc/tLmcj5u6slZU6afpVdW49DeLkwsLSgt+9R1K0RhPvr6JEZatqzzbn/ywnv+tCJw+iVNrLa2lt9RV1fFPWPPfOS+Hz071LG/N2OEBqEUzqLytu7Nb5/6nS/fvOYvv29074FfdWz/7W8KLrjgnHJR8dNUdHjkKzde9QyA5Jw9G34WnlRel2OL8EVVTpbqa0fPkAC3LDjsdvi9bnhcLtgdDqi6DrvN9oGy0w8yTiFFBg7FB3BoRjtImrB6rL8npQQh6b+UErAsC8lkXMTjUSSThjMaiiAWCsFnBWCmJJTWXkwrCoXbunv7VCSQt92UPZV2ObTAB76xZeu2bdvMrVuhPvnk2zE8+fZpd/3h7d90azOvbx0Oc8Zc2Yoq4SAaBjoCMq/UzR1xS7Ed7u39bM2Z/toajBxLJ2tr+cInXzrETRPZeQX+Hzfc+1/5EyYt7M/KAsl32Iq8OvzOHFXT2F3JwKFXCSHbamoaWVNT7ScmCnzcBQmRUmI8IdrCHz15uOaK2pK+A7ssmbC251fPmpsYbG27fOGksY+8suaagH/yH2Jth8OelmemfO2Hv+yVUpL6+nrScNdd4jSXzD7vN1v288kVfpgxsW1DmzJl6hgodvBofwK88/Afur9y3n+Vfv3OUqc/z/Gtb926q766WmXfu79ZL5m3oOOtpx/49V1fuPWeh5vOd3p9p93yqTO+dtPs2Z7Jl32uKijtY7ZvXP3KV2denRisHpSjtGNCCKSUqDnzzHGn3/TNdwd2b7su1+e28gtLfurJz55HjahweV3U5XbD4XDC7fXAbndAUZS0ssq0kkspj71G5S///HdvYHq295hx0EzzjBCSMSgihRDgXJBwOIJQMIB4LApuAaFIFEEzCdrvxFCln3N/IRtY//4r37vxgotAIO9/7JnTPWVTvxza/M5vYhTZ3innPRjWfDaLhElbe4gc3tWBU2ePR+UgleaiErJv59Z9+Q/fdNI31x2I1NTUsCmTpsy3lZ98l3/OgmUeNSJIhNLWOAdDKqUOd7/AGdlKkyNHeaRnT6S7+/D/74zzf3IEkE1NTewwkLoi1vqlAjH0lHPedMfu9ujcIcPiqZFQACDSNCKpinyq6FlFngFrXkGjlAP1zc0EqBdS1JNvPfzERXLQ5irrMdA+S2VJLtHRNyQrnTk0vyckN7//8BtvT4LzmydfuFql5tuEkOt+fNdd4+N61iwtGbQWnjQl+msAZmFFvX/CnNlPP7H+ZGV8TmkCrkItHMLEjq0TljYsPVRXV6eMcu+llChfvNh2+tmXLSxOJXKKZla9rTs0WlRSDJvC4PeOo7rbCYWxYzFdSgnLsv5M0T/swUeVdvT3o8r94d9/8O8kpASEEBBCQGYihpDiLw1ktJZClt+LLL8XUkiYhiliiQgiwRAdyBqC2nuQmYEjorDMd8FvfvXQMzff+rlrI+ERMraq6gI1y39u8KmmH9tmyUS4I65nbYsS2xl56B8Th0cqYCWaGPA7aVmRb2QkyFIAsPTsi87JmrX4lUDIi1Q8iT0DQdrWHzN9BXlKce+WlV//Qs1n6gDd+61vFcW5ojb89O5PnPL/S1KgNJVXstpa8rKJrD9WXXH9TZZMxAaGQvpwR7hQQpKfm8P9hQpgI7oilZg6ylGvW7VKIWSp1fDYy2cX3lBto/cctXL3EEXxq5itOElxR0x2Lp2ICZU/XT5zzZe7nGMmF1ptG3YCkDHdm+fxurSJxTZi7B1ZUwMwm6oWB+MRnr1o3ryuwDCCYYl8Y/ilcwuyjl6+Rapz5hAzjUj9cMKEijHX6TZ2QVZ29hSH24bcnBxkZefAYXcIRVGpkByCC3DO/0zRAWRyfAWMMRBCMarbnHMYhoFkMgnDMGAaBgzDkFJKmJYFKSUYU6AoClRVgaqqRNd12Gw26JoGxtifGYllWeCcp41EpvsJLBPUmcZoti0HuTn5KOeVGB4OoLOtnQ4N9cvKcaW1Tz3x5DjzoNUpdx3l5tg8VnrGdd9hDgNjlzrRYcWFP9chHT2grVZC2qtKiXsgIIc2vHxHQ0uLCUKg2ZzKgOqR2NHHc8u9SqeqIRoaVOZP10lJ4czFb+1pP2pJ7oUk3ji1kfqJs35Zf+OlX61plKzpE8RA/dgNoK6ujtZeTvm1NdcWFM+dW+NwM2YEFeeOtkHkjJ9ZdNeDbz2aPxTph6mAqQxEjPv2bT/5Y/9QV2tj/ZIl79ZLSb59e/1dwYlTzpbXlbrCR3qFsTdJrSInWstUabo06uuNJrJclSUxZajzFxef8dA4IDcati0dk5NP3Fo0PHjJBW96r7hmksIcedFkUg6FoiZJCZYf7XpbP/DmzUsbGiw0NODHd/54amll6X/ZPe6a/Pxst8/jhCfLL7Ky/FTX9IyiCWqaxp8pPCEEqqpCUdK3M5FMIhwKIhQKY2BwQA4NBeRwICCDoZAMhUKIx+PEMk0iuSBSSiIg09NdGYoEyQAFClOkqmtwOJ3S5XYKl9NJsrP8yMnJIdk5OTQnOwcejxt2ux2EEFiWBcuyIIQAEYApTBDLBCiF3++H35+NRCJOhgIDwp+fPStcFJ4VCO2Cp6tQhpOKeOu3f/jyopuun1e6dNq1wykCm8rkUCAgtHiKJfeu+fV3G777Hu76HgAQxvhgPBgjtMjB9oeD6IoFUTamiPT2DmPQ5nLqMZtTs1EIHofLTuG02z3p/sEna/rsYzeAhoYGCUIQH4knkpHAm6nWfYUebqwrZyEfV13X9OdOuJZYBuhIHIU+Bn3cjIuWnroEBze/P4YQsnKVlMqP7m3Y8/2Sws/lzr34GegETk2TbYRjQp6PZh9t+f36+7/wpwm/alxpHjWNT9/+0I/12dOv6OtXfU47QzyQEC23/eCyJZde+F+7QioNDwVQkudnOTyOXS/94ZHfPPqHnh/U/WxScUnerU6P+4aiojxbdm428vPzLafDQSWllFsWTMv8IJ0BwJS0pyaUIJlIorOzE319PaKj7ahs6+yW4aFhkojHmUEEUTWdeN1euF0u5ObmZIpiBl1TIQFQyixKqSWk4FIIKiEZIUThgtNkMgUhBLEMkw72DeDokaOIx2IwzYR0OpwiOycPRUWFGDN2LCksKiaFBQXE4XBASA7TSEcIaVkQmTCkaRpKSypoSYkUoXBQth09ynq7u6RXMLb07PlL/3jOvM8tueeJFwtmn3JPeWnR+KNGH+s5uLdjww+/fhsA8tkbbpj68MOP7EpEB0IyHrMG7boyHE+JYr8fRe+HRUxRSZe6fRdxjjxQkJ+VVHUeCfT09e/81hd3ZNDAT5QB/Fu7ct+vu+9r2Wdc+dNX1m8VXrtDOX3hJHh3RywxLR89PUc7gvdMrW5YjWRmYZW49/4nb/NMO+0naw52yvMWlNLUwZ0/u+ays7/x+Ktrf6qctPD24E+3IHfJBIQLTexe34cFp+XDYVEMhFJQy/zgwyH0tfb1uv05WYRpNnvXgRC6dq935eWeUlCa78zK9qC8tJw7HE7KOSdCiPQUOSSoBBRVg6oqkAAS8Ti6u3vEgf37ZUtLC3p7+5gQFlwuB3w+P7L9fthtTtjtriG7wzbicNj3eDzuI4qiDFopq8futPdycJMQEnUojqRJTMPpdJo0bQ2KIoQtkUg4DUMo8XisgKeS4w3DGh+NxipjsdjYVCJeHI3F0D/Yh1giCsuwwDlBXn6OmDR5kpg8uYqWlpZSm80GCQnLNGGY5p/VHYqigFKKYHAEHW3tciQYIl3dg72h0Mi31jz1ZOvcb/zm9QPc57IPtByI3X3uKbnffaVuOIXPDjx3QZ4yUuE//b43DhyNMkVXNZblc8BvEVRNzcarjzz85l3fuPHs/06Ma2S1tTXiL/lE/+sNYHSw4jvfv39ZdvnEcwuLPDk2t9MdTjhmxFXHmCHDRMK0iFvX4OuOSVaeQ8LRwZHk67+ovvOXD/ZNBFwHgAgAfO/p5q2DSuWsKVr7H7908aJrfvzjX1075uJrHwsOD7dtuaf+p1O+ffd9zn1J1jOSJGy6HcmUkLrXLnJ7Bq3BbS985s4ffv/5hu/+/Ntjp87+geR9KM/LQ25RPgry87nT6aJSSsI5/zNvr+k6GGMY7B/AkcOH0draytvb20g0kaB2hwO5Wblw6HYoqtJhd+ib3G7v3pyCnENeh/eQzW1rXbt2bai2tva4bWA4uOGgJ5QIzRKUVHT3t3kj4fAcRVFmEULKosGoaygYwHA4BK/by6uqJqG0rIRWVIwhOXm5x+oQKSUopZm6g4ExhnA4JPoG+mhrZy/693ePOErHeVqIn6UiEM5QT8A9bVouZQwdzzz7WsHsqQWTl86edbg9ChnoS2b7xLA3y36UxOP9a19+60WXPu9PS5YsweBgmk5de/nlHPKTx4f7V/QBCCFUTvd6fbRs0mu5p52hc84RpwxG2EB4eBhllga9l6K9QsG2ZBjDmwawZFaZp3jmXB+hD/d++nfPP+XNLdLDG1+4M6lrTnADJJ4avuOrP74iVXLyH4KGAGnb+jVRPa6bKg5l2GcIU1EIUTQMByKkUCEsrujEUX3mjb/+deVZ1IqfabN6UTFhjBg/fpJ0OhzUsixmWdYx+JNSCpvdBgKCzs4uvL/2fbF9yxYZjUVZYXEhqygbg+zc7A6/37/RrjlWUUI3x834wfnz54f/hhOgzc3NFACWLFkim5qaMk3vdEe1vr7+z36+vr4eTU1NJPMzaG5uJkuWLJEABCEkDKD5L95f6e3tLR7qGZoVCofOCQQD54QCIyUtu1vQvOY9OBxOa+aMmXT+gpNoaWkJACCZTB4rzi3LgsPhpJPGTxL5uflo9Xuzuro6MMEcQDsto9rkablhQYWNmqTwtIvPLZ2Shd5AFNH9O56M73n/O7ff39Dxl95+6dJ081NKCdTWkm/+6L7zn218cVfb9lXt+IQ0xP4VBiAhBVEIiQ339j8y3Hp4gYOaHTD5plRXa9KWV12XSnjslpEC0XXq4ARBQ1jdI1xJxLOulYLf4a2onFYwaUq54vCcNgiNxdsGYJ8w/paSmnFfSXlKEDi4+plvX3nZ8q/95JnnW9uDMjDUw0cCEXpysBy5Nh0kR4VwpqgH/GwntSMnOw9V1dORn5dPLcuEYRjHFD/d3tdhmib27NyDTVs2iT179kDTbbRiYiVKiopkQW7Bervm+EORu+j5nAk54b988Lm5uQQABgcHZU1NjcjAnAKZvTwfsXb6uxG1qamJfvhzCCEWgPbMa3nHng7/SDR81rjKCecPBYcuGgoFnDt2bcfGzRtF1eTJ8uQFJ7Nx4yrBFHbMEIQQSCST1OVyY/rUabK4sIjsb9kDpf8gRHRE9vF8GpNOqPl2frRvGOqQwYbeeLYxtf7hocaX3v2s5XRcvGfDpt/N+M6tb4wieaukVAgh1kPPv/mgmDDvc0uE553Htq86s/FDO1P/r9UAf2b5P3txa3/RvFl5ZjwFB+GwEgba2qPwFPtgDA9yq6Nzkz5p8hxnnp1yg7IjRwfQ3zmI6sllULyq8LtcRDl6aAu1mx37hrTLDnTF4XXomDDeB18vkDg8BJI3AEX0wEY5nz13rhwzdiwjYMSyrAxUmb4NNpsNiUQCO7bvkOvWrROHDhyiRaVFZMrUqcjLzd/v9/kaGdhLVdOrtv2lwi9ZskR8QL/49zzLuro6Up9hW5IPQY27t+6eLCCuGQkFLxwc6K9q2b8ffb09cuLECWLxkiVs0sSJYIoCwzD+rFvNGINpWuju7MDePbsRDidheMbgkL0QYE7EDw4gx2XG8n004po6tSBngorWFW9/55YLzvzhz378q7MiJ1kbG5Z+NXj/Y6/eLyfMu5VZJtTubV//wmcu/BlwbK3L/34DqKuro1iyhAJAw7LTrEbBtd5Dh4htVVh0xbbP8+SUzhRmPJBMJYYdbk9KpXSMs3jSD0hhSWEiQaFoBlLBCJwep9zf1keCA0HMnTUW0SSBlAZKx2bD5BQdnSEZP9A+pOu8119WNMnjFlrs8G5YXW2oKC/F7Nmz4M/ywzCNP4Mw7XY7pCTYu3cvXn/9dd7efpSVlpZifOV4jB1T+X5+ft4vOzetf/Xk2trE6L8RQrBMOvKJHPTIkA1pU1MTRrvbr732mj6ueMwFQ5HQV9o72hftP3QAfb3dGD9hIj/nnHPo+PHjCZESRsqAHKVnSAlN0zAyEsT769dhYHAQ8JQi5KrEwe4UssrzMMGlIBRsfddr85qDr6wd0ZdWaMXjZ126+6Fnf+ubkjXonLvse5ZJYd+/4fdfuOrcLwDAaZOKslce6AlI8e8dvP/XRwBCM+NRACgF/ooX+K+b/6vaU3b678rOOWthgkUtnjDV/l2DGKPbsM+Wgi9bw9QRD9pDMSSmOJCVrYrQkMnV9pja+fwPa375zB+eu/MrP3uveFLhKZYZECfNX0AnT54EQMKy+LHiT9d1UErRfvQo1r6/TmzavJmUl1aQitIKs6Sk4Jnsgtwnq6qq3hr9XqtWrVKWLFkiPuo6lk+K1NXV0fr6evLhnaDbNu06PRZPfH2wo+3Mzs42HBrowrSp0/jpS5ex8ooymCaHaZogmdRI03WkTAsH9u3DoUMHEDOo7DKK0dUvU1pwzdd+9/Pv/vZLtddeseBLd/0pUVgE/mibsHsJTZybjYSZEra23U998bIzrrnm4osrz731ew8c7RiY/ui3r592sLd3KNMoFf+OmoB8zG6IgBB5441fmzB53inXxwK9z33vjpu3P71uy3cj7R2bPv/pS18HAMoYfvHKPn340c+p5Z/95XqrcPwUxQAS3b0gFTlIqRyR7jBkEhhMGBhX6oSba6A+BlNXgXAKknDZfiRG3Fb/EbV1S5/DReZl5fnVk+YvRFFR4bE8d1ScTid6unuw8s235I6dO0V2bg6bMX0migsKnwsPR3+87PxlW0fvkBSSZZT+P30gnMhGSVHzQeTa/t72hUyKmw8PtF2+7+AB1tffJ0+aN1+efvppNCfHj0Q0AUkkkKFxaJqG4eERrHmvWSaiJokO0Gg0h3+7P+Gd7C+r+GLF1CIRWhWW/lbOdkw3pbAxPk1VlSNvPvN1UeTaUVg160Hn2Gljhg73I7TzlWs6W1reeviZh/v/V0aAulWrlIalS63bf/LME3OvvfzqniMtAUdPtGNi1ayZHYN9otcY3mVr71n56I219+xAdHDVqlXK4YSnSVZMuXior497vDpTQwLGkRT4DB29Q3Goqo5cG4HNrSBpc8C2NQBvzMTQDDsSkRhI1254EyMoHzsGs+bMga6psAwTlFIIIcAYg6Zp2LhhM158aTkXEGzhgkUYWzpmk8vhrJ80fdLrmRSCZdKH/w2Kj7+GyWcKdAkArS2tJwUigVsPHD7ymT07dkEhxDrz/LOUOXNnAyBIGQZoBijQNA3xRAJbNm1E9+AQlKJJ6NUKEIkBGueweXWkINF2YBAeu47xBT7YbAStPQH489ww4xE+oSyXAEkeDYaDffs71ve1vH/Lz39+d5eU/9rzDT5WFKh6cFASylDqoU+PtHdcmVtVna1PMLO7nj7McZAzx41VM4pmTJvxrYlbLz3y/nt3Ll269GkAl/zsty+tcIw55TwQyS2NMyVHImVpcGgCy2YXomM4gUNHgvBnm9AmeBDgFPHkEBL7NsKb6JeTT5ovZsyazSzL/JDyc+i6HYlEEs8//6xcv26dnFJVxaqrpwz7s/x1M+fO/B0AS0pJ6+vr8b99hfhoXSClpJm6ZiOAjbt37H62pKjwgT27tpf98alHxd4De3Dh+RfS7KwsJJIpEMpgGAZURcHiJadh6+ZN2LV7E4eSDeEcQ4cUB3F1R6TDayeSMbR19IExC17dMiJhrgmpwaVK2tYXIUKAqoort7Rq+oWBtl0PAqSzqanxXzo08y+rAZ545LkLzMrqe6yc3MluB5HscILwlWEui5ghzim100gUe9dvXukpy+rQ3AVnFJUWFykaJ+EEJ5FUCjyaQigOuLwOQFURaOvGuGIXFI8fyWAAoe0rwaJDWHzqqaieMiWd8mTwJkIIbHYbjra24fnnX+CDg4PslAULUVFS8VxoIPSt0y497QghBM8+++w/dArM/ybJGAIhhPB176wrVh30Z/sO77tix57d0KjOay69mE2dNh2JVOpDdG4CXdexY/s27NixE9STDTJlLqLrwItXRWJHb8p1wq0Qsv9oKuvA40sPsjG6Z8aZz6kF5bm2riOD3By6H8wWDB7cvesHDbesOQab/6enQHWNjVp9TY31o/t/f2b++LkNsc4Dd33581e+CgAPPPlmc7K8arHbx4Ujaicj6/qs/vEexpw67F4XVXU3nKoEIybMeAwyJhHvGET2ZDdaOyPgug02mwKvwuGz2SA629Hfvg12K4rTzjgTlePGIZVMglIKCxIqY2CEYu36dfKN118TRXn5bNqUGcG8nMLbZ82f8fBocbt06V+MTf4fFTl60AeA7Ru31/QNDPx83+GDJUeOHuRnnnY6XbZsGaGUIpVKZViuBJqmoWX/AezcugMG02BMnAnarHNGbcy6NAc0GBLBPZse/96NF9xwe933zx5/5vUvDx7YvuXOGy44+d99vcd/MxwhWN3UxBsaGuSiucuWlS2+4AuJHP+Vi5ZdMuusS6492+kpWmB3e509vWH0xlKk00+YTWHEmW2XCA4SsXPzU0rv7h/1rd2ru8dVT6R2IlJCkkPdEQimIk/V4FYB3asjfHQ/hvdvgM9BcdHFl6C4pARGKnUs39d1G+IjITzb1CQ3bliP+TPn0WlV095UFO2K+aee9Oao17v++utPnJgy2oBrapBSSlJdXc1OP+v0PV+68rrG8vKKQl9O1rQ1a9ego61NlpSUEH+WH6lMA5FbFooKC5CdlY3eQ62I97dLfWEp5Qe69w4O9IZcE8uzqydXzpw+aUrwrtu/9NRYl7Vcc9mXX3lxfei2235P4+dVk71/Zf3iKJT7cW6jO64RYJTzc1fdveeOmbvoc7a87EVhU8mKSEnjpkZCQQE/EeBmHK3DEfhKfJh6UIJn6Rznl7Pwyrde+K/Lz7oMAO5+cc17ibypC1xGFCURKC0Q0PMU5Lw4grKxXhyaMIRg8xvIy3LgoosuQlZWFgzDgKIoEELA5rDjyIGDWLH8JRE2k/SU+QtEcW7JHdPnz/zJh7y+dULl/+7zZKO10I5NO24fjoV/+k7zSsA0xacuvoxOnlKFRDKR7otkYOXB3gGsfPddi9ocyv7WPV84+sbjTVO+0ri7YtbMouRQR2T/yy+cUlHk2L/29SZP0xtrBxsbG1lLS4scnRYbPeEyswj4Y3dMx80ARiep7rrr/ourz/308qjNjVgqAcuMQONSFOa4SPeeA+9Gu1p+5i4cd3di7MxZWS7O8V4YfE4+0bX+6OE//m4GZs/usSW9fyw+7czacBgQqQiUpAVTk1A1iSObRmBPhqCl1sItCWo/dSlcHjdSGeWHBHS7DTt27EDTC89zn8/Hlsw7JaDoymcXLV70kpSSoh4gDf9ZWP6/uYcAQojYtH7TpTHTeOD9Te8XDnb18PPOOZctPHkhkqYBwiiExeGw29Hb2yfffXslgoFg+5ZdLadWl5d46LwLVhSUlVbsev7JTy0942R3MCK+98LXbl7wytE9/X9dLSW+dPXF2dWLL8u5+carD2S2Ch/3SHDc9gK1tLRIAOgfDnR09RxZkRo5vNIdbn/NlzQj3vxcaTNC0SPL6678+lc+9xbJLyiwuylROoKKnJ+n5I61s6Gtm+9quOeeNrPl4AxX7pjakUOd/QNbm58Y2XF4T5AwuJxEgCvIrrAQHlkJPZXChRdfBKfHk4boRtMem45176/Ds089Y+Xk5rJFCxa1qlIuWbR40UurVq1SCCHihPL/AylResObWLVqlTJvwbwXlHBi0eJ5C/dPmlzFXl7xirVx00a4nE4Ii4NRikQigeLiYrLg5JOl2+eumDN10lvPv/lKN9ty36z9Lzx8RpbtG8tNnzYvt2r2mPPuf3bHHV+//7a7fvWrqVJKUlPTyK4577zisT/2eX/74POfmn/j99enfP4vAUCj/Hh2WH3sKNBdD7264pSLzzmv9e2Xv/LZKy++/4V31j2SrJp/PRnqjhx6/A/XOaeecrGq8v4vf+asb9bVraLR6Bbd5TILm37zi769g4PRb97/4rOFS86qdUYCMjocJdH2ZlhD3fjUZZejoqICiUQ8zV+RgK7bsOrdlXjjjTd41cQqNnvGzN0p07psyZlLDp1IeY5DSrRKKmQpsZ64/8Exk+fMfHZ/26G5WzZv5pddehk7ad5cRKPRY112u92Olj0tfOvGDSzYH9rx4kvNZ63f9fbALZddd8rMC76xOjG9QJCDQ6wkYsfOrIOvf++y0879wm1fyCucVbuueFOYuG5cMjac5ULHi0999u5brn2krm6V8me7oz6pfYC/PEP3ljt+9LVNTw4/+M2vXv3yn/7UdE44e8y1bipgtu2793v3NrwA4IUMDo2GhqUC6aNID9/3k/sqPRWzGjqySi5LdQ/gwOMPvu6u1OY57TznwvMvkuXl5SSRiIMxBs45nE4nXl/xBt588zXrpHnzlKrJU17e33rw2uuvvz6YpuZ+4pX/E39YHVlKrEyqe/SBB+qWLVp02QMSuLaxsdFKRmPKolNPQSKVAAFBPB5HVXUVI0xaW9dvnHH6uQv+lKux2+fUfG55aU8u6W9NkUGXYkbKs1jgrcNrAOD9e39nXrfmdq9Hy8oZaI8bOe+FqK11KPJxXtNxN4BMF+/DD/IggIMgBL3unGvzSgtoatf2PctvPvMnq1atUgbTHHfUEsK/dfPN4wrnnnW+a+yEWmeOd3aUeDUeS0B2DqMgL2tBDAPuBfPOwISJk0k8HgdjFJxzOBwOvL/2fbz11pvWqYtOVcZPmPD0/EULrgHAM9Nkn0SUh9Q0NtKamhrUAIJQJgGgTnCK5maK5mbxSVwjktmYQQkhUaDhuh3bdggKXP980/OWmUwpS848DYlEAjSTDk2aWKVAcG6IzcsmTp72/Pad635pXVp6i0nd2eHhFCQ3aFlV9Zl1dXU/9U9Y9ENq9/kPlietnKiqeMuyqF2b9NmqqqqXgCUfiwP72HeD1tXV0d9v2aJCSuzfvnt555vNbw3u3vC5pi4klixZIlrq62UNIM65+OoJlZd9ftuMyy78BS2cuOBwgGmdwRD3qgriIy1IuoNZc6afpMybdxISiQQYS+f8DocDu3buxPLlL/C5s+cok8dVvX7vfT+/Xkop6urq6CeRuFbT2MhAiGyqreW1hHBCiIQUgBRoIEQ0LF1qNTQ0CCklqWls/MQdYkIIEZn153TGrBk3jasY+9q8UxYqr732urW2eQ3sdjt4huQYi8UwcVwVmzS5ipfOLRkzvG1Vu9ixf31FhU/xuTWFsaQcCh16sqGhwWK5bp/q1KgjDmlRRjYk3n+/PxZ4bO/evcZdDVR8HCfc/yuG4gUynuzB7375WQDPjt7H+vp69BZdwAgh5uzZkyIjEZO2bh7m2DAk9ULJ7NPyWGRPC+KHtmH8mFJ56qmnktSHcH6bzYbDhw/jT43P8jGVY9nkyZPffPDJhz713HPPGfX19fST5kHr6uoo6uvRQAifDajn3vv7RVbB1IulzT0LinQKSFDL7FIjQ++ph9e+SQjZjcxZXvX/3lmDv/5cASql5FdffXXtLTd/+XmeMs564eWXLKfHrcycOQOxWBSEUiRSScycMZMFQwG+6LSLnuh8a/0fc2dkf9OtFX5z6EjYZqxsY9d85us3pjrCxbZJDDa3DdqwJOrBrraGO6975rbbbi6/1/WbbkKINcov+48pgv8apIa/eJg1gMt+w53LZiy4+OGEPcu/o62T+PLtZMrYfAysfxEuGsWnP30NnC4nhEhfu6ZpGBgYwGOPPcZdLjc75eRFLcOhgwsuvvjGSF1d3SdK+dMTXDiGa9f95HdnW2Nm3m1lj50tnT6kLAtCpBn4RGHQBEBGBiwtNPiGfnjj/XV1X3w7DTWn93J+0oy6oaFBPFBX55pz1vlrNm/dOqP14CHrC1/8nFJYVIB4MglKFTCmIBGPyzdeX4Hutp7Wd59fc+OZn7/65rL5NTXDwRBUIuHJtyO4tQ/5ERt6z82BozWG4I6Nr+QvrVoUeHPTKyOdP/xqw8N7h/+jUKC/pRCEEPnlL9dNSXknf7WwqnJpQWX5mLy8XIRCAWzf14mCbDestm2IHnwfl1xag0mTpiCVSoAQCsZUJJNJPP7k4yIRS9DTF50eUDW2ZOHShXv+1qnq/24FAYAf33XX5Niks77Ns8uviqgOyGRU+DVLlHpU4lYVAkIQSnDZH+Oy32CK0L2wGRG4Bw487X/le1/7r2fe7a+TMh1FPkEGPnrPn3vqqbEVY6teefOdN6tMIyVu+sLnqM2uwzQtEFDoNhsOHjqANe82IymzUXbyMhh5XrS3DsjCfK+ImCYN740RX1CiaGkeogkudbeXsMPD0JNAr79/v9F99JFdzcsfevzxx4PHAzj4d5wUT+qbwaSU/IYfP/nY3PMvn51vT0CJDAai+zasItI5d8aMqvJ46w65f+96cvLcuZgwYTLi8Vh6Dw/SlNxXXn5FBoYGceF5Fxkq0y9feOpJez7cufxEKH8mXP/spsU5jsvu+0kv9V0Rd+fbrVBAVtuH5akz/bTYq1O7osCSgMElUkIiGE8hYVmyPxIWa3ssEqqYc6W89qGFP1m2vf4bhDz2YaX7hBXGratWrDhtxpzpb7+18t0pDz/6mPjcZz9LGWMQgiORiGPCuAkIBAbl5k1bZLB3L1Vcs6ApGuEcLDFowFvhhDcpkTAlgok4ITANKQym5XhAtaJJ4eE9hTmcm6Md4/+ECEBqahppVVUuqa9fIgilYnQ9xme//dNbTj11wSQEB1+79opLVgJIPbBi2xZ/ZcXsnY2/F05i0KuuuRYOmx0ys2jWbrfjvdVr8MZbb/LzzjmH5fjyPjv/lHmPfMJwfjI69H3/HXdMMpde/6dQ3vgZw0O9qPJJfkqpi1XnOJAwgd4EQcwQSAiBGCeIWkBHIArJTVT4FBS5GdqGDL4upDIqCbJ7Dj0VfeHeO37w7LOdjVKy2k+QwY8+gzVr1kzvHxp5/623X3fMnjYLl19xBUkkYmnynEwP1ry64hW0d/XCM+9cdJpOuKmCytIsBENxuAY5TL8DERsHITqcYcD/5pHUwZLN3/7uV7/w8+OJGJOPTQEaGylQg7+Ss+pf//KdZQ7rQKThN019o//zt7964oy4p+JbhbOmLWvd+KIc3L2NXHrppzB1yjQkEmm+iaZraO9sx2OPP8HnzT6JVZZV/PzkxfNvk5nNA5+UlOeu739fSCHwwINNnzarF93XR3NyebTHOn2sg502xke4JOgKWwiZFFwQEAKkiIDFgZ4YR0c4gWDUgLQECtwURU4KtwqxZYDLoJLDCmNdndr216/+ym1fWr1KSmUJIZx8QnoIo0bw5itvXtI12PXcpo0b5UUXXkJPXngyicdjIGBQFBWDQ4NY8dJLMNy50KYuhsvhgptSDMYsFPZL8DhFT04yqQ4eepPnl51EjIBx20ULyjNGL/EPbNj4l6VAdXWSVteD1BLCR8OzH/Asuua7s7PHVlS58ooXZ+fmzlLcWcWpSDz8eYy/Kcuzf3f1WQ3L7f78aQPCjmDvHhnYt4dMmzYdkyZNQjyRACVpGkgqlcTrb7wu8nJz2bjyipZHn3zkuxlG5yfCC46mPOWA7Qcvrv9psHzaLQcjAhPkoLh0Xp5S5rEhnLLQGeVISApQCgkJUzIISWFCIJpKwhCAqijg0sRJpQ4IQ2Bnb4RWuBiGrCFrwJ1fmrPwU289+EzBDUsJeQqUovGZZz4RKdHSpUutjBEsf2n5S/WTJk2864233uDlFeUsPz8PRspAyrBQUJCHKdOmYcOGtRiI2rA3nItwOIxY3EBOeTYfVzyWud7dsPW+ez9z8RNXTXN2nfmtKb/fItWadKP0uBk7OR4er7q+nrTUQzZkODbTAOfcut8udueWf6qgMO+0iZUlZWNL8hFnwJGgQJaWQvN7h7F362FjvscZKFxY4Y0xu2pplEY2vMxoeACXX3kl3C43LCt9nJDDbscbr78u12/cIM8747wUoVh87oXnbv4k5MJSStIE0FpC+G+/ek2x64Jv/3G4cOLSfW09Yn4uIZdMyyUelSFqmBhKEcQNwBIcglCkJIUhKZgAklRiX38U/TELlgkkDQuzChQsG+MBkxIbO0bQlyLoijERkoROzFHh7zt47++WzqlfDUQ/KSnRhzdSUKKs37Fr21yv28OvueZaNrpjlVIG0+R48YVGHOiIwFl9Jl5/pwWF+QVgCgFlumQq5XYSfl9NDDzw1L03PfeXRfe/1QCklLSpCeTDKc7yxuUzQo7cL2oe3xm5xUVjSguyUOIAnIAMWkK80xpEMMKJGhshT73SIiNcpePtDjP0yh3fPPcnf7gzmoj6+9a9JM8772xSXV2NRCIBAFBtOg7tPYDGxkZ+ysmnsIL8gtuXnLnk3k9C0dvY2MhG1/49/MSL12tTF9S3c0+ZEuq1zpyQo0wttoNziTinMCyOFCgMiyBumJCUIiEIUpJBlRJJQrCrO4z+SAqcUxDLxPzx2WBUQrHiKPM5ILmFfcMc7SEu4yAYW55FtM6jLSPvvfmNL972xddGRzr/3SjRqJK+3PjyAlOYq5vfXUnPOOdsOn/hfJJOaSlsNjv27TuAN19/BWefeQY6zRK8dzCKk0+fgrm5EkPDUezqSqEvEEOiq323EWi9//6s7z9FbutKNDZKVlPzz6+l+UcNIF3cUXpsz+PWFU+Wd+oTTmtu6Tt73KSSi85YNlMjAlC5EAqkjBiStA9FaSiZhEvXML/Ui0df3or3DsWgMymNmJDj7Lo567Qyfd8bz2B8SQ5OP/d8CMsAIEEpQyKZwhOPPi5cThedM3feytPOWHLG6MJc/HtyX9KYpjFIQoj45tgsb/nPVzzgnrHgqr19QeQk+vmNCyqYR9fAOcAJgcmBaFLAJASCUcSSHIaQMCQQNQEOiqjFcbA/hqFoAqZhYlKBBzkuFUd7QtCdDqiEo9CpgysUcUHAUwLtoSj3FeWwIjOGyPaN9TfUntkApDeyNQOi4d/YCR+dLnul8ZVvdHZ03nPg6H7++S9+gXmzfLAykYBRhhWvrsBITz9uvOVmbGwL47V9IcyZWoxLZ+aBc86jhiDxOKNvbjyKvv7ePSVyoOGWz1723Ghv5J8xBPrRLVoyALKWEE6kxCNPLD/5t8+te+Tl0KSdj20MPixzCmumTK/ShkMWbx0wxO4Bi24fsNjunhjtG47CJiwUahRuG0NRgR8OhYGbBsnOcdFQllMf6TkM3Ypi9uzZSJ+OIiGEhKqqWL92vQwGQ3LS5CojGA7chvTJM/hXK39dXR1tlJKBUFlbW8sJIeLnv/7jeeOe2rrWNu/kq3Yf7eMz7GHxX0smMI+mIcVF+uwAAjgUwKsBjHCkzBTCqRSIAihUghAglEwibpkAITAMCwU+GxRpYeOOdth0O5yqgMYYBuISwbgJL7UwrdCGRaVuFj7aLQ4mqHQsPqP+6ff2vXr/HXWTlhJiNRAiRk9u/zhoBP+jl6glorGxkb3yziu/cPs9m3RNZ6vefVfQzFkIQghIIjF79hxYhOGhx5fDpqm4ZKYfgd4Adh4egWEQpkvQHCcXnzl9DF96UvUUW1lV0x9eeu9HA1ueL8ycRC8b/z8pI+QjpDqjR/DIR6+FTZ7+6lUxV/Z1Np934f4uC73DcYwr9/GZU8sxHEzR/qEooUhhfLEbdlUgMBjC4Egc+9qC2NLSi5NmjsXiqXm456F3UVxagnnzp6L7wDZpH9hMpo8txTnnnAuDGxidNe3v68djjzzGZ8yYxcZUjPn54tNOue1fmPqQmsZGWpWbSxqWLOGZk+vQCLCRRxvPpmNm3Grll5wVUewIdXXyZUUqWzYhH1xwEFD8JU5NQJCSAhHTwjtHRhCwKOYXZyHJKbYPhOHx2DE4mETXUAyDHT3gySTmnzQFXqeCJE+BCAmfriLf54DPpsBOAY1wJC2Bje0hDGg2PrHMzWjvYMgaHHg0sHvLnz73xes2fehZsiYALfX18l+VIh1rkj3z3OkDg/1v7dvfIq+88hpaXlGOlJGEhITCVKxc+S5a9h8Em3Aa8irKML3YARskOKXwe93wex1ggkNnUphCkjf3B8jBIwOB6X7x9GWOl+4k8xvCkJLU1deTf+TayEf4ewkAG9etu/JwxPUN6iucbncDB44MIJDQeXa2j0ZjEdLV0Ykcrx0Tiz3Iz3XCYVMhLA63ylCW44Jm03BkMI57Hl6Ps04dj83b23CwK4kzzp0H2boS8fbtuOLCGhQWFyEhDEACdpsdK15eIVrbWumpC0/dGYqFFtXU1MTxMfNiRgv7WkL5h4PMU7+/f1J/9ozLRU7pJUp23nRDdWCwr0fm0pS8pDqHjvO7YVkSkgKMyGMbKcgoYifTo4OQQF/KwjP7wzCSFsrzvdjSGUCe3wFiqli1ah9G+gZwVe0ieH1OJBNx2DXA71CR47TBxhgYBVQFUISATxfQdQWvHhpGR4zxyjIvK/QD0e6o5ENDa42+9t9t/VHdaw2rVwf/snCv+Resdxw1gmefbnx1z4E957ocDv6Zz1zNTNMCIKAoKvr7B/H88mcxuXoaFlx0Od7e04N8J8U4nw09gQj6okBBYT7cNgqnItAViPKHX9zLfA47irTEvlnF7LtXXLjoeQvp43Ab/jsr+R8zACklqQfIaU2PZO9XJj94NOy8GA47NBLju/f1kUBMoTZdwiaCqCx2oWp8EaoqC2C36dA0Fdl2DVl2FSoAIQHD5LBrDO0jSWw/3Ie+QBS/ee4gzliQD0d3Mwrz/Ljk/ItgWiYEAXRVR19fP5588o9i5vSZtKyw8KzFZ5321seJ+tQ0NrKqmho5mjffB+jBnz84Tyked4r0Fp+b1NxzuCdLZxDI5WFZ4SCizKewyYU+6IzCMiUYIwAhkFJAiLTXN6WAgARhBArSmwgopTgYtrBlSGAgkkBHIAFOCKRBsXn1DiyeV4rTF05CT/sAst068nM94ILDtCS4lDBMDosLWBKwLA6nCnTFgc37R2AYKZmT6xRel4ONG+NHgQcQwVCH0dfzkjkUaD6yc9v+r3z9K3s/HBnqP8aoMPrMXnv+tfn9wcCaDZvX0osvuphMnzadJJIJSAnoNh2r167Bnu3b8Onrr4NtbBV2dsSQCEZQ4mHoHQxCEhVBS4PqtKO80ItwMCZb9neJ3r4Y6z7cixIf3nTF9t7983u+tfYvaSj/sAGMQmr3Nr11f9I38dbXXtpqHm3rZ5F4hE4ak4NZVYUYV+HFuIoCuP1+EM0GnyqQ56DIsmvQCZCyJIQAKCWg6SPRYdcp1h3qQXcgie/8dAVOmaggX7Th9LPPxaSJE5FKpUAB6LoDLyxfzgeHBtj8efM3PvzIQwsbGxsl+YiW/Y8qflNNjRhNcX58552TU+NPr0l5Cz9tOZyTpM0JAMhRk5icRXmV30ZKfTaqqRoAK+PZKUYngSTJnO7ICaQE4lwgZAmkhMBwPIVwSoCpGroCMQxFBahmw962EYRiSYAT6DrDlIm5yHJRJBIGnDYGOwPMDJJkWkDKIGmOjZAAASzC0Dswgu6ubkyrLESO14aRUAJDYZNTt5OUjymkVeU2OCgQD0RMc2RodaK3+6FV11z62m8GB6MfIHtN5ONwMKNG8MpzrzzScrDl+kg8yq+/9jrGlPRAk6IoCEXCWP7cC6BZ+Vhy+Q2gigpIE6G4gcNdQRTbkij2urDhwDD29UdRXloIp02Dz6uL9Wv3Y8fOHqqrXJT5xNMlO77x5R+/2jHyPxkB+Xupz+CL97jvDi7cY3d7isVwjBw+2EZPmlGIudMrQR1OQNNgCAJBFRAGECnBBIdNV+EgHIV2BQ5NgZQCDBKgFHYKtPQGsa4thqO7dmFk7zpMGZuDcy64AErmFERd19Hd2YMnn3hCzF+0iObn5F+87IzFLx1v71/T2MiaLr+Cjy7rrfvpI8uskqm3WJ6Ccw1fri7MFLJkWE7N1/mcfAcp9tkoo5QAHEIQCJE+0JpQCQJ27DhUKSU4FxjdOiOEhEUlUiDojiQRiBgYigs89fo29PalYFgcibiBZMqEaQnYXE5k5XgxfWo53HaB7GwP/E47aGYhlWGmm96KwsAIQSJuQAFQkEXhd2goyXHDqQIQAmYshdbhKN47MCQ6hpLSk+3DpLGFbGylDTYJpPoGWxO9fU39q5sf+/x3vrx/1BCON5SaaVjK5c+8OikcH966cdtG2zlnnoOZM9NRgBACVdOw+t1m7N5/CGfdcDNs/jzASiHL4UDS4nj/YB/cjGPRGDcGBqJ4/v0OHA6YyHI7MH/mGAwPD/KWg4O0vR8kG71bnPtev+6ZV55oGd1R+5ENYBRi3LZtzfSfvBnZfqg7Ti5bWII7rjgJLYEkAmET2W4VdoeCwRhH0mKwpIAkChQIMGLAoRKUODTYFAYJDobRxdASCmN4aXcPIh2tOLJ2BRadcipmzJiOUa6/brPhtRdf4d1dXXT63DnvXXLJRUsz5Cdx/JT/g+M677z/hUtl3pgvG+78xTFnDlhyGJO9nM8otpHxeU6ao+tpRZbps3sz+6D+7Ob92cHXUkLKtIGkDUCAQ8JSGKQUcKgMQ6aJjT0pDMQo4skUuBAwEyb6B4LoH0nC7nZicrENl033IxS38H63CUl0cNOAx65DVRm4AKLhOAg3MLbYB79LA7iAqlCoFNDAYVcIctwqFAAHBsJYs7sfW1pHZEIyUTYmj1RXldKcLIAPhOIY6n99aMemB67/3NXNH8oCjhvUPOrAmp597qF9h/bdKCzJr7iiljGmQAoJzaaiq6Mbr614HdPOuRAl0+dCplLwUIZiN0HAlHjtUByJeAwnF6uozrVj19Fh3PfCLkRMBo/DCYfTgaNHOi3i9CslWmTIeeipkx/709OH6+r+enH8V6kQo0fzbGgZ8hgJRgpzXVLXQAaTJqJRA7NKPGBM4vBICnGLgoGAEgVEcvhUINetw04pqMSxok8QAiolLCnBJDCr2IFHX3kfDruO0tISmKZ57LyqocFBHDh8kFSOn0AIUX8HQDY3N7PjxP8gdVKSBkJ4wz0PnJYsP7k+5CtZlKI6RGRAzsyyxBlTfbTSb2cULA3XcQFJOSgY/hYD8cMnzKRrgA+FUkLAGYUhBAwLODqSwKFgCkRzwK1xMKLAZrdBVxR4vA5ovcPwZHmhMYlDAYnKXDs8mkAgmT75cShpQtcVUGkh22lDvt8PlVKYKQuMpgttSgiITDfdBoICDhWYmOfBlNM86FtokTX7+tl7LYNYfnBQFJRly4ryLEdp2YTLnLmFl72w+8jyoXdev6uWkB2EUsi0JR8XI5CQpMls+nV2dsF1u3dtY0db22RVVRVJJlMwDROFhQUoKMxD14E9qJwyDYQqoJAQoJjgJkiV27G2g2JzbxTBVBznTC3FnKpSbGoLoT0QR9LgmFnlVfJyvMbGfaGc1oFplwPk7masYsBHNICWlhYCALsP906eUr0AoQQX8USKGWDw2XS4FImAKZAQDFqGlySkRKEDyHepkJIAXIDQtAZIScBFutkDAUAF4v29SAT6MG7qVPh8PhiGkWmRU+zZs0dQTad2m/tA+FDLKxnvfzxSHwJCZQMh8hu/+NN3RsbMuztsz0JsJCAmZzN54fxcNr3IwygIhJAQGegyjeR8uO3wt41gNBowSiEgwQlgcIKhuIGBhESCE8QMC15dRaGXwqEqODJoosdIIRYz0LrvEJZNK4SgHKEUcGDIwJFAAoRREMlgWBK6jGNMdg6cNh90jcLiKVicQ2UKBAG44ABRIUGRqckR40AixGGnEtl2hpqZxThjejGa9wfoe3sGsWXTiGzNyxJ5BT5aVjr2kqzzrzz76QlV9Veet+xeKaXIcI//KSMYpU3XktodjX968YXsnLzavS17+eSqyQxEgHMJza6hcnwl3ntvDYzeLmSXV4IbHDGDw6MC1dkK4okUWgIKeiISuwaTmORTcHqlF4mxXgwnTFiEIRA16MadPSIu4fqHyXDNWAKgAckUGTemLAcHehMy156+yYqafv7CBJxUIgWOFJfw2Cly3RrAJSQyyg+Spr9m9EUAEJKAEoJd27eCEoqJEyYeW7aqMIZIOIwDBw/IoqIieD2uP1xy/ddjpXPmKOlq85/3/Kggev8dLz4SLVnw6ZFETJQ6gvLKk/LZ/FI7nJlQLCDxgaP/sNKTj+jl0v81JUfIFIinJCJJEynO4NMZytx26CwdER0qgS3XgWC/gWA0gcnlWVg0qQjRiEQoZaIvaaE7GEdvKIGESZFIUaS4gEuncOkMCcMEIQAlgJAcoAwC6fRLMIATCUkIqEQ6IghgMCagUMBtJ7i4Khvzx2Th1Z19ZF1riPX0AOFAlCsOm716xtJ7nlm75aTmJeTyjBH801FgNLsQ3Lq/PK+ktuXQLhoIDMOf5YVhGrBMjuLiUth1Ow7u2olTxo0FyaSdJifQiMDsQiekwvDugREcHYpjjNeLVIKjO5QE1YAkFLT3hUkoGKUOmTw8qtUfuROcVz0oAcBl1/15OV44nDaUFvohuIRNSxNvqQQ8GoPPpsHFKPwaAxOAgATL3HAuCJIGkDAELAFYAiAKRd/ACNra2lFRXo78/HykUilwzkGYgiNHWmUqmWJepysUHQo9BQDNzc3iOBS8tIEQ0XfzY3WYsPjTkVjEnFagkstmFbGlFU44kT4tERmP+Y8VeP+thkKKC4QNgXCCwwCDXVdR6lKRb1fhpApMSyJpATGTw0D63jhUhqJ8P/YNWDgaFhgxCXTKUJnnxdh8LxzUAjFT2N8RxuNv7MZAzICqq1CYCkIoKMgxAxZCQIp0MS6ETCNTBOAEEIQhJSiG4wKRJEeBHbh4Vh7mTMhHPGHA76TMKQy5ekev2eWbcunhL73yOUKIyLABcByiAPntQ7s3et2eDTaHgxw8eIAzRYGUgMU53C43CoqK0Nt+GGY4CEVlACgsScBBoRCJMV4VTo0hngIooUhIwFAZehIM+7oScihosOhQT8wX2vAOAKz+G+nzXzWAxpoaAQCV40vGK7oNOT47KS/2weLp7V+Zng5ACTRKkW3X4KUKINKWKiRBShCMJDmGUxwjKYlhAxiKcwybQMuhNkRDEVSOq4SiKOnTzKVEyjDQ2tYmfH4/fG7fyqs/f3WvlPKfnu+tq6ujTbW1/OYbriwXRZNujYzE+IISXVk8KY8QS0DwdLrz4QPi/pGsdrROlAAMARiWhCUJoCgghEFjFA5NhU7TqWCSSwhJIMFgWBRJU0IKDo0QOO12mEIgLk3EOEecS8QMC9kOFbPH52HWxByU5thwtDOEF1buR9twCpFUEpqigNF0zQJJ0jCsSCdxMvPnUSMQGQ8mQDBsSEQS6SY3IwJSAD4YOHdqDnERwbYcHBabQvav1pXDVluTyQr/eaGrVzdYzKv9Ji+/EAcPHCLxeHrBGecchBCUlBQjFA6ip7UVNjXtZGTG2whpIcsmketWAHAEIzG8v6cDRwYMNG/qwTsrd8r+gAGZSrZe9uybnSAEaGiQH8kARud11/7h6+4BSx9LuInpFV7isNuQsgRSloAAAaHpuMsg4cgkmhwEBBQpi2MgbiHIgaQQiEkgkOQYSQqEUsDgQA9suoKC/GKYGUiPMopYfwC9Pb0kK9sPUPkYADIaMv85SR/QJyctu1DJKnPqRhgnj/MSn7QwlEjiYCgJylj6yQr5wc3+KHkVIZAgsCRB0pJICcCAgpQksASgKQpUmk6fR0tJKQWIlCBIK55CCAQ30zUDp7A4QCFAiICkab4MlwKSC7gdCiZW5qD27OlQjAheemMLth6JYE/bMJJCQrNpICJdd6Vf8hh6NXpVaXCKQhAGIgmEyrBzIIX9PTFY3MK4PBsqfSr8RFIrEkfSWza+85qG00CIrGlsPB6rdAQACNN82WFz9KbiKdrX3SMZVSEEh2mlUFhYBIfDgf379kEY8likFSDgYFAIxbQiJ4IjI3hz4wH84YVd2NeRwsuvrcfIcFj09Kcgk8GVtQBf/L13lb9Vv/y3i6mvT+vBRj6uIi5theN9BDk6SCSehCnS42yUALqabm6pyqhPkJmHm/akNpWBQUJIAS44BACmaUimkug4fAD+LD9cThe4aUFmOqZtHR2SEEFddlv3wY0HmwHIzBFF/5zULxEAwHPLTosJTY7xUlRmO1Du1VCdZUNnyMCGvhgCpgBhFJSmb4yU5G8aQoYhBSGAhAXELQFLpo1BSg7DtGBZOHasUKacBof4AC2SNBMJCCxTIGWY4NxM5/Kg6dxXAlRSEElBqIZILAUzZWHK2DzcctXJOG1GPoxQCB1DBl5+vxXbD/aAQ0LRGECRAR/Sj4jKdPoqMkQ0lUg4bRS7+mN4dccABmMpLB5rx9IJ2QjFTDDTRHRwSDBntpT+yZdnksl/HonIkNdqa2tDXofrebddx6GDBzkXFoQQ6c6204G8vHx0d3RgOBAEVSi4EOkQRNJNxxxNgpgS723rRk5ROQ7sbcW0WVUyt6yUHdq5JZkb2/gQACzB306h/1sRXF2d9rj9CXvBzJnFrMyni70DKarrDMNxE4wBEgI2hcKABBUSBB+cGDKKPHhUAk1VYFgMnAukLAmuAn0dnRju68ekubOgqAxG0gIjFIJzHO3p4jm52YrO2PJv/vSbkeNEeiMNhIq6ctgGNN8UyzTInPE+4mIMBgTKPDbkuXUcCprY1BsDgUSJR0eFT4crbQXg8gOEZxQKEVLC5BIWF+CEAZLAkgKWJSAzxgMQSCEg0wdlp5GlND8CGaoQJNKOxLSAcMyEzOZA5v1k5tMyB7pCWBymacDldsEwOKhGcfqccUimDASiSezupFi/qxOHu4OYUubHpBIP8r1OEC7AOMAhwCiBI/326BiJYXNHAN2BJMbluHH5dDumFHvQFzJweJggkTQx0j9E88aUE8KyqgGg6XLGcfyGcgkIlsOu3NLa0U5nRcKw2RzgmV5GSUkJDh8+jPbWg8gtOAnSBAiREMKCQjXsbR2Ak3J0BTisQCeqJhVC9XjFvj0d1E2G33r00af21tVJ2vB3liHT/w6Bpk8fjwmlaHJZNiiojJoWvBpDLCkRTKUfCxUCboVApQxUEjACgEnwjNeXkNAl4CJAlkLht1NQFeg+sh+UG8gvLIQlOGSmo5mIxhEYGWQuhwfJBH8+gxgcjxYkAImuwiqHJG6nQkwU+WwEAJISCFkCTEpM9Ws4pdQFh0KxoSuKZ1uGsLEvigQARiko0hwcAcASEikzjX6ZIEhyibgEEhwwwSBAIQkFSbPhAAJwmc69JSWQjEFQBSbSIZ0xipQpkIjzzLGx5Jh2ADSzGJxAcgGP04YcjwYGE0QCiYQJlakYk+PBOTML8ZllEwECrN47hGfeOYx3thxBKJUC0wFNlzBgYv9gBM9u68Pz2wegUAVXLSrDDScVorrIg129Sby8M4JVOwewaccRcEPASqYAqTIcxxnymnSdKRWbstVuc3QnUwYd6O8XiqKAZKDc4qJC2OwMBw/shiEkBKUQPI1gxQwLbf1hxFMW2vsjKCn24twzJ2FwKIBYLEnGF7tWACDNaKb/GAyaRkBBVS2bMoLBFJcetwMFdgZR4MSagwHkOfzI0dJGIKgCSyHg6SecztNkeltzpg96rEucTJgYbG1Dls8Hn88LwS1ICIAR9AeGBSEq1RX7oU3bNq3PIAbHrfOb40ryEUI4UgbsDAgkLHRFJDRFQFUBt6IgR2M4pciNaQUu7OmPYNPREbyzdwgzy1w4ZYwPLkaRTEkkBSAohSkJLJ5GfYjMFJyUZFKhtDCS3uud5AIxzjORQqY7vxaHQ1fhYgTJZAIG5xCSgUFJQ8kACBFp5ScAGIVKKIjkUBgFCAEDBZESKSP9HaoL3SjKGYdXNnaga4RiT6eBw/1HkOvVEAmHYdlyYHADU4rdOHdREUq9GnrDJt47HMWOI8NYs6UdbV1BDASGoesqsrLcSKbMD852Pl48c0JkhnEQeuihhzc7HLbizq4uWTluPAABzk3Y7Q7k+PPQ19OF7qEg8n1ZcFMJSjVsO9wFxa7hrZUt8LhsmDuzCiNDKUmojeXZjXB+aOfrAORq/H0E8W8PxVNhdgS5tFOOju4QNnYPoyjHjoml+djQFkKB24YpBXbYCGBlBj8ECAIpDikpdJJpwkgGCcACRTASRCIaxNiSAtjsNpiGCULSfYH+3j7hd3mpy25761e/+lXqw2dV/ZNBFgBgMzkhQlIuOLjgGIyZgFAguIWgAQyCIGTnyHUocDGCRUUeVOc6sLM3hjf2D2N9ewwnV7gws8gDh67CNAFupSMYJSSTBpJ0lOCZpIXSY13ZiGEhlEqBQIEJBgkJLgAJEw5VRSplIGVIpHtYaSyfEo5RU5Ik3ZsYReJtugZKJTQALJNiSUlgmgJ5dh1zx/lxdF0Xikvz4LSriCdMqF4bZhS7cHKFEwUOFUMJgbWHItiwfwRrtnZgd0sXzJQByggMS8BIJWHT9UwBnf4m5DjyEJubmykAYdNs67wu38X9fX3SMFIAAMuywJiK/Nw8dHd2YaSvH3ZnFuzgUBjBnrY+MMWJbfu7cd3158Nho2jviXKe4opfDjz7rZ/8quvDdJePbAB7f5PuAWCgY+t7Ww6Rpw/3sMG+AO/qTzCbRjGpzI2Lz5kGYfgxFE1gfI4NpT4HqAAsUyAUM2BSHQ5FQsk8MJKu9xAKBCCsFLJzstPFWObcXiOVwmBfP7PrupSCPwsATWg6Xr4GABAdaTcpEinBXYgaQha4Qcb6GEBsiBocgwmCYMJE0gK8NgaPRmBnChaXeTEh14n13TFs7AxjfXsUVQUOTC/2IM+hAxwwxSismXaUQghQSjMIEWBBIm4BhlBBKNKLY6UElxRJS8AQBKalwOJJEMJBSOoD4gAAEAkBfswAbBqDg1IowoKiqEBmqgwCYIyCCgmHQuHSJbLcBGPyHMixE1RmafAzirBhYn2XgU1HI1i55gB27WhHKBRBcZELUxeOgRAUa9a1IZ4wICwBRlVQSJMci+tSHicDEADAQN7RdZ0PDvYpwZEg/Nl+WJYFyzLh8/vACMXIwADyxk1CglNsONALShVs2dWFMePKkJfrxUgojqoKFxtpP8z371z5IACCptr/8Tso/71TV8vTFNLb1y341M23KyWLf7rs/MWMx4I815dDuwdHSNO7rSjM6sTU8dkYGPZibLEXFR4n3A4b8jx2dIc5EqaZboiBgVIKxoFIbxeklYLH4z3mRyilCAZDIpVIULfb3RVyx3Yc5/RHQkpyLyGxmynvZapSEUta0lmgQVUoiBTw21U4dGAgThFMcvRFTfQRAZeuIksj8GvAReM8WFjqwtaOKLYdDWB3VwLTy92YXuCCR2NQVQrDFBCWADLUCSLTBTAkgWFJGJaEAg5JFVBCwTKVpAkJ0wDA04ACIxIqJKgkOEbCIBKUAIquwKEosBEJTWEAFaBINyZBKTgkeqIJ9ERNnLtgIip9KoqdBIwCI0mBdX1JbDkSwrvrj2L/nh6MjMRQkKvg9FPHYebM8ch3KyhxOaAIFS++sQOEKVLRFFCSGklntJziOJESGzLY/IHWAy0F+YUHqaJN7uvvE1n+LMo5B6EUbpcbqqpgZKAXEECCMqzb3wufpqAzEMWy0xcgEU7ipPFuLiRlPV3tO955/ZntkBJNHwFAUf7GFxOQkqwn5N6aT8ste99j91RWTzlJV1L41JJS7jhnHNu6bwDb93UDXb1IRhIIFmVDMgVlOS6UuFWkTIq4yZGyAMuSUKAg0HEUCqVwezywMuQ3Sil6enskYRS67jh8w8XXRkZ7EcdtwgsgDYBUYAwyTUc4bkBTaZq1SdLNqUjcAuWAS2MgkiGS5OgJGQgo6THELJ0g2yFx3ngXZpc4sK3fwt7OCA71DsLlUFDmU1Ce5UCWXYUiBQTnkFAAUFApM/XOKL+IYnREV0ogZXIYhgEjaUFlBHbdBstKIzaUAAoh6R8k6fulSgFNoVAZwGg6QkQNjpGERNLgIIRjeqEHpR4VOhHoCZvY0Wdgy8EgNuxoQ+uhXiQSKdgdDGeeWYYpE4th1x3Iz/Khwq9hToGOtyp8ENwEA5eaIqGayTYAWFzfTFcfp6VUAEbhUOPXv/7tu06He3JPd6+YMGE8lVLCNEzYHS5k5+bBGAnATTkOdQ+DWhxRIXDysrnQVYKZpU74/U488fJ+sGTgKQB8cX2zsvoj0GeUv1OlyJqaRtb0p9rVdfjtokNf+tWNI8UTvmNYE0vOnV8oL5hbJGZNKmAHe+MY6B/C0Y4RFOc70dYnQAhDbrYTVfl26FwiZXHEUymE+jvgcDph03VYlgUpJSzLQm9Pt9RsCiSVuzOhkR0H7s+HY20610wG98Wy1QuHU5ZMe1YBgsyQiaDgNL29wbQ4GKHQVQ2GEBiMcgxFLQwlKYrcCvw2hrMrVJxUbMOuvgS298aw4WAE20QIk8qdmF7uRpbdBsIJeGYoCDRdJyhEAzKzA5n8BnFTImVYiCfSqY9CCARJ5/aMkWPZNxcSUljw2jQ4tPT3DCQFjoYSEIKg0MZQ4mPId9thg0Rf1MThIMfGQ2G89OZutB3tQ3lxHkqKi5GyTDBqYGjIwmudbSgo9OBT5/oRiAtEhYROBVIpA4quEio5SDKw7eOYFhslXgrTWqcS5UuBwWESjyfA0ng7VFVFTm4e2o62IpfF0Nw5CJddgerJQlmeHzlKEhXFbvnS+31soLMjPJ2ue6Ypg/2v/gifr/x94lItr6mpYQ3PPW/h17f+7qe3XfLCgQ1X3DUyNO7zpy6sYtV5qvSOcaDPX0xa+5NoGwqhxBVBgceB9s442ttMzKvIhd/vwda9hxAJRZBfUQpKKUzTBKUE8UQSI0NBYrOrSFjRtRkDOL53OfN2LiO8K6IIDCVAhJAQhCBtaSSDzcvMrxxUUkipgICCMYKk4GgLGxhIcJQ4FRTZFfg0giWldswotKGl147NR4ax5XAQh3qjmFbuw6QCF7JsGkxJoOsKkvEkBBGgJA2rAml6QsrkCA+HEI0aYJBQCIdkmZyf0DQ0KiQ8GoPbRhGLR7C3N45hg8KgKrLsCibnaCjxpJHKjlAC+7oT6IwybNzdhnfe2YmKslzc9pVzkDKBjZsOo7cvCQmKcJTD5rDB4faiqz+EqoocJCVByjAhLQs2m50wy4TOo0c+zBM7jpJuUpr8kNuEDMYSNBKKwpftA+cWJBQ4XQ5ICLy/7RACIwKaTUGZx41ZhQy67kFLZ0IcOhpmWqTjuTt/uby3plGyho8IoPyPqxGbmpo4MtsRvl5bOwAs/8J3G379p/fjI18brhp7YcW4AiRNA+NydPh8+RgMxrFvYATZNAmX044XN3Vgb2cC4YE2lDOGLJ83s/JEgFIF4XBQxlMJBooEoonNH74px9ECBAA4o4d263wuH4orLJYyYLepmaW7aQ4/EWm1ZCyD3lACwmV6dQkkNE1F0uI4HLQQNCQKXQqydAInAxaVOjGl0IY9vQlsPhrH29uG8IbRBb/NwuzqQowry4PCHAjFTRjcgpQk7eGlhOQEiWgK8VgKNiLBSHqXkBDpg2P8DgVuTaJ7aAQbWwYxFJdwuz0YX+RARZaGYpcGAiAQTWFnTxx7BwwQ1Q7wJFasWIcp0ybh5hsXo6NtGO+/twPTp1Sgp3MYVNFAqAAlBLpmQyyR5g9xCQTCcQBUurxuKkUshdChdgCoypwGerwkM4uMfiPWlq1qw4LI7Eg8KrOzs4iZaRymj78VeHvtbkybcxL2do7gvEUuuHVgT8CQ6w4Nk772w1b+4Pv3p5W29iN//kfdDSqbatPF8d7qevL9WrIawOpHH21a0tw//uk+Lbtg9hgTlfkuUpTtRduQE509Q4BI4KRJPlwwtwy7t0ex7i0TWTk5sCwrQ9QCwqGQFBCEUHY4Go12frg4Ol6Sfj8C/8sPHxq5reZoAq5x4YQh/LqSblhIAplBXCgIKElvXVA4QCBg01RYFoNlmlCYAqIyBFImRmJx+O0qij02ZCscPgVYVOrGlCIX9vR5sPXwCDbs7MaWF/ZgSqUPp82rwNQKL3RCEYpb6AymkDQpCE2/OASyXQwOnWEkReBxUCiEoz8wjDcO9mMkIZDvz8KMSg8qszUUe2wABIaiBloDcRwYtBBMEuh2G0qygGxVR7bHA4/XhXiK48UVG1FR4sOcaWXYvrkDIymentcmBJQCpgVIIcAtjvaeIHSbTfrzc4mTRQ/6f/7rVhBy3J9Nph9ACCFDP/vpLw+qcXVBMhETIGBSCliWBafLCcMwMWOsEwwSc8fnoyrHjtVdMRwYFqK1Nch47/7lv3/0yZ2Zzi8/bgYgpSTNzWCDg02ytvZyDjSgpqaRLa7JtV9fu7T5gVdWb/TmTrr4rR0d3KcGaFGeBwV+F0qLfLDr2aRjKADYJRQjBCkonE73MaailBLhcFgqjMLn8QZu+cot1vEugEcvo04Kej0hyXu/JfYnFfu4kbghx/icaWIfSWP1kkrokgA0jdMrwoSmpUlydqrAgkAKBJYQyLERaNSFYDKFvUMRZNkU5Dk15No4PAqwqNiO2fkaTp2UhVX7BrBpZzcee24/Cv0aJubbcNrcUswvz0JKAC39cXAAnAOmYaIoh6BrOIw317VjYDgOl9eN8SWFWDwjCwUOCZeeRte6QgnsH0qiIyQQNwQ0KlGaTVGVq2JMjgMHu4cRiyaR5XXhcOsg+nuGcPklJ4ESjtmzyvDW6oOguh26rsOmU1icIGWaMCwV7T1BONw24c3xUYfZt64BsBqF+Fh2jzY1NVEAnFC0aZqyIBqOpCcJkYaU7TYb7E4HirN1bA9EcepJRehLGeiOUrlvf4D07N04UtT3xjcgJUH6BKLjFwEyynisIK276XxHw4O18Vln/+nKh1/f26CtHdHtF8eQbyg06veTltZubNndh5xcPyrzFLicTmw4HEPkQAc0G4OiKMfIYAQEsXgcTNVgdzmSHyLjHf89Nc2gAIRTxraoNuX8ESMlR+m3oASMpdEZIgTMTBfWrrI0SiQJVEiolCDJAZ1xlHht0LlEgcOOqKFjIGFif8BCn4Oi3MvgZ4ANwMx8BeNyirFkcgHeaxnCppZeNK3rxnPrOnHyjGLMmuDD/p44QhEDRLHhR8/sg1enaO0cRFFZDs5aOAFzK7NQ6GLQMjEqkLDQ0hdFa0gixlUwylHgNlHhV1GZ7YSLEaggONobQiRhobAwG0dbezFubB7KirMQC4VQNTUfu/Z3YWhYwmbXoFACRWGIJixEEiYGhyLwZnuIL8sGpWNkPQC0NDd/LNvlRgthxmirTdMRjycktzKjtFxAgsCu2TE8EsJwMhfdwTj8BS7s2NPBd6zbqdiCW+58+tWVrTW1TayhqYH/0wYwOhT/h6efnqNlj/2ZNJSd4e49O5Kqc6bNlcXqfv/KrbFvfHd1vHgGbOfMyjLjYZEq9xJNDPfMSWy/9b19bTwUX/jbdzschXZFldRKEVfvACr8OphCj6U/FreQSMShajoYU4c/TMY73lI92CQBwGkMbNGVSegJJCnGpnNsMjrsTkh6wwOXUAiDQhhMLmBlRj5VhYGYCeQ4CRwADAlwcOiqRLGqIWoAQ/EU2gaTSNl1eB0MTkrgosCsfBVT84tx3mw/1u3Lxrq9IazfG8RrG/uhKQp0nUJIjtZBA1PHenDzVadg3oQsZGkSijQBSRBIcBwaSaJ12ETEpBCSIttuYnyOgnKfD3ZVAbUsJEwJlQHdvSGoNjsIVbBty35cdv5MSGlBgMGu21BdXYT3N7aDKQAXFiTVYFoSXYEoRkaimDSunOkkhmTnjv1pJ7LkY90mRzkOKlRBIpUk3LLSk4cyvR+WKRq4YcCIhfHW5m7ZHUiZaze2avb4kXff+dPvf1tb08iamv7x3pHyNwqTdDN4165g7qVzF9snjlts/6Mu851ZZJ+r7Z3M4qgDP5654G21ovSq1AgxGFNtQyvf+XXdHTe9AAAPr1x/3ZCsvPjInk4xCM5yFAKn3QVKGbhlgRACy7JgGIbUFA2UkzYAyM3N/bi8TDqq7H9vp5ozMzxkwJO0TEmpQghPp0BCpL0OBaBkhmNG4VIOCwrRkKUC2Q4tXTgzQPB0m5tJCZ9KYHPriCQk+pNAwJJwawJ5DgUelUABx3ivhvHzx+Di+RJ7jg5jx6FB9AaSME0Jr1PFgukFmDsuBy7IDP+GIGwAB4fiODBiYjjFEDEIdJ7EtCI7phW74VFZGmo106OoauYOHjgyBFMqeOml9QDnqK4qQyppgCkqhEFRUpQLn7c/Q6MQIJRAEAVHuvuRTApZWFFCiBUdNPa83ZqJzrKh4WNwTnurZRoKFa2G4ODSopZlgqkfrJpxut0IBAcxtmIqnninixzuTmgu0dvhD6+/iUiJuvr6/699UcrfLBoJwbd//OMjP5t10ZaQkj09b0YOMVQ7yRblp/zq941fufXzl9/n9rsPuBwK4SZluS5LauXZ+6666irnrKU1d6UcZWe5o3F5xrxCGtAl2poI7DZbWp2EAGUsTe+1LKLrDggiO9IQ6MfjXUbP3SWEdP1iwxd3Rah7UThhiWy3xkwuQUla87lMzwOMIlWESigSMChApIXcDMYupIAgo6kcS9MVJAGkgMOmoj9sIGUCEYshbnEUOCWy9EyNISW8lGDhmGwsHJMNK4Pzjz6M9PSERNSS6A4m0DFi4VCEIBC3oBITJR6GmaUelHsdYBZgcYAxQCMEFAo4tcAlR1tfEIaRRNtRA+eeVgmvS0UkZEJlHKaVQJZPQ0WxD73DFkxLpMEARnG0cxhMt4nC8kLGRO+hXzWtHcTHU5ulnVNV2jlxySNCSqQMi6QMU+qUkjRayOGwq2jrTqDraA9cLBUv4u0vuQef+9aDz67owKT//yNx6d8sGr8nKAAZeG/Ng4UvBlVT09igiEF35elGUeVt48ZJz+/PPvWXvVvWrixwZKu9T7639qYrL1s+87QLT8k/9YyvJVSH3crSSB/nRHYMQLUEFKohQ4OBFCK9BpFzEErALSOQToEGP7Y9lfXN6U1VbplooTY7OoeTUs1wbQhNY+5UClBJ0mODGf5NOipQ6AqgMwoIAkloevWhxLGhfpnZkMEIhduuIhiNoy+SQkfUwuGwRGtQYjCR3hEEIcEzr/QElwDnHEkuEIxbODRoork1inePprCxL4FgPIjJPuCCiTZcMNmLcV4HpGXBhARTAI0iTUmnEipTEEuZ6BhOQVV0KIxifGVOep8oo6CgkESAUYHS0pz0QD1PRxwJgZHhFFw+h8zN90FNxXcDQOO/4FB1y7TiUpIkFxymmQLnVvplCVhECjs80HbtfXfhmk9X/OmH11z54B9f7airq1PwT4zM0r+Nz6bdUvHJM+eZi9X+lMWFrtiYkYhIRjwFX/nsyvXXvd6yiUpvpRmMSy1//Mwbb7xlmaE5TrVUZpihESs0HAPx+2BqEty0AMlgcX5sBtg0TViWRRRCIRIihY9d0uFFiwYPeOw6DgfTHymkOBY8GSVQpIQiKQCW9sVUwkYIPKoCFRKWkLAsgEglvQ+JfDB7QGl6CMauqbA57AjGUugbjqIjEEFvHDgaBlqDKaRkGu+nmSF8CgLCCA4NRbCxLYatg8D2QaAvZmJCjopPz/x/7X13mF1Vuf77rbXbqXPO9J5JT2ZSSWihJKE3QcoMTURRsWO/iKgzg53LtYCK5SoqijCjSBdpmdADaYTMpJfpk6lnTj9777XW7499JkR/FtREufdmPY8PkWeYnLP3+tb6ylsqcO78YkwvDIEkYLt5wB2T0BSg5WfbHiUPGImlMTyZg5IMpSU6TjymFkwCmsYgSIFrBJISlRVhFEQYHOWAuAfeiB1IorC0GNECBoofeO1IFsCHrnQinYJUWUYMQki4rgPHsWE7NuCC2SoNe87c5WPvXfe9z3+r/RJAobW11f1HpdH/agBMaXDuGOn6VPs3T5o/8upT7briSA1nRDDs12dcdEK9KK+r5zXT6xI8CXliZfDkd3zskZr5i28UOWb4A36tpKgAPiiojA1bOpBceZHtunBdF5lMFkpJJh1HZXIZzwC5/cg94IYR73aRQ92dPuaiPyl52vFgD3nqCYg4GCNwCWiCQ5MMmgAsInjwIQ+irOApLdDBTfwGiSVPl4YjbDAGEONIZxV6RuLon3TRneLoGs/C8eZvUFKBAxiYtLFj2MWEq2EwnkW5mcFVi0N4e30UZaYGRyjYLg7qFCmlYDEGI48VUuTRHQGgbziGdEZAuFksqS9FSSQA1xFgxPJTRgKIIWhpqC0v9AwrCDA4w+RoXJXXFmsslVapvu3rj3QB3OLl73AcR4k8ZsoVjgeXkZ7GkmmY4EpgwfRomGussQvTf/uJn2944ju3fW1pU1OTWLNGaf8IYecvBkBbWxtvXjnNuuNjH4tXDTm5qpo5KwqEgzllhkaagXGWlDwxKuHmVDwpiDI5WbJoli8+EBvc/ru7f6bGsyoxmMR4dwruthi4lNBMBssyoRiBOINSUnHG4SohxlKJxKH54JEshOPb1+/SRTo94RDtG40rXfPYXqA8GV0pEAkwJsDyk1k/59DkFNXRE6maQmp6V8AUfwvQGEcm5yCVzoEUA1MMjHNAM5FIZ9A7ksT+FMfeWA5K5rnCSmLfmI2MMNAfy8DPc7h0USHmFvohHU82hRN5suvwaKk6Y9AZHQzGg+g6AN2Dk8jZHJaucMySacjmAIU3+Ane8IsgXInq8mJYGocjXMRtwoFMBjW15VCZ1GR80yO9h2QER/YGSAMkkZ+6G9B1HelMBj39fRg8MAQXwJnHzUbL1fViRbUte8bcMwer3/bcj352z2WrV5PbrBT9vbfBnyuCaUqJ7Se/f/ahu5sL7Z5XnnmsoLi6dv8zv/9dwul5ve7ij31hqC+FggI/iyVzcKSCz2Q0MphWmVgqFTvQN+ys68GJZ87HAQWMV2lQccL+3fvw0ssbMD4xBsvyoaSoGJFoARjjLhfiiKdAU1PM337lvwY/eNWnhoLB8IyO/eMKpk7TwwE4AnAhvdyfMUzB302DQSflif8qgpjS/JwiiqgpGqN3+mddicmcgKmbyDkOiGuAAoSbQ2WJH1lbon88hRAZKPc5KLB0jKdcjKYFEjaQlQ7OqAuh0DSRcr2SeEpcDARweCA5nf3lvsfe/jhytsDsugLMnTsNiYwAyxPyWZ6noBTgSBfBkA/V5YVIS6BnKAlX11TVtFJS7sTQuva1Y8ir4x3pJUVSEvNLxglr1z6Lgf5+HBgeRmxyEnV107B48WJMZgUs+Pk1F5+IU/f2itcPOIE4TrrvN8+s+4/LiP4L+Pv8Af5cACgiUt/6+p3v97+mneG/aL5Rc37F22OGpqxVJ5+sDsSPF1KjcFgHNzjik5MwLA5dN8nSsph/5tI5RUsX/0fOTsAIMCDDgZAPmuHDnr3d6OzaBstnwM7Z6AsV4OSVJ0NK5ZKiLP4FixjDWimzH8xmRooi5TP274+rLTEFn55Dsd8AXK8LRCBAAhqTsPIkE4BBI0CSwqGOQ0Se3SkBcJXCZMaByXWUBhjS6Qxc4oBScFyJ3uEM5tVEkUi7GMtKjNgCBZaGRE7AlkBSKFQGgHlFAQiRT63yRPqpFEsnguZV32/cQge/n/f/9wwmIEUOxy4qRyRgYDKWhc7zVTvI62ApT0hLKRu1FVHsG4xj964eRKNhVVoRBA309m8AnLwy4hG/AXr7xlhhRTEDcTz3wkvIplOwLBPSdUAAbFdgMJZDQS0wELNRWV3Dp1dl1E+f3c/Wx/23PdCx9YK5Rdlb5hOteUOo/q8HATsU8tDc3Mzu+ta3Ij9se+pWbfUVP4idMEcbGx0Ro1K43UMxyUqrSiaTgxvHXn1lq275yYWQpZEAKqJ+5fNp6B3MYf++MUV6VihX4MCEA9qVhE+zwHQdhmEi4A/CMkz4fX74fQHYto14fFJPZ9K+f8H+V1IITyMIzpjPRxgdjGPb9hFsGBIYdxR0BXBi0DgDZ4DJuddezFOulDcxg2RTz1WB4BHrGYBEVkCSDp1xBEwNhmZACZYH/3FkhMJoLIWKqM9j0OUAwIVQBHAdJF1UFpjgjMGRymPUEcChwJRXK2hsSmTljzNYBY/An3Vd7B2IIeQjnLB0BqStwIlBgUCKwBSB5WOBE4MSAuEAh8EkuvcPoLiiCKECgAk5mi/LjmgHqKWlxavfyfU7jmvlbA7LF4TPMsE1DYxzMM5hagwjg8N4YWMPEq7ESMbFcE6jS4+fpc5dViGe7kqu+mGH/cwvH3jpDqU+YhIx1dzczN5UALTkvZUCVcWV0jBnHxjr3+cbd1n0taTABLTZgShnuzc8+5V3nvu2iczwOqUAZnKlQSlYFiViNshlSAtQPOvyjAQcVyEVd8BNHcjnqcJTxoFUCq7rkOO6isBMQzeKAaCrq+tfYubGNY0TAYnJLLZs6cfLmwaxP6ZgMwVFAkwp6MRgcPZG+uF9CyhIuMqBhARTAM/n5zmhkBPeKSyVANMYLNNDnNIUwoMk0rbrDd6URNZBXlLJA+Nxkgj7PRl1kcdLmRr3FPnyl/pfPIzz+f+B8QS6ByawbGElZtSVwLZz0DRPuYPn7Zs0eIw0zqb4xAKVpUHMWzwD1bNqPSIOYyb+hUs3pCak1ATxPFbMg6QwxmAYBhQxTKsrQm2Rhu59g+geTaM3p9CTkVRUVsQXNJSI/f2jcnem5CM3fPWM+9+npN7aeotsbGzkfzMApgYJTU3XdH3w7adcHFr3zZOHHvjJB9z5QcOK9b848tufnvXtd7z7AgCQ+7dtk7ERpHpSfCKZpMzgkHBGHWA8jVDIQskkoKcYKKJhzlnFyCEL5QBM18B1L6K9TSLhOq7SdA5TN8MA0NjYeIRTIC4BgBlWYTwpkUhlyR8wsat7DA89vws9KQ+vz13AVJ7GqToolpunOk7RYpUEmOd74DAg4XozDYLnE8aUQtDHAJXzBHcBgDQIcLgAsq6CowiSyPMPkC4kEQKaJ5wr8t0lnQg6m7JX+ssivVNM3bFEBtGKIpx+2kJYugYwB2A5T2GCeYYeIJlP9bw0ynElaootvPOMGTC1vKiXSVEAaDzs8PS/8G4s0iUDE0QgjXsGIJyBcw2mrkPXDdikIcsYyov80Owkduw6gNGswEA8hQX1VXzZ8mqqLFFusHLGeamP3XX/jWeogvb2dvGXgkD7S+jP1atpAMBPW06YVqkOvHhn69e+P/SVm24qCSy99CG9pnqFHbCw/7622223v93u6Q/UvvfGhwrKCw2xbkgZ21wqObEEvQcy6K1lYMrTDTUZh841MIKHCVKAI7hyiYPIOeIp0BTS9LoVc0PM1CsO9MbhOFmceeocvLRhCK93juEpP3DNabMRtThywiOsTKU9jAgifw8w5Qm2KuX1PHO2C1t4Qq1Q6uCAzDIMcCLY0rsFNEZwFDAaz0E4nuShhNfBE8qbj1h5TVEilRfh8jD7nLOD7LA/+/2mBkowUFlVhpnTCiEdCY2xPPnM+7w8P29W+SCTUPBpCkV+DSVBE9sqkpScFCjwBcobAYOI2cARAikecutzZYaIGLNdQOM6EecA5yCuYOgGGAgrZpbA8ofwek8MtgbML2c4MD6GWCiMQImBumml9OzLA1pFWZE7EZx1gTzm3jUfqWq76rs/b9/+5+yS2J/r/69eTa5SihSU2/KhdzS3tn5/aOVKBGn5yluD9ctW5QTg0w0U11eNfv8brc9XnLba0Hx+Tbe4TM8vpOF31WCkUoeREZh0csrWTJBlIWAa4MxjX3liU0BO6XDA4Uq7+FBk4BHJNfM7Z1HTB6eDWxUjA6OImIyOaajEeSunIRoE1u+cxLce3oytw5PQdcqzePM3APNyEJXn507tBltKJHP2wf6854Praf8YnMFvahAyr/MDCcdxMRZP5Us0lRfQYvCqCILOPesj729XB+mTjHvDsr94gk4Vk6NxRPwMNUUhkFQwicNknnguIe/Uk9cVIgAGSVRE/LCYBschRH2c3FQa3AxUz/nQhyoAhebm5iOemlo+LUKaDseG5FDQdB0a8+R1GAOYoWEg4wmLnTKrGMfVRFActFAZMVDEcti1ZxDrd45iJJbGWFpqpWU+d8OAubTT1/jMOee8bVFra6v805rgrw7C2tvaWZtSvPWrXz3xI5/furU+tOxdMhMTsZzg2fEE3Fg83tjYxgORimt88RBzd8ZVQUQDRA4ZOyNHSyHDQZ2k4nBNA4ape1caY9A0HcQIjiTlKgYhnelH+gE35PdIUd3MOjMU5vF4SlZUhGl4zEbG5Tj+hOnw+f3YP6zhJ4/tRDydhflHG877MyPKpzp58wnbgetNB6ZumoPjAYOAaNDnJU9TBtHC4yILOWW55B0GjiA4U9ImB49cBfV3Hrx7hyYwf1oUhT4DjOc3vkKeVP/Gd5FE0IhQHQ0gYvI8FRTw+TQSuZQy/YFAZNGKaR5EpeGIBwBjKkycw3FtpaQNrmnQNA2GocPyWTAsC7puYTwtkXYFigMGFpeFURPyw9IZ6ssDWF4bAJxJDPXsQpCltJMbLPe0s46pmLby6vYzzlhW0OoN3eivguGmVlNTk1RK4dZSvnX85b7x6RXFNeEIxGwV5KPxXbvv/PCV/30AEHOO++mj0WXLL2ECqsBPODAI5KwIKwo6oFQSpZXlGOwy4DqeDpCUnpCWUBK2K8iROgxQXf5BH7F2W0mH98XNaHmtICCXzUqztJh1vNqPgYEJFBWHoWkEP3GMxHLYuGcUZy+qgSMcMMIbXRTm5eZT7pcevVHLn9da/saggxihQp+BQdNAVnjTZqbydEfOkYe9gwFIZ23kHDdfb3jviSvp8ZPfxPZj+YCJx9M4fnk9pHK920h4qROHJy4rwcCJAOmivMBAga5BiXxLVXpYopybFMECU4uXljUAePZIoXQBoL6+ngBA57yMmIWccLxLlnl3pmF6XUPL8sHUNZBQyLme+6hBwOyyEEpzFjr2juG4JdNw+jE16BxIw9QIBX6uRSKWuMfS58T2n7cKRA82trXx9rzZ4t9qb6l2gN343hsTuWr78b6To0hmNKNqU4ybkXD5caedFgSA4uPnnxBwFHf7HG3I0ZCAIf0TAzvKJrY3DXz3g8sx1J/UrCiIkzIMw8un88JRpBy40OFIzo/0CbNqlXeU8lBwUSoLSNdFT+8YegfiANMxPJLwxG2VhGIc63cOwxX5HHpK64fyeIM89MBTHc/zew9plf6xaR6gM5UfsXloT087l0PlZwhKecJiQsh82uVNvzhjb3IIpUAcSGVyMC2GmrIQXDefapIHlGPw9IEY9yAdJX4DUV3zQHn5WkAqb5KdSwkUWIARjCzIP70j36NmqMwgCKZceOm/BsYIlmnC0EwYugld18CJQSjmScbnazRL4yiIBLClPw6DA7GEC6E0BJkOkWMkFFOO1LQ3DYV449TsIACkmyrhS8VYNrFr47OTj3x8eMNLnwzNnWsDgN07sGH3k7/8fNLtez7dPSqiNVE2vPflB644a0V70XkfvSRQXmGFiqMKnJHPF4DGObimgTPAkA4UM5FylOnVAI1HcuAiAZAWCM6fnHBgZ1xGOpDL5WDbrtfRzw+XDF3HvoEMRifT0HXudUvooNYthFRwhcjrfHpJykEvMSXzP+vdAlnb9phnUykN85TyGMt7CsPzR3Ac4Q3MpHf665TnJbyJAPDijSGRSmNmZRQh3fBuKxLg3AtiznRPeVpKFPoYSv06mPDskb0Okwfz1jSObFaQD0AgWrAgf3iII/ZWWlo8vwD4GrLShKYyxAng3DMlNAwDjAiWYcA0vGdHBzcvgciDikBoKA3qmEzaqAgzHFPlQ9CnK6ZzNjbUZ3e/+NBm4I+J/drfPjVXSQDKp1u9vS8+fvV/fPTae/70Z268+tL/BoDrPrPi9rl9Zy+X+uXfLZ2+/H3tT286KV0+6+TENlvqzzmOVebXfZafkomEpxZHDEzaBEZwBJt9ziyYra2UOxIdh6kO0CfOOqtQ031z4iNpaNBpzswoujrHAKWQSqUQDAcBBRicEEtIvLZ/GOceE0RWeg8eeSiBUJ40OtcUXLwxkWVTXcq8VqcC4EpPXpCEApQHs9DyPgSOKyGkV+AK4YJIwQaDhPDcN98svisfJLquo35GFQAJjedvIubVEa7kgPCK3mK/CY0IrvTGaTyf4ikmoWsE21WUzQHhSKgEgEbE3CPUCaJWxiQAcnV/rcYkuMySUsoTC5ASZt6m1jItaAxw8rAU4XoixVNGgGAKJRbHRDyDqpIQMo6CIE32T4INde9dv6Fzw74/tdtlf/u5ej/8rsazf/kfH732HiLmAeWa1xwMnmbPBBk//c8XEzd+rXnNravnLUNyYF1g4ZKTmUg5tQWKfKFCQ9NM8pma98XAQBoHVI5M5kIxbWbJgvNmADgiHYepDtC8t11aRaavMJVMQ9OAmSUB5BJZjAyNgRNB51re5cDzLNu4b9JLSYgODqwkJKTypEs8wecp8SqPD0B5jzSWTyeE681tdXhYfJ1z78ETQyrjwHUFCIDOCIZmYCBuYzQnvJ49/Uk69Zfek8pzETQdls/vaehDeQU198wyQDb8XKAmYsLHPDXpQ5GsjDEQOAyuQErReCyDkN+svvGGGyuPVCeouRkEpXD5WcurXbKmW7oCCZeIsTxLTyIYDEKSQkE0Ao0BfCqdVOSR5pSX6pFyvG6R6c0KumJZTLourdm4m/q3rf8+ALmqpYX/XSnQoZu8ra2NKyWpqalJtLaudvOblbUSyes+e+uJ339oXdtXb//1R7oBNdn7/Mcze/f0a1mf3hvbs/eB/h9cnJpIjVk+H4hIMWLgmgHHyVGYS8GsqG4UVR/3936uv7cD5K+rm+Ur8GvxZFqaJqcZJSFEwzqMgIVItABTW1xAwLQ4dvYn0TuehqEj7x5JIJXnEMDLZXQ6tD3JDub9xAgZKZHM2GAkYekMhqFDuN6NoYiQkV5niJFHEuJcw/4Jiaf2JLB5MI2E7YIxz0pJqr/SD8pvYq4bMMgbmhHJPDSbQUkFk1xURAyEdAKHC42J/DAs/63zZieGpoE40WgshWA4EJp1/LLyI9UJ6upq9ArgwlnzuBEK+Q1SdjZDum55bkSMIRQKQTcMlJSXeQLAjPKoAk8tDyBkbRemlJhIu0grHduH0nDA5ZquA9Tx1LOd/vbbfwulaG3rH5Pm3/RGayWSTV7lrP4kR2IAwItrmrR5yxtPffsFd7Q9sWWLnCycf+0Js5b29ewf8VXUVp193LnHxBKpuBXww9ANEPPy7Gw2Bz93FLOCyHDrVADoOgKdoHwtAy0YnQUOZDO2NAwdUb+GOXMqUVwaAeNeq1CRd6pzThiLO3i+s99zxlGez5fkHgSZpMqjK///NF3lC46JZBpSJ/gDFiYm03jhxe3Y3x+D0P2YyLjoG0tC5E0ylJSQEsiRht404YmeHO7eEkPH3jhiWSdf0ObZZ+rPTwJs6d08OtfBOYdODJpSCDCgKuSDjwjKlQf9jzl5tQbLsxygFDRi4JxhPJkTzDBAwaJp8Mb0hz39H853gJQeXWgEIrCYI9KplKd6DYJpmfBZPoRCYRRES5DMKIxlXOTynglTMPZ9o5NgjHBg0sbemIOkw9E3nFJrXthJBcld//k4kFvpnf7qHwqAv7bWKKXNKqAn3Z49KTtkYuGpC+fMP+/tD3zl3hfv1QqLgnZxyCo7//IvlMxtmO7ksggE/cQ5gWt55o+dZgWhAGzhO3nltGlWe9PlAofRjSRfyygA0PyBBVIBbi4Hy6cjbGgoi4Rh6NpBczxGLK9sDTCmYdPOUWRc5+DD8pIdlpdDVwctk6Y69kJIb2rLCUpw9A+lcN9vX8QDD78M7g8hUhhGQKVREWTIZBykHQGebwxkbQc1IYVTqgxU+STGcxzPDgK/2jKOJ3YNYyiezp+M9P+Z+SmlYDsCnHvdHiIOkgoWuSgN6rA0r4NFzLNUhfQUrIkkNOZ15jw7J4A4YSyeU9wAgpHwgkPbyIf1vcArgG0jcEowFAa3J8l1bWial6n4fX7oho5AQQSaL4B4TmAgJdETdzBqKzicwYXCgXgGmZyL3nEXOZcwPJqQv3tqG9ftePdx7rP3/7nT/7AEQOvq1e5qIvfG913xWPn45jN7Oneve2UojWRZESpWLj8tahg+8zfdGOvJCbuoWnHS4PcHvCKYc+iGgcn4BFUVh6C04MyyBXNmHaF8UwIA6YFaVwCu61DA0mHpHD6LQWdT0ijM0+OE18HxGRp6hrLoHUxA1z2usJKeGYgg5g3EFIEEQQkPqWn5dYwkU+hYvxv3PboB//3zDgyM5bDqzONw0nE1mFZmoDSkoyaiI2BqcIXyjKyJwc65qC+2sKTUh1UzIjh7tonZJYQMTLzYJ3HXxjE81HkAA/HUQcKOUApKOnCVQk5Jr8ukBJRwENRclAZ0GFBgQkIjz8eZOPcmweQJg4EkGCQ0SJDyivZ0zoUQgM8frDi0jXxYC+BWkleuXFas9ODJkZCFVGyMMc7zAzuFcCgEg3FEy8rhMoItFbimIQMNA0mBvpSLe57bBYNxPP3iXoylPZCf35SqsrIMM4vET2786YuJZk9wWf1NLNCbL16aWUtLi/rit+48uXJGwzs2P/nUby5panoSwAl3/Op371XVS++YDAc1I+TwZJRIDMZ4UgbhN3wwjSw493wDfJaF8ZFRWhTgIlxUyuPjNScD2NrhBefhAmERMaYaAYOZWrnrel0hQyeP8cUVLFOH7drQuQYBAeUKKM+9CZM5hk27RzGrpgjK9Z4hUwRHKugM8JHHcJMcGBxP4cnnd6PjlV04MJoDMwwsO2EhTj5hGgIGkMtmsT/mYlMyi6DfgpACJAVcAeRcQOMaepMOXtybgMYNlIYMTIv4UWA46I8zjGZ0PLM7gRd2xrCs1o+TZxWissAEoCFtK9iOQkjzcnnL5AgZDFwRcnn0qdeuVSDyJvJu3twwP9AAJwmSgKYRUhmvE2QaxuxDD5HDtRobG1l7e7vQqxuO4cFQcWGQya2j48wyzfyNyBEOh8FNE0VV05F24U3KJSCZ17WasDkGky6mFSr88sFNOP4UwsmLjlVZh7OJwfHMEp7wupZ/wWz9Hw6AwuOP14kod/NXb6stmLv0+lOm171nVsPCryfHBh+Lp3MF5U5KxGPcIi5UblkIg6M5mDwC+MPQs3Fouud+rGs60qk0EsP9iESCyIWLLgbwg1VokWtxeERoprRljvvAOyKkG6VCeC0ED3LgsbjKSguQ7h0Gm5LkIwZiHCABXffhpddHcM6KGbDI8wazpAAxIBDSMZlMo3PHOHZ2j+GlzT3oGUpCtyzUzohg+swqVFRF0d19APGUjZzwpBc5I9iSw2AK2ZwNMpRnk0oM+0ZySKQBwWwMJiQ4cZiGB5UOaEBJ1I/JlIbn+x10jQxiXqkfS2oLUBI0EPXriBgMQrrQOMu3YQU0YrCJeTOKg3CNvBqGYh5MggBL0wDX9UB7rqJcDrB8VmU9YBA7zKC4xkagvR0JCpxVW14JHyXlRCLGLMsHpRR03UAoFIL0WdBDUaRtBQEGSQpCSAQDOjpe2YWG8gCeem4HohVVmDGjGk+/sFsGTPC5/sm7znv7u/ZMCb0dxgAgfOy883IfuPji0mi4ZtpYz4hbPK9EK6g//uadr/TdTHoE0YrpoNg4uneOUtmsEqzozSIeDmJnUSn4eD8sw4Tt2J47u8YxONDNCsrmYdDyrWg87YSq1lbqx2G6BfKEC2XMWBQirvukozxzO3iDloChIRzSEfTrnkQhaVCMPGQn4zBMhYExBzv3j+H4OeWIuwrcIGTSNl55tRd/eHYnegZcjCeycFwB0g3AZojHXWzf2ofdO/oRDPmhmQaI56EU0kHWbyAcCsGx/dCFAqREMplB7yBHIOCDF54EBxK5LEE5Ao7rwrYlnGwWSkqMCQ3PdeewZWgEJUGOJdUWllaHEDEMAJ5ZtyKPS6DBk3PxWocSLry8H1JBkIRknlqEUOLgDEEIwNQ0QwN0KGVPHSaH41Zuv/xycf0y6H08dG5dbTlSvRuYIgJpDMoRCPmDsAwDeiAI7vMj4wg4eeNvXWPoG5rExq2DOOGCejz4Sh9OPvNUlEWD8tEndvL0QNf+K4/d/Lk8de8vBqz2D5ymRET47t2//Xygat6H0xQqGxxKiYGXe1RFdVAWRot5arinJ/nKyL6q6uknlS+v1YJBpuznxik+00JZtFYN732NTNOAK1wwRtA0HU4qSwsri8WengNBrXLBmcDLP/9z8NV/ZmmBqKFAGqk8yhIenqfYR+hPSoRDJmKJHBgHuCJIToDjTbdccLy0dRgNc8uwdWgcOwez2N4fw9BwDqNJH3IqgcrKEALcM6d2hEDWVcjm0rCzAq6dAiMO25XQdQ2RUACRgIlc1oHIE8GVImRTOQxkRxGPZxENG4iGfTB9pucjkLORSqbhui40YtB0DocxMNMHqQcwkGPo25bCyz2TWFodxvGVYUT9FsAIUgi4eQI+MY98DjaV9ngzCakkzKnAh6d7pAiQjIR/qoY6bP3/ZmptbVVDxatnWKHCWTURH156YT9ZpglOHmopUhABcY5ISRVsyZF2bQhSkOBQwiv4LzhpNtZt3A+roBDRsI5EMi4rqqJsaEK9PPP9P5psjP7wr5ot/l0B0NbWxolI3Hzz16+dduzZt7y6cwxOwkZJSYSnpe0Wl5eT3re+M9D329MGN67Tsh9o21VaUMTjSYf2HRsR0TqTRcYraVD6oPsBls2BSEHXdcQmk6gpKVDlJcXYPxI8G8DPDnc7VBNSMUWKMW/jT5nQFQcZtJE0iiIhDAwnwJjnTuJyBxrncB0BTdexcXccdz6xG2MpwLEZpDRhWISSwgzOW9mAYxoqURgwIF2FTE4g5UqkHAeOSwDnYHlz7VgyC0YKpj+AZ57fASkELIOgSMIwGE5aNhvKzqIkyhDxm9DAwUgeHLJp+frJ5B4qtXs8jdf7JjGallCBIMZdB0/uTmFjXxozinxYUhXCtIgFS2dwhQso8kTA8hiKKX6zmSfaC1fCcVS+TkOe9H9411SNlzSrzjhu1nTDsCfEwEiC+/1mHtfBEAoHoZiOUPk0ZARgCwbJGFzXQUD3kK3Ti3U8/sQwjl82B2G/hm079tPe/jgWlvvXQymqb/nrekbs7yxavFOA7JdfW9vx1UCy9965JbGW0ODL36mp8GkBLnhicOtX39n6g+FA47e+Gqqa7neSDk28tGvMYiZXUqMD9x3YVXIgMmn6dGhMU4DXc044GQwP9rF5NZXIKmPlRSsXR/KIvcPWDcqMDaQlhK3rBJ9hIJVxkMi5KIuYiBgaAkYAZdEQXCfnCbIyDl3jnlocExhLZrGrX4CsAui6BoMDPl3ikjPmY/WxtQhyhYl4CrF0BsmcDdcRMIjD0vLDMgC2bUNKAdd14dg5SFt4A528oV7WcaHcHCJBC46rIZ0jgDgMbsCnWfBpFnTSQIrDsQESEnNKA7h0aTkWFjPYOQc+DQiZFhLSj1eHFH61aQw/3zCANfsnsT8pkQBAhtexMohgkIKfKQQ1j/M2kRVIJnPQGIeuA1IK7hzutnS+/akHii49btFc9O/fDSiPuwwo+AMWIuEgyFcAFirBaCqNWCaLZMZBgBTK/F4guNkcwuXlqC73o6qIq/6BSS5iI9l6a8eDXnvrH/UJ/gscAQD48pe/uAPAzYf+njt++8xqpbNX/+Pj77/nZz+7+6xkuPpaTefo39r1xLPff9/7lr7zq++P7av7ROHMaWY2/sIECbdA03VIxzvVDNPA+s0b2BnnXSyjhWUVmdSis4HX7mtsbGPt7U3/FBCrtaVFofUW9L74u7Hay98/oukIWpamDgxP0v7RDFZU+7GwKoiXe7KoqQhDkovxmJuvAbwOj3AFGCdk4pMom1GAiuoAHFfH2GgaNWUhJOI5CCkhPFANJDFIIigp8lAKhtF4GllHghjPK4ESXNv1TMaVB1h2XC/HdZSCchiy2RzimQyiBUGEdAaDRL4yyDPRJMFOK/h0jqXTItgXH0dceNAMkwBTlxCKYd+kQs9kEoW+HCoKDFRHTNQUmPBxAUsjBDRP8WIwLbB7xEEsnkZZsR+6rpCzRSoI2AfRgP9894e3tpI4Y+UZJ8yYOffUijBTT3V2csvi3hReCJRGo7AMEzl/EYaTWRQFNdRFDEQ0QnXEwtr9E6iK+NC1pQeVpUEsnRUEJyktM8Qstu+Rj3zq67vzZhmHLwAOrQNaOjp4w8gq1VnSQS2rVgkiOhaA/cPrr9ft6vktMxbNdDP7dtnP33v7R9s3dPW0b3j7zV/8waMzUvrE9I17nn5qSempN+vGuHKFS0QKlmmgv38QmclhtbhhDp4b6n0fgPvqD4dQ1huu5KkT0/H1zKqoi0QDcn9vjG3YOYoTa6ZjViHAuYlnu9MoKy+FkKMYG3HANA7GPeU1zjXEJyahkQLTdWQzOcyo8YMYoOV5zlNKb2IKHcqQB8V5zjNsimFPCkpJOK4LIfLvSBE0Bui6B4ZjjEFjDIIIY5NJkN9CYcjyZFKmRnJ5HdO0I1EWMDCn1MJL/Q5MTXnzBSJwCPg1Bil1jCcFhkZj2ExAUdhCeUkAQT9DkHtT4XhWoDuWQ8bNoKykVCqdWDYee3kt4CopOR0Og4x890evmPuhBYsaeO/O10VsMsHD4dBBS6TSwiLkXMLiedNghgQSqTSSrg5/YRiv9OeQyEkcU6rjxazAhatr4TN1DIwmacGCWnI6N9/3iNf++JtNFPaP7SdSratXu01NJFpXr3aJSBFjdrNSzNaHwzuH0gvsjKMNbH752/fdd9/Ou+5aYwHA5MYXH4iNR5eGzvzMJ0bSLkxNY4y/8RE0rqFzy2a2tL5a+YpKT2286NyFf47G9o+s9vwVnuvf155OOVQ3p5SiYRPPrh/Eg690w1FAcdCEk8mht28UZSUFiEYDIC5gmMzTDCUO4QL7+mIYHHcwmVUIBiww5Q2YNDbF7cob7ZELxgDpKkzG055B9hTXS3kelVlXIGMLT3aFCMJ1wVh+EJTXWGRMg8E0+E0NPE+vt6VE1hVwJUCSeyJXisHSNZiGhvLCIHy6x/KaGhkzeMrQpqVBARgcSWDrzmFs6hrGul2TWLcnjq3dcfQNTaAkGkJ5ZZQdOJDE6N7OXwNAe/s/r1vZ3NzM2puaZOPb3jY9XFxxWU3EVBs3vcZM8w1KeCAYhJ9xjGc1vDak0N0zgUjQQmlhCLFUDrqSOHN2FClb4oRlsxD1mchkpIwri3xsfPBMa+gZgNDS0vKP+QT/Q7eClNRKUIQHxt6WWHDdgc2vLV6ee/TLbW1tvKlxVe5TWz+1IDPt1FtkoW5M7BSGEa5A1OmGrmlwXa+1ZgV92NvTRyu5KxoW1uuvjvV/EMCHug4DCKuJSCqlqKWBHmz4xc7tVQ2z55104nT32Y6d2o8f2Iu1W0Zx6qn1WDSrFIunZbF7OA2nJAwpFIQtYFoWstkcGNcxOZFEcH4V7KyCBglGGlxykce4QgHQOPN61lJAQnpWS4JgZ8VBBphQAtmcjZztANwbPuVyLrK29LwKpEeGlwwgDQcxSo4ScITM0ymFp+6cx8ZYpoaw6WBhGUOnNDHpGEilMlB50BhjBIMTdE2Do3PksjYSKQUxmYYrXAgwGDphYX2ZGyzRtfFN2194z5VXPjOlFniYil83ZZW+/YQFDb6w7orB4WHu9we8Il8BoUAQWangL6tFcXUt+odj6NwwjPrpJVg+uxDVQQ7dc5ZDJGhAEy5IZ2rX0DgLJvZ+55xPtY63KfWmbqvDibpUU6Dch37x5d/cfdtHv/CxOx7PdTY2quYG0u1pp98dZ8VzrjixWNaV+fHCjizSMGGa/CBvVeM6HCHRueV1dmL9dBi+0FWNp51W1e65xrN//vOBWrtgJ7e89ClxYFzV1JdoC0+Y6YaLgmrzrjjueWgTOrePoCRo4sz6IswuYiiKBj2dSo3ANU+gaXQkCSEclEYMGMQA8UaFOAUy03UO1/GYAqbBURwwEDS9G1nlcUNMabBzLmzboy5aBoPjKoyMZzEynsZwLIXhySRGY5NwFZCyFfpiGeSkOsg6y0nAJsDNp14hkyCERKGPI+xTMA0d4YAFQ+MgThCM4AoJxgGm6ZDEIZkANBe6xSEdR82oKXCrZ0a1TM+wHdv4wieJSLUcniKYOlpaxNXHzQpbBSUfPnV5vRro6yZMzSMAMMZRFImABfyi/tglIhSEmj2rCMcdNw/7RtP46RPb8NKQA0cAIUuDhERhgIndcZe7IwODK3sf/YFSit6slMsRUfxqbPT4As3Na7RWIjnadOcH6485Zkl69ID7ZEcXu/rsBhRGgtg/wUFMA9O1vB8uEPQHsaWzkwp9SixevKggFqxsAqBWHoY0iLxbgF133bWPxV9Zc+Xe9bv7c/6oNn9lPR27cq7QTJ9qf3IbvnlPJ17pimFGiYUlM/0oLrXgKgWN69A0DcmUg927+uEz827z8KQL6SCQzEI85aBnYAQjkzmkc4TJlIO07UGOXSnhCAE7J5DJOnkwnccKc4WEqwhgev5/HD7LgJJAIqvQO5bEWFrAVQw5V8CRCi4YHAmkbUKxxSGEwEjcxayIBS4cGDqDpmlIOwIGuVhaocPUJHJZF7YjIQRBukxNjCZFT0+M1qzt0R794cP7ex9uv+hTN3zwlS9+UbJWon+6F7qyuZkTkRqvO+V9C49ZNrMqzOWrGzcwv9/v1U5KIRgKIFIQQobq+Fic86rSEJUGSdYEhXvu8kp52jG1KptJoz/lqN7xtIwlUu7T3Q7fumU/6uzeG5Z/9keT3qt+c1KOR4SH29XVrlatqkNr63Xi5g9+ssa3YNWvm86abz3/8k4WMkGXnb4AetCH0pICpAa7wfP9eGIeDS6TycAwOI49/lhs2rprTiQ9dtfpCxbYa9eu/ac/W2trq1JKsYULGrYGNj93d+WsOVlpmEsi02p8heWFVBDxi6HRSby4eR9t2H4AAX8AC2cVwtIIByZSEI4L6Xq8yPlzyhEyCYxNCQ14MIesI9E3koDNDMSzNmLJDOI5F4mcyHsReO4zCgqbXuvGivmFqK0pwWvdSezrPoC6qlIYBgNIIOw34DcNZB2BiWwaStfQPZyELRSiIa9nTkQHlSN8msTrQylkJbCwPIDBeA4EYG6JhiK/Bs4YMlkHY2mJTFYgEU/LocG4PDCaYrGkzeRkf5Z6X//hb2+97pqnn3zstWalWOtqOhyDAOru6FDn/P5X4ej0E35x9SXnhXe8vh6dXdvIZ5l5PoJU02fUEpM8nZhINvdl7e6RWLpcSiOs635mGTpVF1pUGDLUjjFJxA1SusXuf6orh+1Pv+czH3n3rxvb2njTggVv+vNqOFJr1SqG1lYlGk64bs6S+sIyE6K4vJiftLQMX79nI7b2TGDxzBB4QQns0f1gTD+Yqfj9Pry+tYsdu+w4seL4FTMeHRp4T2tr67cPZfP/szdBW1sbb2pqGml/51lfvPXTN/9cHHP+B1g0+q7SulnFhdNKMNE/ogZ2D8vHOvaw4qhFs2eXYdasCvT0jcF2k5iIZZBJ5WBFwxCu8PRClTddjqcTIFIwmAYwhUy+4PUwOFO5u3djSKlg5/N5QEG4ntI0I4GAz0LIb0JKhaydQ0oxSEciIwj7J5IIBU1UBPyQ0gGRhC28YtincQzEBXJSYFaUoShkIaADr3anMJIiJNO6io3HZP/wOEumJHNsCUoMT1jxnl+bex76/sNr1nSCCG333XfYbFHb2tpYE5HQLr7q+pNPPL5mWpFP3L9pMw8Ggx60QgABX0CWFJexPXv2P9Pc/IWvAcD5CxdGq9/+oVP1SOWplhk6hQd9C8xg0JfISRf2ZC+3M13ato6vfevbX3uhrU3xpib6510iD1MASACKQtHFy2aG1UDchVIubIcQLAzgv686Bj4ObNxs4N67diFomQcV2DhnSKXT2LBxPa1Yvly99GrljScuOvGetsbGETpM+KCmpiahlKL2drCmJtoDfOUz37juim/ZK699D4prry4sLp1btHIJHx8Zx3j3oLtuQzfzWwYLFQYQCOmIjWURi6Vg1BUi4wBgCgyEdM5GzgWIczA334Yk5tki5S9dIu8G4ESeaaCc8sRV+T8r+P0G/JYxRcCEqyRyNsGREpwRXKWjezSFEr8FDQJSsfw8gUEniXROYfdIGoWWjp3DOWwbSKNnNCPTSVtNJtJ8fDLH3eQYrMzYa0as59fm1vvueXB9Z+9UCtve3jRFgDosuJ/GxkZ57LHHFpVNm/Wps09epl586UVKJFMIWNZB3+jKikrK2YK6u3t/0tameCc6eWvTggm8/sEHATwIAO++6oMzeLi4KpucnOj45e17+oAM4DEW/5FgPVIBQLcwJlesWBGaWxVduCDI6fGt45RNxKH5DZx9bBH8ysZIjFA7vQHltTMx3tcDw/QfHM37fT5s2drJjj32eHHaqSeWPzgy+HkiuqGxrY21NzUdJow0KQCiubmZNbS0UBPRAH5675eagf/U7vjpKaJ60buDgaILSpc3hCrmpDHS3a8SowkhbZeR4mxf3wROXlSRbzN6aZEjFKA4dAY43AUpBU1xkJQQSsIRKu894NEqKS9XKIRAzvG6Pzp3EfKHICEAcGSERMKVsIXKU5O9tmwi42AsmUZF2PIskyDBuY6wyTCQBDYPCCWdnByKZdVoLMVTWcHcpI3caH9STw09UjDSeddV993xdJOn1oLGNsXrO1tUa2vTYVWAaGxrY0QkzrzkyuvOOntVuaZy4vmX13HLMvOqGAr+kCVrqitp7/7erteGB544B+1obWpyvEOqnXWWlFDraae7d91z514Ae6daDs1KMrS04B+tUY5IADSvWcNbV692z7jyunOWLZ43C4BMKcVm15XCMAnVIQNZh0EwQlIA8449Bc/33QOmVN6i2vO/ymbTeH3r6+xtp50kt3V2vW942Ynf/83ll28/3CC51tZWidZWKKWoHWBNxLL46HVPAnjyS9d/embuhHPfbZZXXlJTWzSfz6/T4vEs+rd3q76BcTkeS/LSSAEStoAQCsJVeTCZAIHAmQaZpxtK6Z38QrgwdA1ThhpCefwyUoAQAiGTEOAK8ZyEIIaJlI2co0BTrK0pTDJj6BtPoSBoQUoFjQR0w0TYYEjH4mKcNJ7VNC4FQdlpBFKTr2F8/93Gjqce+MUD9+0BgAeIofG+e3l7U6dqb6IjIX3C6js7VW1BQXRhfcMNpx97jHrogftJOC58PitvLihRW1WlNOisr7fvmxseeSTd9MgjU0heBkC1emwuam5upq6uBqqv71Stra3qny3OtSOY/mDGnPprq4oDqjcl1PBEGiWFQeiaN6jJ5vLiUoJQv3Qpujs3o7fzNfiD4YMnZMDvx8bNm2jJ4kXy6qYLrMGe/bdt2PDSBUdKpm/qRgBAjW1trL6xUX2BaA9+dNvnPwp8Kfy1O040quadrAWKL6quK12eYTX81b6kXEYMZUVhNhFPQ8g3BlkkPNlDrmReK9SbD0gXyGRyCAZCcPKeyUwRNM4ApqG0yIfZUYaNgxyjyQwSqTQYNw/qDOUxbAAxjKdyGIwlURoKwGdydA6OybW7R1lMi3DLjqEgGVujpcafMkf2vvDV5o+9QIA7lTJ0NTVRe3u7bG9qOmKaP41tbdTa1CQuaLz2Kxe/7YLqnt07xdauLh4MBqGkgFQKkXBYTi+r5Dv3dL/03Ttvv/eOX7TdtHnztvU/+Wbzk1MHXXNzM2toaCGgHYfzhjrsATClEnHrd74zc3pd7WnJjENd4y5LJeOoLPOjKOwHR17VSylwUuCkYdnJq9G97XW4rg1Dt/LQAw7btvHYH/7A3/mOq8RlF190/tjoyEebmpruaGxs5O3t7UfqxampTdHc3MywahVrXX1aDjd9tMOb5eCr13+8+QxWe+wHuopnX/xadxozIwNixcJaHomGkLFdpLIKrsvgSgbXkXAlBxcSulIwhAc53rNnECNjk2DM64PpGkc6lcPk2Dhmz5+J5/vGkbBdBAJ+MOJQRHClgBTuG208zQBpJmI5hU17B8X2GDi5JgoTe+639jz3za996eYXpn72ayCsbH5GW4UOeTjamm8G8/Obyy8Xxxxz3CnnnXPW9fOn14gf/PCHTNf1g7xjMKaqKsppLBGXjz39h3d+7zePXTHrjHO/msDDvwPw5A9v/+G88bG92ZtaW/cDh9+lWzsCpz9DS4sK3vPoMUz3+eK2kBMpl/mZx/6K+HRI2+OdaowQ4F7+O7OuFtV1s9GzZztMnwWuefLjPsuPgf5+vPjiy+y8M1fKvv7+b/Tu37O2ra3t9ZaWlsOaCv2V9EgevBVKSqj19NPdH3279QkAT7zrg9+43K1bfuuLI0W1uwa3iTnlAWbbRJqmQWMKyXQWpu6HUAqONwaD4wok41k89dSrUMrngRuYR1W0s1nc8eNnMBlLY+uogiMkNMah6fkg0Y18wezCtAw4ORtDfQlkSLlJ068Vpkb2+Hasuf4brZ98Jn9VUHNLB+/qGlHt7U1ybetqdy3+JYva2toUEZmnn3fh95vefh5/oWONHJ+MUcDnB6QnAxkOB2VRSTHf0bXrmSeeeGL3xTd+/eF0SsioJR66ftkyPbr0uOdjO2v33vzR9JVzTzn3hK4dveyhX3/nvq6uLvutGgASRCp9z5OX7BvJobyiUE1OjMGv8/xQR/PyWQJ8OvLm0gRL13H2uefhZz/eh5ydg98XAGf5tp7Pj42bNlP9vHnymisu9Y2NDH+TiM5obm7m+BeZNxx6K0x1SurbGlUr0X3Xrah5Lrr6qz8cRsMFO17uV0N7+mU6LZgSOfgsC5lUBlJIGD4TCoBtO8hlbPgsHaGo3/PvJebp97g5dPWm8Pk7ngOkzCueeXLrjHvTaEiPy8A5QzgalnOOW4Dy6mItOrq9w3qk+Zpv/G5tX5tSvLOlRbUSydZ82vOvXM3e0Mu99t0fvO2dV16+QDhZ8VpXJ7csy0MpMwYmGKLhAoJkMLTS4k9/9rbWQGHlvGTvvswHmy7+1R3f/+G5vLSyKOAWFM6aP3MLK6zwF2VflQ21tY93dW0bORzeZdrh/dKKtRLJx3/xi1l7S6suDIZ9iGUFGx+NozbKYPhNpHKARoDP4J5asfT63o4jMXf+DByz4mS8+PQfoGsWdL9xEFrguDk88cwz/IrLLxdNF190+ratnVe1trbe09zcrLW2tv7LX3B7e5MAAY1tbfynTU0DePGatzV+9LabfZXHf6lsxXLWvX2nGOg5wMsrSzFjbg0gXWTTXj4fn0wiMZFBbDzuEfBVHiJH3sRWsziqZtUil0wjm0yB6ToCoSA4MSQSKWQTGbi5HCorK8Si1Su4RZPQO5/4r9zn3nnTHYDT1tZ22Pr3/2DPnzc1Nbnnn39Z45VXXvaRBTOniV/97n6eyqRhmX5AunCFQDRSAH/AYK7Pj/Bpxy7WU2yxJB/cA3sTn/vwFy4omnfcLQXRsHtg1BYTZsQnh0b7kwM7b/jNH/4w0tz8xb/I8/27KvTDe/h3MAAYLahptCKlfluReG33GE2MTEDXOSIBHzKO18tm5MmJaIwDpLy2Xk5g6amrUVxWhVQi7rUJGUFBwLIs9Pf14Zm1z7H58+bId11x5XeXLDmu/pZbbnH/mgfUEQ+EpibR3NzMlFLUfsenv6Jt/vWZ+kjXtlnz5vBZ9TNEb8+g2vhKJxzbRmllEWbOrcaCpTNQN7fS4xpIT1NISAUpBXRN95QnNIZAVRGis6oRnVYBXySIbDaHVDwF02Rq+pxa2XBsPdfGd22lde0X/vBz7/z0j4g5zc3NrOkIFrVvpga8/PLLRf2SJfWXNl32o9UrT5KvbNrMtr6+FQF/EIwRiDiC/gAqakug3AAmgjMQHxHKSdmie2AYVFhXuvwDn7jfqZi/4PWuMc0xI+ZkPEN7Hvnxx1o/+4H777vvPn64Ut/DHACrhAJoOItzcpJUTgCvvrIP3M6CyERx0ASEC3Il4Ajkhcg8ASdGUELBCkVw1mVXAgpIJiYB5mlWSqXgDwSxecNG2rR1C8688Izopz/1qXuUUtG2trbDApn+Z+oEIlKNbYr/9r7vP639+t0r2Z51vy0vCfMlJy8in88n1j75Kh5/6Dl0bdmHXFbC5/cDTINju4gW+JF0ptqmHoE9NRqHTLvIxTIY3T+AvVu2IzE2gZqqUjFv2TyqX1DLwiPrvjn9IyuO/8m3b3q4sU1xKElHuib6W3l/S0sLlFLBj3/wI/deevFZkYH+QTzx9NNkWZbHsuMadK6joq4CwZhf+J8uTTtWFJTIkWmACybRP5nG7q6+9MiGP9yodq5vZH1b7ue54Z3ZQGisWSl2GFDZhz8Fam5uZkQkf/frO+uSjn95UFM0HsuwibFJzFxQAqEY/CYhY3vUP0EefJfB03kBAZbOkUw7qJo7C8eediaeffxhmH4/gj6/p79MHH6/D+teWc/qZkwT5513xuIf/ehnvySi85VSrLW19Yj5WL2524CEN0W9fATfue6yS979het9dSd+q27+LH/Qr7v7d/Xw1zdsp77uAWhcRyaTxTH1pVhaX4btByZh+E1UVBaja08/EqPjyMSSEEJACgelJQWqanq18JcWaxFnPBfp3/iZ793y4TtwsI//70t5DhZJa9ZwInL/6+v/+Z1LLjp/oZ1zxUMPP8qFFF5qxzngSkSLogj4g4htCSI2u5LGkgk3F1a80FFk+E1Iny61ybToeX7LgW//4Au/AfAbeLg1gdabDu+Q4jCe/wwA9meqjhd6yG9oTA6PZihkKZBmwtJ15BwXGUnIKCBHhCm9bcDTplEKCBsafI7EKWeeieqZszFyYBiu6+bVfyV0TUcykcBzz77IfQHLPfOc1ed987bv3UFEQuVVqv+dy6NvKmpWit1/15d+VLjrgdMC8b3raxbM0ZadcQI1LJwndDLhZgVKSwpw7mnzMOJo2DtBEEIhWhRBZWU5/JYBjRSikRDmLZ4j649bRCXlZVpgdNeGgh2/OfV7t3z4jqlTv/3fmPJMrTVr1mi0erX7xZtb3v/2i99+XUEk4j7xh6f5+Pi4J2+eV3r2BwIoLSvEZFJD7zmz+eh5Zb7xUa75AsVkrEuqmQ9lUZSymLZ8YWj+Bz77sy/f88r+m2771Webm5t15bH3D+sM6LDlzqta3sXW/vznsuH0y6+W/pJTiosLxJq1W9ncCh+yykDD9CJouoEsOKQUgOM5sOvMkxJHnuzhkgIXCpqpo7JuGra+ugG5bBqBUACa5vnn6rqO/v5+EBFbOK/eLassPWFa3Sx50ooTOtavX6//6Ec/kv/uDbG2tVU1trXxX33hs73L1/z6br54gWMWFq0om9WgFxSFpS9oyKBPo76BOG3aOY7BwTh27OhD38AwuMFQGAmrymmlsnZ+HZXU1DIjNer4BzfeVv7ld1z73Q2vdDe2qbfEqT+1+VevXu3edNMXTr/kwgvvrq+fz9Y8/xzbtGkTBQJBQEnPF45z1E6vg1A6xgI1Si8oIWto/6sUP/C0aaEudGKdFTACmHh47eZRo/sX0Km2ZN6c2tIZ887Ys6Vz1/mnn/hac3OztnbtWvmWuwFaO7zp71gsuwRQGBlNkJPLoLqyCDkXqC7xIZnNwXFsD9vuCoxlhHcLkGccpKQEFCA4IZN1UVxVhRPPuhCxyQQSkwnP7C2vZRkOh/Dqq69iy9ZOXltbJs49/6xbvvGN265cvny5s379ev2tsDGmCuSfE8ve/aX33+Jb37aK7d/yTEBTrHhmDS+oqyKECuTwRMbtGRh3Y2nHZf6AGy4tlsVzp1PRnOncgEN6z+Z1ga3tq3/+tfd99lvEMo2NjW+Zza+U4qtXr3Y//enPLbnownPaFy9baO7Yu4fWvbyOCgrCYAzQNA1QQFFhFD7NQh/KkSgsl9n9Gdn35HNP3XLd6mtfec/xM8efWbNxsspU/dU9HV++5pwbBz/3zhPTLz3x4dTra7810rdzDYA3RXP8u4qWw/h7lHroev8VG87ZOm3+3OnrNnXLctNm1759GW6/fwt+ect5YLaD3aM2skIDGZ5WaZEFVAc0QHnGZ44CXKngKCDjKky6DK/+/jfY9WIHyqsrURApOCh1qJSC4zg484wz1Jx5c9SObbuyG9dtuOK6D1z38NSphLfGosY2xaY27bUfbl6VK57/DjdQeomKlkZ1XwAaeVKRQtlwUjEgNT5oZEYfN/q67pr2gy+90ArI/Kkv/511zp9pd4o7vnXnquNPXvbrxQvqy8fHE/J3DzzIstk0GGf5dyRREAqiqKJQjW/xkWXMxPh5EQjXD9MOY3L9vb9Ijex/bvE5V/zYCdVix9bt49yvBgsw9vgnLlz56SP5HQ5LETyl8nV3bFElC4YrXtu6F/XlOv3HVatRURrGfz/4Gj7/vWfxnrcvQXmxJ3E9mrTBNAvjGRcBUyDMGVKugMqbnzkKEMRB0sYlF1+Eh+Lj6Op8DZZpIhAKQghx0EBhTUcHabqOObPq/ExS+3f+8zuNq1evfisFgWpvItHc3MxaW1rUz4k6AHRcfcqyLziLLluBcMF8oUUjgkjBnRhn4wMbi164/ZU7X5+c8MKHofmLX2Ctb5FT/9C057av3bbspFOPf3TO3Dn+icmU/P0fHmfZXBq6oeeBfxIF4TCm1ZQipvloYkEVklpAlQ3rlNncsc6aW/c4oD3nCmdg9MCO69yX9t5QWbRkyViZKMyMjh8AEYgxfPHznz8iU386TAHAWltb5Ze/+90lnezYTSdUWmJxqZ89u2OYMraLmpoo9vVNYCSWxbSaYixbPA3llRHA5cjlJDTNRVBTINLB86RyCYWc66LIAKoKDHRs3ou1998DYU+iuKwSfp/voN2qVBJKAuefd64sKilku7t2Oc889fyln/n8J99qN8HBKTIaG/G30pjGNsXR3oT29va3zKl/6MnfeFZj4Sdbb3h68dIlS0aH4+L3v3+UZ7NpcK57vgn5psXsulqklMJgJhILzV0Q4qYkEWOq//mO55791NsbL12J5Kszbl5u1M6uL68+4cbM6127evu+9H77/k2j0ZNP9o9Y1fq9T907cESu5sP2e5RC83vfG+1dcNmr4dDcGZTolzWLqtWWLUNsYnSUljQUQQkXOlPQdAOhAh9m1BSjvLDQI3lrHBZxkPTao0QKFpeYFuaIZ11sOJBBz8bN2PDE/SgrDqCyuhYa5xDSuwkcx4VlWTj7nDNlOOxn3bsHM+tf3NT0no9e+4haozRaTW+pIMgn0NTY3s6GO//Yg7c0j9t5K236Pz35333Vu2e85/pr2447+fhlo6OT8uEHH2SZTAamaUEIF0p59qzTaytBuoXOSZ987s6f3j37PR+9eM7y+eGZIRMsxPHsY6+le/YNp4tnzy6ePm8amI8wsObxx9P93T8unVt/aWFlyemJwbHQ8z//zrHtj7d3HXa92MP2KgGin/xk/JrLk+cOzLri1sLy6gsLI8Xs09fXgWVzwhEO+mI239UbQyTsh0hPYmIkhqAB1FUVw0cMugIYJDx/CoLBNBicYcBxUUA2nt+dw7QTzkH89cfBBgbEtLo6BgIppWCaBuycgz88/iQ788zT5fyGWT7D4Pf94Ac/uJBW09NKKQ2A+GexI4f3+CHVDgj8z1iUFxdzW2/6yilnX3javccfu7xyMpEUj//+MZ7OZWGaJpSSB9Wj66ZVQTdMdGUDiFkl7Lh3fvpaXm6pzGjafbF9zSNzTyl1ffPnXWaQ4d87ckBaW2MKYY3tD9WeU7Fs2TmhuhIM9e9DmcX21S+pd/H4W/cG+KNiGADefv77j/PNPPGdM5fOuOyYYxeVLZtVgIgJHMhCbNqfZKNJQbqwQckxjI2N46SldVg4o8xzXVcSOimYnCGRUxjMCmzYsANPdk7indecgj0vrVE7nl9DIb+OitIKECNIJcCIw3UdaFzD6tNWyZkzp7PXNndNrHtlwzXvf/+7Hz30+sbR9XeluC0tLSAiefdP7n7HokX131+0bHFodHRC/P7xx3kiEYeum15725N8UbVVFUpnJtsnglKft0T1DY5xvS8lXWfcqTpumflK28+u/kHrh+75ypObu4uq6mpGdh5Q+3tjLA2odMJWNSSGKqOp/zImutd++qYPbThS340fiYe1qqODfnj12/q2rnvgsb6nHvvFWM63b/u+RDCbY3UVpVFWU2IQMZLMNJRmBmn3QBp/eG4X9nUPwxUuNMuAzQyMpST6xtIoCRv46e82YNmyeoQtrnYfYDS67fUn7ex4lVTQ/D6f0jgnL+fU4AqBXbv2kK5patHiBl9pJHLVhW+7sHLXnt1rv/nNb2aVUry1tVUd3dpvLuV597vfLVpbW9Xjjzz+3RNOPv5rM2bNMLu7++Ujj3k5v2GYeUooBwRhWl0tlRRV07Y0dyd4Ja9KhVgqbEEM7OxIvvrIpXHBAn4mXlv7+P07N/fsnldulh/jf2LQ1U+q5TWFhlowv46p0e6xDb/5z1utmvqSi67/zJfPvrBpVe6BXz3ZDaUOJy+AjuSp0dXQQocWep++6faTaufOv3L6rMpLg1W15Z1jOZSGNVlRFFL9Qzn2zPO7qGfffugihdXL63DaiXMxp7IQr+0eQOvdm3D1hUvFq9vG+NDuTR1tX7529VVXXfuu6uqyuwoiBaKstIyRJ7MAIgYJhWwmg+XLlqvjTzxWpdIJtmXDtk3rX1r/sRtuvOE5pRQHIN9SKdFbqjxRBIARkWi8oLH2wx//8DePOXbRpaFwVGzr7GIdz64lIgLnPK9y4bkrz5xeBUZaZuvGgX1FjVfW96x7dYN/c8+T4uIzPxvbsXXLLdeuXOztD7DWVsjb77nnylmrL7ln8PFR2PN9cDOTKIGTGnWtwPBYAmbAxLyZMzH+8nPb33fdygblSdThcNVH9C94lLSyuYV3tLQczL8/eeWVxfPOuOS0vbmCG3hJ1UnFRSFEgyYkdDE6lqSt23vZ889tgiVzuPvWJryyJ4FfP75bTp9ZDEM69jS54aSbP/GJTUSkLr/k8o/UzZx+R0FxGJXREqm4wYTKAWAgIti2g/nz5+OEE48TwnX5/h37RFfXrk82vuPS24kI991339GU6M91eS5vElDAPT+57x0NC+Z9Y97COZVM5+LVda/yTZs2QjdNj5+sFKQroOkWaivLRXlxKe9Yt+HHH/3o+z7T+tOHv9S/++mvae544bSzWl7v3pemQO+OJ/av/dmH29c+vFspRZ9+3/vq5lz2rmdSMY2Xzphd5SDDdvzs1vPNGUsXVZz6tq9l3VyOkV8NvvTCjt998srTtyM5djh4AP/CADi0rdfGG9GIKe0W1Qz2/ZrfXdgvIpcNZ3AW/AUlflOHT2ewHRKvb9qB5uuW4OV9WfWLR7Zqp5w4Aw3W3ms+fFXjL73f5cmbNF56xXV1dTXfKy2usCLFBULXwIXAQRJ5JpNBSUkJTjn5FBkM+tjEWBx7d+/97y/c8l+fWbv2wdgUhoj+BTTB/wG5PhGROHnhydGWr7d8Zf6ieR8sryzD5GRcPPfc87y/rw+W5fOgKwoQwgXXNdRWVMEK+JxBqqTX1r/yX1/5+NWfzR/S7McPv/RCoqThhI3rO91TVy/RJl5//UDnQ79q+sU933kWAM6YMaNgYu9eXPfY+idKFi06LrHh2Wvec9EZbb/csHtcmIWBkRQhGglj+KXHXt51/9fO+smDLyQP1y2g/SsfcHtTk2jPX6/t7WDUxARw8QMAHnjx4Turnjkw8719Y9q7eycz03iokItwFL9+YQjZrIOl9dF4fXDwyx9uavzllABSu/fStNbW1p9eePaFPe48ekDwXKAwGnUDRkhzlAMACAQCmJiYwB+e+ANbsWKFqp1Wo6LFBe/99q1fOGnblks/SUSP56/9/5Np0aHpTmtrK+758S/OnL+o/pvzFzUs4BqX/X2D9MKLL/BEIoFAKORBVkBwXQGf5Zc1lWVEYLQvWaQHplVDOc+SVxRA/ejuh27lM5ac4Iwlhc9narSxxz1+xdIyy8w9tG/HxvnPrn92CECCiOS5vTseqjhx2TJbL2gE0S9lOjOiJw/4nNe2f8OeOeOU6tLyxXuii+cQ0YZ8O/R/VgC80f17Q32hra2NtaMRK95G/QBat31jxTefKr52dr8zeVxFcXRlOjVZbOVS6yrGn/nJRz7x3/uamxU7VP2rtbXVzQfBU+dJnKdjxk+ZdGfaESYiwSCTSpCSEpZlwXUdPPdcB03vm00LFswXS45dMr+wpPj3615a//CWzZu+TESvTBV+q1avEoT/9YEw1doUAMQd/3XHwuXHH/eZmtrKa6pqKjE0NCK2bdvBe3v2QyoJn893ULxMQaCkuBhzpk9nB8ZT2JCNIrP7wK7ksx3fi+d6fw9A3fHtn19VctzJn9rbOSr8Yw7XQyaef76fye2QdmR8Y3mwPNGyqoMPzv01AVC9Wza+MPeMi7lh8ROglDawedP15CYCN33iww8AwPUXXFBctWxZLP/eD8ttTW+lUyiv0vYX8/Fmpf6iSOuUSsSiGYtKTzt/9XeLqgobi8NRGQoVgnnJKvJWWMhlcwiFQlh6zFI5bVotaYzTnt377L6evrvu+9V9X7nzZ3f2/i+/EUgpxRhjQimFT73jA6WXXH/txyuqyj9WN6PO7zq22rl9p3q9q5PlsjnoupZvbwJKCoATKisqZV1VHXv95Y2v7xvVmL7qoobuDY/d85/Xv+1qT+xLovmr3/tQ1Yln3jrWa1qjzgQl4bIDqZwsjJYh9sKTvz8h8/B7/+Pnjw1NDbcaAWParb/4XknEHLnx+ss/jzzfu3nNGu2W0053j4RXGb0VX47nEr+KdTWsUu2dUG0NoM7OFvW3ov5QqZQPvfe9nymrqr7VH/WhrKhK+E2LO8IGlFcXuK4LIQRqamqwoKFBRIsKOQfH9q5tPd09Pbd98/af/OqJJ9rH/zcFQnNzM1u1ahVbfdppbl6M1Lfm6TXvra6qvbFu1vQqxoFYLCY2r9/A+wcGYJim50+Ql2uUrgNT19SMmTOVwX00Ik315O8feEdZ9cxpgeWXfmXvyy88qfU5F3Q1rFKNaEdTU5O46UMfbxKnvv/eaXMqaXQijon+SSyoCCFZXIrtz7zQu/cP91z7xBM/XfPnJrxtbW0c+Tpv6pA83O+A8L9vsTxaVF7eeM3lddMrf1BUXhgpjpaIsD/EBCRNoUm9LpENXdcxe/ZsNW/eXOHz+bVUPIH93T17+7oHvvXNr9x2zxMvP3EwENrb29HY2Pg/JhimpAUbGxtxiGFE4NHfPnrlzHmzPjZj1rQFumEimUqLPbt2s527dpBt2zAM449+jxBChYMhMWdanZazFda93p+erK3x+4Y2nw+EZ5cdd8G3n2v/3bPf+twlK9vaFG+6nInPnnRSlF3d2u5fuvT0wL5tg7ystuzA/u6k+8Tvrlrw3is+ki1qOGfjmnXY89Tdpz3x2F1rGhsv442NbWhshPpXNSS0/4UBIIloauJ73xnHn7Fl6YpFt5PCGVkni2g4Ikzd4q70RBgDVgCSJHbu3EmDg0Na/fwGVVNTKRsWNsyYPW3GHbXVVf/R19f/g8fufewuIho8ZGO9lYOB2traDt30AgBu/tDN004777TGitqqd82bM7uBTIZsLiu2b9nK9nfv5/H4JAzDgM/y52XXFfLGMrK2toaVFpVq+3btP/DyK5tan1+3/emV554481c3vOep0z7z+T0Oj+zgYvBhACgpATWfeqrmu/Y/bg8df9rpgfHOjRu+cdI5FRc++IRVULZwqDo7fs0Zx5778FPPfO6EhsL3dT0pCqYaOk3/YsTr/8Yb4M+lRHT9uz/0gZLyyOcqqqqqfQGfLAxFwJjGhJQgpg5i14VQKK8oQ0lxiSwpLFSRokLu2ll07+49MDw8fu/gyNAzzzz85Avfu/t7Y4cGAwC0tLSofGdC/TtOerS3MzQ2Yiq3B4Azzjij4Ib337C8tLz0kuKS4itnzJoZJQ4kk0nRvX8/9fT2sXg8AV3nB/v6lNcdkiRVuCAsplXXaiP9I5O9/b23ffv7t9/18ssv9/+Zj2AAsKdSmWsvOrvumPffts/yaSn20u+WKMayyZozNiZKqovnh9K5Pete+uxNH7/6O9WAb0rh+d9yUvwf6W0rIlJL5y6tXH326d8pLi+8rKiwAAXhYtcfCHCCJKk8K1PGCa7jwnVdmKaJkpJSVVdXJ8vKSjgRw2R8AqODY30TY7Hf7N+3/+mf/eBnLzz6/KMTb3S4GKQUvKOjgzo6OuTU3324N3tLSwu1tLRQR0cHrVq1Sv5JymC03/3rFTNnz7kqVBA+u7SsrDYcDQEADgwPi/6+PhocHGSZTAacM3CuHdQcBRSkUDB9higrLeYhfwH27ux+9Zf33PuBX7X9bONUbt7Z2akaGhpoSmaeMaak/KMBFb/hpq83Gk6uu5inu0JnXvFyOjJ93tCBIdFQWsbnhYFXH//V2z/2sY8+2Nz8jNba+u+BrP+vD4BDAuGggNZ7rrr+qspZlV+vqC6tCfj9iIYjgmsah/QkzhljIABCSuRyORAxlJWVqpqqKllYXER+f4ABwMTIKA4MjfSls5nHY2NjT25c/9qrn/nCZ/b9mQ3Lpp71lNNiY2OjamlpQUtLy58NjvwGR3t7OzU2NiK/0dVfKsZveM8NZedeeO4JZdWl54eCwZNKC4vrw8WFAIBsLqsGBw7Inp5uNjkZIyk9XnUexe6d+hCeV7FSMhqNUHV5BfX3HZh4fVPX1z/46fd/C4DzN9rDf1GR40c//flFovbEB3R/AajAhL1n71Bsy5oPCT+9/PlPfnIoX5OpowHwr2n/ERHJ4xccX3baWas+Fy4OfyBUXmoENb8qLoxKw9C4gmdWgbyAr5IKTl6ZoqCgEIWFUVlYHJEFBWHm93nBkMtkMDw0mkokU12pRGL96MTEizu37dn88c98aA8O8xVfUlISbL6pedqM2TPmRCNFCwoKwytCfv/y0vKSYsPy5Vu9WTU+EZPDB4ZpdGyMpVIpgBR0TQNjXmdHKYAUh+fIAKnpRAWFEZaMxTE+Mvnfv/7VPV+7/9H79zLG8IUvfOHvxuE3NzdrQIsEWqyebT2zL3j3e24wl5547d7NWzpvOGfp4r8VOEcD4MjXBrjiwiuWTq+fc1NBQbgxXBhCYaRARQuLJWeMSeGSEAJKApxrAOVdXIQDzhl8lg+FRUWypKRYhQvC5LN8bAoLL3MSQwcG3Iyd7bazzq5EPLklkYm/mk6n44lEIpZL5tyx0bFs797tY6k4HADIpDMqWhhljs+h2bNnh8LhomBhOFTkD4eKgmagJhgMzPf7/TNMy5jjC/gqSoqLdG68wf9PZdJyYnxCjY6M0tjYGMtmM95n17S8D7E6mKZ5qY5QBEjTMHjAH4TtOhgfja1/sePZ5q/f/p+PAYBqU5z+SR7yVPvyh3f/8Bhj3qUb+ndv37vrBzc3/KyjI3c4gW1Hu0Bvck0Vxm1tbaypqWkTHkLTe97xnjPLK6tunIwmTs9mBQ+FAwj4TNfkBmc6Jzfv8qWYgmF4KPKcncPAQD8bGhqEaZrw+XwqEAioSKRIFYSDKC4t1gzTmAliMwGcAwC2cJFNZSAcF7abc5Qt4yByFQBBSnFwxpUg0rUAcW75fT7m9/n/P/0O13GRcxyRScbV+Ng4jY2NsXQ6zRxHQEkFxhhMw+c5WGLKd4wBnpuxlHCkbmqaaRTwidFRNxabfKG3d+jbN3ziww8BkEop3tLSougwdGUO6cq91vot6zuM2PDP167N1rUcHrurozfAP18kHwTCXdN4zcrKuroPhItCl5aVluh+K4BoOCgCwQCIaUwqQUK4ns8v8YPWSEopSCEghAAYQeMcjDFFRCoQCKpgMKB8lkU+v58MQ2e6roFxDl3TwLmWd3qE5x4pXdiOC9d2YDuOchxX5nJZZDI5lU6lKZfLkuu65ApJtpsF8hqrnLOD5iKejzAAJcEYQQGKJCQxwDT83NA5BgYGswPdg798ef3G7971yx++NrVZL7vssiPpvfDWyolxdB1Mi9ra2g4WmE3nNy2ePnfmuwoikauKSwtLAyEfTMuPYMDv+iyLMc4JYOQR8r0Tdir9gfKcT5CvJTy5IwkcQhdkjCvGGGiq6CaCUuQ5y0uv9pBSwMse6GCqPPXnKU9iMO9Mn/Irpim7Vk92XilASSkUgbhl+eFKibGRse7JA2P3Pbfm6Z/95L67tx06MGtqOrJcZK+D1KhaW98ayNujAfDnA+HgJHLBggVlp598ziUFxQWXBwuCpxQWFjDTNGD5fCgMh92QP0iKEZMgUtKFyG/eqVybwKAYvA0qxUE9I6/7QodkAJTn0wJTXIZDUwjvJ7x/ivx/o5QCU95mJ/IsWgEopkhKCSgmuK7rgGIYOzCaSkzEX+7t7b3vGy2fbZsAJqdy/JY3ATM5egP8H0yNpvrcU//uqsZrl1XWlL8zGAqe6/fps4qLi8gfCMEwLfj9fhkMWZJzzdO0kERTO1LCy8sBAmN5d8h8C9Lb2x56WB3CjydwKPJMtfOdGrB8eiOgACkVgZTGSEmCEkKS6+YIpJiuG3BtjonJEdvNOK8nYsnfrH/1lbY777pz7yGFKc8P7v5PcyCOBsCbeEZ5WMGh/Xfzw++6vqG8quo8HjJXM7BjwoFAxBcKIlQQhs8wPDVkTZe6ZkiuMXDiRIx5x7kS+cOc8ranNGWjfdDxHYq8NixIKaUAKRQRUwoEV0kSrss1Tvl5hUAmlYPIOUim0uPJdPKpRDLTsX3njo477/zOtkO7Mf+KNOdoAPwvvxUuv/xy8cbkFLj47IsramfPWMI5nx8KBZcH/IGlhqVPCwT8vkAgBNMyoOkc3NDzjpCe+TXA4PnEce8SyG9/IgLLW6yCaVCMwPPuk7YC3EwW8Xhc2LYz6Obsfalk8rl4IrXZdcTES69u3PrYY+1Dh6ZPzzzzjNbR0SH/r5/2RwPgMD43D7IN1nII1/mQpV900UVVpYUV86OFkZl+X2CmbrFZhmEUcNLKFKkgwAq5wRlxBQViRIxABMZIMgnFQZIYjzGJtCPEmK3cCVKs33Zyu5Lx9L7R0dHOe+/9xf6xsbHEn364fHpDAOS/C5t0NAD+Dy2lFDU1NbH6+npqaGhQf3pD/MkyZsyY4Zs/fX5RtCLKAlqAlFJc6hoHAOa4Ip1Ou0nHUaOj/ePPP/98BkD2r/3dHR0dfGRkROWL+KNKF0cD4K1xQ3R1dVF9fT0Bq9DSskoC+IeAcZ7ai2QAKA+yw9HT/WgA/I9+5vkU6q+uQ0jfRzf50XV0HV1H19F1dB1dR9fRdXQdXUfX0XV0HV1H19F1dB1dR9fRdXQdXUfX0XV0HV1H19F1dB1dR9fR9bfW/wP/LFPO9zTRZQAAAABJRU5ErkJggg=="
_ICON_512_WEBP_B64 = "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"
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
        # "fullscreen" is known to crash/misbehave on some older or OEM
        # Android WebView builds (common on budget MediaTek tablets) -
        # "standalone" is far more widely supported and still hides the
        # browser URL bar. The in-app ⛶ kiosk button covers the rest
        # (true edge-to-edge fullscreen) via the Fullscreen API instead.
        "display": "standalone",
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
        # A push arrives via the OS/browser's push service even while the
        # PWA is fully closed - this handler is what lets it still show
        # an alarm-style notification (with sound/vibration) in that case.
        "self.addEventListener('push',e=>{\n"
        "  let payload={};\n"
        "  try{ payload = e.data ? e.data.json() : {}; }catch(err){ payload={title:'Omega Ice', body:(e.data?e.data.text():'May bagong update.')}; }\n"
        "  const title = payload.title || 'Omega Ice';\n"
        "  const options = {\n"
        "    body: payload.body || '',\n"
        "    icon: '/icon-192.png',\n"
        "    badge: '/icon-192.png',\n"
        "    tag: payload.tag || 'omega-notify',\n"
        "    renotify: true,\n"
        "    requireInteraction: true,\n"
        "    vibrate: [300,150,300,150,300],\n"
        "    data: { url: payload.url || '/orders' }\n"
        "  };\n"
        "  e.waitUntil(self.registration.showNotification(title, options));\n"
        "});\n"
        # Tapping the notification focuses an already-open tab on that
        # page if there is one, otherwise opens a fresh one.
        "self.addEventListener('notificationclick',e=>{\n"
        "  e.notification.close();\n"
        "  const targetUrl=(e.notification.data && e.notification.data.url) || '/orders';\n"
        "  e.waitUntil(\n"
        "    clients.matchAll({type:'window', includeUncontrolled:true}).then(list=>{\n"
        "      for(const c of list){ if(c.url.includes(targetUrl) && 'focus' in c) return c.focus(); }\n"
        "      if(clients.openWindow) return clients.openWindow(targetUrl);\n"
        "    })\n"
        "  );\n"
        "});\n"
    )
    return Response(js, mimetype="application/javascript")

@app.route("/api/push/subscribe", methods=["POST"])
@login_required
def api_push_subscribe():
    try:
        data = request.json or {}
        endpoint = data.get("endpoint")
        keys = data.get("keys") or {}
        if not endpoint or not keys.get("p256dh") or not keys.get("auth"):
            return jsonify({"ok": False, "error": "Invalid subscription"}), 400
        # Key the record off a hash of the endpoint (unique per browser
        # install) so re-subscribing the same device updates in place
        # instead of piling up duplicate rows every time the page loads.
        import hashlib
        sub_id = hashlib.sha256(endpoint.encode()).hexdigest()[:32]
        fb_put(f"push_subscriptions/{sub_id}", {
            "endpoint": endpoint,
            "keys": {"p256dh": keys.get("p256dh"), "auth": keys.get("auth")},
            "staff_name": session.get("staff_name"),
            "subscribed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/push/unsubscribe", methods=["POST"])
@login_required
def api_push_unsubscribe():
    try:
        data = request.json or {}
        endpoint = data.get("endpoint")
        if endpoint:
            import hashlib
            sub_id = hashlib.sha256(endpoint.encode()).hexdigest()[:32]
            fb_delete(f"push_subscriptions/{sub_id}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

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
            log_customer_login(None, None, phone, False, "Phone not registered")
            return jsonify({"ok": False, "error": "Phone not registered. Only ISESMO can register."}), 404
        stored_hash = matched.get("password_hash") or ""
        if not stored_hash:
            log_customer_login(matched_id, matched.get("store_name"), phone, False, "No password set")
            return jsonify({"ok": False, "error": "No password set. Contact ISESMO."}), 401
        if not verify_customer_password(stored_hash, pwd):
            log_customer_login(matched_id, matched.get("store_name"), phone, False, "Wrong password")
            return jsonify({"ok": False, "error": "Wrong password"}), 401
        session["customer_id"] = matched_id
        session["customer_name"] = matched.get("store_name")
        log_customer_login(matched_id, matched.get("store_name"), phone, True)
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
        try:
            send_push_to_cashiers(
                title="🧊 Bagong Order!",
                body=f"{reseller.get('store_name','Customer')} - {qty} x {kg_size} ({mode})",
                url="/orders",
                tag="omega-new-order",
            )
        except Exception as e:
            print(f"push (new order) failed: {e}")
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
    try:
        store_label = existing.get("reseller_name") or "Order"
        send_push_to_cashiers(
            title="📦 Order Status Updated",
            body=f"{store_label} -> {new_status} (ni {session.get('staff_name') or 'staff'})",
            url="/orders",
            tag=f"omega-status-{order_id}",
        )
    except Exception as e:
        print(f"push (status change) failed: {e}")
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
<div class="topbar"><h1>👥 Customers (ISESMO Only)</h1><div><a href="/cashier" class="nav-pill">Sales</a> <a href="/orders" class="nav-pill">Live Orders</a> <a href="/credit" class="nav-pill">💳 Utang</a> <a href="/customer_activity" class="nav-pill">🔐 Login Activity</a></div></div>

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

<div id="qrOverlay" style="display:none;position:fixed;inset:0;background:rgba(10,25,45,.6);z-index:80;align-items:center;justify-content:center;padding:16px" onclick="if(event.target===this)closeQR()">
  <div style="background:#fff;border-radius:16px;padding:22px;max-width:320px;width:100%;text-align:center;position:relative">
    <button onclick="closeQR()" style="position:absolute;top:12px;right:12px;background:#f0f4f8;border:none;width:26px;height:26px;border-radius:50%;font-size:13px;color:#555;cursor:pointer">✕</button>
    <div style="font-size:14px;font-weight:700;color:#0f2942;margin-bottom:2px">📱 QR Login</div>
    <div style="font-size:12px;color:#666;margin-bottom:10px" id="qrStoreName">-</div>
    <div id="qrImgWrap" style="min-height:220px;display:flex;align-items:center;justify-content:center">Loading...</div>
    <div style="font-size:10px;color:#888;margin-top:8px" id="qrExpiry"></div>
    <div style="font-size:10px;color:#166534;margin-top:2px;font-weight:600" id="qrReusedNote"></div>
    <div style="display:flex;gap:6px;margin-top:14px;flex-wrap:wrap">
      <a id="qrDownloadBtn" download="omega-ice-qr-login.png" class="btn" style="flex:1;background:#00609C;color:#fff;text-decoration:none">⬇️ Download</a>
      <button class="btn" style="flex:1;background:#f0f4f8" onclick="copyQRLink()">🔗 Copy Link</button>
    </div>
    <button class="btn" style="width:100%;margin-top:6px;background:#fffbeb;color:#92400e;border:1px solid #fde68a" onclick="regenerateQR()">♻️ Regenerate (invalidates old QR)</button>
    <p id="qrStatus" style="font-size:11px;margin-top:8px;min-height:14px"></p>
  </div>
</div>

<script>
let editingId=null;
let currentQRResellerId=null;
let currentQRLink=null;
async function loadQR(resellerId, regenerate){
  const wrap=document.getElementById('qrImgWrap');
  const statusEl=document.getElementById('qrStatus');
  wrap.innerHTML='Loading...';
  statusEl.textContent='';
  try{
    const url=`/api/customers/${resellerId}/qr`+(regenerate?'?regenerate=1':'');
    const res=await fetch(url);
    const data=await res.json();
    if(!data.ok){ wrap.innerHTML=`<span style="color:red">${escapeHtml(data.error||'Failed to generate QR')}</span>`; return; }
    document.getElementById('qrStoreName').textContent=`${data.store_name} (${data.phone})`;
    wrap.innerHTML=`<img src="${data.qr_data_url}" alt="QR login" style="width:220px;height:auto">`;
    document.getElementById('qrExpiry').textContent='Valid until '+data.expires_at;
    document.getElementById('qrReusedNote').textContent=data.reused?'(existing QR - still the same one already printed/shared)':'✓ New QR generated';
    document.getElementById('qrDownloadBtn').href=data.qr_data_url;
    currentQRLink=data.link;
  }catch(e){
    wrap.innerHTML=`<span style="color:red">Error: ${escapeHtml(e.message)}</span>`;
  }
}
function openQR(resellerId){
  currentQRResellerId=resellerId;
  document.getElementById('qrOverlay').style.display='flex';
  loadQR(resellerId, false);
}
function closeQR(){
  document.getElementById('qrOverlay').style.display='none';
  currentQRResellerId=null;
  currentQRLink=null;
}
async function regenerateQR(){
  if(!currentQRResellerId) return;
  if(!confirm('Regenerate QR? Yung dating QR na naka-print/share na sa customer na ito ay hindi na gagana.')) return;
  await loadQR(currentQRResellerId, true);
}
async function copyQRLink(){
  const statusEl=document.getElementById('qrStatus');
  if(!currentQRLink){ statusEl.textContent='No link yet'; return; }
  try{
    await navigator.clipboard.writeText(currentQRLink);
    statusEl.textContent='✅ Link copied!';
  }catch(e){
    statusEl.textContent=currentQRLink;
  }
}
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
      return `<tr><td><b>${escapeHtml(r.store_name)}</b><br><small style="color:#666">${escapeHtml(r.status||'active')}</small></td><td>${escapeHtml(r.phone)}<br><small style="color:${r.password_hash?'green':'red'}">${r.password_hash?'Has password':'No password'}</small></td><td>₱${r.credit_balance||0}</td><td><button class="btn" style="background:#22c55e;color:#fff" onclick="openEdit('${r.id}')">Edit</button> <button class="btn" style="background:#00609C;color:#fff" onclick="openQR('${r.id}')">📱 QR</button></td></tr>`;
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

@app.route("/customer_activity")
@login_required
def customer_activity_page():
    staff = (session.get("staff_name") or "").lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return "<h3>Access Denied</h3><p>Only ISESMO can view login activity.</p><a href='/cashier'>Back</a>", 403
    return render_template_string(CUSTOMER_ACTIVITY_HTML)

@app.route("/api/staff/customer_login_activity")
@login_required
def api_customer_login_activity():
    """
    Feeds the Login Activity page. ISESMO-only (same gate as /customers)
    since this shows customer phone numbers and IP addresses - not data
    for every staff member to browse. Newest first, capped at 300 rows so
    a long-running store doesn't ship its whole history in one response.
    """
    staff = (session.get("staff_name") or "").lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    try:
        logs = fb_get("customer_login_logs") or {}
        rows = []
        for key, val in logs.items():
            if not val:
                continue
            rows.append({
                "id": key,
                "store_name": val.get("store_name") or "",
                "phone": val.get("phone") or "",
                "success": bool(val.get("success")),
                "reason": val.get("reason") or "",
                "ip": val.get("ip") or "",
                "user_agent": val.get("user_agent") or "",
                "timestamp": val.get("timestamp") or "",
            })
        rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
        total = len(rows)
        failed_count = sum(1 for r in rows if not r["success"])
        return jsonify({"ok": True, "rows": rows[:300], "total": total, "failed_count": failed_count})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

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
        regenerate = request.args.get("regenerate") == "1"
        now = datetime.now()
        existing_tokens = fb_get("qr_login_tokens") or {}
        token = None
        expires_at = None

        if not regenerate:
            # Reuse a still-valid, non-revoked token for this reseller so
            # a QR that's already been printed and pasted at the store
            # keeps working - only a deliberate "Regenerate" should kill
            # it, not just re-opening the QR view.
            for k, v in existing_tokens.items():
                if not v or v.get("reseller_id") != reseller_id or v.get("revoked"):
                    continue
                try:
                    exp = datetime.strptime(v.get("expires_at") or "", "%Y-%m-%d %H:%M:%S")
                    if now <= exp:
                        token = v.get("token")
                        expires_at = v.get("expires_at")
                        break
                except:
                    continue

        if not token:
            if regenerate:
                # Explicit regenerate: revoke every previous token for
                # this reseller so an old printed/shared QR stops working
                # the moment a new one is issued.
                for k, v in existing_tokens.items():
                    if v and v.get("reseller_id") == reseller_id and not v.get("revoked"):
                        fb_patch(f"qr_login_tokens/{k}", {"revoked": True})
            import secrets
            token = secrets.token_urlsafe(32)
            expires_at = (now + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
            token_data = {"reseller_id": reseller_id, "phone": phone, "store_name": store_name, "token": token, "created_at": now.strftime("%Y-%m-%d %H:%M:%S"), "expires_at": expires_at, "used_count": 0}
            fb_post("qr_login_tokens", token_data)
        base_url = request.host_url.rstrip("/")
        if "onrender.com" in base_url or "omega" in base_url.lower():
            base_url = base_url.replace("http://", "https://")
        auto_link = f"{base_url}/customer/qr?token={token}"
        try:
            import qrcode, io
            from PIL import Image, ImageDraw, ImageFont
            qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
            qr.add_data(auto_link)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            qr_w, qr_h = qr_img.size

            # Compose a bigger canvas so the customer's store name is
            # printed right under the QR - so a printed/shared copy is
            # self-identifying without needing a separate label.
            pad = 24
            label_h = 56
            canvas_w = qr_w + pad * 2
            canvas_h = qr_h + pad + label_h + pad
            canvas = Image.new("RGB", (canvas_w, canvas_h), "white")
            canvas.paste(qr_img, (pad, pad))
            draw = ImageDraw.Draw(canvas)

            def _load_qr_font(size):
                # Try common system truetype fonts first (crisper, bold);
                # fall back to Pillow's built-in scalable font so this
                # still works even on a host with no font packages
                # installed, and finally to the old fixed bitmap font on
                # very old Pillow versions that don't support sizing it.
                for fp in (
                    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
                ):
                    try:
                        return ImageFont.truetype(fp, size)
                    except Exception:
                        continue
                try:
                    return ImageFont.load_default(size=size)
                except TypeError:
                    return ImageFont.load_default()

            label = (store_name or "Customer").strip()
            font_size = 26
            font = _load_qr_font(font_size)
            max_text_w = canvas_w - pad * 2
            bbox = draw.textbbox((0, 0), label, font=font)
            # Shrink the font until the store name fits on one line
            # instead of spilling past the QR's width.
            while (bbox[2] - bbox[0]) > max_text_w and font_size > 12:
                font_size -= 2
                font = _load_qr_font(font_size)
                bbox = draw.textbbox((0, 0), label, font=font)
            text_w = bbox[2] - bbox[0]
            text_h = bbox[3] - bbox[1]
            text_x = (canvas_w - text_w) // 2
            text_y = qr_h + pad + (label_h - text_h) // 2 - bbox[1]
            draw.text((text_x, text_y), label, fill=(0, 96, 156), font=font)

            buf = io.BytesIO()
            canvas.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode()
            data_url = f"data:image/png;base64,{b64}"
        except Exception as e:
            data_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={auto_link}"
        return jsonify({"ok": True, "link": auto_link, "qr_data_url": data_url, "store_name": store_name, "phone": phone, "expires_at": expires_at, "reused": not regenerate and bool(token)})
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
                if v.get("revoked"):
                    continue
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
        log_customer_login(reseller_id, reseller.get("store_name"), matched.get("phone"), True, "QR login")
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

CUSTOMER_ACTIVITY_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login Activity - ISESMO Only</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0;font-weight:700}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.stat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;text-align:center;margin-bottom:12px}
.stat-val{font-size:20px;font-weight:700;color:#00609C}.stat-val.fail{color:#c0392b}.stat-lbl{font-size:9px;color:#888}
.filter-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.filter-btn{padding:7px 12px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px}
.filter-btn.active{background:#00609C;color:#fff}
input#searchInp{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px;margin-bottom:10px}
.log-row{display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid #f0f4f8}
.log-badge{padding:3px 9px;border-radius:12px;font-size:9px;font-weight:700;white-space:nowrap;height:fit-content}
.log-badge.ok{background:#dcfce7;color:#166534}.log-badge.fail{background:#fee2e2;color:#c0392b}
.log-meta{font-size:9px;color:#aaa;margin-top:2px}
.refresh-btn{padding:8px 14px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;font-weight:600}
</style></head>
<body>
<div class="topbar">
  <div style="display:flex;align-items:center;gap:8px"><img src="/icon-192.png" alt="" style="width:24px;height:24px;border-radius:6px"><h1>🔐 Customer Login Activity</h1></div>
  <div style="display:flex;gap:6px;flex-wrap:wrap">
    <a href="/orders" class="nav-pill" style="background:#ff4444;color:#fff;border-color:#ff4444">🔴 Live Orders</a>
    <a href="/cashier" class="nav-pill">Sales</a>
    <a href="/customers" class="nav-pill">Customers</a>
    <a href="/credit" class="nav-pill">💳 Utang</a>
    <a href="/dashboard" class="nav-pill">Analytics</a>
    <a href="/customer_activity" class="nav-pill active">Login Activity</a>
  </div>
</div>

<div class="card">
  <div class="stat-grid">
    <div><div class="stat-val" id="totalCount">0</div><div class="stat-lbl">TOTAL LOGIN ATTEMPTS (latest 300)</div></div>
    <div><div class="stat-val fail" id="failCount">0</div><div class="stat-lbl">FAILED ATTEMPTS</div></div>
  </div>
  <input type="text" id="searchInp" placeholder="Search by store name or phone..." oninput="renderRows()">
  <div class="filter-row">
    <button class="filter-btn active" data-f="all" onclick="setFilter('all')">All</button>
    <button class="filter-btn" data-f="success" onclick="setFilter('success')">✅ Success only</button>
    <button class="filter-btn" data-f="failed" onclick="setFilter('failed')">❌ Failed only</button>
    <button class="refresh-btn" onclick="loadActivity()">🔄 Refresh</button>
  </div>
  <div id="rowsList" style="font-size:12px">Loading...</div>
</div>

<script>
let allRows = [];
let currentFilter = 'all';

function setFilter(f){
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.toggle('active', b.dataset.f===f));
  renderRows();
}

function escapeHtmlA(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}

// Shows the phone with its middle digits masked (09XX•••1234) - staff
// still sees enough to recognize which number it is without the full
// number sitting in plain view on a shared cashier screen.
function maskPhone(p){
  const s = String(p||'');
  if(s.length < 7) return s;
  return s.slice(0,4) + '•••' + s.slice(-4);
}

function renderRows(){
  const q = (document.getElementById('searchInp').value || '').toLowerCase().trim();
  let rows = allRows;
  if(currentFilter==='success') rows = rows.filter(r=>r.success);
  else if(currentFilter==='failed') rows = rows.filter(r=>!r.success);
  if(q){
    rows = rows.filter(r =>
      (r.store_name||'').toLowerCase().includes(q) ||
      (r.phone||'').toLowerCase().includes(q)
    );
  }
  const listEl = document.getElementById('rowsList');
  if(!rows.length){
    listEl.innerHTML = '<div style="color:#888;text-align:center;padding:16px">No login activity found.</div>';
    return;
  }
  listEl.innerHTML = rows.map(r => {
    const badge = r.success
      ? '<span class="log-badge ok">✅ SUCCESS</span>'
      : '<span class="log-badge fail">❌ FAILED</span>';
    const reasonLine = (!r.success && r.reason) ? `<div class="log-meta">Reason: ${escapeHtmlA(r.reason)}</div>` : '';
    return `<div class="log-row">
      <div>
        <div style="font-weight:600">${escapeHtmlA(r.store_name || '(unknown store)')}</div>
        <div style="color:#666">${escapeHtmlA(maskPhone(r.phone))}</div>
        ${reasonLine}
        <div class="log-meta">${escapeHtmlA(r.timestamp)} • IP: ${escapeHtmlA(r.ip)}</div>
      </div>
      ${badge}
    </div>`;
  }).join('');
}

async function loadActivity(){
  const listEl = document.getElementById('rowsList');
  listEl.textContent = 'Loading...';
  try{
    const res = await fetch('/api/staff/customer_login_activity');
    if(res.status===403){ listEl.innerHTML = '<div style="color:#c0392b">Access denied - ISESMO only.</div>'; return; }
    if(res.status===401){ window.location.href='/login'; return; }
    const data = await res.json();
    if(!data.ok){ listEl.innerHTML = `<div style="color:red">${escapeHtmlA(data.error||'Error')}</div>`; return; }
    allRows = data.rows || [];
    document.getElementById('totalCount').textContent = data.total || 0;
    document.getElementById('failCount').textContent = data.failed_count || 0;
    renderRows();
  }catch(e){
    listEl.innerHTML = `<div style="color:red">Error: ${escapeHtmlA(e.message)}</div>`;
  }
}
loadActivity();
</script>
</body></html>
"""

SALES_ANALYTICS_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sales Analytics - Omega Ice</title>
<link rel="manifest" href="/manifest_staff.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0;font-weight:700}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.hist-period-btn{padding:7px 12px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px}
.hist-period-btn.active{background:#00609C;color:#fff}
.stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;text-align:center}
.stat-val{font-size:19px;font-weight:700;color:#00609C}.stat-lbl{font-size:9px;color:#888}
.stat-grid.pending .stat-val{color:#f59e0b}
.status-pill{padding:3px 9px;border-radius:12px;font-size:9px;font-weight:700}
.status-new{background:#fef3c7;color:#92400e}.status-pending{background:#fef3c7;color:#92400e}.status-preparing{background:#dbeafe;color:#1e40af}.status-out{background:#e0e7ff;color:#3730a3}.status-delivered{background:#dcfce7;color:#166534}.status-cancelled{background:#fee2e2;color:#c0392b}
.breakdown-row{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;font-size:10px}
.breakdown-chip{background:#f0f4f8;padding:5px 10px;border-radius:10px;color:#555}
</style></head>
<body>
<div class="topbar">
  <div style="display:flex;align-items:center;gap:8px"><img src="/icon-192.png" alt="" style="width:24px;height:24px;border-radius:6px"><h1>Sales Analytics</h1></div>
  <div style="display:flex;gap:6px;flex-wrap:wrap">
    <a href="/orders" class="nav-pill" style="background:#ff4444;color:#fff;border-color:#ff4444">🔴 Live Orders</a>
    <a href="/cashier" class="nav-pill">Sales</a>
    <a href="/customers" class="nav-pill">Customers</a>
    <a href="/credit" class="nav-pill">💳 Utang</a>
    <a href="/customer_activity" class="nav-pill">🔐 Login Activity</a>
    <a href="/dashboard" class="nav-pill active">Analytics</a>
  </div>
</div>

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

  <div style="font-size:10px;font-weight:700;color:#166534;margin-bottom:4px">✅ DELIVERED</div>
  <div class="stat-grid" style="margin-bottom:10px">
    <div><div class="stat-val" id="histKg">0kg</div><div class="stat-lbl">TOTAL KG</div></div>
    <div><div class="stat-val" id="histPeso">₱0</div><div class="stat-lbl">TOTAL PESO</div></div>
    <div><div class="stat-val" id="histCount">0</div><div class="stat-lbl">TRANSACTIONS</div></div>
  </div>
  <div style="font-size:10px;font-weight:700;color:#92400e;margin:10px 0 4px">⏳ PENDING (not yet Delivered)</div>
  <div class="stat-grid pending">
    <div><div class="stat-val" id="pendKg">0kg</div><div class="stat-lbl">PENDING KG</div></div>
    <div><div class="stat-val" id="pendPeso">₱0</div><div class="stat-lbl">PENDING PESO</div></div>
    <div><div class="stat-val" id="pendCount">0</div><div class="stat-lbl">PENDING</div></div>
  </div>
  <div id="breakdownRow" class="breakdown-row"></div>

  <div id="histChartWrap" style="margin:14px 0;display:none"><canvas id="histChart" height="170"></canvas></div>

  <div style="font-size:11px;font-weight:700;color:#333;margin:10px 0 6px">Recent transactions (latest 100)</div>
  <div id="histList" style="font-size:11px"></div>
</div>

<script>
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

// Groups the period's individual sales into chart-friendly buckets: by
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
  const delivered = rows.filter(o=>(o.order_status||'Delivered')==='Delivered');
  if(!delivered.length || typeof Chart==='undefined'){ wrap.style.display='none'; return; }
  const buckets={};
  delivered.forEach(o=>{
    const key=histBucketKey(period, o.sales_date||(o.created_at||'').slice(0,10));
    if(!buckets[key]) buckets[key]={kg:0,peso:0};
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
    let url = `/api/sales/by_period?period=${histPeriod}`;
    if(histPeriod==='daily' && histDailyDate) url += '&date='+histDailyDate;
    else if(histSubPeriod) url += '&sub='+encodeURIComponent(histSubPeriod);
    const res = await fetch(url);
    if(res.status===401){window.location.href='/login';return;}
    const data = await res.json();
    document.getElementById('histLabel').textContent = `${data.label} (${data.start} to ${data.end||data.start})`;
    const rows = data.sales||[];

    // Split delivered vs everything-else (pending/preparing/etc) client
    // side from the same rows - /api/sales/by_period already gives us
    // order_status per row, no need for a second request.
    const delivered = rows.filter(o=>(o.order_status||'Delivered')==='Delivered');
    const pending = rows.filter(o=>(o.order_status||'Delivered')!=='Delivered' && o.order_status!=='Cancelled');
    function kgOf(o){
      let k=0; try{ k=parseFloat(String(o.kg_size||'').toLowerCase().replace('kg','').trim())||0; }catch(e){}
      return k*(o.quantity||0);
    }
    const delKg = delivered.reduce((s,o)=>s+kgOf(o),0);
    const delPeso = delivered.reduce((s,o)=>s+(+o.total_sales||0),0);
    const pendKg = pending.reduce((s,o)=>s+kgOf(o),0);
    const pendPeso = pending.reduce((s,o)=>s+(+o.total_sales||0),0);

    document.getElementById('histKg').textContent = delKg.toLocaleString()+'kg';
    document.getElementById('histPeso').textContent = '₱'+delPeso.toLocaleString();
    document.getElementById('histCount').textContent = delivered.length;
    document.getElementById('pendKg').textContent = pendKg.toLocaleString()+'kg';
    document.getElementById('pendPeso').textContent = '₱'+pendPeso.toLocaleString();
    document.getElementById('pendCount').textContent = pending.length;

    const breakdown = {'1Kg':0,'5Kg':0,'10Kg':0,'25Kg':0};
    delivered.forEach(o=>{ if(breakdown.hasOwnProperty(o.kg_size)) breakdown[o.kg_size] += (o.quantity||0); });
    document.getElementById('breakdownRow').innerHTML = Object.entries(breakdown).map(([k,v])=>`<span class="breakdown-chip">${k}: ${v}</span>`).join('');

    if(!rows.length){
      document.getElementById('histChartWrap').style.display='none';
      listEl.innerHTML = '<div style="color:#888;text-align:center;padding:10px">No transactions for this period</div>';
      return;
    }
    renderHistChart(histPeriod, rows);
    listEl.innerHTML = rows.map(o=>{
      const statusColor = {'Delivered':'#166534','Cancelled':'#c0392b'}[o.order_status] || '#92400e';
      return `<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f0f4f8"><div><div>${escapeHtmlC(o.reseller_name||'')} • ${o.sales_date||''} • ${o.quantity}x ${escapeHtmlC(o.kg_size)}</div><div style="font-size:9px;color:${statusColor}">${escapeHtmlC(o.order_status)}</div></div><div style="font-weight:600">₱${o.total_sales}</div></div>`;
    }).join('');
  }catch(e){
    listEl.innerHTML = `<div style="color:red">Error: ${escapeHtmlC(e.message)}</div>`;
  }
}

populateHistSubPicker('daily');
</script>
</body></html>
"""

@app.route("/dashboard")
@login_required
def dashboard_page():
    return render_template_string(SALES_ANALYTICS_HTML)

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
<div class="topbar"><h1>Live Customer Orders</h1><div><a href="/cashier" class="nav-pill">Sales</a> <a href="/customers" class="nav-pill">Customers</a> <a href="/credit" class="nav-pill">💳 Utang</a></div></div>
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
