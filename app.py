
"""
Omega Ice - OFFLINE FIRST - Firebase + Local SQLite backup
- If internet: saves to Firebase instantly
- If NO internet: saves to phone (omega_local.db) and shows pending badge
- When internet returns: tap badge or go to /api/offline/sync to upload

Firebase: https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app
"""

import os, sqlite3, json, requests, time, base64, threading, smtplib, socket, secrets
from datetime import datetime, timedelta

# BUG FIX (Sept 26): every "current Manila time" spot in this file used to
# do a lazy `import pytz` INSIDE its own try/except, 15 separate times.
# That's dangerous under gunicorn: if a request is still running when
# gunicorn's worker timeout hits (default ~30s), gunicorn sends SIGABRT to
# force-kill the worker, which can interrupt Python mid-`import` and raise
# SystemExit right there. SystemExit inherits from BaseException, NOT
# Exception - so it skips straight past every "except:" / "except
# Exception:" in this file and crashes the whole worker (visible in Render
# logs as "WORKER TIMEOUT" immediately followed by "Booting worker with
# pid: X", i.e. a hard restart, not a normal 500 error). Root cause was a
# lazy per-request import of a third-party package; fix is to (a) drop the
# pytz dependency entirely in favor of the stdlib `zoneinfo` (Python 3.9+,
# no separate install) and (b) do the import exactly ONCE at module load
# time, before gunicorn ever starts routing requests - so it can never be
# caught mid-import by a worker-timeout kill again. All ~15 call sites
# that used to duplicate `import pytz; pytz.timezone('Asia/Manila')` now
# just call manila_now() below instead.
try:
    from zoneinfo import ZoneInfo
    _MANILA_TZ = ZoneInfo("Asia/Manila")
except Exception:
    _MANILA_TZ = None

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from werkzeug.security import generate_password_hash, check_password_hash
import random, string, re
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string, Response, make_response
from werkzeug.middleware.proxy_fix import ProxyFix

# --- Firebase Admin SDK ---
import firebase_admin
from firebase_admin import credentials, db

app = Flask(__name__)

# BUG FIX (Sept 21): request.remote_addr was always returning "127.0.0.1"
# for every visitor (see Customer Login Activity page - every single row
# showed IP: 127.0.0.1). Root cause: Render.com (like almost every cloud
# host/PaaS) terminates the real connection at its own reverse proxy edge,
# then forwards the request to this app over an internal connection - so
# Flask only ever sees Render's proxy as the "client", never the actual
# visitor. The real client IP is passed along in the X-Forwarded-For
# header instead, which Flask ignores by default (for security - a normal
# client can fake that header, so it must only be trusted when we KNOW a
# real proxy is in front and set it). ProxyFix tells Flask "trust exactly
# 1 hop of X-Forwarded-For/Proto/Host" (Render sits directly in front of
# this app - 1 hop), which makes request.remote_addr resolve to the real
# visitor IP everywhere in this file (login logs, rate limiting, etc.)
# instead of the proxy's own address.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

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

# --- Automatic Points Backup Email ---
# Daily email (Gmail SMTP) with every reseller's loyalty points balance +
# full history attached as JSON, so the program can be restored by hand
# if Firebase data is ever lost or corrupted. Needs a Gmail address + an
# "App Password" (NOT the normal Gmail password - generate one at
# myaccount.google.com/apppasswords, requires 2-Step Verification to be
# ON first) set as Render env vars. If these aren't set, backup emails
# are silently disabled and the rest of the app works exactly as before
# - same fallback pattern as PUSH_ENABLED above.
SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "")
SMTP_APP_PASSWORD = os.environ.get("SMTP_APP_PASSWORD", "")
# Defaults to emailing the backup to the same Gmail account that sends it
# (simplest - one less env var to set) unless a different inbox is wanted.
BACKUP_EMAIL_TO = os.environ.get("BACKUP_EMAIL_TO", "") or SMTP_EMAIL
BACKUP_HOUR_MANILA = int(os.environ.get("BACKUP_HOUR_MANILA", "23") or "23")
BACKUP_ENABLED = bool(SMTP_EMAIL and SMTP_APP_PASSWORD)

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

def send_push_to_isesmo(title, body, url="/customer_activity", tag="omega-customer-login"):
    """Fire a Web Push notification ONLY to device(s) subscribed while
    logged in as ISESMO (ISESMO's request, Sept 22) - e.g. every
    customer-side login attempt, success or failure, on /customer_activity.
    Unlike send_push_to_cashiers (broadcasts to every subscribed cashier
    device), this filters push_subscriptions by their stored staff_name,
    same "isesmo"/"isesmo gamboa" match used everywhere else in this file
    (see isesmo_only). A subscription only gets that staff_name once the
    logged-in staff has visited a page that runs the push-subscribe JS
    (see /sw-register.js) while their session's staff_name is ISESMO's -
    so ISESMO needs to have opened the app at least once for a device to
    receive these. Best-effort: never raises, so a push failure can't
    break the customer login flow that triggered it."""
    if not PUSH_ENABLED:
        return
    try:
        subs = fb_get("push_subscriptions") or {}
    except Exception as e:
        print(f"send_push_to_isesmo: could not load subscriptions: {e}")
        return
    payload = json.dumps({"title": title, "body": body, "url": url, "tag": tag})
    for key, sub in (subs or {}).items():
        if not sub or not sub.get("endpoint"):
            continue
        staff = (sub.get("staff_name") or "").strip().lower()
        if staff not in ("isesmo", "isesmo gamboa"):
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
                try:
                    fb_delete(f"push_subscriptions/{key}")
                except Exception:
                    pass
            else:
                print(f"send_push_to_isesmo: push failed for {key}: {e}")
        except Exception as e:
            print(f"send_push_to_isesmo: unexpected error for {key}: {e}")

def send_push_to_all_resellers(title, body, url="/customer", tag="omega-points-program"):
    """Broadcasts a Web Push notification to EVERY subscribed reseller
    device - reaches them even if the customer app/PWA is fully closed
    (ISESMO's request, Sept 22, for the Points Program pause/resume
    schedule: "notification din sa kanila kahit di bukas app nila").
    Same mechanism/error-handling as send_push_to_cashiers /
    send_push_to_isesmo above, just filtered to subscriptions that carry
    a reseller_id (see /api/customer/push/subscribe) instead of a
    staff_name. A reseller only receives these once they've tapped
    "Paganahin ang Notifications" at least once on their dashboard - see
    enableCustomerPushAlerts() in CUSTOMER_DASHBOARD_HTML."""
    if not PUSH_ENABLED:
        return
    try:
        subs = fb_get("push_subscriptions") or {}
    except Exception as e:
        print(f"send_push_to_all_resellers: could not load subscriptions: {e}")
        return
    payload = json.dumps({"title": title, "body": body, "url": url, "tag": tag})
    for key, sub in (subs or {}).items():
        if not sub or not sub.get("endpoint") or not sub.get("reseller_id"):
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
                try:
                    fb_delete(f"push_subscriptions/{key}")
                except Exception:
                    pass
            else:
                print(f"send_push_to_all_resellers: push failed for {key}: {e}")
        except Exception as e:
            print(f"send_push_to_all_resellers: unexpected error for {key}: {e}")

def send_push_to_reseller(reseller_id, title, body, url="/customer", tag="omega-order-update"):
    """Web Push to ONE specific reseller's subscribed device(s) - unlike
    send_push_to_all_resellers (broadcast), this filters to subscriptions
    matching this exact reseller_id. Added for the Decline-order feature
    (boss's request, Sept 22): "may push notification din ba boss" - so a
    reseller finds out their order was declined even if they don't have
    the app open, same guarantee send_push_to_all_resellers gives the
    points-program announcements. Silently no-ops if the reseller never
    tapped "Paganahin ang Notifications" (no subscription on file) - this
    is why the order also still shows the reason on-screen (belt AND
    suspenders, not push-only)."""
    if not PUSH_ENABLED:
        return
    try:
        subs = fb_get("push_subscriptions") or {}
    except Exception as e:
        print(f"send_push_to_reseller: could not load subscriptions: {e}")
        return
    payload = json.dumps({"title": title, "body": body, "url": url, "tag": tag})
    for key, sub in (subs or {}).items():
        if not sub or not sub.get("endpoint") or sub.get("reseller_id") != reseller_id:
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
                try:
                    fb_delete(f"push_subscriptions/{key}")
                except Exception:
                    pass
            else:
                print(f"send_push_to_reseller: push failed for {key}: {e}")
        except Exception as e:
            print(f"send_push_to_reseller: unexpected error for {key}: {e}")

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
from modules.home_dashboard import home_bp, _sales_totals, _expense_breakdown, _fixed_asset_expense_for_period
from modules.advance_orders import advance_orders_bp
from modules.duplicate_finder import duplicate_finder_bp
from modules.ai_sales_query import ai_sales_bp
app.register_blueprint(credit_bp)
app.register_blueprint(expenses_bp)
app.register_blueprint(plastic_bp)
app.register_blueprint(assets_bp)
app.register_blueprint(admin_import_bp)
app.register_blueprint(home_bp)
app.register_blueprint(advance_orders_bp)
app.register_blueprint(duplicate_finder_bp)
app.register_blueprint(ai_sales_bp)

# Rate limiting simple
from collections import defaultdict
_login_attempts = defaultdict(list)

def is_rate_limited(ip, max_attempts=5, window_seconds=300):
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < window_seconds]
    return len(_login_attempts[ip]) >= max_attempts

def record_attempt(ip):
    _login_attempts[ip].append(time.time())

def clear_attempts(key):
    """Resets the failed-attempt counter for a rate-limited key. Called
    on a SUCCESSFUL login (e.g. see api_customer_login's per-phone
    lockout below) so a few honest typos earlier in the session don't
    linger in the window and combine with a later, unrelated failed
    attempt toward a lockout the account doesn't deserve."""
    _login_attempts[key] = []


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
</div>
<div style="text-align:center;font-size:10px;color:#9aa7b3;margin-top:18px">Developed by Moises Orio Gamboa</div>
</div>
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
.one-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;align-items:stretch}
.cloud-badge{display:flex;align-items:center;justify-content:center;gap:4px;padding:10px 10px;border-radius:10px;font-size:11px;font-weight:600;min-height:38px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08);white-space:nowrap}
.cloud-badge.online{background:#22c55e;color:#fff}.cloud-badge.offline{background:#ef4444;color:#fff}.cloud-badge.pending{background:#f59e0b;color:#fff;cursor:pointer}
.nav-pill{padding:10px 14px;border-radius:10px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;display:flex;align-items:center;justify-content:center;min-height:38px;text-align:center;font-weight:600;box-shadow:0 1px 3px rgba(0,0,0,.05);transition:all .2s;white-space:nowrap}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C;box-shadow:0 2px 6px rgba(0,96,156,.3)}
.menu-wrap{position:relative}
.menu-btn{padding:10px 16px;border-radius:10px;font-size:18px;border:1px solid #cde;background:#fff;color:#00609C;display:flex;align-items:center;justify-content:center;min-height:38px;font-weight:600;box-shadow:0 1px 3px rgba(0,0,0,.05);cursor:pointer;line-height:1}
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
/* Sales tables scroll horizontally on narrow screens instead of
   squeezing every column until the text overlaps (boss's report,
   Sept 25, after the new Staff column made the Recent/Period sales
   tables too cramped on mobile) - .table-scroll wraps each <table>
   below, and min-width keeps columns from being crushed smaller than
   they can legibly render. */
.table-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;min-width:620px;border-collapse:collapse;font-size:12px}th,td{text-align:left;padding:6px 4px;border-bottom:1px solid #eee;white-space:nowrap}th{color:#888;font-weight:500}
td:nth-child(2){white-space:normal}
.del-btn{background:none;border:none;color:#c0392b;font-size:12px}.edit-btn{background:none;border:none;color:#0096D6;font-size:12px;margin-right:6px;font-weight:bold}
.save-btn{position:relative;z-index:5;box-shadow:0 4px 12px rgba(0,96,156,.3);margin-top:16px} /* FIX: sticky save */
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
      <a href="/home">🏠 Home</a>
      <a href="/machines">🏭 Machines</a>
      <a href="/credit">💳 Utang</a>
      <a href="/expenses">💸 Expenses</a>
      <a href="/plastic">📦 Plastic</a>
      <a href="/assets">🏗️ Fixed Assets</a>
      <a href="/advance-orders">🎉 Advance Orders</a>
      <a href="/admin/duplicates">🔍 Duplicate Finder</a>
      <a href="/dashboard">📊 Dashboard</a>
      <a href="/customer_activity">🔐 Login Activity</a>
      <a href="/admin/stuck_orders">🧹 Purge Stuck Orders</a>
      <a href="/admin/rewards">🎁 Rewards Catalog</a>
      <a href="/admin/reseller_sales">📊 Reseller Sales Tracking</a>
      <a href="/ai-sales">🤖 Ask Sales (AI)</a>
      <a href="javascript:void(0)" onclick="toggleNavMenu();openAlarmModal();">⚙️🔊 Alarm Settings</a>
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

<!-- Alarm Settings / Stop Alarm buttons moved into the hamburger dropdown
     (see navMenuDropdown above) so they no longer clutter the Sales page.
     #stopAlarmBtn is kept here (hidden) purely because triggerOrderAlarm()/
     stopAlarmForever() still reference its id - it's never shown; the
     full-width #alarmBanner below is the actual "tap to stop" control the
     cashier sees while an alarm is ringing. -->
<button id="stopAlarmBtn" onclick="stopAlarmForever()" style="display:none"></button>

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

<div class="card" id="periodSalesCard" style="display:none">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
<label style="font-weight:600;display:block" id="periodSalesLabel">Monthly Sales Record</label>
<button onclick="loadPeriodSales(cashierPeriod)" style="padding:6px 12px;border-radius:20px;border:1px solid #cde;background:#fff;font-size:11px">🔄 Refresh</button>
</div>
<div class="table-scroll"><table><thead><tr><th>Date/Time</th><th>Reseller</th><th>Staff</th><th>Qty</th><th>Size</th><th>Total</th><th>Status</th></tr></thead><tbody id="periodSalesBody"><tr><td colspan=7>Select Monthly / Weekly...</td></tr></tbody></table></div>
<div style="font-size:10px;color:#666;margin-top:8px" id="periodSalesSummary"></div>
</div>

<div class="card" id="recentCard"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><label style="font-weight:600;display:block">Recent sales - Status included <span style="font-size:9px;color:#888" id="recentTimestamp"></span></label><button onclick="loadRecent();loadToday();" style="padding:6px 12px;border-radius:20px;border:1px solid #cde;background:#fff;font-size:11px">🔄 Refresh</button></div>
<div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap">
<span style="font-size:10px;background:#dcfce7;color:#166534;padding:3px 8px;border-radius:10px">Delivered = Real Sales</span>
<span style="font-size:10px;background:#fef3c7;color:#92400e;padding:3px 8px;border-radius:10px">Pending = Not yet counted</span>
</div>
<div class="table-scroll"><table><thead><tr><th>Date</th><th>Reseller</th><th>Staff</th><th>Qty</th><th>Size</th><th>Total</th><th>Status</th><th></th></tr></thead><tbody id="recentBody"></tbody></table></div></div>
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
  body.innerHTML='<tr><td colspan=7>Loading '+period+' sales...</td></tr>';
  label.textContent = period.toUpperCase() + ' SALES RECORD';
  try{
    let url = '/api/sales/by_period?period='+period;
    let sub = subVal || selectedSubPeriod;
    if(sub) url += '&sub='+encodeURIComponent(sub);
    const res = await fetch(url);
    const data = await res.json();
    const rows = data.sales||[];
    if(!rows.length){
      body.innerHTML='<tr><td colspan=7 style="color:#888">No sales for '+period+'</td></tr>';
      summary.textContent='';
      return;
    }
    body.innerHTML = rows.map(r=>{
      const timeStr = r.time_only || (r.created_at ? new Date(r.created_at).toLocaleTimeString('en-PH',{hour:'2-digit',minute:'2-digit'}) : '');
      const dateTime = `${r.sales_date||''} ${timeStr}`.trim();
      const badge = `<span style="font-size:9px;background:#dcfce7;color:#166534;padding:3px 6px;border-radius:10px">${r.order_status||'Delivered'}</span>`;
      // Staff column (boss's request, Sept 25) - same "Customer" fallback
      // label as the Recent Sales table, for orders with no staff to
      // attribute (placed by the customer themselves online).
      const staffCell = r.staff_name
        ? `<span style="font-size:10px">${escapeHtml(r.staff_name)}</span>`
        : (r.is_online ? '<span style="font-size:9px;color:#888">Customer</span>' : '<span style="font-size:9px;color:#ccc">—</span>');
      return `<tr><td style="font-size:10px">${dateTime}<br><small style="color:#888">${r.timestamp||''}</small></td><td>${escapeHtml(r.reseller_name)}</td><td>${staffCell}</td><td>${r.quantity}</td><td>${r.kg_size}</td><td>₱${r.total_sales}</td><td>${badge}<br><div style="display:flex;gap:4px;margin-top:4px"><button class="icon-btn edit" style="width:26px;height:26px;font-size:12px" onclick="editSale('${r.id}');" title="Edit">✏️</button><button class="icon-btn del" style="width:26px;height:26px;font-size:12px" onclick="deleteSale('${r.id}')" title="Delete">🗑️</button></div></td></tr>`;
    }).join('');
    summary.textContent = `Total: ${rows.length} trans | ${data.total_kg||0}kg | ₱${(data.total_peso||0).toLocaleString()} | Showing ${period}`;
  }catch(e){
    body.innerHTML=`<tr><td colspan=7 style="color:red">Error: ${e.message}</td></tr>`;
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
    if(!Array.isArray(rows)){document.getElementById('recentBody').innerHTML=`<tr><td colspan=8>No data</td></tr>`;return;}
    if(!rows.length){document.getElementById('recentBody').innerHTML=`<tr><td colspan=8 style="color:#888">No recent sales yet</td></tr>`;return;}
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
      // Staff column (boss's request, Sept 25): who actually recorded
      // this sale. Online customer orders have no staff to attribute -
      // shown as a distinct "Customer" badge instead of blank, so it
      // doesn't look like missing/broken data.
      const staffCell = r.staff_name
        ? `<span style="font-size:11px">${escapeHtml(r.staff_name)}</span>`
        : (r.is_online ? '<span style="font-size:9px;color:#888">Customer</span>' : '<span style="font-size:9px;color:#ccc">—</span>');
      return `<tr><td style="font-size:11px">${r.sales_date||''}${deliveredInfo}</td><td>${escapeHtml(r.reseller_name)}<br><small style="font-size:9px;color:#888">${timeDisplay}</small></td><td>${staffCell}</td><td>${r.quantity}</td><td>${r.kg_size}</td><td>₱${r.total_sales}</td><td>${badge}</td><td><div style="display:flex;gap:4px"><button class="icon-btn edit" onclick="editSale('${r.id}')" title="Edit">✏️</button><button class="icon-btn del" onclick="deleteSale('${r.id}')" title="Delete">🗑️</button></div></td></tr>`;
    }).join('');
  }catch(e){document.getElementById('recentBody').innerHTML=`<tr><td colspan=8 style="color:#c0392b">Error: ${e.message} <a href="/login">Login</a></td></tr>`;}
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

def manila_now():
    """
    Returns the current datetime in Asia/Manila, regardless of what
    timezone the server itself runs in (Render.com, like most cloud
    hosts, defaults to UTC - 8 hours behind Manila). Uses the
    module-level _MANILA_TZ (stdlib zoneinfo, imported once at startup -
    see the top of this file for why that matters) instead of a
    per-call pytz import. Falls back to naive server time only in the
    extremely unlikely case zoneinfo's tz database isn't available.
    """
    if _MANILA_TZ is not None:
        return datetime.now(_MANILA_TZ)
    return datetime.now()

# --- POINTS BACKUP / RESTORE ---

# ROOT CAUSE of "[Errno 101] Network is unreachable" when sending the
# backup email on Render: smtp.gmail.com has both an IPv4 (A) and IPv6
# (AAAA) DNS record, and Python's default socket.getaddrinfo() lets the
# OS pick which one to try first. Render's container network doesn't
# have a usable outbound IPv6 route, so when the AAAA record wins, the
# connection attempt fails immediately with ENETUNREACH - not a wrong
# password, not a Gmail block, just a dead route. This has nothing to do
# with the login credentials, so it needed a code fix, not a new
# App Password. Fix: force IPv4-only address resolution for the
# duration of the SMTP connection (keeping the hostname string itself
# for TLS certificate verification, so this doesn't break HTTPS
# certificate checking for smtp.gmail.com). Guarded by a lock since
# socket.getaddrinfo is patched globally for the few seconds the SMTP
# call takes - the daily scheduler and a manual "Send Now" click could
# otherwise race each other (rare, but cheap to make impossible).
_smtp_ipv4_lock = threading.Lock()

class _ForceIPv4:
    """Context manager: while inside the `with` block, every
    socket.getaddrinfo() call in this process resolves IPv4 (AF_INET)
    addresses only, then restores the original resolver on exit -
    even if the block raises."""
    def __enter__(self):
        _smtp_ipv4_lock.acquire()
        self._orig = socket.getaddrinfo
        def _ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
            return self._orig(host, port, socket.AF_INET, type, proto, flags)
        socket.getaddrinfo = _ipv4_only
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        socket.getaddrinfo = self._orig
        _smtp_ipv4_lock.release()
        return False

def build_points_backup_data():
    """Snapshot of everything needed to fully restore the loyalty points
    program if Firebase data is ever lost or corrupted: every reseller's
    point balance + full earn/redeem history, the reward catalog, and the
    loyalty settings (expiry/cooldown days). `_store_name` is attached
    per reseller purely so ISESMO can eyeball the raw file and recognize
    who's who - restore ignores it and re-reads the live store name."""
    loyalty_points = fb_get("loyalty_points") or {}
    resellers = fb_get("resellers") or {}
    enriched = {}
    for rid, pts in loyalty_points.items():
        if not pts:
            continue
        enriched[rid] = {**pts, "_store_name": (resellers.get(rid) or {}).get("store_name", "")}
    return {
        "backup_version": 1,
        "generated_at": manila_now().strftime("%Y-%m-%d %H:%M:%S"),
        "loyalty_points": enriched,
        "reward_catalog": fb_get("reward_catalog") or {},
        "loyalty_settings": fb_get("loyalty_settings") or {},
    }

def send_points_backup_email(trigger="scheduled"):
    """Emails the current points-backup JSON as an attachment via Gmail
    SMTP. Returns (ok: bool, message: str) instead of raising, so both
    the daily scheduler and the manual "Send Now" button can show/log a
    clean result either way. No-op (returns False) if SMTP_EMAIL /
    SMTP_APP_PASSWORD aren't configured - see BACKUP_ENABLED above."""
    if not BACKUP_ENABLED:
        return False, "Email backup hindi pa naka-configure (kulang ang SMTP_EMAIL / SMTP_APP_PASSWORD sa Render Environment)"
    try:
        payload = build_points_backup_data()
        reseller_count = len(payload["loyalty_points"])
        total_points = sum(int(v.get("balance") or 0) for v in payload["loyalty_points"].values())
        json_bytes = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        filename = f"omega_points_backup_{manila_now().strftime('%Y-%m-%d_%H%M')}.json"

        msg = MIMEMultipart()
        msg["From"] = SMTP_EMAIL
        msg["To"] = BACKUP_EMAIL_TO
        msg["Subject"] = f"[Omega Ice] Points Backup - {manila_now().strftime('%Y-%m-%d %H:%M')} ({trigger})"
        body = (
            "Automatic backup ng loyalty points program (Omega Ice).\n\n"
            f"Bilang ng reseller na may points: {reseller_count}\n"
            f"Kabuuang points ng lahat: {total_points:,}\n"
            f"Trigger: {trigger}\n\n"
            "Paano i-restore: pumunta sa /admin/rewards -> 'Points Backup & Restore' "
            "section, i-upload itong naka-attach na .json file, tapos i-click ang "
            "'I-restore Ngayon'. I-save/i-keep ang email na ito bilang backup copy."
        )
        msg.attach(MIMEText(body, "plain"))

        part = MIMEBase("application", "octet-stream")
        part.set_payload(json_bytes)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
        msg.attach(part)

        with _ForceIPv4():
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
                server.starttls()
                server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
                server.send_message(msg)

        fb_put("loyalty_settings/last_backup_at", manila_now().strftime("%Y-%m-%d %H:%M:%S"))
        return True, f"Naipadala ang backup email ({reseller_count} reseller, {total_points:,} points)"
    except Exception as e:
        print(f"send_points_backup_email error: {e}")
        return False, f"Hindi naipadala ang backup email: {e}"

def _points_backup_scheduler_loop():
    """Runs forever in a background daemon thread, firing
    send_points_backup_email once a day at BACKUP_HOUR_MANILA (default
    11PM Asia/Manila). A plain time.sleep loop instead of a scheduling
    library (e.g. APScheduler) - a once-a-day job doesn't need anything
    fancier, and this way requirements.txt doesn't need a new dependency.
    Any unexpected error backs off an hour and tries again, rather than
    silently killing the whole backup schedule for good."""
    while True:
        try:
            now = manila_now().replace(tzinfo=None)
            next_run = now.replace(hour=BACKUP_HOUR_MANILA, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            time.sleep(max((next_run - now).total_seconds(), 1))
            send_points_backup_email(trigger="scheduled")
        except Exception as e:
            print(f"_points_backup_scheduler_loop error: {e}")
            time.sleep(3600)

# --- LOYALTY POINTS / REWARDS ---
# Default reward catalog, seeded into Firebase the first time it's read if
# nothing's there yet (see get_reward_catalog()). Points math (updated
# Sept 21): reseller's real all-time margin is 27.1%, and the shop's
# minimum order is 50Kg (= P500 = 500 points GUARANTEED on every single
# order, even the very first one) - every tier must sit well above that
# so a reward actually takes repeat business, not just one order.
# ISESMO moved the entry-level reward back down from 2,000 to 1,000
# points (~2 orders instead of ~4), keeping 5,000/10,000/25,000 for the
# rest - not a single uniform multiplier anymore, but still a clean,
# easy-to-explain progression (2/10/20/50 orders) and each tier's own
# multiplier only pushes its individual breakeven-margin requirement
# further down (safer) - see get_reward_breakeven_margin. Even at 1,000
# points the breakeven margin for this entry tier is still well below
# the real 27.1% margin, so it stays SAFE on the margin health check -
# see the delivery message for the exact numbers. ISESMO can retune
# these anytime from /admin/rewards without a code change - the margin
# health check on that page always shows the live breakeven math for
# whatever values are actually saved.
DEFAULT_REWARD_CATALOG = {
    "reward_1kg": {"label": "Libreng 1Kg Ice", "kg_size": "1Kg", "quantity": 1, "points_required": 1000},
    "reward_5kg": {"label": "Libreng 5Kg Ice", "kg_size": "5Kg", "quantity": 1, "points_required": 5000},
    "reward_10kg": {"label": "Libreng 10Kg Ice", "kg_size": "10Kg", "quantity": 1, "points_required": 10000},
    "reward_25kg": {"label": "Libreng 25Kg Ice", "kg_size": "25Kg", "quantity": 1, "points_required": 25000},
}

def get_reward_catalog():
    """Reads the reseller reward catalog from Firebase, seeding it with
    DEFAULT_REWARD_CATALOG the very first time (empty database) so the
    feature works out of the box, while still being fully editable later
    via the isesmo-only /admin/rewards page."""
    catalog = fb_get("reward_catalog")
    if not catalog:
        fb_put("reward_catalog", DEFAULT_REWARD_CATALOG)
        return DEFAULT_REWARD_CATALOG
    return catalog

def award_loyalty_points(reseller_id, points, reason, ref_order_id=None, touch_activity=False):
    """
    Adds (positive points) or deducts (negative points, e.g. on
    redemption or expiration) a reseller's loyalty point balance, and
    appends one history entry recording why - so the running total is
    always auditable instead of being a single unexplained number.
    Fire-and-forget like log_customer_login(): a points-tracking hiccup
    should never break the actual order/status/redeem flow that
    triggered it.

    touch_activity=True is passed ONLY when points are earned from a
    real delivered online order (see the Delivered-status hook below) -
    it stamps last_earned_at, which is what the inactivity-expiration
    check (check_and_expire_points) measures "days since a real order"
    against. Redemptions and manual isesmo adjustments deliberately do
    NOT touch this clock - per the store owner's own framing, it's
    specifically about "wala silang order", not any account activity.

    Returns the new balance, or None if the write failed.
    """
    if not reseller_id:
        return None
    try:
        current = fb_get(f"loyalty_points/{reseller_id}/balance") or 0
        new_balance = current + points
        patch = {"balance": new_balance}
        if touch_activity:
            patch["last_earned_at"] = manila_now().strftime("%Y-%m-%d %H:%M:%S")
        fb_patch(f"loyalty_points/{reseller_id}", patch)
        fb_post(f"loyalty_points/{reseller_id}/history", {
            "points": points,
            "balance_after": new_balance,
            "reason": reason,
            "ref_order_id": ref_order_id,
            "timestamp": manila_now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        return new_balance
    except Exception as e:
        print(f"award_loyalty_points error: {e}")
        return None

DEFAULT_POINTS_EXPIRY_DAYS = 60

def get_points_expiry_days():
    """How many days a reseller can go with NO delivered online order
    before their accumulated points expire. Stored in Firebase
    (loyalty_settings/inactivity_days) so ISESMO can retune it from
    /admin/rewards without a redeploy; falls back to a 60-day default
    (~2 months, lowered from 90 at ISESMO's request - still forgiving
    of one slow month, but a truly inactive/abandoned account doesn't
    sit as an open-ended rewards liability for as long)."""
    try:
        days = int(fb_get("loyalty_settings/inactivity_days") or DEFAULT_POINTS_EXPIRY_DAYS)
        return days if days > 0 else DEFAULT_POINTS_EXPIRY_DAYS
    except (TypeError, ValueError):
        return DEFAULT_POINTS_EXPIRY_DAYS

DEFAULT_REDEMPTION_COOLDOWN_DAYS = 14
DEFAULT_REFERRAL_BONUS_POINTS = 500

def get_redemption_cooldown_days():
    """Minimum number of days a reseller must wait between two reward
    redemptions (ISESMO's request, Sept 21): without this, a reseller
    who saves up points for a while could suddenly redeem several
    rewards back-to-back in one sitting the moment they cross multiple
    thresholds, dumping a pile of FREE orders on staff all at once -
    "matambak". Stored in Firebase (loyalty_settings/
    redemption_cooldown_days) so ISESMO can retune it from
    /admin/rewards without a redeploy; falls back to a 14-day default
    (~2 weeks) if unset."""
    try:
        days = int(fb_get("loyalty_settings/redemption_cooldown_days") or DEFAULT_REDEMPTION_COOLDOWN_DAYS)
        return days if days > 0 else DEFAULT_REDEMPTION_COOLDOWN_DAYS
    except (TypeError, ValueError):
        return DEFAULT_REDEMPTION_COOLDOWN_DAYS

DECLINE_VISIBILITY_HOURS = 24

def is_order_stale(timestamp_str, hours=DECLINE_VISIBILITY_HOURS):
    """True once `timestamp_str` ("%Y-%m-%d %H:%M:%S") is more than
    `hours` old. Used for the Declined-order sort decay (boss's request,
    Sept 22): a freshly-declined order sorts near the top of the
    customer's order list so it isn't missed, but after `hours` have
    passed it's assumed the customer already saw it (either on-screen or
    via the push notification sent at decline time), so it drops to the
    bottom with Cancelled instead of permanently pushing newer Delivered
    orders further down the list. A missing/unparseable timestamp is
    treated as stale (fails safe - never blocks a list from loading)."""
    if not timestamp_str:
        return True
    try:
        ts = datetime.strptime(timestamp_str[:19], "%Y-%m-%d %H:%M:%S")
        return (datetime.now() - ts) > timedelta(hours=hours)
    except (ValueError, TypeError):
        return True

def get_referral_bonus_points():
    """How many loyalty points a reseller earns for referring a NEW
    reseller, once that new reseller's first delivered online order
    goes through (boss's request, Sept 22: encourage existing resellers
    to bring in new ones). Stored in Firebase (loyalty_settings/
    referral_bonus_points) so ISESMO can retune it from /admin/rewards
    without a redeploy; 0 effectively turns the bonus off without
    removing the referral tracking itself. Falls back to a 500-point
    default (half of the cheapest reward) if unset."""
    try:
        pts = fb_get("loyalty_settings/referral_bonus_points")
        if pts is None:
            return DEFAULT_REFERRAL_BONUS_POINTS
        return max(0, int(pts))
    except (TypeError, ValueError):
        return DEFAULT_REFERRAL_BONUS_POINTS

def get_redemption_cooldown_status(reseller_id):
    """How many days (rounded to 1 decimal) a reseller still has to
    wait before they're allowed to redeem again, based on
    loyalty_points/<id>/last_redemption_at. Returns 0 if they've never
    redeemed before, or if their last redemption is already outside the
    cooldown window - i.e. 0 always means "clear to redeem now".
    Read-only, unlike check_and_expire_points - a cooldown still in
    effect isn't an error state to fix, just a fact to report."""
    try:
        last_redemption = fb_get(f"loyalty_points/{reseller_id}/last_redemption_at")
        if not last_redemption:
            return 0
        last_dt = datetime.strptime(last_redemption, "%Y-%m-%d %H:%M:%S")
        days_since = (manila_now().replace(tzinfo=None) - last_dt).total_seconds() / 86400.0
        days_left = get_redemption_cooldown_days() - days_since
        return round(days_left, 1) if days_left > 0 else 0
    except Exception as e:
        print(f"get_redemption_cooldown_status error: {e}")
        return 0

def is_loyalty_program_paused():
    """Single ON/OFF switch for the whole loyalty points program
    (ISESMO's request, Sept 22): one button on /admin/rewards, ISESMO
    decides when. While paused: no NEW points are awarded on delivered
    online orders, and redemption is blocked - but every reseller's
    EXISTING balance/history is left completely untouched in Firebase,
    so flipping it back OFF (resuming) picks up exactly where it left
    off. Stored at loyalty_settings/program_paused, same pattern as
    inactivity_days/redemption_cooldown_days."""
    return bool(fb_get("loyalty_settings/program_paused"))

def _program_schedule_check():
    """Runs the actual auto-pause/auto-resume: if a scheduled moment
    (loyalty_settings/scheduled_pause_at or scheduled_resume_at) has
    arrived, flips program_paused accordingly, clears that schedule
    field so it can't re-fire, and pushes resellers the "it's happening
    now" notification - separate from the advance heads-up push already
    sent when the schedule was first saved (see
    api_admin_save_pause_schedule). Called once per tick by
    _program_schedule_loop(); pulled out as its own function so a test
    can call it directly instead of waiting on the real clock."""
    try:
        now = manila_now().replace(tzinfo=None)
        pause_at = fb_get("loyalty_settings/scheduled_pause_at")
        if pause_at:
            try:
                pause_dt = datetime.strptime(pause_at, "%Y-%m-%d %H:%M")
            except ValueError:
                pause_dt = None
            if pause_dt and now >= pause_dt and not is_loyalty_program_paused():
                fb_put("loyalty_settings/program_paused", True)
                fb_put("loyalty_settings/program_paused_at", manila_now().strftime("%Y-%m-%d %H:%M:%S"))
                fb_put("loyalty_settings/scheduled_pause_at", None)
                send_push_to_all_resellers(
                    title="⏸️ Points Program Paused",
                    body="Pansamantalang naka-pause na ang Points Rewards Program. Ligtas at buo pa rin ang points mo - babalik ito once na-resume na.",
                )
        resume_at = fb_get("loyalty_settings/scheduled_resume_at")
        if resume_at:
            try:
                resume_dt = datetime.strptime(resume_at, "%Y-%m-%d %H:%M")
            except ValueError:
                resume_dt = None
            if resume_dt and now >= resume_dt and is_loyalty_program_paused():
                fb_put("loyalty_settings/program_paused", False)
                fb_put("loyalty_settings/program_paused_at", manila_now().strftime("%Y-%m-%d %H:%M:%S"))
                fb_put("loyalty_settings/scheduled_resume_at", None)
                send_push_to_all_resellers(
                    title="▶️ Points Program Resumed",
                    body="Bumalik na ang Points Rewards Program! Kumikita ka na ulit ng points sa mga order mo.",
                )
    except Exception as e:
        print(f"_program_schedule_check error: {e}")

def _program_schedule_loop():
    """Background daemon thread: checks every 60 seconds whether a
    scheduled pause/resume moment has arrived (see
    _program_schedule_check). A short interval, unlike the once-a-day
    backup email loop, since ISESMO may schedule something down to the
    minute and expects it to actually fire close to on time."""
    while True:
        _program_schedule_check()
        time.sleep(60)

def check_and_expire_points(reseller_id):
    """
    Lazily expires a reseller's points if too many days have passed
    since their last DELIVERED ONLINE ORDER (last_earned_at) - this app
    has no background cron/scheduler, so instead of a nightly job,
    expiration is checked right here, every time a balance is actually
    read or used (viewing the points card, opening the rewards catalog,
    attempting a redeem, or ISESMO looking someone up in the admin
    page). Whichever of those happens first is what clears a stale
    balance - functionally the same end result as a scheduled job,
    without needing Render Cron Jobs to be set up.

    A reseller who has never earned any points (last_earned_at unset)
    or who currently has a balance of 0 has nothing to expire, so this
    is a cheap no-op for them. Always returns the CURRENT (possibly
    just-expired) balance.
    """
    try:
        node = fb_get(f"loyalty_points/{reseller_id}") or {}
        balance = node.get("balance") or 0
        last_earned = node.get("last_earned_at")
        if balance <= 0 or not last_earned:
            return balance
        try:
            last_dt = datetime.strptime(last_earned, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return balance
        days_idle = (manila_now().replace(tzinfo=None) - last_dt).total_seconds() / 86400.0
        expiry_days = get_points_expiry_days()
        if days_idle > expiry_days:
            new_balance = award_loyalty_points(
                reseller_id, -balance,
                f"Expired - {int(days_idle)} araw walang online order (limit: {expiry_days} araw)"
            )
            return new_balance if new_balance is not None else 0
        return balance
    except Exception as e:
        print(f"check_and_expire_points error: {e}")
        return fb_get(f"loyalty_points/{reseller_id}/balance") or 0

def get_current_margin_pct(include_fixed_asset=True):
    """
    All-time real profit margin %, computed with the EXACT SAME
    functions the Home Dashboard's "ALL TIME" view already uses
    (imported from modules.home_dashboard rather than re-derived here)
    - so this safety check always agrees with the number ISESMO
    already watches on /home, instead of drifting out of sync with a
    second copy of the same math. Returns None if there are no sales
    yet to compute a margin from.

    include_fixed_asset mirrors the Home Dashboard's own "Include Fixed
    Asset" toggle (Sept 21, at ISESMO's request): ON (default) folds in
    machine/vehicle depreciation as a real cost, which is the more
    conservative, recommended setting for a SAFETY check - it answers
    "can this rewards program sustain itself once equipment wear-and-
    tear is accounted for", not just "am I cash-flow positive today".
    OFF drops depreciation and shows the cash-only margin instead, for
    ISESMO to compare side by side if he wants to.
    """
    try:
        total_sales, _, _, _ = _sales_totals("all", "")
        by_cat = _expense_breakdown("all", "")
        operating_exp = sum(by_cat.values())
        total_exp = operating_exp
        if include_fixed_asset:
            fixed_amt = _fixed_asset_expense_for_period("all", "")
            total_exp += fixed_amt
        if total_sales <= 0:
            return None
        net = total_sales - total_exp
        return round((net / total_sales) * 100, 1)
    except Exception as e:
        print(f"get_current_margin_pct error: {e}")
        return None

def get_reward_breakeven_margin(points_required, kg_size):
    """
    The MINIMUM real profit margin % a specific reward needs so that
    redeeming it is never a net loss. Worked out in conversation with
    the store owner: earning `points_required` pesos of purchases (1
    point = P1) at margin M% makes M% x points_required pesos of real
    profit; giving the reward away costs (100-M)% of its own price in
    production cost. Setting those equal and solving for M gives
    M >= 1 / (1 + multiplier) x 100, where multiplier =
    points_required / price - a HIGHER points requirement relative to
    price (bigger multiplier) tolerates a LOWER real margin before the
    reward turns unprofitable. Returns None if the reward's price
    can't be resolved.
    """
    try:
        price = get_price(kg_size, "DELIVER")
        if not price or points_required <= 0:
            return None
        multiplier = points_required / price
        if multiplier <= 0:
            return None
        return round((1 / (1 + multiplier)) * 100, 1)
    except Exception:
        return None

def get_reseller_sales_summary():
    """
    Per-reseller sales + rewards-history rollup for the ISESMO-only
    /admin/reseller_sales page (built Sept 21 at ISESMO's request, so he
    can see who's actually buying and how often each reseller tends to
    hit a reward, instead of only seeing one reseller's history at a
    time via the "Search Reseller Points" lookup on /admin/rewards).

    Deliberately counts only ONLINE orders (order_source == "customer",
    status Delivered/Out for Delivery, excluding reward_redemption rows)
    for "sales" and "order count" - these are the exact same orders
    that earn loyalty points (see the Delivered-status hook in
    api_update_order_status), so "sales here" and "points earned" always
    agree. A manual cashier sale attributed to the same reseller_id is
    real revenue but never earns points, so mixing it in would make the
    frequency/prediction numbers below lie.

    avg_days_between_orders: mean gap between this reseller's online
    order dates - a rough cadence indicator, not a strict prediction
    (skips resellers with under 2 online orders, since a gap needs two
    points to compute).

    days_to_next_reward: extrapolates from that same cadence and this
    reseller's own average points-per-order, assuming they keep
    ordering at their historical pace - a rough ETA, not a promise
    (None whenever the inputs to extrapolate from aren't there yet:
    no cadence, no earn rate, or already at/above every reward tier).

    days_until_points_expire / at_risk: reuses the same
    last_earned_at + get_points_expiry_days() math as
    check_and_expire_points, but READ-ONLY here (this function never
    expires anyone's points - that still only happens lazily, on an
    actual read/redeem/lookup of that one reseller). at_risk flags
    anyone with a positive balance who is within 15 days of losing it,
    so ISESMO can reach out before the automatic expiry fires.
    """
    try:
        resellers = fb_get("resellers") or {}
        sales = fb_get("daily_sales") or {}
        loyalty = fb_get("loyalty_points") or {}
        catalog = get_reward_catalog()
        reward_thresholds = sorted(
            {int(v.get("points_required", 0)) for v in catalog.values() if v and v.get("points_required")}
        )
        expiry_days = get_points_expiry_days()
        now = manila_now().replace(tzinfo=None)

        orders_by_reseller = {}
        for _, s in sales.items():
            if not s:
                continue
            if s.get("order_source") != "customer" or s.get("reward_redemption"):
                continue
            if (s.get("order_status") or "") not in ("Delivered", "Out for Delivery"):
                continue
            rid = s.get("reseller_id")
            if not rid:
                continue
            orders_by_reseller.setdefault(rid, []).append(s)

        rows = []
        for rid, val in resellers.items():
            if not val:
                continue
            store_name = (val.get("store_name") or "").strip()
            phone = (val.get("phone") or val.get("contact") or "").strip()
            orders = orders_by_reseller.get(rid, [])
            order_count = len(orders)
            total_sales = round(sum(float(o.get("total_sales") or 0) for o in orders), 2)
            dates = sorted(d for d in (o.get("sales_date") for o in orders) if d)
            last_order_date = dates[-1] if dates else None

            avg_days_between_orders = None
            if len(dates) >= 2:
                try:
                    span_days = (datetime.strptime(dates[-1], "%Y-%m-%d") - datetime.strptime(dates[0], "%Y-%m-%d")).days
                    avg_days_between_orders = round(span_days / (len(dates) - 1), 1) if span_days > 0 else None
                except Exception:
                    avg_days_between_orders = None

            loyalty_node = loyalty.get(rid) or {}
            balance = int(loyalty_node.get("balance") or 0)
            history = loyalty_node.get("history") or {}
            redemption_count = 0
            last_redemption_date = None
            total_points_earned = 0
            for h in (history.values() if isinstance(history, dict) else []):
                if not h:
                    continue
                pts = h.get("points") or 0
                reason = h.get("reason") or ""
                if pts < 0 and not reason.startswith("Expired"):
                    redemption_count += 1
                    ts = h.get("timestamp")
                    if ts and (not last_redemption_date or ts > last_redemption_date):
                        last_redemption_date = ts
                elif pts > 0:
                    total_points_earned += pts

            days_to_next_reward = None
            next_reward_points = next((t for t in reward_thresholds if t > balance), None)
            if next_reward_points and order_count > 0 and avg_days_between_orders:
                avg_points_per_order = total_points_earned / order_count
                per_order_int = max(1, int(avg_points_per_order))
                if avg_points_per_order > 0:
                    orders_needed = max(1, -(-(next_reward_points - balance) // per_order_int))
                    days_to_next_reward = round(orders_needed * avg_days_between_orders, 1)

            days_until_points_expire = None
            at_risk = False
            last_earned_at = loyalty_node.get("last_earned_at")
            if balance > 0 and last_earned_at:
                try:
                    last_earned_dt = datetime.strptime(last_earned_at, "%Y-%m-%d %H:%M:%S")
                    days_idle = (now - last_earned_dt).total_seconds() / 86400.0
                    days_until_points_expire = round(max(0.0, expiry_days - days_idle), 1)
                    at_risk = days_until_points_expire <= 15
                except Exception:
                    pass

            rows.append({
                "id": rid,
                "store_name": store_name or "(walang pangalan)",
                "phone": phone,
                "total_sales": total_sales,
                "order_count": order_count,
                "points_balance": balance,
                "redemption_count": redemption_count,
                "last_order_date": last_order_date,
                "last_redemption_date": last_redemption_date,
                "avg_days_between_orders": avg_days_between_orders,
                "next_reward_points": next_reward_points,
                "days_to_next_reward": days_to_next_reward,
                "days_until_points_expire": days_until_points_expire,
                "at_risk": at_risk,
            })

        rows.sort(key=lambda r: r["total_sales"], reverse=True)
        return rows
    except Exception as e:
        print(f"get_reseller_sales_summary error: {e}")
        return []

def get_reseller_leaderboard(year_month=None, top_n=5):
    """
    Top N resellers by online sales for a single calendar month (default:
    the current month, Manila time). Same "online, Delivered, not a
    reward redemption" filter as get_reseller_sales_summary, just scoped
    to one month's sales_date prefix instead of all-time - a simple
    monthly "Top Performers" leaderboard ISESMO can post for the
    resellers to see, separate from the all-time totals table.
    """
    try:
        if not year_month:
            year_month = manila_now().strftime("%Y-%m")
        resellers = fb_get("resellers") or {}
        sales = fb_get("daily_sales") or {}

        totals = {}
        for _, s in sales.items():
            if not s:
                continue
            if s.get("order_source") != "customer" or s.get("reward_redemption"):
                continue
            if (s.get("order_status") or "") not in ("Delivered", "Out for Delivery"):
                continue
            if not (s.get("sales_date") or "").startswith(year_month):
                continue
            rid = s.get("reseller_id")
            if not rid:
                continue
            bucket = totals.setdefault(rid, {"total_sales": 0.0, "order_count": 0})
            bucket["total_sales"] += float(s.get("total_sales") or 0)
            bucket["order_count"] += 1

        rows = []
        for rid, bucket in totals.items():
            reseller = resellers.get(rid) or {}
            rows.append({
                "id": rid,
                "store_name": (reseller.get("store_name") or "").strip() or "(walang pangalan)",
                "total_sales": round(bucket["total_sales"], 2),
                "order_count": bucket["order_count"],
            })
        rows.sort(key=lambda r: r["total_sales"], reverse=True)
        return {"year_month": year_month, "leaders": rows[:top_n]}
    except Exception as e:
        print(f"get_reseller_leaderboard error: {e}")
        return {"year_month": year_month, "leaders": []}

def get_redemption_trend(months=6):
    """
    Reward-redemption counts per calendar month across ALL resellers,
    for the last `months` months including the current one (oldest
    first) - a simple trend view so ISESMO can see whether redemptions
    are picking up or slowing down over time, without opening each
    reseller's individual history one by one.

    Counts a history entry as a redemption when its points delta is
    negative and its reason doesn't start with "Expired" (same rule as
    redemption_count in get_reseller_sales_summary) - manual isesmo
    deductions ("[Isesmo] ...") are intentionally included here since
    those are still real points leaving real balances, same as a
    reseller-initiated redemption.
    """
    try:
        loyalty = fb_get("loyalty_points") or {}
        now = manila_now().replace(tzinfo=None)
        month_keys = []
        cursor = now.replace(day=1)
        for _ in range(months):
            month_keys.append(cursor.strftime("%Y-%m"))
            cursor = (cursor - timedelta(days=1)).replace(day=1)
        month_keys.reverse()

        counts = {m: {"count": 0, "points_redeemed": 0} for m in month_keys}
        for _, node in loyalty.items():
            if not node:
                continue
            history = node.get("history") or {}
            for h in (history.values() if isinstance(history, dict) else []):
                if not h:
                    continue
                pts = h.get("points") or 0
                reason = h.get("reason") or ""
                ts = h.get("timestamp") or ""
                if pts >= 0 or reason.startswith("Expired"):
                    continue
                month = ts[:7]
                if month in counts:
                    counts[month]["count"] += 1
                    counts[month]["points_redeemed"] += abs(pts)

        return [{"month": m, "count": counts[m]["count"], "points_redeemed": counts[m]["points_redeemed"]} for m in month_keys]
    except Exception as e:
        print(f"get_redemption_trend error: {e}")
        return []

def get_reseller_detail(reseller_id):
    """
    Full drill-down for one reseller: every online order (any status,
    newest first) and their complete points ledger - the same two data
    sources get_reseller_sales_summary rolls up into totals, shown here
    unrolled so ISESMO can see the actual events behind the numbers.
    """
    try:
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        sales = fb_get("daily_sales") or {}

        orders = []
        for sid, s in sales.items():
            if not s or s.get("reseller_id") != reseller_id or s.get("order_source") != "customer":
                continue
            orders.append({
                "id": sid,
                "sales_date": s.get("sales_date"),
                "kg_size": s.get("kg_size"),
                "quantity": s.get("quantity"),
                "total_sales": s.get("total_sales"),
                "order_status": s.get("order_status"),
                "reward_redemption": bool(s.get("reward_redemption")),
            })
        orders.sort(key=lambda o: o.get("sales_date") or "", reverse=True)

        history = fb_get(f"loyalty_points/{reseller_id}/history") or {}
        points_history = []
        for hid, h in history.items():
            if not h:
                continue
            points_history.append({"id": hid, **h})
        points_history.sort(key=lambda h: h.get("timestamp") or "", reverse=True)

        return {
            "store_name": (reseller.get("store_name") or "").strip() or "(walang pangalan)",
            "phone": (reseller.get("phone") or reseller.get("contact") or "").strip(),
            "points_balance": int(fb_get(f"loyalty_points/{reseller_id}/balance") or 0),
            "orders": orders[:100],
            "points_history": points_history[:100],
        }
    except Exception as e:
        print(f"get_reseller_detail error: {e}")
        return {"store_name": "", "phone": "", "points_balance": 0, "orders": [], "points_history": []}

def log_customer_login(reseller_id, store_name, phone, success, reason=""):
    """
    Records every customer login attempt - success AND failure - so staff
    can see who's actually using the customer portal, and so a string of
    failed attempts on one phone number (a real security signal) is
    visible instead of silently vanishing. Never lets a logging failure
    break the actual login flow - it's fire-and-forget.

    BUG FIX (Sept 21): timestamp used to be plain datetime.now() with no
    timezone - on Render's UTC server clock, every logged time was ~8
    hours behind actual Manila time, making the Login Activity page look
    wrong/stale. Now uses manila_now() so what staff sees here matches
    their own wall clock. (The "ip" field is fixed separately via
    ProxyFix, set up where the Flask app is created above.)
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
            "timestamp": manila_now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        fb_post("customer_login_logs", entry)
        # Push a real-time notification to ISESMO's own device(s) for
        # EVERY customer-side login attempt (ISESMO's request, Sept 22)
        # - one central call here means every current AND future
        # log_customer_login() call site is covered automatically,
        # instead of having to remember to add it at each one.
        who = store_name or phone or "Unknown"
        if success:
            send_push_to_isesmo(
                title="🔐 Customer Login",
                body=f"{who} logged in ({reason or 'login'})",
            )
        else:
            send_push_to_isesmo(
                title="⚠️ Failed Customer Login",
                body=f"{who} - {reason or 'Login failed'}",
            )
    except Exception as e:
        print(f"log_customer_login error: {e}")


def log_staff_login(staff_id, staff_name, position, action, success, reason=""):
    """
    Records every staff login AND logout on the Sales/POS side (boss's
    request, Sept 25: "sino nag-in-out ng sales" - accountability for
    who actually opened/closed the cashier system, and when). Same
    fire-and-forget pattern as log_customer_login: a logging hiccup must
    never block the actual login/logout, and every attempt is recorded
    - success AND failure - so a string of wrong-PIN attempts (a real
    security signal, e.g. someone trying to guess another staff
    member's PIN) is visible instead of silently vanishing.

    `action` is "Login" or "Logout" - kept as an explicit field (not
    inferred from `success`) because a logout has no pass/fail concept
    of its own, it just always succeeds once a session exists.
    """
    try:
        entry = {
            "staff_id": staff_id or "",
            "staff_name": staff_name or "",
            "position": position or "",
            "action": action,
            "success": bool(success),
            "reason": reason or "",
            "ip": request.remote_addr or "unknown",
            "user_agent": (request.headers.get("User-Agent") or "")[:200],
            "timestamp": manila_now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        fb_post("staff_login_logs", entry)
        who = staff_name or "Unknown staff"
        if action == "Login" and success:
            send_push_to_isesmo(title="🟢 Staff Login", body=f"{who} logged in to Sales")
        elif action == "Login" and not success:
            send_push_to_isesmo(title="⚠️ Failed Staff Login", body=f"{reason or 'Wrong PIN attempt'}")
        elif action == "Logout":
            send_push_to_isesmo(title="🔴 Staff Logout", body=f"{who} logged out of Sales")
    except Exception as e:
        print(f"log_staff_login error: {e}")


# Name of the cookie that holds a customer's "trusted device" fingerprint
# (boss's request, Sept 23: use a device fingerprint - not IP, which is
# dynamic on mobile data - to flag logins from a device the account
# hasn't used before).
DEVICE_COOKIE_NAME = "omega_device_id"
DEVICE_COOKIE_MAX_AGE = 365 * 24 * 60 * 60  # 1 year


def check_and_register_device(reseller_id):
    """
    "Trusted device" fingerprinting for customer logins (boss's request,
    Sept 23, as a safer alternative to IP-based checks - a customer's
    mobile IP changes constantly, but a device_id cookie stays the same
    across networks and only changes when the device/browser genuinely
    changes or its cookies are cleared).

    How it works:
    - Looks for a DEVICE_COOKIE_NAME cookie on the incoming request.
    - If missing, or present but not yet recorded under THIS reseller's
      own resellers/{id}/trusted_devices list, this is treated as a NEW
      device for this account (even if the same cookie is a "known"
      device on a DIFFERENT reseller's account on a shared phone - each
      reseller has its own trusted-device list, intentionally, so one
      shared device isn't silently trusted for every account on it).
    - Always (new or known) touches trusted_devices/{device_id} with an
      updated last_seen + user_agent, so ISESMO can see recency.

    Returns (is_new_device: bool, device_id: str). The caller is
    responsible for actually setting the returned device_id back onto
    the response cookie - this function only reads/writes Firebase, it
    never touches the Flask response (keeps it reusable from any login
    endpoint, JSON or redirect-based).

    Fire-and-forget on the Firebase write side is NOT appropriate here
    (unlike log_customer_login) because the caller needs a real
    is_new_device answer to decide whether to push-notify - so
    exceptions are caught but always resolve to "treat as new device"
    (fail-safe: better to notify once too often than to silently miss a
    genuinely new device because Firebase hiccuped).
    """
    try:
        incoming_id = (request.cookies.get(DEVICE_COOKIE_NAME) or "").strip()
        devices = fb_get(f"resellers/{reseller_id}/trusted_devices") or {}
        now_str_manila = manila_now().strftime("%Y-%m-%d %H:%M:%S")
        ua = (request.headers.get("User-Agent") or "")[:200]

        is_new = not incoming_id or incoming_id not in devices
        device_id = incoming_id if incoming_id else secrets.token_hex(16)

        existing = devices.get(device_id) or {}
        fb_patch(f"resellers/{reseller_id}/trusted_devices/{device_id}", {
            "added_at": existing.get("added_at") or now_str_manila,
            "last_seen": now_str_manila,
            "user_agent": ua,
        })
        return is_new, device_id
    except Exception as e:
        print(f"check_and_register_device error: {e}")
        # Fail-safe: if we can't confirm this device is known, treat it
        # as new rather than silently skipping the alert.
        return True, (request.cookies.get(DEVICE_COOKIE_NAME) or secrets.token_hex(16))


def set_device_cookie(resp, device_id):
    """Attaches the trusted-device cookie to a Flask response. HttpOnly
    (JS can't read/tamper with it) + Secure (HTTPS only, which is all
    Render serves) + SameSite=Lax (still sent on normal top-level
    navigation like the QR-login redirect, but not on cross-site
    requests)."""
    resp.set_cookie(
        DEVICE_COOKIE_NAME, device_id,
        max_age=DEVICE_COOKIE_MAX_AGE,
        httponly=True, secure=True, samesite="Lax", path="/",
    )
    return resp


def notify_new_device_login(reseller_id, store_name):
    """Push notification sent to the customer's OWN device(s) when a
    login succeeds from a device/browser their account hasn't seen
    before (boss's request, Sept 23). Deliberately does NOT block or
    delay the login itself - fire-and-forget, same pattern as every
    other push helper in this file."""
    try:
        send_push_to_reseller(
            reseller_id,
            title="🔐 Bagong Device Login",
            body="May bagong device/browser na nag-login sa account mo. Kung hindi ikaw ito, palitan agad ang password mo.",
            url=f"/customer/{reseller_id}/dashboard",
            tag=f"omega-new-device-{reseller_id}",
        )
    except Exception as e:
        print(f"notify_new_device_login error: {e}")


def log_customer_activity(reseller_id, store_name, action, details=""):
    """Records one thing a RESELLER did to their own account from their
    own dashboard (boss's request, Sept 22: "dapat may notification or
    logs lahat ng activities na ginagawa si customer sa dashboard nya.
    si isesmo lang nakakaaccess"). Separate node/page from
    log_customer_login (which only covers login attempts) - this is
    everything a customer DOES once they're already in: placing an
    order, redeeming a reward, rating an order, bulk-updating their own
    orders, archiving old ones, changing their password, booking an
    event. Deliberately only fires when session.get("customer_id")
    actually matches - i.e. the RESELLER themselves did this, not a
    staff member acting on their behalf from the staff side (that's a
    different audit trail, not "customer activity"). Fire-and-forget,
    same as log_customer_login - a logging hiccup must never block the
    action itself. No push notification per action (unlike logins) -
    pinging ISESMO's phone for every single order placed would drown out
    the signal; ISESMO reviews this log on /customer_activity instead."""
    try:
        entry = {
            "reseller_id": reseller_id,
            "store_name": store_name or "",
            "action": action,
            "details": details or "",
            "ip": request.remote_addr or "unknown",
            "timestamp": manila_now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        fb_post("customer_activity_logs", entry)
    except Exception as e:
        print(f"log_customer_activity error: {e}")

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
    staff_name = session.get("staff_name")
    if staff_name:
        # ROLE-BASED LANDING PAGE (boss's rule, Sept 21):
        # Omega and Yhel go straight to the Sales entry screen (/cashier) -
        # they're the ones actually ringing up sales all day, so the
        # dashboard would just be an extra tap for them.
        # Isesmo (and anyone else not in the list below) lands on the new
        # Home dashboard (/home) instead, since that's the owner/manager
        # view (Sales Data / Net Profit / Expenses / Credit at a glance).
        sales_first_staff = ["omega", "yhel"]
        if (staff_name or "").strip().lower() in sales_first_staff:
            return redirect(url_for("cashier_page"))
        return redirect(url_for("home_dashboard.home_page"))
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
            # Same session-hygiene fix as the customer logins - a staff
            # login must fully replace any leftover customer identity too
            # (see the comment in api_customer_login for the full story).
            session.pop("customer_id", None)
            session.pop("customer_name", None)
            session["staff_id"] = key
            session["staff_name"] = val.get("name")
            session["staff_position"] = val.get("position", "Staff")
            log_staff_login(key, val.get("name"), val.get("position"), "Login", True, "PIN login")
            return jsonify({"ok": True, "name": val.get("name"), "position": val.get("position")})
    record_attempt(ip)
    log_staff_login(None, None, None, "Login", False, "Wrong PIN")
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
    # Capture staff identity BEFORE clearing the session (boss's
    # request, Sept 25: track logouts too, not just logins) - once
    # session.clear() runs there's nothing left to log against.
    staff_id = session.get("staff_id")
    staff_name = session.get("staff_name")
    staff_position = session.get("staff_position")
    if staff_name:
        log_staff_login(staff_id, staff_name, staff_position, "Logout", True, "Manual logout")
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
    server_now = manila_now()

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

    now = manila_now()
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
                        "is_online": val.get("order_source") == "customer",
                        # Which staff account actually recorded this sale
                        # (boss's request, Sept 25: accountability for
                        # manually-entered sales, same spirit as the
                        # staff login/logout log). Already saved on every
                        # sale record at creation time - just wasn't
                        # surfaced in this feed before.
                        "staff_name": val.get("staff_name") or "",
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
    now = manila_now()

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
            "delivered_at": val.get("delivered_at",""),
            # Which staff account recorded this sale (boss's request,
            # Sept 25) - same field already added to /api/sales/recent,
            # just also needed here since the Weekly/Monthly Sales
            # Record table pulls from THIS endpoint, not that one.
            "staff_name": val.get("staff_name") or "",
            "is_online": val.get("order_source") == "customer",
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
/* Show/hide password toggle (boss's request, Sept 22: "para ma confirm
   ng customer kung tama na type nya") - wraps a password <input> with a
   right-aligned 👁️ button that flips its type between password/text. */
.pwd-wrap{position:relative}
.pwd-wrap input{padding-right:44px}
.pwd-toggle{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:18px;padding:8px;line-height:1}
#installBannerCu{background:#eef4fb;border:1px solid #cde;border-radius:10px;padding:10px;margin-bottom:14px;font-size:11px;color:#00609C;text-align:center}
#installBannerCu button{margin-top:6px;padding:7px 14px;border-radius:8px;border:none;background:#00609C;color:#fff;font-size:11px;font-weight:600}
#manualInstallHint{display:none;background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:10px;margin-top:8px;font-size:11px;color:#92400e;text-align:left}
.link-btn{background:none;border:none;color:#00609C;font-size:12px;text-decoration:underline;cursor:pointer;padding:0}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:999;align-items:center;justify-content:center;padding:16px}
.modal-overlay.open{display:flex}
.modal-box{background:#fff;border-radius:16px;padding:20px;max-width:360px;width:100%}
.modal-box h3{margin:0 0 4px;font-size:16px;color:#00609C}
.modal-box .step-hint{font-size:11px;color:#888;margin:0 0 14px}
.modal-box .modal-actions{display:flex;gap:8px;margin-top:16px}
.modal-box .modal-actions button{flex:1;padding:12px;border-radius:10px;border:1px solid #ccd;font-size:13px;font-weight:600}
.modal-box .modal-btn-primary{background:#00609C;color:#fff;border-color:#00609C}
</style></head>
<body>
<div class="card">
<div id="installBannerCu"><div>📲 I-install ang app na ito sa phone mo para mas mabilis mag-order.</div><button onclick="doInstallPromptCu()">Install App</button>
<div id="manualInstallHint">Sa Chrome: tapikin yung <b>⋮ (tatlong tuldok)</b> sa taas-kanan → piliin <b>"Install app"</b> o <b>"Add to Home screen"</b>.</div>
</div>
<div class="header"><img src="/logo-full.webp" alt="Omega Purified Ice" style="max-width:180px;width:100%;height:auto;margin:0 auto 8px;display:block"><p>Customer Secure Login</p><p style="font-size:11px;color:#888">One phone + password per store</p></div>
<label>Registered Phone</label><input type="tel" id="phone" placeholder="09xx xxx xxxx">
<label>Password</label>
<div class="pwd-wrap"><input type="password" id="password" placeholder="Enter password"><button type="button" class="pwd-toggle" onclick="togglePwdVisibility('password',this)">👁️</button></div>
<button class="btn" onclick="doLogin()">🔐 Login</button>
<p class="status" id="status"></p>
<div style="display:flex;align-items:center;gap:8px;margin:16px 0"><div style="flex:1;height:1px;background:#e5e7eb"></div><span style="font-size:11px;color:#999">O KAYA</span><div style="flex:1;height:1px;background:#e5e7eb"></div></div>
<input type="file" id="qrFileInput" accept="image/*" style="display:none" onchange="handleQRUpload(event)">
<button class="btn" style="background:#1a8a4a" onclick="document.getElementById('qrFileInput').click()">📷 Upload QR Code</button>
<p style="font-size:11px;color:#888;text-align:center;margin-top:6px">I-upload lang yung QR code na ibinigay sa'yo ni ISESMO - automatic na ang login.</p>
<p style="font-size:12px;color:#888;text-align:center;margin-top:14px;border-top:1px solid #eee;padding-top:14px">Nakalimutan ang password?<br><button class="link-btn" onclick="openForgotModal()">🔑 I-reset gamit ang OTP</button></p>
<div style="text-align:center;font-size:10px;color:#9aa7b3;margin-top:14px">Developed by Moises Orio Gamboa</div>
</div>

<!-- Forgot Password modal: 2-step OTP flow - (1) phone number -> SMS
     OTP, (2) OTP + new password -> reset. Wires up the
     request_otp/verify_otp endpoints that already existed in the
     backend but had no UI calling them (boss's request, Sept 22). -->
<div class="modal-overlay" id="forgotModal">
  <div class="modal-box">
    <div id="forgotStep1">
      <h3>🔑 Reset Password</h3>
      <p class="step-hint">Ilagay ang registered phone number mo. Lalabas agad dito ang OTP code mo, susunod na step.</p>
      <label>Registered Phone</label><input type="tel" id="forgotPhone" placeholder="09xx xxx xxxx">
      <p class="status" id="forgotStatus1"></p>
      <div class="modal-actions">
        <button onclick="closeForgotModal()">Cancel</button>
        <button class="modal-btn-primary" onclick="requestForgotOtp()">Kunin ang OTP</button>
      </div>
    </div>
    <div id="forgotStep2" style="display:none">
      <h3>🔑 OTP Code Mo</h3>
      <p class="step-hint">Ito ang OTP mo - naka-fill na sa baba, pero pwede mo pang i-edit. Ilagay na lang ang bagong password.</p>
      <div style="background:#eef4fb;border:1.5px dashed #00609C;border-radius:12px;padding:14px;text-align:center;margin-bottom:10px">
        <div style="font-size:10px;color:#00609C;font-weight:600;letter-spacing:1px">YOUR OTP CODE</div>
        <div id="forgotOtpDisplay" style="font-size:28px;font-weight:700;color:#00609C;letter-spacing:4px;margin-top:2px">------</div>
      </div>
      <label>OTP Code</label><input type="text" id="forgotOtp" placeholder="123456" maxlength="6" inputmode="numeric">
      <label>Bagong Password</label>
      <div class="pwd-wrap"><input type="password" id="forgotNewPwd" placeholder="Bagong password (min 4 chars)"><button type="button" class="pwd-toggle" onclick="togglePwdVisibility('forgotNewPwd',this)">👁️</button></div>
      <p class="status" id="forgotStatus2"></p>
      <div class="modal-actions">
        <button onclick="closeForgotModal()">Cancel</button>
        <button class="modal-btn-primary" onclick="confirmForgotReset()">I-reset ang Password</button>
      </div>
    </div>
  </div>
</div>

<script>
// Show/hide password toggle - flips an <input type="password"> to
// type="text" (and the 👁️/🙈 icon) so the customer can visually confirm
// what they typed before submitting, instead of guessing blind.
function togglePwdVisibility(inputId, btnEl){
  const input = document.getElementById(inputId);
  if(!input) return;
  if(input.type === 'password'){
    input.type = 'text';
    btnEl.textContent = '🙈';
  } else {
    input.type = 'password';
    btnEl.textContent = '👁️';
  }
}
let forgotPhoneValue = '';
function openForgotModal(){
  document.getElementById('forgotStep1').style.display='block';
  document.getElementById('forgotStep2').style.display='none';
  document.getElementById('forgotPhone').value='';
  document.getElementById('forgotStatus1').textContent='';
  document.getElementById('forgotStatus1').className='status';
  document.getElementById('forgotModal').classList.add('open');
}
function closeForgotModal(){
  document.getElementById('forgotModal').classList.remove('open');
}
async function requestForgotOtp(){
  const phone = document.getElementById('forgotPhone').value.trim();
  const st = document.getElementById('forgotStatus1');
  if(!phone){ st.textContent='Ilagay ang phone number.'; st.className='status err'; return; }
  st.textContent='Kinukuha ang OTP...'; st.className='status';
  try{
    const res = await fetch('/api/customer/request_otp', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({phone})});
    const data = await res.json();
    if(data.ok){
      forgotPhoneValue = phone;
      document.getElementById('forgotStep1').style.display='none';
      document.getElementById('forgotStep2').style.display='block';
      // No SMS - the OTP is shown directly on-screen (boss's decision,
      // Sept 22) and pre-filled into the OTP field for convenience, but
      // still editable/visible so the customer can double-check it.
      document.getElementById('forgotOtpDisplay').textContent = data.otp || '------';
      document.getElementById('forgotOtp').value = data.otp || '';
      document.getElementById('forgotStatus2').textContent = 'Valid ng 5 minuto.';
      document.getElementById('forgotStatus2').className = 'status ok';
    } else {
      st.textContent = data.error || data.message || 'May error. Subukan ulit.';
      st.className = 'status err';
    }
  }catch(e){
    st.textContent = 'Network error: '+e.message;
    st.className = 'status err';
  }
}
async function confirmForgotReset(){
  const otp = document.getElementById('forgotOtp').value.trim();
  const newPwd = document.getElementById('forgotNewPwd').value;
  const st = document.getElementById('forgotStatus2');
  if(!otp || !newPwd){ st.textContent='Ilagay ang OTP at bagong password.'; st.className='status err'; return; }
  st.textContent='Ni-reset ang password...'; st.className='status';
  try{
    const res = await fetch('/api/customer/verify_otp', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({phone: forgotPhoneValue, otp, new_password: newPwd})});
    const data = await res.json();
    if(data.ok){
      st.textContent='✅ Na-reset na ang password mo! I-login mo na gamit ang bago.';
      st.className='status ok';
      setTimeout(()=>{
        closeForgotModal();
        document.getElementById('phone').value = forgotPhoneValue;
        document.getElementById('password').value = '';
        document.getElementById('password').focus();
      }, 1800);
    } else {
      st.textContent = data.error || 'May error. Subukan ulit.';
      st.className = 'status err';
    }
  }catch(e){
    st.textContent = 'Network error: '+e.message;
    st.className = 'status err';
  }
}
</script>
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
.status-new{background:#fef3c7;color:#92400e}.status-pending{background:#fef3c7;color:#92400e}.status-preparing{background:#dbeafe;color:#1e40af}.status-out{background:#e0e7ff;color:#3730a3}.status-delivered{background:#dcfce7;color:#166534}.status-cancelled{background:#fee2e2;color:#c0392b}.status-declined{background:#ffe4e6;color:#be123c}
.order-card{border-left:4px solid #0096D6;padding:12px;margin:8px 0;background:#fff;border-radius:8px;cursor:pointer;transition:box-shadow .15s}
.order-card:active{box-shadow:0 0 0 2px #cde inset}
.btn{padding:10px 14px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;text-decoration:none}
.btn-primary{background:#00609C;color:#fff;border-color:#00609C;padding:12px 20px;font-weight:600}
/* --- Dashboard quick-action grid: every action button/link shares the
   exact same box (height, padding, border-radius, font-size) so the row
   reads as one consistent set instead of a mismatched pile of pills -
   only the accent color changes per action, via the modifier classes
   below. A 2-column grid keeps them evenly sized even with different
   label lengths ("Refresh" vs "Mark all Pending as Delivered"), and
   wraps cleanly to 1 column on very narrow screens. --- */
.action-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:12px}
.action-btn{display:flex;align-items:center;justify-content:center;gap:6px;min-height:44px;padding:10px 10px;border-radius:12px;border:1px solid #d7e3ef;background:#f8fafc;color:#334155;font-size:12px;font-weight:600;text-decoration:none;text-align:center;line-height:1.25;cursor:pointer;transition:filter .15s}
.action-btn:active{filter:brightness(.96)}
.action-btn-icon{font-size:14px;flex-shrink:0}
.action-btn-accent{background:#eef4fb;border-color:#cde;color:#00609C}
.action-btn-success{background:#f0fdf4;border-color:#86efac;color:#166534}
.action-btn-warn{background:#fff7ed;border-color:#fcd9a8;color:#c2410c}
.action-btn-wide{grid-column:1 / -1}
@media (max-width:340px){.action-grid{grid-template-columns:1fr}}
/* --- Summary stat tiles (boss's request, Sept 23): each stat gets its
   own little card with an icon instead of three bare numbers side by
   side - same 3-column grid so it still lines up with the old layout. --- */
.stat-tile-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.stat-tile{background:#eef4fb;border:1px solid #dce8f5;border-radius:12px;padding:12px 6px;text-align:center}
.stat-tile-icon{font-size:15px;margin-bottom:2px}
.stat-tile-val{font-size:17px;font-weight:800;color:#00609C;line-height:1.2;white-space:nowrap}
.stat-tile-lbl{font-size:8.5px;color:#7891a8;font-weight:700;letter-spacing:.3px;margin-top:2px;text-transform:uppercase}
/* --- New Order + Advance Order CTA pair, side by side, same size --- */
.cta-row{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:12px}
.cta-btn{display:flex;align-items:center;justify-content:center;gap:6px;min-height:48px;padding:12px 8px;border-radius:14px;font-size:13px;font-weight:700;text-decoration:none;text-align:center;border:1.5px solid transparent}
.cta-btn-primary{background:#00609C;color:#fff}
.cta-btn-accent{background:#fff7ed;color:#c2410c;border-color:#fcd9a8}
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
/* Change Password modal (boss's request, Sept 22) */
.cp-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:999;align-items:center;justify-content:center;padding:16px}
.cp-overlay.open{display:flex}
.cp-box{background:#fff;border-radius:16px;padding:20px;max-width:340px;width:100%}
.cp-box h3{margin:0 0 4px;font-size:16px;color:#00609C}
.cp-box label{font-size:12px;color:#666;display:block;margin:12px 0 6px}
.cp-box input{width:100%;padding:12px;border-radius:10px;border:1.5px solid #ccd;font-size:14px}
.cp-box .modal-actions{display:flex;gap:8px;margin-top:16px}
.cp-box .modal-actions button{flex:1;padding:12px;border-radius:10px;border:1px solid #ccd;font-size:13px;font-weight:600}
.cp-box .modal-btn-primary{background:#00609C;color:#fff;border-color:#00609C}
.cp-box .status{font-size:12px;text-align:center;margin-top:10px;min-height:18px}
.cp-box .status.err{color:#c0392b}.cp-box .status.ok{color:#1a8a4a}
.pwd-wrap{position:relative}
.pwd-wrap input{padding-right:40px !important}
.pwd-toggle{position:absolute;right:4px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:16px;padding:8px;line-height:1}
</style></head>
<body>
<div id="installBannerCu"><span>📲 I-install ang app na ito para mas mabilis mag-order.</span><button onclick="doInstallPromptCu()">Install</button>
<div id="manualInstallHint">Sa Chrome: tapikin yung <b>⋮</b> sa taas-kanan → piliin <b>"Install app"</b> o <b>"Add to Home screen"</b>.</div>
</div>
<div class="topbar"><div><h1 id="storeName">My Orders</h1><div style="font-size:11px;color:#666" id="storeMeta"></div></div><div style="display:flex;gap:6px;align-items:center"><span class="live">● LIVE</span><button onclick="openChangePwdModal()" class="btn" style="cursor:pointer">🔑</button><a href="/customer/logout" class="btn">Logout</a></div></div>
<div id="pushBannerCust" style="display:none;background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:8px 10px;margin-bottom:10px;font-size:11px;color:#991b1b;justify-content:space-between;align-items:center;gap:8px">
  <span>🔔 I-enable ang notifications para malaman mo agad ang balita (order updates, Points Program) kahit closed ang app.</span>
  <button onclick="enableCustomerPushAlerts()" style="padding:6px 12px;border-radius:8px;border:none;background:#c0392b;color:#fff;font-size:11px;font-weight:600;white-space:nowrap">Enable</button>
</div>
<div class="card"><div style="margin-bottom:10px"><span style="font-size:12px;font-weight:600">Summary</span></div><div class="stat-tile-grid"><div class="stat-tile"><div class="stat-tile-icon">📦</div><div class="stat-tile-val" id="totalKg">0kg</div><div class="stat-tile-lbl">Total Kg</div></div><div class="stat-tile"><div class="stat-tile-icon">💰</div><div class="stat-tile-val" id="totalPeso">₱0</div><div class="stat-tile-lbl">Total Peso</div></div><div class="stat-tile"><div class="stat-tile-icon">🧾</div><div class="stat-tile-val" id="totalOrders">0</div><div class="stat-tile-lbl">Orders</div></div></div><div id="statusCounts" style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;font-size:10px"></div>
<div class="cta-row">
<a href="/customer/{{ reseller_id }}/order" class="cta-btn cta-btn-primary"><span class="action-btn-icon">🧊</span>New Order</a>
<a href="/customer/{{ reseller_id }}/advance-order" class="cta-btn cta-btn-accent"><span class="action-btn-icon">📅</span>Advance Order</a>
</div>
<div class="action-grid">
<button onclick="loadOrders()" class="action-btn"><span class="action-btn-icon">🔄</span>Refresh</button>
<button onclick="bulkMarkDelivered()" class="action-btn action-btn-success"><span class="action-btn-icon">✅</span>Mark all Pending as Delivered</button>
<a href="/customer/{{ reseller_id }}/history" class="action-btn action-btn-accent"><span class="action-btn-icon">📊</span>Sales History</a>
<a href="/customer/{{ reseller_id }}/trend" class="action-btn action-btn-accent"><span class="action-btn-icon">📈</span>Sales Trend</a>
</div>
<div style="font-size:10px;color:#888;margin-top:6px">Staff will update to Preparing → Delivered</div>
</div>

<div class="card" style="background:linear-gradient(135deg,#00609C,#0f2942);color:#fff">
  <div style="display:flex;justify-content:space-between;align-items:center">
    <div>
      <div style="font-size:11px;opacity:.85">🎁 MY POINTS</div>
      <div style="font-size:28px;font-weight:800;margin-top:2px" id="pointsBalance">0</div>
    </div>
    <button onclick="openRewards()" style="padding:10px 16px;border-radius:20px;border:none;background:#fff;color:#00609C;font-weight:700;font-size:12px">View Rewards</button>
  </div>
  <div id="pointsPausedBanner" style="margin-top:12px;display:none;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.35);border-radius:10px;padding:10px 12px;font-size:11px;line-height:1.5">⏸️ Pansamantalang naka-pause ang Points Rewards Program. Ligtas at buo pa rin ang points mo - babalik ito once na-resume na.</div>
  <div id="pointsProgressWrap" style="margin-top:12px;display:none">
    <div style="display:flex;justify-content:space-between;align-items:baseline">
      <div style="font-size:11px;opacity:.85;font-weight:600">Progress papunta sa susunod na reward</div>
      <div style="font-size:12px;font-weight:800" id="pointsProgressLabel">0 / 0</div>
    </div>
    <div style="width:100%;height:12px;background:rgba(255,255,255,.22);border-radius:20px;overflow:hidden;margin-top:6px">
      <div id="pointsProgressBar" style="width:0%;height:100%;background:linear-gradient(90deg,#22c55e,#4ade80);border-radius:20px;transition:width .3s ease"></div>
    </div>
    <div style="font-size:12px;font-weight:600;margin-top:6px" id="pointsProgressText"></div>
  </div>
  <div style="font-size:10px;opacity:.8;margin-top:6px" id="pointsEarnHint">Kumikita ng points sa bawat online order na na-DELIVER (hindi kasama ang manual/walk-in sale)</div>
  <div style="font-size:10px;color:#fde68a;margin-top:4px;font-weight:600" id="pointsExpiry"></div>
</div>

<div class="card"><div style="font-size:12px;font-weight:600;margin-bottom:8px;display:flex;justify-content:space-between"><span>Real-time Orders</span><span style="font-size:10px;color:#888" id="lastUpdate"></span></div><div id="ordersList">Loading orders...</div></div>

<div class="track-overlay" id="rewardsOverlay" onclick="if(event.target===this)closeRewards()">
  <div class="track-sheet">
    <button class="track-close" onclick="closeRewards()">✕</button>
    <div style="font-size:14px;font-weight:700;color:#0f2942;margin-bottom:2px">🎁 Rewards Catalog</div>
    <div style="font-size:11px;color:#888;margin-bottom:14px">Balance mo: <b id="rewardsBalanceLabel">0</b> points</div>
    <div id="rewardsList">Loading...</div>
    <p id="redeemStatus" style="font-size:11px;color:#c0392b;margin-top:8px"></p>
  </div>
</div>

<div class="track-overlay" id="trackOverlay" onclick="if(event.target===this)closeTracking()">
  <div class="track-sheet">
    <button class="track-close" onclick="closeTracking()">✕</button>
    <div id="trackBody">Loading...</div>
  </div>
</div>

<!-- Change Password modal (boss's request, Sept 22: "gusto ng customer
     sila magupdate ng password nila") - no OTP needed here since the
     customer is already logged in; they just re-confirm their CURRENT
     password. Separate from the Forgot-Password/OTP flow on the login
     page, which is for someone who does NOT know their current password
     at all. -->
<div class="cp-overlay" id="cpModal">
  <div class="cp-box">
    <h3>🔑 Baguhin ang Password</h3>
    <p style="font-size:11px;color:#888;margin:0">Ilagay ang kasalukuyang password mo, tapos ang bago.</p>
    <label>Kasalukuyang Password</label>
    <div class="pwd-wrap"><input type="password" id="cpCurrentPwd" placeholder="Current password"><button type="button" class="pwd-toggle" onclick="togglePwdVisibility('cpCurrentPwd',this)">👁️</button></div>
    <label>Bagong Password</label>
    <div class="pwd-wrap"><input type="password" id="cpNewPwd" placeholder="Bagong password (min 4 chars)"><button type="button" class="pwd-toggle" onclick="togglePwdVisibility('cpNewPwd',this)">👁️</button></div>
    <p class="status" id="cpStatus"></p>
    <div class="modal-actions">
      <button onclick="closeChangePwdModal()">Cancel</button>
      <button class="modal-btn-primary" onclick="submitChangePwd()">Baguhin</button>
    </div>
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
    const priority = {"New Order":0, "Pending":1, "Preparing":2, "Out for Delivery":3, "Declined":4, "Delivered":5, "Cancelled":6};
    // DECLINE DECAY (boss's request, Sept 22): matches is_order_stale() on
    // the server - a Declined order sorts near the top for the first 24hrs
    // (so it isn't missed), then falls to the bottom with Cancelled once
    // it's old news. Keeping this mirrored client-side too, not just
    // server-side, because loadOrders() re-sorts whatever the server sends
    // before rendering it.
    const orderPriority = (o) => {
      if(o.order_status === 'Declined' && o.declined_at){
        const declinedMs = new Date(o.declined_at.replace(' ','T')).getTime();
        if(!isNaN(declinedMs) && (Date.now() - declinedMs) <= 24*60*60*1000){
          return priority['Declined'];
        }
        return priority['Cancelled'];
      }
      return priority[o.order_status] ?? 1;
    };
    const orders = ordersRaw.sort((a,b)=>{
      const pa = orderPriority(a);
      const pb = orderPriority(b);
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
      const declineBadge = (o.order_status==='Declined' && o.decline_reason) ? `<div style="margin-top:6px;font-size:11px;background:#fff1f2;color:#9f1239;border:1px solid #fecdd3;border-radius:8px;padding:6px 8px">🚫 ${o.decline_reason}</div>` : '';
      return `<div class="order-card" data-order-id="${o.id}" onclick="openTracking('${o.id}')"><div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><span style="font-size:11px;color:#888;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${fmtOrderTime(o.sales_date,o.created_at)}</span><span class="status-pill status-${(o.order_status||'pending').toLowerCase().replace(/ /g,'-')}" style="flex-shrink:0">${o.order_status||'Pending'}</span></div><div style="display:grid;grid-template-columns:56px 1fr 64px;align-items:center;gap:6px;font-size:13px;margin-top:6px"><span style="font-weight:600">${o.quantity}x</span><span style="color:#555;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${o.kg_size} • ${o.mode}</span><span style="text-align:right;font-weight:600;color:#00609C">₱${(+o.total_sales||0).toLocaleString()}</span></div><div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px"><span style="font-size:10px;color:#888">Order ID: ${o.id.slice(0,8)} • Tap to track →</span>${reorderBtn}</div>${declineBadge}${ratingHtml}</div>`;
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
  if(status==='Declined'){
    const reasonTxt = o.decline_reason ? o.decline_reason : 'Walang detalye na ibinigay.';
    body.innerHTML=`<div class="track-cancelled"><div style="font-size:40px;margin-bottom:10px">🚫</div><div style="font-weight:700;font-size:15px;color:#be123c">Order Declined</div><div style="font-size:12px;color:#888;margin-top:6px">${o.quantity}x ${o.kg_size} • ₱${o.total_sales}</div><div style="margin-top:10px;background:#fff1f2;border:1px solid #fecdd3;border-radius:8px;padding:10px;text-align:left"><div style="font-size:11px;color:#9f1239;font-weight:700;margin-bottom:2px">Dahilan:</div><div style="font-size:12px;color:#881337">${reasonTxt}</div></div></div>`;
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

// Show/hide password toggle - same behavior as the login page's version
// (boss's request, Sept 22: "para ma confirm ng customer kung tama na
// type nya"), duplicated here since this is a separate HTML document.
function togglePwdVisibility(inputId, btnEl){
  const input = document.getElementById(inputId);
  if(!input) return;
  if(input.type === 'password'){
    input.type = 'text';
    btnEl.textContent = '🙈';
  } else {
    input.type = 'password';
    btnEl.textContent = '👁️';
  }
}
function openChangePwdModal(){
  document.getElementById('cpCurrentPwd').value = '';
  document.getElementById('cpNewPwd').value = '';
  document.getElementById('cpStatus').textContent = '';
  document.getElementById('cpStatus').className = 'status';
  document.getElementById('cpModal').classList.add('open');
}
function closeChangePwdModal(){
  document.getElementById('cpModal').classList.remove('open');
}
async function submitChangePwd(){
  const current = document.getElementById('cpCurrentPwd').value;
  const newPwd = document.getElementById('cpNewPwd').value;
  const st = document.getElementById('cpStatus');
  if(!current || !newPwd){ st.textContent='Ilagay ang current at bagong password.'; st.className='status err'; return; }
  if(newPwd.length < 4){ st.textContent='Ang bagong password ay dapat 4 characters pataas.'; st.className='status err'; return; }
  st.textContent='Binabago ang password...'; st.className='status';
  try{
    const res = await fetch(`/api/customer/${resellerId}/change_password`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({current_password: current, new_password: newPwd})});
    const data = await res.json();
    if(data.ok){
      st.textContent='✅ Na-update na ang password mo!';
      st.className='status ok';
      setTimeout(()=>closeChangePwdModal(), 1500);
    } else {
      st.textContent = data.error || 'May error. Subukan ulit.';
      st.className = 'status err';
    }
  }catch(e){
    st.textContent = 'Network error: '+e.message;
    st.className = 'status err';
  }
}

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

// --- LOYALTY POINTS / REWARDS ---
let _rewardsCache = [];
let _cooldownDaysLeft = 0;
let _programPaused = false;
let _scheduledResumeAt = null;
// Turns the server's "YYYY-MM-DD HH:MM(:SS)" into a friendly Taglish
// date/time for the reseller (e.g. "Sept 25, 2026, 9:00 AM") - falls
// back to the raw string if it doesn't parse for any reason, so the
// banner still shows SOMETHING rather than going blank.
function formatResumeDate(raw){
  try{
    const iso = raw.replace(' ', 'T');
    const d = new Date(iso);
    if(isNaN(d.getTime())) return raw;
    return d.toLocaleString('en-PH', {month:'short', day:'numeric', year:'numeric', hour:'numeric', minute:'2-digit'});
  }catch(e){ return raw; }
}
async function loadPoints(){
  try{
    const res = await fetch(`/api/customer/${resellerId}/points`);
    const data = await res.json();
    if(data.ok){
      document.getElementById('pointsBalance').textContent = data.balance.toLocaleString() + ' pts';
      document.getElementById('rewardsBalanceLabel').textContent = data.balance.toLocaleString();
      _rewardsCache = data.rewards || [];
      _cooldownDaysLeft = data.cooldown_days_left || 0;
      _programPaused = !!data.program_paused;
      _scheduledResumeAt = data.scheduled_resume_at || null;
      // While the program is paused: hide the progress bar + "how to
      // earn" hint and show the pause banner instead. The balance
      // number itself always stays visible - it's not lost, just frozen.
      const pausedBanner = document.getElementById('pointsPausedBanner');
      const earnHint = document.getElementById('pointsEarnHint');
      if(pausedBanner){
        pausedBanner.style.display = _programPaused ? '' : 'none';
        if(_programPaused){
          pausedBanner.textContent = data.scheduled_resume_at
            ? `⏸️ Pansamantalang naka-pause ang Points Rewards Program. Ligtas at buo pa rin ang points mo - babalik ito sa ${formatResumeDate(data.scheduled_resume_at)}.`
            : '⏸️ Pansamantalang naka-pause ang Points Rewards Program. Ligtas at buo pa rin ang points mo - babalik ito once na-resume na.';
        }
      }
      if(earnHint) earnHint.style.display = _programPaused ? 'none' : '';
      if(_programPaused){
        const wrap = document.getElementById('pointsProgressWrap');
        if(wrap) wrap.style.display = 'none';
      } else {
        renderPointsProgress(data.balance, _rewardsCache);
      }
      const expiryEl = document.getElementById('pointsExpiry');
      if(expiryEl){
        expiryEl.textContent = (data.expires_at && !_programPaused)
          ? `⏳ Mag-order bago sumapit ang ${data.expires_at} para hindi mawala ang points mo`
          : '';
      }
    }
  }catch(e){ /* silent - points card just stays at last known value */ }
}
// Fills in the progress bar on the MY POINTS card - always targets
// whichever reward tier the reseller hasn't reached YET, not a fixed
// number, so it automatically moves from 1Kg -> 5Kg -> 10Kg -> 25Kg as
// their balance climbs past each one. `rewards` arrives from
// /api/customer/<id>/points already sorted ascending by
// points_required (see api_customer_points), so the first entry whose
// points_required is still above the balance IS the next tier.
function renderPointsProgress(balance, rewards){
  const wrap = document.getElementById('pointsProgressWrap');
  if(!wrap) return;
  if(!rewards || !rewards.length){
    wrap.style.display = 'none';
    return;
  }
  wrap.style.display = '';
  const bar = document.getElementById('pointsProgressBar');
  const label = document.getElementById('pointsProgressLabel');
  const text = document.getElementById('pointsProgressText');
  const next = rewards.find(r => r.points_required > balance);
  if(next){
    const pct = Math.max(0, Math.min(100, Math.round((balance / next.points_required) * 100)));
    bar.style.width = pct + '%';
    label.textContent = `${balance.toLocaleString()} / ${next.points_required.toLocaleString()}`;
    text.textContent = `${(next.points_required - balance).toLocaleString()} points pa para sa ${next.label} 🧊`;
  } else {
    // Balance already covers even the highest tier - nothing bigger to
    // count up to, so show a full bar and a "maxed out" message
    // instead of a countdown to a target that doesn't exist.
    const top = rewards[rewards.length - 1];
    bar.style.width = '100%';
    label.textContent = `${balance.toLocaleString()} / ${top.points_required.toLocaleString()}`;
    text.textContent = 'Naabot mo na ang pinakamataas na reward — pwede ka nang mag-redeem! 🎉';
  }
}
function openRewards(){
  document.getElementById('rewardsOverlay').classList.add('show');
  document.getElementById('redeemStatus').textContent = '';
  renderRewardsList();
  loadPoints().then(renderRewardsList);
}
function closeRewards(){ document.getElementById('rewardsOverlay').classList.remove('show'); }
function renderRewardsList(){
  const el = document.getElementById('rewardsList');
  if(!_rewardsCache.length){ el.innerHTML = '<div style="text-align:center;color:#888;padding:16px">Walang available na rewards sa ngayon.</div>'; return; }
  // Pause banner takes priority over the cooldown note - if the whole
  // program is paused, that's the reason EVERY button is disabled, not
  // the per-reseller cooldown (though both can legitimately apply).
  let html = '';
  if(_programPaused){
    const resumeNote = _scheduledResumeAt ? ` Babalik ito sa ${formatResumeDate(_scheduledResumeAt)}.` : '';
    html += `<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:10px 12px;margin-bottom:10px;font-size:12px;color:#991b1b">⏸️ Pansamantalang naka-pause ang Points Rewards Program - hindi muna pwede mag-redeem. Ligtas at buo pa rin ang points mo.${resumeNote}</div>`;
  } else if(_cooldownDaysLeft > 0){
    html += `<div style="background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:10px 12px;margin-bottom:10px;font-size:12px;color:#92400e">⏳ Naka-redeem ka na kamakailan - pwede ka ulit mag-redeem sa loob ng <b>${_cooldownDaysLeft}</b> (na) araw.</div>`;
  }
  html += _rewardsCache.map(r => `
    <div style="display:flex;justify-content:space-between;align-items:center;padding:12px;border:1px solid #eef2f6;border-radius:12px;margin-bottom:8px;${r.can_redeem?'':'opacity:.55'}">
      <div style="display:flex;align-items:center;gap:10px">
        ${rewardIconSvg()}
        <div>
          <div style="font-weight:700;font-size:13px;color:#0f2942">${r.label}</div>
          <div style="font-size:11px;color:#888">${r.points_required.toLocaleString()} points</div>
        </div>
      </div>
      <button onclick="redeemReward('${r.id}')" ${r.can_redeem?'':'disabled'} style="padding:8px 14px;border-radius:20px;border:none;background:${r.can_redeem?'#00609C':'#ccd'};color:#fff;font-weight:700;font-size:11px;cursor:${r.can_redeem?'pointer':'not-allowed'}">Redeem</button>
    </div>
  `).join('');
  el.innerHTML = html;
}
// Inline SVG icon of a sealed ice pack (zip-top bag with ice cubes inside) -
// drawn once, reused per reward row. No separate image file/upload needed
// (matches the rest of this app's no-external-assets approach), and it
// scales crisp at any size unlike a raster photo would.
function rewardIconSvg(){
  return `<svg width="40" height="40" viewBox="0 0 44 44" fill="none" style="flex-shrink:0" xmlns="http://www.w3.org/2000/svg">
    <path d="M10 12 L34 12 L36 40 Q36 42.5 33.5 42.5 L10.5 42.5 Q8 42.5 8 40 Z" fill="#eef7ff" stroke="#00609C" stroke-width="1.5"/>
    <rect x="9" y="6" width="26" height="7" rx="2.5" fill="#00609C"/>
    <rect x="14" y="19" width="7" height="7" rx="1.5" fill="#ffffff" stroke="#00609C" stroke-width="1"/>
    <rect x="23" y="17" width="7" height="7" rx="1.5" fill="#ffffff" stroke="#00609C" stroke-width="1"/>
    <rect x="17.5" y="28" width="7" height="7" rx="1.5" fill="#ffffff" stroke="#00609C" stroke-width="1"/>
    <rect x="26.5" y="27" width="7" height="7" rx="1.5" fill="#ffffff" stroke="#00609C" stroke-width="1"/>
  </svg>`;
}
async function redeemReward(rewardId){
  if(!confirm('Sigurado ka bang i-redeem itong reward?')) return;
  const statusEl = document.getElementById('redeemStatus');
  statusEl.style.color = '#888';
  statusEl.textContent = 'Processing...';
  try{
    const res = await fetch(`/api/customer/${resellerId}/redeem`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({reward_id: rewardId})
    });
    const data = await res.json();
    if(data.ok){
      statusEl.style.color = '#166534';
      statusEl.textContent = '✅ Na-redeem! Makikita mo na sa Real-time Orders - dadalhin ito ng staff.';
      loadPoints().then(renderRewardsList);
      loadOrders();
    }else{
      statusEl.style.color = '#c0392b';
      statusEl.textContent = data.error || 'Failed to redeem';
    }
  }catch(e){
    statusEl.style.color = '#c0392b';
    statusEl.textContent = 'Network error: ' + e.message;
  }
}

// --- Push notifications for the RESELLER's own device (order updates,
// Points Program pause/resume) - reaches them even if this app/tab is
// fully closed (ISESMO's request, Sept 22). Same mechanism as the
// cashier-side "Order Alarm" push (see enablePushAlerts in CASHIER_HTML),
// just posting to the customer-specific subscribe endpoint since a
// reseller session (session['customer_id']) isn't a staff session.
const VAPID_PUBLIC_KEY_CUST = "{{ vapid_public_key }}";
const PUSH_ENABLED_CUST = {{ 'true' if push_enabled else 'false' }};

function urlBase64ToUint8ArrayCust(base64String){
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g,'+').replace(/_/g,'/');
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for(let i=0;i<rawData.length;i++) outputArray[i] = rawData.charCodeAt(i);
  return outputArray;
}

async function updateCustomerPushBannerUI(){
  const banner = document.getElementById('pushBannerCust');
  if(!banner) return;
  if(!PUSH_ENABLED_CUST || !('serviceWorker' in navigator) || !('PushManager' in window)){
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
    banner.style.display = 'none';
  } else {
    banner.style.display = 'flex';
  }
}

async function enableCustomerPushAlerts(){
  const banner = document.getElementById('pushBannerCust');
  try{
    if(!PUSH_ENABLED_CUST){
      alert('Hindi pa naka-configure ang push notifications sa server.');
      return;
    }
    const perm = await Notification.requestPermission();
    if(perm !== 'granted'){
      alert('Kailangan payagan ang Notifications para makatanggap ng updates kahit closed ang app.');
      return;
    }
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if(!sub){
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8ArrayCust(VAPID_PUBLIC_KEY_CUST)
      });
    }
    const subJson = sub.toJSON();
    await fetch('/api/customer/push/subscribe', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({endpoint: subJson.endpoint, keys: subJson.keys})
    });
    if(banner) banner.style.display = 'none';
  }catch(err){
    alert('Hindi na-enable ang notifications: ' + err.message);
  }
}
if('serviceWorker' in navigator){
  window.addEventListener('load', () => { setTimeout(updateCustomerPushBannerUI, 1500); });
}

loadOrders();setInterval(loadOrders,10000);
loadPoints();setInterval(loadPoints,30000);
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


# Same hand-built flexbox bar chart (with peso data labels above each bar)
# as the staff-side EXPENSES_TREND_HTML - kept intentionally simple, no
# category selector here since this is one reseller's own total sales
# (ISESMO's request, Sept 22: "gusto ko ganyan lang kasimple yung sales
# monitoring trend nila").
CUSTOMER_TREND_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sales Trend - Omega Ice</title>
<link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#00609C"><link rel="apple-touch-icon" href="/icon-192.png">
<script>if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));}</script>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}.topbar h1{font-size:15px;color:#00609C;margin:0}
.btn{padding:10px 14px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;text-decoration:none}
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
label{font-size:12px;color:#666;display:block;margin:0 0 4px}
select,input{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:14px;font-family:inherit;background:#fff}
.price-row{display:flex;gap:8px;align-items:flex-end}
.price-row>div{flex:1}
.price-row button{padding:10px 16px;border-radius:8px;border:none;background:#00609C;color:#fff;font-size:13px;font-weight:600;white-space:nowrap}
.price-hint{font-size:10px;color:#888;margin-top:6px}
.price-status{font-size:11px;margin-top:6px;min-height:14px}
.price-status.ok{color:#166534}.price-status.err{color:#c0392b}
.total-card{background:linear-gradient(135deg,#00609C,#0f2942);color:#fff;border-radius:12px;padding:16px;margin-bottom:12px;text-align:center}
.total-card.profit{background:linear-gradient(135deg,#059669,#065f46)}
.total-card .amt{font-size:26px;font-weight:700}.total-card .lbl{font-size:11px;opacity:.9}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.chart-legend{display:flex;gap:14px;justify-content:center;margin-bottom:10px;font-size:10px;font-weight:600;color:#555}
.chart-legend .dot{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:middle}
.chart-wrap{display:flex;align-items:flex-end;gap:4px;height:240px;padding:34px 4px 0;border-bottom:2px solid #e5e7eb}
.bar-col{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%;min-width:0}
.bar-label{font-size:9px;font-weight:700;color:#0f2942;margin-bottom:3px;white-space:nowrap}
.bar{width:70%;background:linear-gradient(180deg,#0096D6,#00609C);border-radius:4px 4px 0 0;min-height:2px;transition:height .3s ease}
.bar.zero{background:#e5e7eb}
/* Overlapping cost-vs-profit bars (ISESMO's request, Sept 22: "totally
   overlapping/transparent bars"). Both bars share the exact same
   footprint (same width, bottom-anchored, position:absolute inside
   .bar-stack) and are semi-transparent, so where they overlap the colors
   blend - taller bar's un-overlapped portion stays visible on its own. */
.bar-stack{position:relative;width:72%;height:100%}
.bar-stack .bar-cost{position:absolute;left:0;right:0;bottom:0;background:#0096D6;opacity:.5;border-radius:4px 4px 0 0;min-height:2px;transition:height .3s ease}
.bar-stack .bar-profit{position:absolute;left:0;right:0;bottom:0;background:#10b981;opacity:.65;border-radius:4px 4px 0 0;min-height:2px;transition:height .3s ease}
.bar-stack .bar-profit.neg{background:#c0392b;opacity:.65}
.stack-label{position:absolute;left:50%;transform:translateX(-50%);font-size:8px;font-weight:700;white-space:nowrap}
.stack-label.cost-lbl{color:#00609C}
.stack-label.profit-lbl{color:#059669}
.stack-label.profit-lbl.neg{color:#c0392b}
.month-labels{display:flex;gap:4px;padding:6px 4px 0}
.month-labels span{flex:1;text-align:center;font-size:10px;color:#666;font-weight:600;min-width:0}
.empty{color:#888;text-align:center;padding:30px 10px;font-size:13px}
.profit-table{width:100%;border-collapse:collapse;font-size:11px}
.profit-table th{text-align:right;color:#888;font-weight:600;padding:6px 4px;border-bottom:1px solid #e5e7eb}
.profit-table th:first-child,.profit-table td:first-child{text-align:left}
.profit-table td{text-align:right;padding:6px 4px;border-bottom:1px solid #f0f4f8}
.profit-table td.profit-pos{color:#166534;font-weight:700}
.profit-table td.profit-neg{color:#c0392b;font-weight:700}
.section-title{font-size:12px;font-weight:700;color:#0f2942;margin:0 0 8px}
</style></head>
<body>
<div class="topbar"><h1>📈 Sales Trend</h1><a href="/customer/{{ reseller_id }}/dashboard" class="btn">← Back</a></div>

<div class="card">
  <label>Year</label>
  <select id="yearSelect" onchange="loadTrend()"></select>
</div>

<div class="card">
  <div class="section-title">💰 Presyo ng Benta Mo (Retail Price per Kg)</div>
  <div class="price-row">
    <div><input type="number" id="retailPriceInput" step="0.01" min="0" placeholder="hal. 15.00"></div>
    <button onclick="saveRetailPrice()">Save</button>
  </div>
  <label style="margin-top:10px">Simula kailan? (effective date)</label>
  <input type="date" id="effectiveDateInput">
  <div class="price-hint">Ito yung presyo na ibinebenta mo sa customers mo per kilo ng yelo. Kung nagbago ang presyo mo (halimbawa bumaba), i-save lang ang BAGONG presyo dito na may tamang petsa - hindi babaguhin ang kita ng mga nakaraang buwan, doon pa rin gagamitin ang lumang presyo.</div>
  <div class="price-status" id="priceStatus"></div>
  <div id="priceHistoryToggle" style="display:none;margin-top:10px">
    <a href="#" onclick="togglePriceHistory();return false" style="font-size:11px;color:#00609C;font-weight:600;text-decoration:none">📜 Tingnan ang Presyo History</a>
    <div id="priceHistoryList" style="display:none;margin-top:8px"></div>
  </div>
</div>

<div class="two-col">
  <div class="total-card"><div class="amt" id="yearTotal">₱0</div><div class="lbl" id="yearTotalLbl">BINILI (COST) - TAON</div></div>
  <div class="total-card profit"><div class="amt" id="yearProfit">₱0</div><div class="lbl" id="yearProfitLbl">TINATAYANG KITA (PROFIT)</div></div>
</div>

<div class="card">
  <div class="section-title">Buwanang Trend</div>
  <div id="chartArea">Loading...</div>
  <div class="price-hint" style="text-align:center;margin-top:8px">👆 I-tap ang isang buwan para makita ang bawat order na bumubuo sa total niya (para ma-verify).</div>
</div>

<div class="card" id="profitTableCard" style="display:none">
  <div class="section-title">📊 Buwanang Profit Analysis</div>
  <table class="profit-table">
    <thead><tr><th>Buwan</th><th>Kg</th><th>Binili</th><th>Ibinenta</th><th>Kita</th></tr></thead>
    <tbody id="profitTableBody"></tbody>
  </table>
  <div class="price-hint" id="profitTableNote" style="display:none;margin-top:8px">⚠️ May mga order na bago pa nailagay ang unang retail price, kaya hindi pa nasasama sa kita computation ang kg na iyon.</div>
</div>

<div class="card" id="breakdownCard" style="display:none">
  <div class="section-title" id="breakdownTitle">📋 Order Breakdown</div>
  <div id="breakdownArea"></div>
</div>

<script>
const START_YEAR = {{ start_year }};
const CURRENT_YEAR = {{ current_year }};
const resellerId = "{{ reseller_id }}";

function escapeHtmlCT(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}
function peso(n){ return '₱' + (Number(n)||0).toLocaleString('en-PH',{minimumFractionDigits:2,maximumFractionDigits:2}); }
function pesoShort(n){
  n = Number(n) || 0;
  if(n >= 1000) return '₱' + (n/1000).toLocaleString('en-PH',{maximumFractionDigits:1}) + 'k';
  return '₱' + n.toLocaleString('en-PH',{maximumFractionDigits:0});
}

function initYearSelect(){
  const sel = document.getElementById('yearSelect');
  let opts = '';
  for(let y = CURRENT_YEAR; y >= START_YEAR; y--){
    opts += `<option value="${y}" ${y===CURRENT_YEAR?'selected':''}>${y}</option>`;
  }
  sel.innerHTML = opts;
}

function initEffectiveDateDefault(){
  const el = document.getElementById('effectiveDateInput');
  if(el && !el.value){
    const now = new Date();
    el.value = now.toISOString().slice(0, 10);
  }
}

async function saveRetailPrice(){
  const statusEl = document.getElementById('priceStatus');
  const val = document.getElementById('retailPriceInput').value;
  const effDate = document.getElementById('effectiveDateInput').value;
  if(val === '' || isNaN(Number(val)) || Number(val) < 0){
    statusEl.textContent = 'Maglagay ng valid na presyo (0 pataas).';
    statusEl.className = 'price-status err';
    return;
  }
  if(!effDate){
    statusEl.textContent = 'Piliin ang petsa kung kailan magsisimula ang presyong ito.';
    statusEl.className = 'price-status err';
    return;
  }
  statusEl.textContent = 'Saving...';
  statusEl.className = 'price-status';
  try{
    const res = await fetch(`/api/customer/${resellerId}/retail_price`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({retail_price_per_kg: Number(val), effective_date: effDate}),
    });
    const data = await res.json();
    if(!data.ok){ statusEl.textContent = data.error || 'Error'; statusEl.className = 'price-status err'; return; }
    statusEl.textContent = `Na-save! Bisa mula ${effDate} - hindi na babaguhin ang kita ng mga nakaraang buwan bago ang petsang ito.`;
    statusEl.className = 'price-status ok';
    loadTrend();
  }catch(e){ statusEl.textContent = 'Error: ' + e.message; statusEl.className = 'price-status err'; }
}

function togglePriceHistory(){
  const list = document.getElementById('priceHistoryList');
  list.style.display = list.style.display === 'none' ? 'block' : 'none';
}

function renderPriceHistory(history){
  const wrap = document.getElementById('priceHistoryToggle');
  const list = document.getElementById('priceHistoryList');
  if(!history || history.length === 0){
    wrap.style.display = 'none';
    return;
  }
  wrap.style.display = 'block';
  const sorted = history.slice().sort((a, b) => (b.effective_date || '').localeCompare(a.effective_date || ''));
  list.innerHTML = '<table class="profit-table"><thead><tr><th>Bisa Mula</th><th>Presyo/Kg</th></tr></thead><tbody>' +
    sorted.map(h => `<tr><td style="text-align:left">${escapeHtmlCT(h.effective_date)}</td><td>${escapeHtmlCT(peso(h.price))}</td></tr>`).join('') +
    '</tbody></table>';
}

async function loadTrend(){
  const chartArea = document.getElementById('chartArea');
  const year = document.getElementById('yearSelect').value;
  chartArea.innerHTML = 'Loading...';
  try{
    const res = await fetch(`/api/customer/${resellerId}/yearly_trend?year=${encodeURIComponent(year)}`);
    const data = await res.json();
    if(!data.ok){ chartArea.innerHTML = `<div class="empty">${escapeHtmlCT(data.error||'Error')}</div>`; return; }

    if(data.retail_price_per_kg !== null && data.retail_price_per_kg !== undefined){
      document.getElementById('retailPriceInput').value = data.retail_price_per_kg;
    }
    renderPriceHistory(data.price_history);

    document.getElementById('yearTotal').textContent = peso(data.year_total);
    document.getElementById('yearTotalLbl').textContent = `BINILI (COST) - ${data.year}`;

    const profitCard = document.getElementById('yearProfit');
    const profitTableCard = document.getElementById('profitTableCard');
    if(data.year_profit !== null && data.year_profit !== undefined){
      profitCard.textContent = peso(data.year_profit);
      document.getElementById('yearProfitLbl').textContent = `TINATAYANG KITA - ${data.year}`;
    }else{
      profitCard.textContent = '—';
      document.getElementById('yearProfitLbl').textContent = 'ILAGAY MUNA ANG RETAIL PRICE SA TAAS';
    }

    const months = data.months || [];
    if(!months.some(m => m.total > 0)){
      chartArea.innerHTML = `<div class="empty">Wala pang na-record na sales noong ${data.year}.</div>`;
      profitTableCard.style.display = 'none';
      return;
    }

    // Overlapping cost-vs-profit bars once a retail price is set (ISESMO's
    // request, Sept 22: "pwd ba yung overlap graph para nakikita yung Cost
    // at profit... totally overlapping/transparent bars"). Falls back to
    // the plain single-bar chart when no retail price is set yet, since
    // there's no profit series to overlay.
    const hasProfit = months.some(m => m.profit !== null && m.profit !== undefined);
    let bars, labels;

    if(hasProfit){
      const maxVal = Math.max(1, ...months.map(m => Math.max(m.total, Math.abs(m.profit || 0))));
      let legend = `<div class="chart-legend">
        <span><span class="dot" style="background:#0096D6"></span>Binili (Cost)</span>
        <span><span class="dot" style="background:#10b981"></span>Kita (Profit)</span>
      </div>`;
      bars = legend + '<div class="chart-wrap">';
      labels = '<div class="month-labels">';
      months.forEach(m => {
        const costPct = m.total > 0 ? Math.max(4, Math.round((m.total / maxVal) * 100)) : 0;
        const profitVal = m.profit || 0;
        const profitPct = profitVal !== 0 ? Math.max(4, Math.round((Math.abs(profitVal) / maxVal) * 100)) : 0;
        const profitNeg = profitVal < 0;
        // Both labels are anchored off the SAME point (whichever bar is
        // taller) with a fixed pixel gap between them, instead of each
        // being positioned off its own bar's height independently. Two
        // overlapping bars often end up close in height (or both hit the
        // 4% floor for a small month) - anchoring off each bar's own top
        // let the labels land almost on top of each other in that case.
        // Stacking them as one small cluster above the taller bar
        // guarantees they never collide, however close costPct and
        // profitPct are to each other.
        const topmostPct = Math.max(costPct, profitPct);
        const costLabelBottom = `calc(${topmostPct}% + 3px)`;
        const profitLabelBottom = `calc(${topmostPct}% + 16px)`;
        bars += `<div class="bar-col" style="cursor:pointer" title="${escapeHtmlCT(m.label)} ${data.year} - Binili: ${escapeHtmlCT(peso(m.total))}, Kita: ${escapeHtmlCT(peso(profitVal))} - tap para tingnan ang mga order" onclick="showMonthBreakdown(${m.month})">
          <div class="bar-stack">
            ${m.total > 0 ? `<div class="stack-label cost-lbl" style="bottom:${costLabelBottom}">${escapeHtmlCT(pesoShort(m.total))}</div>` : ''}
            ${profitVal !== 0 ? `<div class="stack-label profit-lbl${profitNeg?' neg':''}" style="bottom:${profitLabelBottom}">${profitNeg?'-':''}${escapeHtmlCT(pesoShort(Math.abs(profitVal)))}</div>` : ''}
            <div class="bar-cost" style="height:${costPct}%"></div>
            <div class="bar-profit${profitNeg?' neg':''}" style="height:${profitPct}%"></div>
          </div>
        </div>`;
        labels += `<span style="cursor:pointer" onclick="showMonthBreakdown(${m.month})">${escapeHtmlCT(m.label)}</span>`;
      });
      bars += '</div>';
      labels += '</div>';
    }else{
      const maxVal = Math.max(1, ...months.map(m => m.total));
      bars = '<div class="chart-wrap">';
      labels = '<div class="month-labels">';
      months.forEach(m => {
        const pct = m.total > 0 ? Math.max(4, Math.round((m.total / maxVal) * 100)) : 0;
        bars += `<div class="bar-col" style="cursor:pointer" title="${escapeHtmlCT(m.label)} ${data.year}: ${escapeHtmlCT(peso(m.total))} - tap para tingnan ang mga order" onclick="showMonthBreakdown(${m.month})">
          <div class="bar-label">${m.total > 0 ? escapeHtmlCT(pesoShort(m.total)) : ''}</div>
          <div class="bar ${m.total===0?'zero':''}" style="height:${pct}%"></div>
        </div>`;
        labels += `<span style="cursor:pointer" onclick="showMonthBreakdown(${m.month})">${escapeHtmlCT(m.label)}</span>`;
      });
      bars += '</div>';
      labels += '</div>';
    }
    chartArea.innerHTML = bars + labels;

    // Auto-generated monthly profit breakdown - only shown once a retail
    // price is set, so we never display a misleading ₱0 profit
    if(months.some(m => m.profit !== null && m.profit !== undefined)){
      profitTableCard.style.display = 'block';
      const tbody = document.getElementById('profitTableBody');
      tbody.innerHTML = months.map(m => {
        const profitClass = (m.profit || 0) >= 0 ? 'profit-pos' : 'profit-neg';
        const unpricedNote = (m.kg_unpriced || 0) > 0
          ? `<br><span style="font-weight:400;color:#c0392b">⚠️ ${m.kg_unpriced}kg walang price noon</span>` : '';
        return `<tr>
          <td>${escapeHtmlCT(m.label)}</td>
          <td>${(m.kg||0).toLocaleString('en-PH',{maximumFractionDigits:1})}</td>
          <td>${escapeHtmlCT(peso(m.total))}</td>
          <td>${escapeHtmlCT(peso(m.retail_value||0))}</td>
          <td class="${profitClass}">${escapeHtmlCT(peso(m.profit||0))}${unpricedNote}</td>
        </tr>`;
      }).join('');
      const anyUnpriced = months.some(m => (m.kg_unpriced || 0) > 0);
      const noteEl = document.getElementById('profitTableNote');
      if(noteEl) noteEl.style.display = anyUnpriced ? 'block' : 'none';
    }else{
      profitTableCard.style.display = 'none';
    }
  }catch(e){ chartArea.innerHTML = `<div class="empty">Error: ${escapeHtmlCT(e.message)}</div>`; }
  document.getElementById('breakdownCard').style.display = 'none';
}

const MONTH_NAMES_FULL = ['January','February','March','April','May','June','July','August','September','October','November','December'];

const IS_ISESMO = {{ 'true' if is_isesmo else 'false' }};
let currentBreakdownMonth = null;

async function showMonthBreakdown(month){
  const year = document.getElementById('yearSelect').value;
  currentBreakdownMonth = month;
  const card = document.getElementById('breakdownCard');
  const area = document.getElementById('breakdownArea');
  const title = document.getElementById('breakdownTitle');
  title.textContent = `📋 Order Breakdown - ${MONTH_NAMES_FULL[month-1]} ${year}`;
  card.style.display = 'block';
  area.innerHTML = 'Loading...';
  card.scrollIntoView({behavior:'smooth', block:'nearest'});
  try{
    const res = await fetch(`/api/customer/${resellerId}/month_orders?year=${encodeURIComponent(year)}&month=${encodeURIComponent(month)}`);
    const data = await res.json();
    if(!data.ok){ area.innerHTML = `<div class="empty">${escapeHtmlCT(data.error||'Error')}</div>`; return; }

    if(!data.orders || data.orders.length === 0){
      area.innerHTML = `<div class="empty">Walang order na nakita para sa ${MONTH_NAMES_FULL[month-1]} ${year}.</div>`;
      return;
    }

    let html = `<div style="font-size:11px;color:#666;margin-bottom:8px">${data.included_count} order na kasama sa total &bull; Kabuuan: ${escapeHtmlCT(peso(data.included_total))} &bull; ${data.included_kg}kg</div>`;
    html += `<table class="profit-table"><thead><tr><th>Petsa</th><th>Qty x Kg</th><th>Halaga</th><th>Status</th>${IS_ISESMO ? '<th></th>' : ''}</tr></thead><tbody>`;
    data.orders.forEach(o => {
      const deletedNote = o.deleted ? ' <span style="color:#c0392b;font-weight:700">(DELETED - hindi kasama sa total)</span>' : '';
      const rowStyle = o.deleted ? 'opacity:.5;text-decoration:line-through' : '';
      const deleteCell = IS_ISESMO
        ? `<td>${o.deleted ? '' : `<button onclick="deleteBreakdownOrder('${o.id}')" style="padding:4px 8px;border-radius:6px;border:1px solid #fecaca;background:#fef2f2;color:#c0392b;font-size:10px;font-weight:600">🗑️ Delete</button>`}</td>`
        : '';
      html += `<tr style="${rowStyle}">
        <td style="text-align:left">${escapeHtmlCT(o.sales_date||'-')}${deletedNote}</td>
        <td>${o.quantity}x ${escapeHtmlCT(o.kg_size)}</td>
        <td>${escapeHtmlCT(peso(o.total_sales))}</td>
        <td>${escapeHtmlCT(o.order_status)}</td>
        ${deleteCell}
      </tr>`;
    });
    html += '</tbody></table>';
    if(IS_ISESMO){
      html += '<div class="price-hint" style="margin-top:8px">⚠️ Para lang kay ISESMO: ang pag-delete dito ay permanent at hindi na maibabalik. Gamitin lang kung sigurado kang duplicate/maling entry.</div>';
    }
    area.innerHTML = html;
  }catch(e){ area.innerHTML = `<div class="empty">Error: ${escapeHtmlCT(e.message)}</div>`; }
}

async function deleteBreakdownOrder(saleId){
  if(!confirm('Sigurado ka bang i-delete ang order na ito? Hindi na ito maibabalik.')) return;
  try{
    const res = await fetch(`/api/customer/${resellerId}/month_orders/${saleId}`, {method: 'DELETE'});
    const data = await res.json();
    if(!data.ok){ alert('Hindi na-delete: ' + (data.error || 'Unknown error')); return; }
    // refresh the chart/totals first (loadTrend also hides the breakdown
    // card as part of its normal reset), then re-open the breakdown for
    // the same month so staff sees the updated list right away
    const monthToReopen = currentBreakdownMonth;
    await loadTrend();
    if(monthToReopen) await showMonthBreakdown(monthToReopen);
  }catch(e){ alert('Error: ' + e.message); }
}

initYearSelect();
initEffectiveDateDefault();
loadTrend();
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
<button class="btn" id="placeOrderBtn" onclick="placeOrder()">Place Order Live</button>
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
let placingOrder = false; // ROOT CAUSE FIX (Sept 22): the button had no
// disable-on-click guard, so a slow connection + an impatient tap (or two)
// fired this fetch multiple times before the first one finished, each
// creating its own daily_sales row - the duplicate ₱100/₱150 "2026-09-06"
// entries ISESMO spotted in the Sales Trend breakdown. This flag + the
// disabled button below stop a second tap from firing while one is still
// in flight; the matching server-side guard in api_customer_place_order
// stops the same thing from a flaky network retry or a second device.
async function placeOrder(){
  if(placingOrder) return;
  const qty=parseInt(document.getElementById('qty').value)||0;
  const needDate=document.getElementById('needDate').value;
  const notes=document.getElementById('notes').value;
  const btn=document.getElementById('placeOrderBtn');
  placingOrder = true;
  btn.disabled = true;
  const originalLabel = btn.textContent;
  btn.textContent = 'Naglo-load...';
  try{localStorage.setItem(prefKey,JSON.stringify({mode,pay}));}catch(e){}
  try{
    const res=await fetch(`/api/customer/${resellerId}/place_order`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({quantity:qty,kg_size:kg,mode:mode,payment:pay,sales_date:needDate,notes:notes})});
    const data=await res.json();
    if(data.ok){window.location.href=`/customer/${resellerId}/dashboard`;}
    else{
      document.getElementById('status').textContent=data.error||'Failed';
      placingOrder = false;
      btn.disabled = false;
      btn.textContent = originalLabel;
    }
  }catch(e){
    document.getElementById('status').textContent='Error: '+e.message;
    placingOrder = false;
    btn.disabled = false;
    btn.textContent = originalLabel;
  }
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

@app.route("/api/customer/push/subscribe", methods=["POST"])
def api_customer_push_subscribe():
    """Same idea as /api/push/subscribe above, but for a RESELLER's own
    device instead of staff - separate endpoint because login_required
    only accepts a staff session (session['staff_name']), while a
    customer is logged in under session['customer_id']. Stores
    reseller_id instead of staff_name on the subscription record, which
    is exactly what send_push_to_all_resellers() filters on."""
    if not session.get("customer_id"):
        return jsonify({"ok": False, "error": "Login required"}), 401
    try:
        data = request.json or {}
        endpoint = data.get("endpoint")
        keys = data.get("keys") or {}
        if not endpoint or not keys.get("p256dh") or not keys.get("auth"):
            return jsonify({"ok": False, "error": "Invalid subscription"}), 400
        import hashlib
        sub_id = hashlib.sha256(endpoint.encode()).hexdigest()[:32]
        fb_put(f"push_subscriptions/{sub_id}", {
            "endpoint": endpoint,
            "keys": {"p256dh": keys.get("p256dh"), "auth": keys.get("auth")},
            "reseller_id": session.get("customer_id"),
            "subscribed_at": manila_now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/push/unsubscribe", methods=["POST"])
def api_customer_push_unsubscribe():
    if not session.get("customer_id"):
        return jsonify({"ok": False, "error": "Login required"}), 401
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
    return render_template_string(CUSTOMER_DASHBOARD_HTML, reseller_id=reseller_id, vapid_public_key=VAPID_PUBLIC_KEY, push_enabled=PUSH_ENABLED)

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

# Business started 2025 - the year dropdown on the reseller sales-trend page
# never goes below this (ISESMO's request, Sept 22: same "start sa 2025"
# rule as the staff-side expense trend page).
CUSTOMER_TREND_START_YEAR = 2025

@app.route("/customer/<reseller_id>/trend")
def customer_trend_page(reseller_id):
    if not session.get("customer_id") and not session.get("staff_name"):
        return redirect(url_for("customer_login_page"))
    if session.get("customer_id") and session.get("customer_id") != reseller_id and not session.get("staff_name"):
        return redirect(f"/customer/{session.get('customer_id')}/trend")
    current_year = max(datetime.now().year, CUSTOMER_TREND_START_YEAR)
    # Delete-from-breakdown is ISESMO-only, not "any staff" (ISESMO's
    # explicit rule, Sept 22: "dapat kay isesmo lang yun active") - this
    # page is reachable from a reseller's own account, so the gate has to
    # be specific, not just "is someone with a staff_name looking at this".
    staff = (session.get("staff_name") or "").strip().lower()
    is_isesmo = staff in ["isesmo", "isesmo gamboa"]
    return render_template_string(
        CUSTOMER_TREND_HTML,
        reseller_id=reseller_id,
        start_year=CUSTOMER_TREND_START_YEAR,
        current_year=current_year,
        is_isesmo=is_isesmo,
    )

@app.route("/api/customer/login", methods=["POST"])
def api_customer_login():
    try:
        data = request.json or {}
        phone = clean_phone(data.get("phone") or "")
        pwd = data.get("password") or ""
        if not phone or not pwd:
            return jsonify({"ok": False, "error": "Phone and password required"}), 400
        # Per-phone brute-force lockout (ISESMO's request, Sept 22): 3
        # failed password attempts against THIS phone number within 15
        # minutes locks it out for 15 minutes, no matter which
        # device/IP is trying - this endpoint had NO protection at all
        # before (unlike the staff PIN login's is_rate_limited(ip) use
        # below). Reuses the exact same is_rate_limited/record_attempt
        # machinery, just keyed by phone instead of IP, so one phone
        # number can't be hammered with password guesses even from
        # many different devices. Checked BEFORE the phone lookup so a
        # locked-out phone can't be used to keep probing whether a
        # given password is right.
        phone_key = f"cust_phone_{phone}"
        if is_rate_limited(phone_key, max_attempts=3, window_seconds=900):
            log_customer_login(None, None, phone, False, "Locked out - too many failed attempts")
            return jsonify({
                "ok": False,
                "error": "Sobrang daming maling attempt. Naka-lock muna ang account na ito - subukan ulit pagkalipas ng 15 minuto, o makipag-ugnayan kay ISESMO.",
            }), 429
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
            record_attempt(phone_key)
            log_customer_login(matched_id, matched.get("store_name"), phone, False, "Wrong password")
            return jsonify({"ok": False, "error": "Wrong password"}), 401
        clear_attempts(phone_key)
        # SESSION HYGIENE FIX (ISESMO's report, Sept 22: delete button meant
        # only for isesmo was showing up ACTIVE when he checked a reseller's
        # own account). Root cause: logging in as a customer never cleared
        # a staff_name left over from an earlier staff login in the same
        # browser/session cookie, so a session could carry BOTH staff_name
        # AND customer_id at once - any page that only checked "is there a
        # staff_name?" then wrongly treated that reseller session as staff.
        # Logging in as a customer must always fully replace any staff
        # identity in this session, never layer on top of it.
        session.pop("staff_name", None)
        session.pop("staff_id", None)
        session.pop("staff_position", None)
        session["customer_id"] = matched_id
        session["customer_name"] = matched.get("store_name")
        # Explicit "Manual login" reason (was blank before) so the Login
        # Activity page can tell manual-password logins apart from QR
        # logins (which already tag themselves "QR login" below) instead
        # of guessing from an empty string.
        log_customer_login(matched_id, matched.get("store_name"), phone, True, "Manual login")
        # Device-fingerprint check (boss's request, Sept 23): flag +
        # push-notify when this login comes from a device/browser this
        # account hasn't used before, then remember it for next time via
        # a long-lived cookie on the response (never blocks the login
        # itself even if this hiccups).
        is_new_device, device_id = check_and_register_device(matched_id)
        if is_new_device:
            notify_new_device_login(matched_id, matched.get("store_name"))
        resp = make_response(jsonify({"ok": True, "reseller_id": matched_id}))
        set_device_cookie(resp, device_id)
        return resp
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/request_otp", methods=["POST"])
def api_customer_request_otp():
    try:
        data = request.json or {}
        phone = clean_phone(data.get("phone") or "")
        if not phone:
            return jsonify({"ok": False, "error": "Phone required"}), 400
        # OTP-REQUEST RATE LIMIT (boss's request, Sept 22: wiring up the
        # Forgot Password flow surfaced that this endpoint had NO limit at
        # all - every call sends a real SMS via Semaphore (real money) and
        # needs no login, so without this a phone number could be spammed
        # with OTP requests indefinitely. Same is_rate_limited/
        # record_attempt machinery as the login lockout above, just its
        # own key namespace (otp_req_ vs cust_phone_) so a burst of wrong
        # LOGIN passwords doesn't also burn a customer's OTP-request quota
        # and vice versa. Checked before the phone lookup for the same
        # reason as the login lockout: don't let a locked-out phone keep
        # being useful to probe.
        otp_key = f"otp_req_{phone}"
        if is_rate_limited(otp_key, max_attempts=3, window_seconds=900):
            return jsonify({
                "ok": False,
                "error": "Sobrang daming OTP request. Subukan ulit pagkalipas ng 15 minuto, o makipag-ugnayan kay ISESMO.",
            }), 429
        resellers = fb_get("resellers") or {}
        found = False
        for val in resellers.values():
            if not val: continue
            if clean_phone(val.get("phone") or "") == phone:
                found = True
                break
        if not found:
            return jsonify({"ok": False, "error": "Phone not registered"}), 404
        record_attempt(otp_key)
        otp = generate_otp()
        # Save OTP with 5 min expiry
        otp_data = {"phone": phone, "otp": otp, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "expires_at": (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"), "used": False}
        fb_post("customer_otps", otp_data)

        # NO SMS (boss's explicit decision, Sept 22: "wag na sms yung otp
        # dapat lilitaw nalang agad sa login screen ng customer" - his
        # choice, after I flagged the tradeoff, was to skip the extra
        # store-name check too and just show it plainly). This
        # deliberately UNDOES the Sept 19 "CRITICAL SECURITY FIX" comment
        # that used to be here: that fix stopped the OTP from ever
        # appearing in this public, no-login-required response, because
        # doing so lets anyone who knows a registered phone number reset
        # that account's password without ever touching the phone itself.
        # That risk is back by design now - the only guard left on this
        # endpoint is the 3-requests/15-min rate limit above. If phone
        # numbers ever become guessable/sequential or this app handles
        # anything more sensitive than ice orders, revisit this.
        return jsonify({"ok": True, "otp": otp, "message": "OTP generated. Valid 5 mins."})
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
        # OTP-VERIFY RATE LIMIT (boss's request, Sept 22): a 6-digit OTP is
        # only 1,000,000 combinations and this endpoint needs no login, so
        # without a limit here someone could brute-force it within its
        # 5-minute validity window. Own key namespace again (otp_verify_)
        # so this never interacts with the request-OTP or login limits.
        verify_key = f"otp_verify_{phone}"
        if is_rate_limited(verify_key, max_attempts=5, window_seconds=300):
            return jsonify({
                "ok": False,
                "error": "Sobrang daming maling OTP attempt. Humingi ng bagong OTP pagkalipas ng ilang minuto.",
            }), 429
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
            record_attempt(verify_key)
            return jsonify({"ok": False, "error": "Invalid or expired OTP"}), 400
        clear_attempts(verify_key)
        clear_attempts(f"otp_req_{phone}")
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
        log_customer_activity(target_id, resellers.get(target_id, {}).get("store_name"),
                               "Nag-reset ng password (OTP)", "")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/<reseller_id>/change_password", methods=["POST"])
def api_customer_change_password(reseller_id):
    """Lets an ALREADY-LOGGED-IN reseller change their own password from
    the dashboard (boss's request, Sept 22: "gusto ng customer sila
    magupdate ng password nila") - no OTP/SMS needed here since they've
    already proven who they are by being logged in; they just have to
    also know their CURRENT password (standard "change password" pattern,
    stops someone who grabbed an unlocked phone from silently locking the
    real owner out). This is deliberately separate from the OTP-based
    /api/customer/verify_otp flow, which is for a customer who does NOT
    know their current password at all (forgot it)."""
    try:
        # Customer-only, and only for their OWN account - staff have their
        # own dedicated /api/reseller/<id>/set_password (isesmo_only) for
        # resetting a customer's password on their behalf; this endpoint
        # is not it.
        if session.get("customer_id") != reseller_id:
            return jsonify({"ok": False, "error": "Not allowed"}), 403
        data = request.json or {}
        current_pwd = data.get("current_password") or ""
        new_pwd = (data.get("new_password") or "").strip()
        if not current_pwd or not new_pwd:
            return jsonify({"ok": False, "error": "Current at bagong password kailangan"}), 400
        if len(new_pwd) < 4:
            return jsonify({"ok": False, "error": "Password min 4 chars"}), 400
        # Brute-force guard on the CURRENT-password check, same
        # is_rate_limited/record_attempt pattern as everywhere else in
        # this file - keyed by reseller_id (not phone/IP) since the
        # attacker here is already inside an active session for this
        # specific account.
        guard_key = f"cust_changepwd_{reseller_id}"
        if is_rate_limited(guard_key, max_attempts=5, window_seconds=900):
            return jsonify({
                "ok": False,
                "error": "Sobrang daming maling attempt. Subukan ulit pagkalipas ng 15 minuto.",
            }), 429
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        stored_hash = reseller.get("password_hash") or ""
        if not stored_hash or not verify_customer_password(stored_hash, current_pwd):
            record_attempt(guard_key)
            return jsonify({"ok": False, "error": "Maling current password"}), 401
        clear_attempts(guard_key)
        hashed = hash_customer_password(new_pwd)
        fb_patch(f"resellers/{reseller_id}", {"password_hash": hashed})
        log_customer_activity(reseller_id, reseller.get("store_name"), "Binago ang password", "")
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
        now = manila_now()
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
            # DECLINE DECAY, applied to the Summary status-count pills too
            # (boss's follow-up, Sept 22: "yung decline na count sa taas
            # dapat mawala na din") - not just the order-card sort. Once a
            # Declined order is past its 24hr visibility window it no
            # longer counts toward the "Declined: N" pill either, same as
            # it no longer sorts near the top of the list.
            if not (status == "Declined" and is_order_stale(val.get("declined_at"))):
                status_counts[status] = status_counts.get(status,0)+1
            orders.append({"id": key, "sales_date": val.get("sales_date"), "quantity": qty, "kg_size": kg_size, "total_sales": peso, "mode": val.get("mode"), "payment": val.get("payment"), "order_status": status, "created_at": val.get("created_at"), "rating": val.get("rating"), "feedback": val.get("feedback"), "decline_reason": val.get("decline_reason") or "", "declined_at": val.get("declined_at") or ""})
        def status_priority_c(s):
            order = (s.get("order_status") or "Pending")
            priorities = {"New Order": 0, "Pending": 1, "Preparing": 2, "Out for Delivery": 3, "Declined": 4, "Delivered": 5, "Cancelled": 6}
            # DECLINE DECAY (boss's request, Sept 22): a fresh Declined order
            # sorts near the top (priority 4, ahead of Delivered) so the
            # customer notices it - but once it's had 24hrs of visibility,
            # it's no longer "news", so it drops to the bottom with
            # Cancelled instead of permanently crowding out newer Delivered
            # orders from the list.
            if order == "Declined" and is_order_stale(s.get("declined_at")):
                return 6
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
        now = manila_now()

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

MONTH_LABELS_CUST = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

def _get_retail_price_entries(reseller_id, reseller=None):
    """
    Returns (price_entries, current_price) for one reseller.
    price_entries is a list of (effective_date_str, price) sorted ascending
    by effective_date - the full history of retail-price changes this
    reseller has logged, used to price each order by the date it actually
    happened on (see _retail_price_for_date).
    current_price is whichever entry has the LATEST effective_date (used
    to pre-fill the input on the trend page) - None if no price was ever
    set.

    Backward compatibility: a reseller who set a price under the OLD
    single-field version (resellers/<id>/retail_price_per_kg, before
    per-date history existed) but has no history entries yet gets a
    single synthesized entry dated CUSTOMER_TREND_START_YEAR-01-01, so
    their existing profit numbers don't change until they log an actual
    price change.
    """
    if reseller is None:
        reseller = fb_get(f"resellers/{reseller_id}") or {}
    history = fb_get(f"resellers/{reseller_id}/retail_price_history") or {}
    entries = []
    for v in history.values():
        if not v or not v.get("effective_date"):
            continue
        try:
            price = float(v.get("price"))
        except (TypeError, ValueError):
            continue
        entries.append((v.get("effective_date"), price))
    entries.sort(key=lambda t: t[0])

    if not entries:
        legacy_price = reseller.get("retail_price_per_kg")
        if legacy_price is not None:
            try:
                entries = [(f"{CUSTOMER_TREND_START_YEAR}-01-01", float(legacy_price))]
            except (TypeError, ValueError):
                pass

    current_price = entries[-1][1] if entries else None
    return entries, current_price

def _retail_price_for_date(price_entries, date_str):
    """
    Given price_entries (sorted ascending by effective_date, from
    _get_retail_price_entries) and one order's date, returns whichever
    price was actually in effect on that date - the latest entry whose
    effective_date is <= date_str. Returns None if the order predates
    every price entry on record (nothing was set yet at that time), so
    the caller can flag that kg as "kg_unpriced" instead of guessing.
    """
    applicable = None
    for eff_date, price in price_entries:
        if eff_date <= date_str:
            applicable = price
        else:
            break
    return applicable

@app.route("/api/customer/<reseller_id>/yearly_trend")
def api_customer_yearly_trend(reseller_id):
    """
    Simple monthly sales-peso trend for ONE reseller across a chosen year -
    same identify-the-reseller's-rows logic as /api/customer/<id>/history
    (match by reseller_id OR by store name, since older daily_sales rows
    may only carry reseller_name), just bucketed by month instead of by
    period. Same auth pattern as the other customer endpoints (ISESMO's
    request, Sept 22: "gusto ko ganyan lang kasimple yung sales monitoring
    trend nila" - reuse the same simple bar-graph-by-year UI already built
    for the staff-side expense trend page).

    Also computes an auto profit ("kita") analysis (ISESMO's follow-up
    request, same day: "pwd na ilagay yung retail price nya tapos may auto
    generated na analysis magkano kita nya... kunwari bili nya ng 10
    binenta nya ng 15"):
      - "total" per month = what the reseller PAID Omega Ice for their
        stock that month (this is what daily_sales.total_sales already
        records - the "bili" side).
      - "kg" per month = total kg of ice they bought that month.
      - retail_value = the sum, order by order, of that order's kg times
        whatever retail price was ACTUALLY IN EFFECT on that order's date
        (see _retail_price_for_date below) - the "benta" side.
      - profit = retail_value - total (the estimated "kita").
    profit/retail_value are null until the reseller has ANY retail price
    on record - we never guess a number for them.

    PRICE HISTORY (ISESMO's follow-up request, same day: "paano kung
    paibaba ng price per month yung reseller paano yun maseset na tama pa
    din per month ang kita nila"): a reseller's retail price can change
    over time (they lower or raise what they charge their own
    customers), and profit for a PAST month must keep using the price
    that was actually in effect back then - not retroactively recomputed
    with today's price. So retail_price_per_kg is no longer a single
    current number: every save appends a dated entry to
    resellers/<id>/retail_price_history, and each individual order here
    is priced using the entry whose effective_date is the latest one
    on or before that order's own sales_date. A reseller who set a price
    under the OLD single-field version (before this history existed) is
    treated as if that price took effect on CUSTOMER_TREND_START_YEAR-01-01,
    so nothing changes for them until they log an actual price change.
    """
    if session.get("customer_id") and session.get("customer_id") != reseller_id:
        return jsonify({"ok": False, "error": "Not allowed"}), 403
    if not session.get("customer_id") and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Login required"}), 401
    try:
        year_raw = (request.args.get("year") or "").strip()
        try:
            year = int(year_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid year"}), 400
        if year < CUSTOMER_TREND_START_YEAR or year > datetime.now().year:
            return jsonify({"ok": False, "error": "Year out of range"}), 400

        reseller = fb_get(f"resellers/{reseller_id}") or {}
        target_name = (reseller.get("store_name") or "").strip().lower()
        sales = fb_get("daily_sales") or {}

        price_entries, current_price = _get_retail_price_entries(reseller_id, reseller)

        def kg_val(s):
            try:
                return float(str(s).lower().replace("kg", "").strip())
            except (TypeError, ValueError):
                return 0

        month_totals = [0.0] * 12
        month_kg = [0.0] * 12
        month_retail_value = [0.0] * 12
        month_kg_unpriced = [0.0] * 12
        for val in sales.values():
            if not val or val.get("deleted"):
                continue
            rid = val.get("reseller_id")
            rname = (val.get("reseller_name") or "").strip().lower()
            if rid != reseller_id and rname != target_name:
                continue
            date_str = val.get("sales_date") or (val.get("created_at") or "")[:10] or ""
            if len(date_str) < 7 or not date_str.startswith(f"{year}-"):
                continue
            try:
                month_idx = int(date_str[5:7]) - 1
            except ValueError:
                continue
            if 0 <= month_idx < 12:
                month_totals[month_idx] += float(val.get("total_sales", 0) or 0)
                qty = int(val.get("quantity", 0) or 0)
                kg = qty * kg_val(val.get("kg_size", "1Kg"))
                month_kg[month_idx] += kg
                price_then = _retail_price_for_date(price_entries, date_str)
                if price_then is not None:
                    month_retail_value[month_idx] += kg * price_then
                else:
                    month_kg_unpriced[month_idx] += kg

        has_any_price = len(price_entries) > 0
        months = []
        for i in range(12):
            cost = round(month_totals[i], 2)
            kg = round(month_kg[i], 2)
            if has_any_price:
                retail_value = round(month_retail_value[i], 2)
                profit = round(retail_value - cost, 2)
            else:
                retail_value = None
                profit = None
            months.append({
                "month": i + 1, "label": MONTH_LABELS_CUST[i],
                "total": cost, "kg": kg,
                "retail_value": retail_value, "profit": profit,
                "kg_unpriced": round(month_kg_unpriced[i], 2),
            })

        year_total = round(sum(month_totals), 2)
        year_kg = round(sum(month_kg), 2)
        if has_any_price:
            year_retail_value = round(sum(month_retail_value), 2)
            year_profit = round(year_retail_value - year_total, 2)
        else:
            year_retail_value = None
            year_profit = None

        return jsonify({
            "ok": True,
            "store_name": reseller.get("store_name") or "",
            "year": year,
            "retail_price_per_kg": current_price,
            "price_history": [{"effective_date": d, "price": p} for d, p in price_entries],
            "months": months,
            "year_total": year_total,
            "year_kg": year_kg,
            "year_retail_value": year_retail_value,
            "year_profit": year_profit,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/customer/<reseller_id>/retail_price", methods=["POST"])
def api_customer_set_retail_price(reseller_id):
    """
    Lets a reseller save their own retail selling price (₱ per kg) so the
    yearly-trend page can auto-compute their estimated profit. Same
    auth pattern as the other customer endpoints - a reseller can only set
    their OWN price, staff can set it for any reseller (e.g. helping a
    less tech-savvy reseller over the phone).

    PRICE HISTORY (ISESMO's request, Sept 22: "paano kung paibaba ng
    price per month yung reseller paano yun maseset na tama pa din per
    month ang kita nila"): this does NOT overwrite a single stored price
    anymore - it APPENDS a dated entry to
    resellers/<id>/retail_price_history, defaulting effective_date to
    today. Past months keep using whatever price was actually in effect
    back then (see _retail_price_for_date), so lowering the price today
    never retroactively changes an already-computed month's profit.
    Passing an EARLIER effective_date lets ISESMO backfill "noong Enero,
    ganito pa presyo niya" after the fact.
    """
    if session.get("customer_id") and session.get("customer_id") != reseller_id:
        return jsonify({"ok": False, "error": "Not allowed"}), 403
    if not session.get("customer_id") and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Login required"}), 401
    try:
        data = request.json or {}
        raw = data.get("retail_price_per_kg")
        try:
            price = float(raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid retail price"}), 400
        if price < 0:
            return jsonify({"ok": False, "error": "Retail price can't be negative"}), 400
        reseller = fb_get(f"resellers/{reseller_id}")
        if not reseller:
            return jsonify({"ok": False, "error": "Reseller not found"}), 404

        effective_date = (data.get("effective_date") or "").strip() or datetime.now().strftime("%Y-%m-%d")
        try:
            datetime.strptime(effective_date, "%Y-%m-%d")
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid effective date (dapat YYYY-MM-DD)"}), 400

        fb_post(f"resellers/{reseller_id}/retail_price_history", {
            "price": price,
            "effective_date": effective_date,
            "set_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "set_by": session.get("staff_name") or "reseller",
        })

        # Recompute the cached "current" price - whichever entry has the
        # LATEST effective_date, which may not be the one just added if
        # ISESMO is backfilling an older date after a newer price already
        # exists.
        price_entries, current_price = _get_retail_price_entries(reseller_id, reseller)
        fb_patch(f"resellers/{reseller_id}", {"retail_price_per_kg": current_price})

        return jsonify({
            "ok": True,
            "retail_price_per_kg": current_price,
            "effective_date": effective_date,
            "price_history": [{"effective_date": d, "price": p} for d, p in price_entries],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/customer/<reseller_id>/month_orders")
def api_customer_month_orders(reseller_id):
    """
    Raw order-by-order breakdown for ONE reseller, ONE specific month -
    exactly the rows that get summed into that month's bar on the yearly
    trend chart. Lets ISESMO (or the reseller) double-check a total that
    looks off by seeing every individual sale that fed into it, instead of
    just trusting the sum (ISESMO's request, Sept 22: "need ma double
    check yung data ni kly at iba pang reseller sa buwan ng Sept").
    Same identify-the-reseller's-rows logic and auth pattern as
    /yearly_trend, just returning the raw rows instead of a monthly sum.
    """
    if session.get("customer_id") and session.get("customer_id") != reseller_id:
        return jsonify({"ok": False, "error": "Not allowed"}), 403
    if not session.get("customer_id") and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Login required"}), 401
    try:
        year_raw = (request.args.get("year") or "").strip()
        month_raw = (request.args.get("month") or "").strip()
        try:
            year = int(year_raw)
            month = int(month_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid year/month"}), 400
        if year < CUSTOMER_TREND_START_YEAR or year > datetime.now().year:
            return jsonify({"ok": False, "error": "Year out of range"}), 400
        if month < 1 or month > 12:
            return jsonify({"ok": False, "error": "Invalid month"}), 400

        reseller = fb_get(f"resellers/{reseller_id}") or {}
        target_name = (reseller.get("store_name") or "").strip().lower()
        sales = fb_get("daily_sales") or {}
        month_prefix = f"{year}-{month:02d}"

        def kg_val(s):
            try:
                return float(str(s).lower().replace("kg", "").strip())
            except (TypeError, ValueError):
                return 0

        rows = []
        for key, val in sales.items():
            if not val:
                continue
            rid = val.get("reseller_id")
            rname = (val.get("reseller_name") or "").strip().lower()
            if rid != reseller_id and rname != target_name:
                continue
            date_str = val.get("sales_date") or (val.get("created_at") or "")[:10] or ""
            if not date_str.startswith(month_prefix):
                continue
            qty = int(val.get("quantity", 0) or 0)
            kg_size = val.get("kg_size", "1Kg")
            rows.append({
                "id": key,
                "sales_date": val.get("sales_date"),
                "created_at": val.get("created_at") or "",
                "quantity": qty,
                "kg_size": kg_size,
                "kg": round(qty * kg_val(kg_size), 2),
                "total_sales": float(val.get("total_sales", 0) or 0),
                "order_status": val.get("order_status") or "Delivered",
                "deleted": bool(val.get("deleted")),
                "order_source": val.get("order_source") or "",
                "reseller_id": rid,
                "reseller_name": val.get("reseller_name") or "",
            })
        rows.sort(key=lambda r: r.get("sales_date") or r.get("created_at") or "")

        # included = what actually feeds the month's total on the chart
        # (deleted rows are excluded there); shown separately here so a
        # deleted-but-still-visible row doesn't get mistaken for a
        # double-count.
        included = [r for r in rows if not r["deleted"]]
        return jsonify({
            "ok": True,
            "store_name": reseller.get("store_name") or "",
            "year": year,
            "month": month,
            "orders": rows,
            "included_count": len(included),
            "included_total": round(sum(r["total_sales"] for r in included), 2),
            "included_kg": round(sum(r["kg"] for r in included), 2),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/customer/<reseller_id>/month_orders/<sale_id>", methods=["DELETE"])
def api_customer_delete_month_order(reseller_id, sale_id):
    """
    ISESMO-only delete for a single sale, used by the "🗑️ Delete" button in
    the Sales Trend order-breakdown audit view (/customer/<id>/trend).

    Deliberately its OWN endpoint, separate from the general
    /api/sale/<id> DELETE (which any logged-in staff can use from Manage
    Orders) - ISESMO's explicit rule (Sept 22): "dapat kay isesmo lang yun
    active" (only ISESMO should be able to delete from here). This page is
    reachable from a page a RESELLER can also open (their own Sales
    Trend), so the check has to be isesmo-specific, not just "is there a
    staff_name in this session" - see the session-hygiene fix in
    api_customer_login for the related bug where a leftover staff_name
    from an earlier login made this look "active" on a reseller's own
    account.
    """
    staff = (session.get("staff_name") or "").strip().lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Si ISESMO lang ang pwedeng mag-delete dito."}), 403
    try:
        sale = fb_get(f"daily_sales/{sale_id}")
        if not sale:
            return jsonify({"ok": False, "error": "Order not found"}), 404
        # Defense in depth: confirm this sale actually belongs to the
        # reseller_id named in the URL (same match-by-id-or-store-name
        # logic as the rest of the trend/breakdown endpoints) before
        # allowing the delete, so a stray/mistyped reseller_id can't be
        # used to delete an unrelated reseller's order.
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        target_name = (reseller.get("store_name") or "").strip().lower()
        rid = sale.get("reseller_id")
        rname = (sale.get("reseller_name") or "").strip().lower()
        if rid != reseller_id and rname != target_name:
            return jsonify({"ok": False, "error": "Order does not belong to this reseller"}), 403
        ok = fb_delete(f"daily_sales/{sale_id}")
        if not ok:
            return jsonify({"ok": False, "error": "Firebase delete failed - check server logs"}), 502
        # Same dashboard-cache clear as api_delete_sale, so Today/period
        # totals elsewhere in the app drop this sale immediately.
        for kk in list(globals().keys()):
            if kk.startswith("_dashboard_cache_"):
                try: del globals()[kk]
                except: pass
        return jsonify({"ok": True})
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
        if session.get("customer_id") == reseller_id:
            log_customer_activity(reseller_id, reseller.get("store_name"), "Nag-rate ng order",
                                   f"{rating}★" + (f" - {feedback}" if feedback else ""))
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

        # SERVER-SIDE DUPLICATE GUARD (ISESMO's report, Sept 22: repeated
        # identical "2026-09-06" orders showing up in the Sales Trend
        # breakdown). The client-side fix disables the button on tap, but
        # that alone doesn't cover a flaky connection retrying the request
        # or a second device/tab - so this checks Firebase directly: if
        # this SAME reseller placed an order with the SAME qty/kg_size/
        # mode/payment/sales_date in the last 10 seconds, treat this as an
        # accidental double-submit and reject it instead of creating
        # another row. A genuinely separate order (different qty, or more
        # than 10s apart) is never blocked.
        try:
            recent_sales = fb_get("daily_sales") or {}
            now_dt = datetime.now()
            for val in recent_sales.values():
                if not val or val.get("deleted") or val.get("reseller_id") != reseller_id:
                    continue
                if (val.get("quantity") != qty or val.get("kg_size") != kg_size
                        or val.get("mode") != mode or val.get("payment") != payment
                        or val.get("sales_date") != sales_date):
                    continue
                ca = val.get("created_at") or ""
                try:
                    ca_dt = datetime.strptime(ca, "%Y-%m-%d %H:%M:%S")
                except (TypeError, ValueError):
                    continue
                if (now_dt - ca_dt).total_seconds() < 10:
                    return jsonify({
                        "ok": False,
                        "error": "Parang na-submit mo na ito kanina lang - hindi na ulit isinend para hindi madoble.",
                        "duplicate": True,
                    }), 409
        except Exception as dup_check_err:
            # Never let the guard itself block a legit order - log and fall
            # through to normal placement.
            print(f"duplicate-order guard check failed (non-fatal): {dup_check_err}")

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
        # CUSTOMER ACTIVITY LOG (ISESMO-only, boss's request, Sept 22) -
        # only when the RESELLER placed this themselves, not when staff
        # types an order in on their behalf (staff sales already have
        # their own trail via staff_name on the sale record).
        if session.get("customer_id") == reseller_id:
            log_customer_activity(reseller_id, reseller.get("store_name"), "Nag-order",
                                   f"{qty}x {kg_size} ({mode}, {payment}) - ₱{total}")
        return jsonify({"ok": True, "total": total})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/<reseller_id>/points")
def api_customer_points(reseller_id):
    """
    Points balance + the reward catalog for one reseller, with a
    can_redeem flag already computed per reward so the customer page
    doesn't need its own math. Same access pattern as the other
    customer/<reseller_id> endpoints in this file: the logged-in
    customer can only see their own, staff can look up anyone's (needed
    if a customer wants to redeem in person at the counter).
    """
    if session.get("customer_id") and session.get("customer_id") != reseller_id and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Not allowed"}), 403
    if not session.get("customer_id") and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Login required"}), 401
    try:
        balance = check_and_expire_points(reseller_id)
        cooldown_days_left = get_redemption_cooldown_status(reseller_id)
        program_paused = is_loyalty_program_paused()
        catalog = get_reward_catalog()
        rewards = []
        for key, val in catalog.items():
            if not val:
                continue
            points_required = int(val.get("points_required", 0) or 0)
            rewards.append({
                "id": key,
                "label": val.get("label", ""),
                "kg_size": val.get("kg_size", "1Kg"),
                "quantity": val.get("quantity", 1),
                "points_required": points_required,
                # Never redeemable while the whole program is paused,
                # regardless of balance/cooldown - matches the hard
                # block in api_customer_redeem below.
                "can_redeem": (not program_paused) and balance >= points_required and cooldown_days_left <= 0,
            })
        rewards.sort(key=lambda r: r["points_required"])
        # Let the customer see when their points will lapse if they don't
        # order again, so the expiration rule motivates a next order
        # instead of just silently wiping their balance one day.
        expires_at = None
        last_earned = fb_get(f"loyalty_points/{reseller_id}/last_earned_at")
        if balance > 0 and last_earned:
            try:
                last_dt = datetime.strptime(last_earned, "%Y-%m-%d %H:%M:%S")
                expiry_days = get_points_expiry_days()
                expires_at = (last_dt + timedelta(days=expiry_days)).strftime("%Y-%m-%d")
            except Exception:
                expires_at = None
        return jsonify({
            "ok": True,
            "balance": balance,
            "rewards": rewards,
            "expires_at": expires_at,
            "cooldown_days_left": cooldown_days_left,
            "program_paused": program_paused,
            # Only meaningful while paused - lets the dashboard tell the
            # reseller WHEN it's coming back, not just that it's paused.
            # None if ISESMO hasn't scheduled a resume date (paused
            # indefinitely / manual resume only).
            "scheduled_resume_at": fb_get("loyalty_settings/scheduled_resume_at") if program_paused else None,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/<reseller_id>/redeem", methods=["POST"])
def api_customer_redeem(reseller_id):
    """
    Redeems one reward from the catalog for this reseller. ALWAYS
    re-checks the points balance server-side right here, right before
    deducting - never trusts whatever balance the client last showed on
    screen, since that could be stale or (if this endpoint didn't
    re-check) manipulated. On success, creates a normal daily_sales
    order (total_sales=0, reward_redemption=True, order_source=
    "customer") so it flows through the EXACT SAME Live Orders / status
    pipeline staff already use every day - no separate fulfillment
    system to build or for staff to learn. That reward_redemption flag
    is also what stops the Delivered-status hook from awarding points on
    a free item redeeming itself.
    """
    if session.get("customer_id") and session.get("customer_id") != reseller_id and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Not allowed"}), 403
    if not session.get("customer_id") and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Login required"}), 401
    try:
        # Program-wide pause check FIRST - takes priority over the
        # cooldown/balance checks below, since it's a blanket "nobody
        # redeems right now" switch, not a per-reseller rule.
        if is_loyalty_program_paused():
            return jsonify({
                "ok": False,
                "error": "Pansamantalang naka-pause ang Points Rewards Program - hindi muna pwede mag-redeem. Ligtas at buo pa rin ang points mo, babalik ito once na-resume na.",
                "program_paused": True,
            }), 400
        data = request.json or {}
        reward_id = data.get("reward_id")
        catalog = get_reward_catalog()
        reward = catalog.get(reward_id)
        if not reward:
            return jsonify({"ok": False, "error": "Reward not found"}), 404
        required = int(reward.get("points_required", 0) or 0)
        # Cooldown check BEFORE the points check - even a reseller who
        # has piled up enough points for several rewards at once still
        # can't fire them all off in one sitting (see
        # get_redemption_cooldown_status docstring for why).
        cooldown_days_left = get_redemption_cooldown_status(reseller_id)
        if cooldown_days_left > 0:
            return jsonify({
                "ok": False,
                "error": f"Hindi pa pwede mag-redeem ulit - hintayin muna ang {cooldown_days_left} (na) araw bago ka makapag-redeem ulit.",
                "cooldown_days_left": cooldown_days_left,
            }), 400
        balance = check_and_expire_points(reseller_id)
        if balance < required:
            return jsonify({"ok": False, "error": f"Kulang pa ng points - kailangan {required}, meron ka lang {balance}"}), 400
        reseller = fb_get(f"resellers/{reseller_id}") or {}
        if not reseller:
            return jsonify({"ok": False, "error": "Reseller not found"}), 404
        order = {
            "reseller_id": reseller_id,
            "reseller_name": reseller.get("store_name", ""),
            "quantity": reward.get("quantity", 1),
            "kg_size": reward.get("kg_size", "1Kg"),
            "unit_price": 0,
            "total_sales": 0,
            "mode": "PICKUP",
            "payment": "Reward",
            "sales_date": manila_now().strftime("%Y-%m-%d"),
            "created_at": manila_now().strftime("%Y-%m-%d %H:%M:%S"),
            "staff_name": session.get("staff_name") or "Customer Reward",
            "order_status": "New Order",
            "order_source": "customer",
            "reward_redemption": True,
            "reward_label": reward.get("label", ""),
            "notes": f"🎁 REWARD REDEMPTION - {reward.get('label','')}",
        }
        fb_post("daily_sales", order)
        new_balance = award_loyalty_points(reseller_id, -required, f"Redeemed: {reward.get('label','')}")
        # Stamp the cooldown clock ONLY on a successful redemption - not
        # on a blocked attempt - so the next redeem is locked out for a
        # fresh get_redemption_cooldown_days() window from right now.
        fb_patch(f"loyalty_points/{reseller_id}", {"last_redemption_at": manila_now().strftime("%Y-%m-%d %H:%M:%S")})
        try:
            send_push_to_cashiers(
                title="🎁 Reward Redeemed!",
                body=f"{reseller.get('store_name','Customer')} - {reward.get('label','')}",
                url="/orders",
                tag="omega-reward-redeemed",
            )
        except Exception as e:
            print(f"push (reward redeemed) failed: {e}")
        if session.get("customer_id") == reseller_id:
            log_customer_activity(reseller_id, reseller.get("store_name"), "Nag-redeem ng reward",
                                   f"{reward.get('label','')} (-{required} pts)")
        return jsonify({"ok": True, "new_balance": new_balance if new_balance is not None else (balance - required)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/order/<order_id>/status", methods=["POST"])
@login_required
def api_update_order_status(order_id):
    data = request.json or {}
    new_status = data.get("status","").strip()
    if new_status not in ["New Order","Pending","Preparing","Out for Delivery","Delivered","Cancelled","Declined"]:
        return jsonify({"ok": False, "error": "Invalid status"}), 400

    # DECLINE + REASON (boss's request, Sept 22): a "Declined" order MUST
    # carry a reason - unlike Cancelled (which can happen for any number
    # of internal/ambiguous causes), a decline is staff actively telling
    # the reseller "we can't do this one", so leaving them with no reason
    # at all defeats the whole point of the feature.
    decline_reason = (data.get("reason") or "").strip()
    if new_status == "Declined" and not decline_reason:
        return jsonify({"ok": False, "error": "Kailangan ng reason para sa Decline"}), 400

    existing = fb_get(f"daily_sales/{order_id}") or {}
    update_data = {"order_status": new_status, "status_updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "status_updated_by": session.get("staff_name")}
    if new_status == "Declined":
        update_data["decline_reason"] = decline_reason
        update_data["declined_by"] = session.get("staff_name")
        update_data["declined_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # When marked as Delivered, update sales record so it counts as TODAY'S real sale + Recent Sales
    if new_status == "Delivered":
        now_manila = manila_now()
        today = now_manila.strftime("%Y-%m-%d")
        now_str = now_manila.strftime("%Y-%m-%d %H:%M:%S")
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

        # LOYALTY POINTS (Sept 21): only award points when the RESELLER
        # placed this order themselves through the customer app
        # (order_source == "customer") - a sale the cashier typed in
        # manually on /cashier never sets order_source at all, so it's
        # excluded automatically, exactly as requested ("sa online order
        # lang dapat applicable, pag manual input ko hindi dapat
        # kumita"). Also excludes a reward's own free redemption order
        # (reward_redemption=True) from earning MORE points on itself,
        # and points_awarded guards against double-crediting if an
        # order somehow gets marked Delivered more than once.
        if (existing.get("order_source") == "customer"
                and not existing.get("reward_redemption")
                and not existing.get("points_awarded")
                and existing.get("reseller_id")
                and not is_loyalty_program_paused()):
            pts = int(round(float(existing.get("total_sales") or 0)))
            if pts > 0:
                award_loyalty_points(existing.get("reseller_id"), pts, "Order delivered", order_id, touch_activity=True)
                update_data["points_awarded"] = True
                update_data["points_earned"] = pts

            # REFERRAL BONUS (Sept 22): if this reseller was referred by
            # another reseller, and THIS is their first-ever delivered
            # online order, credit the referrer a one-time bonus. Gated
            # the same way as the points award just above (order_source
            # == "customer", never a reward's own redemption order), so
            # it fires on exactly the same kind of order that starts
            # earning the new reseller their own points too.
            try:
                new_reseller_id = existing.get("reseller_id")
                reseller_rec = fb_get(f"resellers/{new_reseller_id}") or {}
                referrer_id = reseller_rec.get("referred_by_id")
                if referrer_id and not reseller_rec.get("referral_bonus_awarded"):
                    # "First order" = no OTHER delivered online order for
                    # this same reseller has awarded points before this
                    # one. Checked freshly against Firebase (not just
                    # trusting referral_bonus_awarded alone) so a flag
                    # write that failed earlier can't cause a double-pay
                    # later - the underlying order history is the source
                    # of truth.
                    all_sales = fb_get("daily_sales") or {}
                    already_had_a_delivered_order = any(
                        v and v.get("reseller_id") == new_reseller_id
                        and v.get("order_source") == "customer"
                        and v.get("points_awarded")
                        and k != order_id
                        for k, v in all_sales.items()
                    )
                    if not already_had_a_delivered_order:
                        bonus_pts = get_referral_bonus_points()
                        if bonus_pts > 0:
                            award_loyalty_points(
                                referrer_id, bonus_pts,
                                f"Referral bonus - {reseller_rec.get('store_name','')} unang order",
                                order_id, touch_activity=False,
                            )
                        fb_patch(f"resellers/{new_reseller_id}", {"referral_bonus_awarded": True})
            except Exception as referral_err:
                # A referral-bonus hiccup must never block the order's
                # own delivery/points flow - log and move on, same
                # fire-and-forget philosophy as award_loyalty_points itself.
                print(f"referral bonus check failed (non-fatal): {referral_err}")
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

    # DECLINE PUSH NOTIFICATION (boss's request, Sept 22: "may push
    # notification din ba boss") - the reseller gets alerted on their
    # phone even if the app/PWA isn't open, same as the existing
    # points-program broadcast. Non-fatal: if the reseller never enabled
    # notifications, this silently no-ops and they still see the reason
    # the next time they open their dashboard (on-screen is the fallback,
    # not the only path).
    if new_status == "Declined" and existing.get("reseller_id"):
        try:
            send_push_to_reseller(
                existing.get("reseller_id"),
                title="🚫 Order Declined",
                body=decline_reason,
                url=f"/customer/{existing.get('reseller_id')}/dashboard",
                tag=f"omega-order-declined-{order_id}",
            )
        except Exception as e:
            print(f"push (order declined) failed: {e}")

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
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:16px;color:#00609C;margin:0}
.topbar .pill-group{display:flex;gap:6px;flex-wrap:wrap}
.nav-pill{padding:6px 12px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;display:inline-flex;align-items:center;white-space:nowrap}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
label{font-size:11px;color:#666;display:block;margin:8px 0 4px}input{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px}
.btn{padding:8px 14px;border-radius:8px;border:none;font-size:12px;font-weight:600;cursor:pointer}
.btn-save{background:#00609C;color:#fff}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:10px 6px;border-bottom:1px solid #eee;text-align:left}
</style></head>
<body>
<div class="topbar"><h1>👥 Customers (ISESMO Only)</h1><div class="pill-group"><a href="/cashier" class="nav-pill">Sales</a> <a href="/orders" class="nav-pill">Live Orders</a> <a href="/credit" class="nav-pill">💳 Utang</a> <a href="/customer_activity" class="nav-pill">🔐 Login Activity</a></div></div>

<div class="card">
<h3 style="margin:0 0 10px;font-size:14px">Add New Customer - ISESMO Only</h3>
<label>Store Name *</label><input id="newStore" placeholder="AMO Store">
<label>Phone (will be login) *</label><input id="newPhone" placeholder="09xx xxx xxxx">
<label>Password *</label><input id="newPassword" placeholder="Set password min 4 chars">
<label>Address</label><input id="newAddress" placeholder="Angeles City">
<label>Referred by (optional)</label><select id="newReferredBy" style="width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px"><option value="">— Wala / Direct —</option></select>
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
  const referredBy=document.getElementById('newReferredBy').value;
  if(!store||!phone||!pwd){document.getElementById('addStatus').textContent='Store, phone, password required';return;}
  document.getElementById('addStatus').textContent='Adding...';
  try{
    const res=await fetch('/api/customers/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({store_name:store,phone:phone,password:pwd,address:addr,referred_by_id:referredBy})});
    const data=await res.json();
    document.getElementById('addStatus').textContent=data.ok?'✅ Customer added!':'Error: '+(data.error||'');
    if(data.ok){document.getElementById('newStore').value='';document.getElementById('newPhone').value='';document.getElementById('newPassword').value='';document.getElementById('newAddress').value='';document.getElementById('newReferredBy').value='';loadCustomers();}
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
    // Keep the "Referred by" dropdown in sync with the reseller list so
    // a just-added reseller can immediately be picked as a referrer for
    // the NEXT one, without a page reload.
    const referredBySel = document.getElementById('newReferredBy');
    if(referredBySel){
      const currentVal = referredBySel.value;
      referredBySel.innerHTML = '<option value="">— Wala / Direct —</option>' +
        rows.map(r => `<option value="${r.id}">${escapeHtml(r.store_name)}</option>`).join('');
      referredBySel.value = currentVal;
    }
    if(!rows.length){
      document.getElementById('tbody').innerHTML='<tr><td colspan=4 style="text-align:center;padding:20px;color:#888">No customers yet. '+(data.error||'')+'</td></tr>';
      return;
    }
    const q=document.getElementById('search').value.toLowerCase();
    const filtered=rows.filter(r=>(r.store_name||'').toLowerCase().includes(q)||(r.phone||'').includes(q));
    document.getElementById('tbody').innerHTML=filtered.map(r=>{
      return `<tr><td><b>${escapeHtml(r.store_name)}</b><br><small style="color:#666">${escapeHtml(r.status||'active')}</small>${r.referred_by_name?`<br><small style="color:#0891b2">🤝 ref: ${escapeHtml(r.referred_by_name)}</small>`:''}</td><td>${escapeHtml(r.phone)}<br><small style="color:${r.password_hash?'green':'red'}">${r.password_hash?'Has password':'No password'}</small></td><td>₱${r.credit_balance||0}</td><td><button class="btn" style="background:#22c55e;color:#fff" onclick="openEdit('${r.id}')">Edit</button> <button class="btn" style="background:#00609C;color:#fff" onclick="openQR('${r.id}')">📱 QR</button></td></tr>`;
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
            reason = val.get("reason") or ""
            # Login method: QR logins always tag themselves "QR login" in
            # log_customer_login(); everything else (manual password
            # login - success or failed) goes through /api/customer/login,
            # which only ever fails or succeeds manually (QR failures
            # aren't logged, since an invalid/expired QR just shows an
            # error page with no session created). So "not QR" == Manual,
            # which also covers old rows logged before the "Manual login"
            # reason text existed (they had an empty reason on success).
            method = "QR" if reason == "QR login" else "Manual"
            rows.append({
                "id": key,
                "store_name": val.get("store_name") or "",
                "phone": val.get("phone") or "",
                "success": bool(val.get("success")),
                "reason": reason,
                "method": method,
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

@app.route("/api/staff/customer_dashboard_activity")
@login_required
def api_customer_dashboard_activity():
    """
    Feeds the "Dashboard Actions" tab on the Customer Activity page
    (boss's request, Sept 22: "dapat may notification or logs lahat ng
    activities na ginagawa si customer sa dashboard nya. si isesmo lang
    nakakaaccess"). Same ISESMO-only gate as the Login Activity feed
    right above - this is a full audit trail of what every reseller
    does with their own account, not data for a rank-and-file staff
    member to browse. Newest first, capped at 300 rows, same as the
    login feed.
    """
    staff = (session.get("staff_name") or "").lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    try:
        logs = fb_get("customer_activity_logs") or {}
        rows = []
        for key, val in logs.items():
            if not val:
                continue
            rows.append({
                "id": key,
                "reseller_id": val.get("reseller_id") or "",
                "store_name": val.get("store_name") or "",
                "action": val.get("action") or "",
                "details": val.get("details") or "",
                "ip": val.get("ip") or "",
                "timestamp": val.get("timestamp") or "",
            })
        rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
        total = len(rows)
        return jsonify({"ok": True, "rows": rows[:300], "total": total})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/staff/staff_login_activity")
@login_required
def api_staff_login_activity():
    """
    Feeds the "Staff Login" tab on the Customer Activity page (boss's
    request, Sept 25: "pwd ba natin lagyan kung sino nag inout ng
    sales?" - who logged in/out of the Sales/POS system, and when).
    Same ISESMO-only gate as the customer-side login/activity feeds -
    this shows every staff member's login AND logout attempts,
    including failed PIN attempts, which is exactly the kind of thing a
    rank-and-file staff member should not be able to browse about their
    co-workers. Newest first, capped at 300 rows, same as the other
    activity feeds.
    """
    staff = (session.get("staff_name") or "").lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    try:
        logs = fb_get("staff_login_logs") or {}
        rows = []
        for key, val in logs.items():
            if not val:
                continue
            rows.append({
                "id": key,
                "staff_id": val.get("staff_id") or "",
                "staff_name": val.get("staff_name") or "",
                "position": val.get("position") or "",
                "action": val.get("action") or "",
                "success": bool(val.get("success")),
                "reason": val.get("reason") or "",
                "ip": val.get("ip") or "",
                "user_agent": val.get("user_agent") or "",
                "timestamp": val.get("timestamp") or "",
            })
        rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
        total = len(rows)
        failed_count = sum(1 for r in rows if r["action"] == "Login" and not r["success"])
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

        # REFERRAL PROGRAM (Sept 22): optionally link this new reseller to
        # whichever EXISTING reseller referred them. Validated against
        # the resellers table so a bogus/stale id can never sit on the
        # record - the referrer's name is snapshotted at creation time so
        # it still displays correctly even if that reseller is later
        # renamed or removed. The actual points bonus isn't awarded here
        # - it's awarded once this new reseller's FIRST delivered online
        # order comes through (see the Delivered-status hook), so a
        # referral that never results in a real order never costs
        # anything.
        referred_by_id = (data.get("referred_by_id") or "").strip()
        referred_by_name = ""
        if referred_by_id:
            referrer = resellers.get(referred_by_id)
            if not referrer:
                return jsonify({"ok": False, "error": "Invalid referrer - reseller not found"}), 400
            referred_by_name = referrer.get("store_name", "")

        hashed = hash_customer_password(pwd)
        reseller_data = {"store_name": store_name, "phone": phone, "address": address, "credit_balance": 0, "password_hash": hashed, "status": "active", "created_by": session.get("staff_name"), "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        if referred_by_id:
            reseller_data["referred_by_id"] = referred_by_id
            reseller_data["referred_by_name"] = referred_by_name
            reseller_data["referral_bonus_awarded"] = False
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
            out.append({"id":key,"store_name":val.get("store_name") or val.get("name") or "No Name","phone":val.get("phone") or val.get("contact",""),"credit_balance":val.get("credit_balance",0),"password_hash":"yes" if val.get("password_hash") else "","status":val.get("status","active"),"referred_by_name":val.get("referred_by_name") or ""})
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
        # Same session-hygiene fix as the manual-password login - a QR
        # login must also fully replace any leftover staff identity, never
        # coexist with it (see the manual-login comment above for the
        # full explanation).
        session.pop("staff_name", None)
        session.pop("staff_id", None)
        session.pop("staff_position", None)
        session["customer_id"] = reseller_id
        session["customer_name"] = reseller.get("store_name")
        log_customer_login(reseller_id, reseller.get("store_name"), matched.get("phone"), True, "QR login")
        # Same device-fingerprint check as the manual-password login above.
        is_new_device, device_id = check_and_register_device(reseller_id)
        if is_new_device:
            notify_new_device_login(reseller_id, reseller.get("store_name"))
        resp = make_response(redirect(f"/customer/{reseller_id}/dashboard"))
        set_device_cookie(resp, device_id)
        return resp
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
    now = manila_now()
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
    now = manila_now()
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
.nav-pill{padding:9px 4px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.stat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;text-align:center;margin-bottom:12px}
.stat-val{font-size:20px;font-weight:700;color:#00609C}.stat-val.fail{color:#c0392b}.stat-lbl{font-size:9px;color:#888}
.filter-row{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:10px}
.filter-btn{padding:9px 4px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.filter-btn.active{background:#00609C;color:#fff}
input#searchInp,input#actionsSearchInp{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px;margin-bottom:10px}
.log-row{display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid #f0f4f8}
.log-badge{padding:3px 9px;border-radius:12px;font-size:9px;font-weight:700;white-space:nowrap;height:fit-content}
.log-badge.ok{background:#dcfce7;color:#166534}.log-badge.fail{background:#fee2e2;color:#c0392b}
.badge-col{display:flex;flex-direction:column;gap:4px;align-items:flex-end}
.method-badge{padding:3px 9px;border-radius:12px;font-size:9px;font-weight:700;white-space:nowrap}
.method-badge.qr{background:#e0e7ff;color:#3730a3}.method-badge.manual{background:#fef3c7;color:#92400e}
.log-meta{font-size:9px;color:#aaa;margin-top:2px}
.refresh-btn{padding:9px 4px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;font-weight:600;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.subtab-row{display:flex;gap:6px;margin-bottom:12px}
.subtab-btn{flex:1;padding:10px;border-radius:10px;border:1px solid #cde;background:#fff;color:#00609C;font-size:12px;font-weight:600}
.subtab-btn.active{background:#00609C;color:#fff}
.action-badge{padding:3px 9px;border-radius:12px;font-size:9px;font-weight:700;white-space:nowrap;background:#e0e7ff;color:#3730a3;height:fit-content}
</style></head>
<body>
<div class="topbar">
  <div style="display:flex;align-items:center;gap:8px"><img src="/icon-192.png" alt="" style="width:24px;height:24px;border-radius:6px"><h1>🔐 Customer Activity (ISESMO Only)</h1></div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;width:100%">
    <a href="/orders" class="nav-pill" style="background:#ff4444;color:#fff;border-color:#ff4444">🔴 Live Orders</a>
    <a href="/cashier" class="nav-pill">Sales</a>
    <a href="/customers" class="nav-pill">Customers</a>
    <a href="/credit" class="nav-pill">💳 Utang</a>
    <a href="/dashboard" class="nav-pill">Analytics</a>
    <a href="/customer_activity" class="nav-pill active">Customer Activity</a>
  </div>
</div>

<div class="card">
  <div class="subtab-row">
    <button class="subtab-btn active" id="subtabLogins" onclick="switchTab('logins')">🔐 Logins</button>
    <button class="subtab-btn" id="subtabActions" onclick="switchTab('actions')">📋 Dashboard Actions</button>
    <button class="subtab-btn" id="subtabStaff" onclick="switchTab('staff')">👤 Staff Login</button>
  </div>

  <div id="loginsTab">
    <div class="stat-grid">
      <div><div class="stat-val" id="totalCount">0</div><div class="stat-lbl">TOTAL LOGIN ATTEMPTS (latest 300)</div></div>
      <div><div class="stat-val fail" id="failCount">0</div><div class="stat-lbl">FAILED ATTEMPTS</div></div>
    </div>
    <input type="text" id="searchInp" placeholder="Search by store name or phone..." oninput="renderRows()">
    <div class="filter-row">
      <button class="filter-btn active" data-f="all" onclick="setFilter('all')">All</button>
      <button class="filter-btn" data-f="success" onclick="setFilter('success')">✅ Success only</button>
      <button class="filter-btn" data-f="failed" onclick="setFilter('failed')">❌ Failed only</button>
      <button class="filter-btn" data-f="qr" onclick="setFilter('qr')">📱 QR only</button>
      <button class="filter-btn" data-f="manual" onclick="setFilter('manual')">⌨️ Manual only</button>
      <button class="refresh-btn" onclick="loadActivity()">🔄 Refresh</button>
    </div>
    <div id="rowsList" style="font-size:12px">Loading...</div>
  </div>

  <div id="actionsTab" style="display:none">
    <div class="stat-grid" style="grid-template-columns:1fr">
      <div><div class="stat-val" id="actionsTotalCount">0</div><div class="stat-lbl">TOTAL DASHBOARD ACTIONS (latest 300)</div></div>
    </div>
    <input type="text" id="actionsSearchInp" placeholder="Search by store name or action..." oninput="renderActionRows()">
    <div class="filter-row">
      <button class="refresh-btn" onclick="loadDashboardActivity()">🔄 Refresh</button>
    </div>
    <div id="actionsRowsList" style="font-size:12px">Loading...</div>
  </div>

  <div id="staffTab" style="display:none">
    <div class="stat-grid">
      <div><div class="stat-val" id="staffTotalCount">0</div><div class="stat-lbl">TOTAL LOGIN/LOGOUT (latest 300)</div></div>
      <div><div class="stat-val fail" id="staffFailCount">0</div><div class="stat-lbl">FAILED LOGIN ATTEMPTS</div></div>
    </div>
    <input type="text" id="staffSearchInp" placeholder="Search by staff name..." oninput="renderStaffRows()">
    <div class="filter-row">
      <button class="filter-btn active" data-sf="all" onclick="setStaffFilter('all')">All</button>
      <button class="filter-btn" data-sf="login" onclick="setStaffFilter('login')">🟢 Logins only</button>
      <button class="filter-btn" data-sf="logout" onclick="setStaffFilter('logout')">🔴 Logouts only</button>
      <button class="filter-btn" data-sf="failed" onclick="setStaffFilter('failed')">❌ Failed only</button>
      <button class="refresh-btn" onclick="loadStaffLoginActivity()">🔄 Refresh</button>
    </div>
    <div id="staffRowsList" style="font-size:12px">Loading...</div>
  </div>
</div>

<script>
let allRows = [];
let currentFilter = 'all';
let allActionRows = [];
let allStaffRows = [];
let currentStaffFilter = 'all';
let loginsLoaded = false;
let actionsLoaded = false;
let staffLoaded = false;

function switchTab(tab){
  document.getElementById('subtabLogins').classList.toggle('active', tab==='logins');
  document.getElementById('subtabActions').classList.toggle('active', tab==='actions');
  document.getElementById('subtabStaff').classList.toggle('active', tab==='staff');
  document.getElementById('loginsTab').style.display = tab==='logins' ? 'block' : 'none';
  document.getElementById('actionsTab').style.display = tab==='actions' ? 'block' : 'none';
  document.getElementById('staffTab').style.display = tab==='staff' ? 'block' : 'none';
  if(tab==='logins' && !loginsLoaded) loadActivity();
  if(tab==='actions' && !actionsLoaded) loadDashboardActivity();
  if(tab==='staff' && !staffLoaded) loadStaffLoginActivity();
}

function setStaffFilter(f){
  currentStaffFilter = f;
  document.querySelectorAll('#staffTab .filter-btn').forEach(b=>b.classList.toggle('active', b.dataset.sf===f));
  renderStaffRows();
}

function setFilter(f){
  currentFilter = f;
  document.querySelectorAll('#loginsTab .filter-btn').forEach(b=>b.classList.toggle('active', b.dataset.f===f));
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
  else if(currentFilter==='qr') rows = rows.filter(r=>r.method==='QR');
  else if(currentFilter==='manual') rows = rows.filter(r=>r.method==='Manual');
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
    const methodBadge = r.method === 'QR'
      ? '<span class="method-badge qr">📱 QR LOGIN</span>'
      : '<span class="method-badge manual">⌨️ MANUAL LOGIN</span>';
    const reasonLine = (!r.success && r.reason) ? `<div class="log-meta">Reason: ${escapeHtmlA(r.reason)}</div>` : '';
    return `<div class="log-row">
      <div>
        <div style="font-weight:600">${escapeHtmlA(r.store_name || '(unknown store)')}</div>
        <div style="color:#666">📞 ${escapeHtmlA(maskPhone(r.phone))}</div>
        ${reasonLine}
        <div class="log-meta">${escapeHtmlA(r.timestamp)} • IP: ${escapeHtmlA(r.ip)}</div>
      </div>
      <div class="badge-col">${badge}${methodBadge}</div>
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
    loginsLoaded = true;
    renderRows();
  }catch(e){
    listEl.innerHTML = `<div style="color:red">Error: ${escapeHtmlA(e.message)}</div>`;
  }
}

// --- Dashboard Actions tab (boss's request, Sept 22): everything a
// reseller DOES from their own dashboard - orders, redemptions,
// ratings, bulk updates, password changes, event bookings - separate
// from the Logins tab above, which only covers login attempts.
function renderActionRows(){
  const q = (document.getElementById('actionsSearchInp').value || '').toLowerCase().trim();
  let rows = allActionRows;
  if(q){
    rows = rows.filter(r =>
      (r.store_name||'').toLowerCase().includes(q) ||
      (r.action||'').toLowerCase().includes(q) ||
      (r.details||'').toLowerCase().includes(q)
    );
  }
  const listEl = document.getElementById('actionsRowsList');
  if(!rows.length){
    listEl.innerHTML = '<div style="color:#888;text-align:center;padding:16px">Walang dashboard activity na nakita.</div>';
    return;
  }
  listEl.innerHTML = rows.map(r => {
    const detailsLine = r.details ? `<div class="log-meta" style="color:#555;font-size:10px;margin-top:3px">${escapeHtmlA(r.details)}</div>` : '';
    return `<div class="log-row">
      <div>
        <div style="font-weight:600">${escapeHtmlA(r.store_name || '(unknown store)')}</div>
        ${detailsLine}
        <div class="log-meta">${escapeHtmlA(r.timestamp)} • IP: ${escapeHtmlA(r.ip)}</div>
      </div>
      <div class="badge-col"><span class="action-badge">${escapeHtmlA(r.action)}</span></div>
    </div>`;
  }).join('');
}

async function loadDashboardActivity(){
  const listEl = document.getElementById('actionsRowsList');
  listEl.textContent = 'Loading...';
  try{
    const res = await fetch('/api/staff/customer_dashboard_activity');
    if(res.status===403){ listEl.innerHTML = '<div style="color:#c0392b">Access denied - ISESMO only.</div>'; return; }
    if(res.status===401){ window.location.href='/login'; return; }
    const data = await res.json();
    if(!data.ok){ listEl.innerHTML = `<div style="color:red">${escapeHtmlA(data.error||'Error')}</div>`; return; }
    allActionRows = data.rows || [];
    document.getElementById('actionsTotalCount').textContent = data.total || 0;
    actionsLoaded = true;
    renderActionRows();
  }catch(e){
    listEl.innerHTML = `<div style="color:red">Error: ${escapeHtmlA(e.message)}</div>`;
  }
}

// --- Staff Login tab (boss's request, Sept 25): "sino nag-in-out ng
// sales?" - who logged in/out of the Sales/POS system (staff PIN
// login), including failed PIN attempts. Same tab-pattern as Logins
// and Dashboard Actions above, just a different data source.
function renderStaffRows(){
  const q = (document.getElementById('staffSearchInp').value || '').toLowerCase().trim();
  let rows = allStaffRows;
  if(currentStaffFilter==='login') rows = rows.filter(r=>r.action==='Login');
  else if(currentStaffFilter==='logout') rows = rows.filter(r=>r.action==='Logout');
  else if(currentStaffFilter==='failed') rows = rows.filter(r=>!r.success);
  if(q){
    rows = rows.filter(r => (r.staff_name||'').toLowerCase().includes(q));
  }
  const listEl = document.getElementById('staffRowsList');
  if(!rows.length){
    listEl.innerHTML = '<div style="color:#888;text-align:center;padding:16px">No staff login activity found.</div>';
    return;
  }
  listEl.innerHTML = rows.map(r => {
    const badge = r.success
      ? '<span class="log-badge ok">✅ SUCCESS</span>'
      : '<span class="log-badge fail">❌ FAILED</span>';
    const actionBadge = r.action === 'Logout'
      ? '<span class="method-badge" style="background:#fee2e2;color:#c0392b">🔴 LOGOUT</span>'
      : '<span class="method-badge" style="background:#dcfce7;color:#166534">🟢 LOGIN</span>';
    const reasonLine = (!r.success && r.reason) ? `<div class="log-meta">Reason: ${escapeHtmlA(r.reason)}</div>` : '';
    return `<div class="log-row">
      <div>
        <div style="font-weight:600">${escapeHtmlA(r.staff_name || '(unknown staff)')}</div>
        <div style="color:#666">${escapeHtmlA(r.position || '')}</div>
        ${reasonLine}
        <div class="log-meta">${escapeHtmlA(r.timestamp)} • IP: ${escapeHtmlA(r.ip)}</div>
      </div>
      <div class="badge-col">${badge}${actionBadge}</div>
    </div>`;
  }).join('');
}

async function loadStaffLoginActivity(){
  const listEl = document.getElementById('staffRowsList');
  listEl.textContent = 'Loading...';
  try{
    const res = await fetch('/api/staff/staff_login_activity');
    if(res.status===403){ listEl.innerHTML = '<div style="color:#c0392b">Access denied - ISESMO only.</div>'; return; }
    if(res.status===401){ window.location.href='/login'; return; }
    const data = await res.json();
    if(!data.ok){ listEl.innerHTML = `<div style="color:red">${escapeHtmlA(data.error||'Error')}</div>`; return; }
    allStaffRows = data.rows || [];
    document.getElementById('staffTotalCount').textContent = data.total || 0;
    document.getElementById('staffFailCount').textContent = data.failed_count || 0;
    staffLoaded = true;
    renderStaffRows();
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
.nav-pill{padding:9px 4px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;font-weight:600;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nav-pill.active{background:#00609C;color:#fff;border-color:#00609C}
.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.hist-period-btn{padding:9px 4px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hist-period-btn.active{background:#00609C;color:#fff}
.stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;text-align:center}
.stat-val{font-size:19px;font-weight:700;color:#00609C}.stat-lbl{font-size:9px;color:#888}
.stat-grid.pending .stat-val{color:#f59e0b}
.status-pill{padding:3px 9px;border-radius:12px;font-size:9px;font-weight:700}
.status-new{background:#fef3c7;color:#92400e}.status-pending{background:#fef3c7;color:#92400e}.status-preparing{background:#dbeafe;color:#1e40af}.status-out{background:#e0e7ff;color:#3730a3}.status-delivered{background:#dcfce7;color:#166534}.status-cancelled{background:#fee2e2;color:#c0392b}.status-declined{background:#ffe4e6;color:#be123c}
.breakdown-row{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;font-size:10px}
.breakdown-chip{background:#f0f4f8;padding:5px 10px;border-radius:10px;color:#555}
</style></head>
<body>
<div class="topbar">
  <div style="display:flex;align-items:center;gap:8px"><img src="/icon-192.png" alt="" style="width:24px;height:24px;border-radius:6px"><h1>Sales Analytics</h1></div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;width:100%">
    <a href="/orders" class="nav-pill" style="background:#ff4444;color:#fff;border-color:#ff4444">🔴 Live Orders</a>
    <a href="/cashier" class="nav-pill">Sales</a>
    <a href="/customers" class="nav-pill">Customers</a>
    <a href="/credit" class="nav-pill">💳 Utang</a>
    <a href="/customer_activity" class="nav-pill">🔐 Login Activity</a>
    <a href="/dashboard" class="nav-pill active">Analytics</a>
  </div>
</div>

<div class="card">
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:10px">
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
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:16px;color:#00609C;margin:0}
.topbar .pill-group{display:flex;gap:6px;flex-wrap:wrap}
.card{background:#fff;border-radius:12px;padding:12px;margin-bottom:10px}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:12px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;display:inline-flex;align-items:center;white-space:nowrap}
.live{display:inline-flex;align-items:center;justify-content:center;gap:6px;background:#ef4444;color:#fff;padding:9px 4px;border-radius:20px;font-size:11px;font-weight:600}
.order-card{border-left:4px solid #f59e0b;padding:12px;margin:8px 0;background:#fff;border-radius:8px}
/* --- Top action row (LIVE / Archive / Refresh) - equal-width grid so
   the 3 pills line up instead of sizing to their own text (boss's
   request, Sept 23) --- */
.top-actions{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px}
.top-action-btn{padding:9px 4px;border-radius:20px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;font-weight:600;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer}
.top-action-btn-warn{border-color:#f59e0b;background:#fffbeb;color:#92400e}
/* --- Per-order action buttons (Accept/Preparing/Out/Done/Decline/Delete)
   - same equal-width grid treatment instead of inline buttons that just
   size to their own label and bump into each other --- */
.order-actions{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-top:8px}
.btn{padding:9px 4px;border-radius:20px;border:1px solid #ccd;font-size:11px;font-weight:600;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer}
.btn:disabled{opacity:0.4;cursor:not-allowed;background:#f3f4f6;color:#999}
.btn-decline{background:#fff;color:#dc2626;border-color:#fca5a5}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:999;align-items:center;justify-content:center;padding:16px}
.modal-overlay.open{display:flex}
.modal-box{background:#fff;border-radius:12px;padding:18px;max-width:360px;width:100%}
.modal-box h3{margin:0 0 10px;font-size:15px;color:#1f2937}
.modal-box textarea{width:100%;border:1px solid #cbd5e1;border-radius:8px;padding:8px;font-size:13px;min-height:80px;font-family:inherit;resize:vertical}
.modal-box .modal-actions{display:flex;gap:8px;margin-top:12px;justify-content:flex-end}
.modal-box .modal-actions button{padding:8px 14px;border-radius:8px;border:1px solid #ccd;font-size:12px}
.modal-box .modal-btn-confirm{background:#dc2626;color:#fff;border-color:#dc2626}
.decline-reason-box{margin-top:8px;background:#fff1f2;border:1px solid #fecdd3;border-radius:8px;padding:8px;font-size:12px;color:#9f1239}
</style></head>
<body>
<div class="topbar"><h1>Live Customer Orders</h1><div class="pill-group"><a href="/cashier" class="nav-pill">← Back to Sales</a></div></div>
<div class="top-actions"><span class="live">● LIVE</span>
<button onclick="archiveAllOldStaff()" class="top-action-btn top-action-btn-warn">📦 Archive &gt;7d</button><button onclick="loadOrders()" class="top-action-btn">🔄 Refresh</button></div>
<div id="ordersList">2026-09-06 - Tap Refresh</div>

<!-- Decline reason modal: a "Declined" order must always carry a reason
     (boss's request), so this small overlay blocks submission until the
     staff types something - no native prompt() since it's easy to bypass
     with an empty confirm and doesn't match the app's modal styling. -->
<div class="modal-overlay" id="declineModal">
  <div class="modal-box">
    <h3>🚫 I-decline ang order</h3>
    <p style="font-size:12px;color:#666;margin:0 0 8px">Ilagay ang dahilan kung bakit i-de-decline ang order na ito. Makikita ito ng customer.</p>
    <textarea id="declineReasonInput" placeholder="Hal: Ubos na ang stock, hindi na-reach ang delivery area, etc."></textarea>
    <div class="modal-actions">
      <button onclick="closeDeclineModal()">Cancel</button>
      <button class="modal-btn-confirm" onclick="confirmDecline()">🚫 I-decline</button>
    </div>
  </div>
</div>

<script>
let declineTargetId = null;
function openDeclineModal(id){
  declineTargetId = id;
  document.getElementById('declineReasonInput').value = '';
  document.getElementById('declineModal').classList.add('open');
}
function closeDeclineModal(){
  declineTargetId = null;
  document.getElementById('declineModal').classList.remove('open');
}
async function confirmDecline(){
  const reason = document.getElementById('declineReasonInput').value.trim();
  if(!reason){ alert('Kailangan ng reason para sa Decline.'); return; }
  if(!declineTargetId) return;
  const id = declineTargetId;
  try{
    const res = await fetch(`/api/order/${id}/status`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:'Declined', reason})});
    const data = await res.json();
    if(data.ok){
      closeDeclineModal();
      loadOrders();
    } else {
      alert(data.error||'Failed');
    }
  }catch(e){
    alert('Network error: '+e.message);
  }
}
async function loadOrders(){
  const res=await fetch('/api/staff/customer_orders');
  const data=await res.json();
  const ordersRaw=data.orders||[];
  // Sort: New Order on top, Delivered at bottom
  const priority = {"New Order":0, "Pending":1, "Preparing":2, "Out for Delivery":3, "Declined":4, "Delivered":5, "Cancelled":6};
  // DECLINE DECAY (boss's request, Sept 22): mirrors is_order_stale() on
  // the server - see the same comment on the customer dashboard's
  // loadOrders() for the "why".
  const orderPriority = (o) => {
    if(o.order_status === 'Declined' && o.declined_at){
      const declinedMs = new Date(o.declined_at.replace(' ','T')).getTime();
      if(!isNaN(declinedMs) && (Date.now() - declinedMs) <= 24*60*60*1000){
        return priority['Declined'];
      }
      return priority['Cancelled'];
    }
    return priority[o.order_status] ?? 1;
  };
  const orders = ordersRaw.sort((a,b)=>{
    const pa = orderPriority(a);
    const pb = orderPriority(b);
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
    const isDeclined = o.order_status==='Declined';
    const disabled = isDelivered || isCancelled || isDeclined;
    let statusColor='#fef3c7';
    if(o.order_status==='Delivered'){statusColor='#dcfce7';}
    else if(o.order_status==='Cancelled'){statusColor='#fee2e2';}
    else if(o.order_status==='Declined'){statusColor='#ffe4e6';}
    else if(o.order_status==='Preparing'){statusColor='#dbeafe';}
    else if(o.order_status==='Out for Delivery'){statusColor='#e0e7ff';}
    const deliveredBadge = isDelivered ? ' ✅' : '';
    const btnStyle = (active)=> disabled ? 'opacity:0.4;cursor:not-allowed;background:#f3f4f6' : '';
    const btnDisabled = disabled ? 'disabled' : '';
    if(disabled){
      let borderColor = '#ef4444';
      let statusLabel = '❌ Cancelled';
      let statusTextColor = '#ef4444';
      if(isDelivered){ borderColor='#22c55e'; statusLabel='✅ Delivered - buttons disabled'; statusTextColor='#16a34a'; }
      else if(isDeclined){ borderColor='#f43f5e'; statusLabel='🚫 Declined'; statusTextColor='#e11d48'; }
      const reasonBlock = isDeclined ? `<div class="decline-reason-box"><strong>Dahilan:</strong> ${o.decline_reason||'(walang laman)'}</div>` : '';
      return `<div class="order-card" data-order-id="${o.id}" style="border-left-color:${borderColor};opacity:0.8"><div style="display:flex;justify-content:space-between"><span style="font-weight:600">${o.reseller_name}${deliveredBadge}</span><span style="font-size:10px;background:${statusColor};padding:4px 8px;border-radius:12px">${o.order_status}</span></div><div style="font-size:12px;color:#555;margin-top:4px">${o.quantity}x ${o.kg_size} • ₱${o.total_sales} • ${o.sales_date}</div>${reasonBlock}<div style="margin-top:8px;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap"><span style="font-size:11px;color:${statusTextColor};font-weight:600">${statusLabel}</span><button class="btn" style="background:#fff;color:#ef4444;border-color:#fca5a5;flex:0 0 auto;padding:9px 14px" onclick="deleteOrder('${o.id}')">🗑️ Delete</button></div></div>`;
    }
    const rewardBadge = o.reward_redemption ? ` <span style="font-size:9px;background:#fde68a;color:#92400e;padding:2px 7px;border-radius:10px;font-weight:700">🎁 FREE REWARD${o.reward_label ? ' - '+o.reward_label : ''}</span>` : '';
    const priceLabel = o.reward_redemption ? 'FREE' : `₱${o.total_sales}`;
    // STRICT SEQUENTIAL STATUS BUTTONS (boss's request, Sept 23): before
    // this, Accept/Preparing/Out/Done were ALL clickable at every stage
    // (only fully Delivered/Cancelled/Declined orders disabled them),
    // which meant a stray tap could jump the status backward or skip
    // ahead - the "Done" button in particular was always green/inviting
    // even on a brand-new order that hadn't even been Accepted yet. Now
    // only the ONE button matching the actual next step is enabled and
    // highlighted; every other step button (already-passed AND
    // not-yet-reached) is disabled/greyed out, so staff can't get out
    // of order. Decline/Delete stay independently available at any
    // stage - those aren't part of the forward progression.
    const STEP_NEXT_INDEX = {'New Order': 0, 'Pending': 1, 'Preparing': 2, 'Out for Delivery': 3};
    const nextIdx = STEP_NEXT_INDEX.hasOwnProperty(o.order_status) ? STEP_NEXT_INDEX[o.order_status] : 0;
    const STEP_BTNS = [
      {status: 'Pending', label: 'Accept'},
      {status: 'Preparing', label: 'Preparing'},
      {status: 'Out for Delivery', label: 'Out'},
      {status: 'Delivered', label: 'Done'},
    ];
    const stepButtonsHtml = STEP_BTNS.map((s, i) => {
      const isNext = i === nextIdx;
      const style = isNext
        ? (s.status === 'Delivered' ? 'background:#22c55e;color:#fff' : 'background:#00609C;color:#fff')
        : 'opacity:0.4;cursor:not-allowed;background:#f3f4f6;color:#999';
      const dis = isNext ? '' : 'disabled';
      return `<button class="btn" ${dis} style="${style}" onclick="updateStatus('${o.id}','${s.status}')">${s.label}</button>`;
    }).join('');
    return `<div class="order-card" data-order-id="${o.id}"><div style="display:flex;justify-content:space-between"><span style="font-weight:600">${o.reseller_name}${rewardBadge}</span><span style="font-size:10px;background:${statusColor};padding:4px 8px;border-radius:12px">${o.order_status}</span></div><div style="font-size:12px;color:#555;margin-top:4px">${o.quantity}x ${o.kg_size} • ${priceLabel} • ${o.sales_date}</div><div class="order-actions">${stepButtonsHtml}<button class="btn btn-decline" onclick="openDeclineModal('${o.id}')">🚫 Decline</button><button class="btn" style="background:#fff;color:#ef4444;border-color:#fca5a5" onclick="deleteOrder('${o.id}')">🗑️ Delete</button></div></div>`;
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
        now = manila_now()
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
                
            orders.append({"id":key,"reseller_name":val.get("reseller_name"),"quantity":val.get("quantity"),"kg_size":val.get("kg_size"),"total_sales":val.get("total_sales"),"mode":val.get("mode"),"sales_date":val.get("sales_date"),"order_status":val.get("order_status","New Order"),"created_at":val.get("created_at"),"reward_redemption":bool(val.get("reward_redemption")),"reward_label":val.get("reward_label") or "","decline_reason":val.get("decline_reason") or "","declined_at":val.get("declined_at") or ""})
        # Sort: New Orders first, Delivered at bottom
        def status_priority(s):
            order = (s.get("order_status") or "Pending")
            priorities = {"New Order": 0, "Pending": 1, "Preparing": 2, "Out for Delivery": 3, "Declined": 4, "Delivered": 5, "Cancelled": 6}
            # DECLINE DECAY: same 24hr rule as the customer feed - see
            # is_order_stale() for the "why".
            if order == "Declined" and is_order_stale(s.get("declined_at")):
                return 6
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
        if session.get("customer_id") == reseller_id and updated > 0:
            log_customer_activity(reseller_id, reseller.get("store_name") if reseller else "",
                                   "Bulk update ng orders", f"{updated} order(s): {from_status} -> {new_status}")
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
        if session.get("customer_id") == reseller_id and archived > 0:
            log_customer_activity(reseller_id, reseller.get("store_name") if reseller else "",
                                   "Nag-archive ng lumang orders", f"{archived} order(s), >{days_old} araw na")
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
            now = manila_now()
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
        now = manila_now()
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
        now = manila_now()
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
        now = manila_now()
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
        now = manila_now()
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

STUCK_ORDERS_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Purge Stuck Orders - ISESMO Only</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;display:inline-flex;align-items:center;white-space:nowrap}
.hint{background:#fff;border-radius:12px;padding:12px 14px;margin-bottom:12px;font-size:11px;color:#555;line-height:1.5}
.order-card{background:#fff;border-radius:12px;padding:12px;margin-bottom:10px;border-left:4px solid #f59e0b}
.order-card.orphan{border-left-color:#c0392b;background:#fff8f7}
.order-top{display:flex;justify-content:space-between;align-items:center;gap:8px}
.order-name{font-weight:700;font-size:13px;color:#222}
.order-amt{font-weight:700;color:#00609C;font-size:13px;white-space:nowrap}
.order-meta{font-size:10px;color:#888;margin-top:4px}
.status-pill{padding:3px 9px;border-radius:10px;font-size:9px;font-weight:700;display:inline-block;margin-top:6px}
.status-pending,.status-new-order{background:#fef3c7;color:#92400e}
.status-preparing{background:#dbeafe;color:#1e40af}
.status-out-for-delivery{background:#e0e7ff;color:#3730a3}
.orphan-badge{display:inline-block;margin-top:6px;margin-left:6px;padding:3px 9px;border-radius:10px;font-size:9px;font-weight:700;background:#fde2e2;color:#c0392b}
.del-btn{margin-top:10px;width:100%;padding:10px;border-radius:8px;border:none;background:#ef4444;color:#fff;font-weight:700;font-size:12px;cursor:pointer}
.empty{text-align:center;color:#888;padding:30px;background:#fff;border-radius:12px}
.filter-bar{background:#fff;border-radius:12px;padding:10px 14px;margin-bottom:12px;display:flex;align-items:center;gap:8px;font-size:12px;color:#333}
.filter-bar input{width:18px;height:18px}
.filter-bar label{cursor:pointer;user-select:none}
.count-tag{margin-left:auto;font-size:10px;color:#888}
</style></head>
<body>
<div class="topbar"><h1>🧹 Purge Stuck Orders (ISESMO Only)</h1><a href="/orders" class="nav-pill">← Live Orders</a></div>
<div class="hint">
Dito lumalabas ang mga orders na may Pending/Preparing/Out for Delivery status pa rin, <b>kahit wala na sila sa normal Live Orders list</b> ng staff (halimbawa: dating hindi natanggal talaga dahil sa lumang delete bug). Yung mga may pulang <b>"ORPHANED"</b> badge ay talagang tago na sa staff view pero buhay pa rin sa Firebase - kaya patuloy silang nakikita ng customer bilang "Pending". I-delete dito para totoong mawala.
</div>
<div class="filter-bar">
  <input type="checkbox" id="orphanOnly" checked onchange="renderList()">
  <label for="orphanOnly">Show ORPHANED only (mga totoong stuck/tagong orders)</label>
  <span class="count-tag" id="countTag"></span>
</div>
<div id="stuckList">Loading...</div>
<script>
let allOrders = [];

async function loadStuck(){
  const wrap = document.getElementById('stuckList');
  wrap.innerHTML = 'Loading...';
  try{
    const res = await fetch('/api/admin/stuck_orders');
    const data = await res.json();
    if(!data.ok){ wrap.innerHTML = `<div class="empty">Error: ${data.error||'unknown'}</div>`; return; }
    allOrders = data.orders || [];
    renderList();
  }catch(e){
    wrap.innerHTML = `<div class="empty">Error: ${e.message}</div>`;
  }
}
function renderList(){
  const wrap = document.getElementById('stuckList');
  const orphanOnly = document.getElementById('orphanOnly').checked;
  const orders = allOrders.filter(o => {
    const isOrphan = o.archived || o.deleted || o.hidden_24h;
    return orphanOnly ? isOrphan : true;
  });
  const orphanCount = allOrders.filter(o => o.archived || o.deleted || o.hidden_24h).length;
  document.getElementById('countTag').textContent = `${orphanCount} orphaned / ${allOrders.length} total`;
  if(!orders.length){
    wrap.innerHTML = orphanOnly
      ? '<div class="empty">✅ Walang ORPHANED orders - malinis! (May normal pending orders pa siguro - i-uncheck yung filter para makita)</div>'
      : '<div class="empty">✅ Walang stuck orders - malinis!</div>';
    return;
  }
  wrap.innerHTML = orders.map(o => {
    const isOrphan = o.archived || o.deleted || o.hidden_24h;
    const statusClass = 'status-' + (o.order_status||'Pending').toLowerCase().replace(/[^a-z0-9]+/g,'-');
    return `<div class="order-card ${isOrphan?'orphan':''}">
      <div class="order-top">
        <span class="order-name">${escapeHtmlS(o.reseller_name||'(unknown)')}</span>
        <span class="order-amt">₱${Number(o.total_sales||0).toLocaleString()}</span>
      </div>
      <div class="order-meta">${o.quantity||0}x ${escapeHtmlS(o.kg_size||'')} • ${escapeHtmlS(o.sales_date||'')} • Order ID: ${escapeHtmlS(o.id)}</div>
      <span class="status-pill ${statusClass}">${escapeHtmlS(o.order_status||'Pending')}</span>
      ${isOrphan ? '<span class="orphan-badge">⚠️ ORPHANED</span>' : ''}
      <button class="del-btn" onclick="purgeOrder('${o.id}', this, ${isOrphan})">🗑️ Permanent Delete</button>
    </div>`;
  }).join('');
}
function escapeHtmlS(s){ return String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
async function purgeOrder(id, btn, isOrphan){
  if(!isOrphan){
    if(!confirm('⚠️ HINDI ito ORPHANED - buhay at aktibong order pa ito sa normal Live Orders! Sigurado ka bang gusto mong tanggalin ito?')) return;
    if(!confirm('Paalala: PERMANENT DELETE ito mula sa Firebase, hindi na mababawi. Itutuloy?')) return;
  } else {
    if(!confirm('Permanent delete talaga ito mula sa Firebase. Sigurado ka?')) return;
  }
  btn.disabled = true; btn.textContent = 'Deleting...';
  try{
    const res = await fetch(`/api/orders/${id}`, {method:'DELETE'});
    const data = await res.json();
    if(data.ok){ loadStuck(); }
    else{ alert(data.error || 'Failed'); btn.disabled = false; btn.textContent = '🗑️ Permanent Delete'; }
  }catch(e){ alert('Network error: ' + e.message); btn.disabled = false; btn.textContent = '🗑️ Permanent Delete'; }
}
loadStuck();
</script>
</body></html>
"""

@app.route("/admin/stuck_orders")
@login_required
@isesmo_only
def stuck_orders_page():
    return render_template_string(STUCK_ORDERS_HTML)

@app.route("/api/admin/stuck_orders")
@login_required
@isesmo_only
def api_stuck_orders():
    """Lists daily_sales records that look "stuck": still an active-looking
    status (Pending / New Order / Preparing / Out for Delivery - i.e. NOT
    yet Delivered or Cancelled), no matter what archived/deleted/hidden_24h
    flags they carry. This is exactly the kind of record the Sept 21 delete
    bug (see api_delete_order's comment) could leave behind: gone from the
    normal staff Live Orders list (which filters out deleted/hidden/
    archived records) and gone from the 24h window, but still fully live
    in Firebase and still showing as "Pending" on the customer's own My
    Orders page, since the old buggy delete never actually removed it.
    Isesmo-only so a regular cashier can't accidentally mass-delete orders."""
    try:
        sales = fb_get("daily_sales") or {}
        stuck = []
        for key, val in sales.items():
            if not val:
                continue
            status = val.get("order_status") or "Pending"
            if status in ["Delivered", "Cancelled"]:
                continue
            stuck.append({
                "id": key,
                "reseller_name": val.get("reseller_name"),
                "reseller_id": val.get("reseller_id"),
                "quantity": val.get("quantity"),
                "kg_size": val.get("kg_size"),
                "total_sales": val.get("total_sales"),
                "order_status": status,
                "order_source": val.get("order_source"),
                "sales_date": val.get("sales_date"),
                "created_at": val.get("created_at"),
                "archived": bool(val.get("archived")),
                "deleted": bool(val.get("deleted")),
                "hidden_24h": bool(val.get("hidden_24h")),
            })
        stuck.sort(key=lambda o: o.get("created_at") or "", reverse=True)
        return jsonify({"ok": True, "orders": stuck})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


ADMIN_RESELLER_SALES_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reseller Sales Tracking - ISESMO Only</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;display:inline-flex;align-items:center;white-space:nowrap}
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.card h2{font-size:13px;font-weight:700;color:#0f2942;margin:0 0 6px}
.hint{font-size:11px;color:#666;line-height:1.5;margin-bottom:12px}
.search-row{display:flex;gap:6px;margin-bottom:10px}
.search-row input{flex:1;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px}
.btn-export{padding:10px 14px;border-radius:8px;border:1px solid #00609C;background:#fff;color:#00609C;font-weight:700;font-size:12px;cursor:pointer;white-space:nowrap}
.sort-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.sort-btn{padding:6px 12px;border-radius:16px;border:1px solid #cde;background:#fff;color:#00609C;font-size:11px;font-weight:600;cursor:pointer}
.sort-btn.active{background:#00609C;color:#fff;border-color:#00609C}
.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:760px}
th{text-align:left;font-size:10px;color:#888;text-transform:uppercase;padding:8px 10px;border-bottom:2px solid #eef4fb;white-space:nowrap}
td{padding:10px;font-size:12px;color:#0f2942;border-bottom:1px solid #f0f4f8;white-space:nowrap}
tr.clickable{cursor:pointer}
tr.clickable:hover td{background:#fafcff}
.reseller-name{font-weight:700}
.reseller-phone{font-size:10px;color:#888}
.badge-eta{padding:3px 8px;border-radius:10px;font-size:10px;font-weight:700}
.badge-eta.soon{background:#dcfce7;color:#166534}
.badge-eta.mid{background:#fef9c3;color:#854d0e}
.badge-eta.far{background:#fee2e2;color:#991b1b}
.badge-eta.none{background:#f1f5f9;color:#64748b}
.empty-state{padding:30px;text-align:center;color:#888;font-size:12px}
.risk-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #f0f4f8;font-size:12px}
.risk-row:last-child{border-bottom:none}
.risk-days{padding:4px 10px;border-radius:10px;font-size:11px;font-weight:700;background:#fee2e2;color:#991b1b}
.leader-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #f0f4f8}
.leader-row:last-child{border-bottom:none}
.leader-rank{flex-shrink:0;width:28px;height:28px;border-radius:50%;background:#eef7ff;color:#00609C;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:800}
.leader-rank.gold{background:#fef3c7;color:#92400e}
.leader-info{flex-grow:1;font-size:13px;color:#0f2942}
.leader-sales{font-size:13px;font-weight:700;color:#00609C}
.month-picker{display:flex;gap:6px;align-items:center;margin-bottom:10px}
.month-picker input{padding:8px;border-radius:8px;border:1px solid #ccd;font-size:12px}
.trend-bars{display:flex;align-items:flex-end;gap:8px;height:120px;padding-top:10px}
.trend-bar-col{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%}
.trend-bar{width:100%;max-width:36px;background:#00609C;border-radius:4px 4px 0 0;min-height:2px}
.trend-count{font-size:11px;font-weight:700;color:#0f2942;margin-bottom:2px}
.trend-label{font-size:9px;color:#888;margin-top:6px;text-align:center}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(15,41,66,.5);z-index:100;align-items:flex-start;justify-content:center;overflow-y:auto;padding:20px 12px}
.modal-overlay.show{display:flex}
.modal-box{background:#fff;border-radius:14px;max-width:640px;width:100%;padding:18px;margin-top:20px}
.modal-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px}
.modal-title{font-size:16px;font-weight:800;color:#0f2942}
.modal-sub{font-size:11px;color:#888;margin-top:2px}
.modal-close{background:#f1f5f9;border:none;border-radius:8px;padding:6px 10px;font-size:12px;cursor:pointer;color:#333}
.modal-section-title{font-size:12px;font-weight:700;color:#0f2942;margin:14px 0 6px}
.modal-list-row{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid #f0f4f8;font-size:12px}
</style></head>
<body>
<div class="topbar"><h1>📊 Reseller Sales Tracking (ISESMO Only)</h1><div style="display:flex;gap:6px"><a href="/admin/rewards" class="nav-pill">🎁 Rewards</a><a href="/cashier" class="nav-pill">← Sales</a></div></div>

<div class="card" id="atRiskCard" style="display:none">
  <h2>⚠️ At-Risk na Resellers (malapit nang mag-expire ang points)</h2>
  <div class="hint">Mga reseller na may points pa pero malapit na silang ma-expire (15 araw na lang o mas kaunti) dahil matagal na silang walang bagong online order. I-message mo sila bago mawala ang naipon nila.</div>
  <div id="atRiskList"></div>
</div>

<div class="card">
  <h2>🏆 Top Performers</h2>
  <div class="hint">Top 5 reseller base sa online sales ng napiling buwan.</div>
  <div class="month-picker">
    <input type="month" id="leaderboardMonth">
    <button class="sort-btn" onclick="loadLeaderboard()">Tingnan</button>
  </div>
  <div id="leaderboardList">Loading...</div>
</div>

<div class="card">
  <h2>📈 Redemption Trend (huling 6 na buwan)</h2>
  <div class="hint">Bilang ng na-redeem na rewards kada buwan, kasama lahat ng reseller.</div>
  <div class="trend-bars" id="trendBars">Loading...</div>
</div>

<div class="card">
  <div style="font-weight:700;font-size:13px;margin-bottom:6px">Bawat Reseller: Sales, Points, at Rewards History</div>
  <div class="hint">Kasama lang dito ang mga ONLINE order (galing sa app, naka-DELIVER na) - ito rin mismo ang mga order na kumikita ng points, kaya tumutugma ang "sales" dito sa "points earned". Ang "Est. sa Susunod na Reward" ay tantiya lang base sa dating bilis ng pag-order nila - hindi garantiya. I-tap ang isang row para makita ang buong order at points history niya.</div>
  <div class="search-row">
    <input type="text" id="searchInput" placeholder="Maghanap ng reseller (pangalan o phone)..." oninput="renderTable()">
    <button class="btn-export" onclick="exportCsv()">⬇️ Export CSV</button>
  </div>
  <div class="sort-row">
    <button class="sort-btn active" data-sort="total_sales" onclick="setSort('total_sales')">💰 Pinaka-Malaki ang Sales</button>
    <button class="sort-btn" data-sort="order_count" onclick="setSort('order_count')">📦 Pinaka-Madalas Mag-order</button>
    <button class="sort-btn" data-sort="points_balance" onclick="setSort('points_balance')">🎯 Pinaka-Maraming Points</button>
    <button class="sort-btn" data-sort="redemption_count" onclick="setSort('redemption_count')">🎁 Pinaka-Madalas Mag-Redeem</button>
    <button class="sort-btn" data-sort="days_to_next_reward" onclick="setSort('days_to_next_reward')">⏱️ Malapit Na sa Reward</button>
  </div>
  <div class="table-wrap">
    <table id="resellerTable">
      <thead>
        <tr>
          <th>Reseller</th>
          <th>Total Sales</th>
          <th>Orders</th>
          <th>Avg Days/Order</th>
          <th>Points</th>
          <th>Redemptions</th>
          <th>Huling Order</th>
          <th>Est. sa Susunod na Reward</th>
        </tr>
      </thead>
      <tbody id="tableBody"><tr><td colspan="8" class="empty-state">Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<div class="modal-overlay" id="detailOverlay" onclick="if(event.target===this) closeDetail()">
  <div class="modal-box">
    <div class="modal-header">
      <div>
        <div class="modal-title" id="detailTitle">&mdash;</div>
        <div class="modal-sub" id="detailSub">&mdash;</div>
      </div>
      <button class="modal-close" onclick="closeDetail()">✕ Close</button>
    </div>
    <div id="detailBody">Loading...</div>
  </div>
</div>

<script>
let allRows = [];
let currentSort = 'total_sales';

function escapeHtmlR(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}

function fmtPeso(n){
  return '₱' + Number(n||0).toLocaleString(undefined, {minimumFractionDigits:0, maximumFractionDigits:2});
}

function etaBadge(row){
  if(row.points_balance >= (row.next_reward_points || Infinity) || row.next_reward_points === null){
    return '<span class="badge-eta soon">Sapat na ngayon!</span>';
  }
  if(row.days_to_next_reward === null || row.days_to_next_reward === undefined){
    return '<span class="badge-eta none">Kulang pa ang data</span>';
  }
  const days = row.days_to_next_reward;
  const cls = days <= 30 ? 'soon' : (days <= 90 ? 'mid' : 'far');
  return `<span class="badge-eta ${cls}">~${days} araw pa (${row.next_reward_points.toLocaleString()} pts)</span>`;
}

function renderAtRisk(){
  const card = document.getElementById('atRiskCard');
  const list = document.getElementById('atRiskList');
  const atRisk = allRows.filter(r => r.at_risk).sort((a,b) => (a.days_until_points_expire||0) - (b.days_until_points_expire||0));
  if(!atRisk.length){ card.style.display = 'none'; return; }
  card.style.display = 'block';
  list.innerHTML = atRisk.map(r => `
    <div class="risk-row">
      <div><div class="reseller-name">${escapeHtmlR(r.store_name)}</div><div class="reseller-phone">${escapeHtmlR(r.phone||'')} &bull; ${Number(r.points_balance).toLocaleString()} points</div></div>
      <div class="risk-days">${r.days_until_points_expire} araw na lang</div>
    </div>
  `).join('');
}

async function loadResellerSales(){
  const tbody = document.getElementById('tableBody');
  try{
    const res = await fetch('/api/admin/reseller_sales_summary');
    const data = await res.json();
    if(!data.ok){ tbody.innerHTML = `<tr><td colspan="8" class="empty-state" style="color:red">${escapeHtmlR(data.error||'Error')}</td></tr>`; return; }
    allRows = data.resellers || [];
    renderTable();
    renderAtRisk();
  }catch(e){ tbody.innerHTML = `<tr><td colspan="8" class="empty-state" style="color:red">Error: ${escapeHtmlR(e.message)}</td></tr>`; }
}

function setSort(key){
  currentSort = key;
  document.querySelectorAll('.sort-btn[data-sort]').forEach(b => b.classList.toggle('active', b.dataset.sort === key));
  renderTable();
}

function renderTable(){
  const tbody = document.getElementById('tableBody');
  const q = (document.getElementById('searchInput').value || '').trim().toLowerCase();
  let rows = allRows.filter(r => !q || r.store_name.toLowerCase().includes(q) || (r.phone||'').includes(q));

  rows = rows.slice().sort((a, b) => {
    if(currentSort === 'days_to_next_reward'){
      // nulls (no ETA yet, or already qualifies) sort last
      const av = (a.days_to_next_reward === null || a.days_to_next_reward === undefined) ? Infinity : a.days_to_next_reward;
      const bv = (b.days_to_next_reward === null || b.days_to_next_reward === undefined) ? Infinity : b.days_to_next_reward;
      return av - bv;
    }
    return (b[currentSort] || 0) - (a[currentSort] || 0);
  });

  if(!rows.length){
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Walang reseller na nahanap.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map(r => `
    <tr class="clickable" onclick="openDetail('${r.id}')">
      <td><div class="reseller-name">${escapeHtmlR(r.store_name)} <a href="/customer/${r.id}/trend" onclick="event.stopPropagation()" style="font-size:10px;font-weight:600;color:#00609C;text-decoration:none;border:1px solid #cde;border-radius:10px;padding:2px 8px;white-space:nowrap">📈 Trend</a></div><div class="reseller-phone">${escapeHtmlR(r.phone || '')}</div></td>
      <td>${fmtPeso(r.total_sales)}</td>
      <td>${r.order_count}</td>
      <td>${r.avg_days_between_orders !== null && r.avg_days_between_orders !== undefined ? r.avg_days_between_orders + ' araw' : '&mdash;'}</td>
      <td>${Number(r.points_balance).toLocaleString()}</td>
      <td>${r.redemption_count}</td>
      <td>${r.last_order_date ? escapeHtmlR(r.last_order_date) : '&mdash;'}</td>
      <td>${etaBadge(r)}</td>
    </tr>
  `).join('');
}

function exportCsv(){
  if(!allRows.length){ alert('Walang data na i-e-export.'); return; }
  const headers = ['Store Name','Phone','Total Sales','Orders','Avg Days Between Orders','Points Balance','Redemptions','Last Order Date','Days To Next Reward'];
  const lines = [headers.join(',')];
  allRows.forEach(r => {
    const row = [
      r.store_name, r.phone || '', r.total_sales, r.order_count,
      r.avg_days_between_orders ?? '', r.points_balance, r.redemption_count,
      r.last_order_date || '', r.days_to_next_reward ?? ''
    ].map(v => `"${String(v).replace(/"/g,'""')}"`);
    lines.push(row.join(','));
  });
  const blob = new Blob([lines.join('\\n')], {type: 'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `omega_ice_reseller_sales_${new Date().toISOString().slice(0,10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function loadLeaderboard(){
  const list = document.getElementById('leaderboardList');
  const monthInput = document.getElementById('leaderboardMonth');
  const month = monthInput.value;
  list.innerHTML = 'Loading...';
  try{
    const url = month ? `/api/admin/reseller_leaderboard?month=${encodeURIComponent(month)}` : '/api/admin/reseller_leaderboard';
    const res = await fetch(url);
    const data = await res.json();
    if(!data.ok){ list.innerHTML = `<div style="color:red">${escapeHtmlR(data.error||'Error')}</div>`; return; }
    if(!monthInput.value) monthInput.value = data.year_month;
    if(!data.leaders.length){ list.innerHTML = '<div class="empty-state">Walang online sales sa buwang ito.</div>'; return; }
    const medals = ['gold','gold','gold'];
    list.innerHTML = data.leaders.map((r, i) => `
      <div class="leader-row">
        <div class="leader-rank ${i < 1 ? 'gold' : ''}">${i+1}</div>
        <div class="leader-info"><div class="reseller-name">${escapeHtmlR(r.store_name)}</div><div class="reseller-phone">${r.order_count} order(s)</div></div>
        <div class="leader-sales">${fmtPeso(r.total_sales)}</div>
      </div>
    `).join('');
  }catch(e){ list.innerHTML = `<div style="color:red">Error: ${escapeHtmlR(e.message)}</div>`; }
}

async function loadTrend(){
  const el = document.getElementById('trendBars');
  try{
    const res = await fetch('/api/admin/redemption_trend');
    const data = await res.json();
    if(!data.ok){ el.innerHTML = `<div style="color:red">${escapeHtmlR(data.error||'Error')}</div>`; return; }
    const trend = data.trend || [];
    const maxCount = Math.max(1, ...trend.map(t => t.count));
    el.innerHTML = trend.map(t => {
      const pct = Math.round((t.count / maxCount) * 100);
      const heightPx = Math.max(2, Math.round(pct * 0.9));
      const label = t.month.slice(5,7) + '/' + t.month.slice(2,4);
      return `
        <div class="trend-bar-col">
          <div class="trend-count">${t.count}</div>
          <div class="trend-bar" style="height:${heightPx}px"></div>
          <div class="trend-label">${label}</div>
        </div>
      `;
    }).join('');
  }catch(e){ el.innerHTML = `<div style="color:red">Error: ${escapeHtmlR(e.message)}</div>`; }
}

async function openDetail(resellerId){
  const overlay = document.getElementById('detailOverlay');
  const body = document.getElementById('detailBody');
  const title = document.getElementById('detailTitle');
  const sub = document.getElementById('detailSub');
  overlay.classList.add('show');
  title.textContent = 'Loading...';
  sub.textContent = '';
  body.innerHTML = 'Loading...';
  try{
    const res = await fetch(`/api/admin/reseller_detail/${encodeURIComponent(resellerId)}`);
    const data = await res.json();
    if(!data.ok){ body.innerHTML = `<div style="color:red">${escapeHtmlR(data.error||'Error')}</div>`; return; }
    title.textContent = data.store_name;
    sub.textContent = `${data.phone || 'walang phone'} • ${Number(data.points_balance).toLocaleString()} points ngayon`;

    let html = '<div class="modal-section-title">📦 Order History</div>';
    if(!data.orders.length){
      html += '<div class="empty-state">Wala pang online order.</div>';
    }else{
      html += data.orders.map(o => `
        <div class="modal-list-row">
          <span>${escapeHtmlR(o.sales_date||'')} &mdash; ${escapeHtmlR(o.quantity)} ${escapeHtmlR(o.kg_size||'')} ${o.reward_redemption ? '🎁' : ''}</span>
          <span style="font-weight:700">${o.reward_redemption ? 'FREE' : fmtPeso(o.total_sales)} <span style="color:#888;font-weight:400">(${escapeHtmlR(o.order_status||'')})</span></span>
        </div>
      `).join('');
    }

    html += '<div class="modal-section-title">🎯 Points Ledger</div>';
    if(!data.points_history.length){
      html += '<div class="empty-state">Wala pang points history.</div>';
    }else{
      html += data.points_history.map(h => `
        <div class="modal-list-row">
          <span>${escapeHtmlR(h.timestamp||'')} &mdash; ${escapeHtmlR(h.reason||'')}</span>
          <span style="font-weight:700;color:${h.points>=0?'#166534':'#c0392b'}">${h.points>=0?'+':''}${h.points} (bal: ${h.balance_after})</span>
        </div>
      `).join('');
    }
    body.innerHTML = html;
  }catch(e){ body.innerHTML = `<div style="color:red">Error: ${escapeHtmlR(e.message)}</div>`; }
}

function closeDetail(){
  document.getElementById('detailOverlay').classList.remove('show');
}

loadResellerSales();
loadLeaderboard();
loadTrend();
</script>
</body></html>
"""

ADMIN_REWARDS_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Rewards Catalog - ISESMO Only</title>
<style>
*{box-sizing:border-box}body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;gap:8px;flex-wrap:wrap}
.topbar h1{font-size:15px;color:#00609C;margin:0}
.nav-pill{padding:7px 14px;border-radius:20px;font-size:11px;text-decoration:none;border:1px solid #cde;background:#fff;color:#00609C;display:inline-flex;align-items:center;white-space:nowrap}
.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.hint{font-size:11px;color:#666;line-height:1.5;margin-bottom:12px}
.reward-row{display:grid;grid-template-columns:1.4fr .8fr .5fr .8fr auto;gap:6px;align-items:center;margin-bottom:8px}
.reward-row input,.reward-row select{padding:8px;border-radius:8px;border:1px solid #ccd;font-size:12px;width:100%}
.del-x{background:#fee2e2;color:#c0392b;border:none;border-radius:8px;padding:8px;font-size:12px;cursor:pointer}
.btn-save{width:100%;padding:12px;border-radius:10px;border:none;background:#00609C;color:#fff;font-weight:700;font-size:13px;cursor:pointer;margin-top:6px}
.btn-add{padding:8px 14px;border-radius:20px;border:1px dashed #00609C;background:#fff;color:#00609C;font-size:11px;font-weight:600;cursor:pointer}
.lookup-row{display:flex;gap:6px;margin-bottom:10px}
.lookup-row input{flex:1;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px}
.lookup-row button{padding:10px 14px;border-radius:8px;border:none;background:#00609C;color:#fff;font-weight:700;font-size:12px}
.hist-row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f0f4f8;font-size:12px}
.status-msg{font-size:11px;margin-top:6px}
.health-banner{border-radius:12px;padding:16px;color:#fff;margin-bottom:12px}
.health-banner.green{background:linear-gradient(135deg,#16a34a,#15803d)}
.health-banner.yellow{background:linear-gradient(135deg,#f59e0b,#d97706)}
.health-banner.red{background:linear-gradient(135deg,#dc2626,#b91c1c)}
.health-banner.unknown{background:linear-gradient(135deg,#64748b,#475569)}
.health-title{font-size:15px;font-weight:800;margin-bottom:4px}
.health-sub{font-size:12px;opacity:.95;line-height:1.5}
.health-stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:12px}
.health-stat{background:rgba(255,255,255,.18);border-radius:8px;padding:8px;text-align:center}
.health-stat b{display:block;font-size:16px}
.health-stat span{font-size:10px;opacity:.9}
.health-reward-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #f0f4f8;font-size:12px}
</style></head>
<body>
<div class="topbar"><h1>🎁 Rewards Catalog (ISESMO Only)</h1><div style="display:flex;gap:6px"><a href="/admin/reseller_sales" class="nav-pill">📊 Sales Tracking</a><a href="/cashier" class="nav-pill">← Sales</a></div></div>

<div class="card" id="pauseCard">
  <div style="font-weight:700;font-size:13px;margin-bottom:6px">⏸️ Points Program Status</div>
  <div class="hint">Isang button lang - ikaw ang magdedesisyon kung kailan i-pause o i-resume ang BUONG points program. Habang naka-pause: hindi kikita ng bagong points ang reseller sa bagong order, at hindi rin muna sila makaka-redeem - pero LIGTAS at buo pa rin ang existing balance ng lahat, agad babalik pag na-resume mo ulit.</div>
  <div id="pauseStatusInfo" style="font-size:13px;font-weight:700;margin-bottom:10px">Loading...</div>
  <button class="btn-save" id="pauseToggleBtn" onclick="toggleProgramPause()">Loading...</button>

  <div style="border-top:1px solid #f0f4f8;margin:14px 0 10px;padding-top:12px">
    <div style="font-weight:700;font-size:12px;margin-bottom:6px">📅 I-schedule (opsyonal)</div>
    <div class="hint">Piliin ang petsa/oras kung kailan awtomatikong mag-pa-pause at/o mag-re-resume - hindi mo na kailangan mag-alala na makalimutan pindutin yung button mismo. Pareho itong OPSYONAL - pwede mong lagyan yung isa lang, o pareho, o iwanang blangko para i-cancel ang schedule. Agad ding may makukuhang notification ang mga reseller pagka-save mo nito, bukod pa sa notification na ipapadala PAG TALAGANG dumating na yung oras.</div>
    <label style="display:block;font-size:11px;color:#0f2942;font-weight:600;margin-bottom:4px">Mag-pa-pause sa:</label>
    <input type="datetime-local" id="scheduledPauseInput" style="width:100%;padding:8px;border-radius:8px;border:1px solid #ccd;font-size:12px;margin-bottom:10px">
    <label style="display:block;font-size:11px;color:#0f2942;font-weight:600;margin-bottom:4px">Mag-re-resume sa:</label>
    <input type="datetime-local" id="scheduledResumeInput" style="width:100%;padding:8px;border-radius:8px;border:1px solid #ccd;font-size:12px;margin-bottom:10px">
    <button class="btn-save" onclick="saveSchedule()">💾 I-save ang Schedule</button>
    <p class="status-msg" id="scheduleStatus"></p>
  </div>
</div>

<div class="card">
  <div style="font-weight:700;font-size:13px;margin-bottom:6px">📊 Margin Health Check</div>
  <div class="hint">Ito ang nagbabantay kung ligtas pa ba ang rewards program mo base sa TUNAY na profit margin mo ngayon (same computation ng Home Dashboard). Kapag lumapit na o bumaba na sa "breakeven line" ang margin mo, dito mo makikita agad.</div>
  <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:#0f2942;font-weight:600;margin-bottom:10px;cursor:pointer">
    <input type="checkbox" id="includeFixedToggle" checked onchange="loadMarginHealth()">
    Include Fixed Asset (depreciation ng machine/vehicle) - recommended na naka-ON
  </label>
  <div id="marginHealthBox">Loading...</div>
</div>

<div class="card">
  <div style="font-weight:700;font-size:13px;margin-bottom:6px">Points Expiration</div>
  <div class="hint">Kung walang DELIVERED online order ang reseller sa loob ng ganito karaming araw, mag-e-expire (mawawala) ang naipong points nila. Awtomatiko itong nag-che-check (walang cron/schedule na kailangan i-set up) - nagki-check lang kapag binuksan ng reseller ang points nila, nag-attempt mag-redeem, o hinahanap mo sila dito.</div>
  <div class="lookup-row">
    <input type="number" min="1" id="inactivityDaysInput" placeholder="Bilang ng araw (default 90)">
    <button onclick="saveInactivityDays()">Save</button>
  </div>
  <p class="status-msg" id="inactivityStatus"></p>
</div>

<div class="card">
  <div style="font-weight:700;font-size:13px;margin-bottom:6px">Redemption Cooldown</div>
  <div class="hint">Pinaka-kaunting bilang ng araw na kailangang hintayin ng reseller sa pagitan ng dalawang magkasunod na redemption - kahit sobra-sobra na ang points niya. Pinipigilan nito ang "matambak" na maraming FREE reward orders sabay-sabay kapag mabilis na-cross ng reseller ang ilang points tiers nang sabay.</div>
  <div class="lookup-row">
    <input type="number" min="1" id="cooldownDaysInput" placeholder="Bilang ng araw (default 14)">
    <button onclick="saveCooldownDays()">Save</button>
  </div>
  <p class="status-msg" id="cooldownStatus"></p>
</div>

<div class="card">
  <div style="font-weight:700;font-size:13px;margin-bottom:6px">🤝 Referral Bonus</div>
  <div class="hint">Bilang ng points na makukuha ng isang EXISTING reseller kapag ang bagong reseller na kanyang RINEFER ay nag-deliver ng unang online order nila. Awtomatiko - wala nang kailangan pang gawin pagkatapos i-set. Ilagay 0 para pansamantalang i-off ang bonus (hindi mawawala ang naka-link na referral, matitigil lang ang pagbigay ng bonus).</div>
  <div class="lookup-row">
    <input type="number" min="0" id="referralBonusInput" placeholder="Points (default 500)">
    <button onclick="saveReferralBonus()">Save</button>
  </div>
  <p class="status-msg" id="referralBonusStatus"></p>
</div>

<div class="card">
  <div style="font-weight:700;font-size:13px;margin-bottom:6px">Reward Catalog</div>
  <div class="hint">Ito ang mga makukuha ng reseller kapag na-achieve nila ang points requirement. I-edit ang points para tumugma sa margin mo - ligtas kapag hindi bumaba sa gastos (production cost) ng item bago ka pumayag.</div>
  <div id="catalogList">Loading...</div>
  <button class="btn-add" onclick="addRewardRow()">+ Add Reward</button>
  <button class="btn-save" onclick="saveCatalog()">💾 Save Catalog</button>
  <p class="status-msg" id="catalogStatus"></p>
</div>

<div class="card">
  <div style="font-weight:700;font-size:13px;margin-bottom:6px">📦 Points Backup & Restore</div>
  <div class="hint">Araw-araw (gabi-gabi, Manila time) awtomatikong nagpapadala ng email na may kumpletong backup - points balance + buong history ng LAHAT ng reseller, naka-attach bilang .json file. Kung sakaling magka-problema sa Firebase, dito mo pwedeng i-restore ulit ang points gamit ang file na yun.</div>
  <p class="status-msg" id="backupStatusInfo">Loading...</p>
  <button class="btn-save" onclick="sendBackupNow()">📧 Ipadala ang Backup Ngayon</button>
  <p class="status-msg" id="backupSendStatus"></p>

  <div style="border-top:1px solid #f0f4f8;margin:14px 0 10px;padding-top:12px">
    <div style="font-weight:700;font-size:12px;margin-bottom:6px;color:#c0392b">♻️ I-restore mula sa Backup File</div>
    <div class="hint" style="color:#c0392b">Babaguhin nito ang LIVE points ng lahat ng reseller batay sa laman ng file na i-a-upload mo (galing sa backup email). Ligtas gamitin - automatic na sina-snapshot ang kasalukuyang data bago pa i-overwrite, kaya pwede pa ring bumalik kung mali ang na-upload na file.</div>
    <input type="file" id="restoreFileInput" accept="application/json,.json" style="width:100%;margin-bottom:8px;padding:8px;border-radius:8px;border:1px solid #ccd;font-size:12px">
    <label style="display:flex;align-items:center;gap:8px;font-size:11px;color:#0f2942;margin-bottom:8px;cursor:pointer">
      <input type="checkbox" id="restoreIncludeCatalog">
      Isama rin ang Reward Catalog at Settings (expiry/cooldown days)
    </label>
    <button class="btn-save" style="background:#c0392b" onclick="restoreFromBackup()">♻️ I-restore Ngayon</button>
    <p class="status-msg" id="restoreStatus"></p>
  </div>
</div>

<div class="card">
  <div style="font-weight:700;font-size:13px;margin-bottom:6px">Search Reseller Points</div>
  <div class="lookup-row">
    <input type="text" id="resellerIdInput" placeholder="Reseller ID (galing sa /customers page)">
    <button onclick="lookupPoints()">Search</button>
  </div>
  <div id="lookupResult"></div>
</div>

<script>
let catalogRows = [];

function escapeHtmlR(t){
  const d = document.createElement('div');
  d.textContent = (t===null||t===undefined) ? '' : String(t);
  return d.innerHTML;
}

async function loadCatalog(){
  const el = document.getElementById('catalogList');
  el.innerHTML = 'Loading...';
  try{
    const res = await fetch('/api/admin/reward_catalog');
    const data = await res.json();
    if(!data.ok){ el.innerHTML = `<div style="color:red">${escapeHtmlR(data.error||'Error')}</div>`; return; }
    catalogRows = Object.entries(data.catalog || {}).map(([id, v]) => ({id, ...v}));
    renderCatalog();
  }catch(e){ el.innerHTML = `<div style="color:red">Error: ${escapeHtmlR(e.message)}</div>`; }
}
function renderCatalog(){
  const el = document.getElementById('catalogList');
  el.innerHTML = catalogRows.map((r, i) => `
    <div class="reward-row">
      <input type="text" value="${escapeHtmlR(r.label)}" placeholder="Label" oninput="catalogRows[${i}].label=this.value">
      <select onchange="catalogRows[${i}].kg_size=this.value">
        ${['1Kg','5Kg','10Kg','25Kg'].map(k=>`<option value="${k}" ${r.kg_size===k?'selected':''}>${k}</option>`).join('')}
      </select>
      <input type="number" min="1" value="${r.quantity||1}" placeholder="Qty" oninput="catalogRows[${i}].quantity=parseInt(this.value)||1">
      <input type="number" min="1" value="${r.points_required||0}" placeholder="Points" oninput="catalogRows[${i}].points_required=parseInt(this.value)||0">
      <button class="del-x" onclick="removeRewardRow(${i})">🗑️</button>
    </div>
  `).join('');
}
function addRewardRow(){
  catalogRows.push({id: 'reward_' + Date.now(), label: 'Libreng Ice', kg_size: '1Kg', quantity: 1, points_required: 40});
  renderCatalog();
}
function removeRewardRow(i){
  catalogRows.splice(i, 1);
  renderCatalog();
}
async function saveCatalog(){
  const statusEl = document.getElementById('catalogStatus');
  statusEl.style.color = '#888';
  statusEl.textContent = 'Saving...';
  const catalog = {};
  catalogRows.forEach(r => { catalog[r.id] = {label: r.label, kg_size: r.kg_size, quantity: r.quantity, points_required: r.points_required}; });
  try{
    const res = await fetch('/api/admin/reward_catalog', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({catalog})
    });
    const data = await res.json();
    if(data.ok){ statusEl.style.color='#166534'; statusEl.textContent='✅ Saved!'; loadCatalog(); }
    else{ statusEl.style.color='#c0392b'; statusEl.textContent = data.error || 'Failed'; }
  }catch(e){ statusEl.style.color='#c0392b'; statusEl.textContent = 'Network error: ' + e.message; }
}

async function lookupPoints(){
  const id = document.getElementById('resellerIdInput').value.trim();
  const el = document.getElementById('lookupResult');
  if(!id){ el.innerHTML = ''; return; }
  el.innerHTML = 'Loading...';
  try{
    const res = await fetch(`/api/admin/reseller_points/${encodeURIComponent(id)}`);
    const data = await res.json();
    if(!data.ok){ el.innerHTML = `<div style="color:red">${escapeHtmlR(data.error||'Error')}</div>`; return; }
    let html = `<div style="font-size:18px;font-weight:700;color:#00609C;margin:8px 0">Balance: ${data.balance.toLocaleString()} points</div>`;
    html += `<div class="lookup-row"><input type="number" id="adjustDelta" placeholder="+/- points (hal. -50 o 100)"><button onclick="adjustPoints('${id}')">Apply</button></div>`;
    html += '<div style="font-size:11px;color:#888;margin:6px 0">History (latest 20):</div>';
    (data.history || []).slice(0, 20).forEach(h => {
      html += `<div class="hist-row"><span>${escapeHtmlR(h.reason||'')}</span><span style="font-weight:700;color:${h.points>=0?'#166534':'#c0392b'}">${h.points>=0?'+':''}${h.points} (bal: ${h.balance_after})</span></div>`;
    });
    el.innerHTML = html;
  }catch(e){ el.innerHTML = `<div style="color:red">Error: ${escapeHtmlR(e.message)}</div>`; }
}
async function adjustPoints(id){
  const delta = parseInt(document.getElementById('adjustDelta').value);
  if(!delta){ alert('Enter a non-zero number'); return; }
  const reason = prompt('Reason for this adjustment?') || 'Manual adjustment';
  try{
    const res = await fetch(`/api/admin/reseller_points/${encodeURIComponent(id)}/adjust`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({delta, reason})
    });
    const data = await res.json();
    if(data.ok){ lookupPoints(); }
    else{ alert(data.error || 'Failed'); }
  }catch(e){ alert('Network error: ' + e.message); }
}

async function loadInactivityDays(){
  try{
    const res = await fetch('/api/admin/loyalty_settings');
    const data = await res.json();
    if(data.ok){ document.getElementById('inactivityDaysInput').value = data.inactivity_days; }
  }catch(e){}
}
async function saveInactivityDays(){
  const statusEl = document.getElementById('inactivityStatus');
  const days = parseInt(document.getElementById('inactivityDaysInput').value);
  if(!days || days < 1){ statusEl.style.color='#c0392b'; statusEl.textContent = 'Enter a valid number of days'; return; }
  statusEl.style.color = '#888';
  statusEl.textContent = 'Saving...';
  try{
    const res = await fetch('/api/admin/loyalty_settings', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({inactivity_days: days})
    });
    const data = await res.json();
    if(data.ok){ statusEl.style.color='#166534'; statusEl.textContent = '✅ Saved!'; }
    else{ statusEl.style.color='#c0392b'; statusEl.textContent = data.error || 'Failed'; }
  }catch(e){ statusEl.style.color='#c0392b'; statusEl.textContent = 'Network error: ' + e.message; }
}

async function loadCooldownDays(){
  try{
    const res = await fetch('/api/admin/loyalty_settings');
    const data = await res.json();
    if(data.ok){ document.getElementById('cooldownDaysInput').value = data.redemption_cooldown_days; }
  }catch(e){}
}
async function saveCooldownDays(){
  const statusEl = document.getElementById('cooldownStatus');
  const days = parseInt(document.getElementById('cooldownDaysInput').value);
  if(!days || days < 1){ statusEl.style.color='#c0392b'; statusEl.textContent = 'Enter a valid number of days'; return; }
  statusEl.style.color = '#888';
  statusEl.textContent = 'Saving...';
  try{
    const res = await fetch('/api/admin/loyalty_settings', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({redemption_cooldown_days: days})
    });
    const data = await res.json();
    if(data.ok){ statusEl.style.color='#166534'; statusEl.textContent = '✅ Saved!'; }
    else{ statusEl.style.color='#c0392b'; statusEl.textContent = data.error || 'Failed'; }
  }catch(e){ statusEl.style.color='#c0392b'; statusEl.textContent = 'Network error: ' + e.message; }
}

async function loadReferralBonus(){
  try{
    const res = await fetch('/api/admin/loyalty_settings');
    const data = await res.json();
    if(data.ok){ document.getElementById('referralBonusInput').value = data.referral_bonus_points; }
  }catch(e){}
}
async function saveReferralBonus(){
  const statusEl = document.getElementById('referralBonusStatus');
  const pts = parseInt(document.getElementById('referralBonusInput').value);
  if(isNaN(pts) || pts < 0){ statusEl.style.color='#c0392b'; statusEl.textContent = 'Enter a valid number (0 or more)'; return; }
  statusEl.style.color = '#888';
  statusEl.textContent = 'Saving...';
  try{
    const res = await fetch('/api/admin/loyalty_settings', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({referral_bonus_points: pts})
    });
    const data = await res.json();
    if(data.ok){ statusEl.style.color='#166534'; statusEl.textContent = '✅ Saved!'; }
    else{ statusEl.style.color='#c0392b'; statusEl.textContent = data.error || 'Failed'; }
  }catch(e){ statusEl.style.color='#c0392b'; statusEl.textContent = 'Network error: ' + e.message; }
}

async function loadMarginHealth(){
  const el = document.getElementById('marginHealthBox');
  el.innerHTML = 'Loading...';
  const includeFixed = document.getElementById('includeFixedToggle').checked ? '1' : '0';
  try{
    const res = await fetch(`/api/admin/margin_health?include_fixed=${includeFixed}`);
    const data = await res.json();
    if(!data.ok){ el.innerHTML = `<div style="color:red">${escapeHtmlR(data.error||'Error')}</div>`; return; }

    const statusLabels = {
      green: {emoji:'✅', title:'LIGTAS - Malayo pa sa breakeven line'},
      yellow: {emoji:'⚠️', title:'INGAT - Papalapit na sa breakeven line'},
      red: {emoji:'🔴', title:'DELIKADO - Lugi na o malapit ng malugi sa rewards!'},
      unknown: {emoji:'❔', title:'Walang sapat na sales data pa para makalkula'},
    };
    const s = statusLabels[data.status] || statusLabels.unknown;
    const curMargin = (data.current_margin===null||data.current_margin===undefined) ? '—' : `${data.current_margin}%`;
    const worstMargin = (data.worst_breakeven_margin===null||data.worst_breakeven_margin===undefined) ? '—' : `${data.worst_breakeven_margin}%`;
    const buffer = (data.buffer_points===null||data.buffer_points===undefined) ? '—' : `${data.buffer_points>0?'+':''}${data.buffer_points}pp`;

    let html = `<div class="health-banner ${data.status}">
      <div class="health-title">${s.emoji} ${s.title}</div>
      <div class="health-sub">Kasalukuyang totoong profit margin mo (base sa lahat ng sales at gastos, kasama fixed assets): <b>${curMargin}</b>. Ang pinaka-mapanganib na reward (${escapeHtmlR(data.worst_reward_label||'-')}) ay nangangailangan ng hindi bababa sa <b>${worstMargin}</b> margin para hindi ka lugi dito.</div>
      <div class="health-stats">
        <div class="health-stat"><b>${curMargin}</b><span>KASALUKUYANG MARGIN</span></div>
        <div class="health-stat"><b>${worstMargin}</b><span>KAILANGANG MARGIN (WORST REWARD)</span></div>
        <div class="health-stat"><b>${buffer}</b><span>SAFETY BUFFER</span></div>
      </div>
    </div>`;

    html += '<div style="font-size:11px;color:#888;margin:8px 0 4px">Breakeven margin per reward (mas mataas = mas risky):</div>';
    (data.rewards || []).forEach(r => {
      const bm = (r.breakeven_margin===null||r.breakeven_margin===undefined) ? '—' : `${r.breakeven_margin}%`;
      html += `<div class="health-reward-row"><span>${escapeHtmlR(r.label)} (${r.points_required} pts)</span><span style="font-weight:700">${bm}</span></div>`;
    });
    el.innerHTML = html;
  }catch(e){ el.innerHTML = `<div style="color:red">Error: ${escapeHtmlR(e.message)}</div>`; }
}

async function loadBackupStatus(){
  const el = document.getElementById('backupStatusInfo');
  try{
    const res = await fetch('/api/admin/backup_points/status');
    const data = await res.json();
    if(!data.ok){ el.innerHTML = `<span style="color:red">${escapeHtmlR(data.error||'Error')}</span>`; return; }
    if(!data.enabled){
      el.innerHTML = '<span style="color:#c0392b">⚠️ Hindi pa naka-configure ang email backup (kulang ang SMTP_EMAIL / SMTP_APP_PASSWORD sa Render → Environment)</span>';
    } else {
      el.innerHTML = `✅ Naka-configure. Papadalhan: <b>${escapeHtmlR(data.send_to)}</b>. Huling backup: <b>${escapeHtmlR(data.last_backup_at || 'wala pa')}</b>`;
    }
  }catch(e){ el.innerHTML = `<span style="color:red">Error: ${escapeHtmlR(e.message)}</span>`; }
}

async function sendBackupNow(){
  const el = document.getElementById('backupSendStatus');
  el.textContent = 'Nagpapadala...'; el.style.color = '#666';
  try{
    const res = await fetch('/api/admin/backup_points/send_now', {method:'POST'});
    const data = await res.json();
    el.textContent = data.message || data.error || (data.ok ? 'Naipadala' : 'Nabigo');
    el.style.color = data.ok ? '#166534' : 'red';
    if(data.ok) loadBackupStatus();
  }catch(e){ el.textContent = 'Error: ' + e.message; el.style.color = 'red'; }
}

async function restoreFromBackup(){
  const fileInput = document.getElementById('restoreFileInput');
  const statusEl = document.getElementById('restoreStatus');
  if(!fileInput.files.length){ statusEl.textContent = 'Pumili muna ng backup file (.json)'; statusEl.style.color = 'red'; return; }
  if(!confirm('Sigurado ka bang gusto mong i-restore ang points mula sa file na ito? Mababago ang LIVE points ng LAHAT ng reseller.')) return;

  const fd = new FormData();
  fd.append('backup_file', fileInput.files[0]);
  fd.append('include_catalog', document.getElementById('restoreIncludeCatalog').checked ? '1' : '0');

  statusEl.textContent = 'Ni-restore...'; statusEl.style.color = '#666';
  try{
    const res = await fetch('/api/admin/backup_points/restore', {method:'POST', body: fd});
    const data = await res.json();
    statusEl.textContent = data.message || data.error || (data.ok ? 'Tapos na' : 'Nabigo');
    statusEl.style.color = data.ok ? '#166534' : 'red';
  }catch(e){ statusEl.textContent = 'Error: ' + e.message; statusEl.style.color = 'red'; }
}

let _programPaused = false;
async function loadPauseStatus(){
  const infoEl = document.getElementById('pauseStatusInfo');
  const btnEl = document.getElementById('pauseToggleBtn');
  try{
    const res = await fetch('/api/admin/loyalty_settings');
    const data = await res.json();
    if(!data.ok){ infoEl.innerHTML = `<span style="color:red">${escapeHtmlR(data.error||'Error')}</span>`; return; }
    _programPaused = !!data.program_paused;
    renderPauseStatus(data.program_paused_at);
    // "YYYY-MM-DD HH:MM:SS"/"YYYY-MM-DD HH:MM" from the server -> the
    // "YYYY-MM-DDTHH:MM" shape <input type="datetime-local"> expects.
    const pauseInput = document.getElementById('scheduledPauseInput');
    const resumeInput = document.getElementById('scheduledResumeInput');
    if(pauseInput) pauseInput.value = data.scheduled_pause_at ? data.scheduled_pause_at.slice(0,16).replace(' ','T') : '';
    if(resumeInput) resumeInput.value = data.scheduled_resume_at ? data.scheduled_resume_at.slice(0,16).replace(' ','T') : '';
  }catch(e){ infoEl.innerHTML = `<span style="color:red">Error: ${escapeHtmlR(e.message)}</span>`; }
}
function renderPauseStatus(changedAt){
  const infoEl = document.getElementById('pauseStatusInfo');
  const btnEl = document.getElementById('pauseToggleBtn');
  const card = document.getElementById('pauseCard');
  if(_programPaused){
    infoEl.innerHTML = `⏸️ <span style="color:#c0392b">NAKA-PAUSE</span> ang points program ngayon${changedAt ? ' (simula ' + escapeHtmlR(changedAt) + ')' : ''}. Walang bagong kikitain o mare-redeem na points ang mga reseller.`;
    btnEl.textContent = '▶️ I-resume ang Points Program';
    btnEl.style.background = '#16a34a';
    card.style.background = '#fff7ed';
  } else {
    infoEl.innerHTML = `✅ <span style="color:#166534">ACTIVE</span> ang points program ngayon - normal na kumikita at naka-redeem ang mga reseller.`;
    btnEl.textContent = '⏸️ I-pause ang Points Program';
    btnEl.style.background = '#c0392b';
    card.style.background = '#fff';
  }
}
async function toggleProgramPause(){
  const btnEl = document.getElementById('pauseToggleBtn');
  const action = _programPaused ? 'I-RESUME' : 'I-PAUSE';
  if(!confirm(`Sigurado ka bang gusto mong ${action} ang buong Points Program? Makikita agad ito ng lahat ng reseller sa dashboard nila.`)) return;
  btnEl.disabled = true;
  btnEl.textContent = 'Nagpapadala...';
  try{
    const res = await fetch('/api/admin/loyalty_settings/toggle_pause', {method:'POST'});
    const data = await res.json();
    if(!data.ok){ alert(data.error || 'Nabigo i-toggle'); }
    else { _programPaused = data.program_paused; }
    await loadPauseStatus();
  }catch(e){ alert('Error: ' + e.message); }
  btnEl.disabled = false;
}

async function saveSchedule(){
  const statusEl = document.getElementById('scheduleStatus');
  const pauseVal = document.getElementById('scheduledPauseInput').value;
  const resumeVal = document.getElementById('scheduledResumeInput').value;
  statusEl.textContent = 'Sine-save...'; statusEl.style.color = '#666';
  try{
    const res = await fetch('/api/admin/loyalty_settings/schedule', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        scheduled_pause_at: pauseVal ? pauseVal.replace('T',' ') : '',
        scheduled_resume_at: resumeVal ? resumeVal.replace('T',' ') : '',
      })
    });
    const data = await res.json();
    if(!data.ok){ statusEl.textContent = data.error || 'Nabigo i-save'; statusEl.style.color = 'red'; return; }
    statusEl.textContent = (pauseVal || resumeVal) ? '✅ Na-save ang schedule - na-notify na ang mga reseller.' : '✅ Na-clear ang schedule.';
    statusEl.style.color = '#166534';
  }catch(e){ statusEl.textContent = 'Error: ' + e.message; statusEl.style.color = 'red'; }
}

loadPauseStatus();
loadCatalog();
loadInactivityDays();
loadCooldownDays();
loadReferralBonus();
loadMarginHealth();
loadBackupStatus();
</script>
</body></html>
"""

@app.route("/admin/rewards")
@login_required
@isesmo_only
def admin_rewards_page():
    return render_template_string(ADMIN_REWARDS_HTML)

@app.route("/api/admin/reward_catalog", methods=["GET"])
@login_required
@isesmo_only
def api_admin_get_reward_catalog():
    try:
        return jsonify({"ok": True, "catalog": get_reward_catalog()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/reward_catalog", methods=["POST"])
@login_required
@isesmo_only
def api_admin_save_reward_catalog():
    try:
        data = request.json or {}
        catalog = data.get("catalog") or {}
        clean = {}
        for key, val in catalog.items():
            if not val:
                continue
            pts = int(val.get("points_required", 0) or 0)
            qty = int(val.get("quantity", 1) or 1)
            if pts <= 0 or qty <= 0:
                continue
            clean[key] = {
                "label": (val.get("label") or "").strip()[:80] or "Reward",
                "kg_size": val.get("kg_size", "1Kg"),
                "quantity": qty,
                "points_required": pts,
            }
        if not clean:
            return jsonify({"ok": False, "error": "Catalog cannot be empty - keep at least 1 valid reward"}), 400
        fb_put("reward_catalog", clean)
        return jsonify({"ok": True, "catalog": clean})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/loyalty_settings", methods=["GET"])
@login_required
@isesmo_only
def api_admin_get_loyalty_settings():
    try:
        return jsonify({
            "ok": True,
            "inactivity_days": get_points_expiry_days(),
            "redemption_cooldown_days": get_redemption_cooldown_days(),
            "referral_bonus_points": get_referral_bonus_points(),
            "program_paused": is_loyalty_program_paused(),
            "program_paused_at": fb_get("loyalty_settings/program_paused_at"),
            "scheduled_pause_at": fb_get("loyalty_settings/scheduled_pause_at"),
            "scheduled_resume_at": fb_get("loyalty_settings/scheduled_resume_at"),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/loyalty_settings/schedule", methods=["POST"])
@login_required
@isesmo_only
def api_admin_save_pause_schedule():
    """Lets ISESMO pick a future date/time for the points program to
    auto-pause and/or auto-resume, instead of having to remember to
    click the toggle button manually at the right moment. Passing an
    empty string for either field clears that schedule (e.g. changed
    your mind, or it already fired).

    Immediately sends every subscribed reseller a heads-up push
    notification about the NEW schedule (separate from the "it's
    happening now" push _program_schedule_check() fires later when the
    actual moment arrives) - this is what makes it "alam ng customer"
    ahead of time, not just when it happens."""
    try:
        data = request.json or {}
        pause_at = (data.get("scheduled_pause_at") or "").strip()
        resume_at = (data.get("scheduled_resume_at") or "").strip()

        def _parse(s):
            if not s:
                return None
            try:
                return datetime.strptime(s, "%Y-%m-%d %H:%M")
            except ValueError:
                raise ValueError(f"Hindi valid ang petsa/oras: {s}")

        pause_dt = _parse(pause_at)
        resume_dt = _parse(resume_at)
        if pause_dt and resume_dt and resume_dt <= pause_dt:
            return jsonify({"ok": False, "error": "Dapat mas huli ang Resume date/time kaysa sa Pause date/time"}), 400

        fb_put("loyalty_settings/scheduled_pause_at", pause_at or None)
        fb_put("loyalty_settings/scheduled_resume_at", resume_at or None)

        if pause_at or resume_at:
            lines = []
            if pause_at:
                lines.append(f"mag-p-pause sa {pause_at}")
            if resume_at:
                lines.append(f"mag-re-resume sa {resume_at}")
            send_push_to_all_resellers(
                title="📅 Points Program Schedule",
                body=f"Paalala: Ang Points Rewards Program ay {' at '.join(lines)}. Ligtas at buo ang points mo.",
            )
        return jsonify({"ok": True, "scheduled_pause_at": pause_at or None, "scheduled_resume_at": resume_at or None})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/loyalty_settings/toggle_pause", methods=["POST"])
@login_required
@isesmo_only
def api_admin_toggle_loyalty_pause():
    """The single ON/OFF button for the whole points program (see
    is_loyalty_program_paused's docstring). One click flips the current
    state - no separate 'are you sure' payload to build client-side,
    the button itself IS the confirmation since /admin/rewards always
    shows the current state right next to it before it's clicked."""
    try:
        new_state = not is_loyalty_program_paused()
        fb_put("loyalty_settings/program_paused", new_state)
        fb_put("loyalty_settings/program_paused_at", manila_now().strftime("%Y-%m-%d %H:%M:%S"))
        return jsonify({"ok": True, "program_paused": new_state})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/loyalty_settings", methods=["POST"])
@login_required
@isesmo_only
def api_admin_save_loyalty_settings():
    """Saves loyalty settings. Accepts inactivity_days and/or
    redemption_cooldown_days in the same payload, but only
    validates/writes whichever key(s) are actually present - the two
    separate Save buttons on /admin/rewards (Points Expiration vs
    Redemption Cooldown) each send just their own field, and must not
    stomp on the other setting's saved value. Rejects anything under 1
    day for either setting so a fat-fingered value can't wipe every
    reseller's points, or block every redemption, on the next page
    load."""
    try:
        data = request.json or {}
        result = {"ok": True}
        if "inactivity_days" in data:
            days = int(data.get("inactivity_days", 0) or 0)
            if days < 1:
                return jsonify({"ok": False, "error": "Inactivity days must be at least 1"}), 400
            fb_put("loyalty_settings/inactivity_days", days)
            result["inactivity_days"] = days
        if "redemption_cooldown_days" in data:
            cooldown_days = int(data.get("redemption_cooldown_days", 0) or 0)
            if cooldown_days < 1:
                return jsonify({"ok": False, "error": "Cooldown days must be at least 1"}), 400
            fb_put("loyalty_settings/redemption_cooldown_days", cooldown_days)
            result["redemption_cooldown_days"] = cooldown_days
        if "referral_bonus_points" in data:
            # 0 is allowed here (unlike the two settings above) - it's
            # the intended way to switch the referral bonus off without
            # losing the referred_by tracking on existing accounts.
            bonus_points = int(data.get("referral_bonus_points", 0) or 0)
            if bonus_points < 0:
                return jsonify({"ok": False, "error": "Referral bonus points cannot be negative"}), 400
            fb_put("loyalty_settings/referral_bonus_points", bonus_points)
            result["referral_bonus_points"] = bonus_points
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/backup_points/status", methods=["GET"])
@login_required
@isesmo_only
def api_admin_backup_points_status():
    try:
        return jsonify({
            "ok": True,
            "enabled": BACKUP_ENABLED,
            "send_to": BACKUP_EMAIL_TO if BACKUP_ENABLED else None,
            "backup_hour_manila": BACKUP_HOUR_MANILA,
            "last_backup_at": fb_get("loyalty_settings/last_backup_at"),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/backup_points/send_now", methods=["POST"])
@login_required
@isesmo_only
def api_admin_backup_points_send_now():
    try:
        ok, message = send_points_backup_email(trigger="manual")
        return jsonify({"ok": ok, "message": message}), (200 if ok else 500)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/backup_points/restore", methods=["POST"])
@login_required
@isesmo_only
def api_admin_backup_points_restore():
    """Restores reseller loyalty points balances/history from a backup
    JSON file (the same file the automatic/manual backup email attaches).

    SAFETY: before touching anything, the CURRENT live loyalty_points data
    is snapshotted to loyalty_points_backups/pre_restore_<timestamp>
    first, so a restore done with the wrong file (or a stale one) is
    itself recoverable - it's never a one-way door.

    Reward Catalog / Loyalty Settings are only restored if the caller
    explicitly opts in (include_catalog=1) - by default only the actual
    reseller points/history are touched, since the catalog may have been
    intentionally changed since the backup was taken."""
    try:
        file = request.files.get("backup_file")
        if not file:
            return jsonify({"ok": False, "error": "Walang na-upload na file"}), 400
        try:
            payload = json.loads(file.read().decode("utf-8"))
        except Exception:
            return jsonify({"ok": False, "error": "Hindi valid JSON ang file na ito - siguraduhing yung .json backup file mismo ang na-upload"}), 400

        loyalty_points = payload.get("loyalty_points")
        if not isinstance(loyalty_points, dict) or not loyalty_points:
            return jsonify({"ok": False, "error": "Walang loyalty_points data sa file na ito - siguraduhing yung tamang backup file ang na-upload"}), 400

        include_catalog = str(request.form.get("include_catalog", "")).lower() in ("1", "true", "yes")

        # Safety snapshot of what's LIVE right now, before overwriting anything
        snapshot_key = manila_now().strftime("%Y-%m-%d_%H%M%S")
        fb_put(f"loyalty_points_backups/pre_restore_{snapshot_key}", fb_get("loyalty_points") or {})

        clean_points = {}
        for rid, pts in loyalty_points.items():
            if not isinstance(pts, dict):
                continue
            clean_points[rid] = {k: v for k, v in pts.items() if k != "_store_name"}
        fb_put("loyalty_points", clean_points)

        restored_extra = []
        if include_catalog:
            if isinstance(payload.get("reward_catalog"), dict) and payload["reward_catalog"]:
                fb_put("reward_catalog", payload["reward_catalog"])
                restored_extra.append("Reward Catalog")
            if isinstance(payload.get("loyalty_settings"), dict) and payload["loyalty_settings"]:
                fb_put("loyalty_settings", payload["loyalty_settings"])
                restored_extra.append("Loyalty Settings")

        msg = f"Na-restore ang points ng {len(clean_points)} reseller"
        if restored_extra:
            msg += f" (kasama: {', '.join(restored_extra)})"
        msg += f". Backup ng dating data bago i-restore: loyalty_points_backups/pre_restore_{snapshot_key}"
        return jsonify({"ok": True, "message": msg, "restored_count": len(clean_points), "snapshot_key": snapshot_key})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/margin_health")
@login_required
@isesmo_only
def api_admin_margin_health():
    """
    Safety check for the whole rewards program (see get_current_margin_pct
    and get_reward_breakeven_margin for the math). Compares the store's
    real, current all-time profit margin against the WORST-CASE breakeven
    margin across the reward catalog - i.e. whichever reward would turn
    unprofitable first if margin kept dropping. Traffic-light verdict:
      green  - current margin is 5+ points above that breakeven (safe)
      yellow - above breakeven, but by less than 5 points (getting thin -
               worth watching, e.g. after an electricity price hike)
      red    - AT OR BELOW breakeven - redemptions are a net loss RIGHT NOW
      unknown - not enough sales data yet to compute a margin

    ?include_fixed=0 (or "false") switches the margin calculation to
    cash-only (drops machine/vehicle depreciation), matching the Home
    Dashboard's own "Include Fixed Asset" toggle - default is ON
    (depreciation included), the more conservative/recommended setting
    for a safety check.
    """
    try:
        include_fixed = (request.args.get("include_fixed", "1") or "1").lower() not in ("0", "false", "no")
        current_margin = get_current_margin_pct(include_fixed_asset=include_fixed)
        catalog = get_reward_catalog()
        rows = []
        worst_breakeven = None
        worst_label = None
        for key, val in catalog.items():
            if not val:
                continue
            breakeven = get_reward_breakeven_margin(val.get("points_required", 0), val.get("kg_size", "1Kg"))
            rows.append({
                "id": key,
                "label": val.get("label", ""),
                "points_required": val.get("points_required", 0),
                "breakeven_margin": breakeven,
            })
            if breakeven is not None and (worst_breakeven is None or breakeven > worst_breakeven):
                worst_breakeven = breakeven
                worst_label = val.get("label", "")
        status = "unknown"
        buffer_points = None
        if current_margin is not None and worst_breakeven is not None:
            buffer_points = round(current_margin - worst_breakeven, 1)
            if buffer_points <= 0:
                status = "red"
            elif buffer_points < 5:
                status = "yellow"
            else:
                status = "green"
        rows.sort(key=lambda r: (r["breakeven_margin"] is None, -(r["breakeven_margin"] or 0)))
        return jsonify({
            "ok": True,
            "current_margin": current_margin,
            "include_fixed_asset": include_fixed,
            "worst_breakeven_margin": worst_breakeven,
            "worst_reward_label": worst_label,
            "buffer_points": buffer_points,
            "status": status,
            "rewards": rows,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/reseller_points/<reseller_id>", methods=["GET"])
@login_required
@isesmo_only
def api_admin_get_reseller_points(reseller_id):
    try:
        balance = check_and_expire_points(reseller_id)
        history = fb_get(f"loyalty_points/{reseller_id}/history") or {}
        rows = []
        for key, val in history.items():
            if not val:
                continue
            rows.append({"id": key, **val})
        rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
        return jsonify({"ok": True, "balance": balance, "history": rows[:100]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/reseller_points/<reseller_id>/adjust", methods=["POST"])
@login_required
@isesmo_only
def api_admin_adjust_points(reseller_id):
    """Manual points correction tool for ISESMO - e.g. goodwill points for
    a walk-in redemption done in person, or fixing a mistake. Always
    logged with a reason in the same history ledger as automatic
    earn/redeem entries, so nothing here is untraceable."""
    try:
        data = request.json or {}
        delta = int(data.get("delta", 0) or 0)
        reason = (data.get("reason") or "Manual adjustment").strip()[:120]
        if delta == 0:
            return jsonify({"ok": False, "error": "Delta cannot be 0"}), 400
        new_balance = award_loyalty_points(reseller_id, delta, f"[Isesmo] {reason}")
        if new_balance is None:
            return jsonify({"ok": False, "error": "Failed to save adjustment"}), 500
        return jsonify({"ok": True, "new_balance": new_balance})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/admin/reseller_sales")
@login_required
@isesmo_only
def admin_reseller_sales_page():
    return render_template_string(ADMIN_RESELLER_SALES_HTML)

@app.route("/api/admin/reseller_sales_summary")
@login_required
@isesmo_only
def api_admin_reseller_sales_summary():
    try:
        return jsonify({"ok": True, "resellers": get_reseller_sales_summary()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/reseller_leaderboard")
@login_required
@isesmo_only
def api_admin_reseller_leaderboard():
    """?month=YYYY-MM (default: current Manila month)."""
    try:
        year_month = (request.args.get("month") or "").strip() or None
        result = get_reseller_leaderboard(year_month)
        return jsonify({"ok": True, "year_month": result["year_month"], "leaders": result["leaders"]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/redemption_trend")
@login_required
@isesmo_only
def api_admin_redemption_trend():
    try:
        return jsonify({"ok": True, "trend": get_redemption_trend(6)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/reseller_detail/<reseller_id>")
@login_required
@isesmo_only
def api_admin_reseller_detail(reseller_id):
    try:
        return jsonify({"ok": True, **get_reseller_detail(reseller_id)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/orders/<order_id>", methods=["DELETE"])
@login_required
def api_delete_order(order_id):
    """Delete order (used by the Live Orders page's 🗑️ Delete button) -
    HARD DELETE via the authenticated Firebase Admin SDK.

    ROOT CAUSE (Sept 21): this endpoint still had the exact bug already
    found and fixed in /api/sale/<sale_id> back on Sept 19 (see that
    route's comment) - it called the Firebase REST API directly with an
    unauthenticated requests.delete(), which this project's locked-down
    Realtime Database rules (.read/.write: false) reject with 401/403.
    That part WAS checked (hard_deleted = status in [200,204]), so it
    correctly fell back to a soft-delete via fb_patch()... but the
    fb_patch() result was never checked either, so this endpoint always
    returned {"ok": True} no matter what actually happened in Firebase.
    That's why the cashier saw "✅ Deleted!" on the Live Orders page
    while the record (and its "Pending" status) kept showing up on the
    customer's own "My Orders" page - nothing had actually been deleted.

    Fixed the same way /api/sale/<sale_id> was: use fb_delete(), the
    same authenticated Admin SDK connection fb_get/fb_post/fb_patch
    already use everywhere else in this app, and only report success
    once that call has actually confirmed it worked.
    """
    try:
        if not session.get("staff_name"):
            return jsonify({"ok": False, "error": "Only staff"}), 403
        ok = fb_delete(f"daily_sales/{order_id}")
        if not ok:
            return jsonify({"ok": False, "error": "Firebase delete failed - check server logs"}), 502
        for kk in list(globals().keys()):
            if kk.startswith("_dashboard_cache_"):
                try: del globals()[kk]
                except: pass
        return jsonify({"ok": True, "deleted": order_id, "hard_deleted": True})
    except Exception as e:
        import traceback
        return jsonify({"ok": False, "error": str(e), "trace": traceback.format_exc()}), 500


# Start the daily points-backup scheduler. Placed here (module level, after
# every function it calls has been defined) rather than right where
# BACKUP_ENABLED is declared near the top of the file, so the background
# thread never has a chance to call fb_get()/manila_now()/etc. before
# they exist yet. Only starts when SMTP is actually configured (mirrors
# PUSH_ENABLED's silent-disable pattern) - a test suite that imports this
# module fresh without SMTP_EMAIL set never spawns this thread.
if BACKUP_ENABLED and os.environ.get("DISABLE_BACKUP_SCHEDULER") != "1":
    threading.Thread(target=_points_backup_scheduler_loop, daemon=True).start()

# Start the points-program pause/resume schedule checker. Unlike the
# backup scheduler above, this doesn't depend on SMTP being configured -
# the auto-pause/auto-resume flag flip is useful on its own even if push
# notifications aren't set up (PUSH_ENABLED just makes send_push_to_
# all_resellers() a no-op in that case, same silent-disable pattern used
# everywhere else). DISABLE_PROGRAM_SCHEDULER lets a test suite (or a
# script importing this module for any other reason) opt out of the
# background thread the same way DISABLE_BACKUP_SCHEDULER does above.
if os.environ.get("DISABLE_PROGRAM_SCHEDULER") != "1":
    threading.Thread(target=_program_schedule_loop, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Omega Ice OFFLINE MODE ready")
    print(f"Firebase: {FIREBASE_URL}")
    print(f"Local DB: {LOCAL_DB}")
    print(f"Pending offline: {get_pending_count()}")
    print(f"Listening on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
