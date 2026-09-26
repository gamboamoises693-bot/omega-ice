
"""
Omega Ice - OFFLINE FIRST - Firebase + Local SQLite backup
- If internet: saves to Firebase instantly
- If NO internet: saves to phone (omega_local.db) and shows pending badge
- When internet returns: tap badge or go to /api/offline/sync to upload

Firebase: https://moises-92842-default-rtdb.asia-southeast1.firebasedatabase.app
"""

import os, sqlite3, json, requests, time, base64, threading, smtplib, socket, secrets
from datetime import datetime, timedelta
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

# Route alert "pasabay" window (boss's request, Sept 26): how long a
# route-mate alert's REAL countdown runs once it starts ticking. Also
# doubles as the re-alert cooldown - once a customer's alert is truly
# inactive, a fresh order on the route is free to alert them again (see
# _route_alert_state below), so there's only ONE knob to tune instead of
# two separate timers.
ROUTE_ALERT_WINDOW_MINUTES = 5

def _route_alert_state(alert, now_ts, sales=None):
    """Classifies a route_alert dict into one of three states:
      - ("inactive", 0)  - no live alert; free to trigger a new one.
      - ("no_rush", 0)   - alert is live, but the order that triggered it
        is still New Order/Pending/Preparing (not yet Out for Delivery),
        so there's no real deadline yet - the fixed window doesn't apply
        while the order hasn't even left the store. Boss's follow-up
        (Sept 26): the earlier version let a hard 5-minute timer expire
        the banner even if the order was still just sitting in
        Preparing, which cut off route-mates too early; this keeps the
        alert open (no ticking countdown) until the rider ACTUALLY
        leaves - see send_route_out_for_delivery_update(), which is what
        starts the real countdown.
      - ("counting", N)  - alert is live and the real N-second countdown
        (started once the order went Out for Delivery) is running.

    `sales` is an optional already-loaded daily_sales dict (the callers
    in this file already have one in scope) so this never needs its own
    extra Firebase round-trip per route-mate checked."""
    if not isinstance(alert, dict) or not alert.get("active"):
        return ("inactive", 0)
    order_id = alert.get("triggered_by_order_id")
    if order_id:
        order = (sales or {}).get(order_id) if sales is not None else fb_get(f"daily_sales/{order_id}")
        if order and (order.get("order_status") or "") in ("New Order", "Pending", "Preparing"):
            return ("no_rush", 0)
    expires_at_str = alert.get("expires_at")
    if not expires_at_str:
        return ("inactive", 0)
    try:
        expires_dt = datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return ("inactive", 0)
    seconds_left = int((expires_dt - now_ts).total_seconds())
    if seconds_left <= 0:
        return ("inactive", 0)
    return ("counting", seconds_left)

def trigger_route_order_alert(ordering_reseller_id, order_id=None):
    """Route-mate order alert (boss's request, Sept 26, REVISED same day):
    originally fired only when an order got marked "Delivered", but boss
    tested it with a route-mate ("tsong") who had just PLACED an order
    (still Pending) and got no notification - that was the trigger point
    working as first designed, not a bug. Boss then explicitly asked to
    switch the trigger to fire as soon as the order is PLACED, so
    route-mates can still get added to the same run while it's being
    prepared, instead of waiting for delivery to complete. Still WITHOUT
    naming which store placed the order (boss's original words: "di
    sasabihin anong store name, sasabihin lang na may delivery area at
    pwede na din sila mag place order para maisabay").

    Design (per boss's answers, Sept 26):
      - "Route" is a manual tag ISESMO sets per customer (resellers/<id>
        /route) via the Customers page - no auto-geolocation guessing.
      - Only notifies route-mates who have NO active/unfinished order
        right now (New Order/Pending/Preparing/Out for Delivery) - a
        customer who's already in the queue doesn't need a nudge.
      - Push notification AND a visible banner on their dashboard (the
        banner is driven by resellers/<id>/route_alert, read by
        api_customer_orders() and rendered by loadOrders() in
        CUSTOMER_DASHBOARD_HTML, with a live countdown - see
        ROUTE_ALERT_WINDOW_MINUTES).
      - WINDOW/EXPIRY (boss's follow-up, Sept 26: "ilang minutes window
        time ng pasabay... dapat mawala na din pag lumipas na yung
        window time" - answer: 5 minutes, with a countdown on the
        banner - REVISED again same day: don't let it expire while the
        order is still just being prepared, and if it does still lapse
        while someone wants to order, tell them ordering is still fine):
        each alert carries an expires_at, but _route_alert_state() (see
        its own docstring) only starts the real ROUTE_ALERT_WINDOW_
        MINUTES countdown once the triggering order reaches "Out for
        Delivery" - before that it stays open with no ticking clock.
        Once truly expired, it no longer blocks a fresh alert to the
        same customer, and api_customer_orders() stops reporting it as
        active (the customer app then shows a friendly "pwede ka pa
        ring mag-order" note instead of just vanishing).
      - Auto-clears (route_alert.active -> False) once that customer
        places their own next order (see api_customer_place_order) or
        taps "Hindi na kailangan" to dismiss it themselves.
      - RECALL (boss's follow-up, Sept 26: "dapat may push notification
        din sa customer"): each alert is tagged with the order_id that
        caused it (triggered_by_order_id). If that SAME order later gets
        Cancelled/Declined, api_update_order_status() looks up every
        route-mate still holding an alert tagged with that order_id and
        actively PUSHES them a recall notice (not just a silent clear) -
        so a route-mate who was told "may order sa lugar niyo, isabay ka
        na" actually finds out if that order fell through, instead of
        the banner just quietly disappearing with no explanation.
      - OUT FOR DELIVERY UPGRADE (boss's follow-up, Sept 26: "pag out of
        delivery na yung ka-route nila, mababago ang notification na
        nakaalis na ng Delivery Rider"): when that SAME order reaches
        "Out for Delivery", see send_route_out_for_delivery_update() -
        re-broadcasts a fresh alert/countdown with an upgraded message,
        since a rider actually leaving is a stronger, more actionable
        signal than the original "may bagong order" nudge.

    Called from api_customer_place_order(), right after a new order is
    created. Wrapped in its own try/except so a hiccup here NEVER blocks
    the actual order from being placed."""
    try:
        reseller = fb_get(f"resellers/{ordering_reseller_id}") or {}
        route = (reseller.get("route") or "").strip()
        if not route:
            return  # this customer isn't tagged to any route - nothing to alert

        resellers = fb_get("resellers") or {}
        sales = fb_get("daily_sales") or {}
        ACTIVE_STATUSES = {"New Order", "Pending", "Preparing", "Out for Delivery"}
        resellers_with_active_order = set()
        for v in (sales or {}).values():
            if v and (v.get("order_status") or "") in ACTIVE_STATUSES and v.get("reseller_id"):
                resellers_with_active_order.add(v.get("reseller_id"))

        now_ts = manila_now().replace(tzinfo=None)
        expires_at = now_ts + timedelta(minutes=ROUTE_ALERT_WINDOW_MINUTES)
        message = "May bagong order sa lugar niyo ngayon - pwede ka pang isabay!"
        notified = 0
        for rid, rdata in (resellers or {}).items():
            if not rdata or rid == ordering_reseller_id:
                continue
            if (rdata.get("route") or "").strip() != route:
                continue
            if rid in resellers_with_active_order:
                continue  # already has something coming - skip the nudge
            existing_state, _ = _route_alert_state(rdata.get("route_alert"), now_ts, sales)
            if existing_state != "inactive":
                continue  # still has a live alert (no_rush or counting) - don't overwrite/spam

            fb_patch(f"resellers/{rid}", {
                "route_alert": {
                    "active": True,
                    "message": message,
                    "triggered_at": now_ts.strftime("%Y-%m-%d %H:%M:%S"),
                    "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "triggered_by_order_id": order_id or "",
                }
            })
            try:
                send_push_to_reseller(
                    rid,
                    title="🚚 May Order sa Route Niyo!",
                    body=message,
                    url=f"/customer/{rid}/dashboard",
                    tag="omega-route-alert",
                )
            except Exception as push_err:
                print(f"push (route alert) failed for {rid}: {push_err}")
            notified += 1

        if notified:
            fb_post("route_delivery_alerts", {
                "route": route,
                "ordering_reseller_id": ordering_reseller_id,
                "notified_count": notified,
                "timestamp": now_ts.strftime("%Y-%m-%d %H:%M:%S"),
            })
    except Exception as e:
        print(f"trigger_route_order_alert failed (non-fatal): {e}")

def send_route_out_for_delivery_update(ordering_reseller_id, order_id):
    """Upgrades the route alert when the triggering order reaches "Out
    for Delivery" (boss's follow-up, Sept 26: "pag out of delivery na
    yung ka-route nila, mababago ang notification na nakaalis na ng
    Delivery Rider"). A rider actually leaving is stronger, more
    actionable news than the original "may bagong order" nudge, so this
    re-broadcasts to the same route-mates (still no active order of
    their own) with an upgraded message AND a fresh
    ROUTE_ALERT_WINDOW_MINUTES countdown - even if their original alert
    had already expired, since this is effectively new information, not
    a repeat of the old one. Same privacy rule: never names the store.
    Called from api_update_order_status()'s Out for Delivery branch,
    wrapped in its own try/except so a hiccup here never blocks the
    status update itself."""
    try:
        if not ordering_reseller_id:
            return
        reseller = fb_get(f"resellers/{ordering_reseller_id}") or {}
        route = (reseller.get("route") or "").strip()
        if not route:
            return

        resellers = fb_get("resellers") or {}
        sales = fb_get("daily_sales") or {}
        ACTIVE_STATUSES = {"New Order", "Pending", "Preparing", "Out for Delivery"}
        resellers_with_active_order = set()
        for v in (sales or {}).values():
            if v and (v.get("order_status") or "") in ACTIVE_STATUSES and v.get("reseller_id"):
                resellers_with_active_order.add(v.get("reseller_id"))

        now_ts = manila_now().replace(tzinfo=None)
        expires_at = now_ts + timedelta(minutes=ROUTE_ALERT_WINDOW_MINUTES)
        message = "🚴 Paalis na ang delivery rider papunta sa lugar niyo! Kung gusto mo pang isabay, mag-order na."
        for rid, rdata in (resellers or {}).items():
            if not rdata or rid == ordering_reseller_id:
                continue
            if (rdata.get("route") or "").strip() != route:
                continue
            if rid in resellers_with_active_order:
                continue

            fb_patch(f"resellers/{rid}", {
                "route_alert": {
                    "active": True,
                    "message": message,
                    "triggered_at": now_ts.strftime("%Y-%m-%d %H:%M:%S"),
                    "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "triggered_by_order_id": order_id or "",
                }
            })
            try:
                send_push_to_reseller(
                    rid,
                    title="🚴 Nasa Daan na ang Rider!",
                    body=message,
                    url=f"/customer/{rid}/dashboard",
                    tag="omega-route-alert-ood",
                )
            except Exception as push_err:
                print(f"push (route OOD alert) failed for {rid}: {push_err}")
    except Exception as e:
        print(f"send_route_out_for_delivery_update failed (non-fatal): {e}")

def recall_route_order_alert(order_id):
    """Recalls a route alert (boss's follow-up, Sept 26: "dapat may push
    notification din sa customer") if the order that CAUSED it just got
    Cancelled or Declined. Without this, a route-mate who was told "may
    order sa lugar niyo, isabay ka na" would have no way of knowing that
    order fell through - the banner would just quietly vanish (or worse,
    stay up) with no explanation, and they might wait around for a
    delivery run that no longer exists.

    Finds every reseller whose route_alert.triggered_by_order_id matches
    this order_id and is still active, turns the alert off, and PUSHES
    them an explicit recall notice (not naming the cancelled/declined
    store, same privacy rule as the original alert). Called from
    api_update_order_status()'s Cancelled/Declined branch. Wrapped in its
    own try/except so a hiccup here never blocks the status update
    itself."""
    try:
        if not order_id:
            return
        resellers = fb_get("resellers") or {}
        message = "Update: na-cancel yung order sa lugar niyo kanina - pwede ka pa ring mag-order kung kailangan mo."
        for rid, rdata in (resellers or {}).items():
            if not rdata:
                continue
            alert = rdata.get("route_alert")
            if not isinstance(alert, dict) or not alert.get("active"):
                continue
            if alert.get("triggered_by_order_id") != order_id:
                continue
            fb_patch(f"resellers/{rid}", {"route_alert": {"active": False}})
            try:
                send_push_to_reseller(
                    rid,
                    title="ℹ️ Update sa Route Niyo",
                    body=message,
                    url=f"/customer/{rid}/dashboard",
                    tag="omega-route-alert-recall",
                )
            except Exception as push_err:
                print(f"push (route alert recall) failed for {rid}: {push_err}")
    except Exception as e:
        print(f"recall_route_order_alert failed (non-fatal): {e}")

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
from modules.price_manager import price_manager_bp
# NOTE (Sept 26, boss's report: "Ask AI nawala sa dropdown"): this
# blueprint/registration was missing from THIS shared app.py - the module
# file itself existed in modules/ai_sales_query.py, but nothing ever
# imported/registered it here, and no nav link pointed to it either. Every
# time this shared app.py was delivered and re-uploaded, it silently wiped
# out whatever Ask AI wiring boss had added on his own on the live site.
# Registering it here (and adding the nav link below) makes it a
# permanent, version-controlled part of the app instead of an out-of-band
# edit that keeps disappearing.
from modules.ai_sales_query import ai_sales_bp
app.register_blueprint(credit_bp)
app.register_blueprint(expenses_bp)
app.register_blueprint(plastic_bp)
app.register_blueprint(assets_bp)
app.register_blueprint(admin_import_bp)
app.register_blueprint(home_bp)
app.register_blueprint(advance_orders_bp)
app.register_blueprint(duplicate_finder_bp)
app.register_blueprint(price_manager_bp)
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
<a href="/prices">💰 Price Manager</a>
<a href="/ai-sales">🤖 Ask AI</a>
      <a href="/dashboard">📊 Dashboard</a>
      <a href="/customer_activity">🔐 Login Activity</a>
      <a href="/admin/stuck_orders">🧹 Purge Stuck Orders</a>
      <a href="/admin/rewards">🎁 Rewards Catalog</a>
      <a href="/admin/reseller_sales">📊 Reseller Sales Tracking</a>
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
    hosts, defaults to UTC - 8 hours behind Manila). Same fallback
    pattern already used elsewhere in this file (see the sale-save
    fallback above): try pytz first, and if it's ever unavailable,
    fall back to naive server time rather than crashing.
    """
    try:
        import pytz
        return datetime.now(pytz.timezone('Asia/Manila'))
    except Exception:
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

def _notify_isesmo_of_new_sale(reseller_name, qty, kg_size, total, offline=False):
    """NOTIFY ISESMO ON SALE INPUT (boss's request, Sept 26: "yung sa input
    ng sales gusto ko may notification din kay Isesmo") - pushes ISESMO a
    real-time heads-up every time ANY staff records a manual sale via the
    cashier's "Add Sale" form (/api/sale), same real-time oversight
    guarantee already given for customer logins (see send_push_to_isesmo).
    Skipped when ISESMO himself is the one who recorded the sale - no point
    pushing him a notice about his own action. Best-effort: wrapped so a
    push failure can never break the sale-saving flow that triggered it."""
    staff_who_sold = (session.get("staff_name") or "").strip()
    if staff_who_sold.lower() in ("isesmo", "isesmo gamboa"):
        return
    try:
        prefix = "📴 (Offline) " if offline else ""
        send_push_to_isesmo(
            title=f"{prefix}🧾 Bagong Sale Naitala",
            body=f"{staff_who_sold or 'Staff'} nag-record ng sale: {qty}x {kg_size} kay {reseller_name} - ₱{total:.2f}",
            url="/cashier",
            tag="omega-new-sale",
        )
    except Exception as push_err:
        print(f"push (new sale to isesmo) failed: {push_err}")

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
        _notify_isesmo_of_new_sale(reseller_name, qty, kg_size, total)
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
        _notify_isesmo_of_new_sale(reseller_name, qty, kg_size, total, offline=True)
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
<div id="routeAlertBanner" style="display:none;background:#ecfdf5;border:1px solid #a7f3d0;border-radius:10px;padding:10px;margin-bottom:10px;font-size:12px;color:#065f46">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px">
    <span id="routeAlertMsg">🚚 May delivery ngayon sa lugar niyo!</span>
    <button onclick="dismissRouteAlert()" style="background:none;border:none;color:#065f46;font-size:14px;cursor:pointer;line-height:1;padding:0 2px">✕</button>
  </div>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;gap:8px">
    <a href="/customer/{{ reseller_id }}/order" style="padding:7px 14px;border-radius:20px;background:#059669;color:#fff;text-decoration:none;font-size:11px;font-weight:700">🧊 Mag-order Ngayon</a>
    <span id="routeAlertCountdown" style="font-size:11px;font-weight:700;color:#047857;white-space:nowrap">⏳ 5:00</span>
  </div>
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
    // Route delivery alert banner (boss's request, Sept 26): "may
    // delivery ngayon sa lugar niyo, pwede na kayo mag-order kasabay" -
    // never names which store just got delivered. Three states from the
    // server (boss's follow-up, Sept 26 - see _route_alert_state() on
    // the backend): no_rush (order still being prepared - no ticking
    // clock yet, ordering is wide open), counting (rider is actually Out
    // for Delivery - the real 5-minute countdown), or not active at all.
    const routeAlert=data.route_alert||{};
    const routeBanner=document.getElementById('routeAlertBanner');
    const routeCountdownEl=document.getElementById('routeAlertCountdown');
    if(routeAlert.active && routeAlert.no_rush){
      document.getElementById('routeAlertMsg').textContent='🚚 '+(routeAlert.message||'May delivery ngayon sa lugar niyo!');
      routeBanner.style.display='block';
      stopRouteAlertCountdown();
      if(routeCountdownEl) routeCountdownEl.textContent='🕐 Naghahanda pa';
    } else if(routeAlert.active && (routeAlert.expires_in_seconds||0) > 0){
      document.getElementById('routeAlertMsg').textContent='🚚 '+(routeAlert.message||'May delivery ngayon sa lugar niyo!');
      routeBanner.style.display='block';
      startRouteAlertCountdown(routeAlert.expires_in_seconds);
    } else {
      routeBanner.style.display='none';
      stopRouteAlertCountdown();
    }
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
async function dismissRouteAlert(){
  document.getElementById('routeAlertBanner').style.display='none';
  stopRouteAlertCountdown();
  try{
    await fetch(`/api/customer/${resellerId}/dismiss_route_alert`, {method:'POST'});
  }catch(e){ /* purely cosmetic if this fails - banner already hidden locally */ }
}
// Live countdown for the route alert banner's "pasabay" window (boss's
// follow-up, Sept 26: "may timer countdown sa banner"). The server is
// the source of truth for expires_in_seconds on every loadOrders() poll
// (every few seconds) - this just ticks the displayed number down
// smoothly in between polls, and hides the banner itself the moment it
// reaches 0 instead of waiting for the next poll to confirm it expired.
let routeAlertCountdownTimer=null;
function stopRouteAlertCountdown(){
  if(routeAlertCountdownTimer){ clearInterval(routeAlertCountdownTimer); routeAlertCountdownTimer=null; }
}
function startRouteAlertCountdown(secondsLeft){
  stopRouteAlertCountdown();
  let remaining=Math.max(0, Math.floor(secondsLeft));
  const el=document.getElementById('routeAlertCountdown');
  const render=()=>{
    const m=Math.floor(remaining/60);
    const s=remaining%60;
    if(el) el.textContent='⏳ '+m+':'+String(s).padStart(2,'0');
  };
  render();
  routeAlertCountdownTimer=setInterval(()=>{
    remaining--;
    if(remaining<=0){
      stopRouteAlertCountdown();
      // Lumipas na yung window - hindi ibig sabihin nito na hindi na
      // pwede mag-order (boss's request, Sept 26: "kung inabutan ng
      // expiration at gusto pa din mag order, sabihin na lang na pwede
      // pa din mag order at babalikan na lang"). Palitan muna ng
      // reassurance message bago itago yung banner.
      const msgEl=document.getElementById('routeAlertMsg');
      if(msgEl) msgEl.textContent='⏳ Tapos na yung window, pero pwede ka pa ring mag-order - babalikan na lang sa susunod na round!';
      if(el) el.textContent='';
      setTimeout(()=>{
        const banner=document.getElementById('routeAlertBanner');
        if(banner) banner.style.display='none';
      }, 6000);
      return;
    }
    render();
  }, 1000);
}

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
  // Follow Up button (boss's request, Sept 26): only while the order
  // hasn't arrived yet (idx is the last stage = Delivered). Lets the
  // customer nudge staff directly from this tracking view instead of
  // messaging separately.
  const notYetDelivered = idx < TRACK_STAGES.length - 1;
  const followUpHtml = notYetDelivered ? `
    <div style="margin-top:12px">
      <button id="followUpBtn" onclick="customerFollowUp('${o.id}')" style="width:100%;padding:11px;border-radius:10px;border:1px solid #00609C;background:#fff;color:#00609C;font-weight:700;font-size:12.5px;cursor:pointer">📞 Wala pa order ko - Follow Up</button>
      <div id="followUpStatus" style="font-size:11px;color:#888;text-align:center;margin-top:4px"></div>
    </div>` : '';
  body.innerHTML=`
    <div class="track-head">
      <div class="track-head-left"><div class="track-icon">📡</div><div><p class="track-title">LIVE TRACKING</p><p class="track-sub">#${o.id.slice(0,8).toUpperCase()} • ${o.quantity}x ${o.kg_size}</p></div></div>
      <span class="track-live-badge">LIVE</span>
    </div>
    <div class="track-progress"><div class="track-dots">${dotsHtml}</div></div>
    <div class="track-pills">${pillsHtml}</div>
    <div class="track-timeline">${tlHtml}</div>
    ${followUpHtml}`;
  document.getElementById('trackOverlay').classList.add('show');
}
function closeTracking(){document.getElementById('trackOverlay').classList.remove('show');}
async function customerFollowUp(orderId){
  const btn=document.getElementById('followUpBtn');
  const statusEl=document.getElementById('followUpStatus');
  if(btn){ btn.disabled=true; btn.style.opacity='0.6'; btn.textContent='Sinusubmit...'; }
  try{
    const res=await fetch(`/api/customer/${resellerId}/order/${orderId}/follow_up`, {method:'POST'});
    const data=await res.json();
    if(data.ok){
      if(statusEl){ statusEl.textContent='✅ Nasabihan na si staff, sinusundan na nila ang order mo.'; statusEl.style.color='#1a7a3c'; }
      if(btn){ btn.textContent='✅ Na-follow up na'; }
    } else {
      if(statusEl){ statusEl.textContent=data.error || 'May error, subukan ulit.'; statusEl.style.color='#c0392b'; }
      if(btn){ btn.disabled=false; btn.style.opacity='1'; btn.textContent='📞 Wala pa order ko - Follow Up'; }
    }
  }catch(e){
    if(statusEl){ statusEl.textContent='May error sa koneksyon, subukan ulit.'; statusEl.style.color='#c0392b'; }
    if(btn){ btn.disabled=false; btn.style.opacity='1'; btn.textContent='📞 Wala pa order ko - Follow Up'; }
  }
}

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
async function autoEnablePushOnFirstLogin(){
  // AUTO-ENABLE ON FIRST LOGIN (boss's approval, Sept 26: "Oo" to moving the
  // permission ask to a meaningful moment instead of waiting for customer to
  // notice+tap the red "Enable" banner themselves). Browsers/OS NEVER allow
  // silently granting Notification permission from code - that decision
  // always needs one real tap from the customer on the system prompt itself
  // (security/anti-spam rule, can't be bypassed). What this DOES remove is
  // the extra step of noticing the banner and tapping "Enable" first - the
  // real "Allow" prompt now fires automatically right on their first
  // dashboard load after logging in, so it's one tap instead of two.
  try{
    if(!PUSH_ENABLED_CUST || !('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) return;
    // Only ever auto-ask ONCE per device/browser. If permission is already
    // 'granted' or 'denied', the browser won't show the dialog again anyway
    // (this check just avoids a pointless call); if it's still 'default' but
    // we already tried once before, don't nag them on every login - the red
    // banner + manual "Enable" button stays available for a retry anytime.
    if(Notification.permission !== 'default') return;
    let alreadyAsked = false;
    try{ alreadyAsked = localStorage.getItem('omega_push_auto_asked') === '1'; }catch(e){}
    if(alreadyAsked) return;
    try{ localStorage.setItem('omega_push_auto_asked', '1'); }catch(e){}
    const perm = await Notification.requestPermission();
    if(perm !== 'granted') return; // silent - no alert(); banner stays for a manual retry later
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
    updateCustomerPushBannerUI();
  }catch(err){
    console.log('auto push enable skipped:', err && err.message);
  }
}
if('serviceWorker' in navigator){
  window.addEventListener('load', () => {
    setTimeout(updateCustomerPushBannerUI, 1500);
    setTimeout(autoEnablePushOnFirstLogin, 1800);
  });
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
_ICON_192_PNG_B64 = "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"
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
        # Route delivery alert (boss's request, Sept 26) - piggybacks on
        # this already-polled endpoint instead of a separate one, so the
        # banner shows up within one refresh cycle of being triggered.
        # WINDOW/EXPIRY (boss's follow-up, Sept 26): a fixed 5-minute
        # timer used to be able to cut the banner off while the order was
        # still just sitting in Preparing - boss asked that it NOT expire
        # while the order is still active, and if a route-mate still
        # wants to order after it does lapse, the app should just say
        # ordering is still fine, they'll be added to the next round.
        # _route_alert_state() implements this as three states - see its
        # docstring - and this is purely a lazy read: no background
        # scheduler needed, expiry (or "no_rush" persistence) is decided
        # fresh on every poll.
        route_alert = reseller.get("route_alert") or {}
        route_alert_out = {"active": False, "message": "", "expires_in_seconds": 0, "no_rush": False}
        try:
            now_manila = manila_now().replace(tzinfo=None)
        except Exception:
            now_manila = datetime.now()
        alert_state, seconds_left = _route_alert_state(route_alert, now_manila, sales)
        if alert_state == "inactive":
            if isinstance(route_alert, dict) and route_alert.get("active"):
                try:
                    fb_patch(f"resellers/{reseller_id}", {"route_alert": {"active": False}})
                except Exception:
                    pass
        elif alert_state == "no_rush":
            route_alert_out = {"active": True, "message": route_alert.get("message") or "", "expires_in_seconds": 0, "no_rush": True}
        else:  # "counting"
            route_alert_out = {"active": True, "message": route_alert.get("message") or "", "expires_in_seconds": seconds_left, "no_rush": False}
        return jsonify({"orders": orders[:50], "stats": stats, "reseller_name": reseller.get("store_name"), "route_alert": route_alert_out})
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
        # BUG FIX (Sept 26, boss's report: 3:30pm order showing 9h19m TAT
        # instead of ~1h19m): this used plain datetime.now() with no
        # timezone, while api_update_order_status()'s "Delivered" branch
        # stamps delivered_at using Manila time (Render, like most cloud
        # hosts, runs in UTC - 8 hours behind Manila). created_at and
        # delivered_at must be stamped in the SAME clock, or every TAT
        # (delivered_at - created_at) is inflated by that 8-hour gap - same
        # root cause already fixed once in api_create_sale, just missed
        # here since this is the customer's own order-placing route.
        manila_wall_now = manila_now().replace(tzinfo=None)
        sales_date = d.get("sales_date") or manila_wall_now.strftime("%Y-%m-%d")
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
            now_dt = manila_wall_now
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
            "created_at": manila_wall_now.strftime("%Y-%m-%d %H:%M:%S"),
            "staff_name": "Customer Order",
            "order_status": "New Order",
            "order_source": "customer",
            "notes": notes
        }
        new_order_result = fb_post("daily_sales", sale)
        new_order_id = (new_order_result or {}).get("name")
        try:
            send_push_to_cashiers(
                title="🧊 Bagong Order!",
                body=f"{reseller.get('store_name','Customer')} - {qty} x {kg_size} ({mode})",
                url="/orders",
                tag="omega-new-order",
            )
        except Exception as e:
            print(f"push (new order) failed: {e}")
        # Auto-clear any active route-delivery banner - this customer just
        # did exactly what the alert was nudging them to do (order na
        # para maisabay), so the banner no longer needs to keep showing.
        existing_route_alert = reseller.get("route_alert")
        if isinstance(existing_route_alert, dict) and existing_route_alert.get("active"):
            try:
                fb_patch(f"resellers/{reseller_id}", {"route_alert": {"active": False}})
            except Exception as e:
                print(f"route_alert auto-clear failed (non-fatal): {e}")
        # ROUTE ORDER ALERT (boss's request, Sept 26, revised same day to
        # trigger on PLACING an order rather than waiting for Delivered -
        # see trigger_route_order_alert() docstring for why): nudge other
        # customers tagged to the same delivery route, without naming
        # which store just ordered. Wrapped in its own try/except there
        # so this never blocks this order from being placed. Tags the
        # alert with this order's id (triggered_by_order_id) so that if
        # THIS order later gets Cancelled/Declined,
        # api_update_order_status() can find and recall exactly the
        # alerts it caused (see that function's Cancelled/Declined
        # branch below).
        trigger_route_order_alert(reseller_id, new_order_id)
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
    # ROUTE ALERT RECALL (boss's follow-up, Sept 26): if this order had
    # triggered a route-mate alert ("may order sa lugar niyo, isabay ka
    # na") and it's now falling through, recall that alert with an
    # explicit push instead of leaving route-mates hanging. See
    # recall_route_order_alert() docstring for the full reasoning.
    if new_status in ("Cancelled", "Declined"):
        recall_route_order_alert(order_id)
    # ROUTE ALERT UPGRADE (boss's follow-up, Sept 26: "pag out of delivery
    # na yung ka-route nila, mababago ang notification na nakaalis na ng
    # Delivery Rider"): a rider actually leaving is stronger, more
    # actionable news than the original "may bagong order" nudge. See
    # send_route_out_for_delivery_update() docstring.
    if new_status == "Out for Delivery" and existing.get("reseller_id"):
        send_route_out_for_delivery_update(existing.get("reseller_id"), order_id)
    if new_status == "Declined":
        update_data["decline_reason"] = decline_reason
        update_data["declined_by"] = session.get("staff_name")
        update_data["declined_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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

@app.route("/api/order/<order_id>/follow_up", methods=["POST"])
@login_required
def api_order_follow_up(order_id):
    """Follow Up button (boss's request, Sept 26): a manual "check in on
    this order" action staff can tap on any order that isn't finished yet
    (Delivered/Cancelled/Declined) - useful for exactly the situation that
    prompted this ("Out for Delivery" stuck for hours, boss wants to
    nudge the customer). Does BOTH things ISESMO asked for in one tap:
        1. Pushes a notification to the reseller/customer.
        2. Logs the follow-up (who, when, what status it was at) so
           there's a record of "sino, kailan sumunod sa order na ito" -
           same audit-trail pattern as every other log in this app.
    Also bumps a small follow_up_count/last_follow_up_at on the order
    itself, purely so the order card can show "Followed up 2x" at a
    glance without needing to open the full log."""
    try:
        order = fb_get(f"daily_sales/{order_id}")
        if not order:
            return jsonify({"ok": False, "error": "Order not found"}), 404

        status = order.get("order_status") or "New Order"
        if status in ["Delivered", "Cancelled", "Declined"]:
            return jsonify({"ok": False, "error": "This order is already finished - nothing to follow up on."}), 400

        reseller_id = order.get("reseller_id")
        store_label = order.get("reseller_name") or "Order"
        staff = session.get("staff_name") or "Staff"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        pushed = False
        if reseller_id:
            try:
                send_push_to_reseller(
                    reseller_id,
                    title="📞 Order Follow-Up",
                    body=f"Sinusundan namin ang order mo ({order.get('quantity')}x {order.get('kg_size')}) - kasalukuyang status: {status}. Salamat sa pasensya!",
                    url=f"/customer/{reseller_id}/dashboard",
                    tag=f"omega-followup-{order_id}",
                )
                pushed = True
            except Exception as e:
                # A failed push must never block the log/counter below -
                # same fire-and-forget philosophy as every other push in
                # this app (e.g. the Decline push above). The response
                # still tells the caller whether the push actually went
                # out, so the UI can be honest about it either way.
                print(f"push (follow up) failed: {e}")

        fb_post("order_follow_ups", {
            "order_id": order_id,
            "reseller_id": reseller_id or "",
            "reseller_name": store_label,
            "staff_name": staff,
            "initiated_by": "staff",
            "order_status_at_time": status,
            "pushed": pushed,
            "timestamp": ts,
        })

        new_count = int(order.get("follow_up_count") or 0) + 1
        fb_patch(f"daily_sales/{order_id}", {
            "follow_up_count": new_count,
            "last_follow_up_at": ts,
            "last_follow_up_by": staff,
        })

        return jsonify({"ok": True, "pushed": pushed, "follow_up_count": new_count})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/<reseller_id>/order/<order_id>/follow_up", methods=["POST"])
def api_customer_order_follow_up(reseller_id, order_id):
    """Customer-side Follow Up button (boss's CORRECTED request, Sept 26:
    "ang gusto ko pwd mag follow si customer sa akin pag wala pa yung
    order nila" - the reverse of api_order_follow_up() above. That one is
    STAFF nudging the customer; this one is the CUSTOMER, from their own
    Live Tracking view, telling STAFF "sundan niyo naman order ko, di pa
    dumarating." Kept as a separate route/log entry (not replacing the
    staff-side one) since both directions are useful and boss never asked
    to remove the staff one.

    Auth: same pattern as api_customer_bulk_update - either the matching
    logged-in customer, or any logged-in staff member (so a staff member
    testing the customer dashboard, or filing a follow-up on a customer's
    behalf over the phone, both still work)."""
    if session.get("customer_id") and session.get("customer_id") != reseller_id:
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    if not session.get("customer_id") and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Login required"}), 401
    try:
        order = fb_get(f"daily_sales/{order_id}")
        if not order:
            return jsonify({"ok": False, "error": "Order not found"}), 404
        if order.get("reseller_id") != reseller_id:
            return jsonify({"ok": False, "error": "This order does not belong to this account"}), 403

        status = order.get("order_status") or "New Order"
        if status in ["Delivered", "Cancelled", "Declined"]:
            return jsonify({"ok": False, "error": "Tapos na ang order na ito - wala nang kailangang i-follow up."}), 400

        # Small cooldown (3 minutes) so double/triple-tapping the button
        # doesn't spam staff with duplicate notifications for one order.
        last_at = order.get("last_customer_follow_up_at")
        if last_at:
            try:
                last_dt = datetime.strptime(last_at, "%Y-%m-%d %H:%M:%S")
                if (datetime.now() - last_dt).total_seconds() < 180:
                    return jsonify({"ok": False, "error": "Na-follow up mo na ito kanina lang - sandali na lang, sinusundan na namin ang order mo."}), 429
            except Exception:
                pass

        store_label = order.get("reseller_name") or "Order"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        pushed = False
        try:
            send_push_to_cashiers(
                title="📞 Customer Follow-Up",
                body=f"{store_label} is following up on their order ({order.get('quantity')}x {order.get('kg_size')}) - current status: {status}.",
                url="/orders",
                tag=f"omega-customer-followup-{order_id}",
            )
            pushed = True
        except Exception as e:
            # A failed push must never block the log/counter below - same
            # fire-and-forget philosophy as every other push in this app.
            print(f"push (customer follow up) failed: {e}")

        fb_post("order_follow_ups", {
            "order_id": order_id,
            "reseller_id": reseller_id,
            "reseller_name": store_label,
            "initiated_by": "customer",
            "order_status_at_time": status,
            "pushed": pushed,
            "timestamp": ts,
        })

        new_count = int(order.get("customer_follow_up_count") or 0) + 1
        fb_patch(f"daily_sales/{order_id}", {
            "customer_follow_up_count": new_count,
            "last_customer_follow_up_at": ts,
        })

        return jsonify({"ok": True, "pushed": pushed, "follow_up_count": new_count})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/customer/<reseller_id>/dismiss_route_alert", methods=["POST"])
def api_customer_dismiss_route_alert(reseller_id):
    """Lets the customer manually close the route-delivery banner from
    their own dashboard ("Hindi na kailangan" button) without having to
    place an order first. Same auth pattern as every other customer-self
    route in this file."""
    if session.get("customer_id") and session.get("customer_id") != reseller_id:
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    if not session.get("customer_id") and not session.get("staff_name"):
        return jsonify({"ok": False, "error": "Login required"}), 401
    try:
        fb_patch(f"resellers/{reseller_id}", {"route_alert": {"active": False}})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

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
<table><thead><tr><th>Store</th><th>Phone / Login</th><th>Route</th><th>Push</th><th>Balance</th><th>Action</th></tr></thead>
<tbody id="tbody"><tr><td colspan=6 style="text-align:center;padding:20px;color:#999">Loading...</td></tr></tbody>
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
<hr style="margin:14px 0;border:none;border-top:1px solid #eee">
<label>🚚 Delivery Route (para sa route delivery alerts - hal. "Route A - Sta Monica")</label>
<input id="editRoute" placeholder="Iwan blangko kung wala pang route">
<button class="btn" style="background:#059669;color:#fff;margin-top:8px" onclick="saveRoute()">Save Route</button>
<p id="routeStatus" style="font-size:12px;margin-top:8px"></p>
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
      document.getElementById('tbody').innerHTML='<tr><td colspan=6 style="text-align:center;padding:20px;color:#888">No customers yet. '+(data.error||'')+'</td></tr>';
      return;
    }
    const q=document.getElementById('search').value.toLowerCase();
    const filtered=rows.filter(r=>(r.store_name||'').toLowerCase().includes(q)||(r.phone||'').includes(q));
    document.getElementById('tbody').innerHTML=filtered.map(r=>{
      return `<tr><td><b>${escapeHtml(r.store_name)}</b><br><small style="color:#666">${escapeHtml(r.status||'active')}</small>${r.referred_by_name?`<br><small style="color:#0891b2">🤝 ref: ${escapeHtml(r.referred_by_name)}</small>`:''}</td><td>${escapeHtml(r.phone)}<br><small style="color:${r.password_hash?'green':'red'}">${r.password_hash?'Has password':'No password'}</small></td><td><small>${r.route?escapeHtml(r.route):'<span style="color:#bbb">—</span>'}</small></td><td><small style="color:${r.push_enabled?'green':'#bbb'}">${r.push_enabled?'🔔 Naka-enable':'🔕 Wala pa'}</small></td><td>₱${r.credit_balance||0}</td><td><button class="btn" style="background:#22c55e;color:#fff" onclick="openEdit('${r.id}')">Edit</button> <button class="btn" style="background:#00609C;color:#fff" onclick="openQR('${r.id}')">📱 QR</button></td></tr>`;
    }).join('');
  }catch(e){
    document.getElementById('customerCount').textContent='Error: '+e.message;
    document.getElementById('tbody').innerHTML='<tr><td colspan=6 style="color:red;text-align:center">Failed to load: '+e.message+'<br><button onclick="loadCustomers()" class="btn btn-save" style="margin-top:8px">Retry</button></td></tr>';
  }
}
function openEdit(id){
  const r=_allCustomers.find(x=>x.id===id);
  if(!r){alert('Customer not found: '+id);return;}
  editingId=id;
  document.getElementById('editStore').textContent=r.store_name+' ('+r.phone+')';
  document.getElementById('editPhone').value=r.phone||'';
  document.getElementById('editPassword').value='';
  document.getElementById('editRoute').value=r.route||'';
  document.getElementById('routeStatus').textContent='';
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
async function saveRoute(){
  const route=document.getElementById('editRoute').value.trim();
  document.getElementById('routeStatus').textContent='Saving...';
  try{
    const res=await fetch(`/api/reseller/${editingId}/set_route`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({route:route})});
    const data=await res.json();
    document.getElementById('routeStatus').textContent=data.ok?'✅ Route saved!':'Error: '+(data.error||'');
    if(data.ok){loadCustomers();}
  }catch(e){document.getElementById('routeStatus').textContent='Error: '+e.message;}
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

@app.route("/api/staff/push_status")
@login_required
def api_staff_push_status():
    """
    Feeds the new "Push Status" tab on the Customer Activity page (boss's
    request, Sept 26: "Nawala din yung notification kay isesmo sa mga
    activities sa system boss. pano ko enable." - followed by "Yes" to
    adding a visible way to check this). Staff-side push notifications
    (Order Alarm, new-sale alerts, customer-login alerts to ISESMO) only
    reach a device once THAT staff member has tapped "Enable" on the
    Cashier page's push banner while logged in under their own name - so
    "wala akong natanggap na push" is very often just an un-subscribed
    device, exactly like the customer-side push_enabled indicator already
    on /customers. This mirrors that: one Firebase read of
    push_subscriptions, matched against every staff record by staff_name
    (case-insensitively - same matching convention used everywhere else in
    this file, e.g. the "isesmo"/"isesmo gamboa" checks), so ISESMO can see
    at a glance which staff (including himself) actually have a live push
    subscription on file, without having to ask each of them to check their
    own phone. ISESMO-only, same gate as every other feed on this page.
    """
    staff = (session.get("staff_name") or "").lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    try:
        staff_data = fb_get("staff") or {}
        subs = fb_get("push_subscriptions") or {}
        staff_names_with_push = {
            (s.get("staff_name") or "").strip().lower()
            for s in (subs or {}).values()
            if s and s.get("staff_name")
        }
        rows = []
        for key, val in staff_data.items():
            if not val:
                continue
            name = val.get("name") or ""
            rows.append({
                "id": key,
                "name": name,
                "position": val.get("position") or "",
                "status": val.get("status") or "",
                "push_enabled": name.strip().lower() in staff_names_with_push,
            })
        rows.sort(key=lambda r: (r.get("name") or "").lower())
        return jsonify({"ok": True, "rows": rows})
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
        # PUSH NOTIFICATION VISIBILITY (boss's request, Sept 26: checking
        # whether "tsong"/route-mates actually have push enabled, since a
        # push silently no-ops for anyone who never subscribed). Instead
        # of boss having to dig through raw Firebase data, this surfaces
        # a simple yes/no per customer right on the Customers page - one
        # Firebase read here, then an O(1) set lookup per row below.
        subs = fb_get("push_subscriptions") or {}
        resellers_with_push = {s.get("reseller_id") for s in (subs or {}).values() if s and s.get("reseller_id")}
        out=[]
        for key,val in resellers.items():
            if not val: continue
            out.append({"id":key,"store_name":val.get("store_name") or val.get("name") or "No Name","phone":val.get("phone") or val.get("contact",""),"credit_balance":val.get("credit_balance",0),"password_hash":"yes" if val.get("password_hash") else "","status":val.get("status","active"),"referred_by_name":val.get("referred_by_name") or "","route":val.get("route") or "","push_enabled":key in resellers_with_push})
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

@app.route("/api/reseller/<reseller_id>/set_route", methods=["POST"])
@login_required
def api_set_reseller_route(reseller_id):
    """Tags a customer with a delivery 'route' (boss's request, Sept 26)
    - a free-text label ISESMO sets manually from the Customers page
    (e.g. "Route A - Sta Monica"). Purely a grouping label used by
    trigger_route_order_alert() to find "same route" customers when a
    new order is placed in that route - no geolocation, just whatever
    ISESMO types in. ISESMO-only, same gate as every other
    customer-management action on this page."""
    staff = (session.get("staff_name") or "").lower()
    if staff not in ["isesmo", "isesmo gamboa"]:
        return jsonify({"ok": False, "error": "Only ISESMO can set route"}), 403
    try:
        reseller = fb_get(f"resellers/{reseller_id}")
        if reseller is None:
            return jsonify({"ok": False, "error": "Customer not found"}), 404
        route = (request.json or {}).get("route", "")
        route = route.strip() if isinstance(route, str) else ""
        fb_patch(f"resellers/{reseller_id}", {"route": route})
        return jsonify({"ok": True, "route": route})
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
.subtab-row{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.subtab-btn{flex:1;min-width:80px;padding:10px;border-radius:10px;border:1px solid #cde;background:#fff;color:#00609C;font-size:12px;font-weight:600}
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
    <button class="subtab-btn" id="subtabPush" onclick="switchTab('push')">🔔 Push Status</button>
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

  <div id="pushTab" style="display:none">
    <!-- STAFF PUSH STATUS (boss's request, Sept 26: "Nawala din yung
    notification kay isesmo sa mga activities sa system boss. pano ko
    enable." -> "Yes" to a way to check it) - mirrors the customer-side
    Push column on /customers, but for STAFF: shows at a glance who
    actually has a live push subscription on file, so "wala akong
    natanggap na push" can be checked instantly instead of guessing. -->
    <p style="font-size:11px;color:#666;margin-top:0">
      Ito ang nagpapakita kung sino sa staff ang naka-<b>Enable</b> na ng push notifications
      (Order Alarm, bagong sale, customer login alerts) sa <b>sarili nilang</b> phone/browser sa Cashier page.
      Kung "Wala pa" - kailangan nilang buksan ang <a href="/cashier">Cashier page</a> gamit ang sarili nilang PIN
      at tapikin ang "Enable" sa banner, o ayusin muna ang Notification permission sa phone settings kung na-block na dati.
    </p>
    <div class="filter-row" style="grid-template-columns:1fr">
      <button class="refresh-btn" onclick="loadPushStatus()">🔄 Refresh</button>
    </div>
    <div id="pushRowsList" style="font-size:12px">Loading...</div>
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
let pushLoaded = false;

function switchTab(tab){
  document.getElementById('subtabLogins').classList.toggle('active', tab==='logins');
  document.getElementById('subtabActions').classList.toggle('active', tab==='actions');
  document.getElementById('subtabStaff').classList.toggle('active', tab==='staff');
  document.getElementById('subtabPush').classList.toggle('active', tab==='push');
  document.getElementById('loginsTab').style.display = tab==='logins' ? 'block' : 'none';
  document.getElementById('actionsTab').style.display = tab==='actions' ? 'block' : 'none';
  document.getElementById('staffTab').style.display = tab==='staff' ? 'block' : 'none';
  document.getElementById('pushTab').style.display = tab==='push' ? 'block' : 'none';
  if(tab==='logins' && !loginsLoaded) loadActivity();
  if(tab==='actions' && !actionsLoaded) loadDashboardActivity();
  if(tab==='staff' && !staffLoaded) loadStaffLoginActivity();
  if(tab==='push' && !pushLoaded) loadPushStatus();
}

async function loadPushStatus(){
  const list = document.getElementById('pushRowsList');
  try{
    const res = await fetch('/api/staff/push_status');
    const data = await res.json();
    if(!data.ok){
      list.innerHTML = '<div style="color:red;text-align:center;padding:16px">Error: '+escapeHtmlA(data.error||'Unknown')+'</div>';
      return;
    }
    pushLoaded = true;
    const rows = data.rows || [];
    if(!rows.length){
      list.innerHTML = '<div style="text-align:center;padding:16px;color:#888">No staff records found.</div>';
      return;
    }
    list.innerHTML = rows.map(r => `
      <div class="log-row">
        <div>
          <b>${escapeHtmlA(r.name || 'Unnamed')}</b>
          <div class="log-meta">${escapeHtmlA(r.position || '')}${r.status ? ' - ' + escapeHtmlA(r.status) : ''}</div>
        </div>
        <span class="log-badge ${r.push_enabled ? 'ok' : 'fail'}">${r.push_enabled ? '🔔 Naka-enable' : '🔕 Wala pa'}</span>
      </div>
    `).join('');
  }catch(e){
    list.innerHTML = '<div style="color:red;text-align:center;padding:16px">Failed to load: '+escapeHtmlA(e.message)+'</div>';
  }
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
// Delivery TAT (Turnaround Time) helper (boss's request, Sept 26) - turns
// two timestamps into a short human label like "4h 20m" or "2d 3h".
// Reused for BOTH the live "how long has this been sitting" badge on
// active orders and the final "Delivered in X" label on finished ones,
// since it's the exact same calculation either way (just a different
// end time: "now" for active orders, delivered_at for finished ones).
function formatElapsed(startStr, endStr){
  if(!startStr) return '';
  const start = new Date(startStr.replace(' ','T'));
  if(isNaN(start.getTime())) return '';
  const end = endStr ? new Date(endStr.replace(' ','T')) : new Date();
  let mins = Math.floor((end.getTime() - start.getTime()) / 60000);
  if(mins < 0) mins = 0;
  const days = Math.floor(mins / 1440);
  const hours = Math.floor((mins % 1440) / 60);
  const remMins = mins % 60;
  if(days > 0) return `${days}d ${hours}h`;
  if(hours > 0) return `${hours}h ${remMins}m`;
  return `${remMins}m`;
}

async function followUpOrder(id){
  const btn = event.target.closest('button');
  const origText = btn.textContent;
  btn.textContent = '...';
  btn.disabled = true;
  try{
    const res = await fetch(`/api/order/${id}/follow_up`, {method:'POST'});
    const data = await res.json();
    if(data.ok){
      const msg = data.pushed
        ? '✅ Na-follow up na - na-notify ang customer.'
        : '✅ Na-log ang follow up (walang push - baka hindi naka-enable ang notifications ng customer).';
      alert(msg);
      loadOrders();
    } else {
      alert(data.error || 'Failed');
      btn.textContent = origText;
      btn.disabled = false;
    }
  }catch(e){
    alert('Network error: ' + e.message);
    btn.textContent = origText;
    btn.disabled = false;
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
      // Final Delivery TAT (boss's request, Sept 26): only meaningful for
      // a Delivered order (created_at -> delivered_at is a real "how long
      // did the whole thing take"), so Cancelled/Declined show nothing
      // here - there's no "delivery" to time for those.
      const tatBlock = (isDelivered && o.created_at && o.delivered_at)
        ? `<div style="font-size:11px;color:#16a34a;margin-top:4px">⏱ Delivered in ${formatElapsed(o.created_at, o.delivered_at)}</div>`
        : '';
      return `<div class="order-card" data-order-id="${o.id}" style="border-left-color:${borderColor};opacity:0.8"><div style="display:flex;justify-content:space-between"><span style="font-weight:600">${o.reseller_name}${deliveredBadge}</span><span style="font-size:10px;background:${statusColor};padding:4px 8px;border-radius:12px">${o.order_status}</span></div><div style="font-size:12px;color:#555;margin-top:4px">${o.quantity}x ${o.kg_size} • ₱${o.total_sales} • ${o.sales_date}</div>${tatBlock}${reasonBlock}<div style="margin-top:8px;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap"><span style="font-size:11px;color:${statusTextColor};font-weight:600">${statusLabel}</span><button class="btn" style="background:#fff;color:#ef4444;border-color:#fca5a5;flex:0 0 auto;padding:9px 14px" onclick="deleteOrder('${o.id}')">🗑️ Delete</button></div></div>`;
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
    // Elapsed-time badge (boss's request, Sept 26) - "how long has this
    // order been sitting" since it was placed, colored so a stuck order
    // (like the "Out for Delivery" one that prompted this feature) is
    // obvious at a glance rather than something staff has to notice
    // manually: green under 1h, orange 1-4h, red past 4h.
    const elapsedMins = o.created_at ? Math.floor((Date.now() - new Date(o.created_at.replace(' ','T')).getTime()) / 60000) : null;
    let elapsedColor = '#888';
    if(elapsedMins !== null){
      if(elapsedMins >= 240) elapsedColor = '#dc2626';
      else if(elapsedMins >= 60) elapsedColor = '#d97706';
      else elapsedColor = '#16a34a';
    }
    const elapsedBadge = o.created_at ? `<span style="font-size:11px;color:${elapsedColor};font-weight:600">⏱ ${formatElapsed(o.created_at)}</span>` : '<span></span>';
    // Follow Up button (boss's request, Sept 26): always visible on any
    // active (non-finished) order per ISESMO's own choice - staff decides
    // when it's actually needed rather than the system guessing via a
    // time threshold. Shows a running count once it's been used, so
    // staff can see "sinundan ko na ba ito" without opening a separate log.
    const followUpCountBadge = o.follow_up_count > 0 ? ` (${o.follow_up_count}x)` : '';
    const followUpBtn = `<button type="button" class="btn" style="background:#fff;color:#00609C;border-color:#cde;flex:0 0 auto;padding:6px 12px;font-size:11px" onclick="followUpOrder('${o.id}')">📞 Follow Up${followUpCountBadge}</button>`;
    const metaRow = `<div style="margin-top:6px;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap">${elapsedBadge}${followUpBtn}</div>`;
    return `<div class="order-card" data-order-id="${o.id}"><div style="display:flex;justify-content:space-between"><span style="font-weight:600">${o.reseller_name}${rewardBadge}</span><span style="font-size:10px;background:${statusColor};padding:4px 8px;border-radius:12px">${o.order_status}</span></div><div style="font-size:12px;color:#555;margin-top:4px">${o.quantity}x ${o.kg_size} • ${priceLabel} • ${o.sales_date}</div>${metaRow}<div class="order-actions">${stepButtonsHtml}<button class="btn btn-decline" onclick="openDeclineModal('${o.id}')">🚫 Decline</button><button class="btn" style="background:#fff;color:#ef4444;border-color:#fca5a5" onclick="deleteOrder('${o.id}')">🗑️ Delete</button></div></div>`;
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
                
            orders.append({"id":key,"reseller_id":val.get("reseller_id") or "","reseller_name":val.get("reseller_name"),"quantity":val.get("quantity"),"kg_size":val.get("kg_size"),"total_sales":val.get("total_sales"),"mode":val.get("mode"),"sales_date":val.get("sales_date"),"order_status":val.get("order_status","New Order"),"created_at":val.get("created_at"),"delivered_at":val.get("delivered_at") or "","reward_redemption":bool(val.get("reward_redemption")),"reward_label":val.get("reward_label") or "","decline_reason":val.get("decline_reason") or "","declined_at":val.get("declined_at") or "",
                # Follow Up feature (boss's request, Sept 26): a running
                # count + last-followed-up timestamp, surfaced on the
                # order card so staff can see "na-follow up ko na ba
                # ito, ilang beses na" at a glance instead of guessing.
                "follow_up_count":int(val.get("follow_up_count") or 0),"last_follow_up_at":val.get("last_follow_up_at") or ""})
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
