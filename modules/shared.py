"""
Shared helpers for Omega Ice feature modules (Blueprints).

Every module needs the same handful of things app.py already has -
Firebase read/write helpers and the staff-login guards - so instead of
each module reaching back into app.py (which would risk a circular
import, since app.py is the one that imports and registers these
modules), they live here ONCE and both app.py and the modules can use
them from a single source of truth.

IMPORTANT: this assumes firebase_admin has already been initialized by
the time any of these functions actually run - app.py initializes it
at import time, before it imports/registers any module blueprint, so
db.reference() below just reaches the existing global Firebase app. It
does NOT need (and must NOT do) its own firebase_admin.initialize_app().
"""
from datetime import datetime
from functools import wraps

from flask import session, redirect, url_for, request
from firebase_admin import db


# ---------- Firebase Realtime Database helpers (identical behavior to
# app.py's own fb_get/fb_post/fb_put/fb_patch/fb_delete - kept as exact
# copies here rather than imported from app.py, precisely to avoid a
# circular import: app.py -> modules.credit -> app.py would fail). ----------

def fb_get(path):
    try:
        return db.reference(path).get()
    except Exception as e:
        print(f"GET {path} error: {e}")
    return None


def fb_post(path, data):
    try:
        new_ref = db.reference(path).push(data)
        return {"name": new_ref.key}
    except Exception as e:
        print(f"POST {path} error: {e}")
    return None


def fb_put(path, data):
    try:
        db.reference(path).set(data)
        return data
    except Exception as e:
        print(f"PUT {path} error: {e}")
    return None


def fb_patch(path, data):
    try:
        db.reference(path).update(data)
        return data
    except Exception as e:
        print(f"PATCH {path} error: {e}")
    return None


def fb_delete(path):
    try:
        db.reference(path).delete()
        return True
    except Exception as e:
        print(f"DELETE {path} error: {e}")
    return False


# ---------- Auth guards (same rules as app.py's own decorators) ----------

def login_required(view):
    """Any logged-in staff member. Mirrors app.py's own login_required
    exactly so a module route behaves identically to a route defined
    directly in app.py."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("staff_name"):
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    return wrapped


def isesmo_only(view):
    """Stricter than login_required - only the Isesmo account. Same
    allow-list app.py already uses elsewhere (customers page, kiosk
    unlock, etc.), kept here so it stays consistent across every module."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("staff_name"):
            return redirect(url_for("login_page"))
        staff = (session.get("staff_name") or "").strip().lower()
        if staff not in ["isesmo", "isesmo gamboa"]:
            return "<h3>Access Denied</h3><p>Only ISESMO can access this page.</p><a href='/cashier'>Back</a>", 403
        return view(*args, **kwargs)
    return wrapped


# ---------- Per-staff PAGE ACCESS (boss's request, Oct 7: "pwd
# magseset ano lang pwd access sa app" - ISESMO can restrict exactly
# which feature pages a given staff member is allowed to open, via
# the Manage Staff page). ----------
#
# Scope decision (confirmed with boss): PAGE-level only - the actual
# GET page routes listed below - not every backing API call. Several
# of those APIs are shared across pages that are NOT part of this list
# (e.g. /api/sales/by_period also powers the always-open Cashier page's
# own "Today's Sales" period picker, not just the gated Sales Dashboard
# page) - gating by URL prefix at that level would risk silently
# breaking a shared feature for every staff member, not just the one
# ISESMO meant to restrict. Sales/Cashier itself is also intentionally
# NEVER gated (boss's answer: it's every staff member's core job).
#
# Firebase shape: staff/<key>/allowed_pages = ["machines","expenses",...]
# or ABSENT entirely. Absent (the default, and every staff member's
# state before this feature existed) means FULL access - this is an
# opt-in RESTRICTION, not an opt-in grant, so shipping it never
# silently locks anyone out. Only once ISESMO explicitly saves a
# staff member's checklist on /admin/staff does enforcement kick in
# for that one staff member - an empty list means "no extra pages at
# all", not "unset".
STAFF_PAGE_KEYS = [
    ("home", "🏠 Home"),
    ("machines", "🏭 Machines"),
    ("credit", "💳 Utang (Credit)"),
    ("expenses", "💸 Expenses"),
    ("plastic", "📦 Plastic"),
    ("assets", "🏗️ Fixed Assets"),
    ("advance_orders", "🎉 Advance Orders"),
    ("duplicates", "🔍 Duplicate Finder"),
    ("dashboard", "📊 Sales Dashboard"),
    ("games", "🎮 Mini-Games"),
]


def staff_has_page_access(page_key):
    """True if the CURRENTLY LOGGED-IN staff member (from the Flask
    session) may open this feature. ISESMO always has full access and
    is never restrictable here - this is his own control panel. A
    staff record ISESMO hasn't looked up (or that can't be read right
    now) fails OPEN, not closed - a lookup hiccup must never lock a
    staff member out of a page that was working a moment ago."""
    staff_name = (session.get("staff_name") or "").strip().lower()
    if staff_name in ("isesmo", "isesmo gamboa"):
        return True
    if not staff_name:
        return False
    staff_id = session.get("staff_id")
    record = fb_get(f"staff/{staff_id}") if staff_id else None
    if not isinstance(record, dict):
        return True
    allowed = record.get("allowed_pages")
    if allowed is None:
        return True
    return page_key in allowed


def page_access_required(page_key):
    """Decorator for a staff-facing PAGE route (HTML, not an API JSON
    endpoint) - gates it by staff_has_page_access(page_key). Does its
    own login check too (same as isesmo_only above), so it works
    standalone without needing a separate @login_required."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("staff_name"):
                return redirect(url_for("login_page"))
            if not staff_has_page_access(page_key):
                return (
                    "<h3>Access Denied</h3>"
                    "<p>Wala kang access sa page na ito. Makipag-ugnayan kay ISESMO kung kailangan mo ito.</p>"
                    "<a href='/cashier'>Back to Sales</a>",
                    403,
                )
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------- Small time helpers used across modules ----------

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str():
    return datetime.now().strftime("%Y-%m-%d")


def log_customer_activity(reseller_id, store_name, action, details=""):
    """Duplicate of app.py's own log_customer_activity (see its
    docstring there for the full 'why' - ISESMO's request, Sept 22, for
    an ISESMO-only audit trail of everything a reseller does from their
    own dashboard). Kept as an exact copy here rather than imported from
    app.py, same circular-import reason as every other helper in this
    file. Uses plain now_str() (server time) rather than app.py's
    manila_now(), matching how every other timestamp already written by
    this module's own routes (advance_orders.py etc.) is stored - so a
    booking made through a module route logs at the same clock as the
    booking itself."""
    try:
        entry = {
            "reseller_id": reseller_id,
            "store_name": store_name or "",
            "action": action,
            "details": details or "",
            "ip": request.remote_addr or "unknown",
            "timestamp": now_str(),
        }
        fb_post("customer_activity_logs", entry)
    except Exception as e:
        print(f"log_customer_activity (shared) error: {e}")
