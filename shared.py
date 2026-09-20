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

from flask import session, redirect, url_for
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


# ---------- Small time helpers used across modules ----------

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str():
    return datetime.now().strftime("%Y-%m-%d")
