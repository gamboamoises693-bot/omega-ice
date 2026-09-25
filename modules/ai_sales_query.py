"""
modules/ai_sales_query.py
----------------------------------------------------------------------------
"Ask AI" (originally "Ask Sales", kept the same module/route names for
backward compatibility - see the Routes section) - a natural-language chat
box (Taglish or English) that answers questions about Omega Ice's own data:
sales, resellers, loyalty points/rewards, staff, machines/equipment, and
expenses (including plastic purchases/usage).
Examples:
    "magkano benta ko last May?"          (sales)
    "total sales this week"               (sales)
    "sino top reseller this month?"       (sales)
    "credit balance ni [store name]?"     (resellers)
    "listahan ng resellers"               (resellers)
    "sino top loyalty points?"            (loyalty & rewards)
    "ano available rewards?"              (loyalty & rewards)
    "sino active staff?"                  (staff)
    "aling machine overdue sa PM?"        (machines & equipment)
    "total harvest this week?"            (machines & equipment)
    "electricity bill ko last month?"     (expenses)
    "breakdown ng expenses this year"     (expenses)
    "ilang plastic nabili last month?"    (expenses)

PLUS: Custom Queries (Sept 26 2026) - ISESMO can register his OWN
question -> fixed-answer pairs directly from the Ask AI page (the
"Custom Queries" panel), stored in Firebase under `custom_queries/{id}`.
This is checked as a last-resort fallback, only once every hardcoded
topic above AND the sales date-parser have already failed to match a
question - see the big comment block above _find_matching_custom_query
for the full design/safety rationale, and _handle_custom_query for how
it's answered (v1 = static text only; a "live number" report-builder
version can be layered in later via the same `query_type` field).

Every topic above is answered 100% locally (Firebase fetch + plain Python
filter/aggregate/format) - see the big comment block above _detect_topic
for the full design rationale on why this works even with zero internet
access to any AI service. Claude is used ONLY as a fallback for freeform
date phrasing within the sales topic (see _ask_claude_for_date_range).

DESIGN - why the math is split the way it is (important, read before editing):
    This feature NEVER lets the AI compute totals itself. An LLM asked to
    "add up these numbers" can silently get arithmetic wrong (hallucinate),
    which is unacceptable for real peso figures. Instead:

    1. AI (Claude) job #1 and ONLY job: read the natural-language question
       and figure out WHICH DATE RANGE is being asked about. Returns
       strict JSON, nothing else.
    2. Plain Python (this file) does 100% of the actual data work: pulling
       records from Firebase and summing/grouping them. Deterministic,
       testable, never hallucinates a peso.
    3. Plain Python formats the final reply text too (no second AI call
       needed) - faster, cheaper (1 API call per question instead of 2),
       and removes any chance of the AI mangling a number while "explaining"
       it.

    The Firebase filtering rules below (skip `deleted`, skip `archived`
    unless it's a customer order / include_in_all_time / an all-time query)
    are copied EXACTLY from the /api/sales/by_period endpoint in app.py,
    which that file's own comments call the app's "single source of truth"
    for sales filtering (see its ROOT-CAUSE FIX comment, Sept 19). Copying
    it here - instead of writing new filtering rules from scratch - is
    deliberate: it's what makes this chat box's numbers always agree with
    what ISESMO already sees on the Sales screen, instead of drifting out
    of sync with a second, slightly-different copy of the same math.

SETUP REQUIRED: NONE - this feature is 100% OFFLINE by default (Sept 26
    2026, ISESMO's explicit call). Every topic (sales, resellers, loyalty,
    staff, machines) is answered by local Firebase fetch + Python math,
    zero AI/internet dependency, zero setup, zero cost.

    Claude is an OPTIONAL enhancement, used only for genuinely freeform
    sales date phrasing the local parser can't confidently match - and
    only even attempted if ANTHROPIC_API_KEY is set. To turn it on later:
    1. Get an Anthropic (Claude) API key: https://console.anthropic.com/
       (needs prepaid usage credits - see _ask_claude_for_date_range
       below for the history of why this replaced the earlier Gemini
       integration, which itself is no longer used anywhere in this file.)
    2. On Render (or wherever this deploys): Environment > add
       ANTHROPIC_API_KEY = <your key>
       (optional) CLAUDE_MODEL = claude-haiku-4-5-20251001   <- default if unset
    Leave ANTHROPIC_API_KEY unset (or blank) to stay fully offline - no
    error, no broken feature, just a slightly less flexible sales-date
    parser for oddly-phrased questions.
    3. No new pip package needed - this uses `requests`, already a
       dependency of app.py.

ACCESS: ISESMO-only for now (same convention as /admin/reseller_sales,
/admin/rewards, /customers, etc. in app.py). To also allow OMEGA (admin),
add "omega" to ALLOWED_STAFF below.

Integration in app.py (2 lines, placed alongside the other `from modules.*`
imports / register_blueprint calls):
    from modules.ai_sales_query import ai_sales_bp
    app.register_blueprint(ai_sales_bp)
----------------------------------------------------------------------------
"""

import os
import re
import time
import json
import calendar
from datetime import datetime, date, timedelta

# Timezone for "today" (Asia/Manila). Uses the stdlib `zoneinfo` (Python 3.9+)
# instead of the third-party `pytz` package, and is imported ONCE here at
# module load time (i.e. when gunicorn boots the worker) rather than inside
# a per-request function. This matters: a lazy `import` executed on every
# request that hits this code path is exactly what caused a real production
# bug (Sept 25, 2026) - a `WORKER TIMEOUT` inside `import pytz`, which
# crashed the gunicorn worker (SystemExit propagates past `except Exception`)
# and turned into a 502 for every single "Ask Sales" request. Doing the
# import once, up front, at the top of the file removes that failure mode
# entirely - there is no import left to hang or race during a request.
try:
    from zoneinfo import ZoneInfo
    _MANILA_TZ = ZoneInfo("Asia/Manila")
except Exception:
    # Extremely unlikely on Linux (Render's containers ship IANA tzdata),
    # but fall back to naive local time rather than crash the whole module.
    _MANILA_TZ = None

import requests
from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template_string

# --- Firebase access -------------------------------------------------------
# app.py's own comment says shared Firebase helpers normally live in
# modules/shared.py - if you already have that file with an equivalent
# fb_get(path), feel free to replace the block below with:
#     from modules.shared import fb_get
# Kept self-contained here (same behavior as app.py's own fb_get) so this
# module works standalone even if modules/shared.py's exact function names
# turn out to differ.
from firebase_admin import db as _fb_db


def fb_get(path):
    try:
        return _fb_db.reference(path).get()
    except Exception as e:
        print(f"[ai_sales_query] GET {path} error: {e}")
        return None


# --- Expenses topic: reuse the REAL per-row amount formula ----------------
# modules/expenses.py's own _effective_amount(row) is the single source of
# truth for "how much did this expense row actually cost" (Electricity rows
# use current_bill when it's set, everything else uses price - see that
# module's docstring). Importing it directly (instead of re-deriving the
# same if/else here) means the Expenses topic below can NEVER silently
# drift out of sync with what ISESMO sees on the real Expenses page. The
# except fallback below is ONLY a safety net in case modules/expenses.py
# ever gets renamed/moved - it mirrors the exact same formula so this file
# still degrades gracefully instead of crashing the whole "Ask AI" feature.
try:
    from modules.expenses import _effective_amount
except Exception as _e:
    print(f"[ai_sales_query] could not import _effective_amount from modules.expenses, using local fallback: {_e}")

    def _effective_amount(row):
        row = row or {}
        if row.get("category") == "Electricity" and float(row.get("current_bill") or 0) > 0:
            return float(row.get("current_bill") or 0)
        return float(row.get("price") or 0)


ai_sales_bp = Blueprint("ai_sales", __name__)

ALLOWED_STAFF = {"isesmo", "isesmo gamboa"}  # add "omega" here to also allow the admin account

CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
# Small, fast, cheap model on purpose - this call only ever has ONE narrow
# job (read a question, output a strict JSON date range), never anything
# that needs deep reasoning, so there's no reason to pay for or wait on a
# bigger model here. Anthropic (like Google before it) can retire/rename
# model strings over time - the exact same "404 that looks like a config
# bug but is actually a model-name problem" lesson learned from the old
# Gemini integration applies here too. If this ever starts erroring with
# "model not found" (or similar), check
# https://docs.claude.com/en/docs/about-claude/models for the current
# model name before assuming the code broke, and override via the
# CLAUDE_MODEL env var on Render (no redeploy needed) while updating this
# default.
#
# Provider history for this project: this feature originally called
# Google's Gemini API (see git history / earlier deploys before Sept 26
# 2026 if you ever need to compare). Switched to Anthropic's Claude API
# at ISESMO's explicit request - same design (1 narrow JSON-extraction
# call, conservative single-retry, permanent status/body logging on
# failure), just a different provider. See _ask_claude_for_date_range.


# ---------------------------------------------------------------------------
# Auth guard (mirrors app.py's own login_required + the ISESMO-only checks
# already used on /customers, /admin/reseller_sales, /admin/rewards, etc.)
# ---------------------------------------------------------------------------
def isesmo_required(view):
    def wrapped(*args, **kwargs):
        staff = (session.get("staff_name") or "").strip().lower()
        if not staff:
            return redirect(url_for("login_page"))
        if staff not in ALLOWED_STAFF:
            return jsonify({"ok": False, "error": "Forbidden - ISESMO only"}), 403
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


# ---------------------------------------------------------------------------
# Small date/number helpers
# ---------------------------------------------------------------------------
def _manila_today():
    if _MANILA_TZ is not None:
        return datetime.now(_MANILA_TZ).date()
    return datetime.now().date()


def _manila_now_iso():
    """Full timestamp (not just date) for created_at/updated_at bookkeeping
    on Custom Queries records below - same Manila-aware source as
    _manila_today(), just with the time-of-day kept."""
    if _MANILA_TZ is not None:
        return datetime.now(_MANILA_TZ).isoformat()
    return datetime.now().isoformat()


def _parse_date(d):
    """Same permissive YYYY-MM-DD[...] parser used throughout app.py."""
    if not d:
        return None
    try:
        return datetime.strptime(str(d)[:10], "%Y-%m-%d")
    except Exception:
        return None


def _safe_parse_iso_date(d):
    dt = _parse_date(d)
    return dt.date() if dt else None


def _kg_value(kg_label):
    """'5Kg' -> 5.0, matches the same parser used by /api/sales/by_period."""
    try:
        return float(str(kg_label).lower().replace("kg", "").strip())
    except Exception:
        return 0.0


def _peso(n):
    try:
        return f"₱{float(n):,.2f}"
    except Exception:
        return "₱0.00"


# ---------------------------------------------------------------------------
# Step 1: AI reads the question, figures out the date range (JSON only)
# ---------------------------------------------------------------------------
def _extract_json(text):
    """Defensive fallback in case the model wraps JSON in ```fences``` or
    adds stray text despite responseMimeType=application/json."""
    text = (text or "").strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Local (no-AI) fast path for the common, unambiguous date phrases - added
# Sept 26 2026 after the 503/429 investigation. Speed AND resilience: most
# real usage is "today", "this week", "this month", "all time", or a plain
# month name - all fully deterministic, so computing them in Python is both
# instant (no network round-trip to Claude) and immune to the AI service
# being overloaded or rate-limited (see _ask_claude_for_date_range's retry
# comment). The AI is now only actually called for genuinely freeform/
# ambiguous questions it's needed for. Mirrors the exact same date-range
# RULES given to Claude in the prompt below - if you change one, change
# the other.
# ---------------------------------------------------------------------------
_MONTH_NAMES = {
    # English (full + common abbreviations)
    "january": 1, "jan": 1, "february": 2, "feb": 2, "march": 3, "mar": 3,
    "april": 4, "apr": 4, "may": 5, "june": 6, "jun": 6, "july": 7, "jul": 7,
    "august": 8, "aug": 8, "september": 9, "sept": 9, "sep": 9,
    "october": 10, "oct": 10, "november": 11, "nov": 11, "december": 12, "dec": 12,
    # Filipino
    "enero": 1, "pebrero": 2, "marso": 3, "abril": 4, "mayo": 5, "hunyo": 6,
    "hulyo": 7, "agosto": 8, "setyembre": 9, "septyembre": 9, "oktubre": 10,
    "nobyembre": 11, "disyembre": 12,
}
# Longest names first so "sept" doesn't eat the "sep" in "september" etc.
_MONTH_PATTERN = re.compile(
    r"\b(" + "|".join(sorted(_MONTH_NAMES.keys(), key=len, reverse=True)) + r")\b(?:\s+(\d{4}))?"
)


def _month_bounds(year, month):
    last_day = calendar.monthrange(year, month)[1]
    return date(year, month, 1), date(year, month, last_day)


def _iso_week_bounds(d):
    monday = d - timedelta(days=d.weekday())
    return monday, monday + timedelta(days=6)


def _try_local_date_extraction(question, today):
    """Returns the same dict shape _ask_claude_for_date_range's parsed JSON
    has, or None if the question isn't a confident match for one of these
    fixed patterns (caller should fall through to Claude in that case)."""
    q = (question or "").strip().lower()
    if not q:
        return None

    def result(date_from, date_to, label, is_all_time=False):
        return {
            "is_sales_question": True,
            "is_all_time": is_all_time,
            "date_from": None if is_all_time else date_from.isoformat(),
            "date_to": None if is_all_time else date_to.isoformat(),
            "label": label,
        }

    if re.search(r"\ball[\s-]?time\b|\blahat\b|\bkabuuan\b|\bever\b", q):
        return result(None, None, "All Time", is_all_time=True)

    if re.search(r"\btoday\b|\bngayon\b", q):
        return result(today, today, today.strftime("%B %d, %Y"))

    if re.search(r"\blast\s*week\b|\bnoong\s*linggo\b", q):
        monday, sunday = _iso_week_bounds(today - timedelta(days=7))
        return result(monday, sunday, f"Last Week ({monday.strftime('%b %d')}-{sunday.strftime('%b %d')})")
    if re.search(r"\bthis\s*week\b|\bngayong\s*linggo\b", q):
        monday, sunday = _iso_week_bounds(today)
        return result(monday, sunday, f"This Week ({monday.strftime('%b %d')}-{sunday.strftime('%b %d')})")

    if re.search(r"\blast\s*month\b|\bnoong\s*buwan\b", q):
        last_month_end = today.replace(day=1) - timedelta(days=1)
        start, end = _month_bounds(last_month_end.year, last_month_end.month)
        return result(start, end, start.strftime("%B %Y"))
    if re.search(r"\bthis\s*month\b|\bngayong\s*buwan\b", q):
        return result(today.replace(day=1), today, today.strftime("%B %Y"))

    if re.search(r"\bthis\s*year\b|\bngayong\s*taon\b", q):
        return result(date(today.year, 1, 1), today, str(today.year))
    if re.search(r"\blast\s*year\b|\bnoong\s*taon\b|\bnakaraang\s*taon\b", q):
        y = today.year - 1
        return result(date(y, 1, 1), date(y, 12, 31), str(y))

    # Month name (+ optional year), and bare 4-digit years - only for SHORT
    # questions, so a long freeform sentence that happens to mention a
    # number/month in passing still goes to the AI instead of being
    # misread as a date-range query.
    if len(q) <= 60:
        year_only = re.search(r"\b(20\d{2})\b", q)
        month_match = _MONTH_PATTERN.search(q)
        if month_match:
            month_num = _MONTH_NAMES[month_match.group(1)]
            if month_match.group(2):
                year = int(month_match.group(2))
            elif year_only:
                year = int(year_only.group(1))
            else:
                year = today.year
                if month_num > today.month:
                    year -= 1  # most recent occurrence at/before today
            start, end = _month_bounds(year, month_num)
            return result(start, end, start.strftime("%B %Y"))
        if year_only and re.fullmatch(r"[\D]*" + year_only.group(1) + r"[\D]*", q):
            y = int(year_only.group(1))
            return result(date(y, 1, 1), date(y, 12, 31), str(y))

    return None  # not a confident local match - let Claude handle it


def _ask_claude_for_date_range(question, today_str):
    """Same job, same contract (returns (parsed_dict_or_None, error_or_None))
    as the old Gemini version this replaced - only the HTTP call and error
    codes are provider-specific. Uses Anthropic's Messages API directly via
    `requests` (no anthropic SDK dependency needed, matching the "just
    requests" approach already used throughout this file)."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return None, "ANTHROPIC_API_KEY is not set sa environment variables mo (Render > Environment)."

    prompt = f"""You are a date-range extractor for a Philippine ice-selling business's sales chatbot ("Omega Ice").
Today's date is {today_str} (YYYY-MM-DD), business operates in Asia/Manila timezone.
The user asks a question in English, Tagalog, or mixed ("Taglish") about SALES data.
Your ONLY job: figure out which date range they're asking about, and return STRICT JSON only - no markdown fences, no extra text.

JSON shape:
{{
  "is_sales_question": true or false,
  "is_all_time": true or false,
  "date_from": "YYYY-MM-DD" or null,
  "date_to": "YYYY-MM-DD" or null,
  "label": "short human-readable label, e.g. 'May 2026' or 'This Week'"
}}

Rules:
- If the question is not about sales at all (small talk, unrelated topic), set is_sales_question=false and leave the rest null.
- "last May" / "noong Mayo" / "May 2026" -> that calendar month's 1st to last day. If no year is stated, use the most recent occurrence of that month at or before today.
- "today" / "ngayon" -> date_from = date_to = today.
- "this week" -> the Mon-Sun ISO week containing today. "last week" -> the ISO week right before that.
- "this month" -> the 1st of the current month through today. "last month" -> the full previous calendar month.
- "this year" -> Jan 1 of the current year through today. A bare 4-digit year like "2025" -> Jan 1 to Dec 31 of that year.
- "all time" / "lahat" / "kabuuan" / "ever" -> is_all_time=true; date_from/date_to can be null.
- An explicit date or date range in the question -> use it directly.
- If genuinely ambiguous, make your single best reasonable guess instead of refusing.

Question: {question}"""

    api_url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": CLAUDE_MODEL,
        "max_tokens": 300,  # the JSON reply is tiny; this is just headroom
        "temperature": 0,   # deterministic - this is extraction, not creative writing
        "system": "You output ONLY valid JSON matching the requested shape - no explanation, no markdown code fences, no extra text before or after.",
        "messages": [{"role": "user", "content": prompt}],
    }

    # Retry ONLY on 429 (rate limited) and 529 (Anthropic's "Overloaded" -
    # their equivalent of the old Gemini 503) - both genuinely transient.
    # Same conservative single-retry + latency budget as the old Gemini
    # integration, for the same reason: gunicorn kills this whole worker if
    # ONE request handling takes longer than ~30s (the WORKER TIMEOUT bug
    # from Sept 25, 2026 - see _manila_today's history). 2 attempts x 12s
    # timeout + a 1.5s backoff = 25.5s worst case, same budget as before.
    # NOT retrying on a timeout/connection error: that attempt already
    # burned its own timeout budget.
    last_exc = None
    resp = None
    for attempt in (1, 2):
        try:
            resp = requests.post(api_url, headers=headers, json=payload, timeout=12)
            if resp.status_code in (429, 529) and attempt == 1:
                time.sleep(1.5)
                continue
            resp.raise_for_status()
            break
        except requests.exceptions.RequestException as e:
            last_exc = e
            resp = getattr(e, "response", None)
            break  # timeouts/connection errors: fail fast, no retry

    if last_exc is not None or resp is None or not resp.ok:
        e = last_exc
        status = getattr(resp, "status_code", None)
        body = getattr(resp, "text", None)
        # Kept permanently (not temp debug) - same lesson as the old Gemini
        # integration: a provider retiring/renaming a model, or changing an
        # error shape, only shows up in the response BODY, never in str(e)
        # alone. Logging status+body here means that's a 2-minute Render
        # Logs check instead of a multi-hour investigation.
        print(
            f"[ai-sales] Claude request failed: status={status} body={(body or '')[:500]!r}",
            flush=True,
        )
        if status == 429:
            return None, "Naabot na ang rate limit ng AI ngayon. Sandali lang, subukan ulit pagkalipas ng isang minuto."
        if status == 529:
            return None, "Sobrang busy ang AI service ngayon (parte ito ng Claude API, hindi sa app natin). Subukan ulit pagkalipas ng ilang segundo."
        if status == 401:
            return None, "Invalid o expired ang ANTHROPIC_API_KEY - i-check mo sa Render > Environment."
        detail = str(e) if e else f"{status} Server Error for url: {api_url}"
        return None, f"Hindi ma-reach ang AI service: {detail}"

    try:
        data = resp.json()
        text = data["content"][0]["text"]
    except (KeyError, IndexError, ValueError):
        return None, "Unexpected response shape from Claude API."

    parsed = _extract_json(text)
    if not parsed:
        return None, "Hindi na-gets ng AI yung tanong mo, subukan mo ulit with a clearer date (hal. 'sales last May')."
    return parsed, None


# ---------------------------------------------------------------------------
# Step 2: Python fetches + filters + aggregates (the ONLY source of truth
# for the actual numbers - see the module docstring for why)
# ---------------------------------------------------------------------------
def _get_sales_in_range(date_from, date_to, is_all_time=False):
    """
    Returns the list of raw daily_sales records (plus their Firebase key and
    resolved date) whose date falls within [date_from, date_to] inclusive.

    Filtering rules below are copied 1:1 from /api/sales/by_period in
    app.py (that file's own "ROOT-CAUSE FIX / single source of truth" for
    sales filtering) - see the module docstring for why this is copied
    rather than re-derived.
    """
    raw = fb_get("daily_sales") or {}
    results = []
    for key, val in raw.items():
        if not val:
            continue
        if val.get("deleted"):
            continue
        # Same archived-record rule as /api/sales/by_period: an archived
        # record is excluded for any bounded period, and only kept for a
        # genuine "all time" query (or when explicitly flagged to always
        # count via include_in_all_time / is_customer_order).
        if val.get("archived") and not val.get("is_customer_order"):
            if not val.get("include_in_all_time") and not is_all_time:
                continue

        sd = _parse_date(val.get("sales_date") or "")
        dd = _parse_date(val.get("delivered_date") or "")
        check_date = sd or dd
        if not check_date:
            check_date = _parse_date((val.get("created_at") or "")[:10])
        if not check_date:
            continue
        check_date = check_date.date()

        if not is_all_time:
            if date_from and check_date < date_from:
                continue
            if date_to and check_date > date_to:
                continue

        results.append({**val, "_id": key, "_date": check_date.isoformat()})
    return results


def _summarize_sales(records):
    total_peso = 0.0
    total_kg = 0.0
    by_size, by_reseller, by_payment = {}, {}, {}

    for r in records:
        peso = float(r.get("total_sales") or 0)
        qty = float(r.get("quantity") or 0)
        kg = _kg_value(r.get("kg_size") or "1Kg")
        total_peso += peso
        total_kg += qty * kg

        size_label = r.get("kg_size") or "Unknown"
        s = by_size.setdefault(size_label, {"count": 0, "peso": 0.0})
        s["count"] += 1
        s["peso"] += peso

        reseller = (r.get("reseller_name") or "").strip() or "Walk-in/Unnamed"
        rr = by_reseller.setdefault(reseller, {"count": 0, "peso": 0.0})
        rr["count"] += 1
        rr["peso"] += peso

        pay = r.get("payment") or r.get("payment_mode") or "Unknown"
        p = by_payment.setdefault(pay, {"count": 0, "peso": 0.0})
        p["count"] += 1
        p["peso"] += peso

    top_resellers = sorted(by_reseller.items(), key=lambda x: -x[1]["peso"])[:5]

    return {
        "total_peso": round(total_peso, 2),
        "total_kg": round(total_kg, 1),
        "count": len(records),
        "by_size": by_size,
        "by_payment": by_payment,
        "top_resellers": top_resellers,
    }


def _format_sales_reply(label, summary):
    lines = [f"📊 Sales Report: {label}", ""]
    lines.append(f"💰 Total Sales: {_peso(summary['total_peso'])}")
    lines.append(f"📦 Total Kilos: {summary['total_kg']:,.1f} kg")
    lines.append(f"🧾 Transactions: {summary['count']}")

    if summary["count"] == 0:
        lines.append("")
        lines.append("Walang naitalang benta sa period na ito.")
        return "\n".join(lines)

    lines.append("")
    lines.append("Breakdown by Size:")
    for size_label, s in sorted(summary["by_size"].items(), key=lambda x: -x[1]["peso"]):
        lines.append(f"  • {size_label}: {s['count']} order(s), {_peso(s['peso'])}")

    if summary["top_resellers"]:
        lines.append("")
        lines.append("Top Resellers:")
        for name, r in summary["top_resellers"]:
            lines.append(f"  • {name}: {_peso(r['peso'])} ({r['count']} order/s)")

    if summary["by_payment"]:
        lines.append("")
        lines.append("Payment Breakdown:")
        for pay, p in sorted(summary["by_payment"].items(), key=lambda x: -x[1]["peso"]):
            lines.append(f"  • {pay}: {_peso(p['peso'])} ({p['count']} order/s)")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# "Ask AI" v2 (Sept 26 2026) - beyond sales. Same design principle as the
# sales flow above: this box NEVER lets an LLM touch the actual data or do
# the math. Every topic below is a LOCAL keyword-based intent router +
# plain-Python Firebase fetch/filter/aggregate - zero AI calls, zero
# internet dependency. Claude is used ONLY as the sales topic's fallback
# for genuinely freeform date phrasing (see _ask_claude_for_date_range) -
# every other topic here works even with ANTHROPIC_API_KEY unset, or with
# Claude's API fully down (rate-limited/overloaded/no internet egress at
# all). That's what makes this "smart" without needing a live AI
# connection: the intelligence is knowing the shape of THIS business's
# own data, not an LLM.
#
# To add a new topic later: (1) add its keywords to a new _TOPIC_KEYWORDS
# regex below, (2) write a `_handle_<topic>_question(question)` function
# that fetches + formats a reply, (3) wire it into _detect_topic() and the
# dispatch table in api_ai_sales_ask(). Keep the priority order below -
# more specific topics are checked BEFORE "sales", since "sales" is the
# fallback/default (it already has to catch bare date phrases like "this
# week" that don't mention any topic keyword at all).
# ---------------------------------------------------------------------------
_LOYALTY_KEYWORDS = re.compile(
    r"\b(points?|puntos|loyalty|rewards?|redeem|redemption)\b", re.I
)
_MACHINE_KEYWORDS = re.compile(
    r"\b(machines?|makina|harvest|preventive maintenance|maintenance due|"
    r"filter change)\b", re.I
)
_STAFF_KEYWORDS = re.compile(
    r"\b(staff|empleyado|employees?|tauhan)\b", re.I
)
_RESELLER_INFO_KEYWORDS = re.compile(
    r"\b(credit balance|utang|presyo per ?kg|price per ?kg|contact number|"
    r"phone number|listahan ng resellers?|list of resellers?|mga reseller|"
    r"resellers ko|last order|huling order|huling bili|huling benta|"
    r"last purchase|last transaction|profit|kinita|kumikita|kikitain|"
    r"margin|ilang beses|how many times|order count|bilang ng order|"
    r"how many orders)\b", re.I
)

# Sub-intents WITHIN the resellers topic, checked once a specific
# reseller/customer has already been identified in the question (see
# _find_matching_reseller) - "customer" and "reseller" are the same
# Firebase entity in this app, see _find_last_order's docstring.
_LAST_ORDER_INTENT = re.compile(
    r"\b(last order|huling order|huling bili|huling benta|last purchase|"
    r"last transaction)\b", re.I
)
_ORDER_COUNT_INTENT = re.compile(
    r"\b(ilang beses|how many times|order count|bilang ng order|"
    r"how many orders)\b", re.I
)
_PROFIT_INTENT = re.compile(
    r"\b(profit|kinita|kumikita|kikitain|margin)\b", re.I
)
_REDEMPTION_COUNT_INTENT = re.compile(
    r"\b(ilang beses|how many times|redemption count|bilang ng redeem)\b", re.I
)

# Expenses topic (Sept 26 2026 addition) - covers modules/expenses.py's
# `expenses` node (Consumables/Fuel/Electricity/Maintenance) AND
# modules/plastic.py's `plastic_purchases`/`plastic_usage` nodes. Note:
# bare "maintenance" here does NOT collide with _MACHINE_KEYWORDS above,
# because that regex only matches the specific phrases "preventive
# maintenance" / "maintenance due" (a machine's PM schedule), never the
# bare word - so "gastos sa maintenance last month" (an EXPENSE category)
# correctly stays out of the machines topic.
_EXPENSE_KEYWORDS = re.compile(
    r"\b(expenses?|gastos|electric\w*|kuryente|koryente|"
    r"ilaw|consumables?|fuel|gasolina|diesel|maintenance|plastic|"
    r"packaging|bags?)\b", re.I
)

# Sub-intents WITHIN the expenses topic.
#
# BUGFIX (Sept 26 2026, ISESMO report): originally this matched the exact
# literal "electricity" only, so a common typo like "electricty" (missing
# the "i") fell through EVERY expense check and landed on the sales
# topic's default date-phrase fallback instead (silently returning a
# generic Sales Report whenever the question also happened to contain a
# recognized date phrase like "this year" - see _detect_topic/
# api_ai_sales_ask). `electric\w*` now matches "electric", "electricity",
# "electricty", "electrical", etc. in one go - same fix applied to
# _EXPENSE_KEYWORDS above - instead of trying to enumerate every possible
# misspelling by hand.
_ELECTRICITY_INTENT = re.compile(r"\b(electric\w*|kuryente|koryente|ilaw)\b", re.I)
_PLASTIC_INTENT = re.compile(r"\b(plastic|packaging|bags?)\b", re.I)
_PLASTIC_USAGE_INTENT = re.compile(
    r"\b(nagamit|ginamit|ginagamit|used|usage|consumed|consumption)\b", re.I
)
_PLASTIC_PURCHASE_INTENT = re.compile(
    r"\b(nabili|binili|bumili|bought|purchased|purchase)\b", re.I
)
# "Breakdown PER MONTH" (Sept 26 2026 addition) - a genuinely separate ask
# from the plain electricity/expense summary: ISESMO wants a month-by-
# month table (Jan: X, Feb: Y, ...), not one combined total for the whole
# range. See _format_electricity_monthly_breakdown.
_PER_MONTH_INTENT = re.compile(
    r"\b(per month|bawat buwan|buwan[- ]buwan|monthly|kada buwan)\b", re.I
)
# Specifically catches "total plastic na nagamit base sa SALES" - see
# _handle_expenses_question's docstring for why this is answered with an
# honest limitation instead of a guessed ratio.
_SALES_BASED_INTENT = re.compile(
    r"\b(base sa sales|batay sa sales|based on sales|galing sa sales)\b", re.I
)


def _detect_topic(question):
    """Local (no-AI) topic router. Checked in priority order - most
    specific first - so e.g. "sino top reseller this month" (a SALES
    question about performance) doesn't get hijacked by the word
    "reseller" alone; only a specific reseller-PROFILE phrase (credit
    balance, contact number, etc.) routes to the resellers topic."""
    q = (question or "").lower()
    if _LOYALTY_KEYWORDS.search(q):
        return "loyalty"
    if _MACHINE_KEYWORDS.search(q):
        return "machines"
    if _STAFF_KEYWORDS.search(q):
        return "staff"
    if _RESELLER_INFO_KEYWORDS.search(q):
        return "resellers"
    if _EXPENSE_KEYWORDS.search(q):
        return "expenses"
    return "sales"


# Generic/filler words that must NEVER be used, by themselves, to match a
# reseller by a single word of their store_name (Pass 2 below). Without
# this, a question like "wala namang store dito" would wrongly "find" a
# reseller literally named "Nena's Ice Store" just because it contains the
# word "store" - or, worse, since this whole business IS an ice company,
# almost every reseller name would contain "Ice" and become impossible to
# tell apart by keyword. Keep this list to genuinely generic business/
# honorific words, not real names - if a future false-match ever shows up
# in testing, add the specific offending word here rather than redesigning
# the matching logic.
_RESELLER_MATCH_STOPWORDS = frozenset({
    # generic business-type nouns (EN)
    "store", "shop", "mart", "supply", "supplies", "trading", "enterprise",
    "enterprises", "corp", "corporation", "inc", "incorporated", "group",
    "co", "company", "resto", "restaurant", "bakery", "grocery",
    "groceries", "water", "refill", "station", "ice",
    # generic business-type nouns (Tagalog)
    "sari", "tindahan", "tinda",
    # generic honorifics/particles (Tagalog) - "Aling"/"Mang" prefix a LOT
    # of small-store names, so they're too common to be distinguishing on
    # their own.
    "aling", "mang", "kuya", "ate", "lola", "lolo", "tita", "tito",
    "ng", "sa", "ni", "kay", "si", "ang", "mga",
})


def _find_matching_reseller(question, resellers):
    """Returns (key, val) of the matching reseller, or (None, None).

    Pass 1 (original behavior): the reseller whose FULL store_name is the
    LONGEST match found as a substring of the question. Longest match wins
    so a short/generic name doesn't win over a more specific one that also
    matches (e.g. "Ice Point" vs "Point"). This is the strongest signal
    and, if found, is returned immediately.

    Pass 2 (Sept 26 2026 addition, ISESMO request: "kahit keyword lng...
    tulad ng AMO RESTO tapos Amo lang nilagay kaya na nya kunin sa db") -
    only runs when Pass 1 found nothing. Matches on any SINGLE WORD of a
    store_name (e.g. "Amo" alone now matches "AMO RESTO"), as long as that
    word is:
      - not in _RESELLER_MATCH_STOPWORDS (generic words like "Store"/
        "Ice"/"Aling" are excluded so they can't falsely match)
      - >=3 characters (same generic-word-length guard used elsewhere in
        this file, e.g. _find_matching_custom_query)
      - present as a WHOLE WORD in the question (word-boundary match via
        tokenizing, not "contained inside a longer unrelated word" - so a
        question about "Icebox" won't accidentally match a store called
        "Ice").
    Longest matching word wins. If two DIFFERENT resellers tie on the same
    word (e.g. two stores that both happen to have a same-length distinct
    word the stoplist doesn't catch), that's genuinely ambiguous - safer
    to return NO match (falls through to the existing "hindi ko na-detect,
    i-type mo ang buong pangalan" message) than to silently guess wrong.
    """
    q = (question or "").lower()

    # --- Pass 1: exact full store-name substring match ---------------------
    best_key, best_val, best_len = None, None, 0
    for key, val in (resellers or {}).items():
        if not val:
            continue
        name = (val.get("store_name") or "").strip()
        if len(name) < 3:
            continue
        if name.lower() in q and len(name) > best_len:
            best_key, best_val, best_len = key, val, len(name)
    if best_key:
        return best_key, best_val

    # --- Pass 2: single-word keyword fallback -------------------------------
    q_tokens = set(re.findall(r"[a-z0-9]+", q))
    best_key, best_val, best_len = None, None, 0
    ambiguous = False
    for key, val in (resellers or {}).items():
        if not val:
            continue
        name = (val.get("store_name") or "").strip()
        if not name:
            continue
        for word in re.findall(r"[a-zA-Z0-9]+", name):
            wl = word.lower()
            if len(wl) < 3 or wl in _RESELLER_MATCH_STOPWORDS:
                continue
            if wl not in q_tokens:
                continue
            if len(word) > best_len:
                best_key, best_val, best_len = key, val, len(word)
                ambiguous = False
            elif len(word) == best_len and key != best_key:
                ambiguous = True

    if ambiguous:
        return None, None
    return best_key, best_val


def _get_reseller_orders_in_range(reseller_key, reseller_name, date_from=None, date_to=None, is_all_time=True):
    """All non-deleted daily_sales records for ONE specific reseller/
    customer within [date_from, date_to] (or all-time if is_all_time).
    "customer" and "reseller" are the same Firebase entity in this app
    (see api_customer_orders(reseller_id) etc. in app.py: the online
    customer portal logs in AS a reseller account). Matches by
    reseller_id first (reliable, survives a store rename); falls back to
    a case-insensitive reseller_name match for older rows saved before
    reseller_id existed on every record (app.py's own dedup/migration
    comments mention legacy rows with reseller_id: None). Reuses
    _get_sales_in_range so every per-customer number here always agrees
    with the exact same deleted/archived filtering every other number in
    this feature already uses - see that function's docstring."""
    records = _get_sales_in_range(date_from, date_to, is_all_time=is_all_time)
    name_lower = (reseller_name or "").strip().lower()
    return [
        r for r in records
        if (r.get("reseller_id") and r.get("reseller_id") == reseller_key)
        or (not r.get("reseller_id") and (r.get("reseller_name") or "").strip().lower() == name_lower)
    ]


def _find_last_order(reseller_key, reseller_name):
    """Most recent (by date) order for one specific reseller/customer, or
    None. See _get_reseller_orders_in_range for the matching rules."""
    mine = _get_reseller_orders_in_range(reseller_key, reseller_name, is_all_time=True)
    if not mine:
        return None
    mine.sort(key=lambda r: r["_date"], reverse=True)
    return mine[0]


def _resolve_question_range(question, today):
    """Runs the question through the SAME local (no-AI) date-range
    extractor the sales topic uses (_try_local_date_extraction), for
    per-customer questions that may or may not mention a date phrase
    ("profit ni X this month" vs just "profit ni X"). Returns
    (date_from, date_to, is_all_time, label) - defaults to all-time when
    no date phrase is found, since that's the more useful answer for a
    question that didn't specify a period. Deliberately does NOT fall
    through to Claude here - a missing date phrase just means
    "all time" for these topics, not "ask the AI to guess"."""
    parsed = _try_local_date_extraction(question, today)
    if parsed and not parsed.get("is_all_time") and (parsed.get("date_from") or parsed.get("date_to")):
        return (
            _safe_parse_iso_date(parsed.get("date_from")),
            _safe_parse_iso_date(parsed.get("date_to")),
            False,
            parsed.get("label") or "Custom Range",
        )
    return None, None, True, "All Time"


# --- Resellers topic ---------------------------------------------------
def _handle_resellers_question(question, today):
    q = (question or "").lower()
    resellers = {k: v for k, v in (fb_get("resellers") or {}).items() if v}
    if not resellers:
        return "Wala pang naka-record na reseller sa system."

    key, match = _find_matching_reseller(question, resellers)

    wants_last_order = bool(_LAST_ORDER_INTENT.search(q))
    wants_order_count = bool(_ORDER_COUNT_INTENT.search(q))
    wants_profit = bool(_PROFIT_INTENT.search(q))

    if (wants_last_order or wants_order_count or wants_profit) and not match:
        return ("Hindi ko na-detect kung sinong reseller/customer ang tinutukoy mo. "
                "I-type mo yung buong pangalan ng store nila "
                '(hal. "profit ni Nena\'s Ice Store this month").')

    if match:
        name = match.get("store_name") or "Unknown"

        # Order count in a period (all-time if no date phrase given)
        if wants_order_count:
            date_from, date_to, is_all_time, label = _resolve_question_range(question, today)
            orders = _get_reseller_orders_in_range(key, name, date_from, date_to, is_all_time)
            total_peso = sum(float(o.get("total_sales") or 0) for o in orders)
            return "\n".join([
                f"🧾 {name} — Orders ({label})", "",
                f"📦 Bilang ng Order: {len(orders)}",
                f"💰 Total: {_peso(total_peso)}",
            ])

        # Estimated resale profit: (their own retail price x kg they
        # bought) minus (what they actually paid Omega). This is THEIR
        # margin as a reseller, not Omega's own margin (see
        # get_current_margin_pct in app.py for that separate, unrelated
        # number). Uses their CURRENT retail_price_per_kg for the whole
        # period - resellers/{id}/retail_price_history in app.py shows
        # this can change over time, so this is a clearly-labeled
        # estimate, not an audited figure.
        if wants_profit:
            price = match.get("retail_price_per_kg")
            if not price:
                return f"Wala pang naka-set na retail price si {name}, kaya hindi ko makukwenta ang profit nila."
            date_from, date_to, is_all_time, label = _resolve_question_range(question, today)
            orders = _get_reseller_orders_in_range(key, name, date_from, date_to, is_all_time)
            if not orders:
                return f"Wala pang naitalang order si {name} sa period na ito."
            total_paid = sum(float(o.get("total_sales") or 0) for o in orders)
            total_kg = sum(float(o.get("quantity") or 0) * _kg_value(o.get("kg_size") or "1Kg") for o in orders)
            est_revenue = total_kg * float(price)
            est_profit = est_revenue - total_paid
            avg_profit = est_profit / len(orders)
            return "\n".join([
                f"💵 Estimated Profit — {name} ({label})", "",
                f"🏷️ Retail Price/Kg (kasalukuyan): {_peso(price)}",
                f"📦 Total Kilos Binili: {total_kg:,.1f} kg",
                f"💳 Binayad kay Omega: {_peso(total_paid)}",
                f"💰 Estimated Kita: {_peso(est_profit)}",
                f"📊 Average Profit per Order: {_peso(avg_profit)} ({len(orders)} order/s)",
                "",
                "⚠️ Estimate lang ito base sa KASALUKUYANG retail price nila - "
                "posibleng iba ang aktwal kung nagbago ang presyo nila noon.",
            ])

        name_line = name
        contact = match.get("contact") or match.get("phone") or "Walang naka-record"
        credit = match.get("credit_balance") or 0
        price = match.get("retail_price_per_kg")
        lines = [f"🏪 {name_line}", "", f"📞 Contact: {contact}", f"💳 Credit Balance: {_peso(credit)}"]
        if price:
            lines.append(f"🏷️ Retail Price/Kg: {_peso(price)}")

        if wants_last_order:
            last = _find_last_order(key, name)
            lines.append("")
            if last:
                qty = last.get("quantity") or 0
                kg_size = last.get("kg_size") or ""
                peso = last.get("total_sales") or 0
                pay = last.get("payment") or last.get("payment_mode") or "Unknown"
                lines.append(f"🕒 Huling Order: {last['_date']}")
                lines.append(f"   {qty} x {kg_size} — {_peso(peso)} ({pay})")
            else:
                lines.append("🕒 Huling Order: Wala pang naitalang order si customer na ito.")

        return "\n".join(lines)

    if re.search(r"\bcredit|utang|balance\b", q):
        with_credit = [
            ((v.get("store_name") or "Unknown"), float(v.get("credit_balance") or 0))
            for v in resellers.values()
        ]
        with_credit = [x for x in with_credit if x[1] > 0]
        with_credit.sort(key=lambda x: -x[1])
        total_credit = sum(x[1] for x in with_credit)
        lines = [
            f"💳 May Credit Balance: {len(with_credit)} sa {len(resellers)} reseller(s)",
            f"💰 Total Credit Outstanding: {_peso(total_credit)}",
        ]
        if with_credit:
            lines.append("")
            lines.append("Pinakamalaking utang:")
            for name, bal in with_credit[:10]:
                lines.append(f"  • {name}: {_peso(bal)}")
        return "\n".join(lines)

    names = sorted((v.get("store_name") or "Unknown") for v in resellers.values())
    shown = names[:20]
    lines = [f"🏪 Total Resellers: {len(names)}", ""]
    lines.extend(f"  • {n}" for n in shown)
    if len(names) > len(shown):
        lines.append(f"  ...at {len(names) - len(shown)} pa.")
    lines.append("")
    lines.append('Tip: itanong mo yung store name (hal. "credit balance ni [store name]") para sa detalye.')
    return "\n".join(lines)


# --- Loyalty & Rewards topic --------------------------------------------
def _handle_loyalty_question(question):
    q = (question or "").lower()
    resellers = fb_get("resellers") or {}
    loyalty = fb_get("loyalty_points") or {}

    rkey, rmatch = _find_matching_reseller(question, resellers)

    # How many times has this specific customer redeemed a reward - checked
    # FIRST (most specific), before the generic catalog-listing branch
    # below, so "ilang beses na nakukaha ng reward si X" doesn't get
    # mistaken for "what rewards are available". Every redemption's
    # history entry is written by app.py's award_loyalty_points() with
    # reason=f"Redeemed: {label}" (see the /api/.../redeem route) - never
    # any other reason string - so filtering on that exact prefix is a
    # precise, non-guessed way to count real redemptions only (not every
    # points-earning or manual-adjustment entry).
    if rmatch and _REDEMPTION_COUNT_INTENT.search(q) and re.search(r"\breward|redeem\b", q):
        history = ((loyalty.get(rkey) or {}).get("history")) or {}
        redemptions = [h for h in history.values() if h and str(h.get("reason") or "").startswith("Redeemed:")]
        redemptions.sort(key=lambda h: h.get("timestamp") or "", reverse=True)
        name = rmatch.get("store_name") or "Unknown"
        lines = [f"🎁 {name} — Reward Redemptions", "", f"🔢 Bilang ng Na-redeem: {len(redemptions)}"]
        if redemptions:
            lines.append("")
            lines.append("Pinakahuling na-redeem:")
            for h in redemptions[:5]:
                reason = (h.get("reason") or "").replace("Redeemed: ", "")
                lines.append(f"  • {h.get('timestamp') or 'N/A'} — {reason}")
        return "\n".join(lines)

    if not rmatch and re.search(r"\breward|catalog|redeem\b", q) and not re.search(r"\btop|pinakamaraming|highest|leader\b", q):
        catalog = {k: v for k, v in (fb_get("reward_catalog") or {}).items() if v}
        if not catalog:
            return "Wala pang na-set up na reward catalog."
        items = sorted(catalog.values(), key=lambda x: float(x.get("points_required") or 0))
        lines = ["🎁 Reward Catalog:", ""]
        for item in items:
            label = item.get("label") or "Unnamed reward"
            pts = item.get("points_required") or 0
            lines.append(f"  • {label} — {int(pts):,} points")
        return "\n".join(lines)

    if rmatch:
        entry = loyalty.get(rkey) or {}
        balance = entry.get("balance") or 0
        last_earned = entry.get("last_earned_at") or "Wala pa"
        last_redeem = entry.get("last_redemption_at") or "Wala pa"
        name = rmatch.get("store_name") or "Unknown"
        return "\n".join([
            f"🏆 Loyalty Points — {name}", "",
            f"⭐ Balance: {int(balance):,} points",
            f"📅 Last Earned: {last_earned}",
            f"🎁 Last Redemption: {last_redeem}",
        ])

    ranked = []
    for rid, entry in (loyalty or {}).items():
        if not entry:
            continue
        bal = entry.get("balance") or 0
        if bal <= 0:
            continue
        name = (resellers.get(rid) or {}).get("store_name") or f"(Unknown reseller {rid})"
        ranked.append((name, bal))
    ranked.sort(key=lambda x: -x[1])

    if not ranked:
        return "Wala pang reseller na may loyalty points ngayon."

    total_points = sum(b for _, b in ranked)
    lines = [f"🏆 Top Loyalty Points Holders", "", f"⭐ Total Points sa Lahat: {int(total_points):,}", ""]
    for name, bal in ranked[:10]:
        lines.append(f"  • {name}: {int(bal):,} points")
    return "\n".join(lines)


# --- Staff topic ----------------------------------------------------------
def _handle_staff_question(question):
    q = (question or "").lower()
    records = [v for v in (fb_get("staff") or {}).values() if v]
    if not records:
        return "Wala pang staff records sa system."

    # SECURITY: never surface the `pin` field here - this feature stays
    # readable to anyone with ISESMO access, and login PINs must not leak
    # through a chat reply. Only name/position/status are shown.
    only_active = bool(re.search(r"\bactive|aktibo\b", q))
    if only_active:
        records = [v for v in records if (v.get("status") or "").lower() == "active"]

    records.sort(key=lambda v: v.get("name") or "")
    lines = [f"👥 {'Active ' if only_active else ''}Staff: {len(records)}", ""]
    for v in records:
        name = v.get("name") or "Unknown"
        position = v.get("position") or "Staff"
        status = v.get("status") or "Unknown"
        lines.append(f"  • {name} — {position} ({status})")
    return "\n".join(lines)


# --- Machines & Equipment topic -------------------------------------------
def _is_pm_overdue(pm_date):
    """Mirrors app.py's own is_pm_overdue() exactly (same naive
    datetime.now().date() comparison, not Manila-adjusted) so this chat
    reply always agrees with what the Machines page itself shows - same
    single-source-of-truth principle as the sales filtering above."""
    if not pm_date:
        return False
    try:
        d = datetime.strptime(str(pm_date), "%Y-%m-%d")
        return d.date() < datetime.now().date()
    except Exception:
        return False


def _handle_machines_question(question, today):
    q = (question or "").lower()
    records = [{**v, "_id": k} for k, v in (fb_get("machines") or {}).items() if v]
    if not records:
        return "Wala pang naka-record na machine sa system."

    if re.search(r"\bpm|maintenance|overdue|filter change|due\b", q):
        overdue = [m for m in records if _is_pm_overdue(m.get("pm_date"))]
        lines = [f"🔧 Machines na Overdue sa PM: {len(overdue)} sa {len(records)}", ""]
        if overdue:
            for m in overdue:
                lines.append(f"  • {m.get('machine_name') or 'Unknown'} — PM date: {m.get('pm_date') or 'N/A'}")
        else:
            lines.append("Walang overdue sa PM ngayon. 👍")
        return "\n".join(lines)

    if re.search(r"\bharvest|output|nakuha|produced\b", q):
        parsed_range = _try_local_date_extraction(question, today)
        logs = fb_get("machine_logs") or {}
        total_kg = 0.0
        total_expense = 0.0
        count = 0
        for lg in (logs or {}).values():
            if not lg or lg.get("status") != "STOPPED":
                continue
            started = _parse_date((lg.get("started_at") or "")[:10])
            if not started:
                continue
            d = started.date()
            if parsed_range and not parsed_range.get("is_all_time"):
                df = _safe_parse_iso_date(parsed_range.get("date_from"))
                dt_ = _safe_parse_iso_date(parsed_range.get("date_to"))
                if df and d < df:
                    continue
                if dt_ and d > dt_:
                    continue
            total_kg += float(lg.get("output_kg") or 0)
            total_expense += float(lg.get("expense") or 0)
            count += 1
        label = (parsed_range or {}).get("label") or "All Time"
        return "\n".join([
            f"🧊 Machine Output: {label}", "",
            f"📦 Total Output: {total_kg:,.1f} kg",
            f"⚡ Total Electricity Expense: {_peso(total_expense)}",
            f"🧾 Completed Runs: {count}",
        ])

    running_logs = fb_get("machine_logs") or {}
    running_count = sum(1 for lg in (running_logs or {}).values() if lg and lg.get("status") == "RUNNING")
    lines = [f"🧊 Machines: {len(records)} total, {running_count} kasalukuyang tumatakbo", ""]
    for m in sorted(records, key=lambda x: x.get("machine_name") or ""):
        overdue = " ⚠️ OVERDUE" if _is_pm_overdue(m.get("pm_date")) else ""
        lines.append(f"  • {m.get('machine_name') or 'Unknown'} — {m.get('wattage') or 0}W, PM: {m.get('pm_date') or 'N/A'}{overdue}")
    return "\n".join(lines)


# --- Expenses topic (Sept 26 2026) --------------------------------------
def _expenses_in_range(date_from, date_to, is_all_time=False):
    """Returns raw modules/expenses.py `expenses/<id>` records (plus their
    Firebase key) whose `date` falls within [date_from, date_to] inclusive.

    Mirrors _get_sales_in_range's own pattern: this is a read-only, LOCAL
    re-filter of the exact same `expenses` Firebase node ISESMO already
    sees on the real Expenses page - it does not import or call that
    page's own route handlers, only the shared _effective_amount(row)
    formula (see the import near the top of this file), so the numbers
    here can't drift from a different aggregation rule.

    Electricity bills that span two calendar months are already split by
    modules.expenses._split_electricity_portions() into two separately-
    dated rows AT SAVE TIME (each with its own correct `date`) - so a
    plain per-row date filter here is correct with no extra handling
    needed for that case.
    """
    raw = fb_get("expenses") or {}
    results = []
    for key, val in raw.items():
        if not val:
            continue
        d = _safe_parse_iso_date(val.get("date"))
        if not d:
            continue
        if not is_all_time:
            if date_from and d < date_from:
                continue
            if date_to and d > date_to:
                continue
        results.append({**val, "_id": key, "_date": d.isoformat()})
    return results


def _format_electricity_monthly_breakdown(rows, label):
    """"Breakdown PER MONTH ng electricity bill this year" - a genuine
    month-by-month table (Jan: X, Feb: Y, ...), not one combined total.
    Buckets by (year, month) of each row's own `date` field - correct
    even for a bill that modules.expenses._split_electricity_portions()
    already split across two calendar months at save time, since each
    split half carries its own correct date."""
    by_month = {}
    for r in rows:
        d = _safe_parse_iso_date(r.get("date"))
        if not d:
            continue
        key = (d.year, d.month)
        m = by_month.setdefault(key, {"peso": 0.0, "kwh": 0.0, "count": 0})
        m["peso"] += _effective_amount(r)
        m["kwh"] += float(r.get("kwh") or 0)
        m["count"] += 1

    lines = [f"⚡ Electricity Bill per Month: {label}", ""]
    grand_total = 0.0
    for (y, mo) in sorted(by_month.keys()):
        m = by_month[(y, mo)]
        month_label = date(y, mo, 1).strftime("%B %Y")
        kwh_part = f", {m['kwh']:,.1f} kWh" if m["kwh"] > 0 else ""
        lines.append(f"  • {month_label}: {_peso(m['peso'])}{kwh_part} ({m['count']} bill/s)")
        grand_total += m["peso"]
    lines.append("")
    lines.append(f"💰 Grand Total: {_peso(grand_total)}")
    return "\n".join(lines)


def _handle_electricity_question(question, today):
    """Covers "Ilang electricity bill ko last xxxx", "Summary ng
    electricity ko this year/last year" (aggregate totals), AND
    "Breakdown per month ng electricity bill this year" (a real
    month-by-month table - added Sept 26 2026 after ISESMO pointed out
    the plain aggregate wasn't actually what "per month" was asking
    for)."""
    q = (question or "").lower()
    date_from, date_to, is_all_time, label = _resolve_question_range(question, today)
    rows = [r for r in _expenses_in_range(date_from, date_to, is_all_time) if r.get("category") == "Electricity"]

    if not rows:
        return f"⚡ Walang naitalang electricity bill sa {label}."

    if _PER_MONTH_INTENT.search(q):
        return _format_electricity_monthly_breakdown(rows, label)

    total_peso = sum(_effective_amount(r) for r in rows)
    total_kwh = sum(float(r.get("kwh") or 0) for r in rows)
    real_rates = [float(r.get("real_kwph") or 0) for r in rows if float(r.get("real_kwph") or 0) > 0]
    avg_real_rate = (sum(real_rates) / len(real_rates)) if real_rates else 0.0

    lines = [
        f"⚡ Electricity Summary: {label}", "",
        f"🧾 Bilang ng Bill: {len(rows)}",
        f"💰 Total Bill: {_peso(total_peso)}",
    ]
    if total_kwh > 0:
        lines.append(f"🔌 Total kWh: {total_kwh:,.1f} kWh")
    if avg_real_rate > 0:
        lines.append(f"📊 Average ₱/kWh (real): {_peso(avg_real_rate)}")

    return "\n".join(lines)


def _handle_expense_breakdown_question(question, today):
    """"Breakdown ng expenses ko last xxx" - groups every `expenses` row
    by category (Consumables/Fuel/Electricity/Maintenance) with % of
    total. Deliberately does NOT include Fixed Asset Depreciation - unlike
    modules/home_dashboard.py's own breakdown card, which injects that as
    a synthetic, live-computed line - because it isn't a real row in the
    `expenses` node, and this topic (unlike the Home dashboard) also needs
    to support finer date granularity (e.g. "this week") that
    home_dashboard.py's own mode="all"/"year"/"month" shape can't do."""
    date_from, date_to, is_all_time, label = _resolve_question_range(question, today)
    rows = _expenses_in_range(date_from, date_to, is_all_time)

    if not rows:
        return f"💸 Walang naitalang expense sa {label}."

    by_category = {}
    total = 0.0
    for r in rows:
        amt = _effective_amount(r)
        cat = r.get("category") or "Other"
        c = by_category.setdefault(cat, {"count": 0, "peso": 0.0})
        c["count"] += 1
        c["peso"] += amt
        total += amt

    lines = [f"💸 Expense Breakdown: {label}", "", f"💰 Total: {_peso(total)}", ""]
    for cat, c in sorted(by_category.items(), key=lambda x: -x[1]["peso"]):
        pct = (c["peso"] / total * 100) if total > 0 else 0.0
        lines.append(f"  • {cat}: {_peso(c['peso'])} ({pct:.0f}%, {c['count']} entry/entries)")

    lines.append("")
    lines.append(
        "ℹ️ Hindi kasama dito ang Fixed Asset Depreciation (naka-display "
        "lang sa Home dashboard - hindi siya totoong row sa expenses)."
    )
    return "\n".join(lines)


def _plastic_entries_in_range(node, date_from, date_to, is_all_time=False):
    """Same filter pattern as _expenses_in_range, for one of
    modules/plastic.py's Firebase nodes ("plastic_purchases" or
    "plastic_usage" - both share the same {date, plastic_type, qty, ...}
    row shape)."""
    raw = fb_get(node) or {}
    results = []
    for key, val in raw.items():
        if not val:
            continue
        d = _safe_parse_iso_date(val.get("date"))
        if not d:
            continue
        if not is_all_time:
            if date_from and d < date_from:
                continue
            if date_to and d > date_to:
                continue
        results.append({**val, "_id": key, "_date": d.isoformat()})
    return results


def _handle_plastic_question(question, today):
    """"Ilang plastic nabili ko last xxx" (defaults to plastic_purchases,
    with peso totals) vs "Ilang plastic nagamit" (routes to plastic_usage
    instead - that node has no peso field, only qty, since it's a
    consumption LOG, not a purchase record - see modules/plastic.py)."""
    q = (question or "").lower()
    date_from, date_to, is_all_time, label = _resolve_question_range(question, today)

    wants_usage = bool(_PLASTIC_USAGE_INTENT.search(q)) and not _PLASTIC_PURCHASE_INTENT.search(q)
    node = "plastic_usage" if wants_usage else "plastic_purchases"
    verb_label = "Nagamit" if wants_usage else "Nabili"

    rows = _plastic_entries_in_range(node, date_from, date_to, is_all_time)
    if not rows:
        return f"🛍️ Walang naitalang plastic na {verb_label.lower()} sa {label}."

    by_type = {}
    total_qty = 0.0
    total_peso = 0.0
    for r in rows:
        ptype = r.get("plastic_type") or "Other"
        qty = float(r.get("qty") or 0)
        peso = float(r.get("total") or 0)  # only plastic_purchases rows have a peso "total"
        t = by_type.setdefault(ptype, {"qty": 0.0, "peso": 0.0})
        t["qty"] += qty
        t["peso"] += peso
        total_qty += qty
        total_peso += peso

    lines = [f"🛍️ Plastic {verb_label}: {label}", "", f"📦 Total: {total_qty:,.0f} pc(s)"]
    if node == "plastic_purchases":
        lines.append(f"💰 Total Gastos: {_peso(total_peso)}")
    lines.append("")
    lines.append("Breakdown by Type:")
    for ptype, t in sorted(by_type.items(), key=lambda x: -x[1]["qty"]):
        detail = f"{t['qty']:,.0f} pc(s)"
        if node == "plastic_purchases":
            detail += f", {_peso(t['peso'])}"
        lines.append(f"  • {ptype}: {detail}")

    return "\n".join(lines)


def _handle_expenses_question(question, today):
    """Top-level dispatcher for the Expenses topic. Order matters:
    the "plastic usage derived FROM sales" check runs FIRST, before the
    generic plastic-usage branch, because it needs an honest limitation
    reply instead of a real number.

    IMPORTANT LIMITATION (by design, not a bug): modules/plastic.py's own
    docstring explicitly says plastic usage is NEVER auto-deducted from
    sales, because mode/kg-size/packaging don't map 1:1 to a specific bag
    type in a way that module can see safely (e.g. one "5Kg" sale could be
    packed in one 5Kg bag OR five 1Kg bags - there's no fixed rule). So
    "total plastic na nagamit base sa sales" can't be safely computed here
    either - inventing a ratio would just be a confident-looking guess.
    Instead this reports the ACTUAL recorded plastic_usage log entries
    (same data _handle_plastic_question already exposes) and tells the
    user plainly why a sales-derived estimate isn't offered.
    """
    q = (question or "").lower()

    if _PLASTIC_INTENT.search(q) and _SALES_BASED_INTENT.search(q):
        actual = _handle_plastic_question("ilang plastic nagamit " + question, today)
        return (
            "⚠️ Wala pang safe na paraan para kwentahin ang plastic usage "
            "base sa sales mo - iba-iba kasi ang packaging depende sa mode "
            "at kg size ng order (hindi laging 1 order = 1 bag), kaya "
            "posibleng mali ang estimate kung basta-basta lang tatantiyahin.\n\n"
            "Ito muna ang ACTUAL na naka-record na plastic usage:\n\n"
            + actual +
            "\n\nKung gusto mo pa rin ng sales-based estimate, sabihin mo "
            "lang kung anong ratio/formula gagamitin (hal. \"palagi 1 order "
            "= 1 5Kg bag\") at pwede na itong i-code."
        )

    if _ELECTRICITY_INTENT.search(q):
        return _handle_electricity_question(question, today)

    if _PLASTIC_INTENT.search(q):
        return _handle_plastic_question(question, today)

    return _handle_expense_breakdown_question(question, today)


# ---------------------------------------------------------------------------
# Custom Queries (Sept 26 2026, ISESMO's request: "gawin nating matalino
# ang system sa pamamagitan ng pag-iipon ng queries sa db") - ISESMO can
# now REGISTER his own question -> answer pairs himself, straight from the
# Ask AI page (see the "Custom Queries" panel in AI_SALES_HTML and the
# api_custom_queries_* routes below), without needing a code change or a
# redeploy every time he thinks of a new question. Stored in Firebase
# under `custom_queries/{id}` so the system's knowledge genuinely grows
# over time by accumulating in the DB - same "the intelligence is knowing
# the shape of THIS business's own data" principle as every other topic
# in this file, except now ISESMO is the one shaping it directly instead
# of it being hardcoded by me.
#
# v1 SCOPE (ISESMO's own choice - see the "Both, simple muna" answer
# logged in chat on Sept 26 2026): only query_type="canned" is
# implemented - a fixed keyword list mapped to a fixed text answer, no
# live DB math. The `query_type` field already exists on every stored
# record so a future v2 ("report" type: pick a collection, a field to
# sum/count, an optional filter - a live number, not static text) can be
# layered in later WITHOUT migrating existing v1 entries -
# _handle_custom_query below already branches on query_type for exactly
# that reason; see its "not implemented yet" branch.
#
# PRIORITY / SAFETY: a custom query is checked ONLY as the very last
# fallback in api_ai_sales_ask() - after every hardcoded topic
# (resellers/loyalty/staff/machines/expenses) AND the sales date-parser
# (local fast path, then optional Claude) have ALL already failed to make
# sense of the question. That ordering is deliberate: a custom keyword
# can only ADD capability by filling a genuine gap - it can never
# silently override or break an already-tested built-in behavior, even
# if ISESMO accidentally registers a keyword that overlaps with one.
# ---------------------------------------------------------------------------
def _find_matching_custom_query(question):
    """Returns (key, entry) for the custom_queries/{id} entry whose
    LONGEST registered keyword is found (case-insensitive substring) in
    the question, or (None, None). Same "longest match wins" tie-break as
    _find_matching_reseller, for the same reason: a short/generic
    keyword shouldn't beat a more specific one that also matches."""
    q = (question or "").lower()
    entries = fb_get("custom_queries") or {}
    best_key, best_entry, best_len = None, None, 0
    for key, entry in entries.items():
        if not entry:
            continue
        for kw in (entry.get("keywords") or []):
            kw = (kw or "").strip().lower()
            if len(kw) < 3:
                continue
            if kw in q and len(kw) > best_len:
                best_key, best_entry, best_len = key, entry, len(kw)
    return best_key, best_entry


def _handle_custom_query(entry, question, today):
    query_type = entry.get("query_type") or "canned"

    if query_type == "canned":
        answer = (entry.get("answer") or "").strip()
        if not answer:
            return ("⚠️ May na-register na custom query na tumugma sa tanong mo, "
                     "pero walang laman ang sagot nito - i-edit mo sa Custom "
                     "Queries panel.")
        return f"📝 {answer}"

    # Future query_type values (e.g. "report") aren't implemented in this
    # version of the code yet - fail safe with a clear explanation
    # instead of crashing or silently ignoring the registered query.
    return (
        f"⚠️ May na-register kang custom query na type na '{query_type}', "
        "pero hindi pa ito suportado ng bersyon na ito ng Ask AI (v1 "
        "canned-answer queries lang muna ang gumagana). Pakisabi kay "
        "Claude na i-add na ang report-type na custom queries kapag "
        "handa ka nang mag-upgrade."
    )


def _serialize_custom_query(key, entry):
    return {
        "id": key,
        "keywords": entry.get("keywords") or [],
        "answer": entry.get("answer") or "",
        "query_type": entry.get("query_type") or "canned",
        "created_by": entry.get("created_by"),
        "created_at": entry.get("created_at"),
        "updated_at": entry.get("updated_at"),
    }


def _validate_custom_query_input(body):
    """Shared validation for create/update - returns (keywords, answer,
    error_or_None). Keeps the two routes below from drifting out of sync
    on what counts as a valid custom query."""
    keywords = [str(k).strip() for k in (body.get("keywords") or []) if str(k).strip()]
    answer = (body.get("answer") or "").strip()

    if not keywords:
        return None, None, "Kailangan ng kahit isang keyword."
    if len(keywords) > 10:
        return None, None, "Max 10 keywords lang bawat query."
    if any(len(k) < 3 for k in keywords):
        return None, None, "Bawat keyword dapat 3+ characters (para hindi masyadong generic)."
    if not answer:
        return None, None, "Kailangan ng sagot."
    if len(answer) > 2000:
        return None, None, "Ang haba naman ng sagot, paikliin mo (max 2000 characters)."
    return keywords, answer, None


# ---------------------------------------------------------------------------
# Custom Queries CRUD routes - all ISESMO-only (same @isesmo_required guard
# as every other route in this file).
# ---------------------------------------------------------------------------
@ai_sales_bp.route("/api/ai-sales/custom-queries", methods=["GET"])
@isesmo_required
def api_custom_queries_list():
    entries = fb_get("custom_queries") or {}
    items = [_serialize_custom_query(k, v) for k, v in entries.items() if v]
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return jsonify({"ok": True, "items": items})


@ai_sales_bp.route("/api/ai-sales/custom-queries", methods=["POST"])
@isesmo_required
def api_custom_queries_create():
    keywords, answer, err = _validate_custom_query_input(request.json or {})
    if err:
        return jsonify({"ok": False, "error": err}), 400

    new_entry = {
        "keywords": keywords,
        "answer": answer,
        "query_type": "canned",
        "created_by": (session.get("staff_name") or "").strip(),
        "created_at": _manila_now_iso(),
    }
    try:
        ref = _fb_db.reference("custom_queries").push(new_entry)
        return jsonify({"ok": True, "item": _serialize_custom_query(ref.key, new_entry)})
    except Exception as e:
        print(f"[ai-sales] custom query create error: {e}", flush=True)
        return jsonify({"ok": False, "error": "Hindi na-save. Subukan mo ulit."}), 500


@ai_sales_bp.route("/api/ai-sales/custom-queries/<query_id>", methods=["PUT"])
@isesmo_required
def api_custom_queries_update(query_id):
    keywords, answer, err = _validate_custom_query_input(request.json or {})
    if err:
        return jsonify({"ok": False, "error": err}), 400

    existing = fb_get(f"custom_queries/{query_id}")
    if not existing:
        return jsonify({"ok": False, "error": "Hindi mahanap ang query na ito - baka na-delete na."}), 404

    updated = {
        **existing,
        "keywords": keywords,
        "answer": answer,
        "updated_at": _manila_now_iso(),
    }
    try:
        _fb_db.reference(f"custom_queries/{query_id}").set(updated)
        return jsonify({"ok": True, "item": _serialize_custom_query(query_id, updated)})
    except Exception as e:
        print(f"[ai-sales] custom query update error: {e}", flush=True)
        return jsonify({"ok": False, "error": "Hindi na-save ang edit. Subukan mo ulit."}), 500


@ai_sales_bp.route("/api/ai-sales/custom-queries/<query_id>", methods=["DELETE"])
@isesmo_required
def api_custom_queries_delete(query_id):
    try:
        _fb_db.reference(f"custom_queries/{query_id}").delete()
        return jsonify({"ok": True})
    except Exception as e:
        print(f"[ai-sales] custom query delete error: {e}", flush=True)
        return jsonify({"ok": False, "error": "Hindi na-delete. Subukan mo ulit."}), 500


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@ai_sales_bp.route("/ai-sales")
@isesmo_required
def ai_sales_page():
    return render_template_string(AI_SALES_HTML, staff_name=session.get("staff_name"))


@ai_sales_bp.route("/api/ai-sales/ask", methods=["POST"])
@isesmo_required
def api_ai_sales_ask():
    question = ((request.json or {}).get("question") or "").strip()
    if not question:
        return jsonify({"ok": False, "error": "Wala kang tinanong."}), 400
    if len(question) > 500:
        return jsonify({"ok": False, "error": "Ang haba naman ng tanong, paikliin mo."}), 400

    today = _manila_today()

    # Multi-topic router (Sept 26 2026): "Ask AI" now covers resellers,
    # loyalty/rewards, staff and machines on top of sales - all 100% local
    # (no AI/internet needed), see the big comment block above
    # _detect_topic for the full design rationale. Sales stays the
    # default/fallback topic since it's the one that has to catch bare
    # date phrases ("this week") with no topic keyword at all.
    topic = _detect_topic(question)
    if topic != "sales":
        try:
            if topic == "resellers":
                reply = _handle_resellers_question(question, today)
            elif topic == "loyalty":
                reply = _handle_loyalty_question(question)
            elif topic == "staff":
                reply = _handle_staff_question(question)
            elif topic == "machines":
                reply = _handle_machines_question(question, today)
            else:  # "expenses"
                reply = _handle_expenses_question(question, today)
            return jsonify({"ok": True, "reply": reply})
        except Exception as e:
            print(f"[ai-sales] topic handler error (topic={topic}): {e}", flush=True)
            return jsonify({
                "ok": False,
                "error": "May error sa pagkuha ng data para dito. Subukan mo ulit.",
            }), 500

    # Try the local (no-AI) fast path first para sa common/fixed phrases
    # ("today", "this week", "last month", month+year, bare year, "all time",
    # atbp). Zero latency, zero API usage, immune sa rate limits/overload.
    #
    # OFFLINE-FIRST BY DESIGN (Sept 26 2026, ISESMO's explicit call after
    # the API billing/key-exposure hassle): Claude is now a purely OPTIONAL
    # enhancement, not a requirement. It's only even attempted when
    # ANTHROPIC_API_KEY is actually set in the environment - if it's
    # unset/blank (no credits set up yet, or ISESMO chose not to use it),
    # this skips the network call entirely and falls straight through to
    # the friendly "here's what you can ask" message below. That means
    # every topic this feature supports (sales, resellers, loyalty, staff,
    # machines) keeps working with ZERO ai/internet dependency - the only
    # thing that needs Claude is a genuinely freeform/ambiguous SALES date
    # phrase the local parser can't confidently match. If ISESMO adds the
    # API key + credits later, this starts using it automatically, no code
    # change needed - and if he removes the key again, it falls back to
    # fully local with no error either way.
    parsed = _try_local_date_extraction(question, today)
    err = None
    if parsed is None and os.environ.get("ANTHROPIC_API_KEY", "").strip():
        parsed, err = _ask_claude_for_date_range(question, today.isoformat())
    if err:
        return jsonify({"ok": False, "error": err}), 502

    if not parsed or not parsed.get("is_sales_question"):
        # CUSTOM QUERIES fallback (Sept 26 2026): reached ONLY once every
        # hardcoded topic AND the sales date-parser (local fast path, then
        # optional Claude) have ALL already failed to make sense of the
        # question - see the big design-rationale comment above
        # _find_matching_custom_query for why it's checked here and not
        # earlier. This is what lets ISESMO grow the system's knowledge
        # himself over time (Custom Queries panel on the Ask AI page)
        # without needing a code change for every new question he thinks of.
        custom_key, custom_entry = _find_matching_custom_query(question)
        if custom_entry:
            return jsonify({"ok": True, "reply": _handle_custom_query(custom_entry, question, today)})

        return jsonify({
            "ok": True,
            "reply": "Hindi ko na-gets kung ano ang tinatanong mo. Subukan mo ulit, hal.:\n"
                     "  • \"magkano benta last May\" / \"total sales this week\"\n"
                     "  • \"credit balance ni [store name]\" / \"listahan ng resellers\"\n"
                     "  • \"sino top loyalty points\" / \"ano available rewards\"\n"
                     "  • \"sino active staff\"\n"
                     "  • \"aling machine overdue sa PM\" / \"total harvest this week\"\n"
                     "  • \"electricity bill ko last month\" / \"breakdown ng expenses this year\"\n"
                     "  • \"ilang plastic nabili last month\"\n\n"
                     "Tip: kung palagi mong itinatanong ito, i-register mo na lang sa "
                     "\"⚙️ Custom Queries\" section sa taas para may fixed sagot na agad "
                     "sa susunod.",
        })

    is_all_time = bool(parsed.get("is_all_time"))
    date_from = _safe_parse_iso_date(parsed.get("date_from"))
    date_to = _safe_parse_iso_date(parsed.get("date_to"))
    label = parsed.get("label") or "Custom Range"

    if not is_all_time and not date_from and not date_to:
        return jsonify({
            "ok": True,
            "reply": "Hindi ko na-gets kung anong date range ang tinutukoy mo. "
                     "Subukan mo ulit na mas specific (hal. \"sales noong Mayo 2026\" o \"this week\").",
        })

    records = _get_sales_in_range(date_from, date_to, is_all_time=is_all_time)
    summary = _summarize_sales(records)
    reply = _format_sales_reply(label, summary)

    return jsonify({"ok": True, "reply": reply, "label": label, "summary": summary})


# ---------------------------------------------------------------------------
# UI - same visual language as the rest of the app (Omega blue theme,
# .nav-pill links, card-style layout)
# ---------------------------------------------------------------------------
AI_SALES_HTML = """
<!DOCTYPE html>
<html translate="no">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<!-- Chrome auto-translate is a real bug here, not a cosmetic one: this page
     mixes English and Tagalog ("Ask Sales", Taglish questions), which makes
     Chrome offer/auto-apply "Translate to English". Translate rewrites text
     nodes in the DOM - including the chat bubbles - and it mangled the
     Gemini API URL shown in error messages (silently dropped a chunk of
     "v1beta/models/gemini-2.5-flash", producing a fake-looking 404 that
     wasted a long debugging session on Sept 25, 2026, before this was
     found). These two tags tell Chrome/Google Translate to leave the page
     alone entirely - do not remove them. -->
<meta name="google" content="notranslate">
<title>Ask AI - Omega Ice</title>
<style>
*{box-sizing:border-box}
body{font-family:sans-serif;background:#eef7ff;margin:0;padding:12px;padding-bottom:24px;color:#1a1a1a}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;padding:4px 2px}
.topbar h1{font-size:16px;color:#00609C;margin:0;font-weight:700}
.nav-pill{display:inline-block;padding:6px 12px;border-radius:20px;border:1px solid #ccd;background:#fff;color:#00609C;font-size:12px;text-decoration:none;font-weight:600}
.card{background:#fff;border-radius:12px;padding:14px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
#chatBox{height:60vh;min-height:320px;overflow-y:auto;display:flex;flex-direction:column;gap:10px;padding:6px}
.msg{max-width:88%;padding:10px 14px;border-radius:14px;font-size:13px;line-height:1.5;white-space:pre-wrap}
.msg.user{align-self:flex-end;background:linear-gradient(135deg,#00609C,#0096D6);color:#fff;border-bottom-right-radius:4px}
.msg.bot{align-self:flex-start;background:#f0f4f8;color:#1a1a1a;border-bottom-left-radius:4px}
.msg.bot.error{background:#fef2f2;color:#991b1b}
.msg.bot.loading{background:#f0f4f8;color:#888;font-style:italic}
.msg-text{display:block}
.msg-copy-btn{display:block;margin-top:6px;font-size:10px;padding:3px 9px;border-radius:8px;border:1px solid #ccd;background:#fff;color:#00609C;cursor:pointer;font-weight:600}
.msg-copy-btn:active{background:#eef7ff}
.inputRow{display:flex;gap:8px;margin-top:12px}
#questionInput{flex:1;padding:12px;border-radius:10px;border:1px solid #ccd;font-size:14px}
#micBtn{padding:12px 14px;border-radius:10px;border:1px solid #ccd;background:#fff;color:#00609C;font-size:16px;cursor:pointer;line-height:1}
#micBtn.listening{background:#fef2f2;border-color:#f3c2c2;color:#991b1b;animation:micPulse 1.1s infinite}
#micBtn:disabled{opacity:.35;cursor:not-allowed}
@keyframes micPulse{0%{opacity:1}50%{opacity:.4}100%{opacity:1}}
.voiceRow{margin-top:8px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
#handsFreeBtn{font-size:11px;padding:6px 12px;border-radius:20px;border:1px solid #ccd;background:#fff;color:#00609C;cursor:pointer;font-weight:700}
#handsFreeBtn.active{background:#00609C;color:#fff;border-color:#00609C;animation:micPulse 1.6s infinite}
#handsFreeBtn:disabled{opacity:.35;cursor:not-allowed}
#handsFreeStatus{display:none;font-size:11px;color:#991b1b;font-weight:600;line-height:1.4}
#askBtn{padding:12px 18px;border-radius:10px;border:none;background:#00609C;color:#fff;font-weight:600;font-size:14px}
#askBtn:disabled{opacity:.6}
.examples{font-size:11px;color:#888;margin-top:8px}
.examples span{display:inline-block;background:#f0f4f8;border-radius:12px;padding:4px 10px;margin:3px 3px 0 0;cursor:pointer}
.examples span.fill{background:#fff7e6;border:1px dashed #e0b34d}
.ex-hint{font-size:11px;color:#00609C;font-weight:700;margin-bottom:2px}
.ex-group{margin:6px 0}
.ex-group-header{display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none;background:#f0f4f8;border-radius:8px;padding:7px 10px;font-size:12px;color:#00609C;font-weight:700}
.ex-group-header:active{background:#e2ebf3}
.ex-group-toggle{font-size:11px;color:#00609C}
.ex-group-body{display:none;padding-top:6px}
.cq-card{margin-top:12px}
.cq-header{display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none}
.cq-header h2{font-size:14px;color:#00609C;margin:0;font-weight:700}
.cq-toggle{font-size:12px;color:#00609C}
.cq-hint{font-size:11px;color:#888;margin:10px 0;line-height:1.5}
.cq-empty{font-size:12px;color:#999;font-style:italic;margin:8px 0}
.cq-item{background:#f8fafc;border-radius:10px;padding:10px;margin-bottom:8px}
.cq-item-kw{font-size:11px;color:#00609C;font-weight:700;margin-bottom:4px}
.cq-item-ans{font-size:13px;color:#333;white-space:pre-wrap;margin-bottom:6px;line-height:1.5}
.cq-item-actions{display:flex;gap:8px}
.cq-item-actions button{font-size:11px;padding:5px 10px;border-radius:8px;border:1px solid #ccd;background:#fff;cursor:pointer}
.cq-item-actions button.danger{color:#991b1b;border-color:#f3c2c2}
.cq-form{margin-top:14px;padding-top:14px;border-top:1px solid #eee}
.cq-form label{display:block;font-size:11px;color:#666;margin:8px 0 4px;font-weight:600}
.cq-form input,.cq-form textarea{width:100%;padding:10px;border-radius:8px;border:1px solid #ccd;font-size:13px;font-family:inherit;resize:vertical}
.cq-form-actions{display:flex;gap:8px;margin-top:10px}
.cq-form-actions button{padding:10px 16px;border-radius:10px;border:none;background:#00609C;color:#fff;font-weight:600;font-size:13px;cursor:pointer}
.cq-form-actions button.cancel{background:#eee;color:#555}
</style>
</head>
<body class="notranslate">
<div class="topbar">
  <h1>💬 Ask AI (ISESMO Only)</h1>
  <a href="/cashier" class="nav-pill">← Back to Sales</a>
</div>

<div class="card">
  <div id="chatBox" class="notranslate" translate="no"></div>
  <div class="inputRow">
    <input type="text" id="questionInput" placeholder="hal. magkano benta ko last May?" autocomplete="off">
    <button id="micBtn" type="button" title="Voice input">🎤</button>
    <button id="askBtn" onclick="askQuestion()">Ask</button>
  </div>
  <div class="voiceRow">
    <button id="handsFreeBtn" type="button">🎧 Hands-Free</button>
    <span id="handsFreeStatus">🎧 Naka-ON — sabihin "OMG" tapos yung tanong (hal. "OMG magkano benta ko today")</span>
  </div>
  <div class="examples">
    <div class="ex-hint">👆 Puting chip = direktang magse-send. Yellow/dashed chip = i-fill lang (palitan ang [store name] bago i-send). Tap sa pangalan ng category para buksan/isara.</div>

    <div class="ex-group">
      <div class="ex-group-header" onclick="toggleExampleGroup(this)">
        <span>📊 Sales</span>
        <span class="ex-group-toggle">▼</span>
      </div>
      <div class="ex-group-body">
        <span onclick="sendExample(this)">magkano benta ko last May?</span>
        <span onclick="sendExample(this)">total sales today</span>
        <span onclick="sendExample(this)">total sales this week</span>
        <span onclick="sendExample(this)">total sales this month</span>
        <span onclick="sendExample(this)">total sales last month</span>
        <span onclick="sendExample(this)">total sales this year</span>
        <span onclick="sendExample(this)">total sales last year</span>
        <span onclick="sendExample(this)">sino top reseller this month?</span>
        <span onclick="sendExample(this)">all time sales</span>
      </div>
    </div>

    <div class="ex-group">
      <div class="ex-group-header" onclick="toggleExampleGroup(this)">
        <span>🏪 Resellers</span>
        <span class="ex-group-toggle">▼</span>
      </div>
      <div class="ex-group-body">
        <span onclick="sendExample(this)">listahan ng resellers</span>
        <span onclick="sendExample(this)">sino may pinakamalaking utang?</span>
        <span class="fill" onclick="fillExample(this)">credit balance ni [store name]?</span>
        <span class="fill" onclick="fillExample(this)">presyo per kg ni [store name]?</span>
        <span class="fill" onclick="fillExample(this)">huling order ni [store name]?</span>
        <span class="fill" onclick="fillExample(this)">ilang beses nag-order si [store name] this month?</span>
        <span class="fill" onclick="fillExample(this)">magkano kinita ni [store name]?</span>
      </div>
    </div>

    <div class="ex-group">
      <div class="ex-group-header" onclick="toggleExampleGroup(this)">
        <span>🏆 Loyalty &amp; Rewards</span>
        <span class="ex-group-toggle">▼</span>
      </div>
      <div class="ex-group-body">
        <span onclick="sendExample(this)">sino top loyalty points?</span>
        <span onclick="sendExample(this)">ano available rewards?</span>
        <span class="fill" onclick="fillExample(this)">ilang points na meron si [store name]?</span>
        <span class="fill" onclick="fillExample(this)">ilang beses na-redeem ni [store name]?</span>
      </div>
    </div>

    <div class="ex-group">
      <div class="ex-group-header" onclick="toggleExampleGroup(this)">
        <span>👥 Staff</span>
        <span class="ex-group-toggle">▼</span>
      </div>
      <div class="ex-group-body">
        <span onclick="sendExample(this)">sino active staff?</span>
        <span onclick="sendExample(this)">listahan ng lahat ng staff</span>
      </div>
    </div>

    <div class="ex-group">
      <div class="ex-group-header" onclick="toggleExampleGroup(this)">
        <span>🧊 Machines &amp; Equipment</span>
        <span class="ex-group-toggle">▼</span>
      </div>
      <div class="ex-group-body">
        <span onclick="sendExample(this)">aling machine overdue sa PM?</span>
        <span onclick="sendExample(this)">total harvest this week?</span>
        <span onclick="sendExample(this)">listahan ng machines</span>
      </div>
    </div>

    <div class="ex-group">
      <div class="ex-group-header" onclick="toggleExampleGroup(this)">
        <span>💸 Expenses</span>
        <span class="ex-group-toggle">▼</span>
      </div>
      <div class="ex-group-body">
        <span onclick="sendExample(this)">electricity bill ko this month?</span>
        <span onclick="sendExample(this)">summary ng electricity this year</span>
        <span onclick="sendExample(this)">summary ng electricity last year</span>
        <span onclick="sendExample(this)">breakdown per month ng electricity bill this year</span>
        <span onclick="sendExample(this)">breakdown ng expenses this month</span>
        <span onclick="sendExample(this)">ilang plastic nabili this month?</span>
        <span onclick="sendExample(this)">ilang plastic nagamit this month?</span>
      </div>
    </div>
  </div>
</div>

<div class="card cq-card">
  <div class="cq-header" onclick="toggleCustomQueries()">
    <h2>⚙️ Custom Queries <span id="cqCount"></span></h2>
    <span class="cq-toggle" id="cqToggleIcon">Ipakita ▼</span>
  </div>
  <div id="cqPanel" style="display:none">
    <p class="cq-hint">
      Dito ka pwede magdagdag ng sarili mong tanong + sagot - kapag hindi ma-gets
      ng system ang isang tanong (o gusto mo talaga ng sarili mong fixed na
      sagot), i-register mo dito. Halimbawa: keywords = "presyo ng diesel,
      magkano diesel", sagot = "₱65/liter ang presyo ng diesel namin ngayon."
      <br><br>
      ⚠️ Fixed/static na text ang sagot dito - hindi ito kukuha ng live na
      numbers mula sa DB (hindi tulad ng sales/expenses/atbp sa itaas). Kung
      nagbago ang totoong sagot, kailangan mo itong i-edit ulit dito.
    </p>

    <div id="cqList"><p class="cq-empty">Tap "Ipakita" para mag-load.</p></div>

    <div class="cq-form">
      <label>Keywords (comma-separated, 3+ letters bawat isa)</label>
      <input type="text" id="cqKeywords" placeholder="hal. presyo ng diesel, magkano diesel">
      <label>Sagot</label>
      <textarea id="cqAnswer" rows="3" placeholder="Itype dito ang sagot na gusto mong ibigay ng system"></textarea>
      <div class="cq-form-actions">
        <button id="cqSaveBtn" onclick="saveCustomQuery()">➕ I-save</button>
        <button id="cqCancelBtn" class="cancel" onclick="cancelEditCustomQuery()" style="display:none">Cancel</button>
      </div>
    </div>
  </div>
</div>

<script>
const chatBox = document.getElementById('chatBox');
const questionInput = document.getElementById('questionInput');
const askBtn = document.getElementById('askBtn');
const micBtn = document.getElementById('micBtn');

function addMessage(text, cls){
  const div = document.createElement('div');
  div.className = 'msg ' + cls;

  const textSpan = document.createElement('span');
  textSpan.className = 'msg-text';
  textSpan.textContent = text;
  div.appendChild(textSpan);

  // Copy button (Sept 26 2026, ISESMO request) - only on a REAL bot
  // reply, never the transient "Sinusuri ko..." loading bubble and never
  // the person's own message (standard chat-app convention: you copy the
  // ANSWER, e.g. to paste a sales report into Messenger/Viber, not your
  // own question).
  if(cls.indexOf('bot') !== -1 && cls.indexOf('loading') === -1){
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'msg-copy-btn';
    copyBtn.textContent = '📋 Copy';
    copyBtn.addEventListener('click', function(){
      copyMessageText(text, copyBtn);
    });
    div.appendChild(copyBtn);
  }

  chatBox.appendChild(div);
  chatBox.scrollTop = chatBox.scrollHeight;
  return div;
}

function fillExample(el){
  // Used for templated per-customer questions (contain "[store name]") -
  // these can't be blindly auto-sent since they'd literally search for a
  // reseller named "[store name]", so this only fills the input and lets
  // the person edit the placeholder before sending.
  questionInput.value = el.textContent;
  questionInput.focus();
}

function sendExample(el){
  // Used for every OTHER example chip (no placeholder to edit) - fills
  // the input AND immediately submits, per ISESMO's request: "tap ko
  // nalang, auto send na" (Sept 26 2026).
  questionInput.value = el.textContent;
  askQuestion();
}

function toggleExampleGroup(headerEl){
  // Per-category collapsible dropdown for the example chips (Sept 26
  // 2026 - "gawing drop down list per type para malinis tignan"). All
  // groups start collapsed via CSS (.ex-group-body{display:none}), so on
  // first click body.style.display is still empty string - fall back to
  // the computed style to know the TRUE current state instead of
  // assuming based on the (possibly unset) inline style alone.
  const body = headerEl.nextElementSibling;
  const toggleIcon = headerEl.querySelector('.ex-group-toggle');
  const isCurrentlyHidden = getComputedStyle(body).display === 'none';
  body.style.display = isCurrentlyHidden ? 'block' : 'none';
  if(toggleIcon) toggleIcon.textContent = isCurrentlyHidden ? '▲' : '▼';
}

async function askQuestion(){
  const q = questionInput.value.trim();
  if(!q) return;
  addMessage(q, 'user');
  questionInput.value = '';
  askBtn.disabled = true;
  const loadingEl = addMessage('Sinusuri ko yung sales data...', 'bot loading');

  try {
    const res = await fetch('/api/ai-sales/ask', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({question: q})
    });
    const data = await res.json();
    loadingEl.remove();
    if(data.ok){
      addMessage(data.reply, 'bot');
    } else {
      addMessage('⚠️ ' + (data.error || 'May error na hindi inaasahan.'), 'bot error');
    }
  } catch(e){
    loadingEl.remove();
    addMessage('⚠️ Hindi ma-reach ang server. Check your connection.', 'bot error');
  } finally {
    askBtn.disabled = false;
    questionInput.focus();
  }
}

questionInput.addEventListener('keydown', function(e){
  if(e.key === 'Enter') askQuestion();
});

// ---------------------------------------------------------------------
// Copy button (Sept 26 2026) - copies a bot message's plain text to the
// clipboard so ISESMO can paste a sales report straight into Messenger/
// Viber/Excel without retyping it. Two-tier approach: the modern
// navigator.clipboard API first (needs https, which Render.com already
// gives us), falling back to the old execCommand('copy') trick (via a
// hidden offscreen textarea) for older/unsupported browsers so the
// button still works either way instead of silently doing nothing.
// ---------------------------------------------------------------------
function copyMessageText(text, btnEl){
  const originalLabel = '📋 Copy';

  function showCopied(){
    btnEl.textContent = '✅ Copied!';
    setTimeout(function(){ btnEl.textContent = originalLabel; }, 1500);
  }
  function showFailed(){
    btnEl.textContent = '⚠️ Failed';
    setTimeout(function(){ btnEl.textContent = originalLabel; }, 1500);
  }

  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(showCopied).catch(function(){
      fallbackCopyText(text, showCopied, showFailed);
    });
  } else {
    fallbackCopyText(text, showCopied, showFailed);
  }
}

function fallbackCopyText(text, onSuccess, onFail){
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    ta.style.top = '0';
    ta.style.left = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    if(ok){ onSuccess(); } else { onFail(); }
  } catch(e){
    onFail();
  }
}

// ---------------------------------------------------------------------
// Voice input (Sept 26 2026) - lets ISESMO SPEAK a question instead of
// typing it, using the browser's built-in Web Speech API. This needs
// Chrome (desktop or Android) - Safari/iOS and Firefox don't implement
// SpeechRecognition at all as of this writing - so the mic/hands-free
// buttons gracefully disable themselves instead of throwing an error
// when it's missing, rather than pretending voice input is available
// everywhere.
//
// TWO MODES share one underlying recognition object:
//
//   'manual' (tap mic button once): recognized speech only FILLS the
//   input box - it does NOT auto-send. Speech recognition can mishear
//   numbers, peso amounts, or reseller names (especially mixed Taglish),
//   so ISESMO gets a chance to glance at/correct the text before
//   anything is actually sent.
//
//   'handsfree' (toggle the 🎧 Hands-Free button ON, Sept 26 2026 ISESMO
//   request: "kahit di ko na pindutin yung mic, may keyword lang na 'OMG'
//   tapos auto sasagot"): the mic stays continuously listening (via a
//   restart-on-end loop, NOT the browser's own continuous=true mode,
//   which is unreliable on mobile Chrome). Every time a phrase is heard,
//   it's checked for the wake word "OMG" - if found, everything AFTER it
//   becomes the question and is auto-filled AND auto-sent immediately,
//   no tap needed. This is the opposite safety trade-off from manual
//   mode (auto-send instead of review-first) - that's what ISESMO
//   explicitly asked for, but it does mean a misheard wake-word phrase
//   can auto-send a wrong question. Off by default; ISESMO turns it on
//   deliberately, and it auto-stops if the browser tab goes to the
//   background (mobile Chrome pauses mic/JS timers there anyway, and
//   silently listening in the background would be unexpected) or after
//   repeated hard errors in a row (bad mic, revoked permission, etc.) so
//   it can't loop forever silently broken.
// ---------------------------------------------------------------------
const SpeechRecognitionAPI = window.SpeechRecognition || window.webkitSpeechRecognition;
const handsFreeBtn = document.getElementById('handsFreeBtn');
const handsFreeStatus = document.getElementById('handsFreeStatus');
const HANDS_FREE_WAKE_WORD = /\\bomg\\b/i;
const HANDS_FREE_MAX_ERROR_STREAK = 5;
const HANDS_FREE_RESTART_DELAY_MS = 350;

let voiceRecognition = null;
let isListening = false;
let voiceMode = 'idle'; // 'idle' | 'manual' | 'handsfree'
let handsFreeEnabled = false;
let handsFreeRestartTimer = null;
let handsFreeErrorStreak = 0;

if(!SpeechRecognitionAPI){
  micBtn.disabled = true;
  micBtn.title = 'Hindi supported ang voice input sa browser na ito - gamitin ang Chrome.';
  handsFreeBtn.disabled = true;
  handsFreeBtn.title = 'Hindi supported ang voice input sa browser na ito - gamitin ang Chrome.';
} else {
  voiceRecognition = new SpeechRecognitionAPI();
  voiceRecognition.lang = 'fil-PH';
  voiceRecognition.continuous = false;
  voiceRecognition.interimResults = true;
  voiceRecognition.maxAlternatives = 1;

  voiceRecognition.onstart = function(){
    isListening = true;
    if(voiceMode === 'manual'){
      micBtn.classList.add('listening');
      micBtn.textContent = '⏹️';
    }
    // hands-free mode intentionally has NO per-utterance icon flicker -
    // the persistent handsFreeStatus label already communicates "always
    // listening" without redrawing on every restart cycle.
  };

  voiceRecognition.onresult = function(event){
    let transcript = '';
    let isFinal = false;
    for(let i = 0; i < event.results.length; i++){
      transcript += event.results[i][0].transcript;
      if(event.results[i].isFinal) isFinal = true;
    }
    if(voiceMode === 'handsfree'){
      if(isFinal) handleHandsFreeTranscript(transcript);
    } else {
      questionInput.value = transcript;
    }
  };

  voiceRecognition.onerror = function(event){
    if(event.error === 'not-allowed' || event.error === 'service-not-allowed'){
      addMessage('⚠️ Hindi pinayagan ang microphone access. I-allow mo muna sa browser settings.', 'bot error');
      if(voiceMode === 'handsfree') stopHandsFree();
      return;
    }
    if(voiceMode === 'handsfree'){
      if(event.error === 'no-speech' || event.error === 'aborted'){
        // Expected/normal while just waiting for the next "OMG" - the
        // onend restart-loop below handles resuming, no need to alarm
        // ISESMO with an error message for ordinary silence.
        handsFreeErrorStreak = 0;
        return;
      }
      handsFreeErrorStreak++;
      if(handsFreeErrorStreak >= HANDS_FREE_MAX_ERROR_STREAK){
        addMessage('⚠️ Paulit-ulit na nag-eerror ang Hands-Free listening (' + event.error + '). In-OFF ko muna - i-tap ulit ang Hands-Free kapag ok na ang mic.', 'bot error');
        stopHandsFree();
      }
      return;
    }
    if(event.error !== 'no-speech' && event.error !== 'aborted'){
      addMessage('⚠️ May problema sa voice input (' + event.error + '). Subukan ulit.', 'bot error');
    }
  };

  voiceRecognition.onend = function(){
    isListening = false;
    if(voiceMode === 'handsfree' && handsFreeEnabled){
      handsFreeRestartTimer = setTimeout(function(){
        if(!handsFreeEnabled) return;
        try {
          voiceRecognition.start();
        } catch(e){
          // Already running, or a transient platform hiccup - the next
          // onend cycle (or the error-streak counter above) will handle
          // it instead of throwing here.
        }
      }, HANDS_FREE_RESTART_DELAY_MS);
      return;
    }
    micBtn.classList.remove('listening');
    micBtn.textContent = '🎤';
    questionInput.focus();
  };

  micBtn.addEventListener('click', function(){
    if(handsFreeEnabled) return; // manual mic is disabled while hands-free is on, but guard anyway
    if(isListening){
      voiceRecognition.stop();
      return;
    }
    voiceMode = 'manual';
    questionInput.value = '';
    try {
      voiceRecognition.start();
    } catch(e){
      addMessage('⚠️ Hindi ma-start ang voice input. Subukan ulit.', 'bot error');
    }
  });

  handsFreeBtn.addEventListener('click', function(){
    if(handsFreeEnabled){ stopHandsFree(); } else { startHandsFree(); }
  });

  // Mobile Chrome pauses mic access and JS timers once a tab goes to the
  // background anyway, so hands-free listening would silently die there
  // regardless - stopping it explicitly (instead of leaving it in a
  // half-broken state) and telling ISESMO is more honest than pretending
  // it's still listening.
  document.addEventListener('visibilitychange', function(){
    if(document.hidden && handsFreeEnabled){
      stopHandsFree();
      addMessage('🎧 Na-off ang Hands-Free dahil umalis ka sa tab/app. I-tap ulit pag balik ka dito.', 'bot');
    }
  });
}

function handleHandsFreeTranscript(transcript){
  const match = HANDS_FREE_WAKE_WORD.exec(transcript);
  if(!match) return; // wake word not heard in this utterance - ignore silently, keep listening
  const query = transcript.slice(match.index + match[0].length).trim();
  if(!query) return; // said "OMG" alone with nothing after it - nothing to ask yet
  questionInput.value = query;
  askQuestion(); // per ISESMO's explicit request: auto-send, no manual "Ask" tap needed
}

function startHandsFree(){
  handsFreeEnabled = true;
  voiceMode = 'handsfree';
  handsFreeErrorStreak = 0;
  micBtn.disabled = true;
  handsFreeBtn.classList.add('active');
  handsFreeBtn.textContent = '🎧 Naka-ON (i-tap para i-OFF)';
  handsFreeStatus.style.display = 'block';
  questionInput.value = '';
  try {
    voiceRecognition.start();
  } catch(e){
    addMessage('⚠️ Hindi ma-start ang Hands-Free listening. Subukan ulit.', 'bot error');
    stopHandsFree();
  }
}

function stopHandsFree(){
  handsFreeEnabled = false;
  voiceMode = 'idle';
  handsFreeErrorStreak = 0;
  if(handsFreeRestartTimer){
    clearTimeout(handsFreeRestartTimer);
    handsFreeRestartTimer = null;
  }
  try { voiceRecognition.stop(); } catch(e){}
  micBtn.disabled = false;
  handsFreeBtn.classList.remove('active');
  handsFreeBtn.textContent = '🎧 Hands-Free';
  handsFreeStatus.style.display = 'none';
}

// ---------------------------------------------------------------------
// Custom Queries panel (Sept 26 2026) - list/add/edit/delete ISESMO's
// own registered question -> answer pairs. Lazy-loaded (only fetches
// when the panel is first opened) so the page stays light by default.
// ---------------------------------------------------------------------
const cqPanel = document.getElementById('cqPanel');
const cqToggleIcon = document.getElementById('cqToggleIcon');
const cqList = document.getElementById('cqList');
const cqKeywords = document.getElementById('cqKeywords');
const cqAnswer = document.getElementById('cqAnswer');
const cqSaveBtn = document.getElementById('cqSaveBtn');
const cqCancelBtn = document.getElementById('cqCancelBtn');
let cqLoadedOnce = false;
let cqEditingId = null;

function toggleCustomQueries(){
  const willShow = cqPanel.style.display === 'none';
  cqPanel.style.display = willShow ? 'block' : 'none';
  cqToggleIcon.textContent = willShow ? 'Itago ▲' : 'Ipakita ▼';
  if(willShow && !cqLoadedOnce){
    cqLoadedOnce = true;
    loadCustomQueries();
  }
}

function escapeHtml(s){
  const d = document.createElement('div');
  d.textContent = s == null ? '' : s;
  return d.innerHTML;
}

async function loadCustomQueries(){
  cqList.innerHTML = '<p class="cq-empty">Loading...</p>';
  try {
    const res = await fetch('/api/ai-sales/custom-queries');
    const data = await res.json();
    if(!data.ok){
      cqList.innerHTML = '<p class="cq-empty">May error sa pag-load.</p>';
      return;
    }
    const items = data.items || [];
    document.getElementById('cqCount').textContent = items.length ? `(${items.length})` : '';
    if(!items.length){
      cqList.innerHTML = '<p class="cq-empty">Wala ka pang na-register na custom query.</p>';
      return;
    }
    cqList.innerHTML = '';
    items.forEach(item => {
      const div = document.createElement('div');
      div.className = 'cq-item';
      const kwText = (item.keywords || []).join(', ');
      // NOTE (Sept 26 2026 bugfix): deliberately using data-id + a
      // delegated click listener below instead of an inline
      // onclick="...('ID')" string. An inline onclick built via string
      // concatenation needs a JS-level escaped quote (\') around the id -
      // but this whole page is itself a Python triple-quoted string
      // (AI_SALES_HTML), and Python's OWN parser treats \' as ITS escape
      // for a literal apostrophe too, silently eating the backslash
      // before the JS ever reaches the browser. That broke the id string
      // mid-token, which is a JS syntax error, which kills the ENTIRE
      // <script> block (not just this button) - explains why "Ask" and
      // "Ipakita" both stopped working. data-id sidesteps the whole
      // class of bug: no quotes to escape across two language layers.
      div.innerHTML =
        '<div class="cq-item-kw">🔑 ' + escapeHtml(kwText) + '</div>' +
        '<div class="cq-item-ans">' + escapeHtml(item.answer) + '</div>' +
        '<div class="cq-item-actions">' +
          '<button data-action="edit" data-id="' + escapeHtml(item.id) + '">✏️ Edit</button>' +
          '<button class="danger" data-action="delete" data-id="' + escapeHtml(item.id) + '">🗑️ Delete</button>' +
        '</div>';
      cqList.appendChild(div);
    });
  } catch(e){
    cqList.innerHTML = '<p class="cq-empty">Hindi ma-reach ang server.</p>';
  }
}

// Delegated click handler for the Edit/Delete buttons rendered above -
// one listener on the (static) container instead of re-attaching inline
// onclick on every re-render. See the NOTE above loadCustomQueries().
cqList.addEventListener('click', function(e){
  const btn = e.target.closest('button[data-action]');
  if(!btn) return;
  const id = btn.dataset.id;
  if(btn.dataset.action === 'edit') startEditCustomQuery(id);
  else if(btn.dataset.action === 'delete') deleteCustomQuery(id);
});

async function saveCustomQuery(){
  const kwRaw = cqKeywords.value.trim();
  const answer = cqAnswer.value.trim();
  if(!kwRaw || !answer){
    alert('Kailangan ng keywords at sagot.');
    return;
  }
  const keywords = kwRaw.split(',').map(k => k.trim()).filter(Boolean);

  const url = cqEditingId ? ('/api/ai-sales/custom-queries/' + cqEditingId) : '/api/ai-sales/custom-queries';
  const method = cqEditingId ? 'PUT' : 'POST';

  cqSaveBtn.disabled = true;
  try {
    const res = await fetch(url, {
      method: method,
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({keywords: keywords, answer: answer})
    });
    const data = await res.json();
    if(!data.ok){
      alert('⚠️ ' + (data.error || 'May error.'));
      return;
    }
    cancelEditCustomQuery();
    loadCustomQueries();
  } catch(e){
    alert('⚠️ Hindi ma-reach ang server.');
  } finally {
    cqSaveBtn.disabled = false;
  }
}

async function startEditCustomQuery(id){
  try {
    const res = await fetch('/api/ai-sales/custom-queries');
    const data = await res.json();
    const item = (data.items || []).find(x => x.id === id);
    if(!item) return;
    cqKeywords.value = (item.keywords || []).join(', ');
    cqAnswer.value = item.answer || '';
    cqEditingId = id;
    cqSaveBtn.textContent = '💾 I-update';
    cqCancelBtn.style.display = 'inline-block';
    cqKeywords.scrollIntoView({behavior: 'smooth', block: 'center'});
  } catch(e){
    alert('⚠️ Hindi ma-reach ang server.');
  }
}

function cancelEditCustomQuery(){
  cqEditingId = null;
  cqKeywords.value = '';
  cqAnswer.value = '';
  cqSaveBtn.textContent = '➕ I-save';
  cqCancelBtn.style.display = 'none';
}

async function deleteCustomQuery(id){
  if(!confirm('Sigurado ka bang gusto mong i-delete ang custom query na ito?')) return;
  try {
    const res = await fetch('/api/ai-sales/custom-queries/' + id, {method: 'DELETE'});
    const data = await res.json();
    if(!data.ok){
      alert('⚠️ ' + (data.error || 'May error.'));
      return;
    }
    if(cqEditingId === id) cancelEditCustomQuery();
    loadCustomQueries();
  } catch(e){
    alert('⚠️ Hindi ma-reach ang server.');
  }
}

addMessage('Hi! Pwede mo akong tanungin tungkol sa sales, resellers, loyalty points/rewards, staff, machines, o expenses (kasama na ang electricity at plastic) mo. Sasagutin kita galing mismo sa totoong records mo. Tap lang sa mga chip sa baba - yung puti ay direktang magse-send, yung yellow/dashed ay i-fill mo lang muna ang [store name] bago i-send. May "⚙️ Custom Queries" ka rin sa ibaba - pwede kang magdagdag ng sarili mong tanong + sagot doon.', 'bot');
</script>
</body>
</html>
"""
