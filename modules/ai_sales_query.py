"""
modules/ai_sales_query.py
----------------------------------------------------------------------------
"Ask AI" (originally "Ask Sales", kept the same module/route names for
backward compatibility - see the Routes section) - a natural-language chat
box (Taglish or English) that answers questions about Omega Ice's own data:
sales, resellers, loyalty points/rewards, staff, and machines/equipment.
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
    return "sales"


def _find_matching_reseller(question, resellers):
    """Returns (key, val) of the reseller whose store_name is the LONGEST
    match found as a substring of the question, or (None, None). Longest
    match wins so a short/generic name doesn't win over a more specific
    one that also matches (e.g. "Ice Point" vs "Point")."""
    q = (question or "").lower()
    best_key, best_val, best_len = None, None, 0
    for key, val in (resellers or {}).items():
        if not val:
            continue
        name = (val.get("store_name") or "").strip()
        if len(name) < 3:
            continue
        if name.lower() in q and len(name) > best_len:
            best_key, best_val, best_len = key, val, len(name)
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
            else:  # "machines"
                reply = _handle_machines_question(question, today)
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
        return jsonify({
            "ok": True,
            "reply": "Hindi ko na-gets kung ano ang tinatanong mo. Subukan mo ulit, hal.:\n"
                     "  • \"magkano benta last May\" / \"total sales this week\"\n"
                     "  • \"credit balance ni [store name]\" / \"listahan ng resellers\"\n"
                     "  • \"sino top loyalty points\" / \"ano available rewards\"\n"
                     "  • \"sino active staff\"\n"
                     "  • \"aling machine overdue sa PM\" / \"total harvest this week\"",
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
.inputRow{display:flex;gap:8px;margin-top:12px}
#questionInput{flex:1;padding:12px;border-radius:10px;border:1px solid #ccd;font-size:14px}
#askBtn{padding:12px 18px;border-radius:10px;border:none;background:#00609C;color:#fff;font-weight:600;font-size:14px}
#askBtn:disabled{opacity:.6}
.examples{font-size:11px;color:#888;margin-top:8px}
.examples span{display:inline-block;background:#f0f4f8;border-radius:12px;padding:4px 10px;margin:3px 3px 0 0;cursor:pointer}
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
    <button id="askBtn" onclick="askQuestion()">Ask</button>
  </div>
  <div class="examples">
    Try:
    <span onclick="fillExample(this)">magkano benta ko last May?</span>
    <span onclick="fillExample(this)">total sales this week</span>
    <span onclick="fillExample(this)">sino top reseller this month?</span>
    <span onclick="fillExample(this)">all time sales</span>
    <span onclick="fillExample(this)">listahan ng resellers</span>
    <span onclick="fillExample(this)">sino top loyalty points?</span>
    <span onclick="fillExample(this)">sino active staff?</span>
    <span onclick="fillExample(this)">aling machine overdue sa PM?</span>
    <span onclick="fillExample(this)">huling order ni [store name]?</span>
  </div>
</div>

<script>
const chatBox = document.getElementById('chatBox');
const questionInput = document.getElementById('questionInput');
const askBtn = document.getElementById('askBtn');

function addMessage(text, cls){
  const div = document.createElement('div');
  div.className = 'msg ' + cls;
  div.textContent = text;
  chatBox.appendChild(div);
  chatBox.scrollTop = chatBox.scrollHeight;
  return div;
}

function fillExample(el){
  questionInput.value = el.textContent;
  questionInput.focus();
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

addMessage('Hi! Pwede mo akong tanungin tungkol sa sales, resellers, loyalty points/rewards, staff, o machines mo - hal. "magkano benta last May?" o "credit balance ni [store]?" Sasagutin kita galing mismo sa totoong records mo.', 'bot');
</script>
</body>
</html>
"""
