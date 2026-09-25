"""
modules/ai_sales_query.py
----------------------------------------------------------------------------
"Ask Sales" - a natural-language chat box (Taglish or English) that answers
questions about Omega Ice's sales data with full details, e.g.:
    "magkano benta ko last May?"
    "total sales this week"
    "ilang kg ang nabenta noong Hunyo 2026?"
    "sino top reseller this month?"

DESIGN - why the math is split the way it is (important, read before editing):
    This feature NEVER lets the AI compute totals itself. An LLM asked to
    "add up these numbers" can silently get arithmetic wrong (hallucinate),
    which is unacceptable for real peso figures. Instead:

    1. AI (Gemini) job #1 and ONLY job: read the natural-language question
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

SETUP REQUIRED:
    1. Get a free Gemini API key: https://aistudio.google.com/apikey
    2. On Render (or wherever this deploys): Environment > add
       GEMINI_API_KEY = <your key>
       (optional) GEMINI_MODEL = gemini-2.5-flash   <- default if unset
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
import json
import calendar
from datetime import datetime, date, timedelta

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

GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_URL_TMPL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"


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
    try:
        import pytz
        return datetime.now(pytz.timezone("Asia/Manila")).date()
    except Exception:
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


def _ask_gemini_for_date_range(question, today_str):
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None, "GEMINI_API_KEY is not set sa environment variables mo (Render > Environment)."

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

    url = GEMINI_URL_TMPL.format(model=GEMINI_MODEL, key=api_key)
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
    }
    try:
        resp = requests.post(url, json=payload, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
    except requests.exceptions.RequestException as e:
        return None, f"Hindi ma-reach ang AI service: {e}"
    except (KeyError, IndexError):
        return None, "Unexpected response shape from Gemini API."

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
    parsed, err = _ask_gemini_for_date_range(question, today.isoformat())
    if err:
        return jsonify({"ok": False, "error": err}), 502

    if not parsed.get("is_sales_question"):
        return jsonify({
            "ok": True,
            "reply": "Sales-related questions lang muna ang kaya kong sagutin dito "
                     "(hal. \"magkano benta last May\", \"total sales this week\", "
                     "\"sino top reseller this month\"). Subukan mo ulit.",
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
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ask Sales - Omega Ice</title>
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
<body>
<div class="topbar">
  <h1>💬 Ask Sales (ISESMO Only)</h1>
  <a href="/cashier" class="nav-pill">← Back to Sales</a>
</div>

<div class="card">
  <div id="chatBox"></div>
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

addMessage('Hi! Magtanong ka tungkol sa sales mo - hal. "magkano benta last May?" Sasagutin kita galing mismo sa totoong sales records.', 'bot');
</script>
</body>
</html>
"""
