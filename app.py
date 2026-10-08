"""Streamlit page: paste a message, get a risk level, the warning signs and what to do.

Run:  .venv\\Scripts\\python -m streamlit run app.py

Nothing is stored: the message is analyzed in memory and discarded.
Text from the message is always HTML-escaped and links are never made clickable.
"""
import html

import pandas as pd
import streamlit as st

from scam_detector import classifier
from scam_detector.detector import HIGH, LOW, MEDIUM_RISK, analyze

MAX_CHARS = 5000

st.set_page_config(page_title="בודק הודעות חשודות", page_icon="🛡️", layout="centered")

st.markdown("""
<style>
  /* Hebrew and English in the same box: each line takes its own direction */
  textarea { unicode-bidi: plaintext; }
  .card { border-radius: 10px; padding: 1rem 1.25rem; margin: 0.75rem 0; text-align: start;
          border-inline-start: 8px solid var(--c); background: color-mix(in srgb, var(--c) 12%, transparent); }
  .card h2 { margin: 0 0 0.5rem 0; font-size: 1.6rem; }
  .card h4 { margin: 0.9rem 0 0.3rem 0; }
  .card ul { margin: 0; padding-inline-start: 1.2rem; }
  .card li { margin: 0.2rem 0; }
  .very_strong { font-weight: 700; }
  .page-head { text-align: center; }
  .page-head p { opacity: 0.75; margin-top: -0.5rem; }
</style>
""", unsafe_allow_html=True)

COLORS = {HIGH: "#d93025", MEDIUM_RISK: "#e8710a", LOW: "#5f6368"}
ICONS = {HIGH: "🔴", MEDIUM_RISK: "🟠", LOW: "⚪"}
HEADINGS = {
    "he": {"signs": "סימני אזהרה", "reassuring": "סימנים מרגיעים", "todo": "מה לעשות"},
    "en": {"signs": "Warning signs", "reassuring": "Reassuring signs", "todo": "What to do"},
}


@st.cache_data
def examples():
    """Written practice examples (not real messages) for trying the page."""
    df = pd.read_csv("data/draft_examples.csv", encoding="utf-8-sig")
    picks = ["he-d01", "he-d04", "he-d09", "he-d10", "en-d01", "en-d04"]
    return {f"{r.id}: {r.text[:45]}…": r.text for r in df[df.id.isin(picks)].itertuples()}


def e(text):
    return html.escape(str(text))


def result_card(result):
    lang = result["language"]
    level = result["risk_level"]
    h = HEADINGS[lang]
    parts = [f'<div class="card" dir="{"rtl" if lang == "he" else "ltr"}" style="--c:{COLORS[level]}">',
             f'<h2>{ICONS[level]} {e(result["risk_text"][lang])}</h2>']
    if result["red_flags"]:
        items = "".join(f'<li class="{s["strength"]}">{e(s[lang])}</li>' for s in result["red_flags"])
        parts.append(f"<h4>{h['signs']}</h4><ul>{items}</ul>")
    if result["reassuring"]:
        items = "".join(f"<li>{e(s[lang])}</li>" for s in result["reassuring"])
        parts.append(f"<h4>{h['reassuring']}</h4><ul>{items}</ul>")
    items = "".join(f"<li>{e(a)}</li>" for a in result["what_to_do"])
    parts.append(f"<h4>{h['todo']}</h4><ul>{items}</ul></div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def technical_details(result):
    with st.expander("פרטים טכניים / Technical details"):
        found = result["extracted"]
        st.write(f"Model score: **{result['model_score']:.2f}** "
                 f"(suspicious above {classifier.thresholds()[0]:.2f}, "
                 f"confident above {classifier.thresholds()[1]:.2f})")
        if found["links"]:
            st.write("Links found (shown as text, never opened):")
            st.code("\n".join(f'{l["url"]}   →  {l["domain"]}' for l in found["links"]), language=None)
        if found["phones"]:
            st.write("Phone numbers:", ", ".join(p["number"] for p in found["phones"]))
        if found["amounts"]:
            st.write("Amounts:", ", ".join(a["text"] for a in found["amounts"]))


st.markdown('<div class="page-head"><h1>🛡️ בודק הודעות חשודות</h1>'
            '<p>Suspicious message checker · עברית / English</p></div>', unsafe_allow_html=True)

if not classifier.MODEL_PATH.exists():
    st.error("The model isn't trained yet. Run: `.venv\\Scripts\\python train\\train.py`")
    st.stop()

with st.expander("רוצים לנסות? בחרו הודעה לדוגמה / Try an example"):
    choice = st.selectbox("Example", ["—"] + list(examples()), label_visibility="collapsed")
    if choice != "—" and st.button("השתמשו בדוגמה / Use it"):
        st.session_state["message"] = examples()[choice]

# A form sends the text and the click together, so one click is enough
with st.form("check", border=False):
    text = st.text_area("הדביקו כאן את ההודעה / Paste the message here", key="message",
                        height=160, max_chars=MAX_CHARS)
    st.caption("🔒 ההודעה לא נשמרת ולא נשלחת לשום שירות חיצוני. · The message isn't saved or sent anywhere.")
    submitted = st.form_submit_button("בדיקה / Check", type="primary", use_container_width=True)

if submitted:
    if not text.strip():
        st.warning("הדביקו הודעה קודם. / Paste a message first.")
    else:
        result = analyze(text)
        result_card(result)
        technical_details(result)
        st.caption("זה כלי עזר, לא ערובה. במקרה של ספק, פנו ישירות לגוף הרשמי. · "
                   "This is a helper, not a guarantee. When in doubt, contact the organization directly.")
