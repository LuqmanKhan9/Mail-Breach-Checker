"""Breach Lookup Metric Board - a small personal security dashboard.

* Email check: looks an address up in a LOCAL MOCK database of fictional
  breaches and shows a risk score, charts and a to-do list.
* Password check: local strength estimate + a real breach check using the free
  Pwned Passwords range API with k-anonymity (only the first 5 characters of the
  SHA-1 hash ever leave your machine).

All breach data in this file is fictional demo data.
"""

import hashlib
import math
import re
from collections import Counter
from datetime import date
from typing import Callable, Dict, List, Optional

import altair as alt
import pandas as pd
import requests
import streamlit as st

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/"
REQUEST_TIMEOUT = 8  # seconds

# ----------------------------- Mock breach data ----------------------------
# Every company below is fictional. Edit freely to build your own demo set.
BREACHES: List[Dict] = [
    {"id": "newsletterly-2017", "name": "Newsletterly", "date": "2017-01-15",
     "accounts_affected": 31_000_000, "data_classes": ["Email addresses"],
     "description": "A fictional mailing-list service. Subscriber addresses were scraped and shared online."},
    {"id": "shopsphere-2016", "name": "ShopSphere", "date": "2016-03-09",
     "accounts_affected": 48_200_000,
     "data_classes": ["Email addresses", "Passwords", "Names", "Physical addresses"],
     "password_storage": "MD5 (unsalted)",
     "description": "A fictional online marketplace. The customer database was posted on a hacking forum."},
    {"id": "pixelplay-2018", "name": "PixelPlay Forums", "date": "2018-07-21",
     "accounts_affected": 1_300_000,
     "data_classes": ["Email addresses", "Usernames", "Passwords", "IP addresses"],
     "password_storage": "Plaintext",
     "description": "A fictional gaming forum. Passwords were stored without any protection."},
    {"id": "fitnest-2019", "name": "FitNest", "date": "2019-11-02",
     "accounts_affected": 7_900_000,
     "data_classes": ["Email addresses", "Names", "Date of birth", "Phone numbers"],
     "description": "A fictional fitness-tracking app. An exposed cloud database leaked profile data."},
    {"id": "quickloan-2020", "name": "QuickLoan Finance", "date": "2020-02-14",
     "accounts_affected": 2_600_000,
     "data_classes": ["Email addresses", "Names", "Phone numbers", "Bank accounts", "Social security numbers"],
     "description": "A fictional online lender. Loan applications were stolen by attackers."},
    {"id": "travelnest-2021", "name": "TravelNest", "date": "2021-06-30",
     "accounts_affected": 15_400_000,
     "data_classes": ["Email addresses", "Names", "Phone numbers", "Physical addresses", "Credit cards"],
     "description": "A fictional travel-booking site. Booking records including card details were exposed."},
    {"id": "streamly-2022", "name": "Streamly", "date": "2022-09-12",
     "accounts_affected": 22_000_000,
     "data_classes": ["Email addresses", "Passwords", "Usernames"],
     "password_storage": "bcrypt",
     "description": "A fictional video-streaming service. Passwords were hashed with bcrypt, which is hard to crack."},
    {"id": "learnhub-2023", "name": "LearnHub Academy", "date": "2023-04-18",
     "accounts_affected": 3_100_000,
     "data_classes": ["Email addresses", "Names", "Passwords"],
     "password_storage": "SHA-1 (unsalted)",
     "description": "A fictional e-learning platform. Weakly hashed passwords were leaked."},
    {"id": "foodrush-2023", "name": "FoodRush", "date": "2023-12-05",
     "accounts_affected": 9_800_000,
     "data_classes": ["Email addresses", "Names", "Phone numbers", "Physical addresses"],
     "description": "A fictional food-delivery app. Delivery details were leaked through a vendor."},
    {"id": "cloudvault-2024", "name": "CloudVault Storage", "date": "2024-08-27",
     "accounts_affected": 5_500_000,
     "data_classes": ["Email addresses", "Passwords", "Security questions"],
     "password_storage": "bcrypt",
     "description": "A fictional cloud-storage provider. Account records were copied by an intruder."},
    {"id": "gamezone-2025", "name": "GameZone Chat", "date": "2025-05-09",
     "accounts_affected": 4_200_000,
     "data_classes": ["Email addresses", "Usernames", "Private messages", "IP addresses"],
     "description": "A fictional chat service for gamers. Message history was exposed."},
    {"id": "medibook-2025", "name": "MediBook Clinics", "date": "2025-11-20",
     "accounts_affected": 850_000,
     "data_classes": ["Email addresses", "Names", "Date of birth", "Phone numbers", "Physical addresses"],
     "description": "A fictional clinic-booking system. Patient contact details were leaked."},
]
BREACH_BY_ID = {b["id"]: b for b in BREACHES}

# Which demo email appears in which breaches. Unlisted emails are "not found".
ACCOUNTS: Dict[str, List[str]] = {
    "demo.high@example.com": ["shopsphere-2016", "pixelplay-2018", "quickloan-2020",
                              "travelnest-2021", "learnhub-2023", "cloudvault-2024"],
    "demo.medium@example.com": ["fitnest-2019", "streamly-2022"],
    "demo.low@example.com": ["newsletterly-2017"],
    "demo.clean@example.com": [],
    "alex.morgan@example.com": ["shopsphere-2016", "streamly-2022", "medibook-2025"],
    "sam.lee@example.org": ["pixelplay-2018", "gamezone-2025", "newsletterly-2017"],
}

# How much each kind of exposed data adds to a breach's severity.
DATA_WEIGHTS = {
    "Social security numbers": 40, "Credit cards": 35, "Bank accounts": 35,
    "Passwords": 30, "Security questions": 20, "Private messages": 15,
    "Phone numbers": 12, "Physical addresses": 12, "Date of birth": 10,
    "IP addresses": 6, "Email addresses": 4, "Names": 4, "Usernames": 3,
}
STRONG_HASH_PASSWORD_WEIGHT = 15  # passwords stored with bcrypt are much safer
MAX_BREACH_SEVERITY = 60

ACTIONS = {
    "Social security numbers": "Place a credit freeze, monitor your credit reports and consider identity-theft protection.",
    "Credit cards": "Contact your card issuer, review statements for unknown charges and replace the card if needed.",
    "Bank accounts": "Tell your bank, turn on transaction alerts and watch for unauthorized transfers.",
    "Passwords": "Change the password on the affected sites and anywhere you reused it. Use a unique password for every account (a password manager helps).",
    "Security questions": "Change your security questions. Use random answers stored in a password manager.",
    "Private messages": "Assume old messages may be public. Don't share sensitive details on similar services.",
    "Phone numbers": "Be suspicious of calls and texts claiming to be your bank or a delivery company (phishing by SMS or phone).",
    "Physical addresses": "Watch for scam mail and don't confirm personal details to unsolicited callers.",
    "Date of birth": "Treat birthday-based security questions as compromised and use unrelated answers.",
}
GENERAL_ACTIONS = [
    "Turn on two-factor authentication (2FA) on important accounts, starting with your email.",
    "Be careful with emails that mention the breached services: attackers often use breach news for phishing.",
]


# ------------------------------ Email / scoring ----------------------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email)) and len(email) <= 254


def lookup_email(email: str) -> List[Dict]:
    """Breaches containing this email in the demo database, newest first."""
    ids = ACCOUNTS.get(normalize_email(email), [])
    return sorted((BREACH_BY_ID[i] for i in ids), key=lambda b: b["date"], reverse=True)


def _class_weight(breach: Dict, data_class: str) -> int:
    if data_class == "Passwords" and breach.get("password_storage", "").lower().startswith("bcrypt"):
        return STRONG_HASH_PASSWORD_WEIGHT
    return DATA_WEIGHTS.get(data_class, 2)


def recency_factor(breach: Dict, today: Optional[date] = None) -> float:
    today = today or date.today()
    age_years = (today - date.fromisoformat(breach["date"])).days / 365.25
    if age_years >= 5:
        return 0.6
    if age_years >= 2:
        return 0.8
    return 1.0


def breach_severity(breach: Dict, today: Optional[date] = None) -> float:
    """0-60: what was exposed, scaled down for older breaches."""
    raw = sum(_class_weight(breach, c) for c in breach["data_classes"])
    return min(raw, MAX_BREACH_SEVERITY) * recency_factor(breach, today)


def risk_score(breaches: List[Dict], today: Optional[date] = None) -> int:
    """0-100. Combines breaches like independent risks: 1 - product(1 - s/100)."""
    survive = 1.0
    for b in breaches:
        survive *= 1 - breach_severity(b, today) / 100
    return round(100 * (1 - survive))


def risk_level(score: int, breach_count: int) -> str:
    if breach_count == 0:
        return "None found"
    if score < 20:
        return "Low"
    if score < 45:
        return "Moderate"
    if score < 70:
        return "High"
    return "Critical"


def data_class_counts(breaches: List[Dict]) -> Counter:
    return Counter(c for b in breaches for c in b["data_classes"])


def build_actions(breaches: List[Dict]) -> List[str]:
    """Specific advice for the data that leaked, most serious first, then general tips."""
    present = data_class_counts(breaches)
    ordered = sorted((c for c in present if c in ACTIONS), key=lambda c: -DATA_WEIGHTS.get(c, 0))
    return [ACTIONS[c] for c in ordered] + (GENERAL_ACTIONS if breaches else [])


# --------------------------------- Passwords -------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "letmein", "admin",
    "welcome", "iloveyou", "abc123", "111111", "monkey", "dragon", "football",
    "login", "master", "sunshine", "princess", "passw0rd", "trustno1",
}
STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]


def password_strength(password: str) -> Dict:
    """Rough local strength estimate. It is a guide, not a guarantee."""
    pool = 0
    pool += 26 if re.search(r"[a-z]", password) else 0
    pool += 26 if re.search(r"[A-Z]", password) else 0
    pool += 10 if re.search(r"\d", password) else 0
    pool += 33 if re.search(r"[^A-Za-z0-9]", password) else 0

    effective_len = min(len(password), len(set(password)) * 3)  # penalize repetition
    entropy = effective_len * math.log2(pool) if pool else 0.0

    base = password.lower().rstrip("0123456789!@#$%^&*._-")
    common = password.lower() in COMMON_PASSWORDS or base in COMMON_PASSWORDS
    if common:
        entropy = min(entropy, 10.0)

    score = 0 if entropy < 28 else 1 if entropy < 36 else 2 if entropy < 60 else 3 if entropy < 80 else 4

    tips = []
    if common:
        tips.append("This is a very common password or a tiny variation of one.")
    if len(password) < 12:
        tips.append("Use at least 12 characters. A passphrase of 4+ random words works well.")
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
        tips.append("Mix upper and lower case letters.")
    if not re.search(r"\d", password):
        tips.append("Add numbers.")
    if not re.search(r"[^A-Za-z0-9]", password):
        tips.append("Add a symbol or use a longer passphrase.")
    if len(password) >= 4 and len(set(password)) <= 3:
        tips.append("Avoid repeating the same few characters.")
    return {"score": score, "label": STRENGTH_LABELS[score], "entropy": round(entropy, 1),
            "common": common, "tips": tips}


def sha1_prefix_suffix(password: str):
    """The Pwned Passwords API is built on SHA-1; it is used for lookup, not for security."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # nosec B324
    return digest[:5], digest[5:]


def parse_range_response(text: str, suffix: str) -> int:
    """Find our hash suffix in the API's 'SUFFIX:COUNT' lines. Padding rows have count 0."""
    for line in text.splitlines():
        found, _, count = line.partition(":")
        if found.strip().upper() == suffix.upper():
            try:
                return int(count.strip() or 0)
            except ValueError:
                return 0
    return 0


def check_pwned_password(password: str, http_get: Callable = requests.get) -> int:
    """How many times the password appears in known breaches (0 = not found).

    k-anonymity: only the first 5 hash characters are sent; matching happens locally.
    """
    prefix, suffix = sha1_prefix_suffix(password)
    response = http_get(
        PWNED_RANGE_URL + prefix,
        headers={"Add-Padding": "true", "User-Agent": "breach-board-demo"},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return parse_range_response(response.text, suffix)


# ----------------------------------- UI ------------------------------------
LEVEL_ICON = {"None found": "🟢", "Low": "🟡", "Moderate": "🟠", "High": "🔴", "Critical": "🚨"}


def set_checked_email(email: str) -> None:
    st.session_state["checked_email"] = email


def render_banner(level: str, score: int) -> None:
    text = f"{LEVEL_ICON[level]} **Risk level: {level}** (score {score}/100)"
    if level in ("High", "Critical"):
        st.error(text)
    elif level == "Moderate":
        st.warning(text)
    else:
        st.info(text)


def render_charts(breaches: List[Dict], today: date) -> None:
    timeline = pd.DataFrame(
        [{"Breach": b["name"], "Date": pd.to_datetime(b["date"]),
          "Severity": round(breach_severity(b, today), 1),
          "Accounts": b["accounts_affected"]} for b in breaches]
    )
    counts = data_class_counts(breaches)
    types_df = pd.DataFrame({"Data type": list(counts), "Breaches": list(counts.values())})

    left, right = st.columns(2)
    with left:
        st.subheader("Breach timeline")
        st.caption("Higher = more sensitive data. Bigger dot = more accounts leaked.")
        st.altair_chart(
            alt.Chart(timeline).mark_circle(opacity=0.8).encode(
                x=alt.X("Date:T", title=None, scale=alt.Scale(padding=20)),
                y=alt.Y("Severity:Q", title="Severity", scale=alt.Scale(domain=[0, 65])),
                size=alt.Size("Accounts:Q", legend=None, scale=alt.Scale(range=[150, 1200])),
                tooltip=["Breach", alt.Tooltip("Date:T", format="%b %Y"), "Severity", "Accounts"],
            ).properties(height=280)
        )
    with right:
        st.subheader("Data exposed")
        st.caption("How many of your breaches leaked each type of data.")
        st.altair_chart(
            alt.Chart(types_df).mark_bar().encode(
                x=alt.X("Breaches:Q", axis=alt.Axis(tickMinStep=1, format="d"), title=None),
                y=alt.Y("Data type:N", sort="-x", title=None),
                tooltip=["Data type", "Breaches"],
            ).properties(height=280)
        )


def render_email_report(email: str) -> None:
    today = date.today()
    breaches = lookup_email(email)
    st.subheader(f"Results for `{email}`")

    if not breaches:
        st.success("🟢 No breaches found in the demo database.")
        st.caption(
            "This demo only knows fictional breaches, so this says nothing about your real accounts. "
            "For real lookups use haveibeenpwned.com."
        )
        return

    score = risk_score(breaches, today)
    level = risk_level(score, len(breaches))
    render_banner(level, score)

    newest = breaches[0]
    pw_breaches = sum("Passwords" in b["data_classes"] for b in breaches)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Breaches found", len(breaches))
    c2.metric("Risk score", f"{score}/100")
    c3.metric("Most recent breach", newest["date"])
    c3.caption(newest["name"])
    c4.metric("Passwords leaked in", f"{pw_breaches} breach{'es' if pw_breaches != 1 else ''}")

    render_charts(breaches, today)

    st.subheader("Breach details")
    for b in breaches:
        with st.expander(f"{b['name']} · {b['date']} · {b['accounts_affected']:,} accounts"):
            st.write(b["description"])
            st.markdown("**Data exposed:** " + ", ".join(b["data_classes"]))
            if "password_storage" in b:
                st.markdown(f"**Password storage:** {b['password_storage']}")

    st.subheader("What to do next")
    key_base = hashlib.sha256(email.encode()).hexdigest()[:8]
    for i, action in enumerate(build_actions(breaches)):
        st.checkbox(action, key=f"action_{key_base}_{i}")


def render_email_tab() -> None:
    st.write("Enter an email address to see which **demo** breaches it appears in.")
    with st.form("email_form"):
        email_in = st.text_input("Email address", placeholder="demo.high@example.com")
        submitted = st.form_submit_button("Check for breaches", type="primary")
    if submitted:
        email = normalize_email(email_in)
        if is_valid_email(email):
            set_checked_email(email)
        else:
            st.session_state.pop("checked_email", None)
            st.error("Please enter a valid email address.")

    st.caption("Quick demo accounts:")
    cols = st.columns(len(ACCOUNTS))
    for col, demo_email in zip(cols, ACCOUNTS):
        col.button(demo_email.split("@")[0], key=f"demo_{demo_email}",
                   on_click=set_checked_email, args=(demo_email,), help=demo_email)

    if "checked_email" in st.session_state:
        st.divider()
        render_email_report(st.session_state["checked_email"])


def render_password_tab() -> None:
    st.warning(
        "⚠️ **Use test passwords on hosted demos.** When you run this app on your own computer the "
        "password stays there, and only the first 5 characters of its SHA-1 hash are sent to the "
        "Pwned Passwords service. On a hosted app (for example Streamlit Cloud) what you type "
        "reaches that app's server, so never enter a password you actually use."
    )
    with st.form("password_form"):
        password = st.text_input("Password to check", type="password")
        submitted = st.form_submit_button("Check password", type="primary")

    if submitted:
        if not password:
            st.session_state.pop("pw_result", None)
            st.error("Type a password first.")
        else:
            result = {"strength": password_strength(password), "pwned": None, "error": None}
            try:
                with st.spinner("Checking known breaches..."):
                    result["pwned"] = check_pwned_password(password)
            except requests.RequestException:
                result["error"] = "Could not reach the Pwned Passwords service. Check your connection and try again."
            st.session_state["pw_result"] = result  # the password itself is never stored

    result = st.session_state.get("pw_result")
    if not result:
        return
    s = result["strength"]
    st.subheader("Strength")
    st.progress((s["score"] + 1) / 5)
    st.write(f"**{s['label']}** · about {s['entropy']} bits (rough estimate)")
    for tip in s["tips"]:
        st.markdown(f"- {tip}")

    st.subheader("Breach check")
    if result["error"]:
        st.warning(result["error"])
    elif result["pwned"]:
        st.error(f"🚨 This password appeared **{result['pwned']:,}** times in known data breaches. Do not use it.")
    else:
        st.success("✅ Not found in known breaches. That does not guarantee it is strong, so check the strength above too.")


def render_about_tab() -> None:
    st.markdown(
        """
**How the risk score works**

Each breach gets a severity from 0 to 60 based on what leaked (for example a card number counts far more than an
email address), reduced for older breaches. Passwords stored with bcrypt count half as much as weakly hashed ones.
The breaches are then combined like independent risks: `100 × (1 − ∏(1 − severity/100))`.

**How the password check stays private (k-anonymity)**

1. Your password is hashed with SHA-1 on your machine.
2. Only the first 5 characters of the hash are sent to the Pwned Passwords service.
3. The service returns every hash suffix that starts with those 5 characters (hundreds of them).
4. Your app looks for your own suffix in that list locally.

The service never learns which password, or even which hash, you were checking.

**Demo data**

All breaches and companies here are fictional. The email check only knows the demo accounts in the
Email tab, so use it to explore the dashboard, not to judge your real accounts.
        """
    )


def main() -> None:
    st.set_page_config(page_title="Breach Lookup Board", page_icon="🛡️", layout="wide")
    st.title("🛡️ Breach Lookup Metric Board")
    st.caption("A personal security dashboard. Email results use fictional demo data.")

    with st.sidebar:
        st.header("About")
        st.info(
            "Demo project. The email lookup uses a local mock database of fictional breaches. "
            "The password check uses the real, free Pwned Passwords API."
        )
        st.caption("Emails and passwords you type are not saved or logged by this app.")

    tab_email, tab_pw, tab_about = st.tabs(["📧 Email check", "🔑 Password check", "ℹ️ How it works"])
    with tab_email:
        render_email_tab()
    with tab_pw:
        render_password_tab()
    with tab_about:
        render_about_tab()


if __name__ == "__main__":
    main()
