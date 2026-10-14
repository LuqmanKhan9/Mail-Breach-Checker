# 🛡️ Breach Lookup Metric Board

A small personal security dashboard built with Streamlit. It tells you whether an email address appears in data breaches, scores the risk, and checks whether a password has been leaked, a simplified take on the idea behind HaveIBeenPwned.

> **Demo data notice:** the email lookup uses a local mock database of **fictional** breaches and companies. It says nothing about your real accounts. The password check uses the real, free Pwned Passwords API.

## Features

- **Email check** against a local mock breach database
  - Metric board: breaches found, risk score (0-100), most recent breach, password exposures
  - Breach timeline and a "data exposed" chart
  - Expandable breach details
  - A "what to do next" checklist tailored to the data that leaked
- **Password check**
  - Local strength estimate with improvement tips
  - Real breach check using **k-anonymity**: only the first 5 characters of the password's SHA-1 hash are sent, and matching happens on your machine
- No API key needed, and nothing is saved or logged

## Demo emails to try

| Email | Breaches | Risk level (approx.) |
|---|---|---|
| `demo.high@example.com` | 6 | Critical (about 90) |
| `alex.morgan@example.com` | 3 | High (about 67) |
| `sam.lee@example.org` | 3 | High (about 48) |
| `demo.medium@example.com` | 2 | Moderate (about 32) |
| `demo.low@example.com` | 1 (email only) | Low (about 2) |
| `demo.clean@example.com` | 0 | None found |
| anything else | not in the demo database | None found |

Scores drift slightly over time because older breaches count for less.

## How the risk score works

1. Each breach gets a **severity (0-60)** from the data that leaked: for example a Social Security number counts 40, a password 30, an email address 4. Passwords stored with bcrypt count half.
2. Severity is multiplied by a **recency factor**: 1.0 for breaches under 2 years old, 0.8 for 2-5 years, 0.6 for older.
3. Breaches combine like independent risks: `score = 100 × (1 − ∏(1 − severity/100))`.
4. Levels: under 20 Low, under 45 Moderate, under 70 High, 70+ Critical.

Weights live in `DATA_WEIGHTS` at the top of `app.py`, so you can tune them.

## Project structure

```
.
├── app.py             # Streamlit app (includes the mock breach database)
├── requirements.txt   # Python dependencies
└── README.md
```

## Run locally

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

No API key or secrets are needed.

## Customize the mock data

Edit the `BREACHES` list (fictional breaches) and the `ACCOUNTS` dictionary (which email appears in which breach ids) near the top of `app.py`.

## Deploy on Streamlit Community Cloud

1. Push this repo to GitHub.
2. Go to https://share.streamlit.io, sign in with GitHub and click **Create app**.
3. Choose your repo, branch `main` and main file `app.py`.
4. Click **Deploy**. No secrets are required.

## Privacy and security notes

- Emails and passwords are not written to disk, logged or stored by this app.
- **Password check on a hosted app:** the browser sends what you type to the app's server, so on Streamlit Cloud never enter a password you really use. Run the app locally for real checks. Doing the hashing in the browser would need a custom JavaScript component.
- The Pwned Passwords API uses SHA-1 because the service is built on it. It is used for lookup, not for protecting data.
- The strength meter is a rough estimate, not a guarantee.

## Ideas for next steps

- Add an optional live email lookup with a HaveIBeenPwned API key (a paid key is required)
- Email verification before showing results, so people can't look up other people's addresses
- Export the report as PDF
