# 🛡️ PhishGuard

**PhishGuard** is a Flask-based phishing email analyzer that checks suspicious messages for common social-engineering and URL warning signs.

Users paste an email or message into the website, and PhishGuard returns a **0–100 risk score** with an explanation of every indicator it detected.

## 🚀 Features

- Detects urgency and pressure language
- Flags requests for passwords and verification codes
- Identifies payment and sensitive-information requests
- Analyzes suspicious URL structures
- Checks for common brand/domain mismatches
- Generates an explainable phishing risk score
- Responsive cybersecurity-themed interface
- No paid API required

## 🛠️ Built With

**Python · Flask · HTML · CSS · Regex · GitHub · Render**

## 🧠 How It Works

PhishGuard uses rule-based security checks rather than machine learning. Each detected warning sign adds points to the message's risk score.

- **0–14:** Low Risk
- **15–39:** Low to Moderate Risk
- **40–69:** Suspicious
- **70–100:** High Risk

## 💻 Run Locally

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Then open `http://127.0.0.1:5000`.

## ⚠️ Important

PhishGuard is an educational project. A low score does not guarantee that an email is safe. Never paste real passwords, payment details, or other sensitive information into the analyzer.
