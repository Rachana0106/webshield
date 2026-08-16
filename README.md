# 🛡️ WebShield — Evidence-Based Website Security Assessment

> A beginner-friendly defensive web security tool that analyzes observable website security controls, explains findings in simple language, and provides evidence-backed remediation guidance.

---

## 🔗 Project Links

🌐 **Live Application:**  
https://webshield-flax.vercel.app/

💻 **GitHub Repository:**  
https://github.com/Rachana0106/webshield

👩‍💻 **Developer:** Rachana Makwana  
🔗 **GitHub Profile:** https://github.com/Rachana0106  
🔗 **LinkedIn:** https://www.linkedin.com/in/rachanamakwana/

---

# 📌 About WebShield

**WebShield** is a defensive website security assessment tool designed to make web security easier to understand.

Many security tools display technical findings such as:

```text
Content-Security-Policy Missing
```

without explaining what that actually means.

WebShield goes further.

For every security finding, it explains:

- 🔍 What was detected
- 📖 What the security term means
- ⚠️ Why the issue matters
- 🔐 How it may affect security
- 🤔 Whether it means the website is hacked
- 🛠️ How the website can be improved
- 🧪 What technical evidence triggered the finding
- 🎯 How confident WebShield is in the result

This makes WebShield useful not only for developers and cybersecurity learners, but also for students and users who may not already understand advanced security terminology.

---

# 🎯 Project Goal

The main goal of WebShield is:

```text
Website
   ↓
Passive Security Analysis
   ↓
Evidence Collection
   ↓
Security Findings
   ↓
Plain-Language Explanation
   ↓
Remediation Guidance
   ↓
Fix Website
   ↓
Rescan
```

WebShield focuses on:

> **Detect → Explain → Educate → Recommend → Improve**

rather than simply displaying technical vulnerability names.

---

# ✨ Main Features

## 🔐 HTTPS & TLS Analysis

WebShield checks whether the website uses HTTPS and analyzes the TLS connection.

It can inspect:

- HTTPS availability
- TLS certificate validity
- Certificate subject
- Certificate issuer
- Certificate expiry
- TLS protocol version
- Cipher suite

Example:

```text
HTTPS: Enabled
Certificate: Valid
TLS: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
```

---

## 🛡️ Security Header Analysis

WebShield evaluates important browser-side security headers such as:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

It does not only check whether a header exists.

For example, WebShield can also detect potentially weak CSP settings such as:

```text
'unsafe-inline'
'unsafe-eval'
```

---

## 🧱 Clickjacking Protection Analysis

WebShield checks whether the site provides protections such as:

```text
X-Frame-Options
```

or:

```text
Content-Security-Policy: frame-ancestors
```

If protection is not detected, WebShield explains what **clickjacking** means and why frame restrictions may be useful.

---

## 🍪 Cookie Security Analysis

WebShield analyzes observed cookies for security attributes including:

```text
Secure
HttpOnly
SameSite
```

Instead of automatically declaring a cookie vulnerable, WebShield considers the finding as a configuration concern when manual context may still be required.

---

## 📝 Form Security Review

WebShield identifies visible HTML forms and reviews indicators such as:

- POST forms
- Password fields
- Form destination
- HTTPS submission
- Anti-CSRF indicators

When protection cannot be verified from HTML alone, WebShield reports:

```text
Manual Review Required
```

instead of claiming a vulnerability definitely exists.

---

## 🔄 CORS Analysis

WebShield reviews observable Cross-Origin Resource Sharing settings such as:

```text
Access-Control-Allow-Origin
Access-Control-Allow-Credentials
```

It can identify broad configurations such as:

```text
Access-Control-Allow-Origin: *
```

while explaining that wildcard CORS may be acceptable for public resources depending on the application.

---

## 🌐 Third-Party Resource Analysis

WebShield identifies resources loaded from external domains.

It can review:

- External scripts
- External resources
- Mixed HTTP/HTTPS content
- Subresource Integrity indicators

---

## 🔗 Mixed Content Detection

An HTTPS website should ideally avoid loading insecure HTTP resources.

WebShield identifies cases such as:

```text
HTTPS Website
      ↓
HTTP Script / Image / Resource
      ↓
Mixed Content
```

and recommends using HTTPS consistently.

---

## 📦 Subresource Integrity Review

WebShield checks externally hosted scripts for possible **Subresource Integrity (SRI)** protection.

Example:

```html
<script
    src="https://cdn.example.com/library.js"
    integrity="sha384-..."
></script>
```

SRI can help verify that fixed third-party resources have not changed unexpectedly.

---

## 💻 Client-Side Security Indicators

WebShield performs passive inspection for potentially security-sensitive JavaScript patterns such as:

```javascript
eval()
document.write()
innerHTML
localStorage
```

Their presence is **not automatically treated as a vulnerability**.

Instead, WebShield marks them for:

```text
Manual Review Required
```

because actual risk depends on how untrusted data reaches the code.

---

## 🔎 Information Exposure Indicators

WebShield checks for publicly observable information such as:

- Server headers
- Framework information
- Technology disclosures
- Debug indicators
- Secret-like patterns
- Stack-trace indicators

Possible findings are clearly separated from confirmed vulnerabilities.

---

# 📊 Evidence-Aware Security Scoring

One of the main design goals of WebShield is to avoid misleading security scores.

WebShield uses:

## **WebShield Observed Security Posture**

The score represents only the security controls WebShield had enough evidence to evaluate.

It is **not**:

- A penetration-testing score
- A guarantee that the website is secure
- Proof that the website cannot be hacked
- Proof that all vulnerabilities were detected

---

## 🔍 Category States

Instead of assuming every untested area is secure, WebShield uses three states.

### ✅ Evaluated

Enough observable evidence exists to calculate a category result.

Example:

```text
Transport Security
74 / 100
Evaluated
```

---

### ⚪ N/A — Not Observed

The relevant feature was not observed.

Example:

```text
Cookie Security
N/A

No Set-Cookie header was observed.
```

This is intentionally **not displayed as `100/100`**.

---

### 🔎 Limited

Passive inspection cannot reliably determine the security of the category.

Example:

```text
Client-Side Review
Limited

Passive HTML inspection cannot prove that
client-side application code is secure.
```

---

# 📈 Assessment Coverage

WebShield also reports how much of its passive assessment model was actually evaluated.

Example:

```text
Observed Security Posture
59 / 100

Assessment Coverage
66%

4 of 8 categories evaluated
```

This gives users context about how much evidence contributed to the result.

---

# 🚦 Severity Levels

Findings may be classified as:

```text
Critical
High
Medium
Low
Informational
```

Severity represents the **possible importance or impact** of a finding.

---

# 🎯 Confidence Levels

WebShield also separates severity from confidence.

```text
Severity
→ How important could the issue be?

Confidence
→ How certain is WebShield about the observation?
```

Confidence levels include:

```text
High
Medium
Low
```

Example:

```text
Finding:
Content-Security-Policy Missing

Severity:
Medium

Confidence:
High
```

---

# 🧪 Finding Status

Security results may use statuses such as:

```text
Confirmed Configuration Finding
Potential Concern
Manual Review Required
Informational
```

This helps prevent WebShield from presenting every observation as a confirmed vulnerability.

---

# 🧠 Beginner-Friendly Security Explanations

Every major finding can explain:

### What did WebShield find?

What observable security condition triggered the result.

### What does the term mean?

A beginner-friendly security definition.

### Why does it matter?

The possible security impact.

### Does this mean the website is hacked?

WebShield avoids unnecessary fear and explains the difference between:

```text
Security weakness
        ≠
Website hacked
```

### What should be done?

A practical security recommendation.

### Technical evidence

The actual evidence behind the result.

---

# ❓ Can WebShield Tell Whether a Website Can Be Hacked?

No passive scanner can truthfully guarantee this.

WebShield therefore reports:

> WebShield cannot determine whether a website is hackable from passive configuration checks alone.

A website may still contain vulnerabilities involving:

- Authentication
- Authorization
- Broken access control
- SQL Injection
- Server-side injection
- Business logic
- Vulnerable dependencies
- Backend APIs
- Infrastructure
- Application code

even when its observable security configuration looks strong.

---

# 🔺 CIA Triad Analysis

WebShield relates relevant findings to the three fundamental cybersecurity principles:

## 🔒 Confidentiality

Protecting information from unauthorized disclosure.

## 🧾 Integrity

Protecting data and application behavior from unauthorized modification.

## 🌐 Availability

Ensuring legitimate users can access systems and services.

WebShield reports CIA effects **qualitatively instead of inventing exact percentages when passive scanning cannot provide enough evidence**.

Example:

```text
Confidentiality
Review Recommended

Integrity
Review Recommended

Availability
Not Assessed
```

---

# 🤖 AI Remediation Prompt

WebShield generates an AI remediation prompt based on the website's actual findings.

The prompt specifically instructs an AI assistant to:

- Preserve existing website functionality
- Avoid unnecessary changes
- Explain security improvements
- Provide exact configuration/code
- Explain what could break
- Provide testing instructions
- Provide rollback instructions
- Consider Confidentiality, Integrity and Availability
- Avoid blindly applying restrictive policies

Example workflow:

```text
WebShield Finding
      ↓
Generate AI Prompt
      ↓
Copy Prompt
      ↓
Provide Framework / Hosting Information
      ↓
Receive Suggested Fix
      ↓
Review
      ↓
Test
      ↓
Deploy
      ↓
Rescan
```

---

# 📄 PDF Security Reports

WebShield can generate downloadable security assessment reports.

Reports include:

- Website information
- Observed Security Posture
- Assessment coverage
- Beginner-friendly summary
- Security categories
- Confirmed findings
- Severity
- Confidence
- Finding status
- Technical evidence
- CIA Triad impact
- Practical remediation plan
- Technical snapshot
- AI remediation prompt
- Security glossary
- Scope limitations

---

# 📚 Security Glossary

Reports also explain common web-security terms such as:

- HTTPS
- TLS
- CSP
- XSS
- CSRF
- CORS
- Cookies
- HttpOnly
- Secure Cookie
- SameSite
- Clickjacking
- Mixed Content
- SRI
- Security Headers
- Severity
- Confidence

This makes the generated report useful as both a **security assessment and learning resource**.

---

# 🔒 Scanner Safety

WebShield includes defensive controls to reduce scanner abuse.

It blocks:

- `localhost`
- Private IP addresses
- Internal network addresses
- Loopback addresses
- Reserved network ranges
- Unsupported protocols
- Non-standard web ports

Redirect destinations are also validated before WebShield follows them.

---

# ⏱️ Reliability Protections

WebShield includes:

- Connection timeouts
- Response timeouts
- Redirect limits
- Response-size limits
- Safe URL validation
- Internal-network blocking
- Basic scan rate limiting
- Friendly connection error messages

If a website cannot be reached reliably, WebShield generates **no security score**.

Example:

```text
Website did not respond in time.

No security result was generated.
```

---

# 🛠️ Technology Stack

## Backend

- Python
- FastAPI
- Uvicorn

## Website Analysis

- Requests
- BeautifulSoup
- Python SSL
- HTTP Response Analysis

## Frontend

- HTML5
- CSS3
- JavaScript

## Database

- SQLite

## Reporting

- ReportLab

## Development & Deployment

- Git
- GitHub
- VS Code
- Vercel

---

# 📁 Project Structure

```text
webshield/
│
├── app.py
│
├── requirements.txt
│
├── README.md
│
├── .gitignore
│
├── analyzer/
│   ├── __init__.py
│   ├── knowledge.py
│   ├── network_guard.py
│   ├── scoring.py
│   └── web_analyzer.py
│
├── reports/
│   ├── __init__.py
│   ├── pdf_report.py
│   └── generated/
│
├── templates/
│   └── index.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
│
└── data/
```

---

# 🚀 Run WebShield Locally

Clone the repository:

```bash
git clone https://github.com/Rachana0106/webshield.git
```

Move inside the project:

```bash
cd webshield
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Start FastAPI:

```powershell
uvicorn app:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

---

# ☁️ Vercel Deployment

WebShield is deployed using **Vercel's FastAPI support**.

🌐 Live application:

https://webshield-flax.vercel.app/

The application automatically detects the Vercel environment.

For local development:

```text
SQLite
→ data/webshield.db

PDF Reports
→ reports/generated/
```

For Vercel:

```text
SQLite
→ /tmp/webshield/webshield.db

PDF Reports
→ /tmp/webshield/reports/
```

---

# ⚠️ Cloud Storage Limitation

Vercel serverless runtime storage is temporary.

Therefore:

> Scan-history persistence is not guaranteed on the deployed version.

The local version keeps scan history using SQLite.

A future cloud-storage upgrade could replace SQLite with a managed database for permanent online history.

This limitation does **not affect the core website analysis engine**.

---

# 🔄 Rescan Comparison

When persistent history is available, WebShield can compare scans of the same website.

Example:

```text
Previous Assessment
72

        ↓ Security Fixes

Current Assessment
86

Resolved:
✓ CSP configured
✓ Clickjacking protection added

New:
None
```

This allows developers to measure security-hardening progress.

---

# 🧪 Tested Against

During development, WebShield was tested using:

- Personal/static websites
- HTTPS-hosted websites
- Acunetix intentionally vulnerable VulnWeb applications
- OWASP security-related websites

The testing process was used to improve:

- False-positive handling
- Assessment coverage
- N/A states
- Limited states
- Severity classification
- Confidence classification
- Security-score calibration
- Report transparency

---

# ⚠️ Scope & Limitations

WebShield is primarily a **passive website security assessment tool**.

It does not replace professional security platforms such as:

- OWASP ZAP
- Burp Suite Professional
- Acunetix
- Nessus

WebShield does not currently perform full active exploitation for vulnerabilities such as:

```text
SQL Injection
Authentication Bypass
IDOR
Broken Access Control
Server-Side Injection
Business-Logic Exploitation
Password Attacks
Brute Force
```

These require deeper crawling, application context and explicitly authorized active security testing.

---

# ⚖️ Responsible Use

WebShield is intended for:

- Defensive security
- Cybersecurity education
- Website hardening
- Security learning
- Authorized assessment

> ⚠️ Only scan websites you own or have explicit permission to assess.

Unauthorized security testing may violate laws, policies or terms of service.

---

# 🗺️ Future Improvements

Potential future improvements include:

- Multi-page authorized crawling
- Managed cloud database
- Persistent online scan history
- Better technology fingerprinting
- Dependency-security information
- Additional passive OWASP checks
- Baseline comparison
- Export formats beyond PDF
- Controlled security-lab integrations

The focus of future improvements will remain:

> **Accuracy and trustworthy evidence over unnecessary feature count.**

---

# 📸 Screenshots

Add screenshots here later:

```text
Dashboard
Security Assessment Result
Finding Explanation
CIA Triad
AI Remediation Prompt
PDF Report
```

You can store screenshots in:

```text
assets/
```

and display them with:

```markdown
![WebShield Dashboard](assets/dashboard.png)
```

---

# 👩‍💻 Developer

## Rachana Makwana

Cybersecurity & Web Development Student

🔗 **GitHub**  
https://github.com/Rachana0106

🔗 **LinkedIn**  
https://www.linkedin.com/in/rachanamakwana/

🌐 **WebShield**  
https://webshield-flax.vercel.app/

---

## ⭐ If you find WebShield useful

Consider starring the repository.

It helps support the project and its continued development.

---

### 🛡️ WebShield

**Understand the finding. Verify the evidence. Improve the security.**
