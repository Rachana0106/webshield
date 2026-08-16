# WebShield Final

WebShield is an evidence-based defensive website security assessment tool.

## Final scoring rules

The **WebShield Observed Security Posture (0-100)** scores only categories for which WebShield collected enough observable evidence.

- **Evaluated** = enough evidence for a numeric category result.
- **N/A / Not observed** = the relevant object was not present; it is not scored.
- **Limited** = passive inspection cannot support a trustworthy numeric score.
- Low coverage applies a small confidence adjustment to the overall score.
- Confirmed High/Critical findings cap an otherwise reassuring overall score.
- Timeout, DNS, TLS, refused-connection, and unreliable-fetch failures produce **no score**.
- CIA impact remains qualitative rather than using fake percentage precision.

WebShield is not a replacement for Acunetix, Burp Suite Professional, Nessus, or OWASP ZAP. Those tools can crawl more deeply and/or actively test application behavior. WebShield should agree with professional tools on the observable controls it actually checks, while marking deeper vulnerability classes outside its scope rather than claiming they are safe.

## Run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app:app --reload
```

Open `http://127.0.0.1:8000`.

Use only on websites you own or are authorized to assess.
