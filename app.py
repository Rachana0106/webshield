from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from datetime import datetime, timezone
import sqlite3
import json
import time

from analyzer.web_analyzer import analyze_website
from reports.pdf_report import build_pdf_report

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "webshield.db"
REPORT_DIR = BASE_DIR / "reports" / "generated"

app = FastAPI(title="WebShield", version="2.0.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# Local-project anti-spam guard. This is not intended to replace a production rate limiter.
LAST_SCAN_BY_CLIENT = {}
SCAN_COOLDOWN_SECONDS = 2.5


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                final_url TEXT,
                score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                findings_count INTEGER NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


@app.on_event("startup")
def startup_event():
    init_db()


def load_recent_scans(limit=10):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, target_url, final_url, score, severity,
                   findings_count, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def find_previous_scan(final_url):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT id, score, result_json, created_at
            FROM scans
            WHERE final_url = ?
            ORDER BY id DESC
            LIMIT 1
        """, (final_url,)).fetchone()
    return row


def build_comparison(previous_row, current):
    if not previous_row:
        return None

    previous = json.loads(previous_row["result_json"])
    previous_codes = {
        (f.get("code"), f.get("title"))
        for f in previous.get("findings", [])
        if f.get("status") == "Confirmed Configuration Finding"
    }
    current_codes = {
        (f.get("code"), f.get("title"))
        for f in current.get("findings", [])
        if f.get("status") == "Confirmed Configuration Finding"
    }

    resolved = sorted(previous_codes - current_codes)
    new = sorted(current_codes - previous_codes)

    return {
        "previous_scan_id": previous_row["id"],
        "previous_score": (None if previous_row["score"] == -1 else previous_row["score"]),
        "current_score": current["score"],
        "score_change": (
            None if current["score"] is None or previous_row["score"] == -1
            else current["score"] - previous_row["score"]
        ),
        "previous_date": previous_row["created_at"],
        "resolved": [title for _, title in resolved][:10],
        "new": [title for _, title in new][:10],
    }


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "history": load_recent_scans(8)}
    )


@app.post("/api/scan")
def scan(request: Request, url: str = Form(...)):
    client = request.client.host if request.client else "local"
    now = time.monotonic()
    last = LAST_SCAN_BY_CLIENT.get(client, 0)

    if now - last < SCAN_COOLDOWN_SECONDS:
        raise HTTPException(
            status_code=429,
            detail="Please wait a moment before starting another scan."
        )

    LAST_SCAN_BY_CLIENT[client] = now

    try:
        result = analyze_website(url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed safely: {exc}")

    previous = find_previous_scan(result["final_url"])
    comparison = build_comparison(previous, result)
    result["comparison"] = comparison

    created_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("""
            INSERT INTO scans (
                target_url, final_url, score, severity,
                findings_count, result_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result["target_url"],
            result["final_url"],
            (result["score"] if result["score"] is not None else -1),
            result["posture"],
            len(result["findings"]),
            json.dumps(result),
            created_at,
        ))
        scan_id = cursor.lastrowid
        conn.commit()

    result["scan_id"] = scan_id
    result["created_at"] = created_at

    # Save the complete object including scan metadata for future report generation.
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE scans SET result_json = ? WHERE id = ?",
            (json.dumps(result), scan_id)
        )
        conn.commit()

    return JSONResponse(result)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = json.loads(row["result_json"])
    result["scan_id"] = row["id"]
    result["created_at"] = row["created_at"]
    return JSONResponse(result)


@app.get("/api/scans")
def list_scans():
    return load_recent_scans(50)


@app.get("/api/report/{scan_id}")
def report(scan_id: int):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = json.loads(row["result_json"])
    result["scan_id"] = row["id"]
    result["created_at"] = row["created_at"]

    output_path = REPORT_DIR / f"webshield_v2_report_{scan_id}.pdf"
    build_pdf_report(result, output_path)

    return FileResponse(
        output_path,
        media_type="application/pdf",
        filename=output_path.name,
    )
