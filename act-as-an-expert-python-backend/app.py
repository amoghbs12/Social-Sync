"""Small Flask API for the Social Sync SIH cybersecurity dashboard.

The API deliberately contains no frontend code and no heavyweight database.
Evidence records are stored in memory for the lifetime of the demo process.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from flask import Flask, jsonify, request
from flask_cors import CORS


app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# CISA's public Known Exploited Vulnerabilities (KEV) catalog.  This is the
# only external source used by this prototype; synthetic values are retained
# when the catalog cannot be reached during a live demo.
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
VALID_APPS = {"all", "instagram", "youtube", "linkedin", "facebook", "whatsapp", "telegram", "x", "discord"}
VALID_CATEGORIES = {"all", "phishing", "botnets", "scams", "disinformation", "malware", "radicalization"}
VALID_AUDIENCES = {"all", "students", "creators", "startups", "ecommerce", "localbusiness", "nonprofits", "agencies"}

_evidence: dict[str, dict] = {}
_evidence_lock = threading.Lock()


@app.get("/")
def dashboard():
    """Serve the supplied Social Sync dashboard as a complete local website."""
    return app.send_static_file("index.html")


def _error(message: str, status: int = 400):
    return jsonify({"error": message}), status


def _validate_filters():
    """Read and validate dashboard filter query parameters."""
    filters = {
        "app": request.args.get("app", "all").lower(),
        "category": request.args.get("category", "all").lower(),
        "audience": request.args.get("audience", "all").lower(),
    }
    allowed = {"app": VALID_APPS, "category": VALID_CATEGORIES, "audience": VALID_AUDIENCES}
    for name, value in filters.items():
        if value not in allowed[name]:
            return None, _error(f"Invalid {name}. Allowed values: {', '.join(sorted(allowed[name]))}")
    return filters, None


def _score(filters: dict) -> int:
    """Produce repeatable demo risk values for each selected dashboard scope."""
    key = "|".join(filters.values()).encode()
    return 42 + int(hashlib.sha256(key).hexdigest()[:4], 16) % 55


def _fetch_kev(limit: int = 5) -> tuple[list[dict], str]:
    """Fetch a small, safe subset of CISA KEV records, with a demo fallback."""
    try:
        req = Request(KEV_CATALOG_URL, headers={"User-Agent": "SocialSync-SIH-demo/1.0"})
        with urlopen(req, timeout=5) as response:  # nosec B310 - fixed public CISA URL
            catalog = json.load(response)
        rows = catalog.get("vulnerabilities", [])[-limit:]
        return [
            {
                "cve": row.get("cveID"),
                "vendor": row.get("vendorProject"),
                "product": row.get("product"),
                "name": row.get("vulnerabilityName"),
                "date_added": row.get("dateAdded"),
                "required_action": row.get("requiredAction"),
            }
            for row in reversed(rows)
        ], "live"
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return [
            {
                "cve": "DEMO-KEV-001",
                "vendor": "Demo source",
                "product": "Social signal monitor",
                "name": "Public-feed fallback record",
                "date_added": None,
                "required_action": "Retry when internet access is available.",
            }
        ], "fallback"


@app.get("/api/health")
def health():
    """Basic readiness check for the frontend or deployment platform."""
    return jsonify({"status": "ok", "service": "social-sync-api", "timestamp": datetime.now(timezone.utc).isoformat()})


@app.get("/api/threats/summary")
def threat_summary():
    """Return filter-aware threat KPIs for the dashboard's main cards."""
    filters, error = _validate_filters()
    if error:
        return error
    risk = _score(filters)
    severity = "critical" if risk >= 85 else "high" if risk >= 70 else "medium"
    return jsonify({
        "filters": filters,
        "risk_score": risk,
        "severity": severity,
        "overall_threats": risk * 47,
        "critical_threats": max(5, risk * 2 - 60),
        "coordinated_clusters": max(3, risk - 36),
        "phishing_signals": risk * 3,
        "bot_coordination": max(1, risk - 44),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


@app.get("/api/threats/feed")
def threat_feed():
    """Return publicly sourced KEV intelligence plus the selected scope."""
    filters, error = _validate_filters()
    if error:
        return error
    records, source_status = _fetch_kev()
    return jsonify({
        "filters": filters,
        "source": "CISA Known Exploited Vulnerabilities Catalog",
        "source_status": source_status,
        "records": records,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


@app.post("/api/evidence")
def create_evidence():
    """Hash a social-media evidence payload and retain it in memory for the demo."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not payload.get("content"):
        return _error("JSON body must include a non-empty 'content' field.")

    content = str(payload["content"]).strip()
    if len(content) > 20_000:
        return _error("'content' must be 20,000 characters or fewer.")
    canonical = json.dumps({"content": content, "source": payload.get("source", "unknown")}, sort_keys=True)
    record = {
        "evidence_id": f"SIH-{uuid4().hex[:12].upper()}",
        "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "source": str(payload.get("source", "unknown")),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "integrity_status": "verified",
    }
    with _evidence_lock:
        _evidence[record["evidence_id"]] = record
    return jsonify(record), 201


@app.get("/api/evidence/<evidence_id>")
def get_evidence(evidence_id: str):
    """Retrieve a previously created in-memory evidence integrity record."""
    with _evidence_lock:
        record = _evidence.get(evidence_id)
    if not record:
        return _error("Evidence record not found.", 404)
    return jsonify(record)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
