# Social Sync SIH Backend

Run locally with Python 3.10+:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

## One-click launch on this computer

Python is not currently installed on this PC, but Node.js is. Double-click
`Open-Social-Sync.bat`. It starts `server.js`, opens the website automatically,
and provides the same API routes as the Flask backend. Keep its command window
open while using the website.

## Deploy online with Render

1. Create a GitHub repository and upload this entire project folder, including
   `static/`, `server.js`, `package.json`, and `render.yaml`.
2. At [Render](https://render.com), select **New → Blueprint**, connect the
   GitHub repository, and approve the detected `render.yaml` settings.
3. Select the free plan for a prototype, then create the service. The health
   check is `/api/health` and Render gives you a public `onrender.com` URL.

Alternatively create **New → Web Service** and use: runtime **Node**, build
command `npm install`, and start command `npm start`.

The website starts at `http://localhost:5000`. Flask serves the supplied dashboard
from `static/index.html`, and `static/backend-connector.js` connects its threat
filters, key metrics, and threat feed to the API.

## Frontend calls

Fetch the dashboard KPIs when an app/category/audience filter changes:

```js
const params = new URLSearchParams({ app: 'instagram', category: 'phishing', audience: 'students' });
const summary = await fetch(`http://localhost:5000/api/threats/summary?${params}`).then(r => r.json());
```

Fetch the current public CISA Known Exploited Vulnerabilities feed:

```js
const feed = await fetch(`http://localhost:5000/api/threats/feed?${params}`).then(r => r.json());
```

Create a tamper-evident demonstration record:

```js
const evidence = await fetch('http://localhost:5000/api/evidence', {
  method: 'POST', headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({source: 'X', content: 'Suspicious URL observed in post'})
}).then(r => r.json());
```

`GET /api/evidence/<evidence_id>` returns a saved record. Evidence is in memory and resets when the server restarts, which is intentional for this prototype.
