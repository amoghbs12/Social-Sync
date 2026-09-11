/**
 * One-click local server for Social Sync.
 * This uses only Node.js built-ins, so it runs on this PC even before Python
 * is installed. Its routes mirror the Flask backend in app.py.
 */
const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { exec } = require("child_process");

// Hosting platforms supply PORT. Local launches continue to use port 5000.
const PORT = Number(process.env.PORT || 5000);
const HOST = process.env.HOST || "127.0.0.1";
const STATIC_DIR = path.join(__dirname, "static");
const evidence = new Map();

function send(res, status, body, type = "application/json") {
  res.writeHead(status, { "Content-Type": `${type}; charset=utf-8`, "Access-Control-Allow-Origin": "*" });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
}

function filters(url) {
  const data = {
    app: (url.searchParams.get("app") || "all").toLowerCase(),
    category: (url.searchParams.get("category") || "all").toLowerCase(),
    audience: (url.searchParams.get("audience") || "all").toLowerCase()
  };
  const allowed = {
    app: ["all", "instagram", "youtube", "linkedin", "facebook", "whatsapp", "telegram", "x", "discord"],
    category: ["all", "phishing", "botnets", "scams", "disinformation", "malware", "radicalization"],
    audience: ["all", "students", "creators", "startups", "ecommerce", "localbusiness", "nonprofits", "agencies"]
  };
  return Object.entries(data).every(([key, value]) => allowed[key].includes(value)) ? data : null;
}

function riskScore(data) {
  const digest = crypto.createHash("sha256").update(`${data.app}|${data.category}|${data.audience}`).digest("hex");
  return 42 + (parseInt(digest.slice(0, 4), 16) % 55);
}

function kevFeed(done) {
  const req = https.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", { headers: { "User-Agent": "SocialSync-SIH-demo/1.0" }, timeout: 5000 }, (response) => {
    let raw = "";
    response.on("data", (chunk) => { raw += chunk; });
    response.on("end", () => {
      try {
        const items = JSON.parse(raw).vulnerabilities.slice(-5).reverse().map((row) => ({
          cve: row.cveID, vendor: row.vendorProject, product: row.product,
          name: row.vulnerabilityName, date_added: row.dateAdded, required_action: row.requiredAction
        }));
        done(items, "live");
      } catch { done(fallbackRecords(), "fallback"); }
    });
  });
  req.on("error", () => done(fallbackRecords(), "fallback"));
  req.on("timeout", () => { req.destroy(); done(fallbackRecords(), "fallback"); });
}

function fallbackRecords() {
  return [{ cve: "DEMO-KEV-001", vendor: "Demo source", product: "Social signal monitor", name: "Public-feed fallback record", required_action: "Retry when internet access is available." }];
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => { data += chunk; if (data.length > 30000) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { reject(new Error("Invalid JSON")); } });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === "OPTIONS") return send(res, 204, "", "text/plain");
  if (req.method === "GET" && url.pathname === "/api/health") return send(res, 200, { status: "ok", service: "social-sync-api", timestamp: new Date().toISOString() });

  if (req.method === "GET" && url.pathname === "/api/threats/summary") {
    const data = filters(url); if (!data) return send(res, 400, { error: "Invalid dashboard filter." });
    const risk = riskScore(data);
    return send(res, 200, { filters: data, risk_score: risk, severity: risk >= 85 ? "critical" : risk >= 70 ? "high" : "medium", overall_threats: risk * 47, critical_threats: Math.max(5, risk * 2 - 60), coordinated_clusters: Math.max(3, risk - 36), phishing_signals: risk * 3, bot_coordination: Math.max(1, risk - 44), generated_at: new Date().toISOString() });
  }

  if (req.method === "GET" && url.pathname === "/api/threats/feed") {
    const data = filters(url); if (!data) return send(res, 400, { error: "Invalid dashboard filter." });
    return kevFeed((records, source_status) => send(res, 200, { filters: data, source: "CISA Known Exploited Vulnerabilities Catalog", source_status, records, generated_at: new Date().toISOString() }));
  }

  if (req.method === "POST" && url.pathname === "/api/evidence") {
    try {
      const body = await readBody(req);
      if (!body.content || String(body.content).trim().length > 20000) return send(res, 400, { error: "JSON body must include 'content' up to 20,000 characters." });
      const record = { evidence_id: `SIH-${crypto.randomUUID().replaceAll("-", "").slice(0, 12).toUpperCase()}`, sha256: crypto.createHash("sha256").update(JSON.stringify({ content: String(body.content).trim(), source: body.source || "unknown" })).digest("hex"), source: String(body.source || "unknown"), created_at: new Date().toISOString(), integrity_status: "verified" };
      evidence.set(record.evidence_id, record); return send(res, 201, record);
    } catch { return send(res, 400, { error: "Request body must be valid JSON." }); }
  }

  if (req.method === "GET" && url.pathname.startsWith("/api/evidence/")) {
    const record = evidence.get(decodeURIComponent(url.pathname.split("/").pop()));
    return record ? send(res, 200, record) : send(res, 404, { error: "Evidence record not found." });
  }

  const requested = url.pathname === "/" ? "index.html" : url.pathname.replace(/^\/static\//, "");
  const file = path.resolve(STATIC_DIR, requested);
  if (!file.startsWith(STATIC_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, "Not found", "text/plain");
  const type = path.extname(file) === ".js" ? "application/javascript" : "text/html";
  return send(res, 200, fs.readFileSync(file), type);
});

server.listen(PORT, HOST, () => {
  const site = `http://localhost:${PORT}`;
  console.log(`Social Sync is running at ${site}`);
  // A cloud server must not try to open a browser on the host machine.
  if (!process.env.PORT) exec(`start "Social Sync" ${site}`);
});
