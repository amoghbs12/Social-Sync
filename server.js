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
// Cloud providers set PORT; listen publicly there, but remain local by default.
const HOST = process.env.HOST || (process.env.PORT ? "0.0.0.0" : "127.0.0.1");
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

function fetchPublicJson(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { "User-Agent": "SocialSync-SIH-demo/1.0" }, timeout: 7000 }, (response) => {
      let raw = "";
      response.on("data", (chunk) => { raw += chunk; });
      response.on("end", () => {
        if (response.statusCode < 200 || response.statusCode >= 300) return reject(new Error(`HTTP ${response.statusCode}`));
        try { resolve(JSON.parse(raw)); } catch { reject(new Error("Invalid JSON")); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(new Error("Request timed out")); });
  });
}

function fetchPublicText(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { "User-Agent": "SocialSync-SIH-demo/1.0" }, timeout: 7000 }, (response) => {
      let raw = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { raw += chunk; });
      response.on("end", () => response.statusCode >= 200 && response.statusCode < 300 ? resolve(raw) : reject(new Error(`HTTP ${response.statusCode}`)));
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(new Error("Request timed out")); });
  });
}

let trendCache = { value: null, expiresAt: 0 };
const decodeXml = (value) => value.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#39;/g, "'").replace(/&quot;/g, '"');
const xmlTag = (xml, tag) => (xml.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, "i")) || [])[1] || "";

/** Fetch real daily India/region search trends from Google's public Trends RSS feed. */
async function publicTrends(geo) {
  if (trendCache.value && trendCache.value.geo === geo && Date.now() < trendCache.expiresAt) return trendCache.value;
  try {
    const rss = await fetchPublicText(`https://trends.google.com/trending/rss?geo=${encodeURIComponent(geo)}`);
    const items = [...rss.matchAll(/<item>([\s\S]*?)<\/item>/gi)].slice(0, 10).map((match) => {
      const item = match[1];
      return { topic: decodeXml(xmlTag(item, "title")).trim(), traffic: decodeXml(xmlTag(item, "ht:approx_traffic")).trim(), published_at: decodeXml(xmlTag(item, "pubDate")).trim(), source: "Google Trends" };
    }).filter((item) => item.topic);
    const value = { geo, source: "Google Trends daily public feed", source_status: items.length ? "live" : "unavailable", items, generated_at: new Date().toISOString() };
    trendCache = { value, expiresAt: Date.now() + 10 * 60 * 1000 };
    return value;
  } catch {
    return { geo, source: "Google Trends daily public feed", source_status: "unavailable", items: [], generated_at: new Date().toISOString() };
  }
}

let intelligenceCache = { value: null, expiresAt: 0 };

/**
 * Build a risk-prioritized, real-data intelligence snapshot.
 * EPSS is a public ML probability of observed exploitation in the next 30 days;
 * it is not a prediction of social-media activity or impact on a specific user.
 */
async function publicIntelligence() {
  if (intelligenceCache.value && Date.now() < intelligenceCache.expiresAt) return intelligenceCache.value;
  const [cisa, nvd] = await Promise.allSettled([
    fetchPublicJson("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
    fetchPublicJson("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5")
  ]);
  const records = [];
  const sources = { cisa_kev: cisa.status === "fulfilled" ? "live" : "unavailable", nist_nvd: nvd.status === "fulfilled" ? "live" : "unavailable", first_epss: "unavailable" };

  if (cisa.status === "fulfilled") {
    records.push(...cisa.value.vulnerabilities.slice(-4).reverse().map((row) => ({
      cve: row.cveID, vendor: row.vendorProject, product: row.product,
      name: row.vulnerabilityName, date_added: row.dateAdded, required_action: row.requiredAction,
      source: "CISA KEV", threat_status: "Known exploited"
    })));
  }
  if (nvd.status === "fulfilled") {
    records.push(...nvd.value.vulnerabilities.slice(0, 5).map(({ cve }) => {
      const metric = (cve.metrics?.cvssMetricV31 || cve.metrics?.cvssMetricV30 || cve.metrics?.cvssMetricV2 || [])[0]?.cvssData;
      return {
        cve: cve.id, vendor: "NIST NVD", product: "Public CVE feed",
        name: cve.descriptions?.find((item) => item.lang === "en")?.value || "CVE record",
        date_added: cve.published, required_action: "Review affected products and apply vendor guidance.",
        source: "NIST NVD", cvss_score: metric?.baseScore ?? null, severity: metric?.baseSeverity ?? "Not scored"
      };
    }));
  }
  const cves = [...new Set(records.map((record) => record.cve).filter((cve) => /^CVE-\d{4}-\d+$/i.test(cve)))];
  const epss = cves.length
    ? await fetchPublicJson(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cves.join(","))}`).catch(() => null)
    : null;
  if (epss) sources.first_epss = "live";
  const probabilities = new Map((epss?.data || []).map((row) => [row.cve, Number(row.epss)]));
  const enriched = (records.length ? records : fallbackRecords()).map((record) => {
    const epssProbability = probabilities.get(record.cve) ?? null;
    const knownExploited = record.source === "CISA KEV";
    const impact = Number(record.cvss_score || 0) / 10;
    const priority = knownExploited ? 100 : Math.round(((epssProbability || 0) * 70 + impact * 30) * 100);
    return { ...record, epss_probability: epssProbability, priority_score: priority, known_exploited: knownExploited };
  }).sort((a, b) => b.priority_score - a.priority_score);
  const top = enriched[0];
  const analysis = {
    method: "EPSS exploitation probability + NVD CVSS impact + CISA known-exploited status",
    records_analyzed: enriched.length,
    high_priority_count: enriched.filter((record) => record.priority_score >= 70).length,
    forecast_window: "next 30 days",
    forecast: top?.known_exploited
      ? `${top.cve} is already listed as known exploited; prioritize remediation now.`
      : top?.epss_probability != null
        ? `${top.cve} has a ${(top.epss_probability * 100).toFixed(1)}% EPSS exploitation probability in the next 30 days.`
        : "No live prediction was available from the public feeds."
  };
  const value = { records: enriched, source_status: enriched[0]?.cve === "DEMO-KEV-001" ? "fallback" : sources, analysis };
  intelligenceCache = { value, expiresAt: Date.now() + 5 * 60 * 1000 };
  return value;
}

function kevFeed(done) {
  publicIntelligence().then(({ records, source_status, analysis }) => done(records, source_status, analysis));
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
    return kevFeed((records, source_status, analysis) => {
      const topScore = records[0]?.priority_score || 0;
      const severity = topScore >= 85 ? "critical" : topScore >= 70 ? "high" : topScore >= 45 ? "medium" : "low";
      send(res, 200, { filters: data, data_mode: "live_public_vulnerability_analysis", risk_score: topScore, severity, overall_threats: analysis.records_analyzed, critical_threats: analysis.high_priority_count, coordinated_clusters: 0, phishing_signals: 0, bot_coordination: 0, source_status, generated_at: new Date().toISOString() });
    });
  }

  if (req.method === "GET" && url.pathname === "/api/threats/feed") {
    const data = filters(url); if (!data) return send(res, 400, { error: "Invalid dashboard filter." });
    return kevFeed((records, source_status, analysis) => send(res, 200, { filters: data, source: "CISA KEV + NIST NVD + FIRST EPSS public feeds", source_status, analysis, records, generated_at: new Date().toISOString() }));
  }

  if (req.method === "GET" && url.pathname === "/api/trends") {
    const geo = (url.searchParams.get("geo") || "IN").toUpperCase();
    if (!/^[A-Z]{2}$/.test(geo)) return send(res, 400, { error: "geo must be a two-letter country code, for example IN." });
    return publicTrends(geo).then((data) => send(res, 200, data));
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
