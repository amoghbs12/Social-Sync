/**
 * SOCIAL SYNC — REAL-TIME PUBLIC INTELLIGENCE BACKEND
 *
 * Frontend is NOT changed.
 *
 * Live/public sources:
 *   1. Google Trends RSS
 *   2. Google News RSS
 *   3. Reddit public JSON
 *   4. CISA Known Exploited Vulnerabilities (KEV)
 *   5. NIST NVD
 *   6. FIRST EPSS
 *
 * Features:
 *   - Live trend analysis
 *   - Social threat signal detection
 *   - Named threat classification
 *   - Cyber vulnerability intelligence
 *   - Threat scoring
 *   - 24–48 hour explainable prediction
 *   - Rolling signal history
 *   - Server-Sent Events
 *   - Evidence hashing
 *
 * IMPORTANT:
 * This backend does not invent live counts.
 * If a public source is unavailable, source_status reports it.
 */

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { exec } = require("child_process");

/* ============================================================
   SERVER CONFIGURATION
   ============================================================ */

const PORT = Number(process.env.PORT || 5000);

const HOST =
  process.env.HOST ||
  (process.env.PORT ? "0.0.0.0" : "127.0.0.1");

const STATIC_DIR = path.join(__dirname, "static");

const evidence = new Map();

/* ============================================================
   CACHE + LIVE REFRESH
   ============================================================ */

const CACHE = {
  trends: 10 * 60 * 1000,
  social: 2 * 60 * 1000,
  news: 2 * 60 * 1000,
  cyber: 5 * 60 * 1000
};

const REFRESH_INTERVAL = 2 * 60 * 1000;

let trendCache = {
  value: null,
  expiresAt: 0
};

let socialCache = {
  value: null,
  expiresAt: 0
};

let newsCache = {
  value: null,
  expiresAt: 0
};

let cyberCache = {
  value: null,
  expiresAt: 0
};

/*
 * Rolling history is used by the prediction engine.
 * It is intentionally in memory so no frontend/database change
 * is required.
 */
const intelligenceHistory = [];

const MAX_HISTORY = 180;

/* ============================================================
   HTTP HELPERS
   ============================================================ */

function send(res, status, body, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": `${type}; charset=utf-8`,
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store"
  });

  if (type === "application/json") {
    res.end(JSON.stringify(body));
  } else {
    res.end(body);
  }
}

/* ============================================================
   DASHBOARD FILTERS
   ============================================================ */

function filters(url) {
  const data = {
    app: (url.searchParams.get("app") || "all").toLowerCase(),
    category: (url.searchParams.get("category") || "all").toLowerCase(),
    audience: (url.searchParams.get("audience") || "all").toLowerCase()
  };

  const allowed = {
    app: [
      "all",
      "instagram",
      "youtube",
      "linkedin",
      "facebook",
      "whatsapp",
      "telegram",
      "x",
      "discord"
    ],

    category: [
      "all",
      "phishing",
      "botnets",
      "scams",
      "disinformation",
      "malware",
      "radicalization"
    ],

    audience: [
      "all",
      "students",
      "creators",
      "startups",
      "ecommerce",
      "localbusiness",
      "nonprofits",
      "agencies"
    ]
  };

  const valid = Object.entries(data).every(
    ([key, value]) => allowed[key].includes(value)
  );

  return valid ? data : null;
}

/* ============================================================
   PUBLIC HTTPS FETCHERS
   ============================================================ */

function fetchText(url, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const request = https.get(
      url,
      {
        headers: {
          "User-Agent": "SocialSync-SIH-2026/1.0",
          "Accept": "*/*",
          ...extraHeaders
        },
        timeout: 10000
      },
      response => {
        let raw = "";

        response.setEncoding("utf8");

        response.on("data", chunk => {
          raw += chunk;
        });

        response.on("end", () => {
          if (
            response.statusCode < 200 ||
            response.statusCode >= 300
          ) {
            reject(
              new Error(`HTTP ${response.statusCode}`)
            );
            return;
          }

          resolve(raw);
        });
      }
    );

    request.on("error", reject);

    request.on("timeout", () => {
      request.destroy(
        new Error("Request timed out")
      );
    });
  });
}

function fetchJson(url, extraHeaders = {}) {
  return fetchText(url, {
    Accept: "application/json",
    ...extraHeaders
  }).then(raw => JSON.parse(raw));
}

/* ============================================================
   XML HELPERS
   ============================================================ */

function decodeXml(value = "") {
  return String(value)
    .replace(
      /<!\[CDATA\[([\s\S]*?)\]\]>/g,
      "$1"
    )
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .trim();
}

function xmlTag(xml, tag) {
  const match = xml.match(
    new RegExp(
      `<${tag}(?:\\:[^>]+)?>([\\s\\S]*?)</${tag}(?:\\:[^>]+)?>`,
      "i"
    )
  );

  return match ? decodeXml(match[1]) : "";
}

/* ============================================================
   GOOGLE TRENDS
   ============================================================ */

async function publicTrends(geo = "IN") {
  if (
    trendCache.value &&
    trendCache.value.geo === geo &&
    Date.now() < trendCache.expiresAt
  ) {
    return trendCache.value;
  }

  try {
    const url =
      `https://trends.google.com/trending/rss?geo=${encodeURIComponent(geo)}`;

    const rss = await fetchText(url);

    const items = [
      ...rss.matchAll(/<item>([\s\S]*?)<\/item>/gi)
    ]
      .slice(0, 20)
      .map(match => {
        const item = match[1];

        return {
          topic: xmlTag(item, "title"),
          traffic: xmlTag(item, "ht:approx_traffic"),
          published_at: xmlTag(item, "pubDate"),
          source: "Google Trends"
        };
      })
      .filter(item => item.topic);

    const result = {
      geo,
      source: "Google Trends public RSS",
      source_status:
        items.length > 0 ? "live" : "unavailable",
      items,
      generated_at: new Date().toISOString()
    };

    trendCache = {
      value: result,
      expiresAt: Date.now() + CACHE.trends
    };

    return result;
  } catch (error) {
    return {
      geo,
      source: "Google Trends public RSS",
      source_status: "unavailable",
      items: [],
      error: error.message,
      generated_at: new Date().toISOString()
    };
  }
}

/* ============================================================
   THREAT CLASSIFICATION ENGINE
   ============================================================ */

function classifyThreat(text) {
  const value = String(text || "").toLowerCase();

  const rules = [
    {
      category: "phishing",
      keywords: [
        "phishing",
        "credential",
        "password",
        "login",
        "otp",
        "verify account",
        "fake login",
        "account verification"
      ],
      name: "Credential-Phishing Attempt",
      code: "THREAT-PHI-001",
      severity: "high"
    },

    {
      category: "scams",
      keywords: [
        "scam",
        "fraud",
        "fake offer",
        "investment scam",
        "giveaway scam",
        "upi fraud",
        "financial fraud"
      ],
      name: "Social Engineering / Scam Signal",
      code: "THREAT-SCM-001",
      severity: "high"
    },

    {
      category: "malware",
      keywords: [
        "malware",
        "ransomware",
        "trojan",
        "spyware",
        "virus",
        "payload",
        "infostealer",
        "malicious file"
      ],
      name: "Malware Distribution Signal",
      code: "THREAT-MAL-001",
      severity: "critical"
    },

    {
      category: "botnets",
      keywords: [
        "botnet",
        "automated accounts",
        "bot activity",
        "coordinated accounts",
        "fake accounts",
        "automation"
      ],
      name: "Automated / Coordinated Activity",
      code: "THREAT-BOT-001",
      severity: "high"
    },

    {
      category: "disinformation",
      keywords: [
        "disinformation",
        "misinformation",
        "fake news",
        "deepfake",
        "fabricated",
        "synthetic media",
        "manipulated video"
      ],
      name: "Potential Coordinated Disinformation",
      code: "THREAT-DIS-001",
      severity: "medium"
    },

    {
      category: "radicalization",
      keywords: [
        "radicalization",
        "extremist recruitment",
        "recruitment propaganda",
        "violent propaganda",
        "radical content"
      ],
      name: "Potential Radicalization Signal",
      code: "THREAT-RAD-001",
      severity: "high"
    }
  ];

  let best = null;
  let highestMatches = 0;

  for (const rule of rules) {
    let matches = 0;

    for (const keyword of rule.keywords) {
      if (value.includes(keyword)) {
        matches++;
      }
    }

    if (matches > highestMatches) {
      highestMatches = matches;
      best = rule;
    }
  }

  if (!best) {
    return {
      category: "informational",
      name: "General Social Signal",
      code: "SIGNAL-001",
      severity: "low"
    };
  }

  return {
    category: best.category,
    name: best.name,
    code: best.code,
    severity: best.severity,
    keyword_matches: highestMatches
  };
}

/* ============================================================
   REDDIT PUBLIC SIGNAL MONITOR
   ============================================================ */

async function redditSignals() {
  if (
    socialCache.value &&
    Date.now() < socialCache.expiresAt
  ) {
    return socialCache.value;
  }

  const query =
    "phishing OR scam OR malware OR ransomware OR deepfake OR botnet";

  const url =
    `https://www.reddit.com/search.json?q=${encodeURIComponent(query)}` +
    `&sort=new&limit=50&raw_json=1`;

  try {
    const data = await fetchJson(url);

    const posts =
      data?.data?.children
        ?.map(item => item.data)
        ?.filter(Boolean) || [];

    const records = posts.map(post => {
      const combinedText =
        `${post.title || ""} ${post.selftext || ""}`;

      const classification =
        classifyThreat(combinedText);

      return {
        id: post.id,
        platform: "Reddit",

        community:
          post.subreddit_name_prefixed || null,

        title:
          post.title || "",

        text_preview:
          String(post.selftext || "")
            .replace(/\s+/g, " ")
            .slice(0, 300),

        url:
          post.permalink
            ? `https://www.reddit.com${post.permalink}`
            : null,

        created_at:
          post.created_utc
            ? new Date(
                post.created_utc * 1000
              ).toISOString()
            : null,

        score:
          Number(post.score || 0),

        comments:
          Number(post.num_comments || 0),

        classification
      };
    });

    const counts = {};

    for (const record of records) {
      const category =
        record.classification.category;

      counts[category] =
        (counts[category] || 0) + 1;
    }

    const result = {
      source: "Reddit public JSON search",
      source_status: "live",
      query,
      records,
      counts,
      generated_at:
        new Date().toISOString()
    };

    socialCache = {
      value: result,
      expiresAt:
        Date.now() + CACHE.social
    };

    return result;
  } catch (error) {
    return {
      source: "Reddit public JSON search",
      source_status: "unavailable",
      query,
      records: [],
      counts: {},
      error: error.message,
      generated_at:
        new Date().toISOString()
    };
  }
}

/* ============================================================
   GOOGLE NEWS THREAT SIGNALS
   ============================================================ */

async function googleNewsSignals() {
  if (
    newsCache.value &&
    Date.now() < newsCache.expiresAt
  ) {
    return newsCache.value;
  }

  const searches = [
    ["phishing", "phishing OR credential theft"],
    ["malware", "malware OR ransomware"],
    ["scams", "online scam OR fraud"],
    ["deepfake", "deepfake OR synthetic media"],
    ["social engineering", "social engineering cyber"]
  ];

  const records = [];
  const source_status = {};

  for (const [category, query] of searches) {
    try {
      const url =
        `https://news.google.com/rss/search?q=${encodeURIComponent(query)}` +
        `&hl=en-IN&gl=IN&ceid=IN:en`;

      const rss = await fetchText(url);

      const items = [
        ...rss.matchAll(/<item>([\s\S]*?)<\/item>/gi)
      ]
        .slice(0, 10)
        .map(match => {
          const item = match[1];

          return {
            category,
            title: xmlTag(item, "title"),
            published_at:
              xmlTag(item, "pubDate"),
            link:
              xmlTag(item, "link"),
            source:
              "Google News RSS"
          };
        })
        .filter(item => item.title);

      records.push(...items);

      source_status[category] = "live";
    } catch (error) {
      source_status[category] =
        "unavailable";
    }
  }

  const counts = {};

  for (const record of records) {
    counts[record.category] =
      (counts[record.category] || 0) + 1;
  }

  const result = {
    source:
      "Google News RSS public feeds",
    source_status,
    records,
    counts,
    generated_at:
      new Date().toISOString()
  };

  newsCache = {
    value: result,
    expiresAt:
      Date.now() + CACHE.news
  };

  return result;
}

/* ============================================================
   CISA + NVD + EPSS CYBER INTELLIGENCE
   ============================================================ */

function fallbackRecords() {
  return [
    {
      cve: "NO-LIVE-CVE",
      vendor: "Public feeds",
      product: "Cyber intelligence",
      name:
        "No public vulnerability feed is currently reachable.",
      required_action:
        "Retry the live sources.",
      source: "fallback",
      priority_score: 0,
      known_exploited: false
    }
  ];
}

async function publicIntelligence() {
  if (
    cyberCache.value &&
    Date.now() < cyberCache.expiresAt
  ) {
    return cyberCache.value;
  }

  const [cisa, nvd] =
    await Promise.allSettled([
      fetchJson(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
      ),

      fetchJson(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10"
      )
    ]);

  const records = [];

  const sources = {
    cisa_kev:
      cisa.status === "fulfilled"
        ? "live"
        : "unavailable",

    nist_nvd:
      nvd.status === "fulfilled"
        ? "live"
        : "unavailable",

    first_epss: "unavailable"
  };

  /* ---------------- CISA KEV ---------------- */

  if (cisa.status === "fulfilled") {
    const vulnerabilities =
      cisa.value.vulnerabilities || [];

    const latest =
      vulnerabilities
        .slice(-10)
        .reverse();

    for (const row of latest) {
      records.push({
        cve: row.cveID,
        vendor: row.vendorProject,
        product: row.product,
        name: row.vulnerabilityName,
        date_added: row.dateAdded,
        required_action:
          row.requiredAction,
        source: "CISA KEV",
        threat_status:
          "Known exploited",
        known_exploited: true
      });
    }
  }

  /* ---------------- NIST NVD ---------------- */

  if (nvd.status === "fulfilled") {
    const vulnerabilities =
      nvd.value.vulnerabilities || [];

    for (const item of vulnerabilities.slice(0, 10)) {
      const cve = item.cve;

      const metrics =
        cve.metrics || {};

      const metric =
        (
          metrics.cvssMetricV31 ||
          metrics.cvssMetricV30 ||
          metrics.cvssMetricV2 ||
          []
        )[0]?.cvssData;

      records.push({
        cve: cve.id,

        vendor: "NIST NVD",

        product:
          "Public CVE feed",

        name:
          cve.descriptions
            ?.find(x => x.lang === "en")
            ?.value ||
          "CVE record",

        date_added:
          cve.published,

        required_action:
          "Review affected products and apply vendor guidance.",

        source:
          "NIST NVD",

        cvss_score:
          metric?.baseScore ?? null,

        severity:
          metric?.baseSeverity ||
          "Not scored",

        known_exploited: false
      });
    }
  }

  /* ---------------- FIRST EPSS ---------------- */

  const cves = [
    ...new Set(
      records
        .map(x => x.cve)
        .filter(
          x =>
            /^CVE-\d{4}-\d+$/i.test(x)
        )
    )
  ];

  let epss = null;

  if (cves.length > 0) {
    try {
      epss = await fetchJson(
        `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(
          cves.join(",")
        )}`
      );

      sources.first_epss = "live";
    } catch {
      sources.first_epss =
        "unavailable";
    }
  }

  const probabilities =
    new Map(
      (epss?.data || []).map(
        row => [
          row.cve,
          Number(row.epss)
        ]
      )
    );

  /* ---------------- PRIORITY SCORE ---------------- */

  const enriched =
    (
      records.length
        ? records
        : fallbackRecords()
    )
      .map(record => {
        const ep =
          probabilities.get(
            record.cve
          ) ?? null;

        const cvss =
          Number(
            record.cvss_score || 0
          );

        const known =
          Boolean(
            record.known_exploited
          );

        /*
         * Known exploited = maximum priority.
         *
         * Otherwise:
         * 70% EPSS
         * 30% CVSS impact
         */

        const calculated =
          known
            ? 100
            : Math.round(
                (
                  (ep || 0) * 70 +
                  (cvss / 10) * 30
                ) * 100
              );

        return {
          ...record,

          epss_probability: ep,

          priority_score:
            Math.min(
              100,
              calculated
            ),

          threat_code:
            known
              ? "THREAT-CVE-KEV"
              : "THREAT-CVE-RISK"
        };
      })
      .sort(
        (a, b) =>
          b.priority_score -
          a.priority_score
      );

  const top =
    enriched[0];

  const result = {
    records: enriched,

    source_status:
      sources,

    analysis: {
      method:
        "CISA known-exploited status + NIST CVSS impact + FIRST EPSS exploitation probability",

      records_analyzed:
        enriched.length,

      high_priority_count:
        enriched.filter(
          x =>
            x.priority_score >= 70
        ).length,

      critical_count:
        enriched.filter(
          x =>
            x.priority_score >= 85 ||
            x.known_exploited
        ).length,

      forecast_window:
        "next 30 days",

      forecast:
        top?.known_exploited
          ? `${top.cve} is already known exploited; remediation should be prioritized.`
          : top?.epss_probability != null
            ? `${top.cve} has ${(top.epss_probability * 100).toFixed(1)}% EPSS exploitation probability in the next 30 days.`
            : "No live exploitation probability was available."
    },

    generated_at:
      new Date().toISOString()
  };

  cyberCache = {
    value: result,
    expiresAt:
      Date.now() + CACHE.cyber
  };

  return result;
}

/* ============================================================
   PREDICTION ENGINE
   ============================================================ */

function buildPrediction(social, news) {
  const categories = [
    "phishing",
    "scams",
    "malware",
    "botnets",
    "disinformation",
    "radicalization"
  ];

  const socialCounts =
    social?.counts || {};

  const newsCounts =
    news?.counts || {};

  /*
   * Only use a previous point if one really exists.
   * This prevents a fake 100% growth reading
   * on the very first refresh.
   */

  const previous =
    intelligenceHistory.length >= 2
      ? intelligenceHistory[
          intelligenceHistory.length - 2
        ]
      : null;

  const candidates =
    categories.map(category => {
      const current =
        Number(
          socialCounts[category] || 0
        );

      const previousCount =
        Number(
          previous
            ?.social
            ?.counts
            ?.[category] || 0
        );

      const newsCount =
        Number(
          newsCounts[category] || 0
        );

      let growth = 0;

      if (previous) {
        if (previousCount > 0) {
          growth =
            (
              (current -
                previousCount) /
              previousCount
            ) * 100;
        } else if (current > 0) {
          growth = 100;
        }
      }

      /*
       * Explainable weighted prediction.
       *
       * Signal volume:
       *   max 35 points
       *
       * Positive velocity:
       *   max 20 points
       *
       * News pressure:
       *   max 15 points
       *
       * Base:
       *   30 points
       */

      const probability =
        Math.min(
          95,
          Math.max(
            5,
            Math.round(
              30 +
              Math.min(
                35,
                current * 7
              ) +
              Math.min(
                20,
                Math.max(0, growth) / 4
              ) +
              Math.min(
                15,
                newsCount * 2
              )
            )
          )
        );

      return {
        category,
        current_signals: current,
        previous_signals:
          previousCount,
        news_signals:
          newsCount,
        growth_percent:
          Math.round(growth),
        probability
      };
    })
    .sort(
      (a, b) =>
        b.probability -
        a.probability
    );

  const top =
    candidates[0] || {
      category: "phishing",
      current_signals: 0,
      previous_signals: 0,
      news_signals: 0,
      growth_percent: 0,
      probability: 5
    };

  const names = {
    phishing: [
      "Credential-Phishing Campaign",
      "PRED-PHI-001"
    ],

    scams: [
      "Social Engineering / Scam Surge",
      "PRED-SCM-001"
    ],

    malware: [
      "Malware Distribution Surge",
      "PRED-MAL-001"
    ],

    botnets: [
      "Automated Coordination Surge",
      "PRED-BOT-001"
    ],

    disinformation: [
      "Coordinated Disinformation Signal",
      "PRED-DIS-001"
    ],

    radicalization: [
      "Potential Radicalization Surge",
      "PRED-RAD-001"
    ]
  };

  const [
    threat,
    threat_code
  ] =
    names[top.category] ||
    names.phishing;

  const confidence =
    top.probability >= 75
      ? "high"
      : top.probability >= 55
        ? "medium"
        : "low";

  return {
    threat,

    threat_code,

    category:
      top.category,

    probability:
      top.probability,

    confidence,

    current_signals:
      top.current_signals,

    previous_signals:
      top.previous_signals,

    news_signals:
      top.news_signals,

    growth_percent:
      top.growth_percent,

    forecast_horizon:
      "next 24–48 hours",

    methodology:
      "Rolling public signal volume + signal velocity + public threat/news activity",

    evidence: [
      `${top.current_signals} current social signals`,
      `${top.news_signals} recent public threat/news signals`,
      `${top.growth_percent >= 0 ? "+" : ""}${top.growth_percent}% signal change since previous refresh`
    ],

    disclaimer:
      "This is an explainable early-warning forecast, not a guarantee of a future event."
  };
}

/* ============================================================
   LIVE SNAPSHOT REFRESH
   ============================================================ */

async function refreshLiveSnapshot() {
  try {
    const [
      social,
      news,
      cyber,
      trends
    ] =
      await Promise.all([
        redditSignals(),
        googleNewsSignals(),
        publicIntelligence(),
        publicTrends("IN")
      ]);

    const snapshot = {
      timestamp:
        new Date().toISOString(),

      social: {
        counts:
          social.counts || {},

        total:
          social.records?.length || 0
      },

      news: {
        counts:
          news.counts || {},

        total:
          news.records?.length || 0
      },

      cyber: {
        high_priority:
          cyber.records?.filter(
            x =>
              x.priority_score >= 70
          ).length || 0,

        critical:
          cyber.records?.filter(
            x =>
              x.priority_score >= 85 ||
              x.known_exploited
          ).length || 0
      },

      trends: {
        total:
          trends.items?.length || 0
      }
    };

    intelligenceHistory.push(
      snapshot
    );

    if (
      intelligenceHistory.length >
      MAX_HISTORY
    ) {
      intelligenceHistory.shift();
    }

    console.log(
      `[LIVE] Refresh completed: ${snapshot.timestamp}`
    );
  } catch (error) {
    console.error(
      "[LIVE] Refresh error:",
      error.message
    );
  }
}

/* ============================================================
   RISK CALCULATION
   ============================================================ */

function riskBand(score) {
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 45) return "medium";
  return "low";
}

async function buildSummary(data) {
  const [
    cyber,
    social,
    news,
    trends
  ] =
    await Promise.all([
      publicIntelligence(),
      redditSignals(),
      googleNewsSignals(),
      publicTrends("IN")
    ]);

  const counts =
    social.counts || {};

  const phishing =
    counts.phishing || 0;

  const scams =
    counts.scams || 0;

  const malware =
    counts.malware || 0;

  const botnets =
    counts.botnets || 0;

  const disinformation =
    counts.disinformation || 0;

  const radicalization =
    counts.radicalization || 0;

  const socialTotal =
    social.records?.length || 0;

  /*
   * Social risk is based on observed signal composition.
   * It is NOT a claim that these posts are confirmed attacks.
   */

  let socialRisk = 0;

  if (socialTotal > 0) {
    socialRisk =
      Math.round(
        (
          (phishing /
            socialTotal) * 45 +

          (scams /
            socialTotal) * 30 +

          (malware /
            socialTotal) * 35 +

          (botnets /
            socialTotal) * 25 +

          (disinformation /
            socialTotal) * 15 +

          (radicalization /
            socialTotal) * 20
        )
      );
  }

  socialRisk =
    Math.min(
      100,
      socialRisk
    );

  const cyberTop =
    cyber.records?.[0]
      ?.priority_score || 0;

  const newsPressure =
    Math.min(
      100,

      (news.counts?.phishing || 0) * 3 +

      (news.counts?.malware || 0) * 3 +

      (news.counts?.scams || 0) * 2 +

      (news.counts?.deepfake || 0) * 2
    );

  const combinedRisk =
    Math.min(
      100,

      Math.round(
        Math.max(
          cyberTop,
          socialRisk +
            newsPressure * 0.15
        )
      )
    );

  const previous =
    intelligenceHistory.length >= 2
      ? intelligenceHistory[
          intelligenceHistory.length - 2
        ]
      : null;

  const previousTotal =
    previous?.social?.total || 0;

  const signalVelocity =
    previousTotal > 0
      ? Math.round(
          (
            (socialTotal -
              previousTotal) /
            previousTotal
          ) * 100
        )
      : 0;

  const threat_counts = {
    phishing,
    scams,
    malware,
    botnets,
    disinformation,
    radicalization
  };

  const totalSignals =
    Object.values(
      threat_counts
    ).reduce(
      (a, b) => a + b,
      0
    );

  const prediction =
    buildPrediction(
      social,
      news
    );

  return {
    filters: data,

    data_mode:
      "live_public_intelligence",

    risk_score:
      combinedRisk,

    severity:
      riskBand(combinedRisk),

    overall_threats:
      totalSignals +
      (
        cyber.records?.filter(
          x =>
            x.priority_score >= 70
        ).length || 0
      ),

    critical_threats:
      cyber.records?.filter(
        x =>
          x.priority_score >= 85 ||
          x.known_exploited
      ).length || 0,

    coordinated_clusters:
      botnets,

    phishing_signals:
      phishing,

    bot_coordination:
      botnets,

    threat_counts,

    trend_count:
      trends.items?.length || 0,

    news_signals:
      news.records?.length || 0,

    signal_velocity_percent:
      signalVelocity,

    predicted_threat:
      prediction.threat,

    predicted_threat_code:
      prediction.threat_code,

    predicted_probability:
      prediction.probability,

    prediction_confidence:
      prediction.confidence,

    sources: {
      social:
        social.source_status,

      news:
        news.source_status,

      cyber:
        cyber.source_status,

      trends:
        trends.source_status
    },

    generated_at:
      new Date().toISOString()
  };
}

/* ============================================================
   PREDICTION API
   ============================================================ */

async function predictions() {
  const [
    social,
    news
  ] =
    await Promise.all([
      redditSignals(),
      googleNewsSignals()
    ]);

  return {
    forecast_horizon:
      "next 24–48 hours",

    prediction:
      buildPrediction(
        social,
        news
      ),

    history_points:
      intelligenceHistory.length,

    generated_at:
      new Date().toISOString()
  };
}

/* ============================================================
   REQUEST BODY
   ============================================================ */

function readBody(req) {
  return new Promise(
    (resolve, reject) => {
      let data = "";

      req.on(
        "data",
        chunk => {
          data += chunk;

          if (
            data.length >
            30000
          ) {
            req.destroy();
          }
        }
      );

      req.on(
        "end",
        () => {
          try {
            resolve(
              JSON.parse(
                data || "{}"
              )
            );
          } catch {
            reject(
              new Error(
                "Invalid JSON"
              )
            );
          }
        }
      );

      req.on(
        "error",
        reject
      );
    }
  );
}

/* ============================================================
   HTTP SERVER
   ============================================================ */

const server =
  http.createServer(
    async (req, res) => {
      try {
        const url =
          new URL(
            req.url,
            `http://${req.headers.host}`
          );

        /* ---------------- OPTIONS ---------------- */

        if (
          req.method ===
          "OPTIONS"
        ) {
          return send(
            res,
            204,
            "",
            "text/plain"
          );
        }

        /* ---------------- HEALTH ---------------- */

        if (
          req.method === "GET" &&
          url.pathname ===
            "/api/health"
        ) {
          return send(
            res,
            200,
            {
              status: "ok",

              service:
                "social-sync-api",

              mode:
                "live-public-intelligence",

              timestamp:
                new Date().toISOString()
            }
          );
        }

        /* ---------------- TRENDS ---------------- */

        if (
          req.method === "GET" &&
          url.pathname ===
            "/api/trends"
        ) {
          const geo =
            (
              url.searchParams.get(
                "geo"
              ) || "IN"
            ).toUpperCase();

          if (
            !/^[A-Z]{2}$/.test(
              geo
            )
          ) {
            return send(
              res,
              400,
              {
                error:
                  "geo must be a two-letter country code."
              }
            );
          }

          return send(
            res,
            200,
            await publicTrends(
              geo
            )
          );
        }

        /* ---------------- SOCIAL SIGNALS ---------------- */

        if (
          req.method === "GET" &&
          url.pathname ===
            "/api/social/signals"
        ) {
          return send(
            res,
            200,
            await redditSignals()
          );
        }

        /* ---------------- THREAT SUMMARY ---------------- */

        if (
          req.method === "GET" &&
          url.pathname ===
            "/api/threats/summary"
        ) {
          const data =
            filters(url);

          if (!data) {
            return send(
              res,
              400,
              {
                error:
                  "Invalid dashboard filter."
              }
            );
          }

          return send(
            res,
            200,
            await buildSummary(
              data
            )
          );
        }

        /* ---------------- THREAT FEED ---------------- */

        if (
          req.method === "GET" &&
          url.pathname ===
            "/api/threats/feed"
        ) {
          const data =
            filters(url);

          if (!data) {
            return send(
              res,
              400,
              {
                error:
                  "Invalid dashboard filter."
              }
            );
          }

          const [
            cyber,
            social,
            news,
            prediction
          ] =
            await Promise.all([
              publicIntelligence(),
              redditSignals(),
              googleNewsSignals(),
              predictions()
            ]);

          return send(
            res,
            200,
            {
              filters: data,

              source:
                "CISA KEV + NIST NVD + FIRST EPSS + Reddit + Google News RSS",

              source_status: {
                cyber:
                  cyber.source_status,

                social:
                  social.source_status,

                news:
                  news.source_status
              },

              cyber_analysis:
                cyber.analysis,

              named_social_threats:
                social.records.filter(
                  record =>
                    record
                      .classification
                      .category !==
                    "informational"
                ),

              cyber_records:
                cyber.records,

              recent_threat_news:
                news.records,

              prediction:
                prediction.prediction,

              generated_at:
                new Date().toISOString()
            }
          );
        }

        /* ---------------- PREDICTIONS ---------------- */

        if (
          req.method === "GET" &&
          url.pathname ===
            "/api/predictions"
        ) {
          return send(
            res,
            200,
            await predictions()
          );
        }

        /* ---------------- LIVE SSE STREAM ---------------- */

        if (
          req.method === "GET" &&
          url.pathname ===
            "/api/stream"
        ) {
          res.writeHead(
            200,
            {
              "Content-Type":
                "text/event-stream; charset=utf-8",

              "Cache-Control":
                "no-cache",

              Connection:
                "keep-alive",

              "Access-Control-Allow-Origin":
                "*"
            }
          );

          const push =
            async () => {
              try {
                const [
                  summary,
                  prediction
                ] =
                  await Promise.all([
                    buildSummary({
                      app: "all",
                      category: "all",
                      audience: "all"
                    }),

                    predictions()
                  ]);

                res.write(
                  `data: ${JSON.stringify({
                    summary,
                    prediction,
                    generated_at:
                      new Date().toISOString()
                  })}\n\n`
                );
              } catch (error) {
                res.write(
                  `data: ${JSON.stringify({
                    error:
                      error.message
                  })}\n\n`
                );
              }
            };

          await push();

          const timer =
            setInterval(
              push,
              REFRESH_INTERVAL
            );

          req.on(
            "close",
            () => {
              clearInterval(
                timer
              );
            }
          );

          return;
        }

        /* ---------------- EVIDENCE ---------------- */

        if (
          req.method === "POST" &&
          url.pathname ===
            "/api/evidence"
        ) {
          try {
            const body =
              await readBody(
                req
              );

            const content =
              String(
                body.content ||
                  ""
              ).trim();

            if (
              !content ||
              content.length >
                20000
            ) {
              return send(
                res,
                400,
                {
                  error:
                    "JSON body must include 'content' up to 20,000 characters."
                }
              );
            }

            const canonical =
              JSON.stringify({
                content,

                source:
                  body.source ||
                  "unknown"
              });

            const record = {
              evidence_id:
                `SIH-${crypto
                  .randomUUID()
                  .replaceAll(
                    "-",
                    ""
                  )
                  .slice(
                    0,
                    12
                  )
                  .toUpperCase()}`,

              sha256:
                crypto
                  .createHash(
                    "sha256"
                  )
                  .update(
                    canonical
                  )
                  .digest(
                    "hex"
                  ),

              source:
                String(
                  body.source ||
                    "unknown"
                ),

              created_at:
                new Date().toISOString(),

              integrity_status:
                "verified"
            };

            evidence.set(
              record.evidence_id,
              record
            );

            return send(
              res,
              201,
              record
            );
          } catch {
            return send(
              res,
              400,
              {
                error:
                  "Request body must be valid JSON."
              }
            );
          }
        }

        /* ---------------- GET EVIDENCE ---------------- */

        if (
          req.method === "GET" &&
          url.pathname.startsWith(
            "/api/evidence/"
          )
        ) {
          const id =
            decodeURIComponent(
              url.pathname
                .split("/")
                .pop()
            );

          const record =
            evidence.get(id);

          return record
            ? send(
                res,
                200,
                record
              )
            : send(
                res,
                404,
                {
                  error:
                    "Evidence record not found."
                }
              );
        }

        /* ====================================================
           EXISTING FRONTEND — UNCHANGED
           ==================================================== */

        const requested =
          url.pathname === "/"
            ? "index.html"
            : url.pathname.replace(
                /^\/static\//,
                ""
              );

        const file =
          path.resolve(
            STATIC_DIR,
            requested
          );

        if (
          !file.startsWith(
            STATIC_DIR
          ) ||
          !fs.existsSync(file) ||
          fs.statSync(file)
            .isDirectory()
        ) {
          return send(
            res,
            404,
            "Not found",
            "text/plain"
          );
        }

        const ext =
          path.extname(
            file
          ).toLowerCase();

        let type =
          "text/html";

        if (
          ext === ".js"
        ) {
          type =
            "application/javascript";
        } else if (
          ext === ".css"
        ) {
          type =
            "text/css";
        } else if (
          ext === ".json"
        ) {
          type =
            "application/json";
        } else if (
          ext === ".svg"
        ) {
          type =
            "image/svg+xml";
        }

        return send(
          res,
          200,
          fs.readFileSync(
            file
          ),
          type
        );
      } catch (error) {
        console.error(
          "[SERVER ERROR]",
          error
        );

        return send(
          res,
          500,
          {
            error:
              "Internal server error.",
            message:
              error.message
          }
        );
      }
    }
  );

/* ============================================================
   START LIVE BACKGROUND REFRESH
   ============================================================ */

refreshLiveSnapshot();

const refreshTimer =
  setInterval(
    refreshLiveSnapshot,
    REFRESH_INTERVAL
  );

if (
  refreshTimer.unref
) {
  refreshTimer.unref();
}

/* ============================================================
   START SERVER
   ============================================================ */

server.listen(
  PORT,
  HOST,
  () => {
    console.log(
      "=========================================="
    );

    console.log(
      " Social Sync — Live Intelligence Backend"
    );

    console.log(
      "=========================================="
    );

    console.log(
      `Server: http://${HOST}:${PORT}`
    );

    console.log(
      "Live refresh: every 2 minutes"
    );

    console.log(
      "Sources: Google Trends, Google News, Reddit"
    );

    console.log(
      "Cyber: CISA KEV, NIST NVD, FIRST EPSS"
    );

    console.log(
      "Frontend: existing static folder"
    );

    console.log(
      "=========================================="
    );

    /*
     * Only open browser during local execution.
     * Railway/cloud deployments have PORT set.
     */
    if (
      !process.env.PORT
    ) {
      exec(
        `start "Social Sync" http://localhost:${PORT}`
      );
    }
  }
);