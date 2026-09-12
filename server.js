// ============================================================
// SOCIAL SYNC - LIVE SOCIAL MEDIA TREND + CYBER THREAT BACKEND
// SIH 2026
// ============================================================

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ------------------------------------------------------------
// CONFIGURATION
// ------------------------------------------------------------

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || "0.0.0.0";

// IMPORTANT:
// Your index.html is in the ROOT of the repository.
// static/ contains additional frontend assets.
const ROOT_DIR = __dirname;
const STATIC_DIR = path.join(__dirname, "static");
const INDEX_FILE = path.join(ROOT_DIR, "index.html");

const REFRESH_INTERVAL = 2 * 60 * 1000; // 2 minutes

// ------------------------------------------------------------
// FILTER OPTIONS
// ------------------------------------------------------------

const SUPPORTED_APPS = [
    "all",
    "instagram",
    "youtube",
    "linkedin",
    "facebook",
    "whatsapp",
    "telegram",
    "x",
    "discord"
];

const THREAT_CATEGORIES = [
    "all",
    "phishing",
    "botnets",
    "scams",
    "disinformation",
    "malware",
    "radicalization"
];

const AUDIENCES = [
    "all",
    "students",
    "creators",
    "startups",
    "ecommerce",
    "localbusiness",
    "nonprofits",
    "agencies"
];

// ------------------------------------------------------------
// GLOBAL INTELLIGENCE STATE
// ------------------------------------------------------------

const state = {
    lastUpdated: null,

    trends: [],
    threats: [],
    evidence: [],

    prediction: {
        horizon: "24-48 hours",
        generatedAt: null,
        signals: []
    },

    sourceStatus: {
        googleTrends: "unknown",
        googleNews: "unknown",
        reddit: "unknown",
        cisaKev: "unknown",
        nvd: "unknown",
        epss: "unknown"
    },

    metrics: {
        trendSignals: 0,
        threatSignals: 0,
        phishingSignals: 0,
        scamSignals: 0,
        malwareSignals: 0,
        botSignals: 0,
        disinformationSignals: 0,
        radicalizationSignals: 0,
        criticalVulnerabilities: 0
    }
};

// Rolling historical intelligence for prediction.
const history = [];

// Connected SSE clients.
const clients = new Set();

// ------------------------------------------------------------
// UTILITY FUNCTIONS
// ------------------------------------------------------------

function nowISO() {
    return new Date().toISOString();
}

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

function hashString(value) {
    return crypto
        .createHash("sha256")
        .update(String(value))
        .digest("hex");
}

function safeNumber(value, fallback = 0) {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
}

function normalizeText(value) {
    return String(value || "")
        .replace(/<[^>]*>/g, " ")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/\s+/g, " ")
        .trim();
}

function escapeHtml(value) {
    return String(value || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ------------------------------------------------------------
// HTTP FETCH
// ------------------------------------------------------------

function fetchURL(url, options = {}) {
    return new Promise((resolve, reject) => {
        const request = https.get(
            url,
            {
                headers: {
                    "User-Agent":
                        "Social-Sync-SIH2026/1.0 (+public-threat-intelligence)",
                    Accept: "*/*",
                    ...options.headers
                },
                timeout: options.timeout || 15000
            },
            (response) => {
                let body = "";

                response.setEncoding("utf8");

                response.on("data", chunk => {
                    body += chunk;
                });

                response.on("end", () => {
                    if (
                        response.statusCode >= 300 &&
                        response.statusCode < 400 &&
                        response.headers.location
                    ) {
                        fetchURL(response.headers.location, options)
                            .then(resolve)
                            .catch(reject);
                        return;
                    }

                    if (response.statusCode < 200 || response.statusCode >= 300) {
                        reject(
                            new Error(
                                `HTTP ${response.statusCode} from ${url}`
                            )
                        );
                        return;
                    }

                    resolve(body);
                });
            }
        );

        request.on("timeout", () => {
            request.destroy();
            reject(new Error(`Timeout: ${url}`));
        });

        request.on("error", reject);
    });
}

async function fetchJSON(url, options = {}) {
    const body = await fetchURL(url, options);

    try {
        return JSON.parse(body);
    } catch {
        throw new Error(`Invalid JSON response from ${url}`);
    }
}

// ------------------------------------------------------------
// RSS PARSER
// ------------------------------------------------------------

function parseRSS(xml, sourceName) {
    const items = [];

    const blocks = xml.match(/<item[\s\S]*?<\/item>/gi) || [];

    for (const block of blocks) {
        const titleMatch =
            block.match(/<title[^>]*>([\s\S]*?)<\/title>/i);

        const linkMatch =
            block.match(/<link[^>]*>([\s\S]*?)<\/link>/i);

        const pubDateMatch =
            block.match(/<pubDate[^>]*>([\s\S]*?)<\/pubDate>/i);

        const descriptionMatch =
            block.match(
                /<description[^>]*>([\s\S]*?)<\/description>/i
            );

        const title = normalizeText(
            titleMatch ? titleMatch[1] : ""
        );

        const link = normalizeText(
            linkMatch ? linkMatch[1] : ""
        );

        const published = normalizeText(
            pubDateMatch ? pubDateMatch[1] : ""
        );

        const description = normalizeText(
            descriptionMatch ? descriptionMatch[1] : ""
        );

        if (!title) continue;

        items.push({
            title,
            link,
            published,
            description,
            source: sourceName
        });
    }

    return items;
}

// ------------------------------------------------------------
// THREAT CLASSIFICATION
// ------------------------------------------------------------

function classifyThreat(text) {
    const value = String(text || "").toLowerCase();

    const rules = [
        {
            category: "phishing",
            name: "Credential-Phishing Attempt",
            code: "THREAT-PHI-001",
            keywords: [
                "phishing",
                "credential theft",
                "fake login",
                "login page",
                "password",
                "account takeover",
                "steal credentials",
                "credential harvesting"
            ]
        },

        {
            category: "scams",
            name: "Social Engineering / Scam Signal",
            code: "THREAT-SCM-001",
            keywords: [
                "scam",
                "fraud",
                "giveaway scam",
                "investment scam",
                "crypto scam",
                "impersonation",
                "fake offer",
                "social engineering"
            ]
        },

        {
            category: "malware",
            name: "Malware Distribution Signal",
            code: "THREAT-MAL-001",
            keywords: [
                "malware",
                "trojan",
                "ransomware",
                "spyware",
                "infostealer",
                "payload",
                "malicious file",
                "malicious software"
            ]
        },

        {
            category: "botnets",
            name: "Automated / Coordinated Activity",
            code: "THREAT-BOT-001",
            keywords: [
                "botnet",
                "bots",
                "automated accounts",
                "coordinated accounts",
                "bot activity",
                "automated activity",
                "fake accounts"
            ]
        },

        {
            category: "disinformation",
            name: "Potential Coordinated Disinformation",
            code: "THREAT-DIS-001",
            keywords: [
                "disinformation",
                "misinformation",
                "false information",
                "propaganda",
                "coordinated campaign",
                "influence operation",
                "information operation"
            ]
        },

        {
            category: "radicalization",
            name: "Potential Radicalization Signal",
            code: "THREAT-RAD-001",
            keywords: [
                "radicalization",
                "extremist recruitment",
                "extremist content",
                "violent extremism",
                "terror recruitment",
                "extremist propaganda"
            ]
        }
    ];

    for (const rule of rules) {
        const matches = rule.keywords.filter(keyword =>
            value.includes(keyword)
        );

        if (matches.length > 0) {
            return {
                category: rule.category,
                name: rule.name,
                code: rule.code,
                matchedKeywords: matches
            };
        }
    }

    return null;
}

// ------------------------------------------------------------
// RISK SCORING
// ------------------------------------------------------------

function calculateRisk(text, source = "") {
    const value = String(text || "").toLowerCase();

    let score = 25;

    const highRiskTerms = [
        "credential",
        "ransomware",
        "malware",
        "exploit",
        "phishing",
        "account takeover",
        "botnet",
        "critical",
        "zero-day",
        "trojan",
        "infostealer"
    ];

    const mediumRiskTerms = [
        "scam",
        "fraud",
        "impersonation",
        "fake",
        "spam",
        "disinformation",
        "malicious",
        "attack",
        "campaign"
    ];

    for (const term of highRiskTerms) {
        if (value.includes(term)) score += 9;
    }

    for (const term of mediumRiskTerms) {
        if (value.includes(term)) score += 4;
    }

    if (source === "CISA KEV") score += 20;
    if (source === "NIST NVD") score += 12;
    if (source === "FIRST EPSS") score += 10;

    return clamp(Math.round(score), 0, 100);
}

function riskLabel(score) {
    if (score >= 80) return "Critical";
    if (score >= 60) return "High";
    if (score >= 40) return "Medium";
    return "Low";
}

// ------------------------------------------------------------
// GOOGLE TRENDS
// ------------------------------------------------------------

async function fetchGoogleTrends() {
    const url =
        "https://trends.google.com/trending/rss?geo=IN";

    try {
        const xml = await fetchURL(url);

        const items = parseRSS(xml, "Google Trends");

        state.sourceStatus.googleTrends = "live";

        return items.map((item, index) => ({
            id: `trend-${index}-${hashString(item.title).slice(0, 10)}`,
            topic: item.title,
            title: item.title,
            source: "Google Trends",
            link: item.link,
            published: item.published,
            category: classifyThreat(item.title)?.category || "general",
            riskScore: calculateRisk(item.title, "Google Trends"),
            riskLevel: riskLabel(
                calculateRisk(item.title, "Google Trends")
            )
        }));
    } catch (error) {
        console.error(
            "[Google Trends] unavailable:",
            error.message
        );

        state.sourceStatus.googleTrends = "unavailable";

        return [];
    }
}

// ------------------------------------------------------------
// GOOGLE NEWS THREAT INTELLIGENCE
// ------------------------------------------------------------

async function fetchGoogleNews() {
    const queries = [
        "social media phishing",
        "social media scam",
        "social media malware",
        "social media botnet",
        "social media disinformation",
        "cyber attack social media"
    ];

    const results = [];

    for (const query of queries) {
        try {
            const url =
                "https://news.google.com/rss/search?q=" +
                encodeURIComponent(query) +
                "&hl=en-IN&gl=IN&ceid=IN:en";

            const xml = await fetchURL(url);

            const items = parseRSS(
                xml,
                "Google News"
            );

            results.push(...items.slice(0, 10));
        } catch (error) {
            console.error(
                `[Google News] ${query}:`,
                error.message
            );
        }
    }

    if (results.length > 0) {
        state.sourceStatus.googleNews = "live";
    } else {
        state.sourceStatus.googleNews = "unavailable";
    }

    return results.map((item, index) => {
        const classification =
            classifyThreat(
                `${item.title} ${item.description}`
            );

        const score = calculateRisk(
            `${item.title} ${item.description}`,
            "Google News"
        );

        return {
            id: `news-${index}-${hashString(item.title).slice(0, 10)}`,
            title: item.title,
            description: item.description,
            source: "Google News",
            link: item.link,
            published: item.published,

            category:
                classification?.category || "general",

            threatType:
                classification?.name || "Emerging Cyber Signal",

            threatCode:
                classification?.code || "SIGNAL-001",

            matchedKeywords:
                classification?.matchedKeywords || [],

            riskScore: score,
            riskLevel: riskLabel(score)
        };
    });
}

// ------------------------------------------------------------
// REDDIT PUBLIC INTELLIGENCE
// ------------------------------------------------------------

async function fetchRedditSignals() {
    const queries = [
        "phishing",
        "scam",
        "malware",
        "botnet",
        "disinformation"
    ];

    const results = [];

    for (const query of queries) {
        try {
            const url =
                "https://www.reddit.com/search.json?q=" +
                encodeURIComponent(query) +
                "&sort=new&limit=10";

            const data = await fetchJSON(url);

            const children =
                data?.data?.children || [];

            for (const child of children) {
                const post = child?.data;

                if (!post) continue;

                results.push({
                    title: post.title || "",
                    description:
                        post.selftext || "",
                    link:
                        post.permalink
                            ? `https://www.reddit.com${post.permalink}`
                            : "",
                    published:
                        post.created_utc
                            ? new Date(
                                post.created_utc * 1000
                            ).toISOString()
                            : "",
                    source: "Reddit"
                });
            }
        } catch (error) {
            console.error(
                `[Reddit] ${query}:`,
                error.message
            );
        }
    }

    if (results.length > 0) {
        state.sourceStatus.reddit = "live";
    } else {
        state.sourceStatus.reddit = "unavailable";
    }

    return results.map((item, index) => {
        const text =
            `${item.title} ${item.description}`;

        const classification =
            classifyThreat(text);

        const score =
            calculateRisk(text, "Reddit");

        return {
            id:
                `reddit-${index}-${hashString(item.title).slice(0, 10)}`,

            title: item.title,
            description: item.description,

            source: "Reddit",
            link: item.link,
            published: item.published,

            category:
                classification?.category || "general",

            threatType:
                classification?.name ||
                "Community Cyber Signal",

            threatCode:
                classification?.code ||
                "COMMUNITY-001",

            matchedKeywords:
                classification?.matchedKeywords || [],

            riskScore: score,
            riskLevel: riskLabel(score)
        };
    });
}

// ------------------------------------------------------------
// CISA KNOWN EXPLOITED VULNERABILITIES
// ------------------------------------------------------------

async function fetchCISAKEV() {
    const url =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    try {
        const data = await fetchJSON(url);

        const vulnerabilities =
            data?.vulnerabilities || [];

        state.sourceStatus.cisaKev = "live";

        return vulnerabilities
            .slice(-40)
            .reverse()
            .map((vuln, index) => ({
                id:
                    `cisa-${index}-${hashString(vuln.cveID).slice(0, 10)}`,

                title:
                    `${vuln.cveID}: ${vuln.vulnerabilityName}`,

                description:
                    `${vuln.vendorProject || ""} ${vuln.product || ""}`.trim(),

                source: "CISA KEV",

                cve:
                    vuln.cveID,

                category: "malware",

                threatType:
                    "Known Exploited Vulnerability",

                threatCode:
                    "CISA-KEV",

                published:
                    vuln.dateAdded || "",

                dueDate:
                    vuln.dueDate || "",

                riskScore: 85,

                riskLevel: "Critical"
            }));
    } catch (error) {
        console.error(
            "[CISA KEV] unavailable:",
            error.message
        );

        state.sourceStatus.cisaKev = "unavailable";

        return [];
    }
}

// ------------------------------------------------------------
// NIST NVD
// ------------------------------------------------------------

async function fetchNVD() {
    const url =
        "https://services.nvd.nist.gov/rest/json/cves/2.0" +
        "?pubStartDate=" +
        encodeURIComponent(
            new Date(
                Date.now() - 7 * 24 * 60 * 60 * 1000
            ).toISOString()
        ) +
        "&resultsPerPage=30";

    try {
        const data = await fetchJSON(url);

        const vulnerabilities =
            data?.vulnerabilities || [];

        state.sourceStatus.nvd = "live";

        return vulnerabilities.map((entry, index) => {
            const cve =
                entry?.cve || {};

            const id =
                cve.id || `NVD-${index}`;

            const description =
                cve.descriptions?.find(
                    d => d.lang === "en"
                )?.value || "";

            const score =
                cve.metrics?.cvssMetricV31?.[0]
                    ?.cvssData?.baseScore ||
                cve.metrics?.cvssMetricV30?.[0]
                    ?.cvssData?.baseScore ||
                cve.metrics?.cvssMetricV2?.[0]
                    ?.cvssData?.baseScore ||
                0;

            return {
                id:
                    `nvd-${index}-${hashString(id).slice(0, 10)}`,

                title:
                    `${id} - Vulnerability Intelligence`,

                description,

                source: "NIST NVD",

                cve: id,

                category: "malware",

                threatType:
                    "New Vulnerability Signal",

                threatCode:
                    "NVD-CVE",

                published:
                    cve.published || "",

                cvss:
                    safeNumber(score),

                riskScore:
                    clamp(
                        Math.round(
                            safeNumber(score) * 10
                        ),
                        0,
                        100
                    ),

                riskLevel:
                    riskLabel(
                        clamp(
                            Math.round(
                                safeNumber(score) * 10
                            ),
                            0,
                            100
                        )
                    )
            };
        });
    } catch (error) {
        console.error(
            "[NIST NVD] unavailable:",
            error.message
        );

        state.sourceStatus.nvd = "unavailable";

        return [];
    }
}

// ------------------------------------------------------------
// FIRST EPSS
// ------------------------------------------------------------

async function fetchEPSS() {
    const url =
        "https://api.first.org/data/v1/epss?limit=30";

    try {
        const data = await fetchJSON(url);

        const records =
            data?.data || [];

        state.sourceStatus.epss = "live";

        return records.map((record, index) => {
            const epss =
                safeNumber(record.epss);

            const percentile =
                safeNumber(record.percentile);

            const score =
                clamp(
                    Math.round(epss * 100),
                    0,
                    100
                );

            return {
                id:
                    `epss-${index}-${hashString(record.cve).slice(0, 10)}`,

                title:
                    `${record.cve} - Exploitation Probability`,

                description:
                    `EPSS probability ${(
                        epss * 100
                    ).toFixed(2)}%`,

                source: "FIRST EPSS",

                cve:
                    record.cve,

                category: "malware",

                threatType:
                    "Exploit Probability Signal",

                threatCode:
                    "EPSS",

                epss:
                    epss,

                percentile:
                    percentile,

                riskScore:
                    score,

                riskLevel:
                    riskLabel(score)
            };
        });
    } catch (error) {
        console.error(
            "[FIRST EPSS] unavailable:",
            error.message
        );

        state.sourceStatus.epss = "unavailable";

        return [];
    }
}

// ------------------------------------------------------------
// THREAT AGGREGATION
// ------------------------------------------------------------

function deduplicate(items) {
    const seen = new Set();
    const result = [];

    for (const item of items) {
        const key =
            item.cve ||
            item.title ||
            item.id;

        const normalized =
            String(key)
                .toLowerCase()
                .trim();

        if (seen.has(normalized)) continue;

        seen.add(normalized);
        result.push(item);
    }

    return result;
}

// ------------------------------------------------------------
// PREDICTION ENGINE
// ------------------------------------------------------------

function buildPrediction() {
    const current = state.metrics;

    const previous =
        history.length >= 1
            ? history[history.length - 1]
            : null;

    const signals = [];

    const categories = [
        {
            category: "phishing",
            name: "Credential-Phishing Campaign",
            code: "PRED-PHI-001",
            current:
                current.phishingSignals
        },

        {
            category: "scams",
            name: "Social Engineering / Scam Surge",
            code: "PRED-SCM-001",
            current:
                current.scamSignals
        },

        {
            category: "malware",
            name: "Malware Distribution Surge",
            code: "PRED-MAL-001",
            current:
                current.malwareSignals
        },

        {
            category: "botnets",
            name: "Automated Coordination Surge",
            code: "PRED-BOT-001",
            current:
                current.botSignals
        },

        {
            category: "disinformation",
            name: "Coordinated Disinformation Signal",
            code: "PRED-DIS-001",
            current:
                current.disinformationSignals
        },

        {
            category: "radicalization",
            name: "Potential Radicalization Surge",
            code: "PRED-RAD-001",
            current:
                current.radicalizationSignals
        }
    ];

    for (const item of categories) {
        const old =
            previous?.[item.category] || 0;

        let growth = 0;

        if (old > 0) {
            growth =
                ((item.current - old) / old) * 100;
        } else if (item.current > 0) {
            // Avoid claiming unrealistic 1000%+ growth
            // when historical data does not yet exist.
            growth = 25;
        }

        growth = clamp(
            Math.round(growth),
            -100,
            200
        );

        let confidence = 35;

        if (history.length >= 2) {
            confidence += 15;
        }

        if (history.length >= 5) {
            confidence += 20;
        }

        if (item.current > 3) {
            confidence += 10;
        }

        confidence =
            clamp(confidence, 0, 90);

        let predictionScore =
            item.current * 10 +
            Math.max(growth, 0) * 0.35;

        predictionScore =
            clamp(
                Math.round(predictionScore),
                0,
                100
            );

        let status = "Stable";

        if (predictionScore >= 70) {
            status = "High Risk";
        } else if (predictionScore >= 45) {
            status = "Watch";
        }

        signals.push({
            category: item.category,

            name: item.name,

            code: item.code,

            currentSignals:
                item.current,

            previousSignals:
                old,

            growthPercent:
                growth,

            predictionScore,

            confidence,

            status,

            horizon:
                "24-48 hours",

            explanation:
                item.current > 0
                    ? `Detected ${item.current} active ${item.category} signal(s). Trend momentum is ${growth >= 0 ? "increasing" : "decreasing"} compared with the previous refresh.`
                    : `No active ${item.category} signals detected in the latest refresh.`
        });
    }

    signals.sort(
        (a, b) =>
            b.predictionScore -
            a.predictionScore
    );

    return {
        horizon: "24-48 hours",

        generatedAt:
            nowISO(),

        methodology:
            "Explainable early-warning scoring based on observed public threat signals, recent signal volume and short-term momentum. Predictions are indicators, not certainty.",

        signals
    };
}

// ------------------------------------------------------------
// METRICS
// ------------------------------------------------------------

function calculateMetrics() {
    const threats =
        state.threats || [];

    const count =
        category =>
            threats.filter(
                t =>
                    t.category === category
            ).length;

    state.metrics = {
        trendSignals:
            state.trends.length,

        threatSignals:
            threats.length,

        phishingSignals:
            count("phishing"),

        scamSignals:
            count("scams"),

        malwareSignals:
            count("malware"),

        botSignals:
            count("botnets"),

        disinformationSignals:
            count("disinformation"),

        radicalizationSignals:
            count("radicalization"),

        criticalVulnerabilities:
            threats.filter(
                t =>
                    t.riskLevel ===
                    "Critical"
            ).length
    };
}

// ------------------------------------------------------------
// EVIDENCE GENERATION
// ------------------------------------------------------------

function buildEvidence() {
    const records = [
        ...state.trends,
        ...state.threats
    ];

    state.evidence =
        records.slice(0, 100).map(item => ({
            id:
                item.id ||
                hashString(
                    item.title
                ),

            source:
                item.source,

            title:
                item.title,

            link:
                item.link || "",

            timestamp:
                item.published ||
                state.lastUpdated,

            hash:
                hashString(
                    JSON.stringify({
                        title:
                            item.title,
                        source:
                            item.source,
                        published:
                            item.published
                    })
                ),

            integrity:
                "SHA-256"
        }));
}

// ------------------------------------------------------------
// REFRESH INTELLIGENCE
// ------------------------------------------------------------

async function refreshIntelligence() {
    console.log(
        `[LIVE] Refresh started: ${nowISO()}`
    );

    const [
        trends,
        news,
        reddit,
        cisa,
        nvd,
        epss
    ] = await Promise.all([
        fetchGoogleTrends(),
        fetchGoogleNews(),
        fetchRedditSignals(),
        fetchCISAKEV(),
        fetchNVD(),
        fetchEPSS()
    ]);

    state.trends =
        deduplicate(trends);

    state.threats =
        deduplicate([
            ...news,
            ...reddit,
            ...cisa,
            ...nvd,
            ...epss
        ])
            .sort(
                (a, b) =>
                    safeNumber(b.riskScore) -
                    safeNumber(a.riskScore)
            )
            .slice(0, 250);

    state.lastUpdated =
        nowISO();

    calculateMetrics();

    // Store current snapshot for prediction.
    history.push({
        timestamp:
            state.lastUpdated,

        phishing:
            state.metrics.phishingSignals,

        scams:
            state.metrics.scamSignals,

        malware:
            state.metrics.malwareSignals,

        botnets:
            state.metrics.botSignals,

        disinformation:
            state.metrics.disinformationSignals,

        radicalization:
            state.metrics.radicalizationSignals
    });

    // Keep last 30 refreshes.
    while (history.length > 30) {
        history.shift();
    }

    state.prediction =
        buildPrediction();

    buildEvidence();

    console.log(
        `[LIVE] Refresh completed: ${state.lastUpdated}`
    );

    console.log(
        `[LIVE] Trends: ${state.trends.length}`
    );

    console.log(
        `[LIVE] Threat signals: ${state.threats.length}`
    );

    console.log(
        `[LIVE] Prediction signals: ${state.prediction.signals.length}`
    );

    console.log(
        `[LIVE] Sources:`,
        state.sourceStatus
    );

    broadcast();
}

// ------------------------------------------------------------
// FILTERING
// ------------------------------------------------------------

function filterItems(items, params) {
    let result = [...items];

    const app =
        String(
            params.get("app") ||
            "all"
        ).toLowerCase();

    const category =
        String(
            params.get("category") ||
            "all"
        ).toLowerCase();

    const audience =
        String(
            params.get("audience") ||
            "all"
        ).toLowerCase();

    if (
        app !== "all" &&
        SUPPORTED_APPS.includes(app)
    ) {
        result =
            result.filter(item =>
                String(
                    `${item.title} ${item.description}`
                )
                    .toLowerCase()
                    .includes(app)
            );
    }

    if (
        category !== "all" &&
        THREAT_CATEGORIES.includes(category)
    ) {
        result =
            result.filter(
                item =>
                    item.category ===
                    category
            );
    }

    // Audience filtering is intentionally
    // keyword-based because public feeds do not
    // provide platform audience metadata.
    if (
        audience !== "all" &&
        AUDIENCES.includes(audience)
    ) {
        result =
            result.filter(item =>
                String(
                    `${item.title} ${item.description}`
                )
                    .toLowerCase()
                    .includes(
                        audience
                            .replace(
                                "localbusiness",
                                "business"
                            )
                    )
            );
    }

    return result;
}

// ------------------------------------------------------------
// JSON RESPONSE
// ------------------------------------------------------------

function sendJSON(res, data, statusCode = 200) {
    const body =
        JSON.stringify(
            data
        );

    res.writeHead(
        statusCode,
        {
            "Content-Type":
                "application/json; charset=utf-8",

            "Cache-Control":
                "no-store",

            "Access-Control-Allow-Origin":
                "*"
        }
    );

    res.end(body);
}

// ------------------------------------------------------------
// STATIC FILE SERVER
// ------------------------------------------------------------

const MIME_TYPES = {
    ".html":
        "text/html; charset=utf-8",

    ".js":
        "application/javascript; charset=utf-8",

    ".css":
        "text/css; charset=utf-8",

    ".json":
        "application/json; charset=utf-8",

    ".png":
        "image/png",

    ".jpg":
        "image/jpeg",

    ".jpeg":
        "image/jpeg",

    ".svg":
        "image/svg+xml",

    ".ico":
        "image/x-icon",

    ".webp":
        "image/webp",

    ".woff":
        "font/woff",

    ".woff2":
        "font/woff2",

    ".ttf":
        "font/ttf"
};

function serveFile(res, filePath) {
    fs.stat(
        filePath,
        (error, stats) => {
            if (error || !stats.isFile()) {
                sendNotFound(res);
                return;
            }

            const ext =
                path.extname(
                    filePath
                ).toLowerCase();

            const contentType =
                MIME_TYPES[ext] ||
                "application/octet-stream";

            res.writeHead(
                200,
                {
                    "Content-Type":
                        contentType,

                    "Cache-Control":
                        "no-cache"
                }
            );

            fs.createReadStream(
                filePath
            ).pipe(res);
        }
    );
}

function sendNotFound(res) {
    res.writeHead(
        404,
        {
            "Content-Type":
                "text/plain; charset=utf-8"
        }
    );

    res.end("Not Found");
}

// ------------------------------------------------------------
// STATIC ROUTING
// ------------------------------------------------------------

function handleStaticRequest(
    req,
    res,
    pathname
) {
    // ROOT PAGE
    // This is the important fix for your current
    // Railway "Not Found" problem.
    if (
        pathname === "/" ||
        pathname === ""
    ) {
        serveFile(
            res,
            INDEX_FILE
        );

        return true;
    }

    // Direct access to index.html
    if (
        pathname === "/index.html"
    ) {
        serveFile(
            res,
            INDEX_FILE
        );

        return true;
    }

    // Static assets:
    // /static/app.js
    // /static/style.css
    // etc.
    if (
        pathname.startsWith(
            "/static/"
        )
    ) {
        const relativePath =
            pathname.replace(
                /^\/static\//,
                ""
            );

        const safePath =
            path.normalize(
                relativePath
            );

        // Prevent path traversal.
        if (
            safePath.startsWith(
                ".."
            ) ||
            path.isAbsolute(
                safePath
            )
        ) {
            sendNotFound(res);
            return true;
        }

        const filePath =
            path.join(
                STATIC_DIR,
                safePath
            );

        serveFile(
            res,
            filePath
        );

        return true;
    }

    // Also support frontend assets that may
    // currently be referenced directly.
    const directRelative =
        pathname.replace(
            /^\/+/,
            ""
        );

    if (
        directRelative &&
        !directRelative.includes("..")
    ) {
        const directFile =
            path.join(
                ROOT_DIR,
                directRelative
            );

        if (
            fs.existsSync(
                directFile
            )
        ) {
            serveFile(
                res,
                directFile
            );

            return true;
        }
    }

    return false;
}

// ------------------------------------------------------------
// SERVER
// ------------------------------------------------------------

const server =
    http.createServer(
        async (req, res) => {
            try {
                const parsed =
                    new URL(
                        req.url,
                        `http://${req.headers.host || "localhost"}`
                    );

                const pathname =
                    parsed.pathname;

                const params =
                    parsed.searchParams;

                // ------------------------------------------------
                // CORS
                // ------------------------------------------------

                res.setHeader(
                    "Access-Control-Allow-Origin",
                    "*"
                );

                res.setHeader(
                    "Access-Control-Allow-Headers",
                    "Content-Type"
                );

                if (
                    req.method === "OPTIONS"
                ) {
                    res.writeHead(
                        204
                    );

                    res.end();

                    return;
                }

                // ------------------------------------------------
                // HEALTH
                // ------------------------------------------------

                if (
                    pathname ===
                    "/api/health"
                ) {
                    sendJSON(
                        res,
                        {
                            status: "ok",

                            service:
                                "social-sync-api",

                            mode:
                                "live-public-intelligence",

                            timestamp:
                                nowISO(),

                            lastUpdated:
                                state.lastUpdated,

                            sources:
                                state.sourceStatus
                        }
                    );

                    return;
                }

                // ------------------------------------------------
                // THREAT SUMMARY
                // ------------------------------------------------

                if (
                    pathname ===
                    "/api/threats/summary"
                ) {
                    sendJSON(
                        res,
                        {
                            status: "ok",

                            generatedAt:
                                state.lastUpdated,

                            metrics:
                                state.metrics,

                            prediction:
                                state.prediction,

                            sources:
                                state.sourceStatus
                        }
                    );

                    return;
                }

                // ------------------------------------------------
                // THREAT FEED
                // ------------------------------------------------

                if (
                    pathname ===
                    "/api/threats/feed"
                ) {
                    const limit =
                        clamp(
                            parseInt(
                                params.get(
                                    "limit"
                                ) || "50",
                                10
                            ),
                            1,
                            250
                        );

                    const filtered =
                        filterItems(
                            state.threats,
                            params
                        );

                    sendJSON(
                        res,
                        {
                            status: "ok",

                            generatedAt:
                                state.lastUpdated,

                            total:
                                filtered.length,

                            filters: {
                                app:
                                    params.get(
                                        "app"
                                    ) || "all",

                                category:
                                    params.get(
                                        "category"
                                    ) || "all",

                                audience:
                                    params.get(
                                        "audience"
                                    ) || "all"
                            },

                            threats:
                                filtered.slice(
                                    0,
                                    limit
                                )
                        }
                    );

                    return;
                }

                // ------------------------------------------------
                // TRENDS
                // ------------------------------------------------

                if (
                    pathname ===
                    "/api/trends"
                ) {
                    const limit =
                        clamp(
                            parseInt(
                                params.get(
                                    "limit"
                                ) || "50",
                                10
                            ),
                            1,
                            100
                        );

                    const filtered =
                        filterItems(
                            state.trends,
                            params
                        );

                    sendJSON(
                        res,
                        {
                            status: "ok",

                            generatedAt:
                                state.lastUpdated,

                            total:
                                filtered.length,

                            trends:
                                filtered.slice(
                                    0,
                                    limit
                                )
                        }
                    );

                    return;
                }

                // ------------------------------------------------
                // EVIDENCE
                // ------------------------------------------------

                if (
                    pathname ===
                    "/api/evidence"
                ) {
                    sendJSON(
                        res,
                        {
                            status: "ok",

                            generatedAt:
                                state.lastUpdated,

                            integrity:
                                "SHA-256",

                            evidence:
                                state.evidence
                        }
                    );

                    return;
                }

                // ------------------------------------------------
                // PREDICTION
                // ------------------------------------------------

                if (
                    pathname ===
                    "/api/prediction"
                ) {
                    sendJSON(
                        res,
                        {
                            status: "ok",

                            prediction:
                                state.prediction
                        }
                    );

                    return;
                }

                // ------------------------------------------------
                // RAW SOURCE STATUS
                // ------------------------------------------------

                if (
                    pathname ===
                    "/api/sources"
                ) {
                    sendJSON(
                        res,
                        {
                            status: "ok",

                            sources:
                                state.sourceStatus,

                            updatedAt:
                                state.lastUpdated
                        }
                    );

                    return;
                }

                // ------------------------------------------------
                // SERVER-SENT EVENTS
                // ------------------------------------------------

                if (
                    pathname ===
                    "/api/stream"
                ) {
                    res.writeHead(
                        200,
                        {
                            "Content-Type":
                                "text/event-stream",

                            "Cache-Control":
                                "no-cache",

                            Connection:
                                "keep-alive",

                            "Access-Control-Allow-Origin":
                                "*"
                        }
                    );

                    const client = {
                        res
                    };

                    clients.add(
                        client
                    );

                    res.write(
                        `data: ${JSON.stringify({
                            type: "connected",
                            timestamp: nowISO()
                        })}\n\n`
                    );

                    req.on(
                        "close",
                        () => {
                            clients.delete(
                                client
                            );
                        }
                    );

                    return;
                }

                // ------------------------------------------------
                // STATIC FRONTEND
                // ------------------------------------------------

                if (
                    handleStaticRequest(
                        req,
                        res,
                        pathname
                    )
                ) {
                    return;
                }

                // ------------------------------------------------
                // 404
                // ------------------------------------------------

                sendNotFound(res);
            } catch (error) {
                console.error(
                    "[SERVER ERROR]",
                    error
                );

                sendJSON(
                    res,
                    {
                        status: "error",
                        message:
                            "Internal server error"
                    },
                    500
                );
            }
        }
    );

// ------------------------------------------------------------
// SSE BROADCAST
// ------------------------------------------------------------

function broadcast() {
    const payload =
        JSON.stringify({
            type:
                "intelligence-update",

            timestamp:
                state.lastUpdated,

            metrics:
                state.metrics,

            prediction:
                state.prediction,

            sourceStatus:
                state.sourceStatus
        });

    for (const client of clients) {
        try {
            client.res.write(
                `data: ${payload}\n\n`
            );
        } catch {
            clients.delete(
                client
            );
        }
    }
}

// ------------------------------------------------------------
// PERIODIC REFRESH
// ------------------------------------------------------------

setInterval(
    () => {
        refreshIntelligence()
            .catch(error => {
                console.error(
                    "[REFRESH ERROR]",
                    error.message
                );
            });
    },
    REFRESH_INTERVAL
);

// ------------------------------------------------------------
// START SERVER
// ------------------------------------------------------------

server.listen(
    PORT,
    HOST,
    () => {
        console.log("");
        console.log(
            "=============================================="
        );
        console.log(
            "      SOCIAL SYNC - LIVE INTELLIGENCE"
        );
        console.log(
            "=============================================="
        );

        console.log(
            `[SERVER] http://${HOST}:${PORT}`
        );

        console.log(
            `[FRONTEND] ${INDEX_FILE}`
        );

        console.log(
            `[STATIC] ${STATIC_DIR}`
        );

        console.log(
            "[LIVE] Refresh: every 2 minutes"
        );

        console.log(
            "[LIVE] Sources: Google Trends, Google News, Reddit"
        );

        console.log(
            "[CYBER] CISA KEV, NIST NVD, FIRST EPSS"
        );

        console.log(
            "[PREDICTION] 24-48 hour explainable early warning"
        );

        console.log(
            "[SECURITY] SHA-256 evidence integrity"
        );

        console.log(
            "=============================================="
        );

        // Initial refresh.
        refreshIntelligence()
            .catch(error => {
                console.error(
                    "[INITIAL REFRESH ERROR]",
                    error.message
                );
            });
    }
);

// ------------------------------------------------------------
// GRACEFUL SHUTDOWN
// ------------------------------------------------------------

function shutdown(signal) {
    console.log(
        `[SERVER] ${signal} received. Shutting down...`
    );

    for (const client of clients) {
        try {
            client.res.end();
        } catch {}
    }

    clients.clear();

    server.close(
        () => {
            process.exit(0);
        }
    );
}

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);