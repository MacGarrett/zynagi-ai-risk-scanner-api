const express     = require("express");
const cors        = require("cors");
const PDFDocument = require("pdfkit");
const cron        = require("node-cron");
const { randomUUID } = require("crypto");

const app     = express();
const VERSION = "2.7";

// Startup diagnostics — visible in Railway deployment logs
console.log("[startup] VERSION:", VERSION);
console.log("[startup] SERPAPI_KEY present:", !!process.env.SERPAPI_KEY, "| length:", (process.env.SERPAPI_KEY || "").length);
console.log("[startup] GOOGLE_PLACES_API_KEY present:", !!process.env.GOOGLE_PLACES_API_KEY);
console.log("[startup] DATABASE_URL present:", !!process.env.DATABASE_URL);
console.log("[startup] ADMIN_SCAN_HISTORY_KEY configured:", !!process.env.ADMIN_SCAN_HISTORY_KEY);
console.log("[startup] SCANNER_ACCESS_PASSWORD configured:", !!process.env.SCANNER_ACCESS_PASSWORD);

// ─────────────────────────────────────────────
// CORS
// Allow: zynagi.com, base44.com subdomains, railway.app previews, localhost
// Set CORS_ALLOW_ALL=true in Railway env to open fully during development.
// ─────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  "https://zynagi.com",
  "https://www.zynagi.com",
  "https://app.base44.com",
];

app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // curl / Postman / server-to-server
      const ok =
        !origin ||
        ALLOWED_ORIGINS.includes(origin) ||
        /\.base44\.com$/.test(origin) ||
        /\.railway\.app$/.test(origin) ||
        /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin) ||
        process.env.CORS_ALLOW_ALL === "true";
      cb(null, ok);
    },
    methods:        ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],
    credentials:    true,
  })
);

app.use(express.json({ limit: "1mb" }));

// ─────────────────────────────────────────────
// IN-MEMORY STORES
// ─────────────────────────────────────────────
const monitoredUrls = new Map();
const scanCache     = new Map();
const CACHE_TTL_MS  = 12 * 60 * 60 * 1000; // 12 h

const rateLimitMap   = new Map();
const RATE_LIMIT_MAX = 50;             // 50/hr per IP (raised for dev/testing; was 5)
const RATE_LIMIT_MS  = 60 * 60 * 1000; // 1 h

// Access gate: lead capture + password attempt rate limits
const accessRequests   = [];         // in-memory lead store (max 200)
const ACCESS_REQ_MAX   = 200;
const accessReqRateMap = new Map();  // 5 requests/hr/IP
const accessPwdRateMap = new Map();  // 10 password attempts/hr/IP

let pagespeedFallbackMode = false;

// ─────────────────────────────────────────────
// SCAN HISTORY STORAGE
// Uses Postgres when DATABASE_URL is set; falls back to bounded in-memory Map.
// ─────────────────────────────────────────────
let pgPool = null;
const MEM_HISTORY_MAX  = 500;
const memHistory       = new Map();   // scanId → { meta, fullResult }
const memHistoryKeys   = [];          // insertion order, oldest first

if (process.env.DATABASE_URL) {
  const { Pool } = require("pg");
  pgPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes("localhost")
      ? false
      : { rejectUnauthorized: false },
  });
  pgPool.query(`
    CREATE TABLE IF NOT EXISTS scan_history (
      scan_id            TEXT PRIMARY KEY,
      timestamp          TIMESTAMPTZ DEFAULT NOW(),
      business_name      TEXT,
      address            TEXT,
      place_id           TEXT,
      maps_url           TEXT,
      source             TEXT,
      max_reviews        INT,
      review_count       INT,
      overall_risk_score INT,
      overall_risk_level TEXT,
      risk_summary       JSONB,
      full_result        JSONB
    )
  `)
  .then(() => console.log("[db] scan_history table ready"))
  .catch(err => console.error("[db] table creation failed:", err.message));
}

// Admin key guard — protects /scan-history endpoints
function requireAdminKey(req, res, next) {
  const required = process.env.ADMIN_SCAN_HISTORY_KEY;
  if (!required) return next(); // no key configured → open (dev mode)
  const provided = req.headers["x-admin-key"] || req.query.key;
  if (provided !== required) {
    return res.status(403).json({ success: false, error: "Unauthorized. Supply x-admin-key header." });
  }
  next();
}

// Save a completed scan (PHI-safe: never logs review text)
async function saveScanHistory(scanId, data) {
  const meta = {
    scanId,
    timestamp:         data.timestamp || new Date().toISOString(),
    businessName:      data.businessName,
    address:           data.address,
    placeId:           data._placeId   || null,
    mapsUrl:           data._mapsUrl   || null,
    source:            data.source,
    maxReviews:        data.maxReviews,
    reviewCount:       data.reviewCount,
    overallRiskScore:  data.overallRiskScore,
    overallRiskLevel:  data.overallRiskLevel,
    riskSummary:       data.riskSummary,
  };

  if (pgPool) {
    try {
      await pgPool.query(
        `INSERT INTO scan_history
           (scan_id,timestamp,business_name,address,place_id,maps_url,
            source,max_reviews,review_count,overall_risk_score,overall_risk_level,
            risk_summary,full_result)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         ON CONFLICT (scan_id) DO NOTHING`,
        [
          scanId, meta.timestamp, meta.businessName, meta.address,
          meta.placeId, meta.mapsUrl, meta.source, meta.maxReviews,
          meta.reviewCount, meta.overallRiskScore, meta.overallRiskLevel,
          JSON.stringify(meta.riskSummary), JSON.stringify(data),
        ]
      );
      // PHI-safe log — business name only, never review content
      console.log(`[history] saved scanId=${scanId} business="${meta.businessName}" storage=postgres`);
    } catch (err) {
      console.error("[history] postgres save failed:", err.message);
    }
  } else {
    // In-memory: evict oldest if full
    if (memHistoryKeys.length >= MEM_HISTORY_MAX) {
      const oldest = memHistoryKeys.shift();
      memHistory.delete(oldest);
    }
    memHistory.set(scanId, { meta, fullResult: data });
    memHistoryKeys.push(scanId);
    console.log(`[history] saved scanId=${scanId} business="${meta.businessName}" storage=memory (${memHistory.size}/${MEM_HISTORY_MAX})`);
  }
}

// ─────────────────────────────────────────────
// GENERIC HELPERS
// ─────────────────────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function isQuotaError(msg = "") {
  return (
    msg.includes("Quota exceeded") ||
    msg.includes("quota") ||
    msg.includes("RESOURCE_EXHAUSTED") ||
    msg.includes("rateLimitExceeded")
  );
}

async function fetchPageSpeed(psiUrl, retries = 2, delayMs = 2000) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const resp = await fetch(psiUrl, { signal: AbortSignal.timeout(35000) });
      const data = await resp.json();
      if (data.error) {
        const msg = data.error.message || "";
        if (isQuotaError(msg)) {
          const e = new Error(msg);
          e.isQuota = true;
          throw e;
        }
        throw new Error(msg);
      }
      return data;
    } catch (err) {
      if (err.isQuota) throw err;
      if (attempt < retries) {
        console.warn(`[PageSpeed] Attempt ${attempt + 1} failed (${err.message}), retrying…`);
        await sleep(delayMs * (attempt + 1));
      } else {
        throw err;
      }
    }
  }
}

function buildFallbackResponse(url) {
  return {
    success:          true,
    scanStatus:       "partial",
    message:          "Scan completed with limited data. Full Lighthouse data available once API quota resets.",
    scannedUrl:       url,
    timestamp:        new Date().toISOString(),
    overallRiskScore: 50,
    scores:           { performance: null, accessibility: null, bestPractices: null, seo: null },
    coreWebVitals:    { lcp: "N/A", tbt: "N/A", cls: "N/A" },
    adaFindings:      [],
    findings: [
      "Performance data temporarily unavailable — API quota exceeded. Retry in a few hours.",
      "ADA compliance data temporarily unavailable.",
      "Manual accessibility review recommended until data is available.",
    ],
    recommendation: "PARTIAL DATA — Retry scan later for a full Lighthouse risk assessment.",
  };
}

function checkRateLimit(ip) {
  const now   = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_MS });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) return false;
  entry.count++;
  return true;
}

// Generic rate limiter for access gate endpoints
function checkCustomRate(map, ip, max, windowMs) {
  const now   = Date.now();
  const entry = map.get(ip);
  if (!entry || now > entry.resetAt) {
    map.set(ip, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= max) return false;
  entry.count++;
  return true;
}

// ─────────────────────────────────────────────
// HEALTH — GET / and GET /health both work
// ─────────────────────────────────────────────
function healthPayload() {
  return {
    status:               "ok",
    version:              VERSION,
    pagespeedFallbackMode,
    cacheSize:            scanCache.size,
    monitoredCount:       monitoredUrls.size,
    rateLimitPolicy:      `${RATE_LIMIT_MAX} scans / hour per IP`,
    cacheTTL:             "12 hours",
    serpApiEnabled:       !!process.env.SERPAPI_KEY,
    historyStorage:       pgPool ? "postgres" : "memory",
    historyCount:         pgPool ? null : memHistory.size,
    adminKeyConfigured:   !!process.env.ADMIN_SCAN_HISTORY_KEY,
  };
}

app.get("/",       (_req, res) => res.json(healthPayload()));
app.get("/health", (_req, res) => res.json(healthPayload()));

// ─────────────────────────────────────────────
// WEBSITE SCAN — Lighthouse + ADA via PageSpeed Insights
// ─────────────────────────────────────────────
app.post("/scan", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });

  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket.remoteAddress ||
    "unknown";
  if (!checkRateLimit(ip)) {
    return res.status(429).json({
      error:   "Too many scans",
      message: `You can run up to ${RATE_LIMIT_MAX} scans per hour. Please wait and try again.`,
    });
  }

  const cacheKey = url.toLowerCase().trim();
  const cached   = scanCache.get(cacheKey);
  if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
    console.log(`[Cache] HIT for ${url}`);
    return res.json({ ...cached.result, fromCache: true, cachedAt: new Date(cached.cachedAt).toISOString() });
  }

  try {
    const apiKey    = process.env.PAGESPEED_API_KEY || "";
    const categories = "category=performance&category=accessibility&category=best-practices&category=seo";
    const psiUrl    = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=desktop&${categories}${apiKey ? "&key=" + apiKey : ""}`;

    let data;
    try {
      data = await fetchPageSpeed(psiUrl);
      pagespeedFallbackMode = false;
    } catch (psiErr) {
      console.warn("[PageSpeed] API unavailable:", psiErr.message);
      pagespeedFallbackMode = true;
      const fallback = buildFallbackResponse(url);
      scanCache.set(cacheKey, { result: fallback, cachedAt: Date.now() - (CACHE_TTL_MS - 30 * 60 * 1000) });
      return res.json(fallback);
    }

    const cats   = data.lighthouseResult?.categories || {};
    const audits = data.lighthouseResult?.audits     || {};

    const perf   = Math.round((cats.performance?.score       || 0) * 100);
    const access = Math.round((cats.accessibility?.score     || 0) * 100);
    const bp     = Math.round((cats["best-practices"]?.score || 0) * 100);
    const seo    = Math.round((cats.seo?.score               || 0) * 100);

    const avgScore  = (perf + access + bp + seo) / 4;
    const riskScore = Math.round(100 - avgScore);

    const adaAuditIds = [
      "color-contrast", "image-alt", "label", "link-name", "button-name",
      "document-title", "html-has-lang", "aria-required-attr", "aria-valid-attr",
      "tabindex", "duplicate-id-aria", "frame-title", "html-lang-valid",
      "landmark-one-main", "region",
    ];
    const adaFindings = adaAuditIds
      .map(id => audits[id])
      .filter(a => a && a.score !== null && a.score < 1)
      .map(a => ({
        id:        a.id,
        title:     a.title,
        description: a.description,
        score:     Math.round((a.score || 0) * 100),
        itemCount: a.details?.items?.length || 0,
      }));

    const findings = [];
    if (perf   < 70) findings.push(`Performance risk (${perf}/100): Slow load times increase bounce rate and reduce conversion`);
    if (access < 90) findings.push(`ADA compliance risk (${access}/100): ${adaFindings.length} accessibility violations detected — potential legal exposure`);
    if (bp     < 80) findings.push(`Security risk (${bp}/100): Missing security headers or deprecated APIs detected`);
    if (seo    < 80) findings.push(`SEO risk (${seo}/100): Visibility gaps that reduce organic and AI-search reach`);
    if (findings.length === 0) findings.push("No major risk findings detected — continue monitoring quarterly");

    const lcp = audits["largest-contentful-paint"]?.displayValue || "N/A";
    const tbt = audits["total-blocking-time"]?.displayValue       || "N/A";
    const cls = audits["cumulative-layout-shift"]?.displayValue   || "N/A";

    const recommendation =
      riskScore > 60 ? "HIGH RISK — Immediate remediation required" :
      riskScore > 30 ? "MODERATE RISK — Review and remediate within 30 days" :
                       "LOW RISK — Monitor quarterly";

    const result = {
      success:          true,
      scanStatus:       "full",
      scannedUrl:       url,
      timestamp:        new Date().toISOString(),
      overallRiskScore: riskScore,
      scores:           { performance: perf, accessibility: access, bestPractices: bp, seo },
      coreWebVitals:    { lcp, tbt, cls },
      adaFindings,
      findings,
      recommendation,
    };

    scanCache.set(cacheKey, { result, cachedAt: Date.now() });
    console.log(`[Cache] STORED for ${url}`);
    res.json(result);
  } catch (err) {
    console.error("Scan error:", err.message);
    res.json(buildFallbackResponse(url));
  }
});

// ─────────────────────────────────────────────
// PDF REPORT
// ─────────────────────────────────────────────
app.post("/report/pdf", async (req, res) => {
  const { scanData } = req.body;
  if (!scanData) return res.status(400).json({ error: "Scan data required" });

  try {
    const doc = new PDFDocument({ margin: 50, size: "A4" });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="zynagi-risk-report-${Date.now()}.pdf"`);
    doc.pipe(res);

    const BLACK = "#000000", GRAY = "#666666", LGRAY = "#aaaaaa";
    const RED   = "#cc2200", AMBER = "#ff8800", GREEN = "#009944", BLUE = "#0055cc";

    const riskScore  = scanData.overallRiskScore ?? 50;
    const riskColor  = riskScore > 60 ? RED : riskScore > 30 ? AMBER : GREEN;
    const scoreColor = s => s == null ? GRAY : s >= 90 ? GREEN : s >= 70 ? AMBER : RED;

    doc.rect(0, 0, 595, 80).fill("#0a0a0a");
    doc.fontSize(26).font("Helvetica-Bold").fillColor("#ffffff").text("ZYNAGI", 50, 22);
    doc.fontSize(10).font("Helvetica").fillColor("#888888").text("AI RISK INTELLIGENCE REPORT", 50, 55);
    doc.fillColor("#ffffff").fontSize(9).text("CONFIDENTIAL", 460, 36);

    let yBase = 100;
    if (scanData.scanStatus === "partial") {
      doc.rect(0, 80, 595, 22).fill("#3a1a00");
      doc.fontSize(8).font("Helvetica").fillColor("#ffaa44")
         .text("PARTIAL SCAN — PageSpeed data unavailable. Retry for a full report.", 50, 87);
      yBase = 112;
    }

    doc.fillColor(BLACK).fontSize(11).font("Helvetica-Bold").text("Scanned URL:", 50, yBase);
    doc.fontSize(11).font("Helvetica").fillColor(BLUE)
       .text(scanData.scannedUrl, 50, yBase + 16, { link: scanData.scannedUrl });
    doc.fillColor(GRAY).fontSize(9)
       .text(`Report generated: ${new Date(scanData.timestamp || Date.now()).toLocaleString("en-US", { dateStyle: "long", timeStyle: "short" })}`, 50, yBase + 34);

    let y = yBase + 58;
    doc.moveTo(50, y).lineTo(545, y).lineWidth(0.5).stroke("#dddddd"); y += 13;
    doc.fontSize(12).font("Helvetica-Bold").fillColor(BLACK).text("OVERALL RISK SCORE", 50, y); y += 17;
    doc.fontSize(60).font("Helvetica-Bold").fillColor(riskColor).text(`${riskScore}`, 50, y);
    doc.fontSize(10).font("Helvetica").fillColor(GRAY).text(`/ 100  ·  ${scanData.recommendation}`, 130, y + 37);

    y += 70;
    doc.moveTo(50, y).lineTo(545, y).lineWidth(0.5).stroke("#dddddd"); y += 13;
    doc.fontSize(12).font("Helvetica-Bold").fillColor(BLACK).text("CATEGORY SCORES", 50, y); y += 24;

    [
      ["Performance",         scanData.scores?.performance],
      ["Accessibility (ADA)", scanData.scores?.accessibility],
      ["Best Practices",      scanData.scores?.bestPractices],
      ["SEO",                 scanData.scores?.seo],
    ].forEach(([label, score]) => {
      doc.fontSize(11).font("Helvetica").fillColor(BLACK).text(label, 50, y);
      doc.rect(250, y + 2, 200, 10).fill("#eeeeee");
      if (score != null) doc.rect(250, y + 2, Math.round(score * 2), 10).fill(scoreColor(score));
      doc.fontSize(11).font("Helvetica-Bold").fillColor(scoreColor(score))
         .text(score != null ? `${score}/100` : "N/A", 462, y);
      y += 26;
    });

    doc.moveTo(50, y + 6).lineTo(545, y + 6).lineWidth(0.5).stroke("#dddddd"); y += 20;
    doc.fontSize(12).font("Helvetica-Bold").fillColor(BLACK).text("CORE WEB VITALS", 50, y); y += 22;
    [
      ["Largest Contentful Paint (LCP)", scanData.coreWebVitals?.lcp],
      ["Total Blocking Time (TBT)",      scanData.coreWebVitals?.tbt],
      ["Cumulative Layout Shift (CLS)",  scanData.coreWebVitals?.cls],
    ].forEach(([label, val]) => {
      doc.fontSize(10).font("Helvetica").fillColor(GRAY).text(label + ":", 50, y);
      doc.font("Helvetica-Bold").fillColor(BLACK).text(val || "N/A", 320, y);
      y += 18;
    });

    doc.moveTo(50, y + 8).lineTo(545, y + 8).lineWidth(0.5).stroke("#dddddd"); y += 22;
    doc.fontSize(12).font("Helvetica-Bold").fillColor(BLACK).text("RISK FINDINGS", 50, y); y += 20;
    (scanData.findings || []).forEach(finding => {
      if (y > 720) { doc.addPage(); y = 50; }
      doc.fontSize(10).font("Helvetica").fillColor("#333333").text(`• ${finding}`, 50, y, { width: 495 });
      y += doc.heightOfString(finding, { width: 495 }) + 8;
    });

    if (scanData.adaFindings?.length > 0) {
      if (y > 650) { doc.addPage(); y = 50; }
      doc.moveTo(50, y + 8).lineTo(545, y + 8).lineWidth(0.5).stroke("#dddddd"); y += 22;
      doc.fontSize(12).font("Helvetica-Bold").fillColor(BLACK).text("ADA ACCESSIBILITY VIOLATIONS", 50, y); y += 20;
      scanData.adaFindings.slice(0, 10).forEach(issue => {
        if (y > 710) { doc.addPage(); y = 50; }
        doc.fontSize(10).font("Helvetica-Bold").fillColor(RED).text(`x  ${issue.title}`, 50, y); y += 16;
        doc.fontSize(9).font("Helvetica").fillColor(GRAY).text(issue.description, 65, y, { width: 480 });
        y += doc.heightOfString(issue.description, { width: 480 }) + 12;
      });
    }

    doc.fontSize(8).fillColor(LGRAY)
       .text("ZYNAGI AI Risk Intelligence  |  zynagi.com  |  Confidential — Not for distribution", 50, 810, { align: "center", width: 495 });
    doc.end();
  } catch (err) {
    console.error("PDF error:", err.message);
    if (!res.headersSent) res.status(500).json({ error: "PDF generation failed", message: err.message });
  }
});

// ─────────────────────────────────────────────
// STRIPE SUBSCRIPTIONS
// ─────────────────────────────────────────────
app.post("/stripe/checkout", async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) return res.status(503).json({ error: "Stripe not configured" });
  const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
  const { plan, email } = req.body;

  const plans = {
    starter:    { price: process.env.STRIPE_PRICE_STARTER },
    growth:     { price: process.env.STRIPE_PRICE_GROWTH },
    enterprise: { price: process.env.STRIPE_PRICE_ENTERPRISE },
  };

  if (!plans[plan]?.price) return res.status(400).json({ error: "Invalid plan or price not configured" });

  try {
    const session = await stripe.checkout.sessions.create({
      mode:                "subscription",
      payment_method_types: ["card"],
      customer_email:      email,
      line_items:          [{ price: plans[plan].price, quantity: 1 }],
      success_url:         `https://zynagi.com/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:          `https://zynagi.com/ai-risk-assessment`,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: "Checkout failed", message: err.message });
  }
});

app.post("/stripe/webhook", express.raw({ type: "application/json" }), (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) return res.json({ received: true });
  const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
  const sig = req.headers["stripe-signature"];
  try {
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    if (event.type === "checkout.session.completed") {
      console.log("New subscriber:", event.data.object.customer_email);
    }
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  res.json({ received: true });
});

// ─────────────────────────────────────────────
// RECURRING MONITORING
// ─────────────────────────────────────────────
app.post("/monitor/add", (req, res) => {
  const { url, email, frequency } = req.body;
  if (!url || !email) return res.status(400).json({ error: "URL and email required" });
  monitoredUrls.set(url, { email, frequency: frequency || "weekly", addedAt: new Date().toISOString(), lastScanned: null, lastScore: null });
  res.json({ success: true, message: `${url} is now being monitored ${frequency || "weekly"}` });
});

app.delete("/monitor/remove", (req, res) => {
  monitoredUrls.delete(req.body.url);
  res.json({ success: true });
});

app.get("/monitor/list", (_req, res) => {
  res.json({ monitored: Array.from(monitoredUrls.entries()).map(([url, data]) => ({ url, ...data })) });
});

cron.schedule("0 8 * * *", async () => {
  console.log(`[Cron] Monitoring scans — ${new Date().toISOString()}`);
  const isMonday = new Date().getDay() === 1;
  for (const [url, data] of monitoredUrls.entries()) {
    if (data.frequency === "daily" || (data.frequency === "weekly" && isMonday)) {
      try {
        const psiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=desktop&category=accessibility&category=performance${process.env.PAGESPEED_API_KEY ? "&key=" + process.env.PAGESPEED_API_KEY : ""}`;
        const d   = await fetchPageSpeed(psiUrl);
        const acc = Math.round((d.lighthouseResult?.categories?.accessibility?.score || 0) * 100);
        const prf = Math.round((d.lighthouseResult?.categories?.performance?.score  || 0) * 100);
        monitoredUrls.set(url, { ...data, lastScanned: new Date().toISOString(), lastScore: { accessibility: acc, performance: prf } });
        scanCache.delete(url.toLowerCase().trim());
        console.log(`[Cron] ${url} -> ADA: ${acc}, Perf: ${prf}`);
      } catch (e) {
        console.error(`[Cron] Failed for ${url}:`, e.message);
      }
    }
  }
});

// ─────────────────────────────────────────────
// HIPAA REVIEW SCANNER
// ─────────────────────────────────────────────

// HIGH — directly confirms PHI, patient status, or specific treatment
const HIPAA_HIGH = [
  // Patient/client relationship
  { r: /\b(as your|you are|you were|you're)\s+(our\s+)?(patient|client)\b/gi,
    v: "Directly confirms reviewer is a patient/client (PHI)" },
  { r: /\bour\s+(patient|client)\b/gi,
    v: "Directly confirms patient status" },

  // Named treatments, procedures, devices
  { r: /\byour\s+(treatment|procedure|surgery|operation|therapy|injection|prescription|medication|diagnosis)\b/gi,
    v: "References specific patient medical information (PHI)" },
  { r: /\byour\s+(Invisalign|braces|aligners|implant|implants|extraction|cleaning|whitening|filling|fillings|root canal|crown|crowns|veneer|veneers|denture|dentures|sleep apnea treatment|CPAP|retainer|sealant|night guard)\b/gi,
    v: "References specific dental treatment or device by name (PHI)" },
  { r: /\b(root canal|Invisalign|sleep apnea|chemotherapy|dialysis|biopsy|radiation therapy|colonoscopy|CPAP therapy)\b/gi,
    v: "Mentions specific medical/dental procedure by name — may confirm patient relationship" },

  // Appointment / visit specifics
  { r: /\byour\s+(appointment|visit|consultation|follow-?up|check-?up)\b/gi,
    v: "References specific patient appointment or visit (PHI)" },
  { r: /\bwhen you (came in|visited us|were here|had your|came for|scheduled)\b/gi,
    v: "References specific patient visit" },

  // Medical condition / test results
  { r: /\byour\s+(condition|diagnosis|symptoms|illness|prognosis|test results?|lab results?|x-?ray|scan results?)\b/gi,
    v: "References patient medical condition or test results (PHI)" },
  { r: /\bour\s+(records|chart|file|notes)\s+(show|indicate|reflect|confirm)\b/gi,
    v: "Implies access to patient medical records" },

  // Financial / insurance tied to care
  { r: /\byour\s+(insurance|coverage|co-?pay|copay|bill|balance|claim|deductible|out-of-pocket)\b/gi,
    v: "References patient financial or insurance information (PHI)" },

  // Care / treatment plan
  { r: /\byour\s+(care plan|treatment plan|wellness plan|recovery plan|dental plan)\b/gi,
    v: "References specific patient care or treatment plan (PHI)" },
];

// MEDIUM — implies patient relationship without explicit PHI
const HIPAA_MEDIUM = [
  { r: /\byour (specific |)(concerns|issues|complaints|problem)\b/gi,
    v: "Implies specific knowledge of patient concerns" },
  { r: /\bas we (discussed|mentioned|spoke about|talked about)\b/gi,
    v: "References prior private communication" },
  { r: /\byour experience with (us|our office|our practice|our team|our clinic)\b/gi,
    v: "May imply confirmed patient relationship" },
  { r: /\bwe understand your (frustration|concern|situation|needs|discomfort)\b/gi,
    v: "Implies specific knowledge of patient situation" },
  { r: /\bwe (see|note|noticed|can see|observe) that\b/gi,
    v: "May imply access to patient records" },
  { r: /\byour (care|dental health|oral health|health journey|smile journey|wellness journey)\b/gi,
    v: "References patient's healthcare context (may confirm relationship)" },
  { r: /\bseeing you (again|back|soon) for (care|treatment|your next)\b/gi,
    v: "Implies ongoing patient relationship and future treatment" },
  { r: /\byour (next|upcoming|scheduled) (care|treatment|checkup|check-?up|cleaning)\b/gi,
    v: "References future care — implies confirmed patient relationship" },
];

// LOW — mild, generic healthcare language that may hint at a care relationship
const HIPAA_LOW = [
  { r: /\byour (smile|comfort|recovery|healing|well-?being)\b/gi,
    v: "Generic healthcare language that may imply a care context" },
  { r: /\bhope (you feel|you are feeling|you're feeling) (better|well|great)\b/gi,
    v: "Implies health/medical context" },
  { r: /\bour (team|staff|doctors?|hygienists?|nurses?|providers?) (cares?|looks?) (about|after) you\b/gi,
    v: "Implies ongoing care relationship" },
];

// ─────────────────────────────────────────────
// HIPAA ANALYSIS ENGINE
// ─────────────────────────────────────────────
function analyzeHipaaResponse(responseText) {
  if (!responseText || !responseText.trim()) {
    return { risk: "NO_RESPONSE", violations: [], score: 0 };
  }

  const violations = [];
  let score = 0;

  for (const p of HIPAA_HIGH) {
    if (p.r.test(responseText)) { violations.push({ severity: "HIGH",   message: p.v }); score += 30; }
    p.r.lastIndex = 0;
  }
  for (const p of HIPAA_MEDIUM) {
    if (p.r.test(responseText)) { violations.push({ severity: "MEDIUM", message: p.v }); score += 12; }
    p.r.lastIndex = 0;
  }
  for (const p of HIPAA_LOW) {
    if (p.r.test(responseText)) { violations.push({ severity: "LOW",    message: p.v }); score +=  5; }
    p.r.lastIndex = 0;
  }

  score = Math.min(100, score);

  const risk =
    violations.some(v => v.severity === "HIGH")   ? "HIGH"   :
    violations.some(v => v.severity === "MEDIUM")  ? "MEDIUM" :
    violations.some(v => v.severity === "LOW")     ? "LOW"    :
    "CLEAN";

  return { risk, violations, score };
}

// HIPAA-safe response templates — never confirm patient status or mention treatment
function generateSafeResponse(rating) {
  const r = Number(rating) || 3;
  if (r >= 4) return "Thank you for your kind feedback. We appreciate you taking the time to share your experience with our team.";
  if (r === 3) return "We appreciate your review and are grateful for your feedback. Our team values every opportunity to provide a positive experience. Please feel free to reach out to our office directly so we can learn more.";
  return "Thank you for sharing your experience. We are sorry to hear your visit did not fully meet your expectations. Please contact our office at your convenience — we would appreciate the opportunity to address your feedback.";
}

// ─────────────────────────────────────────────
// PLACE ID RESOLUTION
// Handles: direct ChIJ IDs, full Maps URLs, shortened goo.gl/maps.app links
// Falls back to Places Text Search if no Place ID found in URL
// ─────────────────────────────────────────────
async function resolveToPlaceId(input, apiKey) {
  if (!input) return null;
  input = input.trim();

  // Direct Place ID
  if (/^ChIJ[a-zA-Z0-9_-]{10,}$/.test(input)) return input;

  let urlToParse = input;

  // Follow redirects for shortened links (goo.gl, maps.app.goo.gl)
  if (/goo\.gl|maps\.app/.test(input)) {
    try {
      const r = await fetch(input, {
        method: "HEAD", redirect: "follow",
        signal: AbortSignal.timeout(6000),
        headers: { "User-Agent": "Mozilla/5.0" },
      });
      urlToParse = r.url || input;
    } catch (_) { /* use original URL */ }
  }

  // !1sChIJ...! embedded in URL data segment
  const m1 = urlToParse.match(/!1s(ChIJ[a-zA-Z0-9_-]+)!/);
  if (m1) return m1[1];

  // ?place_id=... or &place_id=...
  const m2 = urlToParse.match(/[?&]place_id=(ChIJ[a-zA-Z0-9_-]+)/);
  if (m2) return m2[1];

  // ?q=place_id:ChIJ...
  const m3 = urlToParse.match(/q=place_id:(ChIJ[a-zA-Z0-9_-]+)/);
  if (m3) return m3[1];

  // CID format (?cid=NNNN) — resolve via Places Details
  const cidMatch = urlToParse.match(/[?&]cid=(\d+)/);
  if (cidMatch && apiKey) {
    try {
      const r = await fetch(
        `https://maps.googleapis.com/maps/api/place/details/json?cid=${cidMatch[1]}&fields=place_id&key=${apiKey}`,
        { signal: AbortSignal.timeout(8000) }
      );
      const d = await r.json();
      if (d.result?.place_id) return d.result.place_id;
    } catch (_) { /* fall through */ }
  }

  // Extract business name from URL path and use Places Text Search
  if (apiKey) {
    const pathMatch = urlToParse.match(/maps\/place\/([^/@?#]+)/);
    if (pathMatch) {
      const query = decodeURIComponent(pathMatch[1].replace(/\+/g, " "));
      try {
        const r = await fetch(
          `https://maps.googleapis.com/maps/api/place/textsearch/json?query=${encodeURIComponent(query)}&key=${apiKey}`,
          { signal: AbortSignal.timeout(10000) }
        );
        const d = await r.json();
        if (d.results?.[0]?.place_id) return d.results[0].place_id;
      } catch (_) { /* fall through */ }
    }
  }

  return null;
}

// ─────────────────────────────────────────────
// SERPAPI PAGINATED REVIEW FETCHER
// Fetches up to maxReviews reviews, paginating via next_page_token.
// PHI-safe: never logs review text — only page counts and business name.
// ─────────────────────────────────────────────
async function fetchReviewsViaSerpApi(placeId, maxReviews, serpApiKey) {
  const allReviews = [];
  let nextPageToken = null;
  let pageCount     = 0;
  let placeInfo     = null;

  do {
    const params = new URLSearchParams({
      engine:   "google_maps_reviews",
      place_id: placeId,
      sort_by:  "newest",
      hl:       "en",
      api_key:  serpApiKey,
    });
    if (nextPageToken) params.set("next_page_token", nextPageToken);

    const r = await fetch(`https://serpapi.com/search?${params}`, {
      signal: AbortSignal.timeout(20000),
    });
    const data = await r.json();

    if (data.error) {
      const e = new Error(`SerpAPI: ${data.error}`);
      e.serpApiError = data.error;
      throw e;
    }

    if (!placeInfo && data.place_info) {
      placeInfo = data.place_info;
    }

    const pageReviews = data.reviews || [];
    allReviews.push(...pageReviews);
    pageCount++;

    // PHI-safe logging — never log review content
    console.log(`[serpapi] page=${pageCount} page_reviews=${pageReviews.length} total_so_far=${allReviews.length}`);

    nextPageToken = data.serpapi_pagination?.next_page_token || null;

    if (allReviews.length >= maxReviews) break;
    if (!nextPageToken || pageReviews.length === 0) break;

  } while (true);

  return {
    reviews:   allReviews.slice(0, maxReviews),
    placeInfo: placeInfo || {},
    pageCount,
  };
}

// ─────────────────────────────────────────────
// POST /scan-reviews
// Accepts: { placeId, mapsUrl, maxReviews }
// Uses SerpAPI (up to 1000 reviews) if SERPAPI_KEY env var is set.
// Falls back to Google Places API (max 5 reviews) if not.
// ─────────────────────────────────────────────
app.post("/scan-reviews", async (req, res) => {
  const { placeId, mapsUrl, maxReviews: maxReviewsRaw } = req.body;
  const rawInput   = placeId || mapsUrl;
  const maxReviews = Math.max(1, Math.min(parseInt(maxReviewsRaw) || 100, 1000));

  if (!rawInput) {
    return res.status(400).json({
      error: "Provide either placeId (e.g. ChIJ...) or mapsUrl (Google Maps link).",
    });
  }

  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
             req.socket.remoteAddress || "unknown";
  if (!checkRateLimit(ip)) {
    return res.status(429).json({
      success:            false,
      error:              "Too many scans. Please wait and try again.",
      retryAfterMinutes:  60,
    });
  }

  const apiKey     = process.env.GOOGLE_PLACES_API_KEY;
  const serpApiKey = process.env.SERPAPI_KEY;

  if (!apiKey) {
    return res.status(503).json({ error: "GOOGLE_PLACES_API_KEY is not configured on this server." });
  }

  // Resolve input to a canonical Place ID
  let resolved;
  try {
    resolved = await resolveToPlaceId(rawInput, apiKey);
  } catch (err) {
    console.error("[scan-reviews] resolveToPlaceId error:", err.message);
    resolved = null;
  }

  if (!resolved) {
    return res.status(400).json({
      error:
        "Could not extract a valid Place ID from the input. " +
        "Paste the Place ID directly (starts with ChIJ...) or use a full Google Maps URL.",
    });
  }

  // Cache key includes maxReviews so different limits get separate entries
  const cacheKey = `reviews:${resolved}:${maxReviews}`;
  const cached   = scanCache.get(cacheKey);
  if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
    console.log(`[Cache] HIT reviews place_id=${resolved} maxReviews=${maxReviews}`);
    return res.json({ ...cached.result, fromCache: true, cachedAt: new Date(cached.cachedAt).toISOString() });
  }

  try {
    let reviews        = [];
    let businessName   = "Unknown";
    let businessRating = null;
    let totalRatings   = null;
    let address        = "";
    let source;

    if (serpApiKey) {
      // ── SerpAPI path (up to 1000 reviews via pagination) ──────
      const { reviews: serpReviews, placeInfo, pageCount } =
        await fetchReviewsViaSerpApi(resolved, maxReviews, serpApiKey);

      businessName   = placeInfo.title   || placeInfo.name  || "Unknown";
      businessRating = placeInfo.rating  || null;
      totalRatings   = placeInfo.reviews || null;
      address        = placeInfo.address || "";
      source         = "serpapi";

      // PHI-safe — only log business name and counts
      console.log(`[scan-reviews] SerpAPI OK place_id=${resolved} name="${businessName}" pages=${pageCount} reviews=${serpReviews.length}`);

      reviews = serpReviews.map(rv => ({
        author:     rv.user?.name        || "Anonymous",
        rating:     rv.rating            || 0,
        reviewText: rv.snippet           || "",
        reviewTime: rv.date              || rv.iso_date || "",
        response:   rv.response?.snippet || null,
      }));

    } else {
      // ── Google Places API fallback (hard limit: 5 reviews) ────
      const detailsUrl =
        `https://maps.googleapis.com/maps/api/place/details/json` +
        `?place_id=${encodeURIComponent(resolved)}` +
        `&fields=name,rating,user_ratings_total,formatted_address,reviews` +
        `&key=${apiKey}` +
        `&reviews_sort=newest`;

      const r    = await fetch(detailsUrl, { signal: AbortSignal.timeout(15000) });
      const data = await r.json();

      if (data.status === "NOT_FOUND" || data.status === "INVALID_REQUEST") {
        return res.status(400).json({
          error: `Place not found (Google API status: ${data.status}). Verify the Place ID or URL.`,
        });
      }
      if (data.status !== "OK") {
        return res.status(502).json({
          error:  `Google Places API error: ${data.status}`,
          detail: data.error_message || "",
        });
      }

      const place  = data.result;
      businessName   = place.name;
      businessRating = place.rating;
      totalRatings   = place.user_ratings_total;
      address        = place.formatted_address;
      source         = "google_places";

      console.log(`[scan-reviews] Places OK place_id=${resolved} name="${businessName}" reviews=${(place.reviews||[]).length}`);

      reviews = (place.reviews || []).map(rv => ({
        author:     rv.author_name || "Anonymous",
        rating:     rv.rating,
        reviewText: rv.text || "",
        reviewTime: rv.relative_time_description || "",
        response:   rv.author_reply?.text || null,
      }));
    }

    // ── HIPAA Analysis ──────────────────────────────────────────
    // Fast path: skip regex engine for reviews with no owner response
    const analyzed = reviews.map(rv => {
      if (!rv.response || !rv.response.trim()) {
        return {
          ...rv,
          hipaaRisk:    "NO_RESPONSE",
          violations:   [],
          riskScore:    0,
          safeResponse: generateSafeResponse(rv.rating),
        };
      }
      const analysis = analyzeHipaaResponse(rv.response);
      return {
        ...rv,
        hipaaRisk:    analysis.risk,
        violations:   analysis.violations,
        riskScore:    analysis.score,
        safeResponse: generateSafeResponse(rv.rating),
      };
    });

    const withResponses = analyzed.filter(r => r.response);
    const avgScore = withResponses.length
      ? Math.round(withResponses.reduce((s, r) => s + r.riskScore, 0) / withResponses.length)
      : 0;

    const overallRiskLevel =
      avgScore > 60 ? "HIGH"   :
      avgScore > 30 ? "MEDIUM" :
      avgScore > 0  ? "LOW"    : "CLEAN";

    // Violation groupings for frontend toggle + export
    const violationsOnlyReviews = analyzed.filter(r =>
      r.hipaaRisk === "HIGH" || r.hipaaRisk === "MEDIUM" || r.hipaaRisk === "LOW"
    );
    const violationCount  = violationsOnlyReviews.length;
    const cleanCount      = analyzed.filter(r => r.hipaaRisk === "CLEAN").length;
    const noResponseCount = analyzed.filter(r => r.hipaaRisk === "NO_RESPONSE").length;

    const scanId = randomUUID();

    const result = {
      success:          true,
      scanId,
      source,
      businessName,
      businessRating,
      totalRatings,
      address,
      overallRiskScore: avgScore,
      overallRiskLevel,
      riskSummary: {
        high:       withResponses.filter(r => r.hipaaRisk === "HIGH").length,
        medium:     withResponses.filter(r => r.hipaaRisk === "MEDIUM").length,
        low:        withResponses.filter(r => r.hipaaRisk === "LOW").length,
        clean:      withResponses.filter(r => r.hipaaRisk === "CLEAN").length,
        noResponse: analyzed.filter(r => !r.response).length,
      },
      reviewCount: analyzed.length,
      maxReviews,
      violationCount,
      cleanCount,
      noResponseCount,
      violationsOnlyReviews,
      reviews:     analyzed,
      timestamp:   new Date().toISOString(),
      disclaimer:
        "This analysis is for informational purposes only and does not constitute legal advice. " +
        "Consult a HIPAA compliance attorney for formal guidance.",
      // internal fields used by saveScanHistory (not surfaced in UI)
      _placeId: resolved,
      _mapsUrl: mapsUrl || null,
    };

    // Save to history (PHI-safe — function never logs review text)
    await saveScanHistory(scanId, result);

    scanCache.set(cacheKey, { result, cachedAt: Date.now() });
    return res.json(result);

  } catch (err) {
    // Never log review content — only the error message
    console.error("[scan-reviews] error:", err.message);
    return res.status(500).json({
      error:  "Review scan failed. Please try again.",
      detail: err.message,
    });
  }
});

// ─────────────────────────────────────────────
// POST /analyze-response
// ─────────────────────────────────────────────
app.post("/analyze-response", (req, res) => {
  const { responseText, rating } = req.body;
  if (!responseText || !responseText.trim()) {
    return res.status(400).json({ error: "responseText is required and must not be empty." });
  }
  const analysis = analyzeHipaaResponse(responseText);
  return res.json({
    success:      true,
    risk:         analysis.risk,
    violations:   analysis.violations,
    score:        analysis.score,
    safeResponse: generateSafeResponse(rating ?? 3),
  });
});

// ─────────────────────────────────────────────
// TEST / SMOKE-TEST ROUTES (no Google API calls)
// ─────────────────────────────────────────────
app.get("/test/analyze-response", (_req, res) => {
  const sample  = "Thank you for trusting us with your Invisalign treatment. As our patient, we appreciate your feedback.";
  const result  = analyzeHipaaResponse(sample);
  return res.json({
    test:        "analyze-response",
    input:       sample,
    result,
    safeResponse: generateSafeResponse(5),
    status:      result.risk === "HIGH" ? "PASS ✓" : "UNEXPECTED — check patterns",
  });
});

app.get("/test/scan-reviews", (_req, res) => {
  const placesKeyPresent = !!process.env.GOOGLE_PLACES_API_KEY;
  const serpKeyPresent   = !!process.env.SERPAPI_KEY;
  return res.json({
    test:               "scan-reviews",
    googlePlacesKey:    placesKeyPresent ? "SET ✓" : "MISSING ✗",
    serpApiKey:         serpKeyPresent   ? "SET ✓ (up to 1000 reviews)" : "NOT SET (will use Google Places — max 5 reviews)",
    activeSource:       serpKeyPresent   ? "serpapi" : "google_places",
    status:             placesKeyPresent
      ? "CONFIG OK ✓ — POST /scan-reviews with a real placeId to test end-to-end"
      : "MISSING KEY — set GOOGLE_PLACES_API_KEY in Railway environment variables",
    exampleRequest: {
      url:  "POST /scan-reviews",
      body: { placeId: "ChIJN1t_tDeuEmsRUsoyG83frY4", maxReviews: 100 },
      or:   { mapsUrl: "https://www.google.com/maps/place/Google+Sydney/@-33.8,151.1,15z/...", maxReviews: 500 },
    },
  });
});

// ─────────────────────────────────────────────
// SCAN HISTORY ENDPOINTS
// All require x-admin-key header if ADMIN_SCAN_HISTORY_KEY env var is set.
// ─────────────────────────────────────────────

// GET /scan-history — list recent scans, newest first
app.get("/scan-history", requireAdminKey, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);

  if (pgPool) {
    try {
      const { rows } = await pgPool.query(
        `SELECT scan_id, timestamp, business_name, address, source,
                max_reviews, review_count, overall_risk_score,
                overall_risk_level, risk_summary
           FROM scan_history
          ORDER BY timestamp DESC
          LIMIT $1`,
        [limit]
      );
      return res.json({
        success: true,
        storage: "postgres",
        count:   rows.length,
        scans:   rows.map(r => ({
          scanId:           r.scan_id,
          timestamp:        r.timestamp,
          businessName:     r.business_name,
          address:          r.address,
          source:           r.source,
          maxReviews:       r.max_reviews,
          reviewCount:      r.review_count,
          overallRiskScore: r.overall_risk_score,
          overallRiskLevel: r.overall_risk_level,
          riskSummary:      r.risk_summary,
        })),
      });
    } catch (err) {
      console.error("[history] GET /scan-history postgres error:", err.message);
      return res.status(500).json({ success: false, error: "Database error" });
    }
  } else {
    const keys   = [...memHistoryKeys].reverse().slice(0, limit); // newest first
    return res.json({
      success: true,
      storage: "memory",
      warning: "In-memory storage: scans are lost on server restart. Add Railway Postgres (DATABASE_URL) for persistence.",
      count:   keys.length,
      scans:   keys.map(k => {
        const { meta } = memHistory.get(k);
        return {
          scanId:           meta.scanId,
          timestamp:        meta.timestamp,
          businessName:     meta.businessName,
          address:          meta.address,
          source:           meta.source,
          maxReviews:       meta.maxReviews,
          reviewCount:      meta.reviewCount,
          overallRiskScore: meta.overallRiskScore,
          overallRiskLevel: meta.overallRiskLevel,
          riskSummary:      meta.riskSummary,
        };
      }),
    });
  }
});

// GET /scan-history/:scanId — full scan result
app.get("/scan-history/:scanId", requireAdminKey, async (req, res) => {
  const { scanId } = req.params;

  if (pgPool) {
    try {
      const { rows } = await pgPool.query(
        "SELECT full_result FROM scan_history WHERE scan_id = $1", [scanId]
      );
      if (!rows.length) return res.status(404).json({ success: false, error: "Scan not found" });
      return res.json({ success: true, storage: "postgres", ...rows[0].full_result });
    } catch (err) {
      return res.status(500).json({ success: false, error: "Database error" });
    }
  } else {
    const entry = memHistory.get(scanId);
    if (!entry) return res.status(404).json({ success: false, error: "Scan not found (server may have restarted)" });
    return res.json({ success: true, storage: "memory", ...entry.fullResult });
  }
});

// GET /scan-history/:scanId/export-json — download full scan as JSON file
app.get("/scan-history/:scanId/export-json", requireAdminKey, async (req, res) => {
  const { scanId } = req.params;
  let fullResult, bizName, ts;

  if (pgPool) {
    try {
      const { rows } = await pgPool.query(
        "SELECT full_result, business_name, timestamp FROM scan_history WHERE scan_id = $1", [scanId]
      );
      if (!rows.length) return res.status(404).json({ success: false, error: "Scan not found" });
      fullResult = rows[0].full_result;
      bizName    = rows[0].business_name;
      ts         = new Date(rows[0].timestamp).toISOString().split("T")[0];
    } catch (err) {
      return res.status(500).json({ success: false, error: "Database error" });
    }
  } else {
    const entry = memHistory.get(scanId);
    if (!entry) return res.status(404).json({ success: false, error: "Scan not found (server may have restarted)" });
    fullResult = entry.fullResult;
    bizName    = entry.meta.businessName;
    ts         = new Date(entry.meta.timestamp).toISOString().split("T")[0];
  }

  const safe = (bizName || "scan").replace(/[^a-zA-Z0-9]/g, "_").slice(0, 30);
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="zynagi-hipaa-${safe}-${ts}-${scanId.slice(0,8)}.json"`);
  return res.send(JSON.stringify(fullResult, null, 2));
});

// GET /scan-history/:scanId/export-violations-json — violations only (HIGH/MEDIUM/LOW)
app.get("/scan-history/:scanId/export-violations-json", requireAdminKey, async (req, res) => {
  const { scanId } = req.params;
  let fullResult, bizName, ts;

  if (pgPool) {
    try {
      const { rows } = await pgPool.query(
        "SELECT full_result, business_name, timestamp FROM scan_history WHERE scan_id = $1", [scanId]
      );
      if (!rows.length) return res.status(404).json({ success: false, error: "Scan not found" });
      fullResult = rows[0].full_result;
      bizName    = rows[0].business_name;
      ts         = new Date(rows[0].timestamp).toISOString().split("T")[0];
    } catch (err) {
      return res.status(500).json({ success: false, error: "Database error" });
    }
  } else {
    const entry = memHistory.get(scanId);
    if (!entry) return res.status(404).json({ success: false, error: "Scan not found (server may have restarted)" });
    fullResult = entry.fullResult;
    bizName    = entry.meta.businessName;
    ts         = new Date(entry.meta.timestamp).toISOString().split("T")[0];
  }

  const violationsOnly = fullResult.violationsOnlyReviews ||
    (fullResult.reviews || []).filter(r =>
      r.hipaaRisk === "HIGH" || r.hipaaRisk === "MEDIUM" || r.hipaaRisk === "LOW"
    );

  const exportData = {
    businessName:         fullResult.businessName,
    address:              fullResult.address,
    scanId:               fullResult.scanId,
    timestamp:            fullResult.timestamp,
    overallRiskScore:     fullResult.overallRiskScore,
    overallRiskLevel:     fullResult.overallRiskLevel,
    riskSummary:          fullResult.riskSummary,
    violationCount:       fullResult.violationCount ?? violationsOnly.length,
    violationsOnlyReviews: violationsOnly,
  };

  const safe = (bizName || "scan").replace(/[^a-zA-Z0-9]/g, "_").slice(0, 30);
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="zynagi-violations-${safe}-${ts}-${scanId.slice(0,8)}.json"`);
  return res.send(JSON.stringify(exportData, null, 2));
});

// ─────────────────────────────────────────────
// SCANNER ACCESS GATE
// POST /scanner-access-request  — lead capture (rate limited: 5/hr/IP)
// POST /scanner-access-verify   — password check (rate limited: 10/hr/IP)
// GET  /scanner-access-requests — admin view of stored leads
// ─────────────────────────────────────────────

app.post("/scanner-access-request", (req, res) => {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim()
           || req.socket.remoteAddress || "unknown";

  if (!checkCustomRate(accessReqRateMap, ip, 5, RATE_LIMIT_MS)) {
    return res.status(429).json({
      success: false,
      error:   "Too many access requests. Please try again later.",
    });
  }

  const { name, email, company, website, role, locationCount, message } = req.body || {};
  if (!name || !email) {
    return res.status(400).json({ success: false, error: "Name and email are required." });
  }

  const record = {
    id:            randomUUID(),
    timestamp:     new Date().toISOString(),
    name:          String(name).slice(0, 120),
    email:         String(email).slice(0, 200),
    company:       String(company       || "").slice(0, 200),
    website:       String(website       || "").slice(0, 300),
    role:          String(role          || "").slice(0, 120),
    locationCount: String(locationCount || "").slice(0,  20),
    message:       String(message       || "").slice(0, 1000),
    ip,
  };

  // Evict oldest if at capacity
  if (accessRequests.length >= ACCESS_REQ_MAX) accessRequests.shift();
  accessRequests.push(record);

  console.log(`[access-request] name="${record.name}" email="${record.email}" company="${record.company}" ip=${ip}`);

  return res.json({
    success: true,
    message: "Request received. Our team will review your request and send access instructions.",
  });
});

app.post("/scanner-access-verify", (req, res) => {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim()
           || req.socket.remoteAddress || "unknown";

  if (!checkCustomRate(accessPwdRateMap, ip, 10, RATE_LIMIT_MS)) {
    return res.status(429).json({
      success: false,
      error:   "Too many attempts. Please try again later.",
    });
  }

  const password = process.env.SCANNER_ACCESS_PASSWORD;
  if (!password) {
    // Gate not configured — open access (staging / disable gate)
    return res.json({ success: true });
  }

  const { code } = req.body || {};
  if (!code || String(code) !== password) {
    return res.status(403).json({
      success: false,
      error:   "Invalid access code. Please request access.",
    });
  }

  console.log(`[access-verify] successful unlock ip=${ip}`);
  return res.json({ success: true });
});

// Admin endpoint: view captured access leads
app.get("/scanner-access-requests", requireAdminKey, (req, res) => {
  return res.json({
    success:  true,
    count:    accessRequests.length,
    storage:  "memory",
    warning:  "Leads are in-memory and lost on server restart. Export regularly.",
    requests: [...accessRequests].reverse(), // newest first
  });
});

// ─────────────────────────────────────────────
// CACHE MANAGEMENT
// ─────────────────────────────────────────────
app.delete("/cache/clear", (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (adminKey && req.headers["x-admin-key"] !== adminKey) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  scanCache.clear();
  res.json({ success: true, message: "Scan cache cleared" });
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`ZYNAGI Scanner API v${VERSION} on port ${PORT}`));
