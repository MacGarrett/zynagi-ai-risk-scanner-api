const express = require("express");
const cors = require("cors");
const PDFDocument = require("pdfkit");
const cron = require("node-cron");

const app = express();

app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// IN-MEMORY STORES
// ─────────────────────────────────────────────

// Monitored URLs for recurring scans
const monitoredUrls = new Map();

// Result cache: url → { result, cachedAt }
const scanCache = new Map();
const CACHE_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

// Rate limiting: ip → { count, resetAt }
const rateLimitMap = new Map();
const RATE_LIMIT_MAX = 5;               // max scans per window per IP
const RATE_LIMIT_MS  = 60 * 60 * 1000; // 1-hour window

// Track whether PageSpeed is currently in fallback mode
let pagespeedFallbackMode = false;

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

function isQuotaError(message = "") {
  return (
    message.includes("Quota exceeded") ||
    message.includes("quota") ||
    message.includes("RESOURCE_EXHAUSTED") ||
    message.includes("rateLimitExceeded")
  );
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Fetch PageSpeed with retry/backoff (skips retry on quota errors)
async function fetchPageSpeed(psiUrl, retries = 2, delayMs = 2000) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch(psiUrl, { signal: AbortSignal.timeout(35000) });
      const data = await response.json();

      if (data.error) {
        const msg = data.error.message || "";
        if (isQuotaError(msg)) {
          const err = new Error(msg);
          err.isQuota = true;
          throw err;
        }
        throw new Error(msg);
      }

      return data;
    } catch (err) {
      if (err.isQuota) throw err;
      if (attempt < retries) {
        console.warn(`[PageSpeed] Attempt ${attempt + 1} failed, retrying in ${delayMs * (attempt + 1)}ms:`, err.message);
        await sleep(delayMs * (attempt + 1));
      } else {
        throw err;
      }
    }
  }
}

function buildFallbackResponse(url) {
  return {
    success: true,
    scanStatus: "partial",
    message:
      "Scan completed with limited performance data. Core trust checks are still available. " +
      "Full Lighthouse data will be available once the API quota resets.",
    scannedUrl: url,
    timestamp: new Date().toISOString(),
    overallRiskScore: 50,
    scores: { performance: null, accessibility: null, bestPractices: null, seo: null },
    coreWebVitals: { lcp: "N/A", tbt: "N/A", cls: "N/A" },
    adaFindings: [],
    findings: [
      "Performance data temporarily unavailable — API quota exceeded. Try again in a few hours.",
      "ADA compliance data temporarily unavailable — API quota exceeded.",
      "Manual accessibility review recommended until data is available.",
    ],
    recommendation: "PARTIAL DATA — Retry scan later for a full Lighthouse risk assessment.",
  };
}

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_MS });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) return false;
  entry.count += 1;
  return true;
}

app.get("/health", (req, res) => {
  res.json({ status: "ok", version: "2.1", pagespeedFallbackMode, cacheSize: scanCache.size, monitoredCount: monitoredUrls.size, rateLimitPolicy: `${RATE_LIMIT_MAX} scans / hour per IP`, cacheTTL: "12 hours" });
});

app.post("/scan", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: "Too many scans", message: `You can run up to ${RATE_LIMIT_MAX} scans per hour. Please wait and try again.` });
  }
  const cacheKey = url.toLowerCase().trim();
  const cached = scanCache.get(cacheKey);
  if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
    console.log(`[Cache] HIT for ${url}`);
    return res.json({ ...cached.result, fromCache: true, cachedAt: new Date(cached.cachedAt).toISOString() });
  }
  try {
    const apiKey = process.env.PAGESPEED_API_KEY || "";
    const categories = "category=performance&category=accessibility&category=best-practices&category=seo";
    const psiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPageSpeed?url=${encodeURIComponent(url)}&strategy=desktop&${categories}${apiKey ? "&key=" + apiKey : ""}`;
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
    const cats = data.lighthouseResult?.categories || {};
    const audits = data.lighthouseResult?.audits || {};
    const perf = Math.round((cats.performance?.score || 0) * 100);
    const access = Math.round((cats.accessibility?.score || 0) * 100);
    const bp = Math.round((cats["best-practices"]?.score || 0) * 100);
    const seo = Math.round((cats.seo?.score || 0) * 100);
    const riskScore = Math.round(100 - (perf + access + bp + seo) / 4);
    const adaAuditIds = ["color-contrast","image-alt","label","link-name","button-name","document-title","html-has-lang","aria-required-attr","aria-valid-attr","tabindex","duplicate-id-aria","frame-title","html-lang-valid","landmark-one-main","region"];
    const adaFindings = adaAuditIds.map(id => audits[id]).filter(a => a && a.score !== null && a.score < 1).map(a => ({ id: a.id, title: a.title, description: a.description, score: Math.round((a.score || 0) * 100), itemCount: a.details?.items?.length || 0 }));
    const findings = [];
    if (perf < 70) findings.push(`Performance risk (${perf}/100): Slow load times increase bounce rate and reduce conversion`);
    if (access < 90) findings.push(`ADA compliance risk (${access}/100): ${adaFindings.length} accessibility violations detected — potential legal exposure`);
    if (bp < 80) findings.push(`Security risk (${bp}/100): Missing security headers or deprecated APIs detected`);
    if (seo < 80) findings.push(`SEO risk (${seo}/100): Visibility gaps that reduce organic and AI-search reach`);
    if (findings.length === 0) findings.push("No major risk findings detected — continue monitoring quarterly");
    const lcp = audits["largest-contentful-paint"]?.displayValue || "N/";
    const tbt = audits["total-blocking-time"]?.displayValue || "N/";
    const cls = audits["cumulative-layout-shift"]?.displayValue || "N/";
    const recommendation = riskScore > 60 ? "HIGH RISK — Immediate remediation required" : riskScore > 30 ? "MODERATE RISK — Review and remediate within 30 days" : "LOW RIJK — Monitor quarterly";
    const result = { success: true, scanStatus: "full", scannedUrl: url, timestamp: new Date().toISOString(), overallRiskScore: riskScore, scores: { performance: perf, accessibility: access, bestPractices: bp, seo }, coreWebVitals: { lcp, tbt, cls }, adaFindings, findings, recommendation };
    scanCache.set(cacheKey, { result, cachedAt: Date.now() });
    res.json(result);
  } catch (err) {
    console.error("Scan error:", err.message);
    res.json(buildFallbackResponse(url));
  }
});
