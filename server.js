const express = require("express");
const cors = require("cors");
const PDFDocument = require("pdfkit");
const cron = require("node-cron");

const app = express();

app.use(cors());
app.use(express.json());

// In-memory store for monitored URLs (upgrade to DB in production)
const monitoredUrls = new Map();

// ─────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", version: "2.0" });
});

// ─────────────────────────────────────────────
// FULL SCAN — Lighthouse + ADA via PageSpeed Insights
// ─────────────────────────────────────────────
app.post("/scan", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });

  try {
    const apiKey = process.env.PAGESPEED_API_KEY || "";
    const categories = "category=performance&category=accessibility&category=best-practices&category=seo";
    const psiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=desktop&${categories}${apiKey ? "&key=" + apiKey : ""}`;

    const response = await fetch(psiUrl, { signal: AbortSignal.timeout(35000) });
    const data = await response.json();

    if (data.error) throw new Error(data.error.message);

    const cats = data.lighthouseResult?.categories || {};
    const audits = data.lighthouseResult?.audits || {};

    const perf   = Math.round((cats.performance?.score       || 0) * 100);
    const access = Math.round((cats.accessibility?.score     || 0) * 100);
    const bp     = Math.round((cats["best-practices"]?.score || 0) * 100);
    const seo    = Math.round((cats.seo?.score               || 0) * 100);

    const avgScore  = (perf + access + bp + seo) / 4;
    const riskScore = Math.round(100 - avgScore);

    // ADA-specific audit checks
    const adaAuditIds = [
      "color-contrast","image-alt","label","link-name","button-name",
      "document-title","html-has-lang","aria-required-attr","aria-valid-attr",
      "tabindex","duplicate-id-aria","frame-title","html-lang-valid",
      "landmark-one-main","region"
    ];
    const adaFindings = adaAuditIds
      .map(id => audits[id])
      .filter(a => a && a.score !== null && a.score < 1)
      .map(a => ({
        id: a.id,
        title: a.title,
        description: a.description,
        score: Math.round((a.score || 0) * 100),
        itemCount: a.details?.items?.length || 0
      }));

    // Human-readable risk findings
    const findings = [];
    if (perf   < 70) findings.push(`Performance risk (${perf}/100): Slow load times increase bounce rate and reduce conversion`);
    if (access < 90) findings.push(`ADA compliance risk (${access}/100): ${adaFindings.length} accessibility violations detected — potential legal exposure`);
    if (bp     < 80) findings.push(`Security risk (${bp}/100): Missing security headers or deprecated APIs detected`);
    if (seo    < 80) findings.push(`SEO risk (${seo}/100): Visibility gaps that reduce organic and AI-search reach`);
    if (findings.length === 0) findings.push("No major risk findings detected — continue monitoring quarterly");

    // Core Web Vitals
    const lcp = audits["largest-contentful-paint"]?.displayValue || "N/A";
    const tbt = audits["total-blocking-time"]?.displayValue       || "N/A";
    const cls = audits["cumulative-layout-shift"]?.displayValue   || "N/A";

    const recommendation =
      riskScore > 60 ? "HIGH RISK — Immediate remediation required" :
      riskScore > 30 ? "MODERATE RISK — Review and remediate within 30 days" :
                       "LOW RISK — Monitor quarterly";

    res.json({
      success: true,
      scannedUrl: url,
      timestamp: new Date().toISOString(),
      overallRiskScore: riskScore,
      scores: { performance: perf, accessibility: access, bestPractices: bp, seo },
      coreWebVitals: { lcp, tbt, cls },
      adaFindings,
      findings,
      recommendation
    });

  } catch (err) {
    console.error("Scan error:", err.message);
    res.status(500).json({ error: "Scan failed", message: err.message });
  }
});

// ─────────────────────────────────────────────
// PDF REPORT GENERATION
// ─────────────────────────────────────────────
app.post("/report/pdf", async (req, res) => {
  const { scanData } = req.body;
  if (!scanData) return res.status(400).json({ error: "Scan data required" });

  try {
    const doc = new PDFDocument({ margin: 50, size: "A4" });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="zynagi-risk-report-${Date.now()}.pdf"`);
    doc.pipe(res);

    const BLACK = "#000000";
    const GRAY  = "#666666";
    const LGRAY = "#aaaaaa";
    const RED   = "#cc2200";
    const AMBER = "#ff8800";
    const GREEN = "#009944";
    const BLUE  = "#0055cc";

    const riskColor  = scanData.overallRiskScore > 60 ? RED : scanData.overallRiskScore > 30 ? AMBER : GREEN;
    const scoreColor = (s) => s >= 90 ? GREEN : s >= 70 ? AMBER : RED;

    // Header bar
    doc.rect(0, 0, 595, 80).fill("#0a0a0a");
    doc.fontSize(26).font("Helvetica-Bold").fillColor("#ffffff").text("ZYNAGI", 50, 22);
    doc.fontSize(10).font("Helvetica").fillColor("#888888").text("AI RISK INTELLIGENCE REPORT", 50, 55);
    doc.fillColor("#ffffff").fontSize(9).text("CONFIDENTIAL", 460, 36);

    // URL + timestamp
    doc.fillColor(BLACK).fontSize(11).font("Helvetica-Bold").text("Scanned URL:", 50, 100);
    doc.fontSize(11).font("Helvetica").fillColor(BLUE).text(scanData.scannedUrl, 50, 116, { link: scanData.scannedUrl });
    doc.fillColor(GRAY).fontSize(9).text(
      `Report generated: ${new Date(scanData.timestamp || Date.now()).toLocaleString("en-US", { dateStyle: "long", timeStyle: "short" })}`,
      50, 134
    );

    // Risk score
    doc.moveTo(50, 155).lineTo(545, 155).lineWidth(0.5).stroke("#dddddd");
    doc.fontSize(12).font("Helvetica-Bold").fillColor(BLACK).text("OVERALL RISK SCORE", 50, 168);
    doc.fontSize(60).font("Helvetica-Bold").fillColor(riskColor).text(`${scanData.overallRiskScore}`, 50, 185);
    doc.fontSize(10).font("Helvetica").fillColor(GRAY).text(`/ 100  ·  ${scanData.recommendation}`, 130, 222);

    // Category scores
    doc.moveTo(50, 255).lineTo(545, 255).lineWidth(0.5).stroke("#dddddd");
    doc.fontSize(12).font("Helvetica-Bold").fillColor(BLACK).text("CATEGORY SCORES", 50, 268);

    const scoreRows = [
      ["Performance",         scanData.scores?.performance],
      ["Accessibility (ADA)", scanData.scores?.accessibility],
      ["Best Practices",      scanData.scores?.bestPractices],
      ["SEO",                 scanData.scores?.seo],
    ];

    let y = 292;
    scoreRows.forEach(([label, score]) => {
      doc.fontSize(11).font("Helvetica").fillColor(BLACK).text(label, 50, y);
      doc.rect(250, y + 2, 200, 10).fill("#eeeeee");
      doc.rect(250, y + 2, Math.round(score * 2), 10).fill(scoreColor(score));
      doc.fontSize(11).font("Helvetica-Bold").fillColor(scoreColor(score)).text(`${score}/100`, 462, y);
      y += 26;
    });

    // Core Web Vitals
    doc.moveTo(50, y + 6).lineTo(545, y + 6).lineWidth(0.5).stroke("#dddddd");
    y += 20;
    doc.fontSize(12).font("Helvetica-Bold").fillColor(BLACK).text("CORE WEB VITALS", 50, y);
    y += 22;
    [
      ["Largest Contentful Paint (LCP)", scanData.coreWebVitals?.lcp],
      ["Total Blocking Time (TBT)",      scanData.coreWebVitals?.tbt],
      ["Cumulative Layout Shift (CLS)",  scanData.coreWebVitals?.cls],
    ].forEach(([label, val]) => {
      doc.fontSize(10).font("Helvetica").fillColor(GRAY).text(label + ":", 50, y);
      doc.font("Helvetica-Bold").fillColor(BLACK).text(val || "N/A", 320, y);
      y += 18;
    });

    // Risk findings
    doc.moveTo(50, y + 8).lineTo(545, y + 8).lineWidth(0.5).stroke("#dddddd");
    y += 22;
    doc.fontSize(12).font("Helvetica-Bold").fillColor(BLACK).text("RISK FINDINGS", 50, y);
    y += 20;
    (scanData.findings || []).forEach(finding => {
      if (y > 720) { doc.addPage(); y = 50; }
      doc.fontSize(10).font("Helvetica").fillColor("#333333").text(`• ${finding}`, 50, y, { width: 495 });
      y += doc.heightOfString(finding, { width: 495 }) + 8;
    });

    // ADA violations
    if (scanData.adaFindings?.length > 0) {
      if (y > 650) { doc.addPage(); y = 50; }
      doc.moveTo(50, y + 8).lineTo(545, y + 8).lineWidth(0.5).stroke("#dddddd");
      y += 22;
      doc.fontSize(12).font("Helvetica-Bold").fillColor(BLACK).text("ADA ACCESSIBILITY VIOLATIONS", 50, y);
      y += 20;
      scanData.adaFindings.slice(0, 10).forEach(issue => {
        if (y > 710) { doc.addPage(); y = 50; }
        doc.fontSize(10).font("Helvetica-Bold").fillColor(RED).text(`x  ${issue.title}`, 50, y);
        y += 16;
        doc.fontSize(9).font("Helvetica").fillColor(GRAY).text(issue.description, 65, y, { width: 480 });
        y += doc.heightOfString(issue.description, { width: 480 }) + 12;
      });
    }

    // Footer
    doc.fontSize(8).fillColor(LGRAY).text(
      "ZYNAGI AI Risk Intelligence  |  zynagi.com  |  Confidential — Not for distribution",
      50, 810, { align: "center", width: 495 }
    );

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
  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(503).json({ error: "Stripe not configured" });
  }
  const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
  const { plan, email } = req.body;

  const plans = {
    starter:    { price: process.env.STRIPE_PRICE_STARTER },
    growth:     { price: process.env.STRIPE_PRICE_GROWTH },
    enterprise: { price: process.env.STRIPE_PRICE_ENTERPRISE },
  };

  if (!plans[plan]?.price) {
    return res.status(400).json({ error: "Invalid plan or price not configured" });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      customer_email: email,
      line_items: [{ price: plans[plan].price, quantity: 1 }],
      success_url: `https://zynagi.com/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `https://zynagi.com/ai-risk-assessment`,
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
  monitoredUrls.set(url, {
    email,
    frequency: frequency || "weekly",
    addedAt: new Date().toISOString(),
    lastScanned: null,
    lastScore: null,
  });
  res.json({ success: true, message: `${url} is now being monitored ${frequency || "weekly"}` });
});

app.delete("/monitor/remove", (req, res) => {
  const { url } = req.body;
  monitoredUrls.delete(url);
  res.json({ success: true });
});

app.get("/monitor/list", (req, res) => {
  const list = Array.from(monitoredUrls.entries()).map(([url, data]) => ({ url, ...data }));
  res.json({ monitored: list });
});

// Cron: run at 8am UTC daily
cron.schedule("0 8 * * *", async () => {
  console.log(`[Cron] Monitoring scans — ${new Date().toISOString()}`);
  const isMonday = new Date().getDay() === 1;

  for (const [url, data] of monitoredUrls.entries()) {
    if (data.frequency === "daily" || (data.frequency === "weekly" && isMonday)) {
      try {
        const psiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=desktop&category=accessibility&category=performance`;
        const r = await fetch(psiUrl, { signal: AbortSignal.timeout(30000) });
        const d = await r.json();
        const acc = Math.round((d.lighthouseResult?.categories?.accessibility?.score || 0) * 100);
        const prf = Math.round((d.lighthouseResult?.categories?.performance?.score  || 0) * 100);
        monitoredUrls.set(url, { ...data, lastScanned: new Date().toISOString(), lastScore: { accessibility: acc, performance: prf } });
        console.log(`[Cron] ${url} -> ADA: ${acc}, Perf: ${prf}`);
      } catch (e) {
        console.error(`[Cron] Failed for ${url}:`, e.message);
      }
    }
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`ZYNAGI Scanner API v2.0 on port ${PORT}`));
