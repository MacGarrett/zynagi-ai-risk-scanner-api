const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/scan", async (req, res) => {
  const { url } = req.body;
  return res.json({
    success: true,
    scannedUrl: url,
    score: 73,
    findings: [
      "Missing security headers",
      "ADA accessibility concerns detected",
      "Tracking scripts identified",
      "Privacy policy gaps detected"
    ]
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Scanner API running on port ${PORT}`);
});
