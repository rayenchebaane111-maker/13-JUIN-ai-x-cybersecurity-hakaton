const express = require("express");
const EmailAnalysis = require("../models/EmailAnalysis");
const AuditLog = require("../models/AuditLog");
const authenticate = require("../middleware/authenticate");
const { userDailyLimiter } = require("../middleware/rateLimiter");
const emailAnalyzer = require("../services/emailAnalyzer");
const llmAnalyzer = require("../services/llmAnalyzer");
const logger = require("../utils/logger");

const router = express.Router();

function validateAnalyzePayload(payload = {}) {
  const sender = typeof payload.sender === "string" ? payload.sender.trim() : "";
  const subject = typeof payload.subject === "string" ? payload.subject.trim() : "";
  const body = typeof payload.body === "string" ? payload.body.trim() : "";

  if (!sender && !subject && !body) {
    return "At least one of sender, subject, or body is required";
  }

  if (payload.links && !Array.isArray(payload.links)) {
    return "links must be an array";
  }

  if (payload.attachments && !Array.isArray(payload.attachments)) {
    return "attachments must be an array";
  }

  return null;
}

router.post("/analyze", authenticate, userDailyLimiter, async (req, res, next) => {
  try {
    const validationError = validateAnalyzePayload(req.body || {});
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const payload = {
      sender: req.body.sender || "",
      subject: req.body.subject || "",
      body: req.body.body || "",
      links: Array.isArray(req.body.links) ? req.body.links : [],
      attachments: Array.isArray(req.body.attachments) ? req.body.attachments : []
    };

    logger.info("Analysis request received", {
      userId: req.user.id.toString(),
      sender: payload.sender,
      subjectLength: payload.subject.length,
      bodyLength: payload.body.length,
      linkCount: payload.links.length
    });

    const ruleResult = emailAnalyzer.analyzeEmail(payload);
    let result = ruleResult;

    if (llmAnalyzer.shouldCallLLM(ruleResult, payload)) {
      logger.info("Running LLM semantic analysis", {
        userId: req.user.id.toString(),
        ruleScore: ruleResult.threatScore
      });
      const llmResult = await llmAnalyzer.analyze(payload, ruleResult);
      result = llmAnalyzer.merge(ruleResult, llmResult);
    }

    const analysis = await EmailAnalysis.create({
      userId: req.user.id,
      sender: payload.sender,
      subject: payload.subject,
      body: payload.body,
      links: payload.links,
      attachments: payload.attachments,
      threatScore: result.threatScore,
      threatLevel: result.threatLevel,
      detections: result.detections,
      explanations: result.explanations
    });

    await AuditLog.create({
      userId: req.user.id,
      action: "analysis.created",
      details: {
        analysisId: analysis._id,
        threatScore: result.threatScore,
        threatLevel: result.threatLevel
      }
    });

    return res.status(201).json({
      analysisId: analysis._id,
      ...result,
      timestamp: analysis.timestamp
    });
  } catch (error) {
    return next(error);
  }
});

router.post("/analyze/sync", authenticate, userDailyLimiter, async (req, res, next) => {
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];

    if (!items.length) {
      return res.status(400).json({ error: "items array is required" });
    }

    const cappedItems = items.slice(0, 100);
    const inserted = [];

    for (const item of cappedItems) {
      const payload = {
        sender: item.sender || "",
        subject: item.subject || "",
        body: item.body || "",
        links: Array.isArray(item.links) ? item.links : [],
        attachments: Array.isArray(item.attachments) ? item.attachments : []
      };

      const ruleResult = emailAnalyzer.analyzeEmail(payload);
      let result = ruleResult;

      if (llmAnalyzer.shouldCallLLM(ruleResult, payload)) {
        const llmResult = await llmAnalyzer.analyze(payload, ruleResult);
        result = llmAnalyzer.merge(ruleResult, llmResult);
      }

      const doc = await EmailAnalysis.create({
        userId: req.user.id,
        sender: payload.sender,
        subject: payload.subject,
        body: payload.body,
        links: payload.links,
        attachments: payload.attachments,
        threatScore: result.threatScore,
        threatLevel: result.threatLevel,
        detections: result.detections,
        explanations: result.explanations,
        timestamp: item.timestamp ? new Date(item.timestamp) : new Date()
      });

      inserted.push({
        localId: item.localId || null,
        analysisId: doc._id,
        threatScore: doc.threatScore,
        threatLevel: doc.threatLevel
      });
    }

    await AuditLog.create({
      userId: req.user.id,
      action: "analysis.sync",
      details: {
        count: inserted.length
      }
    });

    return res.status(201).json({
      synced: inserted.length,
      items: inserted
    });
  } catch (error) {
    return next(error);
  }
});

router.get("/threat-intel", authenticate, userDailyLimiter, async (req, res, next) => {
  try {
    return res.status(200).json({
      indicators: {
        knownBadDomains: Array.from(emailAnalyzer.threatIntel.knownBadDomains),
        knownBadIPs: Array.from(emailAnalyzer.threatIntel.knownBadIPs)
      },
      note: "Local threat intelligence snapshot for offline/edge consistency"
    });
  } catch (error) {
    return next(error);
  }
});

router.get("/analyze/:id", authenticate, userDailyLimiter, async (req, res, next) => {
  try {
    const analysis = await EmailAnalysis.findOne({
      _id: req.params.id,
      userId: req.user.id
    }).lean();

    if (!analysis) {
      return res.status(404).json({ error: "Analysis not found" });
    }

    return res.status(200).json(analysis);
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
