const express = require("express");
const UserDecision = require("../models/UserDecision");
const AuditLog = require("../models/AuditLog");
const authenticate = require("../middleware/authenticate");
const { userDailyLimiter } = require("../middleware/rateLimiter");

const router = express.Router();

router.post("/decisions", authenticate, userDailyLimiter, async (req, res, next) => {
  try {
    const { analysisId, decision } = req.body || {};

    if (!analysisId) {
      return res.status(400).json({ error: "analysisId is required" });
    }

    if (!["block", "trust", "ignore"].includes(decision)) {
      return res.status(400).json({ error: "decision must be one of: block, trust, ignore" });
    }

    const item = await UserDecision.create({
      userId: req.user.id,
      analysisId,
      decision
    });

    await AuditLog.create({
      userId: req.user.id,
      action: "decision.logged",
      details: {
        analysisId,
        decision
      }
    });

    return res.status(201).json(item);
  } catch (error) {
    return next(error);
  }
});

router.get("/decisions", authenticate, userDailyLimiter, async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip = (page - 1) * limit;

    const [items, total] = await Promise.all([
      UserDecision.find({ userId: req.user.id }).sort({ timestamp: -1 }).skip(skip).limit(limit).lean(),
      UserDecision.countDocuments({ userId: req.user.id })
    ]);

    return res.status(200).json({
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      items
    });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
