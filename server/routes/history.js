const express = require("express");
const EmailAnalysis = require("../models/EmailAnalysis");
const authenticate = require("../middleware/authenticate");
const { userDailyLimiter } = require("../middleware/rateLimiter");

const router = express.Router();

router.get("/history", authenticate, userDailyLimiter, async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip = (page - 1) * limit;

    const query = { userId: req.user.id };

    if (req.query.sender) {
      query.sender = { $regex: req.query.sender, $options: "i" };
    }

    if (req.query.threatLevel) {
      query.threatLevel = req.query.threatLevel;
    }

    if (req.query.startDate || req.query.endDate) {
      query.timestamp = {};
      if (req.query.startDate) query.timestamp.$gte = new Date(req.query.startDate);
      if (req.query.endDate) query.timestamp.$lte = new Date(req.query.endDate);
    }

    const [items, total] = await Promise.all([
      EmailAnalysis.find(query).sort({ timestamp: -1 }).skip(skip).limit(limit).lean(),
      EmailAnalysis.countDocuments(query)
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

router.get("/history/stats", authenticate, userDailyLimiter, async (req, res, next) => {
  try {
    const match = { userId: req.user.id };

    const [counts, average] = await Promise.all([
      EmailAnalysis.aggregate([
        { $match: match },
        { $group: { _id: "$threatLevel", count: { $sum: 1 } } }
      ]),
      EmailAnalysis.aggregate([
        { $match: match },
        { $group: { _id: null, averageScore: { $avg: "$threatScore" }, total: { $sum: 1 } } }
      ])
    ]);

    return res.status(200).json({
      byThreatLevel: counts,
      averageScore: average[0]?.averageScore || 0,
      totalAnalyses: average[0]?.total || 0
    });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
