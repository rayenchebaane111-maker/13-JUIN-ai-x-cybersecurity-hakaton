const rateLimit = require("express-rate-limit");

const userDailyBucket = new Map();

function getDayKey(date = new Date()) {
  return date.toISOString().slice(0, 10);
}

const ipLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests from this IP. Please retry in a minute." }
});

function userDailyLimiter(req, res, next) {
  if (!req.user || !req.user.id) {
    return next();
  }

  const day = getDayKey();
  const key = `${req.user.id.toString()}:${day}`;
  const current = userDailyBucket.get(key) || 0;

  if (current >= 1000) {
    return res.status(429).json({ error: "Daily user request limit exceeded" });
  }

  userDailyBucket.set(key, current + 1);
  return next();
}

module.exports = {
  ipLimiter,
  userDailyLimiter
};
