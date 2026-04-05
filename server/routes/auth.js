const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const AuditLog = require("../models/AuditLog");
const authenticate = require("../middleware/authenticate");
const logger = require("../utils/logger");

const router = express.Router();

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || "");
}

router.post("/register", async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Valid email is required" });
    }

    if (!password || password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const user = await User.create({
      email: email.toLowerCase().trim(),
      password
    });

    await AuditLog.create({
      userId: user._id,
      action: "auth.register",
      details: { email: user.email }
    });

    logger.info("User registered", { userId: user._id.toString(), email: user.email });
    return res.status(201).json({
      message: "User created",
      user: {
        id: user._id,
        email: user.email,
        apiKey: user.apiKey,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    return next(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (!validateEmail(email) || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.authenticate(email, password);
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        tokenVersion: user.tokenVersion
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
    );

    await AuditLog.create({
      userId: user._id,
      action: "auth.login",
      details: { email: user.email }
    });

    logger.info("User logged in", { userId: user._id.toString() });
    return res.status(200).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        apiKey: user.apiKey
      }
    });
  } catch (error) {
    return next(error);
  }
});

router.post("/logout", authenticate, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.tokenVersion += 1;
    await user.save();

    await AuditLog.create({
      userId: user._id,
      action: "auth.logout",
      details: { reason: "token_invalidated" }
    });

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
