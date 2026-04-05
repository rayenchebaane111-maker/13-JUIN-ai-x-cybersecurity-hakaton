require("dotenv").config();

const express = require("express");
const cors = require("cors");
const connectDatabase = require("./config/database");
const authRoutes = require("./routes/auth");
const analysisRoutes = require("./routes/analysis");
const historyRoutes = require("./routes/history");
const decisionRoutes = require("./routes/decisions");
const { ipLimiter } = require("./middleware/rateLimiter");
const logger = require("./utils/logger");

const app = express();
const port = Number(process.env.PORT || 3000);

app.set("trust proxy", 1);
app.use(ipLimiter);
app.use(express.json({ limit: "1mb" }));

app.use(cors({
  origin: process.env.FRONTEND_URL || "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use((req, res, next) => {
  logger.info("Incoming request", {
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get("user-agent") || ""
  });
  next();
});

app.get("/health", async (req, res) => {
  return res.status(200).json({
    status: "ok",
    service: "ai-cyber-human-shield-backend",
    timestamp: new Date().toISOString()
  });
});

app.use("/auth", authRoutes);
app.use("/api", analysisRoutes);
app.use("/api", historyRoutes);
app.use("/api", decisionRoutes);

app.use((req, res) => {
  return res.status(404).json({ error: "Route not found" });
});

app.use((error, req, res, next) => {
  logger.error("Unhandled server error", {
    message: error.message,
    stack: process.env.NODE_ENV === "production" ? undefined : error.stack,
    path: req.path,
    method: req.method
  });

  if (error.name === "ValidationError") {
    return res.status(400).json({ error: "Validation failed", details: error.message });
  }

  if (error.name === "JsonWebTokenError") {
    return res.status(401).json({ error: "Invalid token" });
  }

  if (error.name === "TokenExpiredError") {
    return res.status(401).json({ error: "Token expired" });
  }

  return res.status(500).json({ error: "Internal server error" });
});

async function start() {
  try {
    await connectDatabase();
    app.listen(port, () => {
      logger.info("Server started", { port, env: process.env.NODE_ENV || "development" });
    });
  } catch (error) {
    logger.error("Failed to start server", { error: error.message });
    process.exit(1);
  }
}

start();

process.on("unhandledRejection", (reason) => {
  logger.error("Unhandled rejection", { reason: String(reason) });
});

process.on("uncaughtException", (error) => {
  logger.error("Uncaught exception", { error: error.message });
  process.exit(1);
});
