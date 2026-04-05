const mongoose = require("mongoose");
const logger = require("../utils/logger");

async function connectDatabase() {
  const uri = process.env.MONGODB_URI;

  if (!uri) {
    throw new Error("MONGODB_URI is not set");
  }

  mongoose.connection.on("connected", () => {
    logger.info("MongoDB connected");
  });

  mongoose.connection.on("error", (error) => {
    logger.error("MongoDB connection error", { error: error.message });
  });

  mongoose.connection.on("disconnected", () => {
    logger.warn("MongoDB disconnected");
  });

  await mongoose.connect(uri, {
    maxPoolSize: 20,
    minPoolSize: 3,
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    family: 4
  });

  return mongoose.connection;
}

module.exports = connectDatabase;
