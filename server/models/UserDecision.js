const mongoose = require("mongoose");

const userDecisionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true
  },
  analysisId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "EmailAnalysis",
    required: true
  },
  decision: {
    type: String,
    enum: ["block", "trust", "ignore"],
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
});

userDecisionSchema.index({ userId: 1, timestamp: -1 });

module.exports = mongoose.model("UserDecision", userDecisionSchema);
