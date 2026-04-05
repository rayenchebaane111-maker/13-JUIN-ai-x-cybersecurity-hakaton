const mongoose = require("mongoose");

const emailAnalysisSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true
  },
  sender: { type: String, default: "" },
  subject: { type: String, default: "" },
  body: { type: String, default: "" },
  threatScore: { type: Number, required: true, min: 0, max: 100 },
  threatLevel: { type: String, required: true, enum: ["Low", "Medium", "High", "Critical"] },
  detections: { type: Object, required: true },
  explanations: { type: Array, default: [] },
  links: { type: Array, default: [] },
  attachments: { type: Array, default: [] },
  timestamp: { type: Date, default: Date.now, index: true }
});

emailAnalysisSchema.index({ userId: 1, timestamp: -1 });

module.exports = mongoose.model("EmailAnalysis", emailAnalysisSchema);
