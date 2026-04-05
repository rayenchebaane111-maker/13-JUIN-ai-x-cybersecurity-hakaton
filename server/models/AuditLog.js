const mongoose = require("mongoose");

const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true
  },
  action: {
    type: String,
    required: true,
    trim: true
  },
  details: {
    type: Object,
    default: {}
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
});

auditLogSchema.index({ userId: 1, timestamp: -1 });

module.exports = mongoose.model("AuditLog", auditLogSchema);
