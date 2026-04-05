const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  apiKey: {
    type: String,
    unique: true,
    index: true
  },
  tokenVersion: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.pre("save", async function preSave(next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 12);
  }

  if (!this.apiKey) {
    this.apiKey = this.generateApiKey();
  }

  next();
});

userSchema.methods.generateApiKey = function generateApiKey() {
  return crypto.randomBytes(24).toString("hex");
};

userSchema.methods.authenticate = async function authenticate(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.statics.authenticate = async function authenticate(email, password) {
  const user = await this.findOne({ email: email.toLowerCase().trim() });
  if (!user) {
    return null;
  }

  const isValid = await user.authenticate(password);
  return isValid ? user : null;
};

module.exports = mongoose.model("User", userSchema);
