const jwt = require("jsonwebtoken");
const User = require("../models/User");

async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const payload = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(payload.userId).select("_id email apiKey tokenVersion");
    if (!user) {
      return res.status(401).json({ error: "Invalid token user" });
    }

    if (payload.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({ error: "Token has been invalidated" });
    }

    req.user = {
      id: user._id,
      email: user.email,
      apiKey: user.apiKey
    };

    return next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

module.exports = authenticate;
