const BEHAVIOR_DB_KEY = "adaptive_behavior_db";
const MAX_HISTORY_PER_SENDER = 50;

function normalizeSender(sender) {
  return String(sender || "").trim().toLowerCase();
}

export async function getDatabase() {
  const data = await chrome.storage.local.get(BEHAVIOR_DB_KEY);
  const db = data?.[BEHAVIOR_DB_KEY];

  if (db && typeof db === "object") {
    return {
      senders: db.senders || {},
      blacklist: db.blacklist || {}
    };
  }

  return {
    senders: {},
    blacklist: {}
  };
}

export async function saveDatabase(db) {
  await chrome.storage.local.set({
    [BEHAVIOR_DB_KEY]: {
      senders: db.senders || {},
      blacklist: db.blacklist || {}
    }
  });
}

export async function checkBlacklist(sender) {
  const normalized = normalizeSender(sender);
  if (!normalized) {
    return false;
  }

  const db = await getDatabase();
  return Boolean(db.blacklist[normalized]);
}

export async function addToBlacklist(sender, reason = "manual") {
  const normalized = normalizeSender(sender);
  if (!normalized) {
    return { success: false, reason: "invalid_sender" };
  }

  const db = await getDatabase();
  db.blacklist[normalized] = {
    sender: normalized,
    reason,
    timestamp: new Date().toISOString()
  };

  await saveDatabase(db);
  return { success: true, sender: normalized };
}

export async function updateSenderBehavior(sender, threatScore, indicators = []) {
  const normalized = normalizeSender(sender);
  const timestamp = new Date().toISOString();

  if (!normalized) {
    return {
      status: "NORMAL",
      suspicious_count: 0,
      recommended_action: "NONE",
      explanation: "Sender missing, adaptive sender tracking skipped.",
      evidence: []
    };
  }

  const db = await getDatabase();
  const senderRecord = db.senders[normalized] || {
    sender: normalized,
    suspicious_count: 0,
    history: []
  };

  const cleanIndicators = (Array.isArray(indicators) ? indicators : [])
    .map((value) => String(value || "").trim())
    .filter(Boolean)
    .slice(0, 20);

  senderRecord.history.unshift({
    timestamp,
    score: Number(threatScore || 0),
    indicators: cleanIndicators
  });
  senderRecord.history = senderRecord.history.slice(0, MAX_HISTORY_PER_SENDER);

  if (Number(threatScore || 0) >= 70) {
    senderRecord.suspicious_count += 1;
  }

  const blacklisted = Boolean(db.blacklist[normalized]);
  const { status, recommended_action } = classifyEscalation(senderRecord.suspicious_count, blacklisted);

  senderRecord.status = status;
  senderRecord.last_seen = timestamp;
  db.senders[normalized] = senderRecord;

  await saveDatabase(db);

  return {
    status,
    suspicious_count: senderRecord.suspicious_count,
    recommended_action,
    explanation: buildExplanation(status, senderRecord.suspicious_count, blacklisted),
    evidence: buildEvidence(senderRecord.history, blacklisted)
  };
}

function classifyEscalation(suspiciousCount, blacklisted) {
  if (blacklisted || suspiciousCount >= 10) {
    return {
      status: "COORDINATED ATTACK",
      recommended_action: "BLOCK_AND_BLACKLIST"
    };
  }

  if (suspiciousCount >= 5) {
    return {
      status: "RECURRING THREAT",
      recommended_action: "MONITOR"
    };
  }

  return {
    status: "NORMAL",
    recommended_action: "NONE"
  };
}

function buildExplanation(status, suspiciousCount, blacklisted) {
  if (blacklisted) {
    return `Sender is blacklisted. Immediate escalation applied. Historical suspicious count: ${suspiciousCount}.`;
  }

  if (status === "COORDINATED ATTACK") {
    return `Sender reached ${suspiciousCount} high-risk emails (>=70). This indicates a coordinated attack pattern. Human review should block and blacklist sender.`;
  }

  if (status === "RECURRING THREAT") {
    return `Sender reached ${suspiciousCount} high-risk emails (>=70). Repeated suspicious behavior detected. Continue monitoring and validate before trust.`;
  }

  return `Sender suspicious count is ${suspiciousCount}. No escalation threshold reached.`;
}

function buildEvidence(history, blacklisted) {
  const recent = history.slice(0, 5).map((entry) => ({
    timestamp: entry.timestamp,
    score: entry.score,
    indicators: entry.indicators
  }));

  if (blacklisted) {
    return [{ type: "blacklist", detail: "sender_in_blacklist" }, ...recent];
  }

  return recent;
}
