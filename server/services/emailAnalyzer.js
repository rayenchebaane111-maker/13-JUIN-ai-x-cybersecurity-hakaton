class EmailAnalyzer {
  constructor() {
    this.phishingKeywords = this.readListEnv("PHISHING_KEYWORDS", [
      "verify",
      "account suspended",
      "account locked",
      "password reset",
      "confirm identity",
      "security alert",
      "urgent action",
      "click now",
      "update billing",
      "unusual activity"
    ]);

    this.urgencyKeywords = this.readListEnv("URGENCY_KEYWORDS", [
      "urgent",
      "immediately",
      "act now",
      "asap",
      "final notice",
      "last chance",
      "within 24 hours"
    ]);

    this.financialKeywords = this.readListEnv("FINANCIAL_KEYWORDS", [
      "wire transfer",
      "bank account",
      "routing number",
      "swift",
      "credit card",
      "bitcoin",
      "gift card",
      "crypto"
    ]);

    this.shorteners = new Set(this.readListEnv("URL_SHORTENERS", ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "cutt.ly"]));
    this.suspiciousTlds = this.readListEnv("SUSPICIOUS_TLDS", [".tk", ".top", ".xyz", ".click", ".work", ".gq", ".ml"]);
    this.threatIntel = {
      knownBadIPs: new Set(this.readListEnv("KNOWN_BAD_IPS", ["185.220.101.42", "45.95.147.201", "103.15.28.77"])),
      knownBadDomains: new Set(this.readListEnv("KNOWN_BAD_DOMAINS", ["secure-bankverify.tk", "vendor-payments-check.top", "hr-alert-check.xyz"]))
    };

    this.scoring = {
      phishingKeywordPoint: this.readNumberEnv("SCORE_PHISHING_PER_KEYWORD", 8),
      urgencyKeywordPoint: this.readNumberEnv("SCORE_URGENCY_PER_KEYWORD", 6),
      maliciousLinkPoint: this.readNumberEnv("SCORE_LINK_PER_SIGNAL", 8),
      senderPoint: this.readNumberEnv("SCORE_SENDER_PER_SIGNAL", 5),
      financialKeywordPoint: this.readNumberEnv("SCORE_FINANCIAL_PER_KEYWORD", 5),
      intelPoint: this.readNumberEnv("SCORE_INTEL_PER_MATCH", 15)
    };

    this.thresholds = {
      lowMax: this.readNumberEnv("THRESHOLD_LOW_MAX", 24),
      mediumMax: this.readNumberEnv("THRESHOLD_MEDIUM_MAX", 49),
      highMax: this.readNumberEnv("THRESHOLD_HIGH_MAX", 74)
    };
  }

  analyzeEmail(emailData = {}) {
    const sender = (emailData.sender || "").toLowerCase();
    const subject = (emailData.subject || "").toLowerCase();
    const body = (emailData.body || "").toLowerCase();
    const analysisText = `${subject}\n${body}`;

    if (!sender && !subject && !body) {
      return {
        threatScore: 0,
        threatLevel: "Low",
        detections: this.emptyDetections(),
        explanations: [
          {
            detector: "no_data",
            reason: "No content provided",
            explanation: "No sender, subject, or body was provided to analyze.",
            confidence: 100,
            evidence: []
          }
        ],
        threatIntel: {
          hits: []
        }
      };
    }

    const links = this.extractLinks(emailData.links, analysisText);
    const detections = {
      phishing_text: this.detectKeywordSet("phishing_text", this.phishingKeywords, analysisText, "Phishing phrases"),
      urgency: this.detectKeywordSet("urgency", this.urgencyKeywords, analysisText, "Urgency language"),
      financial_scam: this.detectKeywordSet("financial_scam", this.financialKeywords, analysisText, "Financial scam cues"),
      malicious_link: this.detectMaliciousLinks(links),
      suspicious_sender: this.detectSender(sender),
      threat_intel: this.detectThreatIntel(links, analysisText)
    };

    const scoring = this.calculateScore(detections);

    const explanations = [
      {
        detector: "score_breakdown",
        reason: `Threat score ${scoring.score}`,
        explanation: scoring.breakdown.join("; ") || "No suspicious indicators found.",
        confidence: 100,
        evidence: scoring.evidence
      },
      ...this.flattenDetectionExplanations(detections)
    ];

    return {
      threatScore: scoring.score,
      threatLevel: this.getThreatLevel(scoring.score),
      detections,
      explanations,
      threatIntel: {
        hits: detections.threat_intel.indicators.map((ind) => ind.type)
      }
    };
  }

  detectKeywordSet(detector, keywords, text, reason) {
    const matched = keywords.filter((kw) => text.includes(kw));

    if (!matched.length) {
      return {
        detected: false,
        confidence: 0,
        indicators: [],
        matchedKeywords: []
      };
    }

    const confidence = Math.min(95, 25 + matched.length * 15);
    return {
      detected: true,
      confidence,
      matchedKeywords: matched,
      indicators: [
        {
          type: detector,
          reason: `Found ${matched.length} ${reason.toLowerCase()}`,
          explanation: `${reason} were found in the email content.`,
          confidence,
          evidence: matched
        }
      ]
    };
  }

  detectMaliciousLinks(links) {
    const indicators = [];

    links.forEach((link) => {
      const domain = this.extractDomain(link.href || "");
      if (!domain) {
        return;
      }

      if (this.shorteners.has(domain)) {
        indicators.push({
          type: "url_shortener",
          reason: "Shortened URL detected",
          explanation: "Shorteners can hide final phishing destinations.",
          confidence: 85,
          evidence: [link.href]
        });
      }

      if (this.suspiciousTlds.some((tld) => domain.endsWith(tld))) {
        indicators.push({
          type: "suspicious_tld",
          reason: "Suspicious TLD detected",
          explanation: "This domain TLD is frequently abused by phishing campaigns.",
          confidence: 80,
          evidence: [domain]
        });
      }

      if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/i.test(link.href || "")) {
        indicators.push({
          type: "ip_hosted_url",
          reason: "IP-hosted URL detected",
          explanation: "Raw IP URLs are unusual for legitimate organizations.",
          confidence: 90,
          evidence: [link.href]
        });
      }
    });

    return {
      detected: indicators.length > 0,
      confidence: indicators.length ? Math.min(100, 45 + indicators.length * 15) : 0,
      indicators
    };
  }

  detectSender(sender) {
    const indicators = [];

    if (!sender || !sender.includes("@")) {
      indicators.push({
        type: "missing_sender",
        reason: "Sender is missing or malformed",
        explanation: "A valid sender address is required for trust validation.",
        confidence: 65,
        evidence: [sender || "empty"]
      });
    }

    const domain = sender.split("@")[1] || "";
    if (domain && /(secure|verify|alert|notice)/i.test(domain) && !/\.(com|org|net)$/i.test(domain)) {
      indicators.push({
        type: "suspicious_sender_domain",
        reason: "Sender domain has suspicious naming pattern",
        explanation: "Sender domain appears crafted to look official.",
        confidence: 72,
        evidence: [domain]
      });
    }

    return {
      detected: indicators.length > 0,
      confidence: indicators.length ? Math.min(95, 35 + indicators.length * 20) : 0,
      indicators
    };
  }

  detectThreatIntel(links, text) {
    const indicators = [];

    links.forEach((link) => {
      const domain = this.extractDomain(link.href || "");
      if (domain && this.threatIntel.knownBadDomains.has(domain)) {
        indicators.push({
          type: "known_bad_domain",
          reason: "Domain matched local threat intelligence",
          explanation: "The destination domain exists in local known-bad intelligence.",
          confidence: 95,
          evidence: [domain]
        });
      }
    });

    const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
    const ips = text.match(ipRegex) || [];

    ips.forEach((ip) => {
      if (this.threatIntel.knownBadIPs.has(ip)) {
        indicators.push({
          type: "known_bad_ip",
          reason: "IP matched local threat intelligence",
          explanation: "The IP appears in local known malicious indicators.",
          confidence: 95,
          evidence: [ip]
        });
      }
    });

    return {
      detected: indicators.length > 0,
      confidence: indicators.length ? 95 : 0,
      indicators
    };
  }

  calculateScore(detections) {
    let score = 0;
    const breakdown = [];
    const evidence = [];

    const add = (name, points, why, ev = []) => {
      if (points <= 0) return;
      score += points;
      breakdown.push(`${name} +${points} (${why})`);
      evidence.push(...ev);
    };

    const phishingCount = detections.phishing_text.matchedKeywords.length;
    add("phishing_text", Math.min(35, phishingCount * this.scoring.phishingKeywordPoint), `${phishingCount} keyword(s)`, detections.phishing_text.matchedKeywords);

    const urgencyCount = detections.urgency.matchedKeywords.length;
    add("urgency", Math.min(20, urgencyCount * this.scoring.urgencyKeywordPoint), `${urgencyCount} urgency term(s)`, detections.urgency.matchedKeywords);

    const linkFlags = detections.malicious_link.indicators.length;
    add("malicious_link", Math.min(40, linkFlags * this.scoring.maliciousLinkPoint), `${linkFlags} suspicious link signal(s)`, detections.malicious_link.indicators.map((x) => x.type));

    const senderFlags = detections.suspicious_sender.indicators.length;
    add("suspicious_sender", Math.min(10, senderFlags * this.scoring.senderPoint), `${senderFlags} sender signal(s)`, detections.suspicious_sender.indicators.map((x) => x.type));

    const financialCount = detections.financial_scam.matchedKeywords.length;
    add("financial_scam", Math.min(15, financialCount * this.scoring.financialKeywordPoint), `${financialCount} financial keyword(s)`, detections.financial_scam.matchedKeywords);

    const intelFlags = detections.threat_intel.indicators.length;
    add("threat_intel", Math.min(30, intelFlags * this.scoring.intelPoint), `${intelFlags} threat-intel match(es)`, detections.threat_intel.indicators.map((x) => x.type));

    score = Math.min(100, Math.max(0, Math.round(score)));

    return { score, breakdown, evidence };
  }

  getThreatLevel(score) {
    if (score > this.thresholds.highMax) return "Critical";
    if (score > this.thresholds.mediumMax) return "High";
    if (score > this.thresholds.lowMax) return "Medium";
    return "Low";
  }

  readListEnv(name, defaults) {
    const raw = process.env[name];
    if (!raw) {
      return defaults;
    }

    const parsed = raw
      .split(",")
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean);

    return parsed.length ? parsed : defaults;
  }

  readNumberEnv(name, fallback) {
    const value = Number(process.env[name]);
    return Number.isFinite(value) ? value : fallback;
  }

  flattenDetectionExplanations(detections) {
    const list = [];
    Object.entries(detections).forEach(([detector, result]) => {
      (result.indicators || []).forEach((indicator) => {
        list.push({ detector, ...indicator });
      });
    });
    return list;
  }

  extractDomain(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (error) {
      return "";
    }
  }

  extractLinks(linksInput, text) {
    const fromArray = Array.isArray(linksInput)
      ? linksInput.map((item) => ({ href: item?.href || "", text: item?.text || "" }))
      : [];

    const fromText = [];
    const urlRegex = /https?:\/\/[^\s)\]"'>]+/gi;
    const matches = text.match(urlRegex) || [];
    matches.forEach((href) => fromText.push({ href, text: "" }));

    const merged = [...fromArray, ...fromText].filter((item) => item.href);
    const seen = new Set();

    return merged.filter((item) => {
      if (seen.has(item.href)) {
        return false;
      }
      seen.add(item.href);
      return true;
    });
  }

  emptyDetections() {
    const base = { detected: false, confidence: 0, indicators: [] };
    return {
      phishing_text: { ...base, matchedKeywords: [] },
      urgency: { ...base, matchedKeywords: [] },
      financial_scam: { ...base, matchedKeywords: [] },
      malicious_link: { ...base },
      suspicious_sender: { ...base },
      threat_intel: { ...base }
    };
  }
}

module.exports = new EmailAnalyzer();
