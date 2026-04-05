export class DetectorOrchestrator {
  constructor() {
    this.shorteners = new Set(["bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "rb.gy", "cutt.ly"]);
    this.suspiciousTlds = [".tk", ".top", ".xyz", ".click", ".gq", ".ml", ".work"];
    this.freeMailDomains = new Set(["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me"]);
    this.brandDomains = [
      "paypal.com",
      "amazon.com",
      "apple.com",
      "microsoft.com",
      "google.com",
      "bankofamerica.com",
      "chase.com",
      "wellsfargo.com"
    ];
    this.blacklistedIPs = new Set(["185.220.101.42", "45.95.147.201", "103.15.28.77"]);

    this.phishingKeywords = [
      "verify",
      "account suspended",
      "account locked",
      "password reset",
      "confirm identity",
      "security alert",
      "unusual activity",
      "click now",
      "update billing",
      "login immediately"
    ];

    this.urgencyKeywords = [
      "urgent",
      "immediately",
      "act now",
      "asap",
      "final notice",
      "last chance",
      "within 24 hours",
      "expires today"
    ];

    this.financialKeywords = [
      "wire transfer",
      "bank account",
      "routing number",
      "swift",
      "credit card",
      "bitcoin",
      "gift card",
      "crypto payment"
    ];
  }

  analyzeEmail(emailData) {
    const safeEmail = emailData || {};
    const features = this.extractFeatures(safeEmail);

    // If there is no content to analyze, return score 0 as safe/unknown.
    if (!features.hasContent) {
      const detections = this.emptyDetections();
      return {
        threatScore: 0,
        threatLevel: "Low",
        detections,
        explanations: [
          {
            detector: "no_data",
            type: "no_email_content",
            reason: "No email content was extracted",
            explanation: "Body, subject, sender, and links were empty, so no phishing analysis could be performed.",
            confidence: 100,
            evidence: []
          }
        ],
        features: {
          provider: safeEmail.provider || "unknown",
          sender: "",
          urlCount: 0,
          ipCount: 0
        },
        debug: {
          noData: true,
          note: "Returning score 0 because extracted content is empty"
        },
        analyzedAt: new Date().toISOString()
      };
    }

    const detections = this.runDetectors(features);
    const scoreDetails = this.calculateScoreDetails(detections);
    const explanations = this.generateExplanations(detections, scoreDetails);

    return {
      threatScore: scoreDetails.total,
      threatLevel: this.getThreatLevel(scoreDetails.total),
      detections,
      explanations,
      features: {
        provider: safeEmail.provider || "unknown",
        sender: features.sender,
        urlCount: features.urls.length,
        ipCount: features.ips.length
      },
      debug: {
        keywordMatches: {
          phishing: detections.phishing_text.matchedKeywords,
          urgency: detections.urgency.matchedKeywords,
          financial: detections.financial_scam.matchedKeywords
        },
        scoreContributions: scoreDetails.contributions,
        senderAnalysis: detections.suspicious_sender.debug
      },
      analyzedAt: new Date().toISOString()
    };
  }

  extractFeatures(emailData) {
    const sender = (emailData.sender || "").toLowerCase();
    const subject = (emailData.subject || "").toLowerCase();
    const body = (emailData.body || "").toLowerCase();
    const mergedText = [emailData.sender, emailData.subject, emailData.body].filter(Boolean).join("\n").toLowerCase();

    const urls = this.extractUrls(mergedText, emailData.links || []);
    const ips = this.extractIPs(mergedText);

    return {
      sender,
      subject,
      body,
      fullText: mergedText,
      analysisText: `${subject}\n${body}`,
      urls,
      ips,
      links: emailData.links || [],
      attachments: emailData.attachments || [],
      hasContent: Boolean(sender || subject || body || urls.length)
    };
  }

  runDetectors(features) {
    return {
      malicious_link: this.detectMaliciousLink(features),
      suspicious_domain: this.detectSuspiciousDomain(features),
      phishing_text: this.detectPhishingText(features),
      urgency: this.detectUrgency(features),
      social_engineering: this.detectSocialEngineering(features),
      bad_ip: this.detectBadIP(features),
      toxic_content: this.detectToxicContent(features),
      financial_scam: this.detectFinancialScam(features),
      suspicious_sender: this.detectSuspiciousSender(features)
    };
  }

  calculateScoreDetails(detections) {
    let total = 0;
    const contributions = [];

    const add = (detector, points, detail) => {
      const safePoints = Math.max(0, Math.round(points));
      total += safePoints;
      contributions.push({ detector, points: safePoints, detail });
    };

    const phishingCount = detections.phishing_text.matchedKeywords.length;
    if (phishingCount > 0) {
      add("phishing_text", Math.min(40, phishingCount * 8), `Found ${phishingCount} phishing keywords`);
    }

    const urgencyCount = detections.urgency.matchedKeywords.length;
    if (urgencyCount > 0) {
      add("urgency", Math.min(20, urgencyCount * 5), `Found ${urgencyCount} urgency keywords`);
    }

    const linkFlags = detections.malicious_link.indicators.length;
    if (linkFlags > 0) {
      add("malicious_link", Math.min(45, linkFlags * 15), `Found ${linkFlags} suspicious link signals`);
    }

    const senderFlags = detections.suspicious_sender.indicators.length;
    if (senderFlags > 0) {
      add("suspicious_sender", Math.min(15, senderFlags * 7), `Found ${senderFlags} sender red flags`);
    }

    const domainFlags = detections.suspicious_domain.indicators.length;
    if (domainFlags > 0) {
      add("suspicious_domain", Math.min(20, domainFlags * 8), `Found ${domainFlags} suspicious domain signals`);
    }

    const financialCount = detections.financial_scam.matchedKeywords.length;
    if (financialCount > 0) {
      add("financial_scam", Math.min(15, financialCount * 4), `Found ${financialCount} financial scam keywords`);
    }

    total = Math.min(100, total);
    return { total, contributions };
  }

  generateExplanations(detections, scoreDetails) {
    const explanations = [];

    Object.entries(detections).forEach(([detector, result]) => {
      if (!result.detected) {
        return;
      }

      result.indicators.forEach((indicator) => {
        explanations.push({
          detector,
          ...indicator
        });
      });
    });

    const summary = scoreDetails.contributions
      .map((entry) => `${entry.detector}: +${entry.points} (${entry.detail})`)
      .join("; ");

    explanations.unshift({
      detector: "score_breakdown",
      type: "score_explanation",
      reason: `Threat score ${scoreDetails.total} based on actual extracted content`,
      explanation: summary || "No suspicious signals found in extracted content.",
      confidence: 100,
      evidence: scoreDetails.contributions.map((entry) => `${entry.detector}:${entry.points}`)
    });

    return explanations;
  }

  getThreatLevel(score) {
    if (score >= 75) return "Critical";
    if (score >= 50) return "High";
    if (score >= 25) return "Medium";
    return "Low";
  }

  detectMaliciousLink(features) {
    const indicators = [];

    features.urls.forEach((urlObj) => {
      const domain = this.extractDomain(urlObj.href || urlObj.url || "");
      const source = urlObj.href || urlObj.url || "";
      const text = (urlObj.text || "").toLowerCase();

      if (this.isUrlShortener(domain)) {
        indicators.push({
          type: "url_shortener",
          reason: "Known URL shortener in email link",
          explanation: "Shortened links can hide the final destination and are common in phishing campaigns.",
          confidence: 90,
          evidence: [source, domain]
        });
      }

      const entropy = this.calculateEntropy(source);
      if (entropy > 4.2) {
        indicators.push({
          type: "high_entropy",
          reason: "Unusually random-looking URL",
          explanation: "High-entropy URLs often indicate generated tracking or obfuscation patterns used by attackers.",
          confidence: 70,
          evidence: [source, `entropy:${entropy.toFixed(2)}`]
        });
      }

      if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/i.test(source)) {
        indicators.push({
          type: "ip_in_url",
          reason: "Direct IP used as URL host",
          explanation: "Legitimate transactional emails rarely use raw IPs as destinations.",
          confidence: 92,
          evidence: [source]
        });
      }

      if (
        text &&
        /paypal|amazon|apple|microsoft|bank|secure|verify/i.test(text) &&
        !source.toLowerCase().includes(text.replace(/\s+/g, ""))
      ) {
        indicators.push({
          type: "text_href_mismatch",
          reason: "Displayed link text appears to brand-match but destination differs",
          explanation: "Mismatched anchor text and destination is a common phishing trick.",
          confidence: 78,
          evidence: [text, source]
        });
      }
    });

    const confidence = indicators.length ? Math.min(100, 45 + indicators.length * 15) : 0;
    return { detected: indicators.length > 0, indicators, confidence };
  }

  detectSuspiciousDomain(features) {
    const indicators = [];

    features.urls.forEach((urlObj) => {
      const href = urlObj.href || urlObj.url || "";
      const domain = this.extractDomain(href);

      if (!domain) return;

      if (this.suspiciousTlds.some((tld) => domain.endsWith(tld))) {
        indicators.push({
          type: "suspicious_tld",
          reason: "Domain uses high-risk TLD",
          explanation: "Certain low-cost TLDs are disproportionately used in phishing infrastructure.",
          confidence: 84,
          evidence: [domain]
        });
      }

      const typoResult = this.detectTyposquatting(domain);
      if (typoResult.detected) {
        indicators.push({
          type: "typosquatting",
          reason: `Domain resembles ${typoResult.target}`,
          explanation: "The domain differs by small edits from a known trusted brand domain.",
          confidence: 88,
          evidence: [domain, typoResult.target, `distance:${typoResult.distance}`]
        });
      }

      if (/[0-9]{3,}/.test(domain) || domain.split("-").length > 3) {
        indicators.push({
          type: "new_domain_pattern",
          reason: "Domain pattern looks auto-generated",
          explanation: "Random numeric-heavy or over-hyphenated domains are often throwaway phishing hosts.",
          confidence: 68,
          evidence: [domain]
        });
      }
    });

    const confidence = indicators.length ? Math.min(100, 40 + indicators.length * 14) : 0;
    return { detected: indicators.length > 0, indicators, confidence };
  }

  detectPhishingText(features) {
    const indicators = [];
    const text = features.analysisText || "";
    const found = this.phishingKeywords.filter((keyword) => text.includes(keyword));

    if (found.length) {
      indicators.push({
        type: "phishing_keywords",
        reason: "Multiple phishing-related phrases found",
        explanation: "Language pushes account fear, verification pressure, or immediate corrective action.",
        confidence: Math.min(98, 35 + found.length * 12),
        evidence: found
      });
    }

    const confidence = indicators.length ? indicators[0].confidence : 0;
    return { detected: indicators.length > 0, indicators, confidence, matchedKeywords: found };
  }

  detectUrgency(features) {
    const text = features.analysisText || "";
    const found = this.urgencyKeywords.filter((keyword) => text.includes(keyword));

    const indicators = found.length
      ? [
          {
            type: "urgency_language",
            reason: "Time-pressure wording detected",
            explanation: "Attackers use urgency to reduce critical thinking before a user verifies details.",
            confidence: Math.min(95, 30 + found.length * 13),
            evidence: found
          }
        ]
      : [];

    const confidence = indicators.length ? indicators[0].confidence : 0;
    return { detected: indicators.length > 0, indicators, confidence, matchedKeywords: found };
  }

  detectSocialEngineering(features) {
    const text = features.fullText.toLowerCase();
    const patterns = [
      { label: "bank", regex: /\bbank\b/i },
      { label: "paypal", regex: /\bpaypal\b/i },
      { label: "apple", regex: /\bapple\b/i },
      { label: "microsoft", regex: /\bmicrosoft\b/i },
      { label: "it support", regex: /\bit support\b/i },
      { label: "human resources", regex: /\bhuman resources\b|\bhr team\b/i },
      { label: "ceo", regex: /\bceo\b/i },
      { label: "finance team", regex: /\bfinance team\b/i },
      { label: "helpdesk", regex: /\bhelp\s?desk\b/i }
    ];
    const found = patterns.filter((item) => item.regex.test(text)).map((item) => item.label);

    const senderDomain = (features.sender.split("@")[1] || "").replace(/>.*/, "").trim();
    const brandMentioned = found.some((item) => ["bank", "paypal", "apple", "microsoft"].includes(item));
    const senderBrandMismatch = brandMentioned && senderDomain && !this.brandDomains.some((domain) => senderDomain.includes(domain));

    const indicators = [];
    if (found.length) {
      indicators.push({
        type: "impersonation_pattern",
        reason: "Brand or authority impersonation language detected",
        explanation: "Message content references trusted entities to influence user behavior.",
        confidence: Math.min(96, 50 + found.length * 8),
        evidence: found
      });
    }

    if (senderBrandMismatch) {
      indicators.push({
        type: "sender_brand_mismatch",
        reason: "Sender domain does not match brand referenced in message",
        explanation: "Legitimate official notices usually originate from the organization domain.",
        confidence: 89,
        evidence: [senderDomain]
      });
    }

    const confidence = indicators.length ? Math.min(100, 40 + indicators.length * 16) : 0;
    return { detected: indicators.length > 0, indicators, confidence };
  }

  detectBadIP(features) {
    const indicators = [];

    features.ips.forEach((ip) => {
      if (this.blacklistedIPs.has(ip)) {
        indicators.push({
          type: "blacklisted_ip",
          reason: "Known malicious IP observed",
          explanation: "This IP is listed in a local mock blacklist used for offline demo scoring.",
          confidence: 96,
          evidence: [ip]
        });
      }

      if (this.isPrivateIP(ip)) {
        indicators.push({
          type: "private_ip",
          reason: "Private/internal IP present in email content",
          explanation: "Raw private IP references can indicate suspicious internal-lure or technical deception text.",
          confidence: 64,
          evidence: [ip]
        });
      }
    });

    const confidence = indicators.length ? Math.min(100, 45 + indicators.length * 16) : 0;
    return { detected: indicators.length > 0, indicators, confidence };
  }

  detectToxicContent(features) {
    const toxicKeywords = ["hate", "vermin", "subhuman", "idiot", "worthless", "trash", "kill", "racist", "slur"];
    const text = features.analysisText || "";
    const found = toxicKeywords.filter((keyword) => text.includes(keyword));

    const indicators = found.length
      ? [
          {
            type: "toxic_language",
            reason: "Potentially abusive or hate-oriented language detected",
            explanation: "Toxic content can be part of coercion, intimidation, or harmful scam messaging.",
            confidence: Math.min(92, 45 + found.length * 11),
            evidence: found
          }
        ]
      : [];

    const confidence = indicators.length ? indicators[0].confidence : 0;
    return { detected: indicators.length > 0, indicators, confidence };
  }

  detectFinancialScam(features) {
    const text = features.analysisText || "";
    const found = this.financialKeywords.filter((keyword) => text.includes(keyword));

    const indicators = found.length
      ? [
          {
            type: "financial_request",
            reason: "Financial transfer/payment language detected",
            explanation: "Unexpected payment instructions are a core signal in business email compromise scams.",
            confidence: Math.min(94, 35 + found.length * 10),
            evidence: found
          }
        ]
      : [];

    const confidence = indicators.length ? indicators[0].confidence : 0;
    return { detected: indicators.length > 0, indicators, confidence, matchedKeywords: found };
  }

  detectSuspiciousSender(features) {
    const indicators = [];
    const sender = features.sender || "";
    const senderDomain = (sender.split("@")[1] || "").replace(/>.*/, "").trim();

    if (!sender || !sender.includes("@")) {
      indicators.push({
        type: "missing_sender",
        reason: "Sender address was missing or malformed",
        explanation: "Cannot validate sender authenticity without a valid sender address.",
        confidence: 60,
        evidence: [sender || "empty"]
      });
    }

    if (senderDomain && this.freeMailDomains.has(senderDomain)) {
      indicators.push({
        type: "freemail_sender",
        reason: "Sender uses free-mail domain",
        explanation: "Business-critical requests from free-mail senders can be suspicious.",
        confidence: 55,
        evidence: [senderDomain]
      });
    }

    const confidence = indicators.length ? Math.min(95, 35 + indicators.length * 18) : 0;
    return {
      detected: indicators.length > 0,
      indicators,
      confidence,
      debug: {
        sender,
        senderDomain
      }
    };
  }

  extractUrls(inputText, links) {
    const urlRegex = /https?:\/\/[^\s)\]"'>]+/gi;
    const fromText = (inputText.match(urlRegex) || []).map((href) => ({ href, text: "" }));
    const merged = [...(links || []), ...fromText]
      .filter((entry) => entry && entry.href)
      .map((entry) => ({ href: entry.href, text: entry.text || "" }));

    const seen = new Set();
    return merged.filter((entry) => {
      if (seen.has(entry.href)) {
        return false;
      }
      seen.add(entry.href);
      return true;
    });
  }

  extractIPs(text) {
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
    return Array.from(new Set(text.match(ipRegex) || []));
  }

  extractDomain(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (error) {
      return "";
    }
  }

  isUrlShortener(domain) {
    return this.shorteners.has(domain);
  }

  calculateEntropy(value) {
    if (!value) return 0;
    const str = String(value);
    const freq = {};
    for (const ch of str) {
      freq[ch] = (freq[ch] || 0) + 1;
    }

    let entropy = 0;
    Object.values(freq).forEach((count) => {
      const p = count / str.length;
      entropy -= p * Math.log2(p);
    });

    return entropy;
  }

  detectTyposquatting(domain) {
    const normalized = domain.replace(/^www\./, "");

    for (const brandDomain of this.brandDomains) {
      const dist = this.levenshteinDistance(normalized, brandDomain);
      if (dist > 0 && dist <= 2) {
        return { detected: true, target: brandDomain, distance: dist };
      }
    }

    return { detected: false, target: null, distance: null };
  }

  levenshteinDistance(a, b) {
    const rows = a.length + 1;
    const cols = b.length + 1;
    const dp = Array.from({ length: rows }, () => Array(cols).fill(0));

    for (let i = 0; i < rows; i += 1) dp[i][0] = i;
    for (let j = 0; j < cols; j += 1) dp[0][j] = j;

    for (let i = 1; i < rows; i += 1) {
      for (let j = 1; j < cols; j += 1) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,
          dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + cost
        );
      }
    }

    return dp[a.length][b.length];
  }

  isPrivateIP(ip) {
    return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(ip);
  }

  emptyDetections() {
    const base = { detected: false, indicators: [], confidence: 0 };
    return {
      malicious_link: { ...base },
      suspicious_domain: { ...base },
      phishing_text: { ...base, matchedKeywords: [] },
      urgency: { ...base, matchedKeywords: [] },
      social_engineering: { ...base },
      bad_ip: { ...base },
      toxic_content: { ...base },
      financial_scam: { ...base, matchedKeywords: [] },
      suspicious_sender: { ...base, debug: {} }
    };
  }
}
