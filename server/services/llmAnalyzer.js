const logger = require("../utils/logger");

class LLMAnalyzer {
  constructor() {
    this.enabled = String(process.env.LLM_ENABLED || "false").toLowerCase() === "true";
    this.apiKey = process.env.LLM_API_KEY || "";
    this.baseUrl = process.env.LLM_BASE_URL || "https://api.openai.com/v1";
    this.model = process.env.LLM_MODEL || "gpt-4o-mini";
    this.timeoutMs = Number(process.env.LLM_TIMEOUT_MS || 12000);
    this.weight = Number(process.env.LLM_WEIGHT || 0.3);
    this.alwaysOn = String(process.env.LLM_ALWAYS_ON || "false").toLowerCase() === "true";
    this.domainProfile = process.env.LLM_DOMAIN_PROFILE || "general phishing defense";
    this.priorityLabels = this.readListEnv("LLM_PRIORITY_LABELS", [
      "credential_harvest",
      "business_email_compromise",
      "payment_fraud",
      "impersonation"
    ]);
    this.decisionPolicy = process.env.LLM_DECISION_POLICY || "Prefer caution for financial/account-access requests with urgency";
  }

  isConfigured() {
    return this.enabled && Boolean(this.apiKey);
  }

  shouldCallLLM(ruleResult, emailData) {
    if (!this.isConfigured()) {
      return false;
    }

    if (this.alwaysOn) {
      return true;
    }

    const score = Number(ruleResult?.threatScore || 0);
    const bodyLen = String(emailData?.body || "").length;

    // Use LLM primarily for borderline or long-context cases.
    return (score >= 20 && score <= 80) || bodyLen > 450;
  }

  buildPrompt(emailData, ruleResult) {
    return [
      "You are a phishing-risk classifier.",
      `Domain profile: ${this.domainProfile}`,
      `Priority labels: ${this.priorityLabels.join(", ")}`,
      `Decision policy: ${this.decisionPolicy}`,
      "Return ONLY strict JSON with this schema:",
      "{",
      '  "threatScoreHint": number 0-100,',
      '  "threatLevelHint": "Low"|"Medium"|"High"|"Critical",',
      '  "rationale": string,',
      '  "riskLabels": string[],',
      '  "extractedSignals": string[]',
      "}",
      "No markdown and no extra text.",
      "Prioritize phishing semantics, impersonation intent, coercion urgency, suspicious links, and financial fraud cues.",
      "Email payload:",
      JSON.stringify({
        sender: emailData.sender || "",
        subject: emailData.subject || "",
        body: emailData.body || "",
        links: emailData.links || [],
        attachments: emailData.attachments || []
      }),
      "Rule engine baseline:",
      JSON.stringify({
        threatScore: ruleResult?.threatScore || 0,
        threatLevel: ruleResult?.threatLevel || "Low",
        detections: Object.keys(ruleResult?.detections || {})
      })
    ].join("\n");
  }

  async analyze(emailData, ruleResult) {
    if (!this.isConfigured()) {
      return {
        used: false,
        reason: "llm_not_configured"
      };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const prompt = this.buildPrompt(emailData, ruleResult);

      const response = await fetch(`${this.baseUrl.replace(/\/$/, "")}/chat/completions`, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({
          model: this.model,
          temperature: 0,
          messages: [
            {
              role: "system",
              content: "You output strict JSON only."
            },
            {
              role: "user",
              content: prompt
            }
          ]
        })
      });

      if (!response.ok) {
        const body = await response.text();
        logger.warn("LLM API non-200", { status: response.status, body: body.slice(0, 500) });
        return { used: false, reason: "llm_http_error" };
      }

      const payload = await response.json();
      const content = payload?.choices?.[0]?.message?.content || "";
      const parsed = this.safeParseJSON(content);

      if (!parsed) {
        logger.warn("LLM returned non-JSON content", { content: String(content).slice(0, 500) });
        return { used: false, reason: "llm_invalid_json" };
      }

      const normalized = this.normalizeOutput(parsed);
      return {
        used: true,
        output: normalized
      };
    } catch (error) {
      logger.warn("LLM call failed", { error: error.message });
      return { used: false, reason: "llm_exception" };
    } finally {
      clearTimeout(timeout);
    }
  }

  merge(ruleResult, llmResult) {
    if (!llmResult?.used || !llmResult.output) {
      return {
        ...ruleResult,
        debug: {
          ...(ruleResult.debug || {}),
          llm: {
            used: false,
            reason: llmResult?.reason || "not_used"
          }
        }
      };
    }

    const llm = llmResult.output;
    const ruleScore = Number(ruleResult.threatScore || 0);
    const llmScore = Number(llm.threatScoreHint || 0);
    const weight = Math.max(0, Math.min(1, this.weight));
    const mergedScore = Math.round((ruleScore * (1 - weight)) + (llmScore * weight));

    const explanations = [
      ...(ruleResult.explanations || []),
      {
        detector: "llm_semantic",
        type: "semantic_assessment",
        reason: "LLM semantic review applied",
        explanation: llm.rationale,
        confidence: Math.min(95, Math.max(40, Math.round(llmScore))),
        evidence: [...(llm.riskLabels || []), ...(llm.extractedSignals || [])]
      }
    ];

    const detections = {
      ...(ruleResult.detections || {}),
      llm_semantic: {
        detected: (llm.riskLabels || []).length > 0 || llmScore >= 50,
        confidence: Math.min(100, Math.max(0, Math.round(llmScore))),
        indicators: [
          {
            type: "llm_semantic",
            reason: "LLM semantic interpretation",
            explanation: llm.rationale,
            confidence: Math.min(100, Math.max(0, Math.round(llmScore))),
            evidence: [...(llm.riskLabels || []), ...(llm.extractedSignals || [])]
          }
        ]
      }
    };

    return {
      ...ruleResult,
      threatScore: mergedScore,
      threatLevel: this.levelFromScore(mergedScore),
      detections,
      explanations,
      debug: {
        ...(ruleResult.debug || {}),
        llm: {
          used: true,
          model: this.model,
          llmScoreHint: llmScore,
          mergeWeight: weight,
          riskLabels: llm.riskLabels
        }
      }
    };
  }

  normalizeOutput(obj) {
    const score = Number(obj.threatScoreHint);

    return {
      threatScoreHint: Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : 0,
      threatLevelHint: ["Low", "Medium", "High", "Critical"].includes(obj.threatLevelHint)
        ? obj.threatLevelHint
        : this.levelFromScore(score || 0),
      rationale: typeof obj.rationale === "string" ? obj.rationale.slice(0, 3000) : "No rationale provided.",
      riskLabels: Array.isArray(obj.riskLabels) ? obj.riskLabels.slice(0, 20).map((x) => String(x)) : [],
      extractedSignals: Array.isArray(obj.extractedSignals) ? obj.extractedSignals.slice(0, 30).map((x) => String(x)) : []
    };
  }

  safeParseJSON(content) {
    if (!content || typeof content !== "string") {
      return null;
    }

    const trimmed = content.trim();

    try {
      return JSON.parse(trimmed);
    } catch (error) {
      const match = trimmed.match(/\{[\s\S]*\}/);
      if (!match) {
        return null;
      }
      try {
        return JSON.parse(match[0]);
      } catch (error2) {
        return null;
      }
    }
  }

  levelFromScore(score) {
    const s = Math.max(0, Math.min(100, Number(score) || 0));
    if (s >= 75) return "Critical";
    if (s >= 50) return "High";
    if (s >= 25) return "Medium";
    return "Low";
  }

  readListEnv(name, defaults) {
    const raw = process.env[name];
    if (!raw) {
      return defaults;
    }

    const parsed = raw
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);

    return parsed.length ? parsed : defaults;
  }
}

module.exports = new LLMAnalyzer();
