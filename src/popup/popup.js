class PopupController {
  constructor() {
    this.currentAnalysis = null;
    this.debugModeEnabled = false;
    this.latestExtractionDebug = null;
    this.latestAnalysisDebug = null;
    this.debugger = globalThis.EmailDebugger ? new globalThis.EmailDebugger("popup") : null;

    this.views = {
      initial: document.getElementById("initialView"),
      loading: document.getElementById("loadingView"),
      error: document.getElementById("errorView"),
      main: document.getElementById("mainView"),
      logs: document.getElementById("logView")
    };

    this.elements = {
      errorText: document.getElementById("errorText"),
      retryBtn: document.getElementById("retryBtn"),
      scoreText: document.getElementById("scoreText"),
      gaugeFill: document.getElementById("gaugeFill"),
      threatLevelBadge: document.getElementById("threatLevelBadge"),
      analyzedSender: document.getElementById("analyzedSender"),
      analyzedSubject: document.getElementById("analyzedSubject"),
      analyzedAt: document.getElementById("analyzedAt"),
      analyzedBodyLength: document.getElementById("analyzedBodyLength"),
      analyzedLinksCount: document.getElementById("analyzedLinksCount"),
      analyzedFingerprint: document.getElementById("analyzedFingerprint"),
      adaptiveStatus: document.getElementById("adaptiveStatus"),
      adaptiveCount: document.getElementById("adaptiveCount"),
      adaptiveAction: document.getElementById("adaptiveAction"),
      whySummary: document.getElementById("whySummary"),
      risksList: document.getElementById("risksList"),
      blockBtn: document.getElementById("blockBtn"),
      trustBtn: document.getElementById("trustBtn"),
      ignoreBtn: document.getElementById("ignoreBtn"),
      showLogsBtn: document.getElementById("showLogsBtn"),
      backToMainBtn: document.getElementById("backToMainBtn"),
      exportLogsBtn: document.getElementById("exportLogsBtn"),
      logList: document.getElementById("logList"),
      toggleDebugBtn: document.getElementById("toggleDebugBtn"),
      debugPanel: document.getElementById("debugPanel"),
      refreshDebugBtn: document.getElementById("refreshDebugBtn"),
      exportDebugBtn: document.getElementById("exportDebugBtn"),
      debugSummary: document.getElementById("debugSummary"),
      debugOutput: document.getElementById("debugOutput")
    };
  }

  init() {
    this.bindEvents();
    this.showView("initial");
    this.analyzeActiveEmail();
  }

  bindEvents() {
    this.elements.retryBtn.addEventListener("click", () => this.analyzeActiveEmail());
    this.elements.blockBtn.addEventListener("click", () => this.logHumanDecision("block"));
    this.elements.trustBtn.addEventListener("click", () => this.logHumanDecision("trust"));
    this.elements.ignoreBtn.addEventListener("click", () => this.logHumanDecision("ignore"));

    this.elements.showLogsBtn.addEventListener("click", async () => {
      await this.renderLogs();
      this.showView("logs");
    });

    this.elements.backToMainBtn.addEventListener("click", () => {
      if (this.currentAnalysis) {
        this.showView("main");
      } else {
        this.showView("initial");
      }
    });

    this.elements.exportLogsBtn.addEventListener("click", () => this.exportLogsAsCSV());
    this.elements.toggleDebugBtn.addEventListener("click", () => this.toggleDebugPanel());
    this.elements.refreshDebugBtn.addEventListener("click", () => this.renderDebugPanel());
    this.elements.exportDebugBtn.addEventListener("click", () => this.exportDebugLog());
  }

  showView(viewName) {
    Object.values(this.views).forEach((view) => view.classList.remove("visible"));
    this.views[viewName].classList.add("visible");
  }

  async analyzeActiveEmail() {
    this.showView("loading");
    this.logDebug("popup.analysis.start", { at: new Date().toISOString() });

    try {
      if (!chrome?.runtime?.sendMessage) {
        throw new Error("Extension APIs are unavailable. Open this from the extension popup.");
      }

      const extracted = await this.extractEmailFromActiveTab();
      this.latestExtractionDebug = extracted?.debug || null;
      this.logDebug("popup.extraction.response", {
        success: extracted?.success,
        debug: extracted?.debug || null
      });

      if (!extracted || !extracted.success) {
        throw new Error(extracted?.error || "Could not extract email. Open a message in Gmail/Outlook.");
      }

      const analysisResp = await chrome.runtime.sendMessage({
        action: "analyze_email",
        emailData: extracted.data
      });
      this.latestAnalysisDebug = analysisResp?.debug || null;
      this.logDebug("popup.analysis.response", {
        success: analysisResp?.success,
        debug: analysisResp?.debug || null,
        score: analysisResp?.analysis?.threatScore
      });

      if (!analysisResp || !analysisResp.success) {
        throw new Error(analysisResp?.error || "Analysis failed.");
      }

      this.currentAnalysis = {
        ...analysisResp.analysis,
        emailData: extracted.data
      };

      this.renderMainResult(this.currentAnalysis);
      if (this.debugModeEnabled) {
        await this.renderDebugPanel();
      }
      this.showView("main");
    } catch (error) {
      this.logDebug("popup.analysis.error", { error: error.message || String(error) });
      this.elements.errorText.textContent = error.message || "Unexpected error";
      this.showView("error");
    }
  }

  async extractEmailFromActiveTab() {
    // Retry a few times because webmail DOM can finish rendering after popup opens.
    const maxAttempts = 3;
    let lastResult = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      lastResult = await this.extractEmailOnce();
      if (lastResult?.success) {
        return lastResult;
      }

      if (attempt < maxAttempts) {
        await this.delay(300);
      }
    }

    return lastResult || { success: false, error: "Unable to extract email content." };
  }

  async extractEmailOnce() {
    // Prefer direct tab messaging for speed, then fallback to background relay.
    if (chrome?.tabs?.query && chrome?.tabs?.sendMessage) {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id) {
          return await chrome.tabs.sendMessage(tab.id, { action: "extract_email" });
        }
      } catch (error) {
        // Continue to background fallback.
      }
    }

    return chrome.runtime.sendMessage({ action: "extract_active_email" });
  }

  delay(ms) {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  }

  toggleDebugPanel() {
    this.debugModeEnabled = !this.debugModeEnabled;
    this.elements.debugPanel.classList.toggle("visible", this.debugModeEnabled);
    this.elements.toggleDebugBtn.textContent = this.debugModeEnabled ? "DEBUG MODE ON" : "DEBUG MODE";
    if (this.debugModeEnabled) {
      this.renderDebugPanel();
    }
  }

  async renderDebugPanel() {
    const backgroundDumpResp = await chrome.runtime.sendMessage({ action: "get_debug_dump" });
    const bgDump = backgroundDumpResp?.debug || { total: 0, latest: [], pipeline: {} };

    const localDump = this.debugger ? await this.debugger.dumpToPopup() : { total: 0, latest: [] };

    const score = this.currentAnalysis?.threatScore ?? "N/A";
    const bodyLength = this.latestExtractionDebug?.data_extracted?.body_length ?? bgDump?.pipeline?.bodyLength ?? 0;
    const extracted = this.latestExtractionDebug?.extraction_success ? "YES" : "NO";

    this.elements.debugSummary.innerHTML = [
      `Email extracted: <strong>${extracted}</strong>`,
      `Body length analyzed: <strong>${bodyLength}</strong>`,
      `Score: <strong>${score}</strong>`,
      `Background debug entries: <strong>${bgDump.total || 0}</strong>`,
      `Popup debug entries: <strong>${localDump.total || 0}</strong>`
    ].join(" | ");

    const panelPayload = {
      extraction: this.latestExtractionDebug,
      analysis: this.latestAnalysisDebug,
      currentAnalysisDebug: this.currentAnalysis?.debug || {},
      backgroundPipeline: bgDump.pipeline || {},
      backgroundLatest: bgDump.latest || [],
      popupLatest: localDump.latest || []
    };

    this.elements.debugOutput.textContent = JSON.stringify(panelPayload, null, 2);
  }

  async exportDebugLog() {
    if (this.debugger) {
      await this.debugger.exportDebugLog();
    }
  }

  logDebug(step, data) {
    if (this.debugger) {
      this.debugger.logFullPipeline(step, data || {});
    }
  }

  renderMainResult(payload) {
    const score = payload.threatScore || 0;
    const level = (payload.threatLevel || "Low").toLowerCase();
    const extractionStats = this.latestExtractionDebug?.data_extracted || {};
    const contributionMap = this.getContributionMap(payload);

    this.elements.scoreText.textContent = String(score);
    this.elements.threatLevelBadge.textContent = payload.threatLevel || "Low";
    this.elements.threatLevelBadge.className = `threat-badge ${level}`;

    const gaugeLength = 283;
    const ratio = Math.max(0, Math.min(100, score)) / 100;
    this.elements.gaugeFill.style.strokeDashoffset = String(gaugeLength - gaugeLength * ratio);
    this.elements.gaugeFill.style.stroke = this.getThreatColor(level);

    this.elements.analyzedSender.textContent = payload?.features?.sender || this.currentAnalysis?.emailData?.sender || "Unknown";
    this.elements.analyzedSubject.textContent = this.currentAnalysis?.emailData?.subject || "No subject";
    this.elements.analyzedAt.textContent = payload?.analyzedAt
      ? new Date(payload.analyzedAt).toLocaleString()
      : new Date().toLocaleString();
    this.elements.analyzedBodyLength.textContent = String(
      extractionStats.body_length ?? ((this.currentAnalysis?.emailData?.body || "").length || 0)
    );
    this.elements.analyzedLinksCount.textContent = String(
      extractionStats.links_count ?? (Array.isArray(this.currentAnalysis?.emailData?.links) ? this.currentAnalysis.emailData.links.length : 0)
    );
    this.elements.analyzedFingerprint.textContent = extractionStats.message_fingerprint || "not-available";
    this.elements.adaptiveStatus.textContent = payload?.adaptiveSecurity?.status || "NORMAL";
    this.elements.adaptiveCount.textContent = String(payload?.adaptiveSecurity?.suspicious_count ?? 0);
    this.elements.adaptiveAction.textContent = payload?.adaptiveSecurity?.recommended_action || "NONE";

    this.renderWhySummary(payload, contributionMap, extractionStats);

    this.renderRiskCards(payload.detections || {}, contributionMap);
  }

  renderWhySummary(payload, contributionMap, extractionStats) {
    const explanations = Array.isArray(payload?.explanations) ? payload.explanations : [];
    const contributionItems = Object.values(contributionMap);

    if (contributionItems.length) {
      const topItems = contributionItems
        .sort((a, b) => b.points - a.points)
        .slice(0, 4)
        .map((entry) => `${entry.detector}: +${entry.points} (${entry.detail})`);

      this.elements.whySummary.innerHTML = `
        <strong>WHY this score:</strong>
        <div>${this.escapeHtml(topItems.join("; "))}</div>
        <div>Extracted body length: ${this.escapeHtml(String(extractionStats?.body_length ?? 0))}, links: ${this.escapeHtml(String(extractionStats?.links_count ?? 0))}</div>
        ${payload?.adaptiveSecurity?.explanation ? `<div>Adaptive: ${this.escapeHtml(payload.adaptiveSecurity.explanation)}</div>` : ""}
      `;
      return;
    }

    const firstThree = explanations.slice(0, 3).map((item) => item.reason).filter(Boolean);
    if (firstThree.length) {
      this.elements.whySummary.innerHTML = `
        <strong>WHY signals found:</strong>
        <div>${this.escapeHtml(firstThree.join(" | "))}</div>
      `;
      return;
    }

    this.elements.whySummary.innerHTML = "<strong>WHY:</strong> No suspicious indicators found in the extracted content.";
  }

  renderRiskCards(detections, contributionMap) {
    const entries = Object.entries(detections).filter(([, result]) => result.detected);

    if (!entries.length) {
      this.elements.risksList.innerHTML = "<p>No risk indicators found.</p>";
      return;
    }

    this.elements.risksList.innerHTML = entries
      .map(([name, result], idx) => {
        const detailId = `risk-detail-${idx}`;
        const confidence = Math.round(result.confidence || 0);
        const barColor = this.getConfidenceColor(confidence);
        const contribution = contributionMap[name] || null;
        const scoreImpactLabel = contribution ? `+${contribution.points} pts` : `${confidence}%`;

        const indicatorHtml = result.indicators
          .map(
            (ind) => `
            <div class="why">
              <strong>${this.escapeHtml(ind.reason)}</strong>
              <p>${this.escapeHtml(ind.explanation)}</p>
              <ul class="evidence-list">
                ${(ind.evidence || []).map((ev) => `<li>${this.escapeHtml(String(ev))}</li>`).join("")}
              </ul>
            </div>
          `
          )
          .join("");

        return `
          <article class="risk-card">
            <button class="risk-head" data-target="${detailId}">
              <span>${this.humanize(name)}</span>
              <span>${this.escapeHtml(scoreImpactLabel)}</span>
            </button>
            <div class="risk-detail" id="${detailId}">
              ${contribution ? `<p><strong>Score impact:</strong> ${this.escapeHtml(String(contribution.points))} point(s). ${this.escapeHtml(contribution.detail || "")}</p>` : ""}
              ${indicatorHtml}
              <div class="confidence-wrap">
                <div class="confidence-bar"><span style="width:${confidence}%; background:${barColor};"></span></div>
                <div class="confidence-text">Confidence: ${confidence}%</div>
              </div>
            </div>
          </article>
        `;
      })
      .join("");

    this.elements.risksList.querySelectorAll(".risk-head").forEach((btn) => {
      btn.addEventListener("click", () => {
        const detail = document.getElementById(btn.dataset.target);
        detail.classList.toggle("open");
      });
    });
  }

  getContributionMap(payload) {
    const raw = payload?.debug?.scoreContributions;
    if (!Array.isArray(raw)) {
      return {};
    }

    return raw.reduce((acc, item) => {
      if (!item?.detector) {
        return acc;
      }

      acc[item.detector] = {
        detector: item.detector,
        points: Number(item.points || 0),
        detail: item.detail || ""
      };
      return acc;
    }, {});
  }

  async logHumanDecision(action) {
    if (!this.currentAnalysis) {
      return;
    }

    await chrome.runtime.sendMessage({
      action: "log_decision",
      decision: {
        action,
        context: {
          threatScore: this.currentAnalysis.threatScore,
          threatLevel: this.currentAnalysis.threatLevel,
          sender: this.currentAnalysis.emailData?.sender || "",
          subject: this.currentAnalysis.emailData?.subject || ""
        }
      }
    });

    await this.renderLogs();
    this.showView("logs");
  }

  async renderLogs() {
    const response = await chrome.runtime.sendMessage({ action: "get_logs" });
    const logs = response?.logs || [];

    if (!logs.length) {
      this.elements.logList.innerHTML = "<li class='log-item'>No logs yet.</li>";
      return;
    }

    this.elements.logList.innerHTML = logs
      .map((item) => {
        if (item.type === "analysis") {
          return `
            <li class="log-item">
              <strong>${this.escapeHtml(item.threatLevel || "Unknown")} (${item.threatScore ?? "-"})</strong>
              <div>${this.escapeHtml(item.sender || "Unknown sender")}</div>
              <div>${this.escapeHtml(item.subject || "No subject")}</div>
              <small>${this.escapeHtml(item.timestamp || "")}</small>
            </li>
          `;
        }

        return `
          <li class="log-item">
            <strong>Decision: ${this.escapeHtml(item.decision || "unknown")}</strong>
            <div>Threat: ${this.escapeHtml(String(item.context?.threatLevel || "N/A"))}</div>
            <small>${this.escapeHtml(item.timestamp || "")}</small>
          </li>
        `;
      })
      .join("");
  }

  async exportLogsAsCSV() {
    const response = await chrome.runtime.sendMessage({ action: "get_logs" });
    const logs = response?.logs || [];

    if (!logs.length) {
      return;
    }

    const rows = [
      ["type", "decision", "threatScore", "threatLevel", "sender", "subject", "timestamp"],
      ...logs.map((item) => [
        item.type || "",
        item.decision || "",
        item.threatScore ?? "",
        item.threatLevel || "",
        item.sender || item.context?.sender || "",
        item.subject || item.context?.subject || "",
        item.timestamp || ""
      ])
    ];

    const csv = rows
      .map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(","))
      .join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threat-log-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  getThreatColor(level) {
    if (level === "critical") return "#F44336";
    if (level === "high") return "#FF6F00";
    if (level === "medium") return "#FFC107";
    return "#4CAF50";
  }

  getConfidenceColor(value) {
    if (value >= 75) return "#F44336";
    if (value >= 50) return "#FF6F00";
    if (value >= 25) return "#FFC107";
    return "#4CAF50";
  }

  humanize(name) {
    return name
      .split("_")
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ");
  }

  escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const controller = new PopupController();
  controller.init();
});
