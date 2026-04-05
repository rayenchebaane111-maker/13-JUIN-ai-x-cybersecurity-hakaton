import "../utils/debugger.js";
import { DetectorOrchestrator } from "./detector-orchestrator.js";
import {
  updateSenderBehavior,
  checkBlacklist,
  addToBlacklist
} from "./behavior-tracker.js";

const orchestrator = new DetectorOrchestrator();
const THREAT_LOG_KEY = "threat_log";
const MAX_LOG_ENTRIES = 100;
const TAG = "[AI-CYBER-SHIELD][BG]";
const debuggerInstance = globalThis.EmailDebugger ? new globalThis.EmailDebugger("background") : null;

function log(step, payload) {
  console.log(`${TAG} ${step}`, payload || "");
  if (debuggerInstance) {
    debuggerInstance.logFullPipeline(`background.${step}`, payload || {});
  }
}

function summarizeEmailData(emailData) {
  const base = `${emailData?.sender || ""}|${emailData?.subject || ""}|${(emailData?.body || "").slice(0, 500)}`;
  let hash = 0;
  for (let i = 0; i < base.length; i += 1) {
    hash = ((hash << 5) - hash) + base.charCodeAt(i);
    hash |= 0;
  }

  return {
    provider: emailData?.provider || "unknown",
    sender: emailData?.sender || "",
    subject: emailData?.subject || "",
    bodyLength: (emailData?.body || "").length,
    linkCount: Array.isArray(emailData?.links) ? emailData.links.length : 0,
    attachmentCount: Array.isArray(emailData?.attachments) ? emailData.attachments.length : 0,
    fingerprint: `fp_${Math.abs(hash)}`
  };
}

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await getLogs();
  if (!Array.isArray(existing)) {
    await setLogs([]);
  }
  log("Extension installed", { existingLogs: existing.length });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.action) {
    log("Ignored message without action", { message });
    return false;
  }

  log("Message received", {
    action: message.action,
    senderTabId: sender?.tab?.id,
    senderUrl: sender?.tab?.url || sender?.url || ""
  });
  if (debuggerInstance) {
    debuggerInstance.logFullPipeline("background.message.received", {
      action: message.action,
      senderTabId: sender?.tab?.id,
      senderUrl: sender?.tab?.url || sender?.url || ""
    });
  }

  (async () => {
    try {
      if (message.action === "analyze_email") {
        const emailData = message.emailData || {};
        const emailSummary = summarizeEmailData(emailData);
        log("Analyzing email data", emailSummary);

        if (!emailSummary.bodyLength) {
          log("WARNING: No body received", emailSummary);
        }

        let analysis = orchestrator.analyzeEmail(emailData);

        const sender = emailData.sender || "";

        const isSenderBlacklisted = await checkBlacklist(sender);
        if (isSenderBlacklisted) {
          // Human-in-the-loop: we escalate and recommend actions, but never auto-execute.
          const blacklistExplanation = {
            detector: "adaptive_security",
            type: "blacklisted_sender",
            reason: "Sender previously blacklisted",
            explanation: "This sender exists in local blacklist from prior high-risk behavior. Treat as coordinated attack and require human confirmation before any action.",
            confidence: 100,
            evidence: [sender]
          };

          analysis = {
            ...analysis,
            threatScore: Math.max(analysis.threatScore || 0, 90),
            threatLevel: "Critical",
            detections: {
              ...(analysis.detections || {}),
              adaptive_blacklist: {
                detected: true,
                confidence: 100,
                indicators: [blacklistExplanation]
              }
            },
            explanations: [
              ...(analysis.explanations || []),
              blacklistExplanation
            ]
          };
        }

        const indicatorTypes = Object.entries(analysis.detections || {})
          .filter(([, result]) => result?.detected)
          .flatMap(([, result]) => (result.indicators || []).map((indicator) => indicator.type || "signal"));

        const adaptiveSecurity = await updateSenderBehavior(
          sender,
          analysis.threatScore,
          indicatorTypes
        );

        analysis = {
          ...analysis,
          adaptiveSecurity,
          explanations: [
            ...(analysis.explanations || []),
            {
              detector: "adaptive_security",
              type: "behavior_escalation",
              reason: `Adaptive status: ${adaptiveSecurity.status}`,
              explanation: adaptiveSecurity.explanation,
              confidence: 100,
              evidence: adaptiveSecurity.evidence
            }
          ]
        };

        if (adaptiveSecurity.status === "COORDINATED ATTACK") {
          analysis = {
            ...analysis,
            threatScore: Math.max(analysis.threatScore || 0, 85),
            threatLevel: "Critical"
          };
        } else if (adaptiveSecurity.status === "RECURRING THREAT") {
          analysis = {
            ...analysis,
            threatScore: Math.max(analysis.threatScore || 0, 70),
            threatLevel: analysis.threatLevel === "Low" || analysis.threatLevel === "Medium" ? "High" : analysis.threatLevel
          };
        }

        if (debuggerInstance) {
          await debuggerInstance.logFullPipeline("detector.analysis.complete", {
            threatScore: analysis.threatScore,
            threatLevel: analysis.threatLevel,
            scoreContributions: analysis.debug?.scoreContributions || [],
            adaptiveSecurity
          });
        }
        log("Detector returned analysis", {
          threatScore: analysis.threatScore,
          threatLevel: analysis.threatLevel,
          adaptiveStatus: analysis.adaptiveSecurity?.status || "NORMAL",
          triggeredDetectors: Object.entries(analysis.detections || {})
            .filter(([, result]) => result.detected)
            .map(([key]) => key)
        });

        Object.entries(analysis.detections || {}).forEach(([detectorName, detectorResult]) => {
          log("Detector detail", {
            detector: detectorName,
            detected: detectorResult.detected,
            confidence: detectorResult.confidence,
            indicatorCount: detectorResult.indicators?.length || 0
          });
        });

        log("Score calculation breakdown", {
          threatScore: analysis.threatScore,
          scoreContributions: analysis.debug?.scoreContributions || [],
          adaptiveSecurity: analysis.adaptiveSecurity || {}
        });

        const logEntry = {
          id: crypto.randomUUID(),
          type: "analysis",
          emailProvider: emailData.provider || "unknown",
          sender: emailData.sender || "",
          subject: emailData.subject || "",
          threatScore: analysis.threatScore,
          threatLevel: analysis.threatLevel,
          explanations: analysis.explanations,
          adaptiveSecurity: analysis.adaptiveSecurity || {},
          debug: analysis.debug || {},
          timestamp: new Date().toISOString()
        };

        await appendLog(logEntry);
        log("Analysis response sent", {
          threatScore: analysis.threatScore,
          threatLevel: analysis.threatLevel
        });
        sendResponse({
          success: true,
          analysis,
          debug: {
            received_email_summary: emailSummary,
            adaptive_security: analysis.adaptiveSecurity || {},
            analyzer_debug: analysis.debug || {}
          }
        });
        return;
      }

      if (message.action === "get_logs") {
        const logs = await getLogs();
        log("Returning logs", { count: logs.length });
        sendResponse({ success: true, logs });
        return;
      }

      if (message.action === "get_debug_dump") {
        const dump = debuggerInstance ? await debuggerInstance.dumpToPopup() : { total: 0, latest: [], pipeline: {} };
        sendResponse({ success: true, debug: dump });
        return;
      }

      if (message.action === "export_debug_log") {
        const payload = debuggerInstance ? await debuggerInstance.exportDebugLog() : { exportedAt: new Date().toISOString(), total: 0, logs: [] };
        sendResponse({ success: true, exported: payload });
        return;
      }

      if (message.action === "extract_active_email") {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab || !tab.id) {
          log("extract_active_email failed", { reason: "no_active_tab" });
          sendResponse({ success: false, error: "No active tab found." });
          return;
        }

        const url = tab.url || "";
        const isSupportedHost =
          url.startsWith("https://mail.google.com/") ||
          url.startsWith("https://outlook.live.com/") ||
          url.startsWith("https://outlook.office.com/");

        if (!isSupportedHost) {
          log("extract_active_email failed", { reason: "unsupported_host", url });
          sendResponse({
            success: false,
            error: "Active tab is not Gmail/Outlook. Open an email in a supported webmail tab."
          });
          return;
        }

        log("Requesting extraction from content script", { tabId: tab.id, url });
        let extracted;

        try {
          extracted = await chrome.tabs.sendMessage(tab.id, { action: "extract_email" });
        } catch (error) {
          const msg = error?.message || "";
          const missingReceiver = msg.includes("Receiving end does not exist") || msg.includes("Could not establish connection");

          if (!missingReceiver) {
            throw error;
          }

          log("Content script receiver missing, attempting script injection", {
            tabId: tab.id,
            error: msg
          });

          // Recover after extension reload or tab opened before content-script registration.
          await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ["src/utils/debugger.js", "src/content/contentScript.js"]
          });

          extracted = await chrome.tabs.sendMessage(tab.id, { action: "extract_email" });
        }

        log("Content script extraction response", {
          success: extracted?.success,
          debug: extracted?.debug || null
        });
        sendResponse(extracted || { success: false, error: "No response from content script." });
        return;
      }

      if (message.action === "log_decision") {
        const decision = message.decision || {};

        // Human action can promote sender to blacklist, but only when explicitly chosen.
        if (decision.action === "block" && decision.context?.sender) {
          await addToBlacklist(decision.context.sender, "user_block_decision");
          log("Sender added to blacklist from decision", {
            sender: decision.context.sender
          });
        }

        const logEntry = {
          id: crypto.randomUUID(),
          type: "decision",
          decision: decision.action || "unknown",
          context: decision.context || {},
          timestamp: new Date().toISOString()
        };

        await appendLog(logEntry);
        log("Decision logged", { decision: logEntry.decision, context: logEntry.context });
        sendResponse({ success: true });
        return;
      }

      log("Unknown action", { action: message.action });
      sendResponse({ success: false, error: "Unknown action" });
    } catch (error) {
      console.error(`${TAG} Message handling error`, error);
      sendResponse({ success: false, error: error.message || "Background error" });
    }
  })();

  return true;
});

async function getLogs() {
  const data = await chrome.storage.local.get(THREAT_LOG_KEY);
  return Array.isArray(data[THREAT_LOG_KEY]) ? data[THREAT_LOG_KEY] : [];
}

async function setLogs(logs) {
  await chrome.storage.local.set({ [THREAT_LOG_KEY]: logs.slice(0, MAX_LOG_ENTRIES) });
}

async function appendLog(entry) {
  const logs = await getLogs();
  const next = [entry, ...logs].slice(0, MAX_LOG_ENTRIES);
  await setLogs(next);
}
