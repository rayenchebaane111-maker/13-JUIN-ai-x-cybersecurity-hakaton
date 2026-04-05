(() => {
  "use strict";

  const TAG = "[AI-CYBER-SHIELD][CONTENT]";
  const debuggerInstance = globalThis.EmailDebugger ? new globalThis.EmailDebugger("content") : null;

  function log(step, payload) {
    console.log(`${TAG} ${step}`, payload || "");
    if (debuggerInstance) {
      debuggerInstance.logFullPipeline(`content.${step}`, payload || {});
    }
  }

  function detectProvider() {
    const hostname = window.location.hostname;
    const isGmailHost = hostname.includes("mail.google.com");
    const isOutlookHost = hostname.includes("outlook.live.com") || hostname.includes("outlook.office.com");

    if (isGmailHost) return "gmail";
    if (isOutlookHost) return "outlook";
    return "unknown";
  }

  function firstText(selectors, fieldName) {
    log("selector_scan_start", { field: fieldName, selectors });

    for (const selector of selectors) {
      const el = document.querySelector(selector);
      log("selector_tried", {
        field: fieldName,
        selector,
        found: Boolean(el),
        textLength: (el?.textContent || "").trim().length
      });

      if (el && el.textContent && el.textContent.trim()) {
        log("selector_match", { field: fieldName, selector });
        return { text: el.textContent.trim(), selector };
      }
    }

    log("selector_no_match", { field: fieldName });
    return { text: "", selector: "" };
  }

  function firstTextWithin(root, selectors, fieldName) {
    log("selector_scan_start", { field: fieldName, selectors, scoped: true });

    for (const selector of selectors) {
      const el = root ? root.querySelector(selector) : null;
      log("selector_tried", {
        field: fieldName,
        selector,
        scoped: true,
        found: Boolean(el),
        textLength: (el?.textContent || "").trim().length
      });

      if (el && el.textContent && el.textContent.trim()) {
        log("selector_match", { field: fieldName, selector, scoped: true });
        return { text: el.textContent.trim(), selector };
      }
    }

    log("selector_no_match", { field: fieldName, scoped: true });
    return { text: "", selector: "" };
  }

  function isVisible(node) {
    if (!node) return false;
    const rect = node.getBoundingClientRect();
    const style = getComputedStyle(node);
    return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
  }

  function pickBestBodyNodes(nodes) {
    const visible = nodes.filter((node) => isVisible(node));
    if (!visible.length) return [];

    const sorted = visible
      .map((node) => ({
        node,
        len: (node.innerText || node.textContent || "").trim().length
      }))
      .sort((a, b) => b.len - a.len);

    return sorted.filter((entry) => entry.len > 20).slice(0, 2).map((entry) => entry.node);
  }

  function buildMessageFingerprint(emailData) {
    const base = `${emailData.sender || ""}|${emailData.subject || ""}|${(emailData.body || "").slice(0, 500)}`;
    let hash = 0;
    for (let i = 0; i < base.length; i += 1) {
      hash = ((hash << 5) - hash) + base.charCodeAt(i);
      hash |= 0;
    }
    return `fp_${Math.abs(hash)}`;
  }

  function textFromNodes(nodes) {
    return nodes
      .map((node) => (node.innerText || node.textContent || "").trim())
      .filter(Boolean)
      .join("\n\n");
  }

  function extractLinks(container, maxLinks = 50) {
    const root = container || document;
    const links = Array.from(root.querySelectorAll("a[href]"))
      .map((a) => ({
        href: a.getAttribute("href") || "",
        text: (a.textContent || "").trim()
      }))
      .filter((link) => link.href);

    const seen = new Set();
    return links.filter((link) => {
      if (seen.has(link.href)) {
        return false;
      }
      seen.add(link.href);
      return true;
    }).slice(0, maxLinks);
  }

  function collectAttachments(selectors) {
    const values = [];
    selectors.forEach((selector) => {
      document.querySelectorAll(selector).forEach((node) => {
        const val = (node.textContent || node.getAttribute("aria-label") || "").trim();
        if (val) values.push(val);
      });
    });

    return Array.from(new Set(values));
  }

  function extractFromGmail() {
    const senderSel = [
      ".gD[email]",
      ".gD",
      ".go [email]",
      ".yW span[email]",
      "span[email][name]"
    ];
    const subjectSel = [
      ".hP",
      "h2[data-thread-perm-id]",
      "[role='heading'][data-legacy-thread-id]",
      "[aria-label*='Subject']"
    ];
    const bodySel = [
      "div.a3s.aiL",
      "div.a3s",
      "div.ii.gt",
      "div.ii"
    ];

    const visibleCards = Array.from(document.querySelectorAll("div.adn.ads")).filter(isVisible);
    const activeCard = visibleCards.length ? visibleCards[visibleCards.length - 1] : null;
    const root = activeCard || document;

    const senderData = firstTextWithin(root, senderSel, "gmail_sender");
    const subjectData = firstText(subjectSel, "gmail_subject");

    let bodySelectorUsed = "";
    let bodyNodes = [];
    for (const selector of bodySel) {
      const nodes = Array.from(root.querySelectorAll(selector)).filter((node) => {
        const text = (node.innerText || node.textContent || "").trim();
        return text.length > 20;
      });
      log("selector_tried", { field: "gmail_body", selector, nodeCount: nodes.length });
      if (nodes.length) {
        bodyNodes = pickBestBodyNodes(nodes);
        bodySelectorUsed = selector;
        log("selector_match", { field: "gmail_body", selector, nodeCount: bodyNodes.length });
        break;
      }
    }

    if (!bodyNodes.length) {
      const fallbackNodes = Array.from(document.querySelectorAll("div.a3s.aiL, div.a3s, div.ii.gt, div.ii"));
      bodyNodes = pickBestBodyNodes(fallbackNodes);
      if (bodyNodes.length) {
        bodySelectorUsed = "gmail_fallback_visible_body";
      }
    }

    const body = textFromNodes(bodyNodes);
    const links = bodyNodes.length ? bodyNodes.flatMap((node) => extractLinks(node)) : [];
    const attachments = [
      ...collectAttachments([".aQy", ".vI", ".aZo .aQw"]),
      ...collectAttachments([".aQy", ".vI", ".aZo .aQw"].map((selector) => `div.adn.ads ${selector}`))
    ];

    return {
      provider: "gmail",
      sender: senderData.text,
      subject: subjectData.text,
      body,
      links,
      attachments,
      headers: {
        page_url: location.href
      },
      timestamp: new Date().toISOString(),
      debug: {
        sender_selector: senderData.selector,
        subject_selector: subjectData.selector,
        body_selector: bodySelectorUsed,
        body_node_count: bodyNodes.length,
        active_card_found: Boolean(activeCard)
      }
    };
  }

  function extractFromOutlook() {
    const senderSel = [
      "[data-testid='messageHeader'] [title*='@']",
      "[aria-label^='From'] span",
      "[data-app-section='MessageHeader'] [title*='@']",
      "[data-is-focusable='true'][title*='@']"
    ];
    const subjectSel = [
      "[data-testid='messageHeader'] [role='heading']",
      "[aria-label^='Subject']",
      "[data-testid*='subject']"
    ];
    const bodySel = [
      "[data-testid='messageBody']",
      "[role='document']",
      "[aria-label='Message body']",
      "[aria-label*='Message body']"
    ];

    const readingPanes = Array.from(
      document.querySelectorAll("[data-app-section='MailReadCompose'], [aria-label*='Reading pane'], [role='main']")
    ).filter(isVisible);
    const root = readingPanes.length ? readingPanes[0] : document;

    const senderData = firstTextWithin(root, senderSel, "outlook_sender");
    const subjectData = firstTextWithin(root, subjectSel, "outlook_subject");

    let bodySelectorUsed = "";
    let bodyNodes = [];
    for (const selector of bodySel) {
      const nodes = Array.from(root.querySelectorAll(selector)).filter((node) => {
        const text = (node.innerText || node.textContent || "").trim();
        return text.length > 20;
      });
      log("selector_tried", { field: "outlook_body", selector, nodeCount: nodes.length });
      if (nodes.length) {
        bodyNodes = pickBestBodyNodes(nodes);
        bodySelectorUsed = selector;
        log("selector_match", { field: "outlook_body", selector, nodeCount: bodyNodes.length });
        break;
      }
    }

    if (!bodyNodes.length) {
      const fallbackNodes = Array.from(document.querySelectorAll("[data-testid='messageBody'], [role='document']"));
      bodyNodes = pickBestBodyNodes(fallbackNodes);
      if (bodyNodes.length) {
        bodySelectorUsed = "outlook_fallback_visible_body";
      }
    }

    const body = textFromNodes(bodyNodes);
    const links = bodyNodes.length ? bodyNodes.flatMap((node) => extractLinks(node)) : [];
    const attachments = collectAttachments(["[data-testid*='attachment']", "[aria-label*='Attachment']"]);

    return {
      provider: "outlook",
      sender: senderData.text,
      subject: subjectData.text,
      body,
      links,
      attachments,
      headers: {
        page_url: location.href
      },
      timestamp: new Date().toISOString(),
      debug: {
        sender_selector: senderData.selector,
        subject_selector: subjectData.selector,
        body_selector: bodySelectorUsed,
        body_node_count: bodyNodes.length,
        reading_pane_found: Boolean(readingPanes.length)
      }
    };
  }

  function extractEmailData() {
    const provider = detectProvider();

    if (provider === "gmail") {
      return extractFromGmail();
    }

    if (provider === "outlook") {
      return extractFromOutlook();
    }

    return {
      provider: "unknown",
      sender: "",
      subject: "",
      body: "",
      links: [],
      attachments: [],
      headers: {},
      timestamp: new Date().toISOString()
    };
  }

  function hasMeaningfulEmailContent(emailData) {
    return Boolean(
      (emailData.sender && emailData.sender.trim()) ||
      (emailData.subject && emailData.subject.trim()) ||
      (emailData.body && emailData.body.trim()) ||
      (Array.isArray(emailData.links) && emailData.links.length) ||
      (Array.isArray(emailData.attachments) && emailData.attachments.length)
    );
  }

  function buildExtractionDebug(provider, emailData, extractionSuccess, reason) {
    return {
      is_gmail: provider === "gmail",
      is_outlook: provider === "outlook",
      extraction_success: extractionSuccess,
      data_extracted: {
        sender: Boolean(emailData.sender),
        subject: Boolean(emailData.subject),
        body: Boolean(emailData.body),
        body_length: (emailData.body || "").length,
        links_count: Array.isArray(emailData.links) ? emailData.links.length : 0,
        attachments_count: Array.isArray(emailData.attachments) ? emailData.attachments.length : 0,
        message_fingerprint: buildMessageFingerprint(emailData)
      },
      reason,
      selectors: emailData.debug || {}
    };
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || message.action !== "extract_email") {
      return false;
    }

    try {
      log("Received extract_email message", { url: location.href });
      if (debuggerInstance) {
        debuggerInstance.logFullPipeline("content.extraction.request", { url: location.href });
      }
      const emailData = extractEmailData();
      const provider = emailData.provider;
      const bodyLength = (emailData.body || "").length;
      const emailDetected = hasMeaningfulEmailContent(emailData);

      log("email_detected_status", {
        emailDetected,
        provider,
        bodyLength
      });

      console.log(`${TAG} Email detected: ${emailDetected ? "YES" : "NO"}, Body length: ${bodyLength}`);

      log("Extraction raw result", {
        provider,
        sender: emailData.sender,
        subject: emailData.subject,
        body_length: (emailData.body || "").length,
        links_count: emailData.links.length,
        attachments_count: emailData.attachments.length
      });

      if (emailData.provider === "unknown") {
        const debug = buildExtractionDebug(provider, emailData, false, "unsupported_provider");
        log("Extraction failed", debug);
        alert("AI Cyber Shield: Unsupported page. Open Gmail or Outlook Web.");
        sendResponse({
          success: false,
          error: "Unsupported page. Open Gmail or Outlook Web to analyze emails.",
          debug
        });
        return true;
      }

      if (!hasMeaningfulEmailContent(emailData)) {
        const debug = buildExtractionDebug(provider, emailData, false, "no_open_email_content");
        log("Extraction failed", debug);
        alert("AI Cyber Shield: No open email content detected. Open a message thread and retry.");
        sendResponse({
          success: false,
          error: "No open email detected. Open a message thread, then retry.",
          debug
        });
        return true;
      }

      if (!emailData.body || !emailData.body.trim()) {
        alert("AI Cyber Shield: Warning - email body is empty.");
      }

      const debug = buildExtractionDebug(provider, emailData, true, "ok");
      log("Extraction success", debug);
      if (debuggerInstance) {
        debuggerInstance.logFullPipeline("content.extraction.success", debug);
      }
      log("sending_extracted_payload", {
        provider,
        sender: emailData.sender,
        subject: emailData.subject,
        bodyLength: (emailData.body || "").length,
        linksCount: emailData.links.length
      });
      sendResponse({ success: true, data: emailData, debug });
    } catch (error) {
      console.error(`${TAG} Extraction exception`, error);
      sendResponse({ success: false, error: error.message || "Failed to extract email" });
    }

    return true;
  });
})();
