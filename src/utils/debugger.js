(() => {
  "use strict";

  const DEFAULT_KEY = "ai_cyber_debug_log";

  class EmailDebugger {
    constructor(scope = "unknown", options = {}) {
      this.scope = scope;
      this.key = options.key || DEFAULT_KEY;
      this.maxEntries = options.maxEntries || 500;
    }

    async logFullPipeline(step, data) {
      const entry = {
        id: this.makeId(),
        timestamp: new Date().toISOString(),
        scope: this.scope,
        step,
        meta: this.describeData(data),
        data: this.safeClone(data)
      };

      console.log(`[AI-CYBER-SHIELD][DEBUG][${this.scope}] ${step}`, entry);
      await this.persist(entry);
      return entry;
    }

    async dumpToPopup() {
      const logs = await this.getLogs();
      const latest = logs.slice(-30);
      const lastByStep = {};

      for (const item of logs) {
        lastByStep[item.step] = item;
      }

      return {
        total: logs.length,
        latest,
        lastByStep,
        pipeline: {
          extracted: Boolean(lastByStep["content.extraction.success"]),
          sentToBackground: Boolean(lastByStep["background.message.received"]),
          analyzed: Boolean(lastByStep["detector.analysis.complete"]),
          score: lastByStep["detector.analysis.complete"]?.data?.threatScore ?? null,
          bodyLength: this.findLatestBodyLength(logs)
        }
      };
    }

    async exportDebugLog() {
      const logs = await this.getLogs();
      const payload = {
        exportedAt: new Date().toISOString(),
        total: logs.length,
        logs
      };

      const json = JSON.stringify(payload, null, 2);

      if (typeof document !== "undefined") {
        const blob = new Blob([json], { type: "application/json;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `ai-cyber-debug-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }

      return payload;
    }

    async clearLogs() {
      if (this.hasLocalStorage()) {
        localStorage.setItem(this.key, JSON.stringify([]));
      }

      if (this.hasChromeStorage()) {
        await chrome.storage.local.set({ [this.key]: [] });
      }
    }

    async getLogs() {
      if (this.hasChromeStorage()) {
        try {
          const data = await chrome.storage.local.get(this.key);
          if (Array.isArray(data[this.key])) {
            return data[this.key];
          }
        } catch (error) {
          console.warn("[AI-CYBER-SHIELD][DEBUG] chrome.storage read failed", error);
        }
      }

      if (this.hasLocalStorage()) {
        try {
          const raw = localStorage.getItem(this.key);
          const parsed = raw ? JSON.parse(raw) : [];
          return Array.isArray(parsed) ? parsed : [];
        } catch (error) {
          console.warn("[AI-CYBER-SHIELD][DEBUG] localStorage read failed", error);
          return [];
        }
      }

      return [];
    }

    async persist(entry) {
      const logs = await this.getLogs();
      logs.push(entry);
      const trimmed = logs.slice(-this.maxEntries);

      if (this.hasLocalStorage()) {
        try {
          localStorage.setItem(this.key, JSON.stringify(trimmed));
        } catch (error) {
          console.warn("[AI-CYBER-SHIELD][DEBUG] localStorage write failed", error);
        }
      }

      if (this.hasChromeStorage()) {
        try {
          await chrome.storage.local.set({ [this.key]: trimmed });
        } catch (error) {
          console.warn("[AI-CYBER-SHIELD][DEBUG] chrome.storage write failed", error);
        }
      }
    }

    describeData(data) {
      if (data === null || data === undefined) {
        return { type: String(data), size: 0, keys: [] };
      }

      if (Array.isArray(data)) {
        return {
          type: "array",
          size: data.length,
          keys: []
        };
      }

      if (typeof data === "object") {
        const keys = Object.keys(data);
        return {
          type: "object",
          size: keys.length,
          keys: keys.slice(0, 20)
        };
      }

      return {
        type: typeof data,
        size: String(data).length,
        keys: []
      };
    }

    safeClone(value) {
      try {
        return JSON.parse(JSON.stringify(value));
      } catch (error) {
        return { note: "non-serializable", type: typeof value };
      }
    }

    findLatestBodyLength(logs) {
      for (let i = logs.length - 1; i >= 0; i -= 1) {
        const item = logs[i];
        const len = item?.data?.bodyLength ?? item?.data?.data_extracted?.body_length ?? null;
        if (typeof len === "number") {
          return len;
        }
      }

      return 0;
    }

    hasLocalStorage() {
      try {
        return typeof localStorage !== "undefined";
      } catch (error) {
        return false;
      }
    }

    hasChromeStorage() {
      try {
        return Boolean(globalThis.chrome?.storage?.local);
      } catch (error) {
        return false;
      }
    }

    makeId() {
      if (globalThis.crypto?.randomUUID) {
        return globalThis.crypto.randomUUID();
      }

      return `dbg_${Date.now()}_${Math.random().toString(16).slice(2)}`;
    }
  }

  globalThis.EmailDebugger = EmailDebugger;
})();
