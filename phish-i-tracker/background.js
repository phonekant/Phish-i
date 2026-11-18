let entityMap = {};

// Dynamic rule ID offset for per-site allowlist rules (keeps clear of static rule IDs)
const ALLOWLIST_RULE_OFFSET = 100000;

async function loadEntityMap() {
  try {
    const url = chrome.runtime.getURL("data/entity_map.json");
    const response = await fetch(url);
    entityMap = await response.json();
  } catch (err) {
    console.error("Failed to load entity_map.json:", err);
  }
}

loadEntityMap();

function lookupTracker(hostname) {
  const parts = hostname.toLowerCase().split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    const candidate = parts.slice(i).join(".");
    if (entityMap[candidate]) {
      return { domain: candidate, ...entityMap[candidate] };
    }
  }
  return null;
}

function getBaseDomain(urlStr) {
  try {
    const hostname = new URL(urlStr).hostname;
    const parts = hostname.split(".");
    return parts.slice(-2).join(".");
  } catch {
    return "";
  }
}

// Compute UI-ready severity badge ("low" | "medium" | "high") and plain-language summary
function buildUiReport(tabId, trackers, globalEnabled, sitePaused, hostname) {
  const hasHighRisk = trackers.some(
    (t) => t.category === "Fingerprinting" || t.category === "Cryptomining"
  );

  let severity = "low";
  if (hasHighRisk || trackers.length >= 6) {
    severity = "high";
  } else if (trackers.length >= 1) {
    severity = "medium";
  }

  let summaryText = "No third-party trackers detected on this page.";
  if (!globalEnabled) {
    summaryText = "Tracker protection is currently turned off.";
  } else if (sitePaused) {
    summaryText = `Tracker blocking is paused on ${hostname}.`;
  } else if (trackers.length > 0) {
    const topEntities = [...new Set(trackers.map((t) => t.entity))].slice(0, 2).join(" and ");
    const remainder = trackers.length - 2;
    summaryText =
      remainder > 0
        ? `Blocked ${trackers.length} trackers, including ${topEntities} and ${remainder} more.`
        : `Blocked ${trackers.length} tracker${trackers.length > 1 ? "s" : ""} (${topEntities}).`;
  }

  return {
    tabId,
    hostname,
    globalEnabled,
    sitePaused,
    severity,      // Maps directly to Maggie's traffic-light UI ("low"=green, "medium"=yellow, "high"=red)
    summaryText,   // Plain-language sentence for non-technical users
    trackerCount: trackers.length,
    trackers
  };
}

// Deterministic rule ID from hostname for dynamic allowlisting
function getRuleIdForHost(hostname) {
  let hash = 0;
  for (let i = 0; i < hostname.length; i++) {
    hash = (hash * 31 + hostname.charCodeAt(i)) % 50000;
  }
  return ALLOWLIST_RULE_OFFSET + Math.abs(hash) + 1;
}

async function isSitePaused(hostname) {
  if (!hostname) return false;
  const rules = await chrome.declarativeNetRequest.getDynamicRules();
  const targetId = getRuleIdForHost(hostname);
  return rules.some((r) => r.id === targetId);
}

async function setSitePaused(hostname, pause) {
  const ruleId = getRuleIdForHost(hostname);
  if (pause) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [ruleId],
      addRules: [
        {
          id: ruleId,
          priority: 100,
          action: { type: "allowAllRequests" },
          condition: {
            requestDomains: [hostname],
            resourceTypes: ["main_frame", "sub_frame"]
          }
        }
      ]
    });
  } else {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [ruleId]
    });
  }
}

// Observe outgoing requests and log third-party trackers per tab
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.tabId < 0) return;

    const initiatorUrl = details.initiator || details.originUrl || details.documentUrl;
    if (!initiatorUrl) return;

    const targetBase = getBaseDomain(details.url);
    const pageBase = getBaseDomain(initiatorUrl);
    if (!targetBase || !pageBase || targetBase === pageBase) return;

    const targetHost = new URL(details.url).hostname;
    const match = lookupTracker(targetHost);
    if (!match) return;

    const key = `tab_${details.tabId}`;
    const stored = await chrome.storage.session.get(key);
    const currentList = stored[key] || [];

    if (!currentList.some((item) => item.domain === match.domain)) {
      currentList.push(match);
      await chrome.storage.session.set({ [key]: currentList });

      chrome.action.setBadgeText({
        tabId: details.tabId,
        text: String(currentList.length)
      });
      chrome.action.setBadgeBackgroundColor({
        tabId: details.tabId,
        color: "#D9534F"
      });

      // Notify popup if it is currently open
      chrome.runtime.sendMessage({
        type: "TRACKERS_UPDATED",
        tabId: details.tabId,
        trackerCount: currentList.length
      }).catch(() => {}); // Ignore error if popup is closed
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading" && changeInfo.url) {
    chrome.storage.session.remove(`tab_${tabId}`);
    chrome.action.setBadgeText({ tabId, text: "" });
  }
});

// Unified message API for Maggie's UI & Eddy's Privacy Scorer
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_TAB_TRACKERS") {
    (async () => {
      const tab = await chrome.tabs.get(message.tabId);
      const hostname = tab?.url ? new URL(tab.url).hostname : "";
      const [stored, enabledRulesets, paused] = await Promise.all([
        chrome.storage.session.get(`tab_${message.tabId}`),
        chrome.declarativeNetRequest.getEnabledRulesets(),
        isSitePaused(hostname)
      ]);

      const trackers = stored[`tab_${message.tabId}`] || [];
      const globalEnabled = enabledRulesets.includes("tracker_ruleset");
      sendResponse(buildUiReport(message.tabId, trackers, globalEnabled, paused, hostname));
    })();
    return true;
  }

  if (message.type === "TOGGLE_BLOCKING") {
    const update = message.enabled
      ? { enableRulesetIds: ["tracker_ruleset"] }
      : { disableRulesetIds: ["tracker_ruleset"] };

    chrome.declarativeNetRequest.updateEnabledRulesets(update).then(() => {
      sendResponse({ enabled: message.enabled });
    });
    return true;
  }

  if (message.type === "TOGGLE_SITE_PAUSE") {
    setSitePaused(message.hostname, message.paused).then(() => {
      sendResponse({ hostname: message.hostname, paused: message.paused });
    });
    return true;
  }
});