# Phish-i — Third-Party Tracker Detection & Blocking Module

**Owner:** David Osorio  
**Project:** Phish-i (Browser Extension for Phishing, Impersonation & Tracker Protection)  
**Target Standard:** Manifest V3 (Cross-browser compatible with Google Chrome and Mozilla Firefox)

---

## API Contracts at a Glance

All communication between the popup/banners and the background worker uses `chrome.runtime.sendMessage` / `chrome.runtime.onMessage`.

| Message / Key | Direction | Trigger / Purpose | Request Payload | Response / Event Payload |
| :--- | :--- | :--- | :--- | :--- |
| **`GET_TAB_TRACKERS`** | UI / Scorer $\rightarrow$ Background | Fetch blocked trackers, severity, and plain-language summary for a tab | `{ type: "GET_TAB_TRACKERS", tabId: number }` | `{ tabId, hostname, globalEnabled, sitePaused, severity, summaryText, trackerCount, trackers[] }` |
| **`TOGGLE_BLOCKING`** | UI $\rightarrow$ Background | Enable or disable tracker blocking globally | `{ type: "TOGGLE_BLOCKING", enabled: boolean }` | `{ enabled: boolean }` |
| **`TOGGLE_SITE_PAUSE`** | UI $\rightarrow$ Background | Whitelist/pause blocking on a specific domain | `{ type: "TOGGLE_SITE_PAUSE", hostname: string, paused: boolean }` | `{ hostname: string, paused: boolean }` |
| **`TRACKERS_UPDATED`** | Background $\rightarrow$ UI | Live broadcast whenever a new tracker is blocked on a tab | *Broadcast event (no request)* | `{ type: "TRACKERS_UPDATED", tabId: number, trackerCount: number }` |
| **`tab_<tabId>`** | `chrome.storage.session` | Direct session storage key for per-tab tracker list | `chrome.storage.session.get("tab_12")` | `[{ domain, entity, category, explanation }, ...]` |

---

## Overview

This module detects and blocks invisible third-party web trackers (ad networks, analytics pixels, fingerprinting scripts, social trackers, and cryptominers) while translating blocked domains into plain-language entity names and severity warnings for non-technical users.

### How It Works (Dual-API MV3 Architecture)
1. **Blocking (`chrome.declarativeNetRequest`):** Evaluates static rules (`rules/tracker_rules.json`) natively in the browser engine to block third-party tracking requests and strip cross-site tracking URL parameters (`utm_*`, `fbclid`, `gclid`, `msclkid`, `mc_cid`). Supports per-site allowlisting via `updateDynamicRules` (`allowAllRequests`).
2. **Reporting (`chrome.webRequest` + `chrome.storage.session`):** Observes outgoing requests in non-blocking mode, cross-references third-party domains against `data/entity_map.json`, computes a UI severity rating, and logs plain-language descriptions per tab.

---

## Folder Structure

```text
phish-i-tracker/
├── manifest.json               # MV3 configuration (Chrome & Firefox compatible)
├── background.js               # Background worker: logs trackers, computes severity, handles toggles
├── rules/
│   └── tracker_rules.json      # Generated DNR block/redirect rules (do not edit manually)
├── data/
│   └── entity_map.json         # Generated domain -> { entity, category, explanation } map
├── popup/
│   ├── popup.html              # Prototype UI with traffic-light severity banner & toggles
│   └── popup.js                # Connects UI controls to background.js messages
└── scripts/
    └── build_tracker_rules.py  # Compiles Disconnect.me's tracker list into MV3 JSON files