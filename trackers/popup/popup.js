let currentTabId = null;
let currentHostname = "";

function renderReport(report) {
  const banner = document.getElementById("severityBanner");
  const list = document.getElementById("trackerList");
  const toggleGlobal = document.getElementById("toggleGlobal");
  const toggleSite = document.getElementById("toggleSite");
  const siteLabel = document.getElementById("siteLabel");

  currentHostname = report.hostname;
  toggleGlobal.checked = report.globalEnabled;
  toggleSite.checked = report.sitePaused;
  siteLabel.textContent = report.hostname ? `Pause on ${report.hostname}` : "Pause on this site";

  banner.className = `banner ${report.severity}`;
  banner.textContent = report.summaryText;

  list.innerHTML = "";
  report.trackers.forEach((t) => {
    const li = document.createElement("li");
    li.innerHTML = `
      <div class="entity-row">
        <span>${t.entity}</span>
        <span class="badge">${t.category}</span>
      </div>
      <div class="explanation">${t.explanation} (${t.domain})</div>
    `;
    list.appendChild(li);
  });
}

async function refresh() {
  if (!currentTabId) return;
  chrome.runtime.sendMessage({ type: "GET_TAB_TRACKERS", tabId: currentTabId }, (report) => {
    if (report) renderReport(report);
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTabId = tab.id;
  await refresh();

  document.getElementById("toggleGlobal").addEventListener("change", (e) => {
    chrome.runtime.sendMessage({ type: "TOGGLE_BLOCKING", enabled: e.target.checked }, refresh);
  });

  document.getElementById("toggleSite").addEventListener("change", (e) => {
    if (!currentHostname) return;
    chrome.runtime.sendMessage(
      { type: "TOGGLE_SITE_PAUSE", hostname: currentHostname, paused: e.target.checked },
      refresh
    );
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "TRACKERS_UPDATED" && msg.tabId === currentTabId) {
      refresh();
    }
  });
});