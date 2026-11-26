// Runs on mail.google.com. Watches for an opened email, asks the background worker to score it,
// and hands the result to the banner UI.
//
// Interface for Maggie's banner: listen for the DOM event below.
//   window.addEventListener("phishi:emailResult", (e) => renderBanner(e.detail.result, e.detail.anchor));
//   e.detail.result = { messageId, score, level, label, reasons[], trust[], from, subject, version }
//   e.detail.anchor = the Gmail message element to attach the banner to
// Until the banner exists, results are logged to the console.

(() => {
  const seen = new Set();

  // Gmail tags each rendered message with its API message ID (hex) in data-legacy-message-id.
  // Fallback: data-message-id="#msg-f:<decimal>" -> same ID in hex.
  // Only message elements carry these attributes; inbox rows carry thread attributes instead.
  function messageIdOf(el) {
    const legacy = el.getAttribute("data-legacy-message-id");
    if (legacy) return { id: legacy, source: "data-legacy-message-id" };
    const m = el.getAttribute("data-message-id")?.match(/msg-f:(\d+)/);
    return m ? { id: BigInt(m[1]).toString(16), source: "data-message-id (msg-f -> hex)" } : null;
  }

  function scan() {
    for (const el of document.querySelectorAll("[data-legacy-message-id], [data-message-id]")) {
      const found = messageIdOf(el);
      if (!found || seen.has(found.id)) continue;
      seen.add(found.id);
      console.debug(`[Phish-i] detected message ${found.id} via ${found.source}`);
      analyze(found.id, found.source, el);
    }
  }

  async function analyze(messageId, idSource, anchor) {
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: "phishi:analyzeEmail", messageId, idSource });
    } catch (err) {
      seen.delete(messageId); // extension reloaded mid-session; allow retry
      return;
    }
    if (!res?.ok) {
      seen.delete(messageId);
      window.dispatchEvent(new CustomEvent("phishi:emailError", {
        detail: { messageId, error: res?.error, notSignedIn: res?.notSignedIn, anchor },
      }));
      if (res?.notSignedIn) console.info("[Phish-i] Sign in from the toolbar popup to scan emails.");
      else console.warn("[Phish-i] Analysis failed:", res?.error);
      return;
    }
    window.dispatchEvent(new CustomEvent("phishi:emailResult", { detail: { result: res.data, anchor } }));
    console.info(`[Phish-i] ${res.data.score}/100 (${res.data.level}) — ${res.data.subject}`, res.data.reasons);
  }

  // Gmail is a single-page app; watch for messages being rendered.
  let pending = null;
  new MutationObserver(() => {
    clearTimeout(pending);
    pending = setTimeout(scan, 300);
  }).observe(document.body, { childList: true, subtree: true });
  scan();
})();
