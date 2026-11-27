const statusEl = document.getElementById("status");
const btn = document.getElementById("toggle");
const errEl = document.getElementById("error");

const send = (type) => chrome.runtime.sendMessage({ type });

function render(signedIn) {
  statusEl.textContent = signedIn
    ? "Connected to Gmail. Open any email to scan it."
    : "Connect your Gmail so Phish-i can check emails for phishing. It only reads; it never sends or deletes.";
  btn.textContent = signedIn ? "Disconnect Gmail" : "Connect Gmail";
  btn.dataset.signedIn = signedIn;
  btn.hidden = false;
}

btn.addEventListener("click", async () => {
  errEl.textContent = "";
  btn.disabled = true;
  const res = await send(btn.dataset.signedIn === "true" ? "phishi:signOut" : "phishi:signIn");
  btn.disabled = false;
  if (res?.ok) render(res.data.signedIn);
  else errEl.textContent = res?.error ?? "Something went wrong.";
});

send("phishi:status").then((res) => render(!!res?.data?.signedIn));

// ---- Recent results (read from chrome.storage.session, written by background.js) ----
const recentEl = document.getElementById("recent");

function renderRecent(recent = []) {
  recentEl.replaceChildren();
  if (!recent.length) {
    recentEl.innerHTML = "<p>No emails analyzed yet. Open an email in Gmail.</p>";
    return;
  }
  for (const r of recent) {
    const d = document.createElement("details");
    d.style.marginBottom = "8px";
    const s = document.createElement("summary");
    s.textContent = `${r.score}/100 ${r.label} — ${r.subject || "(no subject)"}`;
    d.append(s);
    const lines = [
      `From: ${r.from.name ? r.from.name + " " : ""}<${r.from.address}>`,
      `Reply-To: ${r.parsed.replyTo ?? "(same)"}`,
      `SPF ${r.parsed.auth.spf} · DKIM ${r.parsed.auth.dkim} · DMARC ${r.parsed.auth.dmarc}`,
      `Links: ${r.parsed.links} · Attachments: ${r.parsed.attachments}`,
      `Message ${r.messageId}${r.resolvedFromThread ? " (resolved from thread ID)" : ""}`,
      ...r.reasons.map((x) => `• ${x.title}`),
      ...r.trust.map((t) => `✓ ${t}`),
    ];
    for (const text of lines) {
      const p = document.createElement("div");
      p.textContent = text; // textContent, not innerHTML: email fields are untrusted
      p.style.cssText = "font-size:12px;color:#333;margin:2px 0 0 12px";
      d.append(p);
    }
    recentEl.append(d);
  }
}

chrome.storage.session.get("phishiRecent").then((o) => renderRecent(o.phishiRecent));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.phishiRecent) renderRecent(changes.phishiRecent.newValue);
});
