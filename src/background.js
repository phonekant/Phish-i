import { signIn, signOut, isSignedIn, NotSignedInError } from "./gmail/auth.js";
import { getMessage, getLatestMessageIdInThread, countMessagesFrom } from "./gmail/api.js";
import { parseMessage } from "./gmail/parse.js";
import { scoreEmail } from "./scoring/score.js";

// Small in-memory cache so re-opening the same email doesn't re-hit the API.
const cache = new Map();
const RECENT_KEY = "phishiRecent"; // chrome.storage.session: what the popup displays
const MAX_RECENT = 10;

// Debug logging for the service worker console. Never logs bodies, links, or tokens.
const DEBUG = true;
const log = (stage, info) => DEBUG && console.info(`[Phish-i] ${stage}`, info ?? "");

async function fetchMessage(id) {
  try {
    return { raw: await getMessage(id), resolvedFromThread: false };
  } catch (err) {
    if (err.status !== 400 && err.status !== 404) throw err;
    // The page gave us a thread ID. Use the newest message in that thread.
    log("2b. id is not a message id, trying as thread id", { id, status: err.status });
    const latest = await getLatestMessageIdInThread(id);
    if (!latest) throw err;
    return { raw: await getMessage(latest), resolvedFromThread: true };
  }
}

async function analyzeEmail(messageId) {
  if (cache.has(messageId)) return cache.get(messageId);

  const { raw, resolvedFromThread } = await fetchMessage(messageId);
  log("2. fetched from Gmail API", {
    requestedId: messageId, messageId: raw.id, threadId: raw.threadId, resolvedFromThread,
    headerCount: raw.payload?.headers?.length ?? 0, labelIds: raw.labelIds,
  });

  const email = parseMessage(raw);
  log("3. parsed", {
    fromDomain: email.from.domain, replyToDomain: email.replyTo?.domain ?? null,
    auth: email.auth, bodyChars: email.text.length, links: email.links.length, attachments: email.attachments.length,
  });

  const prior = await countMessagesFrom(email.from.address).catch(() => undefined);
  // Week 3: classifierProb = await runClassifier(email)  <- Phone's model
  const scored = scoreEmail(email, { priorMessagesFromSender: prior });
  log("4. scored", { score: scored.score, level: scored.level, signals: scored.reasons.map((r) => r.id) });

  const result = {
    messageId: raw.id, threadId: raw.threadId, resolvedFromThread,
    from: email.from, subject: email.subject,
    parsed: { auth: email.auth, links: email.links.length, attachments: email.attachments.length, replyTo: email.replyTo?.address ?? null },
    ...scored,
  };
  cache.set(messageId, result);
  if (cache.size > 200) cache.delete(cache.keys().next().value);
  await saveRecent(result);
  return result;
}

// Keeps the last few results in session storage (cleared when Chrome closes).
// This is the contract between detection and UI: any future popup can render from it.
async function saveRecent(result) {
  const { [RECENT_KEY]: recent = [] } = await chrome.storage.session.get(RECENT_KEY);
  const entry = { ...result, subject: result.subject.slice(0, 80), analyzedAt: Date.now() };
  const next = [entry, ...recent.filter((r) => r.messageId !== result.messageId)].slice(0, MAX_RECENT);
  await chrome.storage.session.set({ [RECENT_KEY]: next });
}

// Score on the toolbar icon for the Gmail tab, so there's a visible signal without opening anything.
const BADGE_COLORS = { safe: "#2e7d32", caution: "#f9a825", warning: "#ef6c00", danger: "#c62828" };
function setBadge(tabId, result) {
  if (tabId == null) return;
  chrome.action.setBadgeText({ tabId, text: String(result.score) });
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[result.level] });
}

const handlers = {
  "phishi:signIn": async () => { await signIn(); return { signedIn: true }; },
  "phishi:signOut": async () => {
    await signOut();
    cache.clear();
    await chrome.storage.session.remove(RECENT_KEY);
    return { signedIn: false };
  },
  "phishi:status": async () => ({ signedIn: await isSignedIn() }),
  "phishi:analyzeEmail": async ({ messageId, idSource }, sender) => {
    log("1. content script detected email", { messageId, idSource, tabId: sender.tab?.id });
    const result = await analyzeEmail(messageId);
    setBadge(sender.tab?.id, result);
    return result;
  },
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const handler = handlers[msg?.type];
  if (!handler) return false;
  handler(msg, sender)
    .then((data) => sendResponse({ ok: true, data }))
    .catch((err) => {
      log("ERROR", { type: msg.type, error: err.message });
      sendResponse({ ok: false, error: err.message, notSignedIn: err instanceof NotSignedInError });
    });
  return true; // keep the channel open for the async response
});
