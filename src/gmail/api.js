import { authedFetch } from "./auth.js";

const BASE = "https://gmail.googleapis.com/gmail/v1/users/me";

export function getMessage(id) {
  return authedFetch(`${BASE}/messages/${encodeURIComponent(id)}?format=full`);
}

// Fallback when the ID we got from the page turns out to be a thread ID, not a message ID.
// Returns the ID of the newest message in the thread.
export async function getLatestMessageIdInThread(threadId) {
  const t = await authedFetch(`${BASE}/threads/${encodeURIComponent(threadId)}?format=minimal`);
  return t.messages?.at(-1)?.id ?? null;
}

// Has the user received mail from this address before? Used for the "first-time sender" signal.
// Returns the number of messages found (capped at 5).
export async function countMessagesFrom(address) {
  const q = encodeURIComponent(`from:${address}`);
  const data = await authedFetch(`${BASE}/messages?q=${q}&maxResults=5`);
  return data.messages?.length ?? 0;
}
