// Gmail sign-in via chrome.identity. No backend, no client secret:
// Chrome handles the OAuth consent screen and caches/refreshes the token.

export async function getToken({ interactive = false } = {}) {
  try {
    const result = await chrome.identity.getAuthToken({ interactive });
    // MV3 resolves to { token, grantedScopes }; older Chrome resolves to a string.
    return typeof result === "string" ? result : result?.token ?? null;
  } catch (err) {
    if (!interactive) return null; // not signed in yet; the caller decides whether to prompt
    throw err;
  }
}

export async function signIn() {
  const token = await getToken({ interactive: true });
  if (!token) throw new Error("Sign-in was cancelled.");
  await chrome.storage.local.set({ phishiSignedIn: true });
  return token;
}

export async function signOut() {
  const token = await getToken({ interactive: false });
  if (token) {
    // Revoke on Google's side, then drop Chrome's cached copy.
    await fetch(`https://oauth2.googleapis.com/revoke?token=${token}`, { method: "POST" }).catch(() => {});
    await chrome.identity.removeCachedAuthToken({ token });
  }
  await chrome.identity.clearAllCachedAuthTokens?.();
  await chrome.storage.local.set({ phishiSignedIn: false });
}

export async function isSignedIn() {
  return (await getToken({ interactive: false })) !== null;
}

// fetch() wrapper that attaches the token and retries once on 401 (expired token).
export async function authedFetch(url, init = {}) {
  let token = await getToken({ interactive: false });
  if (!token) throw new NotSignedInError();

  const doFetch = (t) => fetch(url, { ...init, headers: { ...init.headers, Authorization: `Bearer ${t}` } });

  let res = await doFetch(token);
  if (res.status === 401) {
    await chrome.identity.removeCachedAuthToken({ token });
    token = await getToken({ interactive: false });
    if (!token) throw new NotSignedInError();
    res = await doFetch(token);
  }
  if (!res.ok) {
    const err = new Error(`Gmail API ${res.status}: ${(await res.text()).slice(0, 200)}`);
    err.status = res.status; // lets callers react to 400/404 (e.g. a thread ID passed as a message ID)
    throw err;
  }
  return res.json();
}

export class NotSignedInError extends Error {
  constructor() {
    super("User is not signed in to Phish-i.");
    this.name = "NotSignedInError";
  }
}
