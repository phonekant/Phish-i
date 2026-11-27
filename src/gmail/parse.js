// Turns a Gmail API message (format=full) into a flat object the scorer can use.
// Pure functions only, so they run under Node for tests.

export function parseMessage(msg) {
  const headers = {};
  for (const h of msg.payload?.headers ?? []) {
    const k = h.name.toLowerCase();
    (headers[k] ??= []).push(h.value);
  }
  const first = (k) => headers[k]?.[0] ?? "";

  const parts = flattenParts(msg.payload);
  const html = parts.filter((p) => p.mimeType === "text/html").map((p) => decodeB64Url(p.body?.data)).join("\n");
  const text = parts.filter((p) => p.mimeType === "text/plain").map((p) => decodeB64Url(p.body?.data)).join("\n");
  const attachments = parts
    .filter((p) => p.filename)
    .map((p) => ({ filename: p.filename, mimeType: p.mimeType, size: p.body?.size ?? 0 }));

  return {
    id: msg.id,
    threadId: msg.threadId,
    labelIds: msg.labelIds ?? [],
    snippet: msg.snippet ?? "",
    subject: first("subject"),
    from: parseAddress(first("from")),
    replyTo: first("reply-to") ? parseAddress(first("reply-to")) : null,
    returnPath: parseAddress(first("return-path")),
    auth: parseAuthResults(headers["authentication-results"] ?? [], headers["received-spf"] ?? []),
    html,
    text: text || stripHtml(html),
    links: extractLinks(html, text),
    attachments,
  };
}

function flattenParts(part, out = []) {
  if (!part) return out;
  out.push(part);
  for (const p of part.parts ?? []) flattenParts(p, out);
  return out;
}

export function decodeB64Url(data) {
  if (!data) return "";
  const b64 = data.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8").decode(bytes);
}

// "PayPal Support <support@paypa1-secure.com>" -> { name, address, domain }
export function parseAddress(raw) {
  if (!raw) return { name: "", address: "", domain: "" };
  const m = raw.match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/);
  const name = m ? m[1].trim() : "";
  const address = (m ? m[2] : raw).trim().replace(/^<|>$/g, "").toLowerCase();
  const domain = address.includes("@") ? address.split("@").pop() : "";
  return { name, address, domain };
}

// Reads SPF / DKIM / DMARC verdicts that Google stamps on every received message.
export function parseAuthResults(authHeaders, spfHeaders) {
  const all = authHeaders.join(" ; ").toLowerCase();
  const pick = (method) => {
    const m = all.match(new RegExp(`\\b${method}=(\\w+)`));
    return m ? m[1] : "none";
  };
  let spf = pick("spf");
  if (spf === "none" && spfHeaders.length) spf = spfHeaders[0].trim().split(/\s/)[0].toLowerCase();
  const dkimDomain = all.match(/header\.(?:i|d)=@?([\w.-]+)/)?.[1] ?? "";
  return { spf, dkim: pick("dkim"), dmarc: pick("dmarc"), dkimDomain };
}

// Returns [{ href, text }] for every link. Plain-text URLs get text === href.
export function extractLinks(html, text) {
  const links = [];
  const re = /<a\b[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html))) {
    const href = decodeEntities(m[1].trim());
    if (/^https?:/i.test(href)) links.push({ href, text: stripHtml(m[2]).trim() });
  }
  if (!html) {
    for (const u of text.match(/https?:\/\/[^\s<>"')]+/gi) ?? []) links.push({ href: u, text: u });
  }
  return links;
}

export function stripHtml(html) {
  return decodeEntities(
    html.replace(/<(style|script)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " ")
  ).replace(/\s+/g, " ").trim();
}

function decodeEntities(s) {
  return s
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, " ");
}
