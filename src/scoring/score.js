// Phish-i email phishing RISK SCORE (heuristic, not a probability).
//
// Each signal that fires carries a hand-set weight w in (0, 1). The weights are our judgment of
// how strong each red flag is; they have NOT been fit or validated on data yet. Signals are
// combined with a noisy-OR:
//
//     risk = 1 - Π (1 - w_i)
//
// so adding a red flag can only raise the score, no single weak signal dominates, and the
// result stays in [0, 1]. The formula looks probabilistic, but because the weights are hand-set,
// the output is a 0-100 risk index, not "the % chance this is phishing". A few trust signals
// (known sender + passing DMARC) then scale the risk down. Final score = round(100 * risk).
//
// Week 4 plan: fit the weights on Phone's labeled dataset (logistic regression over these same
// signals) and check calibration before ever describing the score as a probability.
//
// Phone's classifier plugs in as one more signal (`classifierProb`), weighted by
// WEIGHTS.classifier, so the heuristics still explain *why* when the model flags something.

import {
  FREE_MAIL, SHORTENERS, registrable, hostOf, sameOrg, isBrandDomain, brandMentioned, lookalikeOf,
} from "./domains.js";

export const SCORE_VERSION = "0.1.0";

export const WEIGHTS = {
  // Authentication (from Gmail's Authentication-Results header)
  dmarcFail: 0.45,
  spfFail: 0.25,
  spfSoftfail: 0.12,
  dkimFail: 0.25,
  noAuth: 0.15,
  // Sender identity
  displayNameBrandSpoof: 0.4,
  displayNameEmailMismatch: 0.35,
  lookalikeSender: 0.45,
  replyToMismatch: 0.25,
  firstTimeSender: 0.08,
  // Links
  linkTextMismatch: 0.4,
  lookalikeLink: 0.4,
  ipLink: 0.3,
  punycodeLink: 0.3,
  atInUrl: 0.3,
  shortenerLink: 0.12,
  insecureLink: 0.04,
  // Content
  credentialRequest: 0.25,
  moneyRequest: 0.2,
  urgency: 0.15,
  threat: 0.15,
  genericGreeting: 0.08,
  // Attachments
  doubleExtension: 0.5,
  dangerousAttachment: 0.4,
  htmlAttachment: 0.3,
  macroAttachment: 0.3,
  // Other
  gmailSpam: 0.3,
  classifier: 0.8, // multiplied by the model's probability
};

// Trust multipliers applied after combining.
const TRUST = { knownSenderAligned: 0.6 };

export const LEVELS = [
  { min: 75, level: "danger", label: "Very likely phishing" },
  { min: 50, level: "warning", label: "Suspicious" },
  { min: 25, level: "caution", label: "Be careful" },
  { min: 0, level: "safe", label: "No major red flags" },
];

const CONTENT_RULES = [
  {
    id: "credentialRequest",
    re: /\b(verify|confirm|update|validate|re-?activate|unlock)\b.{0,40}\b(account|password|login|identity|credentials|billing|payment (?:info|details)|ssn)\b|\b(log ?in|sign ?in) (here|now|below)\b/i,
    title: "Asks you to log in or confirm account details",
    detail: "Legitimate companies rarely ask you to confirm passwords or account details through an email link.",
  },
  {
    id: "moneyRequest",
    re: /\b(gift ?cards?|wire transfer|bitcoin|crypto(?:currency)? wallet|western union|zelle me|send (?:the )?payment|outstanding (?:invoice|balance)|refund of \$?\d)/i,
    title: "Asks for money or payment",
    detail: "Requests for gift cards, wire transfers, or crypto are a classic scam pattern.",
  },
  {
    id: "urgency",
    re: /\b(urgent|immediately|within (?:24|48|72) hours|act now|final (?:notice|warning)|expires? (?:today|soon)|last chance|right away|as soon as possible)\b/i,
    title: "Pressures you to act fast",
    detail: "Scammers create urgency so you act before thinking.",
  },
  {
    id: "threat",
    re: /\b(suspend(?:ed)?|locked|deactivat(?:ed|ion)|terminat(?:ed|ion)|legal action|unusual (?:sign-?in )?activity|unauthori[sz]ed (?:access|transaction)|will be (?:closed|deleted))\b/i,
    title: "Threatens your account",
    detail: "Threats of suspension or legal action are used to scare you into clicking.",
  },
  {
    id: "genericGreeting",
    re: /^\W*(dear|hello|hi)\s+(customer|user|member|client|account holder|valued \w+|sir\/madam|sir or madam)\b/im,
    title: "Generic greeting",
    detail: "Companies you have accounts with usually address you by name.",
  },
];

const DANGEROUS_EXT = /\.(exe|scr|bat|cmd|com|pif|js|jse|vbs|vbe|wsf|msi|jar|ps1|lnk|iso|img|hta|cpl|reg)$/i;
const MACRO_EXT = /\.(docm|xlsm|pptm|dotm|xlam)$/i;
const HTML_EXT = /\.(html?|shtml|svg)$/i;
const DOUBLE_EXT = /\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|js|vbs|bat|cmd|html?|lnk)$/i;

/**
 * @param {ReturnType<import('../gmail/parse.js').parseMessage>} email
 * @param {{ priorMessagesFromSender?: number, classifierProb?: number }} ctx
 * @returns {{ score: number, level: string, label: string, reasons: Reason[], trust: string[], version: string }}
 */
export function scoreEmail(email, ctx = {}) {
  const reasons = [];
  const add = (id, category, title, detail, scale = 1) =>
    reasons.push({ id, category, title, detail, weight: +(WEIGHTS[id] * scale).toFixed(3) });

  const from = email.from;
  const fromDomain = from.domain;

  // ---- Authentication ----
  const { spf, dkim, dmarc } = email.auth;
  if (dmarc === "fail") add("dmarcFail", "authentication", "Failed sender verification (DMARC)",
    `The message claims to be from ${fromDomain} but that domain's own policy says it didn't send it.`);
  if (spf === "fail") add("spfFail", "authentication", "Sent from an unauthorized server (SPF)",
    `${fromDomain} does not list the sending server as allowed to send its mail.`);
  else if (spf === "softfail") add("spfSoftfail", "authentication", "Sending server not fully authorized (SPF softfail)",
    `${fromDomain} marks the sending server as probably not allowed.`);
  if (dkim === "fail") add("dkimFail", "authentication", "Digital signature is invalid (DKIM)",
    "The message's signature doesn't match, so it may have been forged or altered.");
  if (spf === "none" && dkim === "none" && dmarc === "none") add("noAuth", "authentication",
    "No sender verification at all", "The message carries no SPF, DKIM, or DMARC results.");

  // ---- Sender identity ----
  const brand = brandMentioned(from.name);
  if (brand && !isBrandDomain(fromDomain, brand)) {
    add("displayNameBrandSpoof", "sender", `Pretends to be ${from.name.match(new RegExp(brand, "i"))?.[0] ?? brand}`,
      `The sender name says "${from.name}" but the email actually comes from ${fromDomain}` +
      (FREE_MAIL.has(fromDomain) ? ", a free personal email service." : "."));
  }
  const nameEmail = from.name.match(/[\w.+-]+@([\w-]+\.[\w.-]+)/);
  if (nameEmail && !sameOrg(nameEmail[1], fromDomain)) {
    add("displayNameEmailMismatch", "sender", "Sender name shows a different email address",
      `The name shows ${nameEmail[0]} but the real address is ${from.address}.`);
  }
  const senderLook = lookalikeOf(fromDomain);
  if (senderLook) add("lookalikeSender", "sender", `Sender domain imitates ${senderLook.target}`,
    `${fromDomain} looks like ${senderLook.target} but is a different domain.`);
  if (email.replyTo?.domain && !sameOrg(email.replyTo.domain, fromDomain)) {
    add("replyToMismatch", "sender", "Replies go to a different address",
      `If you hit reply, your message goes to ${email.replyTo.address}, not ${from.address}.`);
  }
  const prior = ctx.priorMessagesFromSender;
  if (prior !== undefined && prior <= 1) add("firstTimeSender", "sender", "First email from this sender",
    `You haven't received mail from ${from.address} before.`);

  // ---- Links ----
  const linkHits = {};
  const linkFlag = (id, title, detail) => { if (!linkHits[id]) linkHits[id] = { title, detail }; };
  for (const { href, text } of email.links) {
    const host = hostOf(href);
    if (!host) continue;
    const shown = text.match(/^(?:https?:\/\/)?((?:[\w-]+\.)+[a-z]{2,})(?:[\/:?#]|$)/i)?.[1];
    if (shown && !sameOrg(shown, host)) linkFlag("linkTextMismatch", "Link text hides the real destination",
      `A link shows "${shown}" but actually goes to ${host}.`);
    const look = lookalikeOf(host);
    if (look) linkFlag("lookalikeLink", `Link imitates ${look.target}`, `${host} looks like ${look.target} but isn't.`);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) linkFlag("ipLink", "Link points to a raw IP address",
      `A link goes to ${host} instead of a named website.`);
    if (host.split(".").some((l) => l.startsWith("xn--"))) linkFlag("punycodeLink", "Link uses disguised characters",
      `${host} uses international characters that can mimic normal letters.`);
    if (/^https?:\/\/[^\/?#]*@/i.test(href)) linkFlag("atInUrl", "Link contains a hidden redirect trick",
      "Everything before the @ in this link is ignored by the browser.");
    if (SHORTENERS.has(registrable(host))) linkFlag("shortenerLink", "Link is shortened",
      `${host} hides where the link really goes.`);
    if (href.toLowerCase().startsWith("http:")) linkFlag("insecureLink", "Link isn't encrypted (http)",
      "Information you enter on that page could be intercepted.");
  }
  for (const [id, { title, detail }] of Object.entries(linkHits)) add(id, "links", title, detail);

  // ---- Content ----
  const body = `${email.subject}\n${email.text}`;
  for (const rule of CONTENT_RULES) if (rule.re.test(body)) add(rule.id, "content", rule.title, rule.detail);

  // ---- Attachments ----
  for (const a of email.attachments) {
    const f = a.filename;
    if (DOUBLE_EXT.test(f)) add("doubleExtension", "attachments", "Attachment disguises its file type",
      `"${f}" looks like a document but is actually a program or web page.`);
    else if (DANGEROUS_EXT.test(f)) add("dangerousAttachment", "attachments", "Attachment can run code",
      `"${f}" is a file type that can install malware if opened.`);
    else if (MACRO_EXT.test(f)) add("macroAttachment", "attachments", "Attachment contains macros",
      `"${f}" is an Office file that can run macros.`);
    else if (HTML_EXT.test(f)) add("htmlAttachment", "attachments", "Attachment is a web page",
      `"${f}" opens a local web page, often a fake login form.`);
  }

  // ---- Other ----
  if (email.labelIds.includes("SPAM")) add("gmailSpam", "other", "Gmail marked this as spam", "Gmail's own filters flagged this message.");
  if (typeof ctx.classifierProb === "number" && ctx.classifierProb > 0.5) {
    add("classifier", "model", "Our model flags this email",
      `The Phish-i model's phishing score for this email is ${ctx.classifierProb.toFixed(2)} (0 = safe, 1 = phishing).`, ctx.classifierProb);
  }

  // ---- Combine ----
  let risk = 1 - reasons.reduce((p, r) => p * (1 - r.weight), 1);

  const trust = [];
  const knownSender = prior !== undefined && prior >= 3;
  if (knownSender && dmarc === "pass" && !senderLook && !brandSpoofed(reasons)) {
    risk *= TRUST.knownSenderAligned;
    trust.push(`You've received mail from ${from.address} before and it passed verification.`);
  }

  const score = Math.round(100 * risk);
  const { level, label } = LEVELS.find((l) => score >= l.min);
  reasons.sort((a, b) => b.weight - a.weight);
  return { score, level, label, reasons, trust, version: SCORE_VERSION };
}

const brandSpoofed = (reasons) => reasons.some((r) => r.id === "displayNameBrandSpoof");

/**
 * @typedef {{ id: string, category: string, title: string, detail: string, weight: number }} Reason
 */
