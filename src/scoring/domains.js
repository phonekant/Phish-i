// Domain helpers shared by the email scorer.
// NOTE: `lookalikeOf` is a stand-in until Caroline's domain-name algorithm (Tranco-based) is ready.
// Keep the same signature: lookalikeOf(domain) -> { brand, target } | null.

export const BRANDS = {
  paypal: ["paypal.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazon.co.uk"],
  microsoft: ["microsoft.com", "outlook.com", "live.com", "office.com"],
  google: ["google.com", "gmail.com", "youtube.com"],
  netflix: ["netflix.com"],
  chase: ["chase.com"],
  "bank of america": ["bankofamerica.com", "bofa.com"],
  wells: ["wellsfargo.com"],
  usps: ["usps.com"],
  fedex: ["fedex.com"],
  ups: ["ups.com"],
  dhl: ["dhl.com"],
  irs: ["irs.gov"],
  docusign: ["docusign.com", "docusign.net"],
  dropbox: ["dropbox.com"],
  facebook: ["facebook.com", "facebookmail.com"],
  instagram: ["instagram.com"],
  linkedin: ["linkedin.com"],
  coinbase: ["coinbase.com"],
  venmo: ["venmo.com"],
  zelle: ["zellepay.com"],
};

export const FREE_MAIL = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
  "aol.com", "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com",
]);

export const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
  "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
]);

const MULTI_PART_TLDS = new Set(["co.uk", "ac.uk", "gov.uk", "com.au", "co.jp", "com.br", "co.in", "com.mx", "co.za"]);

// "mail.secure.paypal.co.uk" -> "paypal.co.uk". Good enough without the full Public Suffix List.
export function registrable(host) {
  const labels = (host || "").toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return MULTI_PART_TLDS.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

export function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

export function sameOrg(a, b) {
  return !!a && !!b && registrable(a) === registrable(b);
}

export function isBrandDomain(domain, brand) {
  const reg = registrable(domain);
  return BRANDS[brand].some((d) => reg === d || domain.endsWith("." + d));
}

// Brand named in free text (e.g. a display name) — returns the brand key or null.
export function brandMentioned(text) {
  const t = (text || "").toLowerCase();
  return Object.keys(BRANDS).find((b) => new RegExp(`\\b${b}\\b`).test(t)) ?? null;
}

const ALL_REAL = new Set(Object.values(BRANDS).flat());

const HOMOGLYPHS =[[/0/g, "o"], [/1/g, "l"], [/rn/g, "m"], [/vv/g, "w"], [/3/g, "e"], [/5/g, "s"]];

export function lookalikeOf(domain) {
  const reg = registrable(domain);
  if (!reg) return null;
  const label = reg.split(".")[0];
  const normalized = HOMOGLYPHS.reduce((s, [re, r]) => s.replace(re, r), label);

  if (ALL_REAL.has(reg)) return null; // it IS a real brand site

  for (const [brand, domains] of Object.entries(BRANDS)) {
    for (const real of domains) {
      const realLabel = real.split(".")[0];
      if (realLabel.length < 5) continue; // ups/dhl/irs/live: too short for edit distance to mean anything
      const dist = levenshtein(normalized, realLabel);
      // paypal-secure.com, amazon-billing.net (hyphenated brand token, not "purchase" ⊃ "chase")
      const containsBrand = label !== realLabel && normalized.split(/[-_]/).includes(realLabel);
      if (dist === 0 || dist === 1 || (dist === 2 && realLabel.length >= 7) || containsBrand) {
        return { brand, target: real };
      }
    }
  }
  return null;
}

export function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[a.length][b.length];
}
