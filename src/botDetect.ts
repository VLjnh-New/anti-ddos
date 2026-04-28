// Simple bot detector based on User-Agent heuristics.
// Returns a "suspicion" verdict — caller decides whether to block, challenge, or pass.

const BAD_UA_PATTERNS: RegExp[] = [
  /\b(curl|wget|libwww|python-requests|python-urllib|java-http-client|go-http-client)\b/i,
  /\b(masscan|nmap|nikto|sqlmap|acunetix|metasploit|wpscan|dirbuster|gobuster)\b/i,
  /\b(scrapy|httpclient|okhttp|axios\/0)\b/i,
  /^Mozilla\/5\.0$/, // Truncated/forged UA
];

const GOOD_BOT_PATTERNS: RegExp[] = [
  /Googlebot/i,
  /Bingbot/i,
  /DuckDuckBot/i,
  /Slurp/i, // Yahoo
];

export type Verdict = "ok" | "suspicious" | "block";

export interface DetectResult {
  verdict: Verdict;
  reason?: string;
}

export function detect(ua: string | undefined, opts: { blockEmptyUA: boolean; blockKnownBadUA: boolean }): DetectResult {
  if (!ua || ua.trim().length === 0) {
    return { verdict: opts.blockEmptyUA ? "block" : "suspicious", reason: "Empty User-Agent" };
  }

  for (const p of GOOD_BOT_PATTERNS) {
    if (p.test(ua)) return { verdict: "ok", reason: "Verified crawler" };
  }

  for (const p of BAD_UA_PATTERNS) {
    if (p.test(ua)) {
      return { verdict: opts.blockKnownBadUA ? "block" : "suspicious", reason: `Bad UA: ${ua.slice(0, 60)}` };
    }
  }

  // Plausible browser fingerprint
  if (/Mozilla\/5\.0.*\b(Chrome|Firefox|Safari|Edge|OPR)\b/i.test(ua)) {
    return { verdict: "ok" };
  }

  // Unknown — treat as suspicious so they hit the JS challenge
  return { verdict: "suspicious", reason: "Non-browser UA" };
}
