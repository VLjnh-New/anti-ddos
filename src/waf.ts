// Lightweight WAF — pattern matching for common Layer 7 attacks
// Inspired by OWASP CRS, but kept compact and readable.

export interface WafRule {
  id: string;
  name: string;
  category: "sqli" | "xss" | "lfi" | "rce" | "ssrf" | "scanner";
  re: RegExp;
}

export const RULES: WafRule[] = [
  // SQL Injection
  { id: "SQL-001", name: "Union-based SQLi", category: "sqli",
    re: /\bunion\b[\s\S]{0,40}\bselect\b/i },
  { id: "SQL-002", name: "Boolean-based SQLi", category: "sqli",
    re: /(['"`])\s*(or|and)\s+\d+\s*=\s*\d+/i },
  { id: "SQL-003", name: "Stacked queries", category: "sqli",
    re: /;\s*(drop|delete|update|insert|alter|create)\s/i },
  { id: "SQL-004", name: "Comment evasion", category: "sqli",
    re: /(--|#|\/\*).*?(or|and|union|select)/i },
  { id: "SQL-005", name: "Information schema probe", category: "sqli",
    re: /\b(information_schema|pg_catalog|sysobjects|sqlite_master)\b/i },

  // XSS
  { id: "XSS-001", name: "Script tag", category: "xss",
    re: /<script[\s>]/i },
  { id: "XSS-002", name: "Event handler", category: "xss",
    re: /\bon(load|click|error|mouseover|focus|blur|submit)\s*=/i },
  { id: "XSS-003", name: "javascript: URI", category: "xss",
    re: /javascript\s*:/i },
  { id: "XSS-004", name: "Data URI HTML", category: "xss",
    re: /data:text\/html/i },
  { id: "XSS-005", name: "iframe injection", category: "xss",
    re: /<iframe[\s>]/i },

  // LFI / Path traversal
  { id: "LFI-001", name: "Directory traversal", category: "lfi",
    re: /\.\.[\\/]/ },
  { id: "LFI-002", name: "Sensitive file read", category: "lfi",
    re: /\/(etc\/passwd|etc\/shadow|proc\/self|windows\/win\.ini)/i },
  { id: "LFI-003", name: "PHP wrapper", category: "lfi",
    re: /php:\/\/(filter|input|expect)/i },

  // RCE
  { id: "RCE-001", name: "Shell metacharacters", category: "rce",
    re: /[;&|`]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b/i },
  { id: "RCE-002", name: "Command substitution", category: "rce",
    re: /\$\([\s\S]+?\)|`[\s\S]+?`/ },
  { id: "RCE-003", name: "Eval / system call", category: "rce",
    re: /\b(eval|system|exec|passthru|popen|proc_open)\s*\(/i },

  // SSRF
  { id: "SSRF-001", name: "Internal IP probe", category: "ssrf",
    re: /\b(127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|localhost)\b/i },

  // Scanner UAs (checked separately on UA)
  { id: "SCN-001", name: "SQLMap", category: "scanner", re: /sqlmap/i },
  { id: "SCN-002", name: "Nikto", category: "scanner", re: /nikto/i },
  { id: "SCN-003", name: "Acunetix", category: "scanner", re: /acunetix/i },
  { id: "SCN-004", name: "Nmap", category: "scanner", re: /nmap/i },
];

export interface WafHit {
  rule: WafRule;
  field: string;   // e.g. "url", "header:user-agent", "body"
  sample: string;  // matched substring
}

function snippet(s: string, m: RegExpExecArray): string {
  const start = Math.max(0, m.index - 10);
  return s.slice(start, m.index + m[0].length + 10).slice(0, 80);
}

export function inspect(payload: { url: string; headers: Record<string, string>; body?: string }): WafHit | null {
  // Decode URL-encoded once before matching
  let decodedUrl = payload.url;
  try { decodedUrl = decodeURIComponent(payload.url); } catch { /* keep raw */ }

  // 1) URL + query string
  for (const r of RULES) {
    if (r.category === "scanner") continue;
    const m = r.re.exec(decodedUrl);
    if (m) return { rule: r, field: "url", sample: snippet(decodedUrl, m) };
  }

  // 2) Headers (User-Agent + Referer + Cookie)
  for (const h of ["user-agent", "referer", "cookie"]) {
    const v = payload.headers[h];
    if (!v) continue;
    for (const r of RULES) {
      const m = r.re.exec(v);
      if (m) return { rule: r, field: `header:${h}`, sample: snippet(v, m) };
    }
  }

  // 3) Body (if buffered)
  if (payload.body && payload.body.length > 0) {
    for (const r of RULES) {
      if (r.category === "scanner") continue;
      const m = r.re.exec(payload.body);
      if (m) return { rule: r, field: "body", sample: snippet(payload.body, m) };
    }
  }

  return null;
}
