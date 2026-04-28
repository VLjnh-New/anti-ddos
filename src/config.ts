import fs from "node:fs";
import yaml from "js-yaml";

export interface Config {
  proxy: { port: number; upstream: string; trustProxy: boolean };
  dashboard: { port: number; username: string; password: string };
  demoBackend: { enabled: boolean; port: number };
  rateLimit: { enabled: boolean; windowMs: number; maxRequests: number; burst: number };
  ban: { enabled: boolean; maxViolations: number; durationMs: number };
  waf: { enabled: boolean; blockOnMatch: boolean; maxBodyBytes: number };
  botDetect: { enabled: boolean; blockEmptyUA: boolean; blockKnownBadUA: boolean };
  challenge: {
    enabled: boolean;
    difficulty: number;
    cookieName: string;
    cookieTTLms: number;
    triggerWhenSuspicious: boolean;
  };
  whitelistIps: string[];
  blacklistIps: string[];
  logging: { level: "debug" | "info" | "warn" | "error" };
}

export function loadConfig(path: string): Config {
  const raw = fs.readFileSync(path, "utf8");
  const parsed = yaml.load(raw) as Config;
  if (!parsed || typeof parsed !== "object") {
    throw new Error(`Config rỗng hoặc không hợp lệ: ${path}`);
  }
  return parsed;
}
