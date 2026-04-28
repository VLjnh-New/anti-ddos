// Helpers for client IP extraction and CIDR matching
import type { IncomingMessage } from "node:http";

export function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.length > 0) {
      return xff.split(",")[0].trim();
    }
  }
  const raw = req.socket.remoteAddress || "unknown";
  // Strip IPv6-mapped IPv4 prefix (::ffff:1.2.3.4 -> 1.2.3.4)
  return raw.startsWith("::ffff:") ? raw.slice(7) : raw;
}

// Convert IPv4 dotted to integer
function ip4ToInt(ip: string): number | null {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

// Check if IP matches a single entry (exact IP or CIDR like 10.0.0.0/8)
export function ipMatches(ip: string, entry: string): boolean {
  if (entry === ip) return true;
  if (!entry.includes("/")) return false;
  const [net, maskStr] = entry.split("/");
  const mask = Number(maskStr);
  const ipInt = ip4ToInt(ip);
  const netInt = ip4ToInt(net);
  if (ipInt === null || netInt === null || Number.isNaN(mask)) return false;
  const maskBits = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
  return (ipInt & maskBits) === (netInt & maskBits);
}

export function ipInList(ip: string, list: string[]): boolean {
  return list.some((entry) => ipMatches(ip, entry));
}
