// Shared in-memory state: stats, ban list, recent events
import { EventEmitter } from "node:events";

export interface AttackEvent {
  ts: number;
  ip: string;
  type: string;       // rate_limit | waf | bot | blacklist | challenge_fail
  detail: string;
  path: string;
  ua: string;
}

export interface Stats {
  totalRequests: number;
  passedRequests: number;
  blockedRequests: number;
  challengeIssued: number;
  challengeSolved: number;
  startedAt: number;
  rps: number;
  peakRps: number;
}

class ShieldState extends EventEmitter {
  stats: Stats = {
    totalRequests: 0,
    passedRequests: 0,
    blockedRequests: 0,
    challengeIssued: 0,
    challengeSolved: 0,
    startedAt: Date.now(),
    rps: 0,
    peakRps: 0,
  };

  // IP -> unbanAt epoch ms
  bannedIps = new Map<string, { until: number; reason: string }>();

  // IP -> count of recent violations
  violations = new Map<string, { count: number; resetAt: number }>();

  // Last 100 attack events
  recent: AttackEvent[] = [];

  // History: 60 seconds of [passed, blocked]
  history: { passed: number[]; blocked: number[] } = {
    passed: new Array(60).fill(0),
    blocked: new Array(60).fill(0),
  };

  recordAttack(ev: Omit<AttackEvent, "ts">) {
    const full: AttackEvent = { ts: Date.now(), ...ev };
    this.recent.unshift(full);
    if (this.recent.length > 100) this.recent.pop();
    this.emit("attack", full);
  }

  isBanned(ip: string): { banned: boolean; reason?: string } {
    const entry = this.bannedIps.get(ip);
    if (!entry) return { banned: false };
    if (entry.until < Date.now()) {
      this.bannedIps.delete(ip);
      return { banned: false };
    }
    return { banned: true, reason: entry.reason };
  }

  ban(ip: string, durationMs: number, reason: string) {
    this.bannedIps.set(ip, { until: Date.now() + durationMs, reason });
  }

  unban(ip: string) {
    this.bannedIps.delete(ip);
  }

  bumpViolation(ip: string, windowMs: number): number {
    const now = Date.now();
    const v = this.violations.get(ip);
    if (!v || v.resetAt < now) {
      this.violations.set(ip, { count: 1, resetAt: now + windowMs });
      return 1;
    }
    v.count++;
    return v.count;
  }

  cleanupExpired() {
    const now = Date.now();
    for (const [ip, e] of this.bannedIps) if (e.until < now) this.bannedIps.delete(ip);
    for (const [ip, v] of this.violations) if (v.resetAt < now) this.violations.delete(ip);
  }
}

export const state = new ShieldState();

// Background: per-second RPS calculator + history rotator
let lastTotal = 0;
let secondPassed = 0;
let secondBlocked = 0;

export function startStatsTicker() {
  setInterval(() => {
    const total = state.stats.totalRequests;
    const rps = total - lastTotal;
    lastTotal = total;
    state.stats.rps = rps;
    if (rps > state.stats.peakRps) state.stats.peakRps = rps;

    // Rotate 60s history
    state.history.passed.shift();
    state.history.passed.push(secondPassed);
    state.history.blocked.shift();
    state.history.blocked.push(secondBlocked);
    secondPassed = 0;
    secondBlocked = 0;

    state.cleanupExpired();
  }, 1000);
}

export function tickPassed() { secondPassed++; }
export function tickBlocked() { secondBlocked++; }
