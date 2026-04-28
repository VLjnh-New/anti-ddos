// Sliding window + burst token-bucket per IP
interface Bucket {
  tokens: number;
  lastRefill: number;
  windowStart: number;
  windowCount: number;
}

export class RateLimiter {
  private buckets = new Map<string, Bucket>();

  constructor(
    private windowMs: number,
    private maxRequests: number,
    private burst: number
  ) {}

  // Returns true if allowed, false if over limit
  hit(ip: string): boolean {
    const now = Date.now();
    let b = this.buckets.get(ip);
    if (!b) {
      b = { tokens: this.burst, lastRefill: now, windowStart: now, windowCount: 0 };
      this.buckets.set(ip, b);
    }

    // Refill burst tokens at rate of maxRequests/windowMs
    const elapsed = now - b.lastRefill;
    const refill = (elapsed / this.windowMs) * this.maxRequests;
    if (refill > 0) {
      b.tokens = Math.min(this.burst, b.tokens + refill);
      b.lastRefill = now;
    }

    // Reset window counter
    if (now - b.windowStart > this.windowMs) {
      b.windowStart = now;
      b.windowCount = 0;
    }
    b.windowCount++;

    if (b.tokens < 1) return false;
    b.tokens--;
    return true;
  }

  // Periodic cleanup of stale buckets
  cleanup() {
    const now = Date.now();
    for (const [ip, b] of this.buckets) {
      if (now - b.lastRefill > this.windowMs * 60) this.buckets.delete(ip);
    }
  }

  size(): number {
    return this.buckets.size;
  }
}
