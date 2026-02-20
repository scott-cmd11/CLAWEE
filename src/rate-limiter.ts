interface Bucket {
  windowStartMs: number;
  count: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

export class FixedWindowRateLimiter {
  private windowMs: number;
  private maxRequests: number;
  private buckets = new Map<string, Bucket>();

  constructor(windowSeconds: number, maxRequests: number) {
    this.windowMs = Math.max(1, Math.floor(windowSeconds)) * 1000;
    this.maxRequests = Math.max(1, Math.floor(maxRequests));
  }

  check(key: string): RateLimitDecision {
    const now = Date.now();
    this.cleanup(now);

    const existing = this.buckets.get(key);
    if (!existing || now - existing.windowStartMs >= this.windowMs) {
      this.buckets.set(key, {
        windowStartMs: now,
        count: 1,
      });
      return {
        allowed: true,
        remaining: this.maxRequests - 1,
        retryAfterSeconds: 0,
      };
    }

    if (existing.count >= this.maxRequests) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((existing.windowStartMs + this.windowMs - now) / 1000),
      );
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds,
      };
    }

    existing.count += 1;
    return {
      allowed: true,
      remaining: Math.max(0, this.maxRequests - existing.count),
      retryAfterSeconds: 0,
    };
  }

  private cleanup(nowMs: number): void {
    for (const [key, bucket] of this.buckets) {
      if (nowMs - bucket.windowStartMs >= this.windowMs * 2) {
        this.buckets.delete(key);
      }
    }
  }
}
