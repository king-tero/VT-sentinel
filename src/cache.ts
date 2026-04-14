/**
 * In-memory cache with TTL and rate limiter for VT API.
 * Free tier: 4 requests/minute, 500 requests/day.
 */

interface CacheEntry<T> {
    value: T;
    expiresAt: number;
}

export class Cache<T> {
    private store = new Map<string, CacheEntry<T>>();
    private ttlMs: number;

    constructor(ttlMinutes: number = 15) {
        this.ttlMs = ttlMinutes * 60 * 1000;
    }

    get(key: string): T | null {
        const entry = this.store.get(key);
        if (!entry) return null;
        if (Date.now() > entry.expiresAt) {
            this.store.delete(key);
            return null;
        }
        return entry.value;
    }

    set(key: string, value: T): void {
        this.store.set(key, {
            value,
            expiresAt: Date.now() + this.ttlMs,
        });
    }

    has(key: string): boolean {
        return this.get(key) !== null;
    }

    clear(): void {
        this.store.clear();
    }
}

export class RateLimiter {
    private timestamps: number[] = [];
    private maxRequests: number;
    private windowMs: number;

    constructor(maxPerMinute: number = 4) {
        this.maxRequests = maxPerMinute;
        this.windowMs = 60 * 1000;
    }

    /**
     * Wait until a request slot is available, then consume it.
     */
    async acquire(): Promise<void> {
        while (true) {
            const now = Date.now();
            // Purge timestamps outside the window
            this.timestamps = this.timestamps.filter((t) => now - t < this.windowMs);

            if (this.timestamps.length < this.maxRequests) {
                this.timestamps.push(now);
                return;
            }

            // Wait until the oldest request exits the window
            const waitMs = this.timestamps[0] + this.windowMs - now + 50;
            await new Promise((resolve) => setTimeout(resolve, waitMs));
        }
    }
}
