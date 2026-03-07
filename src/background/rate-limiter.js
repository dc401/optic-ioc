//Optic IOC - Rate Limiter
//Token bucket algorithm for API rate limiting
//Prevents quota exhaustion and ensures fair resource usage

class RateLimiter {
  constructor(requestsPerMinute, burst) {
    this.requestsPerMinute = requestsPerMinute || 60;
    this.burst = burst || this.requestsPerMinute;
    this.tokens = this.burst; //start with full bucket
    this.lastRefill = Date.now();
    //REMOVED: queue and processing (unused)
  }

  //Refill tokens based on time elapsed
  refillTokens() {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const tokensToAdd = (elapsed / 60000) * this.requestsPerMinute;

    if (tokensToAdd > 0) {
      this.tokens = Math.min(this.burst, this.tokens + tokensToAdd);
      this.lastRefill = now;
    }
  }

  //Check if request can proceed
  async tryAcquire() {
    this.refillTokens();

    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }

    return false;
  }

  //Wait for token availability
  async acquire() {
    this.refillTokens();

    if (this.tokens >= 1) {
      this.tokens -= 1;
      return;
    }

    //Calculate wait time until next token
    const tokensNeeded = 1 - this.tokens;
    const waitMs = (tokensNeeded / this.requestsPerMinute) * 60000;

    await new Promise(resolve => setTimeout(resolve, waitMs));

    //Refill and try again
    this.refillTokens();
    this.tokens -= 1;
  }

  //Execute function with rate limiting
  async execute(fn) {
    await this.acquire();
    try {
      return await fn();
    } catch (error) {
      throw error;
    }
  }

  //Get current token count
  getAvailableTokens() {
    this.refillTokens();
    return Math.floor(this.tokens);
  }

  //Check if rate limit would be exceeded
  wouldExceedLimit() {
    this.refillTokens();
    return this.tokens < 1;
  }

  //Reset rate limiter
  reset() {
    this.tokens = this.burst;
    this.lastRefill = Date.now();
  }
}

//Manager for multiple rate limiters (one per source)
class RateLimiterManager {
  constructor() {
    this.limiters = new Map();
  }

  //Get or create rate limiter for source
  getLimiter(sourceId, config) {
    if (!this.limiters.has(sourceId)) {
      const limiter = new RateLimiter(
        config.requests_per_minute || 60,
        config.burst || config.requests_per_minute || 60
      );
      this.limiters.set(sourceId, limiter);
    }
    return this.limiters.get(sourceId);
  }

  //Execute function with rate limiting for specific source
  async execute(sourceId, config, fn) {
    const limiter = this.getLimiter(sourceId, config);
    return await limiter.execute(fn);
  }

  //Check if request would be rate limited
  wouldLimit(sourceId, config) {
    const limiter = this.getLimiter(sourceId, config);
    return limiter.wouldExceedLimit();
  }

  //Get available tokens for source
  getAvailable(sourceId, config) {
    const limiter = this.getLimiter(sourceId, config);
    return limiter.getAvailableTokens();
  }

  //Reset all limiters
  resetAll() {
    for (const limiter of this.limiters.values()) {
      limiter.reset();
    }
  }

  //Reset specific source
  reset(sourceId) {
    const limiter = this.limiters.get(sourceId);
    if (limiter) {
      limiter.reset();
    }
  }

  //Get stats for all limiters
  getStats() {
    const stats = {};
    for (const [sourceId, limiter] of this.limiters.entries()) {
      stats[sourceId] = {
        available_tokens: limiter.getAvailableTokens(),
        would_limit: limiter.wouldExceedLimit()
      };
    }
    return stats;
  }
}

//Export singleton
const rateLimiterManager = new RateLimiterManager();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { RateLimiter, RateLimiterManager, rateLimiterManager };
}

//Make globally available for service worker
if (typeof self !== 'undefined') {
  self.RateLimiter = RateLimiter;
  self.RateLimiterManager = RateLimiterManager;
  self.rateLimiterManager = rateLimiterManager;
}
