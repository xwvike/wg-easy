'use strict';

/**
 * Per-IP auth attempt limiter (in-memory).
 * Used for login and Authorization-header brute-force protection.
 */
module.exports = class AuthLimiter {

  /**
   * @param {{ maxAttempts?: number, windowMs?: number, lockoutMs?: number }} [options]
   */
  constructor({
    maxAttempts = 5,
    windowMs = 15 * 60 * 1000,
    lockoutMs = 15 * 60 * 1000,
  } = {}) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.lockoutMs = lockoutMs;
    /** @type {Map<string, { failures: number[], lockedUntil: number }>} */
    this._entries = new Map();
  }

  _entry(ip) {
    let entry = this._entries.get(ip);
    if (!entry) {
      entry = { failures: [], lockedUntil: 0 };
      this._entries.set(ip, entry);
    }
    return entry;
  }

  _prune(entry, now) {
    const cutoff = now - this.windowMs;
    entry.failures = entry.failures.filter((ts) => ts > cutoff);
    if (entry.lockedUntil && entry.lockedUntil <= now) {
      entry.lockedUntil = 0;
    }
    if (entry.failures.length === 0 && entry.lockedUntil === 0) {
      return true;
    }
    return false;
  }

  /**
   * @param {string} ip
   * @returns {{ ok: true } | { ok: false, retryAfterSec: number }}
   */
  check(ip) {
    const now = Date.now();
    const entry = this._entry(ip);
    if (this._prune(entry, now)) {
      this._entries.delete(ip);
      return { ok: true };
    }
    if (entry.lockedUntil > now) {
      return { ok: false, retryAfterSec: Math.ceil((entry.lockedUntil - now) / 1000) };
    }
    return { ok: true };
  }

  /**
   * @param {string} ip
   * @returns {{ locked: boolean, retryAfterSec: number }}
   */
  fail(ip) {
    const now = Date.now();
    const entry = this._entry(ip);
    this._prune(entry, now);
    entry.failures.push(now);
    if (entry.failures.length >= this.maxAttempts) {
      entry.lockedUntil = now + this.lockoutMs;
      entry.failures = [];
      return { locked: true, retryAfterSec: Math.ceil(this.lockoutMs / 1000) };
    }
    return { locked: false, retryAfterSec: 0 };
  }

  /**
   * @param {string} ip
   */
  succeed(ip) {
    this._entries.delete(ip);
  }

};
