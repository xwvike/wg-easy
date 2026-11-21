'use strict';

const net = require('node:net');

/**
 * Groups addresses the way an attacker can rotate them cheaply: IPv4 per
 * address, IPv6 per /64 (one customer allocation).
 *
 * @param {string} ip
 * @returns {string}
 */
const bucketOf = (ip) => {
  if (!net.isIPv6(ip)) return ip;
  const [head, tail = ''] = ip.split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = ip.includes('::')
    ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
    : left;
  return `${groups.slice(0, 4).map((g) => (parseInt(g, 16) || 0).toString(16)).join(':')}::/64`;
};

/**
 * In-memory brute-force limiter for login and Authorization-header auth.
 *
 * - Each attempt is counted *before* the password is checked, so firing many
 *   requests in parallel cannot slip past the per-client limit.
 * - A global budget caps total failures; once spent, only clients that have
 *   logged in successfully before may keep trying until it refills.
 * - Password checks run with bounded concurrency, so bcrypt cannot be used
 *   to exhaust the CPU.
 */
module.exports = class AuthLimiter {

  /**
   * @param {{ maxAttempts?: number, globalMaxAttempts?: number, windowMs?: number,
   *   lockoutMs?: number, maxEntries?: number, maxConcurrent?: number, maxQueued?: number }} [options]
   */
  constructor({
    maxAttempts = 5,
    globalMaxAttempts = 100,
    windowMs = 15 * 60 * 1000,
    lockoutMs = 15 * 60 * 1000,
    maxEntries = 4096,
    maxConcurrent = 2,
    maxQueued = 8,
  } = {}) {
    this.maxAttempts = maxAttempts;
    this.globalMaxAttempts = globalMaxAttempts;
    this.windowMs = windowMs;
    this.lockoutMs = lockoutMs;
    this.maxEntries = maxEntries;
    this.maxConcurrent = maxConcurrent;
    this.maxQueued = maxQueued;

    /** @type {Map<string, { failures: number[], pending: number, lockedUntil: number }>} */
    this._entries = new Map();
    /** @type {number[]} */
    this._global = [];
    this._pending = 0;
    /** @type {Map<string, number>} bucket -> last successful login */
    this._known = new Map();

    this._running = 0;
    /** @type {Array<() => void>} */
    this._queue = [];
  }

  _prune(entry, now) {
    const cutoff = now - this.windowMs;
    entry.failures = entry.failures.filter((ts) => ts > cutoff);
    if (entry.lockedUntil <= now) entry.lockedUntil = 0;
    return entry.failures.length === 0 && entry.pending === 0 && entry.lockedUntil === 0;
  }

  _pruneGlobal(now) {
    const cutoff = now - this.windowMs;
    while (this._global.length > 0 && this._global[0] <= cutoff) this._global.shift();
  }

  _remember(map, key, value) {
    // Map keeps insertion order: re-insert to mark as recent, evict the oldest when full
    map.delete(key);
    if (map.size >= this.maxEntries) map.delete(map.keys().next().value);
    map.set(key, value);
  }

  /**
   * Reserves one attempt for `ip`. Settle the returned reservation once the check finishes.
   *
   * @param {string} ip
   */
  begin(ip) {
    const now = Date.now();
    const key = bucketOf(ip);

    let entry = this._entries.get(key);
    if (entry && this._prune(entry, now)) {
      this._entries.delete(key);
      entry = undefined;
    }
    if (entry && entry.lockedUntil > now) {
      return { ok: false, retryAfterSec: Math.ceil((entry.lockedUntil - now) / 1000) };
    }
    if (entry && entry.pending + entry.failures.length >= this.maxAttempts) {
      // attempts still in flight already use up the allowance
      return { ok: false, retryAfterSec: 1 };
    }

    this._pruneGlobal(now);
    if (this._pending + this._global.length >= this.globalMaxAttempts && !this._known.has(key)) {
      const retryAfterSec = this._pending ? 1 : Math.max(1, Math.ceil((this._global[0] + this.windowMs - now) / 1000));
      return { ok: false, retryAfterSec };
    }

    if (!entry) {
      entry = { failures: [], pending: 0, lockedUntil: 0 };
      this._remember(this._entries, key, entry);
    }
    entry.pending++;
    this._pending++;
    return { ok: true, key, entry };
  }

  // A full bcrypt queue has no password verdict. Return both reserved slots.
  cancel({ key, entry }) {
    this._pending--;
    entry.pending--;
    if (this._prune(entry, Date.now()) && this._entries.get(key) === entry) {
      this._entries.delete(key);
    }
  }

  fail({ entry }) {
    const now = Date.now();
    this._pending--;
    entry.pending--;
    this._prune(entry, now);
    entry.failures.push(now);

    this._pruneGlobal(now);
    this._global.push(now);
    if (this._global.length > this.globalMaxAttempts) this._global.shift();

    if (entry.failures.length >= this.maxAttempts) {
      entry.lockedUntil = now + this.lockoutMs;
      entry.failures = [];
      return { locked: true, retryAfterSec: Math.ceil(this.lockoutMs / 1000) };
    }
    return { locked: false, retryAfterSec: 0 };
  }

  succeed(attempt) {
    attempt.entry.failures = [];
    this.cancel(attempt);
    this._remember(this._known, attempt.key, Date.now());
  }

  /**
   * Runs `fn` with bounded concurrency. Returns null when the queue is full.
   *
   * @template T
   * @param {() => Promise<T>} fn
   * @returns {Promise<T> | null}
   */
  withSlot(fn) {
    if (this._running >= this.maxConcurrent && this._queue.length >= this.maxQueued) {
      return null;
    }
    let acquire;
    if (this._running < this.maxConcurrent) {
      this._running++;
      acquire = Promise.resolve();
    } else {
      acquire = new Promise((resolve) => {
        this._queue.push(resolve);
      });
    }
    return acquire.then(async () => {
      try {
        return await fn();
      } finally {
        // hand the slot straight to the next waiter so it can never be overbooked
        const next = this._queue.shift();
        if (next) next();
        else this._running--;
      }
    });
  }

};

module.exports.bucketOf = bucketOf;
