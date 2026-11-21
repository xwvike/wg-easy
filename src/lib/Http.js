'use strict';

const net = require('node:net');

const { createError } = require('h3');

/** Default cap for JSON request bodies; nothing in the API needs more. */
const DEFAULT_BODY_LIMIT = 64 * 1024;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * @param {string|undefined} address
 * @returns {string}
 */
const normalizeIp = (address) => {
  const value = String(address || '').trim();
  return value.startsWith('::ffff:') && net.isIPv4(value.slice(7)) ? value.slice(7) : value;
};

/**
 * Parses a comma-separated list of IPs/CIDRs. Throws on anything malformed so
 * a typo can never silently trust (or fail to trust) a proxy.
 *
 * @param {string} list
 * @returns {net.BlockList|null}
 */
const parseAddressList = (list) => {
  const entries = String(list || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (entries.length === 0) return null;

  const blockList = new net.BlockList();
  for (const entry of entries) {
    const [address, prefix, extra] = entry.split('/');
    let type = null;
    if (net.isIPv4(address)) type = 'ipv4';
    else if (net.isIPv6(address)) type = 'ipv6';
    const max = type === 'ipv4' ? 32 : 128;
    if (!type || extra !== undefined || (prefix !== undefined && !/^\d{1,3}$/.test(prefix)) || Number(prefix) > max) {
      throw new Error(`Invalid IP/CIDR in TRUSTED_PROXIES: ${entry}`);
    }
    if (prefix === undefined) {
      blockList.addAddress(address, type);
    } else {
      blockList.addSubnet(address, Number(prefix), type);
    }
  }
  return blockList;
};

/**
 * @param {net.BlockList|null} list
 * @param {string} ip
 */
const listHas = (list, ip) => {
  if (!list) return false;
  if (net.isIPv4(ip)) return list.check(ip, 'ipv4');
  if (net.isIPv6(ip)) return list.check(ip, 'ipv6');
  return false;
};

module.exports = class Http {

  /**
   * @param {{ trustedProxies?: string, realIpHeader?: string }} options
   */
  constructor({ trustedProxies = '', realIpHeader = 'x-forwarded-for' } = {}) {
    this.trusted = parseAddressList(trustedProxies);
    this.realIpHeader = realIpHeader.toLowerCase();
  }

  /** Address of the TCP peer, never influenced by headers. */
  static socketIp(req) {
    return normalizeIp(req.socket.remoteAddress) || 'unknown';
  }

  isTrustedPeer(req) {
    return listHas(this.trusted, Http.socketIp(req));
  }

  /**
   * Real client IP. Forwarding headers count only when the TCP peer itself is
   * a trusted proxy; for X-Forwarded-For the rightmost untrusted hop wins,
   * because everything left of it is whatever the client chose to send.
   *
   * @param {import('node:http').IncomingMessage} req
   * @returns {string}
   */
  clientIp(req) {
    const peer = Http.socketIp(req);
    if (!this.isTrustedPeer(req)) return peer;

    const raw = req.headers[this.realIpHeader];
    const value = Array.isArray(raw) ? raw.join(',') : raw;
    if (typeof value !== 'string' || value.length === 0) return peer;

    if (this.realIpHeader === 'x-forwarded-for') {
      const hops = value.split(',').map(normalizeIp);
      for (let i = hops.length - 1; i >= 0; i--) {
        if (!net.isIP(hops[i])) return peer;
        if (!listHas(this.trusted, hops[i])) return hops[i];
      }
      return peer;
    }

    const ip = normalizeIp(value.split(',')[0]);
    return net.isIP(ip) ? ip : peer;
  }

  /** HTTPS as seen by the browser (direct TLS, or a trusted proxy saying so). */
  isSecure(req) {
    if (req.socket.encrypted) return true;
    if (!this.isTrustedPeer(req)) return false;
    const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
    return proto === 'https';
  }

  /**
   * Rejects cross-site state-changing requests. Browsers send Sec-Fetch-Site
   * on every request; Origin is the fallback for older ones. Non-browser API
   * clients send neither and are authenticated by password instead.
   *
   * @param {import('node:http').IncomingMessage} req
   */
  assertSameOrigin(req) {
    if (SAFE_METHODS.has(req.method)) return;

    const site = req.headers['sec-fetch-site'];
    if (site !== undefined && site !== 'same-origin' && site !== 'none') {
      throw createError({ status: 403, message: 'Cross-site request blocked' });
    }

    const { origin } = req.headers;
    if (origin === undefined) return;
    const forwardedHost = this.isTrustedPeer(req) ? req.headers['x-forwarded-host'] : undefined;
    const host = forwardedHost || req.headers.host;
    const scheme = this.isSecure(req) ? 'https' : 'http';
    try {
      if (host && origin === new URL(`${scheme}://${host}`).origin) return;
    } catch {
      // Malformed authority headers cannot identify the expected origin.
    }
    throw createError({ status: 403, message: 'Cross-site request blocked' });
  }

  /**
   * Reads a JSON object body with a hard size cap. Never buffers more than
   * `limit` bytes, whatever Content-Length claims; only application/json is
   * accepted, so plain HTML forms cannot reach the API.
   *
   * @param {import('h3').H3Event} event
   * @param {{ limit?: number }} [options]
   * @returns {Promise<Record<string, unknown>>}
   */
  static readJsonBody(event, { limit = DEFAULT_BODY_LIMIT } = {}) {
    const { req, res } = event.node;

    const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/json') {
      return Promise.reject(createError({ status: 415, message: 'Content-Type must be application/json' }));
    }

    const tooLarge = () => {
      // stop the client from streaming the rest into a kept-alive socket
      res.setHeader('Connection', 'close');
      return createError({ status: 413, message: 'Request body too large' });
    };

    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > limit) {
      req.resume();
      return Promise.reject(tooLarge());
    }

    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      let done = false;
      const finish = (fn, value) => {
        if (done) return;
        done = true;
        fn(value);
      };

      req.on('data', (chunk) => {
        if (done) return;
        size += chunk.length;
        if (size > limit) {
          chunks.length = 0;
          finish(reject, tooLarge());
          return;
        }
        chunks.push(chunk);
      });
      req.on('error', (err) => finish(reject, err));
      req.on('end', () => {
        if (done) return;
        let body;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch {
          finish(reject, createError({ status: 400, message: 'Invalid JSON body' }));
          return;
        }
        if (body === null || typeof body !== 'object' || Array.isArray(body)) {
          finish(reject, createError({ status: 400, message: 'JSON body must be an object' }));
          return;
        }
        finish(resolve, body);
      });
    });
  }

  /**
   * @param {import('node:http').ServerResponse} res
   * @param {{ secure: boolean, api: boolean, gravatar: boolean }} options
   */
  static setSecurityHeaders(res, { secure, api, gravatar }) {
    // Vue 2 compiles the in-DOM templates at runtime, which needs 'unsafe-eval'.
    const csp = [
      "default-src 'none'",
      "script-src 'self' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      `img-src 'self' data: blob:${gravatar ? ' https://www.gravatar.com' : ''}`,
      "connect-src 'self'",
      "font-src 'self'",
      "manifest-src 'self'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join('; ');

    res.setHeader('Content-Security-Policy', csp);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    if (secure) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    }
    if (api) {
      res.setHeader('Cache-Control', 'no-store');
    }
  }

};

module.exports.normalizeIp = normalizeIp;
module.exports.parseAddressList = parseAddressList;
