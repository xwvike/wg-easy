'use strict';

const { release: { version } } = require('./package.json');

module.exports.RELEASE = version;
module.exports.PORT = process.env.PORT || '51821';
if (!/^\d{1,5}$/.test(module.exports.PORT)) {
  throw new Error(`Invalid PORT: ${module.exports.PORT}`);
}
module.exports.WEBUI_HOST = process.env.WEBUI_HOST || '0.0.0.0';
/** This is only kept for migration purpose. DO NOT USE! */
module.exports.PASSWORD = process.env.PASSWORD;
/** Required. Web UI / API will not start without it. */
module.exports.PASSWORD_HASH = process.env.PASSWORD_HASH;
/** Optional. Stable across restarts; random if unset (sessions reset on restart). */
module.exports.SESSION_SECRET = process.env.SESSION_SECRET || null;

/**
 * Parse a positive integer env var; fall back when missing/invalid.
 * @param {string|undefined} value
 * @param {number} fallback
 * @returns {number}
 */
const positiveInt = (value, fallback) => {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};

/** Session lifetime in milliseconds (default 12h). */
module.exports.SESSION_MAX_AGE = positiveInt(process.env.SESSION_MAX_AGE, 12 * 60 * 60 * 1000);
/**
 * Cookie Secure flag: 'true' | 'false' | 'auto' (HTTPS request → Secure).
 * Default 'auto' so plain-HTTP LAN installs still work.
 */
module.exports.SECURE_COOKIE = process.env.SECURE_COOKIE || 'auto';
/** Removed: replaced by TRUSTED_PROXIES + REAL_IP_HEADER. Kept only to fail loudly. */
module.exports.TRUST_PROXY = process.env.TRUST_PROXY;
/**
 * Comma-separated IPs/CIDRs of reverse proxies whose forwarding headers are
 * believed (e.g. the Docker gateway in front of cloudflared). Empty = none.
 */
module.exports.TRUSTED_PROXIES = process.env.TRUSTED_PROXIES || '';
/** Header carrying the real client IP from a trusted proxy (e.g. cf-connecting-ip). */
module.exports.REAL_IP_HEADER = (process.env.REAL_IP_HEADER || 'x-forwarded-for').toLowerCase();
/** Failed login / Authorization attempts per client IP (IPv6: per /64) before lockout. */
module.exports.LOGIN_MAX_ATTEMPTS = positiveInt(process.env.LOGIN_MAX_ATTEMPTS, 5);
/** Failed attempts across all clients per window before new logins pause. */
module.exports.LOGIN_GLOBAL_MAX_ATTEMPTS = positiveInt(process.env.LOGIN_GLOBAL_MAX_ATTEMPTS, 100);
/** Sliding window for counting failures (ms). */
module.exports.LOGIN_WINDOW_MS = positiveInt(process.env.LOGIN_WINDOW_MS, 15 * 60 * 1000);
/** Lockout duration after too many failures (ms). */
module.exports.LOGIN_LOCKOUT_MS = positiveInt(process.env.LOGIN_LOCKOUT_MS, 15 * 60 * 1000);
/** Dev only: allow the publicly known example password hash. */
module.exports.INSECURE_ALLOW_DEFAULT_PASSWORD = process.env.INSECURE_ALLOW_DEFAULT_PASSWORD === 'true';
/** Whether VPN peers may reach the Web UI through wg0 (set false behind a proxy/tunnel). */
module.exports.WEBUI_VPN_ACCESS = process.env.WEBUI_VPN_ACCESS !== 'false';
/**
 * Only forward peer traffic leaving the VPN to WG_ALLOWED_IPS; private ranges
 * and cloud metadata stay blocked unless listed explicitly.
 */
module.exports.WG_EGRESS_FILTER = process.env.WG_EGRESS_FILTER !== 'false';
module.exports.WG_PATH = process.env.WG_PATH || '/etc/wireguard/';
module.exports.WG_DEVICE = process.env.WG_DEVICE || 'eth0';
module.exports.WG_HOST = process.env.WG_HOST;
module.exports.WG_PORT = process.env.WG_PORT || '51820';
module.exports.WG_CONFIG_PORT = process.env.WG_CONFIG_PORT || process.env.WG_PORT || '51820';
module.exports.WG_MTU = process.env.WG_MTU || null;
module.exports.WG_PERSISTENT_KEEPALIVE = process.env.WG_PERSISTENT_KEEPALIVE || '0';
module.exports.WG_DEFAULT_ADDRESS = process.env.WG_DEFAULT_ADDRESS || '10.8.0.x';
module.exports.WG_DEFAULT_DNS = typeof process.env.WG_DEFAULT_DNS === 'string'
  ? process.env.WG_DEFAULT_DNS
  : '1.1.1.1';
module.exports.WG_ALLOWED_IPS = process.env.WG_ALLOWED_IPS || '0.0.0.0/0, ::/0';

module.exports.WG_PRE_UP = process.env.WG_PRE_UP || '';
module.exports.WG_POST_UP = process.env.WG_POST_UP || `
iptables -t nat -A POSTROUTING -s ${module.exports.WG_DEFAULT_ADDRESS.replace('x', '0')}/24 -o ${module.exports.WG_DEVICE} -j MASQUERADE;
iptables -A INPUT -p udp -m udp --dport ${module.exports.WG_PORT} -j ACCEPT;
iptables -A FORWARD -i wg0 -j ACCEPT;
iptables -A FORWARD -o wg0 -j ACCEPT;
`.split('\n').join(' ');

module.exports.WG_PRE_DOWN = process.env.WG_PRE_DOWN || '';
module.exports.WG_POST_DOWN = process.env.WG_POST_DOWN || `
iptables -t nat -D POSTROUTING -s ${module.exports.WG_DEFAULT_ADDRESS.replace('x', '0')}/24 -o ${module.exports.WG_DEVICE} -j MASQUERADE;
iptables -D INPUT -p udp -m udp --dport ${module.exports.WG_PORT} -j ACCEPT;
iptables -D FORWARD -i wg0 -j ACCEPT;
iptables -D FORWARD -o wg0 -j ACCEPT;
`.split('\n').join(' ');
module.exports.LANG = process.env.LANG || 'en';
module.exports.UI_TRAFFIC_STATS = process.env.UI_TRAFFIC_STATS || 'false';
module.exports.UI_CHART_TYPE = process.env.UI_CHART_TYPE || 0;
/** Load avatars from gravatar.com (sends a hash of each client name to a third party). */
module.exports.UI_GRAVATAR = process.env.UI_GRAVATAR === 'true';
/** When true, skip real WireGuard and serve live mock traffic for UI preview. */
module.exports.DEMO_TRAFFIC = process.env.DEMO_TRAFFIC === 'true' || process.env.DEMO_TRAFFIC === '1';
