'use strict';

const { release: { version } } = require('./package.json');

module.exports.RELEASE = version;
module.exports.PORT = process.env.PORT || '51821';
module.exports.WEBUI_HOST = process.env.WEBUI_HOST || '0.0.0.0';
/** This is only kept for migration purpose. DO NOT USE! */
module.exports.PASSWORD = process.env.PASSWORD;
/** Required. Web UI / API will not start without it. */
module.exports.PASSWORD_HASH = process.env.PASSWORD_HASH;
/** Optional. Stable across restarts; random if unset (sessions reset on restart). */
module.exports.SESSION_SECRET = process.env.SESSION_SECRET || null;
/** Session idle lifetime in milliseconds (default 12h). */
module.exports.SESSION_MAX_AGE = Number(process.env.SESSION_MAX_AGE) || (12 * 60 * 60 * 1000);
/**
 * Cookie Secure flag: 'true' | 'false' | 'auto' (HTTPS request → Secure).
 * Default 'auto' so plain-HTTP LAN installs still work.
 */
module.exports.SECURE_COOKIE = process.env.SECURE_COOKIE || 'auto';
/** Trust X-Forwarded-* when behind a reverse proxy (also used for client IP). */
module.exports.TRUST_PROXY = process.env.TRUST_PROXY === 'true' || process.env.TRUST_PROXY === '1';
/** Failed login / Authorization attempts before lockout. */
module.exports.LOGIN_MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS) || 5;
/** Sliding window for counting failures (ms). */
module.exports.LOGIN_WINDOW_MS = Number(process.env.LOGIN_WINDOW_MS) || (15 * 60 * 1000);
/** Lockout duration after too many failures (ms). */
module.exports.LOGIN_LOCKOUT_MS = Number(process.env.LOGIN_LOCKOUT_MS) || (15 * 60 * 1000);
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
