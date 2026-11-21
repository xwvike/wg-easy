'use strict';

const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');
const { createServer } = require('node:http');
const { stat, readFile } = require('node:fs/promises');
const { resolve, sep } = require('node:path');

const expressSession = require('express-session');
const debug = require('debug')('Server');

const {
  createApp,
  createError,
  createRouter,
  defineEventHandler,
  fromNodeMiddleware,
  getRouterParam,
  toNodeListener,
  send,
  setHeader,
  setResponseHeader,
  serveStatic,
} = require('h3');

const WireGuard = require('../services/WireGuard');
const Util = require('./Util');
const AuthLimiter = require('./AuthLimiter');
const Http = require('./Http');

const {
  PORT,
  WEBUI_HOST,
  RELEASE,
  PASSWORD,
  PASSWORD_HASH,
  SESSION_SECRET,
  SESSION_MAX_AGE,
  SECURE_COOKIE,
  TRUST_PROXY,
  TRUSTED_PROXIES,
  REAL_IP_HEADER,
  LOGIN_MAX_ATTEMPTS,
  LOGIN_GLOBAL_MAX_ATTEMPTS,
  LOGIN_WINDOW_MS,
  LOGIN_LOCKOUT_MS,
  INSECURE_ALLOW_DEFAULT_PASSWORD,
  WEBUI_VPN_ACCESS,
  WG_DEFAULT_ADDRESS,
  LANG,
  UI_TRAFFIC_STATS,
  UI_CHART_TYPE,
  UI_GRAVATAR,
} = require('../config');

/** Restoring a backup carries every client's keys; still far below this. */
const RESTORE_BODY_LIMIT = 1024 * 1024;
/** Passwords published in this repository's docs and examples. */
const PUBLIC_PASSWORDS = ['foobar123'];

if (PASSWORD) {
  throw new Error('DO NOT USE PASSWORD ENVIRONMENT VARIABLE. USE PASSWORD_HASH INSTEAD.\nSee https://github.com/wg-easy/wg-easy/blob/v14/How_to_generate_an_bcrypt_hash.md');
}

if (!PASSWORD_HASH) {
  throw new Error('PASSWORD_HASH environment variable is required. The Web UI must not run without authentication.\nSee https://github.com/wg-easy/wg-easy/blob/v14/How_to_generate_an_bcrypt_hash.md');
}

if (TRUST_PROXY === 'true' || TRUST_PROXY === '1') {
  throw new Error('TRUST_PROXY has been removed because it let clients spoof their IP. Set TRUSTED_PROXIES to the proxy addresses (e.g. the exact IP of your reverse proxy) and REAL_IP_HEADER (e.g. cf-connecting-ip) instead.');
}

if (!/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(PASSWORD_HASH)) {
  throw new Error('PASSWORD_HASH is not a valid bcrypt hash. Remember to double every $ in docker-compose.yml.');
}

if (Number(PASSWORD_HASH.slice(4, 6)) < 10) {
  // eslint-disable-next-line no-console
  console.warn('PASSWORD_HASH uses a bcrypt cost below 10; generate a new hash with a higher cost.');
}

if (!INSECURE_ALLOW_DEFAULT_PASSWORD && PUBLIC_PASSWORDS.some((pw) => bcrypt.compareSync(pw, PASSWORD_HASH))) {
  throw new Error('PASSWORD_HASH is the publicly known example password. Generate your own hash; see How_to_generate_an_bcrypt_hash.md');
}

const sessionSecret = SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!SESSION_SECRET) {
  // eslint-disable-next-line no-console
  console.warn('SESSION_SECRET is unset. Using a random cookie signing key for this process.');
}

const authLimiter = new AuthLimiter({
  maxAttempts: LOGIN_MAX_ATTEMPTS,
  globalMaxAttempts: LOGIN_GLOBAL_MAX_ATTEMPTS,
  windowMs: LOGIN_WINDOW_MS,
  lockoutMs: LOGIN_LOCKOUT_MS,
});

const http = new Http({
  trustedProxies: TRUSTED_PROXIES,
  realIpHeader: REAL_IP_HEADER,
});

/**
 * @param {string} password
 * @returns {Promise<boolean>}
 */
const isPasswordValid = async (password) => {
  if (typeof password !== 'string' || password.length === 0) {
    return false;
  }
  try {
    return await bcrypt.compare(password, PASSWORD_HASH);
  } catch {
    return false;
  }
};

/**
 * @param {import('h3').H3Event} event
 * @param {number} retryAfterSec
 */
const throwRateLimited = (event, retryAfterSec) => {
  setResponseHeader(event, 'Retry-After', String(retryAfterSec));
  throw createError({
    status: 429,
    message: 'Too Many Attempts',
  });
};

/**
 * Checks a password under the brute-force limiter; throws 401/429 on failure.
 *
 * @param {import('h3').H3Event} event
 * @param {unknown} password
 */
const authenticate = async (event, password) => {
  const attempt = authLimiter.begin(http.clientIp(event.node.req));
  if (!attempt.ok) {
    throwRateLimited(event, attempt.retryAfterSec);
  }

  const pending = authLimiter.withSlot(() => isPasswordValid(password));
  if (!pending) {
    authLimiter.cancel(attempt);
    throwRateLimited(event, 1);
  }

  if (await pending) {
    authLimiter.succeed(attempt);
    return;
  }

  const result = authLimiter.fail(attempt);
  if (result.locked) {
    throwRateLimited(event, result.retryAfterSec);
  }
  throw createError({ status: 401, message: 'Incorrect Password' });
};

/**
 * Whether a request arrived from a VPN peer (its own address or a subnet it routes).
 *
 * @param {import('node:http').IncomingMessage} req
 */
const isFromVpn = async (req) => {
  const ip = Http.socketIp(req);
  if (!Util.isValidIPv4(ip)) return false;
  const self = { address: ip, cidr: 32 };
  if (Util.cidrOverlaps(self, { address: WG_DEFAULT_ADDRESS.replace('x', '0'), cidr: 24 })) return true;
  const config = await WireGuard.getConfig();
  return Object.values(config.clients)
    .some((client) => (client.allowedIPs ?? []).some((allowed) => Util.cidrOverlaps(allowed, self)));
};

/**
 * Regenerate the session id (session fixation defense) and mark authenticated.
 * Must use `req.session` after regenerate — the old object is discarded.
 *
 * @param {import('node:http').IncomingMessage & { session: import('express-session').Session }} req
 * @returns {Promise<void>}
 */
const regenerateSession = (req) => new Promise((resolve, reject) => {
  req.session.regenerate((err) => {
    if (err) return reject(err);
    req.session.authenticated = true;
    req.session.save((saveErr) => {
      if (saveErr) return reject(saveErr);
      resolve();
    });
  });
});

module.exports = class Server {

  constructor() {
    let secureCookie = 'auto';
    if (SECURE_COOKIE === 'true') secureCookie = true;
    if (SECURE_COOKIE === 'false') secureCookie = false;

    const app = createApp({
      onError: (error, event) => {
        if (error.statusCode >= 500) {
          // eslint-disable-next-line no-console
          console.error(error.cause ?? error);
        }
        return send(event, JSON.stringify({ error: error.message }), 'application/json');
      },
    });
    this.app = app;

    app.use(defineEventHandler(async (event) => {
      const { req, res } = event.node;
      // express-session reads req.secure for `secure: 'auto'` when `proxy` is unset
      req.secure = http.isSecure(req);
      Http.setSecurityHeaders(res, {
        secure: req.secure,
        api: req.url.startsWith('/api/'),
        gravatar: UI_GRAVATAR,
      });

      if (!WEBUI_VPN_ACCESS && await isFromVpn(req)) {
        throw createError({ status: 403, message: 'Web UI is not reachable over the VPN' });
      }

      http.assertSameOrigin(req);
    }));

    app.use(fromNodeMiddleware(expressSession({
      name: 'wg-easy.sid',
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: 'strict',
        secure: secureCookie,
        maxAge: SESSION_MAX_AGE,
      },
    })));

    const router = createRouter();
    app.use(router);

    router
      .get('/api/lang', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${LANG}"`;
      }))

      .get('/api/ui-traffic-stats', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${UI_TRAFFIC_STATS}"`;
      }))

      .get('/api/ui-chart-type', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${UI_CHART_TYPE}"`;
      }))

      .get('/api/ui-gravatar', defineEventHandler(() => {
        return UI_GRAVATAR;
      }))

      // Authentication
      .get('/api/session', defineEventHandler((event) => {
        const authenticated = !!(event.node.req.session && event.node.req.session.authenticated);

        return {
          requiresPassword: true,
          authenticated,
        };
      }))
      .post('/api/session', defineEventHandler(async (event) => {
        const { password } = await Http.readJsonBody(event);
        await authenticate(event, password);
        await regenerateSession(event.node.req);

        debug('New session created.');

        return { success: true };
      }));

    // WireGuard API auth
    app.use(
      defineEventHandler(async (event) => {
        const { req } = event.node;
        if (!req.url.startsWith('/api/')) {
          return;
        }

        if (req.session && req.session.authenticated) {
          return;
        }

        if (req.headers['authorization']) {
          await authenticate(event, req.headers['authorization']);
          return;
        }

        throw createError({ status: 401, message: 'Not Logged In' });
      }),
    );

    const router2 = createRouter();
    app.use(router2);

    router2
      .get('/api/release', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return RELEASE;
      }))
      .delete('/api/session', defineEventHandler(async (event) => {
        await new Promise((resolve, reject) => {
          event.node.req.session.destroy((err) => {
            if (err) return reject(err);
            resolve();
          });
        });

        debug('Session deleted.');
        return { success: true };
      }))
      .get('/api/wireguard/client', defineEventHandler(async (event) => {
        const remote = http.clientIp(event.node.req);
        const clients = await WireGuard.getClients();
        return clients.map((client) => ({
          ...client,
          isCurrent: Util.isValidIPv4(remote)
            && client.allowedIPs.some((ip) => Util.cidrOverlaps(ip, { address: remote, cidr: 32 })),
        }));
      }))
      .get('/api/wireguard/traffic/peers', defineEventHandler(() => {
        return WireGuard.getPeerFlows();
      }))
      .get('/api/wireguard/client/:clientId/qrcode.svg', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const svg = await WireGuard.getClientQRCodeSVG({ clientId });
        setHeader(event, 'Content-Type', 'image/svg+xml');
        return svg;
      }))
      .get('/api/wireguard/client/:clientId/configuration', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const client = await WireGuard.getClient({ clientId });
        const config = await WireGuard.getClientConfiguration({ clientId });
        const configName = client.name
          .replace(/[^a-zA-Z0-9_=+.-]/g, '-')
          .replace(/(-{2,}|-$)/g, '-')
          .replace(/-$/, '')
          .substring(0, 32);
        setHeader(event, 'Content-Disposition', `attachment; filename="${configName || clientId}.conf"`);
        setHeader(event, 'Content-Type', 'text/plain');
        return config;
      }))
      .post('/api/wireguard/client', defineEventHandler(async (event) => {
        const { name, fenced } = await Http.readJsonBody(event);
        await WireGuard.createClient({ name, fenced });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/fenced', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const { fenced } = await Http.readJsonBody(event);
        await WireGuard.updateClientFenced({ clientId, fenced });
        return { success: true };
      }))
      .delete('/api/wireguard/client/:clientId', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        await WireGuard.deleteClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/enable', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        await WireGuard.enableClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/disable', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        await WireGuard.disableClient({ clientId });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/name', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const { name } = await Http.readJsonBody(event);
        await WireGuard.updateClientName({ clientId, name });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/address', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const { address } = await Http.readJsonBody(event);
        await WireGuard.updateClientAddress({ clientId, address });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/allowedips', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const { allowedIPs } = await Http.readJsonBody(event);
        await WireGuard.updateClientAllowedIPs({ clientId, allowedIPs });
        return { success: true };
      }));

    const safePathJoin = (base, target) => {
      // Manage web root (edge case)
      if (target === '/') {
        return `${base}${sep}`;
      }

      // Prepend './' to prevent absolute paths
      const targetPath = `.${sep}${target}`;

      // Resolve the absolute path
      const resolvedPath = resolve(base, targetPath);

      // Check if resolvedPath is a subpath of base
      if (resolvedPath.startsWith(`${base}${sep}`)) {
        return resolvedPath;
      }

      throw createError({
        status: 400,
        message: 'Bad Request',
      });
    };

    // backup_restore
    const router3 = createRouter();
    app.use(router3);

    router3
      .get('/api/wireguard/backup', defineEventHandler(async (event) => {
        const config = await WireGuard.backupConfiguration();
        setHeader(event, 'Content-Disposition', 'attachment; filename="wg0.json"');
        setHeader(event, 'Content-Type', 'text/json');
        return config;
      }))
      .put('/api/wireguard/restore', defineEventHandler(async (event) => {
        const { file } = await Http.readJsonBody(event, { limit: RESTORE_BODY_LIMIT });
        await WireGuard.restoreConfiguration(file);
        return { success: true };
      }));

    // Static assets
    const publicDir = resolve(__dirname, '..', 'www');
    app.use(
      defineEventHandler((event) => {
        return serveStatic(event, {
          getContents: (id) => {
            return readFile(safePathJoin(publicDir, id));
          },
          getMeta: async (id) => {
            const filePath = safePathJoin(publicDir, id);

            const stats = await stat(filePath).catch(() => { });
            if (!stats || !stats.isFile()) {
              return;
            }

            setHeader(event, 'Cache-Control', 'no-cache');
            if (id.endsWith('.html')) setHeader(event, 'Content-Type', 'text/html');
            if (id.endsWith('.js')) setHeader(event, 'Content-Type', 'application/javascript');
            if (id.endsWith('.json')) setHeader(event, 'Content-Type', 'application/json');
            if (id.endsWith('.css')) setHeader(event, 'Content-Type', 'text/css');
            if (id.endsWith('.png')) setHeader(event, 'Content-Type', 'image/png');

            return {
              size: stats.size,
              mtime: stats.mtimeMs,
            };
          },
        });
      }),
    );

    const server = createServer({
      headersTimeout: 10 * 1000,
      requestTimeout: 30 * 1000,
      maxHeaderSize: 16 * 1024,
    }, toNodeListener(app));
    server.keepAliveTimeout = 5 * 1000;
    server.listen(PORT, WEBUI_HOST);
    debug(`Listening on http://${WEBUI_HOST}:${PORT}`);
  }

};
