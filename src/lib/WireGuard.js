'use strict';

const fs = require('node:fs/promises');
const path = require('path');
const debug = require('debug')('WireGuard');
const crypto = require('node:crypto');
const QRCode = require('qrcode');

const Util = require('./Util');
const ServerError = require('./ServerError');
const PeerFlows = require('./PeerFlows');

const {
  WG_PATH,
  WG_HOST,
  WG_PORT,
  WG_CONFIG_PORT,
  WG_MTU,
  WG_DEFAULT_DNS,
  WG_DEFAULT_ADDRESS,
  WG_PERSISTENT_KEEPALIVE,
  WG_ALLOWED_IPS,
  WG_PRE_UP,
  WG_POST_UP,
  WG_PRE_DOWN,
  WG_POST_DOWN,
  DEMO_TRAFFIC,
  PORT,
  WEBUI_VPN_ACCESS,
  WG_EGRESS_FILTER,
} = require('../config');

const FENCED_KEEPALIVE = 25;
const MAX_NAME_LENGTH = 64;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
const CLIENT_ID = /^[A-Za-z0-9_-]{1,64}$/;
/** Never forwarded to, even if WG_ALLOWED_IPS covers them: cloud instance metadata. */
const ALWAYS_BLOCKED = ['169.254.0.0/16', '100.100.100.200/32'];
/** Non-public IPv4 space; only forwarded to when WG_ALLOWED_IPS names it explicitly. */
const NON_PUBLIC = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '172.16.0.0/12',
  '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4',
];

/**
 * IPv4 CIDRs from a comma-separated env value, normalized to network address.
 *
 * @param {string} list
 * @returns {{ address: string, cidr: number }[]}
 */
const parseIPv4List = (list) => String(list || '')
  .split(',')
  .map((entry) => entry.trim())
  .map((entry) => {
    const [address, prefix = '32'] = entry.split('/');
    const cidr = Number(prefix);
    if (!Util.isValidIPv4(address) || !/^\d{1,2}$/.test(prefix) || cidr > 32) return null;
    return { address: Util.networkAddress(address, cidr), cidr };
  })
  .filter(Boolean);

const toCidr = ({ address, cidr }) => `${address}/${cidr}`;
const fromCidr = (value) => {
  const [address, cidr] = value.split('/');
  return { address, cidr: Number(cidr) };
};
/** a lies entirely inside b */
const within = (a, b) => a.cidr >= b.cidr && Util.cidrOverlaps(a, b);
// WireGuard data message: 16-byte header + 16-byte auth tag, payload padded to 16 bytes
const WG_MESSAGE_OVERHEAD = 32;
const WG_PADDING = 16;
const PEER_FLOW_MAX_WINDOW_SEC = 5;
const PEER_FLOW_MIN_INTERVAL_MS = 500;

/** Fixed-looking WireGuard keys for DEMO_TRAFFIC only (not used on the wire). */
const DEMO_KEY = (seed) => {
  const buf = crypto.createHash('sha256').update(`wg-easy-demo:${seed}`).digest();
  return buf.toString('base64');
};

module.exports = class WireGuard {

  __buildDemoConfig() {
    const clients = {};
    const demos = [
      {
        name: 'Laptop', address: '10.8.0.2', pattern: 'steady', enabled: true,
      },
      {
        name: 'Phone', address: '10.8.0.3', pattern: 'bursty', enabled: true,
      },
      {
        name: 'NAS', address: '10.8.0.4', pattern: 'heavy', enabled: true,
      },
      {
        name: 'TV', address: '10.8.0.5', pattern: 'idle', enabled: true,
      },
      {
        name: 'Office-PC', address: '10.8.0.6', pattern: 'upload', enabled: true,
      },
      {
        name: 'Tablet', address: '10.8.0.7', pattern: 'download', enabled: true,
      },
      {
        name: 'Spare', address: '10.8.0.8', pattern: 'offline', enabled: false,
      },
    ];

    demos.forEach((demo, index) => {
      const id = crypto.createHash('sha1').update(`demo-client-${index}`).digest('hex')
        .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12}).*$/, '$1-$2-$3-$4-$5');
      clients[id] = {
        id,
        name: demo.name,
        address: demo.address,
        privateKey: DEMO_KEY(`priv:${demo.name}`),
        publicKey: DEMO_KEY(`pub:${demo.name}`),
        preSharedKey: DEMO_KEY(`psk:${demo.name}`),
        createdAt: new Date(Date.now() - (index + 1) * 86400000),
        updatedAt: new Date(),
        allowedIPs: [{ type: 'ipv4', address: demo.address, cidr: 32 }],
        enabled: demo.enabled,
        fenced: false,
        __demoPattern: demo.pattern,
      };
    });

    return {
      server: {
        privateKey: DEMO_KEY('server-priv'),
        publicKey: DEMO_KEY('server-pub'),
        address: WG_DEFAULT_ADDRESS.replace('x', '1'),
      },
      clients,
    };
  }

  __demoTransfer(pattern, elapsedSec) {
    // cumulative bytes of a rate pulsing between 0 and `amp` B/s; monotonic like real counters
    const wave = (period, amp) => {
      const w = (Math.PI * 2) / period;
      return (amp / 2) * (elapsedSec - Math.sin(w * elapsedSec) / w);
    };
    switch (pattern) {
      case 'steady':
        return { rx: 42000 * elapsedSec, tx: 18000 * elapsedSec };
      case 'bursty':
        return {
          rx: (8000 * elapsedSec) + wave(11, 1500000),
          tx: (5000 * elapsedSec) + wave(7, 400000),
        };
      case 'heavy':
        return { rx: 380000 * elapsedSec, tx: 120000 * elapsedSec };
      case 'idle':
        return { rx: 120 * elapsedSec, tx: 80 * elapsedSec };
      case 'upload':
        return { rx: 15000 * elapsedSec, tx: 520000 * elapsedSec };
      case 'download':
        return { rx: 640000 * elapsedSec, tx: 22000 * elapsedSec };
      case 'offline':
      default:
        return { rx: 0, tx: 0 };
    }
  }

  async __getDemoClients() {
    const config = await this.getConfig();
    const elapsedSec = (Date.now() - this.__demoStartedAt) / 1000;

    return Object.entries(config.clients).map(([clientId, client]) => {
      const { rx, tx } = this.__demoTransfer(client.__demoPattern, elapsedSec);
      const online = client.enabled && client.__demoPattern !== 'offline';
      return {
        id: clientId,
        name: client.name,
        enabled: client.enabled,
        fenced: false,
        address: client.address,
        publicKey: client.publicKey,
        createdAt: new Date(client.createdAt),
        updatedAt: new Date(client.updatedAt),
        allowedIPs: client.allowedIPs,
        downloadableConfig: true,
        persistentKeepalive: online ? '25' : null,
        latestHandshakeAt: online ? new Date(Date.now() - (client.__demoPattern === 'idle' ? 90000 : 8000)) : null,
        transferRx: Math.floor(rx),
        transferTx: Math.floor(tx),
      };
    });
  }

  async __buildConfig() {
    if (!WG_HOST) {
      throw new Error('WG_HOST Environment Variable Not Set!');
    }

    debug('Loading configuration...');
    let raw;
    try {
      raw = await fs.readFile(path.join(WG_PATH, 'wg0.json'), 'utf8');
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      const privateKey = await Util.exec('wg genkey');
      const publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`, {
        log: 'echo ***hidden*** | wg pubkey',
      });
      debug('Configuration generated.');
      const initial = {
        server: { privateKey, publicKey, address: WG_DEFAULT_ADDRESS.replace('x', '1') },
        clients: {},
      };
      await this.__persistConfig(initial);
      return initial;
    }

    try {
      return JSON.parse(raw);
    } catch {
      // Node's JSON parser may include private key material in its error message.
      throw new Error('Invalid JSON in wg0.json. Repair the file or restore a valid backup.');
    }
  }

  async getConfig() {
    await this.__queue;
    return this.__getReadyConfig();
  }

  async __getReadyConfig() {
    if (this.__configError) throw this.__configError;
    if (DEMO_TRAFFIC) {
      if (!this.__configPromise) {
        this.__demoStartedAt = Date.now();
        this.__configPromise = Promise.resolve(this.__buildDemoConfig());
        // eslint-disable-next-line no-console
        console.warn('DEMO_TRAFFIC=1: serving mock peers for UI preview (no WireGuard).');
      }
      return this.__configPromise;
    }

    if (!this.__configPromise) {
      this.__configPromise = this.__initialize();
    }
    return this.__configPromise;
  }

  async __initialize() {
    const config = await this.__buildConfig();

    await this.__writeInterfaceConfig(config);
    await Util.exec('wg-quick down wg0').catch(() => { });
    await this.__syncFirewall(config);
    await Util.exec('wg-quick up wg0').catch((err) => {
      if (err && err.message && err.message.includes('Cannot find device "wg0"')) {
        throw new Error('WireGuard exited with the error: Cannot find device "wg0"\nThis usually means that your host\'s kernel does not support WireGuard!');
      }

      throw err;
    });
    // PostUp may have inserted rules above ours; re-pin before peers can talk
    await this.__syncFirewall(config);
    await this.__syncConfig();
    return config;
  }

  __serialize(task) {
    const result = (this.__queue ?? Promise.resolve()).then(() => task());
    this.__queue = result.catch(() => {});
    return result;
  }

  async saveConfig() {
    return this.__mutate(() => {});
  }

  /**
   * Applies `fn` to the config, persists it and pushes it to WireGuard and
   * iptables. If applying fails, the previous state is restored and re-applied,
   * so the stored config never claims protections (e.g. fencing) that are not
   * actually in force.
   *
   * @template T
   * @param {(config: object) => T | Promise<T>} fn
   * @returns {Promise<T>}
   */
  async __mutate(fn) {
    return this.__serialize(async () => {
      const previous = await this.__getReadyConfig();
      const candidate = structuredClone(previous);
      const result = await fn(candidate);
      try {
        await this.__applyConfig(candidate);
        await this.__persistConfig(candidate);
      } catch (err) {
        try {
          await this.__applyConfig(previous);
        } catch (rollbackErr) {
          this.__configError = new ServerError('WireGuard configuration rollback failed. Restart required.', 503);
          // eslint-disable-next-line no-console
          console.error(this.__configError.message, rollbackErr);
          await Util.exec('ip link set dev wg0 down');
          throw this.__configError;
        }
        throw err;
      }
      this.__configPromise = Promise.resolve(candidate);
      return result;
    });
  }

  async __applyConfig(config) {
    if (DEMO_TRAFFIC) return;
    await this.__writeInterfaceConfig(config);
    await this.__syncFirewall(config);
    await this.__syncConfig();
    await this.__syncRoutes(config);
  }

  async __runAll(commands, what) {
    const failures = [];
    for (const cmd of commands) {
      await Util.exec(cmd).catch((err) => failures.push(`${cmd}: ${err.message.trim()}`));
    }

    if (failures.length > 0) {
      throw new ServerError(`Failed to apply ${what}:\n${failures.join('\n')}`, 500);
    }
  }

  /**
   * iptables-restore input for the WG_EASY_* chains (traffic arriving on wg0).
   * Declaring a chain in iptables-restore flushes it, so the whole rule set is
   * replaced atomically.
   */
  __buildFirewallRules(config) {
    const sources = Object.values(config.clients)
      .filter((client) => client.fenced)
      .flatMap((client) => client.allowedIPs ?? [{ address: client.address, cidr: 32 }])
      .map(({ address, cidr }) => `${Util.networkAddress(address, cidr)}/${cidr}`);

    const rules = [
      '*filter',
      ':WG_EASY_FWD - [0:0]',
      ':WG_EASY_IN - [0:0]',
      // fenced peers may only answer connections opened towards them
      ...sources.flatMap((src) => [
        `-A WG_EASY_FWD -s ${src} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT`,
        `-A WG_EASY_FWD -s ${src} -j REJECT`,
        `-A WG_EASY_IN -s ${src} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT`,
        `-A WG_EASY_IN -s ${src} -j REJECT`,
      ]),
    ];

    if (!WEBUI_VPN_ACCESS) {
      rules.push(`-A WG_EASY_IN -p tcp -m tcp --dport ${PORT} -j REJECT --reject-with tcp-reset`);
    }

    if (WG_EGRESS_FILTER) {
      const nonPublic = NON_PUBLIC.map(fromCidr);
      const isNonPublic = (ip) => nonPublic.some((range) => within(ip, range));
      const allowed = parseIPv4List(WG_ALLOWED_IPS);
      // a resolver on a private address (e.g. a LAN DNS) is reachable on port 53 only
      const privateDns = parseIPv4List(WG_DEFAULT_DNS).filter((ip) => ip.cidr === 32 && isNonPublic(ip));
      rules.push(
        // peer to peer, and subnets routed by peers, stay inside the VPN
        '-A WG_EASY_FWD -o wg0 -j RETURN',
        '-A WG_EASY_FWD -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j RETURN',
        ...ALWAYS_BLOCKED.map((dst) => `-A WG_EASY_FWD -d ${dst} -j REJECT`),
        ...privateDns.flatMap((ip) => ['udp', 'tcp'].map((proto) => `-A WG_EASY_FWD -d ${toCidr(ip)} -p ${proto} -m ${proto} --dport 53 -j RETURN`)),
        // private ranges are reachable only when WG_ALLOWED_IPS names them explicitly
        ...allowed.filter(isNonPublic).map((ip) => `-A WG_EASY_FWD -d ${toCidr(ip)} -j RETURN`),
        ...NON_PUBLIC.map((dst) => `-A WG_EASY_FWD -d ${dst} -j REJECT`),
        ...allowed.filter((ip) => !isNonPublic(ip)).map((ip) => `-A WG_EASY_FWD -d ${toCidr(ip)} -j RETURN`),
        '-A WG_EASY_FWD -j REJECT',
      );
    }

    rules.push('COMMIT');
    return rules.join('\n');
  }

  async __syncFirewall(config) {
    const rules = this.__buildFirewallRules(config);

    await Util.exec(`iptables-restore --noflush <<'EOF'\n${rules}\nEOF`, {
      log: 'iptables-restore --noflush (WG_EASY_* chains)',
    }).catch((err) => {
      throw new ServerError(`Failed to apply firewall rules:\n${err.message.trim()}`, 500);
    });

    await this.__pinHook('FORWARD', 'WG_EASY_FWD');
    await this.__pinHook('INPUT', 'WG_EASY_IN');
  }

  /**
   * Makes `-i wg0 -j <target>` the first rule of `chain`. Inserts before
   * deleting, so there is never a moment without the hook.
   */
  async __pinHook(chain, target) {
    const spec = `-A ${chain} -i wg0 -j ${target}`;
    const listRules = async () => (await Util.exec(`iptables -S ${chain}`, { log: false }))
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.startsWith('-A '));

    try {
      const rules = await listRules();
      if (rules[0] === spec && !rules.slice(1).includes(spec)) return;

      if (rules[0] !== spec) {
        await Util.exec(`iptables -I ${chain} 1 -i wg0 -j ${target}`);
      }
      const after = await listRules();
      for (let i = after.length - 1; i >= 1; i--) {
        if (after[i] === spec) {
          await Util.exec(`iptables -D ${chain} ${i + 1}`);
        }
      }
    } catch (err) {
      throw new ServerError(`Failed to apply firewall hook ${chain} -> ${target}:\n${err.message.trim()}`, 500);
    }
  }

  async __syncRoutes(config) {
    const wgSubnet = WG_DEFAULT_ADDRESS.replace('x', '0');
    const isWgSubnet = (address) => Util.networkAddress(address, 24) === wgSubnet;

    const desired = new Set();
    for (const client of Object.values(config.clients)) {
      if (!client.enabled || !client.allowedIPs) continue;
      for (const { address, cidr } of client.allowedIPs) {
        if (!isWgSubnet(address)) desired.add(`${Util.networkAddress(address, cidr)}/${cidr}`);
      }
    }

    const current = (await Util.exec('ip -4 route show dev wg0', { log: false }))
      .split('\n')
      .map((line) => line.split(' ')[0])
      .filter((dst) => Util.isValidIPv4(dst.split('/')[0]))
      .map((dst) => (dst.includes('/') ? dst : `${dst}/32`))
      .filter((dst) => !isWgSubnet(dst.split('/')[0]));

    await this.__runAll([
      ...current.filter((dst) => !desired.has(dst)).map((dst) => `ip route del ${dst} dev wg0`),
      ...[...desired].map((dst) => `ip route replace ${dst} dev wg0`),
    ], 'routes');
  }

  /**
   * @param {unknown} name
   * @returns {string}
   */
  __validateName(name) {
    if (typeof name !== 'string') {
      throw new ServerError('Invalid name', 400);
    }
    const trimmed = name.trim();
    if (trimmed.length === 0 || trimmed.length > MAX_NAME_LENGTH || CONTROL_CHARS.test(trimmed)) {
      throw new ServerError(`Name must be 1-${MAX_NAME_LENGTH} printable characters`, 400);
    }
    return trimmed;
  }

  /**
   * Client addresses must be hosts of the VPN /24, other than the server.
   *
   * @param {object} config
   * @param {unknown} address
   */
  __assertClientAddress(config, address) {
    const wgSubnet = WG_DEFAULT_ADDRESS.replace('x', '0');
    if (!Util.isValidIPv4(address)
      || Util.networkAddress(address, 24) !== wgSubnet
      || ['0', '255'].includes(address.split('.')[3])
      || address === config.server.address) {
      throw new ServerError(`Invalid Address: ${address} (must be a host in ${wgSubnet}/24)`, 400);
    }
  }

  __buildAllowedIPs(client, allowedIPs) {
    if (!Array.isArray(allowedIPs)) {
      throw new ServerError('Invalid AllowedIPs', 400);
    }

    const extra = allowedIPs
      .filter((item) => !(item?.address === client.address && item?.cidr === 32))
      .map((item) => {
        const errorMessage = Util.validateAllowedIP(item ?? {});
        if (errorMessage) {
          throw new ServerError(errorMessage, 400);
        }
        return { type: 'ipv4', address: Util.networkAddress(item.address, item.cidr), cidr: item.cidr };
      });

    return [{ type: 'ipv4', address: client.address, cidr: 32 }, ...extra];
  }

  __claimedIPs(config, exceptClientId) {
    return [
      { address: config.server.address, cidr: 32 },
      ...Object.entries(config.clients)
        .filter(([clientId]) => clientId !== exceptClientId)
        .flatMap(([, client]) => client.allowedIPs ?? [{ address: client.address, cidr: 32 }]),
    ];
  }

  __assertNoOverlap(config, clientId, allowedIPs) {
    const claimed = this.__claimedIPs(config, clientId);
    allowedIPs.forEach((ip, index) => {
      const conflict = [...claimed, ...allowedIPs.slice(0, index)].find((other) => Util.cidrOverlaps(ip, other));
      if (conflict) {
        throw new ServerError(`${ip.address}/${ip.cidr} overlaps with ${conflict.address}/${conflict.cidr}`, 400);
      }
    });
  }

  __validateConfig(config) {
    const isKey = (value) => typeof value === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(value);
    const isOptionalKey = (value) => value == null || isKey(value);
    const fail = (part) => {
      throw new ServerError(`Invalid configuration: ${part}`, 400);
    };

    const { server, clients } = config ?? {};
    const wgSubnet = WG_DEFAULT_ADDRESS.replace('x', '0');
    if (!server || !isKey(server.privateKey) || !isKey(server.publicKey)
      || !Util.isValidIPv4(server.address) || Util.networkAddress(server.address, 24) !== wgSubnet) {
      fail('server');
    }
    if (!clients || typeof clients !== 'object' || Array.isArray(clients)) {
      fail('clients');
    }

    for (const [clientId, client] of Object.entries(clients)) {
      if (!CLIENT_ID.test(clientId)
        || typeof client?.name !== 'string'
        || typeof client.enabled !== 'boolean'
        || !isKey(client.publicKey)
        || !isOptionalKey(client.privateKey)
        || !isOptionalKey(client.preSharedKey)
        || (client.fenced !== undefined && typeof client.fenced !== 'boolean')) {
        fail(`client ${clientId}`);
      }
      try {
        client.name = this.__validateName(client.name);
        this.__assertClientAddress(config, client.address);
      } catch (err) {
        fail(`client ${clientId}: ${err.message}`);
      }
      if (client.allowedIPs !== undefined) {
        client.allowedIPs = this.__buildAllowedIPs(client, client.allowedIPs);
      }
    }

    for (const [clientId, client] of Object.entries(clients)) {
      this.__assertNoOverlap(config, clientId, client.allowedIPs ?? [{ address: client.address, cidr: 32 }]);
    }
  }

  async __persistConfig(config) {
    if (DEMO_TRAFFIC) return;
    const dest = path.join(WG_PATH, 'wg0.json');
    const temp = `${dest}.${crypto.randomUUID()}.tmp`;
    try {
      await fs.writeFile(temp, JSON.stringify(config, null, 2), { mode: 0o600, flag: 'wx' });
      await fs.rename(temp, dest);
    } finally {
      await fs.rm(temp, { force: true });
    }
  }

  async __writeInterfaceConfig(config) {
    // demo data carries well-known keys: never let it reach disk or the interface
    if (DEMO_TRAFFIC) return;
    let result = `
# Note: Do not edit this file directly.
# Your changes will be overwritten!

# Server
[Interface]
PrivateKey = ${config.server.privateKey}
Address = ${config.server.address}/24
ListenPort = ${WG_PORT}
PreUp = ${WG_PRE_UP}
PostUp = ${WG_POST_UP}
PreDown = ${WG_PRE_DOWN}
PostDown = ${WG_POST_DOWN}
`;

    for (const [clientId, client] of Object.entries(config.clients)) {
      if (!client.enabled) continue;
      let allowedIPs = '';
      if (client?.allowedIPs) {
        for (const allowedIP of client.allowedIPs) {
          allowedIPs += `,${allowedIP.address}/${allowedIP.cidr}`;
        }
        allowedIPs = allowedIPs.substring(1);
      } else {
        allowedIPs = client.address;
      }
      result += `

# Client: ${`${client.name} (${clientId})`.replace(/[\r\n]/g, ' ')}
[Peer]
PublicKey = ${client.publicKey}
${client.preSharedKey ? `PresharedKey = ${client.preSharedKey}\n` : ''
}AllowedIPs = ${allowedIPs}`;
    }

    debug('Config saving...');
    await fs.writeFile(path.join(WG_PATH, 'wg0.conf'), result, {
      mode: 0o600,
    });
    debug('Config saved.');
  }

  async __syncConfig() {
    debug('Config syncing...');
    await Util.exec('wg syncconf wg0 <(wg-quick strip wg0)');
    debug('Config synced.');
  }

  __getDemoPeerFlows(clients) {
    const byName = new Map(clients.map((client) => [client.name, client.id]));
    // kept within each demo client's own up/down rates so the totals stay consistent
    const flows = [
      ['Tablet', 'Office-PC', 400000, 10000],
      ['Laptop', 'NAS', 30000, 15000],
      ['NAS', 'Office-PC', 100000, 3000],
      ['TV', 'Phone', 60, 50],
      ['Laptop', 'TV', 0, 0],
    ];
    return {
      supported: true,
      accounting: true,
      flows: flows
        .filter(([a, b]) => byName.has(a) && byName.has(b))
        .map(([a, b, ab, ba]) => ({
          a: byName.get(a),
          b: byName.get(b),
          ab,
          ba,
          abPackets: 0,
          baPackets: 0,
          connections: 1,
        })),
    };
  }

  /**
   * Per-device traffic that is not device-to-device, from WireGuard counters
   * sampled in the same window as the conntrack flows.
   */
  __otherTraffic(clients, peers) {
    const now = Date.now();
    const prev = this.__wgPrev;
    this.__wgPrev = {
      at: now,
      counters: new Map(clients.map((c) => [c.id, { rx: c.transferRx || 0, tx: c.transferTx || 0 }])),
    };
    const dt = prev ? (now - prev.at) / 1000 : 0;
    if (!peers.accounting || dt <= 0 || dt > PEER_FLOW_MAX_WINDOW_SEC) return null;

    const peerOut = new Map();
    const peerIn = new Map();
    const slack = new Map();
    const add = (map, id, bytes, packets) => {
      const avg = packets > 0 ? bytes / packets : 0;
      const pad = (WG_PADDING - (Math.round(avg) % WG_PADDING)) % WG_PADDING;
      map.set(id, (map.get(id) || 0) + bytes + packets * (WG_MESSAGE_OVERHEAD + pad));
      // padding is estimated from the average packet size, so allow one block per packet
      slack.set(id, (slack.get(id) || 0) + packets * WG_PADDING);
    };
    peers.flows.forEach((f) => {
      add(peerOut, f.a, f.ab, f.abPackets || 0);
      add(peerIn, f.b, f.ab, f.abPackets || 0);
      add(peerOut, f.b, f.ba, f.baPackets || 0);
      add(peerIn, f.a, f.ba, f.baPackets || 0);
    });

    const residual = (total, peer, tolerance) => {
      const rest = total - peer;
      // counters are read a few ms apart and the overhead is estimated: ignore noise
      return rest > Math.max(512, total * 0.03, tolerance) ? Math.round(rest) : 0;
    };

    const devices = {};
    clients.forEach((client) => {
      const before = prev.counters.get(client.id);
      if (!before) return;
      const up = Math.max(0, (client.transferRx || 0) - before.rx) / dt;
      const down = Math.max(0, (client.transferTx || 0) - before.tx) / dt;
      devices[client.id] = {
        otherUp: residual(up, peerOut.get(client.id) || 0, slack.get(client.id) || 0),
        otherDown: residual(down, peerIn.get(client.id) || 0, slack.get(client.id) || 0),
      };
    });
    return devices;
  }

  /**
   * Concurrent callers (several open tabs) share one sample, and samples are
   * at least PEER_FLOW_MIN_INTERVAL_MS apart, so the conntrack table is read
   * at a bounded rate and the shared baseline is never raced.
   */
  async getPeerFlows() {
    if (this.__peerFlowsPending) return this.__peerFlowsPending;
    if (this.__peerFlowsLast && Date.now() - this.__peerFlowsLast.at < PEER_FLOW_MIN_INTERVAL_MS) {
      return this.__peerFlowsLast.result;
    }
    this.__peerFlowsPending = this.__samplePeerFlows()
      .then((result) => {
        this.__peerFlowsLast = { at: Date.now(), result };
        return result;
      })
      .finally(() => {
        this.__peerFlowsPending = null;
      });
    return this.__peerFlowsPending;
  }

  async __samplePeerFlows() {
    const clients = await this.getClients();
    let peers;
    if (DEMO_TRAFFIC) {
      peers = this.__getDemoPeerFlows(clients);
    } else {
      if (!this.__peerFlows) this.__peerFlows = new PeerFlows();
      peers = await this.__peerFlows.sample(clients);
    }
    return { ...peers, devices: this.__otherTraffic(clients, peers) };
  }

  async getClients() {
    if (DEMO_TRAFFIC) {
      return this.__getDemoClients();
    }

    const config = await this.getConfig();
    const clients = Object.entries(config.clients).map(([clientId, client]) => ({
      id: clientId,
      name: client.name,
      enabled: client.enabled,
      fenced: client.fenced === true,
      address: client.address,
      publicKey: client.publicKey,
      createdAt: new Date(client.createdAt),
      updatedAt: new Date(client.updatedAt),
      allowedIPs: client?.allowedIPs ? client.allowedIPs : [{ type: 'ipv4', address: client.address, cidr: 32 }],
      downloadableConfig: 'privateKey' in client,
      persistentKeepalive: null,
      latestHandshakeAt: null,
      transferRx: null,
      transferTx: null,
    }));

    // Loop WireGuard status
    const dump = await Util.exec('wg show wg0 dump', {
      log: false,
    });
    dump
      .trim()
      .split('\n')
      .slice(1)
      .forEach((line) => {
        const [
          publicKey,
          preSharedKey, // eslint-disable-line no-unused-vars
          endpoint, // eslint-disable-line no-unused-vars
          allowedIps, // eslint-disable-line no-unused-vars
          latestHandshakeAt,
          transferRx,
          transferTx,
          persistentKeepalive,
        ] = line.split('\t');

        const client = clients.find((client) => client.publicKey === publicKey);
        if (!client) return;

        client.latestHandshakeAt = latestHandshakeAt === '0'
          ? null
          : new Date(Number(`${latestHandshakeAt}000`));
        client.transferRx = Number(transferRx);
        client.transferTx = Number(transferTx);
        client.persistentKeepalive = persistentKeepalive;
      });

    return clients;
  }

  async getClient({ clientId }) {
    const config = await this.getConfig();
    const client = Object.hasOwn(config.clients, clientId) ? config.clients[clientId] : null;
    if (!client) {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }

    return client;
  }

  __fencedAllowedIPs(config) {
    const wgSubnet = `${WG_DEFAULT_ADDRESS.replace('x', '0')}/24`;
    const routed = Object.values(config.clients)
      .filter((client) => !client.fenced)
      .flatMap((client) => (client.allowedIPs ?? []).slice(1))
      .map(({ address, cidr }) => `${address}/${cidr}`);

    return [wgSubnet, ...routed].join(', ');
  }

  async getClientConfiguration({ clientId }) {
    const config = await this.getConfig();
    const client = await this.getClient({ clientId });
    const dns = client.fenced ? null : WG_DEFAULT_DNS;

    return `
[Interface]
PrivateKey = ${client.privateKey ? `${client.privateKey}` : 'REPLACE_ME'}
Address = ${client.address}/24
${dns ? `DNS = ${dns}\n` : ''}\
${WG_MTU ? `MTU = ${WG_MTU}\n` : ''}\

[Peer]
PublicKey = ${config.server.publicKey}
${client.preSharedKey ? `PresharedKey = ${client.preSharedKey}\n` : ''
}AllowedIPs = ${client.fenced ? this.__fencedAllowedIPs(config) : WG_ALLOWED_IPS}
PersistentKeepalive = ${client.fenced ? FENCED_KEEPALIVE : WG_PERSISTENT_KEEPALIVE}
Endpoint = ${WG_HOST}:${WG_CONFIG_PORT}`;
  }

  async getClientQRCodeSVG({ clientId }) {
    const config = await this.getClientConfiguration({ clientId });
    return QRCode.toString(config, {
      type: 'svg',
      width: 512,
    });
  }

  async createClient({ name, fenced = false }) {
    const validName = this.__validateName(name);
    if (typeof fenced !== 'boolean') {
      throw new ServerError('Invalid fenced', 400);
    }

    const privateKey = await Util.exec('wg genkey');
    const publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`, {
      log: 'echo ***hidden*** | wg pubkey',
    });
    const preSharedKey = await Util.exec('wg genpsk');

    return this.__mutate((config) => {
      // Calculate next IP
      const claimed = this.__claimedIPs(config);
      let address;
      for (let i = 2; i < 255; i++) {
        const candidate = { address: WG_DEFAULT_ADDRESS.replace('x', i), cidr: 32 };
        if (!claimed.some((ip) => Util.cidrOverlaps(ip, candidate))) {
          address = candidate.address;
          break;
        }
      }

      if (!address) {
        throw new ServerError('Maximum number of clients reached.', 400);
      }

      const id = crypto.randomUUID();
      const client = {
        id,
        name: validName,
        address,
        privateKey,
        publicKey,
        preSharedKey,

        createdAt: new Date(),
        updatedAt: new Date(),

        allowedIPs: [{ type: 'ipv4', address, cidr: 32 }],

        enabled: true,
        fenced,
      };

      config.clients[id] = client;
      return client;
    });
  }

  /**
   * Looks a client up inside a mutation.
   */
  __clientOf(config, clientId) {
    const client = typeof clientId === 'string' && Object.hasOwn(config.clients, clientId)
      ? config.clients[clientId]
      : null;
    if (!client) {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }
    return client;
  }

  async deleteClient({ clientId }) {
    await this.__mutate((config) => {
      if (Object.hasOwn(config.clients, clientId)) {
        delete config.clients[clientId];
      }
    });
  }

  async enableClient({ clientId }) {
    await this.__mutate((config) => {
      const client = this.__clientOf(config, clientId);
      client.enabled = true;
      client.updatedAt = new Date();
    });
  }

  async disableClient({ clientId }) {
    await this.__mutate((config) => {
      const client = this.__clientOf(config, clientId);
      client.enabled = false;
      client.updatedAt = new Date();
    });
  }

  async updateClientName({ clientId, name }) {
    const validName = this.__validateName(name);
    await this.__mutate((config) => {
      const client = this.__clientOf(config, clientId);
      client.name = validName;
      client.updatedAt = new Date();
    });
  }

  async updateClientFenced({ clientId, fenced }) {
    if (typeof fenced !== 'boolean') {
      throw new ServerError('Invalid fenced', 400);
    }
    await this.__mutate((config) => {
      const client = this.__clientOf(config, clientId);
      client.fenced = fenced;
      client.updatedAt = new Date();
    });
  }

  async updateClientAddress({ clientId, address }) {
    await this.__mutate((config) => {
      const client = this.__clientOf(config, clientId);
      this.__assertClientAddress(config, address);

      const allowedIPs = [{ type: 'ipv4', address, cidr: 32 }, ...(client.allowedIPs ?? []).slice(1)];
      this.__assertNoOverlap(config, clientId, allowedIPs);

      if (client.allowedIPs) {
        client.allowedIPs = allowedIPs;
      }

      client.address = address;
      client.updatedAt = new Date();
    });
  }

  async updateClientAllowedIPs({ clientId, allowedIPs }) {
    await this.__mutate((config) => {
      const client = this.__clientOf(config, clientId);

      const normalized = this.__buildAllowedIPs(client, allowedIPs);
      this.__assertNoOverlap(config, clientId, normalized);

      client.allowedIPs = normalized;
      client.updatedAt = new Date();
    });
  }

  async restoreConfiguration(config) {
    if (DEMO_TRAFFIC) {
      throw new ServerError('Restore is disabled in DEMO_TRAFFIC mode', 400);
    }
    if (typeof config !== 'string') {
      throw new ServerError('Invalid configuration: expected a JSON string', 400);
    }
    debug('Starting configuration restore process.');
    let _config;
    try {
      _config = JSON.parse(config);
    } catch (err) {
      throw new ServerError(`Invalid configuration: ${err.message}`, 400);
    }
    this.__validateConfig(_config);
    await this.__mutate((candidate) => {
      candidate.server = _config.server;
      candidate.clients = _config.clients;
    });
    debug('Configuration restore process completed.');
  }

  async backupConfiguration() {
    debug('Starting configuration backup.');
    const config = await this.getConfig();
    const backup = JSON.stringify(config, null, 2);
    debug('Configuration backup completed.');
    return backup;
  }

  // Shutdown wireguard
  async Shutdown() {
    if (DEMO_TRAFFIC) return;
    await Util.exec('wg-quick down wg0').catch(() => { });
  }

};
