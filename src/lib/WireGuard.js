'use strict';

const fs = require('node:fs/promises');
const path = require('path');
const debug = require('debug')('WireGuard');
const crypto = require('node:crypto');
const QRCode = require('qrcode');

const Util = require('./Util');
const ServerError = require('./ServerError');

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
} = require('../config');

module.exports = class WireGuard {

  async __buildConfig() {
    this.__configPromise = Promise.resolve().then(async () => {
      if (!WG_HOST) {
        throw new Error('WG_HOST Environment Variable Not Set!');
      }

      debug('Loading configuration...');
      let config;
      try {
        config = await fs.readFile(path.join(WG_PATH, 'wg0.json'), 'utf8');
        config = JSON.parse(config);
        debug('Configuration loaded.');
      } catch (err) {
        const privateKey = await Util.exec('wg genkey');
        const publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`, {
          log: 'echo ***hidden*** | wg pubkey',
        });
        const address = WG_DEFAULT_ADDRESS.replace('x', '1');

        config = {
          server: {
            privateKey,
            publicKey,
            address,
          },
          clients: {},
        };
        debug('Configuration generated.');
      }

      return config;
    });

    return this.__configPromise;
  }

  async getConfig() {
    if (!this.__configPromise) {
      const config = await this.__buildConfig();

      await this.__saveConfig(config);
      await Util.exec('wg-quick down wg0').catch(() => { });
      await Util.exec('wg-quick up wg0').catch((err) => {
        if (err && err.message && err.message.includes('Cannot find device "wg0"')) {
          throw new Error('WireGuard exited with the error: Cannot find device "wg0"\nThis usually means that your host\'s kernel does not support WireGuard!');
        }

        throw err;
      });
      // await Util.exec(`iptables -t nat -A POSTROUTING -s ${WG_DEFAULT_ADDRESS.replace('x', '0')}/24 -o ' + WG_DEVICE + ' -j MASQUERADE`);
      // await Util.exec('iptables -A INPUT -p udp -m udp --dport 51820 -j ACCEPT');
      // await Util.exec('iptables -A FORWARD -i wg0 -j ACCEPT');
      // await Util.exec('iptables -A FORWARD -o wg0 -j ACCEPT');
      await this.__syncConfig();
    }

    return this.__configPromise;
  }

  async saveConfig() {
    const config = await this.getConfig();
    await this.__saveConfig(config);
    await this.__syncConfig();
    await this.__syncRoutes(config);
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
      .filter((dst) => dst)
      .map((dst) => (dst.includes('/') ? dst : `${dst}/32`))
      .filter((dst) => !isWgSubnet(dst.split('/')[0]));

    const commands = [
      ...current.filter((dst) => !desired.has(dst)).map((dst) => `ip route del ${dst} dev wg0`),
      ...[...desired].map((dst) => `ip route replace ${dst} dev wg0`),
    ];

    const failures = [];
    for (const cmd of commands) {
      await Util.exec(cmd).catch((err) => failures.push(`${cmd}: ${err.message.trim()}`));
    }

    if (failures.length > 0) {
      throw new ServerError(`Config saved, but failed to apply routes:\n${failures.join('\n')}`, 500);
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
    return Object.entries(config.clients)
      .filter(([clientId]) => clientId !== exceptClientId)
      .flatMap(([, client]) => client.allowedIPs ?? [{ address: client.address, cidr: 32 }]);
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
    if (!server || !isKey(server.privateKey) || !isKey(server.publicKey) || !Util.isValidIPv4(server.address)) {
      fail('server');
    }
    if (!clients || typeof clients !== 'object' || Array.isArray(clients)) {
      fail('clients');
    }

    for (const [clientId, client] of Object.entries(clients)) {
      if (typeof client?.name !== 'string'
        || !Util.isValidIPv4(client.address)
        || !isKey(client.publicKey)
        || !isOptionalKey(client.privateKey)
        || !isOptionalKey(client.preSharedKey)) {
        fail(`client ${clientId}`);
      }
      if (client.allowedIPs !== undefined) {
        client.allowedIPs = this.__buildAllowedIPs(client, client.allowedIPs);
      }
    }

    for (const [clientId, client] of Object.entries(clients)) {
      this.__assertNoOverlap(config, clientId, client.allowedIPs ?? [{ address: client.address, cidr: 32 }]);
    }
  }

  async __saveConfig(config) {
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
    await fs.writeFile(path.join(WG_PATH, 'wg0.json'), JSON.stringify(config, false, 2), {
      mode: 0o660,
    });
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

  async getClients() {
    const config = await this.getConfig();
    const clients = Object.entries(config.clients).map(([clientId, client]) => ({
      id: clientId,
      name: client.name,
      enabled: client.enabled,
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
    const client = config.clients[clientId];
    if (!client) {
      throw new ServerError(`Client Not Found: ${clientId}`, 404);
    }

    return client;
  }

  async getClientConfiguration({ clientId }) {
    const config = await this.getConfig();
    const client = await this.getClient({ clientId });

    return `
[Interface]
PrivateKey = ${client.privateKey ? `${client.privateKey}` : 'REPLACE_ME'}
Address = ${client.address}/24
${WG_DEFAULT_DNS ? `DNS = ${WG_DEFAULT_DNS}\n` : ''}\
${WG_MTU ? `MTU = ${WG_MTU}\n` : ''}\

[Peer]
PublicKey = ${config.server.publicKey}
${client.preSharedKey ? `PresharedKey = ${client.preSharedKey}\n` : ''
}AllowedIPs = ${WG_ALLOWED_IPS}
PersistentKeepalive = ${WG_PERSISTENT_KEEPALIVE}
Endpoint = ${WG_HOST}:${WG_CONFIG_PORT}`;
  }

  async getClientQRCodeSVG({ clientId }) {
    const config = await this.getClientConfiguration({ clientId });
    return QRCode.toString(config, {
      type: 'svg',
      width: 512,
    });
  }

  async createClient({ name }) {
    if (!name) {
      throw new Error('Missing: Name');
    }

    const config = await this.getConfig();

    const privateKey = await Util.exec('wg genkey');
    const publicKey = await Util.exec(`echo ${privateKey} | wg pubkey`, {
      log: 'echo ***hidden*** | wg pubkey',
    });
    const preSharedKey = await Util.exec('wg genpsk');

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
      throw new Error('Maximum number of clients reached.');
    }

    // Create Client
    const id = crypto.randomUUID();
    const client = {
      id,
      name,
      address,
      privateKey,
      publicKey,
      preSharedKey,

      createdAt: new Date(),
      updatedAt: new Date(),

      allowedIPs: [{ type: 'ipv4', address, cidr: 32 }],

      enabled: true,
    };

    config.clients[id] = client;

    await this.saveConfig();

    return client;
  }

  async deleteClient({ clientId }) {
    const config = await this.getConfig();

    if (config.clients[clientId]) {
      delete config.clients[clientId];
      await this.saveConfig();
    }
  }

  async enableClient({ clientId }) {
    const client = await this.getClient({ clientId });

    client.enabled = true;
    client.updatedAt = new Date();

    await this.saveConfig();
  }

  async disableClient({ clientId }) {
    const client = await this.getClient({ clientId });

    client.enabled = false;
    client.updatedAt = new Date();

    await this.saveConfig();
  }

  async updateClientName({ clientId, name }) {
    const client = await this.getClient({ clientId });

    client.name = name;
    client.updatedAt = new Date();

    await this.saveConfig();
  }

  async updateClientAddress({ clientId, address }) {
    const config = await this.getConfig();
    const client = await this.getClient({ clientId });

    if (!Util.isValidIPv4(address)) {
      throw new ServerError(`Invalid Address: ${address}`, 400);
    }

    const allowedIPs = [{ type: 'ipv4', address, cidr: 32 }, ...(client.allowedIPs ?? []).slice(1)];
    this.__assertNoOverlap(config, clientId, allowedIPs);

    if (client.allowedIPs) {
      client.allowedIPs = allowedIPs;
    }

    client.address = address;
    client.updatedAt = new Date();

    await this.saveConfig();
  }

  async __reloadConfig() {
    await this.__buildConfig();
    await this.__syncConfig();
  }

  async restoreConfiguration(config) {
    debug('Starting configuration restore process.');
    let _config;
    try {
      _config = JSON.parse(config);
    } catch (err) {
      throw new ServerError(`Invalid configuration: ${err.message}`, 400);
    }
    this.__validateConfig(_config);
    await this.__saveConfig(_config);
    await this.__reloadConfig();
    await this.__syncRoutes(_config);
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
    await Util.exec('wg-quick down wg0').catch(() => { });
  }

  async updateClientAllowedIPs({ clientId, allowedIPs }) {
    const config = await this.getConfig();
    const client = await this.getClient({ clientId });

    const normalized = this.__buildAllowedIPs(client, allowedIPs);
    this.__assertNoOverlap(config, clientId, normalized);

    client.allowedIPs = normalized;
    client.updatedAt = new Date();

    await this.saveConfig();
  }

};
