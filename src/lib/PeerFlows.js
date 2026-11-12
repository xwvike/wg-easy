'use strict';

const fs = require('node:fs/promises');
const debug = require('debug')('PeerFlows');

const Util = require('./Util');

const CONNTRACK_PATH = '/proc/net/nf_conntrack';
const MAX_LINES = 200000;
// a gap longer than this (e.g. modal closed) restarts the baseline instead of averaging
const MAX_WINDOW_SEC = 5;

/**
 * Parses one /proc/net/nf_conntrack line into its original and reply tuples.
 * Returns null for anything that is not a two-tuple IPv4 entry.
 */
function parseLine(line) {
  if (!line.startsWith('ipv4')) return null;
  const tokens = line.split(/\s+/);
  const tuples = [];
  let current = null;
  let proto = null;
  let sport = null;
  let dport = null;
  for (const token of tokens) {
    if (proto === null && /^(tcp|udp|icmp|gre|sctp|dccp|udplite|unknown)$/.test(token)) {
      proto = token;
    }
    const eq = token.indexOf('=');
    if (eq > 0) {
      const key = token.slice(0, eq);
      const value = token.slice(eq + 1);
      if (key === 'src') {
        current = {
          src: value, dst: null, bytes: null, packets: null,
        };
        tuples.push(current);
      } else if (current && key === 'dst' && current.dst === null) {
        current.dst = value;
      } else if (current && key === 'bytes') {
        current.bytes = Number(value);
      } else if (current && key === 'packets') {
        current.packets = Number(value);
      } else if (tuples.length === 1 && key === 'sport') {
        sport = value;
      } else if (tuples.length === 1 && key === 'dport') {
        dport = value;
      }
    }
  }
  if (tuples.length < 2 || !Util.isValidIPv4(tuples[0].src) || !Util.isValidIPv4(tuples[0].dst)) {
    return null;
  }
  return {
    key: `${proto}|${tuples[0].src}|${sport}|${tuples[0].dst}|${dport}`,
    src: tuples[0].src,
    dst: tuples[0].dst,
    origBytes: tuples[0].bytes,
    replyBytes: tuples[1].bytes,
    origPackets: tuples[0].packets || 0,
    replyPackets: tuples[1].packets || 0,
    unreplied: line.includes('[UNREPLIED]'),
  };
}

/**
 * Samples device-to-device traffic relayed by the VPN from the kernel
 * connection tracking table. Rates are bytes/s between two consecutive samples
 * and need net.netfilter.nf_conntrack_acct=1; without it only active
 * connections are reported.
 */
module.exports = class PeerFlows {

  constructor() {
    this.prev = new Map();
    this.prevAt = 0;
  }

  static __ownerOf(ip, clients) {
    for (const client of clients) {
      if (client.address === ip) return client.id;
    }
    for (const client of clients) {
      const nets = client.allowedIPs || [];
      if (nets.some((net) => net && net.cidr > 0 && Util.cidrOverlaps(net, { address: ip, cidr: 32 }))) {
        return client.id;
      }
    }
    return null;
  }

  /**
   * @param {Array<{id: string, address: string, allowedIPs?: Array}>} clients
   */
  async sample(clients) {
    let raw;
    try {
      raw = await fs.readFile(CONNTRACK_PATH, 'utf8');
    } catch (err) {
      debug(`conntrack unavailable: ${err.message}`);
      return { supported: false, accounting: false, flows: [] };
    }

    const now = Date.now();
    const elapsed = this.prevAt ? (now - this.prevAt) / 1000 : 0;
    const dt = elapsed <= MAX_WINDOW_SEC ? elapsed : 0;
    const owners = new Map();
    const ownerOf = (ip) => {
      if (!owners.has(ip)) owners.set(ip, PeerFlows.__ownerOf(ip, clients));
      return owners.get(ip);
    };

    const next = new Map();
    const pairs = new Map();
    let accounting = false;
    const lines = raw.split('\n');

    for (let i = 0; i < lines.length && i < MAX_LINES; i += 1) {
      const entry = parseLine(lines[i]);
      if (!entry) continue;
      const from = ownerOf(entry.src);
      const to = ownerOf(entry.dst);
      if (!from || !to || from === to) continue;

      const hasBytes = Number.isFinite(entry.origBytes) && Number.isFinite(entry.replyBytes);
      if (hasBytes) accounting = true;

      const [a, b] = from < to ? [from, to] : [to, from];
      const pairKey = `${a}|${b}`;
      if (!pairs.has(pairKey)) {
        pairs.set(pairKey, {
          a, b, ab: 0, ba: 0, abPackets: 0, baPackets: 0, connections: 0,
        });
      }
      const pair = pairs.get(pairKey);
      if (!entry.unreplied) pair.connections += 1;

      if (hasBytes) {
        const cur = {
          orig: entry.origBytes,
          reply: entry.replyBytes,
          origPackets: entry.origPackets,
          replyPackets: entry.replyPackets,
        };
        next.set(entry.key, cur);
        const before = this.prev.get(entry.key) || {
          orig: 0, reply: 0, origPackets: 0, replyPackets: 0,
        };
        if (dt > 0) {
          const fwd = Math.max(0, cur.orig - before.orig) / dt;
          const rev = Math.max(0, cur.reply - before.reply) / dt;
          const fwdPackets = Math.max(0, cur.origPackets - before.origPackets) / dt;
          const revPackets = Math.max(0, cur.replyPackets - before.replyPackets) / dt;
          const forward = from === a;
          pair.ab += forward ? fwd : rev;
          pair.ba += forward ? rev : fwd;
          pair.abPackets += forward ? fwdPackets : revPackets;
          pair.baPackets += forward ? revPackets : fwdPackets;
        }
      }
    }

    this.prev = next;
    this.prevAt = now;

    const flows = [...pairs.values()]
      .filter((pair) => (accounting ? pair.ab > 0 || pair.ba > 0 : pair.connections > 0))
      .map((pair) => ({
        a: pair.a,
        b: pair.b,
        ab: Math.round(pair.ab),
        ba: Math.round(pair.ba),
        abPackets: Math.round(pair.abPackets),
        baPackets: Math.round(pair.baPackets),
        connections: pair.connections,
      }));

    return { supported: true, accounting, flows };
  }

};

module.exports.parseLine = parseLine;
