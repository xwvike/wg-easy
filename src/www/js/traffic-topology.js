/* eslint-disable no-undef */

'use strict';

/**
 * D3 traffic topology: all devices ↔ VPN relay ↔ outside.
 * Particle density on each hop follows live throughput.
 */
class TrafficTopologyChart {

  constructor(container, {
    width = 840,
    height = 460,
    formatRate = (n) => `${n}`,
    dark = false,
  } = {}) {
    this.container = container;
    this.width = width;
    this.height = height;
    this.formatRate = formatRate;
    this.dark = dark;
    this.particles = [];
    this.paths = new Map();
    this.raf = null;
    this.lastTs = 0;

    d3.select(container).selectAll('*').remove();

    this.svg = d3.select(container)
      .append('svg')
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('class', 'w-full h-auto block select-none')
      .attr('role', 'img');

    const defs = this.svg.append('defs');
    const mkGrad = (id, c) => {
      const g = defs.append('linearGradient').attr('id', id)
        .attr('x1', '0%').attr('y1', '0%')
        .attr('x2', '100%')
        .attr('y2', '0%');
      g.append('stop').attr('offset', '0%').attr('stop-color', c).attr('stop-opacity', 0.15);
      g.append('stop').attr('offset', '50%').attr('stop-color', c).attr('stop-opacity', 0.9);
      g.append('stop').attr('offset', '100%').attr('stop-color', c).attr('stop-opacity', 0.15);
    };
    mkGrad('topo-up', '#b91c1c');
    mkGrad('topo-down', '#f87171');

    this.gLinks = this.svg.append('g').attr('class', 'topo-links');
    this.gParticles = this.svg.append('g').attr('class', 'topo-particles');
    this.gNodes = this.svg.append('g').attr('class', 'topo-nodes');
    this.gLabels = this.svg.append('g').attr('class', 'topo-labels');

    this.tick = this.tick.bind(this);
    this.raf = requestAnimationFrame(this.tick);
  }

  setDark(dark) {
    this.dark = dark;
  }

  destroy() {
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = null;
    d3.select(this.container).selectAll('*').remove();
    this.particles = [];
    this.paths.clear();
  }

  /**
   * @param {Array<{id:string,name:string,enabled:boolean,latestHandshakeAt:Date|null,transferRxCurrent:number,transferTxCurrent:number}>} clients
   */
  update(clients) {
    const list = (clients || []).slice();
    const hub = { x: this.width * 0.52, y: this.height * 0.5 };
    const net = { x: this.width * 0.88, y: this.height * 0.5 };
    const arcCx = this.width * 0.28;
    const arcCy = this.height * 0.5;
    const radius = Math.min(this.width * 0.22, this.height * 0.38);

    const devices = list.map((client, index) => {
      const n = Math.max(list.length, 1);
      const angle = n === 1
        ? Math.PI
        : Math.PI * 0.65 + ((index / (n - 1)) * Math.PI * 0.7);
      return {
        ...client,
        x: arcCx + (Math.cos(angle) * radius),
        y: arcCy + (Math.sin(angle) * radius),
        up: Math.max(0, client.transferRxCurrent || 0),
        down: Math.max(0, client.transferTxCurrent || 0),
        online: !!(client.enabled && client.latestHandshakeAt
          && (Date.now() - new Date(client.latestHandshakeAt).getTime()) < 180000),
      };
    });

    const maxRate = Math.max(
      1,
      ...devices.map((d) => d.up),
      ...devices.map((d) => d.down),
    );

    // Build path descriptors: device→hub and hub→net (up), net→hub and hub→device (down)
    const links = [];
    devices.forEach((d) => {
      const upNorm = Math.min(1, d.up / maxRate);
      const downNorm = Math.min(1, d.down / maxRate);
      links.push({
        id: `up-dev-${d.id}`,
        kind: 'up',
        d: this.curve(d.x, d.y, hub.x, hub.y, -1),
        rate: d.up,
        norm: upNorm,
        active: d.online && d.up > 0,
      });
      links.push({
        id: `up-net-${d.id}`,
        kind: 'up',
        d: this.curve(hub.x, hub.y, net.x, net.y, -1),
        rate: d.up,
        norm: upNorm,
        active: d.online && d.up > 0,
      });
      links.push({
        id: `down-net-${d.id}`,
        kind: 'down',
        d: this.curve(net.x, net.y, hub.x, hub.y, 1),
        rate: d.down,
        norm: downNorm,
        active: d.online && d.down > 0,
      });
      links.push({
        id: `down-dev-${d.id}`,
        kind: 'down',
        d: this.curve(hub.x, hub.y, d.x, d.y, 1),
        rate: d.down,
        norm: downNorm,
        active: d.online && d.down > 0,
      });
    });

    // Aggregate hub↔net stroke by total through traffic for visual clarity
    const totalUp = devices.reduce((s, d) => s + (d.online ? d.up : 0), 0);
    const totalDown = devices.reduce((s, d) => s + (d.online ? d.down : 0), 0);

    const linkSel = this.gLinks.selectAll('path.topo-link')
      .data(links, (d) => d.id);

    linkSel.exit().remove();

    const linkEnter = linkSel.enter().append('path')
      .attr('class', 'topo-link')
      .attr('fill', 'none')
      .attr('stroke-linecap', 'round');

    linkEnter.merge(linkSel)
      .attr('d', (d) => d.d)
      .attr('stroke', (d) => (d.kind === 'up' ? 'url(#topo-up)' : 'url(#topo-down)'))
      .attr('stroke-width', (d) => (d.active ? 1.2 + (d.norm * 5) : 1))
      .attr('opacity', (d) => (d.active ? 0.35 + (d.norm * 0.5) : 0.1));

    // Cache path lengths for particles
    this.paths.clear();
    this.gLinks.selectAll('path.topo-link').each((d, i, nodes) => {
      const el = nodes[i];
      this.paths.set(d.id, {
        el,
        length: el.getTotalLength(),
        rate: d.rate,
        norm: d.norm,
        active: d.active,
        kind: d.kind,
      });
    });

    this.syncParticles();

    // Nodes
    const nodeData = [
      ...devices.map((d) => ({
        key: `dev-${d.id}`,
        type: 'device',
        x: d.x,
        y: d.y,
        label: d.name,
        online: d.online,
        sub: this.formatRate(d.up + d.down),
      })),
      {
        key: 'hub',
        type: 'hub',
        x: hub.x,
        y: hub.y,
        label: 'VPN',
        online: true,
        sub: this.formatRate(totalUp + totalDown),
      },
      {
        key: 'net',
        type: 'net',
        x: net.x,
        y: net.y,
        label: 'NET',
        online: true,
        sub: this.formatRate(totalUp + totalDown),
      },
    ];

    const nodeSel = this.gNodes.selectAll('g.topo-node')
      .data(nodeData, (d) => d.key);

    nodeSel.exit().remove();

    const nodeEnter = nodeSel.enter().append('g').attr('class', 'topo-node');
    nodeEnter.append('circle').attr('class', 'topo-node-halo').attr('r', 28).attr('opacity', 0.25);
    nodeEnter.append('circle').attr('class', 'topo-node-core').attr('r', 20);
    nodeEnter.append('text').attr('class', 'topo-node-title')
      .attr('text-anchor', 'middle').attr('dy', 5)
      .attr('font-size', 11)
      .attr('font-weight', 600);
    nodeEnter.append('text').attr('class', 'topo-node-label')
      .attr('text-anchor', 'middle').attr('dy', 40)
      .attr('font-size', 12);
    nodeEnter.append('text').attr('class', 'topo-node-rate')
      .attr('text-anchor', 'middle').attr('dy', 54)
      .attr('font-size', 10)
      .attr('font-family', 'ui-monospace, monospace');

    const merged = nodeEnter.merge(nodeSel)
      .attr('transform', (d) => `translate(${d.x},${d.y})`);

    merged.select('.topo-node-halo')
      .attr('fill', (d) => {
        if (d.type === 'hub') return '#991b1b';
        if (d.type === 'net') return '#6b7280';
        return '#374151';
      })
      .attr('opacity', (d) => (d.type === 'hub' ? 0.3 : 0));

    merged.select('.topo-node-core')
      .attr('fill', (d) => {
        if (d.type === 'hub') return '#991b1b';
        if (d.type === 'net') return this.dark ? '#737373' : '#6b7280';
        if (!d.online) return this.dark ? '#525252' : '#d1d5db';
        return this.dark ? '#e5e5e5' : '#374151';
      });

    merged.select('.topo-node-title')
      .attr('fill', (d) => {
        if (d.type === 'hub' || d.type === 'net') return '#fff';
        if (!d.online) return this.dark ? '#a3a3a3' : '#6b7280';
        return this.dark ? '#171717' : '#fff';
      })
      .text((d) => (d.type === 'device' ? 'DEV' : d.label));

    merged.select('.topo-node-label')
      .attr('fill', this.dark ? '#d4d4d4' : '#4b5563')
      .text((d) => {
        if (d.type === 'device') return d.label;
        if (d.type === 'hub') return 'Relay';
        return 'Outside';
      });

    merged.select('.topo-node-rate')
      .attr('fill', this.dark ? '#a3a3a3' : '#9ca3af')
      .text((d) => `${d.sub}/s`);
  }

  curve(x1, y1, x2, y2, side) {
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const dx = x2 - x1;
    const dy = y2 - y1;
    const len = Math.hypot(dx, dy) || 1;
    const ox = (-dy / len) * 36 * side;
    const oy = (dx / len) * 36 * side;
    return `M ${x1} ${y1} Q ${mx + ox} ${my + oy} ${x2} ${y2}`;
  }

  desiredCount(norm, active) {
    if (!active || norm <= 0) return 0;
    // denser particles ⇒ more traffic
    return Math.max(1, Math.round(1 + (norm * 14)));
  }

  syncParticles() {
    const desired = [];
    this.paths.forEach((meta, id) => {
      const count = this.desiredCount(meta.norm, meta.active);
      for (let i = 0; i < count; i += 1) {
        desired.push({
          id: `${id}:${i}`,
          pathId: id,
          // stagger along the path
          t: (i / Math.max(count, 1) + Math.random() * 0.02) % 1,
          speed: 0.12 + (meta.norm * 0.35),
          kind: meta.kind,
        });
      }
    });

    // Preserve existing particle progress where possible
    const prev = new Map(this.particles.map((p) => [p.id, p]));
    this.particles = desired.map((p) => {
      const old = prev.get(p.id);
      return old ? { ...p, t: old.t } : p;
    });
  }

  tick(ts) {
    const dt = this.lastTs ? Math.min(0.05, (ts - this.lastTs) / 1000) : 0.016;
    this.lastTs = ts;

    this.particles.forEach((p) => {
      p.t = (p.t + (p.speed * dt)) % 1;
    });

    const sel = this.gParticles.selectAll('circle.topo-dot')
      .data(this.particles, (d) => d.id);

    sel.exit().remove();

    sel.enter().append('circle')
      .attr('class', 'topo-dot')
      .attr('r', 3.1)
      .attr('filter', 'drop-shadow(0 0 3px rgba(185,28,28,0.65))')
      .merge(sel)
      .attr('fill', (d) => (d.kind === 'up' ? '#b91c1c' : '#f87171'))
      .attr('cx', (d) => {
        const path = this.paths.get(d.pathId);
        if (!path || !path.length) return -10;
        return path.el.getPointAtLength(d.t * path.length).x;
      })
      .attr('cy', (d) => {
        const path = this.paths.get(d.pathId);
        if (!path || !path.length) return -10;
        return path.el.getPointAtLength(d.t * path.length).y;
      });

    this.raf = requestAnimationFrame(this.tick);
  }

}

window.TrafficTopologyChart = TrafficTopologyChart;
