/* eslint-disable no-undef */

'use strict';

/**
 * Relay topology: devices (left) ⇄ VPN (center) ⇄ Internet (right).
 * Each hop has an upload lane and a download lane; particles move at a
 * constant speed, so their spacing (density) reflects throughput.
 */
class TrafficTopologyChart {

  constructor(container, {
    formatRate = (n) => `${n}`,
    dark = false,
    outsideLabel = 'Internet',
  } = {}) {
    this.container = container;
    this.formatRate = formatRate;
    this.outsideLabel = outsideLabel;
    this.dark = dark;
    this.width = 900;
    this.height = 400;
    this.lanes = new Map();
    this.hoverId = null;
    this.raf = null;
    this.lastTs = 0;

    d3.select(container).selectAll('*').remove();

    this.svg = d3.select(container)
      .append('svg')
      .attr('class', 'traffic-topo-svg')
      .attr('role', 'img');

    this.gLinks = this.svg.append('g');
    this.gDots = this.svg.append('g');
    this.gNodes = this.svg.append('g');

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
    this.lanes.clear();
  }

  palette() {
    return this.dark
      ? {
        up: '#f87171',
        down: '#fbbf24',
        track: '#525252',
        node: '#404040',
        nodeStroke: '#737373',
        text: '#e5e5e5',
        muted: '#a3a3a3',
        offline: '#525252',
        hub: '#b91c1c',
        bg: '#404040',
      }
      : {
        up: '#dc2626',
        down: '#d97706',
        track: '#e5e7eb',
        node: '#ffffff',
        nodeStroke: '#d1d5db',
        text: '#1f2937',
        muted: '#9ca3af',
        offline: '#d1d5db',
        hub: '#991b1b',
        bg: '#ffffff',
      };
  }

  /**
   * @param {Array<object>} clients
   */
  update(clients) {
    const c = this.palette();
    const list = clients || [];
    const rowGap = 56;
    const top = 44;
    this.height = Math.max(320, top * 2 + Math.max(list.length - 1, 0) * rowGap);
    this.svg.attr('viewBox', `0 0 ${this.width} ${this.height}`);

    const midY = this.height / 2;
    const devX = 230;
    const hub = { x: 560, y: midY };
    const net = { x: 800, y: midY };

    const devices = list.map((client, i) => {
      const up = Math.max(0, client.transferRxCurrent || 0);
      const down = Math.max(0, client.transferTxCurrent || 0);
      const online = !!(client.enabled && client.latestHandshakeAt
        && (Date.now() - new Date(client.latestHandshakeAt).getTime()) < 180000);
      return {
        id: client.id,
        name: client.name,
        address: client.address,
        x: devX,
        y: list.length === 1 ? midY : top + i * rowGap,
        up: online ? up : 0,
        down: online ? down : 0,
        online,
      };
    });

    const totalUp = d3.sum(devices, (d) => d.up);
    const totalDown = d3.sum(devices, (d) => d.down);
    const maxRate = Math.max(1, totalUp, totalDown);
    // particle spacing in px: busiest lane ≈ 7px apart, any non-zero flow ≤ 90px apart
    const spacing = d3.scaleSqrt().domain([0, maxRate]).range([90, 7])
      .clamp(true);
    const countFor = (rate, length) => (rate > 0
      ? Math.max(1, Math.round(length / spacing(rate)))
      : 0);
    const widthFor = d3.scaleSqrt().domain([0, maxRate]).range([1.25, 4])
      .clamp(true);

    const link = (x0, y0, x1, y1) => {
      const mx = (x0 + x1) / 2;
      return `M${x0},${y0} C${mx},${y0} ${mx},${y1} ${x1},${y1}`;
    };

    const lanes = [];
    devices.forEach((d) => {
      lanes.push({
        id: `u:${d.id}`,
        owner: d.id,
        kind: 'up',
        rate: d.up,
        online: d.online,
        path: link(d.x, d.y - 4, hub.x, hub.y - 4),
      });
      lanes.push({
        id: `d:${d.id}`,
        owner: d.id,
        kind: 'down',
        rate: d.down,
        online: d.online,
        path: link(hub.x, hub.y + 4, d.x, d.y + 4),
      });
    });
    lanes.push({
      id: 'u:net',
      owner: null,
      kind: 'up',
      rate: totalUp,
      online: true,
      path: link(hub.x, hub.y - 6, net.x, net.y - 6),
    });
    lanes.push({
      id: 'd:net',
      owner: null,
      kind: 'down',
      rate: totalDown,
      online: true,
      path: link(net.x, net.y + 6, hub.x, hub.y + 6),
    });

    const linkSel = this.gLinks.selectAll('path').data(lanes, (l) => l.id);
    linkSel.exit().remove();
    const linkAll = linkSel.enter().append('path')
      .attr('fill', 'none')
      .attr('stroke-linecap', 'round')
      .merge(linkSel)
      .attr('d', (l) => l.path)
      .attr('stroke', (l) => (l.rate > 0 ? c[l.kind] : c.track))
      .attr('stroke-opacity', (l) => (l.rate > 0 ? 0.22 : 1))
      .attr('stroke-width', (l) => (l.rate > 0 ? widthFor(l.rate) : 1))
      .attr('stroke-dasharray', (l) => (l.online ? null : '3 4'));

    const prev = this.lanes;
    this.lanes = new Map();
    linkAll.each((l, i, nodes) => {
      const el = nodes[i];
      const length = el.getTotalLength();
      const samples = 96;
      const lut = d3.range(samples + 1).map((k) => {
        const p = el.getPointAtLength((k / samples) * length);
        return [p.x, p.y];
      });
      this.lanes.set(l.id, {
        ...l,
        lut,
        length,
        count: countFor(l.rate, length),
        phase: prev.has(l.id) ? prev.get(l.id).phase : Math.random(),
      });
    });

    const dots = [];
    this.lanes.forEach((lane) => {
      for (let k = 0; k < lane.count; k += 1) {
        dots.push({ key: `${lane.id}:${k}`, lane: lane.id, k });
      }
    });
    const dotSel = this.gDots.selectAll('circle').data(dots, (d) => d.key);
    dotSel.exit().remove();
    this.dotAll = dotSel.enter().append('circle')
      .attr('r', 2.5)
      .merge(dotSel)
      .attr('fill', (d) => c[this.lanes.get(d.lane).kind]);

    const nodeSel = this.gNodes.selectAll('g.dev').data(devices, (d) => d.id);
    nodeSel.exit().remove();
    const enter = nodeSel.enter().append('g').attr('class', 'dev')
      .style('cursor', 'default')
      .on('mouseenter', (e, d) => {
        this.hoverId = d.id; this.applyHover();
      })
      .on('mouseleave', () => {
        this.hoverId = null; this.applyHover();
      });
    enter.append('rect').attr('class', 'hit');
    enter.append('circle').attr('class', 'dot').attr('r', 7);
    enter.append('text').attr('class', 'name')
      .attr('text-anchor', 'end').attr('font-size', 13)
      .attr('font-weight', 500);
    enter.append('text').attr('class', 'rate')
      .attr('text-anchor', 'end').attr('font-size', 11)
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace');

    const nodes = enter.merge(nodeSel).attr('transform', (d) => `translate(${d.x},${d.y})`);
    nodes.select('.hit')
      .attr('x', -220).attr('y', -22)
      .attr('width', 240)
      .attr('height', 44)
      .attr('fill', 'transparent');
    nodes.select('.dot')
      .attr('fill', (d) => (d.online ? c.node : c.offline))
      .attr('stroke', (d) => (d.online ? '#10b981' : c.nodeStroke))
      .attr('stroke-width', 2.5);
    nodes.select('.name')
      .attr('x', -18).attr('y', -2)
      .attr('fill', (d) => (d.online ? c.text : c.muted))
      .text((d) => d.name);
    nodes.select('.rate')
      .attr('x', -18).attr('y', 14)
      .attr('fill', c.muted)
      .text((d) => (d.online
        ? `↑ ${this.formatRate(d.up)}/s  ↓ ${this.formatRate(d.down)}/s`
        : d.address));

    this.drawHub(hub, totalUp, totalDown, c);
    this.drawNet(net, c);
    this.applyHover();
  }

  drawHub(hub, totalUp, totalDown, c) {
    let g = this.gNodes.select('g.hub');
    if (g.empty()) {
      g = this.gNodes.append('g').attr('class', 'hub');
      g.append('circle').attr('class', 'ring').attr('r', 34);
      g.append('circle').attr('class', 'core').attr('r', 26);
      g.append('text').attr('class', 'title')
        .attr('text-anchor', 'middle').attr('dy', 5)
        .attr('font-size', 13)
        .attr('font-weight', 700)
        .attr('fill', '#fff')
        .text('VPN');
      g.append('text').attr('class', 'up')
        .attr('text-anchor', 'middle').attr('y', 56)
        .attr('font-size', 11)
        .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace');
      g.append('text').attr('class', 'down')
        .attr('text-anchor', 'middle').attr('y', 72)
        .attr('font-size', 11)
        .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace');
    }
    g.attr('transform', `translate(${hub.x},${hub.y})`);
    g.select('.ring').attr('fill', c.hub).attr('opacity', 0.15);
    g.select('.core').attr('fill', c.hub);
    g.select('.up').attr('fill', c.up).text(`↑ ${this.formatRate(totalUp)}/s`);
    g.select('.down').attr('fill', c.down).text(`↓ ${this.formatRate(totalDown)}/s`);
  }

  drawNet(net, c) {
    let g = this.gNodes.select('g.net');
    if (g.empty()) {
      g = this.gNodes.append('g').attr('class', 'net');
      g.append('circle').attr('class', 'core').attr('r', 22);
      // globe glyph
      g.append('circle').attr('class', 'glyph').attr('r', 10)
        .attr('fill', 'none')
        .attr('stroke-width', 1.5);
      g.append('ellipse').attr('class', 'glyph').attr('rx', 4.5)
        .attr('ry', 10)
        .attr('fill', 'none')
        .attr('stroke-width', 1.5);
      g.append('line').attr('class', 'glyph').attr('x1', -10)
        .attr('x2', 10)
        .attr('stroke-width', 1.5);
      g.append('text').attr('class', 'label')
        .attr('text-anchor', 'middle').attr('y', 42)
        .attr('font-size', 12);
    }
    g.attr('transform', `translate(${net.x},${net.y})`);
    g.select('.core').attr('fill', c.node).attr('stroke', c.nodeStroke)
      .attr('stroke-width', 1.5);
    g.selectAll('.glyph').attr('stroke', c.muted);
    g.select('.label').attr('fill', c.muted).text(this.outsideLabel);
  }

  applyHover() {
    const focus = this.hoverId;
    this.gLinks.selectAll('path')
      .attr('opacity', (l) => (!focus || l.owner === null || l.owner === focus ? 1 : 0.15));
    this.gNodes.selectAll('g.dev')
      .attr('opacity', (d) => (!focus || d.id === focus ? 1 : 0.35));
    if (this.dotAll) {
      this.dotAll.attr('opacity', (d) => {
        const lane = this.lanes.get(d.lane);
        return !focus || !lane || lane.owner === null || lane.owner === focus ? 1 : 0.1;
      });
    }
  }

  tick(ts) {
    const dt = this.lastTs ? Math.min(0.05, (ts - this.lastTs) / 1000) : 0;
    this.lastTs = ts;
    const pxPerSec = 80;

    this.lanes.forEach((lane) => {
      if (lane.length > 0) lane.phase = (lane.phase + (pxPerSec * dt) / lane.length) % 1;
    });

    if (this.dotAll) {
      this.dotAll.each((d, i, nodes) => {
        const lane = this.lanes.get(d.lane);
        if (!lane || !lane.count) return;
        const t = (lane.phase + d.k / lane.count) % 1;
        const f = t * (lane.lut.length - 1);
        const a = lane.lut[Math.floor(f)];
        const b = lane.lut[Math.min(lane.lut.length - 1, Math.floor(f) + 1)];
        const r = f - Math.floor(f);
        const el = nodes[i];
        el.setAttribute('cx', a[0] + (b[0] - a[0]) * r);
        el.setAttribute('cy', a[1] + (b[1] - a[1]) * r);
        // fade at both ends so dots don't pop in/out on top of nodes
        el.setAttribute('fill-opacity', Math.min(1, t * 8, (1 - t) * 8));
      });
    }

    this.raf = requestAnimationFrame(this.tick);
  }

}

window.TrafficTopologyChart = TrafficTopologyChart;
