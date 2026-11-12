/* eslint-disable no-undef */

'use strict';

/**
 * Star topology: VPN hub in the center, every device around it.
 * Each spoke has an upload lane and a download lane; particles move at a
 * constant speed, so their spacing (density) reflects throughput.
 */
class TrafficTopologyChart {

  constructor(container, { formatRate = (n) => `${n}`, dark = false } = {}) {
    this.container = container;
    this.formatRate = formatRate;
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
    const n = list.length;
    const radius = Math.max(170, Math.min(260, n * 26));
    this.width = 2 * (radius + 190);
    this.height = 2 * (radius + 64);
    this.svg.attr('viewBox', `0 0 ${this.width} ${this.height}`);

    const hub = { x: this.width / 2, y: this.height / 2, r: 46 };
    const devR = 8;

    const devices = list.map((client, i) => {
      const up = Math.max(0, client.transferRxCurrent || 0);
      const down = Math.max(0, client.transferTxCurrent || 0);
      const online = !!(client.enabled && client.latestHandshakeAt
        && (Date.now() - new Date(client.latestHandshakeAt).getTime()) < 180000);
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(n, 1);
      return {
        id: client.id,
        name: client.name,
        address: client.address,
        angle,
        x: hub.x + radius * Math.cos(angle),
        y: hub.y + radius * Math.sin(angle),
        up: online ? up : 0,
        down: online ? down : 0,
        online,
      };
    });

    const totalUp = d3.sum(devices, (d) => d.up);
    const totalDown = d3.sum(devices, (d) => d.down);
    const maxRate = Math.max(1, d3.max(devices, (d) => Math.max(d.up, d.down)) || 0);
    // particle spacing in px: busiest lane ≈ 7px apart, any non-zero flow ≤ 90px apart
    const spacing = d3.scaleSqrt().domain([0, maxRate]).range([90, 7])
      .clamp(true);
    const countFor = (rate, length) => (rate > 0
      ? Math.max(1, Math.round(length / spacing(rate)))
      : 0);
    const widthFor = d3.scaleSqrt().domain([0, maxRate]).range([1.25, 4])
      .clamp(true);

    const lanes = [];
    devices.forEach((d) => {
      const ux = Math.cos(d.angle);
      const uy = Math.sin(d.angle);
      // perpendicular offset keeps upload and download lanes side by side
      const px = -uy * 3.5;
      const py = ux * 3.5;
      const near = [hub.x + ux * hub.r, hub.y + uy * hub.r];
      const far = [d.x - ux * devR, d.y - uy * devR];
      lanes.push({
        id: `u:${d.id}`,
        owner: d.id,
        kind: 'up',
        rate: d.up,
        online: d.online,
        path: `M${far[0] + px},${far[1] + py} L${near[0] + px},${near[1] + py}`,
      });
      lanes.push({
        id: `d:${d.id}`,
        owner: d.id,
        kind: 'down',
        rate: d.down,
        online: d.online,
        path: `M${near[0] - px},${near[1] - py} L${far[0] - px},${far[1] - py}`,
      });
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
    enter.append('circle').attr('class', 'hit').attr('r', 18)
      .attr('fill', 'transparent');
    enter.append('circle').attr('class', 'dot').attr('r', devR);
    enter.append('text').attr('class', 'name')
      .attr('font-size', 13)
      .attr('font-weight', 500);
    enter.append('text').attr('class', 'rate')
      .attr('font-size', 11)
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace');

    const nodes = enter.merge(nodeSel).attr('transform', (d) => `translate(${d.x},${d.y})`);
    nodes.select('.dot')
      .attr('fill', (d) => (d.online ? c.node : c.offline))
      .attr('stroke', (d) => (d.online ? '#10b981' : c.nodeStroke))
      .attr('stroke-width', 2.5);
    nodes.selectAll('text')
      .attr('text-anchor', (d) => TrafficTopologyChart.anchorFor(d.angle))
      .attr('x', (d) => Math.cos(d.angle) * 18);
    nodes.select('.name')
      .attr('y', (d) => TrafficTopologyChart.labelY(d.angle)[0])
      .attr('fill', (d) => (d.online ? c.text : c.muted))
      .text((d) => d.name);
    nodes.select('.rate')
      .attr('y', (d) => TrafficTopologyChart.labelY(d.angle)[1])
      .attr('fill', c.muted)
      .text((d) => (d.online
        ? `↑ ${this.formatRate(d.up)}/s  ↓ ${this.formatRate(d.down)}/s`
        : d.address));

    this.drawHub(hub, totalUp, totalDown, c);
    this.applyHover();
  }

  static anchorFor(angle) {
    const cos = Math.cos(angle);
    if (cos > 0.3) return 'start';
    if (cos < -0.3) return 'end';
    return 'middle';
  }

  static labelY(angle) {
    const sin = Math.sin(angle);
    if (sin < -0.7) return [-32, -18];
    if (sin > 0.7) return [30, 44];
    return [-2, 13];
  }

  drawHub(hub, totalUp, totalDown, c) {
    let g = this.gNodes.select('g.hub');
    if (g.empty()) {
      g = this.gNodes.append('g').attr('class', 'hub');
      g.append('circle').attr('class', 'ring').attr('r', hub.r + 10);
      g.append('circle').attr('class', 'core').attr('r', hub.r);
      g.append('text').attr('class', 'title')
        .attr('text-anchor', 'middle').attr('y', -8)
        .attr('font-size', 14)
        .attr('font-weight', 700)
        .attr('fill', '#fff')
        .text('VPN');
      g.append('text').attr('class', 'up')
        .attr('text-anchor', 'middle').attr('y', 10)
        .attr('font-size', 10)
        .attr('fill', '#fee2e2')
        .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace');
      g.append('text').attr('class', 'down')
        .attr('text-anchor', 'middle').attr('y', 23)
        .attr('font-size', 10)
        .attr('fill', '#fee2e2')
        .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace');
    }
    g.attr('transform', `translate(${hub.x},${hub.y})`);
    g.select('.ring').attr('fill', c.hub).attr('opacity', 0.15);
    g.select('.core').attr('fill', c.hub);
    g.select('.up').text(`↑ ${this.formatRate(totalUp)}/s`);
    g.select('.down').text(`↓ ${this.formatRate(totalDown)}/s`);
  }

  applyHover() {
    const focus = this.hoverId;
    this.gLinks.selectAll('path')
      .attr('opacity', (l) => (!focus || l.owner === focus ? 1 : 0.15));
    this.gNodes.selectAll('g.dev')
      .attr('opacity', (d) => (!focus || d.id === focus ? 1 : 0.35));
    if (this.dotAll) {
      this.dotAll.attr('opacity', (d) => {
        const lane = this.lanes.get(d.lane);
        return !focus || !lane || lane.owner === focus ? 1 : 0.1;
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
