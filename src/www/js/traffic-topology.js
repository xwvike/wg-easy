/* eslint-disable no-undef */

'use strict';

const TOPO_MONO = 'ui-monospace, SFMono-Regular, Menlo, monospace';

/**
 * Devices sit on a ring around a small VPN hub.
 * - Device ↔ device traffic is a Bézier chord bent through the hub,
 *   one lane per direction, particles in the sender's color.
 * - Remaining traffic of a device is a pair of faint arcs into the hub.
 * Particles move at a constant speed, so their spacing encodes throughput.
 */
class TrafficTopologyChart {

  constructor(container, { formatRate = (n) => `${n}`, dark = false } = {}) {
    this.container = container;
    this.formatRate = formatRate;
    this.dark = dark;
    this.width = 900;
    this.height = 600;
    this.lanes = new Map();
    this.hoverId = null;
    this.raf = null;
    this.lastTs = 0;

    d3.select(container).selectAll('*').remove();

    this.svg = d3.select(container)
      .append('svg')
      .attr('class', 'traffic-topo-svg')
      .attr('role', 'img');

    this.gSpokes = this.svg.append('g');
    this.gChords = this.svg.append('g');
    this.gHub = this.svg.append('g');
    this.gDots = this.svg.append('g');
    this.gNodes = this.svg.append('g');
    this.gLabels = this.svg.append('g').attr('pointer-events', 'none');

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
        track: '#525252',
        spokeDot: '#a3a3a3',
        node: '#404040',
        text: '#e5e5e5',
        muted: '#a3a3a3',
        offline: '#525252',
        hub: '#dc2626',
        labelBg: '#262626',
      }
      : {
        track: '#e5e7eb',
        spokeDot: '#9ca3af',
        node: '#ffffff',
        text: '#1f2937',
        muted: '#9ca3af',
        offline: '#d1d5db',
        hub: '#b91c1c',
        labelBg: '#ffffff',
      };
  }

  static deviceColor(i) {
    return d3.schemeTableau10[i % d3.schemeTableau10.length];
  }

  static quad(p0, c, p1) {
    return `M${p0[0]},${p0[1]} Q${c[0]},${c[1]} ${p1[0]},${p1[1]}`;
  }

  static towards(from, to, dist) {
    const dx = to[0] - from[0];
    const dy = to[1] - from[1];
    const len = Math.hypot(dx, dy) || 1;
    return [from[0] + (dx / len) * dist, from[1] + (dy / len) * dist];
  }

  /**
   * @param {Array<object>} clients
   * @param {{accounting: boolean, flows: Array<{a: string, b: string, ab: number, ba: number}>}|null} peers
   */
  update(clients, peers) {
    const c = this.palette();
    const list = clients || [];
    const n = list.length;
    const radius = Math.max(180, Math.min(280, n * 28));
    this.width = 2 * (radius + 190);
    this.height = 2 * (radius + 70);
    this.svg.attr('viewBox', `0 0 ${this.width} ${this.height}`);

    const center = [this.width / 2, this.height / 2];
    const hubR = 20;
    const devR = 9;

    const devices = list.map((client, i) => {
      const online = !!(client.enabled && client.latestHandshakeAt
        && (Date.now() - new Date(client.latestHandshakeAt).getTime()) < 180000);
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(n, 1);
      return {
        id: client.id,
        name: client.name,
        address: client.address,
        color: TrafficTopologyChart.deviceColor(i),
        angle,
        x: center[0] + radius * Math.cos(angle),
        y: center[1] + radius * Math.sin(angle),
        up: online ? Math.max(0, client.transferRxCurrent || 0) : 0,
        down: online ? Math.max(0, client.transferTxCurrent || 0) : 0,
        peerOut: 0,
        peerIn: 0,
        online,
      };
    });
    const byId = new Map(devices.map((d) => [d.id, d]));

    const accounting = !!(peers && peers.accounting);
    const flows = ((peers && peers.flows) || [])
      .filter((f) => byId.has(f.a) && byId.has(f.b));
    flows.forEach((f) => {
      byId.get(f.a).peerOut += f.ab;
      byId.get(f.a).peerIn += f.ba;
      byId.get(f.b).peerOut += f.ba;
      byId.get(f.b).peerIn += f.ab;
    });

    const lanes = [];
    devices.forEach((d) => {
      const p = [d.x, d.y];
      const start = TrafficTopologyChart.towards(p, center, devR + 2);
      const end = TrafficTopologyChart.towards(center, p, hubR + 4);
      const ux = (center[0] - d.x) / radius;
      const uy = (center[1] - d.y) / radius;
      const mid = [(start[0] + end[0]) / 2, (start[1] + end[1]) / 2];
      const bend = 16;
      lanes.push({
        id: `su:${d.id}`,
        group: 'spoke',
        owners: [d.id],
        rate: Math.max(0, d.up - d.peerOut),
        color: d.color,
        online: d.online,
        path: TrafficTopologyChart.quad(start, [mid[0] - uy * bend, mid[1] + ux * bend], end),
      });
      lanes.push({
        id: `sd:${d.id}`,
        group: 'spoke',
        owners: [d.id],
        rate: Math.max(0, d.down - d.peerIn),
        color: c.spokeDot,
        online: d.online,
        path: TrafficTopologyChart.quad(end, [mid[0] + uy * bend, mid[1] - ux * bend], start),
      });
    });

    flows.forEach((f) => {
      const a = byId.get(f.a);
      const b = byId.get(f.b);
      const pa = [a.x, a.y];
      const pb = [b.x, b.y];
      const mid = [(a.x + b.x) / 2, (a.y + b.y) / 2];
      const ctrl = [center[0] + (mid[0] - center[0]) * 0.3, center[1] + (mid[1] - center[1]) * 0.3];
      const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
      const nx = -(b.y - a.y) / len;
      const ny = (b.x - a.x) / len;
      const lane = (from, to, side, rate, sender) => {
        const s = TrafficTopologyChart.towards(from, ctrl, devR + 2);
        const e = TrafficTopologyChart.towards(to, ctrl, devR + 2);
        return {
          id: `c:${sender.id}:${(sender === a ? b : a).id}`,
          group: 'chord',
          owners: [a.id, b.id],
          pair: [a, b],
          rate: accounting ? rate : 0,
          color: sender.color,
          online: true,
          path: TrafficTopologyChart.quad(
            [s[0] + nx * side * 3, s[1] + ny * side * 3],
            [ctrl[0] + nx * side * 9, ctrl[1] + ny * side * 9],
            [e[0] + nx * side * 3, e[1] + ny * side * 3],
          ),
        };
      };
      lanes.push(lane(pa, pb, 1, f.ab, a));
      lanes.push(lane(pb, pa, -1, f.ba, b));
    });

    const maxRate = Math.max(1, d3.max(lanes, (l) => l.rate) || 0);
    // particle spacing in px: busiest lane ≈ 7px apart, any non-zero flow ≤ 90px apart
    const spacing = d3.scaleSqrt().domain([0, maxRate]).range([90, 7])
      .clamp(true);
    const countFor = (rate, length) => (rate > 0
      ? Math.max(1, Math.round(length / spacing(rate)))
      : 0);
    const widthFor = d3.scaleSqrt().domain([0, maxRate]).range([1, 3.5])
      .clamp(true);

    const spokeLanes = lanes.filter((l) => l.group === 'spoke');
    const chordLanes = lanes.filter((l) => l.group === 'chord');

    const spokeSel = this.gSpokes.selectAll('path').data(spokeLanes, (l) => l.id);
    spokeSel.exit().remove();
    const spokeAll = spokeSel.enter().append('path')
      .attr('fill', 'none')
      .merge(spokeSel)
      .attr('d', (l) => l.path)
      .attr('stroke', c.track)
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', (l) => (l.online ? null : '3 4'));

    const chordSel = this.gChords.selectAll('path').data(chordLanes, (l) => l.id);
    chordSel.exit().remove();
    const chordAll = chordSel.enter().append('path')
      .attr('fill', 'none')
      .attr('stroke-linecap', 'round')
      .merge(chordSel)
      .attr('d', (l) => l.path)
      .attr('stroke', (l) => l.color)
      .attr('stroke-opacity', accounting ? 0.28 : 0.6)
      .attr('stroke-width', (l) => (accounting ? widthFor(l.rate) : 1.5));

    const prev = this.lanes;
    this.lanes = new Map();
    const index = (l, el) => {
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
    };
    spokeAll.each((l, i, nodes) => index(l, nodes[i]));
    chordAll.each((l, i, nodes) => index(l, nodes[i]));

    const dots = [];
    this.lanes.forEach((lane) => {
      for (let k = 0; k < lane.count; k += 1) {
        dots.push({ key: `${lane.id}:${k}`, lane: lane.id, k });
      }
    });
    const dotSel = this.gDots.selectAll('circle').data(dots, (d) => d.key);
    dotSel.exit().remove();
    this.dotAll = dotSel.enter().append('circle')
      .merge(dotSel)
      .attr('r', (d) => (this.lanes.get(d.lane).group === 'chord' ? 2.6 : 1.8))
      .attr('fill', (d) => this.lanes.get(d.lane).color);

    this.drawHub(center, hubR, c);
    this.drawDevices(devices, devR, c);
    this.drawChordLabels(flows, byId, center, accounting, c);
    this.applyHover();
  }

  drawHub(center, hubR, c) {
    let g = this.gHub.select('g.hub');
    if (g.empty()) {
      g = this.gHub.append('g').attr('class', 'hub');
      g.append('circle').attr('class', 'ring');
      g.append('circle').attr('class', 'core');
      g.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', 3.5)
        .attr('font-size', 10)
        .attr('font-weight', 700)
        .attr('fill', '#fff')
        .text('VPN');
    }
    g.attr('transform', `translate(${center[0]},${center[1]})`);
    g.select('.ring').attr('r', hubR + 7).attr('fill', c.hub)
      .attr('opacity', 0.14);
    g.select('.core').attr('r', hubR).attr('fill', c.hub);
  }

  drawDevices(devices, devR, c) {
    const nodeSel = this.gNodes.selectAll('g.dev').data(devices, (d) => d.id);
    nodeSel.exit().remove();
    const enter = nodeSel.enter().append('g').attr('class', 'dev')
      .style('cursor', 'default')
      .on('mouseenter', (e, d) => {
        this.hoverId = d.id;
        this.applyHover();
      })
      .on('mouseleave', () => {
        this.hoverId = null;
        this.applyHover();
      });
    enter.append('circle').attr('class', 'hit').attr('r', 20)
      .attr('fill', 'transparent');
    enter.append('circle').attr('class', 'dot');
    enter.append('text').attr('class', 'name')
      .attr('font-size', 13)
      .attr('font-weight', 500);
    enter.append('text').attr('class', 'rate')
      .attr('font-size', 11)
      .attr('font-family', TOPO_MONO);

    const nodes = enter.merge(nodeSel).attr('transform', (d) => `translate(${d.x},${d.y})`);
    nodes.select('.dot')
      .attr('r', devR)
      .attr('fill', (d) => (d.online ? d.color : c.offline))
      .attr('stroke', c.node)
      .attr('stroke-width', 3);
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
  }

  drawChordLabels(flows, byId, center, accounting, c) {
    const data = accounting ? flows : [];
    const sel = this.gLabels.selectAll('g.flow').data(data, (f) => `${f.a}|${f.b}`);
    sel.exit().remove();
    const enter = sel.enter().append('g').attr('class', 'flow');
    enter.append('rect').attr('rx', 4);
    enter.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', 3.5)
      .attr('font-size', 10.5)
      .attr('font-family', TOPO_MONO);
    const all = enter.merge(sel)
      .attr('transform', (f) => {
        const a = byId.get(f.a);
        const b = byId.get(f.b);
        // quadratic midpoint: halfway between chord midpoint and control point
        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2;
        const cx = center[0] + (mx - center[0]) * 0.3;
        const cy = center[1] + (my - center[1]) * 0.3;
        return `translate(${(mx + cx) / 2},${(my + cy) / 2})`;
      });
    all.select('text')
      .attr('fill', c.text)
      .text((f) => `${this.formatRate(f.ab + f.ba)}/s`);
    all.select('rect')
      .attr('fill', c.labelBg)
      .attr('fill-opacity', 0.9)
      .attr('stroke', c.track)
      .attr('x', -36)
      .attr('y', -9)
      .attr('width', 72)
      .attr('height', 18);
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

  applyHover() {
    const focus = this.hoverId;
    const related = (owners) => !focus || owners.includes(focus);
    this.gSpokes.selectAll('path').attr('opacity', (l) => (related(l.owners) ? 1 : 0.2));
    this.gChords.selectAll('path').attr('opacity', (l) => (related(l.owners) ? 1 : 0.08));
    this.gNodes.selectAll('g.dev').attr('opacity', (d) => {
      if (!focus || d.id === focus) return 1;
      const linked = [...this.lanes.values()]
        .some((l) => l.group === 'chord' && l.owners.includes(focus) && l.owners.includes(d.id));
      return linked ? 1 : 0.3;
    });
    this.gLabels.selectAll('g.flow')
      .attr('opacity', (f) => (focus && (f.a === focus || f.b === focus) ? 1 : 0));
    if (this.dotAll) {
      this.dotAll.attr('opacity', (d) => {
        const lane = this.lanes.get(d.lane);
        return !lane || related(lane.owners) ? 1 : 0.06;
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
