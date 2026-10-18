'use strict';

/**
 * Dependency-free SVG charts for the Metrics view. CSP-safe: no inline style
 * attributes or innerHTML; every label is inserted with textContent.
 * window.ThreatlintCharts.render(container, chart, data, { metric, tooltip })
 * chart: kpi | bar | hbar | line | donut | table | heatmap.
 * Categorical slots follow a fixed order validated for CVD on the dark surface.
 */
(() => {
  const SVG = 'http://www.w3.org/2000/svg';
  const SERIES = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'];
  const SEVERITY = { CRITICAL: '#d03b3b', HIGH: '#ec835a', MEDIUM: '#fab219', LOW: '#3987e5', INFO: '#898781', UNSPECIFIED: '#5c6866' };
  const RAMP = ['#184f95', '#1c5cab', '#256abf', '#2a78d6', '#3987e5', '#5598e7', '#6da7ec', '#86b6ef'];
  const LABELS = { findings: 'Findings', reports: 'Reports', riskScore: 'Risk score', uniqueFindings: 'Unique findings', evidenceCoverage: 'Evidence coverage %' };

  function svg(tag, attributes = {}, parent) {
    const node = document.createElementNS(SVG, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
    parent?.append(node);
    return node;
  }
  function html(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }
  const format = value => (Number.isInteger(value) ? value.toLocaleString() : Number(value).toFixed(1));
  // Color follows the entity: severities are fixed, other keys keep their first-seen slot.
  const slots = new Map();
  function colorFor(key, groupBy) {
    if (groupBy === 'severity' && SEVERITY[key]) return SEVERITY[key];
    const id = `${groupBy}:${key}`;
    if (!slots.has(id)) slots.set(id, SERIES[[...slots.keys()].filter(item => item.startsWith(`${groupBy}:`)).length % SERIES.length]);
    return slots.get(id);
  }

  function attachTooltip(target, tooltip, lines) {
    const show = event => {
      tooltip.replaceChildren();
      for (const [index, line] of lines.entries()) tooltip.append(html(index === 0 ? 'strong' : 'span', '', line));
      tooltip.hidden = false;
      const rect = event.currentTarget.getBoundingClientRect?.() || { left: 0, top: 0, width: 0 };
      const x = event.clientX ?? rect.left + rect.width / 2, y = event.clientY ?? rect.top;
      tooltip.style.left = `${Math.min(window.innerWidth - 220, x + 14)}px`;
      tooltip.style.top = `${Math.max(8, y - 12)}px`;
    };
    const hide = () => { tooltip.hidden = true; };
    target.setAttribute('tabindex', '0');
    target.setAttribute('aria-label', lines.join(', '));
    target.addEventListener('pointermove', show); target.addEventListener('focus', show);
    target.addEventListener('pointerleave', hide); target.addEventListener('blur', hide);
  }

  function legend(rows, groupBy) {
    const list = html('ul', 'chart-legend');
    for (const row of rows.slice(0, 8)) {
      const item = html('li');
      const swatch = html('span', 'chart-swatch'); swatch.style.background = colorFor(row.key, groupBy);
      item.append(swatch, document.createTextNode(row.key));
      list.append(item);
    }
    return list;
  }
  function fold(rows, max) {
    if (rows.length <= max) return rows;
    const rest = rows.slice(max - 1).reduce((sum, row) => sum + row.value, 0);
    return [...rows.slice(0, max - 1), { key: 'Other', value: rest }];
  }

  function table(container, data, options) {
    const wrap = html('div', 'chart-table-wrap');
    const element = html('table', 'chart-table');
    const head = html('tr');
    head.append(html('th', '', data.groupBy || 'Group'), html('th', 'numeric', LABELS[options.metric] || 'Value'));
    const thead = html('thead'); thead.append(head); element.append(thead);
    const body = html('tbody');
    for (const row of data.rows) { const tr = html('tr'); tr.append(html('td', '', row.key), html('td', 'numeric', format(row.value))); body.append(tr); }
    if (!data.rows.length) { const tr = html('tr'); const td = html('td', 'subtle', 'No data yet'); td.colSpan = 2; tr.append(td); body.append(tr); }
    element.append(body); wrap.append(element); container.append(wrap);
  }

  function kpi(container, data, options) {
    const tile = html('div', 'chart-kpi');
    tile.append(html('span', 'chart-kpi-value', format(data.total ?? 0)));
    if (options.metric === 'evidenceCoverage') tile.append(html('span', 'chart-kpi-label', 'of findings cite file:line'));
    container.append(tile);
  }

  function bars(container, data, options, horizontal) {
    const rows = fold(data.rows, horizontal ? 10 : 12);
    if (!rows.length) return empty(container);
    const width = 520, height = horizontal ? Math.max(120, rows.length * 30 + 20) : 220;
    const max = Math.max(1, ...rows.map(row => row.value));
    const root = svg('svg', { viewBox: `0 0 ${width} ${height}`, class: 'chart-svg', role: 'img', 'aria-label': `${LABELS[options.metric]} by ${data.groupBy}` });
    if (horizontal) {
      const left = 150, band = (height - 20) / rows.length, thickness = Math.min(18, band - 6);
      rows.forEach((row, index) => {
        const y = 10 + index * band + (band - thickness) / 2;
        const length = Math.max(2, (width - left - 50) * row.value / max);
        const label = svg('text', { x: left - 8, y: y + thickness / 2 + 4, 'text-anchor': 'end', class: 'chart-label' }, root); label.textContent = row.key.length > 22 ? `${row.key.slice(0, 21)}…` : row.key;
        const bar = svg('rect', { x: left, y, width: length, height: thickness, rx: 4, fill: colorFor(row.key, data.groupBy), class: 'chart-mark' }, root);
        const value = svg('text', { x: left + length + 6, y: y + thickness / 2 + 4, class: 'chart-value' }, root); value.textContent = format(row.value);
        attachTooltip(bar, options.tooltip, [format(row.value), row.key]);
      });
    } else {
      const bottom = height - 34, top = 14, left = 34, band = (width - left - 10) / rows.length, thickness = Math.min(40, band - 6);
      for (const tick of [0, 0.5, 1]) {
        const y = bottom - (bottom - top) * tick;
        svg('line', { x1: left, x2: width - 10, y1: y, y2: y, class: tick ? 'chart-grid' : 'chart-axis' }, root);
        const label = svg('text', { x: left - 6, y: y + 4, 'text-anchor': 'end', class: 'chart-tick' }, root); label.textContent = format(Math.round(max * tick));
      }
      rows.forEach((row, index) => {
        const x = left + index * band + (band - thickness) / 2;
        const length = Math.max(2, (bottom - top) * row.value / max);
        const bar = svg('rect', { x, y: bottom - length, width: thickness, height: length, rx: 4, fill: colorFor(row.key, data.groupBy), class: 'chart-mark' }, root);
        const label = svg('text', { x: x + thickness / 2, y: bottom + 16, 'text-anchor': 'middle', class: 'chart-tick' }, root); label.textContent = row.key.length > 10 ? `${row.key.slice(0, 9)}…` : row.key;
        attachTooltip(bar, options.tooltip, [format(row.value), row.key]);
      });
    }
    container.append(root);
  }

  function line(container, data, options) {
    const rows = data.rows;
    if (!rows.length) return empty(container);
    const width = 520, height = 220, left = 34, right = 14, top = 14, bottom = height - 34;
    const max = Math.max(1, ...rows.map(row => row.value));
    const x = index => (rows.length === 1 ? (left + width - right) / 2 : left + (width - left - right) * index / (rows.length - 1));
    const y = value => bottom - (bottom - top) * value / max;
    const root = svg('svg', { viewBox: `0 0 ${width} ${height}`, class: 'chart-svg', role: 'img', 'aria-label': `${LABELS[options.metric]} over time` });
    for (const tick of [0, 0.5, 1]) {
      svg('line', { x1: left, x2: width - right, y1: y(max * tick), y2: y(max * tick), class: tick ? 'chart-grid' : 'chart-axis' }, root);
      const label = svg('text', { x: left - 6, y: y(max * tick) + 4, 'text-anchor': 'end', class: 'chart-tick' }, root); label.textContent = format(Math.round(max * tick));
    }
    const points = rows.map((row, index) => `${x(index)},${y(row.value)}`).join(' ');
    svg('polyline', { points, fill: 'none', stroke: SERIES[0], 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }, root);
    for (const index of [0, rows.length - 1]) {
      const label = svg('text', { x: x(index), y: bottom + 16, 'text-anchor': index ? 'end' : 'start', class: 'chart-tick' }, root); label.textContent = rows[index].key;
    }
    // Few points: show markers so a single day is still visible.
    if (rows.length <= 12) rows.forEach((row, index) => svg('circle', { cx: x(index), cy: y(row.value), r: 4, fill: SERIES[0], stroke: '#151d1f', 'stroke-width': 2 }, root));
    const cross = svg('line', { y1: top, y2: bottom, class: 'chart-crosshair', visibility: 'hidden' }, root);
    const dot = svg('circle', { r: 4, fill: SERIES[0], stroke: '#151d1f', 'stroke-width': 2, visibility: 'hidden' }, root);
    const hit = svg('rect', { x: left, y: top, width: width - left - right, height: bottom - top, fill: 'transparent', class: 'chart-hit' }, root);
    const locate = event => {
      const box = root.getBoundingClientRect();
      const position = (event.clientX - box.left) * width / box.width;
      return Math.max(0, Math.min(rows.length - 1, Math.round((position - left) / Math.max(1, (width - left - right) / Math.max(1, rows.length - 1)))));
    };
    hit.addEventListener('pointermove', event => {
      const index = locate(event);
      cross.setAttribute('x1', x(index)); cross.setAttribute('x2', x(index)); cross.setAttribute('visibility', 'visible');
      dot.setAttribute('cx', x(index)); dot.setAttribute('cy', y(rows[index].value)); dot.setAttribute('visibility', 'visible');
      options.tooltip.replaceChildren(html('strong', '', format(rows[index].value)), html('span', '', rows[index].key));
      options.tooltip.hidden = false;
      options.tooltip.style.left = `${Math.min(window.innerWidth - 220, event.clientX + 14)}px`; options.tooltip.style.top = `${event.clientY - 12}px`;
    });
    hit.addEventListener('pointerleave', () => { cross.setAttribute('visibility', 'hidden'); dot.setAttribute('visibility', 'hidden'); options.tooltip.hidden = true; });
    container.append(root);
  }

  function donut(container, data, options) {
    const rows = fold(data.rows.filter(row => row.value > 0), 8);
    if (!rows.length) return empty(container);
    const total = rows.reduce((sum, row) => sum + row.value, 0);
    const size = 200, radius = 80, inner = 52, center = size / 2;
    const root = svg('svg', { viewBox: `0 0 ${size} ${size}`, class: 'chart-svg chart-donut', role: 'img', 'aria-label': `${LABELS[options.metric]} share by ${data.groupBy}` });
    let angle = -Math.PI / 2;
    const point = (r, a) => `${center + r * Math.cos(a)} ${center + r * Math.sin(a)}`;
    for (const row of rows) {
      const sweep = Math.min(Math.PI * 2 - 0.0001, Math.PI * 2 * row.value / total);
      const end = angle + sweep, large = sweep > Math.PI ? 1 : 0;
      const d = `M${point(radius, angle)} A${radius} ${radius} 0 ${large} 1 ${point(radius, end)} L${point(inner, end)} A${inner} ${inner} 0 ${large} 0 ${point(inner, angle)} Z`;
      const slice = svg('path', { d, fill: colorFor(row.key, data.groupBy), stroke: '#151d1f', 'stroke-width': 2, class: 'chart-mark' }, root);
      attachTooltip(slice, options.tooltip, [`${format(row.value)} (${Math.round(100 * row.value / total)}%)`, row.key]);
      angle = end;
    }
    const value = svg('text', { x: center, y: center + 2, 'text-anchor': 'middle', class: 'chart-donut-value' }, root); value.textContent = format(total);
    const label = svg('text', { x: center, y: center + 18, 'text-anchor': 'middle', class: 'chart-tick' }, root); label.textContent = 'total';
    const wrap = html('div', 'chart-donut-wrap'); wrap.append(root, legend(rows, data.groupBy));
    container.append(wrap);
  }

  function heatmap(container, data, options) {
    if (!data.rows.length) return empty(container);
    const max = Math.max(1, ...Object.values(data.cells));
    const grid = html('div', 'chart-heatmap');
    grid.style.gridTemplateColumns = `minmax(110px, 1.4fr) repeat(${data.columns.length}, minmax(34px, 1fr))`;
    grid.append(html('span', 'chart-heat-corner'));
    for (const column of data.columns) grid.append(html('span', 'chart-heat-head', column));
    for (const row of data.rows) {
      grid.append(html('span', 'chart-heat-row', row));
      for (const column of data.columns) {
        const count = data.cells[`${row}\u0000${column}`] || 0;
        const cell = html('span', `chart-heat-cell${count ? '' : ' empty'}`, count || '');
        const step = Math.min(RAMP.length - 1, Math.floor((RAMP.length - 1) * count / max));
        if (count) { cell.style.background = RAMP[step]; if (step >= 5) cell.classList.add('on-light'); }
        attachTooltip(cell, options.tooltip, [String(count), `${row} · ${column}`]);
        grid.append(cell);
      }
    }
    container.append(grid);
  }

  function empty(container) {
    container.append(html('p', 'chart-empty', 'No findings yet. Run a review or a runtime scan to populate this widget.'));
  }

  function render(container, chart, data, options) {
    container.replaceChildren();
    const renderers = { kpi, bar: (c, d, o) => bars(c, d, o, false), hbar: (c, d, o) => bars(c, d, o, true), line, donut, table, heatmap };
    (renderers[chart] || table)(container, data, options);
  }

  window.ThreatlintCharts = Object.freeze({ render, table, LABELS, SERIES, SEVERITY });
})();
