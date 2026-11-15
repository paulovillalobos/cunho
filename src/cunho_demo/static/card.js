// The credential's card on the phone page: black, a coin in the middle (the twelve stars of the EU around the arms of
// Portugal for the PID, around a laurel and an open book for the course certificate), and the lines of a nautical
// chart, which draw out from the coin once the wallet has checked the credential, and stay.
(function () {
  "use strict";

  const NS = "http://www.w3.org/2000/svg";
  const W = 1000;
  const H = 630;
  const CX = 500;
  const CY = 282;
  const K = 0.8; // the coin's scale: it is drawn around (0, 0) in the units of the flag's arms
  const LINE = "#8f9095";
  const WHITE = "#f2f3f5";
  const BLACK = "#0b0b0c";
  const NAME_WIDTH = 880;
  const SMALL_WIDTH = 520;

  function el(name, attributes, parent) {
    const node = document.createElementNS(NS, name);
    for (const [key, value] of Object.entries(attributes || {})) node.setAttribute(key, String(value));
    if (parent) parent.appendChild(node);
    return node;
  }

  function point(r, degrees, cx = 0, cy = 0) {
    const a = (degrees * Math.PI) / 180;
    return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  }

  function line(parent, [x1, y1], [x2, y2], attributes) {
    return el("path", { d: `M${x1.toFixed(1)} ${y1.toFixed(1)}L${x2.toFixed(1)} ${y2.toFixed(1)}`, pathLength: 1, ...attributes }, parent);
  }

  function star(parent, cx, cy, r) {
    const points = [];
    for (let i = 0; i < 10; i++) {
      const [x, y] = point(i % 2 === 0 ? r : r * 0.42, -90 + i * 36, cx, cy);
      points.push(`${x.toFixed(1)},${y.toFixed(1)}`);
    }
    el("polygon", { points: points.join(" "), fill: LINE }, parent);
  }

  // The rhumb lines of a Portuguese chart: 32 winds from the coin, and a ring of 16 roses each sending out its 8.
  function chart(parent) {
    const far = 1300;
    const ring = 330;
    for (let i = 0; i < 16; i++) {
      const centre = point(ring, i * 22.5, CX, CY);
      for (let j = 0; j < 8; j++) {
        line(parent, centre, point(far, j * 45, centre[0], centre[1]), { class: "web", stroke: LINE, "stroke-width": 0.9, "stroke-opacity": 0.26 });
      }
    }
    el("circle", { class: "web", cx: CX, cy: CY, r: ring, pathLength: 1, fill: "none", stroke: LINE, "stroke-width": 1.1, "stroke-opacity": 0.35 }, parent);
    for (let i = 0; i < 32; i++) {
      const kind = i % 4 === 0 ? 0 : i % 2 === 0 ? 1 : 2;
      line(parent, [CX, CY], point(far, i * 11.25, CX, CY), {
        class: `wind wind-${kind}`,
        stroke: LINE,
        "stroke-width": [2, 1.4, 1][kind],
        "stroke-opacity": [0.7, 0.5, 0.4][kind],
      });
    }
  }

  // The rim of the coin: the twelve stars between two rings, then a milled edge.
  function rim(parent) {
    const w = 3 / K;
    el("circle", { r: 108, fill: "none", stroke: LINE, "stroke-width": w }, parent);
    el("circle", { r: 116, fill: "none", stroke: LINE, "stroke-width": 2 / K }, parent);
    for (let i = 0; i < 12; i++) {
      const [x, y] = point(132, i * 30 - 90);
      star(parent, x, y, 8.5);
      const [dx, dy] = point(132, i * 30 - 75);
      el("circle", { cx: dx.toFixed(1), cy: dy.toFixed(1), r: 2, fill: LINE }, parent);
    }
    el("circle", { r: 148, fill: "none", stroke: LINE, "stroke-width": 2 / K }, parent);
    el("circle", { r: 154, fill: "none", stroke: LINE, "stroke-width": w }, parent);
    for (let i = 0; i < 96; i++) {
      const angle = (i * 360) / 96;
      el("path", { d: `M${point(158, angle).map((v) => v.toFixed(1)).join(" ")}L${point(164, angle).map((v) => v.toFixed(1)).join(" ")}`, stroke: LINE, "stroke-width": 1.75, "stroke-linecap": "round" }, parent);
    }
  }

  // The course certificate's face: a laurel wreath around an open book, in the arms' white.
  function laurel(parent) {
    const R = 74;
    for (const side of [-1, 1]) {
      const [x0, y0] = point(R, 90 + side * 14);
      const [x1, y1] = point(R, 90 + side * 150);
      el("path", { d: `M${x0.toFixed(1)} ${y0.toFixed(1)}A${R} ${R} 0 0 ${side < 0 ? 0 : 1} ${x1.toFixed(1)} ${y1.toFixed(1)}`, fill: "none", stroke: WHITE, "stroke-width": 3, "stroke-linecap": "round" }, parent);
      for (let j = 0; j < 10; j++) {
        const angle = 90 + side * (22 + j * 13);
        const [x, y] = point(R, angle);
        for (const off of [-1, 1]) {
          const [lx, ly] = [x + off * 9 * Math.cos((angle * Math.PI) / 180), y + off * 9 * Math.sin((angle * Math.PI) / 180)];
          const turn = angle + 90 * side + 32 * side * off;
          el("ellipse", { cx: lx.toFixed(1), cy: ly.toFixed(1), rx: 4.6, ry: 10.5, transform: `rotate(${turn.toFixed(0)} ${lx.toFixed(1)} ${ly.toFixed(1)})`, fill: WHITE, stroke: BLACK, "stroke-width": 1.2 }, parent);
        }
      }
    }
    el("path", { d: "M-14 72q14 10 28 0", fill: "none", stroke: WHITE, "stroke-width": 3, "stroke-linecap": "round" }, parent);
    for (const side of [-1, 1]) {
      const s = side;
      el("path", { d: `M0 -12C${-12 * s} -22 ${-30 * s} -22 ${-40 * s} -16L${-40 * s} 22C${-30 * s} 16 ${-12 * s} 16 0 26Z`, fill: WHITE, stroke: BLACK, "stroke-width": 1.4 }, parent);
    }
    for (let k = 0; k < 4; k++) {
      const y = -8 + k * 7;
      el("path", { d: `M-34 ${y}C-24 ${y - 5} -12 ${y - 5} -5 ${y + 1}M5 ${y + 1}C12 ${y - 5} 24 ${y - 5} 34 ${y}`, fill: "none", stroke: BLACK, "stroke-width": 1.4 }, parent);
    }
    el("path", { d: "M0 -12V26", stroke: BLACK, "stroke-width": 2 }, parent);
  }

  let made = 0;

  function build(host) {
    const id = (name) => `card${made}-${name}`;
    made += 1;
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, class: "card-art", "aria-hidden": "true", focusable: "false" });
    const defs = el("defs", {}, svg);
    el("clipPath", { id: id("edge") }, defs).appendChild(el("rect", { width: W, height: H, rx: 34 }));
    const fadeStops = [[0, "#222"], [0.2, "#222"], [0.3, "#fff"], [0.76, "#fff"], [0.86, "#222"], [1, "#222"]];
    const fade = el("linearGradient", { id: id("fade"), x1: 0, y1: 0, x2: 0, y2: 1 }, defs);
    for (const [offset, colour] of fadeStops) el("stop", { offset, "stop-color": colour }, fade);
    const mask = el("mask", { id: id("mask") }, defs);
    el("rect", { width: W, height: H, fill: `url(#${id("fade")})` }, mask);
    el("circle", { cx: CX, cy: CY, r: 134, fill: "#000" }, mask);
    const gradient = (id, stops, attributes) => {
      const g = el("radialGradient", { id, ...attributes }, defs);
      for (const [offset, colour, opacity] of stops) el("stop", { offset, "stop-color": colour, "stop-opacity": opacity ?? 1 }, g);
    };
    gradient(id("coin"), [[0, "#55565c"], [0.55, "#2c2d31"], [1, "#151517"]], { cx: 0.38, cy: 0.32, r: 0.8 });
    gradient(id("band"), [[0, "#232427"], [1, "#0f0f11"]], { cx: 0.4, cy: 0.35, r: 0.75 });
    gradient(id("glow"), [[0, "#fff", 0.75], [0.35, "#cfd6ff", 0.25], [1, "#fff", 0]], { cx: 0.5, cy: 0.5, r: 0.5 });
    const sheen = el("linearGradient", { id: id("sheen"), x1: 0, y1: 0, x2: 1, y2: 0 }, defs);
    for (const [offset, opacity] of [[0, 0], [0.5, 0.2], [1, 0]]) el("stop", { offset, "stop-color": "#fff", "stop-opacity": opacity }, sheen);

    const body = el("g", { "clip-path": `url(#${id("edge")})` }, svg);
    el("rect", { width: W, height: H, fill: BLACK }, body);
    chart(el("g", { class: "card-lines", mask: `url(#${id("mask")})` }, body));
    el("circle", { class: "card-glow", cx: CX, cy: CY, r: 230, fill: `url(#${id("glow")})` }, body);
    const coin = el("g", { class: "card-coin", transform: `translate(${CX} ${CY}) scale(${K})` }, body);
    el("circle", { r: 154, fill: `url(#${id("band")})` }, coin);
    el("circle", { r: 108, fill: `url(#${id("coin")})` }, coin);
    el("image", { class: "card-arms", href: "/arms.svg", x: -100.24, y: -100.63, width: 200.47, height: 201.25 }, coin);
    laurel(el("g", { class: "card-laurel" }, coin));
    rim(coin);

    const text = (attributes) => el("text", attributes, body);
    const refs = {
      issuer: text({ class: "card-issuer", x: 64, y: 96 }),
      issuerNote: text({ class: "card-small", "font-size": 30, x: 64, y: 140 }),
      type: text({ class: "card-small", "font-size": 30, x: 936, y: 96, "text-anchor": "end" }),
      typeNote: text({ class: "card-small", "font-size": 30, x: 936, y: 138, "text-anchor": "end" }),
      name: text({ class: "card-name", x: 64, y: 532 }),
      line: text({ class: "card-small", x: 64, y: 584 }),
      corner: text({ class: "card-small", x: 936, y: 584, "text-anchor": "end" }),
    };
    el("rect", { class: "card-sheen", x: -420, y: -100, width: 300, height: H + 200, fill: `url(#${id("sheen")})` }, body);
    el("rect", { x: 1.5, y: 1.5, width: W - 3, height: H - 3, rx: 33, fill: "none", stroke: "#4a4b4f", "stroke-width": 3 }, svg);
    host.textContent = "";
    host.appendChild(svg);
    return refs;
  }

  // A line too long for its place is made smaller until it fits, never cut.
  function fit(node, width, size) {
    node.setAttribute("font-size", String(size));
    const length = node.getComputedTextLength ? node.getComputedTextLength() : 0;
    if (length > width) node.setAttribute("font-size", String(Math.floor((size * width) / length)));
  }

  window.CunhoCard = {
    create(host) {
      const refs = build(host);
      let shown = {};
      let timer = null;
      const layout = () => {
        fit(refs.name, NAME_WIDTH, 64);
        fit(refs.line, SMALL_WIDTH, 30);
        fit(refs.corner, NAME_WIDTH - SMALL_WIDTH - 40, 30);
      };
      if (document.fonts && document.fonts.ready) document.fonts.ready.then(layout);
      return {
        // kind is "pid" or "course"; the other fields are the text on the card, already in the page's language
        show(face) {
          if (JSON.stringify(face) === JSON.stringify(shown)) return;
          shown = face;
          host.classList.toggle("course", face.kind === "course");
          for (const key of ["issuer", "issuerNote", "type", "typeNote", "name", "line", "corner"]) refs[key].textContent = face[key] || "";
          refs.line.classList.toggle("bright", face.kind === "course");
          layout();
        },
        // Verified: the coin flares, light sweeps across, the chart draws out; the lines then stay.
        verified(on) {
          if (!on) {
            clearTimeout(timer);
            timer = null;
            host.classList.remove("verifying", "verified");
            return;
          }
          if (host.classList.contains("verified") || host.classList.contains("verifying")) return;
          if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
            host.classList.add("verified");
            return;
          }
          host.classList.add("verifying");
          timer = setTimeout(() => {
            host.classList.remove("verifying");
            host.classList.add("verified");
          }, 2600);
        },
      };
    },
  };
})();
