import { useState, useEffect, useRef, useCallback } from "react";
import { useCrawlStore } from "../hooks/useCrawlStore";
import type { Endpoint } from "../types";

// ── types ──────────────────────────────────────────────────
interface GNode {
  id: string;
  label: string;
  method: string;
  status: number | null;
  source: string;
  params: number;
  depth: number;
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
  isFocus?: boolean;
}

interface GEdge {
  source: string;
  target: string;
}

interface GraphData {
  nodes: GNode[];
  edges: GEdge[];
  nodeMap: Map<string, GNode>;
}

// ── colors ─────────────────────────────────────────────────
const SOURCE_COLORS: Record<string, string> = {
  s1_spider: "#3b82f6",
  s2_bruteforce: "#f97316",
  s3_params: "#10b981",
  s4_js: "#8b5cf6",
  s5_api: "#ec4899",
  s6_passive: "#6b7280",
  s7_auth: "#f59e0b",
  "": "#6b7280",
};

const MODULE_LABELS: Record<string, string> = {
  s1_spider: "Spider",
  s2_bruteforce: "Brute",
  s3_params: "Params",
  s4_js: "JS",
  s5_api: "API",
  s6_passive: "Passive",
  s7_auth: "Auth",
};

function nodeColor(n: GNode): string {
  if (n.status && n.status >= 400) return "#ef4444";
  return SOURCE_COLORS[n.source] || "#6b7280";
}

// ── force layout ───────────────────────────────────────────
function runForceLayout(
  nodes: GNode[],
  edges: GEdge[],
  width: number,
  height: number,
  iterations: number
) {
  if (nodes.length === 0) return;

  const adj = new Map<string, string[]>();
  const idx = new Map<string, number>();
  for (let i = 0; i < nodes.length; i++) {
    idx.set(nodes[i].id, i);
    adj.set(nodes[i].id, []);
  }
  for (const e of edges) {
    adj.get(e.source)?.push(e.target);
    adj.get(e.target)?.push(e.source);
  }

  // Place focus node at center, others radially
  const focusNode = nodes.find((n) => n.isFocus);
  if (focusNode) {
    focusNode.x = width / 2;
    focusNode.y = height / 2;
    focusNode.vx = 0;
    focusNode.vy = 0;
    const others = nodes.filter((n) => !n.isFocus);
    const angleStep = (2 * Math.PI) / Math.max(others.length, 1);
    const radius = Math.min(width, height) * 0.3;
    for (let i = 0; i < others.length; i++) {
      others[i].x = width / 2 + Math.cos(angleStep * i) * radius;
      others[i].y = height / 2 + Math.sin(angleStep * i) * radius;
      others[i].x += (Math.random() - 0.5) * 20;
      others[i].y += (Math.random() - 0.5) * 20;
      others[i].vx = 0;
      others[i].vy = 0;
    }
  } else {
    const depthCounts = new Map<number, number>();
    for (const n of nodes) {
      depthCounts.set(n.depth, (depthCounts.get(n.depth) || 0) + 1);
    }
    const maxDepth = Math.max(...depthCounts.keys()) || 1;
    const depthIndex = new Map<number, number>();
    for (const n of nodes) {
      const di = depthIndex.get(n.depth) || 0;
      const total = depthCounts.get(n.depth) || 1;
      n.x = (n.depth / maxDepth) * width * 0.7 + width * 0.15;
      n.y = ((di + 0.5) / total) * height * 0.8 + height * 0.1;
      n.x += (Math.random() - 0.5) * 40;
      n.y += (Math.random() - 0.5) * 40;
      n.vx = 0;
      n.vy = 0;
      depthIndex.set(n.depth, di + 1);
    }
  }

  const k = Math.sqrt((width * height) / Math.max(nodes.length, 1));
  const kSq = k * k;

  for (let iter = 0; iter < iterations; iter++) {
    const alpha = 0.3 * (1 - iter / iterations);
    if (alpha < 0.001) break;

    const cutoff = k * 4;
    const cutoffSq = cutoff * cutoff;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x;
        const dy = nodes[j].y - nodes[i].y;
        const distSq = dx * dx + dy * dy;
        if (distSq > cutoffSq) continue;
        const dist = Math.sqrt(distSq) || 1;
        const force = (kSq / dist) * alpha;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        nodes[i].vx -= fx;
        nodes[i].vy -= fy;
        nodes[j].vx += fx;
        nodes[j].vy += fy;
      }
    }

    for (const e of edges) {
      const si = idx.get(e.source);
      const ti = idx.get(e.target);
      if (si === undefined || ti === undefined) continue;
      const s = nodes[si];
      const t = nodes[ti];
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist / k) * alpha * 0.7;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      s.vx += fx;
      s.vy += fy;
      t.vx -= fx;
      t.vy -= fy;
    }

    const cx = width / 2;
    const cy = height / 2;
    for (const n of nodes) {
      // Pin focus node at center
      if (n.isFocus) {
        n.x = cx;
        n.y = cy;
        n.vx = 0;
        n.vy = 0;
        continue;
      }
      n.vx += (cx - n.x) * 0.005 * alpha;
      n.vy += (cy - n.y) * 0.005 * alpha;
      n.x += n.vx;
      n.y += n.vy;
      n.vx *= 0.85;
      n.vy *= 0.85;
    }
  }
}

// ── spatial grid for fast hit testing ──────────────────────
class SpatialGrid {
  private cells = new Map<string, GNode[]>();
  private cellSize: number;

  constructor(nodes: GNode[], cellSize = 40) {
    this.cellSize = cellSize;
    for (const n of nodes) {
      const key = `${Math.floor(n.x / cellSize)},${Math.floor(n.y / cellSize)}`;
      const cell = this.cells.get(key);
      if (cell) cell.push(n);
      else this.cells.set(key, [n]);
    }
  }

  findNearest(wx: number, wy: number): GNode | null {
    const cs = this.cellSize;
    const cx = Math.floor(wx / cs);
    const cy = Math.floor(wy / cs);
    let best: GNode | null = null;
    let bestDist = Infinity;
    for (let dx = -1; dx <= 1; dx++) {
      for (let dy = -1; dy <= 1; dy++) {
        const cell = this.cells.get(`${cx + dx},${cy + dy}`);
        if (!cell) continue;
        for (const n of cell) {
          const ddx = n.x - wx;
          const ddy = n.y - wy;
          const dist = ddx * ddx + ddy * ddy;
          const hitR = (n.r + 4) * (n.r + 4);
          if (dist < hitR && dist < bestDist) {
            best = n;
            bestDist = dist;
          }
        }
      }
    }
    return best;
  }
}

// ── helpers ────────────────────────────────────────────────
function getPathname(url: string): string {
  try {
    return new URL(url).pathname || "/";
  } catch {
    return "/";
  }
}

function getParentPath(path: string): string {
  if (path === "/") return "";
  const parts = path.replace(/\/$/, "").split("/");
  parts.pop();
  return parts.join("/") || "/";
}

// ── build ego graph (focus node + 1-hop neighbors) ─────────
function buildEgoGraph(endpoints: Endpoint[], focusPath: string): GraphData {
  // Build full path → endpoint mapping
  const pathMap = new Map<string, Endpoint>();
  for (const ep of endpoints) {
    const path = getPathname(ep.url);
    if (!pathMap.has(path)) {
      pathMap.set(path, ep);
    }
  }

  // Collect 1-hop neighborhood: parent, children, siblings
  const neighborPaths = new Set<string>();
  neighborPaths.add(focusPath);

  const focusParent = getParentPath(focusPath);
  if (focusParent) neighborPaths.add(focusParent);

  // Children: paths whose parent is focusPath
  for (const path of pathMap.keys()) {
    if (getParentPath(path) === focusPath) {
      neighborPaths.add(path);
    }
  }

  // Siblings: paths sharing the same parent
  if (focusParent) {
    for (const path of pathMap.keys()) {
      if (getParentPath(path) === focusParent) {
        neighborPaths.add(path);
      }
    }
  }

  // Build nodes
  const nodeMap = new Map<string, GNode>();
  for (const path of neighborPaths) {
    const ep = pathMap.get(path);
    nodeMap.set(path, {
      id: path,
      label: path.split("/").pop() || "/",
      method: ep?.method || "",
      status: ep?.status_code ?? null,
      source: ep?.source_module || "",
      params: ep?.param_count || 0,
      depth: (path.match(/\//g) || []).length,
      x: 0, y: 0, vx: 0, vy: 0,
      r: 4,
      isFocus: path === focusPath,
    });
  }

  // Build edges (parent-child within neighborhood)
  const edges: GEdge[] = [];
  const edgeSet = new Set<string>();
  for (const path of neighborPaths) {
    if (path === "/") continue;
    const parent = getParentPath(path);
    if (neighborPaths.has(parent)) {
      const key = `${parent}->${path}`;
      if (!edgeSet.has(key)) {
        edgeSet.add(key);
        edges.push({ source: parent, target: path });
      }
    }
  }

  // Size nodes
  const nodes = Array.from(nodeMap.values());
  for (const n of nodes) {
    if (n.isFocus) {
      n.r = Math.max(10, Math.min(20, 12 + n.params * 2));
    } else {
      n.r = Math.max(4, Math.min(14, 5 + n.params * 2));
    }
  }

  return { nodes, edges, nodeMap };
}

// ── draw function ──────────────────────────────────────────
function draw(
  ctx: CanvasRenderingContext2D,
  w: number,
  h: number,
  data: GraphData,
  cam: { ox: number; oy: number; scale: number },
  hovered: GNode | null
) {
  const dpr = window.devicePixelRatio || 1;
  ctx.canvas.width = w * dpr;
  ctx.canvas.height = h * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  ctx.fillStyle = "#0f1117";
  ctx.fillRect(0, 0, w, h);

  ctx.save();
  ctx.translate(cam.ox, cam.oy);
  ctx.scale(cam.scale, cam.scale);

  // Edges
  ctx.lineWidth = 1.5;
  ctx.globalAlpha = 0.35;
  ctx.strokeStyle = "#4a5568";
  ctx.beginPath();
  for (const e of data.edges) {
    const s = data.nodeMap.get(e.source);
    const t = data.nodeMap.get(e.target);
    if (!s || !t) continue;
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(t.x, t.y);
  }
  ctx.stroke();

  // Arrow heads
  ctx.globalAlpha = 0.4;
  ctx.fillStyle = "#4a5568";
  for (const e of data.edges) {
    const s = data.nodeMap.get(e.source);
    const t = data.nodeMap.get(e.target);
    if (!s || !t) continue;
    const dx = t.x - s.x;
    const dy = t.y - s.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist < 1) continue;
    const ux = dx / dist;
    const uy = dy / dist;
    const ax = t.x - ux * (t.r + 3);
    const ay = t.y - uy * (t.r + 3);
    const sz = 6;
    ctx.beginPath();
    ctx.moveTo(ax, ay);
    ctx.lineTo(ax - ux * sz - uy * sz * 0.5, ay - uy * sz + ux * sz * 0.5);
    ctx.lineTo(ax - ux * sz + uy * sz * 0.5, ay - uy * sz - ux * sz * 0.5);
    ctx.closePath();
    ctx.fill();
  }
  ctx.globalAlpha = 1;

  // Nodes
  for (const n of data.nodes) {
    const color = nodeColor(n);
    const isHov = hovered?.id === n.id;
    const isFocus = n.isFocus;

    // Focus node glow
    if (isFocus) {
      ctx.shadowColor = color;
      ctx.shadowBlur = 20;
    } else if (isHov) {
      ctx.shadowColor = color;
      ctx.shadowBlur = 12;
    }

    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(n.x, n.y, isHov ? n.r + 2 : n.r, 0, Math.PI * 2);
    ctx.fill();

    // Focus ring
    if (isFocus) {
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 2;
      ctx.globalAlpha = 0.6;
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + 5, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalAlpha = 1;
    }

    if (n.params > 0) {
      ctx.strokeStyle = "#10b981";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + (isFocus ? 8 : 3), 0, Math.PI * 2);
      ctx.stroke();
    }

    ctx.shadowColor = "transparent";
    ctx.shadowBlur = 0;

    // Always show labels in ego view (few nodes)
    ctx.fillStyle = isFocus ? "#ffffff" : isHov ? "#ffffff" : "#9ca0b0";
    ctx.font = `${isFocus ? "bold 13" : isHov ? "bold 12" : "12"}px monospace`;
    ctx.textAlign = "center";
    ctx.fillText(n.label, n.x, n.y + n.r + 16);
  }

  ctx.restore();

  // Tooltip
  if (hovered) {
    const sx = hovered.x * cam.scale + cam.ox;
    const sy = hovered.y * cam.scale + cam.oy;
    const lines = [
      hovered.id,
      hovered.method ? `${hovered.method} [${hovered.status || "?"}]` : "",
      hovered.params > 0 ? `${hovered.params} params` : "",
      hovered.source ? `via ${hovered.source}` : "",
    ].filter(Boolean);

    const tw = Math.max(...lines.map((l) => l.length)) * 7 + 20;
    const th = lines.length * 16 + 12;
    let tx = sx + 15;
    let ty = sy - 10;
    if (tx + tw > w) tx = sx - tw - 15;
    if (ty + th > h) ty = h - th - 5;
    if (ty < 0) ty = 5;

    ctx.fillStyle = "rgba(26,29,39,0.95)";
    ctx.strokeStyle = "#3b82f6";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(tx, ty, tw, th, 6);
    ctx.fill();
    ctx.stroke();

    ctx.font = "12px monospace";
    ctx.textAlign = "left";
    for (let i = 0; i < lines.length; i++) {
      ctx.fillStyle = i === 0 ? "#e4e5e9" : "#9ca0b0";
      ctx.fillText(lines[i], tx + 10, ty + 16 + i * 16);
    }
  }

  // Node count badge
  ctx.fillStyle = "rgba(26,29,39,0.8)";
  ctx.fillRect(8, h - 24, 120, 20);
  ctx.fillStyle = "#6b7084";
  ctx.font = "11px monospace";
  ctx.textAlign = "left";
  ctx.fillText(
    `${data.nodes.length} nodes / ${data.edges.length} edges`,
    12,
    h - 10
  );
}

// ── endpoint list view ────────────────────────────────────
function EndpointList({
  endpoints,
  onSelect,
}: {
  endpoints: Endpoint[];
  onSelect: (path: string) => void;
}) {
  const [query, setQuery] = useState("");

  // Deduplicate by pathname
  const pathEntries = new Map<string, Endpoint>();
  for (const ep of endpoints) {
    const path = getPathname(ep.url);
    if (!pathEntries.has(path)) {
      pathEntries.set(path, ep);
    } else {
      const existing = pathEntries.get(path)!;
      if ((ep.param_count || 0) > (existing.param_count || 0)) {
        pathEntries.set(path, ep);
      }
    }
  }

  const filtered = Array.from(pathEntries.entries())
    .filter(([path]) => path.toLowerCase().includes(query.toLowerCase()))
    .sort(([a], [b]) => a.localeCompare(b));

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        background: "#0f1117",
      }}
    >
      {/* Search bar */}
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search endpoints..."
          style={{
            width: "100%",
            padding: "8px 12px",
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            color: "var(--text-primary)",
            fontSize: 13,
            fontFamily: "monospace",
            outline: "none",
          }}
        />
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
          {filtered.length} endpoints -- click to explore neighbors
        </div>
      </div>

      {/* Endpoint list */}
      <div style={{ flex: 1, overflowY: "auto", padding: "4px 0" }}>
        {filtered.map(([path, ep]) => (
          <div
            key={path}
            onClick={() => onSelect(path)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "6px 16px",
              cursor: "pointer",
              borderBottom: "1px solid rgba(255,255,255,0.04)",
              transition: "background 0.1s",
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLDivElement).style.background = "rgba(59,130,246,0.08)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLDivElement).style.background = "transparent";
            }}
          >
            {/* Method badge */}
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                fontFamily: "monospace",
                color: "#fff",
                background: SOURCE_COLORS[ep.source_module] || "#6b7280",
                padding: "2px 6px",
                borderRadius: 3,
                minWidth: 32,
                textAlign: "center",
                flexShrink: 0,
              }}
            >
              {ep.method}
            </span>

            {/* Path */}
            <span
              style={{
                flex: 1,
                fontSize: 12,
                fontFamily: "monospace",
                color: "var(--text-primary)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {path}
            </span>

            {/* Status */}
            {ep.status_code && (
              <span
                style={{
                  fontSize: 11,
                  fontFamily: "monospace",
                  color:
                    ep.status_code < 300 ? "#10b981" :
                    ep.status_code < 400 ? "#3b82f6" :
                    ep.status_code < 500 ? "#f97316" : "#ef4444",
                  flexShrink: 0,
                }}
              >
                {ep.status_code}
              </span>
            )}

            {/* Param count */}
            {ep.param_count > 0 && (
              <span
                style={{
                  fontSize: 10,
                  color: "#10b981",
                  fontFamily: "monospace",
                  flexShrink: 0,
                }}
              >
                {ep.param_count}p
              </span>
            )}

            {/* Source */}
            <span
              style={{
                fontSize: 10,
                color: "var(--text-muted)",
                flexShrink: 0,
              }}
            >
              {MODULE_LABELS[ep.source_module] || ""}
            </span>
          </div>
        ))}

        {filtered.length === 0 && (
          <div
            style={{
              padding: 40,
              textAlign: "center",
              color: "var(--text-muted)",
              fontSize: 13,
            }}
          >
            {endpoints.length === 0
              ? "No endpoints discovered yet"
              : "No matching endpoints"}
          </div>
        )}
      </div>
    </div>
  );
}

// ── component ──────────────────────────────────────────────
export function GraphView() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const setSelectedNode = useCrawlStore((s) => s.setSelectedNode);
  const endpoints = useCrawlStore((s) => s.endpoints);

  // Ego-centric state
  const [focusedPath, setFocusedPath] = useState<string | null>(null);

  // All mutable state in refs
  const graphRef = useRef<GraphData | null>(null);
  const gridRef = useRef<SpatialGrid | null>(null);
  const hoveredRef = useRef<GNode | null>(null);
  const camRef = useRef({ ox: 0, oy: 0, scale: 1 });
  const dragRef = useRef({ dragging: false, lastX: 0, lastY: 0 });
  const rafRef = useRef(0);

  const scheduleRedraw = useCallback(() => {
    if (rafRef.current) return;
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = 0;
      const canvas = canvasRef.current;
      if (!canvas || !graphRef.current) return;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      if (w === 0 || h === 0) return;
      draw(ctx, w, h, graphRef.current, camRef.current, hoveredRef.current);
    });
  }, []);

  // Build ego graph when focusedPath changes
  useEffect(() => {
    if (!focusedPath || endpoints.length === 0) {
      graphRef.current = null;
      gridRef.current = null;
      return;
    }
    const data = buildEgoGraph(endpoints, focusedPath);
    const w = containerRef.current?.clientWidth || 900;
    const h = containerRef.current?.clientHeight || 600;
    runForceLayout(data.nodes, data.edges, w, h, Math.min(200, data.nodes.length * 3));
    graphRef.current = data;
    gridRef.current = new SpatialGrid(data.nodes);
    camRef.current = { ox: 0, oy: 0, scale: 1 };
    scheduleRedraw();
  }, [focusedPath, endpoints, scheduleRedraw]);

  // ResizeObserver
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const ro = new ResizeObserver(() => {
      const canvas = canvasRef.current;
      if (!canvas || !container) return;
      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight;
      scheduleRedraw();
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, [scheduleRedraw]);

  useEffect(() => {
    scheduleRedraw();
  }, [scheduleRedraw]);

  useEffect(() => {
    return () => {
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = 0;
      }
    };
  }, []);

  // ── mouse handlers ──────────────────────────────────────
  function screenToWorld(sx: number, sy: number) {
    const cam = camRef.current;
    return {
      x: (sx - cam.ox) / cam.scale,
      y: (sy - cam.oy) / cam.scale,
    };
  }

  function findNode(sx: number, sy: number): GNode | null {
    if (!gridRef.current) return null;
    const { x, y } = screenToWorld(sx, sy);
    return gridRef.current.findNearest(x, y);
  }

  function handleMouseDown(e: React.MouseEvent) {
    dragRef.current = { dragging: true, lastX: e.clientX, lastY: e.clientY };
  }

  function handleMouseMove(e: React.MouseEvent) {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;

    if (dragRef.current.dragging) {
      const dx = e.clientX - dragRef.current.lastX;
      const dy = e.clientY - dragRef.current.lastY;
      camRef.current.ox += dx;
      camRef.current.oy += dy;
      dragRef.current.lastX = e.clientX;
      dragRef.current.lastY = e.clientY;
      scheduleRedraw();
      return;
    }

    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const node = findNode(mx, my);
    if (node !== hoveredRef.current) {
      hoveredRef.current = node;
      const canvas = canvasRef.current;
      if (canvas) canvas.style.cursor = node ? "pointer" : "grab";
      scheduleRedraw();
    }
  }

  function handleMouseUp() {
    if (dragRef.current.dragging) {
      dragRef.current.dragging = false;
      const canvas = canvasRef.current;
      if (canvas) canvas.style.cursor = hoveredRef.current ? "pointer" : "grab";
    }
  }

  function handleClick(e: React.MouseEvent) {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const node = findNode(e.clientX - rect.left, e.clientY - rect.top);
    if (node) {
      // Navigate to clicked node as new focus
      setFocusedPath(node.id);

      // Also set DetailPanel selection
      const ep = useCrawlStore
        .getState()
        .endpoints.find((ep) => {
          try {
            return new URL(ep.url).pathname === node.id;
          } catch {
            return false;
          }
        });
      if (ep) setSelectedNode(ep.url);
    }
  }

  function handleWheel(e: React.WheelEvent) {
    e.preventDefault();
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const cam = camRef.current;
    const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
    const newScale = Math.max(0.1, Math.min(5, cam.scale * zoomFactor));

    cam.ox = mx - ((mx - cam.ox) / cam.scale) * newScale;
    cam.oy = my - ((my - cam.oy) / cam.scale) * newScale;
    cam.scale = newScale;

    scheduleRedraw();
  }

  // ── list mode (no focus selected) ───────────────────────
  if (!focusedPath) {
    return (
      <div
        ref={containerRef}
        style={{ width: "100%", height: "100%", position: "relative", overflow: "hidden" }}
      >
        <EndpointList endpoints={endpoints} onSelect={setFocusedPath} />
      </div>
    );
  }

  // ── ego graph mode ──────────────────────────────────────
  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        height: "100%",
        position: "relative",
        overflow: "hidden",
        cursor: "grab",
      }}
    >
      <canvas
        ref={canvasRef}
        style={{ width: "100%", height: "100%", display: "block" }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={() => {
          dragRef.current.dragging = false;
          hoveredRef.current = null;
          const canvas = canvasRef.current;
          if (canvas) canvas.style.cursor = "grab";
          scheduleRedraw();
        }}
        onClick={handleClick}
        onWheel={handleWheel}
      />

      {/* Back button */}
      <button
        onClick={() => {
          setFocusedPath(null);
          setSelectedNode(null);
        }}
        style={{
          position: "absolute",
          top: 8,
          left: 8,
          background: "rgba(26,29,39,0.9)",
          border: "1px solid var(--border)",
          borderRadius: 6,
          padding: "6px 14px",
          color: "var(--text-primary)",
          cursor: "pointer",
          fontSize: 12,
          fontFamily: "monospace",
          display: "flex",
          alignItems: "center",
          gap: 6,
        }}
      >
        <span style={{ fontSize: 14 }}>&larr;</span>
        Back to list
      </button>

      {/* Current focus label */}
      <div
        style={{
          position: "absolute",
          top: 8,
          left: "50%",
          transform: "translateX(-50%)",
          background: "rgba(26,29,39,0.9)",
          border: "1px solid var(--border)",
          borderRadius: 6,
          padding: "6px 16px",
          fontSize: 12,
          fontFamily: "monospace",
          color: "var(--accent-blue)",
          fontWeight: 600,
        }}
      >
        {focusedPath}
      </div>

      {/* Legend */}
      <div
        style={{
          position: "absolute",
          top: 8,
          right: 8,
          background: "rgba(26,29,39,0.9)",
          border: "1px solid var(--border)",
          borderRadius: 6,
          padding: "8px 12px",
          fontSize: 11,
          color: "var(--text-muted)",
          display: "flex",
          flexDirection: "column",
          gap: 3,
        }}
      >
        {Object.entries({
          Spider: "#3b82f6",
          Brute: "#f97316",
          Params: "#10b981",
          JS: "#8b5cf6",
          API: "#ec4899",
          Passive: "#6b7280",
          Auth: "#f59e0b",
          "4xx/5xx": "#ef4444",
        }).map(([label, color]) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: color,
              }}
            />
            <span>{label}</span>
          </div>
        ))}
        <div style={{ borderTop: "1px solid var(--border)", paddingTop: 3, marginTop: 2 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", border: "2px solid #10b981", background: "transparent" }} />
            <span>Has params</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 2 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", border: "2px solid #ffffff", background: "transparent" }} />
            <span>Focus node</span>
          </div>
        </div>
      </div>
    </div>
  );
}
