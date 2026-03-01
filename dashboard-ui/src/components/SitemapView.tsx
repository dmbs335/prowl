import { useEffect, useState } from "react";
import { useCrawlStore } from "../hooks/useCrawlStore";
import type { Endpoint, SitemapNode } from "../types";

const MODULE_COLORS: Record<string, string> = {
  s1_spider: "#3b82f6",
  s2_bruteforce: "#f97316",
  s3_params: "#10b981",
  s4_js: "#8b5cf6",
  s5_api: "#ec4899",
  s6_passive: "#6b7280",
  s7_auth: "#f59e0b",
};

function TreeNode({
  node,
  depth,
  onSelect,
}: {
  node: SitemapNode;
  depth: number;
  onSelect: (ep: Endpoint) => void;
}) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children.length > 0 || node.endpoints.length > 0;

  return (
    <div style={{ marginLeft: depth > 0 ? 16 : 0 }}>
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "3px 6px",
          cursor: hasChildren ? "pointer" : "default",
          borderRadius: 4,
          fontSize: 13,
          color: "var(--text-primary)",
        }}
        onMouseEnter={(e) =>
          (e.currentTarget.style.background = "var(--bg-tertiary)")
        }
        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
      >
        {hasChildren && (
          <span style={{ fontSize: 10, color: "var(--text-muted)", width: 12 }}>
            {expanded ? "▼" : "▶"}
          </span>
        )}
        <span style={{ fontFamily: "monospace" }}>
          /{node.name}
        </span>
        {node.count > 0 && (
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
            ({node.count})
          </span>
        )}
      </div>

      {expanded && (
        <>
          {node.endpoints.map((ep, i) => (
            <div
              key={i}
              onClick={() => onSelect(ep)}
              style={{
                marginLeft: 28,
                padding: "2px 6px",
                fontSize: 12,
                display: "flex",
                alignItems: "center",
                gap: 8,
                cursor: "pointer",
                borderRadius: 4,
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.background = "var(--bg-tertiary)")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.background = "transparent")
              }
            >
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  color: MODULE_COLORS[ep.source_module] || "#888",
                  minWidth: 36,
                }}
              >
                {ep.method}
              </span>
              <span
                style={{ fontFamily: "monospace", color: "var(--text-secondary)" }}
              >
                {ep.url.split("?")[0].split("/").pop() || "/"}
              </span>
              {ep.param_count > 0 && (
                <span style={{ fontSize: 10, color: "var(--accent-green)" }}>
                  {ep.param_count}p
                </span>
              )}
              {ep.status_code && (
                <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
                  [{ep.status_code}]
                </span>
              )}
            </div>
          ))}
          {node.children.map((child, i) => (
            <TreeNode key={i} node={child} depth={depth + 1} onSelect={onSelect} />
          ))}
        </>
      )}
    </div>
  );
}

export function SitemapView() {
  const [tree, setTree] = useState<SitemapNode | null>(null);
  const { setSelectedNode } = useCrawlStore();
  const endpoints = useCrawlStore((s) => s.endpoints);

  useEffect(() => {
    fetch("/api/sitemap")
      .then((r) => r.json())
      .then(setTree)
      .catch(() => {});

    // Refresh periodically
    const interval = setInterval(() => {
      fetch("/api/sitemap")
        .then((r) => r.json())
        .then(setTree)
        .catch(() => {});
    }, 3000);

    return () => clearInterval(interval);
  }, [endpoints.length]);

  if (!tree) {
    return (
      <div style={{ padding: 24, color: "var(--text-muted)" }}>
        Waiting for endpoints...
      </div>
    );
  }

  return (
    <div
      style={{
        padding: 12,
        overflowY: "auto",
        height: "100%",
        background: "var(--bg-primary)",
      }}
    >
      {tree.children.map((child, i) => (
        <TreeNode
          key={i}
          node={child}
          depth={0}
          onSelect={(ep) => setSelectedNode(ep.url)}
        />
      ))}
    </div>
  );
}
