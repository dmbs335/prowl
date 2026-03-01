import { useState } from "react";
import { useCrawlStore } from "../hooks/useCrawlStore";

export function InterventionBanner() {
  const interventions = useCrawlStore((s) => s.interventions);
  const pending = interventions.filter((i) => i.state === "pending");
  const [showCookieModal, setShowCookieModal] = useState(false);
  const [cookieInput, setCookieInput] = useState("");

  if (pending.length === 0) return null;

  const current = pending[0];

  const kindLabels: Record<string, string> = {
    login: "Login Required",
    captcha: "CAPTCHA Detected",
    "2fa": "2FA Required",
    manual: "Manual Action Needed",
  };

  async function handleResolve() {
    await fetch(`/api/interventions/${current.id}/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    await fetch("/api/crawl/resume", { method: "POST" });
  }

  async function handlePasteCookies() {
    if (!cookieInput.trim()) return;

    // Parse cookies
    const cookies: Record<string, string> = {};
    for (const part of cookieInput.split(";")) {
      const [k, ...v] = part.split("=");
      if (k?.trim()) cookies[k.trim()] = v.join("=").trim();
    }

    await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cookies }),
    });

    await fetch(`/api/interventions/${current.id}/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cookies }),
    });

    await fetch("/api/crawl/resume", { method: "POST" });
    setShowCookieModal(false);
    setCookieInput("");
  }

  return (
    <>
      <div
        className="pulse"
        style={{
          background: "linear-gradient(135deg, #f59e0b20, #f97316 20, #f59e0b20)",
          borderTop: "2px solid var(--accent-yellow)",
          borderBottom: "2px solid var(--accent-yellow)",
          padding: "10px 16px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 20 }}>
            {current.kind === "login"
              ? "\u{1F511}"
              : current.kind === "captcha"
                ? "\u{1F916}"
                : current.kind === "2fa"
                  ? "\u{1F4F1}"
                  : "\u{270B}"}
          </span>
          <div>
            <div style={{ fontWeight: 600, fontSize: 14, color: "var(--accent-yellow)" }}>
              {kindLabels[current.kind] || "Intervention Required"}
            </div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              {current.message}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <button
            onClick={() => setShowCookieModal(true)}
            style={{
              padding: "6px 14px",
              border: "1px solid var(--accent-yellow)",
              borderRadius: 4,
              background: "transparent",
              color: "var(--accent-yellow)",
              cursor: "pointer",
              fontSize: 13,
              fontWeight: 500,
            }}
          >
            Paste Cookies
          </button>
          <button
            onClick={handleResolve}
            style={{
              padding: "6px 14px",
              border: "none",
              borderRadius: 4,
              background: "var(--accent-green)",
              color: "#fff",
              cursor: "pointer",
              fontSize: 13,
              fontWeight: 500,
            }}
          >
            Resume
          </button>
        </div>
      </div>

      {/* Cookie paste modal */}
      {showCookieModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 999,
          }}
          onClick={() => setShowCookieModal(false)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              padding: 24,
              width: 500,
            }}
          >
            <h3 style={{ marginBottom: 12 }}>Paste Cookies</h3>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 12 }}>
              Format: name=value; name2=value2
            </p>
            <textarea
              value={cookieInput}
              onChange={(e) => setCookieInput(e.target.value)}
              placeholder="session_id=abc123; csrf_token=xyz789"
              style={{
                width: "100%",
                height: 100,
                background: "var(--bg-primary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                color: "var(--text-primary)",
                padding: 8,
                fontFamily: "monospace",
                fontSize: 13,
                resize: "vertical",
              }}
            />
            <div style={{ display: "flex", gap: 8, marginTop: 12, justifyContent: "flex-end" }}>
              <button
                onClick={() => setShowCookieModal(false)}
                style={{
                  padding: "6px 14px",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  background: "transparent",
                  color: "var(--text-secondary)",
                  cursor: "pointer",
                }}
              >
                Cancel
              </button>
              <button
                onClick={handlePasteCookies}
                style={{
                  padding: "6px 14px",
                  border: "none",
                  borderRadius: 4,
                  background: "var(--accent-blue)",
                  color: "#fff",
                  cursor: "pointer",
                }}
              >
                Inject & Resume
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
