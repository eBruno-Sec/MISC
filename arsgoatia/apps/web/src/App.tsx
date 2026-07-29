import React, { useEffect, useState } from "react";

interface HealthStatus {
  status: string;
  service: string;
}

function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    fetch("/api/v1/health")
      .then((r) => (r.ok ? r.json() : null))
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", padding: "2rem" }}>
      <header>
        <h1>ArsGoatia</h1>
        <p style={{ color: "#666" }}>
          Unified Deterministic Autonomous Security Validation Platform
        </p>
      </header>

      <main style={{ marginTop: "2rem" }}>
        <section
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
            gap: "1rem",
          }}
        >
          <DashboardCard title="Engagements" value="--" />
          <DashboardCard title="Active Actions" value="--" />
          <DashboardCard title="Findings" value="--" />
          <DashboardCard title="Evidence Items" value="--" />
        </section>

        <section style={{ marginTop: "2rem" }}>
          <h2>API Status</h2>
          {health ? (
            <p style={{ color: "green" }}>
              Connected: {health.service} ({health.status})
            </p>
          ) : (
            <p style={{ color: "#999" }}>Checking API connection...</p>
          )}
        </section>
      </main>
    </div>
  );
}

function DashboardCard({ title, value }: { title: string; value: string }) {
  return (
    <div
      style={{
        border: "1px solid #e0e0e0",
        borderRadius: "8px",
        padding: "1.5rem",
        textAlign: "center",
      }}
    >
      <div style={{ fontSize: "2rem", fontWeight: 700 }}>{value}</div>
      <div style={{ color: "#666", marginTop: "0.5rem" }}>{title}</div>
    </div>
  );
}

export default App;
