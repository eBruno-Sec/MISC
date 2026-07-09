export default function StatBar({ label, value, icon }) {
  const pct = Math.min((value / 500) * 100, 100)

  return (
    <div className="stat-row">
      <span className="stat-icon">{icon}</span>
      <span className="pixel-text stat-label">{label}</span>
      <div className="stat-bar-bg">
        <div className="stat-bar-fill" style={{ width: `${pct}%` }} />
      </div>
      <span className="pixel-text stat-value">{value}</span>
    </div>
  )
}
