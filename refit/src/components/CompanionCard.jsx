export default function CompanionCard({ companion }) {
  return (
    <div className="companion-card">
      <div className="companion-img-wrap">
        <img
          src={companion.image_storage_url}
          alt={companion.companion_name}
          className="companion-img"
          loading="lazy"
        />
      </div>
      <div className="companion-info">
        <span className="pixel-text companion-name">{companion.companion_name}</span>
        <span className="affinity-badge">{companion.workout_affinity}</span>
        <span className="body-text companion-affinity-lv">Affinity Lv.{companion.affinity_level}</span>
      </div>
    </div>
  )
}
