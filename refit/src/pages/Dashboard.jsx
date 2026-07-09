import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { calcLevelFromExp } from '../lib/stats'
import StatBar from '../components/StatBar'

const CLASS_ICON = { WARRIOR: '⚔️', ROGUE: '🗡️', MAGE: '🔮' }

export default function Dashboard({ profile }) {
  const [stats, setStats] = useState(null)

  useEffect(() => {
    supabase
      .from('user_stats')
      .select('*')
      .eq('user_id', profile.user_id)
      .maybeSingle()
      .then(({ data }) => setStats(data ?? {}))
  }, [profile.user_id])

  const { level, remainingExp, expNeeded } = calcLevelFromExp(profile.current_exp ?? 0)
  const expPct = Math.floor((remainingExp / expNeeded) * 100)

  return (
    <div className="page dashboard">
      {/* Hero card */}
      <div className="hero-card">
        <div className="class-badge">
          {CLASS_ICON[profile.class_archetype]} {profile.class_archetype}
        </div>
        <h2 className="pixel-text hero-name">{profile.username}</h2>

        <div className="level-row">
          <span className="pixel-text lv-label">LV {level}</span>
          <div className="exp-track">
            <div className="exp-fill" style={{ width: `${expPct}%` }} />
          </div>
          <span className="body-text exp-nums">{remainingExp}/{expNeeded}</span>
        </div>

        <div className="crystal-row">
          <span>💎</span>
          <span className="pixel-text crystal-count">{profile.gacha_crystals ?? 0} CRYSTALS</span>
        </div>
      </div>

      {/* Attribute panel */}
      {stats && (
        <div className="panel">
          <h3 className="pixel-text panel-title">ATTRIBUTES</h3>
          <StatBar label="STR" value={stats.str_points ?? 0} icon="⚔️" />
          <StatBar label="DEX" value={stats.dex_points ?? 0} icon="🗡️" />
          <StatBar label="AGI" value={stats.agi_points ?? 0} icon="💨" />
          <StatBar label="VIT" value={stats.vit_points ?? 0} icon="🛡️" />
          <StatBar label="INT" value={stats.int_points ?? 0} icon="🔮" />
        </div>
      )}

      {/* Quick actions */}
      <div className="action-grid">
        <Link to="/workout" className="action-card">
          <span className="action-icon">⚔️</span>
          <span className="pixel-text">LOG QUEST</span>
        </Link>
        <Link to="/harem" className="action-card">
          <span className="action-icon">💕</span>
          <span className="pixel-text">COMPANIONS</span>
        </Link>
      </div>
    </div>
  )
}
