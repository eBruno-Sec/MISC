import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import CompanionCard from '../components/CompanionCard'

export default function Harem({ profile }) {
  const [companions, setCompanions] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    supabase
      .from('unlocked_companions')
      .select('*')
      .eq('user_id', profile.user_id)
      .order('unlocked_at', { ascending: false })
      .then(({ data }) => { setCompanions(data ?? []); setLoading(false) })
  }, [profile.user_id])

  if (loading) {
    return (
      <div className="page loading-screen">
        <span className="pixel-text">LOADING...</span>
      </div>
    )
  }

  return (
    <div className="page harem-page">
      <h2 className="pixel-text screen-title">COMPANIONS</h2>
      <p className="body-text harem-count">{companions.length} summoned</p>

      {companions.length === 0 ? (
        <div className="empty-state">
          <p className="pixel-text">No companions yet.</p>
          <p className="body-text">Complete a 60+ min quest to earn a Summoning Crystal, then tap Summon.</p>
        </div>
      ) : (
        <div className="companion-grid">
          {companions.map(c => <CompanionCard key={c.companion_id} companion={c} />)}
        </div>
      )}
    </div>
  )
}
