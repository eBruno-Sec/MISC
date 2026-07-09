import { useState } from 'react'
import { supabase } from '../lib/supabase'

const CLASSES = [
  { id: 'WARRIOR', icon: '⚔️', name: 'Warrior', desc: 'Master of strength. Push exercises grant +5% bonus EXP.', bonus: 'STR Focus' },
  { id: 'ROGUE',   icon: '🗡️', name: 'Rogue',   desc: 'Swift and precise. Cardio exercises grant +5% bonus EXP.', bonus: 'AGI Focus' },
  { id: 'MAGE',    icon: '🔮', name: 'Mage',    desc: 'Mind over matter. Flexibility & meditation grant +5% bonus EXP.', bonus: 'INT Focus' },
]

export default function Onboarding({ userId, onComplete }) {
  const [step, setStep] = useState(0)
  const [cls, setCls] = useState(null)
  const [form, setForm] = useState({ username: '', height: '', weight: '', age: '', gender: 'Other' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  function set(key, val) { setForm(f => ({ ...f, [key]: val })) }

  async function handleFinish() {
    if (!form.username.trim()) { setError('Enter a hero name'); return }
    setLoading(true)
    setError(null)

    const { data, error: err } = await supabase
      .from('users')
      .insert({
        user_id: userId,
        username: form.username.trim(),
        class_archetype: cls,
        height_cm: parseInt(form.height) || null,
        weight_kg: parseFloat(form.weight) || null,
        age: parseInt(form.age) || null,
        gender: form.gender,
      })
      .select()
      .single()

    if (err) { setError(err.message); setLoading(false); return }

    // Initialise stat row
    await supabase.from('user_stats').insert({ user_id: userId })

    onComplete(data)
  }

  return (
    <div className="onboarding-screen">
      {step === 0 && (
        <>
          <h1 className="pixel-text screen-title">CHOOSE YOUR CLASS</h1>
          <p className="body-text onboard-sub">The Goddess awaits your answer, Hero.</p>
          <div className="class-grid">
            {CLASSES.map(c => (
              <div
                key={c.id}
                className={`class-card ${cls === c.id ? 'selected' : ''}`}
                onClick={() => setCls(c.id)}
              >
                <div className="class-icon">{c.icon}</div>
                <h3 className="pixel-text class-name">{c.name}</h3>
                <p className="body-text class-desc">{c.desc}</p>
                <span className="class-bonus">{c.bonus}</span>
              </div>
            ))}
          </div>
          <button className="rpg-btn primary" disabled={!cls} onClick={() => setStep(1)}>
            CONFIRM CLASS
          </button>
        </>
      )}

      {step === 1 && (
        <>
          <h1 className="pixel-text screen-title">HERO PROFILE</h1>
          <p className="body-text onboard-sub">The Goddess records your baseline stats.</p>
          {error && <p className="msg error">{error}</p>}
          <input className="rpg-input" placeholder="Hero Name *" value={form.username} onChange={e => set('username', e.target.value)} />
          <input className="rpg-input" type="number" placeholder="Height (cm)" value={form.height} onChange={e => set('height', e.target.value)} />
          <input className="rpg-input" type="number" placeholder="Weight (kg)" value={form.weight} onChange={e => set('weight', e.target.value)} />
          <input className="rpg-input" type="number" placeholder="Age" value={form.age} onChange={e => set('age', e.target.value)} />
          <select className="rpg-input" value={form.gender} onChange={e => set('gender', e.target.value)}>
            <option>Male</option>
            <option>Female</option>
            <option>Other</option>
          </select>
          <div className="btn-row">
            <button className="rpg-btn ghost" onClick={() => setStep(0)}>BACK</button>
            <button className="rpg-btn primary" onClick={handleFinish} disabled={loading}>
              {loading ? 'SUMMONING...' : 'BEGIN JOURNEY'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}
