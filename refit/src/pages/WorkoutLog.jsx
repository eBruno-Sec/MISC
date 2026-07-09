import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { calcExpGain, calcStatGain, calcCrystals, calcCalories, calcLevelFromExp, STAT_MAP } from '../lib/stats'
import { generateGachaUrl, rollCompanionName } from '../lib/gacha'
import SummoningCircle from '../components/SummoningCircle'

const TYPES = ['Push', 'Pull', 'Cardio', 'Core', 'Flexibility']

export default function WorkoutLog({ profile, setProfile }) {
  const [exerciseType, setExerciseType] = useState('Push')
  const [duration, setDuration] = useState(30)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [companion, setCompanion] = useState(null)
  const navigate = useNavigate()

  const preview = {
    exp: calcExpGain(duration, exerciseType, profile.class_archetype),
    stat: calcStatGain(duration),
    crystals: calcCrystals(duration),
    cal: calcCalories(duration, profile.weight_kg, exerciseType),
    statKey: STAT_MAP[exerciseType],
  }

  async function handleLog(e) {
    e.preventDefault()
    setLoading(true)

    const newExp = (profile.current_exp ?? 0) + preview.exp
    const newCrystals = (profile.gacha_crystals ?? 0) + preview.crystals
    const { level: newLevel } = calcLevelFromExp(newExp)

    // Log the quest
    await supabase.from('workout_quests').insert({
      user_id: profile.user_id,
      exercise_type: exerciseType,
      duration_minutes: duration,
      calories_burned: preview.cal,
      gacha_crystals_earned: preview.crystals,
    })

    // Update user totals
    const { data: updated } = await supabase
      .from('users')
      .update({ current_exp: newExp, gacha_crystals: newCrystals, current_level: newLevel })
      .eq('user_id', profile.user_id)
      .select()
      .single()

    // Increment specific stat (fetch first to avoid overwriting others)
    const { data: curStats } = await supabase
      .from('user_stats')
      .select('*')
      .eq('user_id', profile.user_id)
      .maybeSingle()

    const col = `${preview.statKey}_points`
    await supabase
      .from('user_stats')
      .update({ [col]: (curStats?.[col] ?? 0) + preview.stat })
      .eq('user_id', profile.user_id)

    setProfile(updated)
    setResult({ ...preview, levelUp: newLevel > calcLevelFromExp(profile.current_exp ?? 0).level })
    setLoading(false)
  }

  async function handleSummon() {
    const imageUrl = generateGachaUrl(exerciseType)
    const name = rollCompanionName(exerciseType)

    const newCrystals = (profile.gacha_crystals ?? 0) - 1
    const { data: updated } = await supabase
      .from('users')
      .update({ gacha_crystals: newCrystals })
      .eq('user_id', profile.user_id)
      .select()
      .single()

    await supabase.from('unlocked_companions').insert({
      user_id: profile.user_id,
      companion_name: name,
      workout_affinity: exerciseType,
      image_storage_url: imageUrl,
    })

    setProfile(updated)
    setCompanion({ name, imageUrl, affinity: exerciseType })
  }

  if (companion) {
    return (
      <SummoningCircle
        companion={companion}
        onComplete={() => { setCompanion(null); navigate('/harem') }}
      />
    )
  }

  return (
    <div className="page workout-log">
      <h2 className="pixel-text screen-title">LOG QUEST</h2>

      {!result ? (
        <form onSubmit={handleLog}>
          <div className="type-grid">
            {TYPES.map(t => (
              <button
                key={t}
                type="button"
                className={`type-btn ${exerciseType === t ? 'active' : ''}`}
                onClick={() => setExerciseType(t)}
              >
                <span className="pixel-text">{t.toUpperCase()}</span>
              </button>
            ))}
          </div>

          <div className="panel duration-panel">
            <label className="pixel-text duration-label">DURATION: {duration} MIN</label>
            <input
              type="range"
              min={5} max={180} step={5}
              value={duration}
              onChange={e => setDuration(Number(e.target.value))}
              className="rpg-slider"
            />
          </div>

          <div className="panel preview-panel">
            <GainRow label="EXP Gain" value={`+${preview.exp}`} gold />
            <GainRow label={`${preview.statKey?.toUpperCase()} Gain`} value={`+${preview.stat}`} gold />
            <GainRow label="Crystals" value={`+${preview.crystals} 💎`} gold={preview.crystals > 0} />
            <GainRow label="Calories" value={`~${preview.cal} kcal`} />
          </div>

          <button className="rpg-btn primary" type="submit" disabled={loading}>
            {loading ? 'RECORDING...' : 'COMPLETE QUEST'}
          </button>
        </form>
      ) : (
        <div className="result-screen">
          {result.levelUp && (
            <div className="level-up-banner pixel-text">⬆ LEVEL UP!</div>
          )}
          <h3 className="pixel-text gold result-title">QUEST COMPLETE!</h3>
          <div className="panel result-panel">
            <GainRow label="EXP Gained"  value={`+${result.exp}`}  gold />
            <GainRow label={`${result.statKey?.toUpperCase()} Gained`} value={`+${result.stat}`} gold />
            <GainRow label="Crystals"    value={`+${result.crystals} 💎`} gold={result.crystals > 0} />
            <GainRow label="Calories"    value={`${result.cal} kcal`} />
          </div>

          {(profile.gacha_crystals ?? 0) > 0 && (
            <button className="rpg-btn summon" onClick={handleSummon}>
              💎 SUMMON COMPANION ({profile.gacha_crystals} crystal{profile.gacha_crystals !== 1 ? 's' : ''})
            </button>
          )}
          <button className="rpg-btn ghost" onClick={() => { setResult(null); navigate('/') }}>
            RETURN TO BASE
          </button>
        </div>
      )}
    </div>
  )
}

function GainRow({ label, value, gold }) {
  return (
    <div className="gain-row">
      <span className="body-text gain-label">{label}</span>
      <span className={`pixel-text gain-val ${gold ? 'gold' : ''}`}>{value}</span>
    </div>
  )
}
