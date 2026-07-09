export const STAT_MAP = {
  Push: 'str',
  Pull: 'dex',
  Cardio: 'agi',
  Core: 'vit',
  Flexibility: 'int',
}

export const CLASS_BONUS = {
  WARRIOR: 'Push',
  ROGUE: 'Cardio',
  MAGE: 'Flexibility',
}

// EXP required to advance FROM this level to the next
export function expForLevel(level) {
  if (level <= 10) return level * 50
  return 300 + (level - 10) * 15
}

export function calcLevelFromExp(totalExp) {
  let level = 1
  let remaining = totalExp
  while (level < 200) {
    const needed = expForLevel(level)
    if (remaining < needed) break
    remaining -= needed
    level++
  }
  return { level, remainingExp: remaining, expNeeded: expForLevel(level) }
}

export function calcExpGain(durationMinutes, exerciseType, classArchetype) {
  const base = Math.floor(durationMinutes * 1.5)
  const isBonus = CLASS_BONUS[classArchetype] === exerciseType
  return Math.floor(base * (isBonus ? 1.05 : 1.0))
}

export function calcStatGain(durationMinutes) {
  return Math.max(1, Math.floor(durationMinutes / 10))
}

export function calcCrystals(durationMinutes) {
  return Math.floor(durationMinutes / 60)
}

export function calcCalories(durationMinutes, weightKg, exerciseType) {
  const MET = { Push: 4, Pull: 4, Cardio: 8, Core: 3.5, Flexibility: 2.5 }
  const met = MET[exerciseType] ?? 4
  return Math.floor((met * (weightKg || 70) * durationMinutes) / 60)
}
