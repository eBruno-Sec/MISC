const STYLE_PRESET =
  'masterpiece character art, high quality 2d anime gacha game style, vibrant colors, clean background, standalone character portrait, full body'

const GEAR_THEMES = {
  Push: 'knight armor, silver breastplate, massive runic sword, athletic build, confident heroic pose',
  Pull: 'rogue leather armor, dual glowing daggers, shadow aura, toned physique, dynamic action pose',
  Cardio: 'beastkin scout costume, animal ears, agile posture, wind motion blur effects, energetic stance',
  Core: 'ice mage robes, magical crystal staff, frost particle effects, powerful sorceress pose',
  Flexibility: 'celestial dancer outfit, flowing ethereal robes, radiant aura, graceful elegant pose',
}

const COMPANION_NAMES = {
  Push: ['Valeria', 'Seraphina', 'Astrid', 'Brunhilde', 'Cassandra'],
  Pull: ['Kira', 'Nyx', 'Shade', 'Vespera', 'Lyra'],
  Cardio: ['Zephyra', 'Nimue', 'Swiftpaw', 'Aura', 'Fen'],
  Core: ['Crysta', 'Isolde', 'Glaciara', 'Veil', 'Arctis'],
  Flexibility: ['Lumina', 'Celestia', 'Aethon', 'Solara', 'Mirabel'],
}

export function generateGachaUrl(workoutType) {
  const seed = Math.floor(Math.random() * 9_999_999)
  const theme = GEAR_THEMES[workoutType] ?? GEAR_THEMES.Push
  const prompt = `${STYLE_PRESET}, beautiful anime female character, ${theme}`
  return `https://image.pollinations.ai/prompt/${encodeURIComponent(prompt)}?width=768&height=768&seed=${seed}&nologo=true`
}

export function rollCompanionName(workoutType) {
  const pool = COMPANION_NAMES[workoutType] ?? COMPANION_NAMES.Push
  return pool[Math.floor(Math.random() * pool.length)]
}
