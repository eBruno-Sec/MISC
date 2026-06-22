import type { Monster } from '../types';

export const MONSTERS: Monster[] = [
  { id: 'sprout', name: 'Sprout Slime', emoji: '🟢', table: 1, hpMultiplier: 1 },
  { id: 'twigling', name: 'Twigling', emoji: '🌱', table: 1, hpMultiplier: 1 },
  { id: 'leafbat', name: 'Leaf Bat', emoji: '🦇', table: 2, hpMultiplier: 1 },
  { id: 'mossy', name: 'Mossy Hopper', emoji: '🐸', table: 2, hpMultiplier: 1 },
  { id: 'rockling', name: 'Rockling', emoji: '🪨', table: 3, hpMultiplier: 1.1 },
  { id: 'batling', name: 'Cave Batling', emoji: '🦇', table: 3, hpMultiplier: 1.1 },
  { id: 'pebblet', name: 'Pebblet', emoji: '🧱', table: 4, hpMultiplier: 1.1 },
  { id: 'stoneeye', name: 'Stone Eye', emoji: '👁️', table: 4, hpMultiplier: 1.1 },
  { id: 'tickton', name: 'Tickton', emoji: '🕐', table: 5, hpMultiplier: 1.2 },
  { id: 'chronoth', name: 'Chronoth', emoji: '⏰', table: 5, hpMultiplier: 1.2 },
  { id: 'gearbot', name: 'Gearbot', emoji: '⚙️', table: 6, hpMultiplier: 1.2 },
  { id: 'cogling', name: 'Cogling', emoji: '🔧', table: 6, hpMultiplier: 1.2 },
  { id: 'drakeling', name: 'Drakeling', emoji: '🐲', table: 7, hpMultiplier: 1.3 },
  { id: 'wyrmlet', name: 'Wyrmlet', emoji: '🐉', table: 7, hpMultiplier: 1.3 },
  { id: 'crystalbug', name: 'Crystal Bug', emoji: '💎', table: 8, hpMultiplier: 1.3 },
  { id: 'gemling', name: 'Gemling', emoji: '🔮', table: 8, hpMultiplier: 1.3 },
  { id: 'shadowkit', name: 'Shadow Kit', emoji: '🥷', table: 9, hpMultiplier: 1.4 },
  { id: 'ninjroach', name: 'Ninjroach', emoji: '🪲', table: 9, hpMultiplier: 1.4 },
  { id: 'gateguard', name: 'Gate Guard', emoji: '🏰', table: 10, hpMultiplier: 1.4 },
  { id: 'towerbot', name: 'Towerbot', emoji: '🗼', table: 10, hpMultiplier: 1.4 },
  { id: 'champknight', name: 'Champ Knight', emoji: '🏆', table: 11, hpMultiplier: 1.5 },
  { id: 'starbeast', name: 'Star Beast', emoji: '⭐', table: 12, hpMultiplier: 1.5 },
  { id: 'finalboss', name: 'Arena Champion', emoji: '🐲', table: 0, hpMultiplier: 2 },
];

export const BOSSES: Monster[] = [
  { id: 'boss-meadow', name: 'Meadow Brute', emoji: '🐗', table: 3, hpMultiplier: 1, difficultyLabel: 'Easy', unlockTable: 3 },
  { id: 'boss-forest', name: 'Forest Warden', emoji: '🐻', table: 6, hpMultiplier: 1.25, difficultyLabel: 'Medium', unlockTable: 6 },
  { id: 'boss-cave', name: 'Cave Wyrm', emoji: '🐍', table: 9, hpMultiplier: 1.5, difficultyLabel: 'Hard', unlockTable: 9 },
  { id: 'boss-castle', name: 'Castle Guardian', emoji: '🗿', table: 10, hpMultiplier: 1.75, difficultyLabel: 'Hard', unlockTable: 10 },
  { id: 'finalboss', name: 'Arena Champion', emoji: '🐲', table: 0, hpMultiplier: 2, difficultyLabel: 'Champion', unlockTable: 12 },
];

export function getBosses(maxFactor: number): Monster[] {
  return BOSSES.filter((b) => (b.unlockTable ?? 0) <= maxFactor);
}

export function getBossById(id: string): Monster | undefined {
  return BOSSES.find((b) => b.id === id);
}

export function getMonsterForTable(table: number): Monster {
  const candidates = MONSTERS.filter((m) => m.table === table);
  if (candidates.length === 0) {
    return MONSTERS[Math.floor(Math.random() * (MONSTERS.length - 1))];
  }
  return candidates[Math.floor(Math.random() * candidates.length)];
}

export function getBossMonster(bossId?: string): Monster {
  if (bossId) {
    const found = BOSSES.find((m) => m.id === bossId);
    if (found) return found;
  }
  return BOSSES.find((m) => m.id === 'finalboss')!;
}
