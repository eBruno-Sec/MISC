import type { World } from '../types';

export const WORLDS: World[] = [
  { id: 1, name: 'Training Meadow', emoji: '🌿', table: 1 },
  { id: 2, name: 'Double Forest', emoji: '🌳', table: 2 },
  { id: 3, name: 'Triple Caves', emoji: '🪨', table: 3 },
  { id: 4, name: 'Stone Path', emoji: '🧱', table: 4 },
  { id: 5, name: 'Clock Tower', emoji: '🕐', table: 5 },
  { id: 6, name: 'Gear Factory', emoji: '⚙️', table: 6 },
  { id: 7, name: 'Dragon Ridge', emoji: '🐉', table: 7 },
  { id: 8, name: 'Crystal Mines', emoji: '💎', table: 8 },
  { id: 9, name: 'Ninja Temple', emoji: '🥷', table: 9 },
  { id: 10, name: 'Castle Gate', emoji: '🏰', table: 10 },
  { id: 11, name: 'Champion Zone', emoji: '🏆', table: 11 },
  { id: 12, name: 'Champion Zone II', emoji: '⭐', table: 12 },
  { id: 'mixed', name: 'Final Arena', emoji: '🛡️', table: null },
];

export function getWorldForTable(table: number): World {
  return WORLDS.find((w) => w.table === table) ?? WORLDS[WORLDS.length - 1];
}
