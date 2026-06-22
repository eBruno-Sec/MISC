import type { CosmeticUnlock } from '../types';

export const COSMETIC_DEFINITIONS: Omit<CosmeticUnlock, 'unlockedAt'>[] = [
  { id: 'sword-wood', name: 'Wooden Sword', type: 'sword', icon: '🗡️' },
  { id: 'sword-iron', name: 'Iron Sword', type: 'sword', icon: '⚔️' },
  { id: 'sword-gold', name: 'Golden Sword', type: 'sword', icon: '🏵️' },
  { id: 'shield-wood', name: 'Wooden Shield', type: 'shield', icon: '🛡️' },
  { id: 'shield-iron', name: 'Iron Shield', type: 'shield', icon: '🔰' },
  { id: 'helmet-leather', name: 'Leather Cap', type: 'helmet', icon: '🧢' },
  { id: 'helmet-iron', name: 'Iron Helmet', type: 'helmet', icon: '🪖' },
  { id: 'helmet-gold', name: 'Golden Crown', type: 'helmet', icon: '👑' },
];

export function createDefaultCosmetics(): CosmeticUnlock[] {
  return COSMETIC_DEFINITIONS.map((c, i) => ({
    ...c,
    unlockedAt: i === 0 ? new Date(0).toISOString() : null,
  }));
}

export function getUnlockThresholdForLevel(level: number): string | null {
  const map: Record<number, string> = {
    2: 'sword-iron',
    3: 'shield-wood',
    4: 'helmet-leather',
    6: 'shield-iron',
    8: 'helmet-iron',
    10: 'sword-gold',
    12: 'helmet-gold',
  };
  return map[level] ?? null;
}
