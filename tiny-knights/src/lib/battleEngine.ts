import type { GameMode, Monster } from '../types';
import { getMonsterForTable, getBossMonster } from '../data/monsters';

export const BASE_MONSTER_HP = 3;
export const BOSS_BASE_HP = 8;
export const KNIGHT_BASE_ENERGY = 5;

export function getMonsterMaxHp(monster: Monster, mode: GameMode): number {
  const base = mode === 'bossBattle' ? BOSS_BASE_HP : BASE_MONSTER_HP;
  return Math.round(base * monster.hpMultiplier);
}

export function spawnMonster(table: number | null, mode: GameMode, bossId?: string): Monster {
  if (mode === 'bossBattle' || table === null) {
    return getBossMonster(bossId);
  }
  return getMonsterForTable(table);
}

/** Damage dealt to monster on a correct answer */
export function getAttackDamage(wasFast: boolean, mode?: GameMode): number {
  if (mode === 'bossBattle') return 1;
  return wasFast ? 2 : 1;
}

/** Energy lost by knight on a wrong answer (shield absorbs most of it) */
export function getBlockEnergyLoss(): number {
  return 1;
}

export function clampHp(hp: number, max: number): number {
  return Math.max(0, Math.min(max, hp));
}
