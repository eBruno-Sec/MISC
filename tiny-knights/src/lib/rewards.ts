import type { Badge, FactKey, GameMode, QuestCompletion, UserProgress } from '../types';
import { isTableMastered } from './facts';
import { getWorldForTable } from '../data/worlds';
import { getUnlockThresholdForLevel } from '../data/cosmetics';
import { getBossById } from '../data/monsters';

export const XP_PER_LEVEL = 100;

export function getLevelFromXp(xp: number): number {
  return Math.floor(xp / XP_PER_LEVEL) + 1;
}

export function getXpIntoLevel(xp: number): { current: number; needed: number } {
  const current = xp % XP_PER_LEVEL;
  return { current, needed: XP_PER_LEVEL };
}

export function calculateXpForAnswer(isCorrect: boolean, wasFast: boolean, bucket: string): number {
  if (!isCorrect) return 0;
  let xp = 5;
  if (wasFast) xp += 3;
  if (bucket === 'weak') xp += 2;
  if (bucket === 'coverage') xp += 1;
  return xp;
}

export function calculateCoinsForAnswer(isCorrect: boolean, wasFast: boolean): number {
  if (!isCorrect) return 0;
  return wasFast ? 2 : 1;
}

export function checkAndAwardBadges(
  progress: UserProgress,
  mode: GameMode,
  sessionMissedCount: number,
  sessionFactsMastered: FactKey[],
  bossWon: boolean,
  practicedTablesThisSession: Set<number>,
  sessionCompleted = true
): { badges: Badge[]; newlyEarned: Badge[] } {
  const now = new Date().toISOString();
  const badges = progress.badges.map((b) => ({ ...b }));
  const newlyEarned: Badge[] = [];

  function award(id: string) {
    const badge = badges.find((b) => b.id === id);
    if (badge && !badge.earnedAt) {
      badge.earnedAt = now;
      newlyEarned.push(badge);
    }
  }

  // Table mastery badges
  const tableBadgeMap: Record<number, string> = {
    1: 'badge-1s-hero',
    2: 'badge-2s-hero',
    3: 'badge-3s-hero',
    4: 'badge-4s-hero',
    5: 'badge-5s-clock-master',
    6: 'badge-6s-hero',
    7: 'badge-7s-dragon-tamer',
    8: 'badge-8s-hero',
    9: 'badge-9s-ninja',
    10: 'badge-10s-hero',
    11: 'badge-11s-hero',
    12: 'badge-12s-hero',
  };

  for (let table = 1; table <= progress.maxFactor; table++) {
    if (isTableMastered(progress.facts, table, progress.maxFactor)) {
      const badgeId = tableBadgeMap[table];
      if (badgeId) award(badgeId);
    }
  }

  // Requires a finished session, otherwise quitting after one answer earns it
  if (sessionCompleted && sessionMissedCount === 0) award('badge-no-mistake');
  if (sessionFactsMastered.length > 0) award('badge-comeback');
  if (progress.dailyStreak >= 7) award('badge-7-day-streak');
  if (mode === 'bossBattle' && bossWon) award('badge-boss-slayer');

  const allTablesPracticed = Array.from({ length: progress.maxFactor }, (_, i) => i + 1).every((t) =>
    practicedTablesThisSession.has(t)
  );
  if (allTablesPracticed) award('badge-all-tables');

  return { badges, newlyEarned };
}

export function checkCosmeticUnlocks(progress: UserProgress, newLevel: number): {
  cosmetics: typeof progress.cosmetics;
  newlyUnlocked: typeof progress.cosmetics;
} {
  const cosmetics = progress.cosmetics.map((c) => ({ ...c }));
  const newlyUnlocked: typeof progress.cosmetics = [];

  for (let lvl = 2; lvl <= newLevel; lvl++) {
    const cosmeticId = getUnlockThresholdForLevel(lvl);
    if (cosmeticId) {
      const item = cosmetics.find((c) => c.id === cosmeticId);
      if (item && !item.unlockedAt) {
        item.unlockedAt = new Date().toISOString();
        newlyUnlocked.push(item);
      }
    }
  }

  return { cosmetics, newlyUnlocked };
}

export function getDailyQuestSuggestions(
  weakFactsCount: number,
  recommendedTable: number | null
): string[] {
  const suggestions: string[] = ['Defeat 10 monsters'];
  if (weakFactsCount > 0) suggestions.push('Clear 5 weak facts');
  suggestions.push('Practice every table once');
  if (recommendedTable) {
    const world = getWorldForTable(recommendedTable);
    suggestions.push(`Explore ${world.name}`);
  }
  return suggestions;
}

export function getQuestId(mode: GameMode, table?: number, bossId?: string): string {
  if (mode === 'tableTrainer' && table) return `tableTrainer-${table}`;
  if (mode === 'bossBattle' && bossId) return `bossBattle-${bossId}`;
  return mode;
}

export function getQuestName(mode: GameMode, table?: number, bossId?: string): string {
  switch (mode) {
    case 'dailyQuest':
      return 'Daily Quest';
    case 'tableTrainer':
      return table ? `Table Trainer: ${table}s` : 'Table Trainer';
    case 'bossBattle': {
      if (bossId) {
        const boss = getBossById(bossId);
        if (boss) return `Boss Battle: ${boss.name}`;
      }
      return 'Boss Battle';
    }
    case 'mistakeRescue':
      return 'Mistake Rescue';
    case 'speedRound':
      return 'Speed Round';
    default:
      return mode;
  }
}

export function recordQuestCompletion(
  progress: UserProgress,
  mode: GameMode,
  table: number | undefined,
  accuracy: number,
  streak: number,
  stars: number,
  bossId?: string
): Record<string, QuestCompletion> {
  const questId = getQuestId(mode, table, bossId);
  const existing = progress.questCompletions[questId];
  const now = new Date().toISOString();

  const updated: QuestCompletion = existing
    ? {
        ...existing,
        timesCompleted: existing.timesCompleted + 1,
        bestAccuracy: Math.max(existing.bestAccuracy, accuracy),
        bestStreak: Math.max(existing.bestStreak, streak),
        lastCompletedAt: now,
        starsEarned: Math.max(existing.starsEarned, stars),
      }
    : {
        questId,
        mode,
        table,
        bossId,
        timesCompleted: 1,
        bestAccuracy: accuracy,
        bestStreak: streak,
        lastCompletedAt: now,
        starsEarned: stars,
      };

  return { ...progress.questCompletions, [questId]: updated };
}
