import type { MasteryLevel } from '../types';

export const intervalsByMasterySeconds: Record<MasteryLevel, number> = {
  0: 0,
  1: 10 * 60,
  2: 24 * 60 * 60,
  3: 3 * 24 * 60 * 60,
  4: 7 * 24 * 60 * 60,
  5: 14 * 24 * 60 * 60,
};

const SOON_RETRY_SECONDS = 60;

/**
 * - Correct + fast: increase mastery by 1, schedule farther out.
 * - Correct + slow: keep mastery stable (or +1 only on a strong streak), schedule sooner.
 * - Wrong: decrease mastery by 1, schedule soon, add to session retry queue.
 */
export function calculateNextDueAt(
  updated: { masteryLevel: MasteryLevel; currentStreak: number },
  isCorrect: boolean,
  wasFast: boolean,
  now: Date
): Date {
  if (!isCorrect) {
    return new Date(now.getTime() + SOON_RETRY_SECONDS * 1000);
  }

  if (wasFast) {
    const seconds = intervalsByMasterySeconds[updated.masteryLevel];
    return new Date(now.getTime() + Math.max(seconds, 30) * 1000);
  }

  // correct but slow: schedule sooner than the full interval for the level
  const level = updated.masteryLevel;
  const baseSeconds = intervalsByMasterySeconds[level];
  const soonerSeconds = updated.currentStreak >= 4 ? baseSeconds : Math.max(baseSeconds / 3, 60);
  return new Date(now.getTime() + soonerSeconds * 1000);
}

export function isDue(dueAtIso: string, now: Date): boolean {
  return new Date(dueAtIso).getTime() <= now.getTime();
}
