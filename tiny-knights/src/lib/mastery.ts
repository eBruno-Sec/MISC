import type { Difficulty, FactState, MasteryLevel } from '../types';

export function clampMastery(level: number): MasteryLevel {
  return Math.max(0, Math.min(5, level)) as MasteryLevel;
}

export function getFastThresholdMs(difficulty: Difficulty): number {
  switch (difficulty) {
    case 'easy':
      return 6000;
    case 'challenge':
      return 3000;
    default:
      return 4000;
  }
}

/**
 * A fact becomes mastered only when all are true:
 * - at least 5 total correct answers
 * - correct in at least 3 separate sessions
 * - current streak at least 3
 * - average response time under the difficulty threshold
 * - no incorrect answer in the current session
 */
export function checkMastered(
  fact: FactState,
  difficulty: Difficulty,
  currentSessionId: string
): boolean {
  if (fact.correct < 5) return false;
  if (fact.correctSessionIds.length < 3) return false;
  if (fact.currentStreak < 3) return false;

  const threshold = getFastThresholdMs(difficulty);
  if (fact.averageResponseMs === null || fact.averageResponseMs > threshold) return false;

  const incorrectThisSession =
    fact.lastIncorrectAt !== null &&
    fact.lastSeenAt !== null &&
    fact.correctSessionIds.includes(currentSessionId) &&
    fact.lastIncorrectAt === fact.lastSeenAt;

  // If the most recent incorrect happened in this session and the streak was reset,
  // currentStreak < 3 would already have caught it. This extra guard covers edge
  // cases where lastIncorrectAt is from the current session but streak rebuilt fast.
  if (incorrectThisSession) return false;

  return true;
}

export function getMasteryLabel(level: MasteryLevel): string {
  const labels: Record<MasteryLevel, string> = {
    0: 'New',
    1: 'Learning',
    2: 'Practicing',
    3: 'Improving',
    4: 'Strong',
    5: 'Mastered',
  };
  return labels[level];
}

export function getMasteryColor(level: MasteryLevel): string {
  const colors: Record<MasteryLevel, string> = {
    0: 'bg-gray-300',
    1: 'bg-red-300',
    2: 'bg-orange-300',
    3: 'bg-yellow-300',
    4: 'bg-lime-300',
    5: 'bg-green-400',
  };
  return colors[level];
}
