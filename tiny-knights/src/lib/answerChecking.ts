import type { Difficulty, FactState } from '../types';
import { checkMastered, clampMastery, getFastThresholdMs } from './mastery';
import { calculateNextDueAt } from './spacedRepetition';

export function checkAnswer(userAnswer: number, correctAnswer: number): boolean {
  return Number.isFinite(userAnswer) && userAnswer === correctAnswer;
}

export function updateFactAfterAnswer(params: {
  fact: FactState;
  isCorrect: boolean;
  responseMs: number;
  sessionId: string;
  difficulty: Difficulty;
  now: Date;
}): FactState {
  const { fact, isCorrect, responseMs, sessionId, difficulty, now } = params;
  const fastThreshold = getFastThresholdMs(difficulty);
  const wasFast = responseMs <= fastThreshold;

  const updated: FactState = { ...fact };
  updated.attempts += 1;
  updated.lastSeenAt = now.toISOString();
  updated.lastResponseMs = responseMs;
  updated.responseMsTotal += responseMs;
  updated.averageResponseMs = updated.responseMsTotal / updated.attempts;

  if (isCorrect) {
    updated.correct += 1;
    updated.currentStreak += 1;
    updated.bestStreak = Math.max(updated.bestStreak, updated.currentStreak);
    if (!updated.correctSessionIds.includes(sessionId)) {
      // mastery only needs 3 distinct sessions; cap the list so storage stays small
      updated.correctSessionIds = [...updated.correctSessionIds, sessionId].slice(-10);
    }
    if (wasFast) updated.masteryLevel = clampMastery(updated.masteryLevel + 1);
  } else {
    updated.incorrect += 1;
    updated.currentStreak = 0;
    updated.lastIncorrectAt = now.toISOString();
    updated.masteryLevel = clampMastery(updated.masteryLevel - 1);
  }

  updated.isMastered = checkMastered(updated, difficulty, sessionId);
  updated.dueAt = calculateNextDueAt(updated, isCorrect, wasFast, now).toISOString();
  return updated;
}

/** Returns feedback tier based on correctness and response time */
export function getFeedbackTier(
  isCorrect: boolean,
  responseMs: number,
  difficulty: Difficulty
): 'correct-fast' | 'correct-slow' | 'incorrect' {
  if (!isCorrect) return 'incorrect';
  const threshold = getFastThresholdMs(difficulty);
  return responseMs <= threshold ? 'correct-fast' : 'correct-slow';
}

const ENCOURAGEMENT_CORRECT_FAST = [
  'Nice recall!',
  'Lightning fast!',
  'Sharp swing!',
  'Knight strike!',
  'Boom! Got it!',
];

const ENCOURAGEMENT_CORRECT_SLOW = [
  "You're getting faster.",
  'Got it! Keep going.',
  'Nice work, knight!',
  'Solid hit!',
];

const ENCOURAGEMENT_INCORRECT = [
  "Almost. Let's try that one again soon.",
  'Good try! The shield blocked that one.',
  "So close! Let's give it another go later.",
  'Nice effort, knight. One more try coming up.',
];

export function getRandomFeedback(tier: 'correct-fast' | 'correct-slow' | 'incorrect'): string {
  const pool =
    tier === 'correct-fast'
      ? ENCOURAGEMENT_CORRECT_FAST
      : tier === 'correct-slow'
      ? ENCOURAGEMENT_CORRECT_SLOW
      : ENCOURAGEMENT_INCORRECT;
  return pool[Math.floor(Math.random() * pool.length)];
}
