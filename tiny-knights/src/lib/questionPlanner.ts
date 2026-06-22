import type { FactKey, FactState, GameMode, PlannedQuestion, SelectionBucket } from '../types';
import { getAllTables, getCommutativePair } from './facts';
import { getTablesForCoverage, getUnmasteredTables, pickCoverageFactForTable } from './coverageRules';

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function pickQuestionType(bucket: SelectionBucket, rng = Math.random): PlannedQuestion['questionType'] {
  // Multiple choice is reserved as a hint/support fallback, not chosen up front normally.
  if (bucket === 'masteredReview') {
    return rng() < 0.5 ? 'missingFactor' : 'standard';
  }
  if (bucket === 'coverage' || bucket === 'progression') {
    return rng() < 0.3 ? 'missingFactor' : 'standard';
  }
  return rng() < 0.2 ? 'missingFactor' : 'standard';
}

/** Avoid back-to-back duplicate fact keys (and same fact as its commutative pair) */
function dedupeAdjacent(queue: PlannedQuestion[]): PlannedQuestion[] {
  const result: PlannedQuestion[] = [];
  for (const item of queue) {
    if (result.length === 0) {
      result.push(item);
      continue;
    }
    const prev = result[result.length - 1];
    if (prev.factKey === item.factKey) {
      // try to find a later slot to swap with
      let swapped = false;
      for (let j = result.length; j < queue.length; j++) {
        // not used in single pass; fallback below
      }
      // Simplify: push and let later shuffle pass fix, but try inserting one position back if possible
      if (result.length >= 2) {
        const temp = result[result.length - 1];
        result[result.length - 1] = item;
        result.push(temp);
        swapped = true;
      }
      if (!swapped) result.push(item);
    } else {
      result.push(item);
    }
  }
  return result;
}

/**
 * Build a Daily Quest session plan following:
 * 40% weak/missed, 30% progression, 20% mixed unmastered, 10% mastered review
 * plus required coverage of unmastered tables.
 */
export function buildDailyQuestPlan(params: {
  facts: Record<FactKey, FactState>;
  maxFactor: number;
  sessionQuestionCount: number;
  coverageCursor: number;
  now: Date;
}): { plan: PlannedQuestion[]; nextCoverageCursor: number } {
  const { facts, maxFactor, sessionQuestionCount, coverageCursor, now } = params;
  const allFacts = Object.values(facts);

  const unmasteredTables = getUnmasteredTables(facts, maxFactor);
  const { tables: coverageTables, nextCursor } = getTablesForCoverage(
    unmasteredTables,
    sessionQuestionCount,
    coverageCursor
  );

  const plan: PlannedQuestion[] = [];
  const usedKeys = new Set<FactKey>();

  // 1. Coverage facts first
  for (const table of coverageTables) {
    const fact = pickCoverageFactForTable(facts, table, maxFactor, now);
    if (fact && !usedKeys.has(fact.key)) {
      plan.push({ factKey: fact.key, bucket: 'coverage', questionType: pickQuestionType('coverage') });
      usedKeys.add(fact.key);
    }
  }

  const remaining = sessionQuestionCount - plan.length;
  if (remaining <= 0) {
    return { plan: finalizePlan(plan, sessionQuestionCount), nextCoverageCursor: nextCursor };
  }

  // Categorize facts
  const dueOrMissed = allFacts.filter(
    (f) => !usedKeys.has(f.key) && !f.isMastered && (new Date(f.dueAt).getTime() <= now.getTime() || f.lastIncorrectAt)
  );
  const progressionFacts = allFacts.filter(
    (f) => !usedKeys.has(f.key) && !f.isMastered && !dueOrMissed.includes(f)
  );
  const mixedUnmastered = allFacts.filter((f) => !usedKeys.has(f.key) && !f.isMastered);
  const masteredFacts = allFacts.filter((f) => !usedKeys.has(f.key) && f.isMastered);

  const targetWeak = Math.round(remaining * 0.4);
  const targetProgression = Math.round(remaining * 0.3);
  const targetMixed = Math.round(remaining * 0.2);
  const targetMastered = remaining - targetWeak - targetProgression - targetMixed;

  const counts = {
    weak: targetWeak,
    progression: targetProgression,
    mixedUnmastered: targetMixed,
    masteredReview: Math.max(targetMastered, 0),
  };

  function pull(
    pool: FactState[],
    count: number,
    bucket: SelectionBucket,
    sortFn?: (a: FactState, b: FactState) => number
  ): number {
    let added = 0;
    const sorted = sortFn ? [...pool].sort(sortFn) : shuffle(pool);
    for (const fact of sorted) {
      if (added >= count) break;
      if (usedKeys.has(fact.key)) continue;
      plan.push({ factKey: fact.key, bucket, questionType: pickQuestionType(bucket) });
      usedKeys.add(fact.key);
      added++;
    }
    return added;
  }

  let added = 0;
  added += pull(
    dueOrMissed,
    counts.weak,
    'weak',
    (a, b) => (b.lastIncorrectAt ? 1 : 0) - (a.lastIncorrectAt ? 1 : 0) || a.masteryLevel - b.masteryLevel
  );

  added += pull(progressionFacts, counts.progression, 'progression', (a, b) => a.masteryLevel - b.masteryLevel);

  added += pull(mixedUnmastered, counts.mixedUnmastered, 'mixedUnmastered');

  added += pull(masteredFacts, counts.masteredReview, 'masteredReview');

  // Redistribute any shortfall to remaining due/unmastered facts
  let shortfall = remaining - added;
  if (shortfall > 0) {
    const fallbackPool = allFacts.filter((f) => !usedKeys.has(f.key) && !f.isMastered);
    shortfall -= pull(fallbackPool, shortfall, 'mixedUnmastered');
  }
  if (shortfall > 0) {
    const anyPool = allFacts.filter((f) => !usedKeys.has(f.key));
    pull(anyPool, shortfall, 'masteredReview');
  }

  return { plan: finalizePlan(plan, sessionQuestionCount), nextCoverageCursor: nextCursor };
}

function finalizePlan(plan: PlannedQuestion[], targetCount: number): PlannedQuestion[] {
  // Shuffle non-coverage items lightly while keeping coverage spread out
  const coverage = plan.filter((p) => p.bucket === 'coverage');
  const rest = shuffle(plan.filter((p) => p.bucket !== 'coverage'));

  // Interleave coverage items evenly through the rest
  const merged: PlannedQuestion[] = [];
  const gap = coverage.length > 0 ? Math.max(1, Math.floor(rest.length / (coverage.length + 1))) : rest.length;
  let restIdx = 0;
  let covIdx = 0;
  while (restIdx < rest.length || covIdx < coverage.length) {
    for (let i = 0; i < gap && restIdx < rest.length; i++) {
      merged.push(rest[restIdx++]);
    }
    if (covIdx < coverage.length) {
      merged.push(coverage[covIdx++]);
    }
  }

  const deduped = dedupeAdjacent(merged);
  return deduped.slice(0, targetCount);
}

/**
 * Build a Table Trainer plan focused on a single table.
 */
export function buildTableTrainerPlan(params: {
  facts: Record<FactKey, FactState>;
  table: number;
  maxFactor: number;
  sessionQuestionCount: number;
  now: Date;
}): PlannedQuestion[] {
  const { facts, table, maxFactor, sessionQuestionCount } = params;
  const tableFacts = Object.values(facts).filter(
    (f) => (f.a === table || f.b === table) && f.a <= maxFactor && f.b <= maxFactor
  );

  const weak = tableFacts.filter((f) => !f.isMastered).sort((a, b) => a.masteryLevel - b.masteryLevel);
  const mastered = tableFacts.filter((f) => f.isMastered);

  const plan: PlannedQuestion[] = [];

  let pool = shuffle(weak);
  let i = 0;
  while (plan.length < sessionQuestionCount && (pool.length > 0 || mastered.length > 0)) {
    if (i < pool.length) {
      const fact = pool[i];
      plan.push({ factKey: fact.key, bucket: 'progression', questionType: pickQuestionType('progression') });
      i++;
    } else if (mastered.length > 0) {
      const fact = mastered[Math.floor(Math.random() * mastered.length)];
      plan.push({ factKey: fact.key, bucket: 'masteredReview', questionType: pickQuestionType('masteredReview') });
    } else {
      break;
    }
    if (i >= pool.length && weak.length > 0) {
      pool = shuffle(weak);
      i = 0;
    }
  }

  return dedupeAdjacent(plan).slice(0, sessionQuestionCount);
}

/**
 * Build a Boss Battle plan: mixed weak/due facts, with missed facts becoming priority.
 */
export function buildBossBattlePlan(params: {
  facts: Record<FactKey, FactState>;
  maxFactor: number;
  sessionQuestionCount: number;
  priorityFacts: FactKey[];
  now: Date;
}): PlannedQuestion[] {
  const { facts, maxFactor, sessionQuestionCount, priorityFacts, now } = params;
  const allFacts = Object.values(facts).filter((f) => f.a <= maxFactor && f.b <= maxFactor);

  const priority = priorityFacts
    .map((k) => facts[k])
    .filter((f): f is FactState => !!f);

  const weak = allFacts
    .filter((f) => !f.isMastered)
    .sort((a, b) => {
      const aDue = new Date(a.dueAt).getTime() <= now.getTime() ? 0 : 1;
      const bDue = new Date(b.dueAt).getTime() <= now.getTime() ? 0 : 1;
      return aDue - bDue || a.masteryLevel - b.masteryLevel;
    });

  const plan: PlannedQuestion[] = [];
  const usedKeys = new Set<FactKey>();

  for (const fact of priority) {
    if (plan.length >= sessionQuestionCount) break;
    if (usedKeys.has(fact.key)) continue;
    plan.push({ factKey: fact.key, bucket: 'weak', questionType: 'standard' });
    usedKeys.add(fact.key);
  }

  for (const fact of weak) {
    if (plan.length >= sessionQuestionCount) break;
    if (usedKeys.has(fact.key)) continue;
    plan.push({ factKey: fact.key, bucket: 'weak', questionType: pickQuestionType('weak') });
    usedKeys.add(fact.key);
  }

  if (plan.length < sessionQuestionCount) {
    const mastered = shuffle(allFacts.filter((f) => f.isMastered && !usedKeys.has(f.key)));
    for (const fact of mastered) {
      if (plan.length >= sessionQuestionCount) break;
      plan.push({ factKey: fact.key, bucket: 'masteredReview', questionType: pickQuestionType('masteredReview') });
      usedKeys.add(fact.key);
    }
  }

  return dedupeAdjacent(plan).slice(0, sessionQuestionCount);
}

/**
 * Build a Mistake Rescue plan: low pressure practice for recently missed facts, more hints, no timer.
 */
export function buildMistakeRescuePlan(params: {
  facts: Record<FactKey, FactState>;
  maxFactor: number;
  sessionQuestionCount: number;
}): PlannedQuestion[] {
  const { facts, maxFactor, sessionQuestionCount } = params;
  const allFacts = Object.values(facts).filter((f) => f.a <= maxFactor && f.b <= maxFactor);

  const missed = allFacts
    .filter((f) => f.incorrect > 0 && !f.isMastered)
    .sort((a, b) => {
      const aTime = a.lastIncorrectAt ? new Date(a.lastIncorrectAt).getTime() : 0;
      const bTime = b.lastIncorrectAt ? new Date(b.lastIncorrectAt).getTime() : 0;
      return bTime - aTime;
    });

  const weak = allFacts.filter((f) => !f.isMastered && f.masteryLevel <= 1);

  const pool = missed.length > 0 ? missed : weak.length > 0 ? weak : allFacts.filter((f) => !f.isMastered);

  const plan: PlannedQuestion[] = [];
  const usedKeys = new Set<FactKey>();
  let i = 0;
  let cycle = shuffle(pool);
  while (plan.length < sessionQuestionCount && cycle.length > 0) {
    if (i >= cycle.length) {
      cycle = shuffle(pool);
      i = 0;
    }
    const fact = cycle[i++];
    plan.push({ factKey: fact.key, bucket: 'weak', questionType: 'standard' });
    usedKeys.add(fact.key);
  }

  return dedupeAdjacent(plan).slice(0, sessionQuestionCount);
}

/**
 * Insert the commutative pair of a missed fact later in the queue (used after Mistake Rescue
 * style reinforcement). Returns a new plan with the pair inserted a few slots ahead.
 */
export function insertCommutativePair(
  plan: PlannedQuestion[],
  currentIndex: number,
  factKey: FactKey,
  bucket: SelectionBucket
): PlannedQuestion[] {
  const pairKey = getCommutativePair(factKey);
  if (pairKey === factKey) return plan;

  const alreadyQueued = plan.slice(currentIndex + 1).some((p) => p.factKey === pairKey);
  if (alreadyQueued) return plan;

  const insertOffset = Math.min(3, plan.length - currentIndex - 1);
  const insertAt = Math.max(currentIndex + 2, currentIndex + insertOffset);

  const next = [...plan];
  next.splice(Math.min(insertAt, next.length), 0, {
    factKey: pairKey,
    bucket,
    questionType: 'standard',
  });
  return next;
}

/**
 * Re-insert a missed fact later in the queue (not immediately next), except for
 * Mistake Rescue mode which is handled separately.
 */
export function rescheduleMissedFact(
  plan: PlannedQuestion[],
  currentIndex: number,
  factKey: FactKey,
  mode: GameMode
): PlannedQuestion[] {
  if (mode === 'mistakeRescue') return plan;

  const remaining = plan.length - currentIndex - 1;
  if (remaining <= 0) {
    return [...plan, { factKey, bucket: 'weak', questionType: 'standard' }];
  }

  const minGap = Math.min(3, remaining);
  const insertAt = currentIndex + 1 + minGap + Math.floor(Math.random() * Math.max(1, remaining - minGap + 1));

  const next = [...plan];
  next.splice(Math.min(insertAt, next.length), 0, {
    factKey,
    bucket: 'weak',
    questionType: 'standard',
  });
  return next;
}

export { getAllTables };
