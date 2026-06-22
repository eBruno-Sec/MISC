import type { FactKey, FactState } from '../types';

export function makeFactKey(a: number, b: number): FactKey {
  return `${a}x${b}` as FactKey;
}

export function createInitialFact(a: number, b: number): FactState {
  return {
    key: makeFactKey(a, b),
    a,
    b,
    answer: a * b,
    attempts: 0,
    correct: 0,
    incorrect: 0,
    currentStreak: 0,
    bestStreak: 0,
    responseMsTotal: 0,
    averageResponseMs: null,
    lastResponseMs: null,
    masteryLevel: 0,
    dueAt: new Date(0).toISOString(),
    lastSeenAt: null,
    lastIncorrectAt: null,
    correctSessionIds: [],
    isMastered: false,
  };
}

export function generateFacts(maxFactor: 10 | 12): Record<FactKey, FactState> {
  const facts: Record<FactKey, FactState> = {};
  for (let a = 1; a <= maxFactor; a++) {
    for (let b = 1; b <= maxFactor; b++) {
      const key = makeFactKey(a, b);
      facts[key] = createInitialFact(a, b);
    }
  }
  return facts;
}

/** Extend an existing facts map to a new max factor without wiping existing progress */
export function extendFacts(
  existing: Record<FactKey, FactState>,
  maxFactor: 10 | 12
): Record<FactKey, FactState> {
  const next: Record<FactKey, FactState> = { ...existing };
  for (let a = 1; a <= maxFactor; a++) {
    for (let b = 1; b <= maxFactor; b++) {
      const key = makeFactKey(a, b);
      if (!next[key]) {
        next[key] = createInitialFact(a, b);
      }
    }
  }
  return next;
}

export function getCommutativePair(key: FactKey): FactKey {
  const fact = parseFactKey(key);
  return makeFactKey(fact.b, fact.a);
}

export function parseFactKey(key: FactKey): { a: number; b: number } {
  const [a, b] = key.split('x').map(Number);
  return { a, b };
}

export function getFactsForTable(
  facts: Record<FactKey, FactState>,
  table: number,
  maxFactor: number
): FactState[] {
  const result: FactState[] = [];
  for (let b = 1; b <= maxFactor; b++) {
    const key = makeFactKey(table, b);
    if (facts[key]) result.push(facts[key]);
  }
  return result;
}

export function getAllTables(maxFactor: number): number[] {
  const tables: number[] = [];
  for (let i = 1; i <= maxFactor; i++) tables.push(i);
  return tables;
}

export function isTableMastered(
  facts: Record<FactKey, FactState>,
  table: number,
  maxFactor: number
): boolean {
  const tableFacts = getFactsForTable(facts, table, maxFactor);
  return tableFacts.length > 0 && tableFacts.every((f) => f.isMastered);
}

export function getOverallMasteryPercent(facts: Record<FactKey, FactState>): number {
  const all = Object.values(facts);
  if (all.length === 0) return 0;
  const mastered = all.filter((f) => f.isMastered).length;
  return Math.round((mastered / all.length) * 100);
}
