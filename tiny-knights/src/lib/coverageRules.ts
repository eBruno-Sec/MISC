import type { FactKey, FactState } from '../types';
import { getAllTables, getFactsForTable, isTableMastered } from './facts';

/**
 * Returns tables that are not yet fully mastered, in ascending order.
 */
export function getUnmasteredTables(facts: Record<FactKey, FactState>, maxFactor: number): number[] {
  return getAllTables(maxFactor).filter((t) => !isTableMastered(facts, t, maxFactor));
}

/**
 * Pick one representative fact from a table to guarantee coverage.
 * Prefers facts that are due or have low mastery.
 */
export function pickCoverageFactForTable(
  facts: Record<FactKey, FactState>,
  table: number,
  maxFactor: number,
  now: Date
): FactState | null {
  const tableFacts = getFactsForTable(facts, table, maxFactor).filter((f) => !f.isMastered);
  if (tableFacts.length === 0) {
    const all = getFactsForTable(facts, table, maxFactor);
    return all.length > 0 ? all[Math.floor(Math.random() * all.length)] : null;
  }

  const due = tableFacts.filter((f) => new Date(f.dueAt).getTime() <= now.getTime());
  const pool = due.length > 0 ? due : tableFacts;
  pool.sort((a, b) => a.masteryLevel - b.masteryLevel);
  return pool[0];
}

/**
 * Determines which tables need coverage this session, rotating using coverageCursor
 * so every table eventually appears if the session is too short for full coverage.
 */
export function getTablesForCoverage(
  unmasteredTables: number[],
  sessionQuestionCount: number,
  coverageCursor: number
): { tables: number[]; nextCursor: number } {
  if (unmasteredTables.length === 0) {
    return { tables: [], nextCursor: coverageCursor };
  }

  if (sessionQuestionCount >= unmasteredTables.length) {
    return { tables: [...unmasteredTables], nextCursor: coverageCursor };
  }

  // Rotate through tables using the cursor
  const tables: number[] = [];
  let cursor = coverageCursor % unmasteredTables.length;
  const coverageSlots = Math.max(1, Math.floor(sessionQuestionCount * 0.3));

  for (let i = 0; i < coverageSlots; i++) {
    tables.push(unmasteredTables[cursor]);
    cursor = (cursor + 1) % unmasteredTables.length;
  }

  return { tables, nextCursor: cursor };
}
