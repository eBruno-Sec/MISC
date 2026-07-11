import type { UserProgress } from '../types';
import { generateFacts, extendFacts } from './facts';
import { createDefaultBadges } from '../data/badges';
import { createDefaultCosmetics } from '../data/cosmetics';

export const STORAGE_KEY = 'tiny-knights-progress-v1';
const STORAGE_VERSION = 1;

type StoredEnvelope = {
  version: number;
  data: UserProgress;
};

export function createDefaultProgress(): UserProgress {
  return {
    childName: 'Knight',
    avatarId: 'knight-blue',
    maxFactor: 10,
    xp: 0,
    coins: 0,
    dailyStreak: 0,
    lastPlayedDate: null,
    coverageCursor: 0,
    facts: generateFacts(10),
    sessions: [],
    badges: createDefaultBadges(),
    cosmetics: createDefaultCosmetics(),
    monsterBook: [],
    questCompletions: {},
    settings: {
      sessionQuestionCount: 12,
      maxFactor: 10,
      timedModeEnabled: false,
      soundEnabled: true,
      reducedMotion: false,
      darkMode: false,
      difficulty: 'normal',
    },
  };
}

function isValidProgress(data: unknown): data is UserProgress {
  if (!data || typeof data !== 'object') return false;
  const d = data as Record<string, unknown>;
  return (
    typeof d.xp === 'number' &&
    typeof d.coins === 'number' &&
    typeof d.facts === 'object' &&
    d.facts !== null &&
    typeof d.settings === 'object' &&
    d.settings !== null
  );
}

export function loadProgress(): UserProgress {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return createDefaultProgress();

    const parsed = JSON.parse(raw) as StoredEnvelope | UserProgress;

    // Handle envelope or raw-shape fallback
    const data: unknown =
      typeof parsed === 'object' && parsed !== null && 'version' in parsed && 'data' in parsed
        ? (parsed as StoredEnvelope).data
        : parsed;

    if (!isValidProgress(data)) {
      return createDefaultProgress();
    }

    const progress = migrateProgress(data);
    return progress;
  } catch {
    return createDefaultProgress();
  }
}

function migrateProgress(data: UserProgress): UserProgress {
  const defaults = createDefaultProgress();

  const maxFactor = data.maxFactor === 12 ? 12 : 10;
  const facts = extendFacts(data.facts ?? {}, maxFactor);

  // Trim unbounded lists written by earlier versions
  for (const key of Object.keys(facts) as (keyof typeof facts)[]) {
    const fact = facts[key];
    if (fact.correctSessionIds.length > 10) {
      facts[key] = { ...fact, correctSessionIds: fact.correctSessionIds.slice(-10) };
    }
  }

  return {
    ...defaults,
    ...data,
    maxFactor,
    facts,
    settings: { ...defaults.settings, ...(data.settings ?? {}) },
    badges: data.badges && data.badges.length > 0 ? data.badges : defaults.badges,
    cosmetics: data.cosmetics && data.cosmetics.length > 0 ? data.cosmetics : defaults.cosmetics,
    monsterBook: data.monsterBook ?? [],
    sessions: (data.sessions ?? []).slice(-50),
    questCompletions: data.questCompletions ?? {},
  };
}

export function saveProgress(progress: UserProgress): void {
  try {
    const envelope: StoredEnvelope = { version: STORAGE_VERSION, data: progress };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
  } catch {
    // Storage full or unavailable; fail silently to avoid breaking gameplay
  }
}

export function resetProgress(): UserProgress {
  const fresh = createDefaultProgress();
  saveProgress(fresh);
  return fresh;
}
