// Backup engine. Implements the JSON backup specification: a versioned
// envelope with a sha256-base64 checksum over the payload, an allowlisted
// payload scope, and an import pipeline that validates everything before
// any state changes. Imported files are untrusted input: size, depth, node
// count, string length, and key safety are all capped, and unsupported
// future major versions are rejected before migration is attempted.

export const BACKUP_FORMAT = "nestegghero-backup";
export const BACKUP_SCHEMA_VERSION = "1.0.0";
export const APP_VERSION = "1.0.0";

export const GUARDS = Object.freeze({
  maxBytes: 1_000_000,
  maxDepth: 12,
  maxNodes: 6_000,
  maxStringLength: 2_000,
  maxKeyLength: 96
});

const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export class BackupError extends Error {}

function fail(message) {
  throw new BackupError(`${message} Your current progress was not changed.`);
}

// Deterministic serialization so the checksum does not depend on key order.
export function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const parts = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
    return `{${parts.join(",")}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
}

export async function checksumOf(payload) {
  const bytes = new TextEncoder().encode(stableStringify(payload));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const raw = Array.from(new Uint8Array(digest), (b) => String.fromCharCode(b)).join("");
  return `sha256-${btoa(raw)}`;
}

export function backupFilename(date = new Date()) {
  const day = date.toISOString().slice(0, 10);
  return `NestEggHero_backup_${day}.json`;
}

// Export scope is an allowlist. Analytics counters, calculator run counts,
// and anything outside learning continuity stay out of the file.
export function buildPayload(preferences, learning) {
  return {
    schemaVersion: BACKUP_SCHEMA_VERSION,
    createdAt: learning.createdAt,
    updatedAt: new Date().toISOString(),
    preferences: {
      theme: preferences.theme,
      kidSpeak: preferences.kidSpeak,
      textSize: preferences.textSize
    },
    learning: {
      readArticles: learning.readArticles,
      bookmarks: learning.bookmarks,
      highlights: learning.highlights,
      quizScores: learning.quizScores,
      badges: learning.badges,
      streak: learning.streak
    }
  };
}

export async function buildEnvelope(preferences, learning) {
  const payload = buildPayload(preferences, learning);
  return {
    format: BACKUP_FORMAT,
    schemaVersion: BACKUP_SCHEMA_VERSION,
    exportedAt: new Date().toISOString(),
    appVersion: APP_VERSION,
    checksum: await checksumOf(payload),
    payload
  };
}

function guardStructure(value) {
  let nodes = 0;
  const walk = (node, depth) => {
    nodes += 1;
    if (nodes > GUARDS.maxNodes) {
      fail("This backup file contains too many values to be valid.");
    }
    if (depth > GUARDS.maxDepth) {
      fail("This backup file is nested too deeply to be valid.");
    }
    if (typeof node === "string" && node.length > GUARDS.maxStringLength) {
      fail("This backup file contains text that is too long to be valid.");
    }
    if (Array.isArray(node)) {
      node.forEach((item) => walk(item, depth + 1));
      return;
    }
    if (node && typeof node === "object") {
      for (const key of Object.keys(node)) {
        if (UNSAFE_KEYS.has(key) || key.length > GUARDS.maxKeyLength) {
          fail("This backup file contains an unsafe key.");
        }
        walk(node[key], depth + 1);
      }
    }
  };
  walk(value, 0);
}

function guardEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    fail("This file is not a valid backup object.");
  }
  if (envelope.format !== BACKUP_FORMAT) {
    fail("This file is not a NestEggHero backup.");
  }
  if (typeof envelope.schemaVersion !== "string" || !/^\d+\.\d+\.\d+$/.test(envelope.schemaVersion)) {
    fail("This backup is missing a valid schema version.");
  }
  const major = Number(envelope.schemaVersion.split(".")[0]);
  const supportedMajor = Number(BACKUP_SCHEMA_VERSION.split(".")[0]);
  if (major > supportedMajor) {
    fail("This backup was made by a newer version of NestEggHero and cannot be imported here.");
  }
  if (major < supportedMajor) {
    fail("This backup uses a schema this version no longer supports.");
  }
  if (!envelope.exportedAt || Number.isNaN(Date.parse(envelope.exportedAt))) {
    fail("This backup is missing a valid export date.");
  }
  if (typeof envelope.checksum !== "string" || !envelope.checksum.startsWith("sha256-")) {
    fail("This backup is missing its integrity checksum.");
  }
  if (!envelope.payload || typeof envelope.payload !== "object" || Array.isArray(envelope.payload)) {
    fail("This backup has no readable payload.");
  }
}

function cleanDateMap(source, keyPattern) {
  const result = {};
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    return result;
  }
  for (const [key, value] of Object.entries(source)) {
    if (!keyPattern.test(key)) {
      continue;
    }
    if (typeof value === "string" && !Number.isNaN(Date.parse(value))) {
      result[key] = value;
    }
  }
  return result;
}

function cleanSlugList(source, keyPattern, maxItems) {
  if (!Array.isArray(source)) {
    return [];
  }
  const unique = new Set();
  for (const item of source) {
    if (typeof item === "string" && keyPattern.test(item)) {
      unique.add(item);
    }
    if (unique.size >= maxItems) {
      break;
    }
  }
  return Array.from(unique);
}

const SLUG = /^[a-z0-9][a-z0-9-]{0,79}$/;
const HIGHLIGHT_REF = /^[a-z0-9-]{1,80}#[a-z0-9-]{1,80}$/;

function cleanQuizScores(source) {
  const result = {};
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    return result;
  }
  for (const [key, value] of Object.entries(source)) {
    if (!SLUG.test(key) || !value || typeof value !== "object") {
      continue;
    }
    const correct = Number(value.correct);
    const total = Number(value.total);
    if (!Number.isInteger(correct) || !Number.isInteger(total) || total < 1 || total > 50 || correct < 0 || correct > total) {
      continue;
    }
    result[key] = {
      correct,
      total,
      attempts: Number.isInteger(value.attempts) && value.attempts > 0 ? Math.min(value.attempts, 9999) : 1,
      bestAt: typeof value.bestAt === "string" && !Number.isNaN(Date.parse(value.bestAt))
        ? value.bestAt
        : new Date().toISOString()
    };
  }
  return result;
}

// Normalizes an imported payload down to exactly the fields this app knows,
// dropping anything else. Unknown top-level keys are a hard reject so a
// tampered file cannot smuggle data through an import.
export function sanitizePayload(payload) {
  const allowed = new Set(["schemaVersion", "createdAt", "updatedAt", "preferences", "learning"]);
  for (const key of Object.keys(payload)) {
    if (!allowed.has(key)) {
      fail(`This backup includes data this app does not store (${key}).`);
    }
  }
  const preferences = payload.preferences && typeof payload.preferences === "object" ? payload.preferences : {};
  const learning = payload.learning && typeof payload.learning === "object" ? payload.learning : {};
  const streak = learning.streak && typeof learning.streak === "object" ? learning.streak : {};
  return {
    createdAt: typeof payload.createdAt === "string" && !Number.isNaN(Date.parse(payload.createdAt))
      ? payload.createdAt
      : new Date().toISOString(),
    preferences: {
      theme: preferences.theme === "dark" ? "dark" : "light",
      kidSpeak: preferences.kidSpeak === true,
      textSize: preferences.textSize === "large" ? "large" : "normal"
    },
    learning: {
      readArticles: cleanDateMap(learning.readArticles, SLUG),
      bookmarks: cleanSlugList(learning.bookmarks, SLUG, 100),
      highlights: cleanSlugList(learning.highlights, HIGHLIGHT_REF, 400),
      quizScores: cleanQuizScores(learning.quizScores),
      badges: cleanSlugList(learning.badges, SLUG, 40),
      streak: {
        count: Number.isInteger(streak.count) && streak.count >= 0 ? Math.min(streak.count, 100000) : 0,
        lastActiveDay: typeof streak.lastActiveDay === "string" ? streak.lastActiveDay.slice(0, 10) : "",
        graceUsedOn: typeof streak.graceUsedOn === "string" ? streak.graceUsedOn.slice(0, 10) : ""
      }
    }
  };
}

// The read side of the pipeline: size check, guarded parse, structure
// guards, envelope validation, checksum verification, sanitization.
// Returns a preview the interface shows before asking merge or replace.
export async function inspectBackupText(text, byteLength) {
  if (byteLength > GUARDS.maxBytes) {
    fail("This file is larger than any real NestEggHero backup.");
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail("This file is not valid JSON.");
  }
  guardStructure(parsed);
  guardEnvelope(parsed);
  const expected = await checksumOf(parsed.payload);
  if (expected !== parsed.checksum) {
    fail("This backup failed its integrity check. The file may be corrupted or edited.");
  }
  const clean = sanitizePayload(parsed.payload);
  return {
    exportedAt: parsed.exportedAt,
    appVersion: typeof parsed.appVersion === "string" ? parsed.appVersion.slice(0, 20) : "unknown",
    payload: clean,
    summary: summarizePayload(clean)
  };
}

export function summarizePayload(payload) {
  return [
    { label: "Articles marked read", count: Object.keys(payload.learning.readArticles).length },
    { label: "Bookmarks", count: payload.learning.bookmarks.length },
    { label: "Highlights", count: payload.learning.highlights.length },
    { label: "Quiz results", count: Object.keys(payload.learning.quizScores).length },
    { label: "Badges", count: payload.learning.badges.length },
    { label: "Streak length", count: payload.learning.streak.count }
  ];
}

// Merge keeps the richer of each record; replace adopts the import wholesale.
// Both produce a complete new learning object so the caller can apply it
// atomically in one save.
export function mergeLearning(current, imported) {
  const quizScores = { ...current.quizScores };
  for (const [slug, incoming] of Object.entries(imported.quizScores)) {
    const existing = quizScores[slug];
    if (!existing || incoming.correct > existing.correct) {
      quizScores[slug] = incoming;
    }
  }
  return {
    ...current,
    readArticles: { ...imported.readArticles, ...current.readArticles },
    bookmarks: Array.from(new Set([...current.bookmarks, ...imported.bookmarks])).slice(0, 100),
    highlights: Array.from(new Set([...current.highlights, ...imported.highlights])).slice(0, 400),
    quizScores,
    badges: Array.from(new Set([...current.badges, ...imported.badges])).slice(0, 40),
    streak: imported.streak.count > current.streak.count ? imported.streak : current.streak
  };
}

export function replaceLearning(current, imported, createdAt) {
  return {
    ...current,
    createdAt,
    readArticles: imported.readArticles,
    bookmarks: imported.bookmarks,
    highlights: imported.highlights,
    quizScores: imported.quizScores,
    badges: imported.badges,
    streak: imported.streak
  };
}
