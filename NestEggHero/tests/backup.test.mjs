import test from "node:test";
import assert from "node:assert/strict";
import { buildEnvelope, inspectBackupText, checksumOf, stableStringify, mergeLearning, replaceLearning, backupFilename, BackupError } from "../scripts/backup.js";

function sampleLearning() {
  return {
    schemaVersion: "1.0.0",
    createdAt: "2026-07-01T00:00:00.000Z",
    updatedAt: "2026-07-16T00:00:00.000Z",
    readLessons: { "rmd-basics": "2026-07-10T00:00:00.000Z" },
    bookmarks: ["rmd-basics"],
    highlights: ["rmd-basics#start"],
    quizScores: { "rmd-basics": { correct: 1, total: 1, attempts: 1, bestAt: "2026-07-10T00:00:00.000Z" } },
    badges: ["first-lesson"],
    streak: { count: 3, lastActiveDay: "2026-07-16", graceUsedOn: "" },
    calculatorRuns: { "debt-payoff": 2 },
    events: { calculator_started: 2 }
  };
}

const prefs = { theme: "dark", kidSpeak: true, textSize: "large" };

test("stable stringify is independent of key order", () => {
  assert.equal(stableStringify({ b: 1, a: { d: 2, c: 3 } }), stableStringify({ a: { c: 3, d: 2 }, b: 1 }));
});

test("checksums are deterministic", async () => {
  const first = await checksumOf({ hello: "world" });
  const second = await checksumOf({ hello: "world" });
  assert.equal(first, second);
  assert.match(first, /^sha256-[A-Za-z0-9+/]+=*$/);
});

test("backup round-trips and excludes analytics and calculator counters", async () => {
  const envelope = await buildEnvelope(prefs, sampleLearning());
  assert.equal(envelope.payload.learning.calculatorRuns, undefined);
  assert.equal(envelope.payload.learning.events, undefined);
  const text = JSON.stringify(envelope);
  const inspected = await inspectBackupText(text, text.length);
  assert.equal(inspected.payload.learning.bookmarks[0], "rmd-basics");
  assert.equal(inspected.payload.preferences.kidSpeak, true);
});

test("tampering and unsafe keys are rejected", async () => {
  const envelope = await buildEnvelope(prefs, sampleLearning());
  envelope.payload.learning.badges.push("safe-keeper");
  await assert.rejects(() => inspectBackupText(JSON.stringify(envelope), JSON.stringify(envelope).length), BackupError);
  const clean = await buildEnvelope(prefs, sampleLearning());
  const unsafe = JSON.stringify(clean).replace('"bookmarks"', '"__proto__"');
  await assert.rejects(() => inspectBackupText(unsafe, unsafe.length), BackupError);
});

test("future versions and unknown payload data are rejected", async () => {
  const envelope = await buildEnvelope(prefs, sampleLearning());
  const future = JSON.stringify({ ...envelope, schemaVersion: "2.0.0" });
  await assert.rejects(() => inspectBackupText(future, future.length), BackupError);
  envelope.payload.accountNumbers = ["never"];
  envelope.checksum = await checksumOf(envelope.payload);
  const text = JSON.stringify(envelope);
  await assert.rejects(() => inspectBackupText(text, text.length), BackupError);
});

test("merge and replace are atomic object transforms", () => {
  const current = sampleLearning();
  const imported = { readLessons: { "debt-payoff-basics": "2026-07-12T00:00:00.000Z" }, bookmarks: ["debt-payoff-basics"], highlights: [], quizScores: {}, badges: ["safe-keeper"], streak: { count: 9, lastActiveDay: "2026-07-12", graceUsedOn: "" } };
  const merged = mergeLearning(current, imported);
  assert.equal(Object.keys(merged.readLessons).length, 2);
  assert.ok(merged.bookmarks.includes("rmd-basics"));
  assert.equal(merged.streak.count, 9);
  const replaced = replaceLearning(current, imported, "2026-06-01T00:00:00.000Z");
  assert.equal(Object.keys(replaced.readLessons).length, 1);
  assert.equal(replaced.calculatorRuns["debt-payoff"], 2);
});

test("backup filename follows the spec", () => {
  assert.equal(backupFilename(new Date("2026-07-16T12:00:00Z")), "NestEggHero_backup_2026-07-16.json");
});
