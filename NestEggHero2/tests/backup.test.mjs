import test from "node:test";
import assert from "node:assert/strict";
import {
  stableStringify, checksumOf, buildEnvelope, inspectBackupText,
  mergeLearning, replaceLearning, backupFilename, BackupError
} from "../scripts/backup.js";

function sampleLearning() {
  return {
    schemaVersion: "1.0.0",
    createdAt: "2026-07-01T00:00:00.000Z",
    updatedAt: "2026-07-16T00:00:00.000Z",
    readArticles: { "rmd-basics": "2026-07-10T00:00:00.000Z" },
    bookmarks: ["rmd-basics"],
    highlights: ["rmd-basics#when"],
    quizScores: { "rmd-basics": { correct: 2, total: 2, attempts: 1, bestAt: "2026-07-10T00:00:00.000Z" } },
    badges: ["first-read"],
    streak: { count: 3, lastActiveDay: "2026-07-16", graceUsedOn: "" },
    calculatorRuns: { "debt-payoff": 4 },
    activity: { article_started: 9 }
  };
}

const prefs = { theme: "dark", kidSpeak: true, textSize: "large" };

test("stableStringify is independent of key order", () => {
  assert.equal(
    stableStringify({ b: 1, a: { d: 2, c: 3 } }),
    stableStringify({ a: { c: 3, d: 2 }, b: 1 })
  );
});

test("checksums are deterministic and sha256-base64 shaped", async () => {
  const first = await checksumOf({ hello: "world" });
  const second = await checksumOf({ hello: "world" });
  assert.equal(first, second);
  assert.match(first, /^sha256-[A-Za-z0-9+/]+=*$/);
});

test("an exported envelope round-trips through the import pipeline", async () => {
  const envelope = await buildEnvelope(prefs, sampleLearning());
  const text = JSON.stringify(envelope);
  const inspected = await inspectBackupText(text, text.length);
  assert.equal(inspected.payload.learning.bookmarks[0], "rmd-basics");
  assert.equal(inspected.payload.preferences.kidSpeak, true);
  assert.equal(inspected.summary[0].count, 1);
});

test("analytics and calculator counters stay out of the backup", async () => {
  const envelope = await buildEnvelope(prefs, sampleLearning());
  assert.equal(envelope.payload.learning.activity, undefined);
  assert.equal(envelope.payload.learning.calculatorRuns, undefined);
});

test("a tampered payload fails the integrity check", async () => {
  const envelope = await buildEnvelope(prefs, sampleLearning());
  envelope.payload.learning.badges.push("library-complete");
  const text = JSON.stringify(envelope);
  await assert.rejects(() => inspectBackupText(text, text.length), BackupError);
});

test("foreign formats and future schema versions are rejected", async () => {
  const envelope = await buildEnvelope(prefs, sampleLearning());
  const wrongFormat = JSON.stringify({ ...envelope, format: "other-app-backup" });
  await assert.rejects(() => inspectBackupText(wrongFormat, wrongFormat.length), BackupError);
  const future = JSON.stringify({ ...envelope, schemaVersion: "2.0.0" });
  await assert.rejects(() => inspectBackupText(future, future.length), BackupError);
});

test("unsafe keys anywhere in the file are rejected", async () => {
  const envelope = await buildEnvelope(prefs, sampleLearning());
  const text = JSON.stringify(envelope).replace('"bookmarks"', '"__proto__"');
  await assert.rejects(() => inspectBackupText(text, text.length), BackupError);
});

test("payloads carrying unknown top-level data are rejected", async () => {
  const envelope = await buildEnvelope(prefs, sampleLearning());
  envelope.payload.accountNumbers = ["should never be here"];
  envelope.checksum = await checksumOf(envelope.payload);
  const text = JSON.stringify(envelope);
  await assert.rejects(() => inspectBackupText(text, text.length), BackupError);
});

test("oversized files are rejected before parsing", async () => {
  await assert.rejects(() => inspectBackupText("{}", 5_000_000), BackupError);
});

test("invalid JSON is rejected with progress untouched", async () => {
  await assert.rejects(() => inspectBackupText("not json at all", 15), BackupError);
});

test("sanitization drops malformed entries instead of failing the import", async () => {
  const learning = sampleLearning();
  learning.bookmarks = ["ok-slug", "Bad Slug!", 42];
  learning.quizScores["bad"] = { correct: 9, total: 2 };
  const envelope = await buildEnvelope(prefs, learning);
  const text = JSON.stringify(envelope);
  const inspected = await inspectBackupText(text, text.length);
  assert.deepEqual(inspected.payload.learning.bookmarks, ["ok-slug"]);
  assert.equal(inspected.payload.learning.quizScores.bad, undefined);
});

test("merge keeps the union and the better quiz score", () => {
  const current = sampleLearning();
  const imported = {
    readArticles: { "debt-vs-interest": "2026-07-12T00:00:00.000Z" },
    bookmarks: ["debt-vs-interest"],
    highlights: [],
    quizScores: { "rmd-basics": { correct: 1, total: 2, attempts: 5, bestAt: "2026-07-12T00:00:00.000Z" } },
    badges: ["quiz-ace"],
    streak: { count: 10, lastActiveDay: "2026-07-12", graceUsedOn: "" }
  };
  const merged = mergeLearning(current, imported);
  assert.equal(Object.keys(merged.readArticles).length, 2);
  assert.ok(merged.bookmarks.includes("rmd-basics") && merged.bookmarks.includes("debt-vs-interest"));
  assert.equal(merged.quizScores["rmd-basics"].correct, 2);
  assert.equal(merged.streak.count, 10);
  assert.ok(merged.badges.includes("first-read") && merged.badges.includes("quiz-ace"));
});

test("replace adopts the import and keeps local-only counters", () => {
  const current = sampleLearning();
  const imported = {
    readArticles: {},
    bookmarks: [],
    highlights: [],
    quizScores: {},
    badges: [],
    streak: { count: 0, lastActiveDay: "", graceUsedOn: "" }
  };
  const replaced = replaceLearning(current, imported, "2026-06-01T00:00:00.000Z");
  assert.equal(Object.keys(replaced.readArticles).length, 0);
  assert.equal(replaced.createdAt, "2026-06-01T00:00:00.000Z");
  assert.equal(replaced.calculatorRuns["debt-payoff"], 4);
});

test("backup filenames follow the specification", () => {
  assert.equal(backupFilename(new Date("2026-07-16T12:00:00Z")), "NestEggHero_backup_2026-07-16.json");
});
