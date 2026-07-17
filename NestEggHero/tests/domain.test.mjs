import assert from "node:assert/strict";
import {
  calculateProjection,
  contributionLimitFor,
  stableStringify,
  validateBackupEnvelope
} from "../assets/domain.js";

const zeroRate = calculateProjection({
  initialAmount: 1000,
  monthlyContribution: 100,
  years: 1,
  nominalReturn: 0,
  inflation: 0,
  timing: "end"
});

assert.equal(zeroRate.totals.contributionCents, 220000);
assert.equal(zeroRate.totals.nominalCents, 220000);
assert.equal(zeroRate.totals.realCents, 220000);

const projection = calculateProjection({
  initialAmount: 2500,
  monthlyContribution: 250,
  years: 20,
  nominalReturn: 5,
  inflation: 2.5,
  timing: "end"
});

assert.equal(projection.yearly.length, 20);
assert.ok(projection.totals.nominalCents > projection.totals.contributionCents);
assert.ok(projection.totals.realCents < projection.totals.nominalCents);

assert.equal(contributionLimitFor("ira", 49).amount, 7500);
assert.equal(contributionLimitFor("ira", 50).amount, 8600);
assert.equal(contributionLimitFor("workplace", 59).amount, 32500);
assert.equal(contributionLimitFor("workplace", 60).amount, 35750);
assert.equal(contributionLimitFor("simple", 63).amount, 22250);

assert.throws(() => calculateProjection({
  initialAmount: 0,
  monthlyContribution: 0,
  years: 10,
  nominalReturn: 5,
  inflation: 2,
  timing: "end"
}), /starting amount or a monthly contribution/);

assert.equal(stableStringify({ b: 1, a: 2 }), "{\"a\":2,\"b\":1}");
assert.throws(() => stableStringify(JSON.parse("{\"__proto__\":{\"polluted\":true}}")), /unsafe key/);

validateBackupEnvelope({
  format: "nestegghero-backup",
  schemaVersion: "1.0.0",
  exportedAt: "2026-07-16T00:00:00Z",
  appVersion: "0.1.0",
  checksum: "valid-checksum-placeholder",
  payload: {
    schemaVersion: "1.0.0",
    createdAt: "2026-07-16T00:00:00Z",
    updatedAt: "2026-07-16T00:00:00Z",
    preferences: {
      theme: "system",
      kidSpeak: false,
      textSize: "normal"
    },
    progress: {
      completedLessons: {},
      bookmarks: [],
      quizScores: {},
      badges: [],
      calculatorRuns: 0
    }
  }
});

assert.throws(() => validateBackupEnvelope({
  format: "nestegghero-backup",
  schemaVersion: "2.0.0",
  exportedAt: "2026-07-16T00:00:00Z",
  appVersion: "0.1.0",
  checksum: "valid-checksum-placeholder",
  payload: {}
}), /unsupported future schema/);

console.log("domain tests passed");
