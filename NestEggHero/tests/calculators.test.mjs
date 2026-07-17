import test from "node:test";
import assert from "node:assert/strict";
import { CALCULATORS, runCalculator, contributionGrowth, debtPayoff, effectiveAnnualRate, realReturn } from "../scripts/calculators.js";

test("all calculators are registered with defaults", () => {
  assert.equal(CALCULATORS.length, 8);
  for (const calc of CALCULATORS) {
    assert.ok(calc.slug);
    assert.ok(calc.name);
    assert.ok(calc.fields.length > 0);
    for (const field of calc.fields) assert.notEqual(field.defaultValue, undefined);
  }
});

test("steady saving handles zero-rate branches", () => {
  const result = contributionGrowth({ startingAmount: 1000, monthlyContribution: 100, annualRate: 0, years: 1, timing: "end", inflation: 0 });
  assert.equal(result.headline.value, "$2,200");
  assert.equal(result.stats[0].value, "$2,200");
});

test("debt payoff rejects payments that do not beat interest", () => {
  assert.throws(() => debtPayoff({ balance: 6000, apr: 0.21, monthlyPayment: 100 }), /does not reduce/);
});

test("effective annual rate exceeds stated APR when compounding", () => {
  const result = effectiveAnnualRate({ apr: 0.24, frequency: "daily" });
  assert.match(result.headline.value, /27\./);
});

test("real return uses exact division formula", () => {
  const result = realReturn({ nominalRate: 0.06, inflation: 0.03 });
  assert.match(result.headline.value, /2\.91%/);
});

test("registered calculators run with defaults", () => {
  for (const calc of CALCULATORS) {
    const raw = Object.fromEntries(calc.fields.map((field) => [field.id, field.defaultValue]));
    const result = runCalculator(calc.slug, raw);
    assert.ok(result.headline.label);
    assert.ok(result.assumptions.length > 0);
  }
});
