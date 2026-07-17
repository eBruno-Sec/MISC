import test from "node:test";
import assert from "node:assert/strict";
import { CALCULATORS, runCalculator, contributionGrowth, debtPayoff, effectiveAnnualRate, realReturn, rothTraditionalDecision } from "../scripts/calculators.js";

test("all calculators are registered with defaults", () => {
  assert.equal(CALCULATORS.length, 9);
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

test("Roth vs Traditional ties in same-budget mode when tax rates match", () => {
  const result = rothTraditionalDecision({
    annualAmount: 7500,
    age: 35,
    years: 25,
    annualRate: 0.05,
    currentTaxRate: 0.22,
    retirementTaxRate: 0.22,
    comparisonMode: "same-budget",
    filingStatus: "single",
    workplaceCoverage: "self",
    modifiedAgi: 100000
  });
  assert.equal(result.headline.value, "Tie");
  assert.equal(result.stats[2].value, "$5,850");
  assert.equal(result.decision.sensitivity.breakEvenLabel, "22.00%");
  assert.equal(result.decision.sensitivity.interpretation, "Very sensitive: a small tax-rate change can flip the modeled result.");
  assert.ok(result.decision.factors.some((item) => item.includes("break-even line")));
});

test("Roth vs Traditional surfaces phaseout warnings", () => {
  const result = rothTraditionalDecision({
    annualAmount: 7500,
    age: 35,
    years: 10,
    annualRate: 0.04,
    currentTaxRate: 0.24,
    retirementTaxRate: 0.22,
    comparisonMode: "same-contribution",
    filingStatus: "mfj",
    workplaceCoverage: "self",
    modifiedAgi: 260000
  });
  assert.ok(result.warnings.some((item) => item.includes("Direct Roth IRA contribution") && item.includes("at or above")));
  assert.ok(result.warnings.some((item) => item.includes("Traditional IRA deduction") && item.includes("at or above")));
});

test("registered calculators run with defaults", () => {
  for (const calc of CALCULATORS) {
    const raw = Object.fromEntries(calc.fields.map((field) => [field.id, field.defaultValue]));
    const result = runCalculator(calc.slug, raw);
    assert.ok(result.headline.label);
    assert.ok(result.assumptions.length > 0);
  }
});
