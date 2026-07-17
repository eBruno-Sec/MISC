import test from "node:test";
import assert from "node:assert/strict";
import {
  compoundGrowth, contributionGrowth, presentValue, realReturn,
  todaysDollars, effectiveAnnualRate, debtPayoff, runCalculator, CalculatorInputError
} from "../scripts/calculators.js";

test("compound growth at a zero rate stays flat", () => {
  const result = compoundGrowth({ presentValue: 5000, annualRate: 0, years: 10, frequency: "monthly" });
  assert.equal(result.headline.value, "$5,000");
  assert.equal(result.stats[1].value, "$0");
});

test("more frequent compounding never loses to annual", () => {
  const annual = compoundGrowth({ presentValue: 10000, annualRate: 0.05, years: 10, frequency: "annual" });
  const daily = compoundGrowth({ presentValue: 10000, annualRate: 0.05, years: 10, frequency: "daily" });
  const toNumber = (display) => Number(display.replace(/[^0-9.-]/g, ""));
  assert.ok(toNumber(daily.headline.value) >= toNumber(annual.headline.value));
});

test("beginning-of-month contributions finish at least as high as end-of-month", () => {
  const base = { startingAmount: 0, monthlyContribution: 200, annualRate: 0.05, years: 20, inflation: 0.025 };
  const end = contributionGrowth({ ...base, timing: "end" });
  const beginning = contributionGrowth({ ...base, timing: "beginning" });
  const toNumber = (display) => Number(display.replace(/[^0-9.-]/g, ""));
  assert.ok(toNumber(beginning.headline.value) >= toNumber(end.headline.value));
});

test("zero-rate contributions equal the plain sum", () => {
  const result = contributionGrowth({
    startingAmount: 1000, monthlyContribution: 100, annualRate: 0, years: 2, timing: "end", inflation: 0
  });
  assert.equal(result.headline.value, "$3,400");
});

test("an empty projection is rejected with a recovery message", () => {
  assert.throws(
    () => contributionGrowth({ startingAmount: 0, monthlyContribution: 0, annualRate: 0.05, years: 10, timing: "end", inflation: 0.02 }),
    CalculatorInputError
  );
});

test("present value at a zero rate equals the future amount", () => {
  const result = presentValue({ futureAmount: 10000, annualRate: 0, years: 10 });
  assert.equal(result.headline.value, "$10,000");
});

test("real return divides rather than subtracts", () => {
  const result = realReturn({ nominalRate: 0.06, inflation: 0.08 });
  assert.equal(result.headline.value, "-1.85%");
});

test("today's dollars erodes a future amount", () => {
  const result = todaysDollars({ futureAmount: 500000, inflation: 0.025, years: 25 });
  assert.equal(result.headline.value, "$269,695");
});

test("EAR of 12% APR compounded monthly is about 12.683%", () => {
  const result = effectiveAnnualRate({ apr: 0.12, frequency: "monthly" });
  assert.equal(result.headline.value, "12.683%");
});

test("a payment below the first month's interest is rejected", () => {
  assert.throws(
    () => debtPayoff({ balance: 6000, apr: 0.21, monthlyPayment: 100 }),
    CalculatorInputError
  );
});

test("an interest-free balance pays off in exactly balance over payment months", () => {
  const result = debtPayoff({ balance: 1200, apr: 0, monthlyPayment: 100 });
  assert.equal(result.stats[2].value, "12");
  assert.equal(result.stats[0].value, "$0");
});

test("debt payoff interest grows the total paid above the balance", () => {
  const result = debtPayoff({ balance: 6000, apr: 0.21, monthlyPayment: 250 });
  const toNumber = (display) => Number(display.replace(/[^0-9.-]/g, ""));
  assert.ok(toNumber(result.stats[1].value) > 6000);
});

test("runCalculator validates raw field input", () => {
  assert.throws(
    () => runCalculator("compound-growth", { presentValue: "5000", annualRate: "4", years: "2.5", frequency: "monthly" }),
    CalculatorInputError
  );
  const ok = runCalculator("compound-growth", { presentValue: "5000", annualRate: "4", years: "15", frequency: "monthly" });
  assert.equal(ok.headline.label, "Estimated future value");
});

test("percent fields enforce their documented bounds", () => {
  assert.throws(
    () => runCalculator("contribution-growth", {
      startingAmount: "0", monthlyContribution: "100", annualRate: "40", years: "10", timing: "end", inflation: "2.5"
    }),
    CalculatorInputError
  );
});
