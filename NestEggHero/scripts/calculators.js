export function formatUSD(amount) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(amount);
}

export function formatRate(rate, digits = 2) {
  return `${(rate * 100).toFixed(digits)}%`;
}

export class CalculatorInputError extends Error {}

function fail(message) {
  throw new CalculatorInputError(`${message} Nothing was saved; adjust the input and try again.`);
}

function readDollars(raw, field) {
  if (raw === "" || raw === null || raw === undefined) {
    if (field.optional) return 0;
    fail(`${field.label} is required.`);
  }
  const value = Number(raw);
  if (!Number.isFinite(value)) fail(`${field.label} must be a number.`);
  if (value < 0) fail(`${field.label} cannot be negative.`);
  if (value > 100000000) fail(`${field.label} is capped at $100,000,000 in this educational tool.`);
  return value;
}

function readPercent(raw, field) {
  const value = Number(raw);
  if (!Number.isFinite(value)) fail(`${field.label} must be a number.`);
  if (value < field.min || value > field.max) fail(`${field.label} must be between ${field.min}% and ${field.max}%.`);
  return value / 100;
}

function readWhole(raw, field) {
  const value = Number(raw);
  if (!Number.isInteger(value) || value < field.min || value > field.max) fail(`${field.label} must be a whole number from ${field.min} to ${field.max}.`);
  return value;
}

function readChoice(raw, field) {
  const match = field.options.find((item) => item.value === raw);
  if (!match) fail(`Choose a value for ${field.label}.`);
  return match.value;
}

export function readField(raw, field) {
  if (field.kind === "dollars") return readDollars(raw, field);
  if (field.kind === "percent") return readPercent(raw, field);
  if (field.kind === "whole") return readWhole(raw, field);
  if (field.kind === "choice") return readChoice(raw, field);
  fail(`Unsupported field: ${field.label}.`);
}

const FREQUENCIES = [
  { value: "annual", label: "Once a year", n: 1 },
  { value: "quarterly", label: "Quarterly", n: 4 },
  { value: "monthly", label: "Monthly", n: 12 },
  { value: "daily", label: "Daily (365)", n: 365 }
];

function periods(value) {
  const found = FREQUENCIES.find((item) => item.value === value);
  if (!found) fail("Choose a compounding frequency.");
  return found.n;
}

function frequencyLabel(value) {
  return FREQUENCIES.find((item) => item.value === value).label.toLowerCase();
}

export function compoundGrowth({ presentValue, annualRate, years, frequency }) {
  const n = periods(frequency);
  const atYear = (year) => annualRate === 0 ? presentValue : presentValue * Math.pow(1 + annualRate / n, n * year);
  const rows = [];
  const points = [];
  for (let year = 1; year <= years; year += 1) {
    const value = atYear(year);
    points.push(value);
    rows.push([String(year), formatUSD(value)]);
  }
  const end = atYear(years);
  return {
    headline: { label: "Estimated future value", value: formatUSD(end) },
    stats: [
      { label: "Starting amount", value: formatUSD(presentValue) },
      { label: "Estimated growth", value: formatUSD(end - presentValue) }
    ],
    assumptions: [
      `Nominal annual rate of ${formatRate(annualRate)}, compounded ${frequencyLabel(frequency)}.`,
      `No contributions, withdrawals, fees, taxes, or investment volatility over ${years} year${years === 1 ? "" : "s"}.`
    ],
    table: { caption: "Estimated value at each year end", columns: ["Year", "Estimated value"], rows },
    chart: { label: "Estimated value by year", points }
  };
}

export function contributionGrowth({ startingAmount, monthlyContribution, annualRate, years, timing, inflation }) {
  if (startingAmount === 0 && monthlyContribution === 0) fail("Add a starting amount or a monthly contribution.");
  const monthlyRate = annualRate / 12;
  const valueAt = (months) => {
    const base = monthlyRate === 0 ? startingAmount : startingAmount * Math.pow(1 + monthlyRate, months);
    let stream = monthlyRate === 0 ? monthlyContribution * months : monthlyContribution * ((Math.pow(1 + monthlyRate, months) - 1) / monthlyRate);
    if (timing === "beginning" && monthlyRate !== 0) stream *= 1 + monthlyRate;
    return base + stream;
  };
  const rows = [];
  const points = [];
  for (let year = 1; year <= years; year += 1) {
    const nominal = valueAt(year * 12);
    const real = nominal / Math.pow(1 + inflation, year);
    const contributed = startingAmount + monthlyContribution * year * 12;
    points.push(nominal);
    rows.push([String(year), formatUSD(contributed), formatUSD(nominal), formatUSD(real)]);
  }
  const end = valueAt(years * 12);
  const contributed = startingAmount + monthlyContribution * years * 12;
  return {
    headline: { label: "Estimated ending balance", value: formatUSD(end) },
    stats: [
      { label: "Total contributed", value: formatUSD(contributed) },
      { label: "Estimated growth", value: formatUSD(Math.max(0, end - contributed)) },
      { label: "In today's dollars", value: formatUSD(end / Math.pow(1 + inflation, years)) }
    ],
    assumptions: [
      `Nominal annual return of ${formatRate(annualRate)}, compounded monthly.`,
      `${formatUSD(monthlyContribution)} contributed at the ${timing} of each month for ${years} years.`,
      `${formatRate(inflation)} inflation used only to restate the result in today's dollars.`,
      "No fees, taxes, employer match, missed contributions, or contribution-limit checks."
    ],
    table: { caption: "Estimated year-end balances", columns: ["Year", "Contributed", "Nominal estimate", "Today's dollars"], rows },
    chart: { label: "Estimated nominal balance by year", points }
  };
}

export function presentValue({ futureAmount, annualRate, years }) {
  if (annualRate <= -1) fail("The discount rate must be above -100%.");
  const value = annualRate === 0 ? futureAmount : futureAmount / Math.pow(1 + annualRate, years);
  return {
    headline: { label: "Estimated value today", value: formatUSD(value) },
    stats: [{ label: "Future amount", value: formatUSD(futureAmount) }, { label: "Discount applied", value: formatUSD(futureAmount - value) }],
    assumptions: [`A single future amount ${years} year${years === 1 ? "" : "s"} from now.`, `Constant annual discount rate of ${formatRate(annualRate)}.`]
  };
}

export function realReturn({ nominalRate, inflation }) {
  const exact = (1 + nominalRate) / (1 + inflation) - 1;
  return {
    headline: { label: "Estimated real annual return", value: formatRate(exact) },
    stats: [{ label: "Nominal return", value: formatRate(nominalRate) }, { label: "Inflation", value: formatRate(inflation) }, { label: "Subtraction shortcut", value: formatRate(nominalRate - inflation) }],
    assumptions: ["Both rates are annual and apply over the same period.", "The exact formula divides by inflation; subtraction is only a rough shortcut."]
  };
}

export function todaysDollars({ futureAmount, inflation, years }) {
  const real = futureAmount / Math.pow(1 + inflation, years);
  return {
    headline: { label: "Estimated purchasing power today", value: formatUSD(real) },
    stats: [{ label: "Future nominal amount", value: formatUSD(futureAmount) }, { label: "Purchasing power eroded", value: formatUSD(futureAmount - real) }],
    assumptions: [`Inflation of ${formatRate(inflation)} for ${years} year${years === 1 ? "" : "s"}.`, "Actual inflation varies by year and by household purchases."]
  };
}

export function effectiveAnnualRate({ apr, frequency }) {
  const n = periods(frequency);
  const ear = apr === 0 ? 0 : Math.pow(1 + apr / n, n) - 1;
  return {
    headline: { label: "Effective annual rate", value: formatRate(ear, 3) },
    stats: [{ label: "Stated APR", value: formatRate(apr, 3) }, { label: "Difference", value: formatRate(ear - apr, 3) }],
    assumptions: [`Interest compounds ${frequencyLabel(frequency)} and no balance is paid down mid-year.`, "Fees and balance changes are outside this comparison."]
  };
}

export function debtPayoff({ balance, apr, monthlyPayment }) {
  const monthlyRate = apr / 12;
  const firstInterest = balance * monthlyRate;
  if (monthlyPayment <= firstInterest) fail(`The first month accrues about ${formatUSD(firstInterest)} in interest, so ${formatUSD(monthlyPayment)} does not reduce the balance.`);
  let remaining = Math.round(balance * 100);
  const payment = Math.round(monthlyPayment * 100);
  let interestTotal = 0;
  let months = 0;
  const rows = [];
  const points = [];
  while (remaining > 0) {
    months += 1;
    if (months > 600) fail("This plan takes longer than 50 years, which is outside this tool's range.");
    const interest = Math.round(remaining * monthlyRate);
    interestTotal += interest;
    remaining = Math.max(0, remaining + interest - payment);
    points.push(remaining / 100);
    if (months % 12 === 0 || remaining === 0) rows.push([`Month ${months}`, formatUSD(interestTotal / 100), formatUSD(remaining / 100)]);
  }
  const yearsPart = Math.floor(months / 12);
  const monthsPart = months % 12;
  const duration = [yearsPart ? `${yearsPart} year${yearsPart === 1 ? "" : "s"}` : "", monthsPart ? `${monthsPart} month${monthsPart === 1 ? "" : "s"}` : ""].filter(Boolean).join(", ") || "Under a month";
  return {
    headline: { label: "Estimated time to payoff", value: duration },
    stats: [{ label: "Total interest paid", value: formatUSD(interestTotal / 100) }, { label: "Total paid", value: formatUSD((Math.round(balance * 100) + interestTotal) / 100) }, { label: "Payments", value: String(months) }],
    assumptions: [`Fixed APR of ${formatRate(apr)}, compounded monthly, with payments applied after interest.`, "No new charges, late fees, rate changes, or missed payments."],
    table: { caption: "Estimated balance during payoff", columns: ["Point", "Interest so far", "Balance left"], rows },
    chart: { label: "Balance remaining by month", points }
  };
}

function futureValueAnnualSeries(annualAmount, annualRate, years) {
  if (annualAmount === 0) return 0;
  return annualRate === 0 ? annualAmount * years : annualAmount * ((Math.pow(1 + annualRate, years) - 1) / annualRate);
}

function phaseoutMessage(label, magi, start, end) {
  if (magi <= start) return `${label}: the entered MAGI is below the 2026 phaseout start.`;
  if (magi >= end) return `${label}: the entered MAGI is at or above the 2026 phaseout end.`;
  return `${label}: the entered MAGI is inside the 2026 phaseout range.`;
}

function rothPhaseoutMessage(filingStatus, magi) {
  if (filingStatus === "mfj") return phaseoutMessage("Direct Roth IRA contribution", magi, 242000, 252000);
  if (filingStatus === "mfs") return phaseoutMessage("Direct Roth IRA contribution for married filing separately if spouses lived together", magi, 0, 10000);
  return phaseoutMessage("Direct Roth IRA contribution", magi, 153000, 168000);
}

function traditionalDeductionMessage(filingStatus, coverage, magi) {
  if (coverage === "none") return "Traditional IRA deduction: the federal phaseout generally does not apply when neither spouse is covered by a workplace retirement plan.";
  if (coverage === "spouse") {
    if (filingStatus === "mfj") return phaseoutMessage("Traditional IRA deduction when only the spouse is covered at work", magi, 242000, 252000);
    if (filingStatus === "mfs") return phaseoutMessage("Traditional IRA deduction for married filing separately when a spouse is covered", magi, 0, 10000);
    return "Traditional IRA deduction: spouse-covered phaseouts mainly apply to married filers; verify the actual filing facts.";
  }
  if (filingStatus === "mfj") return phaseoutMessage("Traditional IRA deduction when the contributor is covered at work", magi, 129000, 149000);
  if (filingStatus === "mfs") return phaseoutMessage("Traditional IRA deduction for married filing separately when covered at work", magi, 0, 10000);
  return phaseoutMessage("Traditional IRA deduction when covered at work", magi, 81000, 91000);
}

export function rothTraditionalDecision({ annualAmount, age, years, annualRate, currentTaxRate, retirementTaxRate, comparisonMode, filingStatus, workplaceCoverage, modifiedAgi }) {
  const wholeAge = Math.floor(age);
  const limit = 7500 + (wholeAge >= 50 ? 1100 : 0);
  if (annualAmount === 0) fail("Add an annual comparison amount.");
  if (annualAmount > limit) fail(`The annual comparison amount exceeds the 2026 IRA contribution limit for age ${wholeAge}: ${formatUSD(limit)}.`);

  const traditionalContribution = annualAmount;
  const rothContribution = comparisonMode === "same-budget" ? annualAmount * (1 - currentTaxRate) : annualAmount;
  const rothFuture = futureValueAnnualSeries(rothContribution, annualRate, years);
  const traditionalFuture = futureValueAnnualSeries(traditionalContribution, annualRate, years);
  const rothAfterTax = rothFuture;
  const traditionalAfterTax = traditionalFuture * (1 - retirementTaxRate);
  const difference = rothAfterTax - traditionalAfterTax;
  const tie = Math.abs(difference) < 0.5;
  const leader = tie ? "Tie" : difference > 0 ? `Roth +${formatUSD(Math.abs(difference))}` : `Traditional +${formatUSD(Math.abs(difference))}`;
  const breakEvenTaxRate = traditionalFuture === 0 ? 0 : 1 - rothFuture / traditionalFuture;
  const clampedBreakEven = Math.min(0.6, Math.max(0, breakEvenTaxRate));
  const breakEvenDistance = retirementTaxRate - clampedBreakEven;
  const taxGap = retirementTaxRate - currentTaxRate;
  const modeLabel = comparisonMode === "same-budget" ? "Same pre-tax budget" : "Same IRA deposit";
  const decisionTitle = tie ? "The modeled result is essentially even" : difference > 0 ? "Roth leads in this scenario" : "Traditional leads in this scenario";
  const decisionSummary = tie
    ? "The entered tax rates and growth assumptions leave the modeled after-tax results within rounding distance."
    : difference > 0
      ? "Under these inputs, paying the modeled tax cost now leaves the Roth path ahead after the withdrawal-tax assumption is applied."
      : "Under these inputs, deferring the modeled tax cost leaves the traditional path ahead after the withdrawal-tax assumption is applied.";
  const rateSignal = taxGap > 0.0001
    ? "Retirement tax rate is higher than today's rate, which usually helps the Roth side in this model."
    : taxGap < -0.0001
      ? "Retirement tax rate is lower than today's rate, which usually helps the traditional side in this model."
      : "Current and retirement tax rates match, so the comparison mode and deposit framing drive most of the result.";
  const budgetSignal = comparisonMode === "same-budget"
    ? "Same-budget mode reduces the Roth deposit by the current tax cost, creating a cleaner tax-timing comparison."
    : "Same-deposit mode compares equal IRA deposits and intentionally leaves current-year traditional tax savings outside the model.";
  const breakEvenSignal = Math.abs(breakEvenDistance) < 0.005
    ? "Your entered retirement tax rate is sitting almost exactly on the modeled break-even line."
    : breakEvenDistance > 0
      ? `Your entered retirement tax rate is ${formatRate(Math.abs(breakEvenDistance))} above the modeled break-even line.`
      : `Your entered retirement tax rate is ${formatRate(Math.abs(breakEvenDistance))} below the modeled break-even line.`;

  const rows = [];
  for (let year = 1; year <= years; year += 1) {
    rows.push([
      String(year),
      formatUSD(futureValueAnnualSeries(rothContribution, annualRate, year)),
      formatUSD(futureValueAnnualSeries(traditionalContribution, annualRate, year) * (1 - retirementTaxRate))
    ]);
  }

  const warnings = [
    rothPhaseoutMessage(filingStatus, modifiedAgi),
    traditionalDeductionMessage(filingStatus, workplaceCoverage, modifiedAgi),
    comparisonMode === "same-contribution"
      ? "Same IRA deposit mode does not invest the traditional current-year tax savings."
      : "Same pre-tax budget mode reduces the Roth deposit by the entered current tax rate."
  ];

  return {
    headline: { label: tie ? "Estimated after-tax comparison" : "Estimated after-tax advantage", value: leader },
    decision: {
      title: decisionTitle,
      summary: decisionSummary,
      winner: tie ? "Tie" : difference > 0 ? "Roth" : "Traditional",
      gap: tie ? "Within $1" : formatUSD(Math.abs(difference)),
      primary: [
        { label: "Comparison frame", value: modeLabel, note: comparisonMode === "same-budget" ? "Tax-now vs tax-later on one savings budget" : "Equal IRA deposits, tax savings excluded" },
        { label: "Tax-rate gap", value: `${taxGap >= 0 ? "+" : ""}${formatRate(taxGap)}`, note: `Retirement ${formatRate(retirementTaxRate)} vs current ${formatRate(currentTaxRate)}` },
        { label: "Limit used", value: `${Math.round((annualAmount / limit) * 100)}%`, note: `${formatUSD(annualAmount)} of the ${formatUSD(limit)} 2026 IRA limit` }
      ],
      factors: [
        rateSignal,
        budgetSignal,
        breakEvenSignal,
        `${years} year${years === 1 ? "" : "s"} of growth are modeled before the withdrawal-tax assumption is applied.`
      ],
      sensitivity: {
        enteredRate: retirementTaxRate,
        breakEvenRate: clampedBreakEven,
        maxRate: 0.6,
        enteredLabel: formatRate(retirementTaxRate),
        breakEvenLabel: formatRate(clampedBreakEven),
        distanceLabel: formatRate(Math.abs(breakEvenDistance)),
        interpretation: Math.abs(breakEvenDistance) < 0.005
          ? "Very sensitive: a small tax-rate change can flip the modeled result."
          : breakEvenDistance > 0
            ? "Above break-even: this tax-rate input leans Roth in the model."
            : "Below break-even: this tax-rate input leans Traditional in the model."
      }
    },
    stats: [
      { label: "Roth after-tax estimate", value: formatUSD(rothAfterTax) },
      { label: "Traditional after-tax estimate", value: formatUSD(traditionalAfterTax) },
      { label: "Roth annual deposit", value: formatUSD(rothContribution) },
      { label: "Traditional annual deposit", value: formatUSD(traditionalContribution) }
    ],
    comparison: [
      { label: "Roth", value: rothAfterTax, display: formatUSD(rothAfterTax), accent: "roth" },
      { label: "Traditional", value: traditionalAfterTax, display: formatUSD(traditionalAfterTax), accent: "traditional" }
    ],
    warnings,
    assumptions: [
      `2026 IRA limit used: ${formatUSD(limit)} for age ${wholeAge}.`,
      `Annual return of ${formatRate(annualRate)} for ${years} year${years === 1 ? "" : "s"}, with end-of-year deposits.`,
      `Current federal tax rate entered: ${formatRate(currentTaxRate)}. Retirement federal tax rate entered: ${formatRate(retirementTaxRate)}.`,
      "Roth withdrawals are treated as qualified and tax-free; traditional withdrawals are reduced by the entered retirement tax rate.",
      "Federal-only educational model. It excludes state tax, penalties, RMD strategy, backdoor Roth rules, taxable side accounts, investment fees, and volatility."
    ],
    table: { caption: "Estimated after-tax value by year", columns: ["Year", "Roth", "Traditional"], rows }
  };
}

export function contributionLimit({ accountType, age }) {
  const wholeAge = Math.floor(age);
  let label = "";
  let base = 0;
  let catchUp = 0;
  let caution = "";
  if (accountType === "ira") {
    label = "IRA contribution limit";
    base = 7500;
    catchUp = wholeAge >= 50 ? 1100 : 0;
    caution = "Eligibility, compensation, deduction limits, and Roth phaseouts are separate rules.";
  } else if (accountType === "workplace") {
    label = "401(k), 403(b), governmental 457, or TSP elective-deferral limit";
    base = 24500;
    catchUp = wholeAge >= 60 && wholeAge <= 63 ? 11250 : wholeAge >= 50 ? 8000 : 0;
    caution = "Plan documents and employer rules can narrow what is actually available.";
  } else if (accountType === "simple") {
    label = "SIMPLE IRA salary-reduction limit";
    base = 17000;
    catchUp = wholeAge >= 60 && wholeAge <= 63 ? 5250 : wholeAge >= 50 ? 4000 : 0;
    caution = "Certain applicable SIMPLE plans have specialized higher limits; this tool does not treat them as universal.";
  } else {
    fail("Choose a supported account type.");
  }
  return {
    headline: { label, value: formatUSD(base + catchUp) },
    stats: [{ label: "Base 2026 limit", value: formatUSD(base) }, { label: "Age-based catch-up", value: formatUSD(catchUp) }, { label: "Age entered", value: String(wholeAge) }],
    assumptions: ["Effective year 2026. United States federal educational summary.", caution, "This is not an eligibility, deduction, plan-document, or tax-advice determination."]
  };
}

export const CALCULATORS = [
  { slug: "contribution-growth", name: "Steady saving projection", blurb: "Project monthly saving in future dollars and today's dollars.", fields: [
    { id: "startingAmount", label: "Starting amount", kind: "dollars", optional: true, defaultValue: "1000", step: "100" },
    { id: "monthlyContribution", label: "Monthly contribution", kind: "dollars", optional: true, defaultValue: "250", step: "25" },
    { id: "annualRate", label: "Nominal annual return", kind: "percent", min: -25, max: 25, defaultValue: "5", step: "0.1", suffix: "%" },
    { id: "years", label: "Years", kind: "whole", min: 1, max: 60, defaultValue: "20" },
    { id: "timing", label: "Contribution timing", kind: "choice", defaultValue: "end", options: [{ value: "end", label: "End of month" }, { value: "beginning", label: "Beginning of month" }] },
    { id: "inflation", label: "Inflation assumption", kind: "percent", min: 0, max: 15, defaultValue: "2.5", step: "0.1", suffix: "%" }
  ], compute: contributionGrowth },
  { slug: "compound-growth", name: "Compound growth", blurb: "One amount left alone under a chosen compounding frequency.", fields: [
    { id: "presentValue", label: "Starting amount", kind: "dollars", defaultValue: "5000", step: "100" },
    { id: "annualRate", label: "Nominal annual rate", kind: "percent", min: -25, max: 25, defaultValue: "4", step: "0.1", suffix: "%" },
    { id: "years", label: "Years", kind: "whole", min: 1, max: 60, defaultValue: "15" },
    { id: "frequency", label: "Compounding frequency", kind: "choice", defaultValue: "monthly", options: FREQUENCIES.map(({ value, label }) => ({ value, label })) }
  ], compute: compoundGrowth },
  { slug: "debt-payoff", name: "Debt payoff", blurb: "See whether a payment beats interest and when the balance reaches zero.", fields: [
    { id: "balance", label: "Balance owed", kind: "dollars", defaultValue: "6000", step: "100" },
    { id: "apr", label: "APR", kind: "percent", min: 0, max: 100, defaultValue: "21", step: "0.1", suffix: "%" },
    { id: "monthlyPayment", label: "Monthly payment", kind: "dollars", defaultValue: "250", step: "10" }
  ], compute: debtPayoff },
  { slug: "roth-traditional-lab", name: "Roth vs Traditional Decision Lab", blurb: "Compare tax-now and tax-later IRA assumptions with phaseout warnings.", presets: [
    { label: "Early career", values: { annualAmount: "5000", age: "27", years: "35", annualRate: "6", currentTaxRate: "12", retirementTaxRate: "22", comparisonMode: "same-budget", filingStatus: "single", workplaceCoverage: "self", modifiedAgi: "65000" } },
    { label: "High earner", values: { annualAmount: "7500", age: "42", years: "23", annualRate: "5", currentTaxRate: "32", retirementTaxRate: "24", comparisonMode: "same-budget", filingStatus: "mfj", workplaceCoverage: "self", modifiedAgi: "260000" } },
    { label: "Near retirement", values: { annualAmount: "8600", age: "56", years: "9", annualRate: "4", currentTaxRate: "24", retirementTaxRate: "18", comparisonMode: "same-contribution", filingStatus: "mfj", workplaceCoverage: "none", modifiedAgi: "150000" } }
  ], fields: [
    { id: "annualAmount", label: "Annual comparison amount", kind: "dollars", defaultValue: "7500", step: "100" },
    { id: "age", label: "Age at year end", kind: "whole", min: 0, max: 120, defaultValue: "35" },
    { id: "years", label: "Years invested", kind: "whole", min: 1, max: 60, defaultValue: "25" },
    { id: "annualRate", label: "Nominal annual return", kind: "percent", min: -25, max: 25, defaultValue: "5", step: "0.1", suffix: "%" },
    { id: "currentTaxRate", label: "Current federal tax rate", kind: "percent", min: 0, max: 60, defaultValue: "22", step: "0.1", suffix: "%" },
    { id: "retirementTaxRate", label: "Retirement federal tax rate", kind: "percent", min: 0, max: 60, defaultValue: "22", step: "0.1", suffix: "%" },
    { id: "comparisonMode", label: "Comparison mode", kind: "choice", defaultValue: "same-budget", options: [{ value: "same-budget", label: "Same pre-tax savings budget" }, { value: "same-contribution", label: "Same IRA deposit" }] },
    { id: "filingStatus", label: "Filing status", kind: "choice", defaultValue: "single", options: [{ value: "single", label: "Single" }, { value: "head", label: "Head of household" }, { value: "mfj", label: "Married filing jointly" }, { value: "mfs", label: "Married filing separately" }] },
    { id: "workplaceCoverage", label: "Workplace plan coverage", kind: "choice", defaultValue: "self", options: [{ value: "self", label: "Contributor covered at work" }, { value: "spouse", label: "Only spouse covered at work" }, { value: "none", label: "Neither spouse covered at work" }] },
    { id: "modifiedAgi", label: "Modified AGI", kind: "dollars", defaultValue: "140000", step: "1000" }
  ], compute: rothTraditionalDecision },
  { slug: "todays-dollars", name: "Today's dollars", blurb: "Restate a future amount in current purchasing power.", fields: [
    { id: "futureAmount", label: "Future amount", kind: "dollars", defaultValue: "500000", step: "1000" },
    { id: "inflation", label: "Inflation assumption", kind: "percent", min: 0, max: 25, defaultValue: "2.5", step: "0.1", suffix: "%" },
    { id: "years", label: "Years from now", kind: "whole", min: 1, max: 60, defaultValue: "25" }
  ], compute: todaysDollars },
  { slug: "real-return", name: "Real return", blurb: "Convert nominal return into inflation-adjusted return.", fields: [
    { id: "nominalRate", label: "Nominal annual return", kind: "percent", min: -50, max: 50, defaultValue: "6", step: "0.1", suffix: "%" },
    { id: "inflation", label: "Inflation", kind: "percent", min: -5, max: 25, defaultValue: "3", step: "0.1", suffix: "%" }
  ], compute: realReturn },
  { slug: "present-value", name: "Present value", blurb: "Estimate what a future amount is worth today.", fields: [
    { id: "futureAmount", label: "Future amount", kind: "dollars", defaultValue: "10000", step: "500" },
    { id: "annualRate", label: "Annual discount rate", kind: "percent", min: -25, max: 25, defaultValue: "4", step: "0.1", suffix: "%" },
    { id: "years", label: "Years until received", kind: "whole", min: 1, max: 60, defaultValue: "10" }
  ], compute: presentValue },
  { slug: "effective-rate", name: "Effective annual rate", blurb: "Turn a stated APR into the annual rate after compounding.", fields: [
    { id: "apr", label: "Stated APR", kind: "percent", min: 0, max: 100, defaultValue: "18", step: "0.1", suffix: "%" },
    { id: "frequency", label: "Compounding frequency", kind: "choice", defaultValue: "daily", options: FREQUENCIES.map(({ value, label }) => ({ value, label })) }
  ], compute: effectiveAnnualRate },
  { slug: "limit-helper", name: "2026 contribution limit helper", blurb: "Show source-labeled headline limits by account type and age.", fields: [
    { id: "accountType", label: "Account type", kind: "choice", defaultValue: "ira", options: [{ value: "ira", label: "IRA" }, { value: "workplace", label: "401(k), 403(b), governmental 457, or TSP" }, { value: "simple", label: "SIMPLE IRA" }] },
    { id: "age", label: "Age at year end", kind: "whole", min: 0, max: 120, defaultValue: "35" }
  ], compute: contributionLimit }
];

export function getCalculator(slug) {
  const found = CALCULATORS.find((item) => item.slug === slug);
  if (!found) throw new Error(`Unknown calculator: ${slug}`);
  return found;
}

export function runCalculator(slug, rawValues) {
  const definition = getCalculator(slug);
  const values = {};
  for (const field of definition.fields) values[field.id] = readField(rawValues[field.id], field);
  return definition.compute(values);
}
