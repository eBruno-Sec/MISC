// Calculator engine. Pure functions only: no DOM, no storage, no fetches.
// Formulas follow the calculator specification document. Rates are nominal
// annual unless a field says otherwise, payment timing is explicit, money
// is rounded for display only, and every result is an estimate.

export function formatUSD(amount) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0
  }).format(amount);
}

export function formatRate(rate, digits = 2) {
  return `${(rate * 100).toFixed(digits)}%`;
}

export class CalculatorInputError extends Error {}

function reject(message) {
  throw new CalculatorInputError(`${message} Nothing was saved; adjust the value and try again.`);
}

function readDollars(raw, field) {
  if (raw === "" || raw === null || raw === undefined) {
    if (field.optional) {
      return 0;
    }
    reject(`${field.label} is required.`);
  }
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    reject(`${field.label} must be a number.`);
  }
  if (value < 0) {
    reject(`${field.label} cannot be negative.`);
  }
  if (value > 100_000_000) {
    reject(`${field.label} is capped at $100,000,000 in this educational tool.`);
  }
  return value;
}

function readPercent(raw, field) {
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    reject(`${field.label} must be a number.`);
  }
  if (value < field.min || value > field.max) {
    reject(`${field.label} must be between ${field.min}% and ${field.max}%.`);
  }
  return value / 100;
}

function readWhole(raw, field) {
  const value = Number(raw);
  if (!Number.isInteger(value) || value < field.min || value > field.max) {
    reject(`${field.label} must be a whole number from ${field.min} to ${field.max}.`);
  }
  return value;
}

function readChoice(raw, field) {
  const match = field.options.find((option) => option.value === raw);
  if (!match) {
    reject(`Choose a value for ${field.label}.`);
  }
  return match.value;
}

export function readField(raw, field) {
  switch (field.kind) {
    case "dollars":
      return readDollars(raw, field);
    case "percent":
      return readPercent(raw, field);
    case "whole":
      return readWhole(raw, field);
    case "choice":
      return readChoice(raw, field);
    default:
      reject(`Unsupported field: ${field.label}.`);
  }
}

const FREQUENCIES = [
  { value: "annual", label: "Once a year", n: 1 },
  { value: "quarterly", label: "Quarterly", n: 4 },
  { value: "monthly", label: "Monthly", n: 12 },
  { value: "daily", label: "Daily (365)", n: 365 }
];

function frequencyCount(value) {
  return FREQUENCIES.find((item) => item.value === value).n;
}

// FV = PV x (1 + r/n)^(n x t), with a zero-rate branch.
export function compoundGrowth({ presentValue, annualRate, years, frequency }) {
  const n = frequencyCount(frequency);
  const perYear = (year) => (annualRate === 0 ? presentValue : presentValue * Math.pow(1 + annualRate / n, n * year));
  const futureValue = perYear(years);
  const rows = [];
  for (let year = 1; year <= years; year += 1) {
    rows.push([String(year), formatUSD(perYear(year))]);
  }
  return {
    headline: { label: "Estimated future value", value: formatUSD(futureValue) },
    stats: [
      { label: "Starting amount", value: formatUSD(presentValue) },
      { label: "Estimated growth", value: formatUSD(futureValue - presentValue) }
    ],
    assumptions: [
      `Nominal annual rate of ${formatRate(annualRate)}, compounded ${FREQUENCIES.find((f) => f.value === frequency).label.toLowerCase()}.`,
      `No contributions, withdrawals, fees, or taxes over ${years} year${years === 1 ? "" : "s"}.`
    ],
    table: { caption: "Estimated value at each year end", columns: ["Year", "Estimated value"], rows },
    chart: { label: "Estimated value by year", points: Array.from({ length: years }, (_, i) => perYear(i + 1)) }
  };
}

// FV = PMT x (((1 + i)^N - 1) / i), times (1 + i) for beginning-of-period
// payments, plus compound growth of any starting amount.
export function contributionGrowth({ startingAmount, monthlyContribution, annualRate, years, timing, inflation }) {
  if (startingAmount === 0 && monthlyContribution === 0) {
    reject("Add a starting amount or a monthly contribution.");
  }
  const i = annualRate / 12;
  const valueAt = (months) => {
    const base = i === 0 ? startingAmount : startingAmount * Math.pow(1 + i, months);
    let stream = i === 0 ? monthlyContribution * months : monthlyContribution * ((Math.pow(1 + i, months) - 1) / i);
    if (timing === "beginning" && i !== 0) {
      stream *= 1 + i;
    }
    return base + stream;
  };
  const rows = [];
  const points = [];
  for (let year = 1; year <= years; year += 1) {
    const nominal = valueAt(year * 12);
    const real = nominal / Math.pow(1 + inflation, year);
    const contributed = startingAmount + monthlyContribution * year * 12;
    rows.push([String(year), formatUSD(contributed), formatUSD(nominal), formatUSD(real)]);
    points.push(nominal);
  }
  const nominalEnd = valueAt(years * 12);
  const contributedEnd = startingAmount + monthlyContribution * years * 12;
  return {
    headline: { label: "Estimated ending balance", value: formatUSD(nominalEnd) },
    stats: [
      { label: "Total contributed", value: formatUSD(contributedEnd) },
      { label: "Estimated growth", value: formatUSD(Math.max(0, nominalEnd - contributedEnd)) },
      { label: "In today's dollars", value: formatUSD(nominalEnd / Math.pow(1 + inflation, years)) }
    ],
    assumptions: [
      `Nominal annual return of ${formatRate(annualRate)}, compounded monthly.`,
      `Contributions of ${formatUSD(monthlyContribution)} at the ${timing} of each month, never missed, for ${years} years.`,
      `Inflation of ${formatRate(inflation)} used only to restate results in today's dollars.`,
      "No fees, taxes, employer matching, or contribution-limit checks."
    ],
    table: {
      caption: "Estimated year-end balances",
      columns: ["Year", "Contributed", "Nominal estimate", "Today's dollars"],
      rows
    },
    chart: { label: "Estimated nominal balance by year", points }
  };
}

// PV = FV / (1 + r)^t
export function presentValue({ futureAmount, annualRate, years }) {
  if (annualRate <= -1) {
    reject("The discount rate must be above -100%.");
  }
  const pv = annualRate === 0 ? futureAmount : futureAmount / Math.pow(1 + annualRate, years);
  return {
    headline: { label: "Estimated value today", value: formatUSD(pv) },
    stats: [
      { label: "Future amount", value: formatUSD(futureAmount) },
      { label: "Discount applied", value: formatUSD(futureAmount - pv) }
    ],
    assumptions: [
      `A single amount received ${years} year${years === 1 ? "" : "s"} from now.`,
      `A constant annual discount rate of ${formatRate(annualRate)}.`
    ]
  };
}

// realReturn = ((1 + nominal) / (1 + inflation)) - 1
export function realReturn({ nominalRate, inflation }) {
  const exact = (1 + nominalRate) / (1 + inflation) - 1;
  const shortcut = nominalRate - inflation;
  return {
    headline: { label: "Estimated real annual return", value: formatRate(exact) },
    stats: [
      { label: "Nominal return", value: formatRate(nominalRate) },
      { label: "Inflation assumption", value: formatRate(inflation) },
      { label: "Simple subtraction shortcut", value: formatRate(shortcut) }
    ],
    assumptions: [
      "Both rates are annual and apply over the same period.",
      "The exact formula divides growth by inflation; subtracting the rates is only an approximation."
    ]
  };
}

// realFV = nominalFV / (1 + inflation)^t
export function todaysDollars({ futureAmount, inflation, years }) {
  const real = futureAmount / Math.pow(1 + inflation, years);
  return {
    headline: { label: "Estimated purchasing power today", value: formatUSD(real) },
    stats: [
      { label: "Future nominal amount", value: formatUSD(futureAmount) },
      { label: "Purchasing power eroded", value: formatUSD(futureAmount - real) }
    ],
    assumptions: [
      `Inflation of ${formatRate(inflation)} every year for ${years} year${years === 1 ? "" : "s"}.`,
      "Actual inflation varies year to year and by what you buy."
    ]
  };
}

// EAR = (1 + APR/n)^n - 1
export function effectiveAnnualRate({ apr, frequency }) {
  const n = frequencyCount(frequency);
  const ear = apr === 0 ? 0 : Math.pow(1 + apr / n, n) - 1;
  return {
    headline: { label: "Effective annual rate", value: formatRate(ear, 3) },
    stats: [
      { label: "Stated APR", value: formatRate(apr, 3) },
      { label: "Difference from APR", value: formatRate(ear - apr, 3) }
    ],
    assumptions: [
      `Interest compounds ${FREQUENCIES.find((f) => f.value === frequency).label.toLowerCase()} and is never paid down mid-year.`,
      "Fees and balance changes are outside this comparison."
    ]
  };
}

// Interest accrues per compounding period, then the payment applies.
// Scenarios where the payment does not beat accrued interest are rejected.
export function debtPayoff({ balance, apr, monthlyPayment }) {
  const monthlyRate = apr / 12;
  const firstInterest = balance * monthlyRate;
  if (monthlyPayment <= firstInterest) {
    reject(
      `The first month accrues about ${formatUSD(firstInterest)} in interest, so a payment of ${formatUSD(monthlyPayment)} never reduces the balance.`
    );
  }
  // Money loop runs in integer cents so no fractional cent ever compounds.
  let remaining = Math.round(balance * 100);
  const payment = Math.round(monthlyPayment * 100);
  let interestTotal = 0;
  let months = 0;
  const rows = [];
  const points = [];
  while (remaining > 0) {
    months += 1;
    if (months > 600) {
      reject("This plan takes longer than 50 years to finish, which is outside this tool's range.");
    }
    const interest = Math.round(remaining * monthlyRate);
    interestTotal += interest;
    remaining = Math.max(0, remaining + interest - payment);
    if (months % 12 === 0 || remaining === 0) {
      rows.push([
        `Month ${months}`,
        formatUSD(interestTotal / 100),
        formatUSD(remaining / 100)
      ]);
    }
    points.push(remaining / 100);
  }
  const yearsPart = Math.floor(months / 12);
  const monthsPart = months % 12;
  const duration = [
    yearsPart > 0 ? `${yearsPart} year${yearsPart === 1 ? "" : "s"}` : "",
    monthsPart > 0 ? `${monthsPart} month${monthsPart === 1 ? "" : "s"}` : ""
  ].filter(Boolean).join(", ");
  return {
    headline: { label: "Estimated time to payoff", value: duration || "Under a month" },
    stats: [
      { label: "Total interest paid", value: formatUSD(interestTotal / 100) },
      { label: "Total paid", value: formatUSD((Math.round(balance * 100) + interestTotal) / 100) },
      { label: "Payments made", value: String(months) }
    ],
    assumptions: [
      `A fixed APR of ${formatRate(apr)} compounding monthly, with the payment applied after interest.`,
      "No new charges, fee changes, or missed payments."
    ],
    table: { caption: "Estimated balance at each year of payoff", columns: ["Point", "Interest so far", "Balance left"], rows },
    chart: { label: "Estimated balance remaining by month", points }
  };
}

export const CALCULATORS = [
  {
    slug: "contribution-growth",
    name: "Steady saving projection",
    icon: "M4 19h16M6 16V9m4 7V6m4 10v-6m4 6V4",
    blurb: "See how a monthly amount could grow, in both future dollars and today's dollars.",
    kidBlurb: "Watch what happens when you keep adding a little money every month.",
    fields: [
      { id: "startingAmount", label: "Starting amount", kind: "dollars", optional: true, defaultValue: "1000", step: "100" },
      { id: "monthlyContribution", label: "Monthly contribution", kind: "dollars", optional: true, defaultValue: "200", step: "25" },
      { id: "annualRate", label: "Nominal annual return", kind: "percent", min: -25, max: 25, defaultValue: "5", step: "0.1", suffix: "%" },
      { id: "years", label: "Years of saving", kind: "whole", min: 1, max: 60, defaultValue: "20" },
      {
        id: "timing",
        label: "When each contribution happens",
        kind: "choice",
        defaultValue: "end",
        options: [
          { value: "end", label: "End of the month" },
          { value: "beginning", label: "Beginning of the month" }
        ]
      },
      { id: "inflation", label: "Inflation assumption", kind: "percent", min: 0, max: 15, defaultValue: "2.5", step: "0.1", suffix: "%" }
    ],
    scenarios: [
      { label: "First job, $100 a month", values: { startingAmount: "0", monthlyContribution: "100", annualRate: "5", years: "30", timing: "end", inflation: "2.5" } },
      { label: "Catch-up decade", values: { startingAmount: "20000", monthlyContribution: "800", annualRate: "4.5", years: "10", timing: "beginning", inflation: "2.5" } }
    ],
    compute: contributionGrowth
  },
  {
    slug: "compound-growth",
    name: "Compound growth",
    icon: "M4 20L20 4m0 0h-6m6 0v6",
    blurb: "One amount, left alone: what compounding at different frequencies does to it.",
    kidBlurb: "See how money can grow by itself when you leave it planted.",
    fields: [
      { id: "presentValue", label: "Starting amount", kind: "dollars", defaultValue: "5000", step: "100" },
      { id: "annualRate", label: "Nominal annual rate", kind: "percent", min: -25, max: 25, defaultValue: "4", step: "0.1", suffix: "%" },
      { id: "years", label: "Years", kind: "whole", min: 1, max: 60, defaultValue: "15" },
      {
        id: "frequency",
        label: "Compounding frequency",
        kind: "choice",
        defaultValue: "monthly",
        options: [
          { value: "annual", label: "Once a year" },
          { value: "quarterly", label: "Quarterly" },
          { value: "monthly", label: "Monthly" },
          { value: "daily", label: "Daily (365)" }
        ]
      }
    ],
    scenarios: [
      { label: "A $1,000 gift, 18 years", values: { presentValue: "1000", annualRate: "5", years: "18", frequency: "monthly" } }
    ],
    compute: compoundGrowth
  },
  {
    slug: "debt-payoff",
    name: "Debt payoff",
    icon: "M12 3v18m-7-5c2 2 12 2 14 0M5 8c2-2 12-2 14 0",
    blurb: "How long a balance takes to clear, and why the payment must beat the interest.",
    kidBlurb: "Find out how long it takes to finish paying money back.",
    fields: [
      { id: "balance", label: "Balance owed", kind: "dollars", defaultValue: "6000", step: "100" },
      { id: "apr", label: "APR", kind: "percent", min: 0, max: 100, defaultValue: "21", step: "0.1", suffix: "%" },
      { id: "monthlyPayment", label: "Monthly payment", kind: "dollars", defaultValue: "250", step: "10" }
    ],
    scenarios: [
      { label: "Minimum-payment trap", values: { balance: "6000", apr: "21", monthlyPayment: "100" } },
      { label: "Aggressive payoff", values: { balance: "6000", apr: "21", monthlyPayment: "500" } }
    ],
    compute: debtPayoff
  },
  {
    slug: "todays-dollars",
    name: "Today's dollars",
    icon: "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z",
    blurb: "Restate a future amount in today's purchasing power.",
    kidBlurb: "See what future money would really buy today.",
    fields: [
      { id: "futureAmount", label: "Future amount", kind: "dollars", defaultValue: "500000", step: "1000" },
      { id: "inflation", label: "Inflation assumption", kind: "percent", min: 0, max: 25, defaultValue: "2.5", step: "0.1", suffix: "%" },
      { id: "years", label: "Years from now", kind: "whole", min: 1, max: 60, defaultValue: "25" }
    ],
    scenarios: [
      { label: "A $1M nest egg in 30 years", values: { futureAmount: "1000000", inflation: "2.5", years: "30" } }
    ],
    compute: todaysDollars
  },
  {
    slug: "real-return",
    name: "Real return",
    icon: "M3 12h18M3 12c3-4 6-6 9-6s6 2 9 6c-3 4-6 6-9 6s-6-2-9-6z",
    blurb: "What a return is worth after inflation, exactly rather than by subtraction.",
    kidBlurb: "Learn how rising prices quietly shrink what your growth can buy.",
    fields: [
      { id: "nominalRate", label: "Nominal annual return", kind: "percent", min: -50, max: 50, defaultValue: "6", step: "0.1", suffix: "%" },
      { id: "inflation", label: "Inflation assumption", kind: "percent", min: -5, max: 25, defaultValue: "3", step: "0.1", suffix: "%" }
    ],
    scenarios: [
      { label: "High inflation year", values: { nominalRate: "6", inflation: "8" } }
    ],
    compute: realReturn
  },
  {
    slug: "present-value",
    name: "Present value",
    icon: "M20 12H4m0 0l6-6m-6 6l6 6",
    blurb: "What a future amount is worth today at a chosen discount rate.",
    kidBlurb: "Money later is worth less than money now. See how much less.",
    fields: [
      { id: "futureAmount", label: "Future amount", kind: "dollars", defaultValue: "10000", step: "500" },
      { id: "annualRate", label: "Annual discount rate", kind: "percent", min: -25, max: 25, defaultValue: "4", step: "0.1", suffix: "%" },
      { id: "years", label: "Years until received", kind: "whole", min: 1, max: 60, defaultValue: "10" }
    ],
    scenarios: [
      { label: "Prize paid in 20 years", values: { futureAmount: "100000", annualRate: "5", years: "20" } }
    ],
    compute: presentValue
  },
  {
    slug: "effective-rate",
    name: "Effective annual rate",
    icon: "M9 17l-4 4V5a2 2 0 012-2h10a2 2 0 012 2v16l-4-4H9z",
    blurb: "Turn a stated APR into the rate you actually experience after compounding.",
    kidBlurb: "Two rates can look the same but cost differently. This shows the true one.",
    fields: [
      { id: "apr", label: "Stated APR", kind: "percent", min: 0, max: 100, defaultValue: "18", step: "0.1", suffix: "%" },
      {
        id: "frequency",
        label: "Compounding frequency",
        kind: "choice",
        defaultValue: "daily",
        options: [
          { value: "annual", label: "Once a year" },
          { value: "quarterly", label: "Quarterly" },
          { value: "monthly", label: "Monthly" },
          { value: "daily", label: "Daily (365)" }
        ]
      }
    ],
    scenarios: [
      { label: "Card APR, daily compounding", values: { apr: "24", frequency: "daily" } }
    ],
    compute: effectiveAnnualRate
  }
];

export function getCalculator(slug) {
  const found = CALCULATORS.find((calc) => calc.slug === slug);
  if (!found) {
    throw new Error(`Unknown calculator: ${slug}`);
  }
  return found;
}

export function runCalculator(slug, rawValues) {
  const definition = getCalculator(slug);
  const values = {};
  for (const field of definition.fields) {
    values[field.id] = readField(rawValues[field.id], field);
  }
  return definition.compute(values);
}
