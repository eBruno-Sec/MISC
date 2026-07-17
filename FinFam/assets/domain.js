export const APP_VERSION = "0.1.0";
export const BACKUP_SCHEMA_VERSION = "1.0.0";

export const retirementFacts2026 = {
  effectiveYear: 2026,
  jurisdiction: "United States federal",
  reviewedAt: "2026-07-16",
  reviewer: "NestEggHero fact-check package",
  nextReviewDue: "2027-01-31",
  sources: [
    {
      label: "IRS 2026 retirement limits",
      url: "https://www.irs.gov/newsroom/401k-limit-increases-to-24500-for-2026-ira-limit-increases-to-7500"
    },
    {
      label: "IRS COLA dollar limitations",
      url: "https://www.irs.gov/retirement-plans/cola-increases-for-dollar-limitations-on-benefits-and-contributions"
    },
    {
      label: "IRS Internal Revenue Bulletin 2025-49",
      url: "https://www.irs.gov/irb/2025-49_IRB"
    }
  ],
  limits: [
    { key: "ira", label: "IRA contribution limit", value: 7500 },
    { key: "iraCatchUp", label: "IRA age-50+ catch-up", value: 1100 },
    { key: "workplace", label: "401(k), 403(b), governmental 457, and TSP elective deferral", value: 24500 },
    { key: "workplaceCatchUp", label: "General age-50+ catch-up for those plans", value: 8000 },
    { key: "workplaceCatchUp60", label: "Age 60-63 higher catch-up for those plans", value: 11250 },
    { key: "annualAdditions", label: "Defined-contribution annual additions limit", value: 72000 },
    { key: "sepMaximum", label: "SEP maximum contribution", value: 72000 },
    { key: "sepCompensationCap", label: "SEP compensation cap", value: 360000 },
    { key: "simple", label: "SIMPLE general salary-reduction limit", value: 17000 },
    { key: "simpleCatchUp", label: "SIMPLE general age-50+ catch-up", value: 4000 },
    { key: "simpleCatchUp60", label: "SIMPLE age 60-63 higher catch-up", value: 5250 }
  ]
};

export function formatMoney(value) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0
  }).format(value);
}

export function parseDollarInput(value) {
  if (value === null || value === undefined || value === "") {
    return 0;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new Error("Enter a valid dollar amount.");
  }
  if (parsed < 0) {
    throw new Error("Dollar amounts cannot be negative.");
  }
  return Math.round(parsed * 100);
}

export function parsePercentInput(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new Error("Enter a valid percentage.");
  }
  return parsed / 100;
}

export function calculateProjection(input) {
  const initialCents = parseDollarInput(input.initialAmount);
  const monthlyCents = parseDollarInput(input.monthlyContribution);
  const years = Number(input.years);
  const nominalReturn = parsePercentInput(input.nominalReturn);
  const inflation = parsePercentInput(input.inflation);
  const timing = input.timing === "beginning" ? "beginning" : "end";

  if (!Number.isInteger(years) || years < 1 || years > 60) {
    throw new Error("Years must be a whole number from 1 to 60.");
  }
  if (nominalReturn < -0.25 || nominalReturn > 0.25) {
    throw new Error("Nominal annual return must be between -25% and 25%.");
  }
  if (inflation < 0 || inflation > 0.15) {
    throw new Error("Inflation must be between 0% and 15%.");
  }
  if (initialCents === 0 && monthlyCents === 0) {
    throw new Error("Add a starting amount or a monthly contribution.");
  }

  const monthlyRate = nominalReturn / 12;
  const inflationRate = inflation;
  const yearly = [];
  let balanceCents = initialCents;
  let contributionCents = initialCents;

  for (let month = 1; month <= years * 12; month += 1) {
    if (timing === "beginning") {
      balanceCents += monthlyCents;
      contributionCents += monthlyCents;
    }

    balanceCents = balanceCents * (1 + monthlyRate);

    if (timing === "end") {
      balanceCents += monthlyCents;
      contributionCents += monthlyCents;
    }

    if (month % 12 === 0) {
      const year = month / 12;
      const nominalCents = Math.round(balanceCents);
      const realCents = Math.round(nominalCents / Math.pow(1 + inflationRate, year));
      yearly.push({
        year,
        contributionCents: Math.round(contributionCents),
        nominalCents,
        realCents
      });
    }
  }

  const last = yearly[yearly.length - 1];
  return {
    assumptions: {
      years,
      nominalReturn,
      inflation,
      timing,
      compounding: "Monthly"
    },
    totals: {
      contributionCents: last.contributionCents,
      nominalCents: last.nominalCents,
      realCents: last.realCents,
      estimatedGrowthCents: Math.max(0, last.nominalCents - last.contributionCents)
    },
    yearly
  };
}

export function contributionLimitFor(accountType, ageValue) {
  const age = Number(ageValue);
  if (!Number.isFinite(age) || age < 0 || age > 120) {
    throw new Error("Enter an age from 0 to 120.");
  }
  const wholeAge = Math.floor(age);

  if (accountType === "ira") {
    const catchUp = wholeAge >= 50 ? 1100 : 0;
    return {
      label: "IRA contribution limit",
      amount: 7500 + catchUp,
      pieces: [
        { label: "Base IRA limit", amount: 7500 },
        { label: "Age-50+ catch-up", amount: catchUp }
      ],
      caution: "Eligibility, compensation, deduction limits, and Roth phaseouts are separate questions."
    };
  }

  if (accountType === "workplace") {
    let catchUp = 0;
    if (wholeAge >= 60 && wholeAge <= 63) {
      catchUp = 11250;
    } else if (wholeAge >= 50) {
      catchUp = 8000;
    }
    return {
      label: "401(k), 403(b), governmental 457, or TSP elective deferral limit",
      amount: 24500 + catchUp,
      pieces: [
        { label: "Base employee elective-deferral limit", amount: 24500 },
        { label: wholeAge >= 60 && wholeAge <= 63 ? "Age 60-63 higher catch-up" : "General age-50+ catch-up", amount: catchUp }
      ],
      caution: "Plan documents, employer rules, and annual additions limits can affect what is actually available."
    };
  }

  if (accountType === "simple") {
    let catchUp = 0;
    if (wholeAge >= 60 && wholeAge <= 63) {
      catchUp = 5250;
    } else if (wholeAge >= 50) {
      catchUp = 4000;
    }
    return {
      label: "SIMPLE IRA salary-reduction limit",
      amount: 17000 + catchUp,
      pieces: [
        { label: "General SIMPLE salary-reduction limit", amount: 17000 },
        { label: wholeAge >= 60 && wholeAge <= 63 ? "Age 60-63 higher catch-up" : "General age-50+ catch-up", amount: catchUp }
      ],
      caution: "Certain applicable SIMPLE plans have specialized higher limits; this helper does not present those as universal."
    };
  }

  throw new Error("Choose a supported account type.");
}

export function stableStringify(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value && typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        throw new Error("Backup contains an unsafe key.");
      }
      sorted[key] = sortValue(value[key]);
    }
    return sorted;
  }
  return value;
}

export function validateBackupEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("Backup must be a JSON object.");
  }
  if (envelope.format !== "nestegghero-backup") {
    throw new Error("This is not a NestEggHero backup.");
  }
  if (typeof envelope.schemaVersion !== "string") {
    throw new Error("Backup is missing a schema version.");
  }
  const major = envelope.schemaVersion.split(".")[0];
  if (major !== "1") {
    throw new Error("This backup uses an unsupported future schema version.");
  }
  if (!envelope.exportedAt || Number.isNaN(Date.parse(envelope.exportedAt))) {
    throw new Error("Backup is missing a valid exportedAt date.");
  }
  if (typeof envelope.checksum !== "string" || envelope.checksum.length < 16) {
    throw new Error("Backup is missing a valid checksum.");
  }
  if (!envelope.payload || typeof envelope.payload !== "object" || Array.isArray(envelope.payload)) {
    throw new Error("Backup payload is missing or invalid.");
  }
  validatePayload(envelope.payload);
}

export function validatePayload(payload) {
  const allowedTopLevel = new Set(["schemaVersion", "createdAt", "updatedAt", "preferences", "progress"]);
  for (const key of Object.keys(payload)) {
    if (!allowedTopLevel.has(key)) {
      throw new Error(`Backup payload includes unsupported data: ${key}.`);
    }
  }
  if (payload.schemaVersion !== BACKUP_SCHEMA_VERSION) {
    throw new Error("Backup payload schema is not supported.");
  }
  if (!payload.preferences || typeof payload.preferences !== "object") {
    throw new Error("Backup preferences are missing.");
  }
  if (!payload.progress || typeof payload.progress !== "object") {
    throw new Error("Backup progress is missing.");
  }
}
