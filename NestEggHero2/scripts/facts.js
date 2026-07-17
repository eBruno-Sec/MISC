// Fact registry. Implements the content fact record template: every changing
// financial figure shown anywhere in the app must resolve through a record
// here, carrying value, effective year, jurisdiction, authority status,
// primary source, retrieval date, reviewer, and next-review date.
// A fact whose status is draft, expired, or disputed cannot be published.

export const REVIEWED_AT = "2026-07-16";
export const NEXT_REVIEW_AT = "2027-01-15";
const REVIEWER = "NestEggHero fact-check package 2026-07-16";

const SOURCES = {
  irsNews2026: {
    title: "IRS: 401(k) limit increases to $24,500 for 2026; IRA limit increases to $7,500",
    url: "https://www.irs.gov/newsroom/401k-limit-increases-to-24500-for-2026-ira-limit-increases-to-7500"
  },
  irsCola: {
    title: "IRS: COLA increases for dollar limitations on benefits and contributions",
    url: "https://www.irs.gov/retirement-plans/cola-increases-for-dollar-limitations-on-benefits-and-contributions"
  },
  irsIrb2549: {
    title: "IRS Internal Revenue Bulletin 2025-49",
    url: "https://www.irs.gov/irb/2025-49_IRB"
  },
  irsPub590a: {
    title: "IRS Publication 590-A",
    url: "https://www.irs.gov/publications/p590a"
  },
  irsRmdFaq: {
    title: "IRS: Retirement plan and IRA required minimum distributions FAQs",
    url: "https://www.irs.gov/retirement-plans/retirement-plan-and-ira-required-minimum-distributions-faqs"
  },
  irsRmdTopics: {
    title: "IRS: Retirement topics, required minimum distributions",
    url: "https://www.irs.gov/retirement-plans/plan-participant-employee/retirement-topics-required-minimum-distributions-rmds"
  },
  irsSep: {
    title: "IRS: SEP contribution limits",
    url: "https://www.irs.gov/retirement-plans/plan-participant-employee/sep-contribution-limits-including-grandfathered-sarseps"
  },
  irsSimple: {
    title: "IRS: SIMPLE IRA contribution limits",
    url: "https://www.irs.gov/retirement-plans/plan-participant-employee/retirement-topics-simple-ira-contribution-limits"
  },
  ssaCola2026: {
    title: "SSA: 2026 Social Security changes fact sheet",
    url: "https://www.ssa.gov/cola/factsheets/2026.html"
  },
  ssaWageBase: {
    title: "SSA: Contribution and benefit base determination",
    url: "https://www.ssa.gov/OACT/cola/cbbdet.html"
  },
  irsTrumpNews: {
    title: "IRS: Taxpayers can now view and submit Trump Account elections",
    url: "https://www.irs.gov/newsroom/taxpayers-can-now-view-and-submit-trump-account-elections-in-their-irs-individual-account"
  },
  irsIrb2613: {
    title: "IRS Internal Revenue Bulletin 2026-13 (REG-117270-25)",
    url: "https://www.irs.gov/irb/2026-13_IRB"
  },
  irsIrb2629: {
    title: "IRS Internal Revenue Bulletin 2026-29 (Rev. Proc. 2026-25)",
    url: "https://www.irs.gov/irb/2026-29_irb"
  }
};

function record(factId, claim, value, display, source, extra = {}) {
  return {
    factId,
    claim,
    value,
    display,
    effectiveYear: 2026,
    jurisdiction: "United States federal",
    authorityStatus: "final",
    sourceTitle: SOURCES[source].title,
    sourceUrl: SOURCES[source].url,
    retrievedAt: REVIEWED_AT,
    reviewedBy: REVIEWER,
    reviewedAt: REVIEWED_AT,
    nextReviewAt: NEXT_REVIEW_AT,
    status: "verified",
    notes: "",
    ...extra
  };
}

const RECORDS = [
  // Contribution limits
  record("ira-limit", "IRA contribution limit", 7500, "$7,500", "irsNews2026"),
  record("ira-catchup-50", "IRA age-50+ catch-up", 1100, "$1,100", "irsNews2026"),
  record("ira-total-50", "IRA total for an eligible person age 50 or older", 8600, "$8,600", "irsNews2026", {
    notes: "Subject to compensation and other rules."
  }),
  record("deferral-limit", "401(k), 403(b), governmental 457, and TSP elective-deferral limit", 24500, "$24,500", "irsNews2026"),
  record("deferral-catchup-50", "General age-50+ catch-up for workplace plans", 8000, "$8,000", "irsNews2026"),
  record("deferral-catchup-60", "Higher catch-up at ages 60 to 63 for workplace plans", 11250, "$11,250", "irsNews2026", {
    notes: "Applies where the plan permits it."
  }),
  record("annual-additions", "Defined-contribution annual-additions limit", 72000, "$72,000", "irsCola", {
    notes: "Excludes catch-up contributions."
  }),
  record("comp-limit", "Compensation limit for plan purposes", 360000, "$360,000", "irsCola"),
  record("sep-max", "SEP maximum contribution", 72000, "$72,000", "irsSep", {
    notes: "Generally the lesser of the percentage limit or this cap. SEP plans generally do not permit employee elective deferrals."
  }),
  record("simple-limit", "SIMPLE general salary-reduction limit", 17000, "$17,000", "irsSimple"),
  record("simple-catchup-50", "SIMPLE general age-50+ catch-up", 4000, "$4,000", "irsSimple"),
  record("simple-catchup-60", "SIMPLE higher catch-up at ages 60 to 63", 5250, "$5,250", "irsSimple", {
    notes: "Certain applicable SIMPLE plans have specialized higher limits. Do not present $18,100 as universal."
  }),

  // Traditional IRA deduction phaseouts (contributor covered unless stated)
  record("trad-phaseout-single", "Traditional IRA deduction phaseout, single or head of household, covered by a workplace plan", [81000, 91000], "$81,000 to $91,000", "irsNews2026"),
  record("trad-phaseout-mfj", "Traditional IRA deduction phaseout, married filing jointly, contributing spouse covered", [129000, 149000], "$129,000 to $149,000", "irsNews2026"),
  record("trad-phaseout-spouse", "Traditional IRA deduction phaseout, contributor not covered but spouse covered", [242000, 252000], "$242,000 to $252,000", "irsNews2026"),
  record("trad-phaseout-mfs", "Traditional IRA deduction phaseout, married filing separately and covered", [0, 10000], "$0 to $10,000", "irsPub590a"),

  // Roth IRA contribution phaseouts
  record("roth-phaseout-single", "Roth IRA contribution phaseout, single or head of household", [153000, 168000], "$153,000 to $168,000", "irsNews2026"),
  record("roth-phaseout-mfj", "Roth IRA contribution phaseout, married filing jointly", [242000, 252000], "$242,000 to $252,000", "irsNews2026"),
  record("roth-phaseout-mfs", "Roth IRA contribution phaseout, married filing separately when spouses lived together", [0, 10000], "$0 to $10,000", "irsPub590a"),

  // Saver's Credit income limits
  record("savers-mfj", "Saver's Credit income limit, married filing jointly", 80500, "$80,500", "irsNews2026"),
  record("savers-hoh", "Saver's Credit income limit, head of household", 60375, "$60,375", "irsNews2026"),
  record("savers-single", "Saver's Credit income limit, single or married filing separately", 40250, "$40,250", "irsNews2026"),

  // RMD rules
  record("rmd-age", "General RMD beginning age for traditional, SEP, and SIMPLE IRAs and most covered plans", 73, "age 73", "irsRmdFaq"),

  // Social Security
  record("ssa-cola", "Social Security cost-of-living adjustment for 2026", 2.8, "2.8%", "ssaCola2026"),
  record("ssa-wage-base", "OASDI contribution and benefit base for 2026", 184500, "$184,500", "ssaWageBase"),
  record("ssa-employee-rate", "Employee combined Social Security and Medicare withholding rate shown by SSA", 7.65, "7.65%", "ssaCola2026"),
  record("ssa-self-employed-rate", "Self-employed combined rate shown by SSA", 15.3, "15.30%", "ssaCola2026"),
  record("ssa-oasdi-rate", "OASDI component rate up to the taxable maximum", 6.2, "6.2%", "ssaCola2026"),

  // Trump Accounts: authority status matters more than any number here.
  record("ta-law", "Section 530A was added to the Internal Revenue Code by Public Law 119-21", null, "Enacted law", "irsTrumpNews", {
    authorityStatus: "enacted law"
  }),
  record("ta-operations", "The IRS announced electronic Form 4547 election features in May 2026", null, "IRS operations", "irsTrumpNews", {
    authorityStatus: "agency operations"
  }),
  record("ta-proposed", "REG-117270-25 is proposed guidance, not a final regulation", null, "Proposed regulations", "irsIrb2613", {
    authorityStatus: "proposed regulations"
  }),
  record("ta-revproc", "Revenue Procedure 2026-25 provides a transfer-tax safe harbor for certain contributions", null, "Later guidance", "irsIrb2629", {
    authorityStatus: "revenue procedure"
  })
];

const REGISTRY = new Map(RECORDS.map((entry) => [entry.factId, entry]));

const PUBLISHABLE = new Set(["verified"]);

export function getFact(factId) {
  const fact = REGISTRY.get(factId);
  if (!fact) {
    throw new Error(`Unknown fact id: ${factId}`);
  }
  if (!PUBLISHABLE.has(fact.status)) {
    throw new Error(`Fact ${factId} has status "${fact.status}" and cannot be published.`);
  }
  return fact;
}

export function allFacts() {
  return RECORDS.slice();
}

export function factSources(factIds) {
  const seen = new Map();
  for (const id of factIds) {
    const fact = getFact(id);
    if (!seen.has(fact.sourceUrl)) {
      seen.set(fact.sourceUrl, { title: fact.sourceTitle, url: fact.sourceUrl });
    }
  }
  return Array.from(seen.values());
}
