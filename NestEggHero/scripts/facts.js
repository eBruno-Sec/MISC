export const REVIEWED_AT = "2026-07-16";
export const NEXT_REVIEW_AT = "2027-01-15";
const REVIEWER = "NestEggHero fact-check package 2026-07-16";

export const SOURCES = {
  irsLimits2026: {
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
    title: "IRS required minimum distribution FAQs",
    url: "https://www.irs.gov/retirement-plans/retirement-plan-and-ira-required-minimum-distributions-faqs"
  },
  irsRmdTopics: {
    title: "IRS retirement topics: required minimum distributions",
    url: "https://www.irs.gov/retirement-plans/plan-participant-employee/retirement-topics-required-minimum-distributions-rmds"
  },
  irsSep: {
    title: "IRS SEP contribution limits",
    url: "https://www.irs.gov/retirement-plans/plan-participant-employee/sep-contribution-limits-including-grandfathered-sarseps"
  },
  irsSimple: {
    title: "IRS SIMPLE IRA contribution limits",
    url: "https://www.irs.gov/retirement-plans/plan-participant-employee/retirement-topics-simple-ira-contribution-limits"
  },
  ssaCola2026: {
    title: "SSA 2026 Social Security changes fact sheet",
    url: "https://www.ssa.gov/cola/factsheets/2026.html"
  },
  ssaWageBase: {
    title: "SSA contribution and benefit base determination",
    url: "https://www.ssa.gov/OACT/cola/cbbdet.html"
  },
  trumpAccountOps: {
    title: "IRS Trump Account elections announcement",
    url: "https://www.irs.gov/newsroom/taxpayers-can-now-view-and-submit-trump-account-elections-in-their-irs-individual-account"
  },
  trumpAccountProposed: {
    title: "IRS Internal Revenue Bulletin 2026-13, proposed Trump Account regulations",
    url: "https://www.irs.gov/irb/2026-13_IRB"
  },
  trumpAccountSafeHarbor: {
    title: "IRS Internal Revenue Bulletin 2026-29, Revenue Procedure 2026-25",
    url: "https://www.irs.gov/irb/2026-29_irb"
  }
};

function fact(id, claim, value, display, sourceKey, extra = {}) {
  const source = SOURCES[sourceKey];
  return {
    id,
    claim,
    value,
    display,
    effectiveYear: 2026,
    jurisdiction: "United States federal",
    authorityStatus: "final",
    status: "verified",
    sourceTitle: source.title,
    sourceUrl: source.url,
    retrievedAt: REVIEWED_AT,
    reviewedAt: REVIEWED_AT,
    reviewedBy: REVIEWER,
    nextReviewAt: NEXT_REVIEW_AT,
    note: "",
    ...extra
  };
}

export const FACTS = [
  fact("ira-limit", "IRA contribution limit", 7500, "$7,500", "irsLimits2026"),
  fact("ira-catchup-50", "IRA age-50+ catch-up", 1100, "$1,100", "irsLimits2026"),
  fact("ira-total-50", "IRA total for an eligible person age 50 or older", 8600, "$8,600", "irsLimits2026", { note: "Subject to compensation and other eligibility rules." }),
  fact("workplace-deferral", "401(k), 403(b), governmental 457, and TSP elective-deferral limit", 24500, "$24,500", "irsLimits2026"),
  fact("workplace-catchup-50", "General age-50+ catch-up for workplace plans", 8000, "$8,000", "irsLimits2026"),
  fact("workplace-catchup-60", "Higher catch-up at ages 60 to 63 for workplace plans", 11250, "$11,250", "irsLimits2026", { note: "Applies only where the plan permits it." }),
  fact("annual-additions", "Defined-contribution annual-additions limit", 72000, "$72,000", "irsCola", { note: "Excludes catch-up contributions." }),
  fact("compensation-cap", "Relevant compensation limit", 360000, "$360,000", "irsCola"),
  fact("sep-max", "SEP maximum contribution", 72000, "$72,000", "irsSep", { note: "Generally the lesser of the applicable percentage limit or this dollar cap." }),
  fact("sep-comp-cap", "SEP compensation cap", 360000, "$360,000", "irsSep"),
  fact("simple-limit", "SIMPLE general salary-reduction limit", 17000, "$17,000", "irsSimple"),
  fact("simple-catchup-50", "SIMPLE general age-50+ catch-up", 4000, "$4,000", "irsSimple"),
  fact("simple-catchup-60", "SIMPLE age 60-63 higher catch-up", 5250, "$5,250", "irsSimple", { note: "Certain applicable SIMPLE plans have specialized higher limits; do not present $18,100 as universal." }),
  fact("trad-phaseout-single", "Traditional IRA deduction phaseout, single or head of household, covered by workplace plan", [81000, 91000], "$81,000 to $91,000", "irsLimits2026"),
  fact("trad-phaseout-mfj", "Traditional IRA deduction phaseout, married filing jointly, contributing spouse covered", [129000, 149000], "$129,000 to $149,000", "irsLimits2026"),
  fact("trad-phaseout-spouse", "Traditional IRA deduction phaseout, contributor not covered but spouse covered", [242000, 252000], "$242,000 to $252,000", "irsLimits2026"),
  fact("trad-phaseout-mfs", "Traditional IRA deduction phaseout, married filing separately and covered", [0, 10000], "$0 to $10,000", "irsPub590a"),
  fact("roth-phaseout-single", "Roth IRA contribution phaseout, single or head of household", [153000, 168000], "$153,000 to $168,000", "irsLimits2026"),
  fact("roth-phaseout-mfj", "Roth IRA contribution phaseout, married filing jointly", [242000, 252000], "$242,000 to $252,000", "irsLimits2026"),
  fact("roth-phaseout-mfs", "Roth IRA contribution phaseout, married filing separately when spouses lived together", [0, 10000], "$0 to $10,000", "irsPub590a"),
  fact("savers-mfj", "Saver's Credit income limit, married filing jointly", 80500, "$80,500", "irsLimits2026"),
  fact("savers-hoh", "Saver's Credit income limit, head of household", 60375, "$60,375", "irsLimits2026"),
  fact("savers-single", "Saver's Credit income limit, single or married filing separately", 40250, "$40,250", "irsLimits2026"),
  fact("rmd-age", "General RMD beginning age", 73, "age 73", "irsRmdFaq", { note: "Traditional, SEP, and SIMPLE IRAs and most covered retirement plans generally require RMDs from this age." }),
  fact("ssa-cola", "Social Security 2026 cost-of-living adjustment", 2.8, "2.8%", "ssaCola2026"),
  fact("ssa-wage-base", "2026 OASDI contribution and benefit base", 184500, "$184,500", "ssaWageBase"),
  fact("ssa-employee-rate", "Employee combined Social Security and Medicare withholding rate shown by SSA", 7.65, "7.65%", "ssaCola2026"),
  fact("ssa-self-employed-rate", "Self-employed combined rate shown by SSA", 15.3, "15.30%", "ssaCola2026"),
  fact("ssa-oasdi-rate", "OASDI component rate up to the taxable maximum", 6.2, "6.2%", "ssaCola2026"),
  fact("trump-law", "Section 530A was added to the Internal Revenue Code by Public Law 119-21", null, "Enacted law", "trumpAccountOps", { authorityStatus: "enacted law" }),
  fact("trump-electronic-elections", "The IRS announced electronic Form 4547 election features in May 2026", null, "IRS operations", "trumpAccountOps", { authorityStatus: "agency operations" }),
  fact("trump-proposed-regs", "REG-117270-25 is proposed guidance, not a final regulation", null, "Proposed regulations", "trumpAccountProposed", { authorityStatus: "proposed regulations" }),
  fact("trump-safe-harbor", "Revenue Procedure 2026-25 provides a transfer-tax safe harbor for certain contributions", null, "Revenue procedure", "trumpAccountSafeHarbor", { authorityStatus: "revenue procedure" })
];

const FACT_MAP = new Map(FACTS.map((item) => [item.id, item]));
const PUBLISHABLE = new Set(["verified"]);

export function getFact(id) {
  const item = FACT_MAP.get(id);
  if (!item) {
    throw new Error(`Unknown fact: ${id}`);
  }
  if (!PUBLISHABLE.has(item.status)) {
    throw new Error(`Fact ${id} is not publishable.`);
  }
  return item;
}

export function allFacts() {
  return FACTS.slice();
}

export function sourceListForFactIds(ids) {
  const sources = new Map();
  for (const id of ids) {
    const item = getFact(id);
    if (!sources.has(item.sourceUrl)) {
      sources.set(item.sourceUrl, { title: item.sourceTitle, url: item.sourceUrl });
    }
  }
  return Array.from(sources.values());
}
