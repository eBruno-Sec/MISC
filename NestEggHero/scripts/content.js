export const GLOSSARY = {
  contribution: { word: "contribution", plain: "Money added to an account, separate from growth the account earns.", kid: "Money you put in yourself." },
  "elective-deferral": { word: "elective deferral", plain: "Pay a worker chooses to send into a workplace plan instead of receiving in a paycheck.", kid: "Pay a worker asks to save before it reaches the paycheck." },
  "catch-up": { word: "catch-up contribution", plain: "Extra contribution room available at certain ages, on top of the normal limit.", kid: "Extra saving room for older savers." },
  phaseout: { word: "phaseout", plain: "An income range where a benefit shrinks gradually before disappearing.", kid: "A zone where a tax benefit fades away as income rises." },
  rmd: { word: "required minimum distribution", plain: "A minimum withdrawal required from some retirement accounts after a starting age.", kid: "Money some accounts must send out after a certain age." },
  roth: { word: "Roth", plain: "An account type funded with already-taxed money; qualified withdrawals can be tax-free.", kid: "Pay tax first, then qualifying money can come out tax-free later." },
  traditional: { word: "traditional", plain: "An account type where a deduction may come now and withdrawals are generally taxed later.", kid: "Possibly save tax now, usually pay tax when money comes out." },
  compounding: { word: "compounding", plain: "Growth earning more growth over time.", kid: "When growth starts growing too." },
  inflation: { word: "inflation", plain: "Rising prices that reduce what each dollar can buy.", kid: "Prices going up, so each dollar buys less." },
  apr: { word: "APR", plain: "Annual percentage rate before within-year compounding effects.", kid: "The advertised yearly interest rate." }
};

export const TOPICS = ["Retirement accounts", "Taxes", "Social Security", "Math concepts", "Debt"];

export const ARTICLES = [
  {
    slug: "retirement-limits-2026",
    title: "The 2026 retirement contribution limits, explained",
    topic: "Retirement accounts",
    minutes: 7,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "Final IRS figures",
    learn: ["Which limit belongs to IRAs", "Which limit belongs to workplace plans", "Why a headline limit is not a personal recommendation"],
    summary: {
      plain: "Contribution limits are annual ceilings. For 2026, an IRA limit is [[fact:ira-limit]], while the workplace elective-deferral limit is [[fact:workplace-deferral]]. Catch-up room can increase those numbers for older savers.",
      kid: "Each account has a yearly cap. In 2026, a personal IRA cap is [[fact:ira-limit]] and a work-plan cap is [[fact:workplace-deferral]]. Older savers may get extra room."
    },
    sections: [
      { id: "families", heading: "Two families of limits", paragraphs: [
        { plain: "IRAs and workplace plans are separate families. The 2026 IRA limit is [[fact:ira-limit]], plus [[fact:ira-catchup-50]] from age 50, for [[fact:ira-total-50]] when eligible.", kid: "Personal accounts and work accounts have different caps. The personal cap is [[fact:ira-limit]], with extra room from age 50." },
        { plain: "Workplace plans such as 401(k), 403(b), governmental 457, and TSP share a 2026 elective-deferral limit of [[fact:workplace-deferral]]. The general age-50 catch-up is [[fact:workplace-catchup-50]], and the age 60 to 63 tier is [[fact:workplace-catchup-60]] where the plan permits it.", kid: "Work plans have a bigger cap of [[fact:workplace-deferral]]. Older workers may get [[fact:workplace-catchup-50]] extra, or [[fact:workplace-catchup-60]] from ages 60 to 63 if the plan allows it." }
      ]},
      { id: "not-promise", heading: "The limit is not a promise", paragraphs: [
        { plain: "A limit says what the federal rule allows at the top end. It does not decide eligibility, deduction treatment, plan-document access, employer rules, or whether contributing is right for any person.", kid: "The cap is the top allowed number, not a promise that everyone can use it." }
      ]}
    ],
    example: { plain: "A 52-year-old in a plan that allows catch-up contributions could have a 2026 headline workplace total of $32,500, made from [[fact:workplace-deferral]] plus [[fact:workplace-catchup-50]].", kid: "A 52-year-old worker may be able to use the regular work-plan cap plus catch-up room." },
    activity: { kind: "calculator", slug: "limit-helper", label: "Check a source-labeled limit" },
    risks: ["Limits change by year.", "Eligibility and deduction rules are separate.", "Plan documents can be stricter than the headline federal limit."],
    takeaways: ["IRA and workplace limits are separate.", "Catch-up rules depend on age and plan terms.", "Every changing number needs an effective year and source."],
    quiz: [
      { question: "Does the IRA limit reduce the 401(k) elective-deferral limit?", options: ["Yes", "No"], answer: 1, explain: "They are separate limit families." },
      { question: "What must appear next to changing contribution limits?", options: ["A guarantee", "Effective year and source", "A countdown timer"], answer: 1, explain: "Changing financial facts need year and authority." }
    ],
    factIds: ["ira-limit", "ira-catchup-50", "ira-total-50", "workplace-deferral", "workplace-catchup-50", "workplace-catchup-60"],
    next: "roth-vs-traditional"
  },
  {
    slug: "roth-vs-traditional",
    title: "Roth vs Traditional: tax now or tax later",
    topic: "Retirement accounts",
    minutes: 8,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "General education with IRS figures",
    learn: ["How tax timing differs", "Why future tax rates matter", "Why neither type is universally best"],
    summary: { plain: "A [[term:traditional]] account can move tax later. A [[term:roth]] account generally pays tax first and may allow qualified tax-free withdrawals later. The right comparison depends on assumptions and eligibility.", kid: "One account may save tax now and pay later. The other pays first and may come out tax-free later." },
    sections: [
      { id: "tax-timing", heading: "The timing is the heart", paragraphs: [{ plain: "Traditional treatment can create a deduction today and tax later. Roth treatment gives up the current deduction and may make qualified withdrawals tax-free later.", kid: "Traditional is often tax later. Roth is often tax first." }]},
      { id: "shared-limit", heading: "One combined IRA limit", paragraphs: [{ plain: "For 2026, traditional and Roth IRAs share one combined contribution ceiling of [[fact:ira-limit]], plus [[fact:ira-catchup-50]] when age 50 or older.", kid: "You do not get a full cap for each kind. Both personal IRA kinds share one cap." }]},
      { id: "future", heading: "Unknown future rates", paragraphs: [{ plain: "The comparison often turns on whether today's tax rate or the withdrawal-year tax rate is higher. Future rates, future law, and personal income are uncertain, so this page teaches tradeoffs rather than choosing for the reader.", kid: "The question is whether tax is bigger now or later. Nobody knows that perfectly." }]}
    ],
    example: { plain: "If tax rates are identical now and later, Roth and traditional math can tie before other rules. Differences appear when tax rates, RMDs, phaseouts, and eligibility differ.", kid: "If the tax slice is the same now and later, the two choices can end up the same." },
    activity: { kind: "calculator", slug: "roth-traditional-lab", label: "Compare Roth and Traditional assumptions" },
    risks: ["This is not a recommendation.", "Roth qualified-withdrawal rules have conditions.", "State taxes are not covered here."],
    takeaways: ["The core distinction is tax timing.", "IRA contribution limits are shared across traditional and Roth IRAs.", "Future tax rates are uncertain."],
    quiz: [{ question: "Which statement is safest?", options: ["Roth is always best", "Traditional is always best", "The comparison depends on facts and assumptions"], answer: 2, explain: "Universal claims are not appropriate." }],
    factIds: ["ira-limit", "ira-catchup-50"],
    next: "ira-phaseouts-2026"
  },
  {
    slug: "ira-phaseouts-2026",
    title: "IRA phaseouts: the 2026 income tests",
    topic: "Taxes",
    minutes: 7,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "Final IRS figures",
    learn: ["What phaseouts do", "How traditional deduction tests differ from Roth contribution tests", "Why filing status matters"],
    summary: { plain: "A [[term:phaseout]] is an income range where a tax benefit shrinks. For 2026, traditional IRA deduction and Roth IRA contribution phaseouts use different ranges.", kid: "A phaseout is where a tax benefit fades as income goes up." },
    sections: [
      { id: "traditional", heading: "Traditional IRA deduction ranges", paragraphs: [{ plain: "For a covered single filer or head of household in 2026, the traditional IRA deduction phases out across [[fact:trad-phaseout-single]]. For married filing jointly with the contributing spouse covered, the range is [[fact:trad-phaseout-mfj]].", kid: "The deduction can shrink across income ranges, and the range depends on filing status." }]},
      { id: "roth", heading: "Roth contribution ranges", paragraphs: [{ plain: "For 2026, Roth IRA contributions phase out across [[fact:roth-phaseout-single]] for single or head-of-household filers and [[fact:roth-phaseout-mfj]] for married filing jointly.", kid: "Roth also has income ranges, and they are not the same as deduction ranges." }]},
      { id: "care", heading: "Never infer the answer", paragraphs: [{ plain: "NestEggHero does not infer filing status, compensation, modified adjusted gross income, or eligibility. It teaches the concept and links to official sources.", kid: "The app cannot know someone's tax form, so it does not guess." }]}
    ],
    example: { plain: "A single filer covered by a workplace plan may see a traditional IRA deduction phase out across [[fact:trad-phaseout-single]], while Roth contribution eligibility uses [[fact:roth-phaseout-single]].", kid: "The two ranges can be different even for the same person." },
    activity: { kind: "facts", label: "Open the fact registry" },
    risks: ["MAGI is not the same as salary.", "Filing status changes the range.", "State tax rules are outside this lesson."],
    takeaways: ["Phaseouts are ranges, not cliffs for every rule.", "Traditional deduction and Roth contribution tests differ.", "Never guess eligibility from one number alone."],
    quiz: [{ question: "Are contribution limits, deduction limits, and Roth eligibility the same rule?", options: ["Yes", "No"], answer: 1, explain: "They are separate concepts." }],
    factIds: ["trad-phaseout-single", "trad-phaseout-mfj", "roth-phaseout-single", "roth-phaseout-mfj"],
    next: "rmd-basics"
  },
  {
    slug: "rmd-basics",
    title: "Required minimum distributions without panic",
    topic: "Retirement accounts",
    minutes: 6,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "IRS educational summary",
    learn: ["Which accounts generally require lifetime RMDs", "How Roth treatment differs", "Why aggregation rules matter"],
    summary: { plain: "Traditional, SEP, and SIMPLE IRAs and most covered plans generally require [[term:rmd]]s beginning at [[fact:rmd-age]]. Roth IRAs and designated Roth accounts do not require lifetime RMDs from the original owner.", kid: "Some accounts must start sending money out at [[fact:rmd-age]]. Roth accounts do not force the original owner to do that during life." },
    sections: [
      { id: "start", heading: "The starting age", paragraphs: [{ plain: "The general beginning age is [[fact:rmd-age]], but plan documents, employment status, ownership status, and beneficiary rules can change details.", kid: "The general age is [[fact:rmd-age]], but details can change." }]},
      { id: "aggregate", heading: "Aggregation is not universal", paragraphs: [{ plain: "IRA RMDs are calculated separately but can generally be withdrawn in aggregate from one or more IRAs. 401(k) and 457(b) RMDs generally cannot be aggregated across plans.", kid: "Personal accounts can often be added together. Work plans usually cannot." }]}
    ],
    example: { plain: "A retiree with three traditional IRAs may calculate each amount and take the combined total from one IRA. Two old 401(k)s generally need separate withdrawals.", kid: "Three personal accounts can often be handled together; work plans usually stay separate." },
    activity: { kind: "calculator", slug: "todays-dollars", label: "Restate a future withdrawal" },
    risks: ["Beneficiary rules are different.", "Plan terms can vary.", "Missing an RMD can have tax consequences."],
    takeaways: ["RMDs are account-specific.", "Roth lifetime rules differ from traditional account rules.", "Aggregation is limited."],
    quiz: [{ question: "Can 401(k) RMDs generally be aggregated across plans?", options: ["Yes", "No"], answer: 1, explain: "401(k) and 457(b) RMDs generally cannot be aggregated across plans." }],
    factIds: ["rmd-age"],
    next: "social-security-2026"
  },
  {
    slug: "social-security-2026",
    title: "Social Security in 2026: COLA and taxable maximum",
    topic: "Social Security",
    minutes: 5,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "Final SSA figures",
    learn: ["What COLA means", "What the OASDI wage base is", "Why Medicare differs"],
    summary: { plain: "The 2026 Social Security COLA is [[fact:ssa-cola]]. The 2026 OASDI taxable maximum is [[fact:ssa-wage-base]]. SSA shows employee combined withholding of [[fact:ssa-employee-rate]] and self-employed combined rate of [[fact:ssa-self-employed-rate]].", kid: "Benefits got a [[fact:ssa-cola]] raise for 2026. The Social Security tax applies up to [[fact:ssa-wage-base]]." },
    sections: [
      { id: "cola", heading: "COLA follows prices", paragraphs: [{ plain: "The cost-of-living adjustment changes benefits to help keep pace with inflation. It can be different every year.", kid: "The yearly raise follows prices, so it changes." }]},
      { id: "taxable", heading: "The wage base", paragraphs: [{ plain: "The OASDI component rate is [[fact:ssa-oasdi-rate]] up to [[fact:ssa-wage-base]]. Medicare rules differ and are not capped the same way.", kid: "The Social Security slice stops at a cap. Medicare follows different rules." }]}
    ],
    example: { plain: "A worker earning more than [[fact:ssa-wage-base]] in 2026 pays the OASDI component only up to that base. Medicare withholding has separate rules.", kid: "Above the cap, the Social Security slice stops, but Medicare is different." },
    activity: { kind: "calculator", slug: "real-return", label: "Compare COLA against inflation" },
    risks: ["Personal benefits depend on earnings and claiming age.", "Medicare rules are separate.", "SSA figures change annually."],
    takeaways: ["The 2026 COLA is 2.8%.", "The 2026 OASDI wage base is $184,500.", "Self-employed people cover both halves."],
    quiz: [{ question: "Does the OASDI wage base also cap Medicare tax?", options: ["Yes", "No"], answer: 1, explain: "Medicare follows separate rules." }],
    factIds: ["ssa-cola", "ssa-wage-base", "ssa-employee-rate", "ssa-self-employed-rate", "ssa-oasdi-rate"],
    next: "trump-accounts-status"
  },
  {
    slug: "trump-accounts-status",
    title: "Trump Accounts: final law vs proposed guidance",
    topic: "Retirement accounts",
    minutes: 5,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "Mixed authority levels",
    learn: ["Why authority status matters", "How enacted law differs from proposed regulations", "How to read developing topics carefully"],
    summary: { plain: "For Trump Accounts, [[fact:trump-law]]. Separately, [[fact:trump-electronic-elections]]. But [[fact:trump-proposed-regs]], and [[fact:trump-safe-harbor]].", kid: "Some parts are finished law. Some instructions are still drafts and can change." },
    sections: [
      { id: "layers", heading: "Four layers", paragraphs: [{ plain: "Enacted law, IRS operations, proposed regulations, and revenue procedures carry different authority levels. NestEggHero labels them separately.", kid: "Finished law, current operations, draft rules, and special guidance are not the same thing." }]},
      { id: "careful", heading: "Why it matters", paragraphs: [{ plain: "Presenting a proposed regulation as final can lead people to act on a rule that later changes. Authority labels and review dates are required.", kid: "A draft rule can change, so it needs a label." }]}
    ],
    example: { plain: "If a claim depends on REG-117270-25, the careful label is proposed guidance, not final regulation.", kid: "If it comes from a draft, call it a draft." },
    activity: { kind: "facts", label: "Review authority labels" },
    risks: ["Proposed rules can change.", "Operational features can change independently.", "This page is not advice to open or fund an account."],
    takeaways: ["Authority labels prevent overclaiming.", "Proposed does not mean final.", "Review dates matter."],
    quiz: [{ question: "How should REG-117270-25 be described?", options: ["Final regulation", "Proposed guidance", "No authority"], answer: 1, explain: "It is proposed guidance, not final regulation." }],
    factIds: ["trump-law", "trump-electronic-elections", "trump-proposed-regs", "trump-safe-harbor"],
    next: "compounding-and-inflation"
  },
  {
    slug: "compounding-and-inflation",
    title: "Compounding builds, inflation erodes",
    topic: "Math concepts",
    minutes: 6,
    updatedAt: "2026-07-16",
    effectiveYear: null,
    authorityStatus: "Mathematical education",
    learn: ["What compounding means", "Why today's dollars matter", "How real return differs from a shortcut"],
    summary: { plain: "[[term:compounding]] makes growth build on itself. [[term:inflation]] reduces purchasing power, so projections should show both nominal dollars and today's dollars.", kid: "Money growth can grow too, but prices also rise. Both matter." },
    sections: [
      { id: "growth", heading: "Growth on growth", paragraphs: [{ plain: "The longer the timeline, the more compounding can matter. The rate matters, but time is often the quieter force.", kid: "Starting early gives growth more rounds to grow." }]},
      { id: "real", heading: "Real return", paragraphs: [{ plain: "The exact real-return formula is (1 + nominal return) divided by (1 + inflation), minus 1. Subtracting rates is only an approximation.", kid: "To check what growth really buys, use the real-return formula." }]}
    ],
    example: { plain: "$500,000 in 25 years may buy much less than $500,000 buys today if inflation persists.", kid: "A big future number can shrink when you ask what it buys." },
    activity: { kind: "calculator", slug: "compound-growth", label: "Watch compounding" },
    risks: ["Steady-rate projections hide volatility.", "Inflation is an assumption.", "No projection is a promise."],
    takeaways: ["Show assumptions beside projections.", "Pair nominal dollars with today's dollars.", "Use exact real-return math when possible."],
    quiz: [{ question: "Is a projection a promise?", options: ["Yes", "No"], answer: 1, explain: "A projection is an estimate based on assumptions." }],
    factIds: [],
    next: "debt-payoff-basics"
  },
  {
    slug: "debt-payoff-basics",
    title: "Debt payoff: the payment has to beat interest",
    topic: "Debt",
    minutes: 5,
    updatedAt: "2026-07-16",
    effectiveYear: null,
    authorityStatus: "Mathematical education",
    learn: ["Why too-small payments fail", "How APR differs from effective annual rate", "How extra payment affects time"],
    summary: { plain: "Debt compounds too. If the payment does not exceed the interest accrued for the period, the balance does not fall.", kid: "A payment has to be bigger than the month's added interest or the debt will not shrink." },
    sections: [
      { id: "threshold", heading: "Break-even is not progress", paragraphs: [{ plain: "A payment that barely covers interest keeps the balance alive. Real progress starts when the payment reaches principal after interest is added.", kid: "Paying only the new interest is like standing still." }]},
      { id: "true-rate", heading: "APR is not always the whole rate", paragraphs: [{ plain: "When interest compounds within the year, the effective annual rate can be higher than the stated APR.", kid: "The advertised rate can be lower than the real yearly cost." }]}
    ],
    example: { plain: "On a $6,000 balance at 21% APR, about $105 accrues in the first month. A $100 payment loses ground.", kid: "If the debt grows by $105 and you pay $100, it still grows." },
    activity: { kind: "calculator", slug: "debt-payoff", label: "Compare payoff plans" },
    risks: ["Real accounts can include fees.", "Rates can change.", "Emergency cash needs matter too."],
    takeaways: ["Interest accrues before the payment in this model.", "Payments must beat interest.", "EAR helps compare borrowing costs."],
    quiz: [{ question: "If monthly interest is $105 and the payment is $100, what happens?", options: ["The balance falls", "The balance rises", "The debt disappears"], answer: 1, explain: "The payment is less than the accrued interest." }],
    factIds: [],
    next: "retirement-limits-2026"
  }
];

export function getArticle(slug) {
  const found = ARTICLES.find((article) => article.slug === slug);
  if (!found) throw new Error(`Unknown article: ${slug}`);
  return found;
}
