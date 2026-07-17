// Content library. Every article follows the content style guide order:
// what you will learn, plain-language summary, core explanation, example,
// interactive activity, risks and exceptions, key takeaways, sources, next.
// Text may embed [[fact:id]] tokens, which render through the fact registry
// with an effective year and source, and [[term:slug]] tokens, which render
// as definition popovers. Kid Speak variants simplify wording but keep the
// same meaning, uncertainty, and risks.

export const GLOSSARY = {
  "contribution": {
    word: "contribution",
    plain: "Money you add to an account, as opposed to growth the account earns on its own.",
    kid: "The money you put in yourself."
  },
  "elective-deferral": {
    word: "elective deferral",
    plain: "Pay you choose to send into a workplace plan such as a 401(k) instead of receiving it in your paycheck.",
    kid: "Part of a paycheck a worker asks to have saved instead of paid out."
  },
  "catch-up": {
    word: "catch-up contribution",
    plain: "An extra contribution amount the rules allow for people age 50 and older, on top of the regular limit.",
    kid: "Extra saving room the rules give people who are 50 or older."
  },
  "phaseout": {
    word: "phaseout",
    plain: "An income range where a tax benefit shrinks gradually. Below the range you get the full benefit; above it, none.",
    kid: "A zone where a tax bonus slowly fades away as someone earns more."
  },
  "magi": {
    word: "modified adjusted gross income",
    plain: "An income figure the IRS calculates from your tax return to test eligibility for benefits. It is not the same as salary.",
    kid: "A special income number from a tax form, used to check who qualifies."
  },
  "rmd": {
    word: "required minimum distribution",
    plain: "A minimum amount the rules require to be withdrawn from certain retirement accounts each year, starting at a set age.",
    kid: "Money the rules say must come out of some retirement accounts each year after a certain age."
  },
  "cola": {
    word: "cost-of-living adjustment",
    plain: "An annual change to Social Security benefits intended to keep pace with inflation.",
    kid: "A yearly raise to benefits meant to keep up with rising prices."
  },
  "taxable-maximum": {
    word: "taxable maximum",
    plain: "The highest amount of yearly wages that the Social Security part of payroll tax applies to.",
    kid: "The cap on how much of a year's pay gets the Social Security tax."
  },
  "nominal-return": {
    word: "nominal return",
    plain: "A growth rate before subtracting the effect of inflation.",
    kid: "Growth counted in plain dollars, before checking what those dollars can still buy."
  },
  "real-return": {
    word: "real return",
    plain: "A growth rate after accounting for inflation, showing the change in what the money can actually buy.",
    kid: "Growth measured by what the money can really buy."
  },
  "inflation": {
    word: "inflation",
    plain: "The general rise in prices over time, which lowers what each dollar can buy.",
    kid: "When prices go up, so each dollar buys a little less."
  },
  "compounding": {
    word: "compounding",
    plain: "Earning growth on both the original amount and on growth already earned.",
    kid: "When your money's growth starts growing too."
  },
  "apr": {
    word: "APR",
    plain: "Annual percentage rate: the stated yearly interest rate before the effect of compounding within the year.",
    kid: "The advertised yearly interest rate."
  },
  "roth": {
    word: "Roth",
    plain: "An account type funded with money that was already taxed; qualified withdrawals later can be tax-free under the rules.",
    kid: "An account where the tax was paid first, so qualifying withdrawals later can be tax-free."
  },
  "traditional": {
    word: "traditional",
    plain: "An account type where contributions may be deductible now, growth is tax-deferred, and withdrawals in retirement are generally taxed as ordinary income.",
    kid: "An account where the tax discount can come first, and the tax gets paid when the money comes out later."
  },
  "tax-deferred": {
    word: "tax-deferred",
    plain: "Growth that is not taxed while it stays in the account; tax is due when money is withdrawn.",
    kid: "The growth is not taxed yet. The tax waits until the money comes out."
  }
};

export const TOPICS = ["Retirement accounts", "Taxes", "Social Security", "Concepts", "Debt"];

export const ARTICLES = [
  {
    slug: "retirement-limits-2026",
    title: "The 2026 retirement contribution limits, explained",
    topic: "Retirement accounts",
    minutes: 7,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "Final IRS figures",
    learn: [
      "Which limit applies to an IRA and which applies to a workplace plan",
      "How age-based catch-up amounts stack on top of base limits",
      "Why the limit on paper is not always the amount available to you"
    ],
    summary: {
      plain:
        "Each account type has its own yearly ceiling on [[term:contribution]]s. For 2026, an IRA allows [[fact:ira-limit]] and a workplace plan such as a 401(k) allows [[fact:deferral-limit]] in [[term:elective-deferral]]s. People 50 and older get extra [[term:catch-up]] room, and ages 60 to 63 can get more in workplace plans.",
      kid:
        "There are yearly caps on how much money can go into special saving accounts. In 2026, one kind of account allows [[fact:ira-limit]] and a work account allows [[fact:deferral-limit]]. Older savers are allowed to add extra."
    },
    sections: [
      {
        id: "two-families",
        heading: "Two families of limits",
        paragraphs: [
          {
            plain:
              "IRAs and workplace plans are limited separately. The 2026 IRA limit is [[fact:ira-limit]], with an extra [[fact:ira-catchup-50]] [[term:catch-up]] from age 50, for a possible total of [[fact:ira-total-50]] for an eligible saver.",
            kid:
              "There are two big groups of accounts, and each has its own cap. The personal kind allows [[fact:ira-limit]] a year, and people 50 or older can add [[fact:ira-catchup-50]] more."
          },
          {
            plain:
              "Workplace plans, meaning 401(k), 403(b), governmental 457, and TSP, share a 2026 [[term:elective-deferral]] limit of [[fact:deferral-limit]]. The general age-50 catch-up is [[fact:deferral-catchup-50]], and a higher [[fact:deferral-catchup-60]] applies at ages 60 to 63 where the plan permits it.",
            kid:
              "Accounts through a job share a bigger cap: [[fact:deferral-limit]]. From age 50 workers can add [[fact:deferral-catchup-50]] more, and from 60 to 63 some plans allow [[fact:deferral-catchup-60]]."
          }
        ]
      },
      {
        id: "beyond-deferrals",
        heading: "Limits beyond your own paycheck",
        paragraphs: [
          {
            plain:
              "Employer money counts against a different ceiling. The 2026 defined-contribution annual-additions limit is [[fact:annual-additions]], excluding catch-up contributions. Small-business plans have their own numbers: the SEP maximum is [[fact:sep-max]] and the SIMPLE salary-reduction limit is [[fact:simple-limit]], with catch-ups of [[fact:simple-catchup-50]] from age 50 and [[fact:simple-catchup-60]] at ages 60 to 63.",
            kid:
              "Money a job adds is counted under a separate, bigger cap: [[fact:annual-additions]]. Plans for small businesses have their own caps too."
          }
        ]
      },
      {
        id: "paper-vs-practice",
        heading: "The limit on paper is not a promise",
        paragraphs: [
          {
            plain:
              "A limit is the most the rules allow, not the amount every person can use. Compensation requirements, plan documents, employer rules, and separate deduction or eligibility tests can all lower what is actually available in a given year.",
            kid:
              "The cap is the most the rules allow. Your own situation, or the plan's own rules, can make your real amount smaller."
          }
        ]
      }
    ],
    example: {
      heading: "Example: one saver, two limits",
      plain:
        "A 52-year-old with a 401(k) could defer up to $32,500 in 2026 ([[fact:deferral-limit]] plus the [[fact:deferral-catchup-50]] catch-up) and separately contribute up to [[fact:ira-total-50]] to an IRA, if eligible under the separate IRA rules. The two ceilings do not borrow from each other.",
      kid:
        "A 52-year-old could put money into a work account and a personal account in the same year. Each has its own cap, and one does not shrink the other."
    },
    activity: {
      kind: "calculator",
      slug: "contribution-growth",
      label: "Project a monthly contribution",
      description: "Try the steady saving projection with an amount that fits inside these limits."
    },
    risks: [
      "Limits shown are 2026 United States federal figures and change most years. Never carry them into a new year without rechecking.",
      "Eligibility, compensation floors, employer rules, and deduction tests are separate from the headline limit.",
      "Certain applicable SIMPLE plans have specialized higher limits that are not universal."
    ],
    takeaways: [
      "IRA and workplace limits are separate ceilings.",
      "Catch-up room starts at 50, with a higher workplace tier at ages 60 to 63.",
      "Employer money counts against the annual-additions limit, not your deferral limit.",
      "Always confirm the effective year on any limit you read."
    ],
    quiz: [
      {
        question: "A 45-year-old has both a 401(k) and an IRA in 2026. What is true about the limits?",
        options: [
          "The two accounts share one combined limit",
          "Each account type has its own separate limit",
          "The IRA limit reduces the 401(k) limit dollar for dollar"
        ],
        answer: 1,
        explain: "IRA and workplace-plan limits are separate families. In 2026 they are $7,500 and $24,500 respectively."
      },
      {
        question: "Who can use the higher $11,250 workplace catch-up in 2026?",
        options: [
          "Everyone age 50 and older",
          "Savers aged 60 to 63, where the plan permits it",
          "Anyone whose employer offers matching"
        ],
        answer: 1,
        explain: "The higher tier applies only at ages 60 to 63 and depends on the plan."
      },
      {
        question: "Employer matching dollars count against which ceiling?",
        options: [
          "The employee elective-deferral limit",
          "The IRA contribution limit",
          "The defined-contribution annual-additions limit"
        ],
        answer: 2,
        explain: "Employer money falls under the $72,000 annual-additions limit, which excludes catch-ups."
      }
    ],
    factIds: [
      "ira-limit", "ira-catchup-50", "ira-total-50", "deferral-limit", "deferral-catchup-50",
      "deferral-catchup-60", "annual-additions", "sep-max", "simple-limit", "simple-catchup-50", "simple-catchup-60"
    ],
    next: "roth-vs-traditional-basics"
  },

  {
    slug: "roth-vs-traditional-basics",
    title: "Roth vs Traditional: tax now, or tax later",
    topic: "Retirement accounts",
    minutes: 8,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "Final IRS figures plus general concepts",
    learn: [
      "How the tax timing differs between a Roth and a traditional account",
      "What changes decades later, including required withdrawals",
      "Which factors people commonly weigh when comparing the two"
    ],
    summary: {
      plain:
        "A [[term:traditional]] account can give its tax break now: the contribution may be deductible, growth is [[term:tax-deferred]], and withdrawals are generally taxed later. A [[term:roth]] account flips that: the money is taxed before it goes in, and qualified withdrawals later can be tax-free. Neither is universally better; the comparison depends on facts about you and rules that have their own income tests.",
      kid:
        "With one kind of account, you skip some tax now and pay it later. With the other, you pay the tax first and, if you follow the rules, skip it later. Which is better depends on the person, so there is no one right answer."
    },
    sections: [
      {
        id: "tax-timing",
        heading: "The core difference is when the tax happens",
        paragraphs: [
          {
            plain:
              "With a [[term:traditional]] IRA, the [[term:contribution]] may reduce this year's taxable income if the deduction tests are passed, the account grows [[term:tax-deferred]], and withdrawals in retirement are generally taxed as ordinary income. With a [[term:roth]] IRA, there is no deduction now; the money goes in already taxed, and qualified withdrawals of contributions and growth can come out tax-free under the rules.",
            kid:
              "One account says: save tax today, pay tax when you take the money out. The other says: pay tax today, and later, if the rules are followed, take the money out without tax."
          },
          {
            plain:
              "Both kinds share one yearly ceiling. For 2026 the IRA limit is [[fact:ira-limit]] plus the [[fact:ira-catchup-50]] age-50 catch-up, and that limit applies across all of a person's traditional and Roth IRAs combined, not to each separately.",
            kid:
              "You do not get a full cap for each kind. The yearly IRA cap of [[fact:ira-limit]] covers both kinds added together."
          }
        ]
      },
      {
        id: "later-years",
        heading: "The difference decades later",
        paragraphs: [
          {
            plain:
              "Traditional, SEP, and SIMPLE IRAs generally require minimum withdrawals starting at [[fact:rmd-age]]. Roth IRAs owe no lifetime [[term:rmd]]s to the original owner, which leaves that money more flexible in late retirement and for beneficiaries, who have their own rules either way. The RMD lesson covers those mechanics.",
            kid:
              "The pay-tax-later account eventually forces withdrawals at [[fact:rmd-age]]. The pay-tax-first account does not force the original owner to withdraw at all."
          },
          {
            plain:
              "Tax-free treatment of Roth growth is conditional, not automatic. Qualified withdrawals depend on timing and holding rules described in IRS Publications 590-A and 590-B; withdrawing growth early can be taxable and penalized.",
            kid:
              "The tax-free part has conditions. Taking growth out too early can still cost tax and a penalty, so the rules matter."
          }
        ]
      },
      {
        id: "weighing",
        heading: "What people actually weigh",
        paragraphs: [
          {
            plain:
              "The comparison usually turns on tax rates: a deduction is worth the most when today's rate is high, and Roth treatment is worth the most when the rate at withdrawal would have been high. Since future tax rates and future law are unknown, that comparison is always an estimate.",
            kid:
              "The big question is: is your tax bigger now, or will it be bigger later? Nobody knows future taxes for sure, so it is always a careful guess."
          },
          {
            plain:
              "Eligibility narrows the choice before preference does. The traditional deduction phases out for covered savers, for example across [[fact:trad-phaseout-single]] for single filers in 2026, and Roth contributions phase out across [[fact:roth-phaseout-single]]. Some people qualify for one, both, or neither, and where both are available, contributions can be split. The phaseout lesson walks through every 2026 range.",
            kid:
              "Income rules can close one door or both. Some savers can use either kind, and some split their saving between the two."
          },
          {
            plain:
              "Other factors people weigh: [[term:rmd]] flexibility, whether the deduction is even usable this year, the value of tax diversification across both kinds, and state taxes, which this lesson does not cover. None of these produce a universal answer, which is why this page teaches the tradeoffs instead of picking a side.",
            kid:
              "There are more little factors, and they point different ways for different people. That is why no one kind wins for everyone."
          }
        ]
      }
    ],
    example: {
      heading: "Example: why equal tax rates make it a tie",
      plain:
        "Suppose $1,000 of pay, a 20% tax rate now and at withdrawal, and growth that triples the money. Traditional: $1,000 goes in untaxed, triples to $3,000, and is taxed to $2,400 at withdrawal. Roth: $800 goes in after tax, triples to $2,400, and comes out tax-free. Identical result. The outcomes separate only when the two tax rates differ, or when rules like RMDs and phaseouts come into play.",
      kid:
        "If the tax slice is the same now and later, both accounts end up equal. The difference appears when the slices are different sizes at different times."
    },
    activity: {
      kind: "calculator",
      slug: "contribution-growth",
      label: "Project a yearly IRA contribution",
      description: "Run the steady saving projection with an amount inside the IRA limit. The tool models growth only; it does not model taxes."
    },
    risks: [
      "This lesson is general education, not a recommendation to choose either account type.",
      "Qualified Roth withdrawals depend on timing and holding rules in IRS Publications 590-A and 590-B that this summary does not restate.",
      "Deduction and contribution eligibility depend on 2026 income tests that change most years.",
      "Future tax rates and future tax law are unknown; every comparison rests on assumptions."
    ],
    takeaways: [
      "Traditional defers tax; Roth prepays it. That timing is the entire skeleton of the comparison.",
      "One combined IRA limit covers both kinds together: $7,500 for 2026, plus catch-up.",
      "Roth IRAs owe no lifetime RMDs to the original owner; traditional IRAs generally do from age 73.",
      "If tax rates were identical now and later, the math ties; real differences come from rates, rules, and eligibility."
    ],
    quiz: [
      {
        question: "What is the core mechanical difference between the two account types?",
        options: [
          "Roth accounts earn higher returns",
          "When the tax is paid: deferred to withdrawal, or prepaid at contribution",
          "Traditional accounts have no contribution limit"
        ],
        answer: 1,
        explain: "Investment options and returns are separate matters; the account types differ in tax timing."
      },
      {
        question: "A saver contributes $7,500 to a traditional IRA in 2026. How much more may go into their Roth IRA that year?",
        options: ["Another $7,500", "Nothing, the limit is shared across both", "Half of the limit"],
        answer: 1,
        explain: "The yearly IRA limit applies to all of a person's traditional and Roth IRAs combined."
      },
      {
        question: "Which account owes no lifetime required minimum distributions to its original owner?",
        options: ["Traditional IRA", "SEP IRA", "Roth IRA"],
        answer: 2,
        explain: "Traditional, SEP, and SIMPLE IRAs generally require withdrawals from age 73; Roth IRAs do not during the original owner's lifetime."
      }
    ],
    factIds: ["ira-limit", "ira-catchup-50", "rmd-age", "trad-phaseout-single", "roth-phaseout-single"],
    next: "traditional-vs-roth-2026"
  },

  {
    slug: "traditional-vs-roth-2026",
    title: "Deduction and Roth phaseouts: the 2026 income tests",
    topic: "Taxes",
    minutes: 8,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "Final IRS figures",
    learn: [
      "Why contributing, deducting, and Roth eligibility are three different questions",
      "Where the 2026 income phaseout ranges sit",
      "How the Saver's Credit adds a fourth, separate income test"
    ],
    summary: {
      plain:
        "Being allowed to contribute to an IRA, being allowed to deduct that contribution, and being allowed to contribute to a [[term:roth]] IRA are separate tests. Each has its own 2026 [[term:phaseout]] range based on [[term:magi]].",
      kid:
        "Putting money in, getting a tax discount for it, and using the tax-free-later kind of account are three different permissions. Each one has its own income rules."
    },
    sections: [
      {
        id: "three-questions",
        heading: "Three separate questions",
        paragraphs: [
          {
            plain:
              "The contribution limit says how much can go in. The deduction rules say whether a traditional IRA contribution lowers this year's taxable income. The Roth rules say whether you may contribute to a Roth at all. Passing one test says nothing about the others.",
            kid:
              "Question one: how much can go in? Question two: does it earn a tax discount now? Question three: is the tax-free-later account allowed? Each question is checked on its own."
          }
        ]
      },
      {
        id: "traditional-ranges",
        heading: "2026 traditional IRA deduction phaseouts",
        paragraphs: [
          {
            plain:
              "When the contributor is covered by a workplace plan, the deduction phases out at [[fact:trad-phaseout-single]] for single or head-of-household filers and [[fact:trad-phaseout-mfj]] for married filing jointly. If the contributor is not covered but their spouse is, the range is [[fact:trad-phaseout-spouse]]. Married filing separately while covered faces a narrow [[fact:trad-phaseout-mfs]] range.",
            kid:
              "The tax discount fades out across income zones. The zone depends on how a household files taxes and whether a work plan covers the saver."
          }
        ]
      },
      {
        id: "roth-ranges",
        heading: "2026 Roth contribution phaseouts",
        paragraphs: [
          {
            plain:
              "Roth contribution eligibility phases out at [[fact:roth-phaseout-single]] for single or head-of-household filers and [[fact:roth-phaseout-mfj]] for married filing jointly. Married filing separately when spouses lived together faces the [[fact:roth-phaseout-mfs]] range.",
            kid:
              "The tax-free-later account also has fade-out zones. Above the top of a zone, new money cannot go into that account type that year."
          }
        ]
      },
      {
        id: "savers-credit",
        heading: "A fourth test: the Saver's Credit",
        paragraphs: [
          {
            plain:
              "Lower and moderate incomes may also qualify for the Saver's Credit. The 2026 income limits are [[fact:savers-mfj]] for married filing jointly, [[fact:savers-hoh]] for head of household, and [[fact:savers-single]] for single or married filing separately.",
            kid:
              "Some savers with smaller incomes get an extra reward on their taxes just for saving. It has its own income cutoffs."
          }
        ]
      }
    ],
    example: {
      heading: "Example: allowed to contribute, not allowed to deduct",
      plain:
        "A single filer covered by a 401(k) with [[term:magi]] of $95,000 in 2026 may still contribute to a traditional IRA, but sits above the [[fact:trad-phaseout-single]] deduction range, so the contribution would not be deductible. The same person is under the [[fact:roth-phaseout-single]] Roth range and could contribute to a Roth instead.",
      kid:
        "Someone can be allowed to put money in but not get the tax discount, while still qualifying for the tax-free-later account. The tests really are separate."
    },
    activity: {
      kind: "facts",
      label: "Browse the phaseout fact records",
      description: "Every range on this page links to its IRS source in the fact registry."
    },
    risks: [
      "These ranges use modified adjusted gross income, which differs from salary.",
      "Filing status details, like spouses living together, change which range applies.",
      "This page is general education, not advice about what any specific person should do."
    ],
    takeaways: [
      "Contributing, deducting, and Roth eligibility are tested separately.",
      "Every phaseout range is specific to tax year 2026 and a filing status.",
      "The Saver's Credit is an additional benefit with its own income limits."
    ],
    quiz: [
      {
        question: "A saver's income is above the traditional IRA deduction phaseout. What follows?",
        options: [
          "They cannot contribute to any IRA",
          "They may still be able to contribute, but without the deduction",
          "They automatically qualify for the Saver's Credit"
        ],
        answer: 1,
        explain: "The deduction test is separate from the ability to contribute."
      },
      {
        question: "Which income figure do the phaseout tests use?",
        options: ["Gross salary", "Modified adjusted gross income", "Take-home pay"],
        answer: 1,
        explain: "Phaseouts are measured against MAGI, a figure computed from the tax return."
      }
    ],
    factIds: [
      "trad-phaseout-single", "trad-phaseout-mfj", "trad-phaseout-spouse", "trad-phaseout-mfs",
      "roth-phaseout-single", "roth-phaseout-mfj", "roth-phaseout-mfs",
      "savers-mfj", "savers-hoh", "savers-single"
    ],
    next: "rmd-basics"
  },

  {
    slug: "rmd-basics",
    title: "Required minimum distributions: who must withdraw, and when",
    topic: "Retirement accounts",
    minutes: 6,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "IRS guidance summary",
    learn: [
      "When required withdrawals generally begin",
      "Which accounts are exempt during the original owner's lifetime",
      "Which accounts can and cannot be combined for a withdrawal"
    ],
    summary: {
      plain:
        "Traditional, SEP, and SIMPLE IRAs and most covered retirement plans generally require [[term:rmd]]s beginning at [[fact:rmd-age]]. [[term:roth]] IRAs and designated Roth accounts do not require lifetime withdrawals from the original owner, though beneficiary rules still apply.",
      kid:
        "After a certain age, the rules make people start taking money out of some retirement accounts. A few account types are excused while the original owner is alive."
    },
    sections: [
      {
        id: "when",
        heading: "When withdrawals start",
        paragraphs: [
          {
            plain:
              "The general beginning age is [[fact:rmd-age]]. A workplace-plan participant who is still working may sometimes delay until retirement, but that delay is not available to a 5% owner of the business.",
            kid:
              "Most people start at [[fact:rmd-age]]. Someone still working can sometimes wait, but not if they own a big share of the company."
          }
        ]
      },
      {
        id: "exempt",
        heading: "Accounts excused during the owner's lifetime",
        paragraphs: [
          {
            plain:
              "Roth IRAs and designated Roth accounts do not require lifetime distributions from the original owner. This exemption ends at death: beneficiaries have their own required-withdrawal rules.",
            kid:
              "The tax-free-later accounts do not force the original owner to withdraw. But when the account passes to someone else, that person does have rules to follow."
          }
        ]
      },
      {
        id: "aggregation",
        heading: "Combining withdrawals",
        paragraphs: [
          {
            plain:
              "IRA required amounts are calculated separately for each IRA but can generally be withdrawn in aggregate from one or more of them. Workplace plans are stricter: 401(k) and 457(b) required amounts generally cannot be aggregated across plans.",
            kid:
              "For the personal accounts, the amounts can be added up and taken from one place. For work accounts, each plan usually needs its own withdrawal."
          }
        ]
      }
    ],
    example: {
      heading: "Example: three IRAs, one withdrawal",
      plain:
        "A 74-year-old with three traditional IRAs calculates a required amount for each, then may take the combined total from just one of the three. If the same person also had two old 401(k)s, each plan would generally need its own separate withdrawal.",
      kid:
        "Someone with three personal accounts can total up the required amounts and take it all from one. Old work accounts each need their own withdrawal."
    },
    activity: {
      kind: "calculator",
      slug: "todays-dollars",
      label: "See what a future withdrawal buys",
      description: "Use the today's dollars tool to restate a future withdrawal in current purchasing power."
    },
    risks: [
      "Individual circumstances, plan documents, and beneficiary status change these outcomes.",
      "Missing a required withdrawal can carry an excise tax; timing questions deserve professional review.",
      "This summary reflects guidance reviewed on 2026-07-16 and can change."
    ],
    takeaways: [
      "The general starting age is 73.",
      "Roth IRAs and designated Roth accounts owe no lifetime RMDs to the original owner.",
      "IRAs can aggregate withdrawals; 401(k) and 457(b) plans generally cannot."
    ],
    quiz: [
      {
        question: "Which account owes no lifetime RMDs to its original owner?",
        options: ["Traditional IRA", "SEP IRA", "Roth IRA"],
        answer: 2,
        explain: "Roth IRAs and designated Roth accounts are exempt during the original owner's lifetime; beneficiaries still have rules."
      },
      {
        question: "A retiree has two 401(k) plans. How are required withdrawals handled?",
        options: [
          "Take the combined total from either plan",
          "Each plan generally needs its own withdrawal",
          "Only the larger plan requires withdrawals"
        ],
        answer: 1,
        explain: "401(k) and 457(b) required amounts generally cannot be aggregated across plans."
      }
    ],
    factIds: ["rmd-age"],
    next: "social-security-2026"
  },

  {
    slug: "social-security-2026",
    title: "Social Security in 2026: the COLA and the taxable maximum",
    topic: "Social Security",
    minutes: 5,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "Final SSA figures",
    learn: [
      "What the 2026 cost-of-living adjustment is",
      "How much yearly income the Social Security tax applies to",
      "How employee and self-employed payroll rates differ"
    ],
    summary: {
      plain:
        "The 2026 [[term:cola]] is [[fact:ssa-cola]]. The [[term:taxable-maximum]] for the Social Security portion of payroll tax is [[fact:ssa-wage-base]]. SSA shows a combined employee withholding rate of [[fact:ssa-employee-rate]] and a self-employed combined rate of [[fact:ssa-self-employed-rate]].",
      kid:
        "Benefit checks got a [[fact:ssa-cola]] raise for 2026 to help keep up with prices. Workers pay a slice of each paycheck into the system, and self-employed people pay both halves."
    },
    sections: [
      {
        id: "cola",
        heading: "The adjustment",
        paragraphs: [
          {
            plain:
              "A [[term:cola]] raises benefits to help them keep pace with [[term:inflation]]. For 2026 it is [[fact:ssa-cola]]. The adjustment tracks a price index, so it varies year to year and can be small or zero.",
            kid:
              "The raise follows prices. Some years it is bigger, some years smaller, and it can even be zero."
          }
        ]
      },
      {
        id: "wage-base",
        heading: "The taxable maximum",
        paragraphs: [
          {
            plain:
              "The OASDI portion of payroll tax, [[fact:ssa-oasdi-rate]], applies to wages up to the 2026 [[term:taxable-maximum]] of [[fact:ssa-wage-base]]. Medicare rules differ and are not capped the same way. The combined employee rate SSA shows is [[fact:ssa-employee-rate]]; the self-employed combined rate is [[fact:ssa-self-employed-rate]] because it covers both the employee and employer halves.",
            kid:
              "The Social Security slice applies to pay up to a yearly cap of [[fact:ssa-wage-base]]. People who work for themselves pay both the worker's share and the employer's share."
          }
        ]
      }
    ],
    example: {
      heading: "Example: pay above the cap",
      plain:
        "A worker earning $200,000 in 2026 pays the [[fact:ssa-oasdi-rate]] OASDI rate only on the first [[fact:ssa-wage-base]] of wages. Earnings above the cap still face Medicare tax, which follows different rules.",
      kid:
        "If someone earns more than the cap, the Social Security slice stops at the cap. A different, smaller slice for health coverage keeps going."
    },
    activity: {
      kind: "calculator",
      slug: "real-return",
      label: "Compare a raise against inflation",
      description: "Use the real return tool to see what a 2.8% adjustment means when prices are also rising."
    },
    risks: [
      "These are 2026 figures from SSA and change annually.",
      "Individual benefit amounts depend on personal earnings history and claiming age.",
      "Medicare withholding follows separate rules not covered here."
    ],
    takeaways: [
      "The 2026 COLA is 2.8%.",
      "The 2026 taxable maximum is $184,500.",
      "Self-employed workers pay both halves, shown by SSA as 15.30% combined."
    ],
    quiz: [
      {
        question: "Wages above the 2026 taxable maximum are subject to which tax?",
        options: [
          "The 6.2% OASDI rate continues",
          "Medicare tax, under its own rules",
          "No payroll tax at all"
        ],
        answer: 1,
        explain: "OASDI stops at $184,500 for 2026; Medicare rules differ and continue."
      },
      {
        question: "Why is the self-employed combined rate higher than the employee rate?",
        options: [
          "Self-employment income is taxed twice",
          "It covers both the employee and employer halves",
          "It includes federal income tax"
        ],
        answer: 1,
        explain: "A self-employed person pays both halves, which SSA shows as 15.30% combined."
      }
    ],
    factIds: ["ssa-cola", "ssa-wage-base", "ssa-employee-rate", "ssa-self-employed-rate", "ssa-oasdi-rate"],
    next: "trump-accounts-status"
  },

  {
    slug: "trump-accounts-status",
    title: "Trump Accounts: what is final, and what is still proposed",
    topic: "Retirement accounts",
    minutes: 5,
    updatedAt: "2026-07-16",
    effectiveYear: 2026,
    authorityStatus: "Mixed: enacted law plus proposed guidance",
    learn: [
      "How to tell enacted law apart from proposed regulations",
      "Which parts of the Trump Account rules carry which authority level",
      "Why authority labels matter before acting on new account types"
    ],
    summary: {
      plain:
        "New account types arrive in layers. For Trump Accounts, the statute is enacted: [[fact:ta-law]]. Separately, [[fact:ta-operations]]. But [[fact:ta-proposed]], and [[fact:ta-revproc]]. Each layer carries a different level of authority.",
      kid:
        "A new kind of account was created by a law that is real and finished. Some of the detailed instructions for it, though, are still drafts that could change."
    },
    sections: [
      {
        id: "layers",
        heading: "Four layers, four authority levels",
        paragraphs: [
          {
            plain:
              "Enacted law is settled unless Congress changes it. Agency operations, like the IRS opening electronic Form 4547 elections, describe what you can do today. Proposed regulations such as REG-117270-25 are drafts open to change before finalization. Revenue procedures, like Rev. Proc. 2026-25's transfer-tax safe harbor, are binding guidance on specific questions.",
            kid:
              "Think of it as four shelves: finished law, things you can already do, draft instructions that might change, and official answers to specific questions."
          }
        ]
      },
      {
        id: "why-it-matters",
        heading: "Why the labels matter",
        paragraphs: [
          {
            plain:
              "Educational content that presents a proposed rule as final can lead readers to act on rules that later change. Every claim about a developing account type should carry an authority-status label and a review date, and this article does: reviewed 2026-07-16.",
            kid:
              "If a draft rule gets treated like a finished one, people can make choices based on something that later changes. Labels keep that honest."
          }
        ]
      }
    ],
    example: {
      heading: "Example: reading a claim carefully",
      plain:
        "A blog post says a specific Trump Account contribution treatment is settled. Checking the registry shows the treatment sits in REG-117270-25, which is proposed guidance. The correct reading: possible, not final, and worth rechecking after the regulation is finalized.",
      kid:
        "If a website says a draft rule is finished, the careful move is to check the label. Draft means it can still change."
    },
    activity: {
      kind: "facts",
      label: "See the authority labels in the registry",
      description: "The fact registry shows each Trump Account layer with its status and source."
    },
    risks: [
      "Proposed regulations can change materially before finalization.",
      "Operational features can expand or pause independent of the rulemaking.",
      "This page describes status as of 2026-07-16 and is not advice to open or fund any account."
    ],
    takeaways: [
      "Section 530A is enacted law; REG-117270-25 is a proposal.",
      "Electronic elections exist as an IRS operational feature.",
      "Authority labels plus review dates keep developing topics honest."
    ],
    quiz: [
      {
        question: "REG-117270-25 should be described as what?",
        options: ["Final regulation", "Proposed guidance", "Enacted statute"],
        answer: 1,
        explain: "It is a proposed regulation, open to change until finalized."
      },
      {
        question: "What two things should every claim about a developing account type carry?",
        options: [
          "A projection and a chart",
          "An authority-status label and a review date",
          "A celebrity endorsement and a hashtag"
        ],
        answer: 1,
        explain: "Status labels and review dates let readers judge how settled a claim is."
      }
    ],
    factIds: ["ta-law", "ta-operations", "ta-proposed", "ta-revproc"],
    next: "compounding-and-inflation"
  },

  {
    slug: "compounding-and-inflation",
    title: "Compounding builds, inflation erodes",
    topic: "Concepts",
    minutes: 6,
    updatedAt: "2026-07-16",
    effectiveYear: null,
    authorityStatus: "Mathematical concepts",
    learn: [
      "How compounding differs from simple growth",
      "Why a dollar amount decades away overstates its buying power",
      "How to compute a real return correctly"
    ],
    summary: {
      plain:
        "[[term:compounding]] means growth earns growth, so balances curve upward over time. [[term:inflation]] quietly works against it, so a projection is only honest when it also shows [[term:real-return]] or today's-dollar values.",
      kid:
        "Money can grow on its own growth, like a snowball. But prices creep up too, so future money buys less than it sounds like."
    },
    sections: [
      {
        id: "snowball",
        heading: "The compounding curve",
        paragraphs: [
          {
            plain:
              "With simple growth, a balance earns on the original amount only. With compounding, each period's growth joins the base for the next period, which is why long time horizons matter more than impressive rates. Frequency matters too, but far less than time.",
            kid:
              "Each round of growth gets added to the pile, and the next round grows from the bigger pile. Starting early beats starting big."
          }
        ]
      },
      {
        id: "erosion",
        heading: "The quiet leak",
        paragraphs: [
          {
            plain:
              "A [[term:nominal-return]] ignores prices. To see what growth is really worth, divide instead of subtracting: real return equals (1 + nominal) divided by (1 + inflation), minus 1. At low rates the subtraction shortcut looks close; at higher inflation it misleads.",
            kid:
              "If your money grows 6% but prices grow 3%, you are not really 6% richer. The honest answer needs a small calculation, and this site's tools do it for you."
          }
        ]
      }
    ],
    example: {
      heading: "Example: the impressive number that shrinks",
      plain:
        "A projection says $500,000 in 25 years. At 2.5% inflation, that is roughly $270,000 in today's purchasing power. Both numbers are estimates; only the second one answers what the money could buy.",
      kid:
        "Half a million dollars far in the future sounds huge, but by then prices will have grown too. In today's terms it buys about half as much."
    },
    activity: {
      kind: "calculator",
      slug: "compound-growth",
      label: "Watch one amount compound",
      description: "Run the compound growth tool, then check the same result in the today's dollars tool."
    },
    risks: [
      "Steady-rate projections smooth over real-world volatility.",
      "Inflation assumptions are guesses; actual inflation varies by year and by what you buy.",
      "No projection here is a promise of any outcome."
    ],
    takeaways: [
      "Time in the market powers compounding more than rate chasing.",
      "Always pair a nominal projection with a today's-dollars view.",
      "Divide, do not subtract, to get a real return."
    ],
    quiz: [
      {
        question: "What is the correct way to compute a real return?",
        options: [
          "Nominal return minus inflation",
          "(1 + nominal) divided by (1 + inflation), minus 1",
          "Nominal return divided by 2"
        ],
        answer: 1,
        explain: "Division is exact; subtraction is only an approximation that degrades as rates rise."
      },
      {
        question: "Which factor usually matters most for compounding?",
        options: ["Time invested", "Compounding frequency", "Round-number deposits"],
        answer: 0,
        explain: "Long horizons let growth stack on growth; frequency helps only slightly by comparison."
      }
    ],
    factIds: [],
    next: "debt-vs-interest"
  },

  {
    slug: "debt-vs-interest",
    title: "Paying off debt: the payment has to beat the interest",
    topic: "Debt",
    minutes: 5,
    updatedAt: "2026-07-16",
    effectiveYear: null,
    authorityStatus: "Mathematical concepts",
    learn: [
      "Why a too-small payment can leave a balance frozen or growing",
      "How the same math behind savings growth works against borrowers",
      "What an effective annual rate reveals about a stated APR"
    ],
    summary: {
      plain:
        "Debt compounds just like savings, but in the lender's favor. Each month, interest is added first and the payment is applied after. If the payment does not exceed the month's interest, the balance never falls.",
      kid:
        "Owed money grows on its own, the same way saved money does. A payment has to be bigger than the month's growth, or the debt never shrinks."
    },
    sections: [
      {
        id: "threshold",
        heading: "The break-even payment",
        paragraphs: [
          {
            plain:
              "A balance of $6,000 at 21% [[term:apr]] accrues roughly $105 of interest in the first month. A $100 payment loses ground; $110 barely holds it. Real progress starts well above the break-even point, and every extra dollar goes entirely to the balance.",
            kid:
              "If the debt grows by $105 this month and you pay $100, you owe more than before even though you paid. The payment has to beat the growth."
          }
        ]
      },
      {
        id: "true-rate",
        heading: "The rate behind the rate",
        paragraphs: [
          {
            plain:
              "A stated [[term:apr]] understates the true yearly cost when interest compounds within the year. A 24% APR compounding daily behaves like roughly 27% annually. The effective annual rate makes offers comparable.",
            kid:
              "The advertised rate is not always the whole story. When interest gets charged on interest during the year, the true rate is a bit higher."
          }
        ]
      }
    ],
    example: {
      heading: "Example: two payments, two futures",
      plain:
        "On a $6,000 balance at 21% APR, about $250 a month clears the debt in roughly two years and eight months. About $110 a month stays near break-even and takes around fifteen years, paying more in interest than the original balance. The debt payoff tool shows both paths.",
      kid:
        "Paying a bit more than the minimum can save years of payments and a pile of interest. The calculator lets you compare safely."
    },
    activity: {
      kind: "calculator",
      slug: "debt-payoff",
      label: "Compare payoff plans",
      description: "Try the minimum-payment trap scenario, then raise the payment and compare."
    },
    risks: [
      "Real cards recalculate minimums and add fees; this model holds them constant.",
      "Promotional rates expire; the tool assumes one fixed APR.",
      "Debt decisions interact with emergencies and income stability; no single number decides them."
    ],
    takeaways: [
      "Interest accrues first; only the excess payment touches the balance.",
      "Small payment increases can shorten payoff dramatically.",
      "Compare borrowing costs by effective annual rate, not stated APR."
    ],
    quiz: [
      {
        question: "A month's interest is $105 and the payment is $100. What happens?",
        options: ["The balance falls slightly", "The balance rises", "The balance stays exactly the same"],
        answer: 1,
        explain: "The payment covers less than the accrued interest, so the shortfall joins the balance."
      },
      {
        question: "Why can an EAR exceed the stated APR?",
        options: [
          "Because of late fees",
          "Because interest compounds within the year",
          "Because APRs are quoted monthly"
        ],
        answer: 1,
        explain: "Compounding inside the year charges interest on interest, raising the effective rate."
      }
    ],
    factIds: [],
    next: "retirement-limits-2026"
  }
];

export function getArticle(slug) {
  const found = ARTICLES.find((article) => article.slug === slug);
  if (!found) {
    throw new Error(`Unknown article: ${slug}`);
  }
  return found;
}
