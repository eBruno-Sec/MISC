import {
  APP_VERSION,
  BACKUP_SCHEMA_VERSION,
  calculateProjection,
  contributionLimitFor,
  formatMoney,
  retirementFacts2026,
  stableStringify,
  validateBackupEnvelope
} from "./domain.js";

const DB_NAME = "nestegghero";
const DB_VERSION = 1;
const STORE_NAME = "learning-state";
const STATE_KEY = "current";
const MAX_IMPORT_BYTES = 1024 * 1024;

const lessons = [
  {
    id: "limits-2026",
    title: "2026 retirement contribution limits",
    category: "Account basics",
    minutes: 6,
    reviewedAt: "2026-07-16",
    sourceLabel: "IRS",
    summary: "Contribution limits are annual ceilings set by federal rules. They are not the same as eligibility, deduction, or employer-plan rules.",
    kidSummary: "A contribution limit is like the top line on a measuring cup. It says how much can fit for the year, but other rules can still matter.",
    learn: [
      "The 2026 IRA contribution limit is $7,500, with a $1,100 age-50+ catch-up.",
      "The 2026 employee elective-deferral limit for most 401(k), 403(b), governmental 457, and TSP plans is $24,500.",
      "The general age-50+ catch-up for those workplace plans is $8,000, with a higher age 60-63 catch-up of $11,250 where applicable."
    ],
    core: "Limits tell you the maximum that a rule permits in a category. They do not prove that a contribution is deductible, allowed by a plan, or best for a particular person.",
    example: "If a 52-year-old worker participates in a workplace plan that allows catch-up contributions, the 2026 educational headline total is $24,500 plus the $8,000 general catch-up, or $32,500. Their plan and personal facts can still change what is available.",
    risk: "Do not copy a prior year's number forward. Contribution limits, phaseouts, and plan rules change independently.",
    quiz: {
      question: "Is a contribution limit the same thing as Roth IRA eligibility?",
      options: ["No", "Yes"],
      answer: "No",
      feedback: "Right. A limit is one rule. Roth eligibility and phaseouts are separate rules."
    },
    sources: retirementFacts2026.sources
  },
  {
    id: "estimate-basics",
    title: "What a projection can and cannot promise",
    category: "Calculator literacy",
    minutes: 5,
    reviewedAt: "2026-07-16",
    sourceLabel: "NestEggHero",
    summary: "A projection is a math estimate based on assumptions. It is not a guarantee, forecast, or individualized recommendation.",
    kidSummary: "A projection is a careful guess from the numbers you type in. If the guesses change, the answer changes too.",
    learn: [
      "Assumptions should be visible next to the result.",
      "Rounding should happen for display, not during intermediate math.",
      "Inflation-adjusted dollars help compare future values with today's buying power."
    ],
    core: "Compound growth uses a rate, time period, and contribution schedule. Small assumption changes can create large result differences over long periods.",
    example: "A $250 monthly contribution for 20 years at a 5% nominal annual return produces a different result than the same contribution at 3%. Neither result promises what markets will do.",
    risk: "Fees, taxes, contribution timing, market returns, inflation, and account rules can all change the real outcome.",
    quiz: {
      question: "Should calculator output be labeled as an estimate?",
      options: ["Yes", "No"],
      answer: "Yes",
      feedback: "Yes. A calculator can explain assumptions, but it cannot promise outcomes."
    },
    sources: [
      {
        label: "NestEggHero calculator specification",
        url: "docs/fact-records.md"
      }
    ]
  },
  {
    id: "rmd-basics",
    title: "Required minimum distributions in plain language",
    category: "Retirement rules",
    minutes: 7,
    reviewedAt: "2026-07-16",
    sourceLabel: "IRS",
    summary: "Traditional, SEP, and SIMPLE IRAs and most covered retirement plans generally have required minimum distributions beginning at age 73.",
    kidSummary: "Some retirement accounts have a rule that says money must start coming out after a certain age.",
    learn: [
      "Traditional, SEP, and SIMPLE IRAs generally require lifetime RMDs.",
      "Roth IRAs and designated Roth accounts do not require lifetime RMDs from the original owner.",
      "IRA RMDs can generally be aggregated across IRAs, while many workplace-plan RMDs cannot be combined across plans."
    ],
    core: "RMD rules are account-specific. The same person can have different distribution rules across IRA, workplace, Roth, and inherited accounts.",
    example: "A person with two traditional IRAs generally calculates each IRA RMD separately but may take the total from one or more IRAs. A person with multiple 401(k) accounts generally cannot use that same aggregation shortcut.",
    risk: "Beneficiary rules, 5% owner status, plan terms, and later law changes can alter the answer.",
    quiz: {
      question: "Can 401(k) RMDs generally be aggregated across plans like IRAs?",
      options: ["No", "Yes"],
      answer: "No",
      feedback: "Correct. IRA aggregation and workplace-plan aggregation are different."
    },
    sources: [
      {
        label: "IRS RMD FAQs",
        url: "https://www.irs.gov/retirement-plans/retirement-plan-and-ira-required-minimum-distributions-faqs"
      },
      {
        label: "IRS RMD topics",
        url: "https://www.irs.gov/retirement-plans/plan-participant-employee/retirement-topics-required-minimum-distributions-rmds"
      }
    ]
  }
];

const defaultState = () => {
  const now = new Date().toISOString();
  return {
    schemaVersion: BACKUP_SCHEMA_VERSION,
    createdAt: now,
    updatedAt: now,
    preferences: {
      theme: "system",
      kidSpeak: false,
      textSize: "normal"
    },
    progress: {
      completedLessons: {},
      bookmarks: [],
      quizScores: {},
      badges: [],
      calculatorRuns: 0
    }
  };
};

let state = defaultState();
let dbHandle = null;
let selectedLessonId = lessons[0].id;
let pendingImport = null;

const selectors = {
  lessonList: document.querySelector("#lessonList"),
  lessonReader: document.querySelector("#lessonReader"),
  kidSpeakToggle: document.querySelector("#kidSpeakToggle"),
  themeToggle: document.querySelector("#themeToggle"),
  projectionForm: document.querySelector("#projectionForm"),
  projectionResults: document.querySelector("#projectionResults"),
  projectionChart: document.querySelector("#projectionChart"),
  projectionTableBody: document.querySelector("#projectionTable tbody"),
  projectionError: document.querySelector("#projectionError"),
  factsTable: document.querySelector("#factsTable"),
  limitForm: document.querySelector("#limitForm"),
  limitResult: document.querySelector("#limitResult"),
  progressSummary: document.querySelector("#progressSummary"),
  badgeRow: document.querySelector("#badgeRow"),
  exportButton: document.querySelector("#exportButton"),
  importInput: document.querySelector("#importInput"),
  importPreview: document.querySelector("#importPreview"),
  toast: document.querySelector("#toast"),
  offlineStatus: document.querySelector("#offlineStatus")
};

init();

async function init() {
  state = await loadState();
  applyTheme();
  renderAll();
  bindEvents();
  calculateAndRenderProjection(new FormData(selectors.projectionForm), false);
  renderLimit("ira", 35);
  registerServiceWorker();
}

function bindEvents() {
  selectors.kidSpeakToggle.addEventListener("click", async () => {
    state.preferences.kidSpeak = !state.preferences.kidSpeak;
    await commitState("Kid Speak preference saved.");
    renderLessons();
    renderReader();
  });

  selectors.themeToggle.addEventListener("click", async () => {
    const next = state.preferences.theme === "dark" ? "light" : state.preferences.theme === "light" ? "system" : "dark";
    state.preferences.theme = next;
    applyTheme();
    await commitState(`Theme set to ${next}.`);
  });

  selectors.projectionForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    calculateAndRenderProjection(new FormData(selectors.projectionForm), true);
  });

  selectors.projectionForm.addEventListener("reset", () => {
    window.setTimeout(() => calculateAndRenderProjection(new FormData(selectors.projectionForm), false), 0);
  });

  selectors.limitForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const form = new FormData(selectors.limitForm);
    renderLimit(form.get("accountType"), form.get("age"));
  });

  selectors.exportButton.addEventListener("click", exportState);
  selectors.importInput.addEventListener("change", handleImportSelection);
}

function renderAll() {
  renderFacts();
  renderLessons();
  renderReader();
  renderProgress();
  selectors.kidSpeakToggle.setAttribute("aria-pressed", String(state.preferences.kidSpeak));
}

function renderLessons() {
  selectors.lessonList.replaceChildren();
  lessons.forEach((lesson) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "lesson-button";
    button.setAttribute("aria-current", lesson.id === selectedLessonId ? "true" : "false");
    button.addEventListener("click", () => {
      selectedLessonId = lesson.id;
      renderLessons();
      renderReader();
    });

    const title = document.createElement("strong");
    title.textContent = lesson.title;
    const meta = document.createElement("span");
    meta.textContent = `${lesson.category} | ${lesson.minutes} min | reviewed ${lesson.reviewedAt}`;
    const status = document.createElement("span");
    status.className = "lesson-status";
    status.textContent = state.progress.completedLessons[lesson.id] ? "Complete" : "Not started";

    button.append(title, meta, status);
    selectors.lessonList.append(button);
  });
}

function renderReader() {
  const lesson = lessons.find((item) => item.id === selectedLessonId) || lessons[0];
  const kidSpeak = state.preferences.kidSpeak;
  const isBookmarked = state.progress.bookmarks.includes(lesson.id);
  const isComplete = Boolean(state.progress.completedLessons[lesson.id]);
  selectors.lessonReader.replaceChildren();

  const header = document.createElement("header");
  header.className = "article-header";
  const breadcrumb = document.createElement("nav");
  breadcrumb.setAttribute("aria-label", "Breadcrumb");
  breadcrumb.setAttribute("itemscope", "");
  breadcrumb.setAttribute("itemtype", "https://schema.org/BreadcrumbList");
  breadcrumb.className = "breadcrumbs";
  breadcrumb.textContent = `Lessons / ${lesson.category}`;

  const title = document.createElement("h3");
  title.setAttribute("itemprop", "headline");
  title.textContent = lesson.title;

  const meta = document.createElement("p");
  meta.className = "article-meta";
  meta.textContent = `Reviewed ${lesson.reviewedAt}. Source authority: ${lesson.sourceLabel}. Educational summary.`;

  const controls = document.createElement("div");
  controls.className = "article-actions";
  const bookmark = createButton(isBookmarked ? "Remove bookmark" : "Save lesson", "secondary", async () => {
    toggleBookmark(lesson.id);
    await commitState(isBookmarked ? "Bookmark removed." : "Lesson bookmarked.");
    renderAll();
  });
  const complete = createButton(isComplete ? "Completed" : "Mark complete", "primary", async () => {
    state.progress.completedLessons[lesson.id] = new Date().toISOString();
    awardBadge("First lesson");
    await commitState("Lesson marked complete.");
    renderAll();
  });
  complete.disabled = isComplete;
  controls.append(bookmark, complete);
  header.append(breadcrumb, title, meta, controls);

  const progress = document.createElement("div");
  progress.className = "reading-progress";
  const progressFill = document.createElement("span");
  progressFill.style.width = isComplete ? "100%" : "35%";
  progress.append(progressFill);

  const summary = createSection("Plain-language summary", kidSpeak ? lesson.kidSummary : lesson.summary);
  const learn = document.createElement("section");
  const learnTitle = document.createElement("h4");
  learnTitle.textContent = "What you will learn";
  const list = document.createElement("ul");
  lesson.learn.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    list.append(li);
  });
  learn.append(learnTitle, list);

  const core = createSection("Core explanation", lesson.core);
  const example = createSection("Example", lesson.example);
  const risk = createSection("Risks and exceptions", lesson.risk);
  const quiz = renderQuiz(lesson);
  const sources = renderSources(lesson.sources);
  const next = createSection("Next lesson", "Choose another lesson from the list, or use the calculator to see how assumptions change an estimate.");

  selectors.lessonReader.append(header, progress, summary, learn, core, example, quiz, risk, sources, next);
}

function renderQuiz(lesson) {
  const section = document.createElement("section");
  section.className = "quiz-panel";
  const title = document.createElement("h4");
  title.textContent = "Quick check";
  const question = document.createElement("p");
  question.textContent = lesson.quiz.question;
  const fieldset = document.createElement("fieldset");
  const legend = document.createElement("legend");
  legend.textContent = "Choose one answer";
  fieldset.append(legend);
  const name = `quiz-${lesson.id}`;
  lesson.quiz.options.forEach((option) => {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "radio";
    input.name = name;
    input.value = option;
    label.append(input, document.createTextNode(` ${option}`));
    fieldset.append(label);
  });
  const feedback = document.createElement("p");
  feedback.className = "quiz-feedback";
  const button = createButton("Check answer", "secondary", async () => {
    const selected = fieldset.querySelector(`input[name="${name}"]:checked`);
    if (!selected) {
      feedback.textContent = "Choose an answer first.";
      return;
    }
    const correct = selected.value === lesson.quiz.answer;
    state.progress.quizScores[lesson.id] = {
      score: correct ? 1 : 0,
      attemptedAt: new Date().toISOString()
    };
    if (correct) {
      awardBadge("Careful checker");
    }
    await commitState(correct ? "Quiz answer saved." : "Quiz attempt saved.");
    feedback.textContent = correct ? lesson.quiz.feedback : "Not quite. Review the summary and try again.";
    renderProgress();
  });
  section.append(title, question, fieldset, button, feedback);
  return section;
}

function renderSources(sources) {
  const section = document.createElement("section");
  section.className = "source-panel";
  const title = document.createElement("h4");
  title.textContent = "Sources";
  const list = document.createElement("ul");
  sources.forEach((source) => {
    const li = document.createElement("li");
    const link = document.createElement("a");
    link.href = source.url;
    link.rel = "noopener";
    link.textContent = source.label;
    li.append(link);
    list.append(li);
  });
  section.append(title, list);
  return section;
}

function createSection(titleText, bodyText) {
  const section = document.createElement("section");
  const title = document.createElement("h4");
  title.textContent = titleText;
  const body = document.createElement("p");
  body.textContent = bodyText;
  section.append(title, body);
  return section;
}

function createButton(label, variant, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `button ${variant}`;
  button.textContent = label;
  button.addEventListener("click", handler);
  return button;
}

function renderFacts() {
  selectors.factsTable.replaceChildren();
  retirementFacts2026.limits.forEach((fact) => {
    const row = document.createElement("tr");
    const label = document.createElement("th");
    label.scope = "row";
    label.textContent = fact.label;
    const value = document.createElement("td");
    value.textContent = formatMoney(fact.value);
    row.append(label, value);
    selectors.factsTable.append(row);
  });
}

function renderLimit(accountType, age) {
  selectors.limitResult.replaceChildren();
  try {
    const result = contributionLimitFor(accountType, age);
    const title = document.createElement("h3");
    title.textContent = result.label;
    const amount = document.createElement("p");
    amount.className = "limit-amount";
    amount.textContent = formatMoney(result.amount);
    const list = document.createElement("ul");
    result.pieces.forEach((piece) => {
      const item = document.createElement("li");
      item.textContent = `${piece.label}: ${formatMoney(piece.amount)}`;
      list.append(item);
    });
    const caution = document.createElement("p");
    caution.className = "fine-print";
    caution.textContent = result.caution;
    const source = document.createElement("p");
    source.className = "source-note";
    source.textContent = `Effective year ${retirementFacts2026.effectiveYear}. Reviewed ${retirementFacts2026.reviewedAt}. Authority: ${retirementFacts2026.jurisdiction}.`;
    selectors.limitResult.append(title, amount, list, caution, source);
  } catch (error) {
    const banner = document.createElement("p");
    banner.className = "error-banner";
    banner.textContent = error.message;
    selectors.limitResult.append(banner);
  }
}

async function calculateAndRenderProjection(formData, countRun) {
  selectors.projectionError.hidden = true;
  selectors.projectionError.textContent = "";
  try {
    const projection = calculateProjection(Object.fromEntries(formData));
    renderProjection(projection);
    if (countRun) {
      state.progress.calculatorRuns += 1;
      awardBadge("Estimate explorer");
      await commitState("Estimate updated.");
      renderProgress();
    }
  } catch (error) {
    selectors.projectionResults.replaceChildren();
    selectors.projectionChart.replaceChildren();
    selectors.projectionTableBody.replaceChildren();
    selectors.projectionError.textContent = error.message;
    selectors.projectionError.hidden = false;
  }
}

function renderProjection(projection) {
  selectors.projectionResults.replaceChildren();
  selectors.projectionChart.replaceChildren();
  selectors.projectionTableBody.replaceChildren();

  const summary = document.createElement("div");
  summary.className = "result-summary";
  const items = [
    ["Estimated future value", projection.totals.nominalCents],
    ["In today's dollars", projection.totals.realCents],
    ["Total contributions", projection.totals.contributionCents],
    ["Estimated growth", projection.totals.estimatedGrowthCents]
  ];
  items.forEach(([label, cents]) => {
    const block = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = formatMoney(cents / 100);
    const span = document.createElement("span");
    span.textContent = label;
    block.append(strong, span);
    summary.append(block);
  });

  const assumptions = document.createElement("p");
  assumptions.className = "fine-print";
  assumptions.textContent = `Estimate assumes ${projection.assumptions.compounding.toLowerCase()} compounding, ${(projection.assumptions.nominalReturn * 100).toFixed(1)}% nominal annual return, ${(projection.assumptions.inflation * 100).toFixed(1)}% inflation, and ${projection.assumptions.timing}-of-month contributions. Results are estimates, not promises.`;
  selectors.projectionResults.append(summary, assumptions);

  const max = Math.max(...projection.yearly.map((row) => row.nominalCents));
  projection.yearly.forEach((row) => {
    const bar = document.createElement("div");
    bar.className = "chart-row";
    const label = document.createElement("span");
    label.textContent = `Year ${row.year}`;
    const track = document.createElement("span");
    track.className = "chart-track";
    const fill = document.createElement("span");
    fill.className = "chart-fill";
    fill.style.width = `${Math.max(2, (row.nominalCents / max) * 100)}%`;
    track.append(fill);
    const value = document.createElement("span");
    value.textContent = formatMoney(row.nominalCents / 100);
    bar.append(label, track, value);
    selectors.projectionChart.append(bar);

    const tableRow = document.createElement("tr");
    [row.year, row.contributionCents, row.nominalCents, row.realCents].forEach((valueItem, index) => {
      const cell = document.createElement(index === 0 ? "th" : "td");
      if (index === 0) {
        cell.scope = "row";
        cell.textContent = String(valueItem);
      } else {
        cell.textContent = formatMoney(valueItem / 100);
      }
      tableRow.append(cell);
    });
    selectors.projectionTableBody.append(tableRow);
  });
}

function renderProgress() {
  selectors.progressSummary.replaceChildren();
  selectors.badgeRow.replaceChildren();
  const completed = Object.keys(state.progress.completedLessons).length;
  const quizAttempts = Object.keys(state.progress.quizScores).length;
  const items = [
    ["Lessons completed", `${completed} of ${lessons.length}`],
    ["Bookmarks", String(state.progress.bookmarks.length)],
    ["Quiz attempts", String(quizAttempts)],
    ["Calculator runs", String(state.progress.calculatorRuns)]
  ];
  const list = document.createElement("dl");
  list.className = "progress-stats";
  items.forEach(([label, value]) => {
    const wrapper = document.createElement("div");
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    wrapper.append(dt, dd);
    list.append(wrapper);
  });
  selectors.progressSummary.append(list);

  if (state.progress.badges.length === 0) {
    const empty = document.createElement("p");
    empty.className = "fine-print";
    empty.textContent = "Badges appear after lessons, quizzes, and calculator practice.";
    selectors.badgeRow.append(empty);
    return;
  }

  state.progress.badges.forEach((badge) => {
    const chip = document.createElement("span");
    chip.className = "badge";
    chip.textContent = badge;
    selectors.badgeRow.append(chip);
  });
}

function toggleBookmark(lessonId) {
  const bookmarks = new Set(state.progress.bookmarks);
  if (bookmarks.has(lessonId)) {
    bookmarks.delete(lessonId);
  } else {
    bookmarks.add(lessonId);
  }
  state.progress.bookmarks = Array.from(bookmarks);
}

function awardBadge(label) {
  if (!state.progress.badges.includes(label)) {
    state.progress.badges.push(label);
  }
}

async function exportState() {
  try {
    const payload = sanitizeExportPayload(state);
    const checksum = await sha256Base64(stableStringify(payload));
    const envelope = {
      format: "nestegghero-backup",
      schemaVersion: BACKUP_SCHEMA_VERSION,
      exportedAt: new Date().toISOString(),
      appVersion: APP_VERSION,
      checksum,
      payload
    };
    const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `NestEggHero_backup_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast("Progress backup exported.");
  } catch (error) {
    showToast(error.message);
  }
}

async function handleImportSelection(event) {
  selectors.importPreview.replaceChildren();
  pendingImport = null;
  const file = event.target.files?.[0];
  if (!file) {
    return;
  }
  try {
    if (file.size > MAX_IMPORT_BYTES) {
      throw new Error("Backup file is too large.");
    }
    if (file.type && file.type !== "application/json") {
      throw new Error("Choose a JSON backup file.");
    }
    const text = await file.text();
    const envelope = JSON.parse(text);
    validateBackupEnvelope(envelope);
    const expected = await sha256Base64(stableStringify(envelope.payload));
    if (expected !== envelope.checksum) {
      throw new Error("Backup checksum does not match the payload.");
    }
    pendingImport = envelope.payload;
    renderImportPreview(envelope.payload);
  } catch (error) {
    const banner = document.createElement("p");
    banner.className = "error-banner";
    banner.textContent = error.message;
    selectors.importPreview.append(banner);
  } finally {
    event.target.value = "";
  }
}

function renderImportPreview(payload) {
  const title = document.createElement("h4");
  title.textContent = "Import preview";
  const list = document.createElement("ul");
  [
    ["Completed lessons", Object.keys(payload.progress.completedLessons || {}).length],
    ["Bookmarks", (payload.progress.bookmarks || []).length],
    ["Quiz scores", Object.keys(payload.progress.quizScores || {}).length],
    ["Badges", (payload.progress.badges || []).length]
  ].forEach(([label, value]) => {
    const item = document.createElement("li");
    item.textContent = `${label}: ${value}`;
    list.append(item);
  });
  const merge = createButton("Merge", "primary", () => applyImport("merge"));
  const replace = createButton("Replace", "secondary", () => applyImport("replace"));
  const actions = document.createElement("div");
  actions.className = "form-actions";
  actions.append(merge, replace);
  selectors.importPreview.append(title, list, actions);
}

async function applyImport(mode) {
  if (!pendingImport) {
    return;
  }
  const imported = cloneAllowedState(pendingImport);
  if (mode === "replace") {
    state = {
      ...imported,
      updatedAt: new Date().toISOString()
    };
  } else {
    state = mergeState(state, imported);
  }
  pendingImport = null;
  await saveState(state);
  selectors.importPreview.replaceChildren();
  showToast(mode === "replace" ? "Progress replaced." : "Progress merged.");
  renderAll();
}

function mergeState(current, imported) {
  const now = new Date().toISOString();
  return {
    ...current,
    updatedAt: now,
    preferences: {
      ...current.preferences,
      ...imported.preferences
    },
    progress: {
      completedLessons: {
        ...current.progress.completedLessons,
        ...imported.progress.completedLessons
      },
      bookmarks: Array.from(new Set([...current.progress.bookmarks, ...imported.progress.bookmarks])),
      quizScores: {
        ...current.progress.quizScores,
        ...imported.progress.quizScores
      },
      badges: Array.from(new Set([...current.progress.badges, ...imported.progress.badges])),
      calculatorRuns: Math.max(current.progress.calculatorRuns, imported.progress.calculatorRuns)
    }
  };
}

function cloneAllowedState(candidate) {
  return {
    schemaVersion: BACKUP_SCHEMA_VERSION,
    createdAt: typeof candidate.createdAt === "string" ? candidate.createdAt : new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    preferences: {
      theme: ["system", "light", "dark"].includes(candidate.preferences?.theme) ? candidate.preferences.theme : "system",
      kidSpeak: Boolean(candidate.preferences?.kidSpeak),
      textSize: candidate.preferences?.textSize === "large" ? "large" : "normal"
    },
    progress: {
      completedLessons: cleanRecord(candidate.progress?.completedLessons),
      bookmarks: cleanLessonList(candidate.progress?.bookmarks),
      quizScores: cleanRecord(candidate.progress?.quizScores),
      badges: Array.isArray(candidate.progress?.badges) ? candidate.progress.badges.filter((item) => typeof item === "string").slice(0, 20) : [],
      calculatorRuns: Number.isFinite(candidate.progress?.calculatorRuns) ? Math.max(0, Math.floor(candidate.progress.calculatorRuns)) : 0
    }
  };
}

function cleanRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  const clean = {};
  Object.keys(value).forEach((key) => {
    if (lessons.some((lesson) => lesson.id === key)) {
      clean[key] = value[key];
    }
  });
  return clean;
}

function cleanLessonList(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  const allowed = new Set(lessons.map((lesson) => lesson.id));
  return Array.from(new Set(value.filter((item) => allowed.has(item))));
}

function sanitizeExportPayload(source) {
  return cloneAllowedState(source);
}

async function sha256Base64(text) {
  const bytes = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  const binary = Array.from(new Uint8Array(hash), (byte) => String.fromCharCode(byte)).join("");
  return btoa(binary);
}

async function loadState() {
  try {
    const db = await openDatabase();
    dbHandle = db;
    const stored = await getFromStore(db, STATE_KEY);
    if (stored) {
      return mergeState(defaultState(), cloneAllowedState(stored));
    }
    const fresh = defaultState();
    await saveState(fresh);
    return fresh;
  } catch {
    return defaultState();
  }
}

async function commitState(message) {
  state.updatedAt = new Date().toISOString();
  await saveState(state);
  renderProgress();
  showToast(message);
}

async function saveState(nextState) {
  if (!dbHandle) {
    try {
      dbHandle = await openDatabase();
    } catch {
      return;
    }
  }
  await putInStore(dbHandle, STATE_KEY, nextState);
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    if (!("indexedDB" in window)) {
      reject(new Error("IndexedDB is not available."));
      return;
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function getFromStore(db, key) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readonly");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function putInStore(db, key, value) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readwrite");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put(value, key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

function applyTheme() {
  document.documentElement.dataset.theme = state.preferences.theme;
}

function showToast(message) {
  selectors.toast.textContent = message;
  selectors.toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    selectors.toast.hidden = true;
  }, 3200);
}

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) {
    selectors.offlineStatus.textContent = "Offline cache unavailable in this browser.";
    return;
  }
  window.addEventListener("online", () => {
    selectors.offlineStatus.textContent = "Online. Cached lessons remain available.";
  });
  window.addEventListener("offline", () => {
    selectors.offlineStatus.textContent = "Offline. Cached lessons and calculators still work.";
  });
  navigator.serviceWorker.register("sw.js").then(() => {
    selectors.offlineStatus.textContent = navigator.onLine ? "Online. Offline cache ready after first visit." : "Offline. Cached content is available.";
  }).catch(() => {
    selectors.offlineStatus.textContent = "Offline cache could not start here.";
  });
}
