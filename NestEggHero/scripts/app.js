import { allFacts, getFact, sourceListForFactIds, REVIEWED_AT, NEXT_REVIEW_AT } from "./facts.js";
import { ARTICLES, TOPICS, GLOSSARY, getArticle } from "./content.js";
import { CALCULATORS, getCalculator, runCalculator, CalculatorInputError } from "./calculators.js";
import { defaultLearning, loadLearning, loadPreferences, savePreferences, createAutosaver, persistLearning } from "./storage.js";
import { buildEnvelope, backupFilename, inspectBackupText, mergeLearning, replaceLearning, BackupError, GUARDS } from "./backup.js";

const app = document.querySelector("#app");
const toast = document.querySelector("#toast");
const notice = document.querySelector("#notice");
const nav = document.querySelector("#primaryNav");
const navToggle = document.querySelector("#navToggle");
const themeToggle = document.querySelector("#themeToggle");
const kidToggle = document.querySelector("#kidSpeakToggle");
const textSizeToggle = document.querySelector("#textSizeToggle");
const offlineNote = document.querySelector("#offlineNote");

const BADGES = [
  { id: "first-lesson", name: "First lesson finished" },
  { id: "library-complete", name: "Library complete" },
  { id: "fact-checker", name: "Fact checker" },
  { id: "tool-builder", name: "Calculator explorer" },
  { id: "safe-keeper", name: "Safe keeper" }
];

let state = { preferences: loadPreferences(), learning: defaultLearning(), persisted: false };
let autosaver = createAutosaver(() => showNotice("Local saving is blocked or full. Export a backup from Progress to keep your work."));

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === false || value === null || value === undefined) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "html") node.innerHTML = value;
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

function pick(value) {
  if (typeof value === "string") return value;
  return state.preferences.kidSpeak ? value.kid : value.plain;
}

function textWithTokens(text) {
  const output = [];
  const pattern = /\[\[(fact|term):([a-z0-9-]+)\]\]/g;
  let index = 0;
  for (const match of text.matchAll(pattern)) {
    if (match.index > index) output.push(document.createTextNode(text.slice(index, match.index)));
    if (match[1] === "fact") {
      const fact = getFact(match[2]);
      output.push(el("button", { class: "fact-token", type: "button", "aria-label": `${fact.display}. ${fact.claim}. Source ${fact.sourceTitle}.`, onclick: () => showNotice(`${fact.claim}: ${fact.display}. Effective ${fact.effectiveYear}. Source: ${fact.sourceTitle}. Reviewed ${fact.reviewedAt}.`) }, fact.display, el("sup", { text: String(fact.effectiveYear || "src") })));
    } else {
      const term = GLOSSARY[match[2]];
      output.push(el("button", { class: "term-token", type: "button", onclick: () => showNotice(`${term.word}: ${state.preferences.kidSpeak ? term.kid : term.plain}`) }, term.word));
    }
    index = match.index + match[0].length;
  }
  if (index < text.length) output.push(document.createTextNode(text.slice(index)));
  return output;
}

function showToast(message) {
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { toast.hidden = true; }, 3200);
}

function showNotice(message) {
  notice.textContent = message;
  notice.hidden = false;
  clearTimeout(showNotice.timer);
  showNotice.timer = setTimeout(() => { notice.hidden = true; }, 7000);
}

function saveSoon() {
  autosaver.queue(state.learning);
}

async function saveNow() {
  try {
    state.learning = await persistLearning(state.learning);
    state.persisted = true;
  } catch {
    state.persisted = false;
    showNotice("Local save failed. Export a backup before closing the browser.");
  }
}

function applyPreferences() {
  document.documentElement.dataset.theme = state.preferences.theme;
  document.documentElement.dataset.textSize = state.preferences.textSize;
  kidToggle.setAttribute("aria-pressed", String(state.preferences.kidSpeak));
  textSizeToggle.setAttribute("aria-pressed", String(state.preferences.textSize === "large"));
  themeToggle.textContent = state.preferences.theme === "dark" ? "Light" : "Dark";
}

function setPreference(mutator) {
  mutator(state.preferences);
  savePreferences(state.preferences);
  applyPreferences();
  renderRoute();
}

function card(title, body, href) {
  return el("article", { class: "card" }, el("h3", {}, href ? el("a", { href, text: title }) : title), el("p", {}, ...(Array.isArray(body) ? body : [body])));
}

function disclosure() {
  return el("aside", { class: "disclosure", "aria-label": "Educational disclosure" },
    el("strong", { text: "Educational disclosure" }),
    el("p", { text: "NestEggHero provides general education only. It does not provide individualized tax, legal, fiduciary, or investment advice." }),
    el("p", { class: "muted", text: `Facts reviewed ${REVIEWED_AT}. Next scheduled review ${NEXT_REVIEW_AT}.` })
  );
}

function breadcrumbs(items) {
  return el("nav", { class: "breadcrumbs", "aria-label": "Breadcrumb" }, items.map((item, i) => i === items.length - 1 ? el("span", { "aria-current": "page", text: item[0] }) : el("a", { href: item[1], text: item[0] })));
}

function viewHome() {
  const readCount = Object.keys(state.learning.readLessons).length;
  return el("div", { class: "view" },
    el("section", { class: "hero" },
      el("div", { class: "hero-copy" },
        el("p", { class: "eyebrow", text: "Source-labeled financial learning" }),
        el("h1", { text: "Understand retirement numbers before they become decisions." }),
        el("p", { class: "lead", text: state.preferences.kidSpeak ? "Short lessons, honest examples, and calculators you can try without entering private account details." : "Eight guided lessons, eight deterministic calculators, and a fact registry where changing 2026 figures carry an effective year and official source." }),
        el("div", { class: "actions" }, el("a", { class: "btn primary", href: "#/learn", text: "Start learning" }), el("a", { class: "btn ghost", href: "#/tools", text: "Open calculators" }))
      ),
      el("div", { class: "hero-panel" },
        el("h2", { text: "Learning state" }),
        el("dl", { class: "metric-grid" },
          metric("Lessons read", `${readCount}/${ARTICLES.length}`),
          metric("Calculators", String(CALCULATORS.length)),
          metric("Fact records", String(allFacts().length))
        ),
        el("p", { class: "muted", text: "Everything runs in your browser. No bank credentials, tax IDs, account numbers, or sensitive financial records are requested." })
      )
    ),
    el("section", { class: "band" },
      el("h2", { text: "What makes this careful" }),
      el("div", { class: "card-grid" },
        card("Facts cannot float free", "Every changing number resolves through the registry with source, effective year, authority status, reviewer, and next-review date.", "#/facts"),
        card("Calculators show assumptions", "Results are estimates, not promises. Assumptions and tables sit beside the headline result.", "#/tools"),
        card("Progress stays local", "Learning state uses IndexedDB; only low-risk preferences use localStorage. Backups are validated before import.", "#/progress")
      )
    ),
    disclosure()
  );
}

function metric(label, value) {
  return el("div", {}, el("dt", { text: label }), el("dd", { text: value }));
}

function viewLibrary(topic = "All") {
  const shown = ARTICLES.filter((article) => topic === "All" || article.topic === topic);
  return el("div", { class: "view" },
    breadcrumbs([["Home", "#/"], ["Lessons", "#/learn"]]),
    el("header", { class: "view-header" }, el("p", { class: "eyebrow", text: "Guided lessons" }), el("h1", { text: "Learn the rule, the caveat, and the source." }), el("p", { class: "lead", text: "Each lesson follows the same order: what you will learn, summary, explanation, example, activity, risks, takeaways, quiz, sources, next step." })),
    el("div", { class: "chip-row", role: "group", "aria-label": "Filter by topic" }, ["All", ...TOPICS].map((item) => el("button", { class: "chip", type: "button", "aria-pressed": String(item === topic), onclick: () => { location.hash = item === "All" ? "#/learn" : `#/learn/${encodeURIComponent(item)}`; } }, item))),
    el("div", { class: "card-grid" }, shown.map((article) => {
      const done = Boolean(state.learning.readLessons[article.slug]);
      return el("article", { class: "card lesson-card" }, el("p", { class: "eyebrow", text: article.topic }), el("h2", {}, el("a", { href: `#/lesson/${article.slug}`, text: article.title })), el("p", {}, ...textWithTokens(pick(article.summary))), el("p", { class: "muted", text: `${article.minutes} min | ${article.authorityStatus} | ${done ? "Read" : "Not read"}` }));
    })),
    disclosure()
  );
}

function viewArticle(slug) {
  const article = getArticle(slug);
  const marked = state.learning.bookmarks.includes(article.slug);
  const done = Boolean(state.learning.readLessons[article.slug]);
  const quizState = state.learning.quizScores[article.slug];
  return el("div", { class: "view article-view" },
    breadcrumbs([["Home", "#/"], ["Lessons", "#/learn"], [article.title, `#/lesson/${slug}`]]),
    el("header", { class: "article-header" },
      el("p", { class: "eyebrow", text: article.topic }),
      el("h1", { text: article.title }),
      el("p", { class: "article-meta", text: `${article.minutes} min | ${article.authorityStatus} | Reviewed ${article.updatedAt}${article.effectiveYear ? ` | Effective year ${article.effectiveYear}` : ""}` }),
      el("div", { class: "actions" },
        el("button", { class: "btn ghost", type: "button", "aria-pressed": String(marked), onclick: () => toggleBookmark(article.slug) }, marked ? "Saved" : "Save lesson"),
        el("button", { class: "btn primary", type: "button", disabled: done, onclick: () => markRead(article.slug) }, done ? "Read" : "Mark read")
      )
    ),
    el("div", { class: "article-layout" },
      el("nav", { class: "toc", "aria-label": "On this page" }, el("strong", { text: "On this page" }), el("a", { href: "#learn-goals", text: "What you will learn" }), ...article.sections.map((section) => el("a", { href: `#/lesson/${slug}`, onclick: () => document.querySelector(`#${section.id}`)?.scrollIntoView(), text: section.heading }))),
      el("article", { class: "article-body" },
        sectionBlock("learn-goals", "What you will learn", el("ul", {}, article.learn.map((item) => el("li", { text: item })))),
        sectionBlock("summary", "Plain-language summary", el("p", {}, ...textWithTokens(pick(article.summary)))),
        article.sections.map((section) => sectionBlock(section.id, section.heading, section.paragraphs.map((p) => el("p", {}, ...textWithTokens(pick(p)))), highlightButton(article.slug, section.id))),
        sectionBlock("example", "Example", el("p", {}, ...textWithTokens(pick(article.example)))),
        activityBlock(article.activity),
        sectionBlock("risks", "Risks and exceptions", el("ul", {}, article.risks.map((item) => el("li", { text: item })))),
        sectionBlock("takeaways", "Key takeaways", el("ul", {}, article.takeaways.map((item) => el("li", { text: item })))),
        quizBlock(article, quizState),
        sourcesBlock(sourceListForFactIds(article.factIds)),
        el("div", { class: "next-step" }, el("a", { class: "btn primary", href: `#/lesson/${article.next}`, text: `Next lesson: ${getArticle(article.next).title}` }))
      )
    ),
    disclosure()
  );
}

function sectionBlock(id, title, ...children) {
  return el("section", { class: "article-section", id }, el("h2", { text: title }), children.flat());
}

function highlightButton(slug, id) {
  const ref = `${slug}#${id}`;
  const on = state.learning.highlights.includes(ref);
  return el("button", { class: "inline-action", type: "button", "aria-pressed": String(on), onclick: () => {
    const set = new Set(state.learning.highlights);
    if (set.has(ref)) set.delete(ref); else set.add(ref);
    state.learning.highlights = Array.from(set);
    saveSoon();
    renderRoute();
  } }, on ? "Highlighted" : "Highlight section");
}

function activityBlock(activity) {
  const href = activity.kind === "calculator" ? `#/tools/${activity.slug}` : "#/facts";
  return sectionBlock("activity", "Interactive activity", el("p", { text: activity.label }), el("a", { class: "btn ghost", href, text: "Open activity" }));
}

function quizBlock(article, quizState) {
  const form = el("form", { class: "quiz" });
  article.quiz.forEach((question, qIndex) => {
    form.append(el("fieldset", {}, el("legend", { text: question.question }), question.options.map((option, index) => el("label", { class: "choice" }, el("input", { type: "radio", name: `q${qIndex}`, value: String(index) }), option))));
  });
  const result = el("p", { class: "quiz-result", role: "status", "aria-live": "polite" });
  form.append(el("button", { class: "btn primary", type: "submit" }, "Check answers"), result);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    let answered = 0;
    let correct = 0;
    article.quiz.forEach((question, qIndex) => {
      const selected = form.querySelector(`input[name=q${qIndex}]:checked`);
      if (selected) {
        answered += 1;
        if (Number(selected.value) === question.answer) correct += 1;
      }
    });
    if (answered < article.quiz.length) {
      result.textContent = `Answer all ${article.quiz.length} questions first.`;
      return;
    }
    const previous = state.learning.quizScores[article.slug];
    state.learning.quizScores[article.slug] = { correct: Math.max(correct, previous?.correct || 0), total: article.quiz.length, attempts: (previous?.attempts || 0) + 1, bestAt: new Date().toISOString() };
    maybeAward("fact-checker", correct === article.quiz.length);
    saveSoon();
    result.textContent = `${correct} of ${article.quiz.length} correct. ${article.quiz[0].explain}`;
    renderProgressSnapshot();
  });
  return sectionBlock("quiz", "Quick check", quizState ? el("p", { class: "muted", text: `Best score: ${quizState.correct}/${quizState.total}` }) : null, form);
}

function sourcesBlock(sources) {
  return sectionBlock("sources", "Sources", sources.length ? el("ul", {}, sources.map((source) => el("li", {}, el("a", { href: source.url, rel: "noopener", text: source.title })))) : el("p", { text: "Mathematical concept lesson; formulas are shown in the calculator assumptions." }));
}

function viewTools() {
  return el("div", { class: "view" }, breadcrumbs([["Home", "#/"], ["Calculators", "#/tools"]]), el("header", { class: "view-header" }, el("p", { class: "eyebrow", text: "Estimate lab" }), el("h1", { text: "Calculators that say what they assume." }), el("p", { class: "lead", text: "Each tool is deterministic, labels results as estimates, and uses display rounding only after calculation." })), el("div", { class: "card-grid" }, CALCULATORS.map((calc) => card(calc.name, calc.blurb, `#/tools/${calc.slug}`))), disclosure());
}

function viewCalculator(slug) {
  const calc = getCalculator(slug);
  const results = el("div", { class: "results", "aria-live": "polite" });
  const form = el("form", { class: "tool-form" });
  calc.fields.forEach((field) => {
    const input = field.kind === "choice" ? el("select", { name: field.id }, field.options.map((option) => el("option", { value: option.value, selected: option.value === field.defaultValue, text: option.label }))) : el("input", { name: field.id, type: "number", inputmode: "decimal", value: field.defaultValue, step: field.step || "1" });
    form.append(el("label", {}, el("span", { text: field.label }), field.suffix ? el("span", { class: "input-wrap" }, input, el("span", { text: field.suffix })) : input));
  });
  form.append(el("button", { class: "btn primary", type: "submit" }, "Run estimate"));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    try {
      const raw = Object.fromEntries(new FormData(form));
      const outcome = runCalculator(slug, raw);
      state.learning.calculatorRuns[slug] = (state.learning.calculatorRuns[slug] || 0) + 1;
      maybeAward("tool-builder", Object.keys(state.learning.calculatorRuns).length >= 3);
      saveSoon();
      renderOutcome(results, outcome);
    } catch (error) {
      results.replaceChildren(el("p", { class: "error", text: error instanceof CalculatorInputError ? error.message : "This estimate could not run." }));
    }
  });
  setTimeout(() => form.requestSubmit(), 0);
  return el("div", { class: "view" }, breadcrumbs([["Home", "#/"], ["Calculators", "#/tools"], [calc.name, `#/tools/${slug}`]]), el("header", { class: "view-header" }, el("p", { class: "eyebrow", text: "Estimate, not promise" }), el("h1", { text: calc.name }), el("p", { class: "lead", text: calc.blurb })), el("div", { class: "tool-layout" }, form, results), disclosure());
}

function renderOutcome(host, outcome) {
  host.replaceChildren(el("section", { class: "result-card" }, el("p", { class: "eyebrow", text: outcome.headline.label }), el("h2", { text: outcome.headline.value }), el("div", { class: "metric-grid" }, (outcome.stats || []).map((item) => metric(item.label, item.value))), el("h3", { text: "Assumptions" }), el("ul", {}, outcome.assumptions.map((item) => el("li", { text: item }))), outcome.chart ? chart(outcome.chart) : null, outcome.table ? dataTable(outcome.table) : null));
}

function chart(data) {
  const max = Math.max(...data.points, 1);
  return el("div", { class: "chart", role: "img", "aria-label": data.label }, data.points.slice(0, 60).map((point, index) => el("div", { class: "chart-row" }, el("span", { text: String(index + 1) }), el("progress", { class: "chart-progress", max, value: Math.max(0, point), "aria-label": `${data.label} year ${index + 1}: ${Math.round(point)}` }), el("span", { text: String(Math.round(point)) }))));
}

function dataTable(table) {
  return el("div", { class: "table-wrap" }, el("table", {}, el("caption", { text: table.caption }), el("thead", {}, el("tr", {}, table.columns.map((col) => el("th", { scope: "col", text: col })))), el("tbody", {}, table.rows.map((row) => el("tr", {}, row.map((cell, index) => el(index === 0 ? "th" : "td", index === 0 ? { scope: "row", text: cell } : { text: cell })))))));
}

function viewFacts() {
  const facts = allFacts();
  maybeAward("fact-checker", true);
  return el("div", { class: "view" }, breadcrumbs([["Home", "#/"], ["Fact registry", "#/facts"]]), el("header", { class: "view-header" }, el("p", { class: "eyebrow", text: "Authority before polish" }), el("h1", { text: "Fact registry" }), el("p", { class: "lead", text: "Changing financial facts publish only when the record includes value, year, jurisdiction, authority, source, retrieval date, reviewer, and next review." })), el("div", { class: "table-wrap" }, el("table", {}, el("thead", {}, el("tr", {}, ["Claim", "Value", "Authority", "Source", "Review"].map((h) => el("th", { scope: "col", text: h })))), el("tbody", {}, facts.map((fact) => el("tr", {}, el("th", { scope: "row", text: fact.claim }), el("td", { text: fact.display }), el("td", { text: fact.authorityStatus }), el("td", {}, el("a", { href: fact.sourceUrl, rel: "noopener", text: fact.sourceTitle })), el("td", { text: `${fact.reviewedAt}; next ${fact.nextReviewAt}` })))))), disclosure());
}

function viewProgress() {
  const importPreview = el("div", { class: "import-preview", "aria-live": "polite" });
  const file = el("input", { type: "file", accept: "application/json,.json", class: "visually-hidden", id: "importFile" });
  file.addEventListener("change", () => file.files?.[0] && handleImport(file.files[0], importPreview));
  const readCount = Object.keys(state.learning.readLessons).length;
  return el("div", { class: "view" }, breadcrumbs([["Home", "#/"], ["Progress", "#/progress"]]), el("header", { class: "view-header" }, el("p", { class: "eyebrow", text: "Local learning state" }), el("h1", { text: "Keep only what helps you resume." }), el("p", { class: "lead", text: "Backups include lessons, bookmarks, highlights, quiz scores, badges, streak, and preferences. They exclude calculator inputs, analytics counters, identifiers, credentials, and financial records." })), el("div", { class: "progress-grid" }, el("section", { class: "panel" }, el("h2", { text: "Snapshot" }), el("dl", { class: "metric-grid" }, metric("Lessons read", `${readCount}/${ARTICLES.length}`), metric("Bookmarks", String(state.learning.bookmarks.length)), metric("Highlights", String(state.learning.highlights.length)), metric("Badges", String(state.learning.badges.length)))), el("section", { class: "panel" }, el("h2", { text: "Backup and restore" }), el("p", { class: "muted", text: `Imports are capped at ${Math.round(GUARDS.maxBytes / 1000000)} MB, checked for unsafe keys, verified by checksum, previewed, then merged or replaced.` }), el("div", { class: "actions" }, el("button", { class: "btn primary", type: "button", onclick: exportBackup }, "Export progress"), el("label", { class: "btn ghost", for: "importFile" }, "Import JSON"), file), importPreview)), badgesPanel(), disclosure());
}

function badgesPanel() {
  const earned = new Set(state.learning.badges);
  return el("section", { class: "panel" }, el("h2", { text: "Badges" }), el("div", { class: "badge-row" }, BADGES.map((badge) => el("span", { class: earned.has(badge.id) ? "badge earned" : "badge", text: badge.name }))));
}

async function exportBackup() {
  try {
    const envelope = await buildEnvelope(state.preferences, state.learning);
    const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = el("a", { href: url, download: backupFilename() });
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    maybeAward("safe-keeper", true);
    saveSoon();
    showToast("Backup exported.");
  } catch {
    showNotice("The backup could not be created in this browser.");
  }
}

async function handleImport(file, host) {
  host.replaceChildren();
  try {
    const text = await file.text();
    const inspected = await inspectBackupText(text, file.size);
    host.append(el("div", { class: "panel" }, el("h3", { text: `Backup from ${inspected.exportedAt.slice(0, 10)}` }), el("ul", {}, inspected.summary.map((item) => el("li", { text: `${item.label}: ${item.count}` }))), el("div", { class: "actions" }, el("button", { class: "btn primary", type: "button", onclick: () => applyImport(inspected, "merge", host) }, "Merge"), el("button", { class: "btn ghost", type: "button", onclick: () => applyImport(inspected, "replace", host) }, "Replace"))));
  } catch (error) {
    host.append(el("p", { class: "error", text: error instanceof BackupError ? error.message : "This backup could not be read. Your progress was not changed." }));
  }
}

async function applyImport(inspected, mode, host) {
  if (mode === "replace") {
    state.preferences = inspected.payload.preferences;
    state.learning = replaceLearning(state.learning, inspected.payload.learning, inspected.payload.createdAt);
  } else {
    state.preferences = { ...state.preferences, ...inspected.payload.preferences };
    state.learning = mergeLearning(state.learning, inspected.payload.learning);
  }
  savePreferences(state.preferences);
  applyPreferences();
  await saveNow();
  host.replaceChildren(el("p", { class: "success", text: mode === "replace" ? "Backup restored." : "Backup merged." }));
  renderRoute();
}

function toggleBookmark(slug) {
  const set = new Set(state.learning.bookmarks);
  if (set.has(slug)) set.delete(slug); else set.add(slug);
  state.learning.bookmarks = Array.from(set);
  saveSoon();
  renderRoute();
}

function markRead(slug) {
  state.learning.readLessons[slug] = new Date().toISOString();
  maybeAward("first-lesson", true);
  maybeAward("library-complete", ARTICLES.every((article) => state.learning.readLessons[article.slug]));
  saveSoon();
  showToast("Lesson marked read.");
  renderRoute();
}

function maybeAward(id, condition) {
  if (!condition || state.learning.badges.includes(id)) return;
  state.learning.badges.push(id);
  showToast(`Badge earned: ${BADGES.find((badge) => badge.id === id)?.name || id}`);
}

function renderProgressSnapshot() {
  maybeAward("library-complete", ARTICLES.every((article) => state.learning.readLessons[article.slug]));
}

function missing(message) {
  return el("div", { class: "view" }, el("section", { class: "empty-state" }, el("h1", { text: message }), el("a", { class: "btn primary", href: "#/", text: "Go home" })));
}

function path() {
  return location.hash.replace(/^#\/?/, "").replace(/\/+$/, "") || "";
}

function renderRoute() {
  const current = path();
  let view;
  try {
    if (current === "") view = viewHome();
    else if (current === "learn") view = viewLibrary();
    else if (current.startsWith("learn/")) view = viewLibrary(decodeURIComponent(current.slice(6)));
    else if (current.startsWith("lesson/")) view = viewArticle(current.slice(7));
    else if (current === "tools") view = viewTools();
    else if (current.startsWith("tools/")) view = viewCalculator(current.slice(6));
    else if (current === "facts") view = viewFacts();
    else if (current === "progress") view = viewProgress();
    else view = missing("That page does not exist.");
  } catch (error) {
    view = missing(error.message || "Something went wrong.");
  }
  app.replaceChildren(view);
  app.focus({ preventScroll: true });
  updateNav();
}

function updateNav() {
  const current = path();
  for (const link of nav.querySelectorAll("a")) {
    const target = link.getAttribute("href").replace(/^#\/?/, "").replace(/\/+$/, "") || "";
    const active = target === current || (target && current.startsWith(target + "/"));
    if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  }
}

function bindShell() {
  navToggle.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    navToggle.setAttribute("aria-expanded", String(open));
  });
  nav.addEventListener("click", () => { nav.classList.remove("open"); navToggle.setAttribute("aria-expanded", "false"); });
  themeToggle.addEventListener("click", () => setPreference((p) => { p.theme = p.theme === "dark" ? "light" : "dark"; }));
  kidToggle.addEventListener("click", () => setPreference((p) => { p.kidSpeak = !p.kidSpeak; }));
  textSizeToggle.addEventListener("click", () => setPreference((p) => { p.textSize = p.textSize === "large" ? "normal" : "large"; }));
  window.addEventListener("hashchange", renderRoute);
  window.addEventListener("online", () => { offlineNote.hidden = true; });
  window.addEventListener("offline", () => { offlineNote.hidden = false; });
}

async function init() {
  const loaded = await loadLearning();
  state.learning = loaded.learning;
  state.persisted = loaded.persisted;
  applyPreferences();
  bindShell();
  if (!state.persisted) showNotice("This browser is not allowing local saves. Export a backup from Progress to keep work beyond this session.");
  renderRoute();
  if ("serviceWorker" in navigator && location.protocol.startsWith("http")) navigator.serviceWorker.register("sw.js").catch(() => {});
}

init();
