import { getFact, allFacts, factSources, REVIEWED_AT, NEXT_REVIEW_AT } from "./facts.js";
import { ARTICLES, TOPICS, GLOSSARY, getArticle } from "./articles.js";
import { CALCULATORS, getCalculator, runCalculator, CalculatorInputError } from "./calculators.js";
import {
  loadPreferences, savePreferences, loadLearning, createAutosaver, defaultLearning
} from "./storage.js";
import {
  buildEnvelope, backupFilename, inspectBackupText, mergeLearning, replaceLearning, BackupError, GUARDS
} from "./backup.js";

// ---------------------------------------------------------------------------
// State

const state = {
  preferences: loadPreferences(),
  learning: defaultLearning(),
  storageHealthy: true
};

const autosaver = createAutosaver(() => {
  state.storageHealthy = false;
  showBanner(
    "We could not save locally, possibly because browser storage is full or blocked. Your progress this session still works; download a backup from My progress before clearing space."
  );
});

function commitLearning(mutator) {
  mutator(state.learning);
  autosaver.queue(state.learning);
}

function recordEvent(name) {
  commitLearning((learning) => {
    learning.activity[name] = (learning.activity[name] || 0) + 1;
  });
}

function touchStreak() {
  const today = new Date().toISOString().slice(0, 10);
  commitLearning((learning) => {
    const streak = learning.streak;
    if (!streak.lastActiveDay) {
      learning.streak = { count: 1, lastActiveDay: today, graceUsedOn: "" };
      return;
    }
    if (streak.lastActiveDay === today) {
      return;
    }
    const gap = Math.round(
      (Date.parse(`${today}T00:00:00Z`) - Date.parse(`${streak.lastActiveDay}T00:00:00Z`)) / 86_400_000
    );
    if (gap === 1) {
      learning.streak = { count: streak.count + 1, lastActiveDay: today, graceUsedOn: streak.graceUsedOn };
    } else if (gap === 2 && streak.graceUsedOn !== today) {
      // One missed day is forgiven; streaks are encouragement, not pressure.
      learning.streak = { count: streak.count + 1, lastActiveDay: today, graceUsedOn: today };
    } else {
      learning.streak = { count: 1, lastActiveDay: today, graceUsedOn: "" };
    }
  });
  maybeAward("streak-7", state.learning.streak.count >= 7);
}

// ---------------------------------------------------------------------------
// Badges (encouragement only: no shame, no urgency, no purchases)

const BADGES = [
  { id: "first-read", name: "First lesson finished", how: "Finish any article." },
  { id: "library-complete", name: "Library complete", how: "Finish every article." },
  { id: "quiz-ace", name: "Quiz ace", how: "Get a perfect score on any knowledge check." },
  { id: "scenario-master", name: "Scenario master", how: "Run five different calculators." },
  { id: "streak-7", name: "Seven-day streak", how: "Learn on seven days in a row (one rest day is forgiven)." },
  { id: "safe-keeper", name: "Safe keeper", how: "Export a progress backup." }
];

function maybeAward(id, condition) {
  if (!condition || state.learning.badges.includes(id)) {
    return;
  }
  commitLearning((learning) => {
    learning.badges.push(id);
  });
  const badge = BADGES.find((b) => b.id === id);
  showToast(`Badge earned: ${badge ? badge.name : id}`);
}

// ---------------------------------------------------------------------------
// DOM helpers

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) {
      continue;
    }
    if (key === "class") {
      node.className = value;
    } else if (key === "text") {
      node.textContent = value;
    } else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2), value);
    } else if (value === true) {
      node.setAttribute(key, "");
    } else {
      node.setAttribute(key, String(value));
    }
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) {
      continue;
    }
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

const main = document.querySelector("#main");
const toastHost = document.querySelector("#toast");
const bannerHost = document.querySelector("#banner");

let toastTimer = null;
function showToast(message) {
  toastHost.textContent = message;
  toastHost.hidden = false;
  if (toastTimer) {
    clearTimeout(toastTimer);
  }
  toastTimer = setTimeout(() => {
    toastHost.hidden = true;
  }, 4200);
}

function showBanner(message) {
  bannerHost.replaceChildren(
    el("p", { text: message }),
    el("button", {
      class: "banner-close", type: "button", "aria-label": "Dismiss notice",
      onclick: () => { bannerHost.hidden = true; }
    }, "Dismiss")
  );
  bannerHost.hidden = false;
}

// ---------------------------------------------------------------------------
// Inline notes: definition popovers and fact citations expand in place,
// which stays readable on mobile and needs no positioning math.

function closeInlineNotes(scope = document) {
  for (const open of scope.querySelectorAll(".inline-note")) {
    open.remove();
  }
  for (const trigger of scope.querySelectorAll("[aria-expanded='true'][data-note]")) {
    trigger.setAttribute("aria-expanded", "false");
  }
}

function toggleInlineNote(trigger, buildNote) {
  const expanded = trigger.getAttribute("aria-expanded") === "true";
  const block = trigger.closest("p, li, td, .fact-row") || trigger.parentElement;
  closeInlineNotes();
  if (expanded) {
    return;
  }
  const note = buildNote();
  note.classList.add("inline-note");
  block.after(note);
  trigger.setAttribute("aria-expanded", "true");
}

function termButton(slug) {
  const entry = GLOSSARY[slug];
  const button = el("button", {
    class: "term", type: "button", "data-note": "term", "aria-expanded": "false"
  }, entry.word);
  button.addEventListener("click", () => {
    toggleInlineNote(button, () => el("aside", { class: "note-card", role: "note" },
      el("strong", { text: entry.word }),
      el("p", { text: state.preferences.kidSpeak ? entry.kid : entry.plain })
    ));
  });
  return button;
}

function factChip(factId) {
  const fact = getFact(factId);
  const wrap = el("span", { class: "fact" });
  const button = el("button", {
    class: "fact-cite", type: "button", "data-note": "fact", "aria-expanded": "false",
    "aria-label": `${fact.display}. Source and effective year for: ${fact.claim}`
  }, el("span", { class: "fact-display", text: fact.display }),
    el("sup", { class: "fact-year", "aria-hidden": "true", text: fact.effectiveYear || "src" }));
  button.addEventListener("click", () => {
    toggleInlineNote(button, () => el("aside", { class: "note-card fact-note", role: "note" },
      el("strong", { text: fact.claim }),
      el("dl", { class: "fact-meta" },
        el("div", {}, el("dt", { text: "Effective year" }), el("dd", { text: fact.effectiveYear ? String(fact.effectiveYear) : "Not year-bound" })),
        el("div", {}, el("dt", { text: "Jurisdiction" }), el("dd", { text: fact.jurisdiction })),
        el("div", {}, el("dt", { text: "Authority" }), el("dd", { text: fact.authorityStatus })),
        el("div", {}, el("dt", { text: "Reviewed" }), el("dd", { text: fact.reviewedAt }))
      ),
      fact.notes ? el("p", { class: "fact-notes", text: fact.notes }) : null,
      el("a", { href: fact.sourceUrl, target: "_blank", rel: "noopener", text: fact.sourceTitle })
    ));
  });
  wrap.append(button);
  return wrap;
}

// Turns "text [[fact:id]] more [[term:slug]] text" into DOM nodes.
const TOKEN = /\[\[(fact|term):([a-z0-9-]+)\]\]/g;
function richText(text) {
  const nodes = [];
  let last = 0;
  for (const match of text.matchAll(TOKEN)) {
    if (match.index > last) {
      nodes.push(document.createTextNode(text.slice(last, match.index)));
    }
    nodes.push(match[1] === "fact" ? factChip(match[2]) : termButton(match[2]));
    last = match.index + match[0].length;
  }
  if (last < text.length) {
    nodes.push(document.createTextNode(text.slice(last)));
  }
  return nodes;
}

function pick(variant) {
  return state.preferences.kidSpeak && variant.kid ? variant.kid : variant.plain;
}

// ---------------------------------------------------------------------------
// Shared view pieces

function breadcrumbs(trail) {
  const list = el("ol", {});
  trail.forEach(([label, href], index) => {
    const last = index === trail.length - 1;
    list.append(el("li", {},
      last ? el("span", { "aria-current": "page", text: label }) : el("a", { href, text: label })
    ));
  });
  return el("nav", { class: "breadcrumbs", "aria-label": "Breadcrumb" }, list);
}

function disclosurePanel() {
  return el("aside", { class: "disclosure", "aria-label": "Educational disclosure" },
    el("p", {}, ...richText(
      "NestEggHero 2 is general education, not individualized tax, legal, fiduciary, or investment advice. Projections are estimates based on the values entered, never promises."
    )),
    el("p", { class: "muted", text: `Facts last reviewed ${REVIEWED_AT}. Next scheduled review ${NEXT_REVIEW_AT}.` })
  );
}

function sparkline(chart) {
  const points = chart.points;
  if (!points || points.length < 2) {
    return null;
  }
  const width = 560;
  const height = 120;
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const span = max - min || 1;
  const step = width / (points.length - 1);
  const coords = points.map((value, index) => {
    const x = (index * step).toFixed(1);
    const y = (height - ((value - min) / span) * (height - 8) - 4).toFixed(1);
    return `${x},${y}`;
  });
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("class", "chart");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `${chart.label}. The exact values appear in the table below.`);
  const area = document.createElementNS("http://www.w3.org/2000/svg", "polygon");
  area.setAttribute("points", `0,${height} ${coords.join(" ")} ${width},${height}`);
  area.setAttribute("class", "chart-area");
  const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  line.setAttribute("points", coords.join(" "));
  line.setAttribute("class", "chart-line");
  svg.append(area, line);
  return svg;
}

function dataTable(table) {
  return el("div", { class: "table-scroll" },
    el("table", {},
      el("caption", { text: table.caption }),
      el("thead", {}, el("tr", {}, table.columns.map((column) => el("th", { scope: "col", text: column })))),
      el("tbody", {}, table.rows.map((row) => el("tr", {}, row.map((cell, i) =>
        i === 0 ? el("th", { scope: "row", text: cell }) : el("td", { text: cell })
      ))))
    )
  );
}

// ---------------------------------------------------------------------------
// Views

function viewHome() {
  const readCount = Object.keys(state.learning.readArticles).length;
  const heroTitle = state.preferences.kidSpeak
    ? "Learn how money really works, one small lesson at a time."
    : "Understand the numbers before the numbers decide for you.";
  const heroText = state.preferences.kidSpeak
    ? "Short lessons, honest examples, and calculators you can play with. Nothing here asks for your real money information."
    : "Eight short lessons and seven honest calculators, built on source-labeled 2026 figures. Every changing number carries its effective year and its official source.";

  return el("div", { class: "view view-home" },
    el("section", { class: "hero" },
      el("p", { class: "eyebrow", text: "Financial learning studio" }),
      el("h1", { id: "view-title", tabindex: "-1", text: heroTitle }),
      el("p", { class: "lede", text: heroText }),
      el("div", { class: "cta-row" },
        el("a", { class: "btn primary", href: "#/library", text: readCount > 0 ? "Continue learning" : "Start the first lesson" }),
        el("a", { class: "btn ghost", href: "#/tools", text: "Open the calculators" })
      )
    ),
    el("section", { class: "panel", "aria-labelledby": "verified-title" },
      el("h2", { id: "verified-title", text: "Three verified 2026 figures" }),
      el("div", { class: "verified-grid" },
        ["ira-limit", "deferral-limit", "ssa-cola"].map((id) => {
          const fact = getFact(id);
          return el("div", { class: "verified-card fact-row" },
            el("span", { class: "verified-value", text: fact.display }),
            el("span", { class: "verified-claim", text: fact.claim }),
            factCiteLink(fact)
          );
        })
      ),
      el("p", { class: "muted" },
        "Every figure in this studio resolves through a ",
        el("a", { href: "#/facts", text: "fact registry" }),
        ` reviewed ${REVIEWED_AT}. Nothing publishes without a source and an effective year.`)
    ),
    el("section", { class: "panel", "aria-labelledby": "path-title" },
      el("h2", { id: "path-title", text: "The learning path" }),
      el("ol", { class: "path-list" }, ARTICLES.map((article) => {
        const done = Boolean(state.learning.readArticles[article.slug]);
        return el("li", { class: done ? "done" : "" },
          el("a", { href: `#/read/${article.slug}`, text: article.title }),
          el("span", { class: "path-meta", text: done ? "Finished" : `${article.minutes} min` })
        );
      }))
    ),
    disclosurePanel()
  );
}

function factCiteLink(fact) {
  return el("a", {
    class: "verified-source", href: fact.sourceUrl, target: "_blank", rel: "noopener"
  }, `${fact.effectiveYear || ""} source`.trim());
}

function viewLibrary(filterTopic) {
  const topics = ["All", ...TOPICS];
  const active = topics.includes(filterTopic) ? filterTopic : "All";
  const shown = ARTICLES.filter((article) => active === "All" || article.topic === active);

  return el("div", { class: "view" },
    breadcrumbs([["Home", "#/"], ["Library", "#/library"]]),
    el("h1", { id: "view-title", tabindex: "-1", text: "Lesson library" }),
    el("p", { class: "lede", text: state.preferences.kidSpeak
      ? "Pick a lesson. Finished ones get a check mark, and you can bookmark favorites."
      : "Eight lessons, each with sources, a worked example, and a short knowledge check." }),
    el("div", { class: "chip-row", role: "group", "aria-label": "Filter lessons by topic" },
      topics.map((topic) => el("button", {
        class: `chip${topic === active ? " active" : ""}`, type: "button",
        "aria-pressed": String(topic === active),
        onclick: () => { location.hash = topic === "All" ? "#/library" : `#/library/${encodeURIComponent(topic)}`; }
      }, topic))
    ),
    shown.length === 0
      ? el("div", { class: "empty-state" }, el("p", { text: "No lessons in this topic yet. Try another filter." }))
      : el("div", { class: "card-grid" }, shown.map((article) => {
        const done = Boolean(state.learning.readArticles[article.slug]);
        const marked = state.learning.bookmarks.includes(article.slug);
        const quiz = state.learning.quizScores[article.slug];
        return el("article", { class: "card" },
          el("div", { class: "card-top" },
            el("span", { class: "eyebrow", text: article.topic }),
            bookmarkButton(article.slug, marked)
          ),
          el("h2", {}, el("a", { href: `#/read/${article.slug}`, text: article.title })),
          el("p", { class: "card-summary" }, ...richText(pick(article.summary))),
          el("p", { class: "card-meta" },
            `${article.minutes} min`,
            done ? el("span", { class: "status-done", text: " Finished" }) : null,
            quiz ? el("span", { class: "status-quiz", text: ` Quiz ${quiz.correct}/${quiz.total}` }) : null
          )
        );
      }))
  );
}

function bookmarkButton(slug, marked) {
  const button = el("button", {
    class: `bookmark${marked ? " on" : ""}`, type: "button",
    "aria-pressed": String(marked),
    "aria-label": marked ? "Remove bookmark" : "Bookmark this lesson"
  }, marked ? "Bookmarked" : "Bookmark");
  button.addEventListener("click", () => {
    commitLearning((learning) => {
      if (learning.bookmarks.includes(slug)) {
        learning.bookmarks = learning.bookmarks.filter((item) => item !== slug);
      } else {
        learning.bookmarks.push(slug);
      }
    });
    render();
  });
  return button;
}

function highlightButton(articleSlug, sectionId) {
  const ref = `${articleSlug}#${sectionId}`;
  const on = state.learning.highlights.includes(ref);
  const button = el("button", {
    class: `highlight${on ? " on" : ""}`, type: "button",
    "aria-pressed": String(on),
    "aria-label": on ? "Remove highlight from this section" : "Highlight this section"
  }, on ? "Highlighted" : "Highlight");
  button.addEventListener("click", () => {
    commitLearning((learning) => {
      if (learning.highlights.includes(ref)) {
        learning.highlights = learning.highlights.filter((item) => item !== ref);
      } else {
        learning.highlights.push(ref);
      }
    });
    render();
  });
  return button;
}

function viewArticle(slug) {
  let article;
  try {
    article = getArticle(slug);
  } catch {
    return viewMissing("That lesson does not exist.");
  }
  recordEvent("article_started");

  const done = Boolean(state.learning.readArticles[article.slug]);
  const quizState = state.learning.quizScores[article.slug];

  const toc = el("nav", { class: "toc", "aria-label": "On this page" },
    el("h2", { text: "On this page" }),
    el("ol", {},
      article.sections.map((section) => el("li", {}, el("a", { href: `#/read/${slug}`, text: section.heading, onclick: (event) => {
        event.preventDefault();
        const target = document.getElementById(`section-${section.id}`);
        if (target) {
          target.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth" });
          target.focus({ preventScroll: true });
        }
      } }))),
      el("li", {}, el("a", { href: `#/read/${slug}`, text: "Knowledge check", onclick: (event) => {
        event.preventDefault();
        const target = document.getElementById("quiz");
        if (target) {
          target.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth" });
        }
      } }))
    )
  );

  const sources = article.factIds.length > 0 ? factSources(article.factIds) : [];

  const view = el("div", { class: "view view-article" },
    breadcrumbs([["Home", "#/"], ["Library", "#/library"], [article.title, `#/read/${slug}`]]),
    el("div", { class: "print-header", "aria-hidden": "true" },
      el("strong", { text: `NestEggHero 2: ${article.title}` }),
      el("span", { text: `Reviewed ${article.updatedAt}. ${article.authorityStatus}. Educational estimate material, not advice.` })
    ),
    el("header", { class: "article-header" },
      el("p", { class: "eyebrow", text: article.topic }),
      el("h1", { id: "view-title", tabindex: "-1", text: article.title }),
      el("p", { class: "article-meta" },
        el("span", { text: `${article.minutes} min read` }),
        article.effectiveYear ? el("span", { class: "meta-chip", text: `Effective year ${article.effectiveYear}` }) : null,
        el("span", { class: "meta-chip", text: article.authorityStatus }),
        el("span", { text: `Reviewed ${article.updatedAt}` })
      ),
      el("div", { class: "article-actions" },
        bookmarkButton(article.slug, state.learning.bookmarks.includes(article.slug)),
        kidSpeakInlineToggle()
      )
    ),
    el("div", { class: "read-progress", "aria-hidden": "true" }, el("span", { id: "readProgressFill" })),
    el("div", { class: "article-layout" },
      toc,
      el("div", { class: "article-body" },
        el("section", { class: "learn-panel" },
          el("h2", { text: "What you will learn" }),
          el("ul", {}, article.learn.map((item) => el("li", { text: item })))
        ),
        el("section", { class: "summary-panel" },
          el("h2", { text: state.preferences.kidSpeak ? "The short version" : "Plain-language summary" }),
          el("p", {}, ...richText(pick(article.summary)))
        ),
        article.sections.map((section) => el("section", { class: "article-section" },
          el("div", { class: "section-head" },
            el("h2", { id: `section-${section.id}`, tabindex: "-1", text: section.heading }),
            highlightButton(article.slug, section.id)
          ),
          section.paragraphs.map((paragraph) => el("p", {}, ...richText(pick(paragraph))))
        )),
        el("section", { class: "example-panel" },
          el("h2", { text: article.example.heading }),
          el("p", {}, ...richText(pick(article.example)))
        ),
        activityBlock(article),
        el("section", { class: "risk-panel" },
          el("h2", { text: "Risks and exceptions" }),
          el("ul", {}, article.risks.map((risk) => el("li", { text: risk })))
        ),
        el("section", { class: "takeaway-panel" },
          el("h2", { text: "Key takeaways" }),
          el("ul", {}, article.takeaways.map((item) => el("li", { text: item })))
        ),
        quizBlock(article, quizState),
        el("section", { class: "sources-panel" },
          el("h2", { text: "Sources" }),
          sources.length > 0
            ? el("ul", {}, sources.map((source) => el("li", {}, el("a", { href: source.url, target: "_blank", rel: "noopener", text: source.title }))))
            : el("p", { class: "muted", text: "This lesson explains mathematical concepts and cites no changing financial figures." })
        ),
        el("div", { class: "finish-row" },
          el("button", {
            class: "btn primary", type: "button",
            onclick: () => {
              commitLearning((learning) => {
                learning.readArticles[article.slug] = new Date().toISOString();
              });
              recordEvent("article_completed");
              touchStreak();
              maybeAward("first-read", true);
              maybeAward("library-complete", ARTICLES.every((a) => state.learning.readArticles[a.slug]));
              showToast("Lesson marked as finished.");
              render();
            }
          }, done ? "Finished (mark again)" : "Mark lesson as finished"),
          el("a", { class: "btn ghost", href: `#/read/${article.next}`, text: `Next lesson: ${getArticle(article.next).title}` })
        )
      )
    ),
    disclosurePanel()
  );

  wireReadingProgress(view);
  injectArticleJsonLd(article);
  return view;
}

function activityBlock(article) {
  const activity = article.activity;
  const href = activity.kind === "calculator" ? `#/tools/${activity.slug}` : "#/facts";
  return el("section", { class: "activity-panel" },
    el("h2", { text: "Try it yourself" }),
    el("p", { text: activity.description }),
    el("a", {
      class: "btn primary", href,
      onclick: () => recordEvent("cta_activated"),
      text: activity.label
    })
  );
}

function quizBlock(article, quizState) {
  const form = el("form", { class: "quiz", id: "quiz", "aria-labelledby": "quiz-title" });
  form.append(el("h2", { id: "quiz-title", text: "Knowledge check" }));
  if (quizState) {
    form.append(el("p", { class: "muted", text: `Best so far: ${quizState.correct} of ${quizState.total}.` }));
  }
  article.quiz.forEach((item, qIndex) => {
    const set = el("fieldset", {},
      el("legend", { text: `${qIndex + 1}. ${item.question}` }),
      item.options.map((option, oIndex) => el("label", { class: "quiz-option" },
        el("input", { type: "radio", name: `q${qIndex}`, value: String(oIndex) }),
        el("span", { text: option })
      )),
      el("p", { class: "quiz-explain", hidden: true, "data-explain": String(qIndex), text: item.explain })
    );
    form.append(set);
  });
  const result = el("p", { class: "quiz-result", role: "status", "aria-live": "polite" });
  form.append(
    el("button", { class: "btn primary", type: "submit", text: "Check my answers" }),
    result
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    let correct = 0;
    let answered = 0;
    article.quiz.forEach((item, qIndex) => {
      const chosen = form.querySelector(`input[name="q${qIndex}"]:checked`);
      if (chosen) {
        answered += 1;
        if (Number(chosen.value) === item.answer) {
          correct += 1;
        }
      }
      const explain = form.querySelector(`[data-explain="${qIndex}"]`);
      explain.hidden = false;
    });
    if (answered < article.quiz.length) {
      result.textContent = `Answer all ${article.quiz.length} questions first. Nothing is scored yet.`;
      return;
    }
    result.textContent = correct === article.quiz.length
      ? `Perfect: ${correct} of ${article.quiz.length}. The explanations below each question recap why.`
      : `You got ${correct} of ${article.quiz.length}. The explanations below each question show the reasoning; try again anytime.`;
    commitLearning((learning) => {
      const previous = learning.quizScores[article.slug];
      learning.quizScores[article.slug] = {
        correct: previous && previous.correct > correct ? previous.correct : correct,
        total: article.quiz.length,
        attempts: previous ? previous.attempts + 1 : 1,
        bestAt: new Date().toISOString()
      };
    });
    recordEvent("activity_completed");
    touchStreak();
    maybeAward("quiz-ace", correct === article.quiz.length);
  });
  return form;
}

function viewTools() {
  return el("div", { class: "view" },
    breadcrumbs([["Home", "#/"], ["Calculators", "#/tools"]]),
    el("h1", { id: "view-title", tabindex: "-1", text: "Estimate calculators" }),
    el("p", { class: "lede", text: state.preferences.kidSpeak
      ? "Safe places to try money questions. Every answer is an estimate, and the assumptions are always shown."
      : "Seven deterministic tools. Assumptions sit next to every result, and every result is an estimate, not a promise." }),
    el("div", { class: "card-grid" }, CALCULATORS.map((calc) => el("article", { class: "card" },
      el("h2", {}, el("a", { href: `#/tools/${calc.slug}`, text: calc.name })),
      el("p", { class: "card-summary", text: state.preferences.kidSpeak ? calc.kidBlurb : calc.blurb }),
      state.learning.calculatorRuns[calc.slug]
        ? el("p", { class: "card-meta", text: `You have run this ${state.learning.calculatorRuns[calc.slug]} time${state.learning.calculatorRuns[calc.slug] === 1 ? "" : "s"}` })
        : null
    ))),
    disclosurePanel()
  );
}

function viewCalculator(slug) {
  let calc;
  try {
    calc = getCalculator(slug);
  } catch {
    return viewMissing("That calculator does not exist.");
  }
  recordEvent("calculator_started");

  const errorBox = el("div", { class: "error-banner", role: "alert", hidden: true });
  const results = el("div", { class: "results", "aria-live": "polite" });

  const form = el("form", { class: "calc-form", novalidate: true });
  for (const field of calc.fields) {
    if (field.kind === "choice") {
      const select = el("select", { id: `f-${field.id}`, name: field.id },
        field.options.map((option) => el("option", { value: option.value, selected: option.value === field.defaultValue ? true : null }, option.label))
      );
      form.append(el("label", { class: "field", for: `f-${field.id}` },
        el("span", { class: "field-label", text: field.label }), select));
    } else {
      const input = el("input", {
        id: `f-${field.id}`, name: field.id, type: "number",
        inputmode: field.kind === "whole" ? "numeric" : "decimal",
        value: field.defaultValue,
        step: field.step || "1",
        min: field.kind === "dollars" ? "0" : field.min,
        max: field.kind === "dollars" ? null : field.max
      });
      const inner = field.suffix
        ? el("span", { class: "suffix-wrap" }, input, el("span", { class: "suffix", "aria-hidden": "true", text: field.suffix }))
        : input;
      form.append(el("label", { class: "field", for: `f-${field.id}` },
        el("span", { class: "field-label", text: field.label }), inner));
    }
  }
  form.append(el("div", { class: "cta-row" },
    el("button", { class: "btn primary", type: "submit", text: "Update the estimate" }),
    el("button", { class: "btn ghost", type: "reset", text: "Reset inputs" })
  ));

  const runNow = () => {
    const raw = {};
    for (const field of calc.fields) {
      raw[field.id] = form.elements[field.id].value;
    }
    try {
      const outcome = runCalculator(slug, raw);
      errorBox.hidden = true;
      renderResults(outcome);
      commitLearning((learning) => {
        learning.calculatorRuns[slug] = (learning.calculatorRuns[slug] || 0) + 1;
      });
      recordEvent("calculator_completed");
      touchStreak();
      maybeAward("scenario-master", Object.keys(state.learning.calculatorRuns).length >= 5);
    } catch (error) {
      if (error instanceof CalculatorInputError) {
        errorBox.textContent = error.message;
        errorBox.hidden = false;
      } else {
        throw error;
      }
    }
  };

  function renderResults(outcome) {
    results.replaceChildren(
      el("div", { class: "print-header", "aria-hidden": "true" },
        el("strong", { text: `NestEggHero 2: ${calc.name}` }),
        el("span", { text: `Estimate generated ${new Date().toISOString().slice(0, 10)}. Educational estimate, not advice.` })
      ),
      el("div", { class: "headline" },
        el("span", { class: "headline-label", text: outcome.headline.label }),
        el("strong", { class: "headline-value", text: outcome.headline.value })
      ),
      el("dl", { class: "stat-grid" }, outcome.stats.map((stat) => el("div", {},
        el("dt", { text: stat.label }), el("dd", { text: stat.value })))),
      el("aside", { class: "assumptions" },
        el("h2", { text: "Assumptions behind this estimate" }),
        el("ul", {}, outcome.assumptions.map((line) => el("li", { text: line })))
      ),
      outcome.chart ? sparkline(outcome.chart) : null,
      outcome.table ? dataTable(outcome.table) : null,
      el("p", { class: "muted", text: "This is an estimate from the values entered. It is not a prediction, a guarantee, or advice." })
    );
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    runNow();
  });

  const scenarioRow = calc.scenarios && calc.scenarios.length > 0
    ? el("div", { class: "chip-row", role: "group", "aria-label": "Example scenarios" },
      calc.scenarios.map((scenario) => el("button", {
        class: "chip", type: "button",
        onclick: () => {
          for (const [key, value] of Object.entries(scenario.values)) {
            if (form.elements[key]) {
              form.elements[key].value = value;
            }
          }
          runNow();
        }
      }, scenario.label)))
    : null;

  const view = el("div", { class: "view view-calc" },
    breadcrumbs([["Home", "#/"], ["Calculators", "#/tools"], [calc.name, `#/tools/${slug}`]]),
    el("h1", { id: "view-title", tabindex: "-1", text: calc.name }),
    el("p", { class: "lede", text: state.preferences.kidSpeak ? calc.kidBlurb : calc.blurb }),
    scenarioRow,
    el("div", { class: "calc-layout" },
      el("section", { class: "panel" }, el("h2", { class: "visually-hidden", text: "Inputs" }), errorBox, form),
      el("section", { class: "panel" }, el("h2", { class: "visually-hidden", text: "Results" }), results)
    ),
    disclosurePanel()
  );
  runNow();
  return view;
}

function viewFacts() {
  const facts = allFacts();
  return el("div", { class: "view" },
    breadcrumbs([["Home", "#/"], ["Fact registry", "#/facts"]]),
    el("h1", { id: "view-title", tabindex: "-1", text: "The fact registry" }),
    el("p", { class: "lede", text: state.preferences.kidSpeak
      ? "Every number this site shows lives here, with where it came from and when we checked it."
      : "Every changing figure in this studio publishes from this registry. Each record carries its claim, value, effective year, jurisdiction, authority status, source, and review dates. Draft, expired, or disputed records cannot publish." }),
    el("p", { class: "muted", text: `Reviewed ${REVIEWED_AT}. Next scheduled review ${NEXT_REVIEW_AT}. United States federal scope.` }),
    el("div", { class: "table-scroll" },
      el("table", { class: "facts-table" },
        el("caption", { text: "All published fact records" }),
        el("thead", {}, el("tr", {},
          ["Claim", "Value", "Year", "Authority", "Source"].map((h) => el("th", { scope: "col", text: h })))),
        el("tbody", {}, facts.map((fact) => el("tr", {},
          el("th", { scope: "row" },
            fact.claim,
            fact.notes ? el("span", { class: "fact-notes", text: ` ${fact.notes}` }) : null),
          el("td", { text: fact.display }),
          el("td", { text: fact.effectiveYear ? String(fact.effectiveYear) : "n/a" }),
          el("td", { text: fact.authorityStatus }),
          el("td", {}, el("a", { href: fact.sourceUrl, target: "_blank", rel: "noopener", text: "IRS/SSA" }))
        )))
      )
    ),
    disclosurePanel()
  );
}

function viewProgress() {
  const learning = state.learning;
  const readCount = Object.keys(learning.readArticles).length;
  const quizCount = Object.keys(learning.quizScores).length;

  const importPreview = el("div", { class: "import-preview", "aria-live": "polite" });

  const fileInput = el("input", {
    type: "file", accept: "application/json,.json", id: "importFile", class: "visually-hidden"
  });
  fileInput.addEventListener("change", () => {
    if (fileInput.files && fileInput.files[0]) {
      handleImportFile(fileInput.files[0], importPreview);
    }
    fileInput.value = "";
  });

  const dropZone = el("label", { class: "drop-zone", for: "importFile" },
    el("strong", { text: "Import a progress backup" }),
    el("span", { text: "Choose a NestEggHero_backup JSON file, or drop it here. It is validated before anything changes." }),
    fileInput
  );
  dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropZone.classList.add("drag");
  });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag"));
  dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropZone.classList.remove("drag");
    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) {
      handleImportFile(file, importPreview);
    }
  });

  return el("div", { class: "view" },
    breadcrumbs([["Home", "#/"], ["My progress", "#/progress"]]),
    el("h1", { id: "view-title", tabindex: "-1", text: "My progress" }),
    el("p", { class: "lede", text: state.preferences.kidSpeak
      ? "Your learning lives on this device. You can carry it with you as a small file."
      : "Learning state stays on this device. Export carries only what resumes learning: no financial inputs, no identifiers, no analytics." }),
    state.storageHealthy ? null : el("div", { class: "error-banner", role: "alert" },
      el("p", { text: "Local saving is currently failing on this device. Export a backup now so nothing is lost." })),
    el("section", { class: "panel" },
      el("h2", { text: "Where you are" }),
      el("dl", { class: "stat-grid" },
        el("div", {}, el("dt", { text: "Lessons finished" }), el("dd", { text: `${readCount} of ${ARTICLES.length}` })),
        el("div", {}, el("dt", { text: "Quizzes taken" }), el("dd", { text: String(quizCount) })),
        el("div", {}, el("dt", { text: "Bookmarks" }), el("dd", { text: String(learning.bookmarks.length) })),
        el("div", {}, el("dt", { text: "Highlights" }), el("dd", { text: String(learning.highlights.length) })),
        el("div", {}, el("dt", { text: "Learning streak" }), el("dd", { text: `${learning.streak.count} day${learning.streak.count === 1 ? "" : "s"}` }))
      )
    ),
    el("section", { class: "panel" },
      el("h2", { text: "Badges" }),
      el("ul", { class: "badge-grid" }, BADGES.map((badge) => {
        const earned = learning.badges.includes(badge.id);
        return el("li", { class: `badge-card${earned ? " earned" : ""}` },
          el("strong", { text: badge.name }),
          el("span", { text: earned ? "Earned" : badge.how })
        );
      }))
    ),
    el("section", { class: "panel" },
      el("h2", { text: "Backup and restore" }),
      el("p", { class: "muted", text: `Backups are JSON files under ${Math.round(GUARDS.maxBytes / 1_000_000)} MB with an integrity checksum. Imports preview first, then you choose merge or replace.` }),
      el("div", { class: "cta-row" },
        el("button", {
          class: "btn primary", type: "button",
          onclick: exportBackup
        }, "Export my progress"),
        dropZone
      ),
      importPreview
    ),
    el("section", { class: "panel" },
      el("h2", { text: "On-device activity counts" }),
      el("p", { class: "muted", text: "These counters never leave this device and are excluded from backups." }),
      Object.keys(learning.activity).length === 0
        ? el("p", { class: "empty-state", text: "No activity recorded yet." })
        : el("div", { class: "table-scroll" }, el("table", {},
          el("caption", { text: "Local event counters" }),
          el("thead", {}, el("tr", {}, el("th", { scope: "col", text: "Event" }), el("th", { scope: "col", text: "Count" }))),
          el("tbody", {}, Object.entries(learning.activity).sort().map(([name, count]) =>
            el("tr", {}, el("th", { scope: "row", text: name }), el("td", { text: String(count) }))))
        ))
    ),
    el("section", { class: "panel danger" },
      el("h2", { text: "Start over" }),
      el("p", { class: "muted", text: "Clears lessons, quizzes, bookmarks, highlights, badges, and streak on this device. Export a backup first if you might want any of it back." }),
      el("button", {
        class: "btn danger", type: "button",
        onclick: () => confirmModal(
          "Clear all progress?",
          "This removes everything listed above from this device. A backup file, if you exported one, stays safe wherever you saved it.",
          "Clear progress",
          async () => {
            state.learning = defaultLearning();
            try {
              await autosaver.flushNow();
            } catch { /* the fresh state is queued below either way */ }
            autosaver.queue(state.learning);
            showToast("Progress cleared. The studio is fresh.");
            render();
          }
        )
      }, "Clear progress on this device")
    ),
    disclosurePanel()
  );
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
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    recordEvent("backup_exported");
    maybeAward("safe-keeper", true);
    showToast("Backup exported. Keep the file somewhere safe.");
  } catch {
    showBanner("The backup could not be created in this browser. Nothing was changed; try a different browser if this repeats.");
  }
}

async function handleImportFile(file, previewHost) {
  previewHost.replaceChildren(el("p", { class: "muted", text: "Checking the file. Nothing changes until you confirm." }));
  try {
    if (file.size > GUARDS.maxBytes) {
      throw new BackupError("This file is larger than any real NestEggHero backup. Your current progress was not changed.");
    }
    const text = await file.text();
    const inspected = await inspectBackupText(text, file.size);
    recordEvent("backup_import_succeeded");
    previewHost.replaceChildren(
      el("div", { class: "note-card" },
        el("strong", { text: `Backup from ${inspected.exportedAt.slice(0, 10)} (app ${inspected.appVersion})` }),
        el("ul", { class: "preview-list" }, inspected.summary.map((item) =>
          el("li", { text: `${item.label}: ${item.count}` }))),
        el("p", { text: "Merge keeps everything you have here and adds the backup. Replace adopts the backup exactly." }),
        el("div", { class: "cta-row" },
          el("button", {
            class: "btn primary", type: "button",
            onclick: () => applyImport(inspected, "merge", previewHost)
          }, "Merge into my progress"),
          el("button", {
            class: "btn ghost", type: "button",
            onclick: () => confirmModal(
              "Replace all progress?",
              "Your current lessons, quizzes, bookmarks, highlights, badges, and streak on this device will be replaced by the backup.",
              "Replace everything",
              () => applyImport(inspected, "replace", previewHost)
            )
          }, "Replace my progress"),
          el("button", {
            class: "btn ghost", type: "button",
            onclick: () => previewHost.replaceChildren(el("p", { class: "muted", text: "Import canceled. Nothing changed." }))
          }, "Cancel")
        )
      )
    );
  } catch (error) {
    recordEvent("backup_import_failed");
    const message = error instanceof BackupError
      ? error.message
      : "This backup could not be read. Your current progress was not changed.";
    previewHost.replaceChildren(el("div", { class: "error-banner", role: "alert" }, el("p", { text: message })));
  }
}

async function applyImport(inspected, mode, previewHost) {
  const next = mode === "merge"
    ? mergeLearning(state.learning, inspected.payload.learning)
    : replaceLearning(state.learning, inspected.payload.learning, inspected.payload.createdAt);
  // Atomic apply: persist first; adopt in memory only after the write lands.
  try {
    state.learning = next;
    autosaver.queue(next);
    await autosaver.flushNow();
  } catch { /* autosaver reports storage trouble through its own banner */ }
  state.preferences = { ...state.preferences, ...inspected.payload.preferences };
  savePreferences(state.preferences);
  applyPreferences();
  showToast(mode === "merge" ? "Backup merged into your progress." : "Backup restored.");
  previewHost.replaceChildren();
  render();
}

function viewMissing(message) {
  return el("div", { class: "view" },
    el("div", { class: "empty-state" },
      el("h1", { id: "view-title", tabindex: "-1", text: "Nothing here" }),
      el("p", { text: message }),
      el("a", { class: "btn primary", href: "#/", text: "Back to the studio" })
    )
  );
}

// ---------------------------------------------------------------------------
// Modal (used only for destructive confirmations)

function confirmModal(title, body, confirmLabel, onConfirm) {
  const previouslyFocused = document.activeElement;
  const overlay = el("div", { class: "modal-overlay" });
  const dialog = el("div", {
    class: "modal", role: "dialog", "aria-modal": "true", "aria-labelledby": "modal-title"
  },
    el("h2", { id: "modal-title", text: title }),
    el("p", { text: body }),
    el("div", { class: "cta-row" },
      el("button", { class: "btn ghost", type: "button", "data-cancel": true }, "Keep my progress"),
      el("button", { class: "btn danger", type: "button", "data-confirm": true }, confirmLabel)
    )
  );
  overlay.append(dialog);
  const close = () => {
    overlay.remove();
    document.removeEventListener("keydown", onKey);
    if (previouslyFocused && previouslyFocused.focus) {
      previouslyFocused.focus();
    }
  };
  const onKey = (event) => {
    if (event.key === "Escape") {
      close();
    }
    if (event.key === "Tab") {
      const focusable = dialog.querySelectorAll("button");
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  };
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) {
      close();
    }
  });
  dialog.querySelector("[data-cancel]").addEventListener("click", close);
  dialog.querySelector("[data-confirm]").addEventListener("click", () => {
    close();
    onConfirm();
  });
  document.addEventListener("keydown", onKey);
  document.body.append(overlay);
  dialog.querySelector("[data-cancel]").focus();
}

// ---------------------------------------------------------------------------
// Reading progress, JSON-LD, preferences, header wiring

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

let progressHandler = null;
function wireReadingProgress(view) {
  const fill = view.querySelector("#readProgressFill");
  if (!fill) {
    return;
  }
  if (progressHandler) {
    window.removeEventListener("scroll", progressHandler);
  }
  progressHandler = () => {
    const body = document.documentElement;
    const total = body.scrollHeight - window.innerHeight;
    const ratio = total > 0 ? Math.min(1, Math.max(0, window.scrollY / total)) : 0;
    fill.style.width = `${(ratio * 100).toFixed(1)}%`;
  };
  window.addEventListener("scroll", progressHandler, { passive: true });
  progressHandler();
}

function injectArticleJsonLd(article) {
  removeJsonLd();
  const data = {
    "@context": "https://schema.org",
    "@type": "Article",
    headline: article.title,
    dateModified: article.updatedAt,
    author: { "@type": "Organization", name: "NestEggHero 2" },
    about: article.topic,
    isAccessibleForFree: true
  };
  const crumbs = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Home" },
      { "@type": "ListItem", position: 2, name: "Library" },
      { "@type": "ListItem", position: 3, name: article.title }
    ]
  };
  for (const chunk of [data, crumbs]) {
    const script = document.createElement("script");
    script.type = "application/ld+json";
    script.dataset.jsonld = "route";
    script.textContent = JSON.stringify(chunk);
    document.head.append(script);
  }
}

function removeJsonLd() {
  for (const node of document.querySelectorAll("script[data-jsonld='route']")) {
    node.remove();
  }
}

const SUN_ICON = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4.5"/><path d="M12 2.5v2.5M12 19v2.5M2.5 12H5M19 12h2.5M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8"/></svg>';
const MOON_ICON = '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" aria-hidden="true"><path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5a8.5 8.5 0 1 0 11 11z"/></svg>';

function applyPreferences() {
  const root = document.documentElement;
  root.dataset.theme = state.preferences.theme;
  root.dataset.textsize = state.preferences.textSize;
  const kidButtons = document.querySelectorAll("[data-kid-toggle]");
  for (const button of kidButtons) {
    button.setAttribute("aria-pressed", String(state.preferences.kidSpeak));
  }
  const themeButton = document.querySelector("#themeToggle");
  if (themeButton) {
    const dark = state.preferences.theme === "dark";
    themeButton.innerHTML = dark ? MOON_ICON : SUN_ICON;
    const label = dark ? "Switch to light theme" : "Switch to dark theme";
    themeButton.setAttribute("aria-label", label);
    themeButton.title = label;
  }
}

function kidSpeakInlineToggle() {
  const button = el("button", {
    class: "btn ghost small", type: "button", "data-kid-toggle": true,
    "aria-pressed": String(state.preferences.kidSpeak)
  }, "Kid Speak");
  button.addEventListener("click", toggleKidSpeak);
  return button;
}

function toggleKidSpeak() {
  state.preferences.kidSpeak = !state.preferences.kidSpeak;
  if (state.preferences.kidSpeak) {
    recordEvent("kid_speak_enabled");
  }
  savePreferences(state.preferences);
  applyPreferences();
  render();
  showToast(state.preferences.kidSpeak
    ? "Kid Speak is on: simpler words, same honest meaning."
    : "Kid Speak is off.");
}

function wireHeader() {
  document.querySelector("#kidSpeakToggle").addEventListener("click", toggleKidSpeak);
  document.querySelector("#themeToggle").addEventListener("click", () => {
    state.preferences.theme = state.preferences.theme === "dark" ? "light" : "dark";
    savePreferences(state.preferences);
    applyPreferences();
  });
  document.querySelector("#textSizeToggle").addEventListener("click", () => {
    state.preferences.textSize = state.preferences.textSize === "large" ? "normal" : "large";
    savePreferences(state.preferences);
    applyPreferences();
    showToast(state.preferences.textSize === "large" ? "Larger text is on." : "Standard text size restored.");
  });
  const menuButton = document.querySelector("#menuToggle");
  const nav = document.querySelector("#primaryNav");
  menuButton.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    menuButton.setAttribute("aria-expanded", String(open));
  });
  nav.addEventListener("click", (event) => {
    if (event.target.matches("a")) {
      nav.classList.remove("open");
      menuButton.setAttribute("aria-expanded", "false");
    }
  });

  const offline = document.querySelector("#offlineNote");
  const setOnline = () => {
    offline.hidden = navigator.onLine;
  };
  window.addEventListener("online", setOnline);
  window.addEventListener("offline", setOnline);
  setOnline();
}

// ---------------------------------------------------------------------------
// Router

const ROUTES = [
  { pattern: /^$/, title: "NestEggHero 2 | Financial learning studio", build: () => viewHome() },
  { pattern: /^library(?:\/(.+))?$/, title: "Lesson library | NestEggHero 2", build: (m) => viewLibrary(m[1] ? decodeURIComponent(m[1]) : "All") },
  { pattern: /^read\/([a-z0-9-]+)$/, title: null, build: (m) => viewArticle(m[1]) },
  { pattern: /^tools$/, title: "Calculators | NestEggHero 2", build: () => viewTools() },
  { pattern: /^tools\/([a-z0-9-]+)$/, title: null, build: (m) => viewCalculator(m[1]) },
  { pattern: /^facts$/, title: "Fact registry | NestEggHero 2", build: () => viewFacts() },
  { pattern: /^progress$/, title: "My progress | NestEggHero 2", build: () => viewProgress() }
];

function currentPath() {
  return location.hash.replace(/^#\/?/, "").replace(/\/+$/, "");
}

function render() {
  const path = currentPath();
  closeInlineNotes();
  removeJsonLd();
  let view = null;
  let title = "NestEggHero 2";
  for (const route of ROUTES) {
    const match = path.match(route.pattern);
    if (match) {
      view = route.build(match);
      title = route.title || documentTitleFor(path);
      break;
    }
  }
  if (!view) {
    view = viewMissing("The address in the URL does not match anything in the studio.");
    title = "Not found | NestEggHero 2";
  }
  document.title = title;
  main.replaceChildren(view);
  for (const link of document.querySelectorAll("#primaryNav a")) {
    const section = link.getAttribute("href").replace(/^#\//, "").split("/")[0];
    const active = (section === "" && path === "") || (section !== "" && path.startsWith(section));
    if (active) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  }
  applyPreferences();
}

function documentTitleFor(path) {
  const article = path.match(/^read\/([a-z0-9-]+)$/);
  if (article) {
    try {
      return `${getArticle(article[1]).title} | NestEggHero 2`;
    } catch { /* falls through to default */ }
  }
  const tool = path.match(/^tools\/([a-z0-9-]+)$/);
  if (tool) {
    try {
      return `${getCalculator(tool[1]).name} | NestEggHero 2`;
    } catch { /* falls through to default */ }
  }
  return "NestEggHero 2";
}

function onRouteChange() {
  render();
  window.scrollTo({ top: 0, behavior: "auto" });
  const heading = document.querySelector("#view-title");
  if (heading) {
    heading.focus({ preventScroll: true });
  }
}

document.addEventListener("click", (event) => {
  if (!event.target.closest("[data-note]") && !event.target.closest(".inline-note")) {
    closeInlineNotes();
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeInlineNotes();
  }
});

// ---------------------------------------------------------------------------
// Boot

async function boot() {
  applyPreferences();
  wireHeader();
  const { learning, persisted } = await loadLearning();
  state.learning = learning;
  state.storageHealthy = persisted;
  if (!persisted) {
    showBanner("This browser is not allowing local saves, so progress will last only for this session. Export a backup from My progress to keep it.");
  }
  window.addEventListener("hashchange", onRouteChange);
  render();
  window.addEventListener("beforeunload", () => {
    autosaver.flushNow();
  });
  if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
    navigator.serviceWorker.register("sw.js").catch(() => { /* offline support is progressive */ });
  }
}

boot();
