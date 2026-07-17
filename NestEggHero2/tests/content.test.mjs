import test from "node:test";
import assert from "node:assert/strict";
import { ARTICLES, GLOSSARY, getArticle } from "../scripts/articles.js";
import { getFact, allFacts, factSources } from "../scripts/facts.js";
import { CALCULATORS, getCalculator } from "../scripts/calculators.js";

const TOKEN = /\[\[(fact|term):([a-z0-9-]+)\]\]/g;

function collectStrings(value, bucket) {
  if (typeof value === "string") {
    bucket.push(value);
  } else if (Array.isArray(value)) {
    value.forEach((item) => collectStrings(item, bucket));
  } else if (value && typeof value === "object") {
    Object.values(value).forEach((item) => collectStrings(item, bucket));
  }
  return bucket;
}

test("every fact record is publishable and complete", () => {
  for (const fact of allFacts()) {
    const resolved = getFact(fact.factId);
    assert.equal(resolved.status, "verified");
    assert.ok(resolved.claim.length > 0);
    assert.ok(resolved.sourceUrl.startsWith("https://"));
    assert.ok(resolved.reviewedAt);
    assert.ok(resolved.nextReviewAt);
    assert.ok(resolved.jurisdiction);
    assert.ok(resolved.authorityStatus);
  }
});

test("every inline token in every article resolves", () => {
  for (const article of ARTICLES) {
    const strings = collectStrings(article, []);
    for (const text of strings) {
      for (const match of text.matchAll(TOKEN)) {
        if (match[1] === "fact") {
          assert.doesNotThrow(() => getFact(match[2]), `bad fact token ${match[2]} in ${article.slug}`);
        } else {
          assert.ok(GLOSSARY[match[2]], `bad term token ${match[2]} in ${article.slug}`);
        }
      }
    }
  }
});

test("article metadata is internally consistent", () => {
  for (const article of ARTICLES) {
    assert.doesNotThrow(() => getArticle(article.next), `bad next slug in ${article.slug}`);
    assert.doesNotThrow(() => factSources(article.factIds), `bad factIds in ${article.slug}`);
    if (article.activity.kind === "calculator") {
      assert.doesNotThrow(() => getCalculator(article.activity.slug), `bad activity in ${article.slug}`);
    }
    for (const item of article.quiz) {
      assert.ok(Number.isInteger(item.answer) && item.answer >= 0 && item.answer < item.options.length,
        `quiz answer out of range in ${article.slug}`);
      assert.ok(item.explain.length > 0, `missing quiz explanation in ${article.slug}`);
    }
    assert.ok(article.learn.length >= 3, `too few learning goals in ${article.slug}`);
    assert.ok(article.risks.length >= 3, `too few risk notes in ${article.slug}`);
    assert.ok(article.summary.plain && article.summary.kid, `missing summary variant in ${article.slug}`);
  }
});

test("glossary entries carry both reading levels", () => {
  for (const [slug, entry] of Object.entries(GLOSSARY)) {
    assert.ok(entry.word && entry.plain && entry.kid, `incomplete glossary entry ${slug}`);
  }
});

test("every calculator has fields, defaults, and at least one scenario", () => {
  for (const calc of CALCULATORS) {
    assert.ok(calc.fields.length > 0);
    for (const field of calc.fields) {
      assert.ok(field.defaultValue !== undefined, `missing default in ${calc.slug}.${field.id}`);
    }
    assert.ok(Array.isArray(calc.scenarios) && calc.scenarios.length > 0, `no scenarios in ${calc.slug}`);
    for (const scenario of calc.scenarios) {
      for (const key of Object.keys(scenario.values)) {
        assert.ok(calc.fields.some((field) => field.id === key), `scenario key ${key} unknown in ${calc.slug}`);
      }
    }
  }
});
