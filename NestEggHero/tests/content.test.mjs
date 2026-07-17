import test from "node:test";
import assert from "node:assert/strict";
import { ARTICLES, GLOSSARY, getArticle } from "../scripts/content.js";
import { allFacts, getFact, sourceListForFactIds } from "../scripts/facts.js";
import { CALCULATORS, getCalculator } from "../scripts/calculators.js";

const TOKEN = /\[\[(fact|term):([a-z0-9-]+)\]\]/g;

function collectStrings(value, bucket = []) {
  if (typeof value === "string") bucket.push(value);
  else if (Array.isArray(value)) value.forEach((item) => collectStrings(item, bucket));
  else if (value && typeof value === "object") Object.values(value).forEach((item) => collectStrings(item, bucket));
  return bucket;
}

test("fact records are complete and publishable", () => {
  assert.ok(allFacts().length >= 30);
  for (const fact of allFacts()) {
    assert.equal(getFact(fact.id).status, "verified");
    assert.ok(fact.claim);
    assert.ok(fact.display);
    assert.ok(fact.effectiveYear || fact.authorityStatus);
    assert.ok(fact.jurisdiction);
    assert.ok(fact.sourceUrl.startsWith("https://"));
    assert.ok(fact.reviewedAt);
    assert.ok(fact.nextReviewAt);
  }
});

test("every inline fact and term token resolves", () => {
  for (const article of ARTICLES) {
    for (const text of collectStrings(article)) {
      for (const match of text.matchAll(TOKEN)) {
        if (match[1] === "fact") assert.doesNotThrow(() => getFact(match[2]), `bad fact ${match[2]} in ${article.slug}`);
        if (match[1] === "term") assert.ok(GLOSSARY[match[2]], `bad term ${match[2]} in ${article.slug}`);
      }
    }
  }
});

test("article metadata links are internally valid", () => {
  assert.equal(ARTICLES.length, 8);
  for (const article of ARTICLES) {
    assert.doesNotThrow(() => getArticle(article.next));
    assert.doesNotThrow(() => sourceListForFactIds(article.factIds));
    if (article.activity.kind === "calculator") assert.doesNotThrow(() => getCalculator(article.activity.slug));
    assert.ok(article.learn.length >= 3);
    assert.ok(article.risks.length >= 3);
    assert.ok(article.takeaways.length >= 3);
    for (const item of article.quiz) assert.ok(Number.isInteger(item.answer) && item.answer >= 0 && item.answer < item.options.length);
  }
});

test("calculator slugs are unique", () => {
  const slugs = new Set(CALCULATORS.map((calc) => calc.slug));
  assert.equal(slugs.size, CALCULATORS.length);
});
