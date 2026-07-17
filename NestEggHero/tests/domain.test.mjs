import test from "node:test";
import assert from "node:assert/strict";
import { ARTICLES } from "../scripts/content.js";
import { CALCULATORS } from "../scripts/calculators.js";
import { allFacts } from "../scripts/facts.js";

test("NestEggHero product spine is present", () => {
  assert.equal(ARTICLES.length, 8);
  assert.equal(CALCULATORS.length, 8);
  assert.ok(allFacts().length >= 30);
});
