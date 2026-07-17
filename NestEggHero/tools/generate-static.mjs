import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { ARTICLES, GLOSSARY } from "../scripts/content.js";
import { allFacts, getFact, sourceListForFactIds } from "../scripts/facts.js";
import { CALCULATORS } from "../scripts/calculators.js";

const root = process.cwd();
const site = "https://ebruno-sec.github.io/MISC/NestEggHero";

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function plain(text) {
  return String(text).replace(/\[\[(fact|term):([a-z0-9-]+)\]\]/g, (_all, kind, id) => {
    if (kind === "fact") return getFact(id).display;
    return GLOSSARY[id]?.word || id;
  });
}

function pick(value) {
  return typeof value === "string" ? value : value.plain;
}

function shell({ title, description, path, body, jsonLd = null }) {
  const canonical = `${site}${path}`;
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${esc(title)}</title>
    <meta name="description" content="${esc(description)}">
    <meta name="robots" content="index, follow">
    <meta name="theme-color" content="#101619">
    <meta property="og:title" content="${esc(title)}">
    <meta property="og:description" content="${esc(description)}">
    <meta property="og:type" content="website">
    <meta property="og:url" content="${canonical}">
    <link rel="canonical" href="${canonical}">
    <link rel="stylesheet" href="../styles/main.css">
    <link rel="icon" href="../images/mark.svg" type="image/svg+xml">
    ${jsonLd ? `<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>` : ""}
  </head>
  <body>
    <a class="skip-link" href="#main">Skip to main content</a>
    <header class="site-header">
      <a class="brand" href="../index.html"><img src="../images/mark.svg" alt="" width="42" height="42"><span><strong>NestEggHero</strong><small>Financial learning studio</small></span></a>
      <nav class="primary-nav open" aria-label="Static navigation">
        <a href="../index.html">Interactive app</a>
        <a href="index.html">Lessons</a>
        <a href="../tools/index.html">Calculators</a>
        <a href="../index.html#/tools/roth-traditional-lab">Roth Lab</a>
        <a href="../facts/index.html">Fact registry</a>
      </nav>
    </header>
    <main id="main" class="view">${body}</main>
    <footer class="site-footer"><p><strong>General education only.</strong> Not tax, legal, fiduciary, or investment advice. Facts reviewed 2026-07-16.</p></footer>
  </body>
</html>`;
}

function articlePage(article) {
  const sources = sourceListForFactIds(article.factIds);
  const body = `
    <nav class="breadcrumbs" aria-label="Breadcrumb"><a href="../index.html">Home</a><a href="index.html">Lessons</a><span aria-current="page">${esc(article.title)}</span></nav>
    <article class="article-body">
      <header class="article-header">
        <p class="eyebrow">${esc(article.topic)}</p>
        <h1>${esc(article.title)}</h1>
        <p class="article-meta">${esc(article.minutes)} min | ${esc(article.authorityStatus)} | Reviewed ${esc(article.updatedAt)}${article.effectiveYear ? ` | Effective year ${esc(article.effectiveYear)}` : ""}</p>
      </header>
      <section class="article-section"><h2>What you will learn</h2><ul>${article.learn.map((item) => `<li>${esc(item)}</li>`).join("")}</ul></section>
      <section class="article-section"><h2>Plain-language summary</h2><p>${esc(plain(pick(article.summary)))}</p></section>
      ${article.sections.map((section) => `<section class="article-section"><h2>${esc(section.heading)}</h2>${section.paragraphs.map((p) => `<p>${esc(plain(pick(p)))}</p>`).join("")}</section>`).join("")}
      <section class="article-section"><h2>Example</h2><p>${esc(plain(pick(article.example)))}</p></section>
      <section class="article-section"><h2>Risks and exceptions</h2><ul>${article.risks.map((item) => `<li>${esc(item)}</li>`).join("")}</ul></section>
      <section class="article-section"><h2>Key takeaways</h2><ul>${article.takeaways.map((item) => `<li>${esc(item)}</li>`).join("")}</ul></section>
      <section class="article-section"><h2>Sources</h2>${sources.length ? `<ul>${sources.map((source) => `<li><a href="${esc(source.url)}" rel="noopener">${esc(source.title)}</a></li>`).join("")}</ul>` : `<p>Mathematical education lesson; formulas are shown in calculator assumptions.</p>`}</section>
      <p class="next-step"><a class="btn primary" href="${article.next}.html">Next lesson: ${esc(ARTICLES.find((item) => item.slug === article.next).title)}</a></p>
    </article>`;
  return shell({
    title: `${article.title} | NestEggHero`,
    description: plain(pick(article.summary)).slice(0, 155),
    path: `/learn/${article.slug}.html`,
    body,
    jsonLd: {
      "@context": "https://schema.org",
      "@type": "Article",
      headline: article.title,
      dateModified: article.updatedAt,
      about: article.topic,
      isAccessibleForFree: true,
      educationalUse: "financial education"
    }
  });
}

function lessonIndex() {
  const body = `<header class="view-header"><p class="eyebrow">Static lesson library</p><h1>Source-labeled lessons</h1><p class="lead">These pages provide crawlable lesson content. The interactive app adds quizzes, bookmarks, highlights, progress, and backups.</p></header><div class="card-grid">${ARTICLES.map((article) => `<article class="card"><p class="eyebrow">${esc(article.topic)}</p><h2><a href="${article.slug}.html">${esc(article.title)}</a></h2><p>${esc(plain(pick(article.summary)))}</p><p class="muted">${esc(article.minutes)} min | ${esc(article.authorityStatus)}</p></article>`).join("")}</div>`;
  return shell({ title: "Lessons | NestEggHero", description: "Crawlable NestEggHero lesson library with source-labeled retirement education.", path: "/learn/", body });
}

function factsIndex() {
  const facts = allFacts();
  const body = `<header class="view-header"><p class="eyebrow">Fact registry</p><h1>Changing facts with source labels</h1><p class="lead">Every changing financial figure includes effective year, authority status, official source, review date, and next-review date.</p></header><div class="table-wrap"><table><thead><tr><th scope="col">Claim</th><th scope="col">Value</th><th scope="col">Authority</th><th scope="col">Source</th><th scope="col">Review</th></tr></thead><tbody>${facts.map((fact) => `<tr><th scope="row">${esc(fact.claim)}</th><td>${esc(fact.display)}</td><td>${esc(fact.authorityStatus)}</td><td><a href="${esc(fact.sourceUrl)}" rel="noopener">${esc(fact.sourceTitle)}</a></td><td>${esc(fact.reviewedAt)}; next ${esc(fact.nextReviewAt)}</td></tr>`).join("")}</tbody></table></div>`;
  return shell({ title: "Fact Registry | NestEggHero", description: "NestEggHero source-labeled financial fact registry.", path: "/facts/", body });
}

function toolsIndex() {
  const featured = CALCULATORS.find((calc) => calc.slug === "roth-traditional-lab");
  const body = `<header class="view-header"><p class="eyebrow">Estimate calculators</p><h1>Tools that show assumptions</h1><p class="lead">The interactive app runs these deterministic calculators locally in the browser.</p></header><section class="tool-spotlight"><div><p class="eyebrow">Featured</p><h2>${esc(featured.name)}</h2><p>${esc(featured.blurb)}</p><a class="btn primary" href="../index.html#/tools/${featured.slug}">Compare scenarios</a></div><dl class="metric-grid"><div><dt>Modes</dt><dd>2</dd></div><div><dt>Phaseout checks</dt><dd>3</dd></div><div><dt>Saved data</dt><dd>0</dd></div></dl></section><div class="card-grid tool-grid">${CALCULATORS.map((calc) => `<article class="${calc.slug === featured.slug ? "card tool-card featured-tool" : "card tool-card"}"><p class="eyebrow">${calc.slug === featured.slug ? "Decision lab" : "Calculator"}</p><h2><a href="../index.html#/tools/${calc.slug}">${esc(calc.name)}</a></h2><p>${esc(calc.blurb)}</p></article>`).join("")}</div>`;
  return shell({ title: "Calculators | NestEggHero", description: "NestEggHero deterministic educational calculators.", path: "/tools/", body });
}

async function write(relative, html) {
  const target = join(root, relative);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, html, "utf8");
}

await write("learn/index.html", lessonIndex());
for (const article of ARTICLES) await write(`learn/${article.slug}.html`, articlePage(article));
await write("facts/index.html", factsIndex());
await write("tools/index.html", toolsIndex());

const urls = ["/", "/learn/", ...ARTICLES.map((article) => `/learn/${article.slug}.html`), "/facts/", "/tools/"];
const sitemap = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((path) => `  <url>\n    <loc>${site}${path}</loc>\n    <lastmod>2026-07-17</lastmod>\n    <changefreq>monthly</changefreq>\n    <priority>${path === "/" ? "1.0" : "0.8"}</priority>\n  </url>`).join("\n")}\n</urlset>\n`;
await write("sitemap.xml", sitemap);
