"""robots.txt and sitemap.xml as surface sources.

Neither was ever fetched by a general scan -- they appeared only in a noise-exclusion list and in the
Natas CTF solver. They are the two highest-yield free discovery sources: robots.txt is the owner's own
list of paths they would rather you did not visit, sitemap.xml is an enumerated site index.
"""
import crawl


def test_robots_harvests_disallow_as_recon_not_as_instruction():
    txt = """User-agent: *
Disallow: /admin/
Disallow: /backup/db.sql
Allow: /public/
Disallow: /internal/*
Disallow: /
Sitemap: https://t.tld/sitemap.xml
"""
    got = crawl.parse_robots(txt, "https://t.tld/")
    assert "https://t.tld/admin/" in got["urls"]
    assert "https://t.tld/backup/db.sql" in got["urls"]
    assert "https://t.tld/public/" in got["urls"]          # Allow is surface too
    assert "https://t.tld/internal/" in got["urls"]        # wildcard reduced to its literal prefix
    assert "https://t.tld/" not in got["urls"]             # bare / names the whole site, adds nothing
    assert got["sitemaps"] == ["https://t.tld/sitemap.xml"]


def test_sitemap_separates_pages_from_nested_indexes():
    xml = """<?xml version="1.0"?><urlset>
      <url><loc>https://t.tld/a.html</loc></url>
      <url><loc>https://t.tld/b?x=1&amp;y=2</loc></url>
      <url><loc>https://t.tld/more-sitemap.xml</loc></url>
    </urlset>"""
    got = crawl.parse_sitemap(xml, "https://t.tld/")
    assert "https://t.tld/a.html" in got["urls"]
    assert "https://t.tld/b?x=1&y=2" in got["urls"]        # entities decoded
    assert got["sitemaps"] == ["https://t.tld/more-sitemap.xml"]


def test_relative_locs_resolve_against_the_document():
    got = crawl.parse_sitemap("<urlset><url><loc>page.html</loc></url></urlset>",
                              "https://t.tld/deep/sitemap.xml")
    assert got["urls"] == ["https://t.tld/deep/page.html"]


def test_nothing_is_invented_from_junk():
    for bad in ("", None, "not xml at all", "<urlset></urlset>"):
        assert crawl.parse_sitemap(bad, "https://t.tld/")["urls"] == []
    for bad in ("", None, "# just a comment"):
        assert crawl.parse_robots(bad, "https://t.tld/")["urls"] == []
    # non-navigable schemes must never become targets
    assert crawl.parse_sitemap("<loc>mailto:x@y.z</loc>", "https://t.tld/")["urls"] == []


def test_documents_are_size_bounded():
    huge = "<loc>https://t.tld/x</loc>" * 200000
    assert len(crawl.parse_sitemap(huge, "https://t.tld/")["urls"]) <= 500
