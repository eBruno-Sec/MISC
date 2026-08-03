"""SOA-RNAME / mangled DNS artifacts (hostmaster.hostmaster.x) are not real scan targets.
dns_recon.is_junk_host drops them and memory.snapshot never persists them into warm-start, so a
later scan never re-seeds a junk target that only yields a scope block. The filter is conservative:
plausible real subdomains (www / mail / mx1 / api / admin) are never flagged."""
from __future__ import annotations

import dns_recon
import memory


def test_is_junk_host_flags_soa_rname_and_repeated_labels():
    for h in ["hostmaster.hostmaster.hostmaster.juice-shop", "hostmaster.hostmaster.juice-shop",
              "hostmaster.juice-shop", "postmaster.example.com", "dnsadmin.example.com",
              "www.www.example.com", ""]:
        assert dns_recon.is_junk_host(h) is True, h


def test_is_junk_host_keeps_plausible_real_subdomains():
    for h in ["www.juice-shop", "mail.juice-shop", "mx1.juice-shop", "api.example.com",
              "admin.example.com", "dev.example.com", "juice-shop", "juice-shop:3000"]:
        assert dns_recon.is_junk_host(h) is False, h


def test_memory_snapshot_never_persists_junk_subdomains():
    snap = memory.snapshot(
        {"subdomains": ["www.juice-shop", "mail.juice-shop",
                        "hostmaster.hostmaster.juice-shop", "hostmaster.juice-shop"]}, [], [])
    subs = snap.get("subdomains") or []
    assert "www.juice-shop" in subs and "mail.juice-shop" in subs   # real subs kept
    assert not any("hostmaster" in s for s in subs)                 # SOA-RNAME junk dropped
