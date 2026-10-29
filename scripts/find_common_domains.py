#!/usr/bin/env python3

"""
Find the domains that are both on the OONI test list and in the Poisoned
Wells (dnsblocks.in) blocklist, and pick the hostname to query OONI with.

Poisoned Wells lists apex domains (example.com), while the OONI test list
has full URLs whose hostnames are often subdomains (www.example.com,
secure.example.com). So both sides are reduced to their apex domain
(registrable domain, via tldextract) before comparing.

The OONI measurements API filters on the exact hostname of the tested
URL, so each common apex is mapped back to one hostname from the test
list: the bare apex if listed, else a www. host, else another subdomain
(ties broken by order in the test list).

Outputs (domain_classification/):
  common_domains.txt     common apex domains, sorted
  sanitized_domain.txt   one test-list hostname per common apex, the
                         input to fetch_ooni_data.py (proper1, proper2,
                         proper3 concatenated)
  proper1                hostnames that are the bare apex
  proper2                hostnames that are www.<apex>
  proper3                hostnames on another subdomain
"""

import argparse
from collections import Counter
from pathlib import Path

from common import load_dnsblocks, load_testlist_rows
from paths import DOMAIN_LIST_FILE, DOMAINS_DIR


def host_kind(host, apex):
    if host == apex:
        return "apex"
    # Only a literal www. counts; www-like hosts such as ww25. are
    # treated as ordinary subdomains.
    if host == f"www.{apex}":
        return "www"
    return "subdomain"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=str(DOMAINS_DIR))
    args = parser.parse_args()

    tl = load_testlist_rows()
    pw = {r["domain"] for r in load_dnsblocks()}

    common = []
    for order, r in enumerate(tl):
        if r["apex"] in pw:
            kind = host_kind(r["host"], r["apex"])
            rank = {"apex": 0, "www": 1, "subdomain": 2}[kind]
            common.append({**r, "kind": kind, "rank": rank, "order": order})

    # One hostname per apex: bare apex, then www., then other subdomains,
    # ties by test-list order. Plain character order (not locale
    # collation) so the output is the same on every machine.
    chosen = {}
    for r in sorted(common, key=lambda r: (r["apex"], r["rank"], r["order"])):
        chosen.setdefault(r["apex"], r)
    chosen = sorted(chosen.values(), key=lambda r: (r["rank"], r["host"]))

    out = Path(args.out_dir)

    def write(name, values):
        (out / name).write_text("".join(f"{v}\n" for v in values))

    write("common_domains.txt", sorted(r["apex"] for r in chosen))
    # Apex hosts, then www., then other subdomains.
    write(DOMAIN_LIST_FILE.name, [r["host"] for r in chosen])
    for name, kind in [("proper1", "apex"), ("proper2", "www"), ("proper3", "subdomain")]:
        write(name, [r["host"] for r in chosen if r["kind"] == kind])

    chosen_hosts = {r["host"] for r in chosen}
    skipped = sorted({r["host"] for r in common if r["host"] not in chosen_hosts})
    apexes = {r["apex"] for r in tl if r["apex"] is not None}
    print(f"{len(tl)} test-list URLs, {len(apexes)} apex domains, {len(pw)} PW blocked domains")
    print(f"{len(chosen)} common apex domains")
    print(
        "chosen hostnames: "
        + ", ".join(f"{k} {v}" for k, v in Counter(r["kind"] for r in chosen).most_common())
    )
    print(
        f"{len(skipped)} other test-list hostnames of common apexes not queried: "
        + ", ".join(skipped)
    )


if __name__ == "__main__":
    main()
