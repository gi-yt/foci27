#!/usr/bin/env python3

"""
Write a per domain+ISP breakdown of every combo where OONI gives
mixed results: how many measurements were blocked vs unblocked, by
which method (DNS, TLS, other HTTP failure, TCP/IP, HTTP diff,
blockpage), and on which ASN.

Inputs come from compare_ooni_dnsblocks.py output and (optionally)
fetch_ooni_raw.py output for the TLS split.
"""

import argparse
from collections import Counter, defaultdict
from pathlib import Path

from common import read_csv, write_csv
from paths import MIXED_CSV_2025, MIXED_TXT_2025, RAW_DETAILS_2025, RESULTS_2025, ROOT


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results",
        default=str(RESULTS_2025),
        help="Directory written by compare_ooni_dnsblocks.py.",
    )
    parser.add_argument(
        "--raw",
        default=str(RAW_DETAILS_2025),
        help="CSV written by fetch_ooni_raw.py (for the TLS split).",
    )
    parser.add_argument("--csv", default=str(MIXED_CSV_2025))
    parser.add_argument("--txt", default=str(MIXED_TXT_2025))
    return parser.parse_args()


def asn_breakdown(domain_asn):
    """
    {(domain, isp): 'AS24309 20b/12u, AS18209 20b/0u'}, most measured ASN first.
    """

    parts = defaultdict(list)
    for r in domain_asn:
        usable = int(r["n_usable"])
        if usable <= 0:
            continue
        blocked = int(r["n_anomaly"]) + int(r["n_confirmed"])
        parts[(r["domain"], r["isp"])].append(
            (-usable, int(r["asn"]), f"AS{r['asn']} {blocked}b/{r['n_ok']}u")
        )
    return {k: ", ".join(p for *_, p in sorted(v)) for k, v in parts.items()}


def tls_counts(raw_path):
    """
    {(domain, isp): (n_tls, n_raw_http_failure)}. TLS interference is only
    counted inside http-failure, so the two can be subtracted.
    """

    if not Path(raw_path).exists():
        return None

    counts = defaultdict(lambda: [0, 0])
    for r in read_csv(raw_path):
        if r["blocking_type"] != "http-failure":
            continue
        c = counts[(r["domain"], r["isp"])]
        c[0] += r["tls_interference"].lower() == "true"
        c[1] += 1
    return counts


def by_isp(rows):
    return ", ".join(f"{n} {isp}" for isp, n in Counter(r["isp"] for r in rows).most_common())


def line(r):
    blocked = int(r["n_anomaly"]) + int(r["n_confirmed"])

    methods = [
        f"dns {r['n_dns']}",
        f"tls {r['n_tls']}" if r["has_tls"] else None,
        f"http-failure {r['n_http_failure_other']}"
        if r["has_tls"] else f"http-failure {r['n_http_failure']}",
        f"tcp {r['n_tcp_ip']}",
        f"http-diff {r['n_http_diff']}",
        f"blockpage-confirmed {r['n_confirmed']}",
    ]
    methods = ", ".join(m for m in methods if m)

    return (
        f"{r['isp']:<8} {r['domain']:<34} "
        f"blocked {blocked} / unblocked {r['n_ok']} / failed {r['n_failure']} "
        f"({100 * float(r['block_share']):.0f}% blocked) | {methods} | {r['per_asn']}"
    )


def main():
    args = parse_args()
    results = Path(args.results)

    domain_isp = read_csv(results / "domain_isp.csv")
    fields = list(domain_isp[0])
    per_asn = asn_breakdown(read_csv(results / "domain_asn.csv"))
    tls = tls_counts(args.raw)

    mixed = [r for r in domain_isp if r["ooni_verdict"] == "mixed"]
    for r in mixed:
        key = (r["domain"], r["isp"])
        r["per_asn"] = per_asn.get(key)
        r["has_tls"] = tls is not None
        n_tls, n_raw = tls.get(key, (0, None)) if tls is not None else (0, None)
        r["n_tls"] = n_tls
        r["n_raw_http_failure"] = n_raw
        r["n_http_failure_other"] = int(r["n_http_failure"]) - n_tls

    write_csv(
        args.csv,
        mixed,
        fields + ["per_asn", "has_tls", "n_tls", "n_raw_http_failure", "n_http_failure_other"],
    )

    groups = [
        ("pw_blocked/ooni_mixed",
         "domain+ISP combos where the domain IS marked as blocked by dnsblocks, but getting mixed results from OONI"),
        ("pw_ok/ooni_mixed",
         "domain+ISP combos where the domain isnt marked as blocked by dnsblocks but mixed results from OONI"),
    ]
    named = {g for g, _ in groups}
    has_tls = tls is not None

    out = [
        f"Mixed OONI results per domain+ISP, from {results.resolve().relative_to(ROOT)}",
        "b = blocked (anomaly or confirmed), u = unblocked, failed = measurement failed (excluded from %)",
        "dns/tls/http-failure/tcp/http-diff split the blocked count by method; blockpage-confirmed overlaps them",
        "tls = TLS handshake reset/EOF/timeout after a successful TCP connect (from raw measurements)"
        if has_tls else
        "tls split not available yet: run fetch_ooni_raw.py, then rerun this script",
        "",
        f"{len(mixed)} domain+ISP combos give mixed results",
        "",
    ]

    other_title = "domain+ISP combos where dnsblocks has error/timeout/servfail/nxdomain, with mixed results from OONI"
    for agreement, title in groups + [("other", other_title)]:
        if agreement == "other":
            part = [r for r in mixed if r["agreement"] not in named]
        else:
            part = [r for r in mixed if r["agreement"] == agreement]
        if not part:
            continue

        out.append(f"{len(part)} {title} ({by_isp(part)})")
        out.append("")
        # Stable sort keeps domain_isp.csv order among ties.
        for r in sorted(part, key=lambda r: (r["isp"], -float(r["block_share"]))):
            out.append(line(r))
        out.append("")

    if has_tls:
        with_tls = [r for r in mixed if r["n_tls"] > 0]
        out.append(
            f"{len(with_tls)} mixed domain+ISP combos include TLS interference ({by_isp(with_tls)})"
        )
        out.append("")

    Path(args.txt).write_text("\n".join(out) + "\n")
    print(f"Wrote {args.txt} and {args.csv}")


if __name__ == "__main__":
    main()
