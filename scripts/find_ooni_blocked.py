#!/usr/bin/env python3

"""
Find every blocked OONI result on the study ASNs inside each ISP's
Poisoned Wells window, for any domain (not just the test-list overlap).

1. Aggregation API, one call per ASN: per-hostname totals
   (ok / anomaly / confirmed / failure) for everything measured.
2. Measurement list API with anomaly=true, per ASN: every blocked
   measurement, with its blocking type.
3. Annotate each hostname: in the PW blocklist or not, PW value for
   that ISP, on the OONI test list or not, apex / www / subdomain.

Outputs (default prefix ooni_blocked_2025):
  _measurements.csv  every blocked measurement
  _domains.csv       per hostname x ASN totals, blocking types, verdict
  summary            findings-style counts (repository root)
"""

import argparse
import csv
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from common import (
    ASN_REGION,
    BLOCKING_TYPES,
    ISP_ASNS,
    PW_WINDOW,
    get_json,
    load_testlist,
    np_round,
    pw_lookup,
    read_csv,
    registrable_domain,
    write_csv,
)
from fetch_ooni_data import (
    API_URL,
    OUTPUT_FIELDS,
    PAGE_SIZE,
    flatten_measurement,
)
from paths import BLOCKED_PREFIX_2025, BLOCKED_SUMMARY_2025


AGGREGATION_URL = "https://api.ooni.io/api/v1/aggregation"

WWW_PREFIX = re.compile(r"w{2,3}\d*")
IP_ADDRESS = re.compile(r"[\d.]+|\[?[0-9a-f:]+\]?")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        default=str(BLOCKED_PREFIX_2025),
        help="Prefix for the CSV outputs.",
    )
    parser.add_argument("--summary", default=str(BLOCKED_SUMMARY_2025))
    parser.add_argument("--margin-days", type=int, default=7)
    parser.add_argument("--ok-max", type=float, default=0.1)
    parser.add_argument("--blocked-min", type=float, default=0.9)
    parser.add_argument("--min-measurements", type=int, default=3)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument(
        "--skip-fetch",
        action="store_true",
        help="Reuse the _measurements.csv / _totals.csv from a previous run.",
    )
    return parser.parse_args()


def windows(margin_days):
    margin = timedelta(days=margin_days)

    for isp, asns in ISP_ASNS.items():
        start, end = PW_WINDOW[isp]
        since = datetime.fromisoformat(start) - margin
        until = datetime.fromisoformat(end) + timedelta(days=1) + margin

        for asn in asns:
            yield isp, asn, since.isoformat(), until.isoformat()


def fetch_totals(isp, asn, since, until):
    data = get_json(AGGREGATION_URL, {
        "probe_cc": "IN",
        "probe_asn": f"AS{asn}",
        "test_name": "web_connectivity",
        "since": since,
        "until": until,
        "axis_x": "domain",
    })

    rows = data.get("result") or []

    for r in rows:
        r["isp"] = isp
        r["asn"] = asn

    return rows


def fetch_blocked(isp, asn, since, until, delay):
    rows = []
    url = API_URL
    params = {
        "probe_cc": "IN",
        "probe_asn": f"AS{asn}",
        "test_name": "web_connectivity",
        "anomaly": "true",
        "since": since,
        "until": until,
        "limit": PAGE_SIZE,
    }

    while True:
        data = get_json(url, params)
        results = data.get("results") or []

        for m in results:
            host = hostname(m.get("input"))
            row = flatten_measurement(host, m)
            row["isp"] = isp
            rows.append(row)

        next_url = (data.get("metadata") or {}).get("next_url")

        if not next_url or len(results) < PAGE_SIZE:
            return rows

        url, params = next_url, None
        time.sleep(delay)


def hostname(url):
    if not url:
        return None

    host = re.sub(r"^[a-z]+://", "", str(url).lower())
    return host.split("/")[0].split(":")[0].rstrip(".")


def host_kind(host, apex):
    if not host or not apex:
        return "unknown"

    if IP_ADDRESS.fullmatch(host):
        return "ip"

    if host == apex:
        return "apex"

    prefix = host[: -len(apex) - 1]

    if WWW_PREFIX.fullmatch(prefix):
        return "www"

    return "subdomain"


def fetch(args):
    totals, blocked = [], []

    for isp, asn, since, until in windows(args.margin_days):
        print(f"{isp} AS{asn} {since[:10]} -> {until[:10]}")

        t = fetch_totals(isp, asn, since, until)
        print(f"    {len(t)} hostnames measured")
        totals.extend(t)
        time.sleep(args.delay)

        b = fetch_blocked(isp, asn, since, until, args.delay)
        print(f"    {len(b)} blocked measurements")
        blocked.extend(b)
        time.sleep(args.delay)

    write_csv(f"{args.output}_totals.csv", totals, list(totals[0]) if totals else [])

    with open(f"{args.output}_measurements.csv", "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=OUTPUT_FIELDS + ["isp"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(blocked)


def build(args):
    totals = read_csv(f"{args.output}_totals.csv")

    # Blocking-type counts per hostname x ASN, from every blocked measurement.
    types = defaultdict(Counter)
    seen = set()
    for r in read_csv(f"{args.output}_measurements.csv"):
        if r["measurement_uid"] in seen:
            continue
        seen.add(r["measurement_uid"])
        asn = int(r["probe_asn"].removeprefix("AS"))
        types[(r["domain"], r["isp"], asn)][r["blocking_type"] or "none"] += 1
    present = sorted({t for c in types.values() for t in c})
    type_cols = [t.replace("-", "_") for t in present]
    type_cols += [
        t.replace("-", "_") for t in BLOCKING_TYPES + ["none"]
        if t.replace("-", "_") not in type_cols
    ]

    pw = pw_lookup()
    testlist = load_testlist()

    rows = []
    for t in totals:
        r = {
            "n_anomaly": int(t["anomaly_count"]),
            "n_confirmed": int(t["confirmed_count"]),
            "n_failure": int(t["failure_count"]),
            "n_ok": int(t["ok_count"]),
            "n_total": int(t["measurement_count"]),
            "host": t["domain"],
            "isp": t["isp"],
            "asn": int(t["asn"]),
        }
        counts = types.get((r["host"], r["isp"], r["asn"]), Counter())
        for t_name, col in zip(present + [c for c in BLOCKING_TYPES + ["none"] if c not in present], type_cols):
            r["n_" + col] = counts.get(t_name, 0)

        # Annotate against PW and the test list.
        r["apex"] = registrable_domain(r["host"])
        r["host_kind"] = host_kind(r["host"], r["apex"])
        r["asn_region"] = ASN_REGION.get(r["asn"])
        meta = pw.get((r["apex"], r["isp"]))
        r["pw_category"] = meta["pw_category"] if meta else None
        r["pw_value"] = meta["pw_value"] if meta else None
        r["pw_status"] = meta["pw_status"] if meta else "not_in_blocklist"
        r["testlist_category"] = testlist.get(r["apex"])
        r["on_testlist"] = r["testlist_category"] is not None

        # Verdicts, same rules as compare_ooni_dnsblocks.py.
        r["n_blocked"] = r["n_anomaly"] + r["n_confirmed"]
        r["n_usable"] = r["n_total"] - r["n_failure"]
        r["block_share"] = np_round(r["n_blocked"] / r["n_usable"], 4) if r["n_usable"] else None
        verdict = "mixed"
        if r["block_share"] is not None and r["block_share"] <= args.ok_max:
            verdict = "ok"
        if r["block_share"] is not None and r["block_share"] >= args.blocked_min:
            verdict = "blocked"
        if r["n_usable"] == 0:
            verdict = "failures_only"
        r["ooni_verdict"] = verdict
        r["low_confidence"] = r["n_usable"] < args.min_measurements
        rows.append(r)

    # Stable sort: ties keep the totals file order.
    rows.sort(key=lambda r: (r["pw_status"], -r["n_blocked"]))

    fields = (
        ["n_anomaly", "n_confirmed", "n_failure", "n_ok", "n_total", "host", "isp", "asn"]
        + ["n_" + c for c in type_cols]
        + ["apex", "host_kind", "asn_region", "pw_category", "pw_value", "pw_status",
           "testlist_category", "on_testlist", "n_blocked", "n_usable", "block_share",
           "ooni_verdict", "low_confidence"]
    )
    write_csv(f"{args.output}_domains.csv", rows, fields)
    return rows


def hosts(rows):
    return len({r["host"] for r in rows})


def per_isp(rows):
    """
    '577 AIRTEL, 476 JIO, ...' distinct hostnames per ISP, largest first.
    """

    by = defaultdict(set)
    for r in rows:
        by[r["isp"]].add(r["host"])
    counts = sorted(((isp, len(h)) for isp, h in by.items()))
    return ", ".join(f"{n} {isp}" for isp, n in sorted(counts, key=lambda x: -x[1]))


def summarize(rows, args):
    out = [
        "Every blocked OONI result on the study ASNs, in each ISP's Poisoned Wells window "
        f"(+/- {args.margin_days} days), any domain",
        "blocked = OONI anomaly or confirmed; verdict 'blocked' = at least "
        f"{args.blocked_min:.0%} of usable measurements blocked",
        "",
    ]

    any_blocked = [r for r in rows if r["n_blocked"] > 0]
    apexes = {r["apex"] for r in rows if r["apex"]}

    out += [
        f"{hosts(rows)} hostnames measured by OONI on the study ASNs ({len(apexes)} apex domains)",
        "",
        f"{hosts(any_blocked)} hostnames blocked at least once ({per_isp(any_blocked)})",
        "",
    ]

    for title, status in [
        ("NOT in the PW blocklist at all", "not_in_blocklist"),
        ("in the PW blocklist but marked not blocked on that ISP", "not_blocked"),
    ]:
        part = [r for r in any_blocked if r["pw_status"] == status]
        out.append(f"== Blocked in OONI, {title} ==")
        out.append("")

        strict = [r for r in part if r["ooni_verdict"] == "blocked" and not r["low_confidence"]]
        confirmed = [r for r in part if r["n_confirmed"] > 0]
        three = [r for r in part if r["n_blocked"] >= 3]

        out += [
            f"{hosts(part)} hostnames blocked at least once ({per_isp(part)})",
            f"{hosts(three)} hostnames blocked at least 3 times ({per_isp(three)})",
            f"{hosts(confirmed)} hostnames with a confirmed blockpage ({per_isp(confirmed)})",
            f"{hosts(strict)} hostnames with OONI verdict 'blocked' "
            f"(at least {args.min_measurements} usable measurements) ({per_isp(strict)})",
            "",
        ]

        for kind in ["apex", "www", "subdomain", "ip"]:
            k = [r for r in part if r["host_kind"] == kind]
            ks = [r for r in strict if r["host_kind"] == kind]
            if k:
                out.append(
                    f"  {kind}: {hosts(k)} blocked at least once, {hosts(ks)} with verdict 'blocked'"
                )

        on_tl = [r for r in part if r["on_testlist"]]
        off_tl = [r for r in part if not r["on_testlist"]]
        out.append(
            f"  on the OONI test list: {hosts(on_tl)} hostnames; "
            f"not on it (custom/other inputs): {hosts(off_tl)}"
        )

        dns_seen = [r for r in part if r["n_dns"] > 0]
        dns_only = [r for r in dns_seen if r["n_http_failure"] + r["n_http_diff"] + r["n_tcp_ip"] == 0]
        no_dns = [r for r in part if r["n_dns"] == 0]
        out += [
            f"  DNS blocking seen: {hosts(dns_seen)} hostnames ({hosts(dns_only)} DNS only)",
            f"  no DNS blocking, only http-failure/tcp/http-diff (TLS candidates): "
            f"{hosts(no_dns)} hostnames",
            "",
            "  Top 25 by blocked measurements (hostname, ISP, ASN, blocked/usable, types):",
        ]

        for r in sorted(part, key=lambda r: -r["n_blocked"])[:25]:
            types = ", ".join(
                f"{bt} {r['n_' + bt.replace('-', '_')]}"
                for bt in BLOCKING_TYPES
                if r["n_" + bt.replace("-", "_")] > 0
            )
            out.append(
                f"  {r['host']:<36} {r['isp']:<7} AS{r['asn']:<7} "
                f"{r['n_blocked']}/{r['n_usable']} | {types} | {r['host_kind']}"
            )

        out.append("")

    Path(args.summary).write_text("\n".join(out) + "\n")
    print("\n".join(out))


def main():
    args = parse_args()

    if not args.skip_fetch:
        fetch(args)

    rows = build(args)
    summarize(rows, args)


if __name__ == "__main__":
    main()
