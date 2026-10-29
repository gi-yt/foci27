#!/usr/bin/env python3

"""
Compare OONI Web Connectivity results with the Poisoned Wells
(dnsblocks.in) blocklist, per domain x ISP, domain x ASN and
domain x ISP x month, plus coverage and disagreement summaries.
"""

import argparse
from collections import defaultdict
from pathlib import Path

from common import (
    AGG_FIELDS,
    ASN_REGION,
    COUNT_FIELDS,
    DNS_ISPS,
    PW_ASN,
    PW_FIELDS,
    PW_WINDOW,
    VERDICT_FIELDS,
    add_agreement,
    add_verdicts,
    aggregate,
    apply_window,
    crosstab,
    empty_counts,
    load_dnsblocks,
    load_ooni,
    load_testlist,
    np_round,
    pw_lookup,
    write_crosstab,
    write_csv,
)
from paths import OONI_2025, RESULTS_DIR


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ooni",
        default=str(OONI_2025),
        help="OONI CSV produced by fetch_ooni_data.py.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="Output directory. Default: comparison_results/<ooni file stem>/",
    )
    parser.add_argument(
        "--window",
        choices=["pw", "all"],
        default="pw",
        help=(
            "'pw': keep only OONI measurements inside each ISP's Poisoned "
            "Wells window (+/- --margin-days). 'all': keep every measurement "
            "in the input file."
        ),
    )
    parser.add_argument("--margin-days", type=int, default=7)
    parser.add_argument(
        "--ok-max",
        type=float,
        default=0.1,
        help="'ok' if at most this share of usable measurements are anomalous.",
    )
    parser.add_argument(
        "--blocked-min",
        type=float,
        default=0.9,
        help="'blocked' if at least this share of usable measurements are anomalous.",
    )
    parser.add_argument(
        "--min-measurements",
        type=int,
        default=3,
        help="Verdicts based on fewer usable measurements are flagged low_confidence.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    thresholds = dict(
        ok_max=args.ok_max,
        blocked_min=args.blocked_min,
        min_measurements=args.min_measurements,
    )

    out_dir = Path(args.output_dir or RESULTS_DIR / Path(args.ooni).stem)
    out_dir.mkdir(parents=True, exist_ok=True)

    dns = load_dnsblocks()
    pw = pw_lookup(dns)
    testlist = load_testlist()

    print(f"Loading {args.ooni}...")
    ooni = load_ooni(args.ooni)
    print(f"  {len(ooni)} measurements on mapped ISP ASNs")

    if args.window == "pw":
        ooni = apply_window(ooni, args.margin_days)
        print(f"  {len(ooni)} inside Poisoned Wells windows (+/- {args.margin_days} days)")

    def finish(row, with_testlist=True):
        meta = pw.get((row["domain"], row["isp"]))
        row.update(meta if meta else {f: None for f in PW_FIELDS})
        if not meta:
            row["pw_status"] = "not_in_blocklist"
        if with_testlist:
            row["testlist_category"] = testlist.get(row["domain"])
        add_agreement(add_verdicts(row, **thresholds))
        return row

    # ---- domain x ISP: every queried domain crossed with every ISP, so
    # ISPs with no measurements show up explicitly as no_data ----
    print("Aggregating domain x ISP...")
    agg = aggregate(ooni, ["domain", "isp"])
    queried = list(dict.fromkeys(r["domain"] for r in ooni if r["domain"]))
    domain_isp = []
    for domain in queried:
        for isp in DNS_ISPS:
            row = agg.get((domain, isp)) or {"domain": domain, "isp": isp, **empty_counts()}
            row = finish(row)
            row["pw_asn"] = PW_ASN[isp]
            row["pw_window"] = " -> ".join(PW_WINDOW[isp])
            domain_isp.append(row)
    domain_isp.sort(key=lambda r: (r["isp"], r["agreement"], r["domain"]))

    isp_fields = (
        ["domain", "isp"] + AGG_FIELDS + PW_FIELDS + ["testlist_category"]
        + VERDICT_FIELDS + ["agreement", "pw_asn", "pw_window"]
    )
    write_csv(out_dir / "domain_isp.csv", domain_isp, isp_fields)

    # ---- domain x ASN ----
    print("Aggregating domain x ASN...")
    domain_asn = []
    for row in aggregate(ooni, ["domain", "isp", "asn"]).values():
        row = finish(row)
        row["pw_asn"] = PW_ASN[row["isp"]]
        row["pw_window"] = " -> ".join(PW_WINDOW[row["isp"]])
        row["is_pw_asn"] = row["asn"] == row["pw_asn"]
        row["asn_region"] = ASN_REGION.get(row["asn"])
        domain_asn.append(row)
    domain_asn.sort(key=lambda r: (r["isp"], r["asn"], r["agreement"], r["domain"]))
    write_csv(
        out_dir / "domain_asn.csv",
        domain_asn,
        ["domain", "isp", "asn"] + isp_fields[2:] + ["is_pw_asn", "asn_region"],
    )

    # ---- domain x ISP x month (drift over time) ----
    print("Aggregating domain x ISP x month...")
    monthly = [
        finish(row, with_testlist=False)
        for row in aggregate(ooni, ["domain", "isp", "month"]).values()
    ]
    monthly.sort(key=lambda r: (r["isp"], r["domain"], r["month"]))
    write_csv(
        out_dir / "domain_isp_month.csv",
        monthly,
        ["domain", "isp", "month"] + AGG_FIELDS + PW_FIELDS + VERDICT_FIELDS + ["agreement"],
    )

    # ---- ASN summary: do an ISP's ASNs agree with PW equally? ----
    key = lambda r: (r["isp"], r["asn"], r["asn_region"], r["is_pw_asn"])
    measurements = defaultdict(int)
    for r in domain_asn:
        measurements[key(r)] += r["n_total"]
    usable_asn = [r for r in domain_asn if r["n_usable"] > 0]
    groups, labels, counts = crosstab(usable_asn, key, lambda r: r["agreement"])
    write_csv(
        out_dir / "asn_summary.csv",
        [
            {
                "isp": g[0], "asn": g[1], "asn_region": g[2], "is_pw_asn": g[3],
                "measurements": measurements[g],
                **{label: counts[(g, label)] for label in labels},
            }
            for g in groups
        ],
        ["isp", "asn", "asn_region", "is_pw_asn", "measurements"] + labels,
    )

    # ---- Coverage (RQ1) ----
    print("Computing coverage...")
    measured = {(r["domain"], r["isp"]) for r in domain_isp if r["n_usable"] > 0}
    measured_pw_asn = {
        (r["domain"], r["isp"]) for r in domain_asn if r["is_pw_asn"] and r["n_usable"] > 0
    }
    well_measured = {
        (r["domain"], r["isp"]) for r in domain_isp if r["n_usable"] >= args.min_measurements
    }

    blocked = []
    for isp in DNS_ISPS:
        for d in dns:
            if pw[(d["domain"], isp)]["pw_status"] == "blocked":
                k = (d["domain"], isp)
                blocked.append({
                    "isp": isp,
                    "pw_category": d["pw_category"],
                    "on_testlist": d["domain"] in testlist,
                    "ooni_measured": k in measured,
                    "ooni_measured_on_pw_asn": k in measured_pw_asn,
                    "ooni_well_measured": k in well_measured,
                })

    cov_cols = ["on_testlist", "ooni_measured", "ooni_measured_on_pw_asn", "ooni_well_measured"]

    def coverage(keys, path):
        groups = defaultdict(list)
        for r in blocked:
            groups[tuple(r[k] for k in keys)].append(r)
        out = []
        for g in sorted(groups):
            rows = groups[g]
            rec = dict(zip(keys, g))
            rec["pw_blocked"] = len(rows)
            for c in cov_cols:
                rec[c] = sum(r[c] for r in rows)
            for c in cov_cols:
                rec[f"{c}_pct"] = np_round(100 * rec[c] / rec["pw_blocked"], 2)
            out.append(rec)
        write_csv(path, out, keys + ["pw_blocked"] + cov_cols + [f"{c}_pct" for c in cov_cols])

    coverage(["isp"], out_dir / "coverage_by_isp.csv")
    coverage(["isp", "pw_category"], out_dir / "coverage_by_isp_category.csv")

    # ---- Disagreement summaries (RQ2) ----
    usable = [r for r in domain_isp if r["n_usable"] > 0]
    agreement = lambda r: r["agreement"]

    rl, cl, counts = write_crosstab(
        out_dir / "agreement_by_isp.csv", usable,
        [("agreement", agreement)], lambda r: r["isp"], margins=True,
    )
    write_crosstab(
        out_dir / "agreement_by_blocking_type.csv", usable,
        [("isp", lambda r: r["isp"]), ("agreement", agreement)],
        lambda r: r["dominant_blocking_type"] or "none",
    )
    write_crosstab(
        out_dir / "agreement_by_pw_category.csv", usable,
        [("pw_category", lambda r: r["pw_category"] if r["pw_category"] is not None else "not_in_blocklist")],
        agreement,
    )
    write_crosstab(
        out_dir / "agreement_by_testlist_category.csv", usable,
        [("testlist_category", lambda r: r["testlist_category"] if r["testlist_category"] is not None else "not_on_testlist")],
        agreement,
    )

    print("\nAgreement (domain x ISP with usable OONI data):")
    width = max(len(r) for r in rl)
    print(" " * width + "".join(f"{c:>9}" for c in cl))
    for r in rl:
        print(f"{r:<{width}}" + "".join(f"{counts[(r, c)]:>9}" for c in cl))
    print(f"\nOutput directory: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
