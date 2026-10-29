#!/usr/bin/env python3

"""
Redo the OONI vs Poisoned Wells comparison separately for measurements
made through the probe's own ISP resolver and through public / other
resolvers.

The resolver is only in raw measurements, fetched for the non-DNS
anomalies and for one measurement of every report
(fetch_ooni_raw.py --report-meta). Every measurement in one OONI
report (one probe run) uses the same resolver, so a resolver seen in any
raw measurement of a report is assigned to the whole report. Reports
with no raw-fetched measurement stay "unknown" and are left out.

Outputs:
  csv/resolver_split_2025.csv   per domain x ISP x resolver class
  csv/resolver_split_act_asn_2025.csv   ACT per ASN, ISP resolver only
  resolver_split_2025.txt       findings-style summary
"""

import argparse
from collections import Counter, defaultdict
from pathlib import Path

from common import (
    AGG_FIELDS,
    AGREEMENT_LABELS,
    ISP_ASNS,
    ISP_NAMES,
    VERDICT_FIELDS,
    add_agreement,
    add_verdicts,
    aggregate,
    apply_window,
    crosstab,
    load_ooni,
    pw_lookup,
    read_csv,
    write_csv,
)
from paths import (
    OONI_2025,
    RAW_DETAILS_2025,
    REPORT_META_2025,
    RESOLVER_ACT_ASN_CSV,
    RESOLVER_SPLIT_CSV,
    RESOLVER_SPLIT_TXT,
)

CLASSES = ["isp", "public", "other_study_isp", "internal"]

# A resolver IP with no ASN (AS0) is a bogon: NAT64 (64:ff9b::/96),
# private or loopback, e.g. a home router or the ISP's own resolver seen
# through NAT64. Counted as internal, not public.
INTERNAL_ASN = "AS0"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ooni", default=str(OONI_2025))
    parser.add_argument(
        "--raw",
        nargs="+",
        default=[str(RAW_DETAILS_2025), str(REPORT_META_2025)],
        help="Raw-detail CSVs to take resolvers from (missing files are skipped).",
    )
    parser.add_argument("--csv", default=str(RESOLVER_SPLIT_CSV))
    parser.add_argument("--act-asn-csv", default=str(RESOLVER_ACT_ASN_CSV))
    parser.add_argument("--txt", default=str(RESOLVER_SPLIT_TXT))
    parser.add_argument("--margin-days", type=int, default=7)
    parser.add_argument(
        "--window",
        choices=["pw", "all"],
        default="pw",
        help="'pw': each ISP's Poisoned Wells window; 'all': every measurement in --ooni.",
    )
    parser.add_argument(
        "--label",
        default="2025, PW windows",
        help="Which data this is, for the summary title.",
    )
    parser.add_argument("--ok-max", type=float, default=0.1)
    parser.add_argument("--blocked-min", type=float, default=0.9)
    parser.add_argument("--min-measurements", type=int, default=3)
    return parser.parse_args()


def load_resolver_raw(paths=(RAW_DETAILS_2025, REPORT_META_2025)):
    """
    Raw rows with a resolver from every available fetch: the non-DNS
    anomalies and the per-report metadata (first row per measurement).
    """

    rows, seen = [], set()
    for p in paths:
        if not Path(p).exists():
            continue
        for r in read_csv(p):
            if r["measurement_uid"] in seen:
                continue
            seen.add(r["measurement_uid"])
            rows.append({
                "measurement_uid": r["measurement_uid"],
                "resolver_asn": r["resolver_asn"] or None,
                "resolver_network_name": r["resolver_network_name"] or None,
            })
    return rows


ASN_KEY_TO_ISP = {f"AS{a}": isp for isp, asns in ISP_ASNS.items() for a in asns}


def label_resolvers(ooni, raw):
    """
    Give every measurement its report's resolver_asn, resolver_name and
    resolver_class (isp / public / other_study_isp / internal / unknown). Returns
    (rows, reports using more than one resolver, reports with raw data).
    """

    report_of = {r["measurement_uid"]: r["report_id"] for r in ooni}

    # A few raw measurements have no resolver recorded; their reports stay
    # unknown unless another measurement in the report has one.
    per_report = defaultdict(Counter)
    names = {}
    for r in raw:
        if r["resolver_asn"] is None or r["measurement_uid"] not in report_of:
            continue
        per_report[report_of[r["measurement_uid"]]][r["resolver_asn"]] += 1
        if r["resolver_network_name"] is not None:
            names.setdefault(r["resolver_asn"], r["resolver_network_name"])

    conflicts = sum(1 for c in per_report.values() if len(c) > 1)
    # Most common resolver in the report, smallest ASN on ties.
    resolver = {
        rep: min(asn for asn, n in c.items() if n == max(c.values()))
        for rep, c in per_report.items()
    }

    out = []
    for r in ooni:
        asn = resolver.get(r["report_id"])
        cls = "unknown"
        if asn is not None:
            owner = ASN_KEY_TO_ISP.get(asn)
            if asn == INTERNAL_ASN:
                cls = "internal"
            else:
                cls = "isp" if owner == r["isp"] else "other_study_isp" if owner else "public"
        out.append({**r, "resolver_asn": asn, "resolver_name": names.get(asn), "resolver_class": cls})
    return out, conflicts, len(per_report)


def compare(ooni, pw, cfg):
    """
    Domain x ISP rows (sorted) with verdicts and agreement, usable only.
    """

    rows = []
    for key in sorted(agg := aggregate(ooni, ["domain", "isp"])):
        r = agg[key]
        meta = pw.get(key)
        r["pw_value"] = meta["pw_value"] if meta else None
        r["pw_status"] = meta["pw_status"] if meta else "not_in_blocklist"
        add_agreement(add_verdicts(r, **cfg))
        if r["n_usable"] > 0:
            rows.append(r)
    return rows


def by_isp(counts):
    """
    '50 ACT, 28 Jio' from {isp: n}, largest first, ties alphabetical.
    """

    items = sorted((k, v) for k, v in counts.items() if v > 0)
    return ", ".join(
        f"{v} {ISP_NAMES.get(k, k)}" for k, v in sorted(items, key=lambda x: -x[1])
    )


def share(rows, pred):
    return sum(1 for r in rows if pred(r)) / len(rows) if rows else None


def main():
    args = parse_args()
    cfg = dict(
        ok_max=args.ok_max,
        blocked_min=args.blocked_min,
        min_measurements=args.min_measurements,
    )

    ooni = load_ooni(args.ooni)
    if args.window == "pw":
        ooni = apply_window(ooni, args.margin_days)
    raw = load_resolver_raw(args.raw)
    ooni, conflicts, reports_with_raw = label_resolvers(ooni, raw)

    pw = pw_lookup()

    results = {"all": compare(ooni, pw, cfg)}
    for cls in CLASSES:
        results[cls] = compare([r for r in ooni if r["resolver_class"] == cls], pw, cfg)

    combined = [
        {**r, "resolver_class": cls} for cls, rows in results.items() for r in rows
    ]
    write_csv(
        args.csv,
        combined,
        ["domain", "isp"] + AGG_FIELDS + ["pw_value", "pw_status"] + VERDICT_FIELDS
        + ["agreement", "resolver_class"],
    )

    # ---- Summary ----
    classes = Counter(r["resolver_class"] for r in ooni)
    by_isp_rows = defaultdict(list)
    for r in ooni:
        by_isp_rows[r["isp"]].append(r)

    out = [
        f"OONI vs Poisoned Wells split by the resolver the OONI probe used ({args.label})",
        "Generated by scripts/resolver_split.py",
        "",
        "Resolver inferred per OONI report (one probe run) from the raw-fetched measurements in it; "
        f"{reports_with_raw} reports had raw data, {conflicts} of them used more than one resolver",
        f"{len(ooni):,} measurements ({args.label}): "
        + ", ".join(f"{classes.get(c, 0):,} {c}" for c in CLASSES + ["unknown"])
        + " (internal = resolver IP has no ASN (AS0): NAT64, private or loopback address; "
        "unknown = report had no raw-fetched measurement, excluded below)",
        "Share by ISP (isp / public / other study ISP / internal / unknown): " + "; ".join(
            f"{ISP_NAMES[i]} " + " / ".join(
                f"{100 * share(rows, lambda r, c=c: r['resolver_class'] == c):.0f}%"
                for c in CLASSES + ["unknown"]
            )
            for i, rows in sorted(by_isp_rows.items())
        ),
        "",
    ]

    pub = [r for r in ooni if r["resolver_class"] == "public"]
    # Resolvers without a network name are left out of this list.
    top_pub = Counter(
        (r["resolver_asn"], r["resolver_name"]) for r in pub if r["resolver_name"] is not None
    )
    top_pub = sorted(sorted(top_pub.items()), key=lambda x: -x[1])[:6]
    out.append(
        "Most used public resolvers: "
        + ", ".join(f"{name} ({asn}) {v:,}" for (asn, name), v in top_pub)
    )

    # DNS anomalies by resolver class: public resolvers shouldn't see
    # ISP DNS blocking unless the ISP intercepts DNS traffic.
    is_dns = lambda r: r["blocked"] and r["blocking_type"] == "dns"
    rates = []
    for isp, rows in sorted(by_isp_rows.items()):
        isp_rows = [r for r in rows if r["resolver_class"] == "isp"]
        pub_rows = [r for r in rows if r["resolver_class"] == "public"]
        if isp_rows and pub_rows:
            rates.append(
                f"{ISP_NAMES[isp]} {100 * share(isp_rows, is_dns):.1f}% vs {100 * share(pub_rows, is_dns):.1f}%"
            )
    out.append(
        "Share of measurements with a DNS anomaly (isp resolver vs public resolver): " + ", ".join(rates)
    )

    # A public resolver can't return the ISP's blockpage IP, so confirmed
    # (blockpage-fingerprinted) DNS anomalies through public resolvers
    # point to on-path DNS injection/interception by the ISP.
    pub_dns = defaultdict(list)
    for r in pub:
        if is_dns(r):
            pub_dns[r["isp"]].append(r)
    conf = sorted(sorted(pub_dns.items()), key=lambda x: -len(x[1]))
    out.append(
        "DNS anomalies through a public resolver that return the ISP's blockpage (confirmed): "
        + ", ".join(
            f"{ISP_NAMES[i]} {100 * share(rows, lambda r: r['outcome'] == 'confirmed'):.0f}% of {len(rows):,}"
            for i, rows in conf
        )
    )
    out.append(
        "A public resolver can't answer with the ISP's blockpage, so this points to on-path injection or "
        "interception of plain DNS by the ISP; it is intermittent, so public-resolver probes see DNS "
        "blocking only some of the time"
    )
    out.append("")

    out.append("Agreement per resolver class (domain+ISP combos with usable OONI data):")
    for cls in ["all", "isp", "public"]:
        rows = results[cls]
        counts = Counter(r["agreement"] for r in rows)
        mixed = sum(1 for r in rows if r["ooni_verdict"] == "mixed")
        out.append(
            f"  {cls:<7} {len(rows):>4} combos: "
            + ", ".join(f"{label} {counts.get(label, 0)}" for label in AGREEMENT_LABELS)
            + f" | mixed total {mixed} ({100 * mixed / len(rows):.0f}%)"
        )
    out.append("")

    # Per ISP, PW-blocked combos only: agree vs mixed by resolver class.
    out.append("Domains dnsblocks marks as blocked, OONI agree-blocked / mixed / ok, by resolver class:")
    for isp in ["ACT", "AIRTEL", "JIO", "CONNECT"]:
        parts = []
        for cls in ["all", "isp", "public"]:
            v = Counter(
                r["ooni_verdict"] for r in results[cls]
                if r["isp"] == isp and r["pw_status"] == "blocked"
            )
            parts.append(f"{cls} {v.get('blocked', 0)} / {v.get('mixed', 0)} / {v.get('ok', 0)}")
        out.append(f"  {ISP_NAMES[isp]:<8} " + " | ".join(parts))
    out.append("")

    # What happens to the combos that were mixed using all measurements?
    isp_v = {(r["domain"], r["isp"]): r["ooni_verdict"] for r in results["isp"]}
    pub_v = {(r["domain"], r["isp"]): r["ooni_verdict"] for r in results["public"]}
    mixed_all = [r for r in results["all"] if r["ooni_verdict"] == "mixed"]

    for pw_status, title in [
        ("blocked", "dnsblocks blocked, OONI mixed"),
        ("not_blocked", "dnsblocks not blocked, OONI mixed"),
    ]:
        part = [r for r in mixed_all if r["pw_status"] == pw_status]
        iv = Counter(isp_v.get((r["domain"], r["isp"]), "no isp-resolver data") for r in part)
        pv = Counter(pub_v.get((r["domain"], r["isp"]), "no public-resolver data") for r in part)
        out.append(
            f"{len(part)} combos {title} (all measurements): with ISP resolver only -> "
            + ", ".join(f"{k} {v}" for k, v in iv.most_common())
            + "; with public resolver only -> "
            + ", ".join(f"{k} {v}" for k, v in pv.most_common())
        )
        out.append("  by ISP: " + by_isp(Counter(r["isp"] for r in part)))
    out.append("")

    # ACT per ASN, ISP resolver only.
    act = [r for r in ooni if r["isp"] == "ACT" and r["resolver_class"] == "isp"]
    act_asn = []
    for r in aggregate(act, ["domain", "isp", "asn"]).values():
        meta = pw.get((r["domain"], r["isp"]))
        r["pw_status"] = meta["pw_status"] if meta else "not_in_blocklist"
        add_agreement(add_verdicts(r, **cfg))
        if r["n_usable"] > 0 and r["pw_status"] == "blocked":
            act_asn.append(r)
    asns, verdicts, counts = crosstab(act_asn, lambda r: r["asn"], lambda r: r["ooni_verdict"])
    meas = Counter(r["asn"] for r in act)
    write_csv(
        args.act_asn_csv,
        [{"asn": a, **{v: counts[(a, v)] for v in verdicts}, "measurements": meas[a]} for a in asns],
        ["asn"] + verdicts + ["measurements"],
    )
    out.append(
        "ACT per ASN, ISP resolver only, domains dnsblocks marks as blocked (blocked / mixed / ok, measurements): "
        + ", ".join(
            f"AS{a} {counts[(a, 'blocked')]} / {counts[(a, 'mixed')]} / {counts[(a, 'ok')]} ({meas[a]:,})"
            for a in asns
        )
    )
    out += [
        "",
        "Caveats: measurements in reports with no raw-fetched measurement have an unknown resolver "
        "and are excluded; verdict thresholds as in compare_ooni_dnsblocks.py",
        "",
    ]

    with open(args.txt, "w") as f:
        f.write("\n".join(out))
    print("\n".join(out))


if __name__ == "__main__":
    main()
