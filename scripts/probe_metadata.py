#!/usr/bin/env python3

"""
Who produced the OONI measurements: runs (reports), approximate probes,
software and test versions, platforms, and whether a few probes dominate.
Then redo the OONI vs Poisoned Wells agreement with every probe weighted
equally, and split by web_connectivity version.

OONI publishes no probe identifier (deliberately, for volunteer privacy),
so probes are approximated by a fingerprint of report metadata:
  loose:  ASN + software name/version + platform + architecture + network type
  strict: loose + resolver IP
Loose can merge different devices with identical setups (undercount);
strict can split one device whose resolver IP changed (overcount). The two
bracket the real number.

Report metadata comes from fetch_ooni_raw.py --report-meta (one raw
measurement per report; these fields are constant within a report).

Outputs:
  csv/probe_summary_2025.csv    per ISP x ASN
  csv/probe_weighted_2025.csv   per domain x ISP verdicts, unweighted vs per-probe
  probe_metadata_2025.txt       findings-style summary
"""

import argparse
import math
import re
import statistics
from collections import Counter, defaultdict

from common import (
    AGREEMENT_LABELS as LABELS,
    ISP_NAMES,
    PW_ASN,
    agreement_label,
    apply_window,
    load_ooni,
    np_round,
    pw_lookup,
    read_csv,
    write_csv,
)
from paths import CSV_DIR, OONI_2025, PROBE_METADATA_TXT, REPORT_META_2025
from resolver_split import label_resolvers

LOOSE = ["probe_asn", "software_name", "software_version", "platform", "architecture", "network_type"]
STRICT = LOOSE + ["resolver_ip"]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ooni", default=str(OONI_2025))
    parser.add_argument("--meta", default=str(REPORT_META_2025))
    parser.add_argument("--summary-csv", default=str(CSV_DIR / "probe_summary_2025.csv"))
    parser.add_argument("--weighted-csv", default=str(CSV_DIR / "probe_weighted_2025.csv"))
    parser.add_argument("--txt", default=str(PROBE_METADATA_TXT))
    parser.add_argument("--margin-days", type=int, default=7)
    parser.add_argument("--window", choices=["pw", "all"], default="pw")
    parser.add_argument("--label", default="2025, PW windows")
    parser.add_argument("--ok-max", type=float, default=0.1)
    parser.add_argument("--blocked-min", type=float, default=0.9)
    return parser.parse_args()


def fingerprint(row, cols):
    return "|".join(row[c] or "" for c in cols)


def verdict(share, cfg):
    if share >= cfg["blocked_min"]:
        return "blocked"
    if share <= cfg["ok_max"]:
        return "ok"
    return "mixed"


def mean(values):
    return math.fsum(values) / len(values)


def agreement_counts(ooni, pw, cfg, group=None):
    """
    Verdict per domain x ISP (sorted) from the share of usable measurements
    that are blocked. With `group`, each group (probe) gets equal weight:
    the share is the mean of the per-group shares.
    """

    by = defaultdict(lambda: defaultdict(list))
    for r in ooni:
        if r["outcome"] == "failure":
            continue
        by[(r["domain"], r["isp"])][r[group] if group else None].append(r["blocked"])

    out = []
    for key in sorted(by):
        shares = [mean(v) for _, v in sorted(by[key].items())]
        share = mean(shares) if group else shares[0]
        meta = pw.get(key)
        pw_status = meta["pw_status"] if meta else "not_in_blocklist"
        v = verdict(share, cfg)
        out.append({
            "domain": key[0],
            "isp": key[1],
            "block_share": share,
            "ooni_verdict": v,
            "pw_status": pw_status,
            "agreement": agreement_label(pw_status, v),
        })
    return out


def share_table(rows, col, by="isp"):
    """
    '  Jio: desktop-unattended 60%, ...' share of measurements per value.
    """

    groups = defaultdict(Counter)
    for r in rows:
        groups[r[by]][r[col] or "unknown"] += 1
    values = sorted({v for c in groups.values() for v in c})
    lines = []
    for isp in sorted(groups):
        c, total = groups[isp], sum(groups[isp].values())
        top = sorted(((v, c[v] / total) for v in values), key=lambda x: -x[1])
        lines.append(
            f"  {ISP_NAMES.get(isp, isp)}: "
            + ", ".join(f"{k} {100 * v:.0f}%" for k, v in top if v >= 0.01)
        )
    return lines


def agreement_line(name, rows, width):
    c = Counter(r["agreement"] for r in rows)
    mixed = sum(1 for r in rows if r["ooni_verdict"] == "mixed")
    return (
        f"  {name:<{width}} {len(rows):>4} combos: "
        + ", ".join(f"{label} {c.get(label, 0)}" for label in LABELS)
        + f" | mixed {mixed} ({100 * mixed / len(rows):.0f}%)"
    )


def main():
    args = parse_args()
    cfg = dict(ok_max=args.ok_max, blocked_min=args.blocked_min)

    ooni = load_ooni(args.ooni)
    if args.window == "pw":
        ooni = apply_window(ooni, args.margin_days)
    meta = read_csv(args.meta)

    # Resolver class (isp / public / other) from the same metadata.
    ooni, _, _ = label_resolvers(
        ooni,
        [
            {
                "measurement_uid": r["measurement_uid"],
                "resolver_asn": r["resolver_asn"] or None,
                "resolver_network_name": r["resolver_network_name"] or None,
            }
            for r in meta
        ],
    )

    meta_cols = [
        "software_name", "software_version", "engine_version",
        "test_version", "platform", "architecture", "network_type", "resolver_ip",
    ]
    by_report = {}
    for r in meta:
        by_report.setdefault(r["report_id"], r)
    for r in ooni:
        m = by_report.get(r["report_id"], {})
        for c in meta_cols:
            r[c] = m.get(c) or None
        r["has_meta"] = r["software_name"] is not None
        r["probe_loose"] = fingerprint(r, LOOSE)
        r["probe_strict"] = fingerprint(r, STRICT)
        major = re.match(r"^(\d+\.\d+)", r["test_version"] or "")
        r["test_major"] = major.group(1) if major else None

    pw = pw_lookup()
    with_meta = [r for r in ooni if r["has_meta"]]

    # ---- Per ISP x ASN summary ----
    rows = []
    groups = defaultdict(list)
    for r in ooni:
        groups[(r["isp"], r["asn"])].append(r)
    for (isp, asn), g in sorted(groups.items()):
        m = [r for r in g if r["has_meta"]]
        per_probe = sorted(Counter(r["probe_strict"] for r in m).values(), reverse=True)
        per_report = Counter(r["report_id"] for r in g).values()
        rows.append({
            "isp": isp,
            "asn": asn,
            "is_pw_asn": asn == PW_ASN[isp],
            "measurements": len(g),
            "reports": len(per_report),
            "probes_loose": len({r["probe_loose"] for r in m}),
            "probes_strict": len({r["probe_strict"] for r in m}),
            "median_measurements_per_report": float(statistics.median(per_report)),
            "top_report_share": np_round(max(per_report) / len(g), 4),
            "top_probe_share": np_round(per_probe[0] / len(m), 4) if m else None,
            "top3_probe_share": np_round(sum(per_probe[:3]) / len(m), 4) if m else None,
            "with_metadata": np_round(len(m) / len(g), 4),
        })
    # Stable sort keeps ASN order among ties.
    summary = sorted(rows, key=lambda r: (r["isp"], -r["measurements"]))
    write_csv(args.summary_csv, summary, list(rows[0]))

    # ---- Agreement: unweighted vs per probe ----
    isp_only = [r for r in ooni if r["resolver_class"] == "isp"]
    variants = {
        "unweighted": agreement_counts(ooni, pw, cfg),
        "per probe (strict)": agreement_counts(with_meta, pw, cfg, "probe_strict"),
        "per probe (loose)": agreement_counts(with_meta, pw, cfg, "probe_loose"),
        "ISP resolver, unweighted": agreement_counts(isp_only, pw, cfg),
        "ISP resolver, per probe (strict)": agreement_counts(
            [r for r in isp_only if r["has_meta"]], pw, cfg, "probe_strict"
        ),
    }

    probes = defaultdict(set)
    for r in with_meta:
        probes[(r["domain"], r["isp"])].add(r["probe_strict"])
    weighted = []
    extra = []
    for name in ["per probe (strict)", "ISP resolver, per probe (strict)"]:
        tag = name.replace(" ", "_").replace(",", "").replace("(", "").replace(")", "")
        extra.append((tag, {(r["domain"], r["isp"]): r for r in variants[name]}))
    for r in variants["unweighted"]:
        key = (r["domain"], r["isp"])
        rec = {k: r[k] for k in ["domain", "isp", "pw_status", "block_share", "ooni_verdict", "agreement"]}
        for tag, lookup in extra:
            v = lookup.get(key, {})
            for col in ["block_share", "ooni_verdict", "agreement"]:
                rec[f"{col}_{tag}"] = v.get(col)
        rec["n_probes_strict"] = len(probes[key]) if key in probes else None
        weighted.append(rec)
    write_csv(args.weighted_csv, weighted, list(weighted[0]))

    # ---- Summary text ----
    reports_all = {r["report_id"] for r in ooni}
    reports_meta = {r["report_id"] for r in with_meta}
    out = [
        f"OONI probes, software and test versions behind the measurements ({args.label})",
        "Generated by scripts/probe_metadata.py",
        "",
        "OONI publishes no probe ID; probes approximated by report metadata fingerprints, "
        "loose = ASN+software+version+platform+architecture+network type, strict = loose+resolver IP "
        "(the real number lies roughly between the two)",
        f"Metadata known for {100 * len(with_meta) / len(ooni):.1f}% of {len(ooni):,} measurements "
        f"({len(reports_meta):,} of {len(reports_all):,} reports)",
        "",
        "Per ASN: measurements | reports (runs) | probes loose-strict | top probe share | top 3 probes share | top report share",
    ]
    for r in summary:
        out.append(
            f"  {ISP_NAMES[r['isp']]:<8} AS{r['asn']:<7}{' (PW ASN)' if r['is_pw_asn'] else '         '} "
            f"{r['measurements']:>6,} | {r['reports']:>5,} | {r['probes_loose']:>3}-{r['probes_strict']:<4} | "
            f"{100 * (r['top_probe_share'] or 0):>3.0f}% | {100 * (r['top3_probe_share'] or 0):>3.0f}% | "
            f"{100 * r['top_report_share']:.1f}%"
        )

    per_isp = defaultdict(lambda: {"measurements": 0, "reports": set(), "loose": set(), "strict": set()})
    for r in ooni:
        p = per_isp[r["isp"]]
        p["measurements"] += 1
        p["reports"].add(r["report_id"])
        if r["has_meta"]:
            p["loose"].add(r["probe_loose"])
            p["strict"].add(r["probe_strict"])
    per_isp_sorted = sorted(sorted(per_isp.items()), key=lambda x: -x[1]["measurements"])

    versions_count = Counter(r["software_version"] for r in with_meta if r["software_version"])
    total_versions = sum(versions_count.values())
    out += [
        "",
        "Per ISP: " + "; ".join(
            f"{ISP_NAMES[i]} {p['measurements']:,} measurements, {len(p['reports']):,} reports, "
            f"{len(p['loose'])}-{len(p['strict'])} probes"
            for i, p in per_isp_sorted
        ),
        "",
        "Software (share of measurements):",
        *share_table(with_meta, "software_name"),
        "web_connectivity test version:",
        *share_table(with_meta, "test_version"),
        "Platform:",
        *share_table(with_meta, "platform"),
        "Network type (mobile app only reports it):",
        *share_table(with_meta, "network_type"),
        "Most common software versions overall: " + ", ".join(
            f"{k} {100 * v / total_versions:.0f}%" for k, v in versions_count.most_common(6)
        ),
        "",
        "Agreement with every probe weighted equally (domain+ISP combos):",
    ]
    for name, v in variants.items():
        out.append(agreement_line(name, v, 33))

    base = {(r["domain"], r["isp"]): r["ooni_verdict"] for r in variants["unweighted"]}
    strict = {(r["domain"], r["isp"]): r["ooni_verdict"] for r in variants["per probe (strict)"]}
    both = [(base[k], strict[k]) for k in base if k in strict]
    changed = Counter(p for p in both if p[0] != p[1])
    out.append(
        f"Per-probe weighting changes the OONI verdict for {sum(changed.values())} of {len(both)} combos: "
        + ", ".join(
            # Ties in order of first appearance, as pandas value_counts.
            f"{a} -> {b} {n}" for (a, b), n in changed.most_common()
        )
    )

    versions = Counter(
        (r["test_version"], r["software_name"], r["software_version"])
        for r in with_meta
        if r["test_version"] and r["software_name"] and r["software_version"]
    )
    old = [(k, n) for k, n in sorted(versions.items()) if k[0].startswith("0.0")]
    test_versions = Counter(r["test_version"] for r in with_meta if r["test_version"])
    out += [
        "",
        "web_connectivity versions: " + ", ".join(
            f"{v} {n:,}" for v, n in test_versions.most_common()
        ) + " measurements"
        + (
            f"; no 0.5 measurements ({args.label}), so 0.4 vs 0.5 can't be compared"
            if not any(r["test_major"] == "0.5" for r in with_meta) else ""
        ),
    ]
    if old:
        out.append(
            "0.0.x comes from legacy apps: " + ", ".join(
                f"{sw} {swv} ({n})" for (_, sw, swv), n in old
            )
        )
    out += ["Agreement by web_connectivity version (all resolvers, unweighted):"]
    by_major = defaultdict(list)
    for r in with_meta:
        if r["test_major"]:
            by_major[r["test_major"]].append(r)
    for ver, g in sorted(by_major.items()):
        v = agreement_counts(g, pw, cfg)
        c = Counter(r["agreement"] for r in v)
        mixed = sum(1 for r in v if r["ooni_verdict"] == "mixed")
        out.append(
            f"  {ver}.x: {len(g):,} measurements, {len(v)} combos: "
            + ", ".join(f"{label} {c.get(label, 0)}" for label in LABELS)
            + f" | mixed {mixed} ({100 * mixed / len(v):.0f}%)"
        )
    out += [
        "Versions differ in which probes run them (desktop vs mobile, ISP), so this is not a "
        "controlled comparison of the two test implementations",
        "",
    ]

    with open(args.txt, "w") as f:
        f.write("\n".join(out))
    print("\n".join(out))


if __name__ == "__main__":
    main()
