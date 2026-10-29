#!/usr/bin/env python3

"""
What changed between the 2025 OONI data (each ISP's Poisoned Wells window)
and this week's 2026 OONI data, for the same domains and ISPs.

Probes on public resolvers make DNS blocking look weaker, and the resolver
mix differs between the two periods, so the main comparison uses only
measurements made through the ISP's own resolver in both years
(resolver_split.py). The all-resolver comparison is shown for reference.

Outputs:
  csv/drift_2025_2026.csv   per domain x ISP, both years
  drift_2025_2026.txt       findings-style summary
"""

import argparse
from collections import Counter, defaultdict
from datetime import date

from common import (
    AGREEMENT_LABELS as LABELS,
    BLOCKING_TYPES,
    ISP_NAMES,
    PW_ASN,
    PW_WINDOW,
    apply_window,
    load_ooni,
    read_csv,
    write_csv,
)
from paths import (
    CSV_DIR,
    DRIFT_TXT,
    OONI_2025,
    OONI_2026,
    RAW_DETAILS_2025,
    RAW_DETAILS_2026,
    REPORT_META_2026,
    RESOLVER_SPLIT_CSV,
    RESOLVER_SPLIT_CSV_2026,
    RESULTS_2025,
    RESULTS_2026,
)
from resolver_split import label_resolvers, load_resolver_raw

ORDER = ["JIO", "AIRTEL", "ACT", "CONNECT", "MTNL", "YOU"]

MIN_USABLE = 3


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default=str(CSV_DIR / "drift_2025_2026.csv"))
    parser.add_argument("--txt", default=str(DRIFT_TXT))
    parser.add_argument("--margin-days", type=int, default=7)
    parser.add_argument("--examples", type=int, default=12)
    return parser.parse_args()


def span_days(rows):
    times = [r["time"] for r in rows]
    return max((max(times) - min(times)).total_seconds() / 86400, 1)


def agreement_line(name, d):
    c = Counter(r["agreement"] for r in d)
    mixed = sum(1 for r in d if r["ooni_verdict"] == "mixed")
    return (
        f"  {name:<22} {len(d):>4} combos: "
        + ", ".join(f"{label} {c.get(label, 0)}" for label in LABELS)
        + f" | mixed {mixed} ({100 * mixed / max(len(d), 1):.0f}%)"
    )


def type_shares(rows):
    """
    ({isp: {blocking type: share of blocked measurements}}, {isp: n blocked})
    """

    counts = defaultdict(Counter)
    for r in rows:
        if r["blocked"]:
            counts[r["isp"]][r["blocking_type"] or "none"] += 1
    shares = {
        isp: {t: n / sum(c.values()) for t, n in c.items()} for isp, c in counts.items()
    }
    return shares, {isp: sum(c.values()) for isp, c in counts.items()}


def tls_share(path):
    """
    {isp: (share of http-failure that is TLS interference, n http-failure)}
    """

    c = defaultdict(lambda: [0, 0])
    for r in read_csv(path):
        if r["blocking_type"] == "http-failure":
            c[r["isp"]][0] += r["tls_interference"].lower() == "true"
            c[r["isp"]][1] += 1
    return {isp: (tls / n, n) for isp, (tls, n) in c.items()}


def per_isp(rows):
    """
    '6 Airtel, 5 Jio' rows per ISP, largest first, ties alphabetical.
    """

    counts = sorted(Counter(r["isp"] for r in rows).items())
    return ", ".join(f"{n} {ISP_NAMES[i]}" for i, n in sorted(counts, key=lambda x: -x[1]))


def num(value):
    return float(value) if value not in (None, "") else None


def main():
    args = parse_args()

    o25 = apply_window(load_ooni(OONI_2025), args.margin_days)
    o26 = load_ooni(OONI_2026)
    o25, _, _ = label_resolvers(o25, load_resolver_raw())
    o26, _, _ = label_resolvers(o26, load_resolver_raw([REPORT_META_2026]))

    def results(path, rs_path):
        d = [r for r in read_csv(path / "domain_isp.csv") if int(r["n_usable"]) > 0]
        rs = [r for r in read_csv(rs_path) if r["resolver_class"] == "isp"]
        return d, rs

    d25, i25 = results(RESULTS_2025, RESOLVER_SPLIT_CSV)
    d26, i26 = results(RESULTS_2026, RESOLVER_SPLIT_CSV_2026)

    def index(rows):
        return {(r["domain"], r["isp"]): r for r in rows}

    sources = [
        ("", 2025, index(d25)),
        ("", 2026, index(d26)),
        ("_isp", 2025, index(i25)),
        ("_isp", 2026, index(i26)),
    ]
    pw = {}
    for d in (d25, d26):
        for r in d:
            pw.setdefault((r["domain"], r["isp"]), r["pw_status"])
    reports26 = defaultdict(set)
    for r in o26:
        reports26[(r["domain"], r["isp"])].add(r["report_id"])

    fields = ["domain", "isp"]
    for tag, year, _ in sources:
        fields += [f"{c}{tag}_{year}" for c in ("ooni_verdict", "n_usable", "dominant_blocking_type")]
    fields += ["pw_status", "reports_2026"]

    # Outer join of both years' all-resolver rows, sorted like a pandas merge.
    both = []
    for key in sorted(set(sources[0][2]) | set(sources[1][2])):
        rec = {"domain": key[0], "isp": key[1]}
        for tag, year, rows in sources:
            r = rows.get(key)
            rec[f"ooni_verdict{tag}_{year}"] = r["ooni_verdict"] if r else None
            rec[f"n_usable{tag}_{year}"] = num(r["n_usable"]) if r else None
            rec[f"dominant_blocking_type{tag}_{year}"] = (r["dominant_blocking_type"] or None) if r else None
        rec["pw_status"] = pw.get(key)
        rec["reports_2026"] = len(reports26[key]) if key in reports26 else None
        both.append(rec)
    write_csv(args.csv, both, fields)

    t26 = [r["time"] for r in o26]
    out = [
        "OONI 2025 (PW windows) vs OONI 2026 (this week), same domains and ISPs",
        "Generated by scripts/drift.py",
        "",
        f"2025: {len(o25):,} measurements over each ISP's PW window (+/- {args.margin_days} days); "
        f"2026: {len(o26):,} measurements, {min(t26):%Y-%m-%d} -> {max(t26):%Y-%m-%d}",
        "Main comparison uses ISP-resolver measurements only in both years (public-resolver probes "
        "hide DNS blocking and the resolver mix differs between periods)",
        "",
    ]

    # ---- Volume ----
    out.append("Measurement volume per day (2025 PW window -> 2026 week), reports, measurements per report:")
    d26_days = span_days(o26)
    for isp in ORDER:
        a = [r for r in o25 if r["isp"] == isp]
        b = [r for r in o26 if r["isp"] == isp]
        if not a and not b:
            continue
        w = PW_WINDOW[isp]
        d_a = (date.fromisoformat(w[1]) - date.fromisoformat(w[0])).days + 1 + 2 * args.margin_days
        ra, rb = len({r["report_id"] for r in a}), len({r["report_id"] for r in b})
        out.append(
            f"  {ISP_NAMES[isp]:<8} {len(a) / d_a:>7.1f} -> {len(b) / d26_days:>7.1f} per day | reports "
            f"{ra:,} -> {rb:,} | per report {len(a) / max(ra, 1):.1f} -> {len(b) / max(rb, 1):.1f}"
        )
    out.append(
        "Measurements on PW's own ASN (2025 window -> 2026 week): " + ", ".join(
            f"{ISP_NAMES[i]} AS{PW_ASN[i]} {sum(r['asn'] == PW_ASN[i] for r in o25):,} -> "
            f"{sum(r['asn'] == PW_ASN[i] for r in o26):,}"
            for i in ORDER
        )
    )
    out.append("")

    # ---- Resolver mix ----
    out.append(
        "Resolver used by probes, share of measurements "
        "(isp / public / other study ISP / internal / unknown):"
    )
    classes = ["isp", "public", "other_study_isp", "internal", "unknown"]
    for isp in ORDER:
        parts = []
        for o in (o25, o26):
            x = Counter(r["resolver_class"] for r in o if r["isp"] == isp)
            total = sum(x.values())
            parts.append(" / ".join(f"{100 * x[c] / total:.0f}%" for c in classes) if total else "no data")
        out.append(f"  {ISP_NAMES[isp]:<8} 2025 {parts[0]}  ->  2026 {parts[1]}")
    out.append("")

    # ---- Agreement with PW ----
    out.append("Agreement with Poisoned Wells (domain+ISP combos with usable data):")
    out.append(agreement_line("2025, all resolvers", d25))
    out.append(agreement_line("2025, ISP resolver", i25))
    out.append(agreement_line("2026, all resolvers", d26))
    out.append(agreement_line("2026, ISP resolver", i26))
    out.append("")

    # ---- Verdict transitions ----
    def examples(rows):
        rows = sorted(rows, key=lambda r: -r["n_usable_isp_2026"])[: args.examples]
        return ", ".join(f"{ISP_NAMES[r['isp']]} {r['domain']}" for r in rows) or "none"

    for a, b, title in [
        ("ooni_verdict_isp_2025", "ooni_verdict_isp_2026", "ISP resolver 2025 -> ISP resolver 2026 (main)"),
        ("ooni_verdict_2025", "ooni_verdict_2026", "all resolvers 2025 -> all resolvers 2026 (reference)"),
    ]:
        paired = [r for r in both if r[a] is not None and r[b] is not None]
        tr = Counter((r[a], r[b]) for r in paired)
        tcols = [c for c in ["blocked", "mixed", "ok"] if any(k[1] == c for k in tr)]
        out.append(f"{len(paired)} combos with data in both years; {title}, rows 2025, columns 2026:")
        out.append("  " + " " * 9 + "".join(f"{c:>9}" for c in tcols))
        for r in ["blocked", "mixed", "ok"]:
            if any(k[0] == r for k in tr):
                out.append(f"  {r:<9}" + "".join(f"{tr[(r, c)]:>9}" for c in tcols))
        out.append("")

    paired = [
        r for r in both
        if r["ooni_verdict_isp_2025"] is not None and r["ooni_verdict_isp_2026"] is not None
    ]
    thin = lambda r: r["n_usable_isp_2026"] < MIN_USABLE
    out.append(
        f"Changes, ISP-resolver measurements in both years ({sum(map(thin, paired))} of {len(paired)} combos have "
        f"fewer than {MIN_USABLE} usable 2026 measurements, counted in brackets):"
    )
    for v25, v26, title in [
        ("ok", "blocked", "Newly blocked (ok -> blocked)"),
        ("mixed", "blocked", "Mixed -> blocked"),
        ("blocked", "blocked", "Still blocked"),
        ("blocked", "ok", "Unblocked (blocked -> ok)"),
        ("blocked", "mixed", "Blocked -> mixed"),
        ("ok", "mixed", "Ok -> mixed"),
        ("mixed", "ok", "Mixed -> ok"),
    ]:
        g = [
            r for r in paired
            if r["ooni_verdict_isp_2025"] == v25 and r["ooni_verdict_isp_2026"] == v26
        ]
        out.append(
            f"  {title}: {len(g)} [{sum(map(thin, g))} thin]"
            + (f" ({per_isp(g)})" if g else "")
        )
        if g and title != "Still blocked":
            out.append(f"    e.g. {examples(g)}")
        if g and title.startswith("Unblocked"):
            out.append(
                "    2026 ISP-resolver usable measurements / reports: " + ", ".join(
                    f"{ISP_NAMES[r['isp']]} {r['domain']} {int(r['n_usable_isp_2026'])}/{int(r['reports_2026'])}"
                    for r in sorted(g, key=lambda r: -r["n_usable_isp_2026"])
                )
            )
    newly = [
        r for r in paired
        if r["ooni_verdict_isp_2025"] == "ok" and r["ooni_verdict_isp_2026"] == "blocked"
    ]
    if newly:
        out.append(
            "  newly blocked domains by PW status (2025 scan): "
            + ", ".join(f"{k} {v}" for k, v in Counter(r["pw_status"] for r in newly).most_common())
        )
    out.append("")

    # ---- Blocking method ----
    out.append("Blocked measurements by blocking type, 2025 -> 2026 (share of blocked measurements):")
    for label, f25, f26 in [
        ("all resolvers", o25, o26),
        (
            "ISP resolver",
            [r for r in o25 if r["resolver_class"] == "isp"],
            [r for r in o26 if r["resolver_class"] == "isp"],
        ),
    ]:
        (t25, n25), (t26, n26) = type_shares(f25), type_shares(f26)
        out.append(f" {label}:")
        for isp in ORDER:
            if isp not in t25 and isp not in t26:
                continue
            parts = []
            for bt in BLOCKING_TYPES:
                a = t25.get(isp, {}).get(bt, 0)
                b = t26.get(isp, {}).get(bt, 0)
                parts.append(f"{bt} {100 * a:.0f}% -> {100 * b:.0f}%")
            out.append(
                f"  {ISP_NAMES[isp]:<8} " + ", ".join(parts)
                + f" (blocked measurements {n25.get(isp, 0):,} -> {n26.get(isp, 0):,})"
            )

    s25, s26 = tls_share(RAW_DETAILS_2025), tls_share(RAW_DETAILS_2026)
    out.append(
        "Share of http-failure that is TLS interference (2025 -> 2026): " + ", ".join(
            f"{ISP_NAMES[i]} {100 * s25[i][0]:.0f}% of {s25[i][1]:,} -> "
            + (f"{100 * s26[i][0]:.0f}% of {s26[i][1]:,}" if i in s26 else "none")
            for i in ORDER if i in s25
        )
    )
    out += [
        "",
        "Caveats: 2026 covers one week vs roughly 5 weeks per ISP in 2025, so 2026 verdicts rest on "
        "fewer measurements (see thin counts); different season and probe population; Connect, MTNL "
        "and You have very few measurements in either period",
        "",
    ]

    with open(args.txt, "w") as f:
        f.write("\n".join(out))
    print("\n".join(out))


if __name__ == "__main__":
    main()
