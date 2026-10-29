#!/usr/bin/env python3

"""
Regenerate findings_all.txt and findings_2025.txt from the data and
analysis outputs. Every number is computed here; the only hardcoded
values are facts taken from the Poisoned Wells report (report.pdf)
and the per-ASN regions in common.ASN_REGION.

Run after compare_ooni_dnsblocks.py, mixed_details.py,
find_ooni_blocked.py, resolver_split.py, probe_metadata.py and
drift.py (see run_all.sh).
"""

import csv
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from common import (
    ASN_REGION,
    ISP_ASNS,
    ISP_NAMES,
    PW_ASN,
    PW_WINDOW,
    apply_window,
    load_dnsblocks,
    load_ooni,
    load_testlist_rows,
    read_csv,
)
from paths import (
    BLOCKED_PREFIX_2025,
    DRIFT_TXT,
    FINDINGS_2025,
    FINDINGS_ALL,
    MIXED_CSV_2025,
    OONI_2025,
    OONI_2026,
    PROBE_METADATA_TXT,
    PROBE_METADATA_TXT_2026,
    RAW_DETAILS_2025,
    RESOLVER_ACT_ASN_CSV,
    RESOLVER_ACT_ASN_CSV_2026,
    RESOLVER_SPLIT_TXT,
    RESOLVER_SPLIT_TXT_2026,
    CATEGORY_TEST_TXT,
    CSV_DIR,
    REPORT_META_2026,
    ROBUSTNESS_TXT,
    RESULTS_2025,
    RESULTS_2026,
    ROOT,
)
from resolver_split import label_resolvers, load_resolver_raw

# From report.pdf (Poisoned Wells, Karan Saini, 2026).
PW_APEX_SCANNED = "294M"
PW_QUERIES = "1.76B"
# Report Table 4: blocked domains per ISP.
PW_TABLE4 = {"JIO": 15245, "AIRTEL": 27649, "ACT": 14173, "MTNL": 20085, "YOU": 14052, "CONNECT": 9414}

# From the original findings.txt (ISPs OONI covers that PW did not measure).
ISPS_NOT_IN_PW = (
    "Vodafone Idea, Tata Play, Hathway, Excitel, GTPL, Alliance, "
    "Kerala Vision, BSNL"
)

MARGIN_DAYS = 7

INT_FIELDS = re.compile(r"^(n_|asn$|pw_blocked$|on_testlist$|ooni_measured|ooni_well_measured|measurements$|blocked$|mixed$|ok$)")


# --------------------------------------------------
# Formatting and counting helpers
# --------------------------------------------------

def n(x):
    return f"{int(x):,}"


def pct(a, b, digits=2):
    return f"{100 * a / b:.{digits}f}%" if b else "n/a"


def by_isp(counts):
    """
    '50 ACT, 28 Jio' from {isp: count}, largest first, ties alphabetical.
    """

    items = sorted((k, v) for k, v in counts.items() if v > 0)
    return ", ".join(
        f"{n(v)} {ISP_NAMES.get(k, k)}" for k, v in sorted(items, key=lambda x: -x[1])
    )


def isp_count(rows, col=None):
    """
    {isp: rows} or, with `col`, {isp: distinct values of col}.
    """

    if col is None:
        return Counter(r["isp"] for r in rows)
    values = defaultdict(set)
    for r in rows:
        if r[col] is not None:
            values[r["isp"]].add(r[col])
    return {isp: len(v) for isp, v in values.items()}


def nunique(rows, col):
    return len({r[col] for r in rows if r[col] is not None})


def top(rows, key, k):
    """
    The k rows with the largest key; ties keep input order.
    """

    return sorted(rows, key=lambda r: -key(r))[:k]


def unique(values):
    return list(dict.fromkeys(values))


def typed(rows):
    """
    Parse numeric and boolean columns of CSV rows; empty cells -> None.
    """

    for r in rows:
        for k, v in r.items():
            if v == "":
                r[k] = None
            elif v in ("True", "False"):
                r[k] = v == "True"
            elif INT_FIELDS.match(k):
                r[k] = int(float(v))
    return rows


def rel(path):
    return Path(path).resolve().relative_to(ROOT)


# --------------------------------------------------
# Load everything once
# --------------------------------------------------

class Data:
    def __init__(self):
        print("Loading data...", file=sys.stderr)

        self.dns = load_dnsblocks()
        self.testlist = load_testlist_rows()

        self.ooni_2025_rows = len(read_csv(OONI_2025))
        self.ooni_2026_rows = len(read_csv(OONI_2026))

        self.ooni_2025 = load_ooni(OONI_2025)
        self.ooni_2025_win = apply_window(self.ooni_2025, MARGIN_DAYS)
        self.ooni_2026 = load_ooni(OONI_2026)

        self.di25 = typed(read_csv(RESULTS_2025 / "domain_isp.csv"))
        self.da25 = typed(read_csv(RESULTS_2025 / "domain_asn.csv"))
        self.cov25 = {r["isp"]: r for r in typed(read_csv(RESULTS_2025 / "coverage_by_isp.csv"))}
        self.covcat25 = {
            (r["isp"], r["pw_category"]): r
            for r in typed(read_csv(RESULTS_2025 / "coverage_by_isp_category.csv"))
        }
        self.di26 = typed(read_csv(RESULTS_2026 / "domain_isp.csv"))
        self.da26 = typed(read_csv(RESULTS_2026 / "domain_asn.csv"))

        self.u25 = [r for r in self.di25 if r["n_usable"] > 0]
        self.u26 = [r for r in self.di26 if r["n_usable"] > 0]

        self.raw = read_csv(RAW_DETAILS_2025)
        for r in self.raw:
            r["tls"] = r["tls_interference"].lower() == "true"
        self.resolved, _, _ = label_resolvers(self.ooni_2025_win, load_resolver_raw())

        self.mixed = typed(read_csv(MIXED_CSV_2025))

        self.blk_totals = read_csv(f"{BLOCKED_PREFIX_2025}_totals.csv")
        self.blk_meas = list({
            r["measurement_uid"]: r for r in reversed(read_csv(f"{BLOCKED_PREFIX_2025}_measurements.csv"))
        }.values())
        self.blk = typed(read_csv(f"{BLOCKED_PREFIX_2025}_domains.csv"))
        for r in self.blk:
            r["on_pw_asn"] = r["asn"] == PW_ASN[r["isp"]]

        # Per domain+ISP blocking method, using the TLS split.
        tls = Counter(
            (r["domain"], r["isp"]) for r in self.raw
            if r["blocking_type"] == "http-failure" and r["tls"]
        )
        # Only combos where OONI sees blocking (verdict blocked or mixed)
        # get a method; "dns only" means no TLS, TCP/IP, HTTP-diff or other
        # HTTP-failure blocking was seen at all.
        self.methods = []
        for r in self.u25:
            m = dict(r)
            m["n_tls"] = tls.get((r["domain"], r["isp"]), 0)
            other = m["n_tcp_ip"] + m["n_http_diff"] + (m["n_http_failure"] - m["n_tls"])
            if m["ooni_verdict"] == "ok":
                method = "no blocking"
            elif m["n_tls"] > 0:
                method = "dns + tls" if m["n_dns"] > 0 else "tls only"
            elif m["n_dns"] > 0 and other == 0:
                method = "dns only"
            else:
                method = "other"
            m["method"] = method
            self.methods.append(m)


# --------------------------------------------------
# Sections
# --------------------------------------------------

def header():
    return [
        "ALL FINDINGS SO FAR (OONI vs Poisoned Wells / dnsblocks.in, India)",
        "Generated by scripts/make_findings.py, do not edit by hand",
        "Replaces the earlier hand-written findings.txt (old method: Apr-Sep 2026 data only, pooled ASNs, "
        "any confirmed block = blocked)",
        "",
    ]


def datasets(d):
    dns = d.dns
    blocked = {i: sum(1 for r in dns if r[i] == "1") for i in ISP_ASNS}
    cats = Counter(r["pw_category"] for r in dns)
    tranco = sum(1 for r in dns if r["pw_tranco_rank"] != "-")

    common = {r["apex"] for r in d.testlist} & {r["domain"] for r in dns}
    cdns = [r for r in dns if r["domain"] in common]
    ccats = Counter(r["pw_category"] for r in cdns)

    windows = ", ".join(
        f"{ISP_NAMES[i]} AS{PW_ASN[i]} {PW_WINDOW[i][0]} -> {PW_WINDOW[i][1]}"
        for i in ["ACT", "JIO", "AIRTEL", "MTNL", "YOU", "CONNECT"]
    )

    top_cats = ", ".join(
        f"{c} {n(v)} ({pct(v, len(dns), 1)})" if k < 2 else f"{c} {n(v)}"
        for k, (c, v) in enumerate(cats.most_common(8))
    )
    common_cats = ", ".join(
        f"{c} {100 * ccats.get(c, 0) / len(cdns):.1f}%"
        for c in ["MISC", "PORN", "FILE", "MOV", "UNCAT"]
    )

    non_dns = [
        r for r in d.ooni_2025_win
        if r["blocked"] and r["blocking_type"] in ("http-failure", "tcp_ip", "http-diff")
    ]
    t26 = [r["time"] for r in d.ooni_2026]

    return [
        "== DATASETS ==",
        "",
        f"Poisoned Wells (PW): {PW_APEX_SCANNED} apex domains scanned over DNS on 6 ISPs, "
        f"{PW_QUERIES} queries, {n(len(dns))} domains blocked on at least one ISP",
        f"Only {n(tranco)} PW blocked domains ({pct(tranco, len(dns), 1)}) have a Tranco rank",
        "PW blocked per ISP: " + ", ".join(
            f"{ISP_NAMES[i]} {n(v)}"
            for i, v in sorted(blocked.items(), key=lambda x: -x[1])
        ),
        "Published PW CSV vs report Table 4 (blocked per ISP): " + ", ".join(
            f"{ISP_NAMES[i]} {n(blocked[i])} vs {n(PW_TABLE4[i])}" for i in ISP_ASNS
        ) + f"; same total ({n(len(dns))}), the CSV has slightly fewer per ISP",
        f"PW categories: {top_cats}",
        "PW measured one ASN per ISP, at one time per ISP (2025):",
        windows,
        "PW only queried A records via ISP resolvers, so it can only see DNS blocking",
        "",
        f"OONI test list (citizenlab global + IN): {n(len(d.testlist))} URLs",
        "",
        f"{len(common)} common domains (on OONI test list and in PW blocklist)",
        f"{sum(1 for r in cdns if r['pw_tranco_rank'] != '-')} of the {len(common)} common domains are "
        f"Tranco-ranked (vs {pct(tranco, len(dns), 1)} of all PW blocked)",
        f"Common domains by PW category: {common_cats} "
        f"(vs MOV {100 * cats['MOV'] / len(dns):.1f}%, UNCAT {100 * cats['UNCAT'] / len(dns):.1f}% in all of PW)",
        "",
        f"OONI 2025 fetch (web_connectivity, 2025-03-01 -> 2025-09-16): {n(d.ooni_2025_rows)} "
        f"measurements for the common domains, {n(len(d.ooni_2025))} on mapped ISP ASNs, "
        f"{n(len(d.ooni_2025_win))} inside the PW windows (+/- {MARGIN_DAYS} days)",
        f"OONI 2026 fetch (this week, web_connectivity, "
        f"{min(t26):%Y-%m-%d} -> {max(t26):%Y-%m-%d}): {n(d.ooni_2026_rows)} measurements, "
        f"{n(len(d.ooni_2026))} on mapped ISP ASNs; raw TLS details for its non-DNS anomalies and one raw "
        "measurement per report (resolver, software) fetched as for 2025",
        f"Raw measurements fetched for {n(len(d.raw))} of the {n(len(non_dns))} non-DNS anomalies "
        "in the 2025 PW windows (for TLS split and resolver info)",
        "",
        f"major isps ignored by data / DNS Blocks which was covered by OONI: {ISPS_NOT_IN_PW}",
        "",
        "",
    ]


def asns(d):
    per_asn = Counter(r["asn"] for r in d.ooni_2025_win)

    def cnt(asn):
        return n(per_asn.get(asn, 0))

    def isp_line(isp):
        parts = sorted(ISP_ASNS[isp], key=lambda a: -per_asn.get(a, 0))
        return f"{ISP_NAMES[isp]} " + ", ".join(f"AS{a} {cnt(a)}" for a in parts)

    act = ", ".join(
        f"AS{a} {ASN_REGION[a]}" + (" (PW measured this one)" if a == PW_ASN["ACT"] else "")
        for a in ISP_ASNS["ACT"]
    )
    airtel = ", ".join(
        f"AS{a} {ASN_REGION[a].removeprefix('national (').rstrip(')')}"
        + (" (PW measured this one)" if a == PW_ASN["AIRTEL"] else "")
        for a in ISP_ASNS["AIRTEL"]
    )

    return [
        "== ASNs ==",
        "",
        f"Jio AS55836: one national ASN ({ASN_REGION[55836].removeprefix('national (').rstrip(')')}), "
        "PW measured this one",
        f"Airtel ASNs split by service, not region: {airtel}",
        f"ACT ASNs split by region (ipinfo geolocation of sampled prefixes): {act}",
        f"MTNL AS17813 {ASN_REGION[17813]}, You AS18207 {ASN_REGION[18207]}, "
        f"Connect AS17917 {ASN_REGION[17917]}",
        "",
        "OONI measurements in the PW windows per ASN: " + " | ".join(
            isp_line(i) for i in ["JIO", "AIRTEL", "ACT", "CONNECT", "YOU", "MTNL"]
        ),
        "",
        f"Data gaps: MTNL has {cnt(17813)} OONI measurements in its PW window, You Broadband has "
        f"{cnt(18207)}, Airtel's PW ASN (AS9498) has {cnt(9498)}, so Airtel comparisons rely on "
        "AS24560/AS45609 being on the same blocklist (plausible but untestable)",
        "Regional differences inside Jio and Airtel can't be seen at ASN level (national ASNs); "
        "OONI raw measurements include resolver_ip/resolver_asn which can be used for this",
        "",
        "",
    ]


def coverage(d):
    cov = d.cov25
    common = len({r["apex"] for r in d.testlist} & {r["domain"] for r in d.dns})

    def line(isp):
        r = cov[isp]
        s = f"{ISP_NAMES[isp]} {n(r['ooni_measured'])} / {n(r['pw_blocked'])} ({pct(r['ooni_measured'], r['pw_blocked'])})"
        if isp == "AIRTEL":
            s = s[:-1] + (
                f", but {n(r['ooni_measured_on_pw_asn'])} = "
                f"{pct(r['ooni_measured_on_pw_asn'], r['pw_blocked'])} on AS{PW_ASN['AIRTEL']})"
            )
        return s

    def cat_line(cat, isps):
        return ", ".join(
            f"{ISP_NAMES[i]} {n(d.covcat25[(i, cat)]['ooni_measured'])} / {n(d.covcat25[(i, cat)]['pw_blocked'])}"
            for i in isps if (i, cat) in d.covcat25
        )

    order = ["AIRTEL", "JIO", "ACT", "CONNECT", "MTNL", "YOU"]

    return [
        "== RQ1: COVERAGE (2025, PW windows) ==",
        "",
        f"{common} / {n(len(d.dns))} PW blocked domains are on the OONI test list "
        f"({pct(common, len(d.dns))})",
        "",
        "PW blocked domains measured by OONI in the PW window: "
        + ", ".join(line(i) for i in ["ACT", "JIO", "AIRTEL", "CONNECT", "YOU", "MTNL"]),
        "",
        "Movie/piracy (MOV) domains are almost unmeasured: " + cat_line("MOV", order),
        "Uncategorised (UNCAT) domains: " + cat_line("UNCAT", order),
        "Gambling (GMB) domains: " + cat_line("GMB", order),
        "",
        "",
    ]


AGREEMENT_TEXT = {
    "agree_blocked": "domain+ISP combos where both OONI and dnsblocks say blocked",
    "agree_ok": "domain+ISP combos where both say not blocked",
    "pw_blocked/ooni_mixed": "domain+ISP combos where the domain IS marked as blocked by dnsblocks, "
                             "but getting mixed results from OONI",
    "pw_ok/ooni_mixed": "domain+ISP combos where the domain isnt marked as blocked by dnsblocks "
                        "but mixed results from OONI",
    "ooni_only_blocked": "domain+ISP combos blocked in OONI but marked not blocked by dnsblocks",
    "pw_only_blocked": "domain+ISP combos marked blocked by dnsblocks but OONI reports reachable",
}

PW_OTHER = ["error", "timeout", "servfail", "nxdomain", "refused"]


def agreement(d):
    u = d.u25
    a = Counter(r["agreement"] for r in u)

    def line(label):
        part = [r for r in u if r["agreement"] == label]
        return f"{len(part)} {AGREEMENT_TEXT[label]} ({by_isp(isp_count(part))})"

    mixed = [r for r in u if r["ooni_verdict"] == "mixed"]
    other = [r for r in u if r["pw_status"] in PW_OTHER]
    other_v = Counter(r["ooni_verdict"] for r in other)
    other_blocked = [r for r in other if r["ooni_verdict"] == "blocked"]
    clean = a["ooni_only_blocked"] + a["pw_only_blocked"]
    mixed01 = a["pw_blocked/ooni_mixed"] + a["pw_ok/ooni_mixed"]

    # These categories partition the combos; check they add up.
    partition = [
        "agree_blocked",
        "agree_ok",
        "pw_blocked/ooni_mixed",
        "pw_ok/ooni_mixed",
        "ooni_only_blocked",
        "pw_only_blocked",
    ]
    parts = [a[label] for label in partition] + [len(other)]
    assert sum(parts) == len(u), f"agreement partition {parts} != {len(u)}"

    out = [
        "== RQ2: AGREEMENT (2025, PW windows) ==",
        "",
        "Definitions: OONI \"blocked\" = at least 90% of usable measurements anomalous or confirmed, "
        "\"reachable/ok\" = at most 10%, \"mixed\" = in between. Usable = measurement did not fail.",
        "",
        f"{len(u)} domain+ISP combos with usable OONI data ({by_isp(isp_count(u))})",
        f"They split into these 7 groups: {' + '.join(map(str, parts))} = {len(u)}",
        f"{sum(1 for r in u if r['low_confidence'])} of the {len(u)} rest on fewer than 3 usable "
        "measurements (low confidence)",
        "",
    ]

    for label in partition:
        out += [line(label), ""]

    out += [
        f"{len(other)} domain+ISP combos where dnsblocks has error/timeout/servfail/nxdomain instead of "
        f"a 0/1 value ({by_isp(isp_count(other))}); OONI says blocked {other_v.get('blocked', 0)} ("
        + ", ".join(f"{v} {k}" for k, v in Counter(r["pw_status"] for r in other_blocked).most_common())
        + f"), mixed {other_v.get('mixed', 0)}, ok {other_v.get('ok', 0)}; "
        "so PW's failed lookups may hide real blocks",
        "",
        "Subtotals (these overlap the groups above, don't add them to the total):",
        f"{len(mixed)} domain+ISP combos give mixed results from OONI = "
        f"{a['pw_blocked/ooni_mixed']} dnsblocks-blocked + {a['pw_ok/ooni_mixed']} "
        f"dnsblocks-not-blocked + {other_v.get('mixed', 0)} dnsblocks-error/timeout",
        f"{mixed01 + clean} combos where OONI and dnsblocks disagree (0/1 values only): {mixed01} mixed vs "
        f"{clean} clean contradictions, so most disagreement is \"mixed\" OONI results at these cutoffs "
        "(this depends on the cutoffs, see ROBUSTNESS)",
        "",
        "By PW category (domain+ISP combos):",
    ]

    short = {
        "agree_blocked": "agree-blocked",
        "agree_ok": "agree-ok",
        "pw_blocked/ooni_mixed": "dnsblocks-blocked/OONI-mixed",
        "pw_ok/ooni_mixed": "dnsblocks-ok/OONI-mixed",
        "ooni_only_blocked": "OONI-only blocked",
    }
    ct = Counter((r["pw_category"], r["agreement"]) for r in u)
    categories = {r["pw_category"] for r in u}

    for cat in ["FILE", "PORN", "MISC", "MOV", "UNCAT", "MILX", "LIVE"]:
        if cat not in categories:
            continue
        parts = [f"{ct[(cat, k)]} {v}" for k, v in short.items() if ct[(cat, k)] >= 4]
        out.append(f"{cat} " + ", ".join(parts))

    out += ["(no significance test run yet)", "", ""]
    return out


def regional(d):
    def act_split(da):
        split = defaultdict(lambda: [0, 0])
        for r in da:
            if r["isp"] == "ACT" and r["pw_status"] == "blocked" and r["n_usable"] > 0:
                s = split[r["asn"]]
                s[0] += r["agreement"] == "agree_blocked"
                s[1] += r["agreement"] == "pw_blocked/ooni_mixed"
        return split

    s25 = act_split(d.da25)
    s26 = act_split(d.da26)

    def fmt(split, asns, label=True):
        return ", ".join(
            f"AS{a}" + (f" ({ASN_REGION[a].replace(', ', '/')})" if label and a == 24309 else "")
            + f" {split[a][0]} agree / {split[a][1]} mixed"
            for a in asns if a in split
        )

    m = [
        r for r in d.mixed
        if r["isp"] == "ACT" and r["agreement"] == "pw_blocked/ooni_mixed"
    ]
    example = top(m, lambda r: float(r["block_share"]), 1)

    out = [
        "== REGIONAL BLOCKING (ACT) ==",
        "",
        "ACT, for domains dnsblocks marks as blocked: " + fmt(s25, [18209, 55577, 24309]),
    ]
    if example:
        per_asn = example[0]["per_asn"].replace("b/", " blocked / ").replace("u", " unblocked")
        out.append(
            "In the mixed ACT combos, the \"unblocked\" measurements come mostly from AS24309 "
            f"(e.g. {example[0]['domain']}: {per_asn})"
        )

    # Probes on public resolvers can't see DNS blocking: redo the per-ASN
    # split with ISP-resolver measurements only (resolver_split.py).
    known = defaultdict(list)
    for r in d.resolved:
        if r["isp"] == "ACT" and r["resolver_class"] != "unknown":
            known[r["asn"]].append(r["resolver_class"] == "public")
    share = {asn: sum(v) / len(v) for asn, v in known.items()}

    def load_act(path):
        return {r["asn"]: r for r in typed(read_csv(path))}

    isp_only = load_act(RESOLVER_ACT_ASN_CSV)
    isp_only_26 = load_act(RESOLVER_ACT_ASN_CSV_2026)

    def isp_fmt(asn, table=isp_only):
        r = table[asn]
        return (
            f"AS{asn} {r.get('blocked') or 0} blocked / {r.get('mixed') or 0} mixed "
            f"({n(r['measurements'])} measurements)"
        )

    out += [
        "2026 week, all resolvers: " + fmt(s26, [24309, 55577, 131269, 18209]),
        "2026 week, ISP resolver only: " + ", ".join(
            isp_fmt(a, isp_only_26) for a in [24309, 55577, 18209] if a in isp_only_26
        ),
        "",
        "But the share of ACT measurements made through a public resolver (Cloudflare, Google, "
        "OpenDNS, ...) is " + ", ".join(
            f"AS{a} {100 * share[a]:.0f}%" for a in [24309, 55577, 18209] if a in share
        ) + " (where the resolver is known)",
        "2025 with ISP-resolver measurements only: " + ", ".join(
            isp_fmt(a) for a in [24309, 55577, 18209] if a in isp_only
        ),
        "So AS24309's mixed results come from probes on public resolvers, which see ACT's DNS blocking "
        "only intermittently (via DNS injection, see RESOLVERS), NOT from a regional blocklist; with ISP "
        "resolvers AS24309 and AS55577 agree, so no evidence of regional blocking within ACT",
        "",
        "",
    ]
    return out


def tls(d):
    h = [r for r in d.raw if r["blocking_type"] == "http-failure"]
    t = [r for r in h if r["tls"]]
    other = [r for r in h if not r["tls"]]
    m = d.methods

    tls_fail = Counter(f for r in t for f in (r["tls_failures"] or "").split(";"))
    tls_types = ", ".join(f"{k} {n(v)}" for k, v in tls_fail.most_common(3))
    other_fail = ", ".join(
        f"{k} {n(v)}" for k, v in Counter(
            r["http_experiment_failure"] for r in other if r["http_experiment_failure"]
        ).most_common(6)
    )

    top_tls = sorted(
        sorted(Counter((r["isp"], r["domain"]) for r in t).items()),
        key=lambda x: -x[1],
    )[:9]
    top_s = ", ".join(f"{ISP_NAMES[i]} {dom} {v}" for (i, dom), v in top_tls)

    mc = Counter(r["method"] for r in m)
    assert sum(mc.values()) == len(m), mc
    tls_only = [r for r in m if r["method"] == "tls only"]
    pw_ok_tls = [r for r in tls_only if r["pw_status"] == "not_blocked"]
    ex = top(pw_ok_tls, lambda r: r["n_tls"], 14)
    ex_s = ", ".join(f"{ISP_NAMES[r['isp']]} {r['domain']}" for r in ex)

    def among(label):
        part = [r for r in m if r["agreement"] == label]
        return sum(1 for r in part if r["method"] == "tls only"), len(part)

    mixed_ok = among("pw_ok/ooni_mixed")
    ooni_only = among("ooni_only_blocked")
    agree = [r for r in m if r["agreement"] == "agree_blocked"]
    mixed_tls = [r for r in d.mixed if r["n_tls"] > 0]

    return [
        "== TLS BLOCKING ==",
        "",
        "OONI reports TLS interference as \"http-failure\"; split out using raw measurements "
        "(TLS handshake reset/EOF/timeout after a successful TCP connect to the same IP)",
        "",
        f"{n(len(t))} of {n(len(h))} http-failure measurements in the PW windows are TLS interference "
        f"({by_isp(isp_count(t))})",
        f"TLS failure types: {tls_types}",
        f"Remaining {n(len(other))} non-TLS http-failures: {other_fail}",
        "",
        f"Domains with TLS interference: {by_isp(isp_count(t, 'domain'))}",
        f"Most TLS-blocked: {top_s}",
        "",
        f"Blocking method per domain+ISP combo (only combos OONI sees as blocked or mixed get one): "
        f"{mc.get('dns only', 0)} DNS only, {mc.get('dns + tls', 0)} DNS + TLS, "
        f"{mc.get('tls only', 0)} TLS without DNS ({by_isp(isp_count(tls_only))}), "
        f"{mc.get('other', 0)} other (TCP/IP, HTTP-diff or non-TLS HTTP failure, with or without DNS), "
        f"{mc.get('no blocking', 0)} no blocking (OONI verdict ok) = {len(m)}",
        "",
        f"{len(pw_ok_tls)} domain+ISP combos marked not blocked by dnsblocks but OONI sees TLS blocking "
        f"without DNS blocking ({by_isp(isp_count(pw_ok_tls))}), invisible to a DNS-only scan",
        f"e.g. {ex_s}",
        f"{mixed_ok[0]} of the {mixed_ok[1]} not-blocked-by-dnsblocks/mixed-in-OONI combos are TLS blocking "
        f"without DNS, as are {ooni_only[0]} of the {ooni_only[1]} blocked-only-in-OONI combos",
        "",
        f"{sum(1 for r in agree if r['method'] == 'dns + tls')} of the {len(agree)} agree-blocked combos are blocked "
        "with both DNS and TLS",
        "",
        f"{len(mixed_tls)} of the {len(d.mixed)} mixed combos include TLS interference "
        f"({by_isp(isp_count(mixed_tls))}), per-combo counts in mixed_details_2025.txt",
        "",
        "",
    ]


def embedded(path, title, trailer=("",)):
    """
    A summary written by another script, without its title lines.
    """

    return [title, ""] + path.read_text().splitlines()[3:] + list(trailer)


def bypass(d):
    mc = Counter(r["method"] for r in d.methods)
    tls_any = mc.get("dns + tls", 0) + mc.get("tls only", 0)
    return [
        "== EASY TO BYPASS ==",
        "",
        f"{mc.get('dns only', 0)} domain+ISP combos are blocked by DNS only per OONI (no TLS, TCP/IP or "
        "HTTP blocking seen): bypassable with encrypted DNS (DoH/DoT); a plain alternate resolver is "
        "not enough on ACT (and Jio in 2025), where DNS to public resolvers gets injected (see RESOLVERS)",
        f"{tls_any} combos involve TLS blocking ({mc.get('dns + tls', 0)} DNS + TLS, "
        f"{mc.get('tls only', 0)} TLS without DNS), DoH alone is not enough (needs ECH, proxy or VPN)",
        f"{mc.get('other', 0)} combos involve TCP/IP, HTTP-diff or non-TLS HTTP blocking",
        "",
        "",
    ]


def testlist_not_in_pw(d):
    tl = d.testlist
    pw = {r["domain"] for r in d.dns}
    rest = [r for r in tl if r["apex"] not in pw]
    apexes = unique(r["apex"] for r in rest if r["apex"] is not None)
    tlds = Counter(a.split(".")[-1] for a in apexes).most_common(10)

    sub = [r for r in rest if r["host"] != r["apex"]]
    for r in sub:
        r["prefix"] = r["host"][: -len(r["apex"]) - 1]
    www = [r for r in sub if re.fullmatch(r"w{2,3}\d*", r["prefix"])]
    real = [r for r in sub if not re.fullmatch(r"w{2,3}\d*", r["prefix"])]
    www_prefixes = Counter(r["prefix"] for r in www)

    # One example per apex, from the apex domains with the most
    # subdomains on the list.
    apex_freq = Counter(r["apex"] for r in real)
    examples = unique(
        (r["apex"], r["host"])
        for r in sorted(real, key=lambda r: (-apex_freq[r["apex"]], r["host"]))
    )
    seen, picked = set(), []
    for apex, host in examples:
        if apex not in seen:
            seen.add(apex)
            picked.append(host)

    www_note = (
        "No ww4/ww5-style prefixes, only plain www"
        if list(www_prefixes) == ["www"]
        else "www-style prefixes: " + ", ".join(f"{k} {v}" for k, v in www_prefixes.most_common())
    )

    return [
        "== OONI TEST LIST DOMAINS NOT IN PW ==",
        "",
        f"{n(len(tl))} test-list URLs, {n(nunique(tl, 'apex'))} apex domains, {n(len(apexes))} apex "
        "domains not in the PW blocklist (implicitly unblocked on all 6 ISPs, if PW scanned them)",
        f"TLDs of those {n(len(apexes))}: " + ", ".join(f"{k} {v}" for k, v in tlds),
        "PW input = ICANN CZDS gTLD zone files + Domains Project active list; CZDS has no ccTLDs, so "
        ".in/.uk/.ru etc. were only scanned if on the Domains Project list, .mil probably not at all",
        "",
        f"Hostnames of test-list URLs whose apex is not in PW: {n(len(www))} www., {n(len(real))} real "
        f"subdomains ({n(nunique(real, 'host'))} hosts under {n(nunique(real, 'apex'))} apex domains), "
        "rest bare apex",
        www_note,
        f"Real subdomains e.g. {', '.join(picked[:8])}; PW only tested apex domains so their blocking can't count "
        "against PW",
        "",
        "",
    ]


def blocked_results(d):
    b = d.blk

    # Cross-check aggregation totals against the per-domain fetch.
    mine = defaultdict(lambda: [0, 0])
    for r in d.ooni_2025_win:
        m = mine[(r["hostname"], r["asn"])]
        m[0] += 1
        m[1] += r["blocked"]
    chk = [(mine[(r["host"], r["asn"])], r) for r in b if (r["host"], r["asn"]) in mine]
    total_match = all(m[0] == r["n_total"] for m, r in chk)

    hosts_per_asn = defaultdict(set)
    for r in d.blk_totals:
        hosts_per_asn[int(r["asn"])].add(r["domain"])
    hosts_per_asn = {a: len(h) for a, h in hosts_per_asn.items()}
    blocked_per_asn = Counter(int(r["probe_asn"].removeprefix("AS")) for r in d.blk_meas)

    def asn_line(series):
        parts = []
        for isp in ["JIO", "AIRTEL", "ACT", "CONNECT", "YOU", "MTNL"]:
            asns = sorted(ISP_ASNS[isp], key=lambda a: -series.get(a, 0))
            if len(asns) == 1:
                parts.append(f"{ISP_NAMES[isp]} {n(series.get(asns[0], 0))}")
            else:
                parts.append(
                    f"{ISP_NAMES[isp]} " + ", ".join(f"AS{a} {n(series.get(a, 0))}" for a in asns)
                )
        return " | ".join(parts)

    any_b = [r for r in b if r["n_blocked"] > 0]

    out = [
        "== EVERY BLOCKED OONI RESULT ON STUDY ASNs (2025, PW windows, any domain) ==",
        "",
        "From find_ooni_blocked.py (OONI aggregation API per ASN for totals + every anomaly=true "
        "measurement for blocking types)",
        f"Aggregation totals {'match' if total_match else 'DO NOT match'} the per-domain fetch "
        f"({n(sum(m[0] for m, _ in chk))} vs {n(sum(r['n_total'] for _, r in chk))} measurements over {n(len(chk))} "
        f"hostname x ASN pairs); blocked counts {n(sum(m[1] for m, _ in chk))} vs "
        f"{n(sum(r['n_blocked'] for _, r in chk))} (aggregation counts anomaly+failure as failure)",
        "",
        f"{n(nunique(b, 'host'))} hostnames measured by OONI on the study ASNs in the PW windows "
        f"({n(nunique(b, 'apex'))} apex domains)",
        "Hostnames measured per ASN: " + asn_line(hosts_per_asn),
        "Blocked measurements per ASN: " + asn_line(blocked_per_asn),
        "",
        f"{n(nunique(any_b, 'host'))} hostnames blocked at least once ({by_isp(isp_count(any_b, 'host'))})",
        "",
    ]

    for status, title in [
        ("not_in_blocklist", "apex NOT in the PW blocklist at all"),
        ("not_blocked", "in PW but marked not blocked on that ISP"),
    ]:
        out += blocked_section(b, status, title)

    return out


def strict_dns(part):
    s = [
        dict(r) for r in part
        if r["ooni_verdict"] == "blocked" and not r["low_confidence"]
        and r["host_kind"] in ("apex", "www")
    ]
    for r in s:
        r["dns_major"] = r["n_dns"] >= 0.5 * r["n_blocked"]
        r["gtld"] = len(r["apex"].split(".")[-1]) != 2
    return s


def blocked_section(b, status, title):
    part = [r for r in b if r["pw_status"] == status and r["n_blocked"] > 0]
    three = [r for r in part if r["n_blocked"] >= 3]
    confirmed = [r for r in part if r["n_confirmed"] > 0]
    strict = [r for r in part if r["ooni_verdict"] == "blocked" and not r["low_confidence"]]

    def hosts(rows):
        return f"{n(nunique(rows, 'host'))} hostnames"

    kinds = []
    for kind in ["apex", "www", "subdomain", "ip"]:
        k = [r for r in part if r["host_kind"] == kind]
        if k:
            ks = [r for r in strict if r["host_kind"] == kind]
            kinds.append(f"{kind} {nunique(k, 'host')} / {nunique(ks, 'host')}")

    dns_seen = [r for r in part if r["n_dns"] > 0]
    dns_only = [r for r in dns_seen if r["n_http_failure"] + r["n_http_diff"] + r["n_tcp_ip"] == 0]
    no_dns = [r for r in part if r["n_dns"] == 0]

    s = strict_dns(part)
    s_dns = [r for r in s if r["dns_major"]]
    cand = [r for r in s_dns if r["on_pw_asn"] and r["gtld"]]

    out = [
        f"Blocked in OONI, {title}:",
        f"{hosts(part)} blocked at least once ({by_isp(isp_count(part, 'host'))})"
        + (", upper bound only, single anomalies include network noise" if status == "not_in_blocklist" else ""),
        f"{hosts(three)} blocked at least 3 times ({by_isp(isp_count(three, 'host'))})",
        f"{hosts(confirmed)} with a confirmed blockpage ({by_isp(isp_count(confirmed, 'host'))})",
        f"{hosts(strict)} with OONI verdict 'blocked' (>= 90%, >= 3 usable measurements) "
        f"({by_isp(isp_count(strict, 'host'))})",
        "By hostname type (at least once / verdict blocked): " + ", ".join(kinds),
        f"{n(nunique([r for r in part if r['on_testlist']], 'host'))} on the OONI test list, "
        f"{n(nunique([r for r in part if not r['on_testlist']], 'host'))} not on it (custom/other inputs)",
        f"{n(nunique(dns_seen, 'host'))} hostnames with DNS blocking ({n(nunique(dns_only, 'host'))} DNS only), "
        f"{n(nunique(no_dns, 'host'))} with only http-failure/tcp/http-diff (TLS candidates); "
        "counted per ISP, so a hostname can be in both",
        f"At apex level, {nunique(s, 'apex')} apex domains with verdict blocked: "
        f"{nunique(s_dns, 'apex')} mostly DNS, {nunique([r for r in s if not r['dns_major']], 'apex')} mostly non-DNS "
        "(some domains differ by ISP)",
        "",
    ]

    pairs = unique((r["isp"], r["apex"]) for r in cand)
    per = defaultdict(list)
    for isp, apex in pairs:
        per[isp].append(apex)
    per = {isp: ", ".join(sorted(v)) for isp, v in sorted(per.items())}

    if status == "not_in_blocklist":
        out.append(
            f"{nunique(cand, 'apex')} gTLD apex domains NOT in PW, DNS-blocked per OONI on PW's own ASN "
            "inside its window (strongest PW false-negative candidates, ask dnsblocks.in to re-check):"
        )
        for isp, doms in per.items():
            out.append(f"{ISP_NAMES[isp]}: {doms}")
        out.append("")

        cc = top([r for r in s_dns if not r["gtld"]], lambda r: r["n_blocked"], len(s_dns))
        out.append(
            "ccTLD domains DNS-blocked in OONI but not in PW (may never have been scanned): e.g. "
            + ", ".join(unique(r["host"] for r in cc)[:6])
        )

        air = [r for r in three if r["isp"] == "AIRTEL"]
        on_24560 = sum(1 for r in air if r["asn"] == 24560) / len(air) if air else 0
        air_ex = unique(
            r["apex"] for r in top(
                [r for r in s if r["isp"] == "AIRTEL" and r["asn"] == 24560],
                lambda r: r["n_blocked"], len(s),
            )
        )[:4]
        out.append(
            f"Airtel hostnames not in PW blocked >= 3 times: {100 * on_24560:.0f}% are on AS24560 "
            f"(e.g. {', '.join(air_ex)}), could be ASN difference rather than PW miss"
        )
        out.append("")

        out.append("Most-blocked hostnames not in PW: " + ", ".join(
            f"{r['host']} ({ISP_NAMES[r['isp']]} {r['n_blocked']}/{r['n_usable']} {dominant(r)})"
            for r in top(part, lambda r: r["n_blocked"], 8)
        ))
        out.append("")

        infra_re = re.compile(r"^mask(?:-h2)?\.icloud\.com$|^doh[.-]|\.doh\.|vpn|ipfs")
        infra = top(
            [
                r for r in part
                if infra_re.search(r["host"]) and r["n_blocked"] >= 10
                and r["ooni_verdict"] in ("blocked", "mixed")
            ],
            lambda r: r["n_blocked"], len(part),
        )
        out.append(
            "Privacy / circumvention infrastructure blocked (Private Relay, DoH, VPN, IPFS hostnames, "
            ">= 10 blocked measurements and OONI verdict blocked or mixed): " + ", ".join(
                f"{r['host']} ({ISP_NAMES[r['isp']]} AS{r['asn']} {r['n_blocked']}/{r['n_usable']} {dominant(r)})"
                for r in infra
            )
        )
    else:
        out.append(
            f"{nunique(cand, 'apex')} gTLD apex domains marked 0 by PW but DNS-blocked on PW's own ASN "
            f"({by_isp(Counter(isp for isp, _ in pairs))})"
        )
        for isp, doms in per.items():
            out.append(f"{ISP_NAMES[isp]}: {doms}")
        out.append(
            "Possible reason for Connect: PW measured it through a remotely reachable ISP resolver, "
            "which may not use the same blocklist as the resolvers Connect customers use (untested; "
            "Connect's OONI data also comes from only a few probes, see OONI PROBES)"
        )

    out += ["", ""]
    return out


def dominant(r):
    types = {
        "dns": r["n_dns"],
        "http-failure": r["n_http_failure"],
        "http-diff": r["n_http_diff"],
        "tcp": r["n_tcp_ip"],
    }
    return max(types, key=types.get)


def limitations(d):
    per_asn = Counter(r["asn"] for r in d.ooni_2025_win)
    isps_2026 = {r["isp"] for r in d.ooni_2026}
    probes = {r["asn"]: r for r in read_csv(CSV_DIR / "probe_summary_2025.csv")}
    connect = probes.get("17917")
    resolved_26, _, _ = label_resolvers(d.ooni_2026, load_resolver_raw([REPORT_META_2026]))
    internal_26 = Counter(r["isp"] for r in resolved_26 if r["resolver_class"] == "internal")
    jio_26 = sum(1 for r in d.ooni_2026 if r["isp"] == "JIO")
    low = sum(1 for r in d.u25 if r["low_confidence"])
    missing_26 = [ISP_NAMES[i] for i in ISP_ASNS if i not in isps_2026]
    diffs = [PW_TABLE4[i] - sum(1 for r in d.dns if r[i] == "1") for i in ISP_ASNS]

    return [
        "== LIMITATIONS ==",
        "",
        f"Thin or missing OONI data: MTNL {per_asn.get(17813, 0)} measurements in its 2025 PW window, "
        f"You {per_asn.get(18207, 0)}, Airtel's PW ASN (AS9498) {per_asn.get(9498, 0)}; Airtel results rely "
        "on AS24560/AS45609 sharing AS9498's blocklist",
        f"Connect's 2025 data comes from {connect['probes_loose']}-{connect['probes_strict']} probes"
        if connect else "Connect has no probe metadata",
        f"2026 covers one week only, with no data for {', '.join(missing_26)}",
        f"OONI publishes no probe ID, so probe counts are approximate (loose-strict fingerprint range)",
        f"Verdict cutoffs (0.1 / 0.9) are a choice; ISP-resolver results are stable across 0.05-0.3, "
        "the 'mostly mixed' disagreement is not (see ROBUSTNESS)",
        f"{low} of the {len(d.u25)} 2025 domain+ISP combos rest on fewer than 3 usable measurements",
        "TLS interference = handshake reset/EOF/timeout after a successful TCP connect; the SNI-filtering "
        "signature, but an occasional reset can be a server problem",
        f"Resolvers with no ASN (AS0) are counted as internal: {internal_26.get('JIO', 0):,} of Jio's "
        f"{jio_26:,} 2026 measurements, mostly Jio's own resolvers behind NAT64, so they are missing from "
        "the ISP-resolver view",
        "DNS injection, PW false-negative candidates and the Connect resolver explanation are inferences "
        "that need confirmation (e.g. by dnsblocks.in re-querying the candidates)",
        "Category associations are weak and their p-values optimistic: the same domain on different ISPs "
        "is not independent, and PW's categories are best-effort (see CATEGORIES)",
        f"The published PW CSV has {min(diffs)}-{max(diffs)} fewer blocked domains per ISP than the "
        "report's Table 4 (same total)",
        "",
        "",
    ]


def not_done():
    return [
        "== NOT DONE YET ==",
        "",
        "Decode NAT64 (AS0, counted as internal) resolver addresses to their real ASN: most are Jio's "
        "own resolvers (49.45.x.x), which would add ~900 2026 Jio runs to the ISP-resolver analysis",
        "Redo the TLS split and PW false-negative candidates with ISP-resolver measurements only",
        "Case studies (dnsblocks-only blocked, TLS-only, Connect's OONI-only, the gTLD PW false-negative candidates)",
        "Ask dnsblocks.in which of the non-PW test-list domains were in their input list, and to re-query the DNS-blocked candidates",
        "TLS split (raw fetch) for the non-DNS hostnames blocked outside the PW overlap",
        "Whether PW domains outside the OONI test list are also TLS/HTTP blocked (needs new ooniprobe runs)",
        "RQ3 reproducibility cost model",
        "",
    ]


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():
    csv.field_size_limit(1 << 24)
    d = Data()

    sections = {
        "datasets": datasets(d),
        "asns": asns(d),
        "coverage": coverage(d),
        "agreement": agreement(d),
        "regional": regional(d),
        "tls": tls(d),
        "resolvers": embedded(RESOLVER_SPLIT_TXT, "== RESOLVERS: ISP vs PUBLIC RESOLVER =="),
        "probes": embedded(PROBE_METADATA_TXT, "== OONI PROBES, SOFTWARE AND TEST VERSIONS =="),
        "bypass": bypass(d),
        "drift": embedded(DRIFT_TXT, "== 2025 vs 2026 (DRIFT) ==", ("", "")),
        "resolvers_2026": embedded(
            RESOLVER_SPLIT_TXT_2026, "== RESOLVERS 2026 (THIS WEEK): ISP vs PUBLIC RESOLVER =="
        ),
        "probes_2026": embedded(PROBE_METADATA_TXT_2026, "== OONI PROBES 2026 (THIS WEEK) =="),
        "robustness": embedded(ROBUSTNESS_TXT, "== ROBUSTNESS: VERDICT CUTOFFS =="),
        "categories": embedded(CATEGORY_TEST_TXT, "== CATEGORIES: DOES DISAGREEMENT DEPEND ON CATEGORY? =="),
        "testlist": testlist_not_in_pw(d),
        "blocked": blocked_results(d),
    }

    full = header()
    for s in sections.values():
        full += s
    full += limitations(d)
    full += not_done()
    FINDINGS_ALL.write_text("\n".join(full))

    short = [
        "OONI data matched to Poisoned Wells measurement windows (per ISP, +/- 7 days, 2025)",
        "Generated by scripts/make_findings.py, see findings_all.txt for everything",
        "",
    ]
    sections["limitations"] = limitations(d)
    for key in ["asns", "coverage", "agreement", "regional", "tls", "drift", "robustness", "limitations"]:
        short += sections[key]
    FINDINGS_2025.write_text("\n".join(short).rstrip() + "\n")

    print(f"Wrote {rel(FINDINGS_ALL)} and {rel(FINDINGS_2025)}", file=sys.stderr)


if __name__ == "__main__":
    main()
