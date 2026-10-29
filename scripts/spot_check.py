#!/usr/bin/env python3

"""
Check the saved OONI data against OONI's live API.

Re-fetches a stratified random sample of measurements (fixed seed, so the
same sample every run) and compares the fields the analysis relies on:

  ooni_data_*.csv          anomaly, confirmed, failure, blocking type,
                           report, ASN and input, against measurement_meta
                           (sample: anomalous + any measurement)
  ooni_raw_details_*.csv   TLS label (rule re-applied here, independently
                           of fetch_ooni_raw.py) and resolver, against the
                           raw measurement (sample: TLS + non-TLS
                           http-failures)
  ooni_report_meta_*.csv   report, software, test version, platform,
                           architecture, network type and resolver, against
                           the raw measurement

Calls the API, so run_all.sh does not run it.

Output: spot_check.txt
"""

import argparse
import json
import random
import time

from common import get_json, read_csv
from paths import (
    OONI_2025,
    OONI_2026,
    RAW_DETAILS_2025,
    RAW_DETAILS_2026,
    REPORT_META_2025,
    REPORT_META_2026,
    SPOT_CHECK_TXT,
)

META_URL = "https://api.ooni.io/api/v1/measurement_meta"
RAW_URL = "https://api.ooni.io/api/v1/raw_measurement"

TLS_FAILURES = {"connection_reset", "eof_error", "generic_timeout_error"}

META_FIELDS = [
    "report_id",
    "software_name",
    "software_version",
    "engine_version",
    "test_version",
    "platform",
    "architecture",
    "network_type",
    "resolver_ip",
    "resolver_asn",
]


def text(value):
    return "" if value is None else str(value)


def tls_rule(raw):
    """A TLS handshake reset/EOF/timeout to an IP whose TCP connect succeeded."""

    tk = raw.get("test_keys") or {}
    tcp_ok = {
        t.get("ip")
        for t in tk.get("tcp_connect") or []
        if not (t.get("status") or {}).get("failure")
    }
    return any(
        h.get("failure") in TLS_FAILURES
        and h.get("address", "").rsplit(":", 1)[0].strip("[]") in tcp_ok
        for h in tk.get("tls_handshakes") or []
    )


def check_measurements(row):
    m = get_json(META_URL, {"measurement_uid": row["measurement_uid"]})
    scores = json.loads(m.get("scores") or "{}")
    live = {
        "anomaly": text(m.get("anomaly")),
        "confirmed": text(m.get("confirmed")),
        "failure": text(m.get("failure")),
        "blocking_type": text((scores.get("analysis") or {}).get("blocking_type")),
        "report_id": text(m.get("report_id")),
        "probe_asn": f"AS{m.get('probe_asn')}",
        "input": text(m.get("input")),
    }
    return {k: (row[k], v) for k, v in live.items()}


def check_raw_details(row):
    raw = get_json(RAW_URL, {"measurement_uid": row["measurement_uid"]})
    live = {
        "tls_interference": text(tls_rule(raw)),
        "resolver_ip": text(raw.get("resolver_ip")),
        "resolver_asn": text(raw.get("resolver_asn")),
    }
    return {k: (row[k], v) for k, v in live.items()}


def check_report_meta(row):
    raw = get_json(RAW_URL, {"measurement_uid": row["measurement_uid"]})
    ann = raw.get("annotations") or {}
    live = {
        k: text(ann.get(k) if k in ("engine_version", "platform", "architecture", "network_type") else raw.get(k))
        for k in META_FIELDS
    }
    return {k: (row[k], v) for k, v in live.items()}


def sample(rng, rows, n):
    return rng.sample(rows, min(n, len(rows)))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--anomalous", type=int, default=8, help="Anomalous measurements per year.")
    parser.add_argument("--any", type=int, default=7, help="Measurements of any outcome per year.")
    parser.add_argument("--tls", type=int, default=8, help="HTTP failures labelled TLS per year.")
    parser.add_argument("--non-tls", type=int, default=6, help="HTTP failures not labelled TLS per year.")
    parser.add_argument("--reports", type=int, default=10, help="Report metadata rows per year.")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds between API calls.")
    parser.add_argument("--txt", default=str(SPOT_CHECK_TXT))
    args = parser.parse_args()

    rng = random.Random(args.seed)
    checks = []
    for year, ooni, raw, meta in [
        ("2025", OONI_2025, RAW_DETAILS_2025, REPORT_META_2025),
        ("2026", OONI_2026, RAW_DETAILS_2026, REPORT_META_2026),
    ]:
        rows = read_csv(ooni)
        anomalous = [r for r in rows if r["anomaly"] == "True"]
        picked = sample(rng, anomalous, args.anomalous)
        picked += sample(rng, [r for r in rows if r not in picked], args.any)
        checks += [(year, "measurements", r, check_measurements) for r in picked]

        rows = [r for r in read_csv(raw) if r["blocking_type"] == "http-failure"]
        picked = sample(rng, [r for r in rows if r["tls_interference"] == "True"], args.tls)
        picked += sample(rng, [r for r in rows if r["tls_interference"] == "False"], args.non_tls)
        checks += [(year, "raw_details", r, check_raw_details) for r in picked]

        checks += [(year, "report_meta", r, check_report_meta) for r in sample(rng, read_csv(meta), args.reports)]

    lines, mismatches, fields = [], 0, 0
    for i, (year, kind, row, check) in enumerate(checks, start=1):
        if i > 1:
            time.sleep(args.delay)
        result = check(row)
        bad = {k: v for k, v in result.items() if v[0] != v[1]}
        fields += len(result)
        mismatches += len(bad)
        lines.append(
            f"  {year} {kind:<12} {row['measurement_uid']}  "
            + ("ok" if not bad else "MISMATCH " + "; ".join(f"{k} saved {s!r} live {l!r}" for k, (s, l) in bad.items()))
        )
        print(lines[-1])

    counts = {}
    for year, kind, _, _ in checks:
        counts[(year, kind)] = counts.get((year, kind), 0) + 1

    out = [
        "Saved OONI data vs OONI's live API (stratified random sample)",
        "Generated by scripts/spot_check.py",
        "",
        f"Seed {args.seed}; per year: {args.anomalous} anomalous + {args.any} any measurements, "
        f"{args.tls} TLS + {args.non_tls} non-TLS http-failures, {args.reports} report metadata rows",
        "Sample: " + ", ".join(f"{y} {k} {n}" for (y, k), n in counts.items()),
        "",
        f"{len(checks)} measurements, {fields} fields compared, {mismatches} mismatches",
        "",
        *lines,
        "",
    ]
    with open(args.txt, "w") as f:
        f.write("\n".join(out))
    print("\n".join(out[:7]))


if __name__ == "__main__":
    main()
