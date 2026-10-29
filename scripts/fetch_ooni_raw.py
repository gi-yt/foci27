#!/usr/bin/env python3

"""
Fetch raw OONI measurements for selected rows of ooni_data_*.csv and
extract the details the list API does not expose: the resolver the
probe used, and per-connection TCP / TLS outcomes.

The list API reports TLS interference as blocking_type "http-failure";
the raw test_keys are needed to tell a TLS handshake reset (SNI
filtering) apart from other HTTP failures.
"""

import argparse
import csv
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from common import apply_window, get_json, load_ooni
from paths import OONI_2025, RAW_DETAILS_2025, REPORT_META_2025


RAW_URL = "https://api.ooni.io/api/v1/raw_measurement"

OUTPUT_FIELDS = [
    "measurement_uid",
    "domain",
    "isp",
    "probe_asn",
    "measurement_start_time",
    "input",
    "outcome",
    "blocking_type",
    "test_version",

    "resolver_ip",
    "resolver_asn",
    "resolver_network_name",

    "dns_experiment_failure",
    "http_experiment_failure",
    "raw_blocking",
    "accessible",

    "tcp_ok",
    "tcp_failed",
    "tcp_failures",
    "tls_ok",
    "tls_failed",
    "tls_failures",

    "tls_interference",
]

# Per-report metadata (constant within one OONI report / probe run).
META_FIELDS = [
    "measurement_uid",
    "report_id",
    "isp",
    "probe_asn",
    "measurement_start_time",
    "software_name",
    "software_version",
    "engine_version",
    "test_version",
    "platform",
    "architecture",
    "network_type",
    "resolver_ip",
    "resolver_asn",
    "resolver_network_name",
]

# TLS handshake failures that indicate on-path interference when the
# TCP connection to the same address succeeded.
TLS_INTERFERENCE_FAILURES = {
    "connection_reset",
    "eof_error",
    "generic_timeout_error",
}


def strip_port(address):
    host = address.rsplit(":", 1)[0]
    return host.strip("[]")


def extract(row, raw):
    tk = raw.get("test_keys") or {}

    tcp = tk.get("tcp_connect") or []
    tls = tk.get("tls_handshakes") or []

    tcp_ok_ips = {
        t.get("ip")
        for t in tcp
        if not (t.get("status") or {}).get("failure")
    }
    tcp_failures = [
        (t.get("status") or {}).get("failure")
        for t in tcp
        if (t.get("status") or {}).get("failure")
    ]
    tls_failures = [
        h.get("failure")
        for h in tls
        if h.get("failure")
    ]

    # TLS interference: a handshake reset/EOF/timeout on an address
    # whose TCP connection succeeded.
    tls_interference = any(
        h.get("failure") in TLS_INTERFERENCE_FAILURES
        and strip_port(h.get("address", "")) in tcp_ok_ips
        for h in tls
    )

    return {
        "measurement_uid": row["measurement_uid"],
        "domain": row["domain"],
        "isp": row["isp"],
        "probe_asn": row["probe_asn"],
        "measurement_start_time": str(row["time"]),
        "input": row["input"],
        "outcome": row["outcome"],
        "blocking_type": row["blocking_type"],
        "test_version": raw.get("test_version"),

        "resolver_ip": raw.get("resolver_ip"),
        "resolver_asn": raw.get("resolver_asn"),
        "resolver_network_name": raw.get("resolver_network_name"),

        "dns_experiment_failure": tk.get("dns_experiment_failure"),
        "http_experiment_failure": tk.get("http_experiment_failure"),
        "raw_blocking": tk.get("blocking"),
        "accessible": tk.get("accessible"),

        "tcp_ok": len(tcp) - len(tcp_failures),
        "tcp_failed": len(tcp_failures),
        "tcp_failures": ";".join(sorted(set(tcp_failures))),
        "tls_ok": len(tls) - len(tls_failures),
        "tls_failed": len(tls_failures),
        "tls_failures": ";".join(sorted(set(tls_failures))),

        "tls_interference": tls_interference,
    }


def extract_meta(row, raw):
    ann = raw.get("annotations") or {}

    return {
        "measurement_uid": row["measurement_uid"],
        "report_id": raw.get("report_id"),
        "isp": row["isp"],
        "probe_asn": row["probe_asn"],
        "measurement_start_time": str(row["time"]),
        "software_name": raw.get("software_name"),
        "software_version": raw.get("software_version"),
        "engine_version": ann.get("engine_version"),
        "test_version": raw.get("test_version"),
        "platform": ann.get("platform"),
        "architecture": ann.get("architecture"),
        "network_type": ann.get("network_type"),
        "resolver_ip": raw.get("resolver_ip"),
        "resolver_asn": raw.get("resolver_asn"),
        "resolver_network_name": raw.get("resolver_network_name"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--ooni",
        default=str(OONI_2025),
        help="OONI CSV produced by fetch_ooni_data.py.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help=(
            f"Default: {RAW_DETAILS_2025.name}, or "
            f"{REPORT_META_2025.name} with --report-meta."
        ),
    )
    parser.add_argument(
        "--report-meta",
        action="store_true",
        help=(
            "Fetch one measurement from every OONI report (probe run) and "
            "record its software, test version, platform and resolver."
        ),
    )
    parser.add_argument(
        "--window",
        choices=["pw", "all"],
        default="pw",
        help="Same meaning as in compare_ooni_dnsblocks.py.",
    )
    parser.add_argument(
        "--blocking-types",
        default="http-failure,tcp_ip,http-diff",
        help=(
            "Comma-separated OONI blocking types to fetch, among "
            "anomalous/confirmed measurements. 'all' fetches every "
            "measurement (slow)."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Concurrent requests. Default: 4.",
    )

    args = parser.parse_args()

    if args.output is None:
        args.output = str(REPORT_META_2025 if args.report_meta else RAW_DETAILS_2025)

    ooni = load_ooni(args.ooni)

    if args.window == "pw":
        ooni = apply_window(ooni, 7)

    if args.report_meta:
        # Deterministic pick: the earliest measurement of each report.
        first = {}
        for r in sorted(ooni, key=lambda r: (r["report_id"], r["measurement_uid"])):
            first.setdefault(r["report_id"], r)
        ooni = list(first.values())

    elif args.blocking_types != "all":
        types = set(args.blocking_types.split(","))
        ooni = [r for r in ooni if r["blocked"] and r["blocking_type"] in types]

    done = set()

    if os.path.exists(args.output):
        with open(args.output, encoding="utf-8", newline="") as f:
            done = {r["measurement_uid"] for r in csv.DictReader(f)}

    todo = [r for r in ooni if r["measurement_uid"] not in done]

    print(f"Selected {len(ooni)} measurements, {len(todo)} remaining.")

    write_header = not os.path.exists(args.output)
    lock = threading.Lock()

    def work(row):
        raw = get_json(RAW_URL, {"measurement_uid": row["measurement_uid"]})
        if args.report_meta:
            return extract_meta(row, raw)
        return extract(row, raw)

    with open(args.output, "a", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(
            out,
            fieldnames=META_FIELDS if args.report_meta else OUTPUT_FIELDS,
        )

        if write_header:
            writer.writeheader()

        rows = todo

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(work, r) for r in rows]

            for i, future in enumerate(as_completed(futures), start=1):
                try:
                    result = future.result()
                except Exception as e:
                    print(f"ERROR: {e}", file=sys.stderr)
                    continue

                with lock:
                    writer.writerow(result)

                if i % 100 == 0:
                    out.flush()
                    print(f"{i}/{len(rows)}")

    print(f"Finished. Output: {args.output}")


if __name__ == "__main__":
    main()
