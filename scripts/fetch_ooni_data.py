#!/usr/bin/env python3

import argparse
import csv
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

from common import get_json
from paths import OONI_2025


API_URL = "https://api.ooni.io/api/v1/measurements"

# Be conservative with the API.
PAGE_SIZE = 10000

# The API rejects ranges over 180 days; stay well under it.
MAX_RANGE = timedelta(days=90)

# Poisoned Wells measurement window (report, Table 19):
#   ACT     2025-03-09 -> 2025-04-01
#   Jio     2025-03-09 -> 2025-03-29
#   Airtel  2025-03-11 -> 2025-04-10
#   MTNL    2025-04-12 -> 2025-05-23
#   You     2025-04-21 -> 2025-09-09
#   Connect 2025-04-22 -> 2025-06-17
#
# The defaults cover all of these with ~a week of margin on each
# side. compare_ooni_dnsblocks.py narrows to each ISP's own window.
DEFAULT_SINCE = "2025-03-01T00:00:00"
DEFAULT_UNTIL = "2025-09-16T00:00:00"

OUTPUT_FIELDS = [
    "domain",
    "probe_cc",
    "probe_asn",
    "measurement_start_time",
    "measurement_uid",
    "report_id",
    "test_name",

    "anomaly",
    "confirmed",
    "failure",
    "verification_status",

    "blocking_general",
    "blocking_global",
    "blocking_country",
    "blocking_isp",
    "blocking_local",

    "blocking_type",
    "fingerprints",

    "input",
    "measurement_url",
]


def load_domains(path):
    """
    Load domains from either:

    1. A plain text file:
       example.com
       ...

    2. A CSV containing a 'domain' column.
    """

    path = Path(path)

    if path.suffix.lower() == ".csv":
        domains = []

        with path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)

            if not reader.fieldnames or "domain" not in reader.fieldnames:
                raise ValueError(
                    f"{path} does not contain a 'domain' column."
                )

            for row in reader:
                domain = row["domain"].strip().lower()

                if domain:
                    domains.append(domain)

    else:
        with path.open("r", encoding="utf-8") as f:
            domains = [
                line.strip().lower()
                for line in f
                if line.strip()
            ]

    # Remove duplicates while preserving order.
    domains = list(dict.fromkeys(domains))

    return domains


def flatten_measurement(domain, measurement):
    """
    Convert one OONI measurement JSON object into one CSV row.
    """

    scores = measurement.get("scores") or {}
    analysis = scores.get("analysis") or {}

    # OONI sometimes has fingerprints as a list of objects.
    fingerprints = measurement.get("fingerprints") or []

    fingerprint_names = []

    for fp in fingerprints:
        if isinstance(fp, dict):
            name = fp.get("name")

            if name:
                fingerprint_names.append(name)

    return {
        "domain": domain,

        "probe_cc": measurement.get("probe_cc"),
        "probe_asn": measurement.get("probe_asn"),

        "measurement_start_time":
            measurement.get("measurement_start_time"),

        "measurement_uid":
            measurement.get("measurement_uid"),

        "report_id":
            measurement.get("report_id"),

        "test_name":
            measurement.get("test_name"),

        "anomaly":
            measurement.get("anomaly"),

        "confirmed":
            measurement.get("confirmed"),

        "failure":
            measurement.get("failure"),

        "verification_status":
            measurement.get("verification_status"),

        "blocking_general":
            scores.get("blocking_general"),

        "blocking_global":
            scores.get("blocking_global"),

        "blocking_country":
            scores.get("blocking_country"),

        "blocking_isp":
            scores.get("blocking_isp"),

        "blocking_local":
            scores.get("blocking_local"),

        "blocking_type":
            analysis.get("blocking_type"),

        "fingerprints":
            ";".join(fingerprint_names),

        "input":
            measurement.get("input"),

        "measurement_url":
            measurement.get("measurement_url"),
    }


def date_chunks(since, until):
    """
    Split [since, until) into pieces the API accepts (it rejects
    ranges over 180 days).
    """

    start = datetime.fromisoformat(since)
    end = datetime.fromisoformat(until)

    while start < end:
        stop = min(start + MAX_RANGE, end)
        yield start.isoformat(), stop.isoformat()
        start = stop


# Requests actually sent to the API (pages read from --raw-dir don't count),
# so the polite delay between domains is only spent when needed.
api_calls = 0


def fetch_domain(
    domain,
    since,
    until,
    delay,
    raw_dir=None,
):
    """
    Download all OONI measurements for one domain.
    """

    all_rows = []

    for chunk, (start, stop) in enumerate(
        date_chunks(since, until),
        start=1,
    ):
        all_rows.extend(
            fetch_range(
                domain,
                start,
                stop,
                delay,
                raw_dir,
                chunk,
            )
        )

    return all_rows


def fetch_range(
    domain,
    since,
    until,
    delay,
    raw_dir,
    chunk,
):
    """
    Download one date range for one domain, following pagination.
    """

    global api_calls

    all_rows = []

    params = {
        "probe_cc": "IN",
        "domain": domain,
        "test_name": "web_connectivity",
        "since": since,
        "until": until,
        "limit": PAGE_SIZE,
    }

    url = API_URL
    page = 1

    while True:

        raw_path = (
            Path(raw_dir) / f"{domain.replace('/', '_')}_{chunk}_{page}.json"
            if raw_dir is not None else None
        )

        # Reuse a page saved by an earlier run instead of asking the API.
        cached = raw_path is not None and raw_path.exists()

        print(
            f"    {domain}: {since[:10]} -> {until[:10]}, "
            f"page {page}" + (" (saved)" if cached else "")
        )

        if cached:
            with raw_path.open(encoding="utf-8") as f:
                data = json.load(f)
        else:
            api_calls += 1
            data = get_json(url, params)

            # Save the raw API response if requested.
            if raw_path is not None:
                with raw_path.open("w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

        results = data.get("results", [])

        if not results:
            break

        for measurement in results:

            row = flatten_measurement(
                domain,
                measurement,
            )

            all_rows.append(row)

        metadata = data.get("metadata") or {}

        # The API paginates with a cursor ("cont=...") embedded in
        # next_url, so follow it as-is rather than computing offsets.
        next_url = metadata.get("next_url")

        if not next_url or len(results) < PAGE_SIZE:
            break

        url = next_url
        params = None
        page += 1

        if not cached:
            time.sleep(delay)

    return all_rows


def check_raw_dir(raw_dir, query):
    """
    Saved pages are only reusable for the same query, so the raw directory
    records the query it was fetched with and refuses a different one.
    """

    path = Path(raw_dir) / "_query.json"

    if path.exists():
        saved = json.loads(path.read_text())
        if saved != query:
            raise SystemExit(
                f"{raw_dir} holds pages for {saved}, not {query}; "
                "use another --raw-dir"
            )
    else:
        if any(p.suffix == ".json" for p in Path(raw_dir).iterdir()):
            raise SystemExit(
                f"{raw_dir} has saved pages but no _query.json, so it is unknown "
                "which query they belong to; use another --raw-dir"
            )
        path.write_text(json.dumps(query, indent=2) + "\n")


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Download OONI Web Connectivity measurements "
            "for a list of domains in India."
        )
    )

    parser.add_argument(
        "input",
        help=(
            "Input CSV containing a 'domain' column, "
            "or a text file with one domain per line."
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        default=str(OONI_2025),
        help="Output CSV filename.",
    )

    parser.add_argument(
        "--since",
        default=DEFAULT_SINCE,
        help=(
            "Start of the measurement window (UTC). "
            f"Default: {DEFAULT_SINCE} (Poisoned Wells period)."
        ),
    )

    parser.add_argument(
        "--until",
        default=DEFAULT_UNTIL,
        help=(
            "End of the measurement window (UTC). "
            f"Default: {DEFAULT_UNTIL} (Poisoned Wells period)."
        ),
    )

    parser.add_argument(
        "--raw-dir",
        default=None,
        help=(
            "Directory in which to save raw OONI JSON responses. Pages "
            "already saved there are read instead of fetched again."
        ),
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help=(
            "Seconds to wait between API requests. "
            "Default: 1."
        ),
    )

    args = parser.parse_args()

    domains = load_domains(args.input)

    print(
        f"Loaded {len(domains)} unique domains."
    )
    print(
        f"Window: {args.since} -> {args.until}"
    )

    if args.raw_dir:
        Path(args.raw_dir).mkdir(
            parents=True,
            exist_ok=True,
        )
        check_raw_dir(args.raw_dir, {
            "probe_cc": "IN",
            "test_name": "web_connectivity",
            "since": args.since,
            "until": args.until,
        })

    # Resume support:
    #
    # Finished domains are recorded in a sidecar file, so domains
    # that legitimately returned zero measurements are not
    # re-queried on every run.
    done_path = Path(f"{args.output}.done")

    completed_domains = set()

    if done_path.exists():
        completed_domains = {
            line.strip()
            for line in done_path.read_text().splitlines()
            if line.strip()
        }

        print(
            f"Already collected: "
            f"{len(completed_domains)} domains."
        )

    remaining = [
        d for d in domains
        if d not in completed_domains
    ]

    print(
        f"Remaining: {len(remaining)} domains."
    )

    write_header = not os.path.exists(args.output)

    with open(
        args.output,
        "a",
        encoding="utf-8",
        newline="",
    ) as out, done_path.open("a") as done:

        writer = csv.DictWriter(
            out,
            fieldnames=OUTPUT_FIELDS,
            extrasaction="ignore",
        )

        if write_header:
            writer.writeheader()

        for index, domain in enumerate(
            remaining,
            start=1,
        ):

            print(
                f"\n[{index}/{len(remaining)}] "
                f"{domain}"
            )

            calls_before = api_calls

            try:

                rows = fetch_domain(
                    domain,
                    args.since,
                    args.until,
                    args.delay,
                    raw_dir=args.raw_dir,
                )

            except Exception as e:

                # Not marked done, so it is retried next run.
                print(
                    f"    ERROR: {e}"
                )
                continue

            print(
                f"    Got {len(rows)} measurements."
            )

            # Deduplicate measurements using UID.
            seen = set()

            for row in rows:
                uid = row.get("measurement_uid")

                if uid in seen:
                    continue

                seen.add(uid)
                writer.writerow(row)

            # Append rows and the done-marker together so an
            # interruption never leaves a half-written domain marked
            # as complete.
            out.flush()
            done.write(domain + "\n")
            done.flush()

            if api_calls > calls_before:
                time.sleep(args.delay)

    print(f"\nFinished ({api_calls} API requests, the rest from {args.raw_dir}).")
    print(
        f"Output written to: {args.output}"
    )


if __name__ == "__main__":
    main()
