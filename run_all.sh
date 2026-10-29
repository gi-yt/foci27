#!/usr/bin/env bash
#
# Reproduce every analysis output and findings file from the data in csv/
# and domain_classification/.
#
#   ./run_all.sh           analysis only (uses the CSVs already in csv/)
#   ./run_all.sh --fetch   also fetch from the OONI API whatever is missing
#                          (everything: several hours; nothing: seconds)
#
# Needs uv (https://docs.astral.sh/uv/). The only Python dependency is
# tldextract, pinned to the version the results were produced with; its
# bundled Public Suffix List snapshot decides apex domains.

set -euo pipefail

cd "$(dirname "$0")"
mkdir -p logs

py() {
    env -u VIRTUAL_ENV PYTHONUNBUFFERED=1 uv run -q --no-project --python 3.13 \
        --with tldextract==5.4.0 \
        python "$@"
}

echo "== Common domains (OONI test list x Poisoned Wells, by apex domain)"
py scripts/find_common_domains.py > /dev/null

# Fetch only what is missing:
#   - measurement pages already saved in source_data_*/ are read from disk,
#     so a deleted measurement CSV is rebuilt without API calls;
#   - a measurement CSV that exists without a .done file is complete and
#     is left alone (delete it to rebuild it from source_data_*/);
#   - raw-measurement fetches resume, skipping measurements already in
#     their CSVs;
#   - the blocked-results fetch is skipped if its CSVs exist.
# Logs are appended to, so earlier fetch history is kept.

measurements() {
    local out=$1 raw=$2
    shift 2
    if [[ -f "$out" && ! -f "$out.done" ]]; then
        echo "   $out already complete, not fetching"
        return
    fi
    py scripts/fetch_ooni_data.py domain_classification/sanitized_domain.txt \
        -o "$out" --raw-dir "$raw" "$@"
}

if [[ "${1:-}" == "--fetch" ]]; then
    echo "== Fetching OONI measurements for the common domains (2025 PW period)"
    measurements csv/ooni_data_2025.csv source_data_2025 2>&1 | tee -a logs/fetch_2025.log

    echo "== Fetching raw measurements for non-DNS anomalies"
    py scripts/fetch_ooni_raw.py 2>&1 | tee -a logs/fetch_raw_2025.log

    echo "== Fetching resolver, software, test version and platform for every report"
    py scripts/fetch_ooni_raw.py --report-meta 2>&1 | tee -a logs/fetch_report_meta_2025.log

    echo "== Fetching 2026 OONI measurements (one week, fixed dates)"
    measurements csv/ooni_data_2026.csv source_data_2026 \
        --since 2026-10-14T00:00:00 --until 2026-10-21T00:00:00 2>&1 | tee -a logs/fetch_2026.log
    py scripts/fetch_ooni_raw.py --ooni csv/ooni_data_2026.csv --window all \
        -o csv/ooni_raw_details_2026.csv 2>&1 | tee -a logs/fetch_raw_2026.log
    py scripts/fetch_ooni_raw.py --ooni csv/ooni_data_2026.csv --window all --report-meta \
        -o csv/ooni_report_meta_2026.csv 2>&1 | tee -a logs/fetch_report_meta_2026.log
fi

echo "== Comparing 2025 OONI data with Poisoned Wells (PW windows)"
py scripts/compare_ooni_dnsblocks.py

echo "== Comparing 2026 OONI data (this week) with Poisoned Wells"
py scripts/compare_ooni_dnsblocks.py --ooni csv/ooni_data_2026.csv --window all

echo "== Mixed results per domain+ISP"
py scripts/mixed_details.py

echo "== Every blocked OONI result on the study ASNs"
if [[ "${1:-}" == "--fetch" ]] && ! [[ -f csv/ooni_blocked_2025_totals.csv && -f csv/ooni_blocked_2025_measurements.csv ]]; then
    py scripts/find_ooni_blocked.py 2>&1 | tee -a logs/find_blocked_2025.log
else
    py scripts/find_ooni_blocked.py --skip-fetch > /dev/null
fi

echo "== ISP vs public resolver split"
py scripts/resolver_split.py > /dev/null
py scripts/resolver_split.py --ooni csv/ooni_data_2026.csv --window all \
    --raw csv/ooni_report_meta_2026.csv --label "2026, this week" \
    --csv csv/resolver_split_2026.csv --act-asn-csv csv/resolver_split_act_asn_2026.csv \
    --txt resolver_split_2026.txt > /dev/null

echo "== OONI probes, software and test versions"
py scripts/probe_metadata.py > /dev/null
py scripts/probe_metadata.py --ooni csv/ooni_data_2026.csv --window all \
    --meta csv/ooni_report_meta_2026.csv --label "2026, this week" \
    --summary-csv csv/probe_summary_2026.csv --weighted-csv csv/probe_weighted_2026.csv \
    --txt probe_metadata_2026.txt > /dev/null

echo "== 2025 vs 2026"
py scripts/drift.py > /dev/null

echo "== Verdict cutoff robustness and category test"
py scripts/robustness.py > /dev/null
py scripts/category_test.py > /dev/null

echo "== Findings files"
py scripts/make_findings.py

echo "Done."
