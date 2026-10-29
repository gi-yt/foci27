"""
Repository layout. Every script resolves its default paths from here,
so they work regardless of the current directory.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CSV_DIR = ROOT / "csv"
DOMAINS_DIR = ROOT / "domain_classification"
RESULTS_DIR = ROOT / "comparison_results"
LOGS_DIR = ROOT / "logs"

DNSBLOCKS_FILE = DOMAINS_DIR / "dnsblocksin_blocklist.csv"
TESTLIST_FILE = DOMAINS_DIR / "citizenlab_blocklist_concatenated.csv"
DOMAIN_LIST_FILE = DOMAINS_DIR / "sanitized_domain.txt"

OONI_2025 = CSV_DIR / "ooni_data_2025.csv"
# This week's measurements (2026-10-14 -> 2026-10-21).
OONI_2026 = CSV_DIR / "ooni_data_2026.csv"
RAW_DETAILS_2025 = CSV_DIR / "ooni_raw_details_2025.csv"
REPORT_META_2025 = CSV_DIR / "ooni_report_meta_2025.csv"
RAW_DETAILS_2026 = CSV_DIR / "ooni_raw_details_2026.csv"
REPORT_META_2026 = CSV_DIR / "ooni_report_meta_2026.csv"
BLOCKED_PREFIX_2025 = CSV_DIR / "ooni_blocked_2025"
MIXED_CSV_2025 = CSV_DIR / "mixed_details_2025.csv"
RESOLVER_SPLIT_CSV = CSV_DIR / "resolver_split_2025.csv"
RESOLVER_ACT_ASN_CSV = CSV_DIR / "resolver_split_act_asn_2025.csv"
RESOLVER_SPLIT_CSV_2026 = CSV_DIR / "resolver_split_2026.csv"
RESOLVER_ACT_ASN_CSV_2026 = CSV_DIR / "resolver_split_act_asn_2026.csv"

RESULTS_2025 = RESULTS_DIR / "ooni_data_2025"
RESULTS_2026 = RESULTS_DIR / "ooni_data_2026"

# Human-readable outputs live at the repository root.
MIXED_TXT_2025 = ROOT / "mixed_details_2025.txt"
BLOCKED_SUMMARY_2025 = ROOT / "ooni_blocked_2025_summary.txt"
RESOLVER_SPLIT_TXT = ROOT / "resolver_split_2025.txt"
PROBE_METADATA_TXT = ROOT / "probe_metadata_2025.txt"
RESOLVER_SPLIT_TXT_2026 = ROOT / "resolver_split_2026.txt"
PROBE_METADATA_TXT_2026 = ROOT / "probe_metadata_2026.txt"
DRIFT_TXT = ROOT / "drift_2025_2026.txt"
ROBUSTNESS_TXT = ROOT / "robustness.txt"
CATEGORY_TEST_TXT = ROOT / "category_test.txt"
FINDINGS_ALL = ROOT / "findings_all.txt"
FINDINGS_2025 = ROOT / "findings_2025.txt"

REPORT_PDF = ROOT / "report.pdf"
