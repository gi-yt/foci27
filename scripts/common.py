"""
Shared helpers: CSV I/O, HTTP, apex-domain extraction (tldextract) and
loading the Poisoned Wells, test-list and OONI datasets. Apart from
tldextract, standard library only.
"""

import csv
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import tldextract

from paths import DNSBLOCKS_FILE, TESTLIST_FILE

csv.field_size_limit(1 << 24)


# --------------------------------------------------
# Study configuration
# --------------------------------------------------

# All ASNs attributed to each ISP. Blocking is assumed (not proven) to be
# ISP-wide; the per-ASN outputs let you check.
ISP_ASNS = {
    "JIO": [55836],
    "ACT": [18209, 24309, 55577, 131269],
    "YOU": [18207],
    "MTNL": [17813],
    "AIRTEL": [9498, 24560, 45609],
    "CONNECT": [17917],
}

# The single ASN Poisoned Wells measured per ISP (report, Table 3).
PW_ASN = {
    "JIO": 55836,
    "ACT": 18209,
    "YOU": 18207,
    "MTNL": 17813,
    "AIRTEL": 9498,
    "CONNECT": 17917,
}

# Where each ASN's customers are. ACT is split regionally (from ipinfo
# geolocation of a sample of announced prefixes, Oct 2026); the others are
# single national/state ASNs, so regional differences inside them are
# invisible at the ASN level.
ASN_REGION = {
    55836: "national (mobile + JioFiber)",
    9498: "national (backbone/enterprise)",
    24560: "national (home broadband)",
    45609: "national (mobile)",
    18209: "Delhi, Hyderabad, Jaipur, Lucknow",
    24309: "Bengaluru, Chennai",
    55577: "Hyderabad / Telangana",
    131269: "Andhra Pradesh, Coimbatore",
    17813: "Delhi, Mumbai",
    18207: "Maharashtra",
    17917: "Punjab",
}

# Poisoned Wells measurement window per ISP (report, Table 19).
PW_WINDOW = {
    "ACT": ("2025-03-09", "2025-04-01"),
    "JIO": ("2025-03-09", "2025-03-29"),
    "AIRTEL": ("2025-03-11", "2025-04-10"),
    "MTNL": ("2025-04-12", "2025-05-23"),
    "YOU": ("2025-04-21", "2025-09-09"),
    "CONNECT": ("2025-04-22", "2025-06-17"),
}

DNS_ISPS = list(ISP_ASNS)

BLOCKING_TYPES = ["dns", "http-failure", "http-diff", "tcp_ip"]

ASN_TO_ISP = {asn: isp for isp, asns in ISP_ASNS.items() for asn in asns}

ISP_NAMES = {
    "JIO": "Jio",
    "AIRTEL": "Airtel",
    "ACT": "ACT",
    "MTNL": "MTNL",
    "YOU": "You",
    "CONNECT": "Connect",
}


# --------------------------------------------------
# HTTP (OONI API)
# --------------------------------------------------

USER_AGENT = "InternetChowkidar-OONI-Research/1.0"


def get_json(url, params=None, retries=5, backoff=5, timeout=60):
    """
    GET a JSON API response. Rate limiting (429), server errors and network
    errors are retried with a growing wait; other client errors won't
    succeed on retry, so they raise with the API's explanation.
    """

    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            if e.code != 429 and e.code < 500:
                body = e.read()[:300].decode("utf-8", "replace")
                raise RuntimeError(f"HTTP {e.code}: {body}") from None
            problem = "Rate limited" if e.code == 429 else f"Server error {e.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
            if attempt == retries:
                raise
            problem = f"Request failed: {e}"

        wait = backoff * attempt
        print(f"{problem}. Waiting {wait}s...")
        time.sleep(wait)

    raise RuntimeError("Request failed after retries.")


# --------------------------------------------------
# CSV
# --------------------------------------------------

def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: fmt_cell(row.get(k)) for k in fields})


def fmt_cell(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        if value != value:  # NaN
            return ""
        return repr(value)
    return value


# --------------------------------------------------
# Apex (registrable) domains
# --------------------------------------------------

# Avoid downloading the Public Suffix List at runtime: use the snapshot
# bundled with tldextract (pinned in run_all.sh).
_extractor = tldextract.TLDExtract(suffix_list_urls=())


def registrable_domain(value):
    """
    example.com for https://www.example.com/path, sub.example.co.uk, ...;
    the input unchanged when it has no public suffix (IPs, bare labels).
    """

    if value is None:
        return None
    value = str(value).strip().lower()
    if not value or value == "nan":
        return None

    # Handle URLs such as https://www.example.com/path
    if "://" in value:
        value = urlparse(value).hostname or ""

    # Handle bare hostnames and accidental paths
    value = value.split("/")[0].split(":")[0].rstrip(".")

    extracted = _extractor(value)
    if not extracted.domain or not extracted.suffix:
        return value
    return f"{extracted.domain}.{extracted.suffix}"


# --------------------------------------------------
# Datasets
# --------------------------------------------------

def classify_dnsblocks(value):
    if value is None or value in ("", "NAN", "NONE"):
        return "unknown"
    value = str(value).strip().upper()
    return {"1": "blocked", "0": "not_blocked"}.get(value, value.lower())


def load_dnsblocks():
    """
    Poisoned Wells rows with the domain reduced to its apex, ISP values
    upper-cased, and category/tranco_rank renamed pw_category/pw_tranco_rank.
    """

    rows = read_csv(DNSBLOCKS_FILE)
    for r in rows:
        r["domain"] = registrable_domain(r["domain"])
        for isp in DNS_ISPS:
            r[isp] = r[isp].strip().upper()
        r["pw_category"] = r.pop("category")
        r["pw_tranco_rank"] = r.pop("tranco_rank")
    return rows


def pw_lookup(dns=None):
    """
    {(domain, isp): {pw_value, pw_status, pw_category, pw_tranco_rank}}
    """

    dns = dns if dns is not None else load_dnsblocks()
    out = {}
    for r in dns:
        for isp in DNS_ISPS:
            out[(r["domain"], isp)] = {
                "pw_value": r[isp],
                "pw_status": classify_dnsblocks(r[isp]),
                "pw_category": r["pw_category"],
                "pw_tranco_rank": r["pw_tranco_rank"],
            }
    return out


def load_testlist_rows():
    rows = read_csv(TESTLIST_FILE)
    for r in rows:
        r["apex"] = registrable_domain(r["url"])
        host = re.search(r"://([^/:]+)", r["url"])
        r["host"] = host.group(1).lower().rstrip(".") if host else None
    return rows


def load_testlist():
    """
    {apex domain: "CAT1;CAT2"} from the OONI test list.
    """

    cats = defaultdict(set)
    for r in load_testlist_rows():
        if r["apex"] is None:
            continue
        cats[r["apex"]]
        if r["category_code"]:
            cats[r["apex"]].add(r["category_code"])
    return {apex: ";".join(sorted(c)) for apex, c in cats.items()}


def parse_bool(value):
    return str(value).strip().lower() in ("true", "1")


def parse_time(value):
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc)


def asn_number(value):
    value = str(value or "").upper().replace("AS", "").strip()
    return int(value) if value.isdigit() else None


def load_ooni(path):
    """
    OONI web_connectivity measurements in India on a study ASN, with:
      hostname  tested hostname;  domain  its apex
      asn (int), isp, on_pw_asn, time (datetime), month (YYYY-MM)
      outcome   confirmed / anomaly / failure / ok (mutually exclusive)
    """

    rows, seen = [], set()
    for r in read_csv(path):
        if r["probe_cc"].upper() != "IN" or r["test_name"] != "web_connectivity":
            continue
        # The fetcher can append a domain twice if interrupted.
        if r["measurement_uid"] in seen:
            continue
        seen.add(r["measurement_uid"])

        asn = asn_number(r["probe_asn"])
        isp = ASN_TO_ISP.get(asn)
        if isp is None:
            continue

        r["hostname"] = urlparse(r["input"]).hostname
        r["domain"] = registrable_domain(r["domain"])
        r["asn"] = asn
        r["isp"] = isp
        r["on_pw_asn"] = asn == PW_ASN[isp]
        for col in ("confirmed", "anomaly", "failure"):
            r[col] = parse_bool(r[col])
        r["time"] = parse_time(r["measurement_start_time"])
        r["month"] = r["time"].strftime("%Y-%m") if r["time"] else None

        outcome = "ok"
        if r["failure"]:
            outcome = "failure"
        if r["anomaly"]:
            outcome = "anomaly"
        if r["confirmed"]:
            outcome = "confirmed"
        r["outcome"] = outcome
        r["blocked"] = outcome in ("anomaly", "confirmed")
        r["blocking_type"] = r["blocking_type"] or ""
        rows.append(r)
    return rows


def apply_window(rows, margin_days):
    """
    Keep measurements inside their ISP's Poisoned Wells window +/- margin.
    """

    margin = timedelta(days=margin_days)
    bounds = {}
    for isp, (start, end) in PW_WINDOW.items():
        lo = datetime.fromisoformat(start).replace(tzinfo=timezone.utc) - margin
        # Window end dates are inclusive.
        hi = datetime.fromisoformat(end).replace(tzinfo=timezone.utc) + timedelta(days=1) + margin
        bounds[isp] = (lo, hi)

    return [
        r for r in rows
        if r["time"] is not None and bounds[r["isp"]][0] <= r["time"] < bounds[r["isp"]][1]
    ]


# --------------------------------------------------
# Small aggregation helpers
# --------------------------------------------------

def group_by(rows, *keys):
    groups = defaultdict(list)
    for r in rows:
        groups[tuple(r[k] for k in keys)].append(r)
    return groups


def count_by(rows, key):
    return Counter(r[key] if not callable(key) else key(r) for r in rows)


# --------------------------------------------------
# Domain x ISP aggregation, verdicts and agreement labels
# --------------------------------------------------

COUNT_FIELDS = [
    "n_ok",
    "n_anomaly",
    "n_confirmed",
    "n_failure",
    *("n_" + bt.replace("-", "_") for bt in BLOCKING_TYPES),
    "n_on_pw_asn",
]
AGG_FIELDS = COUNT_FIELDS + ["n_total", "asns", "hostnames", "first_seen", "last_seen"]
VERDICT_FIELDS = [
    "n_usable",
    "block_share",
    "confirmed_share",
    "dominant_blocking_type",
    "ooni_verdict",
    "low_confidence",
]
PW_FIELDS = ["pw_category", "pw_tranco_rank", "pw_value", "pw_status"]

AGREEMENT_LABELS = [
    "agree_blocked",
    "agree_ok",
    "pw_blocked/ooni_mixed",
    "pw_ok/ooni_mixed",
    "ooni_only_blocked",
    "pw_only_blocked",
]


def np_round(x, decimals):
    """
    Round like numpy/pandas: scale, round half to even, unscale.
    """

    scale = 10 ** decimals
    return round(x * scale) / scale


def aggregate(rows, keys):
    """
    {key tuple: row} counting outcomes and blocking types per group.
    """

    out = {}
    for key, g in group_by(rows, *keys).items():
        a = dict(zip(keys, key))
        outcomes = Counter(r["outcome"] for r in g)
        for o in ("ok", "anomaly", "confirmed", "failure"):
            a[f"n_{o}"] = outcomes[o]
        for bt in BLOCKING_TYPES:
            a["n_" + bt.replace("-", "_")] = sum(
                1 for r in g if r["blocked"] and r["blocking_type"] == bt
            )
        a["n_on_pw_asn"] = sum(r["on_pw_asn"] for r in g)
        a["n_total"] = len(g)
        a["asns"] = ";".join(str(x) for x in sorted({r["asn"] for r in g}))
        a["hostnames"] = ";".join(sorted({r["hostname"] for r in g if r["hostname"]}))
        times = [r["time"] for r in g if r["time"] is not None]
        a["first_seen"] = str(min(times)) if times else None
        a["last_seen"] = str(max(times)) if times else None
        out[key] = a
    return out


def empty_counts():
    return {**{f: 0 for f in COUNT_FIELDS}, "n_total": 0}


def add_verdicts(row, ok_max=0.1, blocked_min=0.9, min_measurements=3):
    usable = row["n_total"] - row["n_failure"]
    blocked = row["n_anomaly"] + row["n_confirmed"]

    row["n_usable"] = usable
    row["block_share"] = np_round(blocked / usable, 4) if usable else None
    row["confirmed_share"] = np_round(row["n_confirmed"] / usable, 4) if usable else None

    best, best_n = "", 0
    for bt in BLOCKING_TYPES:
        col = bt.replace("-", "_")
        if row["n_" + col] > best_n:
            best, best_n = col, row["n_" + col]
    row["dominant_blocking_type"] = best

    share = row["block_share"]
    verdict = "mixed"
    if share is not None and share <= ok_max:
        verdict = "ok" # Not Blocked if less than 10% (def) is blocked state
    if share is not None and share >= blocked_min:
        verdict = "blocked"
    if usable == 0 and row["n_total"] > 0:
        verdict = "failures_only"
    if row["n_total"] == 0:
        verdict = "no_data"
    row["ooni_verdict"] = verdict
    row["low_confidence"] = 0 < usable < min_measurements
    return row


def agreement_label(pw_status, verdict):
    """
    Combine the Poisoned Wells value and OONI verdict into one label.
    """

    if verdict in ("no_data", "failures_only"):
        return "no_usable_ooni_data"
    labels = {
        ("blocked", "blocked"): "agree_blocked",
        ("not_blocked", "ok"): "agree_ok",
        # RQ2: blocked per PW, but OONI sees it as reachable.
        ("blocked", "ok"): "pw_only_blocked",
        ("not_blocked", "blocked"): "ooni_only_blocked",
        ("blocked", "mixed"): "pw_blocked/ooni_mixed",
        ("not_blocked", "mixed"): "pw_ok/ooni_mixed",
    }
    return labels.get((pw_status, verdict), f"pw_{pw_status}/ooni_{verdict}")


def add_agreement(row):
    row["agreement"] = agreement_label(row["pw_status"], row["ooni_verdict"])
    return row

# TODO: wtf is a crosstab man
def crosstab(rows, row_key, col_key, margins=False):
    """
    (row labels, column labels, {(r, c): count}) with sorted labels, like
    pandas.crosstab; with margins an "All" row and column are added.
    """

    counts = Counter((row_key(r), col_key(r)) for r in rows)
    rlabels = sorted({k[0] for k in counts})
    clabels = sorted({k[1] for k in counts})
    if margins:
        for r in rlabels:
            counts[(r, "All")] = sum(counts[(r, c)] for c in clabels)
        for c in clabels + ["All"]:
            counts[("All", c)] = sum(counts[(r, c)] for r in rlabels)
        rlabels, clabels = rlabels + ["All"], clabels + ["All"]
    return rlabels, clabels, counts


def write_crosstab(path, rows, row_keys, col_key, margins=False):
    """
    Write a crosstab CSV: one column per row key, then one per column label.
    `row_keys` is a list of (name, function) pairs.
    """

    if len(row_keys) == 1:
        rk = row_keys[0][1]
    else:
        rk = lambda r: tuple(f(r) for _, f in row_keys)
    rl, cl, counts = crosstab(rows, rk, col_key, margins)
    out = []
    for r in rl:
        rvals = r if len(row_keys) > 1 else (r,)
        rec = {name: v for (name, _), v in zip(row_keys, rvals)}
        rec.update({c: counts[(r, c)] for c in cl})
        out.append(rec)
    write_csv(path, out, [name for name, _ in row_keys] + cl)
    return rl, cl, counts
