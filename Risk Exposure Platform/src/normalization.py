import pandas as pd
import re
import sys

# ==========================================================
# Source-type schema definitions
# ==========================================================
#
# Instead of one universal fuzzy matcher trying to guess every field for
# every possible log format, we detect which FAMILY of log this is
# (Windows Security event, Linux auth log, or unknown/generic), then use
# a field-mapping schema specific to that family. Each field maps to an
# ordered list of REGEX patterns (not literal column names) so we match
# naming *conventions* ("SubjectUserName", "subject_user_name", "Subject
# User Name" all match one pattern) rather than memorizing every exact
# header string we've personally encountered. This is the same idea
# real SIEM normalization pipelines use (e.g. Splunk CIM, Elastic ECS):
# source-aware schema mapping instead of one generic guesser.
#
# Patterns are tried in order; the first pattern that matches ANY column
# wins (earlier/more specific patterns take priority over later/broader
# ones). This avoids the earlier bug where a generic keyword like
# "source" could steal a column meant for something else.

SOURCE_SCHEMAS = {

    "windows_security": {
        "asset_id": [r"^computer$", r"hostname", r"host", r"machine"],
        "asset_type": [r"^channel$", r"^logname$"],
        "asset_type_default": "windows_event",
        "vulnerability_id": [r"^eventid$", r"event.?id"],
        "owner": [r"subjectusername", r"targetusername",
                  r"account.?name", r"user", r"login"],
        "severity": [r"^level$", r"severity"],
        "timestamp": [r"timecreated", r"time", r"date", r"utc"],
    },

    "linux_auth": {
        "asset_id": [r"hostname", r"host", r"machine", r"asset"],
        "asset_type": [r"^facility$", r"^source$", r"^process$"],
        "asset_type_default": "linux_event",
        "vulnerability_id": [r"vuln", r"event.?id", r"rule.?id",
                              r"signature.?id", r"rule",
                              r"signature", r"^id$"],
        "owner": [r"user", r"account", r"subject", r"login"],
        "severity": [r"severity", r"priority", r"level"],
        "timestamp": [r"time", r"date", r"utc", r"created"],
    },

    # Fallback for anything that doesn't clearly match a known source
    # family. Broader patterns, same spirit as the original matcher.
    "generic": {
        "asset_id": [r"asset", r"host", r"computer", r"machine"],
        "asset_type": [r"asset.?type", r"platform", r"category", r"source"],
        "asset_type_default": "generic_event",
        "vulnerability_id": [r"vuln", r"event.?id", r"cve",
                              r"rule", r"signature", r"event"],
        "owner": [r"user", r"account", r"subject", r"login"],
        "severity": [r"severity", r"priority", r"level"],
        "timestamp": [r"time", r"date", r"utc", r"created"],
    },
}


# ==========================================================
# Regex-based column resolver (canonical → source-schema regex → default)
# ==========================================================

def regex_get(df, canonical, patterns, default):
    """
    Resolve a field's source column using, in priority order:
    1. An exact canonical column name, if present.
    2. The first regex pattern (in list order) that matches any column
       name, case-insensitive.
    3. A default value/Series if nothing matches.
    """
    if canonical in df.columns:
        return df[canonical]

    for pattern in patterns:
        for col in df.columns:
            if re.search(pattern, col, re.IGNORECASE):
                return df[col]

    return pd.Series([default] * len(df), index=df.index)


# ==========================================================
# Detect source-log family (Windows Security / Linux auth / generic)
# ==========================================================

def detect_source_type(df):
    cols = [c.lower() for c in df.columns]

    has_eventid = any(re.search(r"event.?id", c) for c in cols)
    has_win_marker = any(
        re.search(r"channel|logname|provider|computer", c) for c in cols
    )
    if has_eventid and has_win_marker:
        return "windows_security"

    has_linux_marker = any(
        re.search(r"facility|syslog|pam|process|pid", c) for c in cols
    )
    has_hostname = any(re.search(r"hostname", c) for c in cols)
    if has_linux_marker or (has_hostname and not has_win_marker):
        return "linux_auth"

    return "generic"


# ==========================================================
# Detect input type: RAW logs vs already-ENRICHED/scored data
# ==========================================================

def detect_mode(df):
    enriched_indicators = {
        "risk_score", "likelihood", "business_impact", "severity_score"
    }
    if enriched_indicators.intersection(set(df.columns)):
        return "ENRICHED"
    return "RAW"


# ==========================================================
# Normalization Logic
# ==========================================================

def normalize_evtx(df_raw: pd.DataFrame) -> pd.DataFrame:

    if df_raw is None or df_raw.empty:
        return pd.DataFrame()

    mode = detect_mode(df_raw)
    source_type = detect_source_type(df_raw)
    schema = SOURCE_SCHEMAS[source_type]

    print(f"🔍 Detected input mode: {mode}")
    print(f"🔍 Detected source type: {source_type}")

    df = pd.DataFrame(index=df_raw.index)

    # ---------------------------
    # Asset
    # ---------------------------
    df["asset_id"] = (
        regex_get(df_raw, canonical="asset_id",
                  patterns=schema["asset_id"], default="UNKNOWN")
        .astype(str)
        .fillna("UNKNOWN")
    )

    df["asset_type"] = (
        regex_get(df_raw, canonical="asset_type",
                  patterns=schema["asset_type"],
                  default=schema["asset_type_default"])
        .astype(str)
        .replace({"nan": None, "None": None})
        .fillna(schema["asset_type_default"])
    )

    # ---------------------------
    # Vulnerability / Event ID
    # ---------------------------
    df["vulnerability_id"] = (
        regex_get(df_raw, canonical="vuln_id",
                  patterns=schema["vulnerability_id"], default="N/A")
        .astype(str)
        .fillna("N/A")
    )

    # ---------------------------
    # Severity
    # ---------------------------
    sev_raw = regex_get(df_raw, canonical="severity",
                         patterns=schema["severity"], default=1)

    sev_num = pd.to_numeric(sev_raw, errors="coerce")

    if sev_num.isna().all():
        sev_map = {
            "info": 1,
            "information": 1,
            "warning": 3,
            "error": 6,
            "critical": 9,
            "fatal": 9,
        }
        sev_num = sev_raw.astype(str).str.lower().map(sev_map)

    df["severity"] = sev_num.fillna(1).clip(1, 10).astype(int)

    # ---------------------------
    # Timestamp
    # ---------------------------
    df["last_detected"] = pd.to_datetime(
        regex_get(df_raw, canonical="timestamp",
                  patterns=schema["timestamp"], default=None),
        errors="coerce",
        utc=True,
    )

    # ---------------------------
    # Owner / User (may not exist)
    # ---------------------------
    df["owner"] = (
        regex_get(df_raw, canonical="owner",
                  patterns=schema["owner"], default="UNKNOWN")
        .astype(str)
        .fillna("UNKNOWN")
    )

    # ==========================================================
    # Threat likelihood
    # ==========================================================
    if mode == "ENRICHED":
        df["threat_likelihood"] = (
            pd.to_numeric(
                regex_get(df_raw, canonical="likelihood",
                          patterns=[r"likelihood", r"probability"],
                          default=1),
                errors="coerce",
            )
            .fillna(1)
            .clip(1, 5)
            .astype(int)
        )
    else:
        event_freq = (
            df.groupby("vulnerability_id")["vulnerability_id"]
            .transform("count")
        )

        # Bin directly on event_freq itself. duplicates='drop' means
        # qcut won't fabricate more bins than the data actually
        # supports. If there isn't enough genuine variance to form
        # multiple bins (e.g. only one distinct frequency value), fall
        # back to a single neutral likelihood rather than faking a
        # distribution from arbitrary row order.
        try:
            df["threat_likelihood"] = (
                pd.qcut(
                    event_freq, 5, labels=[1, 2, 3, 4, 5],
                    duplicates="drop"
                )
                .astype(int)
            )
        except (ValueError, TypeError):
            df["threat_likelihood"] = 1

    # ==========================================================
    # Business impact
    # ==========================================================
    if mode == "ENRICHED":
        df["business_impact"] = (
            pd.to_numeric(
                regex_get(df_raw, canonical="business_impact",
                          patterns=[r"impact", r"criticality"],
                          default=1),
                errors="coerce",
            )
            .fillna(1)
            .clip(1, 5)
            .astype(int)
        )
    else:
        df["business_impact"] = (
            (df["asset_id"] != "UNKNOWN").astype(int) * 2
            + (df["owner"] != "UNKNOWN").astype(int) * 2
            + 1
        ).clip(1, 5)

    # ==========================================================
    # Risk calculation
    # ==========================================================
    df["raw_risk"] = (
        df["severity"] * df["threat_likelihood"] * df["business_impact"]
    )

    # Scale against the fixed theoretical maximum (severity 1-10,
    # threat_likelihood 1-5, business_impact 1-5) rather than this
    # file's own min/max, so a file with uniform risk doesn't collapse
    # to 0.0, and scores stay comparable across different uploaded files.
    MAX_POSSIBLE_RISK = 10 * 5 * 5

    df["normalized_risk"] = (df["raw_risk"] / MAX_POSSIBLE_RISK).round(4)

    # ==========================================================
    # Confidence score
    # ==========================================================
    df["confidence"] = (
        (df["asset_id"] != "UNKNOWN").astype(int)
        + (df["owner"] != "UNKNOWN").astype(int)
        + df["last_detected"].notna().astype(int)
    ) / 3

    # ==========================================================
    # Final schema
    # ==========================================================
    return df[[
        "asset_id",
        "asset_type",
        "vulnerability_id",
        "severity",
        "threat_likelihood",
        "business_impact",
        "last_detected",
        "owner",
        "normalized_risk",
        "confidence",
    ]]


# ==========================================================
# Main Execution
# ==========================================================
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python normalization.py <input_csv>")
        raise SystemExit(1)

    input_file = sys.argv[1]

    try:
        df_raw = pd.read_csv(input_file, low_memory=False)
    except FileNotFoundError:
        print(f"❌ ERROR: {input_file} not found")
        raise SystemExit(1)

    print(f"Loaded input file: {input_file}")
    print("Input Columns Detected:")
    print(df_raw.columns.tolist())

    df_norm = normalize_evtx(df_raw)

    print("\nNormalized Output (first 10 rows):")
    print(df_norm.head(10))

    print("\nRisk Summary:")
    print(df_norm["normalized_risk"].describe())

    print("\nConfidence Summary:")
    print(df_norm["confidence"].describe())

    df_norm.to_csv("normalized_output.csv", index=False)
    print("\nExported as normalized_output.csv")