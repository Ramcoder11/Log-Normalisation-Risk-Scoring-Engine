import pandas as pd
import sys
from datetime import datetime

# ----------------------------
# CONFIG
# ----------------------------
REQUIRED_COLUMNS = [
    "asset_id",
    "asset_type",
    "severity",
    "source",
    "timestamp",
    "vuln_id",
    "exploit_available"
]

# ----------------------------
# NORMALIZATION FUNCTION
# ----------------------------
def normalize_df(df):
    print("[*] Starting normalization...")

    # Possible raw -> standard mappings
    column_mapping = {
        "AssetID": "asset_id",
        "Host": "asset_id",
        "Hostname": "asset_id",
        "Device": "asset_id",
        "IP": "asset_id",

        "Type": "asset_type",
        "AssetType": "asset_type",
        "Asset_Type": "asset_type",
        "Category": "asset_type",

        "Severity": "severity",
        "SeverityLevel": "severity",
        "Risk": "severity",

        "Scanner": "source",
        "Tool": "source",
        "Source": "source",

        "Time": "timestamp",
        "Timestamp": "timestamp",
        "Date": "timestamp",

        "VulnID": "vuln_id",
        "CVE": "vuln_id",
        "PluginID": "vuln_id",
        "Vulnerability": "vuln_id",

        "Exploit": "exploit_available",
        "ExploitAvailable": "exploit_available"
    }

    # Rename detected columns
    df = df.rename(columns={k: v for k, v in column_mapping.items() if k in df.columns})

    print("[*] Columns after rename:", df.columns.tolist())

    # Handle missing optional columns
    if "exploit_available" not in df.columns:
        df["exploit_available"] = False

    # Validate required columns
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"[!] Missing required columns: {missing}")

    # Normalize values
    df["severity"] = df["severity"].astype(str).str.lower().str.strip()
    df["source"] = df["source"].astype(str).str.strip()
    df["asset_type"] = df["asset_type"].astype(str).str.strip()

    # Convert timestamp safely
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # Handle missing timestamps
    df["timestamp"] = df["timestamp"].fillna(datetime.utcnow())

    print("[+] Normalization complete.")
    return df

# ----------------------------
# RISK SCORING
# ----------------------------
def calculate_risk(df):
    print("[*] Calculating risk scores...")

    severity_map = {
        "critical": 10,
        "high": 8,
        "medium": 5,
        "low": 2,
        "info": 1
    }

    def score(row):
        base = severity_map.get(str(row["severity"]).lower(), 1)
        exploit_bonus = 2 if str(row["exploit_available"]).lower() in ["true", "1", "yes"] else 0
        return min(base + exploit_bonus, 10)

    df["risk_score"] = df.apply(score, axis=1)

    print("[+] Risk scoring complete.")
    return df

# ----------------------------
# MAIN
# ----------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python ingest.py <input_file.csv>")
        sys.exit(1)

    input_file = sys.argv[1]
    print(f"[*] Loading file: {input_file}")

    try:
        df = pd.read_csv(input_file)
    except Exception as e:
        print(f"[!] Failed to load file: {e}")
        sys.exit(1)

    print("[*] Raw columns:", df.columns.tolist())

    try:
        df = normalize_df(df)
        df = calculate_risk(df)
    except Exception as e:
        print(f"[!] Processing failed: {e}")
        sys.exit(1)

    output_file = "normalized_output.csv"
    df.to_csv(output_file, index=False)

    print(f"[+] Done. Output saved to: {output_file}")

if __name__ == "__main__":
    main()
