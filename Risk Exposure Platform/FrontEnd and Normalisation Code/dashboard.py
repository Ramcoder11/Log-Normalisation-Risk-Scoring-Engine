import streamlit as st
import pandas as pd
from normalization import normalize_evtx

# ==========================================================
# PAGE CONFIG
# ==========================================================
st.set_page_config(
    page_title="CCTS Log Normalization Engine",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================================
# CUSTOM CSS FOR CYBER THEME + BUTTON HOVER WITH BLACK TEXT
# ==========================================================
st.markdown("""
<style>

/* Main background: cool mid-tone gradient */
.stApp {
    background: linear-gradient(135deg, #1e3c72, #2a5298, #4b6cb7, #6a89cc);
    color: #ffffff;
    background-attachment: fixed;
}

/* Title */
h1 {
    font-size: 2.5rem !important;
    font-weight: 700 !important;
    text-align: center;
    color: #00ffe0; /* neon cyan-green */
    text-shadow: 1px 1px 5px rgba(0,0,0,0.6);
}

/* Page padding */
.block-container {
    padding-top: 2rem;
}

/* File uploader: black text + hover glow */
[data-testid="stFileUploader"] {
    background: rgba(255, 255, 255, 0.15);
    border-radius: 12px;
    padding: 1rem;
    border: 1px solid rgba(0, 255, 224, 0.5);
    color: #000000;  /* black text */
    transition: background 0.3s ease;
}
[data-testid="stFileUploader"]:hover {
    background: rgba(0, 255, 224, 0.15);  /* hover glow */
}

/* Buttons (normal) */
.stButton>button {
    background: linear-gradient(90deg, #00ffe0, #0066ff);
    color: black;  /* black text */
    border-radius: 10px;
    border: none;
    font-weight: 600;
    transition: background 0.3s ease;
}
.stButton>button:hover {
    background: linear-gradient(90deg, #00ffe0cc, #0066ffcc); /* hover glow */
}

/* Dataframe */
[data-testid="stDataFrame"] {
    background: rgba(255,255,255,0.08);
    border-radius: 12px;
    color: #ffffff;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: rgba(0, 255, 224, 0.12);
    padding: 1rem;
    border-radius: 12px;
    border: 1px solid rgba(0, 255, 224, 0.3);
    color: #ffffff;
}

/* Download button: black text + hover glow */
.stDownloadButton > button {
    background: rgba(255, 255, 255, 0.15) !important;
    border-radius: 12px !important;
    border: 1px solid rgba(0, 255, 224, 0.5) !important;
    color: black !important;  /* black text */
    padding: 0.8rem 1rem !important;
    font-weight: 600;
    transition: background 0.3s ease;
}
.stDownloadButton > button:hover {
    background: rgba(0, 255, 224, 0.15) !important;  /* hover glow */
}
.stDownloadButton > button[title] {
    pointer-events: auto;
    title: none !important;
}
.stDownloadButton > button[title]:hover::after {
    content: none !important;
}

</style>
""", unsafe_allow_html=True)

# ==========================================================
# HEADER
# ==========================================================
st.markdown("""
<h1>🛡️ CCTS Log Normalization & Risk Engine</h1>
<p style="text-align:center; font-size:1.1rem;">
Upload any security log (Windows, EVTX, CSV) and normalize it into a unified risk model.
</p>
""", unsafe_allow_html=True)

# ==========================================================
# FILE UPLOAD
# ==========================================================
uploaded_file = st.file_uploader(
    "📂 Upload log file (CSV)",
    type=["csv"]
)

if uploaded_file:
    try:
        df_raw = pd.read_csv(uploaded_file, low_memory=False)

        st.success("✅ File loaded successfully")

        # Preview
        with st.expander("🔍 Raw Data Preview"):
            st.dataframe(df_raw.head(20), use_container_width=True)

        # Normalize
        df_norm = normalize_evtx(df_raw)

        # Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Events", len(df_norm))
        col2.metric("Avg Risk", round(df_norm['normalized_risk'].mean(), 3))
        col3.metric("Max Risk", round(df_norm['normalized_risk'].max(), 3))

        # Output
        st.subheader("📊 Normalized Output")
        st.dataframe(df_norm, use_container_width=True)

        # Download
        csv = df_norm.to_csv(index=False).encode('utf-8')
        st.download_button(
            "⬇️ Download Normalized CSV",
            csv,
            "normalized_output.csv",
            "text/csv"
        )

    except Exception as e:
        st.error(f"❌ Error processing file: {e}")

else:
    pass  # no message shown when no file uploaded
