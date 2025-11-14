# app_masking.py
import streamlit as st
import pandas as pd
import pyodbc
import re
import logging
import os
import time
from rapidfuzz import fuzz

# ============================================================== 
# SQL Connection
# ============================================================== 
def connect_sql_server(server, database=None, username=None, password=None, trusted=True, timeout=5):
    try:
        if trusted:
            conn_str = (
                "DRIVER={ODBC Driver 18 for SQL Server};"
                f"SERVER={server};"
                f"{'DATABASE=' + database + ';' if database else ''}"
                "Trusted_Connection=yes;TrustServerCertificate=yes;"
                f"Connection Timeout={timeout};"
            )
        else:
            conn_str = (
                "DRIVER={ODBC Driver 18 for SQL Server};"
                f"SERVER={server};"
                f"{'DATABASE=' + database + ';' if database else ''}"
                f"UID={username};PWD={password};TrustServerCertificate=yes;"
                f"Connection Timeout={timeout};"
            )
        return pyodbc.connect(conn_str)
    except Exception:
        return None


def get_all_databases(server, username=None, password=None, trusted=True):
    conn = connect_sql_server(server, None, username, password, trusted)
    if not conn:
        return []
    try:
        df = pd.read_sql("SELECT name FROM sys.databases WHERE database_id > 4;", conn)
        conn.close()
        return df["name"].tolist()
    except Exception:
        return []


# ============================================================== 
# Metadata and Sampling
# ============================================================== 
def extract_metadata(conn):
    query = """
    SELECT
        t.name AS TableName,
        c.name AS ColumnName,
        ty.name AS DataType
    FROM sys.tables t
    INNER JOIN sys.columns c ON t.object_id = c.object_id
    INNER JOIN sys.types ty ON c.user_type_id = ty.user_type_id
    ORDER BY t.name, c.column_id;
    """
    return pd.read_sql(query, conn)


def sample_column_data(conn, table, column, top_n=5):
    try:
        q = f"SELECT TOP {top_n} [{column}] FROM [{table}] WHERE [{column}] IS NOT NULL;"
        df = pd.read_sql(q, conn)
        return df[column].astype(str).tolist()
    except Exception:
        return []


# ============================================================== 
# Policy Management
# ============================================================== 
def load_base_policy(path="C:\\DiscoveryEng\\Backend\\Mask_policy.csv"):
    try:
        df = pd.read_csv(path, sep=None, engine="python")
        for col in ["Column_Keyword", "Data_Type_Expected", "Masking_Function", "Deterministic", "Null_Handling", "Description"]:
            if col not in df.columns:
                df[col] = ""
        df["Information_Type"] = df["Information_Type"].astype(str)
        df["Sensitivity_Label"] = df["Sensitivity_Label"].astype(str)
        df["Masking_Function"] = df["Masking_Function"].astype(str)
        df["Column_Keyword"] = df["Column_Keyword"].fillna("").astype(str)
        return df
    except Exception:
        return pd.DataFrame(
            columns=[
                "Rule_ID", "Information_Type", "Sensitivity_Label", "Column_Keyword",
                "Data_Type_Expected", "Masking_Function", "Deterministic", "Null_Handling", "Description"
            ]
        )


def merge_policies(base_policy, uploaded_file):
    if uploaded_file is None:
        return base_policy
    try:
        user_policy = pd.read_excel(uploaded_file) if uploaded_file.name.endswith(".xlsx") else pd.read_csv(uploaded_file)
        for col in ["Column_Keyword", "Data_Type_Expected", "Masking_Function", "Deterministic", "Null_Handling", "Description"]:
            if col not in user_policy.columns:
                user_policy[col] = ""
        user_policy["Information_Type"] = user_policy["Information_Type"].astype(str)
        user_policy["Sensitivity_Label"] = user_policy["Sensitivity_Label"].astype(str)
        return pd.concat([base_policy, user_policy], ignore_index=True, sort=False)
    except Exception:
        return base_policy


# ============================================================== 
# Classification Logic
# ============================================================== 
def classify_columns(metadata_df, policy_df, conn, top_n_samples=5):
    results = []
    progress = st.progress(0)
    total = len(metadata_df)

    for i, row in enumerate(metadata_df.itertuples(), start=1):
        table, column, dtype = row.TableName, row.ColumnName, row.DataType
        samples = sample_column_data(conn, table, column, top_n_samples)
        best_match = None
        match_type = None

        # Try regex match
        for _, rule in policy_df.iterrows():
            pattern = rule.get("Sample_Pattern", "") if "Sample_Pattern" in rule.index else ""
            if isinstance(pattern, str) and pattern.strip() and samples:
                try:
                    if any(re.fullmatch(pattern, str(s)) for s in samples):
                        best_match = rule
                        match_type = "data"
                        break
                except:
                    continue

        # Fallback fuzzy column name match
        if best_match is None:
            highest_score = 0
            for _, rule in policy_df.iterrows():
                keywords = [k.strip().lower() for k in str(rule.get("Column_Keyword", "")).split(",") if k.strip()]
                if not keywords:
                    continue
                score = max(fuzz.partial_ratio(column.lower(), k) for k in keywords)
                if score > highest_score:
                    highest_score = score
                    best_match = rule
                    match_type = "name"

        if best_match is not None:
            results.append({
                "Table Name": table,
                "Column Name": column,
                "DataType": dtype,
                "Information_Type": best_match.get("Information_Type", "Unknown"),
                "Sensitivity_Label": best_match.get("Sensitivity_Label", "Confidential"),
                "Selected": True,
            })
        progress.progress(i / total if total else 1)

    return pd.DataFrame(results)


# ============================================================== 
# Masking Engine Integration (Execute mode)
# ============================================================== 
def run_masking_engine_streamlit(classified_df, policy_df, server, database, trusted, username=None, password=None, dry_run=False):
    OUTPUT_DIR = "./masking_output"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ts = int(time.time())
    log_file = os.path.join(OUTPUT_DIR, f"masking_run_{ts}.log")

    logger = logging.getLogger(f"masking_engine_{ts}")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        for h in logger.handlers:
            logger.removeHandler(h)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    sh = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    fh.setFormatter(formatter)
    sh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(sh)

    logger.info("Starting Masking Engine (Execution Mode)")
    try:
        if trusted:
            conn_str = f"DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={server};DATABASE={database};Trusted_Connection=yes;TrustServerCertificate=yes;"
        else:
            conn_str = f"DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password};TrustServerCertificate=yes;"
        conn = pyodbc.connect(conn_str, autocommit=False)
        cursor = conn.cursor()
    except Exception as e:
        logger.error("Connection failed: %s", e)
        st.error(f"❌ Failed to connect: {e}")
        return None, None

    results = []
    total = len(classified_df)
    progress = st.progress(0)

    policy_df_local = policy_df.copy()
    policy_df_local["Information_Type_norm"] = policy_df_local["Information_Type"].astype(str).str.strip().str.lower()
    policy_df_local["Sensitivity_Label_norm"] = policy_df_local["Sensitivity_Label"].astype(str).str.strip().str.lower()

    for i, row in enumerate(classified_df.itertuples(), start=1):
        table = getattr(row, "Table_Name")
        column = getattr(row, "Column_Name")
        data_type = getattr(row, "DataType")
        info_type = getattr(row, "Information_Type")
        sensitivity = getattr(row, "Sensitivity_Label")

        try:
            # Skip computed columns
            cursor.execute("""
                SELECT cc.definition
                FROM sys.computed_columns cc
                JOIN sys.columns c ON cc.object_id = c.object_id AND cc.column_id = c.column_id
                WHERE OBJECT_NAME(cc.object_id) = ? AND c.name = ?;
            """, table, column)
            if cursor.fetchone():
                results.append({"Table": table, "Column": column, "Status": "Skipped", "Reason": "Computed column"})
                continue

            mask_row = policy_df_local[
                (policy_df_local["Information_Type_norm"] == str(info_type).strip().lower()) &
                (policy_df_local["Sensitivity_Label_norm"] == str(sensitivity).strip().lower())
            ]
            if mask_row.empty:
                mask_row = policy_df_local[policy_df_local["Information_Type_norm"] == str(info_type).strip().lower()]
            if mask_row.empty:
                mask_row = policy_df_local[policy_df_local["Information_Type"].str.strip() == "*"]
            if mask_row.empty:
                results.append({"Table": table, "Column": column, "Status": "Skipped", "Reason": "No matching policy"})
                continue

            rule = mask_row.iloc[0]
            mask_function = str(rule.get("Masking_Function", "")).strip()
            if not mask_function or mask_function.lower() == "none":
                results.append({"Table": table, "Column": column, "Status": "Skipped", "Reason": "No Masking Function"})
                continue

            dt = str(data_type).strip()
            dt_safe = f"{dt}(max)" if dt.lower() in ("varchar", "nvarchar", "char", "nchar") else dt
            sql = f"""
;ALTER TABLE [{table}]
ALTER COLUMN [{column}] {dt_safe} MASKED WITH (FUNCTION = '{mask_function}');
"""

            try:
                cursor.execute(sql)
                conn.commit()
                logger.info("✅ Mask applied on %s.%s using %s", table, column, mask_function)
                results.append({"Table": table, "Column": column, "Mask_Function": mask_function, "Status": "Success"})
            except Exception as e:
                conn.rollback()
                logger.error("❌ Failed masking %s.%s: %s", table, column, e)
                results.append({"Table": table, "Column": column, "Mask_Function": mask_function, "Status": "Failed", "Reason": str(e)})

        except Exception as e:
            conn.rollback()
            logger.error("Error processing %s.%s: %s", table, column, e)
            results.append({"Table": table, "Column": column, "Status": "Failed", "Reason": str(e)})

        progress.progress(i / total)

    cursor.close()
    conn.close()
    summary_df = pd.DataFrame(results)
    summary_fname = os.path.join(OUTPUT_DIR, f"masking_summary_{ts}.csv")
    summary_df.to_csv(summary_fname, index=False, encoding="utf-8-sig")
    logger.info("Masking summary written to %s", summary_fname)

    return summary_df, summary_fname


# ============================================================== 
# Streamlit UI (No Change)
# ============================================================== 
def main():
    st.set_page_config(page_title="SQL Server DDC Framework", layout="wide")
    st.markdown("""
        <div style='text-align:center; background-color:#E8F8F5; padding:15px; border-radius:10px;'>
            <h1 style='color:#117A65;'>🔐 Data Masking Framework</h1>
            <p style='color:#148F77; font-size:16px;'>Discover, classify and mask sensitive data dynamically</p>
        </div>
        """, unsafe_allow_html=True)
    st.markdown("<hr style='border: 2px solid #76D7C4;'>", unsafe_allow_html=True)

    defaults = {"databases": [], "classified_df": pd.DataFrame(), "server": "", "database": "", "trusted": True, "username": "", "password": ""}
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)

    st.markdown("### 🔧 Configuration")
    config_col1, config_col2, config_col3, config_col4, config_col5 = st.columns([2.5, 1.5, 2.5, 2.0, 1.6])

    with config_col1:
        st.text_input("SQL Server Instance", key="server", placeholder="Server\\Instance")
    with config_col2:
        st.checkbox("Trusted Connection", key="trusted")
        if not st.session_state.trusted:
            st.text_input("Username", key="username", placeholder="Username")
            st.text_input("Password", key="password", type="password", placeholder="Password")
    with config_col3:
        if st.session_state.server:
            dbs = get_all_databases(st.session_state.server, st.session_state.username, st.session_state.password, st.session_state.trusted)
            if dbs:
                st.session_state.databases = dbs
                st.selectbox("Select Database", dbs, key="database")
            else:
                st.text_input("Database", key="database", placeholder="Enter database name")
        else:
            st.text_input("Database", key="database", placeholder="Enter database name")
    with config_col4:
        st.file_uploader("Upload Additional Policy File (optional)", type=["csv", "xlsx"], key="uploaded_policy")
    with config_col5:
        run = st.button("▶️ Run Classification", use_container_width=True, help="Start classification process", key="run_button")

    st.markdown("<hr style='border: 2px solid #76D7C4;'>", unsafe_allow_html=True)

    if run and st.session_state.server and st.session_state.database:
        with st.spinner("🔗 Connecting to SQL Server..."):
            conn = connect_sql_server(st.session_state.server, st.session_state.database, st.session_state.username,
                                      st.session_state.password, st.session_state.trusted)
        if not conn:
            st.error("❌ Connection failed. Check server or credentials.")
            return

        with st.spinner("📄 Loading policy rules..."):
            base = load_base_policy("C:\\DiscoveryEng\\Backend\\Mask_policy.csv")
            policy = merge_policies(base, st.session_state.uploaded_policy)

        with st.spinner("📊 Extracting metadata..."):
            meta = extract_metadata(conn)

        with st.spinner("🧠 Running classification..."):
            classified = classify_columns(meta, policy, conn)
        conn.close()

        if classified.empty:
            st.warning("⚠️ No sensitive columns detected.")
        else:
            st.session_state.classified_df = classified.rename(columns={
                "Table Name": "Table_Name",
                "Column Name": "Column_Name",
                "Information_Type": "Information_Type",
                "Sensitivity_Label": "Sensitivity_Label",
                "DataType": "DataType",
                "Selected": "Selected"
            })

    if not st.session_state.classified_df.empty:
        st.markdown("### 🧩 Detected Sensitive Columns")
        edited = st.data_editor(st.session_state.classified_df, hide_index=True, use_container_width=True, key="masking_editor")
        st.session_state.classified_df = edited
        selected = edited[edited["Selected"]]
        st.success(f"{len(selected)} columns selected for masking.", icon="✅")

        if st.button("🛡️ Apply Masking", use_container_width=True):
            with st.spinner("🚀 Running Masking Engine..."):
                OUTPUT_DIR = "./masking_output"
                os.makedirs(OUTPUT_DIR, exist_ok=True)
                classified_path = os.path.join(OUTPUT_DIR, "classified_results.csv")
                selected.to_csv(classified_path, index=False, encoding="utf-8-sig")

                base = load_base_policy("C:\\DiscoveryEng\\Backend\\Mask_policy.csv")
                policy = merge_policies(base, st.session_state.uploaded_policy)

                res_df, report_path = run_masking_engine_streamlit(
                    classified_df=selected,
                    policy_df=policy,
                    server=st.session_state.server,
                    database=st.session_state.database,
                    trusted=st.session_state.trusted,
                    username=st.session_state.username,
                    password=st.session_state.password,
                    dry_run=False
                )

            if res_df is not None:
                st.success("✅ Masking Engine completed successfully!")
                st.dataframe(res_df, use_container_width=True)
                if report_path:
                    st.info(f"📄 Summary report saved at: {report_path}")
                else:
                    st.info("📄 Summary report could not be saved to disk; see logs.")


if __name__ == "__main__":
    main()
