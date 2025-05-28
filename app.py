import streamlit as st
import pandas as pd
import json
from datetime import timedelta
from collections import defaultdict

# --- Utility functions ---
def parse_time_window(window_str):
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    try:
        num = int(window_str[:-1])
        unit = units[window_str[-1]]
    except Exception:
        raise ValueError(f"Invalid time window format: {window_str}")
    return timedelta(**{unit: num})

def filter_time_window(df, col, window_str):
    now = pd.Timestamp.utcnow()
    delta = parse_time_window(window_str)
    window_start = now - delta

    # Ensure datetime and timezone-aware
    df[col] = pd.to_datetime(df[col], utc=True, errors='coerce')
    filtered_df = df[df[col] >= window_start]
    return filtered_df

def apply_match_pattern(df, pattern):
    for k, v in pattern.items():
        if k not in df.columns:
            return pd.DataFrame()
        df = df[df[k].astype(str) == str(v)]
        if df.empty:
            return df
    return df

def group_and_aggregate(df, group_by, threshold):
    if isinstance(group_by, str):
        group_by = [group_by]
    grouped = df.groupby(group_by).size().reset_index(name="count")
    filtered_grouped = grouped[grouped["count"] >= threshold]
    return filtered_grouped

def display_alert(st, rule, count, group_val=None):
    group_info = f"\n🧍 Group: `{group_val}`" if group_val else ""
    severity = rule.get("action", {}).get("severity", "medium")
    message = rule.get("action", {}).get("message", "")
    stride = rule.get("stride", "Unknown")
    dread = rule.get("dread", {})
    dread_score = sum(dread.values()) / 5 if dread else "N/A"

    st.error(f"""
🚨 **{rule['name']}**  
🆔 Rule ID: `{rule['rule_id']}`  
🔥 Severity: **{severity}**  
💬 {message}  
🧮 Count: **{count}**{group_info}  
🛡 STRIDE: `{stride}`  
📊 DREAD Score: `{dread_score}`
""")

# --- Chain of Events Detection ---
def detect_chains(df, chain_rules):
    st.subheader("🔗 Chain of Events Alerts")
    chains_triggered = False
    for chain in chain_rules:
        chain_name = chain.get("name", "Unnamed Chain")
        events = chain.get("events", [])
        min_occurrences = chain.get("min_occurrences", 1)
        matched = True
        for evt in events:
            matched_df = apply_match_pattern(df, evt)
            if matched_df.empty:
                matched = False
                break
        if matched:
            st.warning(f"⚠️ Chain Alert: **{chain_name}** triggered by sequence of matching events.")
            chains_triggered = True
    if not chains_triggered:
        st.success("✅ No chain of event alerts triggered.")

# --- Rule engine ---
def apply_rules(df, rules, log_source, threshold_overrides):
    st.subheader("⚠️ Alerts")
    alerts_found = False

    for rule in rules:
        if rule.get("log_source") != log_source:
            continue

        df_copy = df.copy()
        df_copy = apply_match_pattern(df_copy, rule.get("match_pattern", {}))
        if df_copy.empty:
            continue

        if "time_window" in rule:
            df_copy = filter_time_window(df_copy, "timestamp", rule["time_window"])
            if df_copy.empty:
                continue

        threshold = threshold_overrides.get(rule["rule_id"], rule.get("threshold", 1))

        if "group_by" in rule:
            grouped_df = group_and_aggregate(df_copy, rule["group_by"], threshold)
            for _, row in grouped_df.iterrows():
                count = row["count"]
                group_cols = rule["group_by"] if isinstance(rule["group_by"], list) else [rule["group_by"]]
                group_val = ", ".join(str(row[col]) for col in group_cols)
                display_alert(st, rule, count, group_val)
                alerts_found = True
        else:
            if len(df_copy) >= threshold:
                display_alert(st, rule, len(df_copy))
                alerts_found = True

    if not alerts_found:
        st.success("✅ No alerts triggered.")

# --- Streamlit UI ---
st.title("🛡️ Malicious Log Analyzer")

uploaded_log = st.file_uploader("📂 Upload `malicious_logs.json`", type="json")
uploaded_rules = st.file_uploader("⚖️ Upload `rules.json`", type="json")

if uploaded_log:
    try:
        logs = json.loads(uploaded_log.read().decode("utf-8"))
        if isinstance(logs, dict):
            logs = [logs]
        df_logs = pd.DataFrame(logs)

        if "timestamp" not in df_logs.columns:
            st.warning("Missing 'timestamp'. Adding current UTC time to all entries.")
            df_logs["timestamp"] = pd.Timestamp.utcnow()
        else:
            df_logs["timestamp"] = pd.to_datetime(df_logs["timestamp"], utc=True, errors='coerce')
            if df_logs["timestamp"].isnull().any():
                st.warning("Some timestamps could not be parsed and were set to current UTC time.")
                df_logs.loc[df_logs["timestamp"].isnull(), "timestamp"] = pd.Timestamp.utcnow()

        st.success("✅ Log file loaded.")
        st.dataframe(df_logs.head())
    except Exception as e:
        st.error(f"Error parsing logs: {e}")
        df_logs = pd.DataFrame()
else:
    df_logs = pd.DataFrame()

if uploaded_rules:
    try:
        rule_data = json.loads(uploaded_rules.read().decode("utf-8"))
        if isinstance(rule_data, dict):
            rules = rule_data.get("rules", [])
            chain_rules = rule_data.get("chains", [])
        else:
            rules = rule_data
            chain_rules = []
        st.success("✅ Rules loaded.")
    except Exception as e:
        st.error(f"Error parsing rules: {e}")
        rules = []
        chain_rules = []
else:
    rules = []
    chain_rules = []

threshold_overrides = {}
if rules:
    st.sidebar.header("🔧 Rule Threshold Overrides")
    for rule in rules:
        if rule.get("log_source") in ["network_logs", "auth_logs"] and "threshold" in rule:
            default = rule["threshold"]
            threshold_overrides[rule["rule_id"]] = st.sidebar.slider(
                f"{rule['name']} (Rule ID: {rule['rule_id']})",
                min_value=1,
                max_value=20,
                value=default,
                step=1
            )

if not df_logs.empty and rules:
    log_type_guess = st.selectbox("Select log source type:", ["auth_logs", "network_logs"])
    apply_rules(df_logs, rules, log_type_guess, threshold_overrides)
    detect_chains(df_logs, chain_rules)
