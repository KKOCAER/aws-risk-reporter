import os
import sys
from collections import Counter

import pandas as pd
import streamlit as st



sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from parser import load_alerts
from risk_engine import evaluate_risk
from ai_summary import generate_ai_summary


st.set_page_config(page_title="AWS Security Alert Dashboard", layout="wide")
st.title("AWS Security Alert Dashboard")

import json
import streamlit as st
from parser import load_alerts

DEFAULT_PATH = "data/alerts.json"

def save_uploaded_alerts(uploaded_file, path=DEFAULT_PATH):
    data = json.load(uploaded_file)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return data

uploaded_file = st.file_uploader("Upload alerts.json", type=["json"])

if uploaded_file is not None:
    try:
        alerts = save_uploaded_alerts(uploaded_file)
        st.success(f"Saved {len(alerts)} alerts to {DEFAULT_PATH}")
    except Exception as e:
        st.error(f"Upload failed: {e}")
        st.stop()
else:
    alerts = load_alerts(DEFAULT_PATH)


def build_result(alert):
    risk = evaluate_risk(alert)
    return {
        "alert": alert,
        "priority": risk["priority"],
        "score": risk["score"],
        "summary": risk["why_it_matters"],
        "remediation": risk["recommended_action"],
        "response_mode": risk.get("response_mode", "unknown"),
        "auto_remediation_available": risk.get("auto_remediation_available", False),
        "breakdown": risk.get("breakdown", {}),
    }


def detect_risk_theme(item):
    alert = item["alert"]
    text = " ".join(
        [
            str(alert.get("service", "")),
            str(alert.get("alert_type", "")),
            str(alert.get("description", "")),
            str(alert.get("resource", "")),
        ]
    ).lower()

    if any(k in text for k in ["public bucket", "public access", "0.0.0.0/0", "::/0", "internet", "open security group"]):
        return "internet exposure"
    if any(k in text for k in ["iam", "wildcard", "excessive permissions", "administrator", "assume role", "admin"]):
        return "identity and privilege"
    if any(k in text for k in ["cloudtrail", "logging", "audit", "disabled trail"]):
        return "visibility gap"
    if any(k in text for k in ["unencrypted", "encryption", "kms", "ebs"]):
        return "data protection gap"
    return "general misconfiguration"


def build_action_line(posture, top_themes):
    themes = set(top_themes)

    if posture == "CRITICAL":
        if "internet exposure" in themes and "identity and privilege" in themes:
            return (
                "Immediately contain externally exposed assets and reduce excessive IAM permissions. "
                "Assign named owners and remediate in the current change window."
            )
        if "internet exposure" in themes:
            return (
                "Immediately contain internet-exposed resources, validate intended access, "
                "and close unnecessary public paths."
            )
        if "identity and privilege" in themes:
            return (
                "Immediately reduce privilege, remove wildcard access, and validate blast radius "
                "for privileged identities."
            )
        return "Immediate remediation is required for the highest-scoring findings."

    if posture == "HIGH":
        return (
            "Urgent remediation is recommended in the next change window, focusing on the top-scoring "
            "resources and the most concentrated service risk."
        )

    if posture == "MODERATE":
        return (
            "Schedule targeted remediation for the highest-scoring findings and monitor whether risk "
            "is concentrating in one service or control family."
        )

    return (
        "Track the remaining findings in backlog, but keep exposure, privilege, and logging changes "
        "under review."
    )


def generate_executive_summary(
    results,
    avg_score,
    critical_count,
    high_count,
    medium_count,
    low_count,
    top_risks,
    service_risk,
):
    if not results:
        return (
            "### Posture\n"
            "No security findings detected.\n\n"
            "### Business Risk\n"
            "No material cloud security exposure is currently visible in the loaded dataset.\n\n"
            "### Immediate Action\n"
            "Continue monitoring and validate that ingestion is working as expected."
        )

    total = len(results)
    max_score = max(r["score"] for r in results)

    if critical_count >= 2 or max_score >= 90:
        posture = "CRITICAL"
    elif critical_count >= 1 or high_count >= 3 or avg_score >= 75:
        posture = "HIGH"
    elif medium_count >= 1 or avg_score >= 50:
        posture = "MODERATE"
    else:
        posture = "LOW"

    top_service = max(service_risk, key=service_risk.get) if service_risk else "unknown"

    theme_counter = Counter(detect_risk_theme(item) for item in top_risks)
    top_themes = [theme for theme, _ in theme_counter.most_common(2)]
    theme_text = ", ".join(top_themes) if top_themes else "general cloud hygiene"

    top_items = []
    for item in top_risks[:3]:
        alert = item["alert"]
        top_items.append(
            f"- {alert['alert_type']} on `{alert['resource']}` "
            f"({item['priority']}, score {item['score']})"
        )

    findings_text = "\n".join(top_items) if top_items else "- No major findings identified."
    action_line = build_action_line(posture, top_themes)

    return f"""
### Posture
The environment contains **{total} findings**: **{critical_count} Critical**, **{high_count} High**, **{medium_count} Medium**, and **{low_count} Low**. Overall posture is **{posture}**, with the highest concentration of risk in **{top_service}**.

### Business Risk
The dominant risk pattern is **{theme_text}**. The most material findings are:
{findings_text}

### Immediate Action
{action_line}
""".strip()


def build_ai_summary_input(exec_summary, top_risks):
    lines = [exec_summary, "", "Top findings detail:"]
    for item in top_risks[:5]:
        alert = item["alert"]
        lines.append(
            f"- Service={alert['service']}; Type={alert['alert_type']}; "
            f"Resource={alert['resource']}; Region={alert['region']}; "
            f"Priority={item['priority']}; Score={item['score']}; "
            f"Summary={item['summary']}; Remediation={item['remediation']}"
        )
    lines.append("")
    lines.append(
        "Rewrite this as a concise executive security briefing for a CISO. "
        "Be specific, mention the main risk concentration, and end with the most urgent action."
    )
    return "\n".join(lines)


alerts = load_alerts("data/alerts.json")

if not alerts:
    st.warning("No alerts loaded from data/alerts.json")
    st.stop()

all_results = [build_result(alert) for alert in alerts]

service_options = ["All"] + sorted(list({item["alert"]["service"] for item in all_results}))
priority_options = ["All", "Critical", "High", "Medium", "Low"]

col_filter_1, col_filter_2 = st.columns(2)

with col_filter_1:
    service_filter = st.selectbox("Filter by AWS Service", service_options)

with col_filter_2:
    priority_filter = st.selectbox("Filter by Priority", priority_options)

results = []
for item in all_results:
    alert = item["alert"]
    if service_filter != "All" and alert["service"] != service_filter:
        continue
    if priority_filter != "All" and item["priority"] != priority_filter:
        continue
    results.append(item)

st.write(f"Total alerts shown: {len(results)}")

for item in results:
    alert = item["alert"]
    with st.expander(f"{alert['id']} - {alert['alert_type']} [{item['priority']}]"):
        st.write(f"**Service:** {alert['service']}")
        st.write(f"**Resource:** {alert['resource']}")
        st.write(f"**Region:** {alert['region']}")
        st.write(f"**Owner:** {alert.get('owner', 'unassigned')}")
        st.write(f"**Environment:** {alert.get('environment', 'unknown')}")
        st.write(f"**Exposure:** {alert.get('exposure', 'unknown')}")
        st.write(f"**Description:** {alert['description']}")
        st.write(f"**Risk Score:** {item['score']}")
        st.write(f"**Summary:** {item['summary']}")
        st.write(f"**Recommended Action:** {item['remediation']}")
        st.write(f"**Response Mode:** {item['response_mode']}")
        st.write(
            f"**Auto-remediation Available:** {'Yes' if item['auto_remediation_available'] else 'No'}"
        )

        if item["breakdown"]:
            st.write("**Score Breakdown:**")
            st.json(item["breakdown"])

total_alerts = len(results)
critical_count = sum(1 for r in results if r["priority"] == "Critical")
high_count = sum(1 for r in results if r["priority"] == "High")
medium_count = sum(1 for r in results if r["priority"] == "Medium")
low_count = sum(1 for r in results if r["priority"] == "Low")
avg_score = int(sum(r["score"] for r in results) / total_alerts) if total_alerts > 0 else 0

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Alerts", total_alerts)
col2.metric("Critical", critical_count)
col3.metric("High", high_count)
col4.metric("Medium", medium_count)
col5.metric("Avg Risk Score", avg_score)

top_risks = sorted(results, key=lambda x: x["score"], reverse=True)[:5]

service_counts = {}
for item in results:
    service = item["alert"]["service"]
    service_counts[service] = service_counts.get(service, 0) + 1

service_df = pd.DataFrame(
    list(service_counts.items()),
    columns=["Service", "Count"]
)

service_risk = {}
for item in results:
    service = item["alert"]["service"]
    score = item["score"]
    service_risk[service] = service_risk.get(service, 0) + score

service_risk_df = pd.DataFrame(
    list(service_risk.items()),
    columns=["Service", "Total Risk Score"]
)

exec_summary = generate_executive_summary(
    results,
    avg_score,
    critical_count,
    high_count,
    medium_count,
    low_count,
    top_risks,
    service_risk,
)

st.subheader("Executive Summary")
st.markdown(exec_summary)

st.subheader("Top Risky Resources")
for item in top_risks:
    alert = item["alert"]
    with st.expander(f"{alert['resource']} - Score: {item['score']}"):
        st.write(f"Service: {alert['service']}")
        st.write(f"Type: {alert['alert_type']}")
        st.write(f"Priority: {item['priority']}")
        st.write(f"Summary: {item['summary']}")
        st.write(f"Remediation: {item['remediation']}")

df = pd.DataFrame([
    {
        "ID": item["alert"]["id"],
        "Account": item["alert"].get("aws_account_id", ""),
        "Service": item["alert"]["service"],
        "Type": item["alert"]["alert_type"],
        "Resource": item["alert"]["resource"],
        "Region": item["alert"]["region"],
        "Owner": item["alert"].get("owner", "unassigned"),
        "Environment": item["alert"].get("environment", "unknown"),
        "Exposure": item["alert"].get("exposure", "unknown"),
        "Priority": item["priority"],
        "Score": item["score"],
        "Summary": item["summary"],
        "Remediation": item["remediation"],
        "Response Mode": item["response_mode"],
        "Auto Remediation": item["auto_remediation_available"],
    }
    for item in results
])

st.subheader("Service Risk Distribution")
if not service_df.empty:
    st.bar_chart(service_df.set_index("Service"))
else:
    st.info("No service distribution to display.")

priority_data = pd.DataFrame({
    "Priority": ["Critical", "High", "Medium", "Low"],
    "Count": [critical_count, high_count, medium_count, low_count]
})

st.subheader("Priority Distribution")
st.bar_chart(priority_data.set_index("Priority"))

st.subheader("Service Risk Score (Weighted)")
if not service_risk_df.empty:
    st.bar_chart(service_risk_df.set_index("Service"))
else:
    st.info("No service risk score data to display.")

if service_risk:
    top_service = max(service_risk, key=service_risk.get)
    st.warning(f"Highest risk concentrated in: {top_service}")
else:
    st.info("No risk concentration detected.")

csv = df.to_csv(index=False).encode("utf-8")
st.download_button(
    label="Download CSV Report",
    data=csv,
    file_name="aws_security_report.csv",
    mime="text/csv"
)

if "ai_summary" not in st.session_state:
    st.session_state.ai_summary = ""

if st.button("Generate AI Executive Summary"):
    try:
        ai_input = build_ai_summary_input(exec_summary, top_risks)
        st.session_state.ai_summary = generate_ai_summary(ai_input)
    except Exception as e:
        st.session_state.ai_summary = ""
        st.error(f"AI summary generation failed: {e}")

if st.session_state.ai_summary:
    st.subheader("AI Executive Summary")
    st.success(st.session_state.ai_summary)
