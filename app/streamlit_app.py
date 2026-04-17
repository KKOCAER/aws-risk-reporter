import os
import sys
import pandas as pd
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from securityhub_client import load_sample_findings

st.set_page_config(page_title="Security Hub Action Center", layout="wide")
st.title("Security Hub Action Center")
st.caption("MVP inbox for triaging Security Hub findings and preparing analyst actions.")

findings = load_sample_findings("data/sample_findings.json")

col1, col2, col3 = st.columns(3)
with col1:
    severity_filter = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
with col2:
    workflow_filter = st.selectbox("Workflow Status", ["All", "NEW", "NOTIFIED", "SUPPRESSED", "RESOLVED"])
with col3:
    service_filter = st.selectbox("Service", ["All"] + sorted({f["service"] for f in findings}))

filtered = []
for f in findings:
    if severity_filter != "All" and f["severity"] != severity_filter:
        continue
    if workflow_filter != "All" and f["workflow_status"] != workflow_filter:
        continue
    if service_filter != "All" and f["service"] != service_filter:
        continue
    filtered.append(f)

critical_count = sum(1 for f in filtered if f["severity"] == "critical")
high_count = sum(1 for f in filtered if f["severity"] == "high")
medium_count = sum(1 for f in filtered if f["severity"] == "medium")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Visible Findings", len(filtered))
m2.metric("Critical", critical_count)
m3.metric("High", high_count)
m4.metric("Medium", medium_count)

df = pd.DataFrame([
    {
        "Severity": f["severity"],
        "Title": f["alert_type"],
        "Service": f["service"],
        "Owner": f["owner"],
        "Environment": f["environment"],
        "Workflow": f["workflow_status"],
        "Compliance": f["compliance_status"],
        "Region": f["region"],
        "Resource": f["resource"],
    }
    for f in filtered
])

st.subheader("Findings Inbox")
if not df.empty:
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("No findings match the selected filters.")

st.subheader("Finding Details")
for f in filtered:
    with st.expander(f"{f['alert_type']} [{f['severity'].upper()}]"):
        left, right = st.columns(2)

        with left:
            st.write(f"**Resource:** {f['resource']}")
            st.write(f"**Service:** {f['service']}")
            st.write(f"**Owner:** {f['owner']}")
            st.write(f"**Environment:** {f['environment']}")
            st.write(f"**Workflow Status:** {f['workflow_status']}")
            st.write(f"**Compliance Status:** {f['compliance_status']}")

        with right:
            st.write(f"**Exposure:** {f['exposure']}")
            st.write(f"**Privilege Level:** {f['privilege_level']}")
            st.write(f"**Data Sensitivity:** {f['data_sensitivity']}")
            st.write(f"**Source Product:** {f['source_product']}")
            st.write(f"**Account:** {f['aws_account_id']}")
            st.write(f"**Security Control ID:** {f['security_control_id']}")

        st.write(f"**Description:** {f['description']}")

        action_col1, action_col2, action_col3 = st.columns(3)
        action_col1.button("Assign Owner", key=f"assign_{f['id']}")
        action_col2.button("Create Ticket", key=f"ticket_{f['id']}")
        action_col3.button("Request Quarantine", key=f"quarantine_{f['id']}")

        st.json(f)

st.subheader("Service Distribution")
if filtered:
    service_df = pd.DataFrame(filtered)["service"].value_counts().rename_axis("Service").reset_index(name="Count")
    st.bar_chart(service_df.set_index("Service"))
else:
    st.info("No data available for service distribution.")
