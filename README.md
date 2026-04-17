# Security Hub Action Center

Security Hub Action Center is an AWS-native operations console for triaging findings, assigning ownership, tracking analyst actions, and triggering approved response workflows from AWS Security Hub.

Instead of acting as a passive findings viewer, this project turns Security Hub findings into an actionable workflow with:
- finding normalization
- analyst decision tracking
- action queue management
- remediation orchestration
- executive and operational visibility

## Why this project exists

AWS Security Hub already aggregates and normalizes security findings.
The missing layer for many teams is operational decision-making:

- Who owns this finding?
- What action was requested?
- Was a ticket created?
- Was remediation approved?
- Did the response succeed or fail?
- What is the current backlog by severity, owner, or aging?

Security Hub Action Center focuses on that gap.

## Core idea

This project uses Security Hub as the system of record for findings, then adds an operational layer on top of it.

### Main flow

1. Security Hub emits findings events
2. EventBridge routes those events
3. Lambda functions normalize and persist findings
4. Analysts review findings in the UI
5. Analysts trigger actions such as:
   - assign owner
   - create ticket
   - request quarantine
   - mark in progress
   - suppress or resolve
6. Action results are stored and displayed in the dashboard

## AWS-native design

The architecture is based on these AWS building blocks:

- AWS Security Hub for findings ingestion and normalization
- EventBridge for event routing
- Lambda for ingestion and action handlers
- DynamoDB for finding and action state
- Step Functions for multi-step remediation workflows
- Streamlit for the MVP analyst console
- S3 for optional exports and snapshots

## Key capabilities

### Findings Inbox
- View normalized findings
- Filter by severity, account, region, workflow status, owner, and product
- Prioritize active queues

### Finding Detail
- Show finding context
- Show resources and metadata
- Show ownership, notes, and history
- Show recommended response actions

### Action Center
- Assign owner
- Request ticket creation
- Trigger approved remediation
- Update workflow status
- Track execution state and errors

### Ops Dashboard
- Open critical findings
- Aging backlog
- Owner queues
- Service-level risk hotspots
- Action success/failure trends

## Target MVP

The first working version includes:

- sample findings dataset
- finding normalization layer
- Streamlit findings inbox
- finding detail page
- mock action queue
- local or DynamoDB-backed state
- executive summary and operational metrics

## Architecture

```text
Security Hub
   └── Findings Imported V2 / Custom Action
           └── EventBridge
                   ├── ingest_findings Lambda
                   │       └── DynamoDB (findings)
                   ├── custom_action_router Lambda
                   │       └── DynamoDB (action requests)
                   └── remediation / ticket Lambdas
                           └── action execution records

Streamlit UI
   ├── Findings Inbox
   ├── Finding Detail
   ├── Action Queue
   └── Ops Dashboard
```

## Project structure

```text
security-hub-action-center/
├── README.md
├── requirements.txt
├── .streamlit/
│   └── config.toml
├── app/
│   └── streamlit_app.py
├── src/
│   ├── finding_mapper.py
│   ├── securityhub_client.py
│   ├── ddb_store.py
│   ├── action_service.py
│   ├── workflow_service.py
│   ├── metrics_service.py
│   └── utils.py
├── lambdas/
│   ├── ingest_findings/
│   ├── custom_action_router/
│   ├── ticket_action/
│   └── remediation_action/
├── infra/
│   ├── dynamodb.yaml
│   ├── eventbridge_rules.yaml
│   ├── iam_policies.yaml
│   └── securityhub_custom_actions.md
├── data/
│   └── sample_findings.json
└── docs/
    ├── architecture.md
    └── action_flows.md
```

## Data model

### Finding
Normalized representation of a Security Hub finding.

Example attributes:
- finding_id
- aws_account_id
- region
- severity
- title
- description
- product_name
- workflow_status
- record_state
- compliance_status
- resources
- owner
- tags
- updated_at

### ActionRequest
Represents a user-initiated action.

Example:
- request_id
- finding_id
- action_type
- requested_by
- requested_at
- status

### ActionExecution
Represents the execution result.

Example:
- execution_id
- request_id
- target
- started_at
- finished_at
- status
- result
- error_message

### AnalystNote
Represents comments, rationale, or exception handling notes.

## Initial custom actions

Recommended first custom actions:

- `send_to_action_center`
- `create_ticket`
- `request_quarantine`

## Development phases

### Phase 1
- local dataset
- finding mapper
- Streamlit inbox
- detail view
- local action queue

### Phase 2
- Findings Imported V2 ingest
- DynamoDB persistence
- custom action routing
- action history

### Phase 3
- ticket integrations
- remediation adapters
- metrics dashboard
- owner SLA and aging analytics

## Local development

### 1. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the app

```bash
streamlit run app/streamlit_app.py
```

## Future enhancements

- ASFF export and import helpers
- Jira / Slack / ServiceNow adapters
- Step Functions approval workflows
- analyst notes and exception tracking
- automated suppression policies
- remediation playbook catalog
- multi-account and multi-region dashboards

## Design principles

- Keep Security Hub as the findings source of truth
- Keep action state separate from finding state
- Prefer event-driven workflows
- Make analyst actions auditable
- Support gradual move from mock flows to real remediation

## License

MIT
