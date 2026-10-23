# HawkEye-AI — Build Spec

Build a working prototype: ingest security logs → flag anomalies → score risk → generate a plain-English explanation per alert → show it all on a dashboard, with basic log-integrity hashing and role-gated actions.

This is the implementation spec. Do not add multi-agent orchestration, live cloud integration, real-time streaming, or auto-remediation — see "Out of Scope" at the end.

## Tech stack
- Python 3.11+
- pandas, scikit-learn (IsolationForest)
- Streamlit for the dashboard
- hashlib (SHA-256) for log integrity
- An LLM API call for alert explanations (use the Anthropic Python SDK; read the API key from an environment variable, never hardcode it)
- Dataset: NSL-KDD (https://www.unb.ca/cic/datasets/nsl.html) — use `KDDTrain+.txt` / `KDDTest+.txt`. Fall back to a small synthetic CSV generator (see `data/synthetic.py`) if the dataset isn't available, so the demo still runs offline.

## File structure
```
hawkeye/
  data/
    loader.py          # load NSL-KDD or synthetic CSV into a DataFrame
    synthetic.py        # generate a small fallback dataset
  pipeline/
    ingest.py           # parse raw logs -> structured records + SHA-256 hash per batch
    detect.py            # IsolationForest anomaly detection
    score.py             # risk scoring (likelihood x impact -> 1-5 severity)
    explain.py           # LLM call -> natural-language explanation per flagged alert
  dashboard/
    app.py               # Streamlit app: alert table, severity, explanation, role toggle
  auth/
    roles.py             # simple admin/viewer role check (no real auth system needed)
  tests/
    test_pipeline.py     # unit tests for each pipeline stage
  main.py                 # runs ingest -> detect -> score -> explain, writes alerts.json
  requirements.txt
  README.md
```

## Module specs

### `data/loader.py`
```python
def load_logs(path: str, fmt: str = "nsl-kdd") -> pd.DataFrame:
    """Returns a DataFrame with at least: timestamp, src, dst, protocol,
    service, flag, bytes_sent, bytes_recv, label (if present)."""
```

### `pipeline/ingest.py`
```python
def ingest(df: pd.DataFrame) -> tuple[pd.DataFrame, str]:
    """Cleans/normalizes df, returns (clean_df, batch_hash) where
    batch_hash = sha256 of the canonical (sorted, stringified) batch content."""

def verify_batch(df: pd.DataFrame, expected_hash: str) -> bool:
    """Recomputes hash and compares — used by the dashboard to show
    tamper detection (mutate a row, confirm this returns False)."""
```

### `pipeline/detect.py`
```python
def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """Fits IsolationForest on numeric features, returns df with an
    added `anomaly_score` (float) and `is_flagged` (bool) column."""
```

### `pipeline/score.py`
```python
def risk_score(row: pd.Series) -> int:
    """Combine anomaly_score (likelihood) with a simple impact heuristic
    (e.g. service type, bytes transferred) -> integer severity 1-5."""
```

### `pipeline/explain.py`
```python
def explain_alert(row: pd.Series) -> str:
    """Calls the LLM with a fixed prompt template (below), returns a
    1-2 sentence plain-English explanation. Cache responses by row hash
    to avoid repeat API calls during demo/testing."""
```

**Prompt template** (fill in the bracketed fields from the row):
```
You are a SOC analyst assistant. Given this flagged network log entry,
explain in 1-2 plain-English sentences why it looks suspicious and what
category of threat it resembles (e.g. DoS, probe, spoofing, normal-but-unusual).

Log entry:
- protocol: {protocol}
- service: {service}
- flag: {flag}
- bytes_sent: {bytes_sent}, bytes_recv: {bytes_recv}
- anomaly_score: {anomaly_score}
- severity: {severity}

Respond with only the explanation, no preamble.
```

### `auth/roles.py`
```python
def can_dismiss_alert(role: str) -> bool:
    """role in {'admin','viewer'}; only 'admin' can dismiss/act on alerts."""
```

### `dashboard/app.py` (Streamlit)
- Sidebar: role selector (admin/viewer), "verify log integrity" button
- Main table: timestamp, severity (color-coded), anomaly_score, explanation
- Filter/sort by severity
- "Dismiss alert" button — visible only if `can_dismiss_alert(role)` is True
- Integrity panel: shows batch hash, a "tamper this batch" demo button that flips one byte and shows `verify_batch` failing

## Acceptance criteria
- [ ] Running `python main.py` end-to-end on the sample/fallback dataset produces `alerts.json` with flagged rows, severities, and explanations
- [ ] `streamlit run dashboard/app.py` shows the alert table populated from `alerts.json`
- [ ] Given a flagged log row, output includes a severity 1-5 and a 1-2 sentence explanation
- [ ] Mutating one row in a hashed batch causes `verify_batch()` to return False, and the dashboard visibly flags it as tampered
- [ ] Viewer role cannot see/click "dismiss alert"; admin role can
- [ ] `tests/test_pipeline.py` passes for ingest, detect, score (mock the LLM call in `explain` tests — don't hit the real API in CI)

## Out of scope (do not build)
- Multi-agent orchestration / separate autonomous agents coordinating with each other
- Live multi-cloud integration (AWS/Azure/GCP APIs)
- Real-time log streaming at production volume
- Automated response or remediation actions — detection + explanation only
