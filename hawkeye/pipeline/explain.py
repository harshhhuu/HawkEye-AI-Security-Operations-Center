"""
HawkEye-AI — LLM Alert Explanation

Generates plain-English explanations for flagged alerts using
Google Gemini API. Includes response caching to avoid repeat API
calls during demo/testing.
"""

import os
import json
import hashlib
import pandas as pd

try:
    import google.generativeai as genai
except ImportError:
    genai = None

# Gemini configuration
GEMINI_MODEL = "gemini-3.6-flash"

# Auto-load GEMINI_API_KEY from .env if not already in environment
if "GEMINI_API_KEY" not in os.environ:
    _candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".env"),
    ]
    for _env_path in _candidates:
        if os.path.exists(_env_path):
            try:
                with open(_env_path, "r", encoding="utf-8") as _f:
                    for _line in _f:
                        _line = _line.strip()
                        if _line.startswith("GEMINI_API_KEY="):
                            _key = _line.split("=", 1)[1].strip().strip('"').strip("'")
                            if _key:
                                os.environ["GEMINI_API_KEY"] = _key
                                break
            except Exception:
                pass
        if "GEMINI_API_KEY" in os.environ:
            break

# Path for persisting the explanation cache between runs
_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "alerts_cache.json"
)

# In-memory cache (populated from file on first use)
_explanation_cache: dict = {}

# Prompt template from BUILD.md
PROMPT_TEMPLATE = """You are a SOC analyst assistant. Given this flagged network log entry,
explain in 1-2 plain-English sentences why it looks suspicious and what
category of threat it resembles (e.g. DoS, probe, spoofing, normal-but-unusual).

Log entry:
- protocol: {protocol}
- service: {service}
- flag: {flag}
- bytes_sent: {bytes_sent}, bytes_recv: {bytes_recv}
- anomaly_score: {anomaly_score}
- severity: {severity}

Respond with only the explanation, no preamble."""

FALLBACK_MESSAGE = (
    "[LLM unavailable] Anomalous activity detected — manual review recommended."
)


def _load_cache() -> dict:
    """Load the explanation cache from disk."""
    global _explanation_cache
    cache_path = os.path.normpath(_CACHE_FILE)
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                _explanation_cache = json.load(f)
        except (json.JSONDecodeError, IOError):
            _explanation_cache = {}
    return _explanation_cache


def _save_cache() -> None:
    """Persist the explanation cache to disk."""
    cache_path = os.path.normpath(_CACHE_FILE)
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(_explanation_cache, f, indent=2)
    except IOError:
        pass


def _row_hash(row: pd.Series) -> str:
    """Compute a hash key for a log row to use as cache key."""
    key_fields = [
        str(row.get("protocol_type_original", row.get("protocol_type", ""))),
        str(row.get("service_original", row.get("service", ""))),
        str(row.get("flag_original", row.get("flag", ""))),
        str(row.get("bytes_sent", row.get("src_bytes", 0))),
        str(row.get("bytes_recv", row.get("dst_bytes", 0))),
        str(round(row.get("anomaly_score", 0), 4)),
        str(row.get("severity", 0)),
    ]
    key_str = "|".join(key_fields)
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()


def explain_alert(row: pd.Series) -> str:
    """
    Generate a plain-English explanation for a flagged alert.

    Calls Google Gemini API with the fixed prompt template.
    Results are cached by row hash to avoid repeat API calls.

    Args:
        row: A pandas Series representing one flagged log entry.

    Returns:
        A 1-2 sentence explanation string, or a fallback message if
        the API is unavailable.
    """
    global _explanation_cache

    # Ensure cache is loaded
    if not _explanation_cache:
        _load_cache()

    # Check cache first
    row_key = _row_hash(row)
    if row_key in _explanation_cache:
        return _explanation_cache[row_key]

    # Build the prompt
    protocol = row.get("protocol_type_original", row.get("protocol_type", "unknown"))
    service = row.get("service_original", row.get("service", "unknown"))
    flag = row.get("flag_original", row.get("flag", "unknown"))
    bytes_sent = row.get("bytes_sent", row.get("src_bytes", 0))
    bytes_recv = row.get("bytes_recv", row.get("dst_bytes", 0))
    anomaly_score = round(row.get("anomaly_score", 0), 4)
    severity = row.get("severity", 0)

    prompt = PROMPT_TEMPLATE.format(
        protocol=protocol,
        service=service,
        flag=flag,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        anomaly_score=anomaly_score,
        severity=severity,
    )

    # Call Gemini API
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return FALLBACK_MESSAGE

    if genai is None:
        return FALLBACK_MESSAGE

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(GEMINI_MODEL)
        response = model.generate_content(prompt)
        explanation = response.text.strip()

        # Cache the result
        _explanation_cache[row_key] = explanation
        _save_cache()

        return explanation

    except Exception as e:
        print(f"[explain] API call failed: {e}")
        return FALLBACK_MESSAGE


def explain_alerts(
    df: pd.DataFrame,
    max_explain: int = None,
) -> pd.DataFrame:
    """
    Generate explanations for all flagged alerts in the DataFrame.

    Args:
        df:          DataFrame with 'is_flagged' and 'severity' columns.
        max_explain: Optional cap on how many alerts to explain (highest
                     severity first). None = explain all flagged alerts.

    Returns:
        DataFrame with a new 'explanation' column.
    """
    result = df.copy()
    result["explanation"] = ""

    flagged = result[result["is_flagged"] == True]  # noqa: E712

    if max_explain is not None:
        # Explain the most severe alerts first
        flagged = flagged.sort_values("severity", ascending=False).head(max_explain)

    total = len(flagged)
    for i, (idx, row) in enumerate(flagged.iterrows()):
        print(f"[explain] Generating explanation {i + 1}/{total}...", end="\r")
        result.at[idx, "explanation"] = explain_alert(row)

    if total > 0:
        print(f"[explain] Generated {total} explanations.          ")

    return result
