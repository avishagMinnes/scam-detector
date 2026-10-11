"""Short, anonymous event records for monitoring and the Phase 6 dashboard.

One JSON line per event on stdout. Cloud Run turns each line into a structured log
entry (jsonPayload), which log-based metrics and alerts in infra/monitoring.tf count.

NEVER recorded: the message text, links, phone numbers, amounts, or the visitor's
address. Only what kind of result it was. tests/test_eventlog.py checks this.
"""
import json
import sys


def _emit(severity, event, **fields):
    print(json.dumps({"severity": severity, "message": event, "event": event, **fields},
                     ensure_ascii=False), file=sys.stdout, flush=True)


def check_done(result, latency_ms, model_kind):
    _emit("INFO", "check",
          risk_level=result["risk_level"],
          signs=sorted({s["id"] for s in result["red_flags"]}),   # rule ids only, e.g. "lookalike_domain"
          reassuring=bool(result["reassuring"]),
          model_score=round(float(result["model_score"]), 2),
          language=result["language"],
          latency_ms=round(latency_ms),
          model=model_kind)


def rate_limited(scope):
    _emit("WARNING", "rate_limited", scope=scope)


def check_failed(error):
    # The error's type only: an exception message could quote the input
    _emit("ERROR", "check_failed", error_type=type(error).__name__)
