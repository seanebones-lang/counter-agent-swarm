"""Named environment grants for the operator-owned colocated staging profile.

This reduces inherited authority; it is not process, filesystem or OS isolation.
Adding a name here is a deployment policy change, never a model-selected grant.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

Role = Literal["deadbolt", "mothership", "ingress", "edge", "worker"]

# Deliberate runtime values, not wildcard prefixes or a credential-name blacklist.
# PYTHONPATH/PYTHONHOME, dynamic-loader hooks and proxy/credential variables are
# intentionally absent. Children must use the reviewed installed distribution.
RUNTIME_NAMES = frozenset({
    "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "TZ",
    "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC_COLLATE", "LC_MONETARY",
    "LC_NUMERIC", "LC_TIME",
})

ROLE_NAMES: dict[Role, frozenset[str]] = {
    "deadbolt": frozenset({"DEADBOLT_TOKEN"}),
    "edge": frozenset({"COUNTER_SWARM_RUNTIME_CONFIG"}),
    "ingress": frozenset({"COUNTER_SWARM_RUNTIME_CONFIG"}),
    "worker": frozenset({"COUNTER_SWARM_RUNTIME_CONFIG"}),
    "mothership": frozenset({
        "COUNTER_SWARM_CONTROL_BINDING", "COUNTER_SWARM_MOTHERSHIP_AGENT_ID",
        "COUNTER_SWARM_MODEL", "COUNTER_SWARM_MODEL_BUDGET_FILE",
        "COUNTER_SWARM_MAX_MODEL_CALLS", "OPENAI_API_KEY",
        "MS_DATA_DIR", "MS_DATABASE_URL", "MS_MASTER_KEY", "MS_ENV",
        "MS_BOOTSTRAP_OWNER_KEY", "MS_PRODUCT_BINDINGS_FILE", "MS_DEADBOLT_REQUIRED",
        "MS_SMTP_ENABLED", "MS_SCHEDULER_ENABLED", "MS_WEBHOOK_DELIVERY_ENABLED",
        "MS_DEFAULT_RATE_LIMIT_RPS", "MS_DEFAULT_RATE_LIMIT_BURST",
        "MS_DEFAULT_DAILY_CALL_QUOTA", "MS_APPROVAL_TTL_HOURS",
        "MS_RETENTION_DAYS_EVENTS", "MS_RETENTION_DAYS_IDEMPOTENCY", "MS_RETENTION_DAYS_AUDIT",
    }),
}


def child_environment(role: Role, source: Mapping[str, str]) -> dict[str, str]:
    """Copy only this role's static grants from an explicit environment snapshot."""
    allowed = RUNTIME_NAMES | ROLE_NAMES[role]
    result = {name: value for name, value in source.items() if name in allowed}
    result.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
    return result
