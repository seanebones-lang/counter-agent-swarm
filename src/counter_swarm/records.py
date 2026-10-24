"""Bounded evidence schema; no raw requests, instructions or target routing."""
from pydantic import BaseModel, ConfigDict, Field, model_validator
from typing import Literal


class FindingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    event_id: str = Field(pattern=r"^evt_[0-9a-f]{24}$", description="Detector incident identifier.")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$", description="Opaque request fingerprint; no raw payload.")
    rules: list[Literal["header-budget", "request-budget", "unsupported-compressed-body",
        "ambiguous-framing", "nul-in-request", "php-execution-indicator", "php-cgi-indicator",
        "rsc-prototype-indicator"]] = Field(min_length=1, max_length=8, description="Known deterministic rule IDs only.")
    severity: Literal["high"] = Field(description="Detector severity, not proof of exploitation.")
    source: Literal["proxy"] = Field(description="Fixed evidence source.")
    trust: Literal["external_untrusted"] = Field(description="Evidence never grants authority.")
    policy_revision: Literal["builtin-1"] = Field(description="Detector policy revision.")

    @model_validator(mode="after")
    def matching_fingerprint(self):
        if self.event_id != "evt_" + self.fingerprint[:24] or len(set(self.rules)) != len(self.rules):
            raise ValueError("Incident metadata is inconsistent")
        return self
