"""Internal DNS inference contract; never resolves or visits supplied domains."""
import logging
from typing import Literal, Optional
from uuid import UUID

from fastapi import HTTPException
from pydantic import AwareDatetime, BaseModel, Field, TypeAdapter, field_validator, model_validator

from .dns_features import extract_dns_features, from_snapshot
from .score_dns import score_snapshot

logger = logging.getLogger("threatgraph.ml_service")


class DNSRecord(BaseModel):
    value: str = Field(min_length=1, max_length=253)
    preference: Optional[int] = Field(default=None, ge=0, le=65535, strict=True)


class DNSQuery(BaseModel):
    type: Literal["A", "AAAA", "NS", "MX"]
    status: Literal["ok", "no_records", "not_found", "timeout", "error", "canceled"]
    records: list[DNSRecord] = Field(max_length=1024)

    @model_validator(mode="after")
    def valid_records(self):
        if self.status == "ok" and not self.records:
            raise ValueError("ok queries must contain records")
        if self.status != "ok" and self.records:
            raise ValueError("unsuccessful queries cannot contain records")
        if self.type == "MX" and any(record.preference is None for record in self.records):
            raise ValueError("MX records require a preference")
        return self


class DNSSnapshot(BaseModel):
    id: UUID
    domain: str = Field(min_length=1, max_length=253)
    observed_at: str = Field(max_length=64)
    queries: list[DNSQuery] = Field(min_length=4, max_length=4)

    @field_validator("observed_at")
    @classmethod
    def valid_timestamp(cls, value):
        TypeAdapter(AwareDatetime).validate_python(value)
        # Preserve Go's nanosecond precision rather than round-trip via datetime.
        return value

    @model_validator(mode="after")
    def distinct_queries(self):
        if {query.type for query in self.queries} != {"A", "AAAA", "NS", "MX"}:
            raise ValueError("exactly one query per DNS type is required")
        return self


class DNSPredictionResponse(BaseModel):
    snapshot_id: UUID
    domain: str
    observed_at: str
    generic_phishing_score: float = Field(ge=0, le=1)
    threshold: float = Field(ge=0, le=1)
    flagged: bool
    model: str
    model_version: str = Field(pattern=r"^[0-9a-f]{64}$")
    score_semantics: str
    experimental: Literal[True]
    unknown_record_types: list[Literal["A", "AAAA", "NS", "MX"]]


def register_dns_routes(app):
    @app.get("/v1/dns/readyz")
    def ready():
        if app.state.dns_model_bundle is None:
            raise HTTPException(503, "DNS model is not configured")
        return {"status": "ready"}

    @app.post("/v1/score/dns", response_model=DNSPredictionResponse)
    def score(request: DNSSnapshot):
        bundle = app.state.dns_model_bundle
        if bundle is None:
            raise HTTPException(503, "DNS model is not configured")
        if all(query.status in {"timeout", "error", "canceled"} for query in request.queries):
            raise HTTPException(422, "No successful DNS lookup results are available")
        snapshot = request.model_dump(mode="json", exclude_none=True)
        try:
            # Validate inputs separately so artifact/inference errors remain 500s.
            extract_dns_features(snapshot["domain"], from_snapshot(snapshot))
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise HTTPException(422, "Invalid DNS evidence") from exc
        try:
            result = score_snapshot(bundle, snapshot)
            return DNSPredictionResponse(**result, snapshot_id=request.id,
                                         model_version=bundle["model_version"], experimental=True)
        except Exception as exc:
            logger.exception("DNS scoring failed")
            raise HTTPException(500, "DNS model scoring failed") from exc
