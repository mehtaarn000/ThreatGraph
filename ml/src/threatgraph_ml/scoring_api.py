"""Internal HTTP service for the trained brand-pair scoring model."""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .brand_inference import load_brand_pair_model, score_brand_pair


logger = logging.getLogger("threatgraph.ml_service")


class ScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_url: str = Field(min_length=1, max_length=4096)
    brand_name: str = Field(min_length=1, max_length=200)
    brand_domain: str = Field(min_length=1, max_length=253)


class FeatureContribution(BaseModel):
    feature: str
    value: float
    log_odds_contribution: float
    direction: str


class ScoreResponse(BaseModel):
    candidate_url: str
    brand_name: str
    brand_domain: str
    impersonation_score: float = Field(ge=0, le=1)
    score_semantics: str
    feature_contributions: list[FeatureContribution]
    explanation_semantics: str


def _valid_web_url(value: str, allow_domain_only: bool = False) -> bool:
    candidate = value if "://" in value else (f"https://{value}" if allow_domain_only else value)
    try:
        parsed = urlsplit(candidate)
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname)
    except ValueError:
        return False


def create_app(
    model_loader: Callable = load_brand_pair_model,
    scorer: Callable = score_brand_pair,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        model_path = os.getenv("THREATGRAPH_BRAND_MODEL_PATH")
        try:
            app.state.model_bundle = model_loader(Path(model_path)) if model_path else model_loader()
        except Exception as exc:
            logger.exception("failed to load brand-pair model")
            raise RuntimeError("brand-pair model failed to load") from exc
        yield

    app = FastAPI(title="ThreatGraph Model Service", version="0.1.0", lifespan=lifespan)

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.post("/v1/score", response_model=ScoreResponse)
    def score(request: ScoreRequest):
        if not _valid_web_url(request.candidate_url):
            raise HTTPException(status_code=422, detail="candidate_url must be an absolute HTTP(S) URL")
        if not _valid_web_url(request.brand_domain, allow_domain_only=True):
            raise HTTPException(status_code=422, detail="brand_domain must be a domain or HTTP(S) URL")
        try:
            result = scorer(
                request.candidate_url,
                request.brand_name.strip(),
                request.brand_domain.strip(),
                model_bundle=app.state.model_bundle,
            )
        except Exception as exc:
            logger.exception("brand-pair scoring failed")
            raise HTTPException(status_code=500, detail="model scoring failed") from exc
        return result

    return app


app = create_app()
