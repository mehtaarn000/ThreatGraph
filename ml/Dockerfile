FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY ml/requirements-service.txt /app/ml/requirements-service.txt
COPY ml/requirements.txt /app/ml/requirements.txt
RUN pip install --no-cache-dir -r /app/ml/requirements-service.txt
COPY ml/ /app/ml/
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER 10001:10001

EXPOSE 8000
CMD ["uvicorn", "ml.src.threatgraph_ml.scoring_api:app", "--host", "0.0.0.0", "--port", "8000"]
