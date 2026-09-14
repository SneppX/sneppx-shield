# sneppx-shield - AI security & compliance suite
# Usage: docker build -t sneppx-shield . && docker run --rm sneppx-shield audit <model>
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/shield

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

ENTRYPOINT ["sneppx-shield"]
CMD ["--help"]