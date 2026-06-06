FROM python:3.12-slim

LABEL maintainer="Humotica <info@humotica.com>"
LABEL description="Tibet Audit — Compliance health scanner. 17 frameworks, 112+ checks. Like Lynis, but for AI governance."
LABEL org.opencontainers.image.source="https://github.com/Humotica/tibet-audit"

RUN pip install --no-cache-dir tibet-audit==0.23.0

ENTRYPOINT ["tibet-audit"]
CMD ["scan", "--help"]
