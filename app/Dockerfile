# syntax=docker/dockerfile:1

# ---- builder ---------------------------------------------------------------
FROM python:3.14-slim AS builder
WORKDIR /build
COPY requirements.txt .
# The base image's bundled pip/setuptools lag behind and have had fixed
# CVEs (Trivy caught this: pip 25.0.1 had several MEDIUM CVEs fixed by
# 25.3/26.0/26.1.2; setuptools 70.3.0 had HIGH/MEDIUM CVEs fixed by
# 78.1.1/83.0.0) — upgrade both before installing anything with them.
#
# `pip install --upgrade` alone isn't enough: pip's own upgrade log never
# reports "Found existing installation: setuptools 70.3.0" the way it does
# for pip, meaning the base image's setuptools dist-info isn't something
# pip's uninstall-detection sees — it's still on disk after the upgrade,
# and a directory-scanning tool like Trivy still finds and flags it. Track
# down and remove any stale dist-info left over from a version other than
# the one we just installed.
RUN pip install --no-cache-dir --upgrade "pip>=26.1.2" "setuptools>=83.0.0" && \
    installed="$(python3 -c 'import setuptools; print(setuptools.__version__)')" && \
    find /usr/local/lib/python*/site-packages -maxdepth 1 \
      -iname 'setuptools-*' ! -iname "setuptools-${installed}*" \
      -exec rm -rf {} + && \
    pip install --no-cache-dir --user -r requirements.txt

# ---- runtime ----------------------------------------------------------------
FROM python:3.14-slim
LABEL org.opencontainers.image.source="https://github.com/monacomonaco/secure-cicd-pipeline" \
      org.opencontainers.image.description="Trivial Flask API used to demo a secure CI/CD pipeline"

# Same pip/setuptools upgrade + stale-dist-info cleanup as the builder
# stage — this is the image that actually ships and gets scanned, so it's
# the one that has to be clean, not just where requirements.txt gets
# installed.
RUN pip install --no-cache-dir --upgrade "pip>=26.1.2" "setuptools>=83.0.0" && \
    installed="$(python3 -c 'import setuptools; print(setuptools.__version__)')" && \
    find /usr/local/lib/python*/site-packages -maxdepth 1 \
      -iname 'setuptools-*' ! -iname "setuptools-${installed}*" \
      -exec rm -rf {} +
# TEMP DEBUG round 2 — disabling trivy's cache (previous commit) didn't
# change the result either, which rules out staleness and means the
# earlier `-xdev` debug search likely missed something (possibly a
# separate mount BuildKit presents during RUN). No filesystem
# restriction this time, plus grepping metadata content directly for the
# version string in case it's referenced somewhere that isn't named
# "setuptools-*".
RUN echo "=== find, no -xdev ===" && \
    find / -iname '*setuptools*' 2>/dev/null; \
    echo "=== grep for 70.3.0 in any dist-info/egg-info METADATA ===" && \
    grep -rl "70.3.0" /usr/local/lib/python*/site-packages /usr/lib/python3* 2>/dev/null; \
    echo "=== pip list ===" && \
    pip list 2>/dev/null | grep -i setuptools; \
    true

# Non-root user — Kyverno also enforces this cluster-side, this is belt & suspenders.
RUN addgroup --system app && adduser --system --ingroup app --no-create-home app

WORKDIR /app
COPY --from=builder /root/.local /home/app/.local
COPY app.py .

ENV PATH=/home/app/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER app
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else sys.exit(1)"

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--access-logfile", "-", "app:app"]
