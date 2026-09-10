FROM node:22-alpine AS ui
WORKDIR /build/ui
COPY ui/package.json ui/pnpm-lock.yaml ./
RUN npm install -g pnpm@11.19.0 && pnpm install --frozen-lockfile --ignore-scripts
COPY ui/ ./
RUN node node_modules/typescript/bin/tsc --noEmit && node node_modules/vite/bin/vite.js build --configLoader native

FROM python:3.13-slim AS python-base

FROM python-base AS eap-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev openssl patch pkg-config ca-certificates && rm -rf /var/lib/apt/lists/*
COPY runtime/eap /inputs/eap
RUN python /inputs/eap/build.py /build-eap /built-eap

FROM python-base AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SWITCHLAB_DB=/data/switch.db SWITCHLAB_KEY_FILE=/run/secrets/config_key SWITCHLAB_SNMP_DEFAULT_HOST=0.0.0.0
COPY --from=eap-build /built-eap/runtime-packages.txt /tmp/eap-runtime-packages.txt
RUN apt-get update && xargs -r apt-get install -y --no-install-recommends ca-certificates < /tmp/eap-runtime-packages.txt && rm -f /tmp/eap-runtime-packages.txt && rm -rf /var/lib/apt/lists/*
COPY --from=eap-build /built-eap/eapol_test /built-eap/eapol_test.switchlab.json /usr/local/bin/
COPY --from=eap-build /built-eap/notices /usr/local/share/doc/eapol_test
COPY pyproject.toml LICENSE ./
COPY switchlab ./switchlab
COPY --from=ui /build/switchlab/static ./switchlab/static
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home app && mkdir /data && chown app:app /data
USER 10001:10001
EXPOSE 8000/tcp 161/udp
HEALTHCHECK --interval=20s --timeout=3s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"
CMD ["uvicorn", "switchlab.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

FROM runtime AS test
USER root
RUN apt-get update && apt-get install -y --no-install-recommends snmp snmptrapd && rm -rf /var/lib/apt/lists/*
COPY tests ./tests
COPY specification/docs/mib-coverage.csv ./specification/docs/mib-coverage.csv
COPY scripts/load_case.py ./scripts/load_case.py
RUN pip install --no-cache-dir '.[test]'
USER 10001:10001
CMD ["python", "-m", "pytest", "-q", "--tb=short", "-p", "no:cacheprovider"]

# A plain docker build produces the public application, not the test image.
FROM runtime AS release
