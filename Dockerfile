FROM node:22-alpine AS ui
WORKDIR /build/ui
COPY ui/package.json ui/pnpm-lock.yaml ./
RUN npm install -g pnpm@11.19.0 && pnpm install --frozen-lockfile --ignore-scripts
COPY ui/ ./
RUN node node_modules/typescript/bin/tsc --noEmit && node node_modules/vite/bin/vite.js build --configLoader native

FROM python:3.13.18-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1 AS python-base

FROM python-base AS eap-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev openssl patch pkg-config ca-certificates && rm -rf /var/lib/apt/lists/*
COPY runtime/eap /inputs/eap
RUN python /inputs/eap/build.py /build-eap /built-eap

FROM python-base AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SWITCHLAB_DB=/data/switch.db SWITCHLAB_KEY_FILE=/key/config.key \
    SWITCHLAB_SNMP_DEFAULT_HOST=0.0.0.0 SWITCHLAB_COA_DEFAULT_HOST=0.0.0.0 \
    SWITCHLAB_SNMP_LISTEN_PORT=161 SWITCHLAB_COA_LISTEN_PORT=3799
COPY --from=eap-build /built-eap/runtime-packages.txt /tmp/eap-runtime-packages.txt
RUN apt-get update && xargs -r apt-get install -y --no-install-recommends ca-certificates < /tmp/eap-runtime-packages.txt && rm -f /tmp/eap-runtime-packages.txt && rm -rf /var/lib/apt/lists/*
COPY --from=eap-build /built-eap/eapol_test /built-eap/eapol_test.switchlab.json /usr/local/bin/
COPY --from=eap-build /built-eap/notices /usr/local/share/doc/eapol_test
COPY pyproject.toml LICENSE ./
COPY switchlab ./switchlab
COPY --from=ui /build/switchlab/static ./switchlab/static
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home app && mkdir /data /key && chown app:app /data && chown app:app /key && chmod 700 /key
USER 10001:10001
EXPOSE 8000/tcp 161/udp 3799/udp
HEALTHCHECK --interval=20s --timeout=3s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"
CMD ["uvicorn", "switchlab.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

FROM runtime AS test
# Tests choose their own listener ports.
ENV SWITCHLAB_SNMP_LISTEN_PORT= SWITCHLAB_COA_LISTEN_PORT=
USER root
RUN apt-get update && apt-get install -y --no-install-recommends snmp snmptrapd && rm -rf /var/lib/apt/lists/*
COPY tests ./tests
COPY specification ./specification
COPY scripts/load_case.py ./scripts/load_case.py
RUN pip install --no-cache-dir '.[test]'
USER 10001:10001
CMD ["python", "-m", "pytest", "-q", "--tb=short", "-p", "no:cacheprovider"]

# Browser tooling is test-only; the public runtime does not inherit this stage.
FROM node:22-bookworm-slim AS browser-tools
WORKDIR /browser
COPY tests/browser/package.json tests/browser/pnpm-lock.yaml ./
RUN npm install -g pnpm@11.19.0 && pnpm install --frozen-lockfile --ignore-scripts

FROM runtime AS browser-test
ENV SWITCHLAB_SNMP_LISTEN_PORT= SWITCHLAB_COA_LISTEN_PORT=
USER root
COPY --from=browser-tools /usr/local/bin/node /usr/local/bin/node
COPY --from=browser-tools /browser/node_modules /app/tests/browser/node_modules
COPY tests ./tests
COPY scripts/browser_check.py ./scripts/browser_check.py
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 && pip install --no-cache-dir '.[test]' && node tests/browser/node_modules/playwright/cli.js install --with-deps --only-shell chromium && rm -rf /var/lib/apt/lists/*
USER 10001:10001
CMD ["python", "scripts/browser_check.py", "--mode", "full"]

# A plain docker build produces the public application, not the test image.
FROM runtime AS release
