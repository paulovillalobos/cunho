# cunho for a conformance run (tools/oidf/run.py): the checkout under test, served over TLS on cunho.test, with
# only the TLS 1.2 cipher suites BCP 195 recommends for its ECDSA certificate (RFC 9325 §4.2; HAIP and FAPI 2.0 §5.2.2).
FROM python:3.13-slim
WORKDIR /cunho
COPY pyproject.toml README.md NOTICE LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . uvicorn
EXPOSE 443
CMD ["uvicorn", "--factory", "cunho.app:create_app", "--host", "0.0.0.0", "--port", "443", \
     "--ssl-keyfile", "/work/dev/cunho-tls.key", "--ssl-certfile", "/work/dev/cunho-tls.pem", "--no-access-log", \
     "--ssl-ciphers", "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"]
