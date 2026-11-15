# One image for the demo stack: both cunho instances and the demo service, with SoftHSM2 so the keys are used
# through PKCS#11. The base image is pinned by digest and every Python package by version and hash
# (deploy/requirements.txt); build with: docker compose -f deploy/compose.yaml build
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --home-dir /nonexistent cunho \
 && mkdir -p /data /secrets /softhsm /public && chown cunho:cunho /data /secrets /softhsm /public
# Only what the lock names, as built wheels: a release made after the lock was written cannot enter the image, a
# download that differs from the locked file stops the build, and nothing is built or run from a source archive.
COPY deploy/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r /tmp/requirements.txt && rm /tmp/requirements.txt
WORKDIR /app
# cunho and the demo service run from their source (PYTHONPATH below), so no build tool is fetched to package them.
COPY src ./src
COPY tools/dev_pki.py tools/deploy_init.py ./tools/
# dev_pki.py builds the wallet-provider part with the tests' own PKI builder, which imports nothing of the tests.
COPY tests/__init__.py ./tests/__init__.py
COPY tests/engine/__init__.py tests/engine/pki.py ./tests/engine/
COPY demo/metadata ./demo/metadata
ENV SOFTHSM2_CONF=/softhsm/softhsm2.conf PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER cunho
