# Operator-private build: contains a separately authorized Mothership wheel.
# Never push, export or send this image to a tester.
FROM python:3.12-slim-trixie@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 HOME=/tmp/home
WORKDIR /opt/lab
COPY dependency-artifacts/n11_mothership-*.whl /tmp/deps/
RUN python -m pip install /tmp/deps/*.whl pytest pytest-asyncio && rm -rf /tmp/deps
COPY dependency-artifacts/deadbolt /usr/local/bin/deadbolt
COPY pyproject.toml LICENSE NOTICE README.md /opt/lab/
COPY src /opt/lab/src
RUN python -m pip install . && useradd --uid 10001 --create-home tester && chmod 755 /usr/local/bin/deadbolt
COPY scripts /opt/lab/scripts
COPY examples /opt/lab/examples
COPY tests /opt/lab/tests
COPY lab-manifest.json /opt/lab/lab-manifest.json
USER 10001:10001
CMD ["python", "scripts/linux_lab_server.py", "--deadbolt", "/usr/local/bin/deadbolt", "--credentials", "/run/lab/credentials.json", "--manifest", "/opt/lab/lab-manifest.json", "--container"]
