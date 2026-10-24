# Staging template. Supply reviewed Linux dependencies privately; no engine forks.
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY dependency-artifacts/*.whl /tmp/dependencies/
COPY dependency-artifacts/deadbolt /usr/local/bin/deadbolt
RUN python -m pip install /tmp/dependencies/*.whl && rm -rf /tmp/dependencies && chmod 755 /usr/local/bin/deadbolt
COPY pyproject.toml LICENSE README.md /app/
COPY src /app/src
RUN python -m pip install . && useradd --uid 10001 --create-home swarm
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "counter_swarm.supervisor"]
