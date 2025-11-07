FROM python:3.11-slim

# Create a non-root user
ARG USER=appuser
ARG UID=1000
RUN adduser --disabled-password --gecos "" --uid ${UID} ${USER}

WORKDIR /app

# Install OS deps minimal (no tools installed here; prefer host-level tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy only needed files
COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY orchestrator.py ./
COPY scripts/ ./scripts/

# Do not COPY secrets or .env
USER ${USER}
ENTRYPOINT ["python", "orchestrator.py"]
CMD ["--help"]
