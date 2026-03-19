# ==============================================================
# OneInfinity — Production Dockerfile
# Multi-stage build:
#   Stage 1 (go-tools)   — compile all Go security binaries
#   Stage 2 (py-builder) — compile Python wheels
#   Stage 3 (final)      — minimal runtime image
#
# Build:
#   docker build -t oneinfinity .
#   docker build --build-arg INSTALL_AI=1 -t oneinfinity:ai .
#
# Run:
#   docker run --rm -it oneinfinity scan example.com
#   docker run --rm -it -v $(pwd):/data oneinfinity recon example.com
# ==============================================================

# ── Build args ────────────────────────────────────────────────
# INSTALL_AI=1    → install AI/red-team Python deps (heavy, ~2GB extra)
# INSTALL_MOBILE=1 → install mobile analysis Python deps
# GO_VERSION      → Go toolchain version used for compiling tools
ARG INSTALL_AI=0
ARG INSTALL_MOBILE=0
ARG GO_VERSION=1.22
ARG PYTHON_VERSION=3.11

# ==============================================================
# STAGE 1 — Go Tools Builder
# Compiles all Go-based security tools in a throwaway image.
# Only the resulting binaries are copied to the final stage.
# ==============================================================
FROM golang:${GO_VERSION}-bookworm AS go-tools

# Silence interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build output directory — copied wholesale into final image
ENV GOBIN=/go-bins
RUN mkdir -p /go-bins

# ── ProjectDiscovery suite ────────────────────────────────────
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# ── Web & crawling ─────────────────────────────────────────────
RUN go install github.com/lc/gau/v2/cmd/gau@latest
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/hakluke/hakrawler@latest
RUN go install github.com/tomnomnom/assetfinder@latest
RUN go install github.com/ffuf/ffuf/v2@latest

# ── Vulnerability scanning ─────────────────────────────────────
RUN go install github.com/hahwul/dalfox/v2@latest
RUN go install github.com/Emoe/kxss@latest
RUN go install github.com/dwisiswant0/crlfuzz@latest

# ── Secrets ────────────────────────────────────────────────────
RUN go install github.com/trufflesecurity/trufflehog/v3@latest
RUN go install github.com/zricethezav/gitleaks/v8@latest

# ── DNS & misc ─────────────────────────────────────────────────
RUN go install github.com/tomnomnom/gf@latest


# ==============================================================
# STAGE 2 — Python Wheels Builder
# Builds/downloads all Python packages so the final stage
# can install from a local cache without internet access.
# ==============================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS py-builder

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=0 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Build deps needed to compile some Python C-extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev libffi-dev \
        git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /wheels

# ── Copy requirement files ────────────────────────────────────
COPY requirements-core.txt   .
COPY requirements-ai.txt     .
COPY requirements-mobile.txt .
COPY requirements-web.txt    .

# ── Always-on: core + web ─────────────────────────────────────
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
        -r requirements-core.txt \
        -r requirements-web.txt

# ── Optional: AI/ML (slow — ~600 MB extra wheels) ─────────────
ARG INSTALL_AI=0
RUN if [ "$INSTALL_AI" = "1" ]; then \
        pip wheel --no-cache-dir --wheel-dir /wheels \
            adversarial-robustness-toolbox>=1.17.0 \
            playwright>=1.42.0 selenium>=4.18.0 \
        ; fi

# ── Optional: mobile ─────────────────────────────────────────
ARG INSTALL_MOBILE=0
RUN if [ "$INSTALL_MOBILE" = "1" ]; then \
        pip wheel --no-cache-dir --wheel-dir /wheels \
            androguard>=3.4.0 \
        ; fi


# ==============================================================
# STAGE 3 — Final Runtime Image
# Only what's needed to run oneinfinity. No compilers, no Go.
# ==============================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS final

LABEL org.opencontainers.image.title="OneInfinity" \
      org.opencontainers.image.description="AI-Powered Offensive Security Research Framework" \
      org.opencontainers.image.url="https://github.com/Inf1n1tyDeS0ul/oneinfinity" \
      org.opencontainers.image.source="https://github.com/Inf1n1tyDeS0ul/oneinfinity" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    # ── Python tuning ──────────────────────────────────────────
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # ── OneInfinity data directory ────────────────────────────
    # All scan output, DBs, and recon data go here.
    # Map a host directory to /data for persistence:
    #   -v $(pwd)/output:/data
    ONEINFINITY_HOME=/data \
    # ── Nuclei templates directory ────────────────────────────
    NUCLEI_TEMPLATES_PATH=/data/.nuclei-templates \
    # ── PATH — includes Go bins and pip scripts ───────────────
    PATH="/go-bins:/app/scripts:/usr/local/bin:${PATH}"

# ── System tools ──────────────────────────────────────────────
# Ordered by frequency of use (Docker cache-friendly).
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Core pentesting tools
        nmap \
        nikto \
        whatweb \
        # Build & language runtimes needed by wrappers
        perl \
        ruby \
        # HTTP utilities
        curl \
        wget \
        # Version control (secret scanning against repos)
        git \
        # DNS utilities
        dnsutils \
        # Process utilities
        procps \
        # Required by some Python C-extensions at runtime
        libssl3 \
        libffi8 \
        # masscan (fast port scanner — requires NET_RAW cap)
        masscan \
        # Terminal niceties
        less \
        # Shell (used by entrypoint and scripts)
        bash \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# ── Python tools installed as packages ───────────────────────
RUN pip install --no-cache-dir \
        sqlmap \
        dirsearch \
        sublist3r \
        paramspider \
        xssstrike \
        commix \
        arjun \
        s3scanner \
        gobuster 2>/dev/null || true
# NOTE: Some of the above may fail on newer Python; failures are
# non-fatal because they are optional scan-time tools.

# ── Go binary tools ───────────────────────────────────────────
COPY --from=go-tools /go-bins/ /go-bins/

# ── Python wheels ─────────────────────────────────────────────
COPY --from=py-builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels \
        $(ls /wheels/*.whl | xargs -I{} basename {} | sed 's/-[0-9].*//' | tr '\n' ' ') \
    2>/dev/null || \
    # Fallback: install wheel files directly
    pip install --no-cache-dir --no-index --find-links /wheels /wheels/*.whl \
    && rm -rf /wheels

# ── Application source ────────────────────────────────────────
WORKDIR /app
COPY . /app/

# Remove the .venv bundled in the repo (web/backend/.venv is huge)
RUN rm -rf /app/web/backend/.venv /app/__pycache__ \
    && find /app -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# ── Entrypoint & permissions ──────────────────────────────────
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /app/oneinfinity.py \
    # Symlink so `oneinfinity` resolves inside the container
    && ln -sf /app/oneinfinity.py /usr/local/bin/oneinfinity

# ── Non-root user (drop privileges for safer operation) ───────
# Security tools that need raw sockets must be run as root
# or with --cap-add=NET_RAW --cap-add=NET_ADMIN.
# Default: create a dedicated user; escalation docs provided below.
RUN groupadd -r oi && useradd -r -g oi -d /data -s /bin/bash oi \
    && mkdir -p /data \
    && chown -R oi:oi /data /go-bins

# ── Nuclei GF patterns directory ─────────────────────────────
RUN mkdir -p /home/oi/.gf \
    && chown -R oi:oi /home/oi || true

# ── Data volume ───────────────────────────────────────────────
# Declare /data as a volume.
# All scan output, SQLite DBs, and recon data land here.
VOLUME ["/data"]

USER oi

# ── Health check ──────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=1 \
    CMD python /app/oneinfinity.py --help > /dev/null 2>&1 || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--help"]
