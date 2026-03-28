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
ARG GO_VERSION=1.24
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
# libpcap-dev  — required by naabu/gopacket (raw packet capture)
# build-essential/gcc — required by trufflehog (CGO via go-re2/wazero)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates libpcap-dev build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

# Allow Go to auto-download newer toolchains required by @latest modules
ENV GOTOOLCHAIN=auto

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
RUN go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# ── Secrets ────────────────────────────────────────────────────
# trufflehog's go.mod includes replace directives, which blocks `go install module@version`
RUN git clone --depth 1 --branch v3.93.8 https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog \
    && cd /tmp/trufflehog \
    && go build -o /go-bins/trufflehog . \
    && rm -rf /tmp/trufflehog
RUN go install github.com/zricethezav/gitleaks/v8@latest

# ── DNS & misc ─────────────────────────────────────────────────
RUN go install github.com/tomnomnom/gf@latest

# ── Util tools for CLI parity ──────────────────────────────────
RUN go install github.com/tomnomnom/anew@latest
RUN go install github.com/tomnomnom/qsreplace@latest
RUN go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
RUN go install github.com/OJ/gobuster/v3@latest 2>/dev/null || true
RUN go install github.com/bp0lr/gauplus@latest 2>/dev/null || true
# amass v4 (large build — non-fatal)
RUN go install github.com/owasp-amass/amass/v4/...@master 2>/dev/null || true
# kiterunner
RUN go install github.com/assetnote/kiterunner/cmd/kiterunner@latest 2>/dev/null || true
# cloudbrute
RUN go install github.com/0xsha/cloudbrute@latest 2>/dev/null || true


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

# ── Always-on: core + web + browser engine ────────────────────
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
        -r requirements-core.txt \
        -r requirements-web.txt \
        "playwright>=1.42.0" \
        "beautifulsoup4>=4.12.0"

# ── Optional: AI/ML (slow — ~600 MB extra wheels) ─────────────
ARG INSTALL_AI=0
RUN if [ "$INSTALL_AI" = "1" ]; then \
        pip wheel --no-cache-dir --wheel-dir /wheels \
            adversarial-robustness-toolbox>=1.17.0 \
            selenium>=4.18.0 \
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
    PATH="/go-bins:/app/scripts:/usr/local/bin:${PATH}" \
    # ── Python module search path ─────────────────────────────
    # Ensures `import oneinfinity`, `from core.reporter import ...` etc.
    # all resolve without installing the package in editable mode.
    PYTHONPATH=/app

# ── System tools ──────────────────────────────────────────────
# nikto and whatweb are not in Debian Bookworm repos; installed below via git.
# Playwright/Chromium requires several system libraries (libnss3, libatk, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        perl \
        ruby \
        ruby-dev \
        rubygems \
        curl \
        wget \
        git \
        dnsutils \
        procps \
        libssl3 \
        libffi8 \
        libpcap0.8 \
        masscan \
        cron \
        less \
        bash \
        # Playwright/Chromium system dependencies
        libnss3 \
        libnspr4 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libdbus-1-3 \
        libxcb1 \
        libxkbcommon0 \
        libx11-6 \
        libxcomposite1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libpango-1.0-0 \
        libcairo2 \
        libasound2 \
        fonts-liberation \
        xdg-utils \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# ── nikto (Perl web scanner — not in Debian Bookworm repos) ───
RUN git clone --depth=1 https://github.com/sullo/nikto /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# ── whatweb (web fingerprinting — not in Debian Bookworm repos) ─
RUN git clone --depth=1 https://github.com/urbanadventurer/WhatWeb /opt/whatweb \
    && ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb \
    && chmod +x /opt/whatweb/whatweb \
    && cd /opt/whatweb && gem install bundler --no-document \
    && bundle install --without development 2>/dev/null || true

# ── Python tools installed as packages ───────────────────────
# Each tool installed separately so one failure doesn't block others.
# Python 3.11 is used (unlike host 3.13) so wfuzz/paramspider install natively.
RUN pip install --no-cache-dir sqlmap 2>/dev/null || true
RUN pip install --no-cache-dir dirsearch 2>/dev/null || true
RUN pip install --no-cache-dir sublist3r 2>/dev/null || true
RUN pip install --no-cache-dir commix 2>/dev/null || true
RUN pip install --no-cache-dir arjun 2>/dev/null || true
RUN pip install --no-cache-dir s3scanner 2>/dev/null || true
RUN pip install --no-cache-dir wfuzz 2>/dev/null || true
RUN pip install --no-cache-dir garak 2>/dev/null || true
# paramspider: not on PyPI; minimal Wayback Machine shim
RUN printf '#!/usr/bin/env python3\nimport sys,urllib.request,json\ndom=sys.argv[sys.argv.index("-d")+1] if "-d" in sys.argv else (sys.argv[1] if len(sys.argv)>1 else "")\nif not dom: sys.exit(1)\nurl=f"https://web.archive.org/cdx/search/cdx?url=*.{dom}/*&output=json&fl=original&collapse=urlkey&limit=5000"\ntry:\n    data=json.loads(urllib.request.urlopen(url,timeout=30).read())[1:]\n    [print(r[0]) for r in data if "?" in r[0]]\nexcept Exception as e:\n    print(f"paramspider error: {e}",file=sys.stderr)\n' > /usr/local/bin/paramspider && chmod +x /usr/local/bin/paramspider
# xssstrike: PyPI name is XSStrike but it's not on PyPI; install from GitHub
RUN git clone --depth=1 https://github.com/s0md3v/XSStrike /opt/xssstrike 2>/dev/null \
    && pip install --no-cache-dir -r /opt/xssstrike/requirements.txt 2>/dev/null \
    && ln -sf /opt/xssstrike/xsstrike.py /usr/local/bin/xssstrike \
    && chmod +x /opt/xssstrike/xsstrike.py \
    || true
# jwt_tool: not on PyPI either; install from GitHub
RUN git clone --depth=1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null \
    && pip install --no-cache-dir -r /opt/jwt_tool/requirements.txt 2>/dev/null \
    && ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool \
    && chmod +x /opt/jwt_tool/jwt_tool.py \
    || true

# ── findomain (pre-built binary release) ─────────────────────
RUN curl -sL "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip" \
        -o /tmp/findomain.zip 2>/dev/null \
    && unzip -o /tmp/findomain.zip -d /go-bins/ 2>/dev/null \
    && chmod +x /go-bins/findomain \
    && rm -f /tmp/findomain.zip \
    || true

# ── rustscan (deb package release) ───────────────────────────
RUN RVER=$(curl -sL https://api.github.com/repos/RustScan/RustScan/releases/latest 2>/dev/null \
        | grep '"tag_name"' | grep -oP '[\d.]+' | head -1) \
    && echo "RustScan version: $RVER" \
    && [ -n "$RVER" ] \
    && curl -sL "https://github.com/RustScan/RustScan/releases/download/${RVER}/rustscan_${RVER}_amd64.deb" \
        -o /tmp/rustscan.deb 2>/dev/null \
    && dpkg -i /tmp/rustscan.deb 2>/dev/null \
    && rm -f /tmp/rustscan.deb \
    || true

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

# ── Playwright browser install ────────────────────────────────
# Must run as root (before USER oi) so chromium lands in /root/.cache/ms-playwright
# and is accessible to all users via PLAYWRIGHT_BROWSERS_PATH.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN pip install --no-cache-dir playwright 2>/dev/null || true \
    && playwright install chromium 2>/dev/null || true \
    && chmod -R a+rx /opt/ms-playwright 2>/dev/null || true

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
    && mkdir -p /data /data/.nuclei-templates /data/raw /data/databases /data/logs \
                /data/memory /data/reports \
    # /app must be readable+executable by oi; __pycache__ dirs must be writable
    && chown -R oi:oi /data /go-bins \
    && chmod -R o+rX /app \
    # Verify critical security binaries are present and executable
    && test -x /go-bins/nuclei   || (echo "FATAL: nuclei missing"   && exit 1) \
    && test -x /go-bins/httpx    || (echo "FATAL: httpx missing"    && exit 1) \
    && test -x /go-bins/subfinder || (echo "FATAL: subfinder missing" && exit 1) \
    # nuclei_list: registry alias for `nuclei -l <file>` (expected by tool registry)
    && ln -sf /go-bins/nuclei /go-bins/nuclei_list \
    # interactsh: registry uses `interactsh` but binary is `interactsh-client`
    && (test -f /go-bins/interactsh-client && ln -sf /go-bins/interactsh-client /go-bins/interactsh || true) \
    # gauplus fallback: if gauplus failed to build, symlink gau as gauplus
    && (test -f /go-bins/gauplus || (test -f /go-bins/gau && ln -sf /go-bins/gau /go-bins/gauplus) || true) \
    # kiterunner: binary may be named `kiterunner` or `kr`
    && (test -f /go-bins/kiterunner || (test -f /go-bins/kr && ln -sf /go-bins/kr /go-bins/kiterunner) || true)

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
