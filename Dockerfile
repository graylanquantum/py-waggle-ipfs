# ─────────────────────────────────────────────────────────────────────────────
# Fullstack Waggle/IPFS node (CPU) – Python 3.11 slim (Debian bookworm)
# Includes: aiohttp, kademlia, dag-cbor, cryptography, pyoqs, libp2p (optional),
# llama-cpp-python (CPU), webcolors, multiaddr, psutil.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # speed up numpy/scipy/openblas threading defaults
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    # llama.cpp build flags if a source build is required by your platform
    CMAKE_ARGS="-DLLAMA_BLAS=ON -DLLAMA_BLAS_VENDOR=OpenBLAS" \
    # default runtime addresses (override at `docker run`)
    API_ADDR="0.0.0.0:5101" \
    DHT_ADDR="0.0.0.0:6701" \
    P2P_ADDR="/ip4/0.0.0.0/tcp/4701" \
    USE_LIBP2P="1" \
    WAGGLE_ROUND="30" \
    WAGGLE_TOPIC="/waggle/colors/v2" \
    WAGGLE_KEM="ML-KEM-768" \
    WAGGLE_SIG="Dilithium3" \
    WAGGLE_THRESHOLD="0.78" \
    # model handling (opt-in download at runtime)
    LLAMA_MODEL="/models/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf" \
    DOWNLOAD_MODELS="0" \
    MODEL_URL="https://huggingface.co/QuantFactory/Meta-Llama-3-8B-Instruct-GGUF/resolve/main/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf" \
    MODEL_SHA256="86c8ea6c8b755687d0b723176fcd0b2411ef80533d23e2a5030f845d13ab2db7" \
    TMPDIR="/data/tmp"

# ── system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      git \
      curl ca-certificates \
      cmake ninja-build pkg-config \
      libopenblas-dev \
      libssl-dev libffi-dev \
      # runtime libs
      libstdc++6 libgomp1 libopenblas0 \
    && rm -rf /var/lib/apt/lists/*

# ── create non-root user & dirs
RUN useradd -m -u 10001 -s /usr/sbin/nologin app && \
    mkdir -p /app /models /data/tmp && \
    chown -R app:app /app /models /data

WORKDIR /app

# ── optional: if you have a requirements.txt, we’ll use it. Otherwise we install pinned runtime deps.
# copy first so pip install can be layer-cached
COPY requirements.txt /app/requirements.txt
RUN set -eux; \
    if [ -s requirements.txt ]; then \
        pip install --no-cache-dir -r requirements.txt; \
    else \
        pip install --no-cache-dir \
          aiohttp==3.9.5 \
          kademlia==2.2.2 \
          dag-cbor==0.3.3 \
          cryptography==43.0.0 \
          pyoqs==0.9.2 \
          psutil==6.0.0 \
          multiaddr==0.0.9 \
          webcolors==1.13 \
          # optional libp2p stack (best-effort; falls back if missing at runtime)
          libp2p==0.1.9 \
          # llama-cpp-python wheels often available; will compile if needed (uses OpenBLAS above)
          llama-cpp-python==0.2.90; \
    fi

# ── app code
# name your script exactly like this or adjust ENTRYPOINT below
COPY fullstack_waggle_ipfs.py /app/fullstack_waggle_ipfs.py

# ── entrypoint to optionally fetch GGUF model and start the node
RUN printf '%s\n' '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'mkdir -p /models /data/tmp' \
  'if [ "${DOWNLOAD_MODELS:-0}" = "1" ]; then' \
  '  if [ ! -f "${LLAMA_MODEL}" ]; then' \
  '    echo "Downloading model to ${LLAMA_MODEL}";' \
  '    curl -L --progress-bar "${MODEL_URL}" -o "${LLAMA_MODEL}"' \
  '    echo "${MODEL_SHA256}  ${LLAMA_MODEL}" | sha256sum -c -' \
  '  fi' \
  'fi' \
  'exec gosu app:app python /app/fullstack_waggle_ipfs.py --api "${API_ADDR}" --dht "${DHT_ADDR}" --p2p "${P2P_ADDR}" ${BOOTSTRAP:+--bootstrap "${BOOTSTRAP}"}' \
  > /usr/local/bin/docker-entrypoint.sh && chmod +x /usr/local/bin/docker-entrypoint.sh

# ── lightweight gosu for dropping root -> app
# (tiny setuid helper; safer than su/sudo and avoids lingering root-owned files)
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    curl -fsSL -o /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/1.17/gosu-${arch}" && \
    chmod +x /usr/local/bin/gosu && gosu --version

# ── ports
# api (tcp), dht (udp), libp2p (tcp)
EXPOSE 5101/tcp 6701/udp 4701/tcp

# ── healthcheck
HEALTHCHECK --interval=20s --timeout=3s --start-period=25s --retries=5 \
  CMD curl -fsS "http://127.0.0.1:${API_ADDR##*:}/healthz" || exit 1

USER app

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
