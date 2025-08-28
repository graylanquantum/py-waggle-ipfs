# ─────────────────────────────────────────────────────────────────────────────
# Fullstack Waggle/IPFS node with PQE: liboqs (C) + oqs (Python) pinned
# Base: Python 3.11 slim (Debian bookworm)
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    CMAKE_ARGS="-DLLAMA_BLAS=ON -DLLAMA_BLAS_VENDOR=OpenBLAS" \
    API_ADDR="0.0.0.0:5101" \
    DHT_ADDR="0.0.0.0:6701" \
    P2P_ADDR="/ip4/0.0.0.0/tcp/4701" \
    USE_LIBP2P="1" \
    WAGGLE_ROUND="30" \
    WAGGLE_TOPIC="/waggle/colors/v2" \
    WAGGLE_KEM="ML-KEM-768" \
    WAGGLE_SIG="Dilithium3" \
    WAGGLE_THRESHOLD="0.78" \
    LLAMA_MODEL="/models/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf" \
    DOWNLOAD_MODELS="0" \
    MODEL_URL="https://huggingface.co/QuantFactory/Meta-Llama-3-8B-Instruct-GGUF/resolve/main/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf" \
    MODEL_SHA256="86c8ea6c8b755687d0b723176fcd0b2411ef80533d23e2a5030f845d13ab2db7" \
    TMPDIR="/data/tmp"

# --- system deps for liboqs & building wheels ---
RUN apt-get update && apt-get install -y --no-install-recommends \
      git cmake ninja-build build-essential pkg-config ca-certificates \
      curl libssl-dev libffi-dev \
      libopenblas-dev libopenblas0 libstdc++6 libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# --- build & install liboqs (shared, pinned to 0.14.0) ---
RUN git clone --branch "0.14.0" --depth=1 --recurse-submodules https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_USE_OPENSSL=OFF \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      -G Ninja \
 && cmake --build /tmp/liboqs/build --parallel \
 && cmake --install /tmp/liboqs/build \
 && rm -rf /tmp/liboqs

# help the dynamic linker find liboqs
RUN printf "/usr/local/lib\n" > /etc/ld.so.conf.d/usr-local-lib.conf && ldconfig
ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

# create non-root user & dirs
RUN useradd -m -u 10001 -s /usr/sbin/nologin app && \
    mkdir -p /app /models /data/tmp && \
    chown -R app:app /app /models /data

WORKDIR /app

# install Python deps (make sure liboqs-python is NOT in requirements.txt)
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
          psutil==6.0.0 \
          multiaddr==0.0.9 \
          webcolors==1.13 \
          libp2p==0.1.9 \
          llama-cpp-python==0.2.90; \
    fi

# install the oqs Python wrapper after liboqs exists (pinned to 0.12.0)
RUN pip install --no-cache-dir "git+https://github.com/open-quantum-safe/liboqs-python@0.12.0"

# app code (adjust filename if different)
COPY main.py /app/main.py

# lightweight gosu for dropping root -> app
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    curl -fsSL -o /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/1.17/gosu-${arch}" && \
    chmod +x /usr/local/bin/gosu && gosu --version

# entrypoint: optional GGUF fetch, then start node
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

# ports: api (tcp), dht (udp), p2p (tcp)
EXPOSE 5101/tcp 6701/udp 4701/tcp

# healthcheck
HEALTHCHECK --interval=20s --timeout=3s --start-period=25s --retries=5 \
  CMD sh -c 'curl -fsS "http://127.0.0.1:${API_ADDR##*:}/healthz" || exit 1'

USER app

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
