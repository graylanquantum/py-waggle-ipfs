

### usage

build:

```bash
docker build -t waggle-fullstack:latest .
```

run (no model download, LLM fallback palettes):

```bash
docker run --rm -p 5101:5101/tcp -p 6701:6701/udp -p 4701:4701/tcp \
  -e API_ADDR="0.0.0.0:5101" \
  -e DHT_ADDR="0.0.0.0:6701" \
  -e P2P_ADDR="/ip4/0.0.0.0/tcp/4701" \
  -v waggle_data:/data -v waggle_models:/models \
  waggle-fullstack:latest
```

run with automatic GGUF fetch:

```bash
docker run --rm -p 5101:5101 -p 6701:6701/udp -p 4701:4701 \
  -e DOWNLOAD_MODELS=1 \
  -e MODEL_URL="https://huggingface.co/QuantFactory/Meta-Llama-3-8B-Instruct-GGUF/resolve/main/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf" \
  -e MODEL_SHA256="86c8ea6c8b755687d0b723176fcd0b2411ef80533d23e2a5030f845d13ab2db7" \
  -e LLAMA_MODEL="/models/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf" \
  -v waggle_models:/models -v waggle_data:/data \
  waggle-fullstack:latest
```

bootstrap to another node’s DHT:

```bash
# if peer DHT is at 203.0.113.10:6701
docker run --rm -p 5101:5101 -p 6701:6701/udp -p 4701:4701 \
  -e BOOTSTRAP="203.0.113.10:6701" \
  waggle-fullstack:latest
```

> if `libp2p` import fails in the image, the app automatically falls back to the built-in PQ transport/mux. you can also force fallback with `-e USE_LIBP2P=0`.
