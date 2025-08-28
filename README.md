

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
>
> 


#  Waggle IPFS: Post-Quantum Mini-Network in Python

## 1. Core Goals

The system attempts to:

* Provide a **minimal IPFS-like node** (block storage, content addressing, DHT-based provider records).
* Support **libp2p transport** (if available) or fall back to a **post-quantum AEAD socket transport**.
* Introduce a **Waggle service**: a color-palette consensus protocol for round-based node coordination.
* Layer in **post-quantum key exchange (ML-KEM-768)** and **post-quantum signatures (Dilithium3)** using [pyoqs](https://github.com/open-quantum-safe/liboqs).
* Use a **local LLaMA model** (via `llama-cpp-python`) to generate colors, with a deterministic fallback.

It’s ambitious: you’re essentially prototyping an **IPFS + libp2p + PQ crypto + toy consensus protocol**.

---

## 2. Building Blocks

### 📦 BlockStore

* Content is encoded as **DAG-CBOR**, then stored in a filesystem directory.
* `cidv1_dagcbor` function builds proper CIDv1 identifiers (multicodec + multihash).
* Simple async API: `put`, `get`, `has`.

👉 This is the minimal backbone of an IPFS node.

---

### 🌐 Provider Index (DHT)

* Uses [`kademlia`](https://pypi.org/project/kademlia/) to store mappings like `prov:<cid> → [addresses]`.
* Adds Waggle-specific keys (`waggle:<round>` → participant addresses).

👉 This lets nodes discover who has which content, and who’s participating in consensus rounds.

---

### 🔒 Post-Quantum Session (PQSession)

* Wraps OQS KEM (default ML-KEM-768).
* Generates ephemeral keypairs for secure channel bootstrapping.
* Encapsulation + decapsulation to derive shared secrets.

👉 Gives us PQ-ready channels for both Libp2p fallback and Waggle sync.

---

### 🔑 AEAD & Multiplexing

* `AeadStream`: AES-GCM wrapper on asyncio streams with framing.
* `MiniMux`: lightweight multiplexer over AEAD streams.
* Used for fallback transport and Waggle protocols.

👉 This reimplements a mini libp2p-like transport layer — very clever.

---

### 🐝 Waggle Service

This is where things get wild:

* Each round (`round_seconds`), nodes:

  * Generate a color palette (LLM or deterministic).
  * Announce themselves via DHT.
  * Connect to peers for handshake.

* Handshake steps:

  1. Exchange "hello" JSON with PQ keys + signed palette.
  2. Verify signatures and palette similarity.
  3. If above threshold → derive session key.
  4. Add peer to allowlist until round expires.

👉 Essentially a **color-based quorum handshake protocol**. Peers that "see the same palette" are allowed into the swarm.

---

### 🎨 Color Consensus

* Palettes extracted either:

  * From LLaMA text output (`CSS names or hex`), or
  * Via deterministic HSV fallback.
* `palette_similarity()` uses hue distance + Jaccard similarity.
* Threshold decides whether to trust a peer.

👉 This is a quirky but creative **sybil-resistance + trust heuristic**.

---

### 🌐 HTTP API

* Mimics basic IPFS API endpoints:

  * `/api/v0/add` → add file
  * `/api/v0/cat` → fetch file
  * `/api/v0/id` → node identity
  * `/healthz` → metrics
* JSON + streaming responses.

👉 You could point a small IPFS client at this with minor modifications.

---

## 3. Strengths

✅ **Ambitious scope**: PQ crypto, libp2p, DHT, blockstore, HTTP API, consensus — all in \~1600 lines.
✅ **Fallback paths**: If libp2p isn’t present, still runs with custom transport.
✅ **Clean async design**: `asyncio` + tasks → scalable.
✅ **Security-minded**: PQ handshake + AES-GCM framing.
✅ **Hackable**: Each component (BlockStore, Waggle, Exchange) is modular.

---

## 4. Weak Spots & Improvements

🔸 **Error handling**
Many places `except Exception: pass`. Silent failures make debugging hard. Consider logging warnings.

🔸 **Transport fallback symmetry**
The FallbackTransport uses a random parity check (`if hash(...) % 2 == 0`) to decide initiator vs responder. This could break interoperability if hash seeds differ. Better: explicit role negotiation.

🔸 **Session management**
`WaggleService.sessions` is a dict of derived keys but doesn’t handle expiry. Old sessions could pile up.

🔸 **Cryptographic assumptions**

* PQ KEM + AES-GCM is fine, but "double encapsulation" (`ss+ss2`) may need careful review for forward secrecy.
* No replay protection in AEAD streams. Consider adding counters or nonces.

🔸 **DHT bootstrap**
If no bootstrap is provided, nodes will be isolated. Maybe add a default bootstrap list.

🔸 **Palette consensus practicality**
Similarity metric is interesting, but adversaries could spoof LLM-like palettes. Might need extra weighting (round ID, shared salt).

---

## 5. Future Directions

1. 🔧 **Interoperability**: Expose Libp2p Multiaddr in `/id`, so peers can connect using standard libp2p tooling.
2. 📡 **Gossip**: Add a gossip subprotocol for sharing Waggle round states instead of only pairwise.
3. 🛡 **Stronger replay protection**: Nonces, counters, or transcript hashing in AEAD channels.
4. 🧠 **Consensus metrics**: Log palette similarity scores per peer — could visualize cluster formation.
5. 🌍 **Integration with real IPFS**: Wrap this node so it can fetch from a real Kubo node.

---

## 6. TL;DR

This code is an **experimental IPFS-like node** that:

* Stores blocks with CIDv1
* Uses PQ crypto channels
* Syncs peers with color palette similarity
* Exposes a mini IPFS API

It’s not production-ready, but it’s a **fascinating playground** for post-quantum networking, decentralized consensus, and creative trust models.

