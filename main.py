#!/usr/bin/env python3
import os, sys, json, time, base64, re, math, threading, queue, uuid, random, hashlib, colorsys, secrets, struct, logging, signal, socket, pathlib, tempfile, argparse, asyncio, psutil
from typing import Dict, Any, Optional, List, Tuple, Callable, Awaitable, Union

try:
    import aiohttp, aiohttp.web
except Exception as e:
    print("pip install aiohttp", file=sys.stderr); raise

try:
    import oqs
    HAVE_OQS=True
except Exception:
    HAVE_OQS=False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except Exception as e:
    print("pip install cryptography", file=sys.stderr); raise

try:
    from dag_cbor import encode as dagcbor_encode, decode as dagcbor_decode
except Exception as e:
    print("pip install dag-cbor", file=sys.stderr); raise

try:
    from kademlia.network import Server as KadServer
except Exception as e:
    print("pip install kademlia", file=sys.stderr); raise

try:
    from llama_cpp import Llama
    HAS_LLAMA=True
except Exception:
    HAS_LLAMA=False

try:
    import webcolors
except Exception:
    webcolors=None

LOG = logging.getLogger("fullstack-waggle-ipfs")
logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"))

def b64e(b:bytes)->str:
    try: return base64.b64encode(b).decode()
    except Exception: return ""
def b64d(s:str)->bytes:
    try: return base64.b64decode(s.encode())
    except Exception: return b""
def sha256(b:bytes)->bytes:
    try: return hashlib.sha256(b).digest()
    except Exception: return b"\x00"*32
def h32(b:bytes)->str:
    try: return hashlib.sha256(b).hexdigest()[:32]
    except Exception: return "0"*32
def canonical(obj:Any)->bytes:
    try: return json.dumps(obj, separators=(",",":"), sort_keys=True).encode()
    except Exception: return b"{}"
def hkdf(ss:bytes, salt:bytes, info:bytes, n=32)->bytes:
    try:
        return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ss)
    except Exception:
        return b"\x00"*n
def jitter(s:float)->float:
    return max(0.02, s*(0.7+random.random()*0.6))

VARINT_MAX=(1<<63)-1
def _uvarint(n:int)->bytes:
    if n<0 or n>VARINT_MAX: raise ValueError("varint range")
    b=bytearray()
    while True:
        w=n & 0x7F; n >>= 7
        if n: b.append(w|0x80)
        else: b.append(w); break
    return bytes(b)
def _mh_sha256(d:bytes)->bytes:
    return bytes([0x12,32])+sha256(d)
def cidv1_dagcbor(data:bytes)->str:
    import base64 as _b32
    bin_cid=_uvarint(1)+_uvarint(0x71)+_mh_sha256(data)
    enc=_b32.b32encode(bin_cid).decode("ascii").lower().strip("=")
    return "b"+enc

class BlockStore:
    def __init__(self, root:str):
        self.root=pathlib.Path(root); self.root.mkdir(parents=True, exist_ok=True)
    def _p(self,cid:str)->pathlib.Path: return self.root/cid
    async def put(self, raw:bytes)->str:
        cid=cidv1_dagcbor(raw); tmp=self.root/(".tmp."+secrets.token_hex(8))
        tmp.write_bytes(raw); os.replace(tmp, self._p(cid)); return cid
    async def get(self, cid:str)->bytes:
        p=self._p(cid)
        if not p.exists(): raise FileNotFoundError("missing block")
        return p.read_bytes()
    async def has(self, cid:str)->bool:
        return self._p(cid).exists()

class ProviderIndex:
    def __init__(self, kad:KadServer):
        self.kad=kad
    async def provide(self, cid:str, addr:str):
        key=f"prov:{cid}"
        try:
            cur=await self.kad.get(key)
            if isinstance(cur,(bytes,bytearray)): cur=cur.decode()
            arr=json.loads(cur) if cur else []
        except Exception:
            arr=[]
        if addr not in arr: arr.append(addr)
        await self.kad.set(key, json.dumps(arr))
    async def find(self, cid:str)->List[str]:
        key=f"prov:{cid}"
        try:
            v=await self.kad.get(key)
            if isinstance(v,(bytes,bytearray)): v=v.decode()
            arr=json.loads(v) if v else []
            return [str(x) for x in arr]
        except Exception:
            return []
    async def waggle_set(self, round_id:int, addr:str):
        key=f"waggle:{round_id}"
        try:
            cur=await self.kad.get(key)
            if isinstance(cur,(bytes,bytearray)): cur=cur.decode()
            arr=json.loads(cur) if cur else []
        except Exception:
            arr=[]
        if addr not in arr: arr.append(addr)
        await self.kad.set(key, json.dumps(arr))
    async def waggle_get(self, round_id:int)->List[str]:
        key=f"waggle:{round_id}"
        try:
            v=await self.kad.get(key)
            if isinstance(v,(bytes,bytearray)): v=v.decode()
            arr=json.loads(v) if v else []
            return [str(x) for x in arr]
        except Exception:
            return []

class PQSession:
    def __init__(self, kem="ML-KEM-768"):
        self.kem_alg=kem; self.pk=None; self.sk=None
        if HAVE_OQS:
            self._kem=oqs.KeyEncapsulation(kem)
            self.pk=self._kem.generate_keypair()
            self.sk=self._kem.export_secret_key()
        else:
            self._kem=None
    def encap_to(self, pk:bytes)->Tuple[bytes,bytes]:
        if not HAVE_OQS: raise RuntimeError("OQS missing")
        with oqs.KeyEncapsulation(self.kem_alg) as k:
            ct,ss=k.encap_secret(pk); return ct,ss
    def decap(self, ct:bytes)->bytes:
        if not HAVE_OQS: raise RuntimeError("OQS missing")
        k=oqs.KeyEncapsulation(self.kem_alg); k.import_secret_key(self.sk); return k.decap_secret(ct)

class AeadStream:
    def __init__(self, reader:asyncio.StreamReader, writer:asyncio.StreamWriter, key:bytes):
        self.r=reader; self.w=writer; self.key=key; self.aes=AESGCM(key)
    async def send(self, payload:bytes):
        n=os.urandom(12); ct=self.aes.encrypt(n, payload, None)
        l=len(n)+len(ct); self.w.write(struct.pack("!I", l)+n+ct); await self.w.drain()
    async def recv(self)->bytes:
        hdr=await self.r.readexactly(4)
        l=struct.unpack("!I", hdr)[0]
        chunk=await self.r.readexactly(l)
        n=chunk[:12]; ct=chunk[12:]
        return self.aes.decrypt(n, ct, None)
    def close(self):
        try: self.w.close()
        except Exception: pass

class MiniMux:
    def __init__(self, aead:AeadStream):
        self.aead=aead; self.sid=0; self.inbox:Dict[int,asyncio.Queue]={}; self.reader_task=None; self._closed=False
    async def start(self):
        async def reader():
            while not self._closed:
                try:
                    data=await self.aead.recv()
                    if len(data)<5: continue
                    sid=struct.unpack("!I", data[:4])[0]
                    self.inbox.setdefault(sid, asyncio.Queue()).put_nowait(data[4:])
                except Exception:
                    break
        self.reader_task=asyncio.create_task(reader())
    async def open_stream(self)->Tuple[int,Callable[[bytes],Awaitable[None]],Callable[[],Awaitable[bytes]]]:
        self.sid+=1; sid=self.sid
        async def send(b:bytes): await self.aead.send(struct.pack("!I", sid)+b)
        async def recv()->bytes: return await self.inbox.setdefault(sid, asyncio.Queue()).get()
        return sid, send, recv
    async def close(self):
        self._closed=True
        try: self.aead.close()
        except Exception: pass
        try:
            if self.reader_task: self.reader_task.cancel()
        except Exception: pass

class Lp2pUnavailable(Exception): pass

class Libp2pWrapper:
    def __init__(self, listen_ma:str):
        self.listen_ma=listen_ma; self.host=None; self.handlers:Dict[str,Callable[[Any,Any],Awaitable[None]]]={}; self._ok=False
    async def start(self):
        try:
            from libp2p import new_node
            from libp2p.transport.tcp.tcp import TCP
            from libp2p.security.noise.transport import NoiseTransport
            from libp2p.mux.mplex.mplex import Mplex
            from multiaddr import Multiaddr
            self.host=await new_node(transport_opt=[TCP], muxer_opt=[Mplex], security_opt=[NoiseTransport])
            await self.host.get_network().listen(Multiaddr(self.listen_ma))
            for proto,handler in self.handlers.items():
                async def _mk(h):
                    async def _inner(stream):
                        try: await handler(self.host, stream)
                        except Exception: pass
                    return _inner
                await self.host.set_stream_handler(proto, await _mk(handler))
            self._ok=True
        except Exception as e:
            raise Lp2pUnavailable(str(e))
    def set_handler(self, proto:str, handler:Callable[[Any,Any],Awaitable[None]]):
        self.handlers[proto]=handler
        if self.host:
            try:
                async def _inner(stream):
                    try: await handler(self.host, stream)
                    except Exception: pass
                asyncio.create_task(self.host.set_stream_handler(proto, _inner))
            except Exception:
                pass
    async def stop(self):
        try:
            if self.host: await self.host.close()
        except Exception: pass
    async def dial(self, peer_addr:str, proto:str):
        from multiaddr import Multiaddr
        from libp2p.peer.peerinfo import info_from_p2p_addr
        madd=Multiaddr(peer_addr); peerinfo=info_from_p2p_addr(madd)
        await self.host.connect(peerinfo)
        return await self.host.new_stream(peerinfo.peer_id, [proto])

class FallbackTransport:
    def __init__(self, listen_addr:str):
        self.listen_addr=listen_addr; self.server=None; self.handlers:Dict[str,Callable[[AeadStream],Awaitable[None]]]={}; self._kem_alg="ML-KEM-768"
    def register(self, proto:str, handler:Callable[[AeadStream],Awaitable[None]]): self.handlers[proto]=handler
    async def start(self):
        host,port=self.listen_addr.split(":"); port=int(port)
        async def handle(reader, writer):
            try:
                my=PQSession(self._kem_alg)
                writer.write(struct.pack("!I", len(my.pk))+my.pk); await writer.drain()
                peer_pk_len=struct.unpack("!I", await reader.readexactly(4))[0]
                peer_pk=await reader.readexactly(peer_pk_len)
                if hash(writer.get_extra_info("peername"))%2==0:
                    ct,ss=my.encap_to(peer_pk)
                    writer.write(struct.pack("!I", len(ct))+ct); await writer.drain()
                    peer_ct_len=struct.unpack("!I", await reader.readexactly(4))[0]
                    peer_ct=await reader.readexactly(peer_ct_len)
                    ss2=my.decap(peer_ct)
                else:
                    peer_ct_len=struct.unpack("!I", await reader.readexactly(4))[0]
                    peer_ct=await reader.readexactly(peer_ct_len)
                    ss2=my.decap(peer_ct)
                    ct,ss=my.encap_to(peer_pk)
                    writer.write(struct.pack("!I", len(ct))+ct); await writer.drain()
                key=hkdf(ss+ss2, b"mini-fb", b"transport/1", 32)
                st=AeadStream(reader, writer, key)
                mux=MiniMux(st); await mux.start()
                sid, send, recv = await mux.open_stream()
                first=await recv()
                if not first.startswith(b"PROTO "): return
                proto=first[6:].decode().strip()
                h=self.handlers.get(proto)
                if not h: return
                await h(st)
            except Exception:
                pass
            finally:
                try: writer.close()
                except Exception: pass
        self.server=await asyncio.start_server(handle, host, port)
    async def stop(self):
        if self.server: self.server.close(); await self.server.wait_closed()
    async def dial(self, addr:str, proto:str)->AeadStream:
        host,port=addr.split(":"); port=int(port)
        r,w=await asyncio.open_connection(host,port)
        my=PQSession(self._kem_alg)
        w.write(struct.pack("!I", len(my.pk))+my.pk); await w.drain()
        srv_pk_len=struct.unpack("!I", await r.readexactly(4))[0]
        srv_pk=await r.readexactly(srv_pk_len)
        if hash((host,port))%2==0:
            ct,ss=my.encap_to(srv_pk)
            w.write(struct.pack("!I", len(ct))+ct); await w.drain()
            peer_ct_len=struct.unpack("!I", await r.readexactly(4))[0]
            peer_ct=await r.readexactly(peer_ct_len)
            ss2=my.decap(peer_ct)
        else:
            peer_ct_len=struct.unpack("!I", await r.readexactly(4))[0]
            peer_ct=await r.readexactly(peer_ct_len)
            ss2=my.decap(peer_ct)
            ct,ss=my.encap_to(srv_pk)
            w.write(struct.pack("!I", len(ct))+ct); await w.drain()
        key=hkdf(ss+ss2, b"mini-fb", b"transport/1", 32)
        st=AeadStream(r,w,key)
        mux=MiniMux(st); await mux.start()
        sid, send, recv = await mux.open_stream()
        await send(b"PROTO "+proto.encode())
        return st

EX_PROTO="/miniipfs/blocks/1.0.0"
WAG_PROTO="/waggle/colors/1.0.0"

HEX_RE=re.compile(r'#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})')
NAMED_RE=re.compile(r'\b([a-zA-Z]{3,20})\b')

def name_to_rgb(name:str)->Optional[Tuple[int,int,int]]:
    if webcolors is None: return None
    try:
        c=webcolors.name_to_rgb(name.lower()); return (c.red, c.green, c.blue)
    except Exception:
        return None

def parse_colors(text:str, n:int=8)->List[Tuple[int,int,int]]:
    out=[]
    for m in HEX_RE.findall(text or ""):
        hx=m.lstrip("#")
        if len(hx)==3: hx="".join([c*2 for c in hx])
        try:
            r=int(hx[0:2],16); g=int(hx[2:4],16); b=int(hx[4:6],16); out.append((r,g,b))
        except Exception: pass
        if len(out)>=n: return out[:n]
    if len(out)<n:
        for m in NAMED_RE.findall(text or ""):
            rgb=name_to_rgb(m)
            if rgb: out.append(rgb)
            if len(out)>=n: break
    while len(out)<n:
        r,g,b=colorsys.hsv_to_rgb(random.random(), 0.7, 0.9)
        out.append((int(r*255),int(g*255),int(b*255)))
    return out[:n]

def det_seed(*parts:str)->int:
    return int.from_bytes(sha256("|".join(parts).encode())[:8], "big")

def hue(rgb:Tuple[int,int,int])->float:
    r,g,b=[x/255.0 for x in rgb]; h,s,v=colorsys.rgb_to_hsv(r,g,b); return h
def circ(a:float,b:float)->float:
    d=abs(a-b); return min(d,1.0-d)

def palette_similarity(a:List[Tuple[int,int,int]], b:List[Tuple[int,int,int]])->float:
    if not a or not b: return 0.0
    n=min(len(a), len(b)); ha=[hue(x) for x in a[:n]]; hb=[hue(x) for x in b[:n]]
    d=sum(circ(ha[i],hb[i]) for i in range(n))/n
    aset={"%02x%02x%02x"%x for x in a}; bset={"%02x%02x%02x"%x for x in b}
    j=len(aset & bset)/max(1,len(aset|bset))
    return 0.6*(1.0-d)+0.4*j

class LLMColors:
    def __init__(self, model_path=None, ctx=2048, n_gpu_layers=-1):
        self.model_path=model_path or os.getenv("LLAMA_MODEL","/data/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf")
        self.ctx=ctx; self.n_gpu_layers=n_gpu_layers; self.ok=False
        if HAS_LLAMA:
            try:
                self.llm=Llama(model_path=self.model_path, n_ctx=self.ctx, n_gpu_layers=self.n_gpu_layers)
                self.ok=True
            except Exception:
                self.ok=False
    def prompt(self, rnd:str, node:str, topic:str)->str:
        return (
            "You are ColorSyncer. Output exactly 8 color tokens separated by spaces. "
            "Each token is a CSS color name or #RRGGBB. No extra words.\n"
            f"Round:{rnd} Node:{node} Topic:{topic}\nPalette:"
        )
    def generate(self, seed_text:str, rnd:str, node:str, topic:str)->List[Tuple[int,int,int]]:
        if self.ok:
            res=self.llm(self.prompt(rnd,node,topic), max_tokens=64, temperature=0.7, top_p=0.9, seed=det_seed(seed_text,rnd,node,topic)) or {}
            out=(res.get("choices") or [{}])[0].get("text","").strip()
            return parse_colors(out, 8)
        random.seed(det_seed(seed_text,rnd,node,topic))
        seq=[]
        for _ in range(8):
            r,g,b=colorsys.hsv_to_rgb(random.random(), 0.7, 0.9)
            seq.append((int(r*255),int(g*255),int(b*255)))
        return seq

class Allowlist:
    def __init__(self):
        self._ok=set(); self._lock=asyncio.Lock()
    async def allow(self, peer_addr:str, until:int):
        async with self._lock:
            self._ok.add((peer_addr, until))
    async def check(self, peer_addr:str)->bool:
        now=int(time.time())
        async with self._lock:
            new=set()
            ok=False
            for addr,exp in self._ok:
                if exp>=now:
                    new.add((addr,exp))
                    if addr==peer_addr: ok=True
            self._ok=new
            return ok

class ExchangeServer:
    def __init__(self, store:BlockStore, providers:ProviderIndex, dht_addr:str, transport:Union[Libp2pWrapper,FallbackTransport], allow:Allowlist):
        self.store=store; self.providers=providers; self.transport=transport; self.addr=dht_addr; self.allow=allow
        if isinstance(transport, Libp2pWrapper): transport.set_handler(EX_PROTO, self._lp2p_handler)
        else: transport.register(EX_PROTO, self._fb_handler)
    async def _lp2p_handler(self, host, stream):
        try:
            rw=stream
            async def rmsg()->bytes:
                b=await rw.read(4); if not b: return b""
                l=struct.unpack("!I", b)[0]; return await rw.read(l)
            async def wmsg(b:bytes):
                await rw.write(struct.pack("!I", len(b))+b); await rw.drain()
            hello=await rmsg()
            if not hello.startswith(b"ADDR "): return
            peer_addr=hello[5:].decode().strip()
            if not await self.allow.check(peer_addr):
                await wmsg(b"DENY"); return
            await wmsg(b"OK")
            while True:
                m=await rmsg()
                if not m: break
                op,_,rest=m.partition(b" ")
                if op==b"WANT":
                    cid=rest.decode().strip()
                    try:
                        raw=await self.store.get(cid)
                        await wmsg(b"BLOCK "+cid.encode()+b" "+raw)
                    except FileNotFoundError:
                        provs=await self.providers.find(cid)
                        await wmsg(b"MISS "+cid.encode()+b" "+json.dumps(provs).encode())
                elif op==b"PROVIDE":
                    cid=rest.decode().strip()
                    await self.providers.provide(cid, self.addr)
                    await wmsg(b"OK")
                else:
                    await wmsg(b"ERR")
        except Exception:
            pass
        finally:
            try: await stream.close()
            except Exception: pass
    async def _fb_handler(self, aead:AeadStream):
        try:
            mux=MiniMux(aead); await mux.start()
            sid, send, recv = await mux.open_stream()
            hello=await recv()
            if not hello.startswith(b"ADDR "): return
            peer_addr=hello[5:].decode().strip()
            if not await self.allow.check(peer_addr):
                await send(b"DENY"); return
            await send(b"OK")
            while True:
                m=await recv()
                op,_,rest=m.partition(b" ")
                if op==b"WANT":
                    cid=rest.decode().strip()
                    try:
                        raw=await self.store.get(cid)
                        await send(b"BLOCK "+cid.encode()+b" "+raw)
                    except FileNotFoundError:
                        provs=await self.providers.find(cid)
                        await send(b"MISS "+cid.encode()+b" "+json.dumps(provs).encode())
                elif op==b"PROVIDE":
                    cid=rest.decode().strip()
                    await self.providers.provide(cid, self.addr)
                    await send(b"OK")
                else:
                    await send(b"ERR")
        except Exception:
            pass

class ExchangeClient:
    def __init__(self, transport:Union[Libp2pWrapper,FallbackTransport], my_addr:str):
        self.t=transport; self.my_addr=my_addr
    async def get(self, peer_addr:str, cid:str)->Optional[bytes]:
        try:
            if isinstance(self.t, Libp2pWrapper):
                st=await self.t.dial(peer_addr, EX_PROTO)
                try:
                    await st.write(struct.pack("!I", 5+len(self.my_addr))+b"ADDR "+self.my_addr.encode()); await st.drain()
                    rlen=struct.unpack("!I", await st.read(4))[0]; rsp=await st.read(rlen)
                    if rsp!=b"OK": return None
                    pay=b"WANT "+cid.encode()
                    await st.write(struct.pack("!I", len(pay))+pay); await st.drain()
                    rlen=struct.unpack("!I", await st.read(4))[0]; resp=await st.read(rlen)
                    if resp.startswith(b"BLOCK "): return resp.split(b" ",2)[2]
                finally:
                    try: await st.close()
                    except Exception: pass
            else:
                st=await self.t.dial(peer_addr, EX_PROTO)
                mux=MiniMux(st); await mux.start()
                sid, send, recv = await mux.open_stream()
                await send(b"ADDR "+self.my_addr.encode())
                if await recv()!=b"OK": return None
                await send(b"WANT "+cid.encode())
                rsp=await recv()
                if rsp.startswith(b"BLOCK "): return rsp.split(b" ",2)[2]
                st.close()
        except Exception:
            return None
        return None

class MiniIPFSNode:
    def __init__(self, api_host:str, api_port:int, dht_host:str, dht_port:int, listen:str, bootstrap:Optional[str], allow:Allowlist):
        self.api=(api_host, api_port); self.dht=(dht_host, dht_port); self.listen=listen; self.bootstrap=bootstrap
        self.store=BlockStore(os.path.join(tempfile.gettempdir(), "miniipfs_blocks"))
        self.kad=KadServer()
        self.lp2p_ok=False
        self.transport:Union[Libp2pWrapper,FallbackTransport]
        self._choose_transport()
        self.providers=ProviderIndex(self.kad)
        dht_addr=self.listen if self.lp2p_ok else f"{self.dht[0]}:{self.dht[1]+2000}"
        self.exchange=ExchangeServer(self.store, self.providers, dht_addr, self.transport, allow)
        my_addr=self.listen if self.lp2p_ok else f"{self.dht[0]}:{self.dht[1]+2001}"
        self.client=ExchangeClient(self.transport, my_addr)
        self.app=aiohttp.web.Application()
        self.app.add_routes([
            aiohttp.web.post("/api/v0/add", self.http_add),
            aiohttp.web.get("/api/v0/cat", self.http_cat),
            aiohttp.web.get("/api/v0/id", self.http_id),
            aiohttp.web.get("/healthz", self.http_health),
        ])
        self._runner=None; self._site=None
    def _choose_transport(self):
        if os.getenv("USE_LIBP2P","1")!="0":
            try:
                self.transport=Libp2pWrapper(self.listen); self.lp2p_ok=True; return
            except Exception:
                self.lp2p_ok=False
        host,port=self.dht; self.transport=FallbackTransport(f"{host}:{port+2001}"); self.lp2p_ok=False
    async def start(self):
        await self.kad.listen(self.dht[1], interface=self.dht[0])
        if self.bootstrap:
            bhost,bport=self.bootstrap.split(":"); await self.kad.bootstrap([(bhost,int(bport))])
        try:
            await self.transport.start()
        except Lp2pUnavailable:
            host,port=self.dht; self.transport=FallbackTransport(f"{host}:{port+2001}"); await self.transport.start()
        self._runner=aiohttp.web.AppRunner(self.app); await self._runner.setup()
        self._site=aiohttp.web.TCPSite(self._runner, self.api[0], self.api[1]); await self._site.start()
        LOG.info(json.dumps({"api":f"http://{self.api[0]}:{self.api[1]}","dht":f"{self.dht[0]}:{self.dht[1]}","listen":self.listen,"libp2p":self.lp2p_ok}))
    async def stop(self):
        try: await self.kad.stop()
        except Exception: pass
        try: await self.transport.stop()
        except Exception: pass
        try: await self._runner.cleanup()
        except Exception: pass
    async def http_health(self, req):
        return aiohttp.web.json_response({"ok":True,"cpu":psutil.cpu_percent(),"rss":psutil.Process().memory_info().rss,"libp2p":self.lp2p_ok})
    async def http_id(self, req):
        nid=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{self.listen}-{self.dht}-{self.api}"))
        listen=self.listen if self.lp2p_ok else f"/ip4/{self.dht[0]}/tcp/{self.dht[1]+2001}"
        return aiohttp.web.json_response({"ID":nid,"Addresses":[listen]})
    async def http_add(self, req):
        try:
            if req.can_read_body and req.content_type.startswith("multipart/"):
                post=await req.post(); f=post.get("file")
                if f is None: return aiohttp.web.json_response({"Message":"file missing"}, status=400)
                data=f.file.read()
            else:
                data=await req.read()
                if not data: return aiohttp.web.json_response({"Message":"empty"}, status=400)
            block=dagcbor_encode({"bytes":data})
            cid=await self.store.put(block)
            addr=self.listen if self.lp2p_ok else f"{self.dht[0]}:{self.dht[1]+2001}"
            await self.providers.provide(cid, addr)
            return aiohttp.web.json_response({"Name": getattr(f,"filename",""), "Hash": cid, "Size": len(block)})
        except Exception as e:
            return aiohttp.web.json_response({"Message":str(e)}, status=500)
    async def http_cat(self, req):
        cid=req.query.get("arg") or req.query.get("cid")
        if not cid: return aiohttp.web.Response(status=400, text="arg missing")
        if await self.store.has(cid):
            raw=await self.store.get(cid)
            try: obj=dagcbor_decode(raw); data=obj.get("bytes", b"")
            except Exception: data=raw
            return aiohttp.web.Response(body=data)
        provs=await self.providers.find(cid)
        for addr in provs:
            try:
                data=await asyncio.wait_for(self.client.get(addr, cid), timeout=8.0)
                if data is not None: return aiohttp.web.Response(body=data)
            except Exception:
                await asyncio.sleep(jitter(0.2))
        return aiohttp.web.Response(status=404, text="not found")

class WaggleService:
    def __init__(self, providers:ProviderIndex, transport:Union[Libp2pWrapper,FallbackTransport], identity_addr:str, topic:str, round_seconds:int, kem_alg:str, sig_alg:str, threshold:float, model_path:Optional[str]):
        self.providers=providers; self.transport=transport; self.identity_addr=identity_addr; self.topic=topic; self.round_seconds=round_seconds
        self.kem_alg=kem_alg; self.sig_alg=sig_alg; self.threshold=threshold
        self.llm=LLMColors(model_path=model_path)
        self.sig_pk=None; self.sig_sk=None
        self.kem_pk=None; self.kem_sk=None
        self.pending:Dict[Tuple[str,int],bytes]={}
        self.sessions:Dict[Tuple[str,int],bytes]={}
        self.inflight=set()
        self.stop_flag=False
        self._init_pq()
        if isinstance(transport, Libp2pWrapper): transport.set_handler(WAG_PROTO, self._lp2p_handler)
        else: transport.register(WAG_PROTO, self._fb_handler)
    def _init_pq(self):
        if not HAVE_OQS: raise RuntimeError("pyoqs required")
        with oqs.Signature(self.sig_alg) as s:
            self.sig_pk=s.generate_keypair(); self.sig_sk=s.export_secret_key()
        with oqs.KeyEncapsulation(self.kem_alg) as k:
            self.kem_pk=k.generate_keypair(); self.kem_sk=k.export_secret_key()
    def round_id(self)->int: return int(time.time()//self.round_seconds)
    def _sign(self, body:Dict[str,Any])->str:
        b={k:v for k,v in body.items() if k!="sig"}
        with oqs.Signature(self.sig_alg) as s:
            s.import_secret_key(self.sig_sk); sig=s.sign(canonical(b))
        return b64e(sig)
    def _verify(self, body:Dict[str,Any], pk:bytes)->bool:
        b={k:v for k,v in body.items() if k!="sig"}; sig=b64d(body.get("sig",""))
        with oqs.Signature(self.sig_alg) as v:
            v.import_public_key(pk); return v.verify(canonical(b), sig)
    def _palette(self, rnd:int)->List[Tuple[int,int,int]]:
        seed=f"{self.topic}|{rnd}|{self.identity_addr}"; return self.llm.generate(seed, str(rnd), self.identity_addr, self.topic)
    def _derive(self, ss:bytes, a:str, b:str, rnd:int)->bytes:
        salt=sha256(f"{self.topic}|{rnd}".encode()); info=("WAGGLE-"+("|".join(sorted([a,b])))).encode()
        return hkdf(ss, salt, info, 32)
    async def _announce_round(self, rnd:int):
        try:
            await self.providers.waggle_set(rnd, self.identity_addr)
        except Exception:
            pass
    def _pack_hello(self, rnd:int, palette:List[Tuple[int,int,int]])->bytes:
        obj={
            "t":"hello","topic":self.topic,"round":rnd,"addr":self.identity_addr,
            "kem_alg":self.kem_alg,"sig_alg":self.sig_alg,
            "kem_pk":b64e(self.kem_pk),"sig_pk":b64e(self.sig_pk),
            "seq":["#%02x%02x%02x"%c for c in palette],
            "ts":now_ms()
        }
        obj["sig"]=self._sign(obj); data=canonical(obj)
        return struct.pack("!I", len(data))+data
    def _unpack(self, blob:bytes)->Optional[Dict[str,Any]]:
        try: return json.loads(blob.decode())
        except Exception: return None
    async def _lp2p_handler(self, host, stream):
        try:
            rw=stream
            async def rblob()->bytes:
                b=await rw.read(4); if not b: return b""
                l=struct.unpack("!I", b)[0]; return await rw.read(l)
            async def wblob(b:bytes):
                await rw.write(struct.pack("!I", len(b))+b); await rw.drain()
            m=await rblob()
            obj=self._unpack(m)
            if not obj or obj.get("t")!="hello": return
            if not obj.get("topic")==self.topic: return
            pk=b64d(obj.get("sig_pk",""))
            if not self._verify(obj, pk): return
            their_addr=obj.get("addr"); rnd=obj.get("round")
            their_seq=[]
            for hx in obj.get("seq",[]):
                try:
                    v=hx.lstrip("#"); their_seq.append((int(v[0:2],16),int(v[2:4],16),int(v[4:6],16)))
                except Exception: pass
            my_seq=self._palette(rnd)
            sim=palette_similarity(my_seq, their_seq)
            if sim<self.threshold:
                await wblob(canonical({"t":"reject"})); return
            with oqs.KeyEncapsulation(self.kem_alg) as k:
                k.import_secret_key(self.kem_sk); ss=k.decap_secret(b64d(obj["kem_ct"])) if "kem_ct" in obj else None
            if ss is None:
                ct, ss2 = PQSession(self.kem_alg).encap_to(b64d(obj["kem_pk"]))
                key=self._derive(ss2, self.identity_addr, their_addr, rnd)
                ack={"t":"lock","round":rnd,"addr":self.identity_addr,"nonce":b64e(os.urandom(12))}
                n=os.urandom(12); box=AESGCM(key).encrypt(n, b"wag-lock", canonical(ack))
                reply={"t":"lock","from":self.identity_addr,"nonce":b64e(n),"box":b64e(box)}
                await wblob(canonical(reply))
                self.sessions[(their_addr,rnd)]=key
            else:
                key=self._derive(ss, their_addr, self.identity_addr, rnd)
                self.sessions[(their_addr,rnd)]=key
                await wblob(canonical({"t":"ack"}))
        except Exception:
            pass
        finally:
            try: await stream.close()
            except Exception: pass
    async def _fb_handler(self, aead:AeadStream):
        try:
            mux=MiniMux(aead); await mux.start()
            sid, send, recv = await mux.open_stream()
            first=await recv()
            obj=self._unpack(first)
            if not obj or obj.get("t")!="hello": return
            pk=b64d(obj.get("sig_pk",""))
            if not self._verify(obj, pk): return
            their_addr=obj.get("addr"); rnd=obj.get("round")
            their_seq=[]
            for hx in obj.get("seq",[]):
                try:
                    v=hx.lstrip("#"); their_seq.append((int(v[0:2],16),int(v[2:4],16),int(v[4:6],16)))
                except Exception: pass
            my_seq=self._palette(rnd); sim=palette_similarity(my_seq,their_seq)
            if sim<self.threshold:
                await send(canonical({"t":"reject"})); return
            ct=None; ss=None
            try:
                pass
            except Exception:
                pass
            await send(canonical({"t":"ack","ok":True}))
            self.sessions[(their_addr,rnd)]=b"\x00"*32
        except Exception:
            pass
    async def round_loop(self):
        last=None
        while not self.stop_flag:
            rnd=self.round_id()
            if rnd!=last:
                last=rnd
                seq=self._palette(rnd)
                await self._announce_round(rnd)
                try:
                    peers=await self.providers.waggle_get(rnd)
                except Exception:
                    peers=[]
                for addr in peers:
                    if addr==self.identity_addr: continue
                    if (addr,rnd) in self.inflight: continue
                    self.inflight.add((addr,rnd))
                    asyncio.create_task(self._dial_and_sync(addr, rnd, seq))
            await asyncio.sleep(0.5)
    async def _dial_and_sync(self, peer_addr:str, rnd:int, seq:List[Tuple[int,int,int]]):
        try:
            if isinstance(self.transport, Libp2pWrapper):
                st=await self.transport.dial(peer_addr, WAG_PROTO)
                try:
                    await st.write(self._pack_hello(rnd, seq)); await st.drain()
                    rlenb=await st.read(4)
                    if not rlenb: return
                    rlen=struct.unpack("!I", rlenb)[0]
                    resp=json.loads((await st.read(rlen)).decode())
                    if resp.get("t") in ("ack","lock"):
                        exp=int(time.time())+self.round_seconds
                        await ALLOW.allow(peer_addr, exp)
                finally:
                    try: await st.close()
                    except Exception: pass
            else:
                st=await self.transport.dial(self.identity_addr.replace("/ip4/","").replace("/tcp/","").replace("/",""), WAG_PROTO)
                mux=MiniMux(st); await mux.start()
                sid, send, recv = await mux.open_stream()
                await send(self._pack_hello(rnd, seq))
                rsp=await recv()
                try:
                    obj=json.loads(rsp.decode())
                except Exception:
                    obj=None
                if obj and obj.get("t") in ("ack","lock"):
                    exp=int(time.time())+self.round_seconds
                    await ALLOW.allow(peer_addr, exp)
        except Exception:
            pass
        finally:
            try: self.inflight.remove((peer_addr,rnd))
            except Exception: pass

ANSI=sys.stdout.isatty()
def rgb_block(rgb:Tuple[int,int,int])->str:
    if not ANSI: return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
    return f"\x1b[48;2;{rgb[0]};{rgb[1]};{rgb[2]}m  \x1b[0m"
def show_palette(title:str, seq:List[Tuple[int,int,int]]):
    print(title, end=" ")
    for c in seq: sys.stdout.write(rgb_block(c))
    print()

async def orchestrate(args):
    global ALLOW
    ALLOW=Allowlist()
    api_host,api_port=args.api.split(":"); api_port=int(api_port)
    dht_host,dht_port=args.dht.split(":"); dht_port=int(dht_port)
    node=MiniIPFSNode(api_host, api_port, dht_host, dht_port, args.p2p, args.bootstrap, ALLOW)
    identity_addr = args.p2p if args.p2p.startswith("/ip4/") else f"/ip4/{dht_host}/tcp/{dht_port+2001}"
    wag=WaggleService(node.providers, node.transport, identity_addr, args.topic, args.round_seconds, args.kem, args.sig, args.threshold, args.model)
    stop=asyncio.Event()
    loop=asyncio.get_event_loop()
    try:
        loop.add_signal_handler(signal.SIGINT, stop.set)
        loop.add_signal_handler(signal.SIGTERM, stop.set)
    except Exception:
        pass
    await node.start()
    asyncio.create_task(wag.round_loop())
    print(json.dumps({"peer":identity_addr, "topic":args.topic, "kem":args.kem, "sig":args.sig, "model":("llama" if wag.llm.ok else "fallback")}))
    await stop.wait()
    wag.stop_flag=True
    await node.stop()

def main():
    ap=argparse.ArgumentParser(prog="fullstack-waggle-ipfs")
    ap.add_argument("--api", default="127.0.0.1:5101")
    ap.add_argument("--dht", default="0.0.0.0:6701")
    ap.add_argument("--p2p", default="/ip4/0.0.0.0/tcp/4701")
    ap.add_argument("--bootstrap", default=None)
    ap.add_argument("--topic", default="/waggle/colors/v2")
    ap.add_argument("--round-seconds", type=int, default=int(os.getenv("WAGGLE_ROUND","30")))
    ap.add_argument("--kem", default=os.getenv("WAGGLE_KEM","ML-KEM-768"))
    ap.add_argument("--sig", default=os.getenv("WAGGLE_SIG","Dilithium3"))
    ap.add_argument("--threshold", type=float, default=0.78)
    ap.add_argument("--model", default=os.getenv("LLAMA_MODEL","/data/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf"))
    args=ap.parse_args()
    try:
        asyncio.run(orchestrate(args))
    except KeyboardInterrupt:
        pass

if __name__=="__main__":
    main()
