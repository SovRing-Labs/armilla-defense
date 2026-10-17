"""Offline fixture authentication plus bounded trusted persistent anti-replay state.

Uses own Greenmark Ed25519 reference. This is not a network service, production
key store, rollback-proof storage, constant-time implementation or verifiable HE.
"""
import copy
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
try:
    from .common import Refusal,canonical,digest,greenmark,exact_int
except ImportError:
    from common import Refusal,canonical,digest,greenmark,exact_int

FIELDS={"version","payload","context","operator","dependencies","issuer","audience","key_epoch","sequence","nonce","issued","expiry"}


def _pairs(pairs):
    out={}
    for k,v in pairs:
        if k in out:raise Refusal("duplicate_JSON_field")
        out[k]=v
    return out


def encode(value):
    # Canonical wave machinery checks unsupported/nonfinite/deep/large forms.
    canonical(value)
    def json_type(v):
        if type(v) in (str,int,float,bool) or v is None:return
        if type(v) is list:
            for x in v:json_type(x)
            return
        if type(v) is dict and all(type(k) is str for k in v):
            for x in v.values():json_type(x)
            return
        raise Refusal("unsupported_JSON_type")
    json_type(value)
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
    if len(raw)>65536:raise Refusal("envelope_byte_budget")
    return raw


def decode(raw):
    if type(raw) is not bytes or len(raw)>65536:raise Refusal("envelope_byte_budget")
    try:d=json.loads(raw,object_pairs_hook=_pairs)
    except (ValueError,UnicodeError,RecursionError):raise Refusal("malformed_envelope")
    if encode(d)!=raw:raise Refusal("noncanonical_envelope")
    return d


@dataclass(frozen=True)
class Signed:
    body: bytes
    signature: bytes


def sign_fixture(body,seed):
    raw=encode(body)
    return Signed(raw,greenmark().sign(seed,raw))


def body(payload,context,operator="receipt-v1",dependencies=None,issuer="fixture",audience="local-review",key_epoch=1,sequence=0,nonce=None,issued=1000,expiry=1200):
    return {"version":1,"payload":copy.deepcopy(payload),"context":context,"operator":operator,
            "dependencies":copy.deepcopy({} if dependencies is None else dependencies),
            "issuer":issuer,"audience":audience,"key_epoch":key_epoch,"sequence":sequence,
            "nonce":("fixture-"+str(sequence)) if nonce is None else nonce,"issued":issued,"expiry":expiry}


@dataclass(frozen=True)
class Principal:
    issuer: str="fixture"
    audience: str="local-review"
    epoch: int=1
    public_key: bytes=b""

    @property
    def name(self):return digest((self.issuer,self.audience,self.epoch,self.public_key))

    def validate(self):
        if not self.issuer or not self.audience or type(self.issuer) is not str or type(self.audience) is not str:raise Refusal("trust_registry")
        exact_int(self.epoch)
        if not 1<=self.epoch<2**32 or type(self.public_key) is not bytes or len(self.public_key)!=32:raise Refusal("trust_registry")
        G=greenmark();point=G._decode(self.public_key);neutral=(0,1,1,0)
        if point is None or G._encode(point)!=self.public_key or G._eq(G._mul(8,point),neutral) or not G._eq(G._mul(G.L,point),neutral):raise Refusal("trust_public_key")
        return self




class Store:
    def __init__(self,path,principals):
        self.path=Path(path);self.principals=tuple(p.validate() for p in principals)
        if not 1<=len(self.principals)<=16 or len({(p.issuer,p.audience,p.epoch) for p in self.principals})!=len(self.principals):raise Refusal("trust_registry")
        self.policy=digest(tuple((p.issuer,p.audience,p.epoch,p.public_key) for p in self.principals))
        if not self.path.parent.is_dir():raise Refusal("store_parent_missing")
        self._load()  # Opening missing/established corrupt state NEVER enrolls.

    @classmethod
    def enroll(cls,path,principals):
        path=Path(path);principals=tuple(principals)
        # Enrollment is a separately explicit operation, never an admission fallback.
        if not path.parent.is_dir():raise Refusal("store_parent_missing")
        for p in principals:p.validate()
        if not 1<=len(principals)<=16 or len({(p.issuer,p.audience,p.epoch) for p in principals})!=len(principals):raise Refusal("trust_registry")
        policy=digest(tuple((p.issuer,p.audience,p.epoch,p.public_key) for p in principals))
        raw=cls._pack({"version":1,"policy":policy,"clock":0,"principals":{}})
        try:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                with os.fdopen(fd,"wb") as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                cls._sync_parent(path)
            except OSError:raise Refusal("store_persistence")
        except FileExistsError:raise Refusal("already_enrolled")
        except OSError:raise Refusal("store_persistence")
        return cls(path,principals)

    @staticmethod
    def _pack(state):
        raw=encode(state)
        return encode({"state":state,"checksum":hashlib.sha256(raw).hexdigest()})

    @staticmethod
    def _sync_parent(path):
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def _load(self):
        try:
            fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,"rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):raise Refusal("store_corrupt")
                raw=stream.read(65537)
        except FileNotFoundError:raise Refusal("established_store_missing")
        except OSError:raise Refusal("store_unavailable")
        try:
            wrapper=decode(raw)
            if type(wrapper) is not dict or set(wrapper)!={"state","checksum"}:raise Refusal("store_corrupt")
            state=wrapper["state"]
            if hashlib.sha256(encode(state)).hexdigest()!=wrapper["checksum"]:raise Refusal("store_corrupt")
            if type(state) is not dict or set(state)!={"version","policy","clock","principals"} or (type(state["version"]) is not int or state["version"]!=1) or state["policy"]!=self.policy:raise Refusal("store_corrupt")
            exact_int(state["clock"])
            if not 0<=state["clock"]<2**63 or type(state["principals"]) is not dict or len(state["principals"])>4:raise Refusal("store_corrupt")
            trusted={p.name for p in self.principals}
            for name,row in state["principals"].items():
                if name not in trusted or type(row) is not dict or set(row)!={"sequence","nonces"}:raise Refusal("store_corrupt")
                if type(row["sequence"]) is not int or not 0<=row["sequence"]<2**64 or type(row["nonces"]) is not list or len(row["nonces"])>64 or any(type(n) is not str or not 1<=len(n)<=64 for n in row["nonces"]) or len(set(row["nonces"]))!=len(row["nonces"]):raise Refusal("store_corrupt")
            return state
        except (Refusal,KeyError,TypeError,ValueError):raise Refusal("store_corrupt")

    def _persist(self,state):
        raw=self._pack(state)
        temporary=self.path.with_name(self.path.name+".pending-"+secrets.token_hex(8))
        try:
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,"wb") as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,self.path);self._sync_parent(self.path)
        except OSError:raise Refusal("store_persistence")
        # Failed temp files are retained as bounded diagnostic artifacts, not silently removed.

    def inspect(self,envelope,now,context,operator,dependencies=None,expected_payload=None):
        exact_int(now)
        if not 0<=now<2**63:raise Refusal("trusted_time_range")
        if not isinstance(envelope,Signed) or type(envelope.signature) is not bytes or len(envelope.signature)!=64:raise Refusal("unsigned_or_malformed")
        d=decode(envelope.body)
        if type(d) is not dict or set(d)!=FIELDS or type(d["version"]) is not int or d["version"]!=1:raise Refusal("envelope_schema")
        for field in ("context","operator","issuer","audience","nonce"):
            if type(d[field]) is not str or not 1<=len(d[field])<=256:raise Refusal("envelope_schema")
        if len(d["nonce"])>64 or type(d["dependencies"]) is not dict:raise Refusal("envelope_schema")
        for field in ("key_epoch","sequence","issued","expiry"):exact_int(d[field])
        if not 1<=d["key_epoch"]<2**32 or not 0<=d["sequence"]<2**64:raise Refusal("envelope_schema")
        principal=next((p for p in self.principals if p.issuer==d["issuer"] and p.audience==d["audience"] and p.epoch==d["key_epoch"]),None)
        if principal is None:raise Refusal("untrusted_issuer_audience_epoch")
        if not greenmark().verify(principal.public_key,envelope.body,envelope.signature):raise Refusal("authentication_failed")
        if (d["context"],d["operator"],d["dependencies"])!=(context,operator,{} if dependencies is None else dependencies):raise Refusal("authenticated_context_mismatch")
        if not 0<=d["issued"]<=d["expiry"]<2**63 or d["expiry"]-d["issued"]>300:raise Refusal("invalid_lifetime")
        if d["issued"]>now+2:raise Refusal("future_message")
        if d["expiry"]<now-2:raise Refusal("expired_message")
        if expected_payload is not None and encode(d["payload"])!=encode(expected_payload):raise Refusal("independent_target_mismatch")
        return d,principal

    def admit(self,envelope,now,context,operator="receipt-v1",dependencies=None,expected_payload=None):
        d,principal=self.inspect(envelope,now,context,operator,dependencies,expected_payload)
        lock=self.path.with_name(self.path.name+".guardlock")
        try:fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        except OSError:raise Refusal("store_unavailable")
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            state=self._load()  # Re-read under a stable lock; stale Store objects cannot replay.
            if now<state["clock"]:raise Refusal("trusted_clock_rollback")
            prior=state["principals"].get(principal.name)
            if prior is None:
                if len(state["principals"])>=4:raise Refusal("freshness_capacity")
                prior={"sequence":-1,"nonces":[]}
            if d["sequence"]<=prior["sequence"]:raise Refusal("replay_or_out_of_order")
            if d["nonce"] in prior["nonces"]:raise Refusal("nonce_reuse")
            state["principals"][principal.name]={"sequence":d["sequence"],"nonces":(prior["nonces"]+[d["nonce"]])[-64:]}
            state["clock"]=now
            self._persist(state)  # Never return accept before fsync + replace + parent fsync.
            return copy.deepcopy(d),{"status":"authenticated_fresh","principal":principal.name,"sequence":d["sequence"],
                                     "state_bytes":self.path.stat().st_size,"envelope_bytes":len(envelope.body)+64,
                                     "guarantee":"local trusted-clock/store freshness; no rollback or distributed exactly-once proof"}
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
