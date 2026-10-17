import os,sys,pathlib,json
for name in ("OPENBLAS_NUM_THREADS","OMP_NUM_THREADS","MKL_NUM_THREADS"):os.environ[name]="1"
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from common import Refusal
checks=0
def check(condition,label):
    global checks
    checks+=1
    if not condition:raise AssertionError(label)
def refuses(fn,label,errors=(Refusal,ValueError,TypeError,OverflowError,ArithmeticError)):
    try:fn()
    except errors:return check(True,label)
    check(False,label)

import secrets,tempfile
import greenmark as G
from freshness import Store,Principal,body,sign_fixture,Signed
from defense import Graph
from observe import checked_readback
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey,Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
seed=secrets.token_bytes(32);public=G.public_key(seed);message=b"ephemeral portable check"
signature=G.sign(seed,message)
check(G.verify(public,message,signature),"own signature roundtrip")
Ed25519PublicKey.from_public_bytes(public).verify(signature,message);check(True,"independent blackbox signature verification")
oracle=Ed25519PrivateKey.from_private_bytes(seed)
check(oracle.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)==public,"independent public key oracle")
check(oracle.sign(message)==signature,"independent signature oracle")
check(not G.verify(public,message+b"!",signature),"altered body")
check(not G.verify(public,message,signature[:-1]+bytes([signature[-1]^1])),"altered signature")
with tempfile.TemporaryDirectory() as td:
    path=pathlib.Path(td)/"fresh.json";principal=Principal(public_key=public)
    s=Store.enroll(path,[principal])
    envelope=sign_fixture(body({"value":8},"ctx",sequence=1),seed)
    s.admit(envelope,1000,"ctx",expected_payload={"value":8});check(True,"persisted admission")
    reopened=Store(path,[principal])
    refuses(lambda:reopened.admit(envelope,1000,"ctx"),"restart replay rejected")
    wrong=sign_fixture(body({"value":9},"ctx",sequence=2),seed)
    refuses(lambda:reopened.admit(wrong,1000,"ctx",expected_payload={"value":8}),"valid signed wrong target rejected")
    refuses(lambda:reopened.admit(Signed(envelope.body+b" ",envelope.signature),1000,"ctx"),"noncanonical/tampered bytes")
    gp=pathlib.Path(td)/"graph.json";st=Store.enroll(gp,[principal]);graph=Graph(st,[2,None,None],{(0,1):3,(1,2):4})
    check(graph.snapshot()["values"]==(2,5,9),"independent initial paths")
    event={"kind":"set_source","node":0,"value":7,"effect":"a"}
    # Independent complete target, derived from all paths and expected effects.
    target={"sources":(7,None,None),"edges":((0,1,3),(1,2,4)),"values":(7,10,14),"parents":(0,0,1),"versions":(1,1,1),"version":1,"effects":("a",)}
    signed=sign_fixture(body(event,graph.context,"graph-update-v1",graph.dependencies,sequence=1),seed)
    receipt=graph.apply(signed,1000,target)
    check(receipt["status"]=="observed_success" and graph.snapshot()==target,"independent actual graph target")
    event={"kind":"set_source","node":0,"value":8,"effect":"b"}
    target2={**target,"sources":(8,None,None),"values":(8,11,15),"versions":(2,2,2),"version":2,"effects":("a","b")}
    signed=sign_fixture(body(event,graph.context,"graph-update-v1",graph.dependencies,sequence=2),seed)
    old=graph.snapshot();receipt=graph.apply(signed,1000,target2,actuator=lambda proposal:old)
    check(receipt["status"]=="observed_failure" and receipt["freshness_consumed"],"ineffective actuator distinguished from dispatch")
    check(graph.snapshot()==old,"failed effect not installed")
    check(checked_readback(target2,old,emitted_command=target2)["status"]=="rejected","duplicate command not target evidence")
print(json.dumps({"status":"PASS","checks":checks,"scope":"local ephemeral reference signatures/freshness/DAG; no private key output, rollback or durable graph guarantee"}))
