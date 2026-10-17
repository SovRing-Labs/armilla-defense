"""Exact complementary readout with explicit rank/ambiguity and target checks."""
from dataclasses import dataclass
from fractions import Fraction
import hashlib
try:
    from .common import Refusal,canonical,digest
except ImportError:
    from common import Refusal,canonical,digest


def _rational(x):
    if type(x) is int or isinstance(x,Fraction):return Fraction(x)
    raise Refusal("exact_rational_required")


def _reduce(rows,n):
    a=[list(map(_rational,row)) for row in rows];pivots=[];r=0
    for c in range(n):
        k=next((i for i in range(r,len(a)) if a[i][c]),None)
        if k is None:continue
        a[r],a[k]=a[k],a[r];v=a[r][c];a[r]=[x/v for x in a[r]]
        for j in range(len(a)):
            if j!=r:
                v=a[j][c];a[j]=[x-v*y for x,y in zip(a[j],a[r])]
        pivots.append(c);r+=1
    return a,pivots


def nullspace(rows,n):
    a,pivots=_reduce(rows,n);basis=[]
    for free in (c for c in range(n) if c not in pivots):
        v=[Fraction(0)]*n;v[free]=1
        for i,p in enumerate(pivots):v[p]=-a[i][free]
        basis.append(tuple(v))
    return tuple(basis)


@dataclass(frozen=True)
class Observation:
    identity: str
    rows: tuple
    values: tuple
    context: tuple
    dimension: int

    def serialize(self):
        def frac(x):return (x.numerator,x.denominator)
        return canonical((self.identity,tuple(tuple(frac(v) for v in r) for r in self.rows),
                          tuple(frac(v) for v in self.values),self.context,self.dimension))


def read(state,rows,context,identity="linear-readback"):
    if not 1<=len(state)<=256 or not 1<=len(rows)<=512:raise Refusal("observation_budget")
    x=tuple(map(_rational,state));rows=tuple(tuple(map(_rational,r)) for r in rows)
    if any(len(row)!=len(x) for row in rows):raise Refusal("observation_shape")
    values=tuple(sum(a*b for a,b in zip(row,x)) for row in rows)
    return Observation(identity,rows,values,context.token(),len(x))


def admit(target,observations,context,tolerance=0):
    """Unknown/missing information abstains; identical labels imply no independence."""
    if not 1<=len(target)<=256:raise Refusal("observation_budget")
    x=tuple(map(_rational,target));tolerance=_rational(tolerance)
    if tolerance<0:raise Refusal("negative_tolerance")
    if not observations:return {"status":"ambiguous","rank":0,"nullity":len(x),"guarantee":"no observations"}
    rows=[];values=[];size=0
    if len(observations)>256:raise Refusal("observation_budget")
    for obs in observations:
        if not isinstance(obs,Observation):raise Refusal("observation_type")
        if obs.context!=context.token():raise Refusal("observation_context")
        if obs.dimension!=len(x) or any(len(r)!=len(x) for r in obs.rows) or len(obs.rows)!=len(obs.values):raise Refusal("observation_shape")
        rows.extend(tuple(map(_rational,r)) for r in obs.rows);values.extend(map(_rational,obs.values));size+=len(obs.serialize())
        if len(rows)>512:raise Refusal("observation_budget")
    predicted=[sum(a*b for a,b in zip(row,x)) for row in rows]
    errors=[abs(a-b) for a,b in zip(values,predicted)]
    basis=nullspace(rows,len(x));rank=len(x)-len(basis)
    maximum=max(errors,default=Fraction(0))
    status=("rejected" if maximum>tolerance else "ambiguous" if basis else
            "accepted" if tolerance==0 else "compatible_within_tolerance")
    return {"status":status,"rank":rank,"nullity":len(basis),"nullspace":basis,
            "max_observation_error":maximum,"bytes":size,
            "guarantee":"exact rational full-rank target agreement" if status=="accepted" else
                        "no exact target certification","independence":"not assumed; joint outcomes measured"}


def checksum(state):
    return hashlib.sha256(canonical(state)).digest()


def checked_readback(target,actual,emitted_command=None,claimed_checksum=None):
    """Compare ACTUAL readback to independent target, even if attacker recomputes checksum."""
    actual_hash=checksum(actual);target_hash=checksum(target)
    return {"status":"accepted" if actual_hash==target_hash and actual==target else "rejected",
            "target_error":0 if actual==target else None,"bytes":len(canonical(actual))+len(actual_hash),
            "checksum_consistent":claimed_checksum is None or claimed_checksum==actual_hash,
            "guarantee":"exact readback comparison within declared state; checksum alone is nonadversarial"}
