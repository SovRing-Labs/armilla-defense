"""Local authenticated max-plus DAG; no general malware/benign-intent claim."""
import copy
try:
    from .common import Refusal,exact_int,digest
    from .freshness import body,sign_fixture,decode,Signed
except ImportError:
    from common import Refusal,exact_int,digest
    from freshness import body,sign_fixture,decode,Signed
from observe import checked_readback


class Graph:
    def __init__(self,store,sources,edges,context="PUBLIC_MAX_PLUS_V1"):
        self.store=store;self.sources=list(sources);self.n=len(self.sources);self.edges=dict(edges);self._context=context
        if not 1<=self.n<=32 or len(self.edges)>128 or type(context) is not str or not context:raise Refusal("graph_budget")
        for x in self.sources:self._value(x)
        for (i,j),w in self.edges.items():self._edge(i,j,w)
        self.values=[None]*self.n;self.parents=[None]*self.n;self.versions=[0]*self.n;self.version=0;self.effects=[];self.log=[]
        for j in range(self.n):self.values[j],self.parents[j]=self._node(j,self.sources,self.edges,self.values)

    @property
    def context(self):return self._context

    def _value(self,x):
        if x is not None:
            exact_int(x)
            if abs(x)>1000000:raise Refusal("graph_state_range")

    def _edge(self,i,j,weight):
        exact_int(i);exact_int(j);exact_int(weight)
        if not 0<=i<j<self.n:raise Refusal("unsupported_cycle_or_edge_order")
        if abs(weight)>1000:raise Refusal("graph_weight_range")

    @staticmethod
    def _node(j,sources,edges,values):
        candidates=[]
        if sources[j] is not None:candidates.append((sources[j],j))
        for (i,k),w in edges.items():
            if k==j and values[i] is not None:candidates.append((values[i]+w,i))
        if not candidates:return None,None
        maximum=max(v for v,i in candidates);parent=min(i for v,i in candidates if v==maximum)
        if abs(maximum)>1000000:raise Refusal("graph_state_range")
        return maximum,parent

    def snapshot(self):
        return {"sources":tuple(self.sources),"edges":tuple((i,j,w) for (i,j),w in sorted(self.edges.items())),
                "values":tuple(self.values),"parents":tuple(self.parents),"versions":tuple(self.versions),
                "version":self.version,"effects":tuple(self.effects)}

    @property
    def identity(self):return digest((self.context,self.snapshot()))

    @property
    def dependencies(self):return {"base":self.identity,"versions":list(self.versions),"version":self.version}

    def _validate(self,event):
        if type(event) is not dict or "kind" not in event:raise Refusal("graph_event_schema")
        fields={"set_source":{"kind","node","value","effect"},"set_edge":{"kind","src","dst","weight","effect"},
                "delete_edge":{"kind","src","dst","effect"}}
        kind=event["kind"]
        if kind not in fields or set(event)!=fields[kind]:raise Refusal("unsupported_graph_operation")
        if type(event["effect"]) is not str or not 1<=len(event["effect"])<=64:raise Refusal("effect_identity")
        if len(self.log)>=128:raise Refusal("graph_event_capacity")
        if any(row["effect"]==event["effect"] for row in self.log):raise Refusal("stale_effect_identity")
        if kind=="set_source":
            node=exact_int(event["node"])
            if not 0<=node<self.n:raise Refusal("graph_node_range")
            self._value(event["value"])
        else:
            self._edge(event["src"],event["dst"],event.get("weight",0))
            if kind=="delete_edge" and (event["src"],event["dst"]) not in self.edges:raise Refusal("missing_graph_edge")
            if kind=="set_edge" and (event["src"],event["dst"]) not in self.edges and len(self.edges)>=128:raise Refusal("graph_budget")
        return copy.deepcopy(event)

    def proposal(self,event,mode="incremental"):
        event=self._validate(event)
        if mode not in ("incremental","full"):raise Refusal("graph_route")
        sources=list(self.sources);edges=dict(self.edges)
        if event["kind"]=="set_source":sources[event["node"]]=event["value"];seed=event["node"]
        elif event["kind"]=="set_edge":edges[(event["src"],event["dst"])]=event["weight"];seed=event["dst"]
        else:del edges[(event["src"],event["dst"])];seed=event["dst"]
        # Old AND new dependency edges matter for decreasing/deleting updates.
        downstream={i:set() for i in range(self.n)}
        for i,j in set(self.edges)|set(edges):downstream[i].add(j)
        affected={seed};queue=[seed]
        while queue:
            for j in downstream[queue.pop()]:
                if j not in affected:affected.add(j);queue.append(j)
        values=list(self.values);parents=list(self.parents)
        scheduled=sorted(affected) if mode=="incremental" else list(range(self.n))
        for j in scheduled:values[j],parents[j]=self._node(j,sources,edges,values)
        versions=tuple(v+(i in affected) for i,v in enumerate(self.versions))
        target={"sources":tuple(sources),"edges":tuple((i,j,w) for (i,j),w in sorted(edges.items())),
                "values":tuple(values),"parents":tuple(parents),"versions":versions,"version":self.version+1,
                "effects":tuple(self.effects)+(event["effect"],)}
        evidence={"route":mode,"public_shape":(self.n,len(edges),event["kind"],seed),
                  "touched_nodes":len(scheduled),"touched_incoming_edges":sum(j in scheduled for i,j in edges),
                  "affected_nodes":len(affected),"scheduler":"integer node order; max-plus bounded positional scores",
                  "setup_boundary":"dependency union, guards, authentication/store and readback included in total caller timing"}
        return target,evidence


    def apply(self,envelope,now,target,mode="incremental",actuator=None):
        if not isinstance(envelope,Signed):raise Refusal("typed_signed_event")
        raw=decode(envelope.body)
        if type(raw) is not dict or "payload" not in raw:raise Refusal("graph_event_schema")
        event=self._validate(raw["payload"])
        proposed,route=self.proposal(event,mode)
        # Required P4 admission persists freshness BEFORE any actual graph mutation.
        accepted,admission=self.store.admit(envelope,now,self.context,"graph-update-v1",self.dependencies,expected_payload=event)
        readback_error=None
        try:
            actual=copy.deepcopy(proposed) if actuator is None else actuator(copy.deepcopy(proposed))
            independent=checked_readback(target,actual)
            command=checked_readback(proposed,actual)
        except Exception as exc:
            # Freshness may already be consumed. Unknown target observation fails
            # closed and cannot become an implicit successful dispatch receipt.
            readback_error=type(exc).__name__;actual=None
            independent={"status":"rejected","guarantee":"readback unavailable"}
            command={"status":"rejected","guarantee":"readback unavailable"}
        success=independent["status"]=="accepted" and command["status"]=="accepted"
        self.log.append({"effect":event["effect"],"sequence":accepted["sequence"],"envelope":digest((envelope.body,envelope.signature)),
                         "status":"observed_success" if success else "observed_failure"})
        if success:
            self.sources=list(actual["sources"]);self.edges={(i,j):w for i,j,w in actual["edges"]}
            self.values=list(actual["values"]);self.parents=list(actual["parents"]);self.versions=list(actual["versions"])
            self.version=actual["version"];self.effects=list(actual["effects"])
        return {"status":"observed_success" if success else "observed_failure","dispatch":"authenticated_fresh",
                "freshness_consumed":True,"readback_error":readback_error,"state":self.snapshot(),"actual_readback":actual,"independent_target":independent,
                "command_readback":command,"route":route,"admission":admission,
                "guarantee":"exact local declared DAG state/effects against caller-independent target; no production defense/cyclic convergence claim"}
