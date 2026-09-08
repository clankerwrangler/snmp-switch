----------------------------- MODULE Switch -----------------------------
EXTENDS Integers, FiniteSets, Sequences

(***************************************************************************
 Generic SNMP switch emulator, revision 2.
 One switch; independent VLAN learning; no forwarding or vendor behavior.

 `s` is the complete semantic state. MIB operators below are read-only views.
 Finite endpoint/source slots stand for runtime-created persistent instances.
 Generations are equality tokens, NEVER reused while an outstanding job could
 confuse them with a current token. Production uses non-repeating generations.

 A clock step ages entries, then drains due source activity. Topology/config
 actions may interleave with queue/apply, including move-away-and-back races.
 Stale jobs are retained until consumed, not assumed to disappear on cancel.
***************************************************************************)
CONSTANTS Ports, Endpoints, Slots, MACs, VLANs, Tokens,
          PortOrder, IfIndex, VlanToFdb,
          AgingTicks, PeriodTicks, FirstDelayTicks, QueueLimit,
          NoPort, NoSource, NoJob, Untagged

SourceKeys == Endpoints \X Slots
FdbKeys == {VlanToFdb[v] : v \in VLANs} \X MACs
SourceType == [mac : MACs, tag : VLANs \cup {Untagged}]
Defs == [Slots -> SourceType \cup {NoSource}]
EntryType == [port : Ports \cup {NoPort}, ttl : 0..AgingTicks]
EmptyEntry == [port |-> NoPort, ttl |-> 0]
JobType == [port : Ports, vlan : VLANs, mac : MACs,
            egen : Tokens, pgen : Tokens, boot : Tokens]
TrapType == [kind : {"linkUp", "linkDown"}, port : Ports,
             ifIndex : {IfIndex[p] : p \in Ports},
             admin : BOOLEAN, before : BOOLEAN, after : BOOLEAN]

ASSUME /\ IsFiniteSet(Ports) /\ Ports # {} /\ Ports \subseteq 1..65535
       /\ IsFiniteSet(Endpoints) /\ Endpoints # {}
       /\ IsFiniteSet(Slots) /\ Slots # {}
       /\ IsFiniteSet(MACs) /\ MACs # {}
       /\ IsFiniteSet(VLANs) /\ 1 \in VLANs /\ VLANs \subseteq 1..4094
       /\ IsFiniteSet(Tokens) /\ Cardinality(Tokens) >= Cardinality(SourceKeys) + 2
       /\ PortOrder \in Seq(Ports) /\ Len(PortOrder) = Cardinality(Ports)
       /\ {PortOrder[i] : i \in DOMAIN PortOrder} = Ports
       /\ IfIndex \in [Ports -> 1..2147483647]
       /\ \A p, q \in Ports : IfIndex[p] = IfIndex[q] => p = q
       /\ VlanToFdb \in [VLANs -> Nat]
       /\ \A v \in VLANs : VlanToFdb[v] > 0
       /\ \A u, v \in VLANs : VlanToFdb[u] = VlanToFdb[v] => u = v
       /\ AgingTicks \in Nat \ {0} /\ PeriodTicks \in 1..AgingTicks
       /\ FirstDelayTicks \in 1..PeriodTicks /\ QueueLimit \in Nat
       /\ NoPort \notin Ports /\ Untagged \notin VLANs
       /\ NoSource \notin SourceType /\ NoJob \notin JobType

VARIABLE s
vars == <<s>>
Token0 == CHOOSE t \in Tokens : TRUE
Fresh(used) == CHOOSE t \in Tokens \ used : TRUE
At(x, p) == {e \in x.exists : x.attached[e] = p}
Carrier(x, p) == IF x.mode[p] = "shared" THEN x.partner[p] ELSE At(x, p) # {}
Oper(x, p) == x.admin[p] /\ ~x.fault[p] /\ Carrier(x, p)
VlanOf(id) == CHOOSE v \in VLANs : VlanToFdb[v] = id
Live(x) == {k \in FdbKeys : x.fdb[k].port # NoPort}
Effective(x, sk) == IF x.sources[sk].tag = Untagged
                    THEN x.pvid[x.attached[sk[1]]] ELSE x.sources[sk].tag
CanEmit(x, sk) ==
    IF sk[1] \notin x.exists \/ x.sources[sk] = NoSource
       \/ x.attached[sk[1]] = NoPort THEN FALSE
    ELSE sk[1] \in x.active /\ Oper(x, x.attached[sk[1]])
Admitted(x, p, v) == v \in x.vlans /\ v \in x.allowed[p]
Eligible(x, sk) == IF CanEmit(x, sk)
                   THEN Admitted(x, x.attached[sk[1]], Effective(x, sk)) ELSE FALSE

ValidJob(x, sk, j) ==
    IF ~CanEmit(x, sk) THEN FALSE
    ELSE /\ j.egen = x.egen[sk[1]] /\ j.pgen = x.pgen[j.port]
         /\ j.boot = x.boot /\ j.port = x.attached[sk[1]]
         /\ j.mac = x.sources[sk].mac /\ j.vlan = Effective(x, sk)

UsedE(e) == {s.egen[e]} \cup
    {s.pending[sk].egen : sk \in {sk \in SourceKeys :
                               sk[1] = e /\ s.pending[sk] # NoJob}}
UsedP(p) == {s.pgen[p]} \cup
    {s.pending[sk].pgen : sk \in {sk \in SourceKeys :
        IF s.pending[sk] = NoJob THEN FALSE ELSE s.pending[sk].port = p}}
UsedBoot == {s.boot} \cup
    {s.pending[sk].boot : sk \in {sk \in SourceKeys : s.pending[sk] # NoJob}}

KeepLegal(entries, x) ==
    [k \in FdbKeys |->
        IF entries[k].port = NoPort THEN EmptyEntry
        ELSE IF Oper(x, entries[k].port)
                /\ Admitted(x, entries[k].port, VlanOf(k[1]))
             THEN entries[k] ELSE EmptyEntry]

LinkEvents(x) ==
    LET ps == SelectSeq(PortOrder, LAMBDA p : Oper(s, p) # Oper(x, p))
    IN [i \in 1..Len(ps) |->
         LET p == ps[i]
         IN [kind |-> IF Oper(x, p) THEN "linkUp" ELSE "linkDown",
             port |-> p, ifIndex |-> IfIndex[p], admin |-> x.admin[p],
             before |-> Oper(s, p), after |-> Oper(x, p)]]
AppendBounded(q, ev) ==
    LET both == q \o ev
        n == IF Len(both) > QueueLimit THEN QueueLimit ELSE Len(both)
    IN SubSeq(both, 1, n)

(***************************************************************************
 Every UI configuration/topology action uses this commit operation. Cleanup
 removes only entries invalidated by the new state; endpoint edits do not
 erase cached observations. Generation changes invalidate jobs without
 deleting the callbacks, so late delivery remains an explored behavior.
***************************************************************************)
Mutate(x, es, ps) ==
    LET changed == {p \in Ports : Oper(s, p) # Oper(x, p)}
        ports == ps \cup changed
        affected == {sk \in SourceKeys : sk[1] \in es
                     \/ s.attached[sk[1]] \in ports
                     \/ x.attached[sk[1]] \in ports}
        ev == LinkEvents(x)
    IN s' = [x EXCEPT
          !.egen = [e \in Endpoints |-> IF e \in es THEN Fresh(UsedE(e)) ELSE s.egen[e]],
          !.pgen = [p \in Ports |-> IF p \in ports THEN Fresh(UsedP(p)) ELSE s.pgen[p]],
          !.due = [sk \in SourceKeys |->
              IF sk \in affected THEN
                  IF sk[1] \in x.exists /\ x.sources[sk] # NoSource
                  THEN FirstDelayTicks ELSE 0
              ELSE x.due[sk]],
          !.fdb = KeepLegal(x.fdb, x),
          !.traps = AppendBounded(s.traps, ev),
          !.overflow = s.overflow \/ Len(s.traps) + Len(ev) > QueueLimit]

InitialState == [exists |-> {},
    sources |-> [sk \in SourceKeys |-> NoSource], active |-> {},
    attached |-> [e \in Endpoints |-> NoPort],
    egen |-> [e \in Endpoints |-> Token0],
    vlans |-> {1}, vlanNames |-> [v \in VLANs |-> 0], pvid |-> [p \in Ports |-> 1],
    allowed |-> [p \in Ports |-> {1}],
    untagged |-> [p \in Ports |-> {1}], forbidden |-> [p \in Ports |-> {}], legacy |-> 1,
    admin |-> [p \in Ports |-> TRUE], mode |-> [p \in Ports |-> "direct"],
    partner |-> [p \in Ports |-> FALSE], fault |-> [p \in Ports |-> FALSE],
    pgen |-> [p \in Ports |-> Token0], boot |-> Token0,
    fdb |-> [k \in FdbKeys |-> EmptyEntry],
    pending |-> [sk \in SourceKeys |-> NoJob],
    due |-> [sk \in SourceKeys |-> 0], paused |-> FALSE, phase |-> "idle",
    traps |-> <<>>, overflow |-> FALSE]

Init == s = InitialState

CreateEndpoint(e, defs) ==
    /\ e \notin s.exists
    /\ Mutate([s EXCEPT !.exists = @ \cup {e},
          !.sources = [sk \in SourceKeys |-> IF sk[1] = e THEN defs[sk[2]] ELSE @ [sk]]],
          {e}, {})
EditEndpoint(e, defs) ==
    /\ e \in s.exists
    /\ \E slot \in Slots : s.sources[<<e, slot>>] # defs[slot]
    /\ Mutate([s EXCEPT !.sources = [sk \in SourceKeys |->
                   IF sk[1] = e THEN defs[sk[2]] ELSE @ [sk]]], {e}, {})
DeleteEndpoint(e) ==
    /\ e \in s.exists /\ s.attached[e] = NoPort
    /\ Mutate([s EXCEPT !.exists = @ \ {e}, !.active = @ \ {e},
          !.sources = [sk \in SourceKeys |-> IF sk[1] = e THEN NoSource ELSE @ [sk]]],
          {e}, {})

HasRoom(p) == s.mode[p] = "shared" \/ At(s, p) = {}
Connect(e, p) ==
    /\ e \in s.exists /\ s.attached[e] = NoPort /\ HasRoom(p)
    /\ Mutate([s EXCEPT !.attached[e] = p], {e}, {})
Disconnect(e) ==
    /\ e \in s.exists /\ s.attached[e] # NoPort
    /\ Mutate([s EXCEPT !.attached[e] = NoPort], {e}, {})
Move(e, p) ==
    /\ e \in s.exists /\ s.attached[e] # NoPort /\ s.attached[e] # p /\ HasRoom(p)
    /\ Mutate([s EXCEPT !.attached[e] = p], {e}, {})
SetActive(e, on) ==
    /\ e \in s.exists /\ (e \in s.active) # on
    /\ Mutate([s EXCEPT !.active = IF on THEN @ \cup {e} ELSE @ \ {e}], {e}, {})
SetAdmin(p, on) ==
    /\ s.admin[p] # on /\ Mutate([s EXCEPT !.admin[p] = on], {}, {p})
SetFault(p, on) ==
    /\ s.fault[p] # on /\ Mutate([s EXCEPT !.fault[p] = on], {}, {p})
SetMode(p, mode) ==
    /\ s.mode[p] # mode /\ (mode = "shared" \/ Cardinality(At(s, p)) <= 1)
    /\ Mutate([s EXCEPT !.mode[p] = mode, !.partner[p] = (mode = "shared")], {}, {p})
SetPartner(p, on) ==
    /\ s.mode[p] = "shared" /\ s.partner[p] # on
    /\ Mutate([s EXCEPT !.partner[p] = on], {}, {p})

TaggedEndpoints(v) == {e \in s.exists : \E slot \in Slots :
    IF s.sources[<<e, slot>>] = NoSource THEN FALSE
    ELSE s.sources[<<e, slot>>].tag = v}
CreateVlan(v) ==
    /\ v \notin s.vlans
    /\ Mutate([s EXCEPT !.vlans = @ \cup {v}], TaggedEndpoints(v), {})
DeleteVlan(v) ==
    /\ v \in s.vlans /\ v # 1
    /\ \A p \in Ports : s.pvid[p] = v => 1 \notin s.forbidden[p]
    /\ LET ps == {p \in Ports : v \in s.allowed[p]}
           x == [s EXCEPT !.vlans = @ \ {v}, !.vlanNames[v] = 0,
                !.pvid = [p \in Ports |-> IF s.pvid[p] = v THEN 1 ELSE s.pvid[p]],
                !.allowed = [p \in Ports |-> (s.allowed[p] \ {v}) \cup
                                            (IF s.pvid[p] = v THEN {1} ELSE {})],
                !.untagged = [p \in Ports |-> (s.untagged[p] \ {v}) \cup
                    (IF s.pvid[p] = v /\ v \in s.untagged[p] THEN {1} ELSE {})],
                !.forbidden = [p \in Ports |-> s.forbidden[p] \ {v}],
                !.legacy = IF s.legacy = v THEN 1 ELSE s.legacy]
       IN Mutate(x, TaggedEndpoints(v), ps)
ConfigurePort(p, native, members) ==
    /\ native \in members /\ members \subseteq s.vlans
    /\ s.pvid[p] # native \/ s.allowed[p] # members
    /\ members \cap s.forbidden[p] = {}
    /\ LET tags == IF native = s.pvid[p] THEN s.untagged[p]
                   ELSE (s.untagged[p] \ {s.pvid[p]}) \cup {native}
       IN /\ tags \subseteq members
          /\ Mutate([s EXCEPT !.pvid[p] = native, !.allowed[p] = members,
                              !.untagged[p] = tags], {}, {p})
SetLegacy(v) ==
    /\ v \in s.vlans /\ s.legacy # v
    /\ Mutate([s EXCEPT !.legacy = v], {}, {})
ClearPort(p) ==
    Mutate([s EXCEPT !.fdb = [k \in FdbKeys |->
         IF s.fdb[k].port = p THEN EmptyEntry ELSE s.fdb[k]]], {}, {p})

SetPaused(on) ==
    /\ s.phase = "idle" /\ s.paused # on /\ s' = [s EXCEPT !.paused = on]
Advance ==
    /\ s.phase = "idle"
    /\ s' = [s EXCEPT !.phase = "drain",
         !.fdb = [k \in FdbKeys |-> IF s.fdb[k].ttl <= 1 THEN EmptyEntry
                                  ELSE [s.fdb[k] EXCEPT !.ttl = @ - 1]],
         !.due = [sk \in SourceKeys |-> IF s.due[sk] > 0 THEN s.due[sk] - 1 ELSE 0]]
AutoTick == ~s.paused /\ Advance
ManualTick == s.paused /\ Advance

QueueActivity(sk) ==
    /\ s.phase = "drain" /\ CanEmit(s, sk) /\ s.due[sk] = 0
    /\ s.pending[sk] = NoJob
    /\ LET p == s.attached[sk[1]]
           j == [port |-> p, vlan |-> Effective(s, sk), mac |-> s.sources[sk].mac,
                 egen |-> s.egen[sk[1]], pgen |-> s.pgen[p], boot |-> s.boot]
       IN s' = [s EXCEPT !.pending[sk] = j, !.due[sk] = PeriodTicks]
ApplyActivity(sk) ==
    /\ s.phase = "drain" /\ s.pending[sk] # NoJob
    /\ LET j == s.pending[sk]
           accepted == ValidJob(s, sk, j) /\ Admitted(s, j.port, j.vlan)
       IN s' = [s EXCEPT !.pending[sk] = NoJob,
              !.fdb = IF accepted THEN
                  [s.fdb EXCEPT ![<<VlanToFdb[j.vlan], j.mac>>] =
                                      [port |-> j.port, ttl |-> AgingTicks]]
                  ELSE s.fdb]
FinishStep ==
    /\ s.phase = "drain"
    /\ \A sk \in SourceKeys : s.pending[sk] = NoJob /\ ~(CanEmit(s, sk) /\ s.due[sk] = 0)
    /\ s' = [s EXCEPT !.phase = "idle"]
DispatchTrap ==
    /\ Len(s.traps) > 0 /\ s' = [s EXCEPT !.traps = Tail(@)]
Reboot ==
    s' = [s EXCEPT !.boot = Fresh(UsedBoot),
        !.fdb = [k \in FdbKeys |-> EmptyEntry], !.phase = "idle",
        !.due = [sk \in SourceKeys |-> IF sk[1] \in s.exists /\ s.sources[sk] # NoSource
                                      THEN FirstDelayTicks ELSE 0],
        !.traps = <<>>, !.overflow = FALSE]

LibraryNext ==
    \/ \E e \in Endpoints, defs \in Defs : CreateEndpoint(e, defs) \/ EditEndpoint(e, defs)
    \/ \E e \in Endpoints : DeleteEndpoint(e)
TopologyNext ==
    \/ \E e \in Endpoints, p \in Ports : Connect(e, p) \/ Move(e, p)
    \/ \E e \in Endpoints : Disconnect(e)
    \/ \E e \in Endpoints, b \in BOOLEAN : SetActive(e, b)
    \/ \E p \in Ports, b \in BOOLEAN : SetAdmin(p, b) \/ SetFault(p, b) \/ SetPartner(p, b)
    \/ \E p \in Ports, m \in {"direct", "shared"} : SetMode(p, m)
VlanNext ==
    \/ \E v \in VLANs : CreateVlan(v) \/ DeleteVlan(v) \/ SetLegacy(v)
    \/ \E p \in Ports, v \in VLANs, ms \in SUBSET VLANs : ConfigurePort(p, v, ms)
ActivityNext ==
    \/ AutoTick \/ ManualTick \/ FinishStep
    \/ \E sk \in SourceKeys : QueueActivity(sk) \/ ApplyActivity(sk)
Next == LibraryNext \/ TopologyNext \/ VlanNext \/ ActivityNext \/ DispatchTrap \/ Reboot
        \/ (\E b \in BOOLEAN : SetPaused(b)) \/ (\E p \in Ports : ClearPort(p))
Spec == Init /\ [][Next]_vars
ServiceFairness ==
    /\ WF_vars(AutoTick) /\ WF_vars(FinishStep) /\ WF_vars(DispatchTrap)
    /\ \A sk \in SourceKeys : WF_vars(QueueActivity(sk)) /\ WF_vars(ApplyActivity(sk))
FairSpec == Spec /\ ServiceFairness

(***************************************************************************
 Semantic projections. Table indexes appear as record keys, NOT necessarily
 readable columns. Wire OIDs, OCTET STRING bitmaps and TimeFilter belong to
 the SNMP adapter. Untagged and forbidden egress are independent configured membership sets.
***************************************************************************)
IfTable == [p \in Ports |-> [ifIndex |-> IfIndex[p],
    ifAdminStatus |-> IF s.admin[p] THEN 1 ELSE 2,
    ifOperStatus |-> IF Oper(s, p) THEN 1 ELSE 2]]
Dot1dBasePortTable == [p \in Ports |-> [dot1dBasePortIfIndex |-> IfIndex[p]]]
Dot1qTpFdbTable == [k \in Live(s) |-> [dot1qTpFdbPort |-> s.fdb[k].port,
                                     dot1qTpFdbStatus |-> 3]]
LegacyMACs == {m \in MACs : <<VlanToFdb[s.legacy], m>> \in Live(s)}
Dot1dTpFdbTable == [m \in LegacyMACs |-> [dot1dTpFdbAddress |-> m,
    dot1dTpFdbPort |-> s.fdb[<<VlanToFdb[s.legacy], m>>].port, dot1dTpFdbStatus |-> 3]]
Dot1qFdbTable == [id \in {VlanToFdb[v] : v \in s.vlans} |->
    [dot1qFdbDynamicCount |-> Cardinality({k \in Live(s) : k[1] = id})]]
Dot1qVlanCurrentTable == [v \in s.vlans |-> [dot1qVlanFdbId |-> VlanToFdb[v],
    dot1qVlanCurrentEgressPorts |-> {p \in Ports : v \in s.allowed[p]},
    dot1qVlanCurrentUntaggedPorts |-> {p \in Ports : v \in s.untagged[p]},
    dot1qVlanStatus |-> 2]]
Dot1qVlanStaticTable == [v \in s.vlans |-> [
    dot1qVlanStaticEgressPorts |-> {p \in Ports : v \in s.allowed[p]},
    dot1qVlanStaticUntaggedPorts |-> {p \in Ports : v \in s.untagged[p]},
    dot1qVlanForbiddenEgressPorts |-> {p \in Ports : v \in s.forbidden[p]},
    dot1qVlanStaticRowStatus |-> 1]]
Dot1qPvid == s.pvid


(***************************************************************************
 ENTITY-MIB fixed physical inventory. UUID encoding and unknown-value sentinels
 belong to the wire adapter. Labels and the change clock are exercised by the
 EntityInventory fixture; neither endpoint nor VLAN inventory adds hardware.
***************************************************************************)
PhysicalIndex(p) == p + 1
PhysicalPorts == {PhysicalIndex(p) : p \in Ports}
PhysicalDomain == {1} \cup PhysicalPorts
PhysicalPort(i) == CHOOSE p \in Ports : PhysicalIndex(p) = i
EntPhysicalTable == [i \in PhysicalDomain |->
    [parent |-> IF i = 1 THEN 0 ELSE 1,
     class |-> IF i = 1 THEN 3 ELSE 10,
     position |-> IF i = 1 THEN -1 ELSE PhysicalPort(i),
     identity |-> <<"saved-id", i>>]]
EntPhysicalContainsTable == [i \in PhysicalPorts |-> <<1, i>>]
EntAliasMappingTable == [i \in PhysicalPorts |->
    [logicalIndex |-> 0, pointer |-> <<"ifIndex", IfIndex[PhysicalPort(i)]>>]]
EntityOK ==
    /\ DOMAIN EntPhysicalTable = {1} \cup {p + 1 : p \in Ports}
    /\ Cardinality(PhysicalDomain) = Cardinality(Ports) + 1
    /\ EntPhysicalTable[1].parent = 0 /\ EntPhysicalTable[1].position = -1
    /\ \A i \in PhysicalPorts :
          /\ EntPhysicalTable[i].parent = 1 /\ EntPhysicalTable[i].class = 10
          /\ EntPhysicalContainsTable[i] = <<EntPhysicalTable[i].parent, i>>
          /\ EntAliasMappingTable[i].logicalIndex = 0
          /\ EntAliasMappingTable[i].pointer =
                <<"ifIndex", Dot1dBasePortTable[PhysicalPort(i)].dot1dBasePortIfIndex>>
          /\ EntAliasMappingTable[i].pointer = <<"ifIndex", IfTable[PhysicalPort(i)].ifIndex>>

TypeOK ==
    /\ s.exists \subseteq Endpoints /\ s.sources \in [SourceKeys -> SourceType \cup {NoSource}]
    /\ s.active \subseteq s.exists /\ s.attached \in [Endpoints -> Ports \cup {NoPort}]
    /\ s.egen \in [Endpoints -> Tokens] /\ s.vlans \subseteq VLANs
    /\ s.vlanNames \in [VLANs -> 0..1]
    /\ s.pvid \in [Ports -> VLANs] /\ s.allowed \in [Ports -> SUBSET VLANs]
    /\ s.untagged \in [Ports -> SUBSET VLANs]
    /\ s.forbidden \in [Ports -> SUBSET VLANs]
    /\ s.legacy \in VLANs /\ s.admin \in [Ports -> BOOLEAN]
    /\ s.mode \in [Ports -> {"direct", "shared"}]
    /\ s.partner \in [Ports -> BOOLEAN] /\ s.fault \in [Ports -> BOOLEAN]
    /\ s.pgen \in [Ports -> Tokens] /\ s.boot \in Tokens
    /\ s.fdb \in [FdbKeys -> EntryType] /\ s.pending \in [SourceKeys -> JobType \cup {NoJob}]
    /\ s.due \in [SourceKeys -> 0..PeriodTicks] /\ s.paused \in BOOLEAN
    /\ s.phase \in {"idle", "drain"} /\ s.traps \in Seq(TrapType)
    /\ Len(s.traps) <= QueueLimit /\ s.overflow \in BOOLEAN
VlanConfigLegal(x) ==
    /\ 1 \in x.vlans /\ x.legacy \in x.vlans
    /\ \A p \in Ports : x.pvid[p] \in x.allowed[p] /\ x.allowed[p] \subseteq x.vlans
         /\ x.untagged[p] \subseteq x.allowed[p]
         /\ x.forbidden[p] \subseteq x.vlans /\ x.allowed[p] \cap x.forbidden[p] = {}
InventoryOK ==
    /\ 1 \in s.vlans /\ s.legacy \in s.vlans
    /\ \A p \in Ports : s.pvid[p] \in s.allowed[p] /\ s.allowed[p] \subseteq s.vlans
    /\ \A p \in Ports : s.untagged[p] \subseteq s.allowed[p]
         /\ s.forbidden[p] \subseteq s.vlans /\ s.allowed[p] \cap s.forbidden[p] = {}
    /\ \A e \in Endpoints \ s.exists : s.attached[e] = NoPort
         /\ \A slot \in Slots : s.sources[<<e, slot>>] = NoSource
    /\ \A p \in Ports : s.mode[p] = "direct" => Cardinality(At(s, p)) <= 1
FdbOK ==
    /\ \A k \in FdbKeys : (s.fdb[k].port = NoPort) <=> (s.fdb[k].ttl = 0)
    /\ s.fdb = KeepLegal(s.fdb, s)
JobsOK ==
    \A sk \in SourceKeys :
        IF s.pending[sk] = NoJob THEN TRUE
        ELSE LET j == s.pending[sk]
             IN (j.egen = s.egen[sk[1]] /\ j.pgen = s.pgen[j.port] /\ j.boot = s.boot)
                    => ValidJob(s, sk, j)
MibOK ==
    /\ EntityOK
    /\ \A k \in Live(s) :
          Dot1dBasePortTable[Dot1qTpFdbTable[k].dot1qTpFdbPort].dot1dBasePortIfIndex =
          IfTable[s.fdb[k].port].ifIndex
    /\ \A v \in s.vlans :
          Dot1qVlanCurrentTable[v].dot1qVlanCurrentUntaggedPorts \subseteq
          Dot1qVlanCurrentTable[v].dot1qVlanCurrentEgressPorts
    /\ \A m \in LegacyMACs : Dot1dTpFdbTable[m].dot1dTpFdbPort =
              Dot1qTpFdbTable[<<VlanToFdb[s.legacy], m>>].dot1qTpFdbPort
TrapsOK == \A i \in 1..Len(s.traps) :
    LET t == s.traps[i]
    IN t.ifIndex = IfIndex[t.port] /\ t.before # t.after
       /\ (t.kind = "linkUp") = t.after /\ (t.after => t.admin)
Safety == TypeOK /\ InventoryOK /\ FdbOK /\ JobsOK /\ MibOK /\ TrapsOK

LearningStep == \A k \in FdbKeys :
    \/ s'.fdb[k] = s.fdb[k] \/ s'.fdb[k] = EmptyEntry
    \/ (s'.fdb[k].port = s.fdb[k].port /\ s'.fdb[k].ttl < s.fdb[k].ttl)
    \/ \E sk \in SourceKeys :
        IF s.pending[sk] = NoJob THEN FALSE
        ELSE LET j == s.pending[sk]
             IN ValidJob(s, sk, j) /\ Admitted(s, j.port, j.vlan)
                /\ k = <<VlanToFdb[j.vlan], j.mac>> /\ s'.pending[sk] = NoJob
                /\ s'.fdb[k] = [port |-> j.port, ttl |-> AgingTicks]
LearningHasSource == [][LearningStep]_vars
StaleJobCannotCommit == [][\A sk \in SourceKeys :
    IF s.pending[sk] = NoJob THEN TRUE
    ELSE (~ValidJob(s, sk, s.pending[sk]) /\ ApplyActivity(sk)) => s'.fdb = s.fdb]_vars

StableInputs == <>[][UNCHANGED <<s.exists, s.sources, s.active, s.attached,
    s.egen, s.vlans, s.pvid, s.allowed, s.admin, s.mode, s.partner,
    s.fault, s.pgen, s.boot>>]_vars
SourcePresent(sk) == IF ~Eligible(s, sk) THEN FALSE ELSE
    s.fdb[<<VlanToFdb[Effective(s, sk)], s.sources[sk].mac>>].port = s.attached[sk[1]]
StableSourcesProgress ==
    (StableInputs /\ <>[](~s.paused)) =>
       (\A sk \in SourceKeys : (<>[]Eligible(s, sk)) => []<>SourcePresent(sk))
SilentEventuallyAgesOut ==
    (<>[](s.active = {} /\ ~s.paused)) => <>[](Live(s) = {})
QuietLinksDrain ==
    (\E op \in [Ports -> BOOLEAN] : <>[]([p \in Ports |-> Oper(s, p)] = op))
         => <>[](s.traps = <<>>)
=============================================================================
