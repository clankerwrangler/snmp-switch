-------------------------- MODULE SetTransactions --------------------------
EXTENDS TestSwitch
CONSTANTS Credentials, Secrets, Views, Snapshots, Targets,
          NoCredential, NoView, NoRequest, NoResponse, NoPdu
VARIABLES existing, enabled, secret, polling, presentViews, viewOf, includes,
          targetCredential, targetEnabled, writing, writeViewOf, snapshot, request, response
Access == INSTANCE ReadAccess
\* Expand the shared tuple locally for TLC 1.7.4 UNCHANGED evaluation.
accessvars == <<existing, enabled, secret, polling, presentViews, viewOf, includes,
               targetCredential, targetEnabled, writing, writeViewOf, snapshot, request, response>>
VARIABLES pending, result, registration, gate, activation
allvars == <<s, accessvars, pending, result, registration, gate, activation>>
Kinds == {"admin", "pvid", "egress", "untagged", "forbidden", "name", "row", "readonly"}
BitmapKinds == {"egress", "untagged", "forbidden"}
VlanKinds == BitmapKinds \cup {"name", "row"}
PortView == CHOOSE v \in Views : TRUE
VlanView == CHOOSE v \in Views \ {PortView} : TRUE
C1 == CHOOSE c \in Credentials : TRUE
C2 == CHOOSE c \in Credentials \ {C1} : TRUE
K1 == Access!Secret0
K2 == CHOOSE k \in Secrets \ {K1} : TRUE
First(indices) == CHOOSE i \in indices : \A j \in indices : i <= j
Op(kind, key, value) == [kind |-> kind, key |-> key, value |-> value, error |-> "noError"]
BadOp(kind, key, value, error) == [kind |-> kind, key |-> key, value |-> value, error |-> error]
Positions(ops, kind, key) == {i \in DOMAIN ops : ops[i].kind = kind /\ ops[i].key = key}
Has(ops, kind, key) == Positions(ops, kind, key) # {}
Value(ops, kind, key, default) == IF Has(ops, kind, key)
    THEN ops[First(Positions(ops, kind, key))].value ELSE default
Creates(ops) == {v \in VLANs : Has(ops, "row", v) /\ Value(ops,"row",v,0) = 4}
Deletes(ops) == {v \in VLANs : Has(ops, "row", v) /\ Value(ops,"row",v,0) = 6}
ObjectView(op) == IF op.kind \in {"admin", "pvid"} THEN PortView ELSE VlanView

\* Already-decoded type/length/resource errors are symbolic boundary inputs.
\* BER, USM, exact OID prefixes, and byte lengths are not implemented here.
RowError(v, value) ==
    CASE value \notin {1,2,3,4,5,6} \/ value = 3 -> "wrongValue"
      [] v \in s.vlans /\ value \in {4,5} -> "inconsistentValue"
      [] v \notin s.vlans /\ value \in {1,2} -> "inconsistentValue"
      [] value \in {2,5} -> "wrongValue"
      [] v = 1 /\ value = 6 -> "inconsistentValue"
      [] OTHER -> "noError"
VarbindError(ops, i, granted) ==
    LET op == ops[i]
        prior == {j \in 1..(i-1) : ops[j].kind = op.kind /\ ops[j].key = op.key}
    IN CASE ObjectView(op) \notin granted -> "noAccess"
      [] op.kind = "readonly" -> "notWritable"
      [] op.error # "noError" -> op.error
      [] op.kind = "admin" /\ op.value \notin {1,2} -> "wrongValue"
      [] op.kind = "pvid" /\ op.value \notin VLANs -> "wrongValue"
      [] op.kind \in BitmapKinds /\ ~IsFiniteSet(op.value) -> "wrongType"
      [] op.kind \in BitmapKinds /\ ~op.value \subseteq Ports -> "wrongValue"
      [] op.kind = "name" /\ op.value \notin 0..1 -> "wrongValue"
      [] op.kind \in {"admin","pvid"} /\ op.key \notin Ports -> "noCreation"
      [] op.kind \in VlanKinds /\ op.key \notin VLANs -> "noCreation"
      [] op.kind = "row" /\ RowError(op.key,op.value) # "noError" -> RowError(op.key,op.value)
      [] op.kind \in VlanKinds \ {"row"} /\ op.key \notin s.vlans \cup Creates(ops) -> "inconsistentName"
      [] op.kind \in VlanKinds \ {"row"} /\ op.key \in Deletes(ops) -> "inconsistentValue"
      [] \E j \in prior : ops[j].value # op.value -> "inconsistentValue"
      [] OTHER -> "noError"
FirstError(ops, granted) ==
    LET bad == {i \in DOMAIN ops : VarbindError(ops,i,granted) # "noError"}
    IN IF bad = {} THEN [status |-> "noError", index |-> 0]
       ELSE [status |-> VarbindError(ops,First(bad),granted), index |-> First(bad)]

Candidate(ops) ==
    LET gone == Deletes(ops)
        vs == (s.vlans \ gone) \cup Creates(ops)
        fallback == {p \in Ports : s.pvid[p] \in gone /\ ~Has(ops,"pvid",p)}
        defaultMembers == [p \in Ports |-> (s.allowed[p] \ gone) \cup
                             (IF p \in fallback THEN {1} ELSE {})]
        defaultTags == [p \in Ports |-> (s.untagged[p] \ gone) \cup
                         (IF p \in fallback /\ s.pvid[p] \in s.untagged[p] THEN {1} ELSE {})]
    IN [s EXCEPT !.vlans = vs,
        !.admin = [p \in Ports |-> Value(ops,"admin",p,IF s.admin[p] THEN 1 ELSE 2) = 1],
        !.pvid = [p \in Ports |-> Value(ops,"pvid",p,IF p \in fallback THEN 1 ELSE s.pvid[p])],
        !.allowed = [p \in Ports |-> {v \in vs : p \in
            Value(ops,"egress",v,{q \in Ports : v \in defaultMembers[q]})}],
        !.untagged = [p \in Ports |-> {v \in vs : p \in
            Value(ops,"untagged",v,{q \in Ports : v \in defaultTags[q]})}],
        !.forbidden = [p \in Ports |-> {v \in vs : p \in
            Value(ops,"forbidden",v,{q \in Ports : v \in s.forbidden[q] \ gone})}],
        !.vlanNames = [v \in VLANs |-> IF v \notin vs THEN 0
                         ELSE Value(ops,"name",v,IF v \in s.vlans THEN s.vlanNames[v] ELSE 0)],
        !.legacy = IF s.legacy \in gone THEN 1 ELSE s.legacy]
IllegalVlans(p,x) == (x.untagged[p] \ x.allowed[p])
    \cup (x.allowed[p] \cap x.forbidden[p]) \cup (x.allowed[p] \ x.vlans)
    \cup (x.forbidden[p] \ x.vlans)
    \cup (IF x.pvid[p] \notin x.allowed[p] THEN {x.pvid[p]} ELSE {})
ConflictIndex(ops,x) ==
    First({i \in DOMAIN ops : \E p \in Ports :
        LET op == ops[i]
            overlap == x.allowed[p] \cap x.forbidden[p]
            missingTags == x.untagged[p] \ x.allowed[p]
        IN \/ (op.kind = "pvid" /\ op.key = p /\ x.pvid[p] \notin x.allowed[p])
           \/ (op.kind = "egress" /\
                 (op.key \in overlap \cup missingTags \/
                  (op.key = x.pvid[p] /\ x.pvid[p] \notin x.allowed[p])))
           \/ (op.kind = "forbidden" /\ op.key \in overlap)
           \/ (op.kind = "untagged" /\ op.key \in missingTags)
           \/ (op.kind = "row" /\ op.value = 6 /\ op.key = s.pvid[p]
               /\ op.key \in s.vlans /\ ~Has(ops,"pvid",p)
               /\ 1 \in IllegalVlans(p,x))})

Configuration(x) == <<x.vlans,x.admin,x.pvid,x.allowed,x.untagged,x.forbidden,x.vlanNames,x.legacy>>
AffectedPorts(x) == {p \in Ports :
    <<x.admin[p],x.pvid[p],x.allowed[p],x.untagged[p],x.forbidden[p]>> #
    <<s.admin[p],s.pvid[p],s.allowed[p],s.untagged[p],s.forbidden[p]>>}
AffectedEndpoints(ops) == UNION {TaggedEndpoints(v) : v \in Creates(ops) \cup (Deletes(ops) \cap s.vlans)}
EffectivePositions(ops) == {i \in DOMAIN ops :
    LET op == ops[i]
    IN CASE op.kind = "admin" -> op.value # (IF s.admin[op.key] THEN 1 ELSE 2)
      [] op.kind = "pvid" -> op.value # s.pvid[op.key]
      [] op.kind = "name" -> op.key \notin s.vlans \/ op.value # s.vlanNames[op.key]
      [] op.kind = "row" -> (op.value = 4) \/ (op.value = 6 /\ op.key \in s.vlans)
      [] op.kind = "egress" -> op.value # {p \in Ports : op.key \in s.allowed[p]}
      [] op.kind = "untagged" -> op.value # {p \in Ports : op.key \in s.untagged[p]}
      [] op.kind = "forbidden" -> op.value # {p \in Ports : op.key \in s.forbidden[p]}
      [] OTHER -> FALSE}

UsedRegistration(c) == {registration[c]} \cup
    (IF pending = NoPdu THEN {} ELSE IF pending.credential = c THEN {pending.registration} ELSE {})
UsedActivation == {activation} \cup (IF pending = NoPdu THEN {} ELSE {pending.activation})
SetInit ==
    /\ RunningInit /\ Access!Init
    /\ pending = NoPdu /\ result = [status |-> "none", index |-> 0]
    /\ registration = [c \in Credentials |-> Token0] /\ activation = Token0 /\ gate = TRUE
Grant(c, on, vs) ==
    /\ Access!ConfigureCredential(c, on, secret[c], vs)
    /\ registration' = [d \in Credentials |->
         IF (d = c /\ on # (c \in enabled)) \/
            (d \in existing /\ writeViewOf[d] = viewOf[c] /\ vs # Access!grants[c])
         THEN Fresh(UsedRegistration(d)) ELSE registration[d]]
    /\ UNCHANGED <<s,pending,result,gate,activation>>
SetWriteView(c, on, v) ==
    /\ Access!SaveWriting(c,on,v)
    /\ registration' = [registration EXCEPT ![c] =
         IF writing' # writing \/ writeViewOf' # writeViewOf
         THEN Fresh(UsedRegistration(c)) ELSE @]
    /\ UNCHANGED <<s,pending,result,gate,activation>>
SetWriting(c,on) == SetWriteView(c,on,viewOf[c])
ChangeView(v,vs) ==
    /\ Access!SaveView(v,vs)
    /\ registration' = [c \in Credentials |->
         IF c \in existing /\ writeViewOf[c] = v /\
              (v \notin presentViews \/ includes[v] # vs)
         THEN Fresh(UsedRegistration(c)) ELSE registration[c]]
    /\ UNCHANGED <<s,pending,result,gate,activation>>
RemoveCredential(c) ==
    /\ Access!DeleteCredential(c)
    /\ registration' = [registration EXCEPT ![c] =
         IF existing' # existing THEN Fresh(UsedRegistration(c)) ELSE @]
    /\ UNCHANGED <<s,pending,result,gate,activation>>
Rotate(c, k) ==
    /\ Access!SaveCredential(c,TRUE,c \in polling,viewOf[c],k)
    /\ registration' = [registration EXCEPT ![c] =
         IF k # secret[c] \/ c \notin enabled THEN Fresh(UsedRegistration(c)) ELSE @]
    /\ UNCHANGED <<s,pending,result,gate,activation>>
SetGate(on) ==
    /\ gate # on /\ gate' = on /\ activation' = Fresh(UsedActivation)
    /\ UNCHANGED <<s,accessvars,pending,result,registration>>
SubmitSet(c,k,ops,budget,persist) ==
    /\ pending = NoPdu
    /\ pending' = [credential |-> c, secret |-> k, ops |-> ops, budget |-> budget,
                   persist |-> persist, registration |-> registration[c],
                   activation |-> activation, boot |-> s.boot]
    /\ result' = [status |-> "none",index |-> 0]
    /\ UNCHANGED <<s,accessvars,registration,gate,activation>>
Reject(status,index) ==
    /\ result' = [status |-> status,index |-> index] /\ pending' = NoPdu
    /\ UNCHANGED <<s,accessvars,registration,gate,activation>>
HandleSet ==
    /\ pending # NoPdu
    /\ LET r == pending
           auth == Access!WriteAuthorized(r.credential,r.secret)
           error == FirstError(r.ops,Access!WriteGrants(r.credential))
       IN IF ~gate \/ r.activation # activation \/ r.boot # s.boot
             \/ r.registration # registration[r.credential] \/ r.secret # secret[r.credential]
          THEN Reject("dropped",0)
          ELSE IF ~r.budget THEN Reject("tooBig",0)
          ELSE IF ~auth THEN Reject("authorizationError",0)
          ELSE IF error.status # "noError" THEN Reject(error.status,error.index)
          ELSE LET x == Candidate(r.ops)
               IN IF ~VlanConfigLegal(x) THEN Reject("inconsistentValue",ConflictIndex(r.ops,x))
                  ELSE IF Configuration(x) = Configuration(s) THEN Reject("noError",0)
                  ELSE IF ~r.persist THEN Reject("commitFailed",First(EffectivePositions(r.ops)))
                  ELSE /\ Mutate(x,AffectedEndpoints(r.ops),AffectedPorts(x))
                       /\ result' = [status |-> "noError",index |-> 0] /\ pending' = NoPdu
                       /\ UNCHANGED <<accessvars,registration,gate,activation>>
SetReboot ==
    /\ Reboot /\ activation' = Fresh(UsedActivation)
    /\ UNCHANGED <<accessvars,pending,result,registration,gate>>
CoreAction(action) == action /\ UNCHANGED <<accessvars,pending,result,registration,gate,activation>>

\* Bounded arbitrary transaction graph. Larger command combinations use the
\* same HandleSet action in scripted integration traces.
SmallCommands == {Op("admin",P0,1),Op("admin",P0,2),Op("pvid",P0,1),
                   Op("readonly",P0,0),BadOp("admin",P0,1,"wrongType")}
SmallRequests == {<<>>} \cup {<<a>> : a \in SmallCommands}
                    \cup {<<a,b>> : a,b \in SmallCommands}
TransactionNext ==
    \/ \E c \in Credentials, k \in Secrets, ops \in SmallRequests, budget,persist \in BOOLEAN :
           SubmitSet(c,k,ops,budget,persist)
    \/ HandleSet
    \/ \E c \in Credentials, on \in BOOLEAN : SetWriting(c,on)
    \/ \E c \in Credentials, k \in Secrets : Rotate(c,k)
    \/ \E on \in BOOLEAN : SetGate(on)
TransactionInit ==
    /\ RunningInit
    /\ existing = Credentials /\ enabled = Credentials /\ polling = Credentials
    /\ secret \in [Credentials -> Secrets]
    /\ presentViews = Views /\ viewOf = Access!CredentialViews
    /\ includes = [v \in Views |-> Views]
    /\ targetCredential = [t \in Targets |-> NoCredential] /\ targetEnabled = {}
    /\ writing = {} /\ writeViewOf = [c \in Credentials |-> NoView]
    /\ snapshot \in Snapshots /\ request = NoRequest /\ response = NoResponse
    /\ pending = NoPdu /\ result = [status |-> "none", index |-> 0]
    /\ registration = [c \in Credentials |-> Token0] /\ activation = Token0 /\ gate = TRUE
TransactionSpec == TransactionInit /\ [][TransactionNext]_allvars /\ WF_allvars(HandleSet)

SetTypeOK ==
    /\ (pending # NoPdu => result.status = "none")
    /\ Access!TypeOK /\ Access!ReferencesOK /\ registration \in [Credentials -> Tokens]
    /\ activation \in Tokens /\ gate \in BOOLEAN
    /\ result.status \in {"none","noError","authorizationError","noAccess","notWritable",
          "wrongType","wrongLength","wrongValue","noCreation","inconsistentName",
          "inconsistentValue","resourceUnavailable","commitFailed","dropped","tooBig"}
    /\ result.index \in 0..3
FailedSetPreservesState == [][
    (pending # NoPdu /\ pending' = NoPdu /\ result'.status # "noError")
        => UNCHANGED <<s,accessvars,registration,gate,activation>>]_allvars
SuccessfulSetIsAtomic == [][
    (pending # NoPdu /\ pending' = NoPdu /\ result'.status = "noError") =>
        /\ Configuration(s') = Configuration(Candidate(pending.ops))
        /\ s'.fdb = KeepLegal(s.fdb,Candidate(pending.ops))
        /\ UNCHANGED accessvars]_allvars
SuccessfulSetIsAuthorized == [][
    (pending # NoPdu /\ pending' = NoPdu /\ result'.status = "noError") =>
        /\ Access!WriteAuthorized(pending.credential,pending.secret)
        /\ pending.registration = registration[pending.credential]
        /\ pending.activation = activation /\ pending.boot = s.boot /\ gate
        /\ \A i \in DOMAIN pending.ops : ObjectView(pending.ops[i]) \in Access!WriteGrants(pending.credential)]_allvars
SetRequestsComplete == (pending # NoPdu) ~> (pending = NoPdu)
=============================================================================
