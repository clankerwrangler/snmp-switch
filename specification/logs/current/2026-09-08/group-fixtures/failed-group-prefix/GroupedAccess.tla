-------------------------- MODULE GroupedAccess --------------------------
EXTENDS TestSwitch
CONSTANTS Credentials, Secrets, Views, Snapshots, Targets, Groups,
          NoCredential, NoView, NoRequest, NoResponse, NoPdu, NoGroup, NoAudit
VARIABLES cfg, revision, pending, result, registration, gate, activation,
          snapshot, request, response, audit
C1 == CHOOSE c \in Credentials : TRUE
C2 == CHOOSE c \in Credentials \ {C1} : TRUE
G1 == CHOOSE g \in Groups : TRUE
G2 == CHOOSE g \in Groups \ {G1} : TRUE
G3 == CHOOSE g \in Groups \ {G1,G2} : TRUE
V1 == CHOOSE v \in Views : TRUE
V2 == CHOOSE v \in Views \ {V1} : TRUE
K1 == CHOOSE k \in Secrets : TRUE
K2 == CHOOSE k \in Secrets \ {K1} : TRUE
Sources == {"A","B"}
Levels == 1..3
Modes == {<<FALSE,FALSE>>,<<TRUE,FALSE>>,<<TRUE,TRUE>>,<<FALSE,TRUE>>}
Filters == {{},{"A"},{"B"}}
Permission(on,v,nets) == [on |-> on, view |-> v, nets |-> nets]
Policy(r,w) == [read |-> r, write |-> w]
Denied == Policy(Permission(FALSE,V1,{}),Permission(FALSE,NoView,{}))
Group(policy,minimum,label) == [policy |-> policy, minimum |-> minimum, label |-> label]
Community(on,key,profile,label,policy) ==
    [version |-> 2,on |-> on,key |-> key,profile |-> profile,label |-> label,policy |-> policy]
User(on,key,profile,label,group) ==
    [version |-> 3,on |-> on,key |-> key,profile |-> profile,label |-> label,group |-> group]
Empty == [g \in {} |-> g]
PolicyOf(x,c) == IF x.users[c].version = 2 THEN x.users[c].policy
    ELSE IF x.users[c].group = NoGroup THEN Denied
    ELSE x.groups[x.users[c].group].policy
Minimum(x,c) == IF x.users[c].version = 2 \/ x.users[c].group = NoGroup THEN 1
    ELSE x.groups[x.users[c].group].minimum
Enabled(x) == {c \in DOMAIN x.users : x.users[c].on}
Readers(x) == {c \in DOMAIN x.users : PolicyOf(x,c).read.on}
Writers(x) == {c \in DOMAIN x.users : PolicyOf(x,c).write.on}
Keys(x) == [c \in Credentials |-> IF c \in DOMAIN x.users THEN x.users[c].key ELSE K1]
ReadViews(x) == [c \in Credentials |-> IF c \in DOMAIN x.users THEN PolicyOf(x,c).read.view ELSE V1]
WriteViews(x) == [c \in Credentials |-> IF c \in DOMAIN x.users THEN PolicyOf(x,c).write.view ELSE NoView]

\* These projections are expressions over one canonical configuration, not
\* a second per-user policy store. The existing transaction implementation is
\* unchanged. Its single-PDU lifecycle and core mutation are reused below.
Tx == INSTANCE SetTransactions WITH
    existing <- DOMAIN cfg.users, enabled <- Enabled(cfg), secret <- Keys(cfg),
    polling <- Readers(cfg), presentViews <- cfg.present, viewOf <- ReadViews(cfg),
    includes <- cfg.includes, targetCredential <- cfg.targets, targetEnabled <- cfg.targetOn,
    writing <- Writers(cfg), writeViewOf <- WriteViews(cfg)
allvars == <<s,cfg,revision,pending,result,registration,gate,activation,snapshot,request,response,audit>>

PermissionValid(p,vs) == /\ p.on \in BOOLEAN /\ p.nets \in Filters
    /\ p.view \in Views \cup {NoView} /\ (p.on => p.view \in vs)
PolicyValid(p,vs) == /\ PermissionValid(p.read,vs) /\ PermissionValid(p.write,vs)
    /\ p.read.view \in Views
ConfigValid(x) ==
    /\ DOMAIN x.users \subseteq Credentials /\ DOMAIN x.groups \subseteq Groups
    /\ x.present \subseteq Views /\ x.includes \in [Views -> SUBSET Views]
    /\ \A g \in DOMAIN x.groups : /\ x.groups[g].minimum \in Levels
         /\ PolicyValid(x.groups[g].policy,x.present) /\ x.groups[g].label \in 0..1
    /\ \A c \in DOMAIN x.users : LET u == x.users[c] IN
         /\ u.version \in {2,3} /\ u.on \in BOOLEAN /\ u.key \in Secrets
         /\ u.profile \in Levels /\ u.label \in 0..1
         /\ IF u.version = 2 THEN
                /\ DOMAIN u = {"version","on","key","profile","label","policy"}
                /\ PolicyValid(u.policy,x.present)
            ELSE /\ DOMAIN u = {"version","on","key","profile","label","group"}
                 /\ u.group \in DOMAIN x.groups \cup {NoGroup}
    /\ x.targets \in [Targets -> DOMAIN x.users \cup {NoCredential}]
    /\ x.targetOn \subseteq Targets
    /\ \A t \in x.targetOn : x.targets[t] # NoCredential

InSource(p,source) == p.nets = {} \/ source \in p.nets
\* authenticated is an opaque USM outcome. The numeric profile bounds the
\* available suite, not an additional incoming floor. Actual lower-level USM
\* acceptance and wire identity binding are implementation checks.
RequestBoundary(c,level,source,authenticated,use) ==
    /\ c \in DOMAIN cfg.users /\ cfg.users[c].on /\ authenticated
    /\ (cfg.users[c].version = 2 \/
          (level <= cfg.users[c].profile /\ level >= Minimum(cfg,c)))
    /\ InSource(PolicyOf(cfg,c)[use],source)
CanRead(c,level,source,authenticated) ==
    /\ RequestBoundary(c,level,source,authenticated,"read")
    /\ Tx!Access!Authorized([credential |-> c,suppliedSecret |-> Keys(cfg)[c],requestedViews |-> Views])
CanWrite(c,level,source,authenticated) ==
    /\ RequestBoundary(c,level,source,authenticated,"write")
    /\ Tx!Access!WriteAuthorized(c,Keys(cfg)[c])
TrapAllowed(t) == Tx!Access!NotificationAllowed(t)

PolicySignature(x,c) == IF c \notin DOMAIN x.users THEN <<>>
    ELSE LET u == x.users[c] IN
        <<u.version,u.on,u.key,u.profile,
          IF u.version = 3 THEN u.group ELSE NoGroup,PolicyOf(x,c),Minimum(x,c),
          IF PolicyOf(x,c).write.view \in x.present
          THEN x.includes[PolicyOf(x,c).write.view] ELSE {}>>
Affected(x) == {c \in Credentials : PolicySignature(cfg,c) # PolicySignature(x,c)}
Publish(x,expected,persist,intent) ==
    LET accepted == intent /\ expected = revision /\ ConfigValid(x) /\ persist
        changed == accepted /\ x # cfg
    IN /\ cfg' = IF accepted THEN x ELSE IF ~persist THEN [cfg EXCEPT !.groups = x.groups] ELSE cfg
       /\ revision' = IF changed THEN revision + 1 ELSE revision
       /\ registration' = [c \in Credentials |->
              IF changed /\ c \in Affected(x) THEN Tx!Fresh(Tx!UsedRegistration(c)) ELSE registration[c]]
       /\ audit' = [accepted |-> accepted,before |-> cfg,candidate |-> x,
                    oldRevision |-> revision,oldRegistration |-> registration]
       /\ UNCHANGED <<s,pending,result,gate,activation,snapshot,request,response>>
Idle == /\ audit' = NoAudit /\ UNCHANGED <<s,cfg,revision,pending,result,registration,gate,activation,snapshot,request,response>>
GroupEdit(g,policy,minimum,label,expected,persist) ==
    Publish([cfg EXCEPT !.groups[g] = Group(policy,minimum,label)],expected,persist,g \in DOMAIN cfg.groups)
GroupDelete(g,expected,persist) ==
    Publish([cfg EXCEPT !.groups = [h \in DOMAIN cfg.groups \ {g} |-> cfg.groups[h]]],expected,persist,
      ~\E c \in DOMAIN cfg.users : cfg.users[c].version = 3 /\ cfg.users[c].group = g)
Reassign(c,g) == Publish([cfg EXCEPT !.users[c].group = g],revision,TRUE,TRUE)
ViewEdit(v,objects) == Publish([cfg EXCEPT !.includes[v] = objects],revision,TRUE,TRUE)

\* A form submission applies only dirty, final-active restrictions. Its saved
\* fields and draft are inputs, not another persisted permission owner.
FormPermission(saved,on,draft,dirty) ==
    IF on /\ dirty THEN [draft EXCEPT !.on = on] ELSE [saved EXCEPT !.on = on]
FormPolicy(saved,mode,draft,dirty) == Policy(
    FormPermission(saved.read,mode[1],draft.read,dirty[1]),
    FormPermission(saved.write,mode[2],draft.write,dirty[2]))
FormSave(owner,id,mode,draft,dirty,key,on,expected,persist) ==
    IF owner = "group" THEN
       GroupEdit(id,FormPolicy(cfg.groups[id].policy,mode,draft,dirty),
                 cfg.groups[id].minimum,cfg.groups[id].label,expected,persist)
    ELSE Publish([cfg EXCEPT !.users[id] = Community(on,key,cfg.users[id].profile,cfg.users[id].label,
                 FormPolicy(cfg.users[id].policy,mode,draft,dirty))],expected,persist,cfg.users[id].version = 2)

\* Version 1 has one purpose-scoped read permission. Version 2 has the two
\* independent policies. Both normalized inputs retain opaque key material.
LegacyPolicy(old,c) == IF old.schema = 2 THEN old.users[c].policy
    ELSE Policy(Permission(old.users[c].purpose = "poll",old.users[c].view,old.users[c].nets),
                Permission(FALSE,NoView,{}))
MigrationGroup(c) == IF c = C1 THEN G1 ELSE G2
Migrate(old) ==
    [users |-> [c \in DOMAIN old.users |-> LET u == old.users[c] IN
         IF u.version = 2 THEN Community(u.on,u.key,u.profile,u.label,LegacyPolicy(old,c))
         ELSE User(u.on,u.key,u.profile,u.label,MigrationGroup(c))],
     groups |-> [g \in {MigrationGroup(c) : c \in {d \in DOMAIN old.users : old.users[d].version = 3}} |->
         LET c == CHOOSE d \in DOMAIN old.users : old.users[d].version = 3 /\ MigrationGroup(d) = g
         IN Group(LegacyPolicy(old,c),old.users[c].profile,0)],
     present |-> old.present,includes |-> old.includes,targets |-> old.targets,
     targetOn |-> old.targetOn,metadata |-> old.metadata]

ConversionIntent(c,newVersion,transfer,choice,override,explicitProfile) ==
    /\ c \in DOMAIN cfg.users /\ newVersion # cfg.users[c].version /\ ~override
    /\ IF newVersion = 3 THEN
          /\ explicitProfile
          /\ ((transfer \in {"keep","none"}) # (choice # "absent"))
          /\ (transfer = "absent" \/ choice = "absent")
          /\ choice \in DOMAIN cfg.groups \cup {NoGroup,"absent"}
          /\ (transfer # "keep" \/ G3 \notin DOMAIN cfg.groups)
       ELSE /\ newVersion = 2 /\ transfer \in {"keep","none"} /\ choice = "absent"
ConversionCandidate(c,newVersion,transfer,choice,profile,key) ==
    LET u == cfg.users[c]
        group == IF transfer = "keep" THEN G3 ELSE IF choice = "absent" THEN NoGroup ELSE choice
        policy == IF transfer = "keep" THEN PolicyOf(cfg,c) ELSE Denied
    IN IF newVersion = 3 THEN [cfg EXCEPT
           !.users[c] = User(u.on,key,profile,u.label,group),
           !.groups = IF transfer = "keep"
                      THEN [g \in DOMAIN cfg.groups \cup {G3} |->
                             IF g = G3 THEN Group(PolicyOf(cfg,c),profile,0) ELSE cfg.groups[g]]
                      ELSE @]
       ELSE [cfg EXCEPT !.users[c] = Community(u.on,key,profile,u.label,policy)]
Convert(c,newVersion,transfer,choice,override,profile,explicitProfile,key,expected,persist) ==
    Publish(ConversionCandidate(c,newVersion,transfer,choice,profile,key),expected,persist,
            ConversionIntent(c,newVersion,transfer,choice,override,explicitProfile))
NewUser(c,transfer,inline,persist) ==
    LET x == [cfg EXCEPT !.users = [d \in DOMAIN cfg.users \cup {c} |->
                IF d = c THEN User(TRUE,K1,3,0,NoGroup) ELSE cfg.users[d]],
               !.targets = IF inline THEN [t \in Targets |-> c] ELSE @,
               !.targetOn = IF inline THEN Targets ELSE @]
    IN Publish(x,revision,persist,c \notin DOMAIN cfg.users /\ transfer = "absent")
NewGroup(g) == Publish([cfg EXCEPT !.groups = [h \in DOMAIN cfg.groups \cup {g} |->
    IF h = g THEN Group(Denied,3,0) ELSE cfg.groups[h]]],revision,TRUE,g \notin DOMAIN cfg.groups)

Submit(c,budget,persist) == /\ UNCHANGED <<cfg,revision>>
    /\ Tx!SubmitSet(c,Keys(cfg)[c],<<Tx!Op("admin",P0,2)>>,budget,persist)
    /\ audit' = NoAudit
Handle(level,source,authenticated) ==
    /\ UNCHANGED <<cfg,revision>>
    /\ pending # NoPdu
    /\ (IF RequestBoundary(pending.credential,level,source,authenticated,"write")
         THEN Tx!HandleSet ELSE Tx!Reject("dropped",0))
    /\ audit' = NoAudit

BaseInit(x) == /\ RunningInit /\ cfg = x /\ revision = 0
    /\ pending = NoPdu /\ result = [status |-> "none",index |-> 0]
    /\ registration = [c \in Credentials |-> Token0] /\ gate = TRUE /\ activation = Token0
    /\ snapshot \in Snapshots /\ request = NoRequest /\ response = NoResponse /\ audit = NoAudit
GroupType == /\ ConfigValid(cfg) /\ revision \in 0..8 /\ Tx!SetTypeOK
AtomicSave == audit # NoAudit =>
    /\ cfg = (IF audit.accepted THEN audit.candidate ELSE audit.before)
    /\ revision = (IF audit.accepted /\ audit.candidate # audit.before THEN audit.oldRevision + 1 ELSE audit.oldRevision)
    /\ (~audit.accepted => registration = audit.oldRegistration)
TargetsUnchanged == [][cfg'.targets = cfg.targets /\ cfg'.targetOn = cfg.targetOn]_allvars
NoUserPolicyMirror == \A c \in DOMAIN cfg.users : cfg.users[c].version = 3 => "policy" \notin DOMAIN cfg.users[c]
NoTransferPersisted == \A c \in DOMAIN cfg.users : "access_transfer" \notin DOMAIN cfg.users[c]
NoGroupNoIncoming == \A c \in DOMAIN cfg.users :
    (cfg.users[c].version = 3 /\ cfg.users[c].group = NoGroup) => c \notin Readers(cfg) \cup Writers(cfg)
=============================================================================
