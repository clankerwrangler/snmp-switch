---------------------- MODULE GroupedAccessScenarios ----------------------
EXTENDS GroupedAccess
VARIABLES fixture, origin, pc
Combined == <<allvars,fixture,origin,pc>>
Step(action) == /\ action /\ pc' = pc + 1 /\ UNCHANGED <<fixture,origin>>
PairPolicy(mode,nets,missing) == Policy(
    Permission(mode[1],IF missing /\ ~mode[1] THEN V2 ELSE V1,nets),
    Permission(mode[2],IF missing THEN (IF mode[2] THEN V1 ELSE V2) ELSE V2,
               IF nets = {"A"} THEN {"B"} ELSE IF nets = {"B"} THEN {"A"} ELSE {}))
TargetsFor(users) == [t \in Targets |-> IF C2 \in users /\ t = (CHOOSE q \in Targets : TRUE) THEN C2 ELSE C1]
Config(users,groups,missing) == [users |-> users,groups |-> groups,
    present |-> IF missing THEN {V1} ELSE Views,
    includes |-> [v \in Views |-> Views], targets |-> TargetsFor(DOMAIN users),
    targetOn |-> Targets,metadata |-> <<"engine-id","persistent-identity">>]
Legacy(f) == [schema |-> f.schema,
    users |-> [c \in Credentials |->
      LET version == IF c = C1 THEN f.first ELSE f.second
          p == PairPolicy(f.mode,f.nets,FALSE)
      IN IF f.schema = 2 THEN Community(f.on,f.key,f.level,0,p)
         ELSE [version |-> version,on |-> f.on,key |-> f.key,profile |-> f.level,label |-> 0,
               purpose |-> IF f.mode[1] THEN "poll" ELSE "trap",view |-> p.read.view,nets |-> p.read.nets]],
    present |-> Views,includes |-> [v \in Views |-> Views],
    targets |-> TargetsFor(Credentials),targetOn |-> Targets,metadata |-> <<"engine-id","persistent-identity">>]
\* The v2 legacy shape has policy for either wire protocol.
LegacyInput(f) == LET old == Legacy(f) IN
    [old EXCEPT !.users = [c \in Credentials |->
        [old.users[c] EXCEPT !.version = IF c = C1 THEN f.first ELSE f.second]]]
MigrationCases == {[kind |-> "migration",schema |-> schema,first |-> first,second |-> second,
    mode |-> mode,nets |-> nets,on |-> on,key |-> key,level |-> level] :
    schema \in {1,2},first \in {2,3},second \in {2,3},mode \in Modes,nets \in Filters,
    on \in BOOLEAN,key \in Secrets,level \in Levels}
ConversionNames == {"keep","none","null","existing","missing","conflict","override",
                    "stale","failure","noProfile","missingGroup","wrongDirectionGroup"}
ConversionCases == {[kind |-> "conversion",direction |-> direction,name |-> name,mode |-> mode,
    level |-> level,on |-> on,noGroup |-> noGroup] : direction \in {2,3},name \in ConversionNames,
    mode \in Modes,level \in Levels,on \in BOOLEAN,noGroup \in BOOLEAN}
NewCases == {[kind |-> "newUser",transfer |-> transfer,inline |-> inline,persist |-> persist] :
    transfer \in {"absent","keep","none"},inline \in BOOLEAN,persist \in BOOLEAN}
SameCases == {[kind |-> "same",version |-> version,transfer |-> transfer,override |-> override] :
    version \in {2,3},transfer \in {"absent","keep","none"},override \in BOOLEAN}
ReferenceCases == {[kind |-> name] : name \in {"newGroup","deleteReferenced","deleteUnused","invalidUnused"}}
MigrationFixtures == MigrationCases \cup ConversionCases \cup NewCases \cup SameCases \cup ReferenceCases
ConversionStart(f) ==
    LET p == PairPolicy(f.mode,{"A"},FALSE)
        groups == [g \in {G1,G2} |-> Group(p,3,0)]
        c1 == IF f.direction = 3 THEN Community(f.on,K1,1,0,p)
              ELSE User(f.on,K1,f.level,0,IF f.noGroup THEN NoGroup ELSE G1)
    IN Config([c \in Credentials |-> IF c = C1 THEN c1 ELSE User(FALSE,K2,1,0,G2)],groups,FALSE)
DefaultStart == Config([c \in Credentials |-> User(FALSE,K1,3,0,G1)],
                       [g \in {G1,G2} |-> Group(Denied,3,0)],FALSE)
MigrationStart(f) == CASE f.kind = "migration" -> Migrate(LegacyInput(f))
    [] f.kind = "conversion" -> ConversionStart(f)
    [] f.kind = "newUser" -> Config([c \in {C1} |-> Community(TRUE,K2,1,0,Denied)],Empty,FALSE)
    [] f.kind = "same" -> Config([c \in Credentials |->
         IF f.version = 2 THEN Community(TRUE,K1,1,0,Denied) ELSE User(TRUE,K1,3,0,G1)],
         [g \in {G1} |-> Group(Denied,3,0)],FALSE)
    [] OTHER -> DefaultStart
Transfer(f) == IF f.name \in {"none"} THEN "none"
    ELSE IF f.name \in {"null","existing","missing","missingGroup","wrongDirectionGroup"} THEN "absent"
    ELSE "keep"
Choice(f) == CASE f.name = "null" -> NoGroup
    [] f.name \in {"existing","conflict","wrongDirectionGroup"} -> G2
    [] f.name = "missingGroup" -> G3
    [] OTHER -> "absent"
ConversionOK(f) == /\ f.name \notin {"missing","conflict","override","stale","failure","missingGroup"}
    /\ IF f.direction = 3 THEN f.name # "noProfile"
       ELSE f.name \notin {"null","existing","wrongDirectionGroup"}
MigrationLength == 2
MigratedUsers == IF fixture.kind = "migration" THEN
    {c \in Credentials : LegacyInput(fixture).users[c].version = 3} ELSE {}
EditedMigrant == CHOOSE c \in MigratedUsers : TRUE
MigrationAction ==
    IF pc = 1 THEN Idle
    ELSE CASE fixture.kind = "migration" ->
         IF MigratedUsers = {} THEN Idle
         ELSE LET g == cfg.users[EditedMigrant].group
                  p == cfg.groups[g].policy
              IN GroupEdit(g,[p EXCEPT !.read.on = ~@],cfg.groups[g].minimum,0,revision,TRUE)
    [] fixture.kind = "conversion" ->
         Convert(C1,fixture.direction,Transfer(fixture),Choice(fixture),fixture.name = "override",
                 fixture.level,fixture.name # "noProfile",K2,
                 IF fixture.name = "stale" THEN revision + 1 ELSE revision,fixture.name # "failure")
    [] fixture.kind = "newUser" -> NewUser(C2,fixture.transfer,fixture.inline,fixture.persist)
    [] fixture.kind = "same" -> Publish([cfg EXCEPT !.users[C1].key = K2],revision,TRUE,
         fixture.transfer = "absent" /\ ~(fixture.version = 3 /\ fixture.override))
    [] fixture.kind = "newGroup" -> NewGroup(G3)
    [] fixture.kind = "deleteReferenced" -> GroupDelete(G1,revision,TRUE)
    [] fixture.kind = "deleteUnused" -> GroupDelete(G2,revision,TRUE)
    [] fixture.kind = "invalidUnused" -> GroupEdit(G2,
         [Denied EXCEPT !.write = Permission(TRUE,NoView,{})],3,0,revision,TRUE)
MigrationInit == /\ fixture \in MigrationFixtures /\ BaseInit(MigrationStart(fixture)) /\ origin = cfg /\ pc = 0
MigrationNext == IF pc = MigrationLength THEN UNCHANGED Combined ELSE Step(MigrationAction)
MigrationSpec == MigrationInit /\ [][MigrationNext]_Combined /\ WF_Combined(MigrationNext)
MigrationCompletes == <> (pc = MigrationLength)
MigrationPreservesSaved == (fixture.kind = "migration" /\ pc = 0) =>
    LET old == LegacyInput(fixture)
    IN /\ DOMAIN cfg.users = DOMAIN old.users
       /\ cfg.targets = old.targets /\ cfg.targetOn = old.targetOn /\ cfg.metadata = old.metadata
       /\ cfg.present = old.present /\ cfg.includes = old.includes
       /\ \A c \in Credentials :
            /\ <<cfg.users[c].on,cfg.users[c].key,cfg.users[c].profile,cfg.users[c].label>> =
               <<old.users[c].on,old.users[c].key,old.users[c].profile,old.users[c].label>>
            /\ PolicyOf(cfg,c) = LegacyPolicy(old,c)
            /\ (old.users[c].version = 3 => Minimum(cfg,c) = old.users[c].profile)
       /\ \A c,d \in MigratedUsers : cfg.users[c].group = cfg.users[d].group => c = d
MigrationIsolation == (fixture.kind = "migration" /\ pc = MigrationLength) =>
    /\ cfg.users = origin.users /\ cfg.targets = origin.targets /\ cfg.metadata = origin.metadata
    /\ \A c \in Credentials : c \notin MigratedUsers \/ c # EditedMigrant => PolicyOf(cfg,c) = PolicyOf(origin,c)
MigrationAssertions == pc = MigrationLength =>
    CASE fixture.kind = "migration" -> MigrationIsolation
    [] fixture.kind = "conversion" ->
         /\ cfg.targets = origin.targets /\ cfg.targetOn = origin.targetOn /\ cfg.metadata = origin.metadata
         /\ cfg.users[C2] = origin.users[C2]
         /\ \A g \in DOMAIN origin.groups : cfg.groups[g] = origin.groups[g]
         /\ IF ~ConversionOK(fixture) THEN cfg = origin
            ELSE /\ cfg.users[C1].version = fixture.direction
                 /\ cfg.users[C1].on = origin.users[C1].on /\ cfg.users[C1].key = K2
                 /\ IF fixture.direction = 2 THEN
                        PolicyOf(cfg,C1) = (IF Transfer(fixture) = "keep" THEN PolicyOf(origin,C1) ELSE Denied)
                    ELSE IF Transfer(fixture) = "keep" THEN
                        /\ cfg.users[C1].group = G3 /\ cfg.groups[G3].policy = PolicyOf(origin,C1)
                        /\ cfg.groups[G3].minimum = fixture.level
                    ELSE cfg.users[C1].group = (IF Choice(fixture) = "absent" THEN NoGroup ELSE Choice(fixture))
    [] fixture.kind = "newUser" ->
         IF fixture.transfer = "absent" /\ fixture.persist THEN
            /\ cfg.users[C2] = User(TRUE,K1,3,0,NoGroup) /\ cfg.groups = origin.groups
            /\ (fixture.inline => \A t \in Targets : TrapAllowed(t) /\ cfg.targets[t] = C2)
         ELSE cfg = origin
    [] fixture.kind = "same" ->
         IF fixture.transfer = "absent" /\ ~(fixture.version = 3 /\ fixture.override)
         THEN cfg = [origin EXCEPT !.users[C1].key = K2] ELSE cfg = origin
    [] fixture.kind = "newGroup" -> cfg.groups[G3] = Group(Denied,3,0)
    [] fixture.kind = "deleteUnused" -> DOMAIN cfg.groups = {G1}
    [] OTHER -> cfg = origin

FormNames == {"transition","unchanged","secret","cancel","stale","failure","invalid","draftCycle"}
FormFixtures == {f \in {[kind |-> "form",owner |-> owner,name |-> name,start |-> start,finish |-> finish,
    nets |-> nets,key |-> key,on |-> on,missing |-> missing] :
    owner \in {"community","group"},name \in FormNames,start \in Modes,
    finish \in Modes,nets \in Filters,
    key \in Secrets,on \in BOOLEAN,missing \in BOOLEAN} : f.name = "transition" \/ f.finish = f.start}
FormStart(f) ==
    LET p == PairPolicy(f.start,f.nets,f.missing)
    IN Config([c \in Credentials |-> IF f.owner = "community" /\ c = C1
              THEN Community(f.on,f.key,1,0,p) ELSE User(f.on,f.key,3,0,G1)],
              [g \in {G1} |-> Group(p,3,0)],f.missing)
SavedPolicy == IF fixture.owner = "group" THEN origin.groups[G1].policy ELSE origin.users[C1].policy
DraftPolicy == Policy(Permission(TRUE,V1,{"B"}),Permission(TRUE,V2,{"A"}))
FinalMode == IF fixture.name = "invalid" THEN <<TRUE,TRUE>>
             ELSE IF fixture.name = "draftCycle" THEN <<TRUE,TRUE>> ELSE fixture.finish
Dirty == IF fixture.name \in {"unchanged","secret"} THEN <<FALSE,FALSE>> ELSE <<TRUE,TRUE>>
ChosenDraft == IF fixture.name = "invalid" THEN [DraftPolicy EXCEPT !.write.view = NoView] ELSE DraftPolicy
ExpectedPermission(saved,on,draft,dirty) ==
    [on |-> on,view |-> IF on /\ dirty THEN draft.view ELSE saved.view,
     nets |-> IF on /\ dirty THEN draft.nets ELSE saved.nets]
ExpectedPolicy == Policy(ExpectedPermission(SavedPolicy.read,FinalMode[1],ChosenDraft.read,Dirty[1]),
                         ExpectedPermission(SavedPolicy.write,FinalMode[2],ChosenDraft.write,Dirty[2]))
FormAccepted == fixture.name \notin {"cancel","stale","failure","invalid"} /\ PolicyValid(ExpectedPolicy,origin.present)
FormLength == 4
FormAction == IF pc # 2 \/ fixture.name = "cancel" THEN Idle
    ELSE FormSave(fixture.owner,IF fixture.owner = "group" THEN G1 ELSE C1,
         FinalMode,ChosenDraft,Dirty,IF fixture.name = "secret" THEN K2 ELSE fixture.key,fixture.on,
         IF fixture.name = "stale" THEN revision + 1 ELSE revision,fixture.name # "failure")
FormInit == /\ fixture \in FormFixtures /\ BaseInit(FormStart(fixture)) /\ origin = cfg /\ pc = 0
FormNext == IF pc = FormLength THEN UNCHANGED Combined ELSE Step(FormAction)
FormSpec == FormInit /\ [][FormNext]_Combined /\ WF_Combined(FormNext)
FormCompletes == <> (pc = FormLength)
FormAssertions ==
    /\ cfg.targets = origin.targets /\ cfg.targetOn = origin.targetOn /\ cfg.metadata = origin.metadata
    /\ cfg.users[C2] = origin.users[C2]
    /\ (pc < 3 => cfg = origin)
    /\ (pc = FormLength =>
        IF ~FormAccepted THEN cfg = origin
        ELSE /\ PolicyOf(cfg,C1) = ExpectedPolicy
             /\ cfg.users[C1].on = origin.users[C1].on
             /\ (fixture.name \in {"unchanged","secret"} => PolicyOf(cfg,C1) = SavedPolicy)
             /\ (~FinalMode[1] => <<PolicyOf(cfg,C1).read.view,PolicyOf(cfg,C1).read.nets>> =
                                     <<SavedPolicy.read.view,SavedPolicy.read.nets>>)
             /\ (~FinalMode[2] => <<PolicyOf(cfg,C1).write.view,PolicyOf(cfg,C1).write.nets>> =
                                     <<SavedPolicy.write.view,SavedPolicy.write.nets>>)
             /\ (fixture.owner = "group" => cfg.users = origin.users)
             /\ (fixture.owner = "community" => cfg.groups = origin.groups))

StaleNames == {"policyRestore","readRestore","minimumRestore","filterRestore","reassignRestore",
              "viewRestore","viewSelectionRestore","enabledRestore","keyRestore","profileRestore"}
StableNames == {"sameGroup","labelOnly","unrelatedGroup","unreferencedView","sameView","sameMembership",
               "invalidGroup","deleteReferenced","userOverride","noGroup","readOnly","writeOnly","noneMode"}
QueueCases == {[kind |-> "queue",name |-> name,credential |-> c,key |-> key] :
    name \in StaleNames \cup StableNames,c \in Credentials,key \in Secrets}
ProbeCases == {[kind |-> "probe",level |-> level,capability |-> cap,minimum |-> minimum,
    source |-> source,nets |-> nets,authenticated |-> auth,mode |-> mode,credential |-> c,budget |-> budget] :
    level \in Levels,cap \in Levels,minimum \in Levels,source \in Sources,nets \in Filters,
    auth \in BOOLEAN,mode \in Modes,c \in Credentials,budget \in BOOLEAN}
QueueFixtures == QueueCases \cup ProbeCases
QueueMode(f) == IF f.kind = "probe" THEN f.mode
    ELSE CASE f.name = "readOnly" -> <<TRUE,FALSE>> [] f.name = "writeOnly" -> <<FALSE,TRUE>>
       [] f.name \in {"noGroup","noneMode"} -> <<FALSE,FALSE>> [] OTHER -> <<TRUE,TRUE>>
QueueStart(f) ==
    LET p == PairPolicy(QueueMode(f),IF f.kind = "probe" THEN f.nets ELSE {},FALSE)
        cap == IF f.kind = "probe" THEN f.capability ELSE 3
        minimum == IF f.kind = "probe" THEN f.minimum ELSE 3
        key == IF f.kind = "probe" THEN K1 ELSE f.key
    IN [Config([c \in Credentials |-> User(TRUE,key,cap,0,
                IF f.kind = "queue" /\ f.name = "noGroup" THEN NoGroup ELSE G1)],
               [g \in {G1,G2} |-> Group(p,minimum,0)],FALSE)
          EXCEPT !.includes = [v \in Views |-> {V1}]]
QueueLevel == IF fixture.kind = "probe" THEN fixture.level ELSE 3
QueueSource == IF fixture.kind = "probe" THEN fixture.source ELSE "A"
QueueAuthenticated == IF fixture.kind = "probe" THEN fixture.authenticated ELSE TRUE
QueueBudget == IF fixture.kind = "probe" THEN fixture.budget ELSE TRUE
EditQueued ==
    IF fixture.kind = "probe" THEN Idle
    ELSE LET g == cfg.groups[G1]
             original == origin.groups[G1]
         IN CASE fixture.name = "policyRestore" -> GroupEdit(G1,
                IF pc = 1 THEN [g.policy EXCEPT !.write.on = FALSE] ELSE original.policy,g.minimum,0,revision,TRUE)
         [] fixture.name = "readRestore" -> GroupEdit(G1,
                IF pc = 1 THEN [g.policy EXCEPT !.read.on = FALSE] ELSE original.policy,g.minimum,0,revision,TRUE)
         [] fixture.name = "minimumRestore" -> GroupEdit(G1,g.policy,IF pc = 1 THEN 1 ELSE original.minimum,0,revision,TRUE)
         [] fixture.name = "filterRestore" -> GroupEdit(G1,
                IF pc = 1 THEN [g.policy EXCEPT !.write.nets = {"B"}] ELSE original.policy,g.minimum,0,revision,TRUE)
         [] fixture.name = "reassignRestore" -> Reassign(fixture.credential,IF pc = 1 THEN NoGroup ELSE G1)
         [] fixture.name = "viewRestore" -> ViewEdit(V2,IF pc = 1 THEN {} ELSE origin.includes[V2])
         [] fixture.name = "viewSelectionRestore" -> GroupEdit(G1,
                IF pc = 1 THEN [g.policy EXCEPT !.write.view = V1] ELSE original.policy,g.minimum,0,revision,TRUE)
         [] fixture.name = "enabledRestore" -> Publish([cfg EXCEPT !.users[fixture.credential].on = pc # 1],revision,TRUE,TRUE)
         [] fixture.name = "keyRestore" -> Publish([cfg EXCEPT !.users[fixture.credential].key =
                IF pc = 1 THEN (IF fixture.key = K1 THEN K2 ELSE K1) ELSE fixture.key],revision,TRUE,TRUE)
         [] fixture.name = "profileRestore" -> Publish([cfg EXCEPT !.users[fixture.credential].profile = IF pc = 1 THEN 1 ELSE 3],revision,TRUE,TRUE)
         [] fixture.name = "sameGroup" -> GroupEdit(G1,g.policy,g.minimum,g.label,revision,TRUE)
         [] fixture.name = "labelOnly" -> GroupEdit(G1,g.policy,g.minimum,IF pc = 1 THEN 1 ELSE 0,revision,TRUE)
         [] fixture.name = "unrelatedGroup" -> GroupEdit(G2,g.policy,IF pc = 1 THEN 1 ELSE 3,0,revision,TRUE)
         [] fixture.name = "unreferencedView" -> ViewEdit(V1,IF pc = 1 THEN {} ELSE origin.includes[V1])
         [] fixture.name = "sameView" -> ViewEdit(V2,cfg.includes[V2])
         [] fixture.name = "sameMembership" -> Reassign(fixture.credential,G1)
         [] fixture.name = "invalidGroup" -> GroupEdit(G1,[g.policy EXCEPT !.write.view = NoView],g.minimum,0,revision,TRUE)
         [] fixture.name = "deleteReferenced" -> GroupDelete(G1,revision,TRUE)
         [] fixture.name = "userOverride" -> Publish(cfg,revision,TRUE,FALSE)
         [] OTHER -> Idle
QueueLength == 5
QueueAction == CASE pc = 0 -> Submit(fixture.credential,QueueBudget,TRUE)
    [] pc \in {1,2} -> EditQueued
    [] pc = 3 -> Handle(QueueLevel,QueueSource,QueueAuthenticated)
    [] OTHER -> Idle
QueueInit == /\ fixture \in QueueFixtures /\ BaseInit(QueueStart(fixture)) /\ origin = cfg /\ pc = 0
QueueNext == IF pc = QueueLength THEN UNCHANGED Combined ELSE Step(QueueAction)
QueueSpec == QueueInit /\ [][QueueNext]_Combined /\ WF_Combined(QueueNext)
QueueCompletes == <> (pc = QueueLength)
ExpectedBoundary == IF fixture.kind = "probe" THEN
    fixture.authenticated /\ fixture.level = fixture.capability /\ fixture.level >= fixture.minimum /\
    (PolicyOf(origin,fixture.credential).write.nets = {} \/ fixture.source \in PolicyOf(origin,fixture.credential).write.nets)
    ELSE TRUE
ExpectedStatus == IF ~ExpectedBoundary THEN "dropped"
    ELSE IF fixture.kind = "queue" /\ fixture.name \in StaleNames THEN "dropped"
    ELSE IF ~QueueBudget THEN "tooBig"
    ELSE IF ~QueueMode(fixture)[2] THEN "authorizationError" ELSE "noError"
QueueAssertions ==
    /\ cfg.targets = origin.targets /\ cfg.targetOn = origin.targetOn /\ cfg.metadata = origin.metadata
    /\ (pc = 3 /\ fixture.kind = "queue" =>
          IF fixture.name \in StaleNames THEN pending.registration # registration[fixture.credential]
          ELSE pending.registration = registration[fixture.credential])
    /\ (pc >= 4 => /\ pending = NoPdu /\ result.status = ExpectedStatus /\ result.index = 0
                    /\ s.admin[P0] = (ExpectedStatus # "noError"))
ResolverAssertions == fixture.kind = "probe" =>
    /\ StockUsmAccepted(fixture.credential,fixture.level,fixture.authenticated) =
          (fixture.authenticated /\ fixture.level = fixture.capability)
    /\ ((StockUsmAccepted(fixture.credential,fixture.level,fixture.authenticated) /\ fixture.level < fixture.minimum) =>
          /\ ~CanRead(fixture.credential,fixture.level,fixture.source,fixture.authenticated)
          /\ ~CanWrite(fixture.credential,fixture.level,fixture.source,fixture.authenticated))
    /\ CanRead(fixture.credential,fixture.level,fixture.source,fixture.authenticated) =
        (fixture.authenticated /\ fixture.level = fixture.capability /\ fixture.level >= fixture.minimum /\
         fixture.mode[1] /\ (fixture.nets = {} \/ fixture.source \in fixture.nets))
    /\ CanWrite(fixture.credential,fixture.level,fixture.source,fixture.authenticated) =
        (ExpectedBoundary /\ fixture.mode[2])
    /\ \A t \in Targets : TrapAllowed(t)
CompleteRequests == Tx!SetRequestsComplete
FailedTransactionsPreserve == Tx!FailedSetPreservesState
AtomicTransactions == Tx!SuccessfulSetIsAtomic
AuthorizedTransactions == Tx!SuccessfulSetIsAuthorized
FullRequestBoundary == [][(pending # NoPdu /\ pending' = NoPdu /\ result'.status = "noError") =>
    RequestBoundary(pending.credential,QueueLevel,QueueSource,QueueAuthenticated,"write")]_Combined
=============================================================================
