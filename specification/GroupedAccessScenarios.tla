---------------------- MODULE GroupedAccessScenarios ----------------------
EXTENDS GroupedAccess
VARIABLES fixture, origin, pc
Combined == <<allvars,fixture,origin,pc>>
Step(action) == action /\ pc' = pc + 1 /\ UNCHANGED <<fixture,origin>>
SharedPolicy == Policy(Permission(TRUE,V1,{}),Permission(TRUE,V2,{}))
SelectedTarget == CHOOSE t \in Targets : TRUE
Config(users,groups) ==
    [users |-> users, groups |-> groups, present |-> Views,
     includes |-> [v \in Views |-> {V1}],
     targets |-> [t \in Targets |-> IF t = SelectedTarget THEN C1 ELSE C2],
     targetOn |-> Targets, metadata |-> <<"engine-id","persistent-identity">>]
Shared == Config([c \in Credentials |-> User(TRUE,K1,3,0,G1)],
                 [g \in {G1,G2} |-> Group(SharedPolicy,3,0)])
Saved == [Shared EXCEPT !.users = [c \in Credentials |->
    [Community(TRUE,IF c = C1 THEN K1 ELSE K2,3,0,SharedPolicy) EXCEPT !.version = 3]]]
OwnershipCases == {"migrationIsolation","acceptedSave","staleSave","failedSave",
                  "invalidReference","referencedDelete","noGroup","inlineTarget"}
OwnershipStart(name) == CASE
    name = "migrationIsolation" -> Migrate(Saved)
    [] name = "referencedDelete" -> [Shared EXCEPT
         !.users[C1].group = G2, !.users[C2].on = FALSE]
    [] name = "noGroup" -> [Shared EXCEPT !.users[C1].group = NoGroup]
    [] name = "inlineTarget" -> [Shared EXCEPT
         !.users = [c \in {C1} |-> Community(TRUE,K1,1,0,Denied)],
         !.targets = [t \in Targets |-> C1], !.targetOn = {}]
    [] OTHER -> Shared
SaveCandidate == [cfg EXCEPT
    !.groups = [g \in DOMAIN cfg.groups \cup {G3} |->
        IF g = G3 THEN Group([SharedPolicy EXCEPT !.write.on = FALSE],3,0) ELSE cfg.groups[g]],
    !.users[C1].group = G3]
InlineCandidate == [cfg EXCEPT
    !.users = [c \in DOMAIN cfg.users \cup {C2} |->
        IF c = C2 THEN User(TRUE,K2,3,0,NoGroup) ELSE cfg.users[c]],
    !.targets[SelectedTarget] = C2, !.targetOn = @ \cup {SelectedTarget}]
OwnershipAction ==
    IF fixture = "noGroup" THEN
        IF pc = 0 THEN Submit(C1,TRUE,TRUE) ELSE Handle(3,"A",TRUE)
    ELSE IF pc = 1 THEN Idle
    ELSE CASE fixture = "migrationIsolation" ->
             GroupEdit(cfg.users[C1].group,[SharedPolicy EXCEPT !.read.on = FALSE],3,0,revision,TRUE)
         [] fixture \in {"acceptedSave","staleSave","failedSave"} ->
             Publish(SaveCandidate,IF fixture = "staleSave" THEN revision + 1 ELSE revision,
                     fixture # "failedSave",TRUE)
         [] fixture = "invalidReference" ->
             Publish([cfg EXCEPT !.users[C1].group = G3],revision,TRUE,TRUE)
         [] fixture = "referencedDelete" -> GroupDelete(G1,revision,TRUE)
         [] OTHER -> Publish(InlineCandidate,revision,TRUE,TRUE)
OwnershipInit == /\ fixture \in OwnershipCases
    /\ BaseInit(OwnershipStart(fixture)) /\ origin = cfg /\ pc = 0
OwnershipNext == IF pc = 2 THEN UNCHANGED Combined ELSE Step(OwnershipAction)
OwnershipSpec == OwnershipInit /\ [][OwnershipNext]_Combined /\ WF_Combined(OwnershipNext)
OwnershipCompletes == <> (pc = 2)
MigrationPreservesSaved == fixture = "migrationIsolation" /\ pc = 0 =>
    /\ DOMAIN cfg.users = DOMAIN Saved.users
    /\ <<cfg.targets,cfg.targetOn,cfg.metadata,cfg.present,cfg.includes>> =
       <<Saved.targets,Saved.targetOn,Saved.metadata,Saved.present,Saved.includes>>
    /\ \A c \in Credentials :
         /\ PolicyOf(cfg,c) = Saved.users[c].policy
         /\ Minimum(cfg,c) = Saved.users[c].profile
         /\ <<cfg.users[c].on,cfg.users[c].key,cfg.users[c].profile,cfg.users[c].label>> =
            <<Saved.users[c].on,Saved.users[c].key,Saved.users[c].profile,Saved.users[c].label>>
OwnershipAssertions ==
    /\ cfg.metadata = origin.metadata
    /\ (fixture # "inlineTarget" =>
         /\ cfg.targets = origin.targets /\ cfg.targetOn = origin.targetOn
         /\ cfg.users[C2] = origin.users[C2])
    /\ (pc > 0 => CASE
         fixture = "migrationIsolation" ->
             /\ cfg.users = origin.users
             /\ PolicyOf(cfg,C2) = PolicyOf(origin,C2)
             /\ cfg.users[C1].group # cfg.users[C2].group
         [] fixture = "acceptedSave" ->
             /\ cfg.users[C1] = [origin.users[C1] EXCEPT !.group = G3]
             /\ cfg.groups[G3] = Group([SharedPolicy EXCEPT !.write.on = FALSE],3,0)
             /\ \A g \in DOMAIN origin.groups : cfg.groups[g] = origin.groups[g]
         [] fixture = "inlineTarget" ->
             /\ cfg.users[C1] = origin.users[C1] /\ cfg.users[C2] = User(TRUE,K2,3,0,NoGroup)
             /\ cfg.groups = origin.groups
             /\ cfg.targets = [origin.targets EXCEPT ![SelectedTarget] = C2]
             /\ cfg.targetOn = origin.targetOn \cup {SelectedTarget}
         [] OTHER -> cfg = origin)
    /\ (fixture = "noGroup" => TrapAllowed(SelectedTarget) /\ ~CanWrite(C1,3,"A",TRUE))
    /\ (fixture = "noGroup" /\ pc = 2 => result.status = "authorizationError" /\ s.admin[P0])

StaleNames == {"policyRestore","readRestore","minimumRestore","filterRestore","reassignRestore",
              "viewRestore","viewSelectionRestore","enabledRestore","keyRestore","profileRestore"}
StableNames == {"sameGroup","labelOnly","unrelatedGroup","unreferencedView","sameView","sameMembership",
               "invalidGroup","deleteReferenced","userOverride","noGroup","readOnly","writeOnly","noneMode"}
BoundaryNames == {"unauthenticated","unsupportedProfile","minimumDenied","sourceDenied"}
QueueFixtures == {[name |-> name,credential |-> c] :
    name \in StaleNames \cup StableNames \cup BoundaryNames, c \in Credentials}
QueueStart(f) ==
    LET policy == CASE f.name = "readOnly" -> [SharedPolicy EXCEPT !.write.on = FALSE]
           [] f.name = "writeOnly" -> [SharedPolicy EXCEPT !.read.on = FALSE]
           [] f.name \in {"noneMode","noGroup"} -> Denied
           [] f.name = "sourceDenied" -> [SharedPolicy EXCEPT !.write.nets = {"B"}]
           [] OTHER -> SharedPolicy
    IN [Shared EXCEPT
         !.groups[G1].policy = policy,
         !.groups[G1].minimum = IF f.name = "unsupportedProfile" THEN 1 ELSE 3,
         !.users = [c \in Credentials |-> User(TRUE,K1,IF f.name = "minimumDenied" THEN 1 ELSE 3,0,
                      IF f.name = "noGroup" THEN NoGroup ELSE G1)]]
QueueLevel == IF fixture.name \in {"minimumDenied","unsupportedProfile"} THEN 1 ELSE 3
QueueAuthenticated == fixture.name # "unauthenticated"
EditQueued ==
    LET g == cfg.groups[G1]
        original == origin.groups[G1]
    IN CASE fixture.name = "policyRestore" -> GroupEdit(G1,
              IF pc = 1 THEN [g.policy EXCEPT !.write.on = FALSE] ELSE original.policy,g.minimum,0,revision,TRUE)
       [] fixture.name = "readRestore" -> GroupEdit(G1,
              IF pc = 1 THEN [g.policy EXCEPT !.read.on = FALSE] ELSE original.policy,g.minimum,0,revision,TRUE)
       [] fixture.name = "minimumRestore" -> GroupEdit(G1,g.policy,IF pc = 1 THEN 1 ELSE 3,0,revision,TRUE)
       [] fixture.name = "filterRestore" -> GroupEdit(G1,
              IF pc = 1 THEN [g.policy EXCEPT !.write.nets = {"B"}] ELSE original.policy,g.minimum,0,revision,TRUE)
       [] fixture.name = "reassignRestore" -> Reassign(fixture.credential,IF pc = 1 THEN NoGroup ELSE G1)
       [] fixture.name = "viewRestore" -> ViewEdit(V2,IF pc = 1 THEN {} ELSE origin.includes[V2])
       [] fixture.name = "viewSelectionRestore" -> GroupEdit(G1,
              IF pc = 1 THEN [g.policy EXCEPT !.write.view = V1] ELSE original.policy,g.minimum,0,revision,TRUE)
       [] fixture.name = "enabledRestore" -> Publish([cfg EXCEPT !.users[fixture.credential].on = pc # 1],revision,TRUE,TRUE)
       [] fixture.name = "keyRestore" -> Publish([cfg EXCEPT !.users[fixture.credential].key =
              IF pc = 1 THEN K2 ELSE K1],revision,TRUE,TRUE)
       [] fixture.name = "profileRestore" -> Publish([cfg EXCEPT !.users[fixture.credential].profile =
              IF pc = 1 THEN 1 ELSE 3],revision,TRUE,TRUE)
       [] fixture.name = "sameGroup" -> GroupEdit(G1,g.policy,g.minimum,g.label,revision,TRUE)
       [] fixture.name = "labelOnly" -> GroupEdit(G1,g.policy,g.minimum,IF pc = 1 THEN 1 ELSE 0,revision,TRUE)
       [] fixture.name = "unrelatedGroup" -> GroupEdit(G2,g.policy,IF pc = 1 THEN 1 ELSE 3,0,revision,TRUE)
       [] fixture.name = "unreferencedView" -> ViewEdit(V1,IF pc = 1 THEN {} ELSE origin.includes[V1])
       [] fixture.name = "sameView" -> ViewEdit(V2,cfg.includes[V2])
       [] fixture.name = "sameMembership" -> Reassign(fixture.credential,G1)
       [] fixture.name = "invalidGroup" -> GroupEdit(G1,[g.policy EXCEPT !.write.view = NoView],3,0,revision,TRUE)
       [] fixture.name = "deleteReferenced" -> GroupDelete(G1,revision,TRUE)
       [] fixture.name = "userOverride" -> Publish(cfg,revision,TRUE,FALSE)
       [] OTHER -> Idle
QueueAction == CASE pc = 0 -> Submit(fixture.credential,TRUE,TRUE)
    [] pc \in {1,2} -> EditQueued
    [] pc = 3 -> Handle(QueueLevel,"A",QueueAuthenticated)
    [] OTHER -> Idle
QueueInit == /\ fixture \in QueueFixtures /\ BaseInit(QueueStart(fixture)) /\ origin = cfg /\ pc = 0
QueueNext == IF pc = 5 THEN UNCHANGED Combined ELSE Step(QueueAction)
QueueSpec == QueueInit /\ [][QueueNext]_Combined /\ WF_Combined(QueueNext)
QueueCompletes == <> (pc = 5)
ExpectedStatus == IF fixture.name \in StaleNames \cup BoundaryNames THEN "dropped"
    ELSE IF fixture.name \in {"noGroup","readOnly","noneMode"} THEN "authorizationError"
    ELSE "noError"
QueueAssertions ==
    /\ cfg.targets = origin.targets /\ cfg.targetOn = origin.targetOn /\ cfg.metadata = origin.metadata
    /\ (pc >= 4 =>
         /\ pending = NoPdu /\ result.status = ExpectedStatus /\ result.index = 0
         /\ s.admin[P0] = (ExpectedStatus # "noError")
         /\ IF fixture.name \in StaleNames
            THEN registration[fixture.credential] # Token0
            ELSE registration[fixture.credential] = Token0)
CompleteRequests == Tx!SetRequestsComplete
FailedTransactionsPreserve == Tx!FailedSetPreservesState
AtomicTransactions == Tx!SuccessfulSetIsAtomic
AuthorizedTransactions == Tx!SuccessfulSetIsAuthorized
FullRequestBoundary == [][(pending # NoPdu /\ pending' = NoPdu /\ result'.status = "noError") =>
    RequestBoundary(pending.credential,QueueLevel,"A",QueueAuthenticated,"write")]_Combined
=============================================================================
