---------------------- MODULE StorageOutcomes ----------------------
EXTENDS Naturals, FiniteSets
CONSTANTS NoVersion, NoWork, NoRead, Tokens, FirstEffectiveIndex
VARIABLES store, work, result, seen, scenario, workKind, deliveryStage, actualOutcome, pc, anchor
StorageVars == <<store,work,result,seen,scenario,workKind,deliveryStage,actualOutcome,pc,anchor>>
Values == [primary : BOOLEAN, secondary : BOOLEAN]
OldValue == [primary |-> FALSE, secondary |-> FALSE]
Fields == {"primary","secondary"}
Kinds == {"api","set","background","notify"}
Commands == {"api","set","lab","save","reboot","seed"}
Outcomes == {"success","rolledBack","rollbackFailed","commitUnknown"}
ActualDurability == {"old","candidate"}
Faults == {"rollbackFailed","commitUnknown"}
Edit(v, field) == [v EXCEPT ![field] = ~@]
Result(status, index) == [status |-> status, index |-> index, operation |-> "none"]

\* Two current hardware inventories; C replaces B's numeric slot, not its identity.
PortIds == {"A","B","C"}
InitialLab == [ports |-> {"A","B"}, attached |-> {"B"}, sourceTag |-> 20]
ReplacementLab == [ports |-> {"A","C"}, attached |-> {}, sourceTag |-> 20]
Labs == {l \in [ports : SUBSET PortIds, attached : SUBSET PortIds, sourceTag : {20}] :
          l.attached \subseteq l.ports}
Policies == UNION {[ids -> BOOLEAN] : ids \in SUBSET PortIds}
DefaultPolicy == FALSE
Policy(lab,v) == [p \in lab.ports |-> IF p = "A" THEN v.primary ELSE v.secondary]
Compose(lab,saved) == [lab |-> lab,
    policy |-> [p \in lab.ports |-> IF p \in DOMAIN saved THEN saved[p] ELSE DefaultPolicy]]
EditPolicy(policy,field) == [p \in DOMAIN policy |->
    IF (field = "primary" /\ p = "A") \/ (field = "secondary" /\ p # "A") THEN ~policy[p] ELSE policy[p]]
InitialPolicy == Policy(InitialLab,OldValue)
InitialImage == [lab |-> InitialLab, startup |-> InitialPolicy, independent |-> FALSE, seeded |-> TRUE]
Images == [lab : Labs, startup : Policies, independent : BOOLEAN, seeded : BOOLEAN]
InitialStore == [open |-> TRUE, active |-> TRUE, health |-> "healthy",
    published |-> Compose(InitialLab,InitialPolicy), saved |-> InitialPolicy,
    durable |-> InitialImage, transaction |-> NoVersion, incarnation |-> CHOOSE t \in Tokens : TRUE,
    runtime |-> FALSE, sent |-> FALSE]
Gate == store.open /\ store.active /\ store.health = "healthy"
CommitAllowed == Gate
CurrentWork == IF work = NoWork THEN FALSE ELSE Gate /\ work.incarnation = store.incarnation
UsedIncarnations == {store.incarnation} \cup (IF work = NoWork THEN {} ELSE {work.incarnation})
FreshIncarnation == CHOOSE t \in Tokens \ UsedIncarnations : TRUE
Protected(x) == <<x.published,x.saved,x.durable,x.transaction,x.runtime,x.sent,x.incarnation,x.active>>
ReadView == [value |-> store.published, confirmed |-> TRUE, writable |-> Gate, health |-> store.health]
StorageView == [value |-> IF store.transaction = NoVersion THEN store.durable ELSE store.transaction,
                confirmed |-> FALSE, writable |-> FALSE, health |-> store.health]
Dirty == store.published # Compose(store.published.lab,store.saved)
RebootLab == store.durable.lab

\* An image denotes only these durable projections. Ordinary required event,
\* revision and protocol transactions may stutter in this projection.
Candidate(operation,field) ==
    LET nextLab == Compose(ReplacementLab,store.published.policy)
        published == CASE operation \in {"api","set"} ->
                [store.published EXCEPT !.policy = EditPolicy(@,field)]
          [] operation = "lab" -> [nextLab EXCEPT !.policy = EditPolicy(@,field)]
          [] operation = "reboot" -> Compose(RebootLab,store.saved)
          [] operation = "seed" -> Compose(store.durable.lab,store.durable.startup)
          [] OTHER -> store.published
        saved == IF operation = "save" THEN store.published.policy
                 ELSE IF operation = "seed" THEN store.durable.startup ELSE store.saved
        image == CASE operation = "save" -> [store.durable EXCEPT !.startup = store.published.policy]
          [] operation = "lab" -> [store.durable EXCEPT !.lab = ReplacementLab]
          [] operation = "seed" -> [store.durable EXCEPT !.seeded = TRUE]
          [] OTHER -> store.durable
    IN [published |-> published, saved |-> saved, image |-> image,
        reset |-> operation \in {"reboot","seed"},
        runtime |-> IF operation \in {"reboot","seed"} THEN FALSE
                   ELSE IF operation \in {"api","set","lab"} THEN ~store.runtime ELSE store.runtime]
OutcomeResult(outcome) == CASE outcome = "success" -> Result("noError",0)
    [] outcome = "rolledBack" -> Result("commitFailed",FirstEffectiveIndex)
    [] outcome = "rollbackFailed" -> Result("undoFailed",0)
    [] outcome = "commitUnknown" -> Result("dropped",0)
CommitState(c,outcome,actual) ==
    CASE outcome = "success" -> [store EXCEPT !.published = c.published, !.saved = c.saved,
          !.durable = c.image, !.transaction = NoVersion, !.runtime = c.runtime,
          !.incarnation = IF c.reset THEN FreshIncarnation ELSE @, !.active = TRUE]
      [] outcome = "rolledBack" -> store
      [] outcome = "rollbackFailed" -> [store EXCEPT !.transaction = c.image, !.health = "rollbackFailed"]
      [] outcome = "commitUnknown" -> [store EXCEPT !.durable = IF actual = "old" THEN @ ELSE c.image,
                                       !.health = "commitUnknown", !.transaction = NoVersion]
Attempt(operation,field,outcome,actual) ==
    /\ operation \in Commands /\ field \in Fields /\ outcome \in Outcomes /\ actual \in ActualDurability
    /\ (IF CommitAllowed \/ (operation = "seed" /\ store.open /\ ~store.active /\ store.health = "healthy")
       THEN /\ store' = CommitState(Candidate(operation,field),outcome,actual)
            /\ result' = [OutcomeResult(outcome) EXCEPT !.operation = operation]
       ELSE /\ UNCHANGED store /\ result' = [Result("blocked",0) EXCEPT !.operation = operation])
    /\ UNCHANGED <<work,seen>>
Background ==
    /\ (IF Gate THEN /\ store' = [store EXCEPT !.runtime = ~@] /\ result' = Result("background",0)
        ELSE /\ UNCHANGED store /\ result' = Result("blocked",0))
    /\ UNCHANGED <<work,seen>>
Send == /\ (IF Gate THEN /\ store' = [store EXCEPT !.sent = ~@] /\ result' = Result("sent",0)
            ELSE /\ UNCHANGED store /\ result' = Result("blocked",0)) /\ UNCHANGED <<work,seen>>
RecordIndependentFact == /\ Gate /\ store' = [store EXCEPT !.durable.independent = TRUE]
    /\ result' = Result("recorded",0) /\ UNCHANGED <<work,seen>>
Queue(kind) == /\ Gate /\ work = NoWork /\ kind \in Kinds
    /\ work' = [kind |-> kind, incarnation |-> store.incarnation]
    /\ result' = Result("queued",0) /\ UNCHANGED <<store,seen>>
Handle(outcome,actual) == /\ work # NoWork /\ outcome \in Outcomes /\ actual \in ActualDurability
    /\ (IF CurrentWork
       THEN IF work.kind = "notify"
            THEN /\ store' = [store EXCEPT !.sent = ~@] /\ result' = Result("workSent",0)
            ELSE IF work.kind = "background"
                 THEN /\ store' = [store EXCEPT !.runtime = ~@] /\ result' = Result("background",0)
                 ELSE /\ store' = CommitState(Candidate(work.kind,"secondary"),outcome,actual)
                      /\ result' = [OutcomeResult(outcome) EXCEPT !.operation = work.kind]
       ELSE /\ UNCHANGED store /\ result' = Result("workDropped",0))
    /\ work' = NoWork /\ UNCHANGED seen
HandleWork == IF work = NoWork THEN FALSE
    ELSE \E o \in (IF CurrentWork /\ work.kind \in {"api","set"} THEN Outcomes ELSE {"success"}) :
             Handle(o,"candidate")
ReadConfirmed == /\ store.open /\ store.active /\ seen' = ReadView
    /\ result' = Result("read",0) /\ UNCHANGED <<store,work>>
InspectStorage == /\ store.open /\ seen' = StorageView
    /\ result' = Result("inspected",0) /\ UNCHANGED <<store,work>>
Close == /\ store.open /\ store' = [store EXCEPT !.open = FALSE, !.active = FALSE, !.transaction = NoVersion]
    /\ result' = Result("closed",0) /\ UNCHANGED <<work,seen>>
CloseFailed == /\ store.open /\ store.health # "healthy"
    /\ result' = Result("closeFailed",0) /\ UNCHANGED <<store,work,seen>>
Open(load) == /\ ~store.open /\ load \in {"valid","unavailable","invalid"}
    /\ (IF load = "valid" /\ store.durable.seeded
       THEN /\ store' = [store EXCEPT !.open = TRUE, !.active = TRUE, !.health = "healthy",
                 !.published = Compose(store.durable.lab,store.durable.startup), !.saved = store.durable.startup,
                 !.transaction = NoVersion, !.incarnation = FreshIncarnation, !.runtime = FALSE]
            /\ result' = Result("reopened",0)
       ELSE /\ UNCHANGED store
            /\ result' = Result(IF load = "unavailable" THEN "loadUnavailable" ELSE "loadInvalid",0))
    /\ UNCHANGED <<work,seen>>
BaseInit == /\ work = NoWork /\ result = Result("none",0) /\ seen = NoRead /\ anchor = NoRead /\ pc = 0
StorageInit == BaseInit /\ store = InitialStore /\ scenario = [operation |-> "set", outcome |-> "success"]
    /\ workKind = "set" /\ deliveryStage = "afterRestart" /\ actualOutcome = "candidate"
KeepFixture == UNCHANGED <<scenario,workKind,deliveryStage,actualOutcome,pc,anchor>>
StorageNext ==
    /\ ((\E k \in {"api","set","save","reboot"} :
             \E f \in (IF CommitAllowed /\ k \in {"api","set"} THEN Fields ELSE {"primary"}) :
             \E o \in (IF CommitAllowed THEN Outcomes ELSE {"success"}) :
             \E a \in (IF o = "commitUnknown" /\ Candidate(k,f).image # store.durable
                       THEN ActualDurability ELSE {"candidate"}) : Attempt(k,f,o,a))
        \/ Background \/ Send \/ (\E k \in Kinds : Queue(k)) \/ HandleWork
        \/ Close \/ CloseFailed \/ (\E load \in {"valid","unavailable","invalid"} : Open(load)))
    /\ KeepFixture
\* External successful restart/storage availability, not automatic application recovery.
RecoveryProgress == /\ ((store.health # "healthy" /\ Close) \/ Open("valid")) /\ KeepFixture
GraphHandle == HandleWork /\ KeepFixture
StorageSpec == StorageInit /\ [][StorageNext]_StorageVars
    /\ WF_StorageVars(RecoveryProgress) /\ WF_StorageVars(GraphHandle)
RecoveryEventuallyUsable == (~store.open \/ store.health # "healthy") ~> Gate
QueuedWorkCompletes == (work # NoWork) ~> (work = NoWork)

StorageTypeOK ==
    /\ store.open \in BOOLEAN /\ store.active \in BOOLEAN
    /\ store.health \in {"healthy","rollbackFailed","commitUnknown"}
    /\ store.published.lab \in Labs /\ store.published.policy \in Policies /\ store.saved \in Policies
    /\ DOMAIN store.published.policy = store.published.lab.ports
    /\ store.durable \in Images /\ store.transaction \in Images \cup {NoVersion}
    /\ store.incarnation \in Tokens /\ store.runtime \in BOOLEAN /\ store.sent \in BOOLEAN
    /\ work \in {NoWork} \cup [kind : Kinds, incarnation : Tokens]
    /\ result.status \in {"none","noError","commitFailed","undoFailed","dropped","blocked","background","sent",
        "queued","workSent","workDropped","read","inspected","closed","closeFailed","reopened","loadInvalid","loadUnavailable","recorded"}
    /\ result.index \in {0,FirstEffectiveIndex} /\ result.operation \in Commands \cup {"none"}
    /\ actualOutcome \in ActualDurability
HealthyConsistency == store.health = "healthy" =>
    /\ store.published.lab = store.durable.lab /\ store.saved = store.durable.startup /\ store.transaction = NoVersion
OpenRollbackState == store.open /\ store.health = "rollbackFailed" => store.transaction # NoVersion
ClosedTransactionGone == ~store.open => ~store.active /\ store.transaction = NoVersion
CommittedUnknownState == store.health = "commitUnknown" => store.transaction = NoVersion
ActivationNeedsSplit == store.active => store.durable.seeded
NormalCapabilities == Gate =>
    /\ ENABLED Attempt("api","secondary","success","candidate")
    /\ ENABLED Attempt("set","secondary","success","candidate")
    /\ ENABLED Attempt("save","primary","success","candidate")
    /\ ENABLED Attempt("reboot","primary","success","candidate") /\ ENABLED Background /\ ENABLED Send
FreshAvailable == Tokens \ UsedIncarnations # {}
UncertaintyBlocksEffects == [][store.open /\ store.health # "healthy" /\ store'.open => Protected(store') = Protected(store)]_StorageVars
UnconfirmedDurableSurvives == [][store.health # "healthy" => store'.durable = store.durable]_StorageVars
NoInPlaceHealthReset == [][store.open /\ store.health # "healthy" /\ store'.open => store'.health = store.health]_StorageVars
ClosedCannotMutate == [][~store.open => /\ store'.durable = store.durable /\ store'.sent = store.sent]_StorageVars
ValidRestartOnly == [][~store.open /\ store'.open =>
    /\ result'.status = "reopened" /\ store'.health = "healthy" /\ store'.active
    /\ store'.published = Compose(store.durable.lab,store.durable.startup) /\ store'.saved = store.durable.startup
    /\ store'.transaction = NoVersion /\ store'.incarnation \notin UsedIncarnations /\ ~store'.runtime]_StorageVars
FailedLoadPreserves == [][result'.status \in {"loadInvalid","loadUnavailable"} => UNCHANGED store]_StorageVars
ConfirmedRollbackPreserves == [][result'.status = "commitFailed" => /\ UNCHANGED store /\ result'.index = FirstEffectiveIndex]_StorageVars
FailedRollbackOutcome == [][result'.status = "undoFailed" =>
    /\ store'.open /\ store'.health = "rollbackFailed" /\ store'.transaction # NoVersion
    /\ store'.durable = store.durable /\ store'.published = store.published /\ store'.saved = store.saved
    /\ store'.active = store.active /\ result'.index = 0
    /\ store'.transaction \in {Candidate(result'.operation,f).image : f \in Fields}
    /\ UNCHANGED <<store.runtime,store.sent,store.incarnation>>]_StorageVars
UnknownCommitOutcome == [][result'.status = "dropped" =>
    /\ store'.health = "commitUnknown" /\ store'.transaction = NoVersion
    /\ store'.published = store.published /\ store'.saved = store.saved /\ store'.active = store.active
    /\ result'.index = 0 /\ UNCHANGED <<store.runtime,store.sent,store.incarnation>>
    /\ store'.durable \in {store.durable} \cup {Candidate(result'.operation,f).image : f \in Fields}]_StorageVars
QueuedEffectsRequireCurrent == [][work # NoWork /\ work' = NoWork /\ Protected(store') # Protected(store) => CurrentWork]_StorageVars
StaleWorkDrops == [][work # NoWork /\ ~CurrentWork /\ work' = NoWork => /\ UNCHANGED store /\ result'.status = "workDropped"]_StorageVars
SuccessfulPublicationIsAtomic == [][result'.status = "noError" =>
    \E f \in Fields : LET c == Candidate(result'.operation,f) IN
        /\ store'.published = c.published /\ store'.saved = c.saved /\ store'.durable = c.image
        /\ store'.runtime = c.runtime /\ store'.transaction = NoVersion /\ store'.active
        /\ store'.incarnation = (IF c.reset THEN FreshIncarnation ELSE store.incarnation)
        /\ UNCHANGED <<store.open,store.health,store.sent>>]_<<store,work,result,seen>>
RunningDoesNotSave == [][result'.status = "noError" /\ result'.operation \in {"api","set"} =>
    /\ store'.saved = store.saved /\ store'.durable = store.durable /\ store'.published.lab = store.published.lab]_StorageVars
LabDoesNotSave == [][result'.status = "noError" /\ result'.operation = "lab" =>
    /\ store'.saved = store.saved /\ store'.durable.startup = store.durable.startup
    /\ store'.published.lab = ReplacementLab /\ store'.durable.lab = ReplacementLab]_StorageVars
SaveCapturesRunning == [][result'.status = "noError" /\ result'.operation = "save" =>
    /\ store'.saved = store.published.policy /\ store'.durable.startup = store.published.policy
    /\ UNCHANGED <<store.published,store.runtime,store.sent,store.incarnation,work>>]_StorageVars
RebootUsesCurrentLab == [][result'.status = "noError" /\ result'.operation = "reboot" =>
    /\ store'.published = Compose(store.durable.lab,store.saved)
    /\ store'.durable = store.durable /\ store'.saved = store.saved
    /\ store'.incarnation \notin UsedIncarnations /\ ~store'.runtime]_StorageVars
IndependentFactSurvives == [][store.durable.independent => store'.durable.independent]_StorageVars
ReadIsConfirmed == [][result'.status = "read" => /\ seen' = ReadView /\ UNCHANGED store]_StorageVars
InspectionCannotHeal == [][result'.status = "inspected" => /\ seen' = StorageView /\ UNCHANGED store]_StorageVars

\* The original 40 outcome/work/stage cases remain for SET; Save and mixed lab
\* each add the same 40. Unknown actual-old is not conflated with candidate.
RecoveryInitialStore(op) == IF op = "save" THEN [InitialStore EXCEPT
    !.published.policy = Policy(InitialLab,Edit(OldValue,"primary"))] ELSE InitialStore
RecoveryInit == BaseInit /\ scenario \in [operation : {"set","save","lab"}, outcome : Outcomes]
    /\ workKind \in Kinds /\ deliveryStage \in {"faulted","afterRestart"}
    /\ actualOutcome \in (IF scenario.outcome = "commitUnknown" THEN ActualDurability ELSE {"candidate"})
    /\ store = RecoveryInitialStore(scenario.operation)
Wait == UNCHANGED <<store,work,result,seen>>
RecoveryAction == CASE pc = 0 -> Queue(workKind)
    [] pc = 1 -> Attempt(scenario.operation,"primary",scenario.outcome,actualOutcome)
    [] pc = 2 -> ReadConfirmed
    [] pc = 3 -> InspectStorage
    [] pc = 4 -> Attempt("api","secondary","success","candidate")
    [] pc = 5 -> Attempt("save","primary","success","candidate")
    [] pc = 6 -> Attempt("set","secondary","success","candidate")
    [] pc = 7 -> Background
    [] pc = 8 -> Send
    [] pc = 9 -> IF deliveryStage = "faulted" THEN Handle("success","candidate") ELSE Wait
    [] pc = 10 -> IF store.health # "healthy" THEN CloseFailed ELSE Wait
    [] pc = 11 -> Close
    [] pc = 12 -> Open("unavailable")
    [] pc = 13 -> Open("invalid")
    [] pc = 14 -> Open("valid")
    [] pc = 15 -> Close
    [] pc = 16 -> Open("valid")
    [] pc = 17 -> IF work = NoWork THEN Wait ELSE Handle("success","candidate")
    [] pc = 18 -> Queue(workKind)
    [] pc = 19 -> Handle("success","candidate")
    [] pc = 20 -> Attempt("api","secondary","success","candidate")
    [] pc = 21 -> Send
    [] pc = 22 -> ReadConfirmed
RecoveryNext == IF pc = 23 THEN UNCHANGED StorageVars
    ELSE /\ RecoveryAction /\ pc' = pc + 1
         /\ anchor' = IF pc = 1 THEN [before |-> store, state |-> store', outcome |-> result'] ELSE anchor
         /\ UNCHANGED <<scenario,workKind,deliveryStage,actualOutcome>>
RecoverySpec == RecoveryInit /\ [][RecoveryNext]_StorageVars /\ WF_StorageVars(RecoveryNext)
RecoveryCompletes == <> (pc = 23)
RecoveryAssertions ==
    /\ (pc = 2 => result = [OutcomeResult(scenario.outcome) EXCEPT !.operation = scenario.operation]
         /\ (scenario.outcome = "success" => Gate /\ store.saved = store.durable.startup
             /\ (scenario.operation = "set" => store.published.policy = Policy(InitialLab,Edit(OldValue,"primary")) /\ store.durable = InitialImage)
             /\ (scenario.operation = "save" => store.published = anchor.before.published /\ store.saved = anchor.before.published.policy)
             /\ (scenario.operation = "lab" => store.published.lab = ReplacementLab /\ store.durable.lab = ReplacementLab /\ store.saved = InitialPolicy))
         /\ (scenario.outcome = "rolledBack" => store = anchor.before /\ Gate)
         /\ (scenario.outcome \in Faults => ~Gate /\ store.published = anchor.before.published /\ store.saved = anchor.before.saved)
         /\ (scenario.outcome = "commitUnknown" /\ actualOutcome = "old" => store.durable = anchor.before.durable)
         /\ (scenario.outcome = "commitUnknown" /\ actualOutcome = "candidate" =>
             /\ (scenario.operation = "save" => store.durable.startup = anchor.before.published.policy)
             /\ (scenario.operation = "lab" => store.durable.lab = ReplacementLab)))
    /\ (pc = 3 => seen = [value |-> anchor.state.published, confirmed |-> TRUE,
                writable |-> (scenario.outcome \notin Faults), health |-> anchor.state.health])
    /\ (pc = 4 => ~seen.confirmed /\ store = anchor.state
         /\ seen.value = (IF anchor.state.transaction = NoVersion THEN anchor.state.durable ELSE anchor.state.transaction))
    /\ (pc \in 5..11 /\ scenario.outcome \in Faults => Protected(store) = Protected(anchor.state) /\ store.open)
    /\ (pc = 11 /\ scenario.outcome \in Faults => result.status = "closeFailed")
    /\ (pc \in 12..14 => ~store.open /\ store.transaction = NoVersion)
    /\ (pc = 13 => result.status = "loadUnavailable") /\ (pc = 14 => result.status = "loadInvalid")
    /\ (pc \in 12..18 /\ scenario.outcome \in Faults => store.durable = anchor.state.durable)
    /\ (pc \in {15,17,18} => Gate /\ ~Dirty)
    /\ (pc = 17 /\ deliveryStage = "afterRestart" => work.incarnation # store.incarnation)
    /\ (pc = 18 => work = NoWork)
    /\ (pc = 18 /\ deliveryStage = "afterRestart" => result.status = "workDropped")
    /\ (pc = 20 => work = NoWork /\ Gate /\ result.status \in {"noError","background","workSent"})
    /\ (pc = 21 => Gate /\ result.status = "noError") /\ (pc = 22 => Gate /\ result.status = "sent")
    /\ (pc = 23 => seen = ReadView /\ seen.writable /\ seen.confirmed /\ work = NoWork)

\* One physical-identity witness, plus five atomic legacy-seeding outcomes.
LegacyStore == [InitialStore EXCEPT !.active = FALSE, !.durable.seeded = FALSE]
StartupInit == BaseInit /\ workKind = "set" /\ deliveryStage = "afterRestart"
    /\ scenario \in [operation : {"lifecycle","seed"}, outcome : Outcomes]
    /\ (scenario.operation = "lifecycle" => scenario.outcome = "success")
    /\ actualOutcome \in (IF scenario.outcome = "commitUnknown" THEN ActualDurability ELSE {"candidate"})
    /\ store = IF scenario.operation = "seed" THEN LegacyStore ELSE InitialStore
StartupAction == CASE pc = 0 -> Attempt("api","primary","success","candidate")
    [] pc = 1 -> Attempt("set","secondary","success","candidate")
    [] pc = 2 -> Attempt("save","primary","success","candidate")
    [] pc = 3 -> RecordIndependentFact
    [] pc = 4 -> Queue("set")
    [] pc = 5 -> Attempt("set","secondary","success","candidate")
    [] pc = 6 -> Attempt("lab","primary","success","candidate")
    [] pc = 7 -> ReadConfirmed
    [] pc \in {8,9} -> Attempt("reboot","primary","success","candidate")
    [] pc = 10 -> Handle("success","candidate")
    [] pc = 11 -> Close
    [] pc = 12 -> Open("valid")
    [] pc = 13 -> Attempt("api","primary","success","candidate")
    [] pc = 14 -> Attempt("save","primary","success","candidate")
    [] pc = 15 -> Attempt("set","secondary","success","candidate")
    [] pc = 16 -> Attempt("reboot","primary","success","candidate")
StartupDone == IF scenario.operation = "seed" THEN pc = 1 ELSE pc = 17
StartupNext == IF StartupDone THEN UNCHANGED StorageVars
    ELSE /\ (IF scenario.operation = "seed" THEN Attempt("seed","primary",scenario.outcome,actualOutcome) ELSE StartupAction)
         /\ pc' = pc + 1 /\ UNCHANGED <<scenario,workKind,deliveryStage,actualOutcome,anchor>>
StartupSpec == StartupInit /\ [][StartupNext]_StorageVars /\ WF_StorageVars(StartupNext)
StartupCompletes == <> StartupDone
StartupAssertions ==
    /\ (scenario.operation = "seed" /\ pc = 1 =>
         /\ (scenario.outcome = "success" => Gate /\ store.durable.seeded /\ store.published = Compose(InitialLab,InitialPolicy) /\ store.saved = InitialPolicy)
         /\ (scenario.outcome # "success" => ~store.active /\ ~Gate /\ store.published = LegacyStore.published
             /\ (scenario.outcome = "rolledBack" => store = LegacyStore)
             /\ (scenario.outcome = "commitUnknown" => store.durable.seeded = (actualOutcome = "candidate"))))
    /\ (scenario.operation = "lifecycle" =>
         /\ (pc = 2 => store.published.policy = Policy(InitialLab,[primary |-> TRUE,secondary |-> TRUE]) /\ store.saved = InitialPolicy /\ Dirty)
         /\ (pc \in 3..7 => store.saved = Policy(InitialLab,[primary |-> TRUE,secondary |-> TRUE]))
         /\ (pc \in 7..17 => store.published.lab = ReplacementLab /\ store.durable.lab = ReplacementLab)
         /\ (pc \in 4..17 => store.durable.independent)
         /\ (pc = 7 => store.published.policy = Policy(ReplacementLab,OldValue) /\ Dirty /\ store.published.lab.sourceTag = 20)
         /\ (pc \in {9,10,11,13} => store.published.policy = Policy(ReplacementLab,[primary |-> TRUE,secondary |-> FALSE]) /\ ~Dirty /\ ~store.runtime)
         /\ (pc = 10 => work.incarnation # store.incarnation)
         /\ (pc = 11 => work = NoWork /\ result.status = "workDropped")
         /\ (pc = 15 => DOMAIN store.saved = {"A","C"} /\ ~Dirty)
         /\ (pc = 16 => Dirty)
         /\ (pc = 17 => store.published.policy = Policy(ReplacementLab,OldValue) /\ ~Dirty))
=============================================================================
