---------------------- MODULE StorageOutcomes ----------------------
EXTENDS Naturals, FiniteSets
CONSTANTS NoVersion, NoWork, NoRead, Tokens, FirstEffectiveIndex
VARIABLES store, work, result, seen, scenario, workKind, deliveryStage, actualOutcome, pc, anchor
StorageVars == <<store,work,result,seen,scenario,workKind,deliveryStage,actualOutcome,pc,anchor>>
Values == [primary : BOOLEAN, secondary : BOOLEAN]
OldValue == [primary |-> FALSE, secondary |-> FALSE]
Fields == {"primary","secondary"}
Kinds == {"api","set","background","notify"}
Outcomes == {"success","rolledBack","rollbackFailed","commitUnknown"}
ActualDurability == {"old","candidate"}
Faults == {"rollbackFailed","commitUnknown"}
Edit(v, field) == [v EXCEPT ![field] = ~@]
Result(status, index) == [status |-> status, index |-> index]
Gate == store.open /\ store.health = "healthy"
CommitAllowed == store.open /\ store.health # "rollbackFailed"
CurrentWork == IF work = NoWork THEN FALSE
               ELSE Gate /\ work.incarnation = store.incarnation
UsedIncarnations == {store.incarnation} \cup
    (IF work = NoWork THEN {} ELSE {work.incarnation})
FreshIncarnation == CHOOSE t \in Tokens \ UsedIncarnations : TRUE
Protected(x) == <<x.published,x.durable,x.transaction,x.runtime,x.sent>>
ReadView == [value |-> store.published, confirmed |-> TRUE,
             writable |-> Gate, health |-> store.health]
StorageView == [value |-> IF store.transaction = NoVersion THEN store.durable ELSE store.transaction,
                confirmed |-> FALSE, writable |-> FALSE, health |-> store.health]
InitialStore == [open |-> TRUE, health |-> "healthy", published |-> OldValue,
    durable |-> OldValue, transaction |-> NoVersion, incarnation |-> CHOOSE t \in Tokens : TRUE,
    runtime |-> FALSE, sent |-> FALSE]
BaseInit == /\ store = InitialStore /\ work = NoWork /\ result = Result("none",0)
    /\ seen = NoRead /\ anchor = NoRead /\ pc = 0
StorageInit == BaseInit /\ scenario = "graph" /\ workKind = "set" /\ deliveryStage = "afterRestart" /\ actualOutcome = "candidate"
OutcomeResult(outcome) == CASE outcome = "success" -> Result("noError",0)
    [] outcome = "rolledBack" -> Result("commitFailed",FirstEffectiveIndex)
    [] outcome = "rollbackFailed" -> Result("undoFailed",0)
    [] outcome = "commitUnknown" -> Result("dropped",0)
CommitState(value, outcome, actual) ==
    CASE outcome = "success" -> [store EXCEPT !.published = value, !.durable = value,
          !.transaction = NoVersion, !.runtime = ~@]
      [] outcome = "rolledBack" -> store
      [] outcome = "rollbackFailed" -> [store EXCEPT !.transaction = value, !.health = "rollbackFailed"]
      [] outcome = "commitUnknown" -> [store EXCEPT !.durable = IF actual = "old" THEN @ ELSE value, !.health = "commitUnknown",
                                      !.transaction = NoVersion]
\* Every persistent API/SET transaction uses the same Store/Engine health gate.
Attempt(kind, field, outcome, actual) ==
    /\ kind \in {"api","set"} /\ field \in Fields /\ outcome \in Outcomes /\ actual \in ActualDurability
    /\ (IF CommitAllowed
       THEN /\ store' = CommitState(Edit(store.published,field),outcome,actual)
            /\ result' = OutcomeResult(outcome)
       ELSE /\ UNCHANGED store /\ result' = Result("blocked",0))
    /\ UNCHANGED <<work,seen>>
Background ==
    /\ (IF Gate THEN /\ store' = [store EXCEPT !.runtime = ~@]
                    /\ result' = Result("background",0)
       ELSE /\ UNCHANGED store /\ result' = Result("blocked",0))
    /\ UNCHANGED <<work,seen>>
Send ==
    /\ (IF Gate THEN /\ store' = [store EXCEPT !.sent = ~@]
                    /\ result' = Result("sent",0)
       ELSE /\ UNCHANGED store /\ result' = Result("blocked",0))
    /\ UNCHANGED <<work,seen>>
Queue(kind) == /\ Gate /\ work = NoWork /\ kind \in Kinds
    /\ work' = [kind |-> kind, incarnation |-> store.incarnation]
    /\ result' = Result("queued",0) /\ UNCHANGED <<store,seen>>
Handle(outcome, actual) == /\ work # NoWork /\ outcome \in Outcomes /\ actual \in ActualDurability
    /\ (IF CurrentWork
       THEN IF work.kind = "notify"
            THEN /\ store' = [store EXCEPT !.sent = ~@] /\ result' = Result("workSent",0)
            ELSE IF work.kind = "background"
                 THEN /\ store' = [store EXCEPT !.runtime = ~@] /\ result' = Result("background",0)
                 ELSE /\ store' = CommitState(Edit(store.published,"secondary"),outcome,actual)
                      /\ result' = OutcomeResult(outcome)
       ELSE /\ UNCHANGED store /\ result' = Result("workDropped",0))
    /\ work' = NoWork /\ UNCHANGED seen
HandleWork == \E outcome \in Outcomes, actual \in ActualDurability : Handle(outcome,actual)
ReadConfirmed == /\ store.open /\ seen' = ReadView
                 /\ result' = Result("read",0) /\ UNCHANGED <<store,work>>
\* A diagnostic observation of the connection cannot establish commit health.
InspectStorage == /\ store.open /\ seen' = StorageView
                  /\ result' = Result("inspected",0) /\ UNCHANGED <<store,work>>
Close == /\ store.open
    /\ store' = [store EXCEPT !.open = FALSE, !.transaction = NoVersion]
    /\ result' = Result("closed",0) /\ UNCHANGED <<work,seen>>
CloseFailed == /\ store.open /\ store.health # "healthy"
    /\ result' = Result("closeFailed",0) /\ UNCHANGED <<store,work,seen>>
Open(load) == /\ ~store.open /\ load \in {"valid","unavailable","invalid"}
    /\ (IF load = "valid"
       THEN /\ store' = [store EXCEPT !.open = TRUE, !.health = "healthy",
                   !.published = store.durable, !.transaction = NoVersion,
                   !.incarnation = FreshIncarnation, !.runtime = FALSE]
            /\ result' = Result("reopened",0)
       ELSE /\ UNCHANGED store
            /\ result' = Result(IF load = "invalid" THEN "loadInvalid" ELSE "loadUnavailable",0))
    /\ UNCHANGED <<work,seen>>
KeepFixture == UNCHANGED <<scenario,workKind,deliveryStage,actualOutcome,pc,anchor>>
StorageNext ==
    /\ ((\E k \in {"api","set"}, f \in Fields, o \in Outcomes, a \in ActualDurability : Attempt(k,f,o,a))
        \/ Background \/ Send \/ (\E k \in Kinds : Queue(k)) \/ HandleWork
        \/ Close \/ CloseFailed \/ (\E load \in {"valid","unavailable","invalid"} : Open(load)))
    /\ KeepFixture
\* This is an external successful restart/storage-availability assumption,
\* not an automatic restart action in the application.
RecoveryProgress == /\ ((store.health # "healthy" /\ Close) \/ Open("valid"))
                    /\ KeepFixture
GraphHandle == HandleWork /\ KeepFixture
StorageSpec == StorageInit /\ [][StorageNext]_StorageVars
    /\ WF_StorageVars(RecoveryProgress) /\ WF_StorageVars(GraphHandle)
RecoveryEventuallyUsable == (~store.open \/ store.health # "healthy") ~> Gate
QueuedWorkCompletes == (work # NoWork) ~> (work = NoWork)
StorageTypeOK ==
    /\ store.open \in BOOLEAN /\ store.health \in {"healthy","rollbackFailed","commitUnknown"}
    /\ store.published \in Values /\ store.durable \in Values
    /\ store.transaction \in Values \cup {NoVersion} /\ store.incarnation \in Tokens
    /\ store.runtime \in BOOLEAN /\ store.sent \in BOOLEAN
    /\ work \in {NoWork} \cup [kind : Kinds, incarnation : Tokens]
    /\ result.status \in {"none","noError","commitFailed","undoFailed","dropped","blocked",
           "background","sent","queued","workSent","workDropped","read","inspected",
           "closed","closeFailed","reopened","loadInvalid","loadUnavailable"}
    /\ result.index \in {0,FirstEffectiveIndex}
    /\ actualOutcome \in ActualDurability
HealthyConsistency == store.health = "healthy" =>
    store.published = store.durable /\ store.transaction = NoVersion
OpenRollbackState == store.open /\ store.health = "rollbackFailed" =>
    store.transaction # NoVersion /\ store.durable = store.published
ClosedTransactionGone == ~store.open => store.transaction = NoVersion
CommittedUnknownState == store.health = "commitUnknown" => store.transaction = NoVersion
NormalCapabilities == Gate =>
    /\ ENABLED Attempt("api","secondary","success","candidate")
    /\ ENABLED Attempt("set","secondary","success","candidate") /\ ENABLED Background /\ ENABLED Send
FreshAvailable == Tokens \ UsedIncarnations # {}
UncertaintyBlocksEffects == [][store.open /\ store.health # "healthy" /\ store'.open =>
    Protected(store') = Protected(store)]_StorageVars
UnconfirmedDurableSurvives == [][store.health # "healthy" => store'.durable = store.durable]_StorageVars
NoInPlaceHealthReset == [][store.open /\ store.health # "healthy" /\ store'.open =>
    store'.health = store.health]_StorageVars
ClosedCannotMutate == [][~store.open =>
    /\ store'.durable = store.durable /\ store'.sent = store.sent]_StorageVars
ValidRestartOnly == [][~store.open /\ store'.open =>
    /\ result'.status = "reopened" /\ store'.health = "healthy"
    /\ store'.published = store.durable /\ store'.transaction = NoVersion
    /\ store'.incarnation \notin UsedIncarnations /\ ~store'.runtime]_StorageVars
FailedLoadPreserves == [][result'.status \in {"loadInvalid","loadUnavailable"} => UNCHANGED store]_StorageVars
ConfirmedRollbackPreserves == [][result'.status = "commitFailed" =>
    /\ UNCHANGED store /\ result'.index = FirstEffectiveIndex]_StorageVars
FailedRollbackOutcome == [][result'.status = "undoFailed" =>
    /\ store'.open /\ store'.health = "rollbackFailed" /\ store'.transaction # NoVersion
    /\ store'.durable = store.durable /\ store'.published = store.published /\ result'.index = 0
    /\ store'.transaction \in {Edit(store.published,f) : f \in Fields}]_StorageVars
UnknownCommitOutcome == [][result'.status = "dropped" =>
    /\ store'.health = "commitUnknown" /\ store'.transaction = NoVersion
    /\ store'.published = store.published /\ result'.index = 0
    /\ store'.durable \in {store.durable} \cup {Edit(store.published,f) : f \in Fields}]_StorageVars
QueuedEffectsRequireCurrent == [][(work # NoWork /\ work' = NoWork /\ Protected(store') # Protected(store)) => CurrentWork]_StorageVars
StaleWorkDrops == [][(work # NoWork /\ ~CurrentWork /\ work' = NoWork) =>
    /\ UNCHANGED store /\ result'.status = "workDropped"]_StorageVars

\* Focused reads, faults, failed startup, two restarts, and resumed operations.
RecoveryInit == BaseInit /\ scenario \in Outcomes /\ workKind \in Kinds
    /\ deliveryStage \in {"faulted","afterRestart"}
    /\ actualOutcome \in (IF scenario = "commitUnknown" THEN ActualDurability ELSE {"candidate"})
Wait == UNCHANGED <<store,work,result,seen>>
RecoveryAction == CASE pc = 0 -> Queue(workKind)
    [] pc = 1 -> Attempt("set","primary",scenario,actualOutcome)
    [] pc = 2 -> ReadConfirmed
    [] pc = 3 -> InspectStorage
    [] pc = 4 -> Attempt("api","secondary","success","candidate")
    [] pc = 5 -> Attempt("set","secondary","success","candidate")
    [] pc = 6 -> Background
    [] pc = 7 -> Send
    [] pc = 8 -> IF deliveryStage = "faulted" THEN Handle("success","candidate") ELSE Wait
    [] pc = 9 -> IF store.health # "healthy" THEN CloseFailed ELSE Wait
    [] pc = 10 -> Close
    [] pc = 11 -> Open("unavailable")
    [] pc = 12 -> Open("invalid")
    [] pc = 13 -> Open("valid")
    [] pc = 14 -> Close
    [] pc = 15 -> Open("valid")
    [] pc = 16 -> IF work = NoWork THEN Wait ELSE Handle("success","candidate")
    [] pc = 17 -> Queue(workKind)
    [] pc = 18 -> Handle("success","candidate")
    [] pc = 19 -> Attempt("api","secondary","success","candidate")
    [] pc = 20 -> Send
    [] pc = 21 -> ReadConfirmed
RecoveryNext == IF pc = 22 THEN UNCHANGED StorageVars
    ELSE /\ RecoveryAction /\ pc' = pc + 1
         /\ anchor' = IF pc = 1 THEN [state |-> store', outcome |-> result'] ELSE anchor
         /\ UNCHANGED <<scenario,workKind,deliveryStage,actualOutcome>>
RecoverySpec == RecoveryInit /\ [][RecoveryNext]_StorageVars /\ WF_StorageVars(RecoveryNext)
RecoveryCompletes == <> (pc = 22)
ReadIsConfirmed == [][result'.status = "read" =>
    /\ seen' = ReadView /\ UNCHANGED store]_StorageVars
InspectionCannotHeal == [][result'.status = "inspected" =>
    /\ seen' = StorageView /\ UNCHANGED store]_StorageVars
FirstOutcomeState ==
    /\ (scenario = "success" => store.published = Edit(OldValue,"primary")
         /\ store.durable = Edit(OldValue,"primary") /\ Gate)
    /\ (scenario = "rolledBack" => store = InitialStore /\ Gate)
    /\ (scenario = "rollbackFailed" => store.published = OldValue /\ store.durable = OldValue
         /\ store.transaction = Edit(OldValue,"primary") /\ store.health = "rollbackFailed" /\ ~Gate)
    /\ (scenario = "commitUnknown" => store.published = OldValue /\ store.transaction = NoVersion
         /\ store.health = "commitUnknown" /\ ~Gate
         /\ store.durable = (IF actualOutcome = "old" THEN OldValue ELSE Edit(OldValue,"primary")))
RecoveryAssertions ==
    /\ (pc = 2 => result = OutcomeResult(scenario) /\ FirstOutcomeState)
    /\ (pc = 3 => seen = [value |-> anchor.state.published, confirmed |-> TRUE,
                writable |-> (scenario \notin Faults), health |-> anchor.state.health])
    /\ (pc = 4 => ~seen.confirmed /\ store = anchor.state
         /\ seen.value = (IF anchor.state.transaction = NoVersion THEN anchor.state.durable ELSE anchor.state.transaction))
    /\ (pc \in 5..10 /\ scenario \in Faults => Protected(store) = Protected(anchor.state) /\ store.open)
    /\ (pc = 10 /\ scenario \in Faults => result.status = "closeFailed")
    /\ (pc \in 11..13 => ~store.open /\ store.transaction = NoVersion)
    /\ (pc = 12 => result.status = "loadUnavailable")
    /\ (pc = 13 => result.status = "loadInvalid")
    /\ (pc \in 11..17 /\ scenario \in Faults => store.durable = anchor.state.durable)
    /\ (pc \in {14,16,17} => Gate /\ store.published = store.durable)
    /\ (pc = 16 /\ deliveryStage = "afterRestart" => work.incarnation # store.incarnation)
    /\ (pc = 17 => work = NoWork)
    /\ (pc = 17 /\ deliveryStage = "afterRestart" => result.status = "workDropped")
    /\ (pc = 19 => work = NoWork /\ Gate /\ result.status \in {"noError","background","workSent"})
    /\ (pc = 20 => Gate /\ result.status = "noError" /\ store.published = store.durable)
    /\ (pc = 21 => Gate /\ result.status = "sent")
    /\ (pc = 22 => seen = ReadView /\ seen.writable /\ seen.confirmed /\ work = NoWork)
=============================================================================
