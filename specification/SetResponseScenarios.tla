---------------------- MODULE SetResponseScenarios ----------------------
EXTENDS SetTransactions
CONSTANTS NoEntry, NoTicket
VARIABLES life, scenario, pc, frozen
R == INSTANCE SetResponseLifecycle
Combined == <<allvars,life,scenario,pc,frozen>>
KeepTx(action) == action /\ UNCHANGED allvars
KeepResource(action) == action /\ UNCHANGED life
ResponseStep(action) == action /\ pc' = pc + 1 /\ UNCHANGED <<scenario,frozen>>
ReuseCases == {"cancelExpiry", "expiryCancel", "closeLate", "mpReuse", "securityReuse", "mpLiveReuse", "securityLiveReuse", "wrongMpOwner", "wrongSecurityOwner", "wrongEngine", "missingSecurity", "missingCancel", "missingExpiry", "missingRevoke", "missingClose", "foreignCancel", "foreignExpiry", "foreignRevoke", "foreignClose"}
ReuseLength == CASE scenario = "cancelExpiry" -> 6
    [] scenario = "expiryCancel" -> 6
    [] scenario = "closeLate" -> 6
    [] scenario = "mpReuse" -> 4
    [] scenario = "securityReuse" -> 7
    [] scenario = "mpLiveReuse" -> 3
    [] scenario = "securityLiveReuse" -> 3
    [] scenario = "wrongMpOwner" -> 3
    [] scenario = "wrongSecurityOwner" -> 3
    [] scenario = "wrongEngine" -> 3
    [] scenario = "missingSecurity" -> 3
    [] scenario = "missingCancel" -> 3
    [] scenario = "missingExpiry" -> 3
    [] scenario = "missingRevoke" -> 3
    [] scenario = "missingClose" -> 3
    [] scenario = "foreignCancel" -> 3
    [] scenario = "foreignExpiry" -> 3
    [] scenario = "foreignRevoke" -> 3
    [] scenario = "foreignClose" -> 3
ReuseAction == CASE scenario = "cancelExpiry" -> (CASE pc = 0 -> R!Cancel("cancel")
         [] pc = 1 -> R!OriginalExpiryBoundary
         [] pc = 2 -> R!ReplaceMp
         [] pc = 3 -> R!ReplaceSecurity
         [] pc = 4 -> R!LateCall("lateSend")
         [] pc = 5 -> R!LateCall("lateDiscard"))
    [] scenario = "expiryCancel" -> (CASE pc = 0 -> R!OriginalExpiryBoundary
         [] pc = 1 -> R!Cancel("cancel")
         [] pc = 2 -> R!ReplaceMp
         [] pc = 3 -> R!ReplaceSecurity
         [] pc = 4 -> R!LateCall("lateDiscard")
         [] pc = 5 -> R!LateCall("lateSend"))
    [] scenario = "closeLate" -> (CASE pc = 0 -> R!Close
         [] pc = 1 -> R!Close
         [] pc = 2 -> R!ReplaceMp
         [] pc = 3 -> R!ReplaceSecurity
         [] pc = 4 -> R!LateCall("lateSend")
         [] pc = 5 -> R!LateCall("lateDiscard"))
    [] scenario = "mpReuse" -> (CASE pc = 0 -> R!Cancel("cancel")
         [] pc = 1 -> R!ReplaceMp
         [] pc = 2 -> R!LateCall("lateSend")
         [] pc = 3 -> R!LateCall("lateDiscard"))
    [] scenario = "securityReuse" -> (CASE pc = 0 -> R!Claim
         [] pc = 1 -> R!TakeMp
         [] pc = 2 -> R!ConsumeSecurity
         [] pc = 3 -> R!Send
         [] pc = 4 -> R!ReplaceSecurity
         [] pc = 5 -> R!LateCall("lateDiscard")
         [] pc = 6 -> R!LateCall("lateSend"))
    [] scenario = "mpLiveReuse" -> (CASE pc = 0 -> R!ReplaceMp
         [] pc = 1 -> R!RejectNotReady
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "securityLiveReuse" -> (CASE pc = 0 -> R!ReplaceSecurity
         [] pc = 1 -> R!RejectNotReady
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "wrongMpOwner" -> (CASE pc = 0 -> R!WrongMpOwner
         [] pc = 1 -> R!RejectNotReady
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "wrongSecurityOwner" -> (CASE pc = 0 -> R!WrongSecurityOwner
         [] pc = 1 -> R!RejectNotReady
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "wrongEngine" -> (CASE pc = 0 -> R!WrongEngine
         [] pc = 1 -> R!RejectNotReady
         [] pc = 2 -> R!LateCall("lateSend"))
    [] scenario = "missingSecurity" -> (CASE pc = 0 -> R!MissingSecurity
         [] pc = 1 -> R!RejectNotReady
         [] pc = 2 -> R!LateCall("lateSend"))
    [] scenario = "missingCancel" -> (CASE pc = 0 -> R!MissingSecurity
         [] pc = 1 -> R!Cancel("cancel")
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "missingExpiry" -> (CASE pc = 0 -> R!MissingSecurity
         [] pc = 1 -> R!OriginalExpiryBoundary
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "missingRevoke" -> (CASE pc = 0 -> R!MissingSecurity
         [] pc = 1 -> R!Revoke
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "missingClose" -> (CASE pc = 0 -> R!MissingSecurity
         [] pc = 1 -> R!Close
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "foreignCancel" -> (CASE pc = 0 -> R!ReplaceSecurity
         [] pc = 1 -> R!Cancel("cancel")
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "foreignExpiry" -> (CASE pc = 0 -> R!ReplaceSecurity
         [] pc = 1 -> R!OriginalExpiryBoundary
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "foreignRevoke" -> (CASE pc = 0 -> R!ReplaceSecurity
         [] pc = 1 -> R!Revoke
         [] pc = 2 -> R!LateCall("lateDiscard"))
    [] scenario = "foreignClose" -> (CASE pc = 0 -> R!ReplaceSecurity
         [] pc = 1 -> R!Close
         [] pc = 2 -> R!LateCall("lateDiscard"))
LossCases == {"missingCancel", "missingExpiry", "missingRevoke", "missingClose", "foreignCancel", "foreignExpiry", "foreignRevoke", "foreignClose"}
ForeignLossCases == {"foreignCancel", "foreignExpiry", "foreignRevoke", "foreignClose"}

ReuseInit == /\ TransactionInit /\ secret = [c \in Credentials |-> K1]
             /\ life = R!LifeInitial("noop") /\ scenario \in ReuseCases
             /\ pc = 0 /\ frozen = s
ReuseNext == IF pc < ReuseLength THEN ResponseStep(KeepTx(ReuseAction)) ELSE UNCHANGED Combined
ReuseSpec == ReuseInit /\ [][ReuseNext]_Combined /\ WF_Combined(ReuseNext)
ReuseCompletes == <> (pc = ReuseLength)
ReuseAssertions == pc = ReuseLength =>
    /\ life.phase = "terminal" /\ life.terminalCount = 1 /\ ~life.didCommit
    /\ s = frozen
    /\ (scenario \in LossCases => life.diagnostic /\ life.mpPops = 1 /\ life.securityPops = 0 /\ life.sendAttempts = 0)
    /\ (scenario \in ForeignLossCases => life.security = R!SecB)
    /\ (scenario \in {"cancelExpiry","expiryCancel","closeLate"} =>
           life.mp = R!MPB /\ life.security = R!SecB /\ life.sendAttempts = 0)
    /\ (scenario = "closeLate" => ~life.admission)
    /\ (scenario \in {"mpReuse","mpLiveReuse"} => life.mp = R!MPB)
    /\ (scenario \in {"securityReuse","securityLiveReuse"} => life.security = R!SecB)
    /\ (scenario = "securityReuse" => life.mpPops = 1 /\ life.securityPops = 1 /\ life.sendAttempts = 1)
    /\ (scenario = "wrongMpOwner" => life.mp = R!MPForeign /\ life.mpPops = 0)
    /\ (scenario = "wrongSecurityOwner" => life.security = R!SecForeign /\ life.securityPops = 0)
    /\ (scenario = "missingSecurity" => life.mpPops = 1 /\ life.securityPops = 0)
    /\ (scenario \in {"mpLiveReuse","securityLiveReuse","wrongMpOwner",
            "wrongSecurityOwner","wrongEngine","missingSecurity"} =>
            life.diagnostic /\ life.sendAttempts = 0)
IntegrationCases == {"normal", "noop", "error", "authorizationError", "tooBig", "commitFailed", "beforeMpFailure", "afterMpFailure", "encodeFailure", "transportFailure", "cancel", "expiry", "revoke", "close"}

CanceledCases == {"cancel","expiry","revoke","close"}
ChangedCases == {"normal","beforeMpFailure","afterMpFailure","encodeFailure","transportFailure"}
KindOf(c) == IF c \in ChangedCases THEN "change"
            ELSE IF c \in {"error","authorizationError"} THEN "error"
            ELSE IF c = "tooBig" THEN "tooBig"
            ELSE IF c = "commitFailed" THEN "commitFailed" ELSE "noop"
RequestOps == IF scenario = "noop" THEN <<>>
              ELSE IF scenario = "error" THEN <<Op("readonly",P0,0)>>
              ELSE <<Op("admin",P0,2)>>
IntegrationInit == /\ TransactionInit /\ secret = [c \in Credentials |-> K1]
    /\ scenario \in IntegrationCases /\ life = R!LifeInitial(KindOf(scenario))
    /\ pc = 0 /\ frozen = s
Cancellation == CASE scenario = "cancel" -> KeepTx(R!Cancel("cancel"))
    [] scenario = "expiry" -> KeepTx(R!OriginalExpiryBoundary)
    [] scenario = "close" -> KeepTx(R!Close)
    [] scenario = "revoke" -> R!Revoke /\ SetWriting(C1,FALSE)
ClaimTransaction == /\ R!Claim /\ HandleSet /\ pc' = pc + 1
    /\ life'.didCommit = (Configuration(s') # Configuration(s))
    /\ frozen' = s' /\ UNCHANGED scenario
IntegrationLength == IF scenario \in CanceledCases THEN 5
    ELSE IF scenario = "beforeMpFailure" THEN 5
    ELSE IF scenario = "afterMpFailure" THEN 6 ELSE 7
IntegrationNext ==
    IF pc = IntegrationLength THEN UNCHANGED Combined
    ELSE CASE pc = 0 -> ResponseStep(KeepResource(SetWriting(C1,scenario # "authorizationError")))
      [] pc = 1 -> ResponseStep(KeepResource(SubmitSet(C1,K1,RequestOps,scenario # "tooBig",scenario # "commitFailed")))
      [] pc = 2 -> IF scenario \in CanceledCases THEN ResponseStep(Cancellation) ELSE ClaimTransaction
      [] pc = 3 -> IF scenario \in CanceledCases THEN ResponseStep(KeepResource(Reject("dropped",0)))
                   ELSE IF scenario = "beforeMpFailure" THEN ResponseStep(KeepTx(R!BeforeMpFailure))
                   ELSE ResponseStep(KeepTx(R!TakeMp))
      [] pc = 4 -> IF scenario \in CanceledCases \cup {"beforeMpFailure"}
                   THEN ResponseStep(KeepTx(R!LateCall("lateSend")))
                   ELSE IF scenario = "afterMpFailure" THEN ResponseStep(KeepTx(R!AfterMpFailure))
                   ELSE ResponseStep(KeepTx(R!ConsumeSecurity))
      [] pc = 5 -> IF scenario = "afterMpFailure" THEN ResponseStep(KeepTx(R!LateCall("lateDiscard")))
                   ELSE IF scenario = "encodeFailure" THEN ResponseStep(KeepTx(R!EncodeFailure))
                   ELSE IF scenario = "transportFailure" THEN ResponseStep(KeepTx(R!TransportFailure))
                   ELSE ResponseStep(KeepTx(R!Send))
      [] pc = 6 -> ResponseStep(KeepTx(R!LateCall("lateDiscard")))
IntegrationSpec == IntegrationInit /\ [][IntegrationNext]_Combined /\ WF_Combined(IntegrationNext)
IntegrationCompletes == <> (pc = IntegrationLength)
MaterializationPreservesState == [][pc >= 3 => UNCHANGED s]_Combined
IntegrationAssertions ==
    /\ (pc >= 3 => s = frozen)
    /\ (pc >= 3 /\ scenario \notin CanceledCases => life.didCommit = (scenario \in ChangedCases))
    /\ (pc = IntegrationLength =>
         /\ life.phase = "terminal" /\ life.terminalCount = 1 /\ pending = NoPdu
         /\ (scenario \in ChangedCases => ~s.admin[P0] /\ result.status = "noError")
         /\ (scenario = "noop" => s.admin[P0] /\ result.status = "noError")
         /\ (scenario = "error" => s.admin[P0] /\ result.status = "notWritable" /\ result.index = 1)
         /\ (scenario = "authorizationError" => s.admin[P0] /\ result.status = "authorizationError")
         /\ (scenario = "tooBig" => s.admin[P0] /\ result.status = "tooBig" /\ result.index = 0)
         /\ (scenario = "commitFailed" => s.admin[P0] /\ result.status = "commitFailed" /\ result.index = 1)
         /\ (scenario \in CanceledCases => s.admin[P0] /\ result.status = "dropped" /\ life.sendAttempts = 0)
         /\ (scenario = "transportFailure" => life.delivery = "unknown" /\ life.sendAttempts = 1)
         /\ (scenario \in {"beforeMpFailure","afterMpFailure","encodeFailure"} => life.delivery = "failed")
         /\ (scenario = "beforeMpFailure" => life.mpPops = 1 /\ life.securityPops = 1)
         /\ (scenario = "afterMpFailure" => life.mpPops = 1 /\ life.securityPops = 1)
         /\ (scenario = "encodeFailure" => life.mpPops = 1 /\ life.securityPops = 1 /\ life.sendAttempts = 0))
LifeType == R!LifeTypeOK
LifeOwnership == R!TerminalOwnership
LifeProgressAvailable == R!ProgressAvailable
LifeNoCanceledEffects == R!CanceledBeforeEffects
LifeReady == R!ClaimRequiresReady /\ R!PrecommitReady
LifeNoRollback == R!CommitSurvivesDelivery
LifeNoAwait == R!NoAwaitInterval
LifeForeignSafe == R!CleanupPreservesForeign
LifeLossReported == R!QueuedOwnershipLossReported
LifeComplete == R!TicketCompletes

\* Event observation extends the existing finite transaction fixture, not its
\* SET or response actions. The storage instance uses the original pure commit
\* relation on an image augmented with history; forgetting history gives the
\* checked running/startup projection. Wire status remains owned by the adapter:
\* persist=FALSE supplies HandleSet's unchanged-state branch for all store faults.
\* Action-only is an opaque accepted runtime effect, not a PAE implementation.
EventP1 == CHOOSE p \in Ports \ {P0} : TRUE
EventCases == {"link", "trapOff", "noLink", "noop", "replay", "error", "stale",
    "notReady", "rolledBack", "rollbackFailed", "unknownOld", "unknownCandidate",
    "deliveryFailure", "actionOnly", "attachment"}
EventFaults == {"rolledBack", "rollbackFailed", "unknownOld", "unknownCandidate"}
EventChanges == {"link", "trapOff", "noLink", "replay", "deliveryFailure", "actionOnly"}
EventOutcome == IF scenario \in {"unknownOld","unknownCandidate"} THEN "commitUnknown"
    ELSE IF scenario \in {"rolledBack","rollbackFailed"} THEN scenario ELSE "success"
EventActual == IF scenario = "unknownOld" THEN "old" ELSE "candidate"
ES == INSTANCE StorageOutcomes WITH NoVersion <- NoEntry, NoWork <- NoTicket,
    NoRead <- NoEntry, Tokens <- Tokens, FirstEffectiveIndex <- 1,
    store <- frozen.storage, work <- NoTicket,
    result <- [status |-> "none", index |-> 0, operation |-> "none"], seen <- NoEntry,
    scenario <- scenario, workKind <- "set", deliveryStage <- "afterRestart",
    actualOutcome <- EventActual, pc <- pc, anchor <- NoEntry
EventWithHistory(value, history) == [k \in DOMAIN value \cup {"history"} |->
    IF k = "history" THEN history ELSE value[k]]
EventHistory == frozen.storage.published.history
EventInitialStore ==
    LET policy == [p \in ES!InitialLab.ports |-> TRUE]
        lab == [ES!InitialLab EXCEPT !.attached = {"A"}]
        image == [ES!InitialImage EXCEPT !.lab = lab, !.startup = policy]
    IN [ES!InitialStore EXCEPT !.published = EventWithHistory(ES!Compose(lab,policy),<<>>),
         !.saved = policy, !.durable = EventWithHistory(image,<<>>)]
EventRecord(kind, resource, before, after, admin, ordinal) ==
    [id |-> Len(EventHistory) + ordinal, revision |-> frozen.revision + 1,
     kind |-> kind, resource |-> resource, before |-> before, after |-> after,
     admin |-> admin, ifIndex |-> IF resource \in Ports THEN IfIndex[resource] ELSE 0,
     beforePort |-> NoPort, afterPort |-> NoPort]
EventSetBatch(x) ==
    LET changed == SelectSeq(PortOrder,LAMBDA p : s.admin[p] # x.admin[p])
        config == [i \in DOMAIN changed |-> LET p == changed[i] IN
            EventRecord("configuration",p,s.admin[p],x.admin[p],x.admin[p],i+1)]
        action == IF scenario = "actionOnly"
            THEN <<EventRecord("access",P0,FALSE,FALSE,x.admin[P0],2)>> ELSE <<>>
        links == LinkEvents(x)
    IN <<EventRecord("operation",NoPort,FALSE,FALSE,FALSE,1)>> \o config \o action \o
        [i \in DOMAIN links |-> LET e == links[i] IN
            EventRecord("link",e.port,e.before,e.after,e.admin,1+Len(config)+Len(action)+i)]
EventStoreCandidate(x, history) ==
    LET c == ES!Candidate("set","primary")
        publication == IF Configuration(x) = Configuration(s)
                       THEN frozen.storage.published ELSE c.published
    IN [c EXCEPT !.published = EventWithHistory(publication,history),
                  !.image = EventWithHistory(c.image,history)]
EventPublishedStore(committed,candidate) == committed
EventInit == /\ TransactionInit /\ secret = [c \in Credentials |-> K1]
    /\ scenario \in EventCases /\ pc = 0
    /\ life = (IF scenario = "attachment"
         THEN R!DiscardState(R!LifeInitial("noop"),"cancel",FALSE)
         ELSE R!LifeInitial(IF scenario \in EventChanges THEN "change"
                           ELSE IF scenario \in EventFaults THEN "commitFailed" ELSE "noop"))
    /\ frozen = [storage |-> EventInitialStore, revision |-> 0,
                  trapEnabled |-> scenario # "trapOff"]
EventStep(action) == action /\ pc' = pc + 1 /\ UNCHANGED scenario
EventKeep(action) == EventStep(action) /\ UNCHANGED frozen
EventOps == IF scenario = "actionOnly" THEN <<>>
    ELSE IF scenario = "error" THEN <<Op("readonly",P0,0)>>
    ELSE <<Op("admin",P0,IF scenario = "noop" THEN 1 ELSE 2)>>
EventClaim == /\ R!Claim /\ HandleSet /\ pc' = pc + 1 /\ UNCHANGED scenario
    /\ LET x == Candidate(pending.ops)
           attempted == result'.status \in {"noError","commitFailed"}
               /\ (Configuration(x) # Configuration(s) \/ scenario = "actionOnly")
           c == EventStoreCandidate(x,EventHistory \o EventSetBatch(x))
           committed == IF attempted THEN ES!CommitState(c,EventOutcome,EventActual)
                        ELSE frozen.storage
       IN frozen' = [frozen EXCEPT
            !.storage = EventPublishedStore(committed,c),
            !.revision = @ + (IF attempted /\ EventOutcome = "success" THEN 1 ELSE 0)]
EventMove(p) == /\ CoreAction(Move(E0,p)) /\ UNCHANGED life
    /\ LET history == Append(EventHistory,
               [EventRecord("attachment",E0,FALSE,FALSE,FALSE,1) EXCEPT
                   !.beforePort = s.attached[E0], !.afterPort = p])
           lab == [frozen.storage.published.lab EXCEPT
                    !.attached = {IF p = P0 THEN "A" ELSE "B"}]
           c == [ES!Candidate("set","primary") EXCEPT
                !.published = EventWithHistory([frozen.storage.published EXCEPT !.lab = lab],history),
                !.image = EventWithHistory([frozen.storage.durable EXCEPT !.lab = lab],history)]
       IN frozen' = [frozen EXCEPT !.storage = ES!CommitState(c,"success","candidate"),
                                    !.revision = @ + 1]
EventLength == IF scenario = "attachment" THEN 3 ELSE 9
EventNext ==
    IF pc = EventLength THEN UNCHANGED Combined
    ELSE IF scenario = "attachment" THEN
        IF pc < 2 THEN EventStep(EventMove(IF pc = 0 THEN EventP1 ELSE P0))
        ELSE EventKeep(UNCHANGED <<allvars,life>>)
    ELSE CASE pc = 0 -> EventKeep(KeepResource(IF scenario = "noLink"
                              THEN CoreAction(SetFault(P0,TRUE)) ELSE UNCHANGED allvars))
      [] pc = 1 -> EventKeep(KeepResource(SetWriting(C1,TRUE)))
      [] pc = 2 -> EventKeep(KeepResource(SubmitSet(C1,K1,EventOps,TRUE,scenario \notin EventFaults)))
      [] pc = 3 -> EventKeep(IF scenario = "stale" THEN KeepResource(SetWriting(C1,FALSE))
                     ELSE IF scenario = "notReady" THEN KeepTx(R!ReplaceSecurity)
                     ELSE UNCHANGED <<allvars,life>>)
      [] pc = 4 -> IF scenario = "notReady"
                   THEN EventKeep(R!RejectNotReady /\ Reject("dropped",0)) ELSE EventClaim
      [] pc = 5 -> EventKeep(KeepTx(IF life.phase = "terminal" THEN R!LateCall("lateSend")
                     ELSE IF scenario \in {"rollbackFailed","unknownOld","unknownCandidate"}
                     THEN R!BeforeMpFailure ELSE R!TakeMp))
      [] pc = 6 -> EventKeep(KeepTx(IF life.phase = "terminal" THEN R!LateCall("lateDiscard")
                                   ELSE R!ConsumeSecurity))
      [] pc = 7 -> EventKeep(KeepTx(IF life.phase = "terminal" THEN R!LateCall("lateSend")
                     ELSE IF scenario = "deliveryFailure" THEN R!TransportFailure ELSE R!Send))
      [] pc = 8 -> EventKeep(KeepTx(R!LateCall("lateSend")))
EventSpec == EventInit /\ [][EventNext]_Combined /\ WF_Combined(EventNext)
EventCompletes == <> (pc = EventLength)
EventType == /\ scenario \in EventCases /\ pc \in 0..EventLength
    /\ frozen.revision \in 0..3 /\ frozen.trapEnabled \in BOOLEAN
    /\ Len(EventHistory) <= 9 /\ Len(frozen.storage.durable.history) <= 9
    /\ \A i \in DOMAIN EventHistory : LET e == EventHistory[i] IN
         /\ e.id = i /\ e.revision \in 1..3
         /\ e.kind \in {"operation","configuration","link","access","attachment"}
         /\ e.resource \in Ports \cup Endpoints \cup {NoPort}
         /\ e.before \in BOOLEAN /\ e.after \in BOOLEAN
         /\ e.beforePort \in Ports \cup {NoPort} /\ e.afterPort \in Ports \cup {NoPort}
         /\ e.admin \in BOOLEAN /\ e.ifIndex \in {0} \cup {IfIndex[p] : p \in Ports}
EventStartup == /\ frozen.storage.saved = EventInitialStore.saved
                /\ frozen.storage.durable.startup = EventInitialStore.durable.startup
EventStoreConsistent == /\ ES!HealthyConsistency /\ ES!OpenRollbackState
    /\ ES!CommittedUnknownState /\ ES!ActivationNeedsSplit
    /\ frozen.storage.published.policy["A"] = s.admin[P0]
    /\ frozen.storage.published.policy["B"] = s.admin[EventP1]
    /\ frozen.storage.published.lab.attached = {IF s.attached[E0] = P0 THEN "A" ELSE "B"}
EventFailedPublication == [][pc = 4 /\ result'.status # "noError" =>
    /\ EventHistory' = EventHistory /\ frozen'.revision = frozen.revision /\ UNCHANGED s]_Combined
EventBatchAtomic == [][pc = 4 =>
    LET delta == SubSeq(EventHistory',Len(EventHistory)+1,Len(EventHistory'))
        changed == Configuration(s') # Configuration(s)
        links == {p \in Ports : Oper(s,p) # Oper(s',p)}
    IN /\ Len(delta) = (IF changed THEN 2 + Cardinality(links)
                        ELSE IF scenario = "actionOnly" THEN 2 ELSE 0)
       /\ (Len(delta) > 0 => /\ delta[1].kind = "operation"
              /\ \A i \in DOMAIN delta : delta[i].revision = frozen'.revision
              /\ frozen'.revision = frozen.revision + 1)
       /\ (changed => /\ delta[2].kind = "configuration" /\ delta[2].resource = P0
              /\ delta[2].before = s.admin[P0] /\ delta[2].after = s'.admin[P0])
       /\ (scenario = "actionOnly" => delta[2].kind = "access" /\ UNCHANGED s)
       /\ \A p \in Ports : (p \in links) <=>
            (\E i \in DOMAIN delta : delta[i].kind = "link" /\ delta[i].resource = p)
       /\ \A i \in DOMAIN delta : delta[i].kind = "link" =>
            /\ delta[i].before = Oper(s,delta[i].resource)
            /\ delta[i].after = Oper(s',delta[i].resource)
            /\ delta[i].admin = s'.admin[delta[i].resource]
            /\ delta[i].ifIndex = IfIndex[delta[i].resource]]_Combined
EventAppendOnly == [][ /\ Len(EventHistory') >= Len(EventHistory)
    /\ SubSeq(EventHistory',1,Len(EventHistory)) = EventHistory]_Combined
EventDeliveryPreserves == [][scenario # "attachment" /\ pc >= 5 =>
    UNCHANGED <<s,frozen>>]_Combined
EventAssertions == pc = EventLength =>
    /\ (scenario \in {"link","trapOff","replay","deliveryFailure"} =>
          /\ ~s.admin[P0] /\ Len(EventHistory) = 3 /\ frozen.revision = 1
          /\ EventHistory[3].kind = "link" /\ EventHistory[3].before /\ ~EventHistory[3].after)
    /\ (scenario = "trapOff" => ~frozen.trapEnabled /\ Len(EventHistory) = 3)
    /\ (scenario = "noLink" => ~s.admin[P0] /\ ~Oper(s,P0) /\ Len(EventHistory) = 2)
    /\ (scenario = "actionOnly" => s.admin[P0] /\ Len(EventHistory) = 2)
    /\ (scenario \in {"noop","error","stale","notReady"} \cup EventFaults =>
          EventHistory = <<>> /\ frozen.revision = 0 /\ s.admin[P0])
    /\ (scenario = "rolledBack" => frozen.storage = EventInitialStore)
    /\ (scenario = "rollbackFailed" => Len(frozen.storage.transaction.history) = 3
                                        /\ frozen.storage.durable.history = <<>>)
    /\ (scenario = "unknownOld" => frozen.storage.durable.history = <<>>)
    /\ (scenario = "unknownCandidate" => Len(frozen.storage.durable.history) = 3)
    /\ (scenario = "deliveryFailure" => life.delivery = "unknown" /\ life.didCommit)
    /\ (scenario = "attachment" =>
          /\ s.attached[E0] = P0 /\ frozen.revision = 2 /\ Len(EventHistory) = 2
          /\ EventHistory[1].resource = E0 /\ EventHistory[1].beforePort = P0
          /\ EventHistory[1].afterPort = EventP1 /\ EventHistory[2].beforePort = EventP1
          /\ EventHistory[2].afterPort = P0)
=============================================================================
