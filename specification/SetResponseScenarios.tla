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
=============================================================================
