---------------------- MODULE SetResponseLifecycle ----------------------
EXTENDS Naturals, FiniteSets
CONSTANTS NoEntry, NoTicket
VARIABLE life
LifeVars == <<life>>
MPA == [engine |-> "e0", owner |-> "mp0", reference |-> 0, record |-> "A"]
MPB == [MPA EXCEPT !.record = "B"]
MPForeign == [MPA EXCEPT !.owner = "mp1"]
SecA == [engine |-> "e0", owner |-> "sec0", reference |-> 0, record |-> "A"]
SecB == [SecA EXCEPT !.record = "B"]
SecForeign == [SecA EXCEPT !.owner = "sec1"]
TicketA == [engine |-> "e0", mp |-> MPA, security |-> SecA]
Kinds == {"change", "noop", "error", "tooBig", "commitFailed"}
Internal == {"claimed", "mpTaken", "securityConsumed"}
OwnMp(x) == IF x.ticket = NoTicket THEN FALSE ELSE x.mp = x.ticket.mp
OwnSecurity(x) == IF x.ticket = NoTicket THEN FALSE ELSE x.security = x.ticket.security
Ready(x) == /\ x.phase = "queued" /\ x.admission /\ x.current
            /\ x.ticket # NoTicket /\ x.engine = x.ticket.engine
            /\ OwnMp(x) /\ OwnSecurity(x)
LifeInitial(k) == [phase |-> "queued", kind |-> k, ticket |-> TicketA,
    engine |-> "e0", mp |-> MPA, security |-> SecA, outgoing |-> FALSE,
    admission |-> TRUE, current |-> TRUE, didCommit |-> FALSE,
    delivery |-> "none", disposition |-> "none", terminalCount |-> 0,
    mpPops |-> 0, securityPops |-> 0, sendAttempts |-> 0,
    diagnostic |-> FALSE, lastAction |-> "init"]
LifeInit == \E k \in Kinds : life = LifeInitial(k)

\* Discard only records still owned by this exact opaque ticket. Terminal
\* publication and both removals are one synchronous finalization transition.
DiscardState(x, reason, report) ==
    [x EXCEPT !.phase = "terminal", !.ticket = NoTicket,
        !.mp = IF OwnMp(x) THEN NoEntry ELSE @,
        !.security = IF OwnSecurity(x) THEN NoEntry ELSE @,
        !.mpPops = @ + (IF OwnMp(x) THEN 1 ELSE 0),
        !.securityPops = @ + (IF OwnSecurity(x) THEN 1 ELSE 0),
        !.delivery = IF x.phase = "queued" THEN "canceled" ELSE "failed",
        !.disposition = "discard", !.terminalCount = @ + 1,
        !.diagnostic = report \/ (x.phase = "queued" /\ OwnMp(x) /\ ~OwnSecurity(x)),
        !.lastAction = reason,
        !.current = IF reason = "revoke" THEN FALSE ELSE @,
        !.admission = IF reason = "close" THEN FALSE ELSE @]
Discard(reason, report) ==
    /\ life.phase # "terminal"
    /\ life' = DiscardState(life,reason,report)
LateCall(reason) ==
    /\ life.phase = "terminal"
    /\ life' = [life EXCEPT !.lastAction = reason]
Cancel(reason) ==
    IF life.phase = "terminal" THEN LateCall(reason)
    ELSE /\ life.phase = "queued" /\ Discard(reason,FALSE)
OriginalExpiryBoundary == Cancel("expiry")
Revoke ==
    IF life.phase = "terminal" THEN life' = [life EXCEPT !.current = FALSE, !.lastAction = "revoke"]
    ELSE /\ life.phase = "queued" /\ Discard("revoke",FALSE)

Close ==
    IF life.phase = "terminal" THEN life' = [life EXCEPT !.admission = FALSE, !.lastAction = "close"]
    ELSE /\ life.phase = "queued" /\ Discard("close",FALSE)


Claim ==
    /\ Ready(life)
    /\ life' = [life EXCEPT !.phase = "claimed",
                 !.didCommit = (life.kind = "change"), !.lastAction = "claim"]
RejectNotReady == /\ life.phase = "queued" /\ ~Ready(life)
                  /\ Discard("ownershipError",TRUE)
TakeMp ==
    /\ life.phase = "claimed" /\ OwnMp(life)
    /\ life' = [life EXCEPT !.phase = "mpTaken", !.mp = NoEntry,
                 !.mpPops = @ + 1, !.lastAction = "takeMp"]
ConsumeSecurity ==
    /\ life.phase = "mpTaken" /\ OwnSecurity(life)
    /\ life' = [life EXCEPT !.phase = "securityConsumed", !.security = NoEntry,
                 !.securityPops = @ + 1, !.lastAction = "consumeSecurity"]
Finish(delivery, attempt, reason) ==
    /\ life.phase = "securityConsumed"
    /\ life' = [life EXCEPT !.phase = "terminal", !.ticket = NoTicket,
        !.delivery = delivery, !.disposition = "consume", !.terminalCount = @ + 1,
        !.sendAttempts = @ + (IF attempt THEN 1 ELSE 0), !.lastAction = reason]
BeforeMpFailure == /\ life.phase = "claimed" /\ Discard("beforeMpFailure",TRUE)
AfterMpFailure == /\ life.phase = "mpTaken" /\ Discard("afterMpFailure",TRUE)
EncodeFailure == Finish("failed",FALSE,"encodeFailure")
TransportFailure == Finish("unknown",TRUE,"transportFailure")
Send == Finish("sent",TRUE,"send")
Progress == Claim \/ RejectNotReady \/ TakeMp \/ ConsumeSecurity \/ Send
            \/ BeforeMpFailure \/ AfterMpFailure \/ EncodeFailure \/ TransportFailure

\* A fixed-slot replacement is a foreign-owner/reuse witness, not another SET.
ReplaceMp == /\ life.phase \in {"queued","terminal"}
             /\ life' = [life EXCEPT !.mp = MPB, !.lastAction = "replaceMp"]
ReplaceSecurity == /\ life.phase \in {"queued","terminal"}
                   /\ life' = [life EXCEPT !.security = SecB, !.lastAction = "replaceSecurity"]
WrongMpOwner == /\ life.phase = "queued"
                /\ life' = [life EXCEPT !.mp = MPForeign, !.lastAction = "wrongMpOwner"]
WrongSecurityOwner == /\ life.phase = "queued"
                      /\ life' = [life EXCEPT !.security = SecForeign, !.lastAction = "wrongSecurityOwner"]
WrongEngine == /\ life.phase = "queued"
               /\ life' = [life EXCEPT !.engine = "e1", !.lastAction = "wrongEngine"]
MissingSecurity == /\ life.phase = "queued"
                   /\ life' = [life EXCEPT !.security = NoEntry, !.lastAction = "missingSecurity"]
OutgoingProgress == /\ life.phase \in {"queued","terminal"}
                    /\ life' = [life EXCEPT !.outgoing = ~@, !.lastAction = "outgoing"]
LifeNext == Progress \/ Cancel("cancel") \/ OriginalExpiryBoundary \/ Revoke \/ Close
    \/ ReplaceMp \/ ReplaceSecurity \/ WrongMpOwner \/ WrongSecurityOwner
    \/ WrongEngine \/ MissingSecurity \/ OutgoingProgress
    \/ LateCall("lateSend") \/ LateCall("lateDiscard")
LifeSpec == LifeInit /\ [][LifeNext]_LifeVars /\ WF_LifeVars(Progress)

LifeTypeOK ==
    /\ life.phase \in {"queued","claimed","mpTaken","securityConsumed","terminal"}
    /\ life.kind \in Kinds /\ life.ticket \in {TicketA,NoTicket}
    /\ life.mp \in {MPA,MPB,MPForeign,NoEntry}
    /\ life.security \in {SecA,SecB,SecForeign,NoEntry}
    /\ life.engine \in {"e0","e1"}
    /\ life.outgoing \in BOOLEAN /\ life.admission \in BOOLEAN /\ life.current \in BOOLEAN
    /\ life.didCommit \in BOOLEAN /\ life.diagnostic \in BOOLEAN
    /\ life.delivery \in {"none","sent","failed","unknown","canceled"}
    /\ life.disposition \in {"none","consume","discard"}
    /\ life.terminalCount \in 0..1 /\ life.mpPops \in 0..1
    /\ life.securityPops \in 0..1 /\ life.sendAttempts \in 0..1
TerminalOwnership ==
    /\ (life.phase = "terminal") = (life.ticket = NoTicket)
    /\ (life.phase = "terminal") = (life.terminalCount = 1)
    /\ (life.phase = "terminal" => life.mp # MPA /\ life.security # SecA)
    /\ (life.phase # "terminal" => life.disposition = "none")
ProgressAvailable == life.phase # "terminal" => ENABLED Progress
ClaimRequiresReady == [][life'.lastAction = "claim" => Ready(life)]_LifeVars
PrecommitReady == [][(~life.didCommit /\ life'.didCommit) => Ready(life)]_LifeVars
CommitSurvivesDelivery == [][life.didCommit => life'.didCommit]_LifeVars
NoAwaitInterval == [][life.phase \in Internal =>
    life'.lastAction \in {"takeMp","consumeSecurity","send","beforeMpFailure",
                          "afterMpFailure","encodeFailure","transportFailure"}]_LifeVars
CleanupPreservesForeign == [][
    life'.lastAction \in {"cancel","expiry","revoke","close","ownershipError",
        "beforeMpFailure","afterMpFailure","encodeFailure","transportFailure","send",
        "lateSend","lateDiscard"} =>
       /\ (life.mp \in {MPB,MPForeign} => life'.mp = life.mp)
       /\ (life.security \in {SecB,SecForeign} => life'.security = life.security)
       /\ life'.outgoing = life.outgoing]_LifeVars
CanceledBeforeEffects == life.delivery = "canceled" =>
    ~life.didCommit /\ life.sendAttempts = 0
QueuedOwnershipLossReported == [][
    life.phase = "queued" /\ OwnMp(life) /\ ~OwnSecurity(life) /\ life'.phase = "terminal"
        => life'.diagnostic]_LifeVars
TicketCompletes == (life.phase # "terminal") ~> (life.phase = "terminal")

\* The MP record owns this opaque insertion-time association. It contains no
\* security data, new index, or timer. No application ticket exists at insertion.
EntryWitness(sec) == [lifetime |-> "e0", securityOwner |-> "sec0", security |-> sec]
EntryInitial(k, sec) == [stage |-> "before", kind |-> k, engine |-> "e0",
    mp |-> NoEntry, security |-> sec, outgoing |-> FALSE, admission |-> TRUE,
    diagnostic |-> FALSE, mpPops |-> 0, securityPops |-> 0, terminalCount |-> 0,
    lastAction |-> "init"]
EntryInserted(x) == [x EXCEPT !.stage = "unadmitted",
    !.mp = [identity |-> MPA, witness |-> EntryWitness(x.security)],
    !.lastAction = "insert"]
EntryOwnMp(x) == IF x.mp = NoEntry THEN FALSE ELSE x.mp.identity = MPA
EntryWitnessValid(x) ==
    IF ~EntryOwnMp(x) THEN FALSE
    ELSE IF x.mp.witness = NoEntry THEN FALSE
    ELSE /\ x.mp.witness.lifetime = x.engine
         /\ x.engine = "e0"
         /\ x.mp.witness.securityOwner = "sec0"
         /\ x.mp.witness.security \in {SecA,NoEntry}
EntryCanCapture(x) == IF ~EntryWitnessValid(x) THEN FALSE
                      ELSE x.mp.witness.security # NoEntry
EntryCaptured(x) == [LifeInitial(x.kind) EXCEPT
    !.ticket = [engine |-> x.engine, mp |-> x.mp.identity,
                security |-> x.mp.witness.security],
    !.engine = x.engine, !.mp = x.mp.identity, !.security = x.security,
    !.outgoing = x.outgoing, !.admission = x.admission]
\* Admission and fallback cleanup use the same stored association. A live
\* numeric lookup is a comparison, never a replacement for the original witness.
EntryCleanupView(x) == IF x.security = NoEntry THEN EntryCaptured(x)
    ELSE [EntryCaptured(x) EXCEPT !.ticket.security = x.security]
EntryDisposed(x, reason) ==
    IF EntryCanCapture(x)
    THEN LET after == DiscardState(EntryCleanupView(x),reason,FALSE)
         IN [x EXCEPT !.stage = "terminal", !.mp = NoEntry,
              !.security = after.security, !.diagnostic = after.diagnostic,
              !.mpPops = after.mpPops, !.securityPops = after.securityPops,
              !.terminalCount = after.terminalCount, !.admission = after.admission,
              !.lastAction = reason]
    ELSE [x EXCEPT !.stage = "terminal",
          !.mp = IF EntryOwnMp(x) THEN NoEntry ELSE @,
          !.mpPops = @ + (IF EntryOwnMp(x) THEN 1 ELSE 0),
          !.diagnostic = TRUE, !.terminalCount = @ + 1,
          !.admission = IF reason = "close" THEN FALSE ELSE @,
          !.lastAction = reason]
\* Transfer changes the abstraction's active owner, not either cache. The
\* lifecycle record receives the exact MP/security entries; no mirror remains.
EntryTransferred(x) == [x EXCEPT !.stage = "handed", !.mp = NoEntry,
                         !.security = NoEntry, !.lastAction = "admit"]
=============================================================================
