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
Discard(reason, report) ==
    /\ life.phase # "terminal"
    /\ life' = [life EXCEPT !.phase = "terminal", !.ticket = NoTicket,
        !.mp = IF OwnMp(life) THEN NoEntry ELSE @,
        !.security = IF OwnSecurity(life) THEN NoEntry ELSE @,
        !.mpPops = @ + (IF OwnMp(life) THEN 1 ELSE 0),
        !.securityPops = @ + (IF OwnSecurity(life) THEN 1 ELSE 0),
        !.delivery = IF life.phase = "queued" THEN "canceled" ELSE "failed",
        !.disposition = "discard", !.terminalCount = @ + 1,
        !.diagnostic = report, !.lastAction = reason,
        !.current = IF reason = "revoke" THEN FALSE ELSE @,
        !.admission = IF reason = "close" THEN FALSE ELSE @]
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
=============================================================================
