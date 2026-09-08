---------------------- MODULE SetResponseEntry ----------------------
EXTENDS SetResponseLifecycle, Sequences
VARIABLES entry, pc, route, fault, kind
EntryVars == <<life,entry,pc,route,fault,kind>>
Routes == {"admit","expiry","close"}
Faults == {"none","lost","reused","missingAtInsert","missingWitness",
           "foreignLifetime","foreignOwner","wrongEngine"}
EntryInit == /\ route \in Routes /\ fault \in Faults /\ kind \in Kinds
    /\ entry \in {[EntryInitial(kind,IF fault = "missingAtInsert" THEN NoEntry ELSE SecA)
                      EXCEPT !.outgoing = b] : b \in BOOLEAN}
    /\ life = NoEntry /\ pc = 0
KeepLife(x) == entry' = x /\ UNCHANGED life
EntryFault == KeepLife(
    CASE fault \in {"lost","reused"} -> [entry EXCEPT !.security = NoEntry, !.lastAction = "loss"]
      [] fault = "missingWitness" -> [entry EXCEPT !.mp.witness = NoEntry, !.lastAction = "missingWitness"]
      [] fault = "foreignLifetime" -> [entry EXCEPT !.mp.witness.lifetime = "e1", !.lastAction = "foreignWitness"]
      [] fault = "foreignOwner" -> [entry EXCEPT !.mp.witness.securityOwner = "sec1", !.lastAction = "foreignWitness"]
      [] fault = "wrongEngine" -> [entry EXCEPT !.engine = "e1", !.lastAction = "wrongEngine"]
      [] OTHER -> [entry EXCEPT !.lastAction = "delay"])
EntryReuse == KeepLife(IF fault \in {"reused","missingAtInsert"}
    THEN [entry EXCEPT !.security = SecB, !.lastAction = "reuse"]
    ELSE [entry EXCEPT !.lastAction = "delay"])
EntryAdmit == IF EntryCanCapture(entry)
    THEN /\ life' = EntryCaptured(entry) /\ entry' = EntryTransferred(entry)
    ELSE KeepLife(EntryDisposed(entry,"admissionError"))
EntryRoute == IF route = "admit" THEN EntryAdmit
              ELSE KeepLife(EntryDisposed(entry,route))
EntryLate == IF entry.stage = "handed"
             THEN LateCall("lateSend") /\ UNCHANGED entry
             ELSE KeepLife([entry EXCEPT !.lastAction = "lateSend"])
Pipeline(action) == action /\ UNCHANGED entry
EntryAction == CASE pc = 0 -> KeepLife(EntryInserted(entry))
    [] pc = 1 -> EntryFault
    [] pc = 2 -> EntryReuse
    [] pc = 3 -> EntryRoute
    [] pc = 4 -> IF entry.stage = "handed"
                 THEN Pipeline(IF Ready(life) THEN Claim ELSE RejectNotReady)
                 ELSE EntryLate
    [] pc = 5 -> IF entry.stage = "handed" /\ life.phase = "claimed"
                 THEN Pipeline(TakeMp) ELSE EntryLate
    [] pc = 6 -> IF entry.stage = "handed" /\ life.phase = "mpTaken"
                 THEN Pipeline(ConsumeSecurity) ELSE EntryLate
    [] pc = 7 -> IF entry.stage = "handed" /\ life.phase = "securityConsumed"
                 THEN Pipeline(Send) ELSE EntryLate
    [] pc = 8 -> EntryLate
EntryNext == IF pc = 9 THEN UNCHANGED EntryVars
             ELSE EntryAction /\ pc' = pc + 1 /\ UNCHANGED <<route,fault,kind>>
EntrySpec == EntryInit /\ [][EntryNext]_EntryVars /\ WF_EntryVars(EntryNext)
EntryCompletes == <> (pc = 9)
ObservedSecurity == IF entry.stage = "handed" THEN life.security ELSE entry.security
ObservedMp == IF entry.stage = "handed" THEN life.mp
              ELSE IF entry.mp = NoEntry THEN NoEntry ELSE entry.mp.identity
ObservedOutgoing == IF entry.stage = "handed" THEN life.outgoing ELSE entry.outgoing
ObservedDiagnostic == IF entry.stage = "handed" THEN life.diagnostic ELSE entry.diagnostic
ObservedSecurityPops == IF entry.stage = "handed" THEN life.securityPops ELSE entry.securityPops
ObservedMpPops == IF entry.stage = "handed" THEN life.mpPops ELSE entry.mpPops
ObservedTerminals == IF entry.stage = "handed" THEN life.terminalCount ELSE entry.terminalCount
ObservedSends == IF entry.stage = "handed" THEN life.sendAttempts ELSE 0
ObservedCommit == IF entry.stage = "handed" THEN life.didCommit ELSE FALSE
EntryTypeOK ==
    /\ route \in Routes /\ fault \in Faults /\ kind \in Kinds /\ pc \in 0..9
    /\ entry.stage \in {"before","unadmitted","handed","terminal"}
    /\ entry.security \in {NoEntry,SecA,SecB}
    /\ entry.engine \in {"e0","e1"}
    /\ entry.outgoing \in BOOLEAN /\ entry.diagnostic \in BOOLEAN
    /\ entry.admission \in BOOLEAN
    /\ entry.mpPops \in 0..1 /\ entry.securityPops \in 0..1
    /\ entry.terminalCount \in 0..1
    /\ (entry.stage = "handed" => LifeTypeOK)
    /\ (entry.stage # "handed" => life = NoEntry)
EntrySingleOwner == entry.stage = "handed" => entry.mp = NoEntry /\ entry.security = NoEntry
AdmittedSafety == entry.stage = "handed" =>
    /\ TerminalOwnership /\ ProgressAvailable /\ CanceledBeforeEffects
EntryReady == [][entry.stage = "handed" /\ life'.lastAction = "claim" => Ready(life)]_EntryVars
EntryCommitReady == [][~ObservedCommit /\ ObservedCommit' =>
    entry.stage = "handed" /\ Ready(life)]_EntryVars
EntryNoRollback == [][ObservedCommit => ObservedCommit']_EntryVars
EntryNoAwait == [][entry.stage = "handed" /\ life.phase \in Internal =>
    life'.lastAction \in {"takeMp","consumeSecurity","send","beforeMpFailure",
                          "afterMpFailure","encodeFailure","transportFailure"}]_EntryVars
EntryForeignSafe == [][ObservedSecurity = SecB => ObservedSecurity' = SecB]_EntryVars
EntryOutgoingSafe == [][ObservedOutgoing' = ObservedOutgoing]_EntryVars
EntryUnknownSafe == [][pc = 3 /\ ~EntryCanCapture(entry) =>
    /\ ObservedSecurity' = ObservedSecurity /\ ObservedDiagnostic'
    /\ ObservedMp' = NoEntry /\ ObservedSends' = 0 /\ ~ObservedCommit']_EntryVars
InsertionCapturesOriginal == [][pc = 0 =>
    /\ entry'.mp.witness = EntryWitness(entry.security)
    /\ entry'.mp.identity = MPA /\ life' = NoEntry]_EntryVars
AssociationStaysFixed == [][(pc \in {1,2} /\ fault \notin {"missingWitness","foreignLifetime","foreignOwner"}) =>
    entry'.mp.witness = entry.mp.witness]_EntryVars
AdmissionCopiesOriginal == [][pc = 3 /\ route = "admit" /\ EntryCanCapture(entry) =>
    /\ life' = EntryCaptured(entry) /\ life'.ticket.security = entry.mp.witness.security
    /\ ObservedMp' = ObservedMp /\ ObservedSecurity' = ObservedSecurity
    /\ ObservedMpPops' = 0 /\ ObservedSecurityPops' = 0]_EntryVars
EntryAssertions == pc = 9 =>
    /\ ObservedTerminals = 1 /\ ObservedMp = NoEntry /\ ObservedMpPops = 1
    /\ (fault = "none" => ~ObservedDiagnostic /\ ObservedSecurity = NoEntry /\ ObservedSecurityPops = 1)
    /\ (fault # "none" => ObservedDiagnostic /\ ObservedSecurityPops = 0 /\ ObservedSends = 0 /\ ~ObservedCommit)
    /\ (fault \in {"reused","missingAtInsert"} => ObservedSecurity = SecB)
    /\ (fault \in {"missingWitness","foreignLifetime","foreignOwner","wrongEngine"} => ObservedSecurity = SecA)
    /\ (fault = "lost" => ObservedSecurity = NoEntry)
    /\ (fault = "none" /\ route = "admit" => ObservedSends = 1 /\ ObservedCommit = (kind = "change"))
    /\ (route # "admit" => ObservedSends = 0 /\ ~ObservedCommit)
    /\ (route = "close" => ~entry.admission)
=============================================================================
