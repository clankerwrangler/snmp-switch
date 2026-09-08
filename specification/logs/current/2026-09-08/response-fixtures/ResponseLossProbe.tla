---------------------- MODULE ResponseLossProbe ----------------------
EXTENDS SetResponseLifecycle, Sequences
VARIABLES idx, step, observed
ProbeVars == <<life,idx,step,observed>>
Cases == <<[fault |-> "missing", trigger |-> "cancel"], [fault |-> "missing", trigger |-> "expiry"],
           [fault |-> "missing", trigger |-> "revoke"], [fault |-> "missing", trigger |-> "close"],
           [fault |-> "foreign", trigger |-> "cancel"], [fault |-> "foreign", trigger |-> "expiry"],
           [fault |-> "foreign", trigger |-> "revoke"], [fault |-> "foreign", trigger |-> "close"]>>
ProbeInit == life = LifeInitial("noop") /\ idx = 1 /\ step = 0 /\ observed = <<>>
Trigger == CASE Cases[idx].trigger = "cancel" -> Cancel("cancel")
    [] Cases[idx].trigger = "expiry" -> OriginalExpiryBoundary
    [] Cases[idx].trigger = "revoke" -> Revoke
    [] Cases[idx].trigger = "close" -> Close
ProbeNext == IF idx > Len(Cases) THEN UNCHANGED ProbeVars
    ELSE CASE step = 0 ->
        /\ (IF Cases[idx].fault = "missing" THEN MissingSecurity ELSE ReplaceSecurity)
        /\ step' = 1 /\ UNCHANGED <<idx,observed>>
      [] step = 1 -> /\ Trigger /\ step' = 2 /\ UNCHANGED <<idx,observed>>
      [] step = 2 ->
        /\ observed' = Append(observed,[case |-> Cases[idx], reported |-> life.diagnostic,
                mpPops |-> life.mpPops, securityPops |-> life.securityPops])
        /\ idx' = idx + 1 /\ step' = 0
        /\ life' = IF idx < Len(Cases) THEN LifeInitial("noop") ELSE life
ProbeSpec == ProbeInit /\ [][ProbeNext]_ProbeVars /\ WF_ProbeVars(ProbeNext)
AllLossesReported == idx <= Len(Cases) \/ (Len(observed) = 8 /\ \A i \in DOMAIN observed : observed[i].reported)
ProbeCompletes == <> (idx = 9)
=============================================================================
