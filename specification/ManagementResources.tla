------------------------- MODULE ManagementResources ------------------------
EXTENDS Naturals, FiniteSets, Sequences
Workers == 1..3
Roles == {"viewer", "admin"}
VARIABLES running, requests, sessions, admission
vars == <<running, requests, sessions, admission>>
Init == /\ running = {} /\ requests = {} /\ sessions = <<>>
        /\ admission = [role |-> "none", evicted |-> "none"]
Start(w) == /\ w \in Workers \ running /\ Cardinality(running) < 2
            /\ running' = running \cup {w} /\ requests' = requests \cup {w}
            /\ UNCHANGED <<sessions, admission>>
Cancel(w) == /\ w \in requests /\ requests' = requests \ {w}
             /\ UNCHANGED <<running, sessions, admission>>
Finish(w) == /\ w \in running /\ running' = running \ {w} /\ requests' = requests \ {w}
             /\ UNCHANGED <<sessions, admission>>
RemoveAt(s, i) == SubSeq(s, 1, i-1) \o SubSeq(s, i+1, Len(s))
Issue(r) == LET viewers == {i \in 1..Len(sessions) : sessions[i] = "viewer"}
                victim == IF viewers # {} THEN CHOOSE i \in viewers : \A j \in viewers : i <= j
                          ELSE IF r = "admin" THEN 1 ELSE 0
            IN /\ r \in Roles
               /\ sessions' = IF Len(sessions) < 2 THEN Append(sessions, r)
                               ELSE IF victim = 0 THEN sessions ELSE Append(RemoveAt(sessions, victim), r)
               /\ admission' = [role |-> r, evicted |-> IF Len(sessions) = 2 /\ victim # 0 THEN sessions[victim] ELSE "none"]
               /\ UNCHANGED <<running, requests>>
Logout(i) == /\ i \in 1..Len(sessions) /\ sessions' = RemoveAt(sessions, i)
             /\ UNCHANGED <<running, requests, admission>>
Next == (\E w \in Workers : Start(w) \/ Cancel(w) \/ Finish(w)) \/
        (\E r \in Roles : Issue(r)) \/ (\E i \in 1..Len(sessions) : Logout(i))
BoundedWork == Cardinality(running) <= 2
OwnedRequests == requests \subseteq running
BoundedSessions == Len(sessions) <= 2
AdminRecovery == admission.role = "viewer" => admission.evicted # "admin"
Spec == Init /\ [][Next]_vars
=============================================================================
