---- MODULE Good ----
EXTENDS Naturals
VARIABLE n
Init == n = 0
Next == n' = n
Spec == Init /\ [][Next]_n
Safe == n = 0
====
