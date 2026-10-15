--------------------------- MODULE SnapshotCounts ---------------------------
EXTENDS Naturals, FiniteSets
Ports == {1, 2}
Rows == 1..3
VARIABLES source, captured, remaining, counts, busy, published, publishedSource
vars == <<source, captured, remaining, counts, busy, published, publishedSource>>
Count(rows, p, keys) == Cardinality({k \in keys : rows[k] = p})
Init == /\ source \in [Rows -> Ports \cup {0}]
        /\ captured = source /\ remaining = {} /\ busy = FALSE
        /\ counts = [p \in Ports |-> 0]
        /\ published = [p \in Ports |-> Count(source, p, Rows)]
        /\ publishedSource = source
Change == /\ source' \in [Rows -> Ports \cup {0}]
          /\ UNCHANGED <<captured, remaining, counts, busy, published, publishedSource>>
Begin == /\ ~busy /\ busy' = TRUE /\ captured' = source
         /\ remaining' = Rows /\ counts' = [p \in Ports |-> 0]
         /\ UNCHANGED <<source, published, publishedSource>>
Accumulate(k) == /\ busy /\ k \in remaining
                 /\ remaining' = remaining \ {k}
                 /\ counts' = IF captured[k] = 0 THEN counts
                              ELSE [counts EXCEPT ![captured[k]] = @ + 1]
                 /\ UNCHANGED <<source, captured, busy, published, publishedSource>>
Publish == /\ busy /\ remaining = {} /\ busy' = FALSE
           /\ published' = counts /\ publishedSource' = captured
           /\ UNCHANGED <<source, captured, remaining, counts>>
Next == Change \/ Begin \/ Publish \/ (\E k \in Rows : Accumulate(k))
PartialCounts == busy => \A p \in Ports : counts[p] = Count(captured, p, Rows \ remaining)
ExactCounts == \A p \in Ports : published[p] = Count(publishedSource, p, Rows)
Spec == Init /\ [][Next]_vars
=============================================================================
