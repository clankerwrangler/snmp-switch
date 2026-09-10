----------------------- MODULE RadiusAuthorization -----------------------
EXTENDS Integers, FiniteSets

(***************************************************************************
 One-port authorization boundary, separate from the existing Switch model.
 Packets/EAP methods are abstract outcomes. A single retained request per
 client is enough to expose late-result races; it is not a transport limit.
 0 = no policy/request, -1 = inherit the port PVID. VLAN 1 is permanent.
****************************************************************************)
CONSTANTS Clients, VLANs, Tokens, Lease
ASSUME /\ IsFiniteSet(Clients) /\ Clients # {}
       /\ IsFiniteSet(VLANs) /\ 1 \in VLANs
       /\ VLANs \subseteq 1..4094
       /\ IsFiniteSet(Tokens) /\ Tokens \subseteq Nat \ {0}
       /\ Cardinality(Tokens) >= 3
       /\ Lease \in Nat \ {0}

VARIABLES mode, link, available, pvid, policy, remaining,
          generation, pending, paused, accountingUp
vars == <<mode, link, available, pvid, policy, remaining,
          generation, pending, paused, accountingUp>>
Modes == {"auto", "force-authorized", "force-unauthorized"}
Effective(c) == IF policy[c] = -1 THEN pvid ELSE policy[c]
Fresh(c) == CHOOSE t \in Tokens \ {generation[c], pending[c]} : TRUE
FreshAll == [c \in Clients |-> Fresh(c)]
EmptyPolicy == [c \in Clients |-> 0]

Init == /\ mode = "auto" /\ link = TRUE
        /\ available = VLANs /\ pvid = 1
        /\ policy = EmptyPolicy /\ remaining = EmptyPolicy
        /\ generation = [c \in Clients |-> CHOOSE t \in Tokens : TRUE]
        /\ pending = EmptyPolicy
        /\ paused = FALSE /\ accountingUp = TRUE

TypeOK == /\ mode \in Modes /\ link \in BOOLEAN
          /\ available \subseteq VLANs /\ 1 \in available
          /\ pvid \in available
          /\ policy \in [Clients -> ({-1, 0} \cup VLANs)]
          /\ remaining \in [Clients -> 0..Lease]
          /\ generation \in [Clients -> Tokens]
          /\ pending \in [Clients -> (Tokens \cup {0})]
          /\ paused \in BOOLEAN /\ accountingUp \in BOOLEAN
AuthorizationValid ==
    \A c \in Clients :
        /\ (policy[c] # 0 =>
              mode = "auto" /\ link /\ Effective(c) \in available)
        /\ ((policy[c] = 0) <=> (remaining[c] = 0))

Begin(c) ==
    /\ mode = "auto" /\ link /\ pending[c] = 0
    /\ pending' = [pending EXCEPT ![c] = generation[c]]
    \* A periodic exchange leaves an existing grant effective while pending.
    /\ UNCHANGED <<mode, link, available, pvid, policy, remaining,
                    generation, paused, accountingUp>>

Reply(c, result) ==
    /\ pending[c] # 0
    /\ LET current == pending[c] = generation[c] /\ mode = "auto" /\ link
           vid == IF result = -1 THEN pvid ELSE result
           accepted == result # 0 /\ vid \in available
       IN /\ pending' = [pending EXCEPT ![c] = 0]
          /\ policy' = IF current
                       THEN [policy EXCEPT ![c] = IF accepted THEN result ELSE 0]
                       ELSE policy
          /\ remaining' = IF current
                          THEN [remaining EXCEPT ![c] = IF accepted THEN Lease ELSE 0]
                          ELSE remaining
    /\ UNCHANGED <<mode, link, available, pvid, generation, paused, accountingUp>>

Restart(c) ==
    /\ generation' = [generation EXCEPT ![c] = Fresh(c)]
    /\ policy' = [policy EXCEPT ![c] = 0]
    /\ remaining' = [remaining EXCEPT ![c] = 0]
    \* Keep the old capture to check a reply arriving after invalidation.
    /\ UNCHANGED <<mode, link, available, pvid, pending, paused, accountingUp>>

SetMode(m) ==
    /\ m \in Modes /\ m # mode
    /\ mode' = m /\ generation' = FreshAll
    /\ policy' = EmptyPolicy /\ remaining' = EmptyPolicy
    /\ UNCHANGED <<link, available, pvid, pending, paused, accountingUp>>

SetLink(value) ==
    /\ value \in BOOLEAN /\ value # link
    /\ link' = value /\ generation' = FreshAll
    /\ policy' = EmptyPolicy /\ remaining' = EmptyPolicy
    /\ UNCHANGED <<mode, available, pvid, pending, paused, accountingUp>>

SetPvid(v) ==
    /\ v \in available /\ v # pvid
    /\ pvid' = v
    /\ UNCHANGED <<mode, link, available, policy, remaining,
                    generation, pending, paused, accountingUp>>

DeleteVlan(v) ==
    /\ v \in available \ {1}
    /\ LET affected == {c \in Clients : Effective(c) = v}
       IN /\ policy' = [c \in Clients |-> IF c \in affected THEN 0 ELSE policy[c]]
          /\ remaining' = [c \in Clients |-> IF c \in affected THEN 0 ELSE remaining[c]]
    /\ available' = available \ {v}
    /\ pvid' = IF pvid = v THEN 1 ELSE pvid
    \* Invalidate pending work even if deletion is later reversed.
    /\ generation' = FreshAll
    /\ UNCHANGED <<mode, link, pending, paused, accountingUp>>

CreateVlan(v) ==
    /\ v \in VLANs \ available
    /\ available' = available \cup {v}
    /\ generation' = FreshAll
    /\ UNCHANGED <<mode, link, pvid, policy, remaining, pending, paused, accountingUp>>

StepClock ==
    /\ LET expired == {c \in Clients : remaining[c] = 1}
       IN /\ remaining' = [c \in Clients |-> IF remaining[c] = 0 THEN 0 ELSE remaining[c] - 1]
          /\ policy' = [c \in Clients |-> IF c \in expired THEN 0 ELSE policy[c]]
          /\ generation' = [c \in Clients |-> IF c \in expired THEN Fresh(c) ELSE generation[c]]
    /\ UNCHANGED <<mode, link, available, pvid, pending, paused, accountingUp>>
AutomaticTick == /\ ~paused /\ StepClock
ManualTick == /\ paused /\ StepClock
TogglePause == /\ paused' = ~paused
               /\ UNCHANGED <<mode, link, available, pvid, policy, remaining,
                               generation, pending, accountingUp>>
AccountingChange ==
    /\ accountingUp' = ~accountingUp
    /\ UNCHANGED <<mode, link, available, pvid, policy, remaining,
                    generation, pending, paused>>

Next == \/ \E c \in Clients : Begin(c) \/ Restart(c)
        \/ \E c \in Clients, r \in VLANs \cup {-1, 0, 9999} : Reply(c, r)
        \/ \E m \in Modes : SetMode(m)
        \/ \E b \in BOOLEAN : SetLink(b)
        \/ \E v \in VLANs : SetPvid(v) \/ DeleteVlan(v) \/ CreateVlan(v)
        \/ AutomaticTick \/ ManualTick \/ TogglePause \/ AccountingChange
Spec == Init /\ [][Next]_vars

\* These inspect observed transitions, not only a final state shape.
NoStaleGrant == [] [\A c \in Clients :
    (pending[c] # 0 /\ pending[c] # generation[c] /\ pending'[c] = 0)
        => UNCHANGED <<policy, remaining>>]_vars
AuthEditKeepsLink == [] [mode' # mode => link' = link]_vars
AccountingIndependent == [] [accountingUp' # accountingUp =>
    UNCHANGED <<policy, remaining, mode, link>>]_vars
=============================================================================
