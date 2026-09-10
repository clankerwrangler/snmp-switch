------------------ MODULE RadiusDynamicAuthorization ------------------
EXTENDS Integers, FiniteSets

(***************************************************************************
 One authenticated, immutable request and its cached result, with two client
 session incarnations. A request can match several clients. A MAC selector is
 abstracted as queryClients; an optional exact session ID is conjoined with it.
 Wire parsing, sender authentication, cache expiry/durability, and the rest of
 the switch are outside this small graph. Replay survives session replacement.
****************************************************************************)
CONSTANTS Clients, VLANs
ASSUME /\ IsFiniteSet(Clients) /\ Clients # {}
       /\ IsFiniteSet(VLANs) /\ VLANs # {} /\ VLANs \subseteq 1..4094
VARIABLES queryClients, querySession, requestedVlan, operation, canApply,
          session, vlan, usedNew, reply, event
vars == <<queryClients, querySession, requestedVlan, operation, canApply,
          session, vlan, usedNew, reply, event>>
Inputs == <<queryClients, querySession, requestedVlan, operation, canApply>>
SessionIds == {<<>>} \cup {<<c, n>> : c \in Clients, n \in 1..2}
Matched == {c \in Clients : session[c] # 0 /\ c \in queryClients /\
    (querySession = <<>> \/ querySession = <<c, session[c]>>)}
Applicable == Matched # {} /\ Matched \subseteq canApply /\
    (operation = "disconnect" \/ requestedVlan \in VLANs)

Init == /\ queryClients \in SUBSET Clients
        /\ querySession \in SessionIds
        /\ requestedVlan \in VLANs \cup {9999}
        /\ operation \in {"coa", "disconnect"}
        /\ canApply \in SUBSET Clients
        /\ session = [c \in Clients |-> 1]
        /\ vlan \in [Clients -> VLANs]
        /\ usedNew = {} /\ reply = "none" /\ event = "init"

TypeOK == /\ queryClients \subseteq Clients /\ querySession \in SessionIds
          /\ requestedVlan \in VLANs \cup {9999}
          /\ operation \in {"coa", "disconnect"} /\ canApply \subseteq Clients
          /\ session \in [Clients -> 0..2]
          /\ vlan \in [Clients -> (VLANs \cup {0})]
          /\ usedNew \subseteq Clients
          /\ reply \in {"none", "ack", "nak"}
          /\ event \in {"init", "process", "replay", "reauth"}
PolicyOK == \A c \in Clients :
    /\ ((session[c] = 0) <=> (vlan[c] = 0))
    /\ (session[c] = 2 => c \in usedNew)

Process ==
    /\ event' = IF reply = "none" THEN "process" ELSE "replay"
    /\ IF reply # "none"
       THEN UNCHANGED <<session, vlan, reply>>
       ELSE /\ reply' = IF Applicable THEN "ack" ELSE "nak"
            /\ session' = [c \in Clients |->
                  IF Applicable /\ c \in Matched /\ operation = "disconnect"
                  THEN 0 ELSE session[c]]
            /\ vlan' = [c \in Clients |->
                  IF Applicable /\ c \in Matched
                  THEN IF operation = "disconnect" THEN 0 ELSE requestedVlan
                  ELSE vlan[c]]
    /\ UNCHANGED <<queryClients, querySession, requestedVlan, operation,
                    canApply, usedNew>>

Reauthenticate(c, v) ==
    /\ session[c] = 0 /\ c \notin usedNew /\ v \in VLANs
    /\ session' = [session EXCEPT ![c] = 2]
    /\ vlan' = [vlan EXCEPT ![c] = v]
    /\ usedNew' = usedNew \cup {c}
    /\ event' = "reauth"
    \* A new client packet and successful authentication are abstracted here.
    \* The old request's cached decision must not disappear with its session.
    /\ UNCHANGED <<queryClients, querySession, requestedVlan, operation, canApply, reply>>

Next == Process \/ (\E c \in Clients, v \in VLANs : Reauthenticate(c, v))
Spec == Init /\ [][Next]_vars

DuplicateNoEffect == [] [event' = "replay" => UNCHANGED <<session, vlan, reply>>]_vars
NakPreservesState == [] [
    event' = "process" /\ reply = "none" /\ reply' = "nak"
        => UNCHANGED <<session, vlan>>]_vars
AckIsAtomic == [] [
    event' = "process" /\ reply = "none" /\ reply' = "ack" =>
        /\ Applicable
        /\ \A c \in Matched :
             IF operation = "disconnect"
             THEN session'[c] = 0 /\ vlan'[c] = 0
             ELSE session'[c] = session[c] /\ vlan'[c] = requestedVlan
        /\ \A c \in Clients \ Matched :
             session'[c] = session[c] /\ vlan'[c] = vlan[c]]_vars
=============================================================================
