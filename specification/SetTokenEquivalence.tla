----------------------- MODULE SetTokenEquivalence -----------------------
EXTENDS SetTransactions

\* Equality observations of two independent opaque lifecycle token owners.
\* All other request, access, result, and switch state remains in the VIEW.
OtherToken == CHOOSE t \in Tokens \ {Token0} : TRUE
CanonicalRegistrations == [c \in Credentials |-> Token0]
TokenView(rs, a, pdu) ==
    [registration |-> CanonicalRegistrations, activation |-> Token0,
     pending |-> IF pdu = NoPdu THEN NoPdu ELSE
         [pdu EXCEPT
             !.registration = IF pdu.registration = rs[pdu.credential]
                              THEN Token0 ELSE OtherToken,
             !.activation = IF pdu.activation = a THEN Token0 ELSE OtherToken]]
CanonicalSetView == <<s, accessvars, result, gate,
                     TokenView(registration, activation, pending)>>

\* The expected abstract update remembers revocation until this PDU completes.
\* Changed may include either credential, both shared-view consumers, or neither.
ExpectedChange(changed, restart) ==
    LET q == TokenView(registration, activation, pending)
    IN IF pending = NoPdu THEN q ELSE
        [q EXCEPT
            !.pending.registration = IF pending.credential \in changed
                                     THEN OtherToken ELSE @,
            !.pending.activation = IF restart THEN OtherToken ELSE @]
ChangedRegistrations(changed) == [c \in Credentials |->
    IF c \in changed THEN Fresh(UsedRegistration(c)) ELSE registration[c]]
ChangedActivation(restart) == IF restart THEN Fresh(UsedActivation) ELSE activation
TransitionCongruence ==
    \A changed \in SUBSET Credentials, restart \in BOOLEAN :
        TokenView(ChangedRegistrations(changed), ChangedActivation(restart), pending)
            = ExpectedChange(changed, restart)

WitnessPdu(c, r, a) ==
    [credential |-> c, secret |-> K1, ops |-> <<>>, budget |-> TRUE,
     persist |-> TRUE, registration |-> r, activation |-> a, boot |-> s.boot]
CaptureCongruence == pending = NoPdu =>
    \A c \in Credentials :
        TokenView(registration, activation, WitnessPdu(c,registration[c],activation))
          = [registration |-> CanonicalRegistrations, activation |-> Token0,
             pending |-> WitnessPdu(c,Token0,Token0)]
CompletionCongruence ==
    TokenView(registration, activation, NoPdu) =
        [registration |-> CanonicalRegistrations, activation |-> Token0, pending |-> NoPdu]
ProjectionIdempotent ==
    LET q == TokenView(registration, activation, pending)
    IN TokenView(q.registration,q.activation,q.pending) = q

\* 27 no-PDU assignments plus 486 captured-token assignments: 513 initial states.
\* The certificate applies actual allocator operators to every affected subset
\* and restart flag in each state, including all already-stale combinations.
CertificateInit ==
    /\ RunningInit /\ Access!Init
    /\ secret = [c \in Credentials |-> K1]
    /\ registration \in [Credentials -> Tokens] /\ activation \in Tokens
    /\ pending \in {NoPdu} \cup
         {WitnessPdu(c,r,a) : c \in Credentials, r,a \in Tokens}
    /\ result = [status |-> "none", index |-> 0] /\ gate = TRUE
CertificateSpec == CertificateInit /\ [][UNCHANGED allvars]_allvars

\* A small compatibility fixture retains the real HandleSet action, its weak
\* fairness, completed outcomes, and the same canonical VIEW as the full graph.
CompatibilityNext == HandleSet \/ (pending = NoPdu /\ UNCHANGED allvars)
CompatibilitySpec == CertificateInit /\ [][CompatibilityNext]_allvars /\ WF_allvars(HandleSet)
=============================================================================
