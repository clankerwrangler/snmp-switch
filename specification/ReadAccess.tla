--------------------------- MODULE ReadAccess ---------------------------
EXTENDS Naturals, FiniteSets

(***************************************************************************
 Separate abstraction for configurable read credentials and an atomic read.
 Opaque Secrets do not model SNMPv3 cryptography, USM, VACM, or web sessions.
 Snapshots stand for immutable Switch projections, not a second switch model.
 Authorization is checked when a queued request is handled, not at submission.
***************************************************************************)
CONSTANTS Credentials, Secrets, Views, Snapshots, NoRequest, NoResponse

VARIABLES enabled, secret, grants, snapshot, request, response
vars == <<enabled, secret, grants, snapshot, request, response>>

RequestType == [credential : Credentials, suppliedSecret : Secrets,
                requestedViews : SUBSET Views]
ResponseType == [authorized : BOOLEAN, returnedViews : SUBSET Views,
                 dataSnapshot : Snapshots]
ASSUME /\ IsFiniteSet(Credentials) /\ Credentials # {}
       /\ IsFiniteSet(Secrets) /\ Secrets # {}
       /\ IsFiniteSet(Views) /\ Views # {}
       /\ IsFiniteSet(Snapshots) /\ Snapshots # {}
       /\ NoRequest \notin RequestType
       /\ NoResponse \notin ResponseType

Authorized(r) ==
    r.credential \in enabled /\ r.suppliedSecret = secret[r.credential]

Reply(r) ==
    [authorized |-> Authorized(r),
     returnedViews |-> IF Authorized(r)
                      THEN r.requestedViews \cap grants[r.credential]
                      ELSE {},
     dataSnapshot |-> snapshot]

Init ==
    /\ enabled = {}
    /\ secret \in [Credentials -> Secrets]
    /\ grants = [c \in Credentials |-> {}]
    /\ snapshot \in Snapshots
    /\ request = NoRequest
    /\ response = NoResponse

ConfigureCredential(c, on, s, vs) ==
    /\ enabled' = IF on THEN enabled \cup {c} ELSE enabled \ {c}
    /\ secret' = [secret EXCEPT ![c] = s]
    /\ grants' = [grants EXCEPT ![c] = vs]
    /\ UNCHANGED <<snapshot, request, response>>

Submit(c, s, vs) ==
    /\ request = NoRequest
    /\ request' = [credential |-> c, suppliedSecret |-> s,
                    requestedViews |-> vs]
    /\ UNCHANGED <<enabled, secret, grants, snapshot, response>>

Handle ==
    /\ request # NoRequest
    /\ response' = Reply(request)
    /\ request' = NoRequest
    /\ UNCHANGED <<enabled, secret, grants, snapshot>>

ChangeSnapshot(s) ==
    /\ snapshot' = s
    /\ UNCHANGED <<enabled, secret, grants, request, response>>

Next ==
    \/ \E c \in Credentials, on \in BOOLEAN, s \in Secrets, vs \in SUBSET Views :
           ConfigureCredential(c, on, s, vs)
    \/ \E c \in Credentials, s \in Secrets, vs \in SUBSET Views : Submit(c, s, vs)
    \/ Handle
    \/ \E s \in Snapshots : ChangeSnapshot(s)

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(Handle)

TypeOK ==
    /\ enabled \subseteq Credentials
    /\ secret \in [Credentials -> Secrets]
    /\ grants \in [Credentials -> SUBSET Views]
    /\ snapshot \in Snapshots
    /\ request \in RequestType \cup {NoRequest}
    /\ response \in ResponseType \cup {NoResponse}

\* The snapshot identifier in a denied response is a model-only marker.
\* No objects/rows are returned when returnedViews is empty.
DeniedReadsHaveNoData ==
    response # NoResponse => (~response.authorized => response.returnedViews = {})

ReadStep ==
    IF request # NoRequest /\ request' = NoRequest
    THEN /\ response'.authorized = Authorized(request)
         /\ response'.returnedViews =
                (IF Authorized(request)
                 THEN request.requestedViews \cap grants[request.credential]
                 ELSE {})
         /\ response'.dataSnapshot = snapshot
         /\ UNCHANGED <<enabled, secret, grants, snapshot>>
    ELSE response' = response

ReadsUseCurrentAuthorization == [][ReadStep]_vars
RequestsEventuallyComplete == (request # NoRequest) ~> (request = NoRequest)
=============================================================================
