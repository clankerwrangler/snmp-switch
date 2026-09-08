--------------------------- MODULE ReadAccess ---------------------------
EXTENDS Naturals, FiniteSets

(***************************************************************************
 Shared credentials, polling access, view references, and target references.
 Secrets and snapshots are opaque; cryptography, CIDRs, listener gates, wire
 identity uniqueness, delivery, and persistence internals remain outside this
 model. Authorization is evaluated when a request is handled.

 Views is the finite universe of both named view slots and observable object
 families. A view may include no modeled families even when its real OID
 prefixes are nonempty. Secret equality stands for successful authentication.
***************************************************************************)
CONSTANTS Credentials, Secrets, Views, Snapshots, Targets,
          NoCredential, NoView, NoRequest, NoResponse

VARIABLES existing, enabled, secret, polling, presentViews, viewOf, includes,
          targetCredential, targetEnabled, writing, writeViewOf, snapshot, request, response
configvars == <<existing, enabled, secret, polling, presentViews, viewOf,
               includes, targetCredential, targetEnabled, writing, writeViewOf>>
vars == <<configvars, snapshot, request, response>>

RequestType == [credential : Credentials, suppliedSecret : Secrets,
                requestedViews : SUBSET Views]
ResponseType == [authorized : BOOLEAN, returnedViews : SUBSET Views,
                 dataSnapshot : Snapshots]
ASSUME /\ IsFiniteSet(Credentials) /\ Credentials # {}
       /\ IsFiniteSet(Secrets) /\ Secrets # {}
       /\ IsFiniteSet(Views) /\ Cardinality(Views) >= Cardinality(Credentials)
       /\ IsFiniteSet(Snapshots) /\ Snapshots # {}
       /\ IsFiniteSet(Targets)
       /\ NoCredential \notin Credentials /\ NoView \notin Views
       /\ NoRequest \notin RequestType /\ NoResponse \notin ResponseType

Secret0 == CHOOSE k \in Secrets : TRUE
View0 == CHOOSE v \in Views : TRUE
CredentialViews == CHOOSE f \in [Credentials -> Views] :
    \A c, d \in Credentials : f[c] = f[d] => c = d

grants == [c \in Credentials |-> includes[viewOf[c]]]
Authorized(r) ==
    /\ r.credential \in existing \cap enabled \cap polling
    /\ viewOf[r.credential] \in presentViews
    /\ r.suppliedSecret = secret[r.credential]
WriteAuthorized(c, k) ==
    /\ c \in existing \cap enabled \cap writing
    /\ writeViewOf[c] \in presentViews /\ k = secret[c]
WriteGrants(c) == IF writeViewOf[c] \in presentViews THEN includes[writeViewOf[c]] ELSE {}
NotificationAllowed(t) ==
    targetCredential[t] # NoCredential /\ t \in targetEnabled
        /\ targetCredential[t] \in existing \cap enabled
Reply(r) ==
    [authorized |-> Authorized(r),
     returnedViews |-> IF Authorized(r)
                      THEN r.requestedViews \cap grants[r.credential] ELSE {},
     dataSnapshot |-> snapshot]

(***************************************************************************
 The original read fixture retains its action families and independent
 credential grants: one fixed distinct view slot per credential. Additional
 relationship state is constant in that fixture, not a reduced read bound.
***************************************************************************)
Init ==
    /\ existing = Credentials /\ enabled = {} /\ polling = Credentials
    /\ secret \in [Credentials -> Secrets]
    /\ presentViews = Views /\ viewOf = CredentialViews
    /\ includes = [v \in Views |-> {}]
    /\ targetCredential = [t \in Targets |-> NoCredential]
    /\ targetEnabled = {}
    /\ writing = {} /\ writeViewOf = [c \in Credentials |-> NoView]
    /\ snapshot \in Snapshots /\ request = NoRequest /\ response = NoResponse

ConfigureCredential(c, on, k, vs) ==
    /\ c \in existing /\ viewOf[c] \in presentViews
    /\ enabled' = IF on THEN enabled \cup {c} ELSE enabled \ {c}
    /\ secret' = [secret EXCEPT ![c] = k]
    /\ includes' = [includes EXCEPT ![viewOf[c]] = vs]
    /\ UNCHANGED <<existing, polling, presentViews, viewOf, targetCredential,
                    targetEnabled, writing, writeViewOf, snapshot, request, response>>
Submit(c, k, vs) ==
    /\ request = NoRequest
    /\ request' = [credential |-> c, suppliedSecret |-> k, requestedViews |-> vs]
    /\ UNCHANGED <<configvars, snapshot, response>>
Handle ==
    /\ request # NoRequest
    /\ response' = Reply(request) /\ request' = NoRequest
    /\ UNCHANGED <<configvars, snapshot>>
ChangeSnapshot(value) ==
    /\ snapshot' = value /\ UNCHANGED <<configvars, request, response>>
ReadNext ==
    \/ \E c \in Credentials, k \in Secrets, vs \in SUBSET Views : Submit(c, k, vs)
    \/ Handle
    \/ \E value \in Snapshots : ChangeSnapshot(value)
Next ==
    \/ \E c \in Credentials, on \in BOOLEAN, k \in Secrets, vs \in SUBSET Views :
           ConfigureCredential(c, on, k, vs)
    \/ ReadNext
Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(Handle)

(***************************************************************************
 Each configuration action publishes one complete candidate or no change.
 An explicit failed persistence outcome is included for inline creation.
 Missing views are allowed only for inactive polling, regardless of the
 credential-wide enable flag. Disabled targets still retain references.
***************************************************************************)
SharedInit ==
    /\ existing = {} /\ enabled = {} /\ polling = {}
    /\ secret = [c \in Credentials |-> Secret0]
    /\ presentViews = {} /\ viewOf = [c \in Credentials |-> View0]
    /\ includes = [v \in Views |-> {}]
    /\ targetCredential = [t \in Targets |-> NoCredential] /\ targetEnabled = {}
    /\ writing = {} /\ writeViewOf = [c \in Credentials |-> NoView]
    /\ snapshot \in Snapshots /\ request = NoRequest /\ response = NoResponse

SaveCredential(c, on, poll, v, k) ==
    IF poll /\ v \notin presentViews THEN UNCHANGED vars
    ELSE /\ existing' = existing \cup {c}
         /\ enabled' = IF on THEN enabled \cup {c} ELSE enabled \ {c}
         /\ polling' = IF poll THEN polling \cup {c} ELSE polling \ {c}
         /\ secret' = [secret EXCEPT ![c] = k]
         /\ viewOf' = [viewOf EXCEPT ![c] = v]
         /\ UNCHANGED <<presentViews, includes, targetCredential, targetEnabled,
                         writing, writeViewOf, snapshot, request, response>>
DeleteCredential(c) ==
    IF c \notin existing \/ (\E t \in Targets : targetCredential[t] = c)
    THEN UNCHANGED vars
    ELSE /\ existing' = existing \ {c} /\ enabled' = enabled \ {c}
         /\ polling' = polling \ {c}
         /\ writing' = writing \ {c}
         /\ writeViewOf' = [writeViewOf EXCEPT ![c] = NoView]
         /\ secret' = [secret EXCEPT ![c] = Secret0]
         /\ viewOf' = [viewOf EXCEPT ![c] = View0]
         /\ UNCHANGED <<presentViews, includes, targetCredential, targetEnabled,
                         snapshot, request, response>>
SaveView(v, vs) ==
    /\ presentViews' = presentViews \cup {v}
    /\ includes' = [includes EXCEPT ![v] = vs]
    /\ UNCHANGED <<existing, enabled, secret, polling, viewOf, targetCredential,
                    targetEnabled, writing, writeViewOf, snapshot, request, response>>
DeleteView(v) ==
    IF v \notin presentViews \/ (\E c \in polling : viewOf[c] = v)
       \/ (\E c \in writing : writeViewOf[c] = v)
    THEN UNCHANGED vars
    ELSE /\ presentViews' = presentViews \ {v}
         /\ includes' = [includes EXCEPT ![v] = {}]
         /\ UNCHANGED <<existing, enabled, secret, polling, viewOf, targetCredential,
                         targetEnabled, writing, writeViewOf, snapshot, request, response>>
SaveTarget(t, c, on) ==
    IF c \notin existing THEN UNCHANGED vars
    ELSE /\ targetCredential' = [targetCredential EXCEPT ![t] = c]
         /\ targetEnabled' = IF on THEN targetEnabled \cup {t} ELSE targetEnabled \ {t}
         /\ UNCHANGED <<existing, enabled, secret, polling, presentViews, viewOf,
                         includes, writing, writeViewOf, snapshot, request, response>>
DeleteTarget(t) ==
    /\ targetCredential' = [targetCredential EXCEPT ![t] = NoCredential]
    /\ targetEnabled' = targetEnabled \ {t}
    /\ UNCHANGED <<existing, enabled, secret, polling, presentViews, viewOf,
                    includes, writing, writeViewOf, snapshot, request, response>>
InlineTarget(t, c, k, persist) ==
    IF c \in existing \/ ~persist THEN UNCHANGED vars
    ELSE /\ existing' = existing \cup {c} /\ enabled' = enabled \cup {c}
         /\ secret' = [secret EXCEPT ![c] = k]
         /\ writing' = writing \ {c}
         /\ writeViewOf' = [writeViewOf EXCEPT ![c] = NoView]
         /\ polling' = polling \ {c} /\ viewOf' = [viewOf EXCEPT ![c] = View0]
         /\ targetCredential' = [targetCredential EXCEPT ![t] = c]
         /\ targetEnabled' = targetEnabled \cup {t}
         /\ UNCHANGED <<presentViews, includes, snapshot, request, response>>
SaveWriting(c, on, v) ==
    IF c \notin existing \/ (on /\ v \notin presentViews) THEN UNCHANGED vars
    ELSE /\ writing' = IF on THEN writing \cup {c} ELSE writing \ {c}
         /\ writeViewOf' = [writeViewOf EXCEPT ![c] = v]
         /\ UNCHANGED <<existing, enabled, secret, polling, presentViews, viewOf,
                         includes, targetCredential, targetEnabled, snapshot, request, response>>
WritingNext == \E c \in Credentials, on \in BOOLEAN, v \in Views \cup {NoView} :
    SaveWriting(c, on, v)
SharedConfigurationNext ==
    \/ \E c \in Credentials, on, poll \in BOOLEAN, v \in Views, k \in Secrets :
           SaveCredential(c, on, poll, v, k)
    \/ \E c \in Credentials : DeleteCredential(c)
    \/ \E v \in Views, vs \in SUBSET Views : SaveView(v, vs)
    \/ \E v \in Views : DeleteView(v)
    \/ \E t \in Targets, c \in Credentials, on \in BOOLEAN : SaveTarget(t, c, on)
    \/ \E t \in Targets : DeleteTarget(t)
    \/ \E t \in Targets, c \in Credentials, k \in Secrets, persist \in BOOLEAN :
           InlineTarget(t, c, k, persist)
SharedSpec == SharedInit /\ [][SharedConfigurationNext]_vars

WriteAccessSpec == SharedInit /\ [][SharedConfigurationNext \/ WritingNext \/ ReadNext]_vars
                    /\ WF_vars(Handle)
TypeOK ==
    /\ writing \subseteq Credentials /\ writeViewOf \in [Credentials -> Views \cup {NoView}]
    /\ existing \subseteq Credentials /\ enabled \subseteq Credentials
    /\ secret \in [Credentials -> Secrets] /\ polling \subseteq Credentials
    /\ presentViews \subseteq Views /\ viewOf \in [Credentials -> Views]
    /\ includes \in [Views -> SUBSET Views]
    /\ targetCredential \in [Targets -> Credentials \cup {NoCredential}]
    /\ targetEnabled \subseteq Targets /\ snapshot \in Snapshots
    /\ request \in RequestType \cup {NoRequest}
    /\ response \in ResponseType \cup {NoResponse}
ReferencesOK ==
    /\ enabled \subseteq existing /\ polling \subseteq existing /\ writing \subseteq existing
    /\ \A c \in writing : writeViewOf[c] \in presentViews
    /\ \A c \in polling : viewOf[c] \in presentViews
    /\ \A t \in Targets : targetCredential[t] \in existing \cup {NoCredential}
    /\ \A t \in targetEnabled : targetCredential[t] # NoCredential

\* A denied response's snapshot identifier is a model-only marker, not data.
DeniedReadsHaveNoData ==
    response # NoResponse => (~response.authorized => response.returnedViews = {})
ReadStep ==
    IF request # NoRequest /\ request' = NoRequest
    THEN /\ response'.authorized = Authorized(request)
         /\ response'.returnedViews =
                (IF Authorized(request)
                 THEN request.requestedViews \cap grants[request.credential] ELSE {})
         /\ response'.dataSnapshot = snapshot
         /\ UNCHANGED <<configvars, snapshot>>
    ELSE response' = response
ReadsUseCurrentAuthorization == [][ReadStep]_vars
RequestsEventuallyComplete == (request # NoRequest) ~> (request = NoRequest)
TargetEditsPreservePolling == [][
    ((targetCredential' # targetCredential \/ targetEnabled' # targetEnabled)
     /\ UNCHANGED <<existing, enabled, secret, presentViews, viewOf, includes>>)
        => UNCHANGED polling]_vars
InlineCreationHasNoPolling == [][
    \A c \in existing' \ existing :
        (\E t \in Targets : targetCredential'[t] = c)
            => c \notin polling' /\ c \notin writing']_vars
=============================================================================
