-------------------------- MODULE ManagementAccess --------------------------
EXTENDS Naturals, FiniteSets, Sequences
\* Finite segment-boundary abstraction of the framework routing helper. Concrete
\* URL/root_path spelling and Origin handling are implementation-test obligations.
RoutePaths == {<<"api", "v1">>, <<"switchlab", "api", "v1">>,
               <<"switchlab-extra", "api", "v1">>, <<"switchlab">>, <<"other">>}
RelativePath(root, path) == IF root # "" /\ Len(path) > 0 /\ Head(path) = root
                           THEN Tail(path) ELSE path
SecurityPath(root, path) == RelativePath(root, path)
IsApi(path) == Len(path) > 0 /\ Head(path) = "api"
Roles == {"viewer", "admin"}
VARIABLES generation, viewerEnabled, session, serial, pending, queued, write, stream, issuance, routeObservation
vars == <<generation, viewerEnabled, session, serial, pending, queued, write, stream, issuance, routeObservation>>
None == [role |-> "none", epoch |-> 0, token |-> 0, authenticated |-> FALSE]
EmptyPending == [role |-> "none", epoch |-> 0, authenticated |-> FALSE]
ReadPermissions == {"state:read", "scenario:export"}
WritePermissions == {"simulation:write", "configuration:write", "security:write"}
Live(s) == s.role \in Roles /\ s.token # 0 /\
           (s.role = "admin" \/ (viewerEnabled /\ s.epoch = generation))
Permissions(s) == IF ~Live(s) THEN {} ELSE
                  IF s.role = "admin" THEN ReadPermissions \cup WritePermissions ELSE ReadPermissions
Init == /\ generation = 0 /\ viewerEnabled = FALSE /\ session = None
        /\ serial = 0 /\ pending = EmptyPending /\ queued = 0
        /\ write = [made |-> FALSE, live |-> FALSE, role |-> "none"]
        /\ stream = [sent |-> FALSE, live |-> FALSE]
        /\ issuance = [accepted |-> FALSE, current |-> FALSE]
        /\ routeObservation = [root |-> "", path |-> <<"other">>, routed |-> FALSE, guarded |-> FALSE]
BeginLogin(r, verified) == /\ r \in Roles /\ pending.role = "none"
                 /\ pending' = [role |-> r, epoch |-> generation, authenticated |-> verified]
                 /\ UNCHANGED <<generation, viewerEnabled, session, serial, queued, write, stream, issuance, routeObservation>>
FinishLogin == /\ pending.role \in Roles /\ pending.authenticated /\ serial < 2
               /\ (pending.role = "admin" \/ (viewerEnabled /\ pending.epoch = generation))
               /\ serial' = serial + 1
               /\ session' = [role |-> pending.role, epoch |-> generation, token |-> serial', authenticated |-> pending.authenticated]
               /\ pending' = EmptyPending
               /\ issuance' = [accepted |-> TRUE, current |-> (pending.role = "admin" \/ (viewerEnabled /\ pending.epoch = generation))]
               /\ UNCHANGED <<generation, viewerEnabled, queued, write, stream, routeObservation>>
RejectLogin == /\ pending.role \in Roles /\ pending' = EmptyPending
               /\ UNCHANGED <<generation, viewerEnabled, session, serial, queued, write, stream, issuance, routeObservation>>
ChangeViewer == /\ generation < 2 /\ generation' = generation + 1
                /\ viewerEnabled' \in BOOLEAN
                /\ UNCHANGED <<session, serial, pending, queued, write, stream, issuance, routeObservation>>
LogoutOrExpire == /\ session' = None
                  /\ UNCHANGED <<generation, viewerEnabled, serial, pending, queued, write, stream, issuance, routeObservation>>
QueueWrite == /\ Live(session) /\ session.role = "admin" /\ queued = 0
              /\ queued' = session.token
              /\ UNCHANGED <<generation, viewerEnabled, session, serial, pending, write, stream, issuance, routeObservation>>
ExecuteWrite == /\ queued # 0
                /\ write' = [made |-> (Live(session) /\ session.role = "admin" /\ queued = session.token),
                             live |-> (Live(session) /\ queued = session.token), role |-> session.role]
                /\ queued' = 0
                /\ UNCHANGED <<generation, viewerEnabled, session, serial, pending, stream, issuance, routeObservation>>
SendEvent == /\ stream' = [sent |-> Live(session), live |-> Live(session)]
             /\ UNCHANGED <<generation, viewerEnabled, session, serial, pending, queued, write, issuance, routeObservation>>
ObserveRoute(root, path) == /\ routeObservation' = [root |-> root, path |-> path,
                                                     routed |-> IsApi(RelativePath(root, path)), guarded |-> IsApi(SecurityPath(root, path))]
    /\ UNCHANGED <<generation, viewerEnabled, session, serial, pending, queued, write, stream, issuance>>
RoutingBoundary == routeObservation.routed => routeObservation.guarded
Presentation == UNCHANGED vars
Next == (\E r \in Roles, verified \in BOOLEAN : BeginLogin(r, verified)) \/ FinishLogin \/ RejectLogin \/ ChangeViewer \/
        LogoutOrExpire \/ QueueWrite \/ ExecuteWrite \/ SendEvent \/ Presentation \/
        (\E root \in {"", "switchlab"}, path \in RoutePaths : ObserveRoute(root, path))
WritesAuthorized == write.made => (write.live /\ write.role = "admin")
StreamsAuthorized == stream.sent => stream.live
ViewerReadOnly == session.role = "viewer" => Permissions(session) \subseteq ReadPermissions
UnknownDenied == "unknown" \notin Permissions(session)
IssuanceCurrent == issuance.accepted => issuance.current
SessionAuthenticated == session.role \in Roles => session.authenticated
LocalRecovery == (pending.role = "admin" /\ pending.authenticated /\ serial < 2) => ENABLED FinishLogin
Spec == Init /\ [][Next]_vars
=============================================================================
