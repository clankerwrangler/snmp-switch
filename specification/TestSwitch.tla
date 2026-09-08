--------------------------- MODULE TestSwitch ---------------------------
EXTENDS Switch

OrderedPorts == [i \in 1..Cardinality(Ports) |-> i]
Indices == [p \in Ports |-> 100 + p]
FdbMap == [v \in VLANs |-> 1000 + v]
P0 == CHOOSE p \in Ports : TRUE
E0 == CHOOSE e \in Endpoints : TRUE
M0 == CHOOSE m \in MACs : TRUE
OneDef(m, t) == [slot \in Slots |-> [mac |-> m, tag |-> t]]

RunningState == [InitialState EXCEPT
    !.exists = Endpoints,
    !.sources = [sk \in SourceKeys |-> [mac |-> M0, tag |-> Untagged]],
    !.active = Endpoints,
    !.attached = [e \in Endpoints |-> P0],
    !.mode = [p \in Ports |-> "shared"],
    !.partner = [p \in Ports |-> TRUE],
    !.due = [sk \in SourceKeys |-> FirstDelayTicks]]
RunningInit == s = RunningState

VlanSpec == RunningInit /\ [][VlanNext \/ ActivityNext \/ DispatchTrap]_vars
EditNext ==
    \/ \E e \in Endpoints, defs \in Defs : EditEndpoint(e, defs)
    \/ \E e \in Endpoints, p \in Ports : Move(e, p)
    \/ ActivityNext \/ DispatchTrap \/ Reboot
EditSpec == RunningInit /\ [][EditNext]_vars

MultiInit == s = [RunningState EXCEPT
    !.vlans = VLANs, !.allowed = [p \in Ports |-> VLANs],
    !.sources = [sk \in SourceKeys |->
       [mac |-> M0, tag |-> IF sk[2] = 1 THEN Untagged ELSE 10]]]
MultiSpec == MultiInit /\ [][VlanNext \/ ActivityNext \/ DispatchTrap]_vars

SharedNext ==
    \/ \E e \in Endpoints, p \in Ports : Connect(e, p)
    \/ \E e \in Endpoints : Disconnect(e)
    \/ \E p \in Ports, b \in BOOLEAN : SetPartner(p, b) \/ SetFault(p, b)
    \/ ActivityNext \/ DispatchTrap
SharedSpec == RunningInit /\ [][SharedNext]_vars

LivenessNext == ActivityNext \/ DispatchTrap
ActiveSpec == RunningInit /\ [][LivenessNext]_vars /\ ServiceFairness
AgingInit == s = [RunningState EXCEPT !.active = {},
    !.fdb = [k \in FdbKeys |-> [port |-> P0, ttl |-> AgingTicks]]]
AgingSpec == AgingInit /\ [][LivenessNext]_vars /\ ServiceFairness
DrainInit == s = [RunningState EXCEPT !.traps =
    <<[kind |-> "linkUp", port |-> P0, ifIndex |-> IfIndex[P0],
       admin |-> TRUE, before |-> FALSE, after |-> TRUE]>>]
DrainSpec == DrainInit /\ [][LivenessNext]_vars /\ ServiceFairness
=============================================================================
