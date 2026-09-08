------------------------- MODULE EntityInventory -------------------------
EXTENDS TestSwitch

\* Two opaque labels and a four-value clock exercise change, equal-tick writes,
\* and wrap. This clock is independent of the simulation clock in Switch.
VARIABLES names, description, clock, lastChange, observation, chosen
entityvars == <<names, description, clock, lastChange, observation, chosen>>
allvars == <<s, entityvars>>
Labels == {"A", "B"}
Inventory == [i \in PhysicalDomain |->
    [physical |-> EntPhysicalTable[i], name |-> names[i],
     description |-> IF i = 1 THEN description ELSE "Emulated Ethernet port"]]
Snapshot(rows,aliases,interfaces) ==
    [rows |-> [i \in rows |-> Inventory[i]],
     aliases |-> [i \in aliases |-> EntAliasMappingTable[i]],
     interfaces |-> [i \in interfaces |-> IfTable[PhysicalPort(i)]],
     changed |-> lastChange]
EntityInit ==
    /\ Init /\ names = [i \in PhysicalDomain |-> "A"] /\ description = "A"
    /\ clock = 0 /\ lastChange = 0
    /\ chosen = [rows |-> {},aliases |-> {},interfaces |-> {}]
    /\ observation = [rows |-> [i \in {} |-> Inventory[i]],
                       aliases |-> [i \in {} |-> EntAliasMappingTable[i]],
                       interfaces |-> [i \in {} |-> IfTable[PhysicalPort(i)]], changed |-> 0]
EditInventory(newNames, newDescription, persist) ==
    /\ UNCHANGED <<s, clock, observation, chosen>>
    /\ IF ~persist \/ (names = newNames /\ description = newDescription)
       THEN UNCHANGED <<names, description, lastChange>>
       ELSE /\ names' = newNames /\ description' = newDescription /\ lastChange' = clock
ManagementTick ==
    /\ clock' = (clock + 1) % 4
    /\ UNCHANGED <<s, names, description, lastChange, observation, chosen>>
ReadCells(rows,aliases,interfaces) ==
    /\ chosen' = [rows |-> rows,aliases |-> aliases,interfaces |-> interfaces]
    /\ observation' = Snapshot(rows,aliases,interfaces)
    /\ UNCHANGED <<s, names, description, clock, lastChange>>
ReadInventory(selection) == ReadCells(selection,selection \cap PhysicalPorts,{})
IrrelevantChange ==
    /\ (TopologyNext \/ VlanNext \/ ActivityNext \/ DispatchTrap)
    /\ UNCHANGED entityvars
ManagementReboot ==
    /\ Reboot /\ clock' = 0 /\ lastChange' = 0
    /\ UNCHANGED <<names, description, observation, chosen>>
EntityNext ==
    \/ \E ns \in [PhysicalDomain -> Labels], d \in Labels, persist \in BOOLEAN :
           EditInventory(ns, d, persist)
    \/ ManagementTick \/ ManagementReboot
EntitySpec == EntityInit /\ [][EntityNext]_allvars
\* This focused graph reaches reads and concurrent immutable-name snapshots.
\* The separate metadata graph exercises the management-clock transitions.
EntityReadNext ==
    \/ \E rows \in SUBSET PhysicalDomain, aliases,ifs \in SUBSET PhysicalPorts :
           ReadCells(rows,aliases,ifs)
    \/ \E ns \in [PhysicalDomain -> Labels] : EditInventory(ns,description,TRUE)
EntityReadSpec == EntityInit /\ [][EntityReadNext]_allvars
EntityTypeOK ==
    /\ names \in [PhysicalDomain -> Labels] /\ description \in Labels
    /\ clock \in 0..3 /\ lastChange \in 0..3
    /\ chosen.rows \subseteq PhysicalDomain /\ chosen.aliases \subseteq PhysicalPorts
    /\ chosen.interfaces \subseteq PhysicalPorts
    /\ DOMAIN observation.rows = chosen.rows
    /\ DOMAIN observation.aliases = chosen.aliases
    /\ DOMAIN observation.interfaces = chosen.interfaces
    /\ observation.changed \in 0..3
StablePhysicalIdentity == [][
    UNCHANGED <<EntPhysicalTable, EntPhysicalContainsTable, EntAliasMappingTable>>]_allvars
TimestampStep ==
    IF s'.boot # s.boot THEN lastChange' = 0
    ELSE IF names' # names \/ description' # description THEN lastChange' = clock
    ELSE lastChange' = lastChange
EntityTimestampCorrect == [][TimestampStep]_allvars
EntityReadStep ==
    (observation' # observation \/ chosen' # chosen) =>
        /\ observation' = Snapshot(chosen'.rows,chosen'.aliases,chosen'.interfaces)
        /\ UNCHANGED <<s, names, description, clock, lastChange>>
EntityReadsAreSnapshots == [][EntityReadStep]_allvars
=============================================================================
