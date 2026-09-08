-------------------------- MODULE EntityScenarios --------------------------
EXTENDS EntityInventory
VARIABLE pc
scenarioVars == <<allvars,pc>>
ScenarioInit == EntityInit /\ pc = 0
ScenarioLength == 19
ScenarioNext ==
    \/ (pc = ScenarioLength /\ UNCHANGED scenarioVars)
    \/ (pc = 0 /\ (ManagementTick) /\ pc' = pc + 1)
    \/ (pc = 1 /\ (EditInventory([names EXCEPT ![PhysicalIndex(1)] = "B"],description,TRUE)) /\ pc' = pc + 1)
    \/ (pc = 2 /\ (ReadInventory({PhysicalIndex(1)})) /\ pc' = pc + 1)
    \/ (pc = 3 /\ (EditInventory([names EXCEPT ![PhysicalIndex(1)] = "A"],description,TRUE)) /\ pc' = pc + 1)
    \/ (pc = 4 /\ (ManagementTick) /\ pc' = pc + 1)
    \/ (pc = 5 /\ (ManagementTick) /\ pc' = pc + 1)
    \/ (pc = 6 /\ (ManagementTick) /\ pc' = pc + 1)
    \/ (pc = 7 /\ (EditInventory(names,description,TRUE)) /\ pc' = pc + 1)
    \/ (pc = 8 /\ (EditInventory(names,"B",FALSE)) /\ pc' = pc + 1)
    \/ (pc = 9 /\ (SetMode(1,"shared") /\ UNCHANGED entityvars) /\ pc' = pc + 1)
    \/ (pc = 10 /\ (CreateVlan(10) /\ UNCHANGED entityvars) /\ pc' = pc + 1)
    \/ (pc = 11 /\ (ConfigurePort(1,10,{1,10}) /\ UNCHANGED entityvars) /\ pc' = pc + 1)
    \/ (pc = 12 /\ (SetAdmin(1,FALSE) /\ UNCHANGED entityvars) /\ pc' = pc + 1)
    \/ (pc = 13 /\ (ManagementTick) /\ pc' = pc + 1)
    \/ (pc = 14 /\ (EditInventory([names EXCEPT ![PhysicalIndex(2)] = "B"],description,TRUE)) /\ pc' = pc + 1)
    \/ (pc = 15 /\ (ManagementReboot) /\ pc' = pc + 1)
    \/ (pc = 16 /\ (ReadInventory(PhysicalDomain)) /\ pc' = pc + 1)
    \/ (pc = 17 /\ (ReadCells({},{PhysicalIndex(1)},{})) /\ pc' = pc + 1)
    \/ (pc = 18 /\ (ReadCells({},{},{PhysicalIndex(1)})) /\ pc' = pc + 1)
ScenarioAssertions ==
    /\ pc \in 0..ScenarioLength
    /\ (pc = 2 => (lastChange = 1 /\ names[PhysicalIndex(1)] = "B"))
    /\ (pc = 3 => (DOMAIN observation.rows = {PhysicalIndex(1)} /\ observation.aliases[PhysicalIndex(1)].pointer = <<"ifIndex",IfIndex[1]>> /\ observation.changed = 1))
    /\ (pc = 4 => (lastChange = 1 /\ observation.rows[PhysicalIndex(1)].name = "B"))
    /\ (pc = 7 => (clock = 0 /\ lastChange = 1))
    /\ (pc = 8 => (lastChange = 1))
    /\ (pc = 9 => (description = "A" /\ lastChange = 1))
    /\ (pc = 10 => (lastChange = 1))
    /\ (pc = 11 => (lastChange = 1))
    /\ (pc = 12 => (lastChange = 1))
    /\ (pc = 13 => (lastChange = 1 /\ names[PhysicalIndex(1)] = "A"))
    /\ (pc = 15 => (lastChange = 1 /\ names[PhysicalIndex(2)] = "B"))
    /\ (pc = 16 => (lastChange = 0 /\ clock = 0 /\ names[PhysicalIndex(2)] = "B"))
    /\ (pc = 17 => (DOMAIN observation.rows = PhysicalDomain /\ observation.changed = 0))
    /\ (pc = 18 => (DOMAIN observation.rows = {} /\ DOMAIN observation.interfaces = {} /\ DOMAIN observation.aliases = {PhysicalIndex(1)} /\ observation.aliases[PhysicalIndex(1)].pointer = <<"ifIndex",IfIndex[1]>>))
    /\ (pc = 19 => (DOMAIN observation.rows = {} /\ DOMAIN observation.aliases = {} /\ observation.interfaces[PhysicalIndex(1)].ifIndex = IfIndex[1]))
ScenarioSpec == ScenarioInit /\ [][ScenarioNext]_scenarioVars /\ WF_scenarioVars(ScenarioNext)
Completes == <>(pc = ScenarioLength)
=============================================================================
