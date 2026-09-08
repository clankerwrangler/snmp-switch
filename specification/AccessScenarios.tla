-------------------------- MODULE AccessScenarios --------------------------
EXTENDS ReadAccess
VARIABLE pc
allvars == <<vars, pc>>
C1 == CHOOSE c \in Credentials : TRUE
C2 == CHOOSE c \in Credentials \ {C1} : TRUE
T1 == CHOOSE t \in Targets : TRUE
T2 == CHOOSE t \in Targets \ {T1} : TRUE
K1 == Secret0
K2 == CHOOSE k \in Secrets \ {K1} : TRUE
V1 == View0
ScenarioInit == SharedInit /\ pc = 0
ScenarioLength == 30
ScenarioNext ==
    \/ (pc = ScenarioLength /\ UNCHANGED allvars)
    \/ (pc = 0 /\ InlineTarget(T1,C1,K1,FALSE) /\ pc' = pc + 1)
    \/ (pc = 1 /\ InlineTarget(T1,C1,K1,TRUE) /\ pc' = pc + 1)
    \/ (pc = 2 /\ Submit(C1,K1,Views) /\ pc' = pc + 1)
    \/ (pc = 3 /\ Handle /\ pc' = pc + 1)
    \/ (pc = 4 /\ SaveCredential(C1,FALSE,TRUE,V1,K1) /\ pc' = pc + 1)
    \/ (pc = 5 /\ SaveView(V1,Views) /\ pc' = pc + 1)
    \/ (pc = 6 /\ SaveCredential(C1,TRUE,TRUE,V1,K1) /\ pc' = pc + 1)
    \/ (pc = 7 /\ SaveTarget(T2,C1,FALSE) /\ pc' = pc + 1)
    \/ (pc = 8 /\ Submit(C1,K1,Views) /\ pc' = pc + 1)
    \/ (pc = 9 /\ SaveCredential(C1,TRUE,FALSE,V1,K1) /\ pc' = pc + 1)
    \/ (pc = 10 /\ Handle /\ pc' = pc + 1)
    \/ (pc = 11 /\ SaveCredential(C1,TRUE,TRUE,V1,K1) /\ pc' = pc + 1)
    \/ (pc = 12 /\ Submit(C1,K1,Views) /\ pc' = pc + 1)
    \/ (pc = 13 /\ SaveCredential(C1,TRUE,TRUE,V1,K2) /\ pc' = pc + 1)
    \/ (pc = 14 /\ Handle /\ pc' = pc + 1)
    \/ (pc = 15 /\ Submit(C1,K2,Views) /\ pc' = pc + 1)
    \/ (pc = 16 /\ Handle /\ pc' = pc + 1)
    \/ (pc = 17 /\ SaveCredential(C1,FALSE,TRUE,V1,K2) /\ pc' = pc + 1)
    \/ (pc = 18 /\ DeleteView(V1) /\ pc' = pc + 1)
    \/ (pc = 19 /\ SaveCredential(C1,FALSE,FALSE,V1,K2) /\ pc' = pc + 1)
    \/ (pc = 20 /\ DeleteView(V1) /\ pc' = pc + 1)
    \/ (pc = 21 /\ DeleteTarget(T1) /\ pc' = pc + 1)
    \/ (pc = 22 /\ DeleteCredential(C1) /\ pc' = pc + 1)
    \/ (pc = 23 /\ DeleteTarget(T2) /\ pc' = pc + 1)
    \/ (pc = 24 /\ DeleteCredential(C1) /\ pc' = pc + 1)
    \/ (pc = 25 /\ InlineTarget(T1,C2,K1,TRUE) /\ pc' = pc + 1)
    \/ (pc = 26 /\ SaveTarget(T1,C1,TRUE) /\ pc' = pc + 1)
    \/ (pc = 27 /\ InlineTarget(T2,C1,K1,TRUE) /\ pc' = pc + 1)
    \/ (pc = 28 /\ InlineTarget(T1,C1,K1,TRUE) /\ pc' = pc + 1)
    \/ (pc = 29 /\ DeleteTarget(T2) /\ pc' = pc + 1)
ScenarioAssertions ==
    /\ pc \in 0..ScenarioLength
    /\ (pc = 1 => (existing = {} /\ targetCredential[T1] = NoCredential))
    /\ (pc = 2 => (existing = {C1} /\ polling = {} /\ NotificationAllowed(T1)))
    /\ (pc = 4 => (~response.authorized /\ response.returnedViews = {}))
    /\ (pc = 5 => (enabled = {C1} /\ polling = {}))
    /\ (pc = 7 => (polling = {C1} /\ NotificationAllowed(T1)))
    /\ (pc = 10 => (NotificationAllowed(T1)))
    /\ (pc = 11 => (~response.authorized /\ response.returnedViews = {}))
    /\ (pc = 15 => (~response.authorized /\ response.returnedViews = {}))
    /\ (pc = 17 => (response.authorized /\ response.returnedViews = Views))
    /\ (pc = 18 => (~NotificationAllowed(T1) /\ polling = {C1}))
    /\ (pc = 19 => (V1 \in presentViews))
    /\ (pc = 21 => (presentViews = {} /\ viewOf[C1] = V1))
    /\ (pc = 22 => (C1 \in existing))
    /\ (pc = 23 => (C1 \in existing /\ targetCredential[T2] = C1))
    /\ (pc = 25 => (existing = {}))
    /\ (pc = 26 => (existing = {C2} /\ NotificationAllowed(T1) /\ polling = {}))
    /\ (pc = 27 => (targetCredential[T1] = C2))
    /\ (pc = 28 => (existing = Credentials /\ polling = {}))
    /\ (pc = 29 => (targetCredential[T1] = C2))
    /\ (pc = 30 => (existing = Credentials))
ScenarioSpec == ScenarioInit /\ [][ScenarioNext]_allvars /\ WF_allvars(ScenarioNext)
Completes == <>(pc = ScenarioLength)
=============================================================================
