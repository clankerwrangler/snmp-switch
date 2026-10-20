-------------------------- MODULE SnmpSecurity --------------------------
EXTENDS Naturals, Integers, TLC
\* One credential's selected protocols and effective USM registration. Keys are
\* opaque; concrete cryptography, BER sizing, parsing and encrypted storage need
\* implementation checks. The existing GroupedAccess owner retains group policy.
VARIABLES phase, selected, installed, persisted, observation, policy, sizing
vars == <<phase, selected, installed, persisted, observation, policy, sizing>>
Levels == {"noAuthNoPriv", "authNoPriv", "authPriv"}
Auth == {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}
Priv == {"des", "aes128", "aes192", "aes256"}
Profile(level, auth, priv) == [level |-> level, auth |-> auth, priv |-> priv,
                              authKey |-> "auth-secret", privKey |-> "priv-secret"]
Default == Profile("authPriv", "sha256", "aes128")
Profiles == {Profile(l,a,p) : l \in Levels, a \in Auth, p \in Priv}
Effective(p) ==
    [auth |-> IF p.level = "noAuthNoPriv" THEN "none" ELSE p.auth,
     priv |-> IF p.level = "authPriv" THEN p.priv ELSE "none",
     authKey |-> IF p.level = "noAuthNoPriv" THEN "none" ELSE p.authKey,
     privKey |-> IF p.level = "authPriv" THEN p.privKey ELSE "none"]
Accept(level, authMatches, privMatches) ==
    /\ level = selected.level
    /\ (installed.auth = "none" \/ authMatches)
    /\ (installed.priv = "none" \/ privMatches)
Init == /\ phase = 0 /\ selected = Default /\ installed = Effective(Default)
        /\ persisted = Default /\ observation = [level |-> "authPriv", auth |-> TRUE,
              priv |-> TRUE, accepted |-> TRUE]
        /\ policy \in {"deny", "read-only", "read-write"}
        /\ sizing = [scope |-> 0, budget |-> 0, accepted |-> FALSE]
Select == /\ phase = 0 /\ selected' \in Profiles /\ phase' = 1
          /\ UNCHANGED <<installed, persisted, observation, policy, sizing>>
FailedSave == /\ phase = 1 /\ phase' = 2
              /\ UNCHANGED <<selected, installed, persisted, observation, policy, sizing>>
SaveAndReload == /\ phase = 2 /\ persisted' = selected /\ phase' = 3
                 /\ UNCHANGED <<selected, installed, observation, policy, sizing>>
Install == /\ phase = 3 /\ installed' = Effective(persisted) /\ phase' = 4
           /\ UNCHANGED <<selected, persisted, observation, policy, sizing>>
Receive == /\ phase = 4 /\ phase' = 5
           /\ \E l \in Levels, a \in BOOLEAN, p \in BOOLEAN :
                observation' = [level |-> l, auth |-> a, priv |-> p, accepted |-> Accept(l,a,p)]
           /\ UNCHANGED <<selected, installed, persisted, policy, sizing>>

\* BER length-of-length changes are retained around 127/128 and 255/256.
\* Fixed header content is opaque; Python tests own complete real USM encoding.
Tlv(n) == n + 1 + (IF n < 128 THEN 1 ELSE IF n < 256 THEN 2 ELSE 3)
Digest == [md5 |-> 12, sha1 |-> 12, sha224 |-> 16,
           sha256 |-> 24, sha384 |-> 32, sha512 |-> 48]
ActualLength(n) ==
    LET d == IF selected.level = "noAuthNoPriv" THEN 0 ELSE Digest[selected.auth]
        encrypted == selected.level = "authPriv"
        body == IF encrypted /\ selected.priv = "des" THEN 8 * ((n \div 8) + 1) ELSE n
    IN Tlv(40 + Tlv(30 + Tlv(d) + Tlv(IF encrypted THEN 8 ELSE 0)) + Tlv(body))
Estimate(n) ==
    LET d == IF installed.auth = "none" THEN 0 ELSE Digest[installed.auth]
        encrypted == installed.priv # "none"
        body == n + IF installed.priv = "des" THEN 8 - (n % 8) ELSE 0
    IN Tlv(40 + Tlv(30 + Tlv(d) + Tlv(IF encrypted THEN 8 ELSE 0)) + Tlv(body))
SizeResponse == /\ phase = 5 /\ phase' = 6
    /\ \E n \in {7,8,9,119,120,121,127,128,129,247,248,249,255,256,257} :
          \E b \in {ActualLength(n)-1, ActualLength(n), ActualLength(n)+1} :
        sizing' = [scope |-> n, budget |-> b, accepted |-> Estimate(n) <= b]
    /\ UNCHANGED <<selected, installed, persisted, observation, policy>>
BudgetBoundary == phase = 6 => sizing.accepted = (ActualLength(sizing.scope) <= sizing.budget)

Done == /\ phase = 6 /\ UNCHANGED vars
Next == Select \/ FailedSave \/ SaveAndReload \/ Install \/ Receive \/ SizeResponse \/ Done
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)
TypeOK == /\ phase \in 0..6 /\ selected \in Profiles /\ persisted \in Profiles
          /\ policy \in {"deny", "read-only", "read-write"}
Defaults == phase = 0 => selected.auth = "sha256" /\ selected.priv = "aes128"
FailedSavePreserves == phase = 2 => persisted = Default
SelectionRoundTrips == phase >= 3 => persisted = selected
Registration == phase >= 4 => installed = Effective(selected)
InactiveMaterialAbsent == phase >= 4 =>
    /\ (selected.level = "noAuthNoPriv" => installed.auth = "none" /\ installed.authKey = "none")
    /\ (selected.level # "authPriv" => installed.priv = "none" /\ installed.privKey = "none")
NoPrivacyOnly == installed.priv # "none" => installed.auth # "none"
RequestBoundary == phase >= 5 => observation.accepted =
    (observation.level = selected.level
     /\ (selected.level = "noAuthNoPriv" \/ observation.auth)
     /\ (selected.level # "authPriv" \/ observation.priv))
PolicyUnchanged == [][policy' = policy]_vars
Completes == <>(phase = 6)
=============================================================================
