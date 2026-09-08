# Documentation changes: revision 2.1

**Date:** 7 September 2026

## Identity and release policy

Public runtime defaults leave `identity.sys_object_id` null. The operator supplies any syntactically valid full numeric OID; no project-owned PEN registration or ownership verification is a publishing prerequisite. Isolated development explicitly loads the documented placeholder `1.3.6.1.4.1.32473.1`, with the RFC 5612 caveat. Public runtime defaults must not inherit it.

The technical specification now defines the SNMP setup gate, configuration validation, UI messaging, listener and sender shutdown when identity is cleared, readiness separation, persistence, and release acceptance cases. Simulation remains available while identity is unset. Identity changes do not select vendor behavior. README, setup guidance, and the object-manifest generator/CSV agree with that policy.

## Changed deliverables

Updated `TECHNICAL_SPECIFICATION.md`, `README.md`, the verification-scope note, and the `sysObjectID` manifest value source. Added `docs/IDENTITY_SETUP.md` and separate illustrative public/development identity fragments. Regenerated package checksums.

## Verification boundary

No `.tla`, `.cfg`, scenario generator, checker runner, or recorded TLC log/result changed. The revision-2 formal-input hashes remain applicable. The identity configuration/gate is not part of those models. This update adds future implementation tests; it neither implements nor claims to have tested a running SNMP agent. The superseded draft named `TECHNICAL_SPEC.md` is not part of this package; use `TECHNICAL_SPECIFICATION.md`.
