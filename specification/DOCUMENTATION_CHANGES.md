# Documentation changes: revision 2.1

**Date:** 2026-09-07

## Identity and release policy

Public runtime defaults leave `identity.sys_object_id` null. The operator supplies any syntactically valid full numeric OID; no project-owned PEN registration or ownership verification is a publishing prerequisite. Isolated development explicitly loads the documented placeholder `1.3.6.1.4.1.32473.1`, with the RFC 5612 caveat. Public runtime defaults must not inherit it.

The technical specification now defines the SNMP setup gate, configuration validation, UI messaging, listener and sender shutdown when identity is cleared, readiness separation, persistence, and release acceptance cases. Simulation remains available while identity is unset. Identity changes do not select vendor behavior. README, setup guidance, and the object-manifest generator/CSV agree with that policy.

## Documentation updates

Updated `TECHNICAL_SPECIFICATION.md`, `README.md`, the verification-scope note, and the `sysObjectID` manifest value source. Added `docs/IDENTITY_SETUP.md` and separate illustrative public/development identity fragments.

## Verification boundary

Revision 2.1 does not change the revision-2 formal models, configurations, generators, checker runner, or recorded TLC results. The formal-input hashes remain applicable. The identity configuration and setup gate are outside those models. The acceptance cases specify application behavior; they do not establish that it has been tested. Application test results are recorded separately in the [application validation report](../docs/VALIDATION.md).
