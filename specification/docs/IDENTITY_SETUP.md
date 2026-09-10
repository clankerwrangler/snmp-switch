# SNMP identity setup

**Documentation revision 2.1.** This guide defines identity requirements and illustrative configuration fragments. For runnable setup instructions, see the [application README](../../README.md).

## Development and public defaults

| Environment | Effective identity |
|---|---|
| Explicit development overlay | Loads `1.3.6.1.4.1.32473.1`. Credentials and destinations are configured separately. |
| Public release, fresh installation | `identity.sys_object_id` starts null. SNMP setup includes a full numeric OID. |
| Existing operator configuration | Retains the saved value or intentionally unset state across restart. |

The base/default configuration remains unset in source. A development overlay provides the placeholder only when explicitly loaded. Public packaging excludes that overlay from active runtime configuration; it does not depend on manually replacing a hard-coded identity just before publication.

[Public identity fragment](config/identity.public.yaml):

```yaml
identity:
  sys_descr: "Generic SNMP Switch Emulator"
  sys_object_id: null
```

[Isolated-development override](config/identity.development.yaml):

```yaml
identity:
  sys_object_id: "1.3.6.1.4.1.32473.1"
```

These fragments document the intended fields. They do not enable SNMP by themselves, configure authentication, or provide an executable launch command.

## First-run setup

The UI, API, and switch simulation start with identity unset. The SNMP listener remains unbound, and every notification path, including a test-send button, remains disabled. The status is `identity_required`, with the message **SNMP disabled: configure a system object ID**. This setup condition does not fail application health checks.

In **SNMP**:

1. Edit **SNMP identity** and enter the full numeric **System object ID (`sysObjectID`)**. A PEN alone is not a complete value. The field starts empty; no registration certificate or ownership lookup is required.
2. Add a v2c community with **Access**, or add a v3 group and assign users to it. Select independent read/write views and optional source networks in the community or group form. New incoming access is denied by default. The [credential reference](../TECHNICAL_SPECIFICATION.md#71-credentials) describes profiles and shared policy.
3. Open **Configure** in **SNMP service**, verify the listener address/port, and select **Enable SNMP**. Fresh Docker configurations use `0.0.0.0:161`; native configurations use `127.0.0.1:161`. Saved settings take precedence. With Compose, the saved port must match `SWITCHLAB_SNMP_PORT`; native managers use the listener directly. The operating system must permit binding that port.
4. Check **Listener status**. For traps, add a notification target and select or create its credential in the target form. Trap transport does not require incoming access.

Managers connect to the host address, not the container wildcard address. Publishing a host port alone does not enable SNMP.

Input is parsed as an SNMP-compatible numeric OBJECT IDENTIFIER. Any syntactically valid numeric OID is allowed for testing, including values outside the enterprises prefix. A blank form field saves configuration null; malformed nonempty input is rejected without replacing an existing valid value. The API uses `identity.sys_object_id: null` to clear it explicitly.

`sysObjectID.0`, at `1.3.6.1.2.1.1.2.0`, returns the configured OID as an OBJECT IDENTIFIER when SNMP is active. The scalar instance's `.0` is not appended to the configured value. There is no empty string, ASN.1 NULL, omitted-identity mode, or automatic `0.0` fallback. [1]

Clearing the identity stops the listener and sender safely before the clear is acknowledged; it does not stop the simulation. Unsent notification work is discarded with a reason. Events produced while disabled remain local history and are not replayed as traps on activation. Invalid startup configuration leaves SNMP disabled but exposes a repairable setup error.

Changing the advertised OID does not enable vendor-specific MIBs, change notifications or port behavior, flush the FDB, reboot the simulation, or regenerate the SNMPv3 engine identity. Lab scenario imports do not replace deployment identity.

## OID interpretation

RFC 3418 defines `sysObjectID` as an allocated management-implementation identifier in the enterprises subtree. The application accepts arbitrary syntactically valid test values without allocating or checking ownership of them. It has no PEN-registration prerequisite. [1]

PEN 32473 is reserved for documentation, not assigned to this project. RFC 5612 does not expect implementations to transmit it. The development overlay uses it as a test placeholder, and the UI displays a warning whenever it is configured. Public defaults leave identity unset. [2]

## Public release checks

Public packaging starts with unset identity and no active development override, embedded lab database, or saved test identity. Development fixtures are separate from the normal public entrypoint and quick start.

Test the built image with a fresh volume and no overrides. Confirm null effective identity, a functioning UI/simulation, a closed SNMP gate, no notification sends, and a healthy application setup path. Then explicitly configure an operator OID and verify the response type/value with an independent SNMP client. Verify clearing, malformed input, in-flight shutdown, restart/upgrade persistence, and the absence of vendor behavior changes. These acceptance tests are specified in section 12.2 of the [technical specification](../TECHNICAL_SPECIFICATION.md). They are requirements, not test results; the [application validation report](../../docs/VALIDATION.md) records executed checks and their limits.

## References

[1] IETF RFC 3418, SNMPv2-MIB, `sysObjectID`: https://www.rfc-editor.org/rfc/rfc3418.html

[2] IETF RFC 5612, Enterprise Number for Documentation Use: https://www.rfc-editor.org/rfc/rfc5612.html
