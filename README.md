# Switch Lab

A vendor-neutral switch management emulator. It includes a Python/FastAPI backend, a TypeScript web interface, SQLite persistence, and a PySNMP agent. It simulates management state; it does not forward Ethernet frames.

![Switch overview](docs/screenshots/overview.png)

## Run with Docker

From this directory, create the encryption key once:

```powershell
# Windows PowerShell
.\scripts\init-key.ps1
docker compose up --build -d
docker compose logs switchlab
```

```sh
# Linux/macOS (requires OpenSSL)
sh scripts/init-key.sh
docker compose up --build -d
docker compose logs switchlab
```

Open **http://localhost:8000**. Use the setup token printed in the first-run logs to create the administrator password (at least 12 characters). There are no default web or SNMP credentials. The generated key is mounted separately from the database volume. Back up both; losing the key makes the encrypted configuration unreadable.

The default Compose ports are bound to localhost. The container runs as UID 10001 with all capabilities dropped, a read-only root filesystem, and no host Docker socket. Keep one backend process/worker per deployment.

### First simulation

1. Pause the clock for deterministic manual control.
2. Create an endpoint in **Endpoint library** and add a unicast MAC source. An empty source list is also valid.
3. Attach it to a port. Direct ports allow one endpoint; shared ports have an explicit link-partner setting.
4. Advance 1 second. The default source learns in the port's PVID, initially VLAN 1.
5. Inspect **Learned addresses** and **Interfaces**. Edit a source or add VLAN membership to observe the cache rules.

### Enable SNMP

Open **SNMP & settings**:

1. Enter your full numeric **System object ID (`sysObjectID`)**. The public default is intentionally unset. Changing it affects advertised identity only.
2. Create a polling credential. SNMPv3 supports SHA-256 authentication and AES-128 privacy. SNMPv2c and unprotected v3 modes are labeled as unencrypted.
3. Configure the listener. **Inside Docker, select `0.0.0.0:1161`** so the published UDP port reaches it. For native localhost use, retain `127.0.0.1:1161`.
4. Explicitly enable SNMP. Check the effective status before polling.
5. For traps, create a separate credential with purpose **Notification only**, then add a destination and event filters.

```sh
# Supply your own values; there is no implicit public community.
snmpwalk -v2c -c "$COMMUNITY" -On localhost:1161 1.3.6.1.2.1.17.7
snmpget -v3 -u "$SNMP_USER" -l authPriv -a SHA-256 -A "$AUTH_PASS" \
  -x AES -X "$PRIV_PASS" -On localhost:1161 1.3.6.1.2.1.1.2.0
```

Choose source CIDRs for your actual deployment. Docker NAT may change the source observed by the agent. Remote exposure requires deliberately changing Compose's host bindings and using HTTPS through a trusted reverse proxy; set `SWITCHLAB_SECURE_COOKIES=1` for HTTPS. Configure proxy forwarding only for your trusted proxy. Published HTTP and UDP ports, trap source addresses, and source-CIDR policy must be verified on the deployment network.

Clearing identity closes the SNMP listener and cancels unsent notifications before the API acknowledges the change. UI, API, and simulation remain available. Restoring identity does not replay disabled-period link events.

## Run natively

Python 3.12+ is required. The compiled UI is included, so Node.js is only needed when changing it.

```sh
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: . .venv/bin/activate
python -m pip install .
python scripts/init.py
python -m uvicorn switchlab.api:app --host 127.0.0.1 --port 8000 --workers 1
```

Environment options:

| Variable | Default | Purpose |
|---|---|---|
| `SWITCHLAB_DB` | `data/switch.db` | Persistent SQLite file |
| `SWITCHLAB_KEY_FILE` | `secrets/config.key` | Separately stored Fernet key |
| `SWITCHLAB_PORT_COUNT` | `24` | Initial fixed port count, 1–256 |
| `SWITCHLAB_SETUP_TOKEN` | Random on first boot | Optional explicit bootstrap token; never a default password |
| `SWITCHLAB_SECURE_COOKIES` | Unset | Set `1` when serving via HTTPS |
| `SWITCHLAB_CONFIG` | Unset | Explicit JSON overlay for a fresh database only |

For isolated development only, explicitly set `SWITCHLAB_CONFIG=development/identity.json` on a fresh native database. This supplies the documentation-only placeholder and displays a warning. The development overlay is excluded from Docker builds. Existing operator identity, including an intentionally unset identity, wins over overlays.

## API

Interactive OpenAPI documentation is at `/docs`; the exported schema is [docs/openapi.json](docs/openapi.json). Operational routes are under `/api/v1`. Authenticate using `/auth/setup` or `/auth/login`, retain the HTTP-only session cookie, and send the returned CSRF token in `X-CSRF-Token` for writes.

Mutations require either `expected_revision` (the complete state revision) or `expected_configuration_revision` (the configuration revision). The latter lets a form remain open while simulation time advances, while detecting conflicting configuration edits. Both are returned by `/state`. Rejected commands leave state and notifications unchanged. Optional `Idempotency-Key` headers retain the most recent 256 command results in the database.

Example request body for `POST /api/v1/endpoints`:

```json
{
  "expected_configuration_revision": 0,
  "name": "Workstation",
  "active": true,
  "sources": [
    {"mac": "02:00:00:00:00:10", "tag": "untagged", "initial_delay_ms": 1000, "interval_ms": 30000}
  ]
}
```

Use the current revision, not the example value. Endpoint tags may reference absent VLANs; those observations are rejected until the VLAN exists and is admitted. Source replacement preserves explicitly supplied source IDs. Credential updates merge omitted secret fields; returned values expose only secret-presence flags.

Scenario exports contain lab state and fixed port IDs, not identity, SNMP settings, credentials or targets. Imports restore a baseline for the same switch inventory. Invalid imports are atomic failures. Exports are portable between backups of that deployment; importing a different deployment's port UUIDs is rejected.

## Architecture and behavior

- `switchlab/engine.py`: serialized copy/validate/persist/publish transactions; immutable job identities; chronological source scheduling and aging; selective flushing; VLAN 1 fallback; bounded event history and outbox.
- `switchlab/mib.py`: all 72 manifest definitions accounted for: 68 readable object definitions and four non-readable indexes. Typed scalar/table projections, numeric ordering, fixed MAC indexes, PortList encoding, legacy FDB scope, and single-traversal TimeFilter behavior.
- `switchlab/snmp.py`: one snapshot and current authorization per PDU; v2c/v3 reads; SET rejection; bounded bulk responses; persistent USM identity/boots; standard notifications.
- `switchlab/storage.py`: encrypted configuration and security state with transactional event/outbox metadata. Restart clears operational learning and restarts source delays.
- `switchlab/api.py`: administrator setup, Argon2 passwords, protected sessions, CSRF, request limits, revision checks, scenario import/export and event streaming.
- `ui/src/`: responsive operator interface. Polls the authoritative API; it contains no second simulation.

FDB capacity defaults to 16,384. New keys are rejected at capacity without evicting unrelated rows; existing keys still refresh/move. Event history retains 2,000 records. Notification queue capacity defaults to 1,024; overflow drops new items. A manual step may process at most 200,000 source observations; larger steps return 429 and should be split into smaller durations.

UDP notifications are best effort. “Sent” records a successful local send attempt, not receipt. A crash between send and recording its outcome can leave delivery uncertain. No informs, SNMP SET, vendor extensions, multiple switches, RADIUS, or packet forwarding are implemented.

## Build and verify

```sh
python -m pip install '.[test]'
python -m pytest -q

# Includes independent Net-SNMP polling and authenticated trap reception
docker build --target test -t switchlab-test .
docker run --rm --cap-drop ALL --security-opt no-new-privileges switchlab-test
docker run --rm switchlab-test python scripts/load_case.py

# Frontend source build (Node 22+, pnpm 11)
cd ui
pnpm install --frozen-lockfile --ignore-scripts
node node_modules/typescript/bin/tsc --noEmit
node node_modules/vite/bin/vite.js build --configLoader native
```

The native suite skips Net-SNMP tests when its executables are absent; the Docker test image installs them. [Validation report](docs/VALIDATION.md) records actual executed checks and boundaries. `tests/ui-smoke.cjs` exercises a fresh instance using Playwright; set `SWITCHLAB_TEST_URL`, `SWITCHLAB_TEST_TOKEN` and `SWITCHLAB_TEST_PASSWORD`. Use `SWITCHLAB_BROWSER_CHANNEL=msedge` to test installed Edge, or install Playwright's Chromium.

The [technical specification and formal models](specification/) describe the design. The bundled TLC reports cover finite models; they are not proof of this application. NAC-product integration has not been tested.

Implementation references: [PySNMP agent interfaces](https://docs.lextudio.com/pysnmp/v7.1/examples/v3arch/asyncio/agent/cmdrsp/agent-side-mib-implementations), [IF-MIB](https://www.rfc-editor.org/rfc/rfc2863.html), [Q-BRIDGE-MIB](https://www.rfc-editor.org/rfc/rfc4363.html), [TimeFilter](https://www.rfc-editor.org/rfc/rfc4502.html).

