# Switch Lab

A vendor-neutral switch management emulator. It includes a Python/FastAPI backend, a TypeScript web interface, SQLite persistence, and a PySNMP agent. It simulates management state; it does not forward Ethernet frames.

![Switch overview](docs/screenshots/overview.png)

## Run with Docker

From this directory, create the encryption key once:

```powershell
# Windows PowerShell
.\scripts\init-key.ps1
docker compose up --build -d
```

```sh
# Linux/macOS (requires OpenSSL)
sh scripts/init-key.sh
docker compose up --build -d
```

Open **http://localhost:8000** and create the administrator password. Any nonempty password up to 1,024 characters is accepted. The setup form is available only until the administrator is created; subsequent access uses that password. There are no default web or SNMP credentials. The generated key is mounted separately from the database volume. Restoring encrypted configuration requires both the database and its key; losing the key makes it unreadable.

The default Compose ports are bound to localhost. The container runs as UID 10001 with all capabilities dropped, a read-only root filesystem, and no host Docker socket. Compose sets `net.ipv4.ip_unprivileged_port_start=161` in the container’s private network namespace so this process can bind UDP 161 without additional capabilities. The host setting is unchanged. Each deployment uses one backend process/worker.

### LAN web access

To allow other devices on the LAN to connect, create a `.env` file next to `compose.yaml` with the host computer's LAN IPv4 address. Replace `192.168.1.50` with an address assigned to that computer, not the container's address:

```dotenv
SWITCHLAB_BIND_ADDRESS=192.168.1.50
```

The host HTTP port is configured separately. For example, add `SWITCHLAB_HTTP_PORT=8080` to `.env` to use **http://192.168.1.50:8080**. Unset or empty values use 8000. The internal HTTP listener remains on port 8000.

After creating the encryption key as described in **Run with Docker**, start or update the deployment:

```sh
docker compose up --build -d
```

On another LAN device, open **http://192.168.1.50:8000** (or the selected HTTP port) and complete administrator setup or sign in. Use the host's LAN address in the browser, not `localhost` or `0.0.0.0`. The UI and API use the same address; no CORS configuration is needed.

`SWITCHLAB_BIND_ADDRESS` controls the host IP address for HTTP and SNMP. Their default host ports are TCP 8000 and UDP 161. Set it to `0.0.0.0` to listen on all host IPv4 interfaces, or to `127.0.0.1` to return to localhost-only access. An unset or empty value also defaults to `127.0.0.1`. Publishing UDP does not enable SNMP; follow **Enable SNMP** separately.

HTTP defaults to host TCP 8000; `SWITCHLAB_HTTP_PORT` can change the published port without changing the container listener. SNMP queries use UDP 161 on both the host and the container by default. Remote connectivity also depends on the host firewall and network routing.

HTTP traffic is unencrypted. HTTPS can be provided by a reverse proxy. Setting `SWITCHLAB_SECURE_COOKIES=1` in `.env` adds the Secure attribute to session cookies; Compose passes this option to the application. Secure cookies require HTTPS for LAN access.

Authenticated API writes require a session cookie and CSRF token. A supplied `Origin` header must match the request URL's scheme, host, and port. Behind a proxy, this comparison depends on the Host header and the forwarded scheme accepted by Uvicorn.

### First simulation

1. Pause the clock for deterministic manual control.
2. Create an endpoint in **Endpoint library** and add a unicast MAC source. An empty source list is also valid.
3. Attach it to a port. Direct ports allow one endpoint; shared ports have an explicit link-partner setting.
4. Advance 1 second. The default source learns in the port's PVID, initially VLAN 1.
5. Inspect **Learned addresses** and **Interfaces**. Edit a source or add VLAN membership to observe the cache rules.

In **Switch overview**, select a port and click **Disconnect** beside an attached endpoint. This removes only that attachment; the saved endpoint and its sources remain in **Endpoint library**. Use **+ Attach endpoint** to reconnect it. On a shared port, other endpoints remain attached.

### Enable SNMP

Open **SNMP & settings**:

1. Enter your full numeric **System object ID (`sysObjectID`)**. The public default is intentionally unset. Changing it affects advertised identity only.
2. Create an **SNMP credential**, then open its **Polling** settings and select **Allow polling**. SNMPv3 supports SHA-256 authentication and AES-128 privacy. SNMPv2c and unprotected v3 modes are labeled as unencrypted.
3. New Docker configurations initialize the listener to `0.0.0.0:161`; managers use the host address and the same port. Native configurations default to `127.0.0.1:161`. Saved or explicitly configured addresses take precedence. **Configure** changes the listener address and port. Native binding requirements are described in **Run natively**.
4. Select **Enable SNMP**. Check **Polling state** before polling.
5. For traps, select **+ Target**, enter a receiver address and event filters, and select an existing credential or **Create new** in the same form. The version selector filters compatible credentials. The destination defaults to UDP 162 and can be changed per target. Trap sending does not require polling access.

```sh
# Compose defaults; supply your configured SNMP credentials.
snmpwalk -v2c -c "$COMMUNITY" -On localhost:161 1.3.6.1.2.1.17.7
snmpget -v3 -u "$SNMP_USER" -l authPriv -a SHA-256 -A "$AUTH_PASS" \
  -x AES -X "$PRIV_PASS" -On localhost:161 1.3.6.1.2.1.1.2.0
```

To use another query port, set the listener port in **SNMP & settings**, set the same `SWITCHLAB_SNMP_PORT` value in `.env`, and run `docker compose up -d`. Compose uses that port on both sides; an unset or empty value uses 161. The saved listener configuration is managed through the UI and is not overwritten by this Compose option.

Credential forms and redacted API responses show only the selected SNMP version's settings. Blank secret fields retain saved secrets on same-version edits. Changing between v2c and v3 requires the new version's credentials and clears the old version's fields.

Polling access is independent of trap destinations and starts disabled for new credentials. A credential can serve both polling and any number of trap destinations. Disabling the credential disables both uses; disabling only **Allow polling** leaves trap destinations available.

Source-IP restrictions and read views apply only to polling. Enabled polling access requires an existing read view, even when the credential itself is disabled. Disabled polling retains its saved view ID and source networks without requiring the view to exist; trap-only credentials need no read views. The polling editor shows a missing saved view until you select an existing one.

The allowed-networks list starts empty, which means no source-IP restriction when polling access is enabled. A nonempty list restricts requests to those CIDRs, such as `192.168.1.20/32`; requests outside the list are rejected. Saved lists remain unchanged until edited or cleared. For LAN polling, managers use the host LAN address on UDP 161 (or the selected query port). Docker NAT may change the source address seen by the agent.

The agent uses one enabled credential per v2c community or v3 username. A shared v3 user uses the same security level and keys for polling and traps. Trap receivers configure that user against the sender’s engine ID, shown in **SNMP service**.

Traps are outbound notifications to the configured receiver, normally on UDP 162. Switch Lab does not receive traps, so Compose has no inbound UDP 162 mapping. Delivery and the source address seen by the receiver depend on container networking and routing.

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

For native LAN access, replace `--host 127.0.0.1` with the host LAN IPv4 address, or `--host 0.0.0.0` for all IPv4 interfaces. Connect from another device using the host LAN address and port 8000. The connection settings described in **LAN web access** also apply. `SWITCHLAB_BIND_ADDRESS` affects Compose only; native Uvicorn uses its `--host` option.

The native SNMP listener defaults to `127.0.0.1:161`. For native LAN polling, select the host LAN IP or `0.0.0.0` in **SNMP & settings**. Native operation has no Compose port translation; managers connect directly to the configured listener. `SWITCHLAB_SNMP_PORT` and `SWITCHLAB_HTTP_PORT` affect Compose only.

Binding port 161 requires the operating system to permit it for the process. A nonroot native Linux process typically cannot bind ports below 1024; a rootless container runtime may also restrict host publication of port 161. In those environments, a higher listener port such as 1161 remains available. Use the same port for the manager and, with Compose, `SWITCHLAB_SNMP_PORT`. A failed SNMP bind is reported separately from HTTP readiness; the application does not fall back to another port.

```sh
# Native alternative, after selecting listener port 1161 and configuring SNMP.
snmpwalk -v2c -c "$COMMUNITY" -On localhost:1161 1.3.6.1.2.1.17.7
```

Environment options:

| Variable | Default | Purpose |
|---|---|---|
| `SWITCHLAB_DB` | `data/switch.db` | Persistent SQLite file |
| `SWITCHLAB_KEY_FILE` | `secrets/config.key` | Separately stored Fernet key |
| `SWITCHLAB_PORT_COUNT` | `24` | Initial fixed port count, 1–256 |
| `SWITCHLAB_SNMP_DEFAULT_HOST` | `127.0.0.1` natively; `0.0.0.0` in the Docker image | Initial SNMP listen address for a fresh configuration; saved settings and explicit startup configuration take precedence. Does not enable SNMP or control Compose host publication. |
| `SWITCHLAB_SECURE_COOKIES` | Unset natively; `0` in Compose | Set `1` to add the Secure cookie attribute (requires HTTPS) |
| `SWITCHLAB_BIND_ADDRESS` | `127.0.0.1` | Compose-only host address for published HTTP and SNMP ports |
| `SWITCHLAB_SNMP_PORT` | `161` | Compose-only SNMP port, equal on host and container; matches the saved listener port |
| `SWITCHLAB_HTTP_PORT` | `8000` | Compose-only HTTP host port, forwarded to container TCP 8000 |
| `SWITCHLAB_CONFIG` | Unset | Explicit JSON overlay for a fresh database only |

`SWITCHLAB_CONFIG=development/identity.json` loads the development overlay on a fresh native database. It supplies the documentation-only placeholder and displays a warning. The development overlay is excluded from Docker builds. Existing operator identity, including an intentionally unset identity, wins over overlays.

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

Credential polling settings are nested as `polling: {enabled, view_id, networks}`. Partial credential or polling updates preserve omitted fields. Target writes accept exactly one of `credential_id` or `new_credential`; the latter contains only a label and protocol credentials. Inline credential and target creation is one transaction, and the response includes both IDs. Deleting a target retains its reusable credential; deleting a referenced credential is rejected.

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
docker run --rm --cap-drop ALL --security-opt no-new-privileges --sysctl net.ipv4.ip_unprivileged_port_start=161 switchlab-test
docker run --rm switchlab-test python scripts/load_case.py

# Isolated Compose bindings, LAN HTTP/session/CSRF, and SNMP source-CIDR checks
# Requires Docker Engine on Linux, Compose v2, and the test image built above.
# Localhost ports 8000/tcp and 161/udp must be free.
docker build --target runtime -t switchlab:0.1.0 .
python scripts/lan_check.py

# Frontend source build (Node 22+, pnpm 11)
cd ui
pnpm install --frozen-lockfile --ignore-scripts
node node_modules/typescript/bin/tsc --noEmit
node node_modules/vite/bin/vite.js build --configLoader native
```

The LAN check creates a disposable Docker bridge and binds only to localhost or that bridge's gateway, never to all host interfaces. Containers have ordinary Docker bridge outbound connectivity. The check exercises UDP 161 and an explicit UDP 1161 alternative with equal host/container ports, then verifies a saved-port transition back to 161. The alternative phase also checks host HTTP 8080 forwarded to container TCP 8000. It checks the container-only port permission and nonroot process constraints. It uses temporary fixture data and removes its containers, volume, and network. This verifies Linux Docker networking in the fixture, not a physical LAN, Docker Desktop NAT, or a host firewall configuration.

The native suite skips Net-SNMP tests when its executables are absent; the Docker test image installs them. [Validation report](docs/VALIDATION.md) records actual executed checks and boundaries. `tests/ui-smoke.cjs` exercises a fresh instance using Playwright; set `SWITCHLAB_TEST_URL` and `SWITCHLAB_TEST_PASSWORD`. Use `SWITCHLAB_BROWSER_CHANNEL=msedge` to test installed Edge, or install Playwright's Chromium. `SWITCHLAB_TEST_SCREENSHOTS` selects the browser test's screenshot output directory.

The [technical specification and formal models](specification/) describe the design. The bundled TLC reports cover finite models; they are not proof of this application. NAC-product integration has not been tested.

Implementation references: [PySNMP agent interfaces](https://docs.lextudio.com/pysnmp/v7.1/examples/v3arch/asyncio/agent/cmdrsp/agent-side-mib-implementations), [IF-MIB](https://www.rfc-editor.org/rfc/rfc2863.html), [Q-BRIDGE-MIB](https://www.rfc-editor.org/rfc/rfc4363.html), [TimeFilter](https://www.rfc-editor.org/rfc/rfc4502.html).

## License

Original Switch Lab code, documentation, models, and project assets are licensed under the [MIT License](LICENSE), copyright 2026 Präludium. Third-party code and dependencies retain their upstream licenses.

The browser bundle includes Vite's modulepreload helper, adapted from es-module-shims. Its copyrights and MIT terms are in [third-party notices](ui/public/assets/THIRD_PARTY_NOTICES.txt). The same notices ship with the packaged UI at `/assets/THIRD_PARTY_NOTICES.txt` and in the Python distribution's license files.

