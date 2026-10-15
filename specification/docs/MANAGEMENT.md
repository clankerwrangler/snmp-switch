# Local management access

Switch Lab has one local administrator and one optional shared local viewer
credential. These accounts are separate from simulated port-access RADIUS, SNMP
credentials, and scenario data. RADIUS and TACACS+ management login are not
implemented.

## Enable read-only access

1. Sign in as **Local administrator**.
2. Open **Settings → Manage viewer access**.
3. Check **Enable viewer sign-in**, enter a viewer password, and save.
4. In another browser session, select **Local viewer** on the sign-in form.

Viewer access starts disabled. A viewer can browse the same redacted switch
state, collections, event history/live stream, and scenario export as an
administrator, but cannot change simulation, configuration, or security settings.
The visible role, export, and sign-out controls remain available on narrow and
short screens. Hiding controls is presentation only; the API enforces access.

Reopen the viewer-access dialog to rotate the password or disable access. Blank
password means unchanged; disabling retains the stored password. Every accepted
save, including an unchanged save, revokes existing viewer sessions and pending
viewer logins. A concurrent save returns a conflict: reopen the dialog rather
than replaying its secret. Administrator sessions and the original administrator
password are unaffected. Management policy is durable immediately and does not
use **Save configuration**, simulation revisions, reboot, or scenario import.

## Sessions and recovery

Sessions expire eight hours after login; there is no sliding idle extension.
Successful login rotates the calling session token and CSRF token. The process
holds at most 20 sessions. Viewer admission replaces the oldest viewer only; a
full set of administrator sessions returns 429 without revoking any administrator.
Administrator admission prefers the oldest viewer, otherwise the oldest
administrator. Replacing one's eligible existing session does not consume an
additional slot. Process restart clears all sessions.

Storage failure disables viewer access, including live streams and in-flight
logins. The confirmed local administrator credential remains usable to read the
last confirmed state. Failed rollback or an unknown commit blocks further writes;
restart from the existing database/key is the recovery path. A known rollback
preserves the prior viewer policy and sessions. No network-provider fallback or
password reset is implied.

Passwords are Argon2 hashes in encrypted storage, excluded from state, scenario
export, and public policy responses. Password work has four worker-owned slots:
canceling an HTTP request does not release a slot before its worker finishes.
Use HTTPS for remote browser credentials; HTTP remains unencrypted. Existing
CSRF, same-origin write checks, request limits, and secure-cookie configuration
still apply.

## API contract

All paths below are relative to `/api/v1`.

- `GET /auth/status` retains `setup_required`, `authenticated`, and `csrf_token`;
  it adds available `providers`, current `provider`, `role`, and `permissions`.
  Anonymous identity fields are null with an empty permission list.
- `POST /auth/setup {password}` creates the sole administrator as before.
- `POST /auth/login {password, provider?}` selects `local-admin` (default) or
  `local-viewer` explicitly. Bad or disabled credentials return generic 401;
  unknown providers return 422, never a fallback. Setup/login return the CSRF
  token, provider, role, and permissions.
- `POST /auth/logout` is permitted for either authenticated role with CSRF.
- Administrator-only `GET /management/viewer` returns only `enabled`,
  `password_configured`, and independent `generation`.
- Administrator-only `PUT /management/viewer` accepts `expected_generation`,
  `enabled`, and optional `password` (1–1024 characters). Omit the password to
  preserve it; explicit null/empty is invalid. Enabling needs a saved or supplied
  password. An accepted update increments generation; stale generation returns
  409, invalid input 422, denied access/CSRF/Origin 403, and faulted storage 503.

Named permissions are `state:read`, `scenario:export`, `simulation:write`,
`configuration:write`, and `security:write`. Administrator has all five; viewer
has the first two. Logout is a session operation. `switchlab/management.py` owns
the explicit route/action matrix; an unclassified API route denies by default.
Middleware and route dependencies use the framework's route-relative path,
including ASGI `root_path` deployments. Writes recheck the live session inside
the I/O lock, and event streams recheck before each yielded event.

## Future network-provider boundary

The following is a design constraint, not an available feature. A remote provider
would authenticate and then supply a separately validated authorization grant;
missing, conflicting, unsupported, or unmapped grants must deny. A deliberate
local-admin login remains separate from remote failure handling.

For RADIUS web management, [RFC 5607](https://www.rfc-editor.org/rfc/rfc5607.html)
defines Service-Type 18, Framed-Management-Protocol 133 value 2, and named
Management-Policy-Id 135. Named policies map to locally configured permissions;
CLI privilege values and vendor attributes are not universal web roles. A new
transport needs authenticated RadSec and modern TLS guidance, not reuse of the
simulated port-access configuration or weaker response-integrity checks
([RFC 6614](https://www.rfc-editor.org/rfc/rfc6614.html),
[RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html)).

For TACACS+, authentication PASS alone is insufficient: validate the separate
authorization response and mandatory arguments
([RFC 8907](https://www.rfc-editor.org/rfc/rfc8907.html)). Any privilege-level
mapping must be explicitly configurable for exact values 0–15; no universal
viewer/admin meaning or hardcoded 1/15 mapping is assumed. A new secure transport
must implement immediate mutually authenticated TLS 1.3+ on the separate TLS
service, without legacy fallback or body obfuscation
([RFC 9887](https://www.rfc-editor.org/rfc/rfc9887.html)). Library selection,
bounded framing, correlation, duplicate/conflicting arguments, secret-safe
logging, late replies, and transport-negative tests remain future work.
