# Extending HostSeal

HostSeal is extensible in specific, named places and closed everywhere else. This document lists both,
because "where can I add things" and "where will my pull request be rejected" are the same question
and it is rude to answer only the first half.

The governing rule: **extension means adding an implementation, never editing a `switch`.** If adding
support for something requires you to modify a type switch, an `if` chain, or a lookup table in the
core, that is a missing seam and a legitimate bug report.

The governing constraint: **nothing added at run time may cause code to run on a managed host.** Every
open seam below either runs on the operator's machine, runs in the server, or is compiled into the
agent from source.

---

## Open seams

### `collect.Platform` — an operating-system family

```go
// Platform is the per-family behaviour that fact collection depends on.
type Platform interface {
    Identify() (Distribution, error)
    UpgradablePackages(ctx context.Context) ([]Package, error)
    SecurityOrigins() []string
    RebootRequired(ctx context.Context) (RebootReport, error)
    SubscriptionStatus(ctx context.Context) (*Subscription, error) // nil where not applicable
    Services(ctx context.Context) ([]Unit, bool, error)
    KernelRelease() string
}
```

Most of these take a context, because they start a process — `apt-get`, `needrestart`, `pro`, and the
Windows update scan — and a heartbeat that could not be cancelled would hold the agent open behind a
hung package manager. `RebootRequired` returns a `RebootReport` rather than a bare boolean and a list,
because the answer has four parts: whether a reboot is needed, which packages need it, which services
still hold replaced libraries, and whether the scan that produced that last list could see every process.

The last two arrived with the second operating system, and the first of them was a bug this document
already predicted. `Gather` used to call `collect.ListUnits` directly, which is systemd over D-Bus — a
type switch waiting to happen the moment anything else had services. `KernelRelease` is on the seam for
the same reason: a package-level reader of `/proc/sys/kernel/osrelease` would have returned `"unknown"`
for every Windows host for ever, which is a silent wrong answer of exactly the class this interface
exists to name.

There is an optional half, as there is for collectors:

```go
// PolicyGatedPackages is for a platform whose package enumeration is itself expensive or privileged.
type PolicyGatedPackages interface {
    PackagesPermittedBy(p policy.Policy) (bool, string)
}
```

Implement it where listing updates is not free. On Linux it is `apt-get --just-print` — local,
milliseconds, changes nothing — so neither Linux platform implements it and `Gather` asks them nothing.
On Windows the same question is a network conversation that changes state under `%windir%` and takes
minutes, which makes it privileged work wearing a read class; `[updates] scan` is the key that refuses
it. A platform that does not implement this behaves exactly as it did before the interface existed.

Add a file under `internal/collect/platform/`, implement the interface, and return it from that
package's `Detect`. `Detect` is build-tagged rather than switching on `runtime.GOOS`: on Linux it parses
os-release and chooses a distribution family, on Windows it asks the kernel. HostSeal ships `ubuntu`,
`debian` and `windows`.

Four differences between families are already known to produce **silent wrong answers** rather than
errors, so any new implementation must state what it does about each:

| Difference | The silent failure |
| --- | --- |
| Security-origin patterns (`${distro_id}:${distro_codename}-security` on Ubuntu, `origin=Debian,codename=${distro_codename}-security` on Debian) | The security/regular split is quietly wrong — the one number the product exists to show |
| `/var/run/reboot-required` is an Ubuntu `update-notifier` convention, not a Debian one | Reboot-required silently reads as `false` forever. Treat the marker file as one input, never as the answer; on Debian, `needrestart` is the reliable source |
| Ubuntu Pro and Livepatch do not exist on Debian | An empty amber "unknown" badge on every Debian host teaches operators to ignore the dashboard. Render "not applicable" |
| `apt-check` lives in `update-notifier-common`, absent from minimal images of both | Zero upgrades reported on exactly the hosts most likely to be forgotten. The simulation parse is the primary path; `apt-check` is an optimisation |

### `collect.Collector` — a new fact

```go
// Collector produces one named section of a host's fact report.
type Collector interface {
    Name() string
    Collect(ctx context.Context) (any, error)
}
```

Collectors are read-only by construction and run as the unprivileged `hostseal` user with no
capabilities. A collector that needs root is not a collector; it is a request for a new intent, which
is a different and much longer conversation.

Add a file under `internal/collect/collector` with a `Register` call in its `init`, and nothing else in
the codebase learns about it. Output appears under the collector's name in the facts document's `extra`
object. HostSeal ships three.

`network` reports interfaces, their MTUs, their IP addresses and their MAC addresses. It is also what
justifies `AF_NETLINK` in the systemd unit's `RestrictAddressFamilies`: `net.Interfaces` uses a netlink
socket on Linux and returns nothing without it, silently. It is worth reading for the mistake it used to
be: it shipped without a `PolicyGated` half, which was an omission rather than a decision and became
indefensible the moment it gained hardware addresses — the rule below is not "gate the revealing ones",
it is "gate the ones a host might reasonably decline", and a section nobody can refuse is one no document
can honestly describe.

`resources` reports capacity and how much of it is gone — filesystems, memory, processor count and load,
per-interface traffic — from `/proc` and `statfs(2)`. It is the one to read before adding a collector
whose numbers move, because the interesting problem there is not the reading. Every volatile figure it
reports is **banded**, coarsely enough that a host whose state has not changed produces byte-identical
bytes and keeps sending a digest rather than a full report. A section that ignores this does not fail;
it works perfectly and quietly turns [`PROTOCOL.md` §4.1](PROTOCOL.md#41-digest-first) off for every host
that carries it, which that section calls a production incident rather than an inefficiency. Pick the
band from the granularity at which the number is worth acting on, name it in a constant with the reason,
and round **down** so the reported figure is never higher than the truth.

`containers` reports Docker container state from `/proc` and the cgroup tree, and it is the one that
shows what the optional half of this seam is for:

```go
// PolicyGated is the optional half of the Collector seam, for a section a host may refuse to send.
type PolicyGated interface {
    PermittedBy(p policy.Policy) bool
}
```

Implement it when a section is a disclosure a host might reasonably decline, and `Gather` will ask
before collecting. Most facts are not: a unit list and a package count say nothing a hostname does not.
Container state is, which is why `[containers] report` ships `false`. A refused section is **absent**
rather than empty, and the host's policy travels in the same heartbeat, so a client can say "this host
does not report containers" rather than "this host has none".

A gate does not have to ship off, and `[resources] report` ships **on**. The two questions are separate:
whether a host should be able to decline a section, and what it should do when nobody has said. Capacity
gets a gate because mount points are filesystem layout and some fleets will not want to send it; it
defaults on because a disk about to fill up is what a fleet agent was installed to answer, which is the
same argument `[updates] scan` makes. What a default-on gate does owe the reader is the fourth case:
`Parse` decodes over `Default`, so a policy file written before the key existed keeps the shipped value —
without that, adding a default-on key would silence every host in every existing fleet on the day its
agent was upgraded. `Closed()` is the exception in the other direction and takes the less-disclosing
value whatever the default is, because a host whose policy file does not parse has said nothing.

`[network] report` ships on for a third reason, which is the one to reach for when adding a gate to a
section that already exists: it predates its own key. A default of false there would not be caution, it
would silently take a fact away from every fleet on the day its agents were upgraded — so a gate added
after the fact defaults to what the section already did, and the argument about disclosure decides
whether the key exists rather than which way it points.

The policy is asked of, not read by, the collector. A collector that called `policy.Load` itself would
be reading that file a second time on its own schedule, with no guarantee of agreeing with the policy
the rest of the agent is enforcing at that moment — and a fact reported under a permission that was
withdrawn two minutes ago is a permission that was not withdrawn.

Keep the output bounded — see [`PROTOCOL.md` §4.5](PROTOCOL.md#45-bounds) — and stable. The name becomes
a key in a document that is digested, stored and compared, so renaming one makes every host in a fleet
look changed on the same afternoon. A collector that fails leaves its section absent rather than empty:
"no network interfaces" is a very different claim from "the network collector failed".

### `signing.Signer` — a key backend

```go
// Signer produces a detached signature over the canonical job payload.
type Signer interface {
    KeyID() string
    Algorithm() Algorithm
    Public() crypto.PublicKey
    Backend() string
    Sign(ctx context.Context, payload []byte) ([]byte, error)
    Close() error
}
```

Implemented today:

| Backend | Reference scheme | What holds the key |
| --- | --- | --- |
| `file` | `file:`, or any path | A passphrase-protected key file: scrypt over the passphrase, NaCl secretbox over a PKCS#8 key |
| `pkcs11` | `pkcs11:` | Any PKCS#11 module — YubiKey PIV, Nitrokey and SoftHSM through one implementation |
| `kms` | `awskms:`, `gcpkms:`, `azurekms:` | AWS KMS, Google Cloud KMS or Azure Key Vault, over their REST APIs and no vendor SDK |

The middle column has more entries than the first on purpose: one backend registers three schemes,
because `awskms:`, `gcpkms:` and `azurekms:` are what cosign already uses and an operator who has
signed a container image has seen them. A single `kms:` would put five colons in an AWS reference and
make the reader count them.

Specified and not yet written: `sshagent` (including FIDO2 `ed25519-sk`) and `gpgagent`. Deliberately
no vendor is hard-coded: a PKCS#11 key is named with an RFC 7512 URI, which is what every other tool
that talks to a token already speaks, and a cloud is named by its own scheme rather than by a flag.

A backend registers itself with `internal/signing/backend` from its `init`, and `hostseal` blank-imports
the ones it ships — the shape `database/sql` uses. `--key` takes a reference, and a reference selects a
backend if and only if it begins with a registered scheme and a colon; everything else is a path, so
`--key ~/.config/hostseal/ops.key` keeps meaning what it always did. The parser touches no filesystem:
a rule that depended on what happened to exist on disk would mean different things on two machines.

The registry lives one directory below `internal/signing` so that the agent and the control plane, which
import the verifier, link no backend at all — and after `pkcs11`, which loads a shared library an
operator names, that is asserted rather than reviewed for. See
`TestGuaranteeNoManagedHostBinaryLoadsASigningBackend`. It is not the plugin loader this document
refuses below: that refusal is about the agent, and this is the operator's own tool.

**A backend ships only when `hostseal sign` can exercise it end to end.** Signing is the one path where
being wrong is unrecoverable: a signature no host accepts arrives as a trust anchor that has stopped
working, days later, on machines nobody can easily inspect. An implementation that nothing drives is
untested code in the worst place to have it, so a backend and the means to use it land together. The
table above is the only list of which ones exist —
`TestTheBackendsThisBuildLinksAreTheOnesTheDocumentationLists` holds it to what `hostseal` actually
links, because the same list restated in a doc comment went two releases out of date before anybody
noticed.

**A backend verifies its own signature before returning it.** Every remote key store gets one encoding
detail differently — a PKCS#11 token returns ECDSA as a raw `r‖s` pair, Azure returns it base64url and
raw, AWS needs the whole payload rather than a digest for Ed25519 — and each mistake produces a
well-formed signature that no host accepts, reported days later as a trust anchor that has stopped
working. `signing.SelfCheck` turns the whole class into an error at the terminal of the person who ran
the command.

**This is the seam that is safest to leave open, and it is worth understanding why: the verifier never
changes.** The agent only ever sees a public key and a signature over a canonical payload. It cannot
learn — and does not care — which backend produced the signature. Adding a backend is therefore purely
client-side and cannot widen the agent's attack surface by even one branch.

Two algorithms exist on the wire: `ed25519` (the default) and `ecdsa-p256`. ECDSA is present because
YubiKey PIV before firmware 5.7.0 and several cloud key stores cannot do Ed25519 at all. Carrying one
algorithm tag now is much cheaper than rewriting every host's `trusted-signers` later, and it is not
hypothetical: **Azure Key Vault has no EdDSA algorithm and no `OKP` key type**, so `ecdsa-p256` is the
only thing a Key Vault key can be. AWS KMS and Cloud KMS can do both, and AWS's Ed25519 has a limit
worth knowing about — pure Ed25519 needs `MessageType: RAW`, which caps a payload at 4096 bytes.

A backend reports what a key can do rather than assuming: the algorithm comes from the key itself, and
one this build cannot carry fails when the key is opened, with a message naming what it actually is.

Whatever the backend, the audit log and the UI always record **which** signer authorised a job:
`ops-laptop (file)` must read differently from `ops-yubikey-1 (PKCS#11)`.

### `notify.Sink` — an outbound notification

```go
// Sink delivers an event to something outside HostSeal.
type Sink interface {
    Name() string
    Deliver(ctx context.Context, ev Event) error
}
```

This is the one seam the **server** may extend at run time: an operator can configure a webhook
without recompiling. That is safe because of the asymmetry that governs the whole design —
**sinks send data out; nothing sends code in.**

Three sinks exist: the tenant webhook, SMTP for the recipients an alert rule names, and the browser —
which is not a `Sink` at all but a server-sent-events stream held open by an operator's tab, because a
subscription that vanishes when somebody closes a laptop is not something the `Deliver` contract can
describe. What is durable is neither of those: every event is written to the tenant's inbox before any
delivery is attempted, so best-effort delivery *looks* best-effort rather than turning into silence.

What a sink may deliver is **closed at compile time**, like the intent catalogue and for a related
reason. `notify.Kind` is an unexported-in-spirit set of constants with a test that fails when the set
changes, because a kind is a word operators build webhook filters, mail rules and dashboards on: one
handler spelling it `job.fail` and another `job.failed` is two dashboards that each miss half the
events. Adding a member means editing `internal/notify/kinds.go` and the expected set in
`notify_test.go` in the same commit.

Alerting rules sit on top of the sinks and add nothing to what may leave: a rule decides *which*
events are worth interrupting somebody for and *who*, never what may be done. **A rule produces a
notification. A rule never produces a job** — there is deliberately no code path that could, and
"auto-remediate when more than five updates are pending" is a different feature with a different
argument, not a checkbox on this one.

### `auth.Provider` — operator authentication

```go
// Provider authenticates a human operator against the control plane.
type Provider interface {
    Name() string
    Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}
```

Local accounts, OIDC, SAML. This governs access to the *control plane*, and it is worth being clear
that it is not a security boundary for the guarantee: a compromised administrator account is
explicitly inside the threat model of [`SECURITY.md` §1](SECURITY.md#1-the-guarantee) and still cannot
run code on a host.

Two implementations ship, and they compose through `auth.Chain` rather than replacing one another:

| Implementation | The credential | What it is for |
| --- | --- | --- |
| `Accounts` | an address and a password, then a session cookie | people. It is what makes the audit trail name somebody and the two-person approval rule satisfiable. |
| `APITokens` | a token belonging to one account, `Authorization: Bearer hsl_…` | scripts. It authenticates *as* that account, so nothing downstream has to know which of the two a request arrived on. |

There used to be a third, `StaticToken`: one shared bearer token per fleet, configured with a flag. It
is gone rather than deprecated, for the reasons [`SECURITY.md`
§4.5](SECURITY.md#45-who-the-operator-is) gives.

`APITokens` reports the same `Name()` as `Accounts`, which is the one surprising line in the package and
is load-bearing. `Principal()` is provider-qualified and is compared for equality by the approval rule,
so a token that called itself something else would make one person look like two. What distinguishes
them is `Identity.Credential`, which is deliberately *not* part of the principal: who did something and
what they were holding are two questions, and only the first is an identity. Exactly one group of routes
reads it — `/api/v1/account`, which refuses a token, because one that could mint another with no expiry
would survive its own revocation.

Both reach `internal/store`, which is why this package does — a property of local accounts rather than
of the seam, since an OIDC implementation would reach an issuer instead. A third implementation adds a
type here and an argument to the `auth.Chain` call in `cmd/hostseal-server`; `Chain` asks every member,
so adding one cannot silently shadow another. What it must do is set `Identity.Provider`, for the reason
above, and `Identity.Credential` — an OIDC or SAML implementation produces a session like any other,
because what that field distinguishes is not where the identity came from but whether a person is at the
other end of the request. [`SECURITY.md` §4.5](SECURITY.md#45-who-the-operator-is) is the specification
for what the shipped pair actually do.

**`Identity.Subject` must name one person.** It is the half of `Principal()` that distinguishes
operators, and the two-person approval rule is `created_by <> approver`, evaluated as a string
comparison in one `UPDATE`. A provider returning a group, a role, or any subject two people share makes
that comparison false for every pair of them — so `second_person` becomes unsatisfiable, quietly and
fail-closed: the job sits awaiting approval, the operator who switched the rule on believes a second
person is reviewing destructive work, and no second person can. `StaticToken` was exactly that shape,
which is why it is gone rather than configurable. An OIDC `sub` claim is a per-person subject; a group
claim is not, and belongs in `Display` or nowhere.

### The Angular application

Standalone components and lazily loaded routes, in `web/src/app`. There is no panel registry: it would
be indirection without a reader, and it can be introduced when there is a second thing to register.
Adding a page means a component and a route.

There is one exception, and it matters because getting it wrong produces a page that works for whoever
wrote it and for nobody else. A route the shell must render *without* a session is a third
thing: it carries `data: { public: true }`, which is what the shell reads to suppress the toolbar and
the sign-in gate. The flag lives on the route rather than being derived from its path, because a shell
matching on the string `'board'` is a check that survives a rename by continuing to compile. `/board`,
the published wallboard, is the only one today; what such a route may show, and why it is a fixed-shape
projection rather than a page that reads whatever the API returns, is
[`SECURITY.md` §4.6](SECURITY.md#46-the-wallboard-and-its-link).

One piece of it is worth knowing before you copy it. The live event feed reads the stream with `fetch`
and a `ReadableStream`, not with `EventSource`, because `EventSource` cannot set a request header —
and the browser's credential needs one. The cookie itself travels on its own, but the control plane
refuses a cookie-authenticated request without `X-HostSeal-Session`, which is the cross-site request
forgery defence and is not something `EventSource` can supply. The usual workaround puts a credential
into the query string, and from there into every access log and proxy trace it passes. The cost is the
reconnect loop in `core/event-stream.ts`, which `EventSource` would otherwise have supplied.

The bundle carries a size budget in `angular.json`, and it is worth knowing which kind it is. The
warning threshold is a tripwire for growth somebody should look at, not a limit: the error threshold is
a long way above it. Raising the warning is a normal thing to do when a page adds a real feature, and
raising it without noticing what grew is not — the enrolment panel on the fleet page moved it once, for
about a kilobyte, and the check that made that a decision rather than an accident was reading which
module the kilobyte came from. It came from a Material expansion panel, for one disclosure widget, and
a native `<details>` does the same job for nothing.

Whatever it grows into, the UI reads the API and can reach no host directly — it has no credential that
any agent would accept, because agents authenticate the *control plane* by certificate and authorise
work by signature.

---

## Closed on purpose

Each of these has its reasoning in [`SECURITY.md`](SECURITY.md). They are listed again here because
this is the document people read *before* opening the pull request.

### The intent catalogue

Not a registry, not configurable, not loadable. New intents arrive as source changes in a reviewed
pull request, and the `guarantee` CI workflow fails until the expected-set literal is updated in the
same commit — so adding one is impossible to do quietly.

That friction **is the feature**. It is what makes "we ship no remote execution" a property a stranger
can verify by reading one file, rather than a promise about our intentions.

The permanently-refused list is in
[`SECURITY.md`](SECURITY.md#permanently-refused): `shell.exec`, `script.run`, arbitrary `file.write`,
`apt.addRepository`, `user.create`, `ssh.authorizedKeys.add`, `agent.updateFromURL`.

### The three root helpers

`apply-updates`, `restart-unit`, `reboot-host`. There is no fourth one that "runs the configured
command", and none of the three will grow a parameter that names a program.

The agent reaches them over one unix socket each, activated by systemd, and never through `sudo` —
nothing in HostSeal is setuid. The routing table in `internal/privsep` is the complete statement of which
intent reaches which helper, and it is checked against the catalogue on every build. Adding a socket, or
widening the group on one of the three, is the same request as adding a fourth helper.

### Runtime plugins in the agent

Never. Any mechanism that loads code into the agent at run time is remote code execution wearing a
plugin API — dlopen, a WASM sandbox, an embedded interpreter, a "safe" expression language that grows
a function call syntax in version two. Agent extension is compile-time only.

### A privileged tier on Windows

**Closed, and not a matter of effort.** The Windows agent exists and executes the read tier; what is
refused is growing a privileged one. There is no `execve` with an argument vector, no socket activation
to give a privileged helper a fresh process per operation, and no service manager that applies a sandbox
from reviewable text — so a privileged operation on Windows would rest on the agent process alone, and
[`SECURITY.md` §1](SECURITY.md#1-the-guarantee)'s second and third clauses would rest on it with them.

That is enforced rather than remembered. `intent.ProfileWindowsReadOnly` is a closed compile-time set,
`internal/agent`'s `hostProfile` is a `const` in a build-tagged file, and
`TestGuaranteeTheWindowsProfileHoldsOnlyReadIntents` fails on anything outside the read class — by
class, not by a list of names, because a list would be a copy rather than a check.

Two capabilities are refused for a reason no amount of design would fix: a Windows cumulative update has
no installable security-only subset, so `packages.applySecurity` cannot mean there what `policy.toml`
says it means; and `InitiateSystemShutdownEx` documents that a success return may not reboot the host
and can wedge it so that nothing else can either. The intent-by-intent table is in
[`SECURITY.md` §12](SECURITY.md#12-windows-hosts).

Two rules hold whatever is built. **No interpreter, anywhere** — `powershell.exe`, `pwsh.exe`,
`cmd.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe` and `msiexec.exe` are in
`interpreterBasenames` beside `sh` and `bash`, and `refused.go` has refused an intent *named*
`powershell` since before any of this was discussed. Constrained Language Mode is not an answer:
Microsoft's `about_Language_Modes` says its cmdlets "are fully functional and have complete access to
system resources", and every act this guarantee prevents is a cmdlet. **And the agent still loads no
foreign code** — enumerating Windows updates means loading `wuapi.dll`, so it happens in a separate
short-lived unprivileged process reached through `internal/run`, never in the process holding the host's
mTLS key.

### `store.Store`

**Not a seam.** The interface exists so that tests do not need a database. It is not a portability
layer and pull requests adding MySQL or SQLite backends will be declined.

HostSeal uses Postgres features that are load-bearing rather than incidental: `JSONB` with GIN indexes
for facts that gain fields constantly, partial indexes for the job claim, `LISTEN`/`NOTIFY` to wake
long-polls without Redis, and `SELECT … FOR UPDATE SKIP LOCKED` for atomic job claiming. Abstracting
those away would mean reimplementing a job queue and a pub/sub system badly, and then shipping a
second one as a dependency — which is precisely the four-service Compose stack this project chose not
to be.

---

## Adding a new intent, if you are sure

This is the process, not an invitation.

1. Open a discussion first. Describe the operational problem, not the operation you want.
2. Write the intent as **typed parameters with a validator**, never a string that gets interpreted.
   If your parameter is a path, a command, a URL or a template, stop.
3. Classify it: `read`, `routine`, or `destructive`. If in doubt it is `destructive`; there is no
   graded tier below that, deliberately.
4. Update `internal/intent`, and update the expected-set literal in the guarantee test in the same
   commit — CI will fail until you do.
5. If it needs root, it goes in one of the three existing helpers, and that helper re-reads and
   re-enforces `/etc/hostseal/policy.toml` itself. It does not get a new helper, and it does not get a
   new socket: add it to the routing table in `internal/privsep` naming the helper that already
   performs work of that kind, or the guarantee suite fails.
6. Add the policy knob that lets a host refuse it. Every privileged intent must be refusable locally,
   or the guarantee is no longer true.
7. Document it in `SECURITY.md` §3 and `PROTOCOL.md`.

Steps 4 through 6 are where most proposals stop, and that is the process working.
