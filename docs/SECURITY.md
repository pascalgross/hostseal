# Security

This document is the specification of HostSeal's security posture. It is not marketing copy: every
claim below is either enforced by code with a test in the `guarantee` CI workflow, or explicitly
marked as a boundary that HostSeal does **not** defend.

If you find a way to violate the guarantee in [§1](#1-the-guarantee), that is the most serious class
of bug this project can have. See [§11](#11-reporting-a-vulnerability).

---

## 1. The guarantee

> An attacker who fully owns the HostSeal control plane, its database, and an administrator account
> still cannot run arbitrary code on any **enrolled** host, cannot exceed any host's local policy, and
> cannot reboot or stop services on hosts whose policy forbids it.
>
> A host **being enrolled** applies, at most once, the bootstrap template its operator named on the
> command line — shown in full before it runs, signed by a key from that host's own
> `trusted-signers`, and recorded permanently on the host.

Both paragraphs ship together, always. The second is the price of the Tier 2 bootstrap feature
([§7](#7-provisioning-and-the-enrolment-time-exception)); a guarantee with an undisclosed exception is
worse than no guarantee, so the first paragraph is never quoted on its own — not in the README, not
in a release announcement, not on a slide — because it reads better that way.

HostSeal competes with Landscape, Salt, Uyuni and Rudder on exactly one axis: all of them ship a remote
execution channel, and HostSeal does not. That absence is the product.

Neither paragraph names an operating system, and neither will. HostSeal manages Ubuntu and Debian today
and ships no agent for anything else; where another platform cannot carry a mechanism at the strength
Linux carries it, HostSeal does less there rather than qualifying the sentence above.
[§12](#12-windows-hosts) is where that is worked out for Windows, and it is a set of decisions rather
than a description of shipped code.

---

## 2. The three mechanisms

The guarantee is not a policy decision that a future maintainer can quietly relax. It is the emergent
property of three mechanisms, each of which is load-bearing on its own.

### 2.1 A closed intent catalogue

The wire protocol carries an enumerated, typed operation — never a command string. `internal/intent`
defines the complete set of things a HostSeal job can be, as Go constants. There is no registry, no
plugin table, no configuration file that adds an intent, and no code path that leads from a network
message to a shell.

Every external process invocation in the agent and in the root helpers is `execve` with a fixed argv
slice built from validated, typed parameters. Nothing anywhere concatenates remote input into a
command string, and nothing passes remote input to `sh -c`, `bash -c`, `os/exec` with a shell, or any
equivalent.

Parameters are typed and constrained at the boundary. A systemd unit name, for example, must match:

```
^[a-zA-Z0-9@._-]+\.(service|socket|timer)$
```

The `guarantee` CI workflow asserts that the catalogue matches an expected literal set, so **adding an
intent fails CI until the expectation is updated in the same commit** — which is the point. It also
asserts that no member's name matches execution-shaped patterns, that every member has a class and a
parameter validator, and that fuzzing the parameter parser never produces a shell invocation or a
string that escapes the unit-name pattern.

### 2.2 Local policy sovereignty

Each host carries `/etc/hostseal/policy.toml`, owned `root:root`, mode `0644`, shipped
`config|noreplace` so package upgrades never overwrite a local edit. The agent runs as the unprivileged
`hostseal` user and **cannot write it**. No intent modifies it. There is no `policy.set` operation and
there will not be one.

Effective permission is always:

```
effective = min(central request, local policy)
```

Never the maximum, never a union, never "central overrides for emergencies". A host configured with
`allow = "none"` cannot be made to apply updates by anyone in the control plane holding any role, ever,
including the person who installed the control plane.

**Enforcement lives in the root helper, not in the agent.** The agent's own policy check exists to save
a round trip and to give a good error message. The check that matters runs as root, inside
`/usr/libexec/hostseal/*`, re-reading the root-owned policy file from disk on every invocation. That
placement is what makes the guarantee survive a *fully compromised agent process*: an attacker with
arbitrary code execution as `hostseal` still cannot exceed the policy, because the helper does not
trust its caller.

"Does not trust its caller" includes not taking the policy's location from it. The helpers accept no
`--policy` flag: the path is the packaged constant, always. The agent can write `/var/lib/hostseal`, so
a helper that read a caller-supplied path would enforce — carefully, as root — whatever policy the
attacker had just written. Nor is there a field for one in the request that crosses the socket. A test
in `internal/intent` parses each helper's source and fails if one grows such a flag.

`systemctl stop hostseal-agent` and the presence of `/etc/hostseal/paused` are a kill switch that the
control plane cannot override. There is deliberately **no `agent.resume` intent** — an off switch that
something else can flip back on is not an off switch.

### 2.3 Offline job signing

Destructive operations require a detached signature from a key the control plane does not hold — and,
more precisely, one it **cannot cause to be used**. The distinction did not matter while the only
backend was a file on a laptop, and it matters now that a key can live in a cloud key store: the
control plane holds nothing there either, and if its own identity can call `Sign` on that key then it
has the authority anyway. For the `kms` backend this is an IAM property of the deployment rather than
anything HostSeal can enforce, and it is stated as such in [§9](#9-what-hostseal-does-not-defend-against)
and [§10](#10-hardening-notes-for-operators).

The trust anchor is `/etc/hostseal/trusted-signers` — **not the package**. It is root-owned,
`config|noreplace`, and **empty by default**, so a freshly installed agent will execute nothing
destructive until an administrator deliberately places a public key in it.

This placement is deliberate and is worth being explicit about. If the signing key shipped in the
`.deb`, the trust chain would be `APT signing key → package → job signing key`, which quietly promotes
whoever controls APT signing to ultimate authority over every host. In a hosted deployment that would
hand the provider a route around the customer's own control plane. So the anchor is established
locally, by the administrator, at enrolment time (see [§7](#7-provisioning-and-the-enrolment-time-exception)).

The signed payload is the canonical JSON encoding of:

```
{jobId, hostId, intent, params, notBefore, notAfter, nonce}
```

Nonces are persisted on the host so a replayed signature is refused. Validity windows are checked
against the **local** clock only (see [§4.3](#43-clock-skew)).

---

## 3. The intent catalogue

The catalogue is closed. Its current contents:

### Read-only — unprivileged, unsigned

mTLS is sufficient authorisation. These run as the `hostseal` user with no capabilities and read
nothing an unprivileged local user could not read.

| Intent | What it does |
| --- | --- |
| `facts.collect` | Inventory: OS, kernel, hardware, network, uptime, capacity and load |
| `packages.listUpgradable` | Simulated upgrade parse; splits security from regular |
| `services.list` | systemd unit state over the D-Bus read interface |
| `reboot.checkRequired` | Reboot-required markers and `needrestart` output |

### Routine — signed by the control plane's online key

| Intent | What it does |
| --- | --- |
| `packages.applySecurity` | Applies security-origin updates only, subject to policy |

This is the one privileged operation that does not require an offline signature, because it is the
operation the host would perform on its own timer anyway via `unattended-upgrades`. The control plane
can, at most, make a host do sooner what its own local policy already permits it to do unattended.
A host with `allow = "none"` refuses it.

The control plane signs it with a key it holds itself, generated on first start and kept beside the CA.
The public half reaches agents in the enrolment response and on every heartbeat, so rotation needs no
operator action — see [`PROTOCOL.md` §5.2](PROTOCOL.md#52-the-control-planes-online-key).

**That the control plane distributes the key it signs with is not an oversight, and it does not weaken
[§1](#1-the-guarantee).** An attacker who owns the control plane owns this key, so it defends against
nothing in §1's scenario. What bounds a routine intent is the paragraph above: the host's own policy,
re-read as root by the helper. So why sign at all? Because the alternative is a privileged operation
authorised by mTLS alone, and because it keeps one mechanism instead of two — every privileged job
carries a signature over the same canonical payload, checked in the same place, against the same replay
store. An agent with a second code path for "privileged but unsigned" would have a second place to get
it wrong.

**The same arrangement for the destructive tier would be a backdoor.** An agent therefore verifies the
two tiers against two anchors and never one: a signature by the online key must not authorise a reboot,
and a signature by a key in `trusted-signers` is not an online-key signature. That is asserted
mechanically, in both directions, by `TestGuaranteeTheOnlineKeyCannotAuthoriseADestructiveJob`.

**A reboot must be unreachable from the routine tier by effect, not merely by class.** That distinction
is load-bearing and it was once got wrong here: `packages.applySecurity` shared a parameter decoder with
`packages.applyAll`, so it accepted `rebootIfRequired`, and the root helper acted on the flag without
asking which intent had carried it. The control plane could therefore reboot a host with a key it holds
itself, while a test asserting that the online key cannot sign a *destructive-class* job stayed green —
a reboot reached through a routine intent's parameters is never classified as anything.

`packages.applySecurity` now has its own decoder and takes no parameters at all. The field is unknown to
it rather than accepted and ignored, because a field that is accepted and ignored is one flipped
condition away from being honoured. The root helper refuses the combination a second time, since it runs
as root and the catalogue does not.
`TestGuaranteeTheRoutineTierCannotExpressAReboot` asserts this over the whole catalogue rather than over
one intent, because the defect was a shared decoder and no test naming a single member would have seen
it.

### Destructive — signed by a key in the **host's** `trusted-signers`

| Intent | What it does |
| --- | --- |
| `packages.applyAll` | Applies all available updates, subject to policy |
| `service.start` | Starts a unit on the policy's `restartable` list |
| `service.stop` | Stops a unit on the policy's `restartable` list |
| `service.restart` | Restarts a unit on the policy's `restartable` list |
| `host.reboot` | Reboots the host, subject to the policy's reboot rule |

**Every destructive intent is offline-signed. There is deliberately no graded tier by blast radius.**
A design in which "small" destructive operations took a weaker authorisation would weaken the claim to
"cannot reboot your fleet *in one action*" — and a control plane holding two operator accounts could
simply walk the fleet host by host. One tier, no exceptions.

**Approval** is the other half, and it is a property of the control plane rather than of the host. Each
tenant chooses one of three modes:

| Mode | What it means |
| --- | --- |
| `none` | The signature is the whole of the control-plane-side authorisation. A destructive job is claimable as soon as it is created. **This is the default.** |
| `self` | Somebody must release the job before any host may claim it, and it may be whoever created it. |
| `second_person` | Somebody *other than* the job's creator must release it. |

`POST /api/v1/jobs/{id}/approve` records a release. Under `second_person` the refusal to self-approve
is enforced in the statement that performs the update rather than in the handler — two requests
arriving together would otherwise let one operator release their own job by racing it against itself.

**Which mode applies is decided when the job is created and recorded on its row**, not looked up when
somebody presses approve. That is not an optimisation. A mode read at approval time could be defeated in
two API calls: queue the job while the tenant requires a second person, relax the tenant's setting,
release it yourself. A job records what it required.

The default is `none`, and the reasoning is worth stating plainly because the previous default was the
strictest of the three. What the guarantee in [§1](#1-the-guarantee) rests on for a destructive intent
is the **signature** — made offline, by a key in the host's own `trusted-signers`, which this control
plane does not hold and cannot obtain. Approval sits on top of that and is a different kind of control:
it defends against a careless operator, not a compromised one, because an attacker who owns the control
plane owns the approval mechanism too. It is also the one part of the destructive tier the *host* does
not check. Requiring a second person by default meant that an installation with one operator could not
reach the destructive tier at all — not "with difficulty", but at all — so the strict default was a tier
nobody could use rather than a tier everybody used carefully.

An organisation with more than one operator should turn `second_person` on. It is one field on the
tenant, and it is the setting that makes "nobody reboots production alone" true rather than customary.
It needs one thing to be true first: the rule compares the approver's principal against the job's
creator, so every operator has to be a distinct principal. An account is
([§4.5](#45-who-the-operator-is)), and so is the API token that account issues, because a token acts as
its owner. The shared bearer token this control plane used to accept was not, and under one the rule
failed closed and nobody could release anything — which is one of the reasons it is gone.

**Every destructive intent is offline-signed, in every mode.** No approval setting relaxes that, and
there is no mode in which a destructive job runs on mTLS alone.

### Permanently refused

The following will never be added. In an open-source project the request arrives eventually, usually
from a well-meaning contributor with a real problem, and the answer needs to be a document rather than
an argument. Pull requests adding any of these will be closed with a link to this section.

| Refused | Why |
| --- | --- |
| `shell.exec` | It *is* the thing this product exists not to have. Every other item on this list is a way of spelling it. |
| `script.run` | `shell.exec` with an extra step. Fetching the script from the control plane makes the control plane a code-execution channel by definition. |
| Arbitrary `file.write` | Write to `/etc/sudoers.d/`, `/etc/cron.d/`, `~/.ssh/authorized_keys`, or any systemd unit path and you have code execution. A file-write primitive that is safe requires an allowlist of paths *and* content schemas, at which point it is a set of typed intents, which is what the catalogue already is. |
| `apt.addRepository` | Adding a repository plus a signing key means every future package on the host is chosen by whoever added it. It is remote code execution with a delay. |
| `user.create` | Account creation is privilege creation; with a shell or a password it is direct access, and without one it is a foothold for the next step. |
| `ssh.authorizedKeys.add` | Direct interactive root-adjacent access from the control plane. |
| `agent.updateFromURL` | Self-update from a control-plane-supplied URL replaces the binary that enforces every other rule here. Agent updates come from the signed APT repository through the host's own package manager, on the host's own schedule. |

If you have a use case that seems to require one of these, open a discussion. The likely answer is a
new *typed* intent with validated parameters — which is a normal, reviewable source change — rather
than a general-purpose escape hatch.

### Also closed

- **The intent catalogue is not a registry.** New intents arrive as source changes in a reviewed pull
  request. That friction is a feature, not an oversight.
- **There are exactly three root helpers.** There is no fourth one that "runs the configured command".
- **There is no runtime plugin loader in the agent, ever.** Any mechanism that loads code into the
  agent at run time is remote code execution wearing a plugin API. Agent extension is compile-time
  only.

The asymmetry that keeps this workable: **the server may be extended at run time in the outbound
direction only.** Webhook sinks send data out; nothing sends code in.

---

## 4. Transport and identity

### 4.1 Direction

There is no server→agent direction at all. Every byte moves on a connection the host opened. There is
no listening port on a managed host, and therefore no port to firewall, no inbound ACL to get wrong,
and no benefit to putting the fleet behind a VPN.

The agent makes exactly four calls plus a certificate renewal, documented in
[`PROTOCOL.md`](PROTOCOL.md).

### 4.2 mTLS

A private CA is created at control-plane install time (`hostseal-server ca init`). Agent certificates
are host-scoped, valid 90 days, and auto-renewed at two-thirds of lifetime via `POST /agent/v1/renew`
authenticated by the current certificate.

**Revocation is a database fingerprint check on every request**, not CRL and not OCSP. A revoked host
stops being able to talk to the control plane on its next request, with no distribution delay and no
stapling infrastructure.

The same lookup retires a certificate a renewal has replaced. The agent generates a fresh key each time
it renews, and that was worth almost nothing while the certificate it rotated away from stayed valid to
its ninetieth day: somebody who read `agent.pem` on day ten kept a working authentication path for
eighty more, and could spend the renewals themselves to extend it indefinitely. A renewal now stamps the
presenting certificate with the moment it stops being accepted, 48 hours out — long enough that a host
interrupted between obtaining a certificate and promoting it can come back on the old pair, and short
enough that a copied credential is worth two days rather than three months. Renewal is also rate-limited
per host and a host may hold only a few valid certificates at once, because a caller who can mint rows
in a table every tenant shares, and a CA signature with each, should not be able to do so without bound.
The cap and both writes are one transaction under a lock on the host: counting and then inserting
separately is check-then-act, and the burst the limiter permits is exactly the concurrency that reaches
it.

Revoking a host also releases its machine — the salted `/etc/machine-id` hash a host claims at
enrolment — so the same physical machine can enrol again under a new identity. The revoked row and its
history stay. Without that release, any host row that outlived its certificate would wedge the machine
permanently: unable to authenticate, and refused re-enrolment because a host with that machine id
already exists. `DELETE /api/v1/hosts/{id}` releases it too, and discards the history with it; revoke
is the answer that keeps the audit trail, and is the one to reach for. The agent's private key and
certificate are stored as one file and promoted by one rename, so a renewal interrupted at any point
leaves a matching pair on disk rather than half of a new one.

The CA private key is the control plane's most sensitive secret. Compromising it lets an attacker
impersonate *hosts to the server* — it does **not** let them run code on a host, because the agent
authorises jobs by intent class and signature, not by who asked.

**The transport floor is TLS 1.2 with AEAD suites only.** Both numbers are stated once, in
`internal/protocol`, and read by the listener and by the agent's client, so the two ends of a
connection cannot be hardened apart. TLS 1.3 is preferred and needs nothing said about it: its suites
are not negotiable. What is configured is the 1.2 fallback, where Go's default selection would
otherwise include ECDHE with AES-CBC and a SHA-1 HMAC — the encrypt-then-MAC construction a decade of
padding-oracle results have been about. The list here is forward-secret and AEAD only.

The floor is 1.2 rather than 1.3 because of the listener rather than the protocol: one port carries
enrolling agents, enrolled agents and an operator's browser, and only the first two are built from this
repository. Nothing rests on the difference. A downgrade cannot forge a client certificate the
fingerprint lookup accepts, which is what actually authenticates an agent.

### 4.3 Clock skew

Clock skew is a security boundary, not an operational annoyance.

`notBefore`/`notAfter` on a signed job are validated against the **local** clock only. The agent never
adjusts its notion of time to server-supplied time; a compromised control plane could otherwise extend
a signature's validity window arbitrarily by lying about the current time. The `serverTime` field in
the heartbeat response is used *solely* to compute and report an offset for display.

When the measured offset exceeds five minutes:

- read-only intents still run,
- privileged intents refuse — **fail closed**,
- the UI flags the host.

### 4.4 No VPN requirement

HostSeal will never require a VPN. The agent connects outbound, so there is no port to protect; and
tunnel membership cannot prove host identity anyway, which is what mTLS is for. Running HostSeal over
an existing Tailscale or WireGuard network already works with zero additional code — the agent talks
to a URL.

For a hosted offering this is not a neutral choice: a provider-operated VPN hub reaching into customer
networks would be a substantially larger backdoor than the remote-exec channel this product removes.

---

### 4.5 Who the operator is

Everybody who reaches the administrative API is an **account**, and `auth.Provider` is the seam. There
is no shared credential and no way to configure one. `HOSTSEAL_ADMIN_TOKEN` and `HOSTSEAL_PLATFORM_TOKEN`
were exactly that and have been removed rather than deprecated: one string for a whole fleet names
nobody in the audit trail, cannot be taken from one person who has left, never expires, is changed only
by restarting the control plane and telling everybody, and made the second-person rule below
unsatisfiable by construction.

An account is an address and a password, and it belongs to one fleet — or, for a platform administrator,
to none, which is the whole of what makes them one ([§5.3](#53-the-platform-administrator)). The
password is stored as Argon2id with the cost parameters written into the hash beside the digest, so they
can be raised later without invalidating anybody; a sign-in rewrites a hash it finds below the current
cost, because sign-in is the one moment the password is known.

Two ways to present that identity, and they differ in what they are for.

A **session** is what a browser holds. Signing in exchanges the password for an opaque 256-bit token in
an `HttpOnly`, `Secure`, `SameSite=Lax` cookie; only its SHA-256 is stored, so a database dump is not a
set of live sessions. Two windows bound it and the credential dies at whichever comes first: twelve
hours idle, restarting each time it is used, inside seven days absolute, measured from the sign-in and
never extended. Both are checked against the control plane's own clock, like every other validity window
in HostSeal ([§4.3](#43-clock-skew)). Signing out deletes the row; so does deleting the account; and an operator
can end every session they hold, from any of them, in one request. A cookie without the
`X-HostSeal-Session` header authenticates nothing, which is the cross-site request forgery defence: a
cross-site form post cannot set a header, and a cross-site fetch that sets one triggers a preflight this
server does not answer.

An **API token** is what a script holds. An operator issues one for themselves, gives it a label and an
expiry, and revokes it from the same page in a second; only its SHA-256 is stored, and it is shown once.
It acts *as that account* — same provider, same subject, therefore the same principal — which is not
laziness about the audit trail but what keeps the second-person rule honest: a token with a principal of
its own would let one person queue a job in a browser and release it with their token, and the
comparison would see two people.

The cost of that is one rule, and it is the only place in this server where *what* the caller was
holding matters as much as *who* they are. A token presented to `/api/v1/account` — the routes that mint
and revoke tokens, change a password and end sessions — is refused with 403. A token that could issue
another, with no expiry, would survive its own revocation.

**Accounts are created on the machine**, with `hostseal-server accounts`, and by no API at all. That is
[§5.3](#53-the-platform-administrator) applied rather than worked around: a platform credential must not
be able to authenticate as a customer, so it is not given a route that would let it. Creating an account
from a shell on the control plane adds no power to a role that §5.3 already concedes has the database
and the process — it makes a power that already existed findable instead of something to write SQL for.
The exception is the first one: a control plane whose database holds no accounts creates one on start
and prints its password once, because a control plane with no way in is one that gets abandoned or made
reachable in a hurry, and the second is much worse.

The fleet is never a field on the sign-in form. It comes from the account row, the way an agent's tenant
comes from its certificate row, which is what keeps [§5.2](#52-where-the-boundary-is-enforced)'s first
layer true of a browser as well as of an agent.

**None of this is a boundary the guarantee in [§1](#1-the-guarantee) rests on.** A compromised
administrator account is inside that threat model by construction, and better operator authentication
does not move that line. What it buys is narrower and worth naming: an audit trail that records *which
person* queued a job rather than the word "operator"; a second-person approval rule that can actually be
satisfied, because it compares two principals and a shared token makes them equal; and the ability to
withdraw one person's access without rotating everybody's.

---

### 4.6 The wallboard and its link

A wallboard is one screen of a fleet's own status — the counts, and the handful of machines something
is wrong with — on a television in a corridor. What makes it a section in this document rather than
another page in the interface is that **the room has no account**. Every other read of control-plane
state is performed by somebody who signed in, and a screen on a wall cannot: a session dies twelve
hours idle inside seven days absolute ([§4.5](#45-who-the-operator-is)), so a television lent an
operator's session goes dark on the Tuesday, and until it does it is an unattended credential that can
queue a reboot. So a share is a credential of its own kind. It reaches one fixed-shape summary of one
fleet, over one endpoint, and there is no route from it to a second thing.

That is a shared bearer credential in a URL, which is exactly what [§4.5](#45-who-the-operator-is)
removed, so the comparison is owed rather than avoided. `HOSTSEAL_ADMIN_TOKEN` was refused on five
counts, and four of them are answered here. It could not be taken away from one person who had left; a
share is withdrawn in one request, by deleting one row, and stops answering at the next poll — within
fifteen seconds. It never expired; a share is given an expiry or it is not created, ninety days by
default and 365 at the most, with deliberately no "never". It was changed only by restarting the
control plane and telling everybody; a share is a row, so withdrawing one disturbs nothing else and
nobody has to be told anything. And it made the second-person rule unsatisfiable by construction,
because that rule compares two principals and one shared string made every principal the same one; a
share cannot approve anything, create anything or reach a job at all, so the rule is untouched by it.
One more thing is true that is not on that list of five: the old token wrote, and this one reads. The
only write anywhere behind a share is the timestamp recording that a screen polled.

**The first of the five is the one that survives, and it survives permanently.** A share does not name
its readers. It records who published it — the one name attached to it, and the useful one, because
the question a share can answer is who decided this fleet could go on a wall — but a link can be
forwarded, and nothing in this design can tell that it was. There is no cleverer version of it
available: the whole point of the credential is that the room does not sign in, and a reader nobody
authenticates is a reader nobody can name. Saying that is the honest form of the trade-off. Counting
polls, or recording the addresses they come from and calling the result an audit trail, would be
answering a different question in a way that reads like an answer to this one.

What makes it acceptable is the size of what leaks. **A leaked link discloses, to a remote party,
roughly what somebody standing in the room already sees** — and it discloses it continuously, at
fifteen-second resolution, for as long as the share lives. Both halves of that sentence do work. The
first is why publishing one is defensible at all: if the screen may be read by anyone who walks past
the lift, the marginal disclosure of a copy of the screen is small. The second is why the expiry is
mandatory, why the list of live shares is kept short enough to read, and why the payload is what it is
rather than whatever was convenient.

So the payload is a **projection built field by field**, not a filtered version of what the fleet page
returns. The distinction is a security property rather than a matter of style. `hostView` carries a
host's facts document verbatim, so a public payload made by removing fields from it would put whatever
a future collector adds onto a public page without anybody deciding, and the commit that did it would
touch no file in this directory and mention none of this. A field has to be written into the
projection to appear on the wall.

What is on it: the fleet's size split three ways, the security backlog, how many hosts are waiting for
a reboot, how many have a failed unit, and at most twelve hosts named with a one-word reason from a
closed vocabulary and one short composed sentence. The split is three-valued — ok, bad and
**unknown** — everywhere on the screen, because a wallboard that paints "not measured" the same colour
as "healthy" is a wallboard that lies in the one direction nobody checks. What is not on it: no facts
document in any form, no host identifiers, no unit, package, kernel or distribution names, no
addresses, no container process names, no group names, and nothing about jobs — not a summary, not a
principal, not an approval state. A hostname is the single host-reported string that reaches it, and
it is there because a tile that names nothing sends somebody to a terminal to find out which machine
it meant, which is the errand the screen exists to save.

"No host identifiers" is meant literally, including in the case that makes it inconvenient. A machine
that has never reported has no hostname, and the obvious fallback is its identifier — which would put
the value `GET /api/v1/hosts/{id}`, `POST /api/v1/hosts/{id}/revoke` and `POST /api/v1/jobs` all name
onto a page reachable without an account, in twenty-six characters of base32 that nobody could read
from across the room anyway. So the tile carries no name at all and says so. The count is exact
either way, which is where the truth on this screen lives.

The operator's own wallboard is answered by the same projection, and differs only in its heading. That
is deliberate: two payloads would in practice be one payload and a public subset of it, the subset
would drift behind, and somebody would eventually and reasonably reuse the richer one on the route
that does not authenticate.

**The key travels in the URL fragment.** A published link is
`https://hostseal.example/board#hsb_<tenant>.<secret>`, and the page reads the fragment and sends it as
an `Authorization: Bearer` header. A fragment is never transmitted, so the secret is absent from this
control plane's access log, from a reverse proxy's log, from `Referer` on anything the page links to,
and from the fetch a chat client's link-preview crawler makes when somebody pastes the link into a
channel — which, for a credential in a query string, is the single likeliest way one escapes. What a
fragment does not do is disappear. It remains in browser history, in a bookmark, in whatever
synchronises those between somebody's devices, and on a photograph of the address bar. The response
that hands the link over says both halves of that, once, because that is the only moment anybody is
reading.

**The fleet's identifier is inside the key, and inside the digest.** That is what keeps this table out
of [§5.2](#52-where-the-boundary-is-enforced)'s narrow exemption. Four tables have to be findable
before the tenant is known, because finding them is *how* it becomes known, and each takes a read-only
`hostseal.resolve_key` disjunct admitting exactly the one row whose key the caller can already name. A
fifth one, on a table reached by an unauthenticated request from the public internet, would be the
widest of the set — and it is not needed: the server splits the key, opens a handle for the fleet the
key names, and only then looks the secret up, so the lookup already runs inside a transaction that has
set `hostseal.tenant`. Naming the fleet in a credential a stranger holds is safe because the stored
digest covers the *whole* key rather than its secret half: a key edited to name a neighbouring fleet
hashes to a value no row holds, and is refused by the lookup before the tenant predicate and the
row-level security policy are consulted at all. Both of those are still there, second and third. It is
the fleet's identifier rather than its slug, because a slug is chosen to be readable and frequently
names the customer, and the discipline of this whole feature is that it never says whose fleet is on
the screen.

A share may carry a passphrase, and what becomes of it afterwards is the part worth stating plainly.
It is verified once, with Argon2id, and exchanged for a value the screen keeps in an `HttpOnly`,
`Secure`, `SameSite=Strict` cookie. The exchange is not a shortcut around the password hash: one
Argon2id derivation allocates 64 MiB, only a few may run at once, and a wallboard asks again every
fifteen seconds for months, so a handful of screens would occupy the entire sign-in path's memory
budget indefinitely. The consequence is the honest part. **An unlocked screen holds a credential
equivalent to the link plus the passphrase**, and holds it until the share expires or its passphrase
changes. There is no per-viewer revocation and there could not be: a television has no identity to
revoke. What exists instead is that the value is derived from the presented key and the stored
password hash rather than stored anywhere, so neither half produces it alone — whoever leaked the link
cannot compute it without the database, whoever holds the database cannot compute it without the link
— and changing the passphrase changes the hash, which drops every screen unlocked under the old one at
its next poll.

The rest is bounds, and each is chosen for what it makes noticeable rather than for what it prevents. A
fleet may hold twenty live shares, which is not a capacity limit: it is the number that keeps the list
something an operator reads down and recognises every line of, because "there is a share here I do not
remember" is the only detection this feature has. `last_seen_at` records that a screen polled,
throttled, and is read no more precisely than that; it exists so somebody can tell which of four links
is still on a wall before revoking one and waiting to see who complains, and it is **not an access
log**. Unlock attempts are rate limited per share rather than per source address — unlike every other
limiter in this server — because a corridor, a NAT and a reverse proxy all put many screens behind one
address, and the address is the wrong thing to punish.

Every refusal on the public routes is the same refusal, with one stated exception. An unknown key, a
withdrawn share, an expired one, a share with no passphrase and a wrong passphrase are one answer down
one path — the liveness test is a predicate in the query rather than a check afterwards, which is what
keeps the five from drifting into five refusals somebody has to remember to keep matched. The exception
is a screen that presents a live key for a share whose passphrase it has not yet proved: that is told
so, because it is the one refusal a screen can act on, and telling it "no such link" would leave a
television in a corridor rendering "this link has been withdrawn" for ever with a passphrase form one
answer away. What it discloses is that the link exists, which is a fact whoever is holding the link
already has.

**None of this touches [§1](#1-the-guarantee).** A share is a read of control-plane state. It reaches
no host, carries no intent, produces no job, and there is no route from one to anything that writes to
a fleet. The attacker §1 already concedes — the one who owns the control plane and its database — can
publish a share, and could equally have read the same rows with `psql`; what that changes is the
convenience of the crossing rather than its existence, and it is written down in
[§9](#9-what-hostseal-does-not-defend-against) rather than here.

The limits, stated as limits rather than left to be inferred from what is not claimed:

- **A share names no reader, and no version of it could.** Publishing is attributed; reading is not.
- **A leaked link is a live feed and not a snapshot.** It keeps working, at fifteen-second resolution,
  until it expires or somebody deletes the row — those are the only two things that stop it.
- **The fragment keeps the key out of logs, not out of the world.** History, bookmarks, whatever
  synchronises them, and a photograph of the address bar all keep a working copy.
- **An unlocked screen holds link-plus-passphrase.** Expiry, a passphrase change and deleting the
  share are the ways it is taken back, and none of them takes it back from one viewer.
- **`last_seen_at` answers "is anybody still watching", not "who watched".** It is not an audit trail
  and must not be quoted as one during an incident.
- **There is no counters-only mode.** A board that says three hosts are offline and will not say which
  starts the search it was built to end — so the names are on it, and a share is therefore not a thing
  to publish outside the building it hangs in.

## 5. Tenants

One control plane can serve many independent fleets. That is what makes hosting HostSeal for other
people possible, and it introduces the only boundary in this document that is *not* enforced on the
host: everything else here is something a machine checks about a job, and this is something the control
plane checks about a request.

So it is worth being precise about what it does and does not add to [§1](#1-the-guarantee). It adds
nothing. The guarantee already assumes an attacker who owns the control plane and its database; against
that attacker, tenancy is not a defence and is not claimed as one. What tenancy defends against is a
*bug* — a query that forgot a predicate, a handler that took an id from a URL without asking whose it
was — and the failure it prevents is one customer seeing another's fleet.

### 5.1 What a tenant is

A tenant owns its hosts and the certificates that authenticate them, its enrolment tokens, its jobs
and their results, its provisioning templates, its events and the unit-transition history behind them,
its alerting rules and the firing state those rules keep, the accounts of its operators together with
every session and API token those accounts hold, and the wallboard shares it has published
([§4.6](#46-the-wallboard-and-its-link)). It chooses its own approval mode
([§3](#3-the-intent-catalogue)) and its own event webhook. A tenant is not a permission level: there is
no hierarchy of tenants, and no tenant can see into another.

The list is written out rather than summarised as "its data" because it has to stay true in two places
at once — it is what [§5.2](#52-where-the-boundary-is-enforced) puts behind row-level security and
what [§5.4](#54-what-deleting-a-tenant-does-not-do) has to remove — and a table added later that
appears on neither list is exactly how this boundary would fail without anybody noticing.

### 5.2 Where the boundary is enforced

Three layers, and the order matters, because only the last of them is a rule rather than a habit.

1. **The credential names the tenant.** An operator credential resolves to exactly one tenant. The
   tenant is not in the URL, not in a header and not in the body, so there is no field of a request an
   operator could edit to reach another fleet. An agent's tenant comes from its certificate's row,
   which the revocation lookup already reads on every request — so an agent never names its own tenant
   and could not name a different one. **This is also why the agent protocol needed no change for any
   of it:** tenancy is a property of the credential, and the credential is a certificate this control
   plane issued.

2. **The handler cannot reach an unscoped store.** Middleware hands a handler a store handle already
   scoped to the request's tenant. A tenant-scoped operation is not a method somebody remembers to pass
   a tenant to; it is a method that cannot be reached without one.

3. **PostgreSQL refuses the row.** Every table holding tenant data has row-level security `ENABLE`d and
   `FORCE`d, with a policy keyed on a session setting the application sets inside the transaction that
   runs the query. A statement that forgets its `WHERE` clause returns nothing rather than everything,
   and a statement issued with no tenant set returns nothing at all — `current_setting(…, true)` is
   NULL when unset, and `tenant_id = NULL` is not true. The failure mode is an empty result, which is
   loud, rather than another customer's fleet, which is silent.

   `FORCE` is the half that is easy to omit and worthless to omit: without it the table's owner — which
   is the role running the application — bypasses every policy.

   The setting is `SET LOCAL`, scoped to the transaction, which is why every scoped statement runs in
   one even when it is a single `SELECT`. A session-level setting on a pooled connection would be
   inherited by the next request that borrowed it.

   Two rows have to be findable before the tenant is known, because finding them is *how* the tenant
   becomes known: the certificate on an agent request and the enrolment token from a machine that is
   not yet a host. Rather than exempting those two tables, their policies admit exactly one row — the
   row whose key the caller can already name, through a second session setting. Naming a SHA-256 you
   already hold is not an enumeration path. The sign-in path added two more of the same shape: an
   address on a form, and an account id read out of a session.

   **That exemption is read-only, and never appears in a `WITH CHECK`.** The reason is the whole reason
   it is narrow at all. A resolve-key transaction is precisely one where no tenant is set, so in a write
   check the tenant half of the predicate is NULL and the key half becomes the entire rule: a writer
   could then place a row in *any* fleet, provided its key matched the one they named. One policy
   carried the disjunct on both halves; migration 0011 removed it, and
   `TestGuaranteeTheResolveKeyExemptionIsReadOnly` sweeps `pg_policies` so that no future one can
   reintroduce it — the database's own account of what is in force, rather than the migration files,
   which are what somebody meant to put there.

Composite foreign keys carry the tenant alongside every reference, so a row claiming one tenant while
pointing at another's host is refused by the database rather than noticed in review.

**A role that bypasses row-level security removes all of layer 3 with no symptom.** A superuser, or a
role with `BYPASSRLS`, is exempt from every policy: the policies are still in the schema, the predicates
are still in the queries, and every query returns every tenant's rows. `hostseal-server` therefore checks
its own role at startup and **refuses to start** rather than serving many customers from one database
with the boundary switched off.

### 5.3 The platform administrator

Running an installation is a different job from reading what runs on it, and HostSeal keeps them
separate. A platform administrator can create, configure and delete tenants through `/api/v1/tenants`.
They hold no tenant of their own, and every route that reaches a tenant's hosts or jobs refuses them.

They are an account like anybody else — created with `hostseal-server accounts add --platform`, signing
in with an address and a password — and the only thing that distinguishes them is that their account
row carries no tenant. That is a database fact rather than a flag: the row-level security policy on
accounts admits a tenant's rows through `hostseal.tenant` and the tenantless ones through
`hostseal.platform`, and `NULL = 'anything'` is `NULL` rather than true, so neither side can reach the
other. A row that claimed to be a platform administrator *and* named a fleet is not a state that exists
to be refused; it is a state the schema cannot represent.

It also cannot mint an operator credential. Issuing a fleet's credential belongs to the identity
provider — `auth.Provider` is the seam for it — and a tenant API that handed out tokens would make the
platform administrator able to authenticate as any customer, which is precisely the separation the role
exists to keep. This is why a fleet's accounts are created with `hostseal-server accounts`, on the
machine, and by no route: see [§4.5](#45-who-the-operator-is).

The interface it reaches is one screen: the fleets, their names, approval modes and webhooks, and the
one destructive control in the whole application — retiring a fleet, which requires its slug to be typed
back. That bar is not decoration. It is the only action in the interface that destroys anything, a
dialog with a Yes in it is a dialog people click through, and typing the name is the smallest bar that
requires having read which fleet this is. What it removes is in [§5.4](#54-what-deleting-a-tenant-does-not-do),
and what it does not reach is every machine.

There is no host list on the screen, no job list and no way to reach one, because there is no route
behind it that would answer — which is the same statement as the paragraph above rather than a second
one. `whoami` is
the single route that answers both credentials, and it hands a platform credential no tenant at all;
it exists so the interface can say *what this credential is for* instead of rendering an empty console
to somebody whose account administers the installation rather than a fleet in it. The one other route
both reach is `/api/v1/account`: everybody has an account, and everybody has a password to change.

There are two settings the platform role administers that reach *into* a fleet's behaviour, and one
route through which it learns something about a fleet's contents. Both are new, both are narrower than
what they replace, and both are worth stating plainly rather than leaving to be discovered.

**`hostLimit` — how many hosts may enrol.** `NULL` for no limit, which is the default and what
`hostseal-server serve` creates. It is checked twice, and the two checks answer different questions.
The enrolment handler checks it after the machine-id claim and before the token is consumed, so that
the ordinary refusal leaves the token usable. That check is a courtesy and not the boundary: it reads a
count and writes the host several statements later, so two machines presenting two valid tokens into a
fleet with one slot left both pass it. `Scoped.CreateEnrolledHost` is where the limit is *enforced* —
it locks the fleet's row, counts and writes inside one transaction, and answers `ErrHostLimitReached`
when there is no room, which the handler renders as the same `403 host_limit_reached`.
`TestGuaranteeAHostLimitHoldsAgainstSimultaneousEnrolments` enrols twelve machines at once into a fleet
of three and is the test for that; without the row lock, six get in. What makes the setting safe to
exist is
the asymmetry: **lowering a limit below a fleet's current size revokes nothing, pauses nothing and
reaches no machine.** Hosts that are enrolled stay enrolled and stay accepted; what changes is the
answer the next machine gets. A setting that could take a running host away from its operator would be
the first lever in this control plane able to act on an enrolled host, and [§1](#1-the-guarantee) is a
promise that there are none.
`TestGuaranteeAHostLimitNeverReachesAnEnrolledHost` is where that is enforced rather than described.

**`suspended` — whether this fleet's agents are answered.** A suspended fleet's requests are refused
with `403 tenant_suspended`, at enrolment and on every authenticated agent route. It is refusal, not
reach. The agent goes on running, goes on applying the host's own local policy and goes on installing
security updates on its own timer — which is exactly what it does when the control plane is unreachable
for any other reason, a state [`docs/INSTALL.md`](INSTALL.md) already documents as supported because an
outage produces it. Nothing is uninstalled, nothing is deleted, and one field reverses it.

**`GET /api/v1/tenants/{id}/usage` — how large a fleet is.** It answers with a total, an active count, a
revoked count, the limit, the suspension state and a timestamp. No hostname, no group, no agent
version, no fact, no job. The count runs through `Store.In(tenant)` like every other read of a
tenant-owned table, so [§5.2](#52-where-the-boundary-is-enforced)'s policy answers it; there is no
exemption here and there must not be one.

This is a real widening of the platform role and it is stated as one: it can now learn an integer about
a fleet it previously could not. The reason to accept it is what it replaces. Before it existed, an
installation billing per host had exactly one way to count — an operator account *inside* the
customer's fleet, which can queue jobs, read facts and revoke hosts, held by somebody who wanted to
count to three. Given the choice between a credential that reaches everything and a route that returns
a number, the number is the smaller disclosure, and it is the one this document is willing to defend.

The honest limit: a platform administrator has the database and the process. Nothing here prevents
somebody with shell access on the control plane from reading a tenant's rows, and this document does
not claim otherwise. What it prevents is *the product* offering that as a feature, and a bug offering
it by accident.

### 5.4 What deleting a tenant does not do

It removes everything on [§5.1](#51-what-a-tenant-is)'s list: the hosts and their certificates, the
enrolment tokens, the jobs and their results, the templates, the events and unit transitions, the
alerting rules and their state, the accounts of that fleet's operators with every session and token
those accounts hold, and the published wallboard shares. The cascade is declared in the schema rather
than assembled in a handler, so the question a new table has to answer is one the migration asks rather
than one review has to remember — which is the same reason §5.1 keeps a list instead of gesturing at
one.

A published wallboard link ([§4.6](#46-the-wallboard-and-its-link)) is worth naming on its own, because
it is the one thing about a departed customer that a stranger may still be holding. Deleting the fleet
deletes its shares, so the link stops **resolving**: the next poll finds no row and receives the same
refusal as an unknown or withdrawn key. That is the required outcome and not merely a tidy one. A share
that outlived its fleet would resolve to a fleet with no hosts in it, and a wallboard with no hosts in
it renders as a *healthy* one — counters at zero and an all-clear panel where the failures would be. A
green screen in a corridor for a customer who left three weeks ago is the worst failure this screen
has, because a green screen is the one nobody investigates.

It does not reach the machines — nothing in HostSeal does. Their agents keep running, keep applying
their own local policy, and are refused at the next request as an unknown certificate. That is the
correct end state for a customer who has left, and it is worth saying out loud that deleting a tenant
does not uninstall anything.

---

## 6. Host privileges

The agent runs as the `hostseal` system user with **zero capabilities**, under a systemd unit hardened
as shown in `packaging/hostseal-agent.service`. Notably it sets `MemoryDenyWriteExecute=yes`, which is
one of the reasons the agent is written in Go: any JIT runtime is incompatible with that setting, so
choosing a JIT language would have silently cost this mitigation.

Privileged work happens in exactly three root helpers:

```
/usr/libexec/hostseal/apply-updates
/usr/libexec/hostseal/restart-unit
/usr/libexec/hostseal/reboot-host
```

Each helper re-reads and enforces `/etc/hostseal/policy.toml` itself, as root, on every invocation. None
of them accepts a command to run, a path to execute, or a shell fragment.

**The agent reaches them over a unix socket, not through `sudo`.** Nothing in HostSeal is setuid and
there is no `/etc/sudoers.d/hostseal`. That is forced rather than chosen: with `NoNewPrivileges=yes` in
force, `execve` drops the setuid bit, so `sudo` cannot become root at all — and systemd *implies*
`NoNewPrivileges=yes` from `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectClock`,
`RestrictNamespaces`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`, `LockPersonality` and
`SystemCallFilter`, every one of which the agent's unit sets. Keeping `sudo` would have meant dropping
most of this section.

```
/run/hostseal/apply-updates.sock   root:hostseal 0660  → hostseal-apply-updates@N.service (root)
/run/hostseal/restart-unit.sock    root:hostseal 0660  → hostseal-restart-unit@N.service  (root)
/run/hostseal/reboot-host.sock     root:hostseal 0660  → hostseal-reboot-host@N.service   (root)
```

Each socket is `Accept=yes`: systemd accepts the connection and starts one instance of one helper with
the connection as its standard input. There is no listening socket inside a privileged process, no
accept loop of HostSeal's own, and **no resident root daemon** — a helper exists for exactly as long as
one operation does.

The three properties that made the sudoers entry safe are kept, and each is asserted by the guarantee
suite rather than reviewed for:

1. **The set of reachable operations is closed and visible in one place.** It is the routing table in
   `internal/privsep`, checked against the catalogue on every build. An intent that is not in it has no
   route from the agent to root at all, whatever the policy file says and however well the job was
   signed.
2. **A caller names an intent, never a program.** The request carries an intent and a parameter object
   and has no field a path, a command or an argument vector could occupy — and the helper decodes the
   parameters again, itself, with the same catalogue decoder, on its own side of the boundary.
3. **Authorisation is by identity the caller cannot forge.** The socket's mode names the `hostseal`
   group; the helper additionally reads the peer's credentials with `SO_PEERCRED`, which the kernel
   records at connect time. Only the agent's own account and root are served.

A helper also refuses an intent it does not serve. systemd routes a connection to exactly one helper,
but the request arriving on it still names an intent, and nothing about the socket would stop a
compromised agent from sending `host.reboot` to the one that restarts units.

### What the root boundary does not check

**No helper verifies the offline signature.** The request crossing the socket carries a job id, an
intent, a parameter object and an issue time, and nothing else — no signature, no nonce, no validity
window. `verifyOfflineSignature` runs in exactly one place, the unprivileged agent process, and this
section says so rather than leaving it to be discovered.

That is a decision and not an oversight, and it follows from [§2.2](#22-local-policy-sovereignty). What
survives a compromised agent is *policy*, not the signature: an attacker with code execution as
`hostseal` is in the `hostseal` group, so they can reach the sockets and invoke any routed intent without
one — and the helper still performs `min(request, policy)` against the root-owned file it read itself.
A host whose policy forbids reboot does not reboot, whoever is asking and whatever they claim to hold.

Moving the check into the helper would not close that. The signed payload binds a host id, and the
host id lives in `/var/lib/hostseal`, which the agent can write; a helper verifying a signature would be
verifying it against an identity the attacker chose. It would also require `privsep.Request` to grow
four fields, which is the property in point 2 above — a caller names an intent and never anything else
— given up for a check that does not hold. `TestGuaranteeARequestCannotNameAProgram` asserts the field
set, and would fail.

So the offline signature is what stands between a *taken-over control plane* and a destructive
operation, which is the adversary [§1](#1-the-guarantee) names. Local policy is what stands between a
*taken-over agent* and one. They are two controls against two adversaries, and neither is the other's
backstop.

The helper units themselves are **not** sandboxed, and that is deliberate rather than an omission: a
program whose job is to install packages cannot be confined against writing to `/usr` and `/etc`. What
bounds them is the root-owned policy file and the closed catalogue, not a systemd directive.

`hostseal-agent doctor` checks the whole path from the agent's own account and changes nothing: it sends
an intent that is in no catalogue and on no route, which every helper refuses at its first check. A
refusal is what success looks like, because there is no harmless privileged intent to send instead.

**`hostseal` is never added to the `docker` group.** Docker socket access is root equivalence and would
silently undo everything in this section. If you package HostSeal for a system where the agent needs to
report container state, that must be done through a read-only path, not group membership.

That read-only path now exists, and it is worth naming because it is what makes the refusal above
sustainable rather than merely principled. The `containers` collector reads `/proc` and the unified
cgroup hierarchy as the unprivileged `hostseal` user: no socket, no helper, no group, no new intent,
and nothing in this section changes. It is off until `[containers] report = true` is written into the
host's own `policy.toml`, because container state is a more revealing disclosure than a unit list.

What it costs is real and is stated where an operator will read it rather than discovered: the kernel
knows a container's id, its main process and that process's *name*, when it started, and its resource
use — and knows nothing at all about image names, exit codes, restart counts or health, because those
are daemon state behind the socket. It reports the executable name from `/proc/<pid>/comm` and never
the command line, which is where credentials end up. In exchange it answers four questions `docker ps`
does not: whether a container is privileged, whether its seccomp filter was disabled, whether it runs
as root, and **whether the Docker socket is bind-mounted into it** — which is the risk this very
paragraph is about, found on a host rather than assumed.

The `resources` collector is the second read-only path and reaches no further: `/proc` for the processor
count, the load average, memory and per-interface counters, and `statfs(2)` for each mounted filesystem.
No socket, no helper, no group, no new intent, and nothing in this section changes for it either. It is
**on** until `[resources] report = false` is written into the host's own `policy.toml`, which is the
opposite default from containers and is argued out in [`PROTOCOL.md` §4.2](PROTOCOL.md#42-full-report):
what a business runs on a host is a disclosure that host has not agreed to make, while a disk about to
fill up is what somebody installed a fleet agent to see.

What it discloses is worth naming here rather than leaving to be inferred, because [§1](#1-the-guarantee)
assumes the control plane is hostile and therefore assumes an attacker reads everything a host reports.
Three things are new to that attacker. **Filesystem layout** — mount points, device names and sizes —
which is the same inventory the `containers` collector deliberately refuses to disclose as a side effect
of asking about a bind-mounted socket; the difference is that here the layout *is* the question, since
"which host is about to run out of disk" has no answer that does not name the filesystem. **MAC
addresses**, added to the `network` collector in the same change, which identify a machine to a DHCP
server, a switch and a hypervisor — everything outside HostSeal, which already knows the host by its
certificate. Those live in `extra.network`, which has a key of its own — `[network] report` — because a
section that ships a durable hardware identifier and had no way to be refused was an omission rather than
a decision, and this document had no honest way to write it down. And **capacity and load**, which is a coarse shape of what the machine is for.

Both are refusable, and both keys ship on for the same reason with opposite histories: `[resources]`
answers the question a fleet agent was installed for, and `[network]` reports something every release so
far has reported, so turning it off by default would take a fact away from every existing fleet rather
than protect it.

None of it widens what may be *done* to a host: no intent, no helper, no socket, no privilege. What it
widens is what a compromised control plane learns, which is the axis [§9](#9-what-hostseal-does-not-defend-against)
names rather than the one §1 does. The policy keys are the answer for a host where that trade is the wrong
way round, and they are host-side switches precisely because the control plane must not be able to flip
one.

---

## 7. Provisioning and the enrolment-time exception

This is the exception named in the second paragraph of the guarantee. It is stated plainly here because
it is the only way a HostSeal component ever applies operator-authored configuration to a host.

**Tier 1 — implemented.** HostSeal stores, versions and renders cloud-init templates, and **never
delivers them to a host**. The rendered `user-data` goes to a human, or to Terraform / Proxmox / MAAS /
a cloud provider's user-data field; the machine consumes it at first boot from the hypervisor that
created it. HostSeal is not in the delivery path at all. This also covers bare metal, since Ubuntu
`autoinstall` for PXE and ISO is delivered as cloud-init user-data.

A template is a document with `{{placeholder}}` substitution sites and nothing else: no conditional, no
loop, no expression — a renderer that grew a `{{ exec }}` would defeat the guarantee without touching
the intent catalogue, so `internal/provision` refuses to be a template language by construction. Every
saved revision is a new immutable version, because the Tier 2 record below names one and a record that
resolves to editable bytes is not a record.

A template is therefore never deleted, and the control plane has no endpoint that could delete one.
What an operator retiring a template gets instead is an **archival**, which withdraws the *name*: an
archived template leaves the listing, refuses new versions, cannot be named by a new enrolment token,
cannot be rendered, and is refused at enrolment — while every stored version stays readable, so the
record on a host still resolves to the bytes that ran on it. The archival is a row about the name in a
table of its own, never a column on a version, because a version is written once and never updated and
an UPDATE path added to carry a flag would be an UPDATE path whatever it was first used for. Restoring
deletes that row and changes nothing else: a restored template is issuable at enrolment only on the
conditions that already governed it, signature included, so undoing an archival can never be the step
that lets something reach a host.

HostSeal ships no template: what a machine should look like on its first boot is a decision about a
fleet. One worked body — unattended upgrades left on, a `wheel` group, `su` restricted to it — is in
[`examples/cloud-init/`](../examples/cloud-init/README.md), as an example to read rather than a default
to inherit.

**Tier 2 — the exception, implemented.** `hostseal enroll --bootstrap NAME` applies a named template
once, on a host that is being enrolled by hand. The template arrives in the enrolment response carrying
a signature the control plane stored but cannot mint — it is produced offline by
`hostseal sign-template`, with a key the control plane does not hold, and the enrolment token must have
been minted naming that template, so holding a leaked token is not the authority to choose what runs.
An agent that asked for a template and receives none, or an unsigned one, or one the fleet has since
archived, fails the enrolment loudly rather than continuing as though something had been applied. Every one of these guardrails is required:

1. Explicit `--bootstrap NAME` on that specific invocation. Never implicit, never a server default,
   never a group setting.
2. The full text is printed to the terminal and recorded in
   `/var/lib/hostseal/bootstrap-applied.json` **before** execution. The record is fsynced — file and
   directory — before anything runs, because it is the only thing that survives a template that
   crashes the machine halfway, and "what was attempted" is the question an incident asks.

   The **journal gets the template's name, version, signer, length and SHA-256, and not its body.** A
   template legitimately carries credentials — a break-glass account's hashed password, a static deploy
   key, the shapes `provision.Warnings` flags — and journald keeps a structured, indexed, root-readable
   copy for as long as the journal is retained, on every host enrolled from that template. The fsynced
   record is the verbatim copy this guardrail is about; the digest is what lets an operator prove the
   two are the same document without the journal holding the second.
3. It is signed by a key already present in that host's `trusted-signers`.
4. It runs exactly once, enforced by an on-disk interlock — which is the record itself, one file, so
   the two cannot disagree. A crash between "decided to apply" and "applied" refuses a second attempt
   rather than permitting one; re-enrolling a bootstrapped host does not re-apply. The record is
   created with `link(2)`, which fails when the file exists, so two concurrent enrolments sharing a
   state directory produce one application and one refusal rather than two applications — a rename
   would have let the second silently replace the first's record.
5. **cloud-init does the applying.** HostSeal writes the verified body into cloud-init's NoCloud seed
   directory under a fresh instance-id and runs cloud-init's own stages with argument vectors fixed in
   the agent; no byte of a template ever reaches a command line. HostSeal never ships a hand-written
   YAML-to-shell engine — that would be the exec channel wearing a hat.

The seed is the one thing beside the template that the control plane has any say in, because its
meta-data carries the host id the enrolment response assigned. That is a YAML document cloud-init parses
and acts on, so the id is validated to letters and digits before it is written: an id carrying a newline
would be adding *keys* to that document rather than filling one in, and `public-keys` is a NoCloud key
that cloud-init installs into `authorized_keys`. That would be a path from a compromised control plane
to an SSH key on a host, running beside a template the operator did approve while having none of the
guardrails above — not covered by the signature, not shown, not recorded. The seed is also removed once
cloud-init has read it, because a NoCloud seed left in place outranks the machine's real datasource on
every later boot.

Two honest limits on guardrail 2. The record is written by `hostseal enroll`, which runs as root, but it
lives in a directory the unprivileged `hostseal` user owns — so it defends the audit trail against the
adversary [§1](#1-the-guarantee) is about, the control plane, and not against local code running as the
agent, which [§2.2](#22-local-policy-sovereignty) already assumes may be compromised and which is above
this file in the trust hierarchy. And the terminal copy is standard output, which systemd also routes to
the journal when enrolment is run from a unit — so a host enrolled by a unit rather than by a person
still has the body in its journal, unstructured. An operator running `hostseal enroll` by hand, which is
what guardrail 2 is written for, sees it on their terminal and nowhere else.

The chicken-and-egg problem is that `trusted-signers` is empty on a fresh install. It is solved by
establishing the anchor from a local, administrator-chosen file **before** anything is fetched:

```bash
sudo hostseal enroll --token XYZ \
     --signers ./trusted-signers \   # local, admin-chosen, written first
     --policy  ./policy.toml \
     --bootstrap standard-server     # fetched, verified against the above, displayed, confirmed
```

Without signers present, `--bootstrap` **refuses**. It never falls back to trusting the server.

**Tier 3 — pushing configuration to an already-enrolled host — is never built.** That is the line
between "fleet management without a remote shell" and "a remote shell with extra steps".

### Templates are not a secret store

cloud-init `user-data` is plaintext in the cloud metadata service and in
`/var/lib/cloud/instance/user-data.txt`, readable by anything with instance or metadata access. HostSeal
therefore:

- **warns** (and does not block) on private-key blocks, `password:` fields and API-token shapes in
  template bodies;
- treats rendered output as a credential in its own right, because it carries a live enrolment token;
- encrypts template bodies at rest.

---

## 8. Observability

HostSeal tells an operator what it noticed. It does not act on it — the two halves of that sentence are
the whole of this section.

### 8.1 What may be said, and where it goes

The event vocabulary is **closed at compile time**, like the intent catalogue and for a related reason:
a kind is a word operators build webhook filters, mail rules and dashboards on, and a control plane
that let a handler invent one under deadline is a control plane whose dashboards each miss half the
events. The set lives in `internal/notify/kinds.go`, and a test fails when it changes without the
expected-set literal changing in the same commit.

| Kind | When |
| --- | --- |
| `host.enrolled` | A machine joined the fleet |
| `host.silent` / `host.recovered` | A host stopped, then resumed, heartbeating |
| `job.created` / `job.approved` | A job was queued, or released by an operator |
| `job.failed` | A host attempted a job and failed it |
| `job.expired` | A job's validity window closed before it executed |
| `service.failed` / `service.recovered` | A watched unit failed, then ran again |
| `updates.pending` / `updates.resolved` | A host's security backlog crossed a rule's line, then fell back |
| `reboot.overdue` / `reboot.done` | A reboot went unaddressed past a rule's line, then happened |
| `delivery.failed` | A tenant's webhook did not accept an event |

A refusal is deliberately not in that list. `refused_by_policy` is the system working, and an event
stream that painted it the same colour as a failure would teach its readers to ignore both.

Every event is written to its tenant's **inbox** before any delivery is attempted, because the inbox is
the only delivery with a guarantee. Everything after it is best-effort and has to *look* best-effort:
an open tab receives the event over a server-sent-events stream, the tenant's webhook receives it if
one is configured, and an alert rule's recipients receive mail. A tab that was closed, a webhook that
was down and a relay that refused all produce the same outcome — the event is on the page when somebody
looks.

`delivery.failed` is the one kind that is only ever recorded and never delivered, and the reason is the
loop: sending a delivery-failure notice through the delivery that just failed either fails again and
emits another, or succeeds on the retry and reports a failure that had already resolved. It exists
because a webhook that is down takes every event with it in silence — the inbox fills, the chat channel
stays quiet, and nothing on either side says which of the two is happening.

Delivery outside the process runs **detached from the request that produced it**, retried with a short
backoff and bounded, and drained on shutdown. That is not an optimisation: `emit` is called from
handlers an agent is waiting on, and a control plane made slow by somebody else's mail server is a
control plane whose heartbeats time out.

Scoping is the same as everywhere else. An event carries its tenant, reaches that tenant's endpoint and
that tenant's tabs, and nothing else; the stream is authorised exactly like any other read of
control-plane state ([§5](#5-tenants)).

**A webhook is https, is not redirected, and is not link-local.** An event carries hostnames, job
summaries and the principal of whoever queued the work, which is exactly the reasoning that makes the
mail sink refuse a relay offering no STARTTLS — so the same data is not posted in cleartext either. The
scheme is refused where a webhook is configured, so an operator learns of the mistake in the second it
takes to read the response, and again in the sink, because a row written before this rule existed is
the one that would still be posting. A redirect is refused rather than followed: the sink reads only
the status code, so a redirected POST is a destination nobody chose and an outcome nobody sees. And the
address the connection is actually made to is checked at the socket rather than in the URL, because a
name resolves at dial time and can resolve differently on the next attempt.

The destination rule is link-local only — `169.254.0.0/16` and `fe80::/10`, where the cloud metadata
services live — and deliberately not the strictest available. Loopback and private ranges stay
reachable, because a self-hosted control plane posting to a chat relay on its own network is the
ordinary deployment, and breaking it would buy nothing the paragraph above has not already bought.

A rule that fires across many hosts at once collapses into a **digest**, because three hundred identical
pages during a partition are how the one different page gets missed. The collapse is a property of the
notification and not of the record: every host still gets its own row in the inbox, so "what did I miss
overnight" is answerable afterwards for all three hundred rather than for the three the digest had room
to name.

**A firing is tracked per rule, per host, and per subject** — the unit, for a rule that watches units.
The cooldown that keeps a restart-looping unit from mailing on every loop is keyed the same way, which
is what stops the first failing unit on a machine from silencing the second one in silence. And a
recovery clears the firing while **keeping** the cooldown: clearing both would make the cooldown
unreachable for anything that oscillates, because each recovery would hand the next firing a clean slate
and a condition crossing its line every few minutes would mail every few minutes, for ever.

### 8.2 What the host decides

`[services] watched` in `policy.toml` lists the units whose state changes this host considers worth an
event, with the same shell-style globbing as `restartable`. It is on the host because which units
matter is a per-host question: the machine's owner knows that `nginx.service` matters and
`motd-news.timer` does not.

Two properties of it are worth stating, because both are the opposite of what the neighbouring key
does. The empty default watches **everything** — permitting an action and reporting a fact are
different questions, and a fresh host should surface a failed unit rather than hide it behind a setting
nobody has heard of. And widening the list is **not a permission change**: it bounds what the control
plane says about this host, never what may be done to it.

The resolution is the heartbeat interval, by construction: state changes are noticed by comparing one
full report against the previous one, so a unit that fails and recovers between two beats is invisible.
That is a stated property rather than a bug, and the UI states it where the history is rendered rather
than leaving somebody to discover it during an incident.

### 8.3 The line an alerting rule does not cross

**A rule produces a notification. A rule never produces a job.**

"Apply the security updates when more than five are pending" is the obvious next request, and it does
not break [§1](#1-the-guarantee) — the host's own policy still bounds it, and anything destructive
still needs a signature from a key in that host's own `trusted-signers`. What it does is convert the
control plane from something that asks into something that acts on a schedule of its own, and that is a
different feature with a different threat model. There is deliberately no code path here that could,
and it gets its own argument or it does not happen.

Rules live in the control plane's own database and not in `policy.toml`, for the reason that file
exists: `policy.toml` is the *host's* authority over what may be done to it, and an alerting rule is the
control plane's business. Putting them together would blur the one distinction the whole design rests
on. Like everything else a tenant owns, rules are behind forced row-level security.

Two conditions watch the security backlog, and they answer different questions. `security_updates`
fires on a count; `security_updates_age` fires when there has been *any* backlog for longer than its
threshold in days. One host with twelve updates published this morning is healthy and one with a single
update from a fortnight ago is not, and it is the second that describes a machine nobody is patching.
The age is measured from when this control plane first saw the backlog become non-empty, which is an
honest answer rather than an exact one: nothing on the wire carries when an update was published, so a
host enrolled today with a month-old backlog reads as new.

Mail leaves over STARTTLS on 587 or implicit TLS on 465 and never in plaintext, because an alert
legitimately carries hostnames and failure text. The relay is process configuration — which mail server
an installation may speak to is the installation operator's decision — and the recipients are per rule,
which is the one delivery a tenant opts into. A rule whose last mail did not go out says so on the
rule: an alert that never went out and an alert that never fired are indistinguishable from an inbox.

---

## 9. What HostSeal does *not* defend against

An honest guarantee needs an honest boundary. HostSeal does not protect you from:

- **Anyone with root on the managed host.** They can edit `policy.toml` and `trusted-signers`, or
  simply not run the agent. Local root is above HostSeal in the trust hierarchy, by construction.
- **A compromised holder of a key in `trusted-signers`.** That key is the authority for destructive
  operations; this is exactly why the hardware-backed signing backends exist and why the audit log
  records *which* signer authorised each job.
- **A cloud KMS key the control plane's own identity can reach.** The `kms` backend keeps the private
  key in AWS KMS, Cloud KMS or Key Vault, and the control plane holds nothing — but "holds nothing" is
  not the property [§1](#1-the-guarantee) rests on. If the control plane runs in the same account and
  can assume a role with `kms:Sign`, `cryptoKeyVersions.useToSign` or the Key Vault `sign` permission on
  that key, then an attacker who owns the control plane can authorise a reboot, and **§1 is false for
  that installation**. A hardware token keeps them apart by physics; a KMS does it by IAM policy, which
  is a weaker thing and one people misconfigure. HostSeal cannot check this, so it is
  [§10](#10-hardening-notes-for-operators)'s job to say what to check.
- **The APT repository's signing key.** The agent is installed and updated as a normal Debian package
  from a signed repository. Whoever controls that GPG key controls the agent binary on every host that
  updates from it. This is a different adversary from the one in §1 — it is the ordinary distribution
  trust that applies to every package on the system — but it is real, and the honest statement of the
  guarantee is that it covers *control-plane* compromise, not *package-supply-chain* compromise. Hosts
  use deb822 with `Signed-By:` and an explicit keyring so the HostSeal key is trusted for the HostSeal
  repository only, never system-wide; `apt-key` is never used.
- **Denial of service by a compromised control plane.** An attacker owning the control plane can stop
  issuing jobs, or issue jobs that fail. They cannot make hosts do anything the policy forbids, but
  they can make the fleet less useful. Note that patching continues regardless: when the control plane
  is unreachable, hosts keep applying updates from their local policy on their own timer, because
  `unattended-upgrades` does not need us. A control-plane outage must never mean an unpatched fleet.
- **Traffic analysis.** The existence, timing and size of heartbeats are visible to anyone on the
  path, even though the contents are not.
- **What a host chooses to report.** Everything in the facts document reaches a control plane this
  section assumes is hostile, so a compromised one learns a fleet's network topology — MAC addresses,
  IP addresses, interface names — its filesystem layout and its capacity, along with everything else a
  host sends. That is a disclosure boundary rather than a control boundary: none of it lets anybody *do*
  anything to a host, and §1 is untouched. What bounds it is the host's own `policy.toml`, which is why
  every section a host might reasonably decline has a key that declines it
  ([§8.2](#82-what-the-host-decides)): `[resources] report = false` refuses capacity, filesystem layout
  and traffic volumes, and `[network] report = false` refuses interface names, addresses and hardware
  addresses. Both ship **on**, because both sections either predate their key or answer the question a
  fleet agent was installed for, and a key whose default removed a fact an existing fleet already
  receives would be a worse failure than the disclosure. A host that turns both off is still identified
  by its certificate and its hostname, which is what identifies it everywhere else in this system.
- **A host enrolled *during* a control-plane compromise being given somebody else's identity.** The
  signed job payload binds a job to a `hostId`, and a host learns its `hostId` from the enrolment
  response — so a control plane that was already compromised when a host enrolled can hand that host an
  identity belonging to another, and jobs signed for the other host will verify on it. The blast radius
  is bounded by the mechanism that matters: the root helper re-reads the *local* policy of the machine
  it is running on, so nothing exceeds what that host's own operator permitted, and §1 still holds. What
  is lost is targeting — a signed job can reach a host it was not meant for. Binding the signature to
  the certificate would not help, because the adversary in §1 owns the CA. An operator who cares should
  enrol hosts from a control plane they have reason to trust at that moment, which is the same
  requirement the bootstrap exception in §7 already makes.
- **Anyone with the control plane's database or shell.** Tenants are isolated from each other
  ([§5](#5-tenants)), and they are not isolated from whoever runs the installation. A platform
  administrator cannot read a customer's fleet *through the product* — no route they hold reaches one —
  but they have `psql`. What §5 buys is that a bug cannot cross the boundary and that the feature set
  does not offer crossing it as a convenience; it does not turn a hosting provider into a party you do
  not have to trust. If you need that, run your own control plane; the binary is the same one.

  The wallboard ([§4.6](#46-the-wallboard-and-its-link)) changes what that access is worth rather than
  whether it exists, and the difference is worth stating. Somebody with `psql` could always read a
  fleet's rows; what is new is that they can now write one — a row in `wallboard_shares`, with a digest
  they chose — and then read that fleet's status screen from an ordinary browser, from anywhere,
  holding no credential this installation issued, until somebody deletes the row. Nothing prevents
  that, and nothing could: the row is the credential, and the party who can write rows is the party
  this bullet is about. What exists is a mitigation, and it is worth what an operator's attention is
  worth. The share appears in that fleet's own list of published links, with its label, its date and
  the principal that published it, and the list is capped at twenty precisely so that it stays
  something somebody reads down and recognises every line of. A share nobody remembers publishing is
  the detection; there is no other, and it is a detection only for a fleet whose operators look.

  There is deliberately **no support path** across the boundary — no impersonation, no read-only view of
  a customer's hosts, no "open a ticket and we will look". A hosting provider who needs to see a
  customer's fleet asks the customer for a credential. That is inconvenient on purpose, because the
  alternative is a mechanism that exists, is audited by nobody in particular, and is used at three in
  the morning during an incident.

---

## 10. Hardening notes for operators

- Put real keys in `trusted-signers` and use a touch-required hardware token where you can. The
  audit log distinguishes `ops-laptop (file)` from `ops-yubikey-1 (PKCS#11)` precisely so that this is
  visible to reviewers after the fact. File-based keys are fully supported; refusing them would not
  make anyone buy a token, it would push them to keep the key on the control plane instead, which is
  strictly worse.
- **If you use the `kms` backend, put the signing key where the control plane cannot reach it.** A
  separate account, subscription or project; a key policy or role assignment that names the operator
  principals and *excludes* the control plane's own role or managed identity. Then check it the only
  way that catches the mistake: assume the control plane's identity and confirm that signing with that
  key is denied. Everything in [§9](#9-what-hostseal-does-not-defend-against) about this depends on that
  one arrangement, and nothing in HostSeal can verify it for you.
- Set `policy.toml` to the least permission each host actually needs. It is the only control that
  survives a total control-plane compromise.
- Leave `[containers] report` off unless somebody has asked for it. It is off in the shipped file. A
  container list describes what a business runs, and a host that agreed to report its package state
  has not thereby agreed to report that — see [§6](#6-host-privileges) for what it does and does not
  disclose.
- Do not add a socket unit, and do not widen the group on the three that exist. If you find yourself
  wanting a fourth helper, that is a request for a new typed intent upstream.
- Back up the control plane's CA key separately from its database. An attacker with both can
  impersonate hosts; an attacker with the database alone cannot.
- Review `/var/lib/hostseal/bootstrap-applied.json` on hosts you did not personally enrol.
- **Connect the control plane to PostgreSQL as an ordinary role that owns its schema — never as a
  superuser, and never as one with `BYPASSRLS`.** Both are exempt from every row-level security policy,
  which is the whole of the tenant boundary ([§5](#5-tenants)), and the exemption has no symptom: the
  policies are still there, the queries still carry their predicates, and every one of them returns
  every tenant's rows. `hostseal-server` checks its own role at startup and refuses to run on either, so
  this is a note about what to configure rather than a trap left open — but a `postgres://postgres@…`
  URL in a Compose file is the obvious thing to reach for, and it is the wrong thing.
- If you run one control plane for more than one customer, turn on `second_person` approval for the
  tenants that want it and leave it off for the ones that cannot staff it. It is a per-tenant setting
  precisely so that one fleet's answer does not have to be everybody's.

---

## 11. Reporting a vulnerability

Report security issues privately through GitHub's **Report a vulnerability** button on the repository's
Security tab, which opens a private advisory. Please do not open a public issue for a vulnerability.

Include a description, affected versions, and a reproduction if you have one. We aim to acknowledge
within three working days.

Findings that break the [§1](#1-the-guarantee) guarantee are the highest severity this project
recognises, regardless of how difficult they are to reach. That includes:

- any path from a control-plane-supplied value to a shell, an interpreter, or an unvalidated `execve`;
- any way for the control plane to cause an operation the host's local policy forbids;
- any way to make a root helper act without re-checking policy;
- any way to get a job accepted without a valid signature from the host's own `trusted-signers`, for
  an intent whose class requires one.

---

## 12. Windows hosts

**A Windows agent ships, and it is a smaller product than the Linux one.** It executes the four
read-class intents and refuses everything else — not as a staging decision to be revisited quietly, but
because of 12.2 below. `cmd/hostseal-agent` carries `//go:build linux || windows`, and
`TestGuaranteeTheAgentBinaryNamesItsPlatforms` fails if a third platform is added without the three
things that make one real: a `collect.Platform` implementation, an `intent.Profile` saying what it will
execute, and a section of this document saying which mechanisms it enforces by test rather than by
convention.

What a host will execute is a compile-time set, not a run-time one. `internal/intent`'s `profiles` map
is a second closed literal beside the catalogue — the catalogue itself is untouched, still ten members
in one file — and `internal/agent`'s `hostProfile` is a `const` in a build-tagged file, so nothing can
assign to it. The profile also travels on no wire in the direction that would matter: enforcement is on
the host, against that constant.

### 12.1 The guarantee does not change

Both paragraphs of [§1](#1-the-guarantee) say **any enrolled host**. No operating system appears in
either, and none will. A Windows host is inside the guarantee or it is not managed.

That is a constraint on what may be built rather than a claim that it is easy. Where Windows cannot
carry a mechanism at the strength Linux carries it, the answer is that HostSeal does less on Windows —
never that the sentence acquires a qualifier. The CI check that pins both paragraphs matches them word
for word for exactly this reason: `grep`ping a fragment of the first one also matches "on any enrolled
**Linux** host", which is how a guarantee narrows without anybody deciding to narrow it.

### 12.2 Two of the three mechanisms port unchanged

[§2](#2-the-three-mechanisms) says the guarantee is the emergent property of three mechanisms, each
load-bearing on its own. Two of them are pure Go and are unaffected by the platform:

- **[§2.1](#21-a-closed-intent-catalogue), the closed catalogue.** Same file, same ten members, same
  compile-time map. A Windows agent adds no intent and no name. `internal/canonical`,
  `internal/protocol` and the verifying half of `internal/signing` are likewise untouched.
- **[§2.3](#23-offline-job-signing), offline job signing.** Ed25519 over canonical JSON, verified
  against the host's own `trusted-signers`, in the unprivileged agent process. Nothing about it is
  Linux.

**[§2.2](#22-local-policy-sovereignty), local policy sovereignty, is where Windows differs**, and it is
the one that decides what a Windows agent may do at all. Three Linux primitives carry it, and none has
a Windows equivalent:

| Linux | Why it is load-bearing | Windows |
| --- | --- | --- |
| `execve` with an argument vector | `internal/run` concatenates nothing; the program and each argument are separate strings the kernel copies | `CreateProcess` takes one command-line string that the callee re-parses under its own rules, and `msiexec.exe` and `cmd.exe` do not use `CommandLineToArgvW`'s algorithm |
| systemd socket activation, `Accept=yes` | a **fresh** root helper per operation, which re-reads the root-owned policy itself and then exits | nothing starts a privileged process per accepted connection; a Windows helper is a resident service on a named pipe — all three things [§6](#6-host-privileges) refuses by name |
| a service manager that applies the sandbox from reviewable text | `MemoryDenyWriteExecute` and the rest are declared in a unit file and enforced by PID 1, which is why `sudo` could not have worked without dismantling the sandbox | service registration has no equivalent line; the containment moves into registry values written by an installer, verified by nothing comparable to `systemd-analyze verify` and `testfleet` |

### 12.3 What a Windows agent may do

Read-only, and the read tier only. That is not a staging decision to be revisited quietly; it follows
from 12.2. Without a privilege boundary of the same shape, there is no place for a privileged operation
to be re-checked against the host's own policy, and [§1](#1-the-guarantee)'s second and third clauses
would rest on the agent process alone.

| Intent | On Windows |
| --- | --- |
| `facts.collect` | **ships** — `RtlGetVersion`, the `CurrentVersion` registry values, `GetComputerNameExW`, `GetTickCount64`, `GetAdaptersAddresses` |
| `services.list` | **ships** — `OpenSCManagerW`, `EnumServicesStatusExW`, `QueryServiceConfigW` |
| `reboot.checkRequired` | **ships**, and weaker than on Linux: the pending-reboot registry keys have no `needrestart` half. See 12.5 |
| `packages.listUpgradable` | **ships**, and is **not a read intent on Windows**. See 12.4 |
| `packages.applySecurity` | **permanently refused.** See 12.5 |
| `packages.applyAll` | not implemented |
| `service.start`, `service.stop`, `service.restart` | not implemented |
| `host.reboot` | **refused.** See 12.5 |

"Not implemented" is expressed the way the catalogue already expresses it: the agent refuses the intent
and answers `unsupported_intent`, exactly as it does for a member no build has an executor for. The
catalogue is not edited, no member gains a platform field, and no name is added or removed.

Two tests keep that honest, and they check opposite directions.
`TestGuaranteeTheLinuxProfileIsTheWholeCatalogue` fails if a catalogue member is ever added without
being added to the Linux profile, because the symptom would otherwise be every Linux host quietly
refusing it. `TestGuaranteeTheWindowsProfileHoldsOnlyReadIntents` fails if anything outside the read
tier appears in the Windows one — checked by class rather than against a list of four names, because a
list would have to be edited by the same hand in the same commit, which is a copy rather than a check.

### 12.4 The update scan is privileged work wearing a read class

On Linux `packages.listUpgradable` is `apt-get --just-print`: local, no network, no state change, and
[§3](#3-the-intent-catalogue) can honestly say a read intent changes nothing. On Windows the same
question is a Windows Update Agent scan, which goes to the network, mutates
`%windir%\SoftwareDistribution`, and takes minutes. Both of §3's claims about the read tier become
false.

So it does not travel as a read intent on a Windows host without the thing every privileged intent must
have: **a policy knob that lets the host refuse it.** That is step 6 of *Adding a new intent* in
`docs/EXTENDING.md`, and it is not waived here. Without it, a control plane holding nothing but mTLS
could drive every Windows host into a continuous scan loop, and the host would have been given no policy
to exceed.

The knob is `[updates] scan`, and it defaults to true — the opposite of `[containers] report`, for a
reason worth stating: a container name describes what a business runs and is a disclosure a host has not
agreed to make, whereas a count of missing patches is the number this product exists to show. A host
that sets it false reports its updates as **unmeasured**, never as none.

A second bound is not a policy key and is deliberately not configurable. The agent asks Windows Update
at most once every six hours and serves a cached answer in between, because `Gather` runs on every full
heartbeat and an uncached implementation would leave a host scanning continuously and reporting facts
almost never. How stale a patch count may be is not a decision that differs usefully between hosts;
whether the host scans at all is, and that is the key that exists.

Two further decisions:

- **The scan runs in a separate, unprivileged, short-lived process**, not in the agent. Enumerating
  updates requires loading `wuapi.dll`, and [§3](#3-the-intent-catalogue) refuses a runtime code loader
  in the agent without qualification — the agent holds the host's mTLS private key. A package-shipped
  binary at a fixed absolute path, started through `internal/run` with a fixed argument vector, is the
  same shape the agent already uses for `apt-get`: it does not parse apt's internals either.
- **`ServerSelection` is `ssDefault`.** A host configured against WSUS is scanned against WSUS.
  HostSeal never selects `ssWindowsUpdate`, which would bypass an authority the host's owner chose.

The privilege split in Microsoft's own API is worth recording, because it lands almost exactly where
this catalogue's classes already are: `IUpdateSearcher` and `IUpdateSession` are available to the User
group, `IUpdateDownloader` to Power Users and Administrators, and `IUpdateInstaller` to Administrators
alone. Enumeration genuinely does not need privilege.

### 12.5 What Windows cannot do, and why it is refused rather than approximated

- **`packages.applySecurity` is permanently refused on Windows.** From Windows Server 2016 a quality
  update is one indivisible cumulative package; `CategoryIDs` selects packages and does not subdivide
  them. `[updates] allow = "security"` therefore cannot mean on Windows what `packaging/policy.toml`
  says it means, and a host set to `security` would receive non-security changes. This is the one
  routine member — the only operation the control plane signs with its own online key — so §3's
  sentence that the control plane "can at most make a host do sooner what its own local policy already
  permits it to do unattended" would become false. An approximation that reimplemented the filter would
  also be the thing `helpers/apply-updates` exists not to do: there is no `unattended-upgrades` on
  Windows to delegate the definition of "security" to.
- **`host.reboot` is refused.** `InitiateSystemShutdownEx` documents that a success return does not mean
  the shutdown will happen, and that with `bForceAppsClosed` false it can enter a state where the
  shutdown neither completes nor can be aborted except by the console user, and no further shutdown can
  be initiated. A job would durably record success, the host would not reboot, and every later attempt
  would be blocked.
- **`needrestart` has no Windows answer.** Windows cannot replace a file mapped by a running process; an
  installer defers the rename to boot with `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`, which is why
  `PendingFileRenameOperations` exists. The state `needrestart` detects cannot occur, so "which running
  services still hold replaced libraries" — the question `internal/run` calls more actionable than
  reboot-required — is not weakly answered on Windows. It is absent.

### 12.6 What the root boundary does not check, on Windows

In the spirit of [§6](#6-host-privileges)'s own list, written down rather than left to be discovered:

- **COM class resolution is a registry lookup.** `CoCreateInstance` resolves a CLSID to a DLL through
  `HKCR\CLSID\{...}\InprocServer32`. Anyone who can write that key can choose what the scan process
  loads. That is local administrator, who is already above HostSeal in the trust hierarchy by
  [§9](#9-what-hostseal-does-not-defend-against)'s first bullet — the adversary [§1](#1-the-guarantee)
  names is a control plane, which cannot write a host's registry. It is recorded here because "the
  agent loads no foreign code" is a claim with a footnote on Windows and should not read as one without.
- **A result is fsynced, but its directory entry is not.** The agent's promise that a result reaches
  the disk before an operation that may not return is kept one shade less firmly here. Every file is
  still written to a temporary, flushed with `FlushFileBuffers`, and renamed with `MoveFileEx`, which is
  atomic on NTFS — so a crash never exposes a truncated file and a reader never sees a half-written
  credential. What Windows offers no way to do is flush the *directory entry*: `File.Sync` on a
  directory handle is `FlushFileBuffers`, which is documented as requiring a handle opened for writing,
  and a directory cannot be opened that way. A power loss in the window after a rename can therefore
  leave the previous name in place. The file is intact either way, and the recovery for both cases is
  the one the agent already has — the control plane re-issues the job, or the host is re-enrolled.

  Reporting the failure instead was tried and is worse: it would make every atomic write return an error
  after its rename had already succeeded, and enrolment writes the credential through that path — so the
  agent would abort after the control plane had consumed the single-use token, leaving a host that is
  registered and permanently unable to authenticate. A durability guarantee that cannot be kept must not
  become a failure in the operation it was protecting.

- **There is no conffile.** MSI has no equivalent of dpkg's conffile handling, and WiX's default major
  upgrade removes the old product before installing the new one — which deletes an edited
  `trusted-signers` and reinstalls it empty. A silent trust-anchor wipe on upgrade re-opens every
  destructive operation an administrator had closed, with no symptom until a signature that should
  verify does not. Any Windows packaging must solve this before it ships, and must be tested for it.
