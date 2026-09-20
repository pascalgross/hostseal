![](brand/hostseal-mark.svg)

# HostSeal

**Fleet management for Ubuntu and Debian servers, without a remote shell.** The agent is
outbound-only, runs a closed set of typed operations, and obeys a policy the control plane cannot
change. Windows Server hosts are reported on read-only, for reasons
[`docs/SECURITY.md` §12](docs/SECURITY.md#12-windows-hosts) sets out rather than as a first version.

By [Pascal Groß](https://hostseal.io). Licensed **Apache-2.0**.
Documentation: [hostseal.io](https://hostseal.io).

> [!IMPORTANT]
> HostSeal has **shipped phases 1, 2 and 3, and there is no phase 4** — the sequence ends where the
> product does, and it stops there on purpose.
>
> **Phase 1 — the intent catalogue.** All ten catalogue members have an executor: the four read-only
> operations, the one routine operation, and all five destructive ones — apply every update, start,
> stop or restart a unit, and reboot. They enforce the host's own policy as root, over a socket rather
> than through `sudo`.
>
> The control plane issues them and `hostseal sign` authorises the destructive ones. That command never
> contacts the server: it renders what you are about to authorise from the same canonical payload it
> then signs, so a compromised control plane cannot show one operation and have another signed.
>
> It is multi-tenant — one control plane, many isolated fleets, separated by PostgreSQL row-level
> security — and each fleet decides for itself whether a destructive job waits for somebody to release
> it, and whether that somebody has to be a second person.
>
> The jobs page offers exactly what a browser may legitimately authorise: it queues reports and security
> updates, and releases destructive work somebody else signed. It will never offer to *create* a
> destructive job, because that needs a key the control plane does not hold and a browser is the last
> place it should ever be.
>
> The two provisioning phases stay numbered, because a tier boundary is what each of them crossed:
>
> - **Phase 2 — Tier 1 provisioning** ([#9](https://github.com/pascalgross/hostseal/issues/9)), shipped:
>   cloud-init templates stored, versioned, encrypted at rest and rendered by HostSeal, and handed to
>   *you* — Terraform, Proxmox, MAAS, a cloud provider's user-data field. HostSeal is never in the
>   delivery path. It came before Tier 2 by dependency: phase 3 applies a *named* template, so storage
>   had to exist before anything could name one.
> - **Phase 3 — Tier 2 provisioning** ([#10](https://github.com/pascalgross/hostseal/issues/10)),
>   shipped: `hostseal enroll --bootstrap NAME` applies one named template, exactly once, at enrolment,
>   behind every guardrail [`docs/SECURITY.md` §7](docs/SECURITY.md#7-provisioning-and-the-enrolment-time-exception)
>   lists — and cloud-init does the applying. It is the enrolment-time exception the second paragraph
>   of the guarantee names, which is why that paragraph is never omitted.
>
> **The product ends at the enrolment boundary, and that is what it is for.** Once a host is enrolled,
> the control plane may ask it for one of ten typed operations and can never hand it new instructions.
> Pushing configuration to a running host — Tier 3 — is the single capability that would leave the
> guarantee below unstateable, so the product stops just short of it. Every competitor that crossed
> that line traded the claim for the feature. Keeping the claim is what lets a stranger audit it in an
> afternoon, and it is the reason to choose HostSeal at all.
>
> Observability ([#14](https://github.com/pascalgross/hostseal/issues/14)) and the signing backends that
> keep a key off a laptop ([#11](https://github.com/pascalgross/hostseal/issues/11)) have landed too, and
> were deliberately never phases: they attach to no tier boundary, so they arrived when they were ready
> rather than holding a place in this sequence.

---

## The guarantee

> An attacker who fully owns the HostSeal control plane, its database, and an administrator account
> still cannot run arbitrary code on any **enrolled** host, cannot exceed any host's local policy, and
> cannot reboot or stop services on hosts whose policy forbids it.
>
> A host **being enrolled** applies, at most once, the bootstrap template its operator named on the
> command line — shown in full before it runs, signed by a key from that host's own
> `trusted-signers`, and recorded permanently on the host.

Both paragraphs ship together, always. The second is the price of the bootstrap feature, and a
guarantee with an undisclosed exception is worse than no guarantee — so the first paragraph is never
quoted on its own just because it reads better.

Landscape, Salt, Uyuni and Rudder all ship a remote execution channel. HostSeal does not. **That
absence is the product**, and everything below exists to make the absence hold up under a control
plane that has been fully compromised.

## How it holds

Three mechanisms, specified in [`docs/SECURITY.md`](docs/SECURITY.md) and asserted by a required CI
workflow that no maintainer can override:

1. **A closed intent catalogue.** The wire protocol carries an enumerated, typed operation — never a
   command string. No code path leads from a network message to a shell. Every external call is
   `execve` with a fixed argv slice.
2. **Local policy sovereignty.** Each host carries a root-owned `/etc/hostseal/policy.toml` that the
   control plane cannot modify and no intent can touch. Effective permission is always
   `min(central request, local policy)` — never the max. The check that matters runs as root in the
   helper, so a *fully compromised agent process* is still bounded.
3. **Offline job signing.** Every destructive operation requires a signature from a key in that host's
   own `/etc/hostseal/trusted-signers` — a key the control plane does not hold. The file is empty by
   default, so a fresh agent executes nothing destructive until an administrator puts a key in it.

## What it does

- **Inventory** — OS, kernel, hardware, network interfaces with their MAC and IP addresses, uptime,
  Ubuntu Pro / ESM status where applicable.
- **Capacity and load** — disk space and how full each filesystem is, memory and swap, processor
  count and load, per-interface traffic. Read from `/proc` as an unprivileged user, with every
  volatile figure deliberately banded so a host that has not changed keeps sending a digest rather
  than a full report. A host can switch it off; it ships on.
- **systemd service state** — read over D-Bus, not by parsing `systemctl` output. On Windows, service
  state from the SCM, read with enumerate rights rather than as an administrator.
- **Package update visibility** — security updates separated from the rest, correctly on both Ubuntu
  and Debian, plus `needrestart`'s answer to "which running services still hold the old library".
- **Policy-gated update application** — the host decides what it will accept; the control plane can
  only ask for something within that.
- **Provisioning templates** — cloud-init templates stored, versioned, encrypted at rest and rendered
  by HostSeal, and handed to *you*. HostSeal is not in the delivery path. A template signed offline may
  additionally be applied by a machine **once, at enrolment**, which is the one exception to
  everything else here and is argued out in
  [`docs/SECURITY.md` §7](docs/SECURITY.md#7-provisioning-and-the-enrolment-time-exception).
- **Observability that reaches somebody** — unit-state history at heartbeat resolution, a durable
  event inbox, a live feed in the interface, and alerting rules that mail, post to a webhook or raise
  a browser notification. A rule produces a notification and never a job; see
  [`docs/SECURITY.md` §8](docs/SECURITY.md#8-observability).
- **Container state, without the `docker` group** — off until a host opts in, read from `/proc` and the
  cgroup tree rather than from the socket, because socket access is root equivalence. It answers what
  is running and whether any of it is privileged, seccomp-disabled or holding the Docker socket; it
  cannot answer image names or exit codes, and says so rather than guessing.
- **Signing keys that are not files** — the destructive tier's key can live on a PKCS#11 token or in
  AWS KMS, Cloud KMS or Key Vault. Whichever it is, the control plane does not hold it, and the audit
  log records which one authorised each job.

## What it will never do

No remote shell. No configuration management — this is not Ansible. No metrics platform — Prometheus
does time series properly; this takes a low-frequency state snapshot. That sentence survives the
capacity figures above rather than in spite of them: one banded value per heartbeat, nothing retained
between them, no rates computed and no history kept. It tells you which host to point Prometheus at. No secret distribution — the
control plane never pushes credentials to hosts. No VPN requirement. No runtime plugin loader. No
database abstraction layer for portability.

`shell.exec`, `script.run`, arbitrary `file.write`, `apt.addRepository`, `user.create`,
`ssh.authorizedKeys.add` and `agent.updateFromURL` are **permanently refused**, each with its reason
written down in [`docs/SECURITY.md`](docs/SECURITY.md#permanently-refused). In an open-source project
that request arrives eventually, usually from someone with a real problem, and the answer needs to be
a document rather than an argument.

## Architecture

| | |
| --- | --- |
| **Agent** | Go. A static binary — no runtime on managed hosts, which is what keeps `MemoryDenyWriteExecute=yes` available |
| **Control plane** | Go. **One binary** with the Angular bundle embedded via `embed.FS`, plus PostgreSQL |
| **Database** | PostgreSQL, used deliberately: `JSONB` + GIN for facts, partial indexes for the job claim, `LISTEN`/`NOTIFY` instead of Redis, `SELECT … FOR UPDATE SKIP LOCKED` for atomic claims |
| **Web UI** | Angular + Angular Material + Tailwind v4, standalone components |
| **Queue / pubsub** | None |
| **Transport** | HTTPS long-poll with mTLS. Agent to server, never the reverse |

Open-source software is installed by strangers who close the tab on friction, and a four-service
Compose stack is friction. The stack in [`deploy/`](deploy/README.md) is those two services and nothing
else — no cache, no queue, no worker, no proxy of its own. Sharing one language between both sides also means the intent catalogue and
signature verification are *literally the same code* on the agent and on the server, rather than two
implementations that agree until they don't.

## Supported platforms

Ubuntu 22.04 (jammy), 24.04 (noble), 26.04 (resolute); Debian 12 (bookworm) and 13 (trixie).

The policy is a rule rather than a list: **the Ubuntu LTS releases in standard support, plus Debian
stable and oldstable.** Ubuntu 20.04 is excluded as ESM-only.

Windows Server 2019, 2022 and 2025 — **read-only**, and that is the design rather than a first version.

A Windows agent reports inventory, services, pending updates and reboot state, and refuses every
privileged intent. The mechanism that keeps a Linux host sovereign over privileged work is a fresh,
socket-activated root helper that re-reads the host's own policy and then exits; Windows has nothing of
that shape, so a privileged operation there would rest on the agent process alone. Two capabilities
cannot exist on Windows at all: there is no installable security-only subset of a cumulative update, so
`packages.applySecurity` is refused rather than approximated, and there is no `needrestart`.

The guarantee above is unchanged and unqualified — it says *any enrolled host* and names no operating
system. Where a platform cannot carry a mechanism at the strength Linux carries it, HostSeal does less
there. [`docs/SECURITY.md` §12](docs/SECURITY.md#12-windows-hosts) works that out in full.
Installing is [`docs/INSTALL.md`](docs/INSTALL.md#windows-server): there is no repository for Windows,
so the agent is one archive attached to each release and the installer in it is
`Install-HostSealAgent.ps1` — the only PowerShell in HostSeal, running once from an administrator's
session before there is an agent to constrain. The agent itself invokes no interpreter, and
`powershell.exe` is in the deny-lists that `internal/run` and `internal/intent` both check.

## Documentation

| | |
| --- | --- |
| [`docs/`](docs/) | Everything below, plus a note on where the design rationale lives |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Getting a control plane and a host running, and what a fresh host will and will not do |
| [`docs/SECURITY.md`](docs/SECURITY.md) | The guarantee, the three mechanisms, the permanently-refused list, and an honest statement of what HostSeal does *not* defend against |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | The agent protocol, specified well enough to reimplement |
| [`docs/EXTENDING.md`](docs/EXTENDING.md) | The seams that are open, and the ones that are closed on purpose |
| [`deploy/README.md`](deploy/README.md) | The control plane in containers: the image, the Compose stack, Traefik without terminating TLS, Let's Encrypt for the interface, and a streaming replica |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | DCO sign-off, English, and the comment rule |
| [`TRADEMARK.md`](TRADEMARK.md) | What you may call your fork |

## Building

```bash
make build          # all three binaries into ./dist
make test           # unit tests
make guarantee      # the tests that enforce docs/SECURITY.md §1
make lint           # golangci-lint + doccheck
make web            # the Angular application, embedded into hostseal-server
make deb            # the hostseal-agent .deb via nfpm
make image          # the hostseal-server container image
```

Go 1.26 or newer. `make deb` additionally needs [`nfpm`](https://nfpm.goreleaser.com/);
`make web` needs Node and pnpm; `make image` needs Docker.

## Licence, and why it will not change

**Apache-2.0 for everything.** Contributions are made under the
[Developer Certificate of Origin](https://developercertificate.org/) — there is no CLA, and Pascal
Groß holds no special rights over contributed code that you do not also hold. Copyright stays with
each contributor: the notice for the project as a whole reads
"Copyright 2026 Pascal Groß and the HostSeal contributors" (see [`NOTICE`](NOTICE)).

This is deliberately permanent. Relicensing a DCO project requires the agreement of every contributor,
which means **no future owner of this repository can take it proprietary**, including us. For a
security tool whose entire value is that you can verify its claims yourself, the ability to promise
that is worth more than the option to change our minds.

Apache-2.0 §6 grants no permission to use the project's name or other identifying signs as branding
for your own product. HostSeal is not a registered trademark; the uses of the **HostSeal** name and
brand that Pascal Groß permits are described in [`TRADEMARK.md`](TRADEMARK.md). You may fork the code
and ship it; please do not call your fork HostSeal.

## Contributing

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. Two rules catch most first-time contributors:

- **Everything is in English** — identifiers, comments, docs, commit messages, issues, UI strings. A
  project asking strangers to audit its security claims cannot also ask them to read German first.
- **Every type and function carries a doc comment covering what it does *and why it exists*.**
  Exported or not. If the comment would still be true after you deleted the function, it is not a
  comment about why the function exists.

Security issues go through GitHub's private advisory flow, not the public tracker —
[`docs/SECURITY.md` §11](docs/SECURITY.md#11-reporting-a-vulnerability).
