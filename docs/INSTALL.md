# Installing HostSeal

What you get from this is a fleet that reports: inventory, systemd unit state, pending updates with
security separated from the rest, and which services still hold replaced libraries.

The privileged operations are real now — applying updates, starting, stopping and restarting a unit,
rebooting — and each is bounded by a root-owned file the control plane cannot modify. The control plane
can ask for them: `POST /api/v1/jobs` queues one, and whether it then waits for somebody to release it
is a setting on your fleet — see [`SECURITY.md` §3](SECURITY.md#3-the-intent-catalogue).

A destructive job carries a signature made offline by a key the control plane does not hold. `hostseal
sign` is what produces one, and it never contacts the server — it renders what you are about to
authorise from the same payload it then signs.

## The control plane

You need PostgreSQL 14 or newer, and one binary.

```bash
# 1. The certificate authority that issues agent certificates.
sudo hostseal-server ca init --ca-dir /var/lib/hostseal-server/ca

# 2. A database. An ordinary role that owns the schema — not the postgres superuser.
sudo -u postgres createuser hostseal --pwprompt
sudo -u postgres createdb --owner hostseal hostseal

# 3. Run it. The schema is created on first start, and so is the first account —
#    whose password is printed once, on this terminal, and nowhere else.
export HOSTSEAL_DATABASE_URL='postgres://hostseal:...@localhost/hostseal?sslmode=disable'
hostseal-server serve --addr :8443 --ca-dir /var/lib/hostseal-server/ca
```

**Connect as an ordinary role, not as `postgres`.** Fleets are isolated from one another by PostgreSQL
row-level security, and a superuser — or any role with `BYPASSRLS` — is exempt from every policy in the
schema. The exemption has no symptom whatsoever: the policies are still there, the queries still carry
their predicates, and every query returns every fleet's rows. `hostseal-server` checks its own role at
startup and refuses to run on either, so you will be told rather than left to find out. See
[`SECURITY.md` §5](SECURITY.md#5-tenants).

Two things about TLS are worth knowing before you reach them.

The agent protocol authenticates hosts with **client certificates**, which do not exist without TLS —
so a control plane with no certificate does not serve agents insecurely, it cannot serve them at all.
`hostseal-server serve` therefore refuses to start without one, and issues one from its own CA if you do
not supply one. An enrolled agent trusts that automatically, because it is handed the CA bundle at
enrolment. A browser will not, so pass `--tls-cert` and `--tls-key` from whatever issues your public
certificates before operators use the interface in earnest.

Back up `ca.key` **separately from the database**. An attacker with both can impersonate hosts to this
control plane; an attacker with the database alone cannot. Neither lets them run code on a host: an
agent authorises a job by its class and its signature, not by who asked.

The other key in that directory asks nothing of you. `online.key` is generated on first start, and it
signs the one privileged operation that carries no offline signature: `packages.applySecurity`. There is
no command that creates it and nothing to distribute — its public half reaches agents in the enrolment
response and on every heartbeat, so rotating it is deleting the file and restarting: hosts pick the new
one up on their next heartbeat, and a routine job queued before the change stops verifying. It is
**not** a trust anchor and never belongs in a host's `trusted-signers`: an agent that accepted an
online-key signature for a reboot would be the backdoor the rest of this design is arranged against, and
it refuses one. What bounds a routine job instead is the host's own policy — see
[`SECURITY.md` §3](SECURITY.md#3-the-intent-catalogue).

### Operators, and how they sign in

Everybody gets an account: an address, a password, and a session in an `HttpOnly` cookie. There is no
shared credential and deliberately no way to configure one. `HOSTSEAL_ADMIN_TOKEN` and
`HOSTSEAL_PLATFORM_TOKEN` used to be here, and they are gone rather than deprecated — one string for a
whole fleet names nobody in the audit trail, cannot be taken away from one person who has left, never
expires, and made the two-person approval rule unsatisfiable by construction, because it compares the
approver against the job's creator and under one token those were always the same string.

The first start of an empty database creates one account so that there is a way in, and prints its
password once:

```
This control plane had no accounts, so one has been created.

  address:  admin@localhost
  password: <24 characters, printed here and nowhere else>
```

Set `HOSTSEAL_BOOTSTRAP_EMAIL`, and `HOSTSEAL_BOOTSTRAP_PASSWORD` or `--bootstrap-password-file`, to
choose them yourself. Either way the accounts table is the truth afterwards: neither is read again.

Then give each person their own:

```bash
sudo -u hostseal hostseal-server accounts add --email ops@example.org --name "Ops"
# Password: (typed, twice, never a flag: argv is world-readable in ps)
```

`accounts list` shows who has one and when they last signed in, `accounts passwd` sets a new password,
and `accounts remove` deletes the account together with every session and token it holds — which is the
whole of "somebody has left". Somebody who is signed in can change their own password from the account
page without any of this.

Accounts are created here, on the machine, and by no API. That is deliberate and
[`SECURITY.md` §5.3](SECURITY.md#53-the-platform-administrator) says why: the credential that
administers fleets must not be able to authenticate as a customer, so it is given no route that would
let it. `--tenant` names the fleet; it defaults to the one the control plane serves.

### What a script uses

Not a password, and not a shared token. An operator issues an **API token** from the account page in the
web interface: it belongs to that account, acts as that account in the audit trail, may expire, and is
revoked from the same page in a second.

```bash
export HOSTSEAL_TOKEN=hsl_...                      # shown once, when it is issued
curl -s https://hostseal.example.org/api/v1/hosts \
  -H "Authorization: Bearer $HOSTSEAL_TOKEN"
```

It is a bearer token and that is not a contradiction with the paragraph above. What was wrong with the
old one was never the word "bearer": it was one credential for a whole fleet, held in a flag, naming
nobody, never expiring, and withdrawable only by restarting the control plane with a new one and telling
everybody.

One thing a token deliberately cannot do is reach `/api/v1/account` — the routes that mint and revoke
tokens, change a password and end sessions. A token that could issue another, with no expiry, would
outlive its own revocation. Those routes want a signed-in browser, and answer a token with 403 and a
sentence saying so.

### In containers, if that is how you run things

The same two pieces — one binary and PostgreSQL — as a Compose stack, in
[`deploy/`](../deploy/README.md):

```bash
cd deploy
cp .env.example .env      # four passwords; `openssl rand -hex 32` for each
docker compose up -d
```

The first start builds the image from the checkout, creates the certificate authority, creates an
ordinary database role and the database it owns, and serves on `https://localhost:8443`. The role is
the part worth reading about before you deviate from it: the PostgreSQL image's own superuser is exempt
from every row-level security policy in the schema, which is the paragraph above with the failure mode
that has no symptom.

Traefik is optional, in an overlay of its own, and routes rather than terminates — a **TCP** router with
`tls.passthrough=true`. A proxy that terminated TLS would end the connection carrying an agent's client
certificate and open one that does not, and the only way for the server to keep identifying hosts across
that would be to believe a header that anything reaching the proxy's back end can set. What follows from
passthrough — which certificate a browser sees, and why enrolling a rack at once through a proxy meets
the rate limiter — is in [`deploy/README.md`](../deploy/README.md).

A certificate a browser trusts comes from giving the interface a **second** hostname, where Traefik does
terminate and Let's Encrypt applies normally. Agents keep the passthrough name and need no public
certificate at all, because they verify against the CA bundle they were handed at enrolment. That is a
second overlay, and the agent endpoints are refused on the interface name.

A streaming replica is a second overlay. The database is configured for one from its first start, so
adding it later needs no restart of a primary that is by then serving a fleet.

### Mail, for alerts that reach somebody who is not looking

Optional, and off until you configure it. Alerting rules are per fleet and editable in the interface;
which relay this installation may speak to is yours:

```bash
hostseal-server serve \
  --smtp-host smtp.example.com --smtp-port 587 \
  --smtp-from hostseal@example.com --smtp-username hostseal \
  --smtp-password-file /etc/hostseal-server/smtp.password \
  ...
```

Port 465 speaks TLS from the first byte and anything else — 587 in practice — upgrades with STARTTLS.
Plaintext SMTP is not offered: an alert legitimately carries hostnames and failure text, and a relay
that does not offer STARTTLS is refused rather than downgraded to. The password comes from a file, or
from `HOSTSEAL_SMTP_PASSWORD`, and never from a flag, because `argv` is world-readable in `ps`.

Without a relay, every other route still works — the event inbox, the live feed in the interface, and
each fleet's webhook — and a rule that names recipients says on the rule that its mail did not go out.

### A screen, for the people who are

The wallboard is the fleet in one glance — how many hosts are fine, how many are not, how many nobody
can answer for, and the handful worth walking towards — refreshed every fifteen seconds and legible
from the other side of a room. Operators reach it at `/wallboard` with the credential they already
have. A television in a corridor cannot sign in, so it gets a **published link** instead:

```bash
# The label is the heading the screen shows, so name the fleet rather than the link.
curl -sX POST https://hostseal.example.org/api/v1/wallboard/shares \
  -H "Authorization: Bearer $HOSTSEAL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"Production — Frankfurt","days":90,"passphrase":"the one on the sticker"}'
```

```json
{
  "share": {
    "id": "01JAV0Q7X4M2R6P9T3K5N8W1YB",
    "label": "Production — Frankfurt",
    "createdAt": "2026-08-28T09:14:02Z",
    "createdBy": "local-account:ops@example.org",
    "expiresAt": "2026-11-26T09:14:02Z",
    "lastSeenAt": null,
    "passphrase": true,
    "expired": false
  },
  "link": "https://hostseal.example.org/board#hsb_01JAV0….k7q2…"
}
```

**Keep the link now — it is shown once and cannot be recovered.** Only its digest is stored, exactly as
for an enrolment token and an API token, so there is nothing to print it from later. If you lose it,
publish another and withdraw this one; that is a second of work and the only way back.

The secret is the part after the `#`, and a fragment is never sent to a server. It is in no access log
here, none at your reverse proxy, no `Referer`, and not in the fetch a chat client makes to build a
preview when somebody pastes the link into a channel. It is still in the browser's history and still in
the address bar, so treat a photograph of the screen as a copy of the link.

`days` is optional — ninety by default, 365 at most, and deliberately no "never". `passphrase` is
optional too: with one, the board asks for it once on that screen and remembers the answer in a cookie
until the link expires or you change the passphrase, which drops every screen that was unlocked under
the old one.

Listing and withdrawing are the other two:

```bash
curl -s https://hostseal.example.org/api/v1/wallboard/shares \
  -H "Authorization: Bearer $HOSTSEAL_TOKEN"

# Withdrawing is a delete, and takes effect at the next poll — within fifteen seconds.
curl -sX DELETE https://hostseal.example.org/api/v1/wallboard/shares/01JAV0Q7X4M2R6P9T3K5N8W1YB \
  -H "Authorization: Bearer $HOSTSEAL_TOKEN"
```

The listing includes expired links as well as live ones, because a screen that has gone dark is the
first thing somebody comes looking for and "there is no such link" is the wrong answer to give the
person holding it. `lastSeenAt` says that a screen is still polling, roughly; it does not say who is
watching, and cannot.

A fleet may hold twenty live links at once. That is not a capacity limit — it keeps the list short
enough that you recognise every line of it, which is how you would notice one you did not publish.

Read [`SECURITY.md` §4.6](SECURITY.md#46-the-wallboard-and-its-link) before publishing a link outside
the building it hangs in. The short version is that a leaked link shows a remote stranger roughly what
somebody standing in the corridor already sees, continuously, until it expires or you delete it — and
that it names whoever published it and can never name who read it.

### More than one fleet

The command above gives you a fleet called `default`, and if that is all you want you can stop reading
this section — everything below is optional and nothing above changes.

One control plane can serve several independent fleets. They share the binary, the database and the
certificate authority, and they share nothing else: no fleet can see another's hosts, tokens, jobs or
results, and an operator credential reaches exactly one of them. There is no fleet in any URL, so there
is nothing an operator could edit to be somewhere else.

Provisioning one is a separate account's job. A **platform administrator** carries no fleet at all, and
that is the whole of what makes them one:

```bash
sudo -u hostseal hostseal-server accounts add --platform --email you@example.org --name "You"
```

They sign in exactly like anybody else, and get a fleets screen — create, rename, retire, and set each
fleet's approval mode and webhook — and nothing else, because a platform credential is refused by every
route that reaches a fleet's hosts or jobs. The same thing from a terminal, with an API token that
account issued for itself:

```bash
# $HOSTSEAL_TOKEN is an API token that account issued for itself, from its own account page.
curl -sX POST https://control.example.org/api/v1/tenants \
  -H "Authorization: Bearer $HOSTSEAL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"slug":"acme","displayName":"Acme Ltd","approvalMode":"second_person"}'
```

A platform administrator administers fleets and **reaches no fleet's hosts or jobs** — every operator
route refuses them, and every fleet route refuses an operator. That separation is the point of having
two kinds of account rather than one: running HostSeal for other people should not require being able to
read what they run.

They also cannot create a fleet's operator. That happens on the machine, like every other account:

```bash
hostseal-server accounts add --tenant acme --email ops@acme.example --name "Acme Ops"
```

Which is not an inconvenience to be routed around — [`SECURITY.md`
§5.3](SECURITY.md#53-the-platform-administrator) turns on it, because an API that handed out a fleet's
credentials would make whoever runs the installation able to authenticate as any customer.

`approvalMode` is that fleet's answer to "who has to agree before a host may act on a destructive job",
and it is per fleet because a one-person shop and a regulated customer cannot share an answer. The three
values and the reasoning are in [`SECURITY.md` §3](SECURITY.md#3-the-intent-catalogue).

## A host

The interface has this as a panel: **Fleet → Add a host** mints the token, fills in this control plane's
own address and gives you the three commands with a copy button on each. The label, the group and the
lifetime are fields beside the button, each optional. Under the steps, the panel lists every token
minted in the fleet — never the values, which
are not stored — with whether each is open, was spent and by which host, or expired unused. What
follows is the same thing for a script, and the same thing to read when you want to know what those
commands do.

```bash
# On the control plane, or through the web interface:
curl -sX POST https://hostseal.example.org/api/v1/tokens \
  -H "Authorization: Bearer $HOSTSEAL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"web tier","group":"web-prod"}'
```

The token comes back once and is not recoverable: only its hash is stored, so a database dump does not
let its holder enrol hosts. It is single-use and expires in a day by default.

```bash
# On the host:
curl -fsSL https://hostseal.io/apt/hostseal-archive-keyring.gpg \
  | sudo tee /usr/share/keyrings/hostseal-archive-keyring.gpg > /dev/null
curl -fsSL https://hostseal.io/apt/hostseal.sources \
  | sudo tee /etc/apt/sources.list.d/hostseal.sources > /dev/null
sudo apt-get update && sudo apt-get install hostseal-agent

# Trust this control plane's authority, before enrolling rather than after: an agent that starts
# without it fails to verify the server and retries, so you get a running service and a host that
# never appears — which reads as a control-plane fault. The certificate is public; it is handed to
# every enrolling agent before that agent has a credential at all.
#
# Fetch it over a connection you can already verify — see below, because on the agent hostname you
# cannot, and that is not a fault either.
curl -fsSL https://hostseal.example.org/api/v1/ca.crt \
  | sudo install -D -o root -g root -m 0644 /dev/stdin /etc/hostseal/server-ca.crt

sudo hostseal enroll --server https://hostseal.example.org --token hsl_…
sudo systemctl restart hostseal-agent
```

`hostseal enroll` reads that path without being told, so the two commands are the ordering they look
like: install the authority, then enrol against it. `--ca` overrides it, and a `--ca` naming a file that
is not there fails rather than quietly falling back to the system roots — which would verify a chain
you did not ask for at the one moment you were being specific about which to trust.

Skip the certificate step only when the control plane has a publicly trusted certificate, which is what
the Traefik overlay in `deploy/` gives the *interface* and deliberately not the agent hostname: agents
verify against the CA they were handed, so they need no public certificate and get no benefit from one.

### Where to fetch it from

That `curl` verifies the control plane like any other client, so it works from a hostname whose
certificate the host already trusts and not from one whose certificate is the thing being fetched. On a
control plane serving its own certificate — the default, and the agent hostname in the Traefik
deployment, where TLS passes through to `hostseal-server` untouched — it fails with `unable to get local
issuer certificate`. That is the tool being right: nothing has told this host to trust that authority
yet, which is the entire reason for the step.

There are three honest ways round it, in order of preference.

**From the interface hostname**, when the two-hostname Traefik deployment gave it a publicly trusted
certificate. `/api/v1/ca.crt` is unauthenticated and outside the `/agent` prefix that hostname refuses,
so the command above works unchanged with that name in it.

**By copying the file**, which needs no TLS at all. On the control plane:

```bash
docker compose cp hostseal-server:/var/lib/hostseal-server/ca/ca.crt ./hostseal-ca.crt
```

Then move it to each host and `install` it at the same path. It is a public document, so it needs no
protection in transit beyond arriving unmodified.

**By fetching it unverified and checking the fingerprint**, when the host can reach neither. This is
what **Fleet → Add a host** prints for you when it detects that case, with the expected digest filled
in — it knows its own, and your session is the channel that carries it. Written out:

```bash
curl -fsSLk https://agents.hostseal.example.org/api/v1/ca.crt -o /tmp/hostseal-ca.crt
if [ "$(openssl x509 -in /tmp/hostseal-ca.crt -noout -fingerprint -sha256)" \
     = "sha256 Fingerprint=<the digest the panel shows>" ]; then
  sudo install -D -o root -g root -m 0644 /tmp/hostseal-ca.crt /etc/hostseal/server-ca.crt
else
  echo "FINGERPRINT MISMATCH - do not install this certificate" >&2
  false
fi
```

The comparison is in the shell rather than in your eyes on purpose: two 64-character hex strings are
compared by looking at the first four characters, and that is not a comparison. It is an `if` rather
than the shorter `test … && install || echo`, because in that form the `||` binds to the whole list —
so a missing `sudo` or a full disk fails the install, prints an attack that did not happen, and then
exits 0, leaving a script free to enrol against a certificate it never installed. If you have no panel
to read the digest from, take it from the control plane itself:

```bash
docker compose exec hostseal-server \
  openssl x509 -in /var/lib/hostseal-server/ca/ca.crt -noout -fingerprint -sha256
```

`-k` with no comparison is not a shortcut, it is the enrolment trusting whoever answered the name. The
window is one request wide and the consequence lasts the life of the host: an authority accepted here
is what every later connection is checked against, so an attacker who owned that one response owns the
host's idea of the control plane permanently.

### When the agent says "not enrolled" on a host that enrolled

`hostseal enroll` is run with `sudo` and the service runs as the unprivileged `hostseal` account, so
everything enrolment writes is handed to that account before it returns. On an agent built before that
was true, the credential stayed root-owned at mode 0600 and the service could not open it — which looks
like nothing at all: the control plane lists the host, because the enrolment did succeed, and the unit
is active, because an unenrolled agent idles rather than exiting. Only the absence of facts says
anything is wrong. If you have a host in that state, it needs no second enrolment and no second token:

```bash
sudo chown -R hostseal:hostseal /var/lib/hostseal
sudo systemctl restart hostseal-agent
```

The `.sources` file uses deb822 with `Signed-By:` naming an explicit keyring, so the HostSeal key is
trusted for the HostSeal repository only. `apt-key` is never used: it installs a key that is trusted for
every repository on the system, which turns one compromised project into root on the machine.

### Windows Server

A Windows host is read-only — inventory, services, pending updates and reboot state — and that is the
design rather than a first version. [`SECURITY.md` §12](SECURITY.md#12-windows-hosts) works out why, and
what it would take for that to change. Everything else is the enrolment above: the same token, the same
certificate, the same single outbound connection, the same guarantee.

What is different is how the software arrives. There is no repository to subscribe to. The agent is one
archive — `hostseal-agent-windows-amd64.zip`, attached to every [release][releases] — and an upgrade is
the same download through the same installer. Nothing on a Windows host fetches the next version by
itself, so this is a step somebody comes back for.

The archive holds `hostseal-agent.exe`, `hostseal-update-scan.exe`, `hostseal.exe`, the default
`policy.toml` and `Install-HostSealAgent.ps1`. The installer is the only PowerShell in HostSeal and runs
once, from an administrator's own session, before there is an agent to constrain — the agent itself
invokes no interpreter, and `powershell.exe` is in the deny-lists `internal/run` and `internal/intent`
both check. Everything below runs in an **elevated** session.

```powershell
# 1. Fetch the archive and run the installer.
& {
  $ErrorActionPreference = 'Stop'
  $zip = Join-Path $env:TEMP 'hostseal-agent-windows-amd64.zip'
  $dir = Join-Path $env:TEMP 'hostseal-agent'
  Remove-Item -Path $zip, $dir -Recurse -Force -ErrorAction SilentlyContinue
  curl.exe -fsSL https://github.com/pascalgross/hostseal/releases/latest/download/hostseal-agent-windows-amd64.zip -o $zip
  if ($LASTEXITCODE -ne 0) { throw 'the download failed; nothing has been installed' }
  Expand-Archive -Path $zip -DestinationPath $dir
  Get-ChildItem -Path $dir -Recurse | Unblock-File
  & (Join-Path $dir 'Install-HostSealAgent.ps1')
}

# 2. Trust this control plane's authority, before enrolling rather than after — the same ordering,
#    and the same failure when it is done the other way round.
& {
  $ErrorActionPreference = 'Stop'
  $tmp = Join-Path $env:TEMP 'hostseal-ca.crt'
  curl.exe -fsSL https://hostseal.example.org/api/v1/ca.crt -o $tmp
  if ($LASTEXITCODE -ne 0) { throw 'the certificate could not be fetched; nothing was installed' }
  Copy-Item -Path $tmp -Destination 'C:\Program Files\HostSeal\server-ca.crt' -Force
}

# 3. Enrol, and restart so the running service reads it.
& 'C:\Program Files\HostSeal\hostseal.exe' enroll --server https://hostseal.example.org --token hsl_…
Restart-Service hostseal-agent
```

Each step is one `& { … }` block because that is what makes a failure stop it. Pasted as loose lines,
every line is its own statement: a download that fails leaves the next command running, and the staging
paths are fixed, so the run before this one may have left an archive and an unpacked tree in `%TEMP%`.
The installer would then start from stale files, stop the service, copy older binaries over newer ones
and report a successful upgrade. Inside a block, `throw` abandons the rest, and
`$ErrorActionPreference` set there belongs to that block's scope, so a failing cmdlet is terminating
without the session being left altered afterwards. `$LASTEXITCODE` is checked by hand because no
preference variable covers a native program, and `-f` makes curl *return* failure rather than raise it.

Step 2 fetches to a temporary file and copies it in, rather than writing straight to the trust anchor's
path, for the same reason: curl truncates its output file before it knows the response status — and
`--remove-on-error`, which would clean that up, is newer than the curl on Server 2019 — so the direct
form can leave an empty `server-ca.crt` behind on a 404. `hostseal enroll` reads that path when it
exists, so enrolment would then fail to verify a control plane that was never the problem.

Step 3 needs no such block. A failed enrolment is loud, and restarting an agent that is still unenrolled
changes nothing: it idles again, exactly as it was.

`curl.exe` with the extension, and that is not pedantry: in Windows PowerShell 5.1 — what ships with
every supported Windows Server — `curl` is an alias for `Invoke-WebRequest`, whose parameters these
arguments do not fit (`-o` is ambiguous between `-OutFile` and two common parameters), and which fails
on a host with Internet Explorer Enhanced Security for want of `-UseBasicParsing`. The real curl has
been in `System32` since Server 2019, which is this project's floor.

`Unblock-File` because every file unpacked from a downloaded archive carries the internet zone, and the
default execution policy on Windows Server refuses an unsigned script bearing it. The error names the
execution policy rather than the zone, which sends people to `Set-ExecutionPolicy Bypass` and leaves the
machine weaker than it was found. Clearing the zone on the files you just downloaded is the smaller act.
Run the installer from where the archive was unpacked, too: it installs `policy.toml` from beside
itself.

There is no `chown` or `chmod` in step 2 and nothing is missing. The installer replaces the ACL on
`C:\Program Files\HostSeal` with an explicit one that inherits, granting the agent's service account
read and execute and nothing else, so a file created there is already right. That is also why the last
line is `Copy-Item` and not `Move-Item`: a copy creates a new file, which inherits that ACL, while a
move within a volume keeps the permissions the file had in `%TEMP%`, where the agent's account is not
named at all — leaving it unable to read the authority it verifies the control plane against.

The restart in step 3 is not optional, and it is not optional on Debian either. The installer starts the
service, so by the time you enrol there is already an agent running — one that found no credential, said
so, and settled into reporting local state on a timer. That loop re-reads the local policy on every tick
and never re-reads the enrolment state. Skip the restart and you have an active service, a host the
control plane heard from exactly once, and no facts arriving.

**Fleet → Add a host** prints all three with this control plane's own address and a fresh token filled
in; the switch above the commands is what chooses between these and the Debian ones.

#### When the control plane serves its own certificate

Step 2 fetches over a connection `curl.exe` verifies like any other client, so it works from a hostname
the host already trusts and not from one whose certificate is the thing being fetched — the same
[bootstrap problem](#where-to-fetch-it-from) as on Debian, with the same three ways round it. Written
out, the unverified fetch with the fingerprint check that makes it safe:

```powershell
& {
  $ErrorActionPreference = 'Stop'
  $tmp = Join-Path $env:TEMP 'hostseal-ca.crt'
  curl.exe -fsSLk https://agents.hostseal.example.org/api/v1/ca.crt -o $tmp
  if ($LASTEXITCODE -ne 0) { throw 'the certificate could not be fetched; nothing was installed' }
  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $tmp
  $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)
  $got = ($sha | ForEach-Object { $_.ToString('X2') }) -join ':'
  if ($got -ne '<the digest the panel shows>') {
    throw 'FINGERPRINT MISMATCH - do not install this certificate'
  }
  Copy-Item -Path $tmp -Destination 'C:\Program Files\HostSeal\server-ca.crt' -Force
}
```

The fetch is checked before anything is compared, and that ordering is the point rather than tidiness.
Without it a failed download leaves `$cert` unset, the digest empty and the comparison false — so the
step reports a fingerprint mismatch, naming an attack that did not happen, for a control plane that was
merely unreachable. It is the same failure the shell version's `if`/`else` is written to avoid, and the
mismatch is a guard clause rather than the `else` of the copy so that a copy which fails keeps its own
error too.

The digest is computed over the certificate's `RawData` rather than with `Get-FileHash`, because the
value the panel shows is openssl's — a SHA-256 over the DER — and hashing the PEM file's bytes produces
a different number that matches nothing. A check that fails every honest fetch is a check people stop
performing, which is worse than not writing one. `SHA256::Create` rather than `GetCertHash('SHA256')`,
whose overload arrived in .NET Framework 4.8 and is absent on a Server 2019 host nobody has updated.

#### What the installer did, and undoing it

The service runs as `NT SERVICE\hostseal-agent` with an empty required-privileges list — the SCM strips
every privilege not named, and `SeShutdownPrivilege` is therefore absent, so the agent could not restart
its host if its code tried to. It is a member of `BUILTIN\Users`, which is the weakest membership
`IUpdateSearcher` will answer to; without it the update scan fails with `E_ACCESSDENIED` and the host
reports its updates as unmeasurable for ever. `trusted-signers` is created empty and never overwritten,
on a fresh install and on an upgrade alike.

```powershell
# From the unpacked archive: the installer is not one of the files it copies into Program Files.
& (Join-Path $env:TEMP 'hostseal-agent\Install-HostSealAgent.ps1') -Uninstall
```

removes the service and the three binaries, and deliberately leaves the state directory, the policy file
and the trust anchor behind. Deleting `trusted-signers` would silently re-open every destructive operation
an administrator had closed, with no symptom until a signature that should verify does not.

[releases]: https://github.com/pascalgross/hostseal/releases

## Asking a host to do something

```bash
# Read-only work needs nothing but an operator credential.
curl -sX POST https://hostseal.example.org/api/v1/jobs \
  -H "Authorization: Bearer $HOSTSEAL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"hostId":"01J…","intent":"facts.collect","params":{}}'

curl -s "https://hostseal.example.org/api/v1/jobs?host=01J…" \
  -H "Authorization: Bearer $HOSTSEAL_TOKEN"
```

A job comes back with a `state`: `queued`, `awaiting_approval`, `running`, or whatever status the host
reported. The `result` is null until the host reports one, which is how "not reported yet" stays
distinguishable from "reported nothing".

A **destructive** job — applying every update, starting, stopping or restarting a unit, rebooting —
needs two more things, and neither of them is the control plane's to give.

1. A signature over the job, made offline with a key listed in that host's own
   `/etc/hostseal/trusted-signers`. It is sent with the request, along with the `id`, `nonce`,
   `notBefore` and `notAfter` it covers; every one of those comes from the signer, because a value
   chosen by the control plane would invalidate the signature.

   ```bash
   hostseal sign --key ~/.hostseal/ops.key --host 01J9ABC… \
     --intent service.restart --params '{"unit":"nginx.service"}' \
   | curl -sX POST "$HOSTSEAL_URL/api/v1/jobs" \
       -H "Authorization: Bearer $HOSTSEAL_TOKEN" \
       -H 'Content-Type: application/json' -d @-
   ```

   It shows you the operation, the host, the window and the exact bytes it is about to sign, and asks
   before signing. It never talks to the control plane: if it signed a digest the server handed it, a
   compromised control plane could display one operation and have another authorised. `hostseal` runs
   on your own machine and is not the agent — [the operator's CLI](#the-operators-cli) is where to get
   it.

   The web interface can do the same thing without the copying — see
   [signing from the web interface](#signing-from-the-web-interface) below.
2. Release, if your fleet asks for it — `POST /api/v1/jobs/{id}/approve`. Whether that is required at
   all, and whether the releaser must be somebody other than the job's creator, is your fleet's
   `approvalMode`. A new fleet requires nothing; see
   [`SECURITY.md` §3](SECURITY.md#3-the-intent-catalogue).

A **routine** job — `packages.applySecurity` — needs neither. The control plane signs it with its own
key, and what bounds it is your host's `updates.allow`: the worst the control plane can do is make a
host apply security updates sooner than its own timer would have.

### The operator's CLI

`hostseal` is the one binary that runs on **your** machine rather than on a managed host. It enrols
hosts, generates and inspects signing keys, signs jobs offline, and answers the web
interface over loopback. It is also the only binary in HostSeal that links a signing backend — a
PKCS#11 module, a cloud KMS — which is why no agent, helper or server does, and why a host cannot tell
which kind of key signed the job it is verifying.

Every release attaches it, for the platforms an operator signs from:

```bash
# Linux. The checksums name the paths the release was built from, so compare against that line.
curl -fsSL -o hostseal \
  https://github.com/pascalgross/hostseal/releases/latest/download/hostseal-linux-amd64
curl -fsSL -o SHA256SUMS \
  https://github.com/pascalgross/hostseal/releases/latest/download/SHA256SUMS
grep 'dist/hostseal-linux-amd64$' SHA256SUMS | awk '{print $1}'
sha256sum hostseal | awk '{print $1}'
sudo install -m 0755 hostseal /usr/local/bin/hostseal
```

```powershell
# Windows. The archive holds hostseal.exe and nothing else — it is not the agent and installs no
# service. LOCALAPPDATA rather than Program Files: this is one operator's tool, holding one operator's
# key, and putting it there needs no administrator.
& {
  $ErrorActionPreference = 'Stop'
  $dir = Join-Path $env:LOCALAPPDATA 'HostSeal'
  $zip = Join-Path $env:TEMP 'hostseal-windows-amd64.zip'
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  curl.exe -fsSL https://github.com/pascalgross/hostseal/releases/latest/download/hostseal-windows-amd64.zip -o $zip
  if ($LASTEXITCODE -ne 0) { throw 'the download failed; nothing has been installed' }
  Expand-Archive -Path $zip -DestinationPath $dir -Force
  Unblock-File -Path (Join-Path $dir 'hostseal.exe')

  # Nothing puts it on PATH for you. New sessions only — this one already has the old value.
  $user = [Environment]::GetEnvironmentVariable('Path', 'User')
  if ($user -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable('Path', "$user;$dir", 'User')
  }
}
```

From source, `make build` writes it to `dist/hostseal` along with everything else.

What **not** to do is install a host's package to get it. The `.deb` and
`hostseal-agent-windows-amd64.zip` both carry the same `hostseal` binary, because `hostseal enroll`
runs on the host being enrolled and a machine with only the agent could never enrol. Installing either
of them on a workstation brings an agent with it: the package enables and starts
`hostseal-agent.service` and the three root-helper sockets, and `Install-HostSealAgent.ps1` registers
and starts the Windows service. Neither is wrong on a host and neither belongs on the machine that
holds your signing key.

### Signing from the web interface

Copying a JSON document out of a terminal and into a browser is not the interesting part of signing,
and on a Windows workstation it was for a long time the only way to use a YubiKey at all. So the same
tool will answer the browser directly:

```powershell
# On the machine your token is plugged into. Windows, with Yubico's PKCS#11 module. By path, because
# nothing adds hostseal.exe to PATH — `hostseal signer` works once you have added it yourself, above.
& "$env:LOCALAPPDATA\HostSeal\hostseal.exe" signer `
  --key "pkcs11:token=YubiKey PIV #12345678;object=SIGN key?module-path=C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll" `
  --origin https://hostseal.example.org
```

```bash
# The same thing on Linux, with whatever module your token uses:
hostseal signer \
  --key 'pkcs11:token=ops;object=ops-yubikey-1?module-path=/usr/lib/opensc-pkcs11.so' \
  --origin https://hostseal.example.org
```

It asks for the token's PIN once, prints the `trusted-signers` line for the key it found, and listens
on `127.0.0.1:18515` — loopback only, and only for the origins you named. The Jobs page then offers
**Sign with your token**: the browser sends what you filled in, the signer decodes it
against its own copy of the catalogue, prints what it means in *its* terminal, and waits for you to
answer and to touch the key. What comes back is a signature; what never moves is the key.

Three things are worth knowing before you rely on it:

- **The terminal is the display that counts.** What you confirm there is what gets signed — the signer
  builds the signed document itself and will not sign anything handed to it. If the terminal shows an
  operation you did not ask for in the browser, say no: you have just caught a compromised control
  plane.
- **`--origin` is not optional and is not a wildcard.** It is the address you open HostSeal at.
  Without it, any page in your browser could ask your signer for a signature.
- **The signer exits after half an hour of doing nothing** (`--idle`), because a logged-in token
  session nobody is using is worth closing. Start it again when you need it.

#### Starting it at logon

Remembering to start the signer is the part nobody does, and the moment you remember it is the moment
the Jobs page has already told you that nothing answered. On Windows, `--install` registers the command
you just typed to run at your next logon:

```powershell
& "$env:LOCALAPPDATA\HostSeal\hostseal.exe" signer `
  --key "pkcs11:token=YubiKey PIV #12345678;object=SIGN key?module-path=C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll" `
  --origin https://hostseal.example.org `
  --install
```

It writes one value — `HostSeal signer`, under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
— and prints the command line it registered, so you can read what will run before a logon depends on
it. Nothing is elevated, nothing is registered for the other accounts on that machine, and your token
is not opened: run the same command without `--install` once, so that a wrong module path is something
you find now rather than at a logon. `--uninstall` removes the registration, needs none of the other
flags, and is safe to run whether or not there is one.

What starts is the same program in your own session, in a window of its own, asking for the PIN there.
The idle exit is unchanged — a signer nothing has asked for anything in half an hour still stops, and
the next one starts at your next logon — so this shortens the typing rather than lengthening the time a
token session is open.

It is deliberately **not** a service, and that is a refusal rather than a gap. Every signature is
confirmed at the signer's own terminal; that confirmation is the control, not the loopback bind and not
the origin list. A Windows service runs in session 0 with no console to read an answer from, so a signer
installed as one would decline every request it ever received — and the only way to make it useful again
would be a flag that signs without asking, which is the signing oracle this whole arrangement exists to
refuse. On Linux `--install` refuses for the same reason: a systemd user unit has no terminal either.

For an operator without a signer running, the Jobs page prints the `hostseal sign` command for what
they filled in and takes the signed document back by paste. Same signature, two more steps.

Nothing about the trust model changes: a host acts on what a key signed only if that key's line is in
its own `/etc/hostseal/trusted-signers`, which the control plane cannot write and this signer cannot
write either. Paste the line it prints onto the hosts that key may act on, by hand, deliberately — or
hand it to `hostseal enroll --signers` when the host is enrolled, which installs the file before
anything is fetched from the control plane:

```bash
sudo hostseal enroll \
  --server https://agents.hostseal.example.org \
  --token "$HOSTSEAL_TOKEN" \
  --signers ./trusted-signers
```

## What a fresh host will and will not do

Straight after installation, before you change anything:

| | |
| --- | --- |
| Reports inventory, services, pending updates and reboot state | **yes** |
| Applies security updates on its own timer, via `unattended-upgrades` | **yes** — and it keeps doing this if the control plane is unreachable, or if you never enrol it at all |
| Applies security updates because the control plane asked | **only if `updates.allow` permits it** — the control plane signs the request, and the host's own policy decides |
| Applies *every* update because the control plane asked | **no** — `packages.applyAll` needs a signature from a key you place on the host |
| Applies updates because an administrator ran the helper on the host | only security updates, and only what the policy below allows |
| Restarts a service, or reboots | **no**, from anyone, until you change the two files below |
| Reports which of its units are in the failed state | **yes**, for every unit. `[services] watched` narrows which *changes* become events, not what is reported |
| Reports the containers running on it | **no**, until `[containers] report = true` |
| Reports its disk, memory, processor load and interface traffic | **yes**, until `[resources] report = false` |
| Reports its interfaces, IP addresses and MAC addresses | **yes**, until `[network] report = false` |

The two files are the whole of it:

**`/etc/hostseal/policy.toml`** — root-owned, a dpkg conffile, and the control plane cannot modify it.
It ships permitting security updates, no reboots, and no restartable units. Effective permission for
any job is `min(what the control plane asked for, what this file allows)` — never the maximum. Check an
edit with `hostseal-agent policy check` before restarting anything: a file that does not parse makes the
host refuse all privileged work rather than fall back to a default, which is deliberate and is a
miserable way to discover a typo.

Four keys in it are the exception to everything the paragraph above says, because they bound what this
host *says* rather than what may be done to it. None is a permission, and none involves a signature.

`[services] watched` decides which unit-state changes become events, and its empty default means
*every* unit rather than none: permitting an action and reporting a fact are different questions, and a
fresh host should surface a failed unit rather than hide it. Narrowing it quietens a noisy machine;
widening it grants nothing.

`[containers] report` is the other way round: it ships `false`, and a host reports nothing about the
containers on it until somebody writes `true`. A container list describes what a business runs, which is
a different disclosure from a package count. Turning it on reports each container's id, its main
process's *name* — never its command line, which is where credentials end up — when it started, its
resource use, and four things `docker ps` will not tell you: whether it is privileged, whether its
seccomp filter is off, whether it runs as root, and whether the Docker socket is bind-mounted into it.
It cannot report image names, exit codes, restart counts or health, because those live behind the
socket that `hostseal` is deliberately not in the group for.

Two practical notes. The resource figures change on every collection, so a host that opts in sends a
full report on every heartbeat rather than the digest it would otherwise send. And **upgrade the agent
before you add the key**: the policy parser refuses a file it does not understand and falls closed, so
writing `[containers]` into a host still running an older agent turns that host's update permission off
until the agent catches up.

`[resources] report` is the third, and it is the one that ships **on**. A host reports how full each of
its filesystems is, how much memory and swap are spoken for, its processor count and load, and what each
interface has moved since boot — the two questions a fleet tool is asked at three in the morning. It ships
on for the same reason the update count does: it is what somebody installed a fleet agent to see. Write
`false` if the mount points and device names are nobody else's business, which is the one genuinely new
disclosure in it.

It costs much less bandwidth than the containers section, and deliberately. Every utilisation figure is
banded — load and memory to five percentage points, disks to one, traffic to whole gibibytes — so a host
whose state has not changed keeps sending a digest instead of a full report. The per-interface error and
drop counters are the one exception and are exact, because the value of those numbers is entirely in
whether they are moving; an interface that drops the odd unwanted multicast frame is therefore enough to
keep a host sending full reports, which is the reason this key is worth knowing about on a metered link.

It cannot see what the agent's own sandbox hides. `ProtectHome=` and `PrivateTmp=` in the agent's unit
replace `/home`, `/root`, `/tmp` and `/var/tmp` with empty filesystems inside the agent's mount
namespace, so a separate `/home` partition is not in the report. The report names those paths rather than
leaving you to notice a missing disk. The same **upgrade the agent before you add the key** warning applies — though
leaving the key out entirely is safe on every version, because an absent key means `true`.

`[network] report` is the fourth, and it also ships **on** — but for a different reason, which is worth
knowing before you reason about the others. That section has been in every release; the key is new. A
default of `false` would not have been caution, it would have silently removed a fact your fleet already
receives on the day you upgraded. The key exists because MAC addresses do: an address list describes your
network's internal structure, and a MAC address is a durable hardware identifier that outlives a
reinstallation and joins a host to a DHCP lease, a switch port and a hypervisor's inventory. None of it
tells the control plane anything it does not already hold — but that control plane may not be yours.
Write `false` if the network layout is the sensitive part; the host stays identified by its certificate
and its hostname.

**`/etc/hostseal/trusted-signers`** — root-owned, a dpkg conffile, and **empty**. Every destructive
operation needs a signature from a key listed here, and the control plane holds none of them. Generate
one on your own machine:

```bash
hostseal key generate --out ~/.config/hostseal/signing.key --id ops-laptop
# prints the line to paste into /etc/hostseal/trusted-signers on the hosts that key may act on
```

### Keys that are not files

A key file on a laptop is a real improvement over a shared credential and it is still a file: it can be
copied, and nobody would know. `--key` takes a reference rather than a path, so the same command signs
with a hardware token or a cloud key store, and `hostseal key show --in <reference>` prints the
`trusted-signers` line for any of them.

```bash
# A PKCS#11 token — YubiKey PIV, Nitrokey, SoftHSM. The URI is RFC 7512, which is what
# OpenSSL, GnuTLS and p11-kit already speak, so an existing one can be pasted.
hostseal key show --in "pkcs11:token=ops;object=ops-yubikey-1?module-path=/usr/lib/opensc-pkcs11.so"

# A cloud key store. The #fragment is the identity the audit log records and every host lists —
# a resource name is not one, and it is required rather than derived.
hostseal key show --in "awskms:arn:aws:kms:eu-central-1:123456789012:key/abcd-1234#ops-kms-1"
hostseal key show --in "gcpkms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1#ops-kms-1"
hostseal key show --in "azurekms:ops.vault.azure.net/keys/hostseal-signing/9885aa55#ops-kms-1"
```

A PIN is prompted for, or read from a file with `pin-source=/path`. It is never a URI attribute and
never a flag: a secret on a command line is readable from the process list by every user on the machine.

A token label does not have to be unique, and two identically provisioned tokens — an operator with a
spare — carry the same one. `serial=` names one physical token, so `token=ops;serial=d276000124010200`
means "the token labelled `ops` whose serial is that" and finds nothing rather than falling back to the
other `ops`. Where the reference has not narrowed and two tokens answer to the label, `hostseal` refuses
and prints the serials it found, rather than signing with whichever the module enumerated first. The
other token attributes an RFC 7512 URL carries — `model=`, `manufacturer=`, `library-version` and the
rest of that set — are accepted and ignored, because `p11tool --list-tokens` prints them for every
token and they name a product line rather than a token. `pin-value` and `module-name` are the two the
reference refuses outright, for the reasons the error messages give.

**A YubiKey, from empty to a `trusted-signers` line.** HostSeal does not generate a key on a token —
`ykman` does, and the key has no way out of the device afterwards.

```bash
# 9c is PIV's signature slot: it asks for the PIN on every operation rather than caching it.
# ED25519 needs firmware 5.7 or newer, and ECCP256 is what everything before it can do — which is why
# two algorithms exist on the wire at all.
ykman piv keys generate --algorithm ECCP256 --touch-policy always 9c signing.pub

# A self-signed certificate in the same slot: most PKCS#11 modules enumerate a PIV slot only once it
# holds one, so a key without a certificate is a key nothing can find.
ykman piv certificates generate --subject "CN=ops-yubikey-1" 9c signing.pub

hostseal key show --in "pkcs11:id=%02?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so"
```

Slot 9c is `CKA_ID` 02, and the reference names that rather than a label, because a PIV token's labels
are worded by whoever wrote the module — `SIGN key` under OpenSC, `Private key for Digital Signature`
under Yubico's own `libykcs11` — and matching on one is fragile across vendors in the way this backend
exists not to be. What follows from that is worth knowing before anything is engraved on a host: the
identity recorded in `trusted-signers` and in the audit log is then `pkcs11:02`, derived from the id.
`object=<label>` supplies a name instead, where the module lets you choose one — SoftHSM does, PIV does
not.

With `--touch-policy always`, a signature needs the finger as well as the PIN, which is the property
worth having on a key that authorises reboots. `hostseal sign` waits thirty seconds for it and then gives
up, rather than blocking on a token nobody is standing at.

Cloud credentials come from the environment, then the provider's own well-known file, then the instance
metadata service — which is the order that answers promptly on a laptop, where the metadata address
does not refuse a connection but black-holes it. The flows that are not implemented, because they are
most of what a vendor SDK weighs, have one escape hatch each:

```bash
eval "$(aws configure export-credentials --profile ops --format env)"                    # SSO, assume-role, federation
export HOSTSEAL_KMS_BEARER_TOKEN="$(gcloud auth print-access-token)"                       # workload identity
export HOSTSEAL_KMS_BEARER_TOKEN="$(az account get-access-token   --resource https://vault.azure.net --query accessToken -o tsv)"                         # certificate auth, federation
```

**Where a cloud key lives matters more than which cloud it is in.** A KMS key the control plane's own
identity can call `Sign` on is a key the control plane holds, whatever the console says about custody —
see [`SECURITY.md` §9](SECURITY.md#9-what-hostseal-does-not-defend-against). Put it in an account the
control plane has no role in, and check it the way that catches the mistake: assume the control plane's
identity and confirm that signing is denied.

Note that Azure Key Vault has no EdDSA algorithm at all, so a Key Vault key must be P-256 and its
`trusted-signers` line will read `ecdsa-p256`. AWS KMS and Cloud KMS can do either.

A package upgrade never replaces either file. There is a test in `testfleet/` that asserts it, and for
`trusted-signers` that is a security test rather than a convenience one.

## Stopping a host

```bash
sudo touch /etc/hostseal/paused      # refuse everything, immediately
sudo systemctl stop hostseal-agent   # or just stop it
```

Neither can be undone by the control plane. There is deliberately no `agent.resume` operation: an off
switch that something else can flip back on is not an off switch. The host keeps patching from its
local policy either way — a paused host should not become an unpatched host.

## Upgrading the agent

Through APT, on the host's own schedule, like any other package. There is no `agent.updateFromURL` and
there never will be: a self-update from a control-plane-supplied URL replaces the binary that enforces
every other rule.

## Building from source

```bash
make build    # all binaries into ./dist
make web      # the Angular application, embedded into hostseal-server
make deb      # the hostseal-agent package
make test lint guarantee
```

Go 1.26 or newer. `make deb` needs [nfpm](https://nfpm.goreleaser.com/install/); `make web` needs Node
and pnpm.

## Where to look when something is wrong

```bash
journalctl -u hostseal-agent -n 200     # the agent logs JSON; paste it whole rather than summarising
hostseal-agent policy check             # most "it refused" reports are the policy working correctly
hostseal-server catalogue               # everything the control plane can ask a host to do
```

The last one is worth running once even when nothing is wrong. It prints the complete, closed set of
operations plus the list this project has permanently refused to implement, and it is the fastest way
to check that the claim on the front page is true of the binary you actually installed.
