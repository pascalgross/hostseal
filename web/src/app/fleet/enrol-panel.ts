import { Component, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTooltipModule } from '@angular/material/tooltip';

import { EnrolmentInstructions, MintedEnrolmentToken } from '../core/api.models';
import { ApiService } from '../core/api.service';
import { describeError } from '../core/errors';

/**
 * Builds a download URL from a base and the control plane's own path for the certificate.
 *
 * It exists because `caCertificatePath` is server-absolute — `/api/v1/ca.crt` — and concatenating that
 * onto a base silently discards any path the control plane is published under. A deployment behind
 * `https://hostseal.example.org/control` would be handed a command pointing at the bare origin, which
 * is a 404 or, worse, somebody else's route on a shared hostname.
 *
 * The base's own path is kept and the certificate path appended to it, so the prefix survives. An
 * unparseable base falls back to plain concatenation rather than throwing: the panel printing a
 * slightly wrong command is recoverable, and a component that renders nothing at all is not.
 */
function caUrl(base: string, certificatePath: string): string {
  try {
    const parsed = new URL(base);
    return `${parsed.origin}${parsed.pathname.replace(/\/$/, '')}${certificatePath}`;
  } catch {
    return `${base.replace(/\/$/, '')}${certificatePath}`;
  }
}

/**
 * Whether two URLs are served by the same origin, ignoring path and trailing slash.
 *
 * The panel's whole branch — a fetch it can verify against one it cannot — turns on whether the agent
 * API and this page share a host, and that question is about scheme, host and port only. A string
 * comparison answered it wrongly for every deployment carrying a port or a path prefix, and wrongly in
 * the unsafe direction: it claimed the fetch was verifiable when it was not.
 *
 * Either side failing to parse returns false, which sends the panel to the fingerprint-checked command.
 * That is the safe way to be wrong: it prints a check that is unnecessary rather than skipping one that
 * was not.
 */
function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

/**
 * Which operating system the commands on this panel are written for.
 *
 * Two members and not a list of distributions: every Debian and Ubuntu host installs the agent the same
 * way, and Windows is the one platform that shares none of it — no repository, a different service
 * manager, different paths, and a smaller set of intents once it is running.
 */
type Platform = 'linux' | 'windows';

/**
 * Where Install-HostSealAgent.ps1 puts what bounds the agent, and the Windows counterpart of
 * /etc/hostseal.
 *
 * Program Files rather than ProgramData, which is the whole of local policy sovereignty on that
 * platform: the agent's own service account is granted read and execute here and write nowhere in it,
 * so the policy file and the trust anchor are not things the agent can rewrite. The panel names the
 * path rather than deriving one, because a certificate installed anywhere else is a step that appeared
 * to succeed and changed nothing.
 */
const windowsInstallDir = 'C:\\Program Files\\HostSeal';

/**
 * The CA bundle's path as PowerShell has to be handed it.
 *
 * Quoted, because `Program Files` has a space in it and an unquoted path is silently parsed as two
 * arguments — which fails in the confusing direction, writing a file called `C:\Program` that nothing
 * reads and reporting nothing wrong.
 */
const windowsCAPath = `'${windowsInstallDir}\\server-ca.crt'`;

/**
 * How to invoke the operator CLI on the host.
 *
 * The call operator, for the same reason as the quoting: PowerShell treats a quoted string in command
 * position as a string to print rather than a program to run, so `'C:\Program Files\…\hostseal.exe'
 * enroll …` echoes the path and exits 0. That is an enrolment that looked like it worked.
 */
const windowsCLI = `& '${windowsInstallDir}\\hostseal.exe'`;

/**
 * How to enrol a host, as three steps somebody can follow without leaving the page.
 *
 * It exists because the fleet page's answer to "how do I add a machine" was one line of shell with the
 * literal placeholder `https://this-control-plane` in it, shown only when the fleet was empty. Every
 * other part of the answer — the APT repository, the CA certificate, the fact that a token has to be
 * minted first and is shown once — was in INSTALL.md, which is a different document on a different
 * screen, and the placeholder had to be replaced by hand with a value the page already knows.
 *
 * The three steps are one panel rather than three, and in this order, because enrolment fails in a
 * particular way when they are done out of it: an agent installed before the CA is in place starts,
 * fails to verify the control plane, and retries — so the operator sees a running service and a host
 * that never appears, which reads as a control-plane fault.
 *
 * Nothing here changes what enrolment *is*. The token is the same single-use token the API has always
 * minted, the command is the same command, and the control plane still has no path to a host: every
 * one of these steps is something a person runs on the machine. What the panel removes is the chance
 * to get one of them subtly wrong.
 */
@Component({
  selector: 'hostseal-enrol-panel',
  imports: [
    DatePipe,
    MatButtonModule,
    MatCardModule,
    MatIconModule,
    MatProgressBarModule,
    MatTooltipModule,
  ],
  templateUrl: './enrol-panel.html',
  styleUrl: './enrol-panel.scss',
})
export class EnrolPanel {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** What the control plane says about itself, null until the panel is first opened. */
  protected readonly instructions = signal<EnrolmentInstructions | null>(null);

  /** Why the instructions could not be read, empty when they could. */
  protected readonly error = signal('');

  /** The token minted most recently, null before anybody has asked for one. */
  protected readonly minted = signal<MintedEnrolmentToken | null>(null);

  /** Why minting failed, empty when it did not. */
  protected readonly mintError = signal('');

  /** Whether a request is in flight, so the button can be disabled. */
  protected readonly busy = signal(false);

  /** Which command was copied most recently, so the button can say so. Empty for none. */
  protected readonly copied = signal('');

  /**
   * Which platform the three steps are shown for.
   *
   * Linux first because that is the fleet HostSeal is for, and Windows present at all because the
   * agent for it shipped, was described nowhere an operator would look, and had no installation
   * instructions outside a PowerShell file's own comment header. A panel that printed `apt-get` to
   * somebody holding a Windows Server is not neutral about the question — it answers it wrongly.
   */
  protected readonly platform = signal<Platform>('linux');

  /**
   * Switches the commands to a platform, and forgets which command was copied.
   *
   * The tick is forgotten because it is a claim about the text currently on screen. Leaving it up
   * after a switch tells an operator they have already copied a command they have not seen, and the
   * one they did copy is for the other operating system.
   */
  protected showPlatform(platform: Platform): void {
    this.platform.set(platform);
    this.copied.set('');
  }

  /** The commands that install the agent, for whichever platform is being shown. */
  protected readonly installCommand = computed(() =>
    this.platform() === 'windows' ? this.windowsInstallCommand() : this.aptInstallCommand(),
  );

  /** The commands that add the APT repository and install the agent. */
  protected readonly aptInstallCommand = computed(() => {
    const apt = this.instructions()?.aptUrl ?? '';
    return [
      `curl -fsSL ${apt}/hostseal-archive-keyring.gpg \\`,
      '  | sudo tee /usr/share/keyrings/hostseal-archive-keyring.gpg > /dev/null',
      `curl -fsSL ${apt}/hostseal.sources \\`,
      '  | sudo tee /etc/apt/sources.list.d/hostseal.sources > /dev/null',
      'sudo apt-get update && sudo apt-get install hostseal-agent',
    ].join('\n');
  });

  /**
   * The commands that fetch the Windows archive and run its installer.
   *
   * There is no repository to subscribe to, so this is a download and an upgrade is the same download
   * again. That is a real difference from APT and the panel does not dress it up: nothing on a Windows
   * host will fetch the next version by itself.
   *
   * `curl.exe` with the extension, which is not pedantry. In Windows PowerShell 5.1 — what ships with
   * every supported Windows Server — `curl` is an alias for `Invoke-WebRequest`, so the bare name runs
   * a different program whose parameters these arguments do not fit: `-o` is ambiguous between
   * `-OutFile` and two common parameters, and a request that got past that would still fail on a
   * server with Internet Explorer Enhanced Security for want of `-UseBasicParsing`. The real curl has
   * been in System32 since Server 2019, which is this project's floor.
   *
   * `Unblock-File` because the archive arrived from the internet and every file unpacked from it
   * carries the mark of that zone. The default execution policy on Windows Server is RemoteSigned,
   * which refuses an unsigned script bearing it — with an error naming the execution policy, sending
   * the administrator to `Set-ExecutionPolicy Bypass` and a machine left weaker than it was found.
   * Clearing the zone on the files just downloaded is the smaller act and the honest one.
   *
   * The installer is run from where the archive was unpacked rather than copied elsewhere first,
   * because it installs `policy.toml` from beside itself. Run alone it throws on the missing file, and
   * that is the good failure; the bad one would be an agent with no policy at all.
   *
   * The whole sequence is one `& { … }` block, and that is what makes a failure stop it. Pasted line
   * by line at a prompt, each line is its own statement: a download that fails leaves the next command
   * running anyway, and because the staging paths are fixed, the run before this one may have left an
   * archive and an unpacked tree there. The installer would then be started from stale files, stop the
   * service, copy last month's binaries over this month's and report a successful upgrade. Inside a
   * block, `throw` abandons the rest; `$ErrorActionPreference` is set in that block's own scope, so a
   * cmdlet that fails is terminating here and the operator's session is not left altered afterwards.
   *
   * `$LASTEXITCODE` is checked by hand because `curl.exe` is a native program: no preference variable
   * covers it, and `-f` makes curl *return* failure rather than raise one. The staging paths are
   * cleared first for the same reason — curl truncates its output file before it knows the response
   * status, and the `--remove-on-error` that would clean that up is newer than the curl on Server 2019.
   */
  protected readonly windowsInstallCommand = computed(() => {
    const archive = this.instructions()?.windowsArchiveUrl ?? '';
    return [
      '& {',
      "  $ErrorActionPreference = 'Stop'",
      "  $zip = Join-Path $env:TEMP 'hostseal-agent-windows-amd64.zip'",
      "  $dir = Join-Path $env:TEMP 'hostseal-agent'",
      '  Remove-Item -Path $zip, $dir -Recurse -Force -ErrorAction SilentlyContinue',
      `  curl.exe -fsSL ${archive} -o $zip`,
      "  if ($LASTEXITCODE -ne 0) { throw 'the download failed; nothing has been installed' }",
      '  Expand-Archive -Path $zip -DestinationPath $dir',
      '  Get-ChildItem -Path $dir -Recurse | Unblock-File',
      "  & (Join-Path $dir 'Install-HostSealAgent.ps1')",
      '}',
    ].join('\n');
  });

  /**
   * The command that installs the CA certificate, fetching it from this control plane.
   *
   * It reads the certificate over the network rather than telling the operator to download it here and
   * copy it across, because a step that spans two machines is the step people improvise around — and
   * the improvisation is a host that trusts the system roots instead of this authority.
   *
   * `install` rather than `cp`, with the owner, group and mode written out: the file is what the agent
   * checks the control plane against, and one left mode 0600 root-owned in a directory the agent can
   * read is a difference nobody notices until enrolment fails.
   *
   * It fetches from **this page's own address** rather than from the agent URL, and that is the whole
   * point of the computed rather than a template string. `curl` verifies the control plane like any
   * other client, so it can only fetch the certificate from a name whose certificate is already
   * trusted — and the agent hostname's is precisely the one that is not, since it is what the file
   * being fetched would establish. In the documented two-hostname deployment this page is the
   * interface, where Traefik terminates with a publicly trusted certificate, so the command works;
   * against the agent hostname it fails with `unable to get local issuer certificate` every time. When
   * the two are the same host it fails either way, which is what the other command is for.
   */
  protected readonly caCommand = computed(() => {
    const details = this.instructions();
    if (!details) {
      return '';
    }
    if (this.caFetchIsUnverifiable()) {
      return this.caCommandUnverified();
    }
    const url = caUrl(this.pageBase(), details.caCertificatePath);
    if (this.platform() === 'windows') {
      // Fetched to a temporary file and copied in on success, rather than written straight to the
      // trust anchor's path. `-f` makes curl return failure rather than raise it, and curl truncates
      // its output file before it knows the response status — so the direct form can leave an empty
      // server-ca.crt behind on a 404. `hostseal enroll` reads that path when it exists, so enrolment
      // would then fail to verify a control plane that was never the problem.
      //
      // A copy rather than a move, and that is where the Windows equivalent of `-o root -g root -m
      // 0644` is: the installer replaced this directory's ACL with an explicit one that inherits, so
      // a file created here grants the agent's account read and execute and nothing else, while a
      // moved file would keep the permissions it had in %TEMP%, where that account is not named.
      return [
        '& {',
        "  $ErrorActionPreference = 'Stop'",
        "  $tmp = Join-Path $env:TEMP 'hostseal-ca.crt'",
        `  curl.exe -fsSL ${url} -o $tmp`,
        "  if ($LASTEXITCODE -ne 0) { throw 'the certificate could not be fetched; nothing was installed' }",
        `  Copy-Item -Path $tmp -Destination ${windowsCAPath} -Force`,
        '}',
      ].join('\n');
    }
    return [
      `curl -fsSL ${url} \\`,
      '  | sudo install -D -o root -g root -m 0644 /dev/stdin /etc/hostseal/server-ca.crt',
    ].join('\n');
  });

  /** The certificate's SHA-256, shown so an unverified fetch has something to be checked against. */
  protected readonly fingerprint = computed(() => this.instructions()?.caFingerprint ?? '');

  /**
   * The same step for a control plane whose certificate cannot be verified from the host.
   *
   * `-k` is in here and it is not a shortcut: it is one half of a check, and the command fails closed
   * without the other half. The certificate is fetched unverified, its digest is compared against the
   * one this page is showing, and it is installed only on a match — so the bytes are accepted because
   * they match a value that arrived over this authenticated session, not because whoever answered the
   * hostname said so.
   *
   * The comparison is done by the shell rather than by eye, because two 64-character hex strings are
   * compared by looking at the first four characters, and that is not a comparison.
   *
   * `if`/`else` rather than `test && install || echo`, which is the same three commands and is wrong.
   * In that form the `||` binds to the whole list, so a missing `sudo`, a cancelled password prompt or
   * a full disk makes `install` fail and prints `FINGERPRINT MISMATCH` — naming an attack that did not
   * happen, for a digest that matched — and then `echo` succeeds, so the line exits 0 and a script
   * carries on to enrolment with no certificate installed. Here the two failures stay distinct and
   * `install` keeps its own exit status; `false` rather than `exit` because this gets pasted into an
   * interactive shell, and a mismatch should report itself rather than close the operator's session.
   *
   * The PowerShell form is the same check and three of its parts are not interchangeable with the
   * obvious ones. The digest is computed over the certificate's `RawData` rather than with
   * `Get-FileHash`, because the value this page shows is openssl's — a SHA-256 of the DER — and
   * hashing the PEM file's bytes produces a different number that would fail every honest fetch. It
   * is computed with `SHA256::Create` rather than `GetCertHash('SHA256')`, whose overload arrived in
   * .NET Framework 4.8 and is therefore absent on a Server 2019 host nobody has updated. And the
   * certificate is copied into place rather than moved: a move within a volume keeps the permissions
   * the file had in %TEMP%, where the agent's service account is not named, so the agent would be
   * left unable to read the authority it verifies the control plane against.
   *
   * `throw` where the shell uses `false`, for the reason the shell does not use `exit`: it fails a
   * script and reports itself at an interactive prompt without closing the session somebody pasted
   * this into. It is inside a `& { … }` block because that is the only thing that makes it stop
   * anything — pasted as loose lines, a `throw` ends one statement and the next runs regardless.
   *
   * That block is also what keeps the two failures apart, which is the same property the shell form
   * is written for. Without it a failed fetch leaves `$cert` unset, the digest empty and the
   * comparison false, so the step reports a fingerprint mismatch — an attack that did not happen —
   * for a control plane that was merely unreachable. The exit status of the fetch is therefore
   * checked before anything is compared, and a mismatch is a guard clause rather than the `else` of
   * the copy, so a copy that fails keeps its own error too.
   */
  protected readonly caCommandUnverified = computed(() => {
    const details = this.instructions();
    if (!details) {
      return '';
    }
    const url = caUrl(details.agentUrl, details.caCertificatePath);
    if (this.platform() === 'windows') {
      return [
        '& {',
        "  $ErrorActionPreference = 'Stop'",
        "  $tmp = Join-Path $env:TEMP 'hostseal-ca.crt'",
        `  curl.exe -fsSLk ${url} -o $tmp`,
        "  if ($LASTEXITCODE -ne 0) { throw 'the certificate could not be fetched; nothing was installed' }",
        '  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $tmp',
        '  $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)',
        "  $got = ($sha | ForEach-Object { $_.ToString('X2') }) -join ':'",
        `  if ($got -ne '${details.caFingerprint}') {`,
        "    throw 'FINGERPRINT MISMATCH - do not install this certificate'",
        '  }',
        `  Copy-Item -Path $tmp -Destination ${windowsCAPath} -Force`,
        '}',
      ].join('\n');
    }
    return [
      `curl -fsSLk ${url} -o /tmp/hostseal-ca.crt`,
      'if [ "$(openssl x509 -in /tmp/hostseal-ca.crt -noout -fingerprint -sha256)" \\',
      `     = "sha256 Fingerprint=${details.caFingerprint}" ]; then`,
      '  sudo install -D -o root -g root -m 0644 /tmp/hostseal-ca.crt /etc/hostseal/server-ca.crt',
      'else',
      '  echo "FINGERPRINT MISMATCH - do not install this certificate" >&2',
      '  false',
      'fi',
    ].join('\n');
  });

  /**
   * The address this page is served from, including any path the control plane is published under.
   *
   * `document.baseURI` rather than `window.location.origin`, because a control plane behind a proxy
   * path prefix is a supported deployment — the container entrypoint takes a whole HOSTSEAL_AGENT_URL
   * for exactly that case — and an origin alone drops the prefix, producing a download URL that is a
   * 404 on the one deployment that most needs the command to work. Read through a getter so a test can
   * replace it; the document is otherwise a global the component would be pinned to.
   */
  protected pageBase(): string {
    return document.baseURI;
  }

  /**
   * Whether the certificate has to be fetched from the same host it authenticates.
   *
   * True in the single-hostname deployment, where the interface and the agent API share an origin
   * serving HostSeal's own certificate. The plain command cannot verify that connection — nothing has
   * told the host to trust this authority yet, which is the reason for the step — so the panel prints
   * the fingerprint-checked fetch instead of a command that always fails.
   *
   * Origins are compared rather than the strings, because the two values are not the same kind of
   * thing: the agent URL is a full base URL and may carry a port or a path prefix, and the page's is a
   * document address. Comparing them literally made every prefixed or non-default-port deployment look
   * like the two-hostname one — so the panel took the verifiable branch, built the download from the
   * page's address, dropped the prefix, and printed a command that either fetched the wrong route or
   * failed the very TLS verification this whole step exists to establish.
   */
  protected readonly caFetchIsUnverifiable = computed(() => {
    const details = this.instructions();
    return !!details && sameOrigin(details.agentUrl, this.pageBase());
  });

  /**
   * The enrolment command, carrying the token when one has been minted, and the restart after it.
   *
   * The restart is the step that was missing, on both platforms. Installing the agent starts it — the
   * package does, and so does the Windows installer — so by the time anybody enrols there is already
   * a service running that found no credential and went into the idle loop. That loop re-reads the
   * local policy on every tick and never re-reads the enrolment state, so an operator who stopped
   * after `hostseal enroll` had a host the control plane had heard of exactly once, a service that
   * was active, and no facts arriving. Nothing about that state says which of the three steps was
   * incomplete, which is why it belongs in the command rather than in a note under it.
   *
   * These two lines need no `& { … }` guard, unlike the steps above them. A failed enrolment is loud
   * — it prints why and exits non-zero — and restarting an agent that is still unenrolled changes
   * nothing: it idles again, exactly as it was. There is no stale state for a second command to act
   * on and nothing that could look like success.
   */
  protected readonly enrolCommand = computed(() => {
    const details = this.instructions();
    if (!details) {
      return '';
    }
    const token = this.minted()?.token ?? '<TOKEN>';
    if (this.platform() === 'windows') {
      return [
        `${windowsCLI} enroll --server ${details.agentUrl} --token ${token}`,
        'Restart-Service hostseal-agent',
      ].join('\n');
    }
    return [
      `sudo hostseal enroll --server ${details.agentUrl} --token ${token}`,
      'sudo systemctl restart hostseal-agent',
    ].join('\n');
  });

  /** Where the CA certificate can be downloaded, for an operator who would rather have the file. */
  protected readonly caDownloadUrl = computed(() => this.instructions()?.caCertificatePath ?? '');

  /**
   * Reads the instructions when the panel is opened, and not before.
   *
   * A native `<details>` rather than a Material expansion panel, and the reason is measurable: the
   * expansion module put the initial bundle over its budget for one disclosure widget on one page.
   * `<details>` is the same control, is keyboard-operable and announced without anything being added
   * for it, and costs nothing.
   *
   * The guard makes the toggle idempotent: `toggle` fires on closing as well as opening, and the
   * answer does not change while the page is open.
   */
  protected load(): void {
    if (this.instructions() !== null) {
      return;
    }
    this.api.enrolment().subscribe({
      next: (details) => {
        this.instructions.set(details);
        this.error.set('');
      },
      error: (err: unknown) => this.error.set(describeError(err)),
    });
  }

  /**
   * Mints one single-use enrolment token.
   *
   * The result is shown once and never again — only its SHA-256 is stored — which the panel says at
   * the moment it is shown rather than in a footnote. A token nobody copied is not recoverable and is
   * not a problem: minting another costs one click.
   */
  protected mint(): void {
    this.busy.set(true);
    this.mintError.set('');
    this.api.createEnrolmentToken({ label: 'from the fleet page', group: '' }).subscribe({
      next: (token) => {
        this.busy.set(false);
        this.minted.set(token);
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.mintError.set(describeError(err));
      },
    });
  }

  /**
   * Copies one command, and remembers which so the button can confirm it.
   *
   * Best-effort, like the template page's copy: the text is on screen and selectable, and a browser
   * refusing clipboard access — several do without a gesture they recognise — must not look like the
   * command itself is wrong.
   */
  protected async copy(name: string, text: string): Promise<void> {
    if (!text || !navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      this.copied.set(name);
    } catch {
      // Left on screen for a manual copy, which is the fallback that always works.
    }
  }
}
