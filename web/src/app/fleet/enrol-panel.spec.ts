import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { of } from 'rxjs';

import { ApiService } from '../core/api.service';
import {
  CreateEnrolmentTokenRequest,
  EnrolmentInstructions,
  EnrolmentTokenSummary,
  TemplateSummary,
} from '../core/api.models';
import { EnrolPanel } from './enrol-panel';

/** Builds one answer from the control plane, so each spec names only the part it is about. */
function instructions(partial: Partial<EnrolmentInstructions> = {}): EnrolmentInstructions {
  return {
    agentUrl: 'https://agents.example.org',
    agentUrlIsAGuess: false,
    caCertificatePath: '/api/v1/ca.crt',
    caFingerprint: 'C0:62:73:A0:FD:3C:25:86:BE:F7:7F:0E:08:66:72:C0:F6:E3:AF:3B:A4:94:FB:2A:D9:BF:CC:1D:C5:8E:15:61',
    aptUrl: 'https://hostseal.io/apt',
    windowsArchiveUrl:
      'https://github.com/pascalgross/hostseal/releases/latest/download/hostseal-agent-windows-amd64.zip',
    ...partial,
  };
}

/** Builds one template listing row, so a spec names only what it is about. */
function template(partial: Partial<TemplateSummary>): TemplateSummary {
  return {
    name: 'standard-server',
    latestVersion: 1,
    createdAt: '2026-08-24T09:41:07.512Z',
    createdBy: 'test:tester',
    signed: true,
    signerKeyId: 'ops-yubikey-1',
    signerAlgorithm: 'ecdsa-p256',
    archived: false,
    ...partial,
  };
}

/** Builds one row of the token listing, so a spec names only what it is about. */
function tokenRow(partial: Partial<EnrolmentTokenSummary>): EnrolmentTokenSummary {
  return {
    label: 'web tier',
    group: '',
    createdAt: '2026-09-20T09:00:00Z',
    expiresAt: '2026-09-21T09:00:00Z',
    consumed: false,
    usable: true,
    ...partial,
  };
}

/** The one call of the control plane a spec counts, on the stub `render` installs. */
interface TokenReads {
  /** Reads the token listing. */
  enrolmentTokens: () => unknown;
}

/** The half of a signal these specs use: the ability to put a value into a form field. */
interface Writable<T> {
  /** Sets the field, as the markup's two-way binding does. */
  set(value: T): void;
}

/**
 * The protected members these specs reach for, named so the casts below stay readable.
 *
 * Protected rather than public because they are the template's to call, and a spec that drives the
 * panel the way the markup does has to say so out loud rather than widen the component's surface.
 */
interface PanelInternals {
  /** Reads the instructions, which the disclosure element does on open. */
  load(): void;

  /** Mints one enrolment token, naming a template when one is given. */
  mint(bootstrap?: string): void;

  /** The page's own address, which the CA command is built against. */
  pageBase(): string;

  /** Switches the commands to a platform, which the two buttons above them do. */
  showPlatform(platform: 'linux' | 'windows'): void;

  /** What the next token will be called. */
  tokenLabel: Writable<string>;

  /** The group a host enrolled with the next token joins. */
  tokenGroup: Writable<string>;

  /** How many hours the next token stays redeemable. */
  tokenHours: Writable<number | null>;
}

/**
 * Renders the panel with the control plane stubbed out, already opened.
 *
 * The module is reset first so that one spec can render twice — the pair of assertions about a guessed
 * address is one property, and splitting it into two specs would let either half pass alone while the
 * panel said the same thing in both cases.
 */
function render(
  details: EnrolmentInstructions,
  pageBase = 'https://hostseal.example.org/',
  templates: TemplateSummary[] = [],
  minted: CreateEnrolmentTokenRequest[] = [],
  tokens: EnrolmentTokenSummary[] = [],
): ComponentFixture<EnrolPanel> {
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      {
        provide: ApiService,
        useValue: {
          enrolment: () => of(details),
          templates: () => of({ templates }),
          enrolmentTokens: () => of({ tokens }),
          createEnrolmentToken: (request: CreateEnrolmentTokenRequest) => {
            minted.push(request);
            return of({
              token: 'frr-enrol-abcdef',
              label: request.label,
              group: '',
              expiresAt: '2026-08-29T00:00:00Z',
              ...(request.bootstrap ? { bootstrap: request.bootstrap } : {}),
            });
          },
        } as unknown as ApiService,
      },
    ],
  });
  const fixture = TestBed.createComponent(EnrolPanel);
  const panel = fixture.componentInstance as unknown as PanelInternals;
  // The page's own address decides where the certificate is fetched from, and under Karma it is the
  // test runner's. Stubbed rather than asserted around, because the two-hostname and single-hostname
  // deployments differ in exactly this value and both have to be exercised.
  panel.pageBase = () => pageBase;
  fixture.detectChanges();
  panel.load();
  fixture.detectChanges();
  return fixture;
}

/** Renders the panel and switches it to Windows, which is what clicking the second button does. */
function renderWindows(
  details: EnrolmentInstructions,
  pageBase = 'https://hostseal.example.org/',
): ComponentFixture<EnrolPanel> {
  const fixture = render(details, pageBase);
  (fixture.componentInstance as unknown as PanelInternals).showPlatform('windows');
  fixture.detectChanges();
  return fixture;
}

/** Collapses whitespace, so an assertion can be written the way the panel actually reads. */
function text(element: Element | null): string {
  return (element?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

describe('EnrolPanel', () => {
  /**
   * The commands carry the address agents actually use, not a placeholder and not the browser's.
   *
   * This is the whole reason the panel reads the address from the control plane rather than assembling
   * it here. The fleet page used to print the literal string `https://this-control-plane`, which every
   * operator replaced by hand with a value the page already knew — and the documented Traefik
   * deployment serves this page on a hostname where the agent API answers 403, so the browser's own
   * address is not a safe substitute either.
   */
  it('builds every command from the configured agent address', () => {
    const rendered = text(render(instructions()).nativeElement);

    expect(rendered).toContain('sudo hostseal enroll --server https://agents.example.org');
    expect(rendered).toContain('https://hostseal.io/apt/hostseal.sources');
    expect(rendered).not.toContain('this-control-plane');
  });

  /**
   * The certificate is fetched from this page's address, not from the agent hostname.
   *
   * `curl` verifies the control plane like every other client, so it can only fetch the certificate
   * over a connection it can already verify — and the agent hostname's certificate is precisely the
   * one it cannot, because the file being fetched is what would establish it. In the documented
   * two-hostname deployment this page is served where Traefik terminates with a publicly trusted
   * certificate, so pointing the command here is the difference between a command that works and one
   * that fails with `unable to get local issuer certificate` for every operator who copies it.
   */
  it('fetches the certificate from the interface address, not the agent address', () => {
    const rendered = text(render(instructions()).nativeElement);

    expect(rendered).toContain('https://hostseal.example.org/api/v1/ca.crt');
    expect(rendered).not.toContain('https://agents.example.org/api/v1/ca.crt');
  });

  /**
   * When one hostname serves both, the panel says the fetch cannot be verified.
   *
   * There is no address to point the command at in that deployment: the only name serving the
   * certificate is the one the certificate would authenticate. Printing a command that always fails
   * and saying nothing is how an operator concludes the control plane is broken, so the panel names
   * the error and the two ways round it instead.
   */
  it('warns when the certificate would be fetched from the name it authenticates', () => {
    const shared = text(
      render(instructions({ agentUrl: 'https://hostseal.example.org' }), 'https://hostseal.example.org/')
        .nativeElement,
    );
    expect(shared).toContain('unable to get local issuer certificate');

    const split = text(render(instructions()).nativeElement);
    expect(split).not.toContain('unable to get local issuer certificate');
  });

  /**
   * The unverified fetch is never offered without the check that makes it safe.
   *
   * `-k` alone accepts whoever answered the hostname, and what it would accept is the authority every
   * later connection from that host is checked against — so a mistake here is not one bad request, it
   * is a permanently wrong trust anchor. The command therefore carries the fingerprint, compares it in
   * the shell rather than asking a person to compare two 64-character strings by eye, and installs
   * nothing on a mismatch. This asserts the three halves travel together.
   */
  it('pairs an unverified fetch with a fingerprint check that fails closed', () => {
    const rendered = text(
      render(instructions({ agentUrl: 'https://hostseal.example.org' }), 'https://hostseal.example.org/')
        .nativeElement,
    );

    expect(rendered).toContain('curl -fsSLk');
    expect(rendered).toContain('sha256 Fingerprint=C0:62:73:A0');
    expect(rendered).toContain('FINGERPRINT MISMATCH');
  });

  /**
   * The verifiable deployment gets the plain command, with no -k anywhere near it.
   *
   * A panel that printed `-k` unconditionally would teach the habit it exists to avoid, on the
   * majority deployment where the fetch verifies perfectly well.
   */
  it('does not offer an unverified fetch when the fetch can be verified', () => {
    const rendered = text(render(instructions()).nativeElement);

    expect(rendered).not.toContain('curl -fsSLk');
    expect(rendered).toContain('curl -fsSL https://hostseal.example.org/api/v1/ca.crt');
  });

  /**
   * When nobody configured the address, the panel says the commands may be wrong.
   *
   * A guess is right for the ordinary single-hostname deployment and wrong for the two-hostname one,
   * and the interface cannot tell which it is in. Saying so is what stops the failure being discovered
   * after an agent has been installed on a machine and cannot enrol — which reads as a broken control
   * plane rather than as a missing setting.
   */
  it('says so when the agent address is a guess', () => {
    const guessed = text(
      render(instructions({ agentUrl: 'https://hostseal.example.org', agentUrlIsAGuess: true })).nativeElement,
    );
    expect(guessed).toContain('HOSTSEAL_AGENT_URL');

    const configured = text(render(instructions()).nativeElement);
    expect(configured).not.toContain('HOSTSEAL_AGENT_URL');
  });

  /**
   * The token is in the command once it exists, and the panel says it is shown once.
   *
   * Only the SHA-256 is stored, so a token nobody copied is not recoverable. That has to be said at
   * the moment it is on screen rather than in a footnote, because the alternative is an operator who
   * closes the panel expecting to come back for it.
   */
  it('puts a minted token into the command and says it cannot be shown again', () => {
    const fixture = render(instructions());

    expect(text(fixture.nativeElement)).toContain('--token <TOKEN>');

    (fixture.componentInstance as unknown as PanelInternals).mint();
    fixture.detectChanges();

    const rendered = text(fixture.nativeElement);
    expect(rendered).toContain('--token frr-enrol-abcdef');
    expect(rendered).toContain('cannot be shown again');
  });

  /**
   * A token for a template is offered only for templates a host could actually be handed.
   *
   * The control plane refuses to mint a token naming an unsigned or archived template, and it is
   * right to: an enrolling host verifies the template's signature against its own trusted-signers,
   * which this control plane cannot satisfy, and an archived name is refused at enrolment. A menu
   * that listed those would offer choices that fail — either here, with an error, or on the machine,
   * which is worse. So the menu is the control plane's rule applied in advance, and a fleet with no
   * signed template gets the plain button and no menu at all.
   */
  it('offers a token only for signed, live templates', () => {
    const withChoices = render(instructions(), 'https://hostseal.example.org/', [
      template({ name: 'baseline' }),
      template({ name: 'unsigned', signed: false }),
      template({ name: 'retired', archived: true }),
    ]);
    const handle = withChoices.nativeElement.querySelector('.hostseal-split__more') as HTMLElement;
    expect(handle).not.toBeNull();
    handle.click();
    withChoices.detectChanges();

    const items = Array.from(document.querySelectorAll('[mat-menu-item]')).map((item) =>
      text(item),
    );
    expect(items).toEqual(['Generate token for baseline']);

    const withoutChoices = render(instructions(), 'https://hostseal.example.org/', [
      template({ name: 'unsigned', signed: false }),
    ]);
    expect(withoutChoices.nativeElement.querySelector('.hostseal-split__more')).toBeNull();
    expect(text(withoutChoices.nativeElement)).toContain('Generate token');
  });

  /**
   * A token minted for a template names it in the request, and the command names it on the host.
   *
   * The template is chosen here, by an authenticated operator, and stamped on the token; the command
   * carries `--bootstrap` and `--signers` together because the agent refuses one without the other.
   * That pairing is the mechanism rather than a convenience: the trust anchor is a file the operator
   * puts on the host before anything is fetched, so a control plane that owns the token still cannot
   * choose what runs. A command that omitted the file would fail on the machine, with an error about
   * ordering that nothing on this page explains.
   */
  it('mints a token for the chosen template and pairs --bootstrap with --signers', () => {
    const minted: CreateEnrolmentTokenRequest[] = [];
    const fixture = render(
      instructions(),
      'https://hostseal.example.org/',
      [template({ name: 'baseline', signerKeyId: 'ops-yubikey-1' })],
      minted,
    );

    (fixture.componentInstance as unknown as PanelInternals).mint('baseline');
    fixture.detectChanges();

    expect(minted).toEqual([
      { label: 'from the fleet page, for baseline', group: '', bootstrap: 'baseline' },
    ]);
    const rendered = text(fixture.nativeElement);
    expect(rendered).toContain('--token frr-enrol-abcdef');
    expect(rendered).toContain('--signers ./trusted-signers --bootstrap baseline');
    expect(rendered).toContain('ops-yubikey-1');
  });

  /**
   * A plain token sends no template at all, rather than an empty one.
   *
   * The two are the same to the control plane today; the assertion is that the panel's default
   * remains the case it always minted, so a fleet that never signs a template sees no change.
   */
  it('mints a plain token with no bootstrap when none is chosen', () => {
    const minted: CreateEnrolmentTokenRequest[] = [];
    const fixture = render(
      instructions(),
      'https://hostseal.example.org/',
      [template({ name: 'baseline' })],
      minted,
    );

    (fixture.componentInstance as unknown as PanelInternals).mint();
    fixture.detectChanges();

    expect(minted).toEqual([{ label: 'from the fleet page', group: '' }]);
    expect(text(fixture.nativeElement)).not.toContain('--bootstrap');
  });

  /**
   * A Windows host is not offered a template, and a token that names one is called out there.
   *
   * A bootstrap is applied through cloud-init, which a Windows host does not run. The menu that
   * would mint such a token is withheld on that platform, and a token already minted for a template
   * is not silently printed into a PowerShell command that cannot honour it.
   */
  it('withholds the template menu on Windows and says why a template token will not work there', () => {
    const fixture = render(instructions(), 'https://hostseal.example.org/', [
      template({ name: 'baseline' }),
    ]);
    (fixture.componentInstance as unknown as PanelInternals).mint('baseline');
    (fixture.componentInstance as unknown as PanelInternals).showPlatform('windows');
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.hostseal-split__more')).toBeNull();
    const rendered = text(fixture.nativeElement);
    expect(rendered).not.toContain('--bootstrap');
    expect(rendered).toContain('a Windows host cannot apply one');
  });

  /**
   * The label, the group and the lifetime reach the control plane when they are filled in, and the
   * request carries no lifetime when the field is empty.
   *
   * The empty case is the one worth asserting: a lifetime of zero is what a cleared number field
   * reads as, and the control plane takes zero to mean "your default" — so sending it would be
   * harmless today and wrong the day the server starts refusing a zero. Omitting it is the honest
   * reading of an empty field. Hours are sent as seconds because that is the unit of the API, and the
   * conversion is the kind of arithmetic that is wrong by a factor of sixty without anybody noticing.
   */
  it('sends the label, the group and the lifetime, and omits a lifetime that was not chosen', () => {
    const minted: CreateEnrolmentTokenRequest[] = [];
    const fixture = render(instructions(), 'https://hostseal.example.org/', [], minted);
    const panel = fixture.componentInstance as unknown as PanelInternals;

    panel.mint();
    panel.tokenLabel.set(' web tier ');
    panel.tokenGroup.set('web-prod');
    panel.tokenHours.set(2);
    panel.mint();

    expect(minted).toEqual([
      { label: 'from the fleet page', group: '' },
      { label: 'web tier', group: 'web-prod', ttlSeconds: 7200 },
    ]);
  });

  /**
   * The listing says where every token stands, in three states rather than two booleans.
   *
   * "Not usable" on its own conflates the token a host redeemed with the one nobody ever did, and
   * they are different findings: one is a machine in the fleet and the other is an invitation that
   * sat open for a day. The listing also has to name the host that spent a token, because that is
   * the one line of provenance an enrolment leaves behind.
   */
  it('lists every token with its label, its template and where it stands', () => {
    const rendered = text(
      render(instructions(), 'https://hostseal.example.org/', [], [], [
        tokenRow({ label: 'web tier', group: 'web-prod', bootstrap: 'baseline' }),
        tokenRow({ label: 'db-07', consumed: true, consumedByHost: 'db-07', usable: false }),
        tokenRow({ label: 'forgotten', usable: false }),
      ]).nativeElement,
    );

    expect(rendered).toContain('web tier');
    expect(rendered).toContain('web-prod');
    expect(rendered).toContain('baseline');
    expect(rendered).toContain('open');
    expect(rendered).toContain('used by db-07');
    expect(rendered).toContain('expired unused');
  });

  /**
   * Minting a token re-reads the listing, so the row for it appears without a reload.
   *
   * Re-read rather than appended, because only the control plane knows whether a token minted a
   * moment ago has already been spent by a host that was waiting for it — and a listing that showed
   * "open" for a token in use would be wrong about the one thing it exists to say.
   */
  it('re-reads the listing after minting', () => {
    let reads = 0;
    const fixture = render(instructions());
    const api = TestBed.inject(ApiService) as unknown as TokenReads;
    const original = api.enrolmentTokens;
    api.enrolmentTokens = () => {
      reads += 1;
      return original();
    };

    (fixture.componentInstance as unknown as PanelInternals).mint();
    fixture.detectChanges();

    expect(reads).toBe(1);
  });

  /**
   * The certificate is installed by reading it from the control plane, not by hand.
   *
   * A step that spans two machines is the step people improvise around, and the improvisation here is
   * a host that verifies the control plane against the system roots instead of this authority — which
   * works, until the day it matters. The mode and owner are in the command for the same reason: a file
   * the agent cannot read fails enrolment in a way that names neither.
   */
  it('installs the CA certificate with an explicit owner and mode', () => {
    const rendered = text(render(instructions()).nativeElement);
    expect(rendered).toContain('/etc/hostseal/server-ca.crt');
    expect(rendered).toContain('-o root -g root -m 0644');
  });
  /**
   * A failed install is never reported as a fingerprint mismatch.
   *
   * `test && install || echo` reads correctly and is wrong: the `||` binds to the whole list, so a
   * missing sudo or a full disk prints an attack that did not happen and then exits 0, leaving a
   * script free to enrol against a certificate that was never installed. The two outcomes have to be
   * distinguishable, and the install has to keep its own exit status.
   */
  it('separates a fingerprint mismatch from a failed installation', () => {
    const command = text(
      render(instructions({ agentUrl: 'https://hostseal.example.org' }), 'https://hostseal.example.org/')
        .nativeElement,
    );

    expect(command).not.toContain('|| echo "FINGERPRINT MISMATCH');
    expect(command).toContain('if [');
    expect(command).toContain('else');
  });

  /**
   * A Windows host gets the commands that work on it, not a translation of the Debian ones.
   *
   * The Windows agent shipped and every route to installing it was a Linux command: the panel printed
   * `apt-get`, the release attached no archive, and INSTALL.md said nothing — so the only instructions
   * that existed were the comment header of a PowerShell file nobody had a copy of. This asserts the
   * whole path is here: where the archive comes from, the installer that unpacks it, the CLI under
   * Program Files, and the service restart.
   */
  it('writes PowerShell for a Windows host, and names the archive it comes from', () => {
    const rendered = text(renderWindows(instructions()).nativeElement);

    expect(rendered).toContain('hostseal-agent-windows-amd64.zip');
    expect(rendered).toContain('Install-HostSealAgent.ps1');
    expect(rendered).toContain("& 'C:\\Program Files\\HostSeal\\hostseal.exe' enroll");
    expect(rendered).toContain('Restart-Service hostseal-agent');
    expect(rendered).not.toContain('apt-get');
    expect(rendered).not.toContain('sudo');
  });

  /**
   * `curl.exe`, never the bare name, and the downloaded files are unblocked before one is run.
   *
   * Both are the difference between a command that works on a fresh Windows Server and one that fails
   * while looking correct. `curl` is an alias for `Invoke-WebRequest` in Windows PowerShell 5.1, which
   * reads the arguments differently and needs `-UseBasicParsing` on a host with Internet Explorer
   * Enhanced Security; and a script unpacked from a downloaded archive carries the internet zone, which
   * the default RemoteSigned execution policy refuses — with an error that sends people to
   * `Set-ExecutionPolicy Bypass` and leaves the machine weaker than it was found.
   */
  it('uses the real curl and clears the zone before running the installer', () => {
    const rendered = text(renderWindows(instructions()).nativeElement);

    expect(rendered).toContain('curl.exe -fsSL');
    expect(rendered).toContain('Unblock-File');
    expect(rendered).not.toContain('Set-ExecutionPolicy');
  });

  /**
   * The Windows fingerprint check hashes the certificate, not the file that carries it.
   *
   * The digest on this page is openssl's: a SHA-256 over the DER. `Get-FileHash` on the downloaded PEM
   * is a different number that never matches, so a check written that way fails every honest fetch —
   * and the operator's way out of a step that always says MISMATCH is to stop performing it. The copy
   * matters for a quieter reason: a move would carry the permissions the file had in %TEMP%, where the
   * agent's service account is not named, leaving it unable to read the authority it verifies against.
   */
  it('checks the Windows download against the certificate digest and copies it into place', () => {
    const rendered = text(
      renderWindows(instructions({ agentUrl: 'https://hostseal.example.org' }), 'https://hostseal.example.org/')
        .nativeElement,
    );

    expect(rendered).toContain('curl.exe -fsSLk');
    expect(rendered).toContain('$cert.RawData');
    expect(rendered).toContain("$got -ne 'C0:62:73:A0");
    expect(rendered).toContain('FINGERPRINT MISMATCH');
    expect(rendered).toContain("Copy-Item -Path $tmp -Destination 'C:\\Program Files\\HostSeal\\server-ca.crt'");
    expect(rendered).not.toContain('Get-FileHash');
    expect(rendered).not.toContain('Move-Item');
  });

  /**
   * Every Windows step stops at its first failure, which loose PowerShell lines do not.
   *
   * Pasted at a prompt, each line is its own statement: a download that fails leaves the next command
   * running, and the staging paths are fixed, so a previous run's archive may still be sitting there.
   * The installer would start from stale files and report an upgrade it did not perform. The same
   * shape is worse in the certificate step — a fetch that failed leaves the digest empty, the
   * comparison false, and the operator looking at MISMATCH, which names an attack for a control plane
   * that was merely unreachable.
   *
   * `& { … }` is what gives `throw` something to abandon, `$ErrorActionPreference` inside it makes a
   * failing cmdlet terminating without altering the session afterwards, and `$LASTEXITCODE` is
   * checked by hand because no preference variable covers a native program.
   */
  it('stops each Windows step at the first failure rather than carrying on', () => {
    const install = text(renderWindows(instructions()).nativeElement);

    expect(install).toContain('& { $ErrorActionPreference');
    expect(install).toContain('$LASTEXITCODE -ne 0');
    expect(install).toContain('Remove-Item -Path $zip, $dir');

    const unverified = text(
      renderWindows(instructions({ agentUrl: 'https://hostseal.example.org' }), 'https://hostseal.example.org/')
        .nativeElement,
    );

    // The fetch is checked before anything is compared, so an unreachable control plane cannot be
    // reported as a fingerprint mismatch.
    expect(unverified.indexOf('$LASTEXITCODE -ne 0')).toBeLessThan(
      unverified.indexOf('FINGERPRINT MISMATCH'),
    );
  });

  /**
   * Enrolment is followed by a restart, on both platforms, in the command rather than in a footnote.
   *
   * Installing the agent starts it, so by the time anybody enrols there is a service that found no
   * credential and went into the idle loop — which re-reads the local policy on every tick and never
   * re-reads the enrolment state. An operator who stopped after `hostseal enroll` was left with an
   * active service, a host the control plane had heard of once, and no facts arriving; nothing in that
   * state names the missing step.
   */
  it('restarts the agent after enrolling, on either platform', () => {
    expect(text(render(instructions()).nativeElement)).toContain(
      'sudo systemctl restart hostseal-agent',
    );
    expect(text(renderWindows(instructions()).nativeElement)).toContain(
      'Restart-Service hostseal-agent',
    );
  });

  /**
   * A path prefix or a port does not make a single-hostname deployment look like a two-hostname one.
   *
   * The agent URL is a full base URL and the page's is a document address, so comparing them as
   * strings answered "can this fetch be verified?" wrongly whenever the deployment carried either —
   * and wrongly in the unsafe direction, claiming verifiable when it was not. The command it then
   * built dropped the prefix too. Both halves are asserted here because either alone would pass with
   * the other still broken.
   */
  it('compares origins, and keeps the path a control plane is published under', () => {
    const prefixed = text(
      render(
        instructions({ agentUrl: 'https://hostseal.example.org/control' }),
        'https://hostseal.example.org/control/',
      ).nativeElement,
    );

    expect(prefixed).toContain('unable to get local issuer certificate');
    expect(prefixed).toContain('https://hostseal.example.org/control/api/v1/ca.crt');
  });

  /**
   * The verifiable branch keeps the prefix too, for a two-hostname deployment behind a path.
   *
   * The same bug in the other direction: an interface published under a path would have been handed a
   * download URL at the bare origin, which is a 404 rather than a certificate.
   */
  it('keeps the interface path when the fetch can be verified', () => {
    const rendered = text(
      render(instructions(), 'https://hostseal.example.org/control/').nativeElement,
    );

    expect(rendered).toContain('curl -fsSL https://hostseal.example.org/control/api/v1/ca.crt');
  });
});
