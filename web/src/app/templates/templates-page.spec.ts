import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { Subject, of, throwError } from 'rxjs';

import { ApiService } from '../core/api.service';
import {
  TemplateRevision,
  TemplateSummary,
  TemplateVersion,
  TemplatesResponse,
} from '../core/api.models';
import { LocalSignerService } from '../core/local-signer.service';
import { TemplatesPage } from './templates-page';

/** Builds one revision of the history, so each spec names only the part it is about. */
function revision(partial: Partial<TemplateRevision>): TemplateRevision {
  return {
    version: 1,
    signed: false,
    createdAt: '2026-08-24T09:41:07.512Z',
    createdBy: 'test:tester',
    ...partial,
  };
}

/** Builds one listing row, so each spec names only the part it is about. */
function summary(partial: Partial<TemplateSummary>): TemplateSummary {
  return {
    name: 'standard-server',
    latestVersion: 1,
    createdAt: '2026-08-24T09:41:07.512Z',
    createdBy: 'test:tester',
    signed: false,
    archived: false,
    ...partial,
  };
}

/** Builds the one version the detail pane holds open. */
function version(partial: Partial<TemplateVersion>): TemplateVersion {
  return {
    name: 'standard-server',
    version: 3,
    body: '#cloud-config\n{}\n',
    signed: false,
    createdAt: '2026-08-24T09:41:07.512Z',
    createdBy: 'test:tester',
    placeholders: [],
    warnings: [],
    archived: false,
    ...partial,
  };
}

/**
 * The two protected members these specs reach for, named so the casts below stay readable.
 *
 * Protected rather than public because they are the template's to call, and a spec that drives the
 * page the way the markup does has to say so out loud rather than widen the component's surface.
 */
interface PageInternals {
  /** Opens one template, which is also what loads its revision history. */
  open(name: string, version?: number): void;

  /** Renders one revision's stored time, which is the formatting one spec is about. */
  stored(revision: TemplateRevision): string;

  /** Shows or hides the withdrawn templates, which is what puts two listings in flight. */
  toggleArchived(): void;
}

/** Renders the page with one template open and a fixed history behind it. */
function render(
  open: TemplateVersion,
  history: TemplateRevision[] | 'fails',
): ComponentFixture<TemplatesPage> {
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      {
        provide: ApiService,
        useValue: {
          templates: () =>
            of({
              templates: [
                {
                  name: open.name,
                  latestVersion: open.version,
                  createdAt: open.createdAt,
                  createdBy: open.createdBy,
                  signed: open.signed,
                },
              ],
            }),
          template: () => of(open),
          templateVersions: () =>
            history === 'fails'
              ? throwError(() => new Error('the control plane is down'))
              : of({ name: open.name, versions: history }),
        } as unknown as ApiService,
      },
    ],
  });
  const fixture = TestBed.createComponent(TemplatesPage);
  fixture.detectChanges();
  (fixture.componentInstance as unknown as PageInternals).open(open.name);
  fixture.detectChanges();
  return fixture;
}

/**
 * Every h2 on the page, collapsed.
 *
 * The detail pane's heading is not the first h2 — the stored-templates list has one above it — so a
 * spec asking "is this template open" has to look at the set rather than at whichever comes first.
 */
function headings(fixture: ComponentFixture<TemplatesPage>): string[] {
  return Array.from(fixture.nativeElement.querySelectorAll('h2')).map((h) => text(h as Element));
}

/** Every card title on the page, collapsed, so a spec can assert a pane is absent. */
function cardTitles(fixture: ComponentFixture<TemplatesPage>): string[] {
  return Array.from(fixture.nativeElement.querySelectorAll('mat-card-title')).map((t) =>
    text(t as Element),
  );
}

/** Collapses whitespace, so an assertion can be written the way a row actually reads. */
function text(element: Element | null): string {
  return (element?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

describe('TemplatesPage version history', () => {
  /**
   * Immutable versioning is the storage model, and until this pane existed it was something an
   * operator had to take on faith: the listing showed only the latest version, so reaching version 3
   * of a template whose latest is 7 meant guessing a number. A property nobody can look at is not a
   * property worth having.
   */
  it('lists every stored revision with who stored it and whether it is signed', () => {
    const fixture = render(version({ version: 3 }), [
      revision({ version: 3, createdBy: 'test:tester' }),
      revision({ version: 2, signed: true, signerKeyId: 'ops-1', createdBy: 'alice' }),
      revision({ version: 1, createdBy: 'alice' }),
    ]);

    const rendered = Array.from(
      fixture.nativeElement.querySelectorAll('mat-card-content > div'),
    ).map((row) => text(row as Element));
    const rows = rendered.filter((row) => /^v\d/.test(row));

    expect(rows.length).toBe(3);
    expect(rows[0]).toContain('v3');
    expect(rows[1]).toContain('v2');
    expect(rows[1]).toContain('signed');
    expect(rows[1]).toContain('alice');
    expect(rows[2]).toContain('unsigned');
  });

  /**
   * The timestamp is UTC and stated as such. Every other page in this application renders an age
   * against the control plane's clock, precisely because a laptop clock ten minutes out would corrupt
   * a number operators make decisions on. This response carries no server time, so the answer here is
   * to consult no clock at all: "which of these is the one from Tuesday's change window" is answered
   * by the stamp the server wrote.
   */
  it('renders the stored time in UTC rather than relative to the browser', () => {
    const fixture = render(version({}), [revision({ version: 1 })]);
    const shown = (fixture.componentInstance as unknown as PageInternals).stored(
      revision({ createdAt: '2026-08-24T09:41:07.512Z' }),
    );

    expect(shown).toBe('2026-08-24 09:41 UTC');
    expect(shown).not.toContain('ago');
  });

  /**
   * The history is context beside the version, not the thing the operator asked for. A failure to
   * load it must not put an error banner over a pane whose body, warnings and render form are on
   * screen and correct — that reports a working page as broken.
   */
  it('stays silent when the history cannot be loaded', () => {
    const fixture = render(version({ body: '#cloud-config\nhostname: fixed\n' }), 'fails');

    expect(text(fixture.nativeElement.querySelector('pre'))).toContain('hostname: fixed');
    expect(fixture.nativeElement.querySelectorAll('.text-hostseal-bad').length).toBe(0);
  });

  /**
   * A single-version template has no history worth a pane: one row saying "v1, open" is furniture
   * that makes the page longer without answering a question anybody had.
   */
  it('shows no pane for a template with one version', () => {
    const fixture = render(version({ version: 1 }), [revision({ version: 1 })]);
    const titles = Array.from(fixture.nativeElement.querySelectorAll('mat-card-title')).map((t) =>
      text(t as Element),
    );

    expect(titles).not.toContain('Versions');
    expect(titles).toContain('Render');
  });
});

describe('TemplatesPage pane correlation', () => {
  /**
   * Opening a template is two requests — the body and the history — and nothing else ties their
   * answers together. They can disagree in both directions: reading a version decrypts a sealed body
   * and answers 500 where the listing, which decrypts nothing, answers 200; and two clicks in flight
   * can land in either order. Either way the markup would compare one template's revision numbers
   * against another's open version, marking the wrong row "open" and offering buttons that pair this
   * name with that one's versions.
   */
  it('discards a history that belongs to a different template', () => {
    const open = version({ name: 'standard-server', version: 2 });
    TestBed.configureTestingModule({
      providers: [
        provideZonelessChangeDetection(),
        {
          provide: ApiService,
          useValue: {
            templates: () => of({ templates: [] }),
            template: () => of(open),
            // A late answer about the template the operator has already navigated away from.
            templateVersions: () =>
              of({
                name: 'something-else',
                versions: [revision({ version: 9 }), revision({ version: 8 })],
              }),
          } as unknown as ApiService,
        },
      ],
    });
    const fixture = TestBed.createComponent(TemplatesPage);
    fixture.detectChanges();
    (fixture.componentInstance as unknown as PageInternals).open('standard-server');
    fixture.detectChanges();

    expect(cardTitles(fixture)).not.toContain('Versions');
    expect(headings(fixture)).toContain('standard-server v2');
  });

  /**
   * The complementary half: a failed body fetch must not leave the previous template on screen while
   * the new one's history loads underneath it. Clearing both up front is what makes the pane's two
   * halves always describe the same template, including in the window before either answer arrives.
   */
  it('does not show one template\'s history against another template\'s body', () => {
    let call = 0;
    TestBed.configureTestingModule({
      providers: [
        provideZonelessChangeDetection(),
        {
          provide: ApiService,
          useValue: {
            templates: () => of({ templates: [] }),
            // The first open succeeds; the second — a different template — fails on the body.
            template: () =>
              call++ === 0
                ? of(version({ name: 'first', version: 1 }))
                : throwError(() => new Error('sealed')),
            templateVersions: (name: string) =>
              of({ name, versions: [revision({ version: 4 }), revision({ version: 3 })] }),
          } as unknown as ApiService,
        },
      ],
    });
    const fixture = TestBed.createComponent(TemplatesPage);
    fixture.detectChanges();
    const page = fixture.componentInstance as unknown as PageInternals;

    page.open('first');
    fixture.detectChanges();
    expect(headings(fixture)).toContain('first v1');

    page.open('second');
    fixture.detectChanges();

    // No stale header, and therefore no pane pairing "second"'s revisions with "first"'s version.
    expect(headings(fixture).join(' ')).not.toContain('first v1');
    expect(cardTitles(fixture)).not.toContain('Versions');
  });
});

describe('TemplatesPage cloud-init examples', () => {
  /**
   * The link exists, points at the examples, and opens safely.
   *
   * This page is where somebody writing their first template arrives, and the repository already
   * carries an annotated baseline they would otherwise never find. It is asserted rather than reviewed
   * for because its absence is silent: the page renders, reads complete, and simply never mentions the
   * examples again.
   *
   * `rel` is checked with it, because `target="_blank"` without `noopener` hands the opened page a
   * handle on this one — and this one is a signed-in control plane.
   */
  it('links to the worked cloud-init examples in the repository', () => {
    const fixture = render(version({}), [revision({ version: 3 })]);

    const links = Array.from(
      fixture.nativeElement.querySelectorAll('a[href]'),
    ) as HTMLAnchorElement[];
    const examples = links.find((a) => a.href.includes('examples/cloud-init'));

    expect(examples)
      .withContext('the Templates page no longer links to examples/cloud-init')
      .toBeDefined();
    expect(examples?.href).toBe(
      'https://github.com/pascalgross/hostseal/tree/main/examples/cloud-init',
    );
    expect(examples?.rel).toContain('noopener');
  });
});

/** What `renderArchivable` hands a spec: the page, and a record of what it asked the control plane. */
interface ArchivableHarness {
  /** The rendered page, with one template already open. */
  fixture: ComponentFixture<TemplatesPage>;

  /** Every archive and restore the page sent, in order, each as `action:name`. */
  calls: string[];

  /** Whether each listing request asked for the archived templates too, in order. */
  listings: boolean[];
}

describe('TemplatesPage archiving', () => {
  /**
   * Builds a page whose fake control plane records what was asked of it.
   *
   * The recorder is the point of these specs rather than a convenience: archiving is the page's
   * answer to a delete button, and what has to be asserted is which request it sends and when —
   * a page that archived on the first click, or that sent a delete, would look identical on screen.
   */
  function renderArchivable(open: TemplateVersion): ArchivableHarness {
    const calls: string[] = [];
    const listings: boolean[] = [];
    TestBed.configureTestingModule({
      providers: [
        provideZonelessChangeDetection(),
        {
          provide: ApiService,
          useValue: {
            templates: (includeArchived = false) => {
              listings.push(includeArchived);
              return of({
                templates: [
                  {
                    name: open.name,
                    latestVersion: open.version,
                    createdAt: open.createdAt,
                    createdBy: open.createdBy,
                    signed: open.signed,
                    archived: open.archived,
                    archivedAt: open.archivedAt,
                    archivedBy: open.archivedBy,
                  },
                ],
              });
            },
            template: () => of(open),
            templateVersions: (name: string) => of({ name, versions: [revision({ version: 1 })] }),
            archiveTemplate: (name: string) => {
              calls.push(`archive:${name}`);
              return of({ name, archived: true });
            },
            restoreTemplate: (name: string) => {
              calls.push(`restore:${name}`);
              return of({ name, archived: false });
            },
          } as unknown as ApiService,
        },
      ],
    });
    const fixture = TestBed.createComponent(TemplatesPage);
    fixture.detectChanges();
    (fixture.componentInstance as unknown as PageInternals).open(open.name);
    fixture.detectChanges();
    return { fixture, calls, listings };
  }

  /** Every button on the page, collapsed, so a spec can assert an affordance is absent. */
  function buttons(fixture: ComponentFixture<TemplatesPage>): string[] {
    return Array.from(fixture.nativeElement.querySelectorAll('button')).map((b) =>
      text(b as Element),
    );
  }

  /** Clicks the first button whose label contains the given text. */
  function click(fixture: ComponentFixture<TemplatesPage>, label: string): void {
    const found = (
      Array.from(fixture.nativeElement.querySelectorAll('button')) as HTMLButtonElement[]
    ).find((b) => text(b).includes(label));
    if (!found) {
      throw new Error(`no button reading ${label}: ${buttons(fixture).join(' | ')}`);
    }
    found.click();
    fixture.detectChanges();
  }

  /**
   * The page offers no delete, and this is the spec that keeps it that way.
   *
   * A version is what a host's bootstrap record names, so nothing here may destroy one — and an
   * operator looking for the missing button has to find the reason where they looked, rather than
   * reading its absence as an oversight.
   */
  it('offers archiving instead of a delete, and says why', () => {
    const { fixture } = renderArchivable(version({}));

    expect(buttons(fixture)).toContain('Archive');
    expect(buttons(fixture).join(' | ')).not.toContain('Delete');
    expect(text(fixture.nativeElement)).toContain('Nothing here can be deleted');
  });

  /**
   * Archiving is confirmed, not done on one click. It is undone in one click and destroys nothing,
   * but what it breaks in the meantime is somebody else's enrolment, hours later, on a machine being
   * built — so the request must not leave until an operator has read that sentence.
   */
  it('asks before withdrawing a name, and sends nothing until it is confirmed', () => {
    const { fixture, calls } = renderArchivable(version({ name: 'standard-server' }));

    click(fixture, 'Archive');
    expect(calls).toEqual([]);
    expect(text(fixture.nativeElement)).toContain('enrolments requesting it are refused');

    click(fixture, 'Archive standard-server');
    expect(calls).toEqual(['archive:standard-server']);
  });

  /**
   * An archived template is still readable — that is the whole difference from a delete — so the pane
   * has to say which of the two states it is showing, and offer the undo rather than an edit.
   */
  it('marks an archived template, keeps its body on screen and offers the restore', () => {
    const { fixture, calls } = renderArchivable(
      version({
        body: '#cloud-config\nhostname: retired\n',
        archived: true,
        archivedAt: '2026-08-24T09:41:07.512Z',
        archivedBy: 'alice',
      }),
    );

    expect(text(fixture.nativeElement)).toContain('Archived on 2026-08-24 09:41 UTC by alice');
    expect(text(fixture.nativeElement.querySelector('pre'))).toContain('hostname: retired');
    expect(buttons(fixture)).toContain('Restore');
    expect(buttons(fixture)).not.toContain('Archive');
    expect(buttons(fixture)).not.toContain('Edit as new version');

    click(fixture, 'Restore');
    expect(calls).toEqual(['restore:standard-server']);
  });

  /**
   * Two listings are in flight whenever the toggle is pressed while the constructor's first one is
   * still out, and nothing but the requested mode ties an answer to the question it answers. Landing
   * out of order would leave the button reading "Hide archived" over a list with the archived ones
   * missing — which reads as the toggle being broken rather than as a response arriving late.
   */
  it('discards a listing that answers the mode the page is no longer in', () => {
    const live = new Subject<TemplatesResponse>();
    const withArchived = new Subject<TemplatesResponse>();
    TestBed.configureTestingModule({
      providers: [
        provideZonelessChangeDetection(),
        {
          provide: ApiService,
          useValue: {
            templates: (includeArchived = false) => (includeArchived ? withArchived : live),
          } as unknown as ApiService,
        },
      ],
    });
    const fixture = TestBed.createComponent(TemplatesPage);
    fixture.detectChanges();

    // The constructor's listing is still out when the operator asks for the archived ones.
    (fixture.componentInstance as unknown as PageInternals).toggleArchived();
    fixture.detectChanges();

    withArchived.next({ templates: [summary({ name: 'retired', archived: true })] });
    fixture.detectChanges();
    expect(text(fixture.nativeElement)).toContain('retired');

    // And now the first request finally answers, about a mode the page has left.
    live.next({ templates: [summary({ name: 'in-use' })] });
    fixture.detectChanges();

    expect(text(fixture.nativeElement)).toContain('retired');
    expect(text(fixture.nativeElement)).not.toContain('in-use');
  });

  /**
   * Hidden by default, because that is what retiring a template was for; listable on request,
   * because a name nobody can see is a name nobody can restore — which would make archiving the
   * deletion it deliberately is not.
   */
  it('asks the control plane for the archived templates only when they are shown', () => {
    const { fixture, listings } = renderArchivable(version({}));

    expect(listings).toEqual([false]);

    click(fixture, 'Show archived');
    expect(listings).toEqual([false, true]);
    expect(buttons(fixture)).toContain('Hide archived');

    click(fixture, 'Hide archived');
    expect(listings).toEqual([false, true, false]);
  });
});


/**
 * The signing members these specs drive, named so the casts below stay readable.
 *
 * Driven directly rather than through the buttons for the reason the interface above exists: what is
 * under test is what the page does with a signature, and a click path through Material's button
 * component would be testing Material.
 */
interface SigningInternals {
  /** Looks for a signer on this machine. */
  findSigner(): void;

  /** Signs the open version and stores the result as the next one. */
  signOpen(): void;
}

/** A local signer that answers, or fails the way a missing one does. */
interface FakeSigner {
  /** What `status()` answers with, or the failure it raises. */
  status: () => ReturnType<LocalSignerService['status']>;

  /** What `signTemplate()` answers with, or the failure it raises. */
  signTemplate: (name: string, body: string) => ReturnType<LocalSignerService['signTemplate']>;
}

/** Renders the page with one version open, a fake control plane and a fake local signer. */
function renderWithSigner(
  open: TemplateVersion,
  signer: Partial<FakeSigner>,
  api: Partial<Record<string, unknown>> = {},
): ComponentFixture<TemplatesPage> {
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      {
        provide: ApiService,
        useValue: {
          templates: () => of({ templates: [] }),
          template: () => of(open),
          templateVersions: () => of({ name: open.name, versions: [revision({ version: 1 })] }),
          createTemplate: () => of({ name: open.name, version: open.version + 1, signed: true }),
          ...api,
        } as unknown as ApiService,
      },
      {
        provide: LocalSignerService,
        useValue: {
          status: () => throwError(() => ({ status: 0 })),
          signTemplate: () => throwError(() => ({ status: 0 })),
          ...signer,
        } as unknown as LocalSignerService,
      },
    ],
  });
  const fixture = TestBed.createComponent(TemplatesPage);
  fixture.detectChanges();
  (fixture.componentInstance as unknown as PageInternals).open(open.name);
  fixture.detectChanges();
  return fixture;
}

describe('TemplatesPage signing', () => {
  /**
   * The page has to say why a bootstrap needs a signature at all, where the signature is made, and
   * what the host checks it against. Those three sentences are the difference between an operator who
   * understands that HostSeal cannot sign for them and one who files a bug asking for a "sign"
   * button on the server.
   *
   * Asserted rather than reviewed for because an explanation is the first thing a redesign drops: the
   * page still works without it, and nothing goes red.
   */
  it('explains why a bootstrap is signed, where, and what verifies it', () => {
    const fixture = renderWithSigner(version({}), {});
    const page = text(fixture.nativeElement.querySelector('mat-card-content'));
    const whole = text(fixture.nativeElement);

    expect(page).toBeDefined();
    expect(whole).toContain('/etc/hostseal/trusted-signers');
    expect(whole).toContain('never leaves the YubiKey');
    expect(whole).toContain('on your own machine');
  });

  /**
   * "Signed" on its own answers half the question. Which key, and under which algorithm, is what an
   * operator compares against a host's trusted-signers line — and a version signed by the right
   * person under the other algorithm is refused at enrolment with nothing on the page to explain it.
   */
  it('names the key and the algorithm a version was signed with', () => {
    const fixture = renderWithSigner(
      version({ signed: true, signerKeyId: 'ops-yubikey-1', signerAlgorithm: 'ecdsa-p256' }),
      {},
    );

    const whole = text(fixture.nativeElement);
    expect(whole).toContain('ops-yubikey-1');
    expect(whole).toContain('ecdsa-p256');
  });

  /**
   * The flow itself: the page sends the open version's name and body to the signer, and stores what
   * comes back as a new version carrying the signature triple.
   *
   * The body is asserted on the way out because it is the thing the signature covers. A page that
   * sent one body to the signer and stored another would produce a version that looks signed and is
   * refused by every host — the failure is silent here and loud, days later, on somebody's machine.
   */
  it('signs the open version with the local signer and stores the signature', () => {
    const stored: Record<string, unknown>[] = [];
    const asked: string[] = [];
    const fixture = renderWithSigner(
      version({ name: 'standard-server', version: 3, body: '#cloud-config\nhostname: x\n' }),
      {
        signTemplate: (name: string, body: string) => {
          asked.push(`${name}|${body}`);
          return of({
            name,
            signature: 'c2lnbmF0dXJl',
            signerKeyId: 'ops-yubikey-1',
            signerAlgorithm: 'ecdsa-p256',
          });
        },
      },
      {
        createTemplate: (request: Record<string, unknown>) => {
          stored.push(request);
          return of({ name: 'standard-server', version: 4, signed: true });
        },
      },
    );

    (fixture.componentInstance as unknown as SigningInternals).signOpen();
    fixture.detectChanges();

    expect(asked).toEqual(['standard-server|#cloud-config\nhostname: x\n']);
    expect(stored.length).toBe(1);
    expect(stored[0]).toEqual({
      name: 'standard-server',
      body: '#cloud-config\nhostname: x\n',
      signature: 'c2lnbmF0dXJl',
      signerKeyId: 'ops-yubikey-1',
      signerAlgorithm: 'ecdsa-p256',
    });
  });

  /**
   * A signature is only ever about the template it was made for. Storing one against another name
   * would produce a version that reads as signed here and is refused by every host, for a reason
   * nothing on this page could explain — so the echoed name is checked and nothing is stored.
   */
  it('stores nothing when the signer answers about a different template', () => {
    const stored: unknown[] = [];
    const fixture = renderWithSigner(
      version({ name: 'standard-server' }),
      {
        signTemplate: () =>
          of({
            name: 'something-else',
            signature: 'c2ln',
            signerKeyId: 'ops-yubikey-1',
            signerAlgorithm: 'ed25519',
          }),
      },
      {
        createTemplate: (request: unknown) => {
          stored.push(request);
          return of({ name: 'standard-server', version: 4, signed: true });
        },
      },
    );

    (fixture.componentInstance as unknown as SigningInternals).signOpen();
    fixture.detectChanges();

    expect(stored.length).toBe(0);
    expect(text(fixture.nativeElement)).toContain('something-else');
  });

  /**
   * The actionable half of "no signer". A page that said "could not connect" would leave an operator
   * with nothing to do; the command, with this page's own origin already in it, is the one thing they
   * cannot guess — a signer started with any other --origin refuses every request from here.
   */
  it('says what to run when no signer answers', () => {
    const fixture = renderWithSigner(version({}), {
      status: () => throwError(() => ({ status: 0 })),
    });

    (fixture.componentInstance as unknown as SigningInternals).findSigner();
    fixture.detectChanges();

    const whole = text(fixture.nativeElement);
    expect(whole).toContain('hostseal signer');
    expect(whole).toContain('--origin');
    expect(whole).toContain(location.origin);
    expect(whole).toContain('libykcs11.dll');
  });

  /**
   * And the found case: the key that will sign, and the line a host needs in its own
   * trusted-signers for that key to mean anything. The second is the step that otherwise gets
   * skipped, because it is the only part of this that no tooling can do for anybody — the file is
   * edited by hand, by an administrator, on each host.
   */
  it('shows the key it found and the line a host needs for it', () => {
    const fixture = renderWithSigner(version({}), {
      status: () =>
        of({
          signer: 'hostseal',
          version: '1.2.3',
          keyId: 'ops-yubikey-1',
          algorithm: 'ecdsa-p256',
          backend: 'pkcs11',
          trustedSignerLine: 'ecdsa-p256 QUJD ops-yubikey-1 pkcs11',
        }),
    });

    (fixture.componentInstance as unknown as SigningInternals).findSigner();
    fixture.detectChanges();

    const whole = text(fixture.nativeElement);
    expect(whole).toContain('ops-yubikey-1');
    expect(whole).toContain('pkcs11');
    expect(whole).toContain('ecdsa-p256 QUJD ops-yubikey-1 pkcs11');
  });
});
