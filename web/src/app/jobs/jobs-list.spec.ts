import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { of, throwError } from 'rxjs';

import { ApiService } from '../core/api.service';
import { SignedJob } from '../core/api.models';
import { LocalSignerService } from '../core/local-signer.service';
import { JobsList } from './jobs-list';

/** The catalogue the page builds both of its forms from. */
const catalogue = {
  intents: [
    {
      name: 'services.list',
      class: 'read',
      summary: 'list units',
      implemented: true,
      requiresOfflineSignature: false,
    },
    {
      name: 'host.reboot',
      class: 'destructive',
      summary: 'reboot the host',
      implemented: true,
      requiresOfflineSignature: true,
    },
  ],
  refused: [],
  note: '',
};

/** One signed job, as the local signer hands it back. */
function signedJob(partial: Partial<SignedJob> = {}): SignedJob {
  return {
    id: '01JJOB000000000000000000000',
    hostId: '01JHOST00000000000000000000',
    intent: 'host.reboot',
    params: { delaySeconds: 60 },
    notBefore: '2026-09-21T10:00:00Z',
    notAfter: '2026-09-21T11:00:00Z',
    nonce: '01JNONCE0000000000000000000',
    signature: 'c2lnbmF0dXJl',
    signerKeyId: 'ops-yubikey-1',
    signerAlgorithm: 'ecdsa-p256',
    ...partial,
  };
}

/** The half of a signal these specs use: the ability to put a value into a form field. */
interface Writable<T> {
  /** Sets the field, as the markup's two-way binding does. */
  set(value: T): void;
}

/**
 * The protected members these specs drive.
 *
 * Driven directly rather than through Material's buttons and selects, for the reason the templates
 * page's specs give: what is under test is what the page does with a signature, and a click path
 * through a component library is a test of that library.
 */
interface PageInternals {
  /** The host the report form is about. */
  chosenHost: Writable<string>;

  /** The operation the report form is about. */
  chosenIntent: Writable<string>;

  /** The parameters for the report form, as JSON. */
  readParams: Writable<string>;

  /** Queues what the report form holds. */
  createJob(): void;

  /** The host the destructive form is about. */
  signHost: Writable<string>;

  /** The operation the destructive form is about. */
  signIntent: Writable<string>;

  /** The parameters for it, as JSON. */
  signParams: Writable<string>;

  /** How long the signature stays valid. */
  signValidMinutes: Writable<number>;

  /** A signed job pasted in from a terminal. */
  pastedJob: Writable<string>;

  /** Asks the local signer for a signature and queues what comes back. */
  signAndQueue(): void;

  /** Queues a signed job that was pasted in. */
  queuePasted(): void;

  /** Looks for a signer on this machine. */
  findSigner(): void;

  /** Shows the command to copy and the box to paste into. */
  toggleTerminalPath(): void;

  /** The `hostseal sign` command for what the form holds. */
  signCommand(): string;
}

/** Renders the page against a fake control plane and a fake local signer. */
function render(
  signer: Partial<Record<string, unknown>>,
  api: Partial<Record<string, unknown>> = {},
): ComponentFixture<JobsList> {
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      {
        provide: ApiService,
        useValue: {
          jobs: () => of({ jobs: [], truncated: false, serverTime: '2026-09-21T10:00:00Z' }),
          jobsAwaitingApproval: () =>
            of({ jobs: [], truncated: false, serverTime: '2026-09-21T10:00:00Z' }),
          fleet: () =>
            of({ hosts: [{ id: '01JHOST00000000000000000000', hostname: 'web-01', revoked: false }] }),
          catalogue: () => of(catalogue),
          createSignedJob: () => of({}),
          ...api,
        } as unknown as ApiService,
      },
      {
        provide: LocalSignerService,
        useValue: {
          status: () => throwError(() => ({ status: 0 })),
          signJob: () => throwError(() => ({ status: 0 })),
          ...signer,
        } as unknown as LocalSignerService,
      },
    ],
  });
  const fixture = TestBed.createComponent(JobsList);
  fixture.detectChanges();
  return fixture;
}

/** Collapses whitespace, so an assertion can be written the way the page actually reads. */
function text(element: Element | null): string {
  return (element?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

/** Fills in the destructive form. */
function fill(fixture: ComponentFixture<JobsList>): PageInternals {
  const page = fixture.componentInstance as unknown as PageInternals;
  page.signHost.set('01JHOST00000000000000000000');
  page.signIntent.set('host.reboot');
  page.signParams.set('{"delaySeconds": 60}');
  page.signValidMinutes.set(30);
  return page;
}

describe('JobsList report form', () => {
  /**
   * The parameters typed into the report form reach the control plane as the object they describe,
   * and a field that is not JSON stops the request before it leaves.
   *
   * Every operation the form can queue today takes an empty object, so the field's value is nearly
   * always `{}` — but "nearly always" is how a parameter that mattered gets silently dropped: the
   * form used to send an empty object whatever was on screen. The parse is asserted from both sides
   * because a form that sent the text unparsed would fail every request the same way.
   */
  it('sends the parameters as an object, and refuses text that is not JSON', () => {
    const queued: Record<string, unknown>[] = [];
    const fixture = render(
      {},
      {
        createReadJob: (request: Record<string, unknown>) => {
          queued.push(request);
          return of({});
        },
      },
    );
    const page = fixture.componentInstance as unknown as PageInternals;
    page.chosenHost.set('01JHOST00000000000000000000');
    page.chosenIntent.set('services.list');

    page.readParams.set('{"unit": "nginx.service",}');
    page.createJob();
    fixture.detectChanges();
    expect(queued.length).toBe(0);
    expect(text(fixture.nativeElement)).toContain('not valid JSON');

    page.readParams.set('{"unit": "nginx.service"}');
    page.createJob();
    fixture.detectChanges();
    expect(queued).toEqual([
      {
        hostId: '01JHOST00000000000000000000',
        intent: 'services.list',
        params: { unit: 'nginx.service' },
      },
    ]);
  });
});

describe('JobsList destructive signing', () => {
  /**
   * The destructive tier is offered rather than only explained.
   *
   * What this page used to do was name the tier, say why there was no control for it, and leave the
   * operator to assemble a `hostseal sign` command and find curl. Nothing about the security model
   * changed to make a form possible — the signature still comes from a key on somebody's own machine
   * — so the form is what should always have been here.
   */
  it('offers the operations that need a signature, and says where the signature comes from', () => {
    const fixture = render({});
    const whole = text(fixture.nativeElement);

    expect(whole).toContain('Sign a destructive operation');
    expect(whole).toContain('trusted-signers');
    expect(whole).toContain('never leaves the token');
  });

  /**
   * The flow: host, operation and parameters go to the signer; what comes back goes to the control
   * plane unchanged.
   *
   * "Unchanged" is the assertion that matters. The signature covers the identifier, the host, the
   * intent, the parameters, the window and the nonce, so a page that rebuilt or tidied the document
   * would produce a job the control plane stores and every host refuses — a failure that is silent
   * here and loud, later, on somebody else's machine.
   */
  it('sends the operation to the local signer and forwards the signed job verbatim', () => {
    const asked: unknown[] = [];
    const posted: unknown[] = [];
    const document = signedJob();
    const fixture = render(
      {
        signJob: (request: unknown) => {
          asked.push(request);
          return of(document);
        },
      },
      {
        createSignedJob: (request: unknown) => {
          posted.push(request);
          return of({});
        },
      },
    );

    fill(fixture).signAndQueue();
    fixture.detectChanges();

    expect(asked).toEqual([
      {
        hostId: '01JHOST00000000000000000000',
        intent: 'host.reboot',
        params: { delaySeconds: 60 },
        validForSeconds: 1800,
      },
    ]);
    expect(posted).toEqual([document]);
  });

  /**
   * Parameters that are not JSON are a message under the field, not a request that travels to another
   * process to be refused. The signer would refuse it correctly; the operator would read "the local
   * signer returned 400" and go looking in the wrong place.
   */
  it('refuses parameters that are not JSON before anything is asked of the signer', () => {
    const asked: unknown[] = [];
    const fixture = render({
      signJob: (request: unknown) => {
        asked.push(request);
        return of(signedJob());
      },
    });

    const page = fill(fixture);
    page.signParams.set('{delaySeconds: 60');
    page.signAndQueue();
    fixture.detectChanges();

    expect(asked.length).toBe(0);
    expect(text(fixture.nativeElement)).toContain('not valid JSON');
  });

  /**
   * The terminal path, which is the answer for an operator with no signer running: the command for
   * what they filled in, and a box to paste the result back into. The command has to carry the
   * form's own values — a generic example would leave them assembling arguments, which is the thing
   * that made this page a dead end.
   */
  it('prints the sign command for what the form holds, and queues what is pasted back', () => {
    const posted: unknown[] = [];
    const fixture = render({}, { createSignedJob: (r: unknown) => (posted.push(r), of({})) });

    const page = fill(fixture);
    page.toggleTerminalPath();
    fixture.detectChanges();

    const command = page.signCommand();
    expect(command).toContain('hostseal sign');
    expect(command).toContain('--host 01JHOST00000000000000000000');
    expect(command).toContain('--intent host.reboot');
    expect(command).toContain('--valid-for 30m');
    expect(text(fixture.nativeElement)).toContain('hostseal sign');

    const document = signedJob();
    page.pastedJob.set(JSON.stringify(document));
    page.queuePasted();
    fixture.detectChanges();

    expect(posted).toEqual([document]);
  });

  /**
   * And a paste that is not a signed job at all. The page checks for the two fields that make the
   * document what it claims to be, because the alternative is a 400 from the control plane about a
   * request the operator believed they had copied whole.
   */
  it('says so when what was pasted is not a signed job', () => {
    const posted: unknown[] = [];
    const fixture = render({}, { createSignedJob: (r: unknown) => (posted.push(r), of({})) });

    const page = fill(fixture);
    page.toggleTerminalPath();
    page.pastedJob.set('{"hostId": "01JHOST00000000000000000000"}');
    page.queuePasted();
    fixture.detectChanges();

    expect(posted.length).toBe(0);
    expect(text(fixture.nativeElement)).toContain('no signature');
  });

  /**
   * The actionable half of "no signer": the command that starts one, with this page's own origin
   * already in it. A signer started with any other `--origin` refuses every request from here, and
   * that is the one part an operator cannot guess.
   */
  it('says what to run when no signer answers', () => {
    const fixture = render({ status: () => throwError(() => ({ status: 0 })) });

    (fixture.componentInstance as unknown as PageInternals).findSigner();
    fixture.detectChanges();

    const whole = text(fixture.nativeElement);
    expect(whole).toContain('hostseal signer');
    expect(whole).toContain(location.origin);
  });
});
