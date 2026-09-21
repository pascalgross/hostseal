import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSelectModule } from '@angular/material/select';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';

import { CatalogueEntry, Host, Job, SignedJob } from '../core/api.models';
import { ApiService } from '../core/api.service';
import { describeError } from '../core/errors';
import { formatAge } from '../core/format';
import {
  LOCAL_SIGNER_URL,
  LocalSignerService,
  LocalSignerStatus,
  describeSignerError,
} from '../core/local-signer.service';

/**
 * How long a signature stays valid when the form's own field is empty or half-typed.
 *
 * An hour, which is what `hostseal sign` and the signer both default to — stated here rather than left
 * to the signer's default so that the page never sends a number it did not mean. The window is the
 * blast radius of a signature: it is how long the job can still reach a host that was switched off.
 */
const DEFAULT_VALID_MINUTES = 60;

/**
 * The jobs page: what has been asked of the fleet, and what came back.
 *
 * Two forms, because there are two kinds of authorisation and conflating them would misrepresent both.
 * A read or routine job is authorised by the operator's own credential and the control plane's key, so
 * the first form queues one directly. A destructive job needs a signature from a key in the target
 * host's own `trusted-signers`, which this control plane does not hold and a browser must never hold
 * either — so the second form does not sign anything: it asks the HostSeal signer running on the
 * operator's own machine, which decodes the operation against its own catalogue, prints what it means
 * in its terminal, waits for a human there and a touch on a token, and hands back a signed job this
 * page forwards unchanged.
 *
 * For an operator without a signer running, the same form prints the `hostseal sign` command for what
 * they filled in and takes the signed document back by paste. That is the same act with two more steps,
 * and it is here because the alternative — a page that names a command and leaves the operator to
 * assemble the arguments and then find curl — is the one thing this page used to do and the reason it
 * read as a dead end.
 *
 * What the page does with a signed job either way is store it and release it, which is the half that
 * belongs in a control plane. Whether a job needs releasing at all, and whether the releaser has to be
 * somebody other than its creator, is a setting on the fleet — and it is read from the job rather than
 * from the fleet, because a job records the rule it was created under.
 */
@Component({
  selector: 'hostseal-jobs-list',
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressBarModule,
    MatSelectModule,
    MatTableModule,
    MatTooltipModule,
    RouterLink,
  ],
  templateUrl: './jobs-list.html',
  styleUrl: './jobs-list.scss',
})
export class JobsList {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /**
   * Talks to the signer on the operator's own machine.
   *
   * The one thing this page reaches that the control plane does not run, cannot reach, and must never
   * be able to impersonate — which is precisely why a signature from it means something here.
   */
  private readonly localSigner = inject(LocalSignerService);

  /** The columns rendered, in order. */
  protected readonly columns = ['intent', 'host', 'state', 'authorisation', 'created', 'actions'];

  /** The jobs, newest first. Null while the first load is in flight. */
  protected readonly jobs = signal<Job[] | null>(null);

  /**
   * Every job waiting to be released, whether or not it is on the page below.
   *
   * Fetched separately for the reason the separate endpoint exists: the list is bounded, and a
   * destructive job on a busy fleet leaves the newest page within a working day. An approver who can
   * only release what happens to still be on screen is not the approver docs/SECURITY.md §3 describes.
   */
  protected readonly awaiting = signal<Job[]>([]);

  /**
   * Whether the approval queue filled its bound, so its oldest entries may be missing.
   *
   * Its own flag rather than a share of `truncated`, because the two truncations mean opposite
   * things: a bounded history is routine, a bounded approval queue may be hiding exactly the jobs
   * that have waited longest from exactly the person who must see them. It is rendered inside the
   * card as a warning, not as a footnote — and the warning says "may", because the server reports
   * the bound being filled, which a queue of exactly the bound's size does without losing anything.
   */
  protected readonly awaitingTruncated = signal(false);

  /**
   * The last error from fetching the approval queue, rendered where the queue would have been.
   *
   * Its own signal rather than a share of `error`, and that is the fix for a real defect: the two
   * requests raced into one signal, the job list usually answered last, and its success handler wiped
   * the queue's failure — so the operator saw a full page of history, no card and no error, and
   * concluded there was nothing to release. A failure to load the queue must appear in the queue's
   * own place.
   */
  protected readonly awaitingError = signal('');

  /** Whether the list below was cut short, so there are older jobs it does not show. */
  protected readonly truncated = signal(false);

  /** Every enrolled host, for the form's host picker. */
  protected readonly hosts = signal<Host[]>([]);

  /** The catalogue, for the form's operation picker. */
  protected readonly intents = signal<CatalogueEntry[]>([]);

  /** The last error from fetching the job list, cleared when a later fetch succeeds. */
  private readonly jobsError = signal('');

  /** The last error from loading the hosts and the catalogue, which the form cannot offer without. */
  private readonly referenceError = signal('');

  /**
   * What the page-level error card shows.
   *
   * Composed from the fetches whose failure means the page is broken, each kept in its own signal so
   * that one request's success can only ever clear its own failure. The approval queue is deliberately
   * not in here — its error renders inside its own card, where the missing information would have
   * been.
   */
  protected readonly error = computed(() => this.referenceError() || this.jobsError());

  /** The last error from creating or approving, shown beside the form rather than replacing the page. */
  protected readonly actionError = signal('');

  /** The host selected in the form. */
  protected readonly chosenHost = signal('');

  /** The operation selected in the form. */
  protected readonly chosenIntent = signal('');

  /** Whether a create or approve request is in flight, so the buttons can be disabled. */
  protected readonly busy = signal(false);

  /**
   * The control plane's clock, taken from the last jobs response, for rendering ages.
   *
   * Never the browser's, for the rule `formatAge` states: ages on this page are decision inputs — the
   * approval card shows "asked 4h ago" to the second operator deciding whether to release — and a
   * laptop ten minutes slow would understate every one of them while showing every recent job as "0s
   * ago". The browser's clock is only the placeholder until the first response arrives.
   */
  protected readonly now = signal(new Date().toISOString());

  /**
   * The operations this page will queue without a signature.
   *
   * Everything the control plane can authorise on its own: read intents, which need no signature at
   * all, and the routine one, which the control plane signs with its own key. The destructive tier is
   * deliberately absent from this list and has a form of its own, because what it needs is not another
   * button here but a signature from a key this control plane does not hold.
   */
  protected readonly startableIntents = computed(() =>
    this.intents().filter(
      (entry) => entry.implemented && (entry.class === 'read' || entry.class === 'routine'),
    ),
  );

  /**
   * The operations that need a signature from the host's own trusted-signers.
   *
   * Offered rather than hidden, which is the change this form is: the page used to name the tier,
   * explain why it was not there, and leave an operator to assemble a command by hand. Naming the
   * operations is not the same as being able to authorise them — nothing here can sign, and the
   * signature still comes from a key on somebody's own machine.
   */
  protected readonly signableIntents = computed(() =>
    this.intents().filter((entry) => entry.implemented && entry.requiresOfflineSignature),
  );

  /** Where a HostSeal signer listens, for the message that tells an operator to start one. */
  protected readonly signerUrl = LOCAL_SIGNER_URL;

  /**
   * The address this page was served from, which is what a signer has to be told to sign for.
   *
   * Read once and held, so the instructions this page prints are the ones that will actually work: a
   * signer started with any other --origin refuses every request from here.
   */
  protected readonly origin = typeof location === 'undefined' ? '' : location.origin;

  /** The local signer that answered, null when none has been found in this session. */
  protected readonly signerStatus = signal<LocalSignerStatus | null>(null);

  /** Why the local signer could not be reached or would not sign, empty when it did. */
  protected readonly signerError = signal('');

  /** What the signer is doing: being looked for, or waiting for a human and a token. */
  protected readonly signerState = signal<'' | 'finding' | 'waiting'>('');

  /** The host the destructive form is about. */
  protected readonly signHost = signal('');

  /** The operation the destructive form is about. */
  protected readonly signIntent = signal('');

  /**
   * The parameters for that operation, as JSON.
   *
   * A JSON field rather than a generated form, because the catalogue tells this page which operations
   * exist and not what each one's parameters are — and a form built from a guess would be a form that
   * silently omits the field an operator needed. The signer decodes this against the real catalogue
   * and refuses what it cannot read, before anybody is asked to touch a token.
   */
  protected readonly signParams = signal('{}');

  /**
   * How long the signature stays valid, in minutes.
   *
   * It is on the form rather than fixed because the window is the blast radius of a signature: an
   * hour is right for "restart this now", and a change window that opens after the shop closes is a
   * legitimate reason to ask for longer. The signer has a ceiling of its own.
   */
  protected readonly signValidMinutes = signal(60);

  /** A signed job pasted in from a terminal, empty when none is. */
  protected readonly pastedJob = signal('');

  /** Why the pasted document could not be queued, empty when it was. */
  protected readonly pasteError = signal('');

  /** Whether the terminal path — the command to copy, the box to paste into — is on screen. */
  protected readonly showTerminalPath = signal(false);

  /**
   * The parameters for the report form, as JSON text.
   *
   * Every operation that form can queue today takes an empty object, and the control plane's decoders
   * refuse a field none of them knows. The field is here so that an operation which does take
   * parameters is queued the way everything else is, and so the object is typed rather than assumed;
   * the hint under it says the current truth so nobody types into it expecting otherwise.
   */
  protected readonly readParams = signal('{}');

  /** Whether the form has enough to submit. */
  protected readonly canCreateJob = computed(
    () => this.chosenHost().length > 0 && this.chosenIntent().length > 0 && !this.busy(),
  );

  /** Whether the destructive form has enough to ask for a signature. */
  protected readonly canSign = computed(
    () =>
      this.signHost().length > 0 &&
      this.signIntent().length > 0 &&
      this.signerState() === '' &&
      !this.busy(),
  );

  /**
   * The `hostseal sign` command for what the destructive form currently holds.
   *
   * It exists for the operator who has no signer running and for the one who would rather see the
   * command than trust a button — and, more usefully, for both to be able to check that the page and
   * the terminal are asking for the same thing. The key reference is left as a placeholder because it
   * is the one part of this that belongs to the person rather than to the job.
   *
   * The parameters are collapsed onto one line so the command survives being copied into a shell.
   */
  protected readonly signCommand = computed(() => {
    const params = this.signParams().replace(/\s+/g, ' ').trim() || '{}';
    return (
      `hostseal sign --key <your key> \\\n` +
      `  --host ${this.signHost() || '<host id>'} \\\n` +
      `  --intent ${this.signIntent() || '<operation>'} \\\n` +
      `  --params '${params}' \\\n` +
      `  --valid-for ${this.signValidMinutes()}m`
    );
  });

  /** Loads everything the page shows. */
  constructor() {
    this.reload();
    this.api.fleet().subscribe({
      next: (fleet) => this.hosts.set(fleet.hosts),
      error: (err: unknown) => this.referenceError.set(describeError(err)),
    });
    this.api.catalogue().subscribe({
      next: (catalogue) => this.intents.set(catalogue.intents),
      error: (err: unknown) => this.referenceError.set(describeError(err)),
    });
  }

  /**
   * Re-reads the job list.
   *
   * It is called after every create and approve rather than the response being spliced into the list,
   * because what the control plane holds is the answer and a locally patched row would eventually
   * disagree with it — most likely about a job somebody was watching.
   */
  protected reload(): void {
    this.api.jobs().subscribe({
      next: (response) => {
        this.jobs.set(response.jobs);
        this.truncated.set(response.truncated);
        this.now.set(response.serverTime);
        this.jobsError.set('');
      },
      error: (err: unknown) => this.jobsError.set(describeError(err)),
    });
    this.api.jobsAwaitingApproval().subscribe({
      next: (response) => {
        this.awaiting.set(response.jobs);
        this.awaitingTruncated.set(response.truncated);
        this.now.set(response.serverTime);
        this.awaitingError.set('');
      },
      error: (err: unknown) => this.awaitingError.set(describeError(err)),
    });
  }

  /** Queues the job the form describes. */
  protected createJob(): void {
    // Parsed here first, so that a stray comma is a message under the field rather than a request
    // the control plane refuses with a message about the wire format.
    let params: Record<string, unknown>;
    try {
      params = JSON.parse(this.readParams().trim() || '{}') as Record<string, unknown>;
    } catch {
      this.actionError.set('The parameters are not valid JSON. An empty object is {} .');
      return;
    }
    if (params === null || typeof params !== 'object' || Array.isArray(params)) {
      this.actionError.set('The parameters must be a JSON object. An empty one is {} .');
      return;
    }
    this.busy.set(true);
    this.actionError.set('');
    this.api
      .createReadJob({ hostId: this.chosenHost(), intent: this.chosenIntent(), params })
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.reload();
        },
        error: (err: unknown) => {
          this.busy.set(false);
          this.actionError.set(describeError(err));
        },
      });
  }

  /**
   * Looks for a signer on this machine, and remembers what it says.
   *
   * Asked for rather than probed on load, so that an operator who never signs from a browser does not
   * get a failed loopback request in their console every time this page opens.
   */
  protected findSigner(): void {
    this.signerError.set('');
    this.signerState.set('finding');
    this.localSigner.status().subscribe({
      next: (status) => {
        this.signerState.set('');
        this.signerStatus.set(status);
      },
      error: (err: unknown) => {
        this.signerState.set('');
        this.signerStatus.set(null);
        this.signerError.set(describeSignerError(err, this.origin));
        this.showTerminalPath.set(true);
      },
    });
  }

  /**
   * Asks the local signer for a signature over the destructive form, then queues what comes back.
   *
   * What crosses to the signer is the host, the operation and its parameters. What comes back is a
   * complete signed job — identifier, nonce and validity window included, all chosen there — which
   * this page forwards to the control plane unchanged. It is unchanged because it has to be: the
   * signature covers every one of those fields, so anything the browser rearranged on the way through
   * would stop verifying on the host, which is exactly the protection being relied on.
   *
   * The parameters are parsed here first so that a stray comma is a message under the field rather
   * than a request that travels to another process to be refused.
   */
  protected signAndQueue(): void {
    let params: Record<string, unknown>;
    try {
      params = JSON.parse(this.signParams().trim() || '{}') as Record<string, unknown>;
    } catch {
      this.signerError.set('The parameters are not valid JSON. An empty object is {} .');
      return;
    }

    // A cleared or half-typed field is a number this page should not send: it would arrive as zero,
    // which the signer reads as "use your default" — an hour, silently, where the operator was in the
    // middle of typing five. Falling back to the value the field shows when it is empty is the honest
    // reading of an empty field.
    const minutes = Number.isFinite(this.signValidMinutes()) ? Math.trunc(this.signValidMinutes()) : 0;

    this.signerError.set('');
    this.actionError.set('');
    this.signerState.set('waiting');
    this.localSigner
      .signJob({
        hostId: this.signHost(),
        intent: this.signIntent(),
        params,
        validForSeconds: minutes > 0 ? minutes * 60 : DEFAULT_VALID_MINUTES * 60,
      })
      .subscribe({
        next: (signed) => {
          this.signerState.set('');
          this.queueSigned(signed);
        },
        error: (err: unknown) => {
          this.signerState.set('');
          this.signerError.set(describeSignerError(err, this.origin));
          this.showTerminalPath.set(true);
        },
      });
  }

  /**
   * Queues a signed job that was produced in a terminal and pasted in.
   *
   * The document goes to the control plane as it arrived. Nothing here inspects or improves it: the
   * signature covers the whole of it, so a browser that corrected a field would produce a job every
   * host refuses — and a browser that could usefully correct one would be a browser holding authority
   * it must not have.
   */
  protected queuePasted(): void {
    let document: SignedJob;
    try {
      document = JSON.parse(this.pastedJob()) as SignedJob;
    } catch {
      this.pasteError.set(
        'That is not valid JSON. Paste the whole document `hostseal sign` printed, braces included.',
      );
      return;
    }
    if (!document?.signature || !document?.hostId) {
      this.pasteError.set(
        'That document carries no signature and a host id, so it is not what `hostseal sign` prints. ' +
          'Paste its output whole.',
      );
      return;
    }
    this.pasteError.set('');
    this.queueSigned(document);
  }

  /** Posts a signed job to the control plane and reloads the list. */
  private queueSigned(document: SignedJob): void {
    this.busy.set(true);
    this.api.createSignedJob(document).subscribe({
      next: () => {
        this.busy.set(false);
        this.pastedJob.set('');
        this.reload();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.actionError.set(describeError(err));
      },
    });
  }

  /**
   * Copies the `hostseal sign` command to the clipboard.
   *
   * Best-effort and never reported as a failure: the command is on screen and selectable, and a
   * browser refusing clipboard access must not look like something went wrong with the job.
   */
  protected async copySignCommand(): Promise<void> {
    if (!navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(this.signCommand());
    } catch {
      // Left on screen for a manual copy, which is the fallback that always works.
    }
  }

  /** Shows or hides the terminal path — the command to copy and the box to paste a signed job into. */
  protected toggleTerminalPath(): void {
    this.showTerminalPath.update((shown) => !shown);
  }

  /** Records this operator's release of a destructive job. */
  protected approve(job: Job): void {
    this.busy.set(true);
    this.actionError.set('');
    this.api.approveJob(job.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.reload();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.actionError.set(describeError(err));
      },
    });
  }

  /** Renders how long ago a job was created. */
  protected age(job: Job): string {
    return formatAge(job.createdAt, this.now());
  }

  /** Renders the hostname for a job, falling back to the identifier the host has not named itself with. */
  protected hostname(job: Job): string {
    return this.hosts().find((host) => host.id === job.hostId)?.hostname ?? job.hostId;
  }

  /**
   * Describes how a job was authorised, in the words that matter.
   *
   * "The client certificate alone" is not a euphemism for unauthorised: a read intent changes nothing
   * and reads nothing an unprivileged local user could not, so the certificate is the whole of what it
   * needs. Saying so beside a signed job is what makes the difference between the tiers visible.
   *
   * It is the catalogue's sentence word for word, because this column and the catalogue's carry the
   * same heading and answer the same question. This used to read "mTLS only", which is the same fact
   * in the transport's vocabulary rather than the reader's — and two spellings under one heading are
   * read as two different things by the person the wording is for.
   */
  protected authorisation(job: Job): string {
    if (!job.signed) {
      return 'the client certificate alone';
    }
    return `signed by ${job.signerKeyId ?? 'an unnamed key'}`;
  }

  /** Reports whether this job is waiting to be released. */
  protected awaitingApproval(job: Job): boolean {
    return job.state === 'awaiting_approval';
  }

  /**
   * Reports whether a job's outcome is one an operator should look at.
   *
   * A refusal is not a failure, and the two are coloured differently on purpose: an operator who is
   * shown red for every job local policy declined learns to ignore red, which is the wrong lesson to
   * take from the mechanism working exactly as designed.
   */
  protected failed(job: Job): boolean {
    return job.state === 'failed';
  }

  /** Reports whether a job was refused rather than attempted. */
  protected refused(job: Job): boolean {
    return job.state.startsWith('refused_') || job.state === 'unsupported_intent' || job.state === 'expired';
  }
}
