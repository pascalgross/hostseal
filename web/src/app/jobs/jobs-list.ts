import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSelectModule } from '@angular/material/select';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';

import { CatalogueEntry, Host, Job } from '../core/api.models';
import { ApiService } from '../core/api.service';
import { describeError } from '../core/errors';
import { formatAge } from '../core/format';

/**
 * The jobs page: what has been asked of the fleet, and what came back.
 *
 * Only read-only work can be started from here, and that is not a limitation of the page. A destructive
 * job carries a signature made offline by a key the control plane does not hold, and a browser is the
 * last place that key should ever be — so the form offers what a browser can legitimately authorise and
 * says plainly why the rest is not there, rather than presenting a control that cannot work.
 *
 * What the page *can* do for a destructive job is release one, which is the half that belongs in a
 * control plane. Whether a job needs releasing at all, and whether the releaser has to be somebody
 * other than its creator, is a setting on the fleet — and it is read from the job rather than from the
 * fleet, because a job records the rule it was created under.
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
   * The operations this page will offer to start.
   *
   * Everything the control plane can authorise on its own: read intents, which need no signature at
   * all, and the routine one, which the control plane signs with its own key. What is missing is the
   * destructive tier, and that is permanent rather than pending — it needs a signature made by a key
   * listed in the host's own trusted-signers, which this control plane does not hold and a browser is
   * the last place it should ever be. Sign one with `hostseal sign` and post it.
   */
  protected readonly startableIntents = computed(() =>
    this.intents().filter(
      (entry) => entry.implemented && (entry.class === 'read' || entry.class === 'routine'),
    ),
  );

  /** Whether the form has enough to submit. */
  protected readonly canCreateJob = computed(
    () => this.chosenHost().length > 0 && this.chosenIntent().length > 0 && !this.busy(),
  );

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
    this.busy.set(true);
    this.actionError.set('');
    this.api
      .createReadJob({ hostId: this.chosenHost(), intent: this.chosenIntent(), params: {} })
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
