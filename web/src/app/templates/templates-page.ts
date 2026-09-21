import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTooltipModule } from '@angular/material/tooltip';

import {
  CreateTemplateRequest,
  RenderedTemplate,
  TemplateRevision,
  TemplateSummary,
  TemplateVersion,
} from '../core/api.models';
import { ApiService } from '../core/api.service';
import { describeError } from '../core/errors';
import {
  LOCAL_SIGNER_URL,
  LocalSignerService,
  LocalSignerStatus,
  describeSignerError,
} from '../core/local-signer.service';

/** The placeholder the control plane mints itself and refuses to accept from a caller. */
const TOKEN_PLACEHOLDER = 'enrollmentToken';

/**
 * The provisioning templates page: write one, version it, render it, paste it into a provisioner.
 *
 * Where the line sits is worth stating, because a page that stores and renders machine configuration
 * looks like it ought to grow a "push to host" button. It does not, ever. HostSeal is not in the
 * delivery path: a template is rendered here and handed to whatever creates the machine — Terraform,
 * a cloud console, a Proxmox form — and the control plane never reaches a host. Tier 3 is never
 * built, and this page deliberately offers no affordance implying otherwise.
 *
 * Signing is on this page and the key is not, which is the distinction worth keeping straight. The
 * signature that lets an enrolling host apply a template is made by `hostseal signer` on the
 * operator's own machine, against a body printed in that machine's terminal and confirmed by a human
 * there; what this page does is ask for one and store what comes back. Neither the browser nor the
 * control plane ever holds the key, and a control plane that served a malicious version of this
 * application still could not get a signature over a template whose text nobody read.
 *
 * Within that line a full editor is fine, and this is one: storing a template authorises nothing on
 * any machine. Two properties of the storage model surface directly in the UI. Every save is a new
 * version and nothing is ever edited in place, because a host's bootstrap record names a version and
 * has to resolve to the bytes that actually ran. And a secret in a body produces a warning and never
 * a refusal — user-data is readable from inside the instance and from the metadata service, so the
 * warning names that consequence, and blocking the save would only teach operators to route around
 * the one control that should be read.
 *
 * What the page has instead of a delete button is the third. Retiring a template archives the *name*:
 * it leaves the listing and is refused for new versions, renders, enrolment tokens and enrolments,
 * while every stored version stays readable — because the record on a host names a version, and a
 * record that resolves to nothing is no better than one that resolves to bytes somebody edited. The
 * page says so where an operator looks for the missing button, rather than leaving its absence to be
 * read as an oversight.
 */
@Component({
  selector: 'hostseal-templates-page',
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressBarModule,
    MatTooltipModule,
  ],
  templateUrl: './templates-page.html',
  styleUrl: './templates-page.scss',
})
export class TemplatesPage {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /**
   * Talks to the signer on the operator's own machine, which is the one thing on this page that the
   * control plane does not run and cannot reach.
   */
  private readonly localSigner = inject(LocalSignerService);

  /**
   * The placeholder syntax, as a field rather than as literal text in the template.
   *
   * Angular decodes HTML entities before it parses interpolation, so a doubled brace written any way
   * at all in the markup becomes an expression the compiler then fails to resolve. Naming the two
   * examples here is the standard way out, and it keeps the hint's wording beside the code that
   * implements it.
   */
  protected readonly placeholderSyntax = '{{name}}';

  /**
   * Where the worked cloud-init examples live.
   *
   * A field rather than a literal in the markup so the specification can assert it: this page is where
   * somebody writing their first template arrives, and the repository already carries an annotated
   * baseline they would otherwise never find. A link that silently broke would leave the page looking
   * complete while the examples went unread.
   *
   * It points at `main` rather than at the running version's tag. An installation on an older release
   * may see a newer example, which is the lesser of the two costs — the alternative is a link that is
   * dead for every build from an unreleased commit, and the examples are prose about cloud-init rather
   * than an interface that moves with the release.
   */
  protected readonly examplesUrl =
    'https://github.com/pascalgross/hostseal/tree/main/examples/cloud-init';

  /** The reserved placeholder the control plane mints and refuses to accept from a caller. */
  protected readonly tokenSyntax = `{{${TOKEN_PLACEHOLDER}}}`;

  /** One summary per template, null while the first load is in flight. */
  protected readonly templates = signal<TemplateSummary[] | null>(null);

  /**
   * Whether the listing includes templates that have been withdrawn from use.
   *
   * Off by default, because hiding a retired template from the page an operator reads every day is
   * what retiring it was for. On by request, because the alternative is a name nobody can see and
   * therefore nobody can restore — which would make archiving the deletion it deliberately is not.
   */
  protected readonly showArchived = signal(false);

  /** Why the page could not load, empty when it did. */
  protected readonly error = signal('');

  /** The version currently open, null when none is. */
  protected readonly opened = signal<TemplateVersion | null>(null);

  /**
   * The template this pane is currently about, empty when none is.
   *
   * It exists because opening a template is two requests — the version and its history — and nothing
   * else ties their answers together. Without a name to check them against, a response that arrives
   * for a template the operator has already navigated away from overwrites the one they are looking
   * at. Written before either request goes out, so both have something to be late for.
   */
  private readonly opening = signal('');

  /**
   * Every stored revision of the open template, newest first, empty when none is open.
   *
   * Held beside the open version rather than derived from it, because it answers a different
   * question: the version pane shows one revision's bytes, this shows that the others exist. Until
   * it did, "every save is a new version" was a property an operator had to take on faith — the
   * listing showed only the latest, and reaching an older one meant guessing a number.
   */
  protected readonly revisions = signal<TemplateRevision[]>([]);

  /** Why the last write or render failed, shown where the action was taken. */
  protected readonly actionError = signal('');

  /** Whether a write is in flight. */
  protected readonly busy = signal(false);

  /** Where a HostSeal signer listens, for the message that tells an operator to start one. */
  protected readonly signerUrl = LOCAL_SIGNER_URL;

  /**
   * The address this page was served from, which is what a signer has to be told to sign for.
   *
   * Read once and held, so the instructions this page prints are the ones that will actually work: a
   * signer started with any other --origin refuses every request from here, and the difference is
   * invisible in both places it is written down.
   */
  protected readonly origin = typeof location === 'undefined' ? '' : location.origin;

  /** The local signer that answered, null when none has been found in this session. */
  protected readonly signerStatus = signal<LocalSignerStatus | null>(null);

  /** Why the local signer could not be reached or would not sign, empty when it did. */
  protected readonly signerError = signal('');

  /**
   * Which of the two signing buttons the page is currently busy on behalf of.
   *
   * The page has one signer and two places to ask it from — the editor, and the version pane — and
   * what it has to say while waiting is several lines long. Rendering that under both would show the
   * same paragraph twice; rendering it under neither in particular would leave an operator looking
   * for the button they just pressed. Set when the interaction starts, so the progress bar and the
   * message that follows it land in the same place.
   */
  protected readonly signerWhere = signal<'' | 'editor' | 'version'>('');

  /**
   * What the signer is doing: looking for it, or waiting for a human and a token.
   *
   * It is a state rather than a boolean because the two mean different things to somebody watching:
   * "finding" is over in milliseconds, and "waiting" is a request that will sit there until they walk
   * to their machine, read a template and touch a key. A spinner with no sentence beside it would
   * look like a page that has hung.
   */
  protected readonly signerState = signal<'' | 'finding' | 'waiting'>('');

  /**
   * Whether the terminal path — the command to run, the file to run it on, the box to paste into —
   * is on screen under the Signature card.
   *
   * Off by default and opened by a button, or by a signer that could not be reached. The signer is
   * the shorter path and the one the card is written around; the terminal is the same signature with
   * two more steps, for the operator with no signer running or one who would rather see the command.
   */
  protected readonly showTerminalPath = signal(false);

  /** A signed template pasted in from a terminal, empty when none is. */
  protected readonly pastedTemplate = signal('');

  /** Why the pasted document could not be stored, empty when it was. */
  protected readonly pasteError = signal('');

  /**
   * Whether the archive confirmation is showing for the open template.
   *
   * Confirmed rather than done on one click, which is the opposite of how a wallboard share is
   * withdrawn here, and the difference is who finds out. Archiving is undone in one click and
   * destroys nothing — but the thing it breaks in the meantime is somebody else's enrolment, hours
   * later, on a machine that is being built. A sentence in the way is cheap against that.
   */
  protected readonly confirmingArchive = signal(false);

  /** The name typed in the editor. */
  protected readonly draftName = signal('');

  /** The body typed in the editor. */
  protected readonly draftBody = signal('');

  /** The values typed for the open template's placeholders. */
  protected readonly renderParams = signal<Record<string, string>>({});

  /** The fleet group hosts enrolled by a rendered token should join. */
  protected readonly renderGroup = signal('');

  /** The template a rendered token may request at enrolment, empty for none. */
  protected readonly renderBootstrap = signal('');

  /**
   * The last render, held only in this component and never stored.
   *
   * It is a credential: it usually carries a live enrolment token minted at render time. Nothing on
   * the server keeps it, it is not cacheable, and leaving this page loses it — which costs nothing,
   * because rendering again mints a fresh token.
   */
  protected readonly rendered = signal<RenderedTemplate | null>(null);

  /** The placeholders the open template expects an operator to fill in. */
  protected readonly askedPlaceholders = computed(() =>
    (this.opened()?.placeholders ?? []).filter((name) => name !== TOKEN_PLACEHOLDER),
  );

  /** Whether the open template mints an enrolment token, which changes what the render form asks. */
  protected readonly mintsToken = computed(() =>
    (this.opened()?.placeholders ?? []).includes(TOKEN_PLACEHOLDER),
  );

  /** Whether the editor has enough to save. */
  protected readonly canSave = computed(
    () => !this.busy() && this.draftName().trim().length > 0 && this.draftBody().trim().length > 0,
  );

  /** Whether anything at all may be asked of the signer right now. */
  protected readonly canSign = computed(() => this.signerState() === '' && !this.busy());

  /**
   * The file name the open version's body is offered under, for `hostseal sign-template --body`.
   *
   * The name and the version are in it so that the file on an operator's disk says which bytes it
   * holds: the command below signs whatever file it is pointed at, and two templates saved as
   * `body.yaml` are how the wrong one gets signed.
   */
  protected readonly bodyFileName = computed(() => {
    const record = this.opened();
    return record ? `${record.name}-v${record.version}.yaml` : '';
  });

  /**
   * The `hostseal sign-template` command for the open version.
   *
   * The same act the Sign button performs, written out: the same canonical {name, body} document is
   * signed, by the same kind of key, and the control plane stores the same triple. It exists for the
   * operator with no signer running, for the one who would rather see the command than trust a button,
   * and for both to be able to check that the page and the terminal are asking for the same thing.
   * The key reference is left as a placeholder because it is the one part that belongs to the person
   * rather than to the template.
   */
  protected readonly signTemplateCommand = computed(() => {
    const record = this.opened();
    if (!record) {
      return '';
    }
    return (
      `hostseal sign-template --key <your key> \\\n` +
      `  --name ${record.name} \\\n` +
      `  --body ${this.bodyFileName()}`
    );
  });

  /** Loads the template list. */
  constructor() {
    this.reload();
  }

  /** Shows or hides the templates that have been withdrawn from use, and re-reads the list. */
  protected toggleArchived(): void {
    this.showArchived.update((shown) => !shown);
    this.reload();
  }

  /**
   * Re-reads the template list.
   *
   * The mode the request went out with is checked again when it comes back, for the reason the open
   * pane checks the template name: the toggle sends a second listing while the first is still in
   * flight — including the one the constructor started — and nothing else ties an answer to the
   * question it answers. Landing out of order would leave the button reading "Hide archived" over a
   * list with the archived ones missing, which reads as the toggle being broken rather than as a
   * response arriving late. A stale answer is dropped rather than shown: the matching one is always
   * still on its way.
   */
  protected reload(): void {
    const wanted = this.showArchived();
    this.api.templates(wanted).subscribe({
      next: (response) => {
        if (this.showArchived() !== wanted) {
          return;
        }
        this.templates.set(response.templates);
        this.error.set('');
      },
      error: (err: unknown) => {
        if (this.showArchived() === wanted) {
          this.error.set(describeError(err));
        }
      },
    });
  }

  /**
   * Opens one version, defaulting to the latest.
   *
   * The whole render form is dropped as the page moves, the previous render included: a credential
   * belonging to one template must not still be on screen while another is open, where somebody
   * would eventually copy the wrong one.
   */
  protected open(name: string, version?: number): void {
    this.clearRenderForm();
    this.actionError.set('');
    this.confirmingArchive.set(false);
    this.opened.set(null);
    this.revisions.set([]);
    this.opening.set(name);

    this.api.template(name, version).subscribe({
      next: (record) => {
        if (this.opening() === record.name) {
          this.opened.set(record);
        }
      },
      error: (err: unknown) => {
        if (this.opening() === name) {
          this.actionError.set(describeError(err));
        }
      },
    });
    this.loadRevisions(name);
  }

  /**
   * Re-reads one template's revision history, discarding an answer about a different template.
   *
   * The discard is not defensive coding, it is the correctness of the pane. This is a second request
   * racing the one that fetches the body, and the two can disagree in both directions: reading a
   * version decrypts a sealed body and can answer 500 where this listing, which decrypts nothing,
   * answers 200; and two clicks in flight can land in either order. Either way the markup would then
   * compare one template's revision numbers against another template's open version — marking the
   * wrong row "open" and offering buttons that pair this name with that one's versions. The response
   * names the template it is about, so it can be checked rather than assumed.
   *
   * Its failure stays silent, and deliberately so: the history is context beside the version, not the
   * thing the operator asked for, and an error banner over an empty list would report a page as
   * broken when the version it exists to show is on screen and correct. What a failure costs is the
   * list of older revisions, which the operator can get back by opening the template again.
   */
  private loadRevisions(name: string): void {
    this.api.templateVersions(name).subscribe({
      next: (response) => {
        if (this.opening() === response.name) {
          this.revisions.set(response.versions);
        }
      },
      error: () => {
        if (this.opening() === name) {
          this.revisions.set([]);
        }
      },
    });
  }

  /** Closes the open version, dropping the render form and any render with it. */
  protected close(): void {
    this.opening.set('');
    this.opened.set(null);
    this.revisions.set([]);
    this.clearRenderForm();
    this.actionError.set('');
    this.confirmingArchive.set(false);
  }

  /** Opens or closes the archive confirmation, clearing whatever the last attempt said. */
  protected toggleArchiveConfirmation(): void {
    this.actionError.set('');
    this.confirmingArchive.update((open) => !open);
  }

  /**
   * Withdraws the open template's name from use.
   *
   * This is the delete button this page does not have and is never going to have. A version is what a
   * host's bootstrap record names — "web-07 was bootstrapped with standard-server v3" — and a record
   * that resolves to nothing is no better than one that resolves to bytes somebody edited afterwards.
   * So nothing is destroyed here: what an operator retiring a template wants is that nobody uses it
   * again, and that is exactly what this does. The name leaves the listing, and new versions,
   * renders, enrolment tokens naming it and enrolments are all refused until it is restored.
   *
   * The open version stays open afterwards, deliberately. An archived template is still readable —
   * that is the whole point — and closing the pane would suggest something had gone away.
   */
  protected archive(): void {
    const record = this.opened();
    if (!record || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.actionError.set('');
    this.api.archiveTemplate(record.name).subscribe({
      next: () => {
        this.busy.set(false);
        this.confirmingArchive.set(false);
        this.reload();
        this.open(record.name, record.version);
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.actionError.set(describeError(err));
      },
    });
  }

  /**
   * Puts the open template's name back into use.
   *
   * No confirmation, and not for symmetry with the archive above: restoring grants nothing the name
   * did not already have. A restored template is issued at enrolment only on the conditions that
   * governed it before — a signature this control plane cannot produce, and a token minted naming it
   * — so undoing an archival is never the step that lets something reach a host.
   */
  protected restore(): void {
    const record = this.opened();
    if (!record || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.actionError.set('');
    this.api.restoreTemplate(record.name).subscribe({
      next: () => {
        this.busy.set(false);
        this.reload();
        this.open(record.name, record.version);
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.actionError.set(describeError(err));
      },
    });
  }

  /**
   * Renders when a template was withdrawn, in UTC, to the minute.
   *
   * The same format `stored` uses, and for the same reason: this response carries no server time, and
   * what a reader asks of it is which side of a change window it falls on.
   */
  protected withdrawn(at: string | undefined): string {
    if (!at) {
      return '—';
    }
    const when = new Date(at);
    if (Number.isNaN(when.getTime())) {
      return '—';
    }
    return `${when.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  }

  /**
   * Drops everything the render form holds: placeholder values, fleet group, bootstrap template and
   * the last render.
   *
   * One method because those four have to move together, and the bootstrap field is why. A render
   * mints a live enrolment token, and `bootstrap` decides which template that token may request when
   * a host enrols with it — so a name typed while template A was open and left in place would arm
   * template B's freshly minted token with A's bootstrap, with nothing on screen having asked. The
   * group has the same shape of consequence one step down: it decides which fleet group the host
   * joins. Carrying either across a template switch is a setting the operator did not make.
   */
  private clearRenderForm(): void {
    this.renderParams.set({});
    this.renderGroup.set('');
    this.renderBootstrap.set('');
    this.rendered.set(null);
  }

  /**
   * Renders when a revision was stored, in UTC, to the minute.
   *
   * A timestamp rather than an age, which is the opposite of what every other page here does, and for
   * the reason those pages give: `formatAge` insists on the control plane's clock because an age is a
   * decision input and a wrong laptop clock silently corrupts it. This response carries no server
   * time — and a version history does not need one. What an operator asks of this column is "which of
   * these is the one from the change window on Tuesday", and a UTC stamp answers that without
   * consulting any clock at all.
   */
  protected stored(revision: TemplateRevision): string {
    const at = new Date(revision.createdAt);
    if (Number.isNaN(at.getTime())) {
      return '—';
    }
    return `${at.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  }

  /**
   * Renders who signed a version and with what.
   *
   * Both halves, because both are what a host checks: a `trusted-signers` line carries an algorithm
   * beside the key id, and a version signed by the right person under the other algorithm is refused
   * at enrolment. A key id with no algorithm beside it leaves an operator comparing half a line
   * against a machine they cannot see.
   *
   * A method rather than braces in the markup, because the alternative was an inline conditional
   * inside a sentence, which reads as punctuation until somebody looks closely.
   */
  protected signedBy(record: TemplateSummary | TemplateVersion | TemplateRevision): string {
    const key = record.signerKeyId || 'an unnamed key';
    return record.signerAlgorithm ? `${key} (${record.signerAlgorithm})` : key;
  }

  /** Loads the open template's body into the editor, as the starting point for its next version. */
  protected editOpen(): void {
    const record = this.opened();
    if (!record) {
      return;
    }
    this.draftName.set(record.name);
    this.draftBody.set(record.body);
  }

  /**
   * Stores the editor's contents as the next version, unsigned.
   *
   * Unsigned is a complete answer for most of what this page is for: a template that will be rendered
   * and pasted into a provisioner needs no signature at all. Only a bootstrap handed to an enrolling
   * agent does, because the agent verifies it against its own trusted-signers — and that signature is
   * made by a key on the operator's own machine, never here. "Sign and save" beside this button is
   * that, done in one step; the key still never reaches the browser or the control plane.
   */
  protected save(): void {
    this.store({ name: this.draftName().trim(), body: this.draftBody() });
  }

  /**
   * Stores one version, signed or not, and opens what was stored.
   *
   * One method for both paths so that an unsigned save and a signed one cannot drift apart in what
   * they do afterwards — the re-read below is the part that matters, and it is exactly as necessary
   * for a signed version as for an unsigned one.
   */
  private store(request: CreateTemplateRequest): void {
    this.busy.set(true);
    this.actionError.set('');
    this.api.createTemplate(request).subscribe({
      next: (stored) => {
        this.busy.set(false);
        this.pastedTemplate.set('');
        this.reload();
        // Re-read rather than opening the create response. That response confirms what was stored
        // and does not echo the body, so trusting it would leave the pane blank and the editor
        // holding nothing to start the next version from. Re-reading is also the only way to be
        // looking at what the control plane holds rather than at what this page sent.
        this.open(stored.name, stored.version);
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
   * Asked for rather than probed on load: a page that reached a loopback port unprompted would put a
   * failed request in the console of every operator who does not sign from a browser, which is how
   * people learn to ignore console errors. It is also the step that answers the question an operator
   * has before they sign anything — which key is about to be used, and what line a host needs in its
   * own trusted-signers for that key to mean anything.
   */
  protected findSigner(): void {
    this.signerError.set('');
    this.signerWhere.set('version');
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
        // The terminal is the answer to a signer that is not there, so it opens without being asked.
        this.showTerminalPath.set(true);
      },
    });
  }

  /** Signs the open version's bytes, storing the result as the template's next version. */
  protected signOpen(): void {
    const record = this.opened();
    if (!record) {
      return;
    }
    this.signAndStore(record.name, record.body, 'version');
  }

  /** Signs what is in the editor, storing it as the next version in one step. */
  protected signDraft(): void {
    this.signAndStore(this.draftName().trim(), this.draftBody(), 'editor');
  }

  /**
   * Asks the local signer for a signature over a template, then stores it as a new version.
   *
   * The name and the body go to the signer and come back with a signature over the two of them
   * together — the same canonical {name, body} document `hostseal sign-template` signs and an
   * enrolling agent verifies. Signing the body alone would let a compromised control plane hand a host
   * a genuinely signed template under a name the operator never asked for, which is why the signature
   * covers both and why this page sends both.
   *
   * The echoed name is checked before anything is stored. It costs a comparison and it closes the one
   * gap this page could otherwise have: a signature is only about the template it was made for, and
   * storing one against another name would produce a version that looks signed here and is refused by
   * every host, for a reason nothing on this page could explain.
   *
   * Nothing is stored when the signer refuses. A declined confirmation is an operator saying no at the
   * machine holding the key, and the right response to that is to leave the control plane exactly as
   * it was.
   */
  private signAndStore(name: string, body: string, where: 'editor' | 'version'): void {
    if (!name || !body) {
      return;
    }
    this.signerError.set('');
    this.signerWhere.set(where);
    this.actionError.set('');
    this.signerState.set('waiting');

    this.localSigner.signTemplate(name, body).subscribe({
      next: (signed) => {
        this.signerState.set('');
        if (signed.name !== name) {
          this.signerError.set(
            `The signer returned a signature for "${signed.name}" and this page asked about ` +
              `"${name}". Nothing was stored: a signature is only about the template it was made for.`,
          );
          return;
        }
        this.store({
          name,
          body,
          signature: signed.signature,
          signerKeyId: signed.signerKeyId,
          signerAlgorithm: signed.signerAlgorithm,
        });
      },
      error: (err: unknown) => {
        this.signerState.set('');
        this.signerError.set(describeSignerError(err, this.origin));
        if (where === 'version') {
          this.showTerminalPath.set(true);
        }
      },
    });
  }

  /** Shows or hides the terminal path under the Signature card. */
  protected toggleTerminalPath(): void {
    this.showTerminalPath.update((shown) => !shown);
  }

  /**
   * Copies the `hostseal sign-template` command to the clipboard.
   *
   * Best-effort and never reported as a failure: the command is on screen and selectable, and a
   * browser refusing clipboard access must not look like something went wrong with the template.
   */
  protected async copySignTemplateCommand(): Promise<void> {
    if (!navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(this.signTemplateCommand());
    } catch {
      // Left on screen for a manual copy, which is the fallback that always works.
    }
  }

  /**
   * Hands the open version's body to the browser as a file, for `--body`.
   *
   * A download rather than a copy, because the signature covers the exact bytes and a body that went
   * through a clipboard, an editor and a save dialog is a body with a trailing newline or a tab
   * somewhere it was not — signed correctly, stored as a new version, and refused by no host, but not
   * the version the operator thought they were signing. A file written by the browser holds what the
   * control plane holds.
   *
   * The object URL is revoked once the click has been dispatched: the blob lives as long as the page
   * otherwise, and a template is small but an operator signs more than one.
   */
  protected downloadBody(): void {
    const record = this.opened();
    if (!record) {
      return;
    }
    const url = URL.createObjectURL(new Blob([record.body], { type: 'text/plain;charset=utf-8' }));
    try {
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = this.bodyFileName();
      anchor.click();
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  /**
   * Stores a signed template that was produced in a terminal and pasted in.
   *
   * The document goes to the control plane as it arrived, which is what `hostseal sign-template`
   * itself tells the operator to do with it. Nothing here inspects or improves the body: the
   * signature covers the name and the body together, so a page that corrected either would produce
   * a version that reads as signed here and is refused by every host.
   *
   * The name is checked against the open template, and it is the only thing checked. A signature is
   * only about the template it was made for, and storing one against another name is the one
   * mistake this page can make that no host could explain — the same check the signer path makes on
   * the name the signer echoes back. The body is not compared: the operator read it in full in the
   * terminal before confirming, and what they signed is what is stored, as the next version.
   */
  protected storePasted(): void {
    const record = this.opened();
    if (!record) {
      return;
    }
    let document: CreateTemplateRequest;
    try {
      document = JSON.parse(this.pastedTemplate()) as CreateTemplateRequest;
    } catch {
      this.pasteError.set(
        'That is not valid JSON. Paste the whole document `hostseal sign-template` printed, braces ' +
          'included.',
      );
      return;
    }
    if (!document?.signature || !document?.signerKeyId || !document?.signerAlgorithm) {
      this.pasteError.set(
        'That document carries no signature, so it is not what `hostseal sign-template` prints. ' +
          'Paste its output whole.',
      );
      return;
    }
    if (document.name !== record.name) {
      this.pasteError.set(
        `That document signs "${document.name}" and this card is about "${record.name}". Nothing ` +
          'was stored: a signature is only about the template it was made for.',
      );
      return;
    }
    if (typeof document.body !== 'string' || document.body.length === 0) {
      this.pasteError.set('That document carries no body. Paste the whole of what was printed.');
      return;
    }
    this.pasteError.set('');
    this.store({
      name: document.name,
      body: document.body,
      signature: document.signature,
      signerKeyId: document.signerKeyId,
      signerAlgorithm: document.signerAlgorithm,
    });
  }

  /** Records one placeholder's value. */
  protected setParam(name: string, value: string): void {
    this.renderParams.update((held) => ({ ...held, [name]: value }));
  }

  /** Reads one placeholder's value. */
  protected param(name: string): string {
    return this.renderParams()[name] ?? '';
  }

  /** Renders the open version to user-data. */
  protected render(): void {
    const record = this.opened();
    if (!record) {
      return;
    }
    this.busy.set(true);
    this.actionError.set('');
    this.api
      .renderTemplate(record.name, {
        version: record.version,
        params: this.renderParams(),
        token: this.mintsToken()
          ? { group: this.renderGroup(), bootstrap: this.renderBootstrap() }
          : undefined,
      })
      .subscribe({
        next: (result) => {
          this.busy.set(false);
          this.rendered.set(result);
        },
        error: (err: unknown) => {
          this.busy.set(false);
          this.actionError.set(describeError(err));
        },
      });
  }

  /**
   * Copies the rendered user-data to the clipboard.
   *
   * Best-effort and never reported as a failure that matters: the text is on screen and selectable,
   * and a browser refusing clipboard access — which several do without a user gesture they recognise
   * — must not look like the render itself went wrong.
   */
  protected async copyRendered(): Promise<void> {
    const result = this.rendered();
    if (!result || !navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(result.userData);
    } catch {
      // Left on screen for a manual copy, which is the fallback that always works.
    }
  }
}
