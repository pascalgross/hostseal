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
  RenderedTemplate,
  TemplateRevision,
  TemplateSummary,
  TemplateVersion,
} from '../core/api.models';
import { ApiService } from '../core/api.service';
import { describeError } from '../core/errors';

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

  /** Loads the template list. */
  constructor() {
    this.reload();
  }

  /** Shows or hides the templates that have been withdrawn from use, and re-reads the list. */
  protected toggleArchived(): void {
    this.showArchived.update((shown) => !shown);
    this.reload();
  }

  /** Re-reads the template list. */
  protected reload(): void {
    this.api.templates(this.showArchived()).subscribe({
      next: (response) => {
        this.templates.set(response.templates);
        this.error.set('');
      },
      error: (err: unknown) => this.error.set(describeError(err)),
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
   * Stores the editor's contents as the next version.
   *
   * Unsigned: a signature is made offline by `hostseal sign-template`, with a key this control plane
   * does not hold, and a browser is the last place that key should ever be. An unsigned template can
   * be rendered and pasted into a provisioner, which is what this page is for; only a signed one may
   * be handed to an enrolling agent, because the agent verifies it against its own trusted-signers.
   */
  protected save(): void {
    this.busy.set(true);
    this.actionError.set('');
    this.api
      .createTemplate({ name: this.draftName().trim(), body: this.draftBody() })
      .subscribe({
        next: (stored) => {
          this.busy.set(false);
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
