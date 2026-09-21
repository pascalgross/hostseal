import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';

import { FleetResponse, Host } from '../core/api.models';
import { EnrolPanel } from './enrol-panel';
import { ApiService } from '../core/api.service';
import { describeError } from '../core/errors';
import { formatAge, formatDuration, formatOffset } from '../core/format';

/** What the fleet request can be doing, so the template can render each state distinctly. */
type LoadState = 'loading' | 'loaded' | 'failed';

/**
 * How often the list is re-read before the control plane has said how often hosts report.
 *
 * Only the first interval, since every answer carries the heartbeat pacing and the cadence follows it
 * from then on. Half a minute is short enough that a host enrolled while the page is open appears
 * before anybody reaches for the reload key, and long enough that a tab left open on a small fleet is
 * not a noticeable share of the control plane's requests.
 */
const DEFAULT_REFRESH_SECONDS = 30;

/**
 * The shortest interval the list will re-read at, whatever the fleet's heartbeat.
 *
 * A fleet paced at five seconds does not need a list that polls at five seconds: nobody reads a table
 * that fast, and every open tab would be a client the control plane serves as often as its hosts.
 */
const MINIMUM_REFRESH_SECONDS = 15;

/**
 * The longest interval the list will re-read at, whatever the fleet's heartbeat.
 *
 * The heartbeat bounds how fast a *host's* row can change, and nothing else: an enrolment, a
 * revocation or a job result changes the list whenever it happens. A fleet paced at ten minutes would
 * otherwise show a host enrolled a moment ago ten minutes from now.
 */
const MAXIMUM_REFRESH_SECONDS = 60;

/**
 * The fleet list: every enrolled host and the four things an operator checks first.
 *
 * Those four are chosen deliberately. Whether the host is reachable, how many security updates it is
 * behind, whether it needs a reboot, and whether anything is wrong with its clock or its policy — that
 * last group being the one most dashboards omit, because it is the one that only matters when something
 * has already gone wrong.
 *
 * Everything a cell can say is derived from what the host reported. Nothing here infers state the agent
 * did not send: a column that guessed would eventually guess wrong about the host somebody was looking
 * at during an incident.
 */
@Component({
  selector: 'hostseal-fleet-list',
  imports: [
    EnrolPanel,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatIconModule,
    MatProgressBarModule,
    MatTableModule,
    MatTooltipModule,
    RouterLink,
  ],
  templateUrl: './fleet-list.html',
  styleUrl: './fleet-list.scss',
})
export class FleetList {
  /** Talks to the control plane. */
  private readonly api = inject(ApiService);

  /** Stops the refresh and the visibility listener when the page is left. */
  private readonly destroyRef = inject(DestroyRef);

  /** The pending re-read, null when none is booked. */
  private timer: ReturnType<typeof setTimeout> | null = null;

  /** The columns rendered, in order. */
  protected readonly columns = [
    'hostname',
    'status',
    'distribution',
    'updates',
    'reboot',
    'policy',
    'lastSeen',
  ];

  /** Why the first load failed, empty when it did not. Only the first: see `refreshError`. */
  protected readonly error = signal('');

  /**
   * Why the most recent re-read failed, empty when it succeeded.
   *
   * Kept apart from `error` because the two failures mean different things on screen. A first load
   * that fails leaves nothing to show, so the page says so in place of the list. A re-read that fails
   * leaves the last good list, which is still the best answer available — replacing a table of hosts
   * with an error card every time a proxy hiccups would make the page unusable exactly when somebody
   * is watching it. So the list stays, dated, with the failure said beside it.
   */
  protected readonly refreshError = signal('');

  /**
   * The fleet, or null until the first answer.
   *
   * A signal written by the read loop rather than a conversion of one request, because the request is
   * repeated: the list re-reads itself for as long as the page is open, at the pace the control plane
   * says hosts report, so that a host enrolled, a job finished or a reboot completed shows up without
   * anybody pressing reload. Before this, the fleet page was a snapshot of whenever it was opened,
   * which on a page people leave open is a snapshot of the wrong moment.
   */
  protected readonly fleet = signal<FleetResponse | null>(null);

  /** When the list was last read successfully, by the browser's clock, zero for never. */
  protected readonly refreshedAt = signal(0);

  /** Whether a re-read is in flight, so the header can say so without the table going anywhere. */
  protected readonly refreshing = signal(false);

  /** Which of the three states the page is in. */
  protected readonly state = computed<LoadState>(() => {
    if (this.fleet() !== null) {
      return 'loaded';
    }
    return this.error() ? 'failed' : 'loading';
  });

  /** The time of the last successful read, for the header. */
  protected readonly refreshedClock = computed(() => {
    const at = this.refreshedAt();
    return at === 0 ? '' : new Date(at).toLocaleTimeString();
  });

  /**
   * How long to wait before the next read, in seconds.
   *
   * Paced by the fleet's heartbeat because that is how fast a row can change on its own, bounded on
   * both sides for the reasons the two bounds give. Computed from the last answer rather than fixed,
   * so a fleet whose pacing is changed on the control plane changes the page's without a release.
   */
  protected readonly refreshSeconds = computed(() => {
    const heartbeat = this.fleet()?.heartbeatSeconds;
    if (!heartbeat || heartbeat <= 0) {
      return DEFAULT_REFRESH_SECONDS;
    }
    return Math.min(MAXIMUM_REFRESH_SECONDS, Math.max(MINIMUM_REFRESH_SECONDS, heartbeat));
  });

  /**
   * Starts the read loop, and ties it to whether the page can be seen.
   *
   * A tab in the background is re-read by nobody, so the loop stops while the document is hidden and
   * reads at once when it is shown again — which is also the moment somebody switching back to the
   * tab most wants a current list rather than one from before they left. The listener is removed
   * with the component, for the same reason the timer is: a page that was left must cost the
   * control plane nothing.
   */
  constructor() {
    this.read();
    const onVisibility = (): void => {
      if (this.pageHidden()) {
        this.stop();
      } else {
        this.read();
      }
    };
    document.addEventListener('visibilitychange', onVisibility);
    this.destroyRef.onDestroy(() => {
      document.removeEventListener('visibilitychange', onVisibility);
      this.stop();
    });
  }

  /**
   * Whether the document is hidden, read through a method so a spec can say it is.
   *
   * `document.hidden` is a browser global the loop has to consult, and a spec that could not set it
   * could not prove the loop stops for a hidden tab — which is the half of the behaviour that costs
   * the control plane something if it is wrong.
   */
  protected pageHidden(): boolean {
    return document.hidden;
  }

  /**
   * Reads the fleet once, now, and books the next read afterwards.
   *
   * Also the manual refresh: an operator who has just run a command on a host does not want to wait
   * out the interval to see the result. Any pending read is cancelled first so a manual read and a
   * scheduled one cannot leave two loops running.
   *
   * The request is cancelled with the component rather than merely ignored, because a read still in
   * flight when the page is left would otherwise land on a dead component and book the next one —
   * a timer nothing can reach, reading the fleet for the life of the tab.
   */
  protected read(): void {
    this.stop();
    this.refreshing.set(true);
    this.api
      .fleet()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (fleet) => {
          this.fleet.set(fleet);
          this.error.set('');
          this.refreshError.set('');
          this.refreshedAt.set(Date.now());
          this.refreshing.set(false);
          this.schedule();
        },
        error: (err: unknown) => {
          const message = describeError(err);
          if (this.fleet() === null) {
            this.error.set(message);
          } else {
            this.refreshError.set(message);
          }
          this.refreshing.set(false);
          this.schedule();
        },
      });
  }

  /** Books the next read, unless the page cannot be seen. */
  private schedule(): void {
    this.stop();
    if (this.pageHidden()) {
      return;
    }
    this.timer = setTimeout(() => this.read(), this.refreshSeconds() * 1000);
  }

  /** Cancels the pending read, which is how "stop refreshing" is actually spelled. */
  private stop(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  /** The hosts, or an empty list while loading. */
  protected readonly hosts = computed<Host[]>(() => this.fleet()?.hosts ?? []);

  /** The control plane's clock, used so ages do not depend on the browser's. */
  protected readonly serverTime = computed(() => this.fleet()?.serverTime ?? new Date().toISOString());

  /** How many hosts are currently reachable, for the summary line. */
  protected readonly onlineCount = computed(() => this.hosts().filter((h) => h.online).length);

  /** How many security updates are outstanding across the fleet. */
  protected readonly securityBacklog = computed(() =>
    this.hosts().reduce((total, h) => total + (h.facts?.packages?.upgradableSecurity ?? 0), 0),
  );

  /** How many hosts are waiting on a reboot. */
  protected readonly rebootCount = computed(
    () => this.hosts().filter((h) => h.facts?.reboot?.required).length,
  );

  /** Renders how long ago a host was last heard from, against the control plane's clock. */
  protected age(host: Host): string {
    return formatAge(host.lastSeen, this.serverTime());
  }

  /** Renders a host's uptime. */
  protected uptime(host: Host): string {
    return formatDuration(host.uptimeSeconds);
  }

  /** Renders a host's clock offset with its sign. */
  protected offset(host: Host): string {
    return formatOffset(host.clockOffsetSeconds);
  }

  /**
   * Describes a host's release, or says the facts have not arrived yet.
   *
   * "Not reported yet" is shown rather than a blank cell, because a blank cell in a fleet list reads as
   * "nothing to say" and this means "the host has not told us".
   */
  protected release(host: Host): string {
    const dist = host.facts?.distribution;
    if (!dist) {
      return 'not reported yet';
    }
    return dist.prettyName || `${dist.id} ${dist.version} (${dist.codename})`;
  }

  /**
   * Reports whether a host is on a release HostSeal supports.
   *
   * An unsupported release is flagged rather than hidden. A host nobody is patching is exactly the one
   * an operator needs to see.
   */
  protected unsupportedRelease(host: Host): boolean {
    return host.facts?.distribution?.supported === false;
  }

  /**
   * Summarises a host's policy in one phrase.
   *
   * The policy is the thing the control plane cannot change, so what it says is worth a column of its
   * own rather than being buried on the detail page. A host that will accept nothing looks different
   * here from one that will accept everything, at a glance.
   */
  protected policySummary(host: Host): string {
    const policy = host.policy;
    if (!policy) {
      return 'not reported yet';
    }
    const reboot = policy.updates.reboot === 'never' ? 'no reboots' : `reboots in ${policy.updates.window}`;
    return `${policy.updates.allow} updates, ${reboot}`;
  }

  /** Reports whether anything about a host warrants an operator's attention. */
  protected needsAttention(host: Host): boolean {
    return (
      !host.online ||
      host.paused ||
      host.revoked ||
      host.clockSkewed ||
      (host.facts?.packages?.upgradableSecurity ?? 0) > 0 ||
      (host.facts?.reboot?.required ?? false)
    );
  }
}
