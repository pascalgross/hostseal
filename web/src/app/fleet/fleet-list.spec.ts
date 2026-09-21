import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideZonelessChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { Observable, of, throwError } from 'rxjs';

import { ApiService } from '../core/api.service';
import { FleetResponse, Host } from '../core/api.models';
import { FleetList } from './fleet-list';

/** One host with everything the list reads, so a spec names only the part it is about. */
function host(partial: Partial<Host>): Host {
  return {
    id: '01JHOST00000000000000000000',
    hostname: 'web-01',
    group: '',
    agentVersion: '1.0.0',
    enrolledAt: '2026-09-01T00:00:00Z',
    lastSeen: '2026-09-21T10:00:00Z',
    online: true,
    uptimeSeconds: 100,
    clockOffsetSeconds: 0,
    clockSkewed: false,
    paused: false,
    revoked: false,
    factsDigest: '',
    policyDigest: '',
    signersDigest: '',
    facts: null,
    policy: null,
    signers: null,
    updates: { pending: 0, security: 0, rebootRequired: false },
    services: { failed: 0 },
    ...partial,
  } as Host;
}

/** One answer from the control plane, paced at whatever heartbeat the spec is about. */
function fleet(hosts: Host[], heartbeatSeconds = 60): FleetResponse {
  return { hosts, heartbeatSeconds, serverTime: '2026-09-21T10:00:00Z' };
}

/** The protected members these specs reach for, named so the casts below stay readable. */
interface ListInternals {
  /** Whether the document is hidden, which the loop consults before booking a read. */
  pageHidden(): boolean;

  /** Reads the fleet now, which the refresh button does. */
  read(): void;
}

/**
 * Renders the list against a control plane that answers each read from a queue.
 *
 * A queue rather than one canned answer, because what these specs are about is the *sequence*: what
 * the second read shows, and what a failed second read leaves on screen. The enrolment panel's own
 * calls are stubbed to nothing, since it is rendered inside this page and is not what is under test.
 */
function render(answers: (() => Observable<FleetResponse>)[]): ComponentFixture<FleetList> {
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [
      provideZonelessChangeDetection(),
      provideRouter([]),
      {
        provide: ApiService,
        useValue: {
          // The last answer repeats, so a spec about one sequence need not spell out every later read.
          fleet: () => (answers.length > 1 ? answers.shift()! : answers[0])(),
          enrolment: () => of(null),
          templates: () => of({ templates: [] }),
          enrolmentTokens: () => of({ tokens: [] }),
        } as unknown as ApiService,
      },
    ],
  });
  const fixture = TestBed.createComponent(FleetList);
  fixture.detectChanges();
  return fixture;
}

/** Collapses whitespace, so an assertion can be written the way the page actually reads. */
function text(element: Element | null): string {
  return (element?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

describe('FleetList refresh', () => {
  beforeEach(() => jasmine.clock().install());
  afterEach(() => jasmine.clock().uninstall());

  /**
   * The list re-reads itself at the pace the control plane says hosts report.
   *
   * Before this the fleet page was a snapshot of whenever it was opened, and on a page people leave
   * open that is a snapshot of the wrong moment: a host enrolled, a job finished or a reboot completed
   * showed up only after a reload. The cadence is asserted as well as the re-read, because a loop
   * that read at the wrong pace would pass a test that only counted.
   */
  it('re-reads the fleet at the heartbeat cadence, and shows what the re-read returned', () => {
    let reads = 0;
    const fixture = render([
      () => {
        reads += 1;
        return of(fleet([host({ hostname: 'web-01' })], 20));
      },
      () => {
        reads += 1;
        return of(fleet([host({ hostname: 'web-01' }), host({ id: 'x', hostname: 'web-02' })], 20));
      },
    ]);

    expect(reads).toBe(1);
    expect(text(fixture.nativeElement)).toContain('every 20s');

    jasmine.clock().tick(19_999);
    expect(reads).toBe(1);
    jasmine.clock().tick(1);
    fixture.detectChanges();

    expect(reads).toBe(2);
    expect(text(fixture.nativeElement)).toContain('web-02');
    expect(text(fixture.nativeElement)).toContain('2 of 2 online');
  });

  /**
   * The cadence is bounded on both sides, whatever the heartbeat.
   *
   * A five-second fleet does not want a five-second table, and a ten-minute fleet does not want a
   * host enrolled just now to appear in ten minutes: the heartbeat bounds how fast a row changes on
   * its own, and nothing else about the list.
   */
  it('keeps the cadence between the two bounds', () => {
    expect(text(render([() => of(fleet([], 5))]).nativeElement)).toContain('every 15s');
    expect(text(render([() => of(fleet([], 600))]).nativeElement)).toContain('every 60s');
  });

  /**
   * A re-read that fails leaves the last good list on screen, and says so beside it.
   *
   * The first load failing leaves nothing to show, so the page says so in place of the list. A
   * re-read failing is different: the last list is still the best answer there is, and replacing a
   * table of hosts with an error card every time a proxy hiccups would make the page unusable at the
   * moment somebody is watching it.
   */
  it('keeps the last fleet on screen when a re-read fails, and recovers on the next', () => {
    const fixture = render([
      () => of(fleet([host({ hostname: 'web-01' })])),
      () => throwError(() => new Error('the control plane is down')),
      () => of(fleet([host({ hostname: 'web-01' })])),
    ]);

    jasmine.clock().tick(60_000);
    fixture.detectChanges();

    const failed = text(fixture.nativeElement);
    expect(failed).toContain('web-01');
    expect(failed).toContain('last refresh failed');
    expect(failed).toContain('could not be reached');

    jasmine.clock().tick(60_000);
    fixture.detectChanges();

    expect(text(fixture.nativeElement)).not.toContain('last refresh failed');
  });

  /**
   * A first load that fails still shows the failure in place of the list.
   *
   * The behaviour the page always had, asserted so the refresh loop cannot have quietly turned a
   * failed first load into an empty fleet with a warning nobody reads.
   */
  it('shows a failed first load as a failure, not as an empty fleet', () => {
    const fixture = render([() => throwError(() => new Error('the control plane is down'))]);

    const rendered = text(fixture.nativeElement);
    expect(rendered).toContain('could not be reached');
    expect(rendered).not.toContain('of 0 online');
  });

  /**
   * A hidden tab is read by nobody, so it is not read at all — and a page that was left costs the
   * control plane nothing.
   *
   * Both halves are asserted here. The hidden case is the one with a cost if it is wrong: every tab
   * left open in the background would be a client the control plane serves as often as its hosts.
   * The destroyed case is the one with a leak if it is wrong: a timer nothing can reach, reading the
   * fleet for the life of the tab.
   */
  it('stops reading while the page is hidden, and when it is left', () => {
    let reads = 0;
    const fixture = render([
      () => {
        reads += 1;
        return of(fleet([], 60));
      },
    ]);
    const list = fixture.componentInstance as unknown as ListInternals;

    list.pageHidden = () => true;
    document.dispatchEvent(new Event('visibilitychange'));
    jasmine.clock().tick(120_000);
    expect(reads).toBe(1);

    list.pageHidden = () => false;
    document.dispatchEvent(new Event('visibilitychange'));
    expect(reads).toBe(2);

    fixture.destroy();
    jasmine.clock().tick(120_000);
    expect(reads).toBe(2);
  });
});
