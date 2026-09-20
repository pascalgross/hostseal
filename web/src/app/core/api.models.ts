/**
 * Types mirroring the HostSeal control plane's administrative API.
 *
 * They are written by hand rather than generated, because there are few of them and because the shapes
 * are stable by design: `docs/PROTOCOL.md` says additive changes do not bump the version and unknown
 * fields are ignored in both directions, so a hand-written interface that is a subset of what the
 * server sends stays correct as the server grows.
 */

/** One trusted signing key as a host reports it, for display in the audit trail. */
export interface SignerSummary {
  /** The identity from the host's own `trusted-signers` file, recorded against every signed job. */
  keyId: string;

  /** The signature algorithm, `ed25519` or `ecdsa-p256`. */
  algorithm: string;

  /**
   * How the private key is held, as the administrator annotated it.
   *
   * It is advisory: nothing can verify where a signature was produced. It exists so that
   * `ops-laptop (file)` reads differently from `ops-yubikey-1 (pkcs11)` to whoever reviews the log.
   */
  backend?: string;
}

/** The parts of a host's fact report the fleet list renders. */
export interface HostFacts {
  /** What the host calls itself. */
  hostname?: string;

  /** Distribution identity, used to show the release and whether HostSeal supports it. */
  distribution?: {
    /** The os-release ID, `ubuntu` or `debian`. */
    id: string;
    /** The release codename, such as `noble`. */
    codename: string;
    /** The release version, such as `24.04`. */
    version: string;
    /** The os-release PRETTY_NAME. */
    prettyName?: string;
    /** Whether this release is one HostSeal supports. */
    supported?: boolean;
  };

  /** The running kernel release. */
  kernel?: string;

  /** Pending update counts, with security separated from the rest. */
  packages?: {
    /** How many pending updates come from a security origin. */
    upgradableSecurity: number;
    /** How many updates are pending in total. */
    upgradableTotal: number;
    /**
     * Whether the host could not gather the list at all, absent when it could.
     *
     * The counts have no absent value, so a host whose apt lock was held sends the same two zeroes a
     * fully patched host sends. Render this as "could not be determined", never as "no updates".
     */
    incomplete?: boolean;
  };

  /** Whether a reboot is needed and what still runs replaced libraries. */
  reboot?: {
    /** Whether a reboot is required. */
    required: boolean;

    /**
     * Whether the host could answer the question at all.
     *
     * `/var/run/reboot-required` is an Ubuntu convention and `needrestart` is only a Recommends on
     * Debian, so a bare `required: false` frequently means *nothing here can tell*. Reading that as
     * "no reboot needed" is the quiet version of the mistake `serviceScanComplete` and
     * `servicesTruncated` already exist to prevent, and it is quieter than either: a fleet of Debian
     * hosts renders as a fleet that is fully up to date. Absent from an older control plane's
     * response, which is why every reader treats only an explicit `false` as inconclusive.
     */
    conclusive?: boolean;

    /** The packages that require it. */
    reasons?: string[];
    /** Units that still hold replaced libraries, per needrestart. */
    services?: string[];
    /**
     * Whether the needrestart scan could see every process.
     *
     * The agent is unprivileged, so it often cannot. An incomplete scan is shown as incomplete rather
     * than as a clean bill of health: "no services need restarting" and "I could not see the services
     * that do" must not look the same.
     */
    serviceScanComplete?: boolean;
  };

  /**
   * Every systemd unit the host reported, with its load, active and sub state.
   *
   * The full list rather than only the failed ones, because the distinction between `failed`,
   * `inactive` and `not-found` is the point: a masked unit and a crashed unit are different problems.
   */
  services?: UnitState[];

  /**
   * Whether that list was cut at the protocol's cap, in sorted order.
   *
   * Reported so that "no failed units" and "the failed unit sorts after the cap" do not render
   * identically — the same rule `serviceScanComplete` follows, and for the same reason.
   */
  servicesTruncated?: boolean;

  /** Ubuntu Pro state, or a not-applicable marker on Debian. */
  subscription?: {
    /**
     * Whether the concept exists on this host at all.
     *
     * False on Debian, where it must render as "not applicable" rather than "unknown". A Debian host
     * with a permanent amber ESM badge teaches its operator to ignore the dashboard.
     */
    applicable: boolean;
    /** Whether the host is attached to a subscription. */
    attached: boolean;
    /** Each Ubuntu Pro service and its status. */
    services?: Record<string, string>;
    /** An explanation of an absent or unreadable answer. */
    note?: string;
  };
}

/** One host as the fleet list and the host detail page render it. */
export interface Host {
  /** The control plane's identifier for the host, and its certificate subject. */
  id: string;

  /** What the host calls itself. Display only: hostnames are not unique and a host can change its own. */
  hostname: string;

  /** The fleet group, from the enrolment token. */
  group: string;

  /** The agent build the host last reported. */
  agentVersion: string;

  /** When the host first enrolled. */
  enrolledAt: string;

  /** The last heartbeat, or null if the host has never been heard from. */
  lastSeen: string | null;

  /** Whether the host has been heard from recently enough to be considered up. */
  online: boolean;

  /** How long the host has been up, in seconds. */
  uptimeSeconds: number;

  /** The host's own measurement of its offset from the control plane, in seconds. */
  clockOffsetSeconds: number;

  /** Whether the offset is large enough that the host refuses privileged intents. */
  clockSkewed: boolean;

  /**
   * Whether `/etc/hostseal/paused` exists on the host.
   *
   * It is a local kill switch the control plane cannot override, and there is deliberately no
   * `agent.resume` intent — so this is shown as a state, never as something to toggle from here.
   */
  paused: boolean;

  /** Whether this host's certificates have been withdrawn. */
  revoked: boolean;

  /** The digest of the facts document the host last reported. */
  factsDigest: string;

  /** The digest of the effective local policy the host last reported. */
  policyDigest: string;

  /** The digest of the host's trusted key set. */
  signersDigest: string;

  /** The last full inventory, or null if none has been received. */
  facts: HostFacts | null;

  /** The host's last reported effective policy, or null. */
  policy: HostPolicy | null;

  /** The host's trusted key identities, or null. */
  signers: SignerSummary[] | null;
}

/** A host's effective local policy, as it reports it. */
export interface HostPolicy {
  /** The `[updates]` section. */
  updates: {
    /** How far the host will go in applying updates: `none`, `security` or `all`. */
    allow: string;
    /** Whether the host applies permitted updates on its own timer. */
    autoApply: boolean;
    /** The maintenance window, or `always`. */
    window: string;
    /** The IANA timezone the window is expressed in. */
    timezone: string;
    /** Whether and when the host will reboot: `never` or `window`. */
    reboot: string;
  };

  /** The `[services]` section. */
  services: {
    /** Units the host will act on, matched as shell globs. Empty means none. */
    restartable: string[];

    /**
     * Units whose state changes this host considers worth an event, matched the same way.
     *
     * Empty means every unit, which is the opposite default from `restartable` and deliberately so:
     * a fresh host should surface a failed unit rather than hide it behind a setting nobody has
     * heard of, and permitting an action is a different question from reporting a fact.
     */
    watched?: string[];
  };

  /** The `[limits]` section. */
  limits: {
    /** How long after issue a job may still be executed. */
    maxJobAgeSeconds: number;
  };

  /** Where the policy was read from, for the UI to show when it is not the packaged file. */
  source: string;
}

/** The response of `GET /api/v1/hosts`. */
export interface FleetResponse {
  /** Every enrolled host, ordered by hostname. */
  hosts: Host[];

  /** The heartbeat pacing the control plane is handing out, used to explain what "online" means. */
  heartbeatSeconds: number;

  /** The control plane's clock, so the UI can render ages without trusting the browser's. */
  serverTime: string;
}

/** One member of the intent catalogue. */
export interface CatalogueEntry {
  /** The wire identifier, such as `services.list`. */
  name: string;

  /** The authorisation tier: `read`, `routine` or `destructive`. */
  class: string;

  /** One line of description. */
  summary: string;

  /** Whether an executor exists behind it on the agent. */
  implemented: boolean;

  /** Whether a key from the host's own `trusted-signers` is required. */
  requiresOfflineSignature: boolean;
}

/** The response of `GET /api/v1/catalogue`. */
export interface CatalogueResponse {
  /** Every operation this control plane can ask a host to perform. */
  intents: CatalogueEntry[];

  /** Operations this project has permanently refused to implement. */
  refused: string[];

  /** The control plane's own note about the set being closed. */
  note: string;
}

/** What a host reported back about a job it ran. */
export interface JobResult {
  /** The job this result belongs to. */
  jobId: string;

  /** One of the protocol's stable status strings, such as `succeeded` or `refused_by_policy`. */
  status: string;

  /** When the host started the operation, by the host's own clock. */
  startedAt: string;

  /** When it finished, by the same clock. Never the control plane's; see `docs/SECURITY.md` §4.3. */
  finishedAt: string;

  /** The root helper's exit status, where one applies. */
  exitCode: number;

  /** The last 64 KiB of what the operation printed. The tail, because the failure is at the end. */
  output?: string;

  /** Whether the output was cut, so a reader knows it is partial by design. */
  outputTruncated?: boolean;

  /** The intent-specific typed result, for the read intents that produce one. */
  result?: unknown;

  /** A human-readable failure or refusal reason, absent on success. */
  error?: string;
}

/** One job as the control plane holds it. */
export interface Job {
  /** The job identifier. For a signed job it is covered by the signature. */
  id: string;

  /** The host it was issued to. */
  hostId: string;

  /** The catalogue member. */
  intent: string;

  /** The parameter object, as validated by the catalogue's own decoder. */
  params: Record<string, unknown>;

  /** The authorisation tier, for display. The agent takes it from its own catalogue, not from here. */
  class: string;

  /** When the control plane created it. */
  createdAt: string;

  /** Which operator asked, recorded for the audit trail rather than for any decision. */
  createdBy: string;

  /** When the job becomes valid, checked on the host against the host's own clock. */
  notBefore: string;

  /** When it stops being valid, checked against the same clock and never a server-supplied one. */
  notAfter: string;

  /**
   * Whether an offline signature is attached.
   *
   * The signature itself is never sent to the browser. It authorises nothing here — the host is what
   * verifies it — and putting one on a dashboard would invite somebody to copy it.
   */
  signed: boolean;

  /** The key that signed it, absent for an unsigned job. */
  signerKeyId?: string;

  /** Whether somebody must release it before any host may claim it. */
  approvalRequired: boolean;

  /**
   * Whether the release must come from somebody other than the job's creator.
   *
   * Recorded on the job when it was created, from the fleet's approval mode at that moment — so a
   * fleet that has since changed its mind does not change what this job requires.
   */
  approvalDistinctOperator: boolean;

  /** When it was released, null until it is. */
  approvedAt: string | null;

  /** Which operator agreed, absent until one does. */
  approvedBy?: string;

  /** When a host took it, null if none has. */
  claimedAt: string | null;

  /** One word for what is happening: `queued`, `awaiting_approval`, `running`, or a result status. */
  state: string;

  /**
   * What the host reported, null until it does.
   *
   * Null rather than an empty object: "not reported yet" and "reported nothing" are different states,
   * and a host part way through a forty-minute upgrade is in the first one.
   */
  result: JobResult | null;
}

/** The response of `GET /api/v1/jobs`. */
export interface JobsResponse {
  /** Jobs, newest first. */
  jobs: Job[];

  /** The bound that was applied to this listing. */
  limit: number;

  /** The largest bound the control plane will accept. */
  maxLimit: number;

  /**
   * Whether the listing filled its bound, so there may be older jobs it did not return.
   *
   * It is reported by the server rather than worked out from the row count, because a client that has
   * to derive it is a client that will eventually forget to.
   */
  truncated: boolean;

  /**
   * The control plane's clock, so job ages can be rendered without trusting the browser's.
   *
   * The rule is the one `formatAge` states: everything on these pages measures against the server's
   * clock, because an age here is a decision input — "asked 4h ago" is why a second operator releases
   * a job — and a laptop ten minutes slow would understate every one of them.
   */
  serverTime: string;
}

/** The body of `POST /api/v1/jobs` for an unsigned, read-only job. */
export interface CreateReadJobRequest {
  /** The host to issue to. */
  hostId: string;

  /** The catalogue member, which must be a read intent for a request this shape. */
  intent: string;

  /** The parameter object. Every read intent takes an empty one. */
  params: Record<string, unknown>;
}

/** One tenant: an isolated fleet with its own hosts, operators and settings. */
export interface Tenant {
  /** The identifier every scoped row carries. */
  id: string;

  /** The short stable handle used in URLs, logs and support tickets. */
  slug: string;

  /** What the fleet is called in the interface. */
  displayName: string;

  /** When the tenant was created. */
  createdAt: string;

  /** How this fleet releases a destructive job: "none", "self" or "second_person". */
  approvalMode: string;

  /** Where this fleet's events are posted, empty for nowhere. */
  webhookUrl: string;
}

/**
 * The body of `GET /api/v1/whoami`.
 *
 * The application asks for it on start, for the same reason a shell prompt shows the hostname: an
 * operator with two fleets open in two tabs needs the page to say which one they are looking at before
 * they queue a reboot in it.
 */
export interface Whoami {
  /** The identifier the identity provider knows this operator by. */
  subject: string;

  /** A human-readable name. */
  display: string;

  /** Which provider authenticated them. */
  provider: string;

  /** The provider-qualified string recorded as the author of anything they do. */
  principal: string;

  /**
   * Whether this is the installation's platform administrator rather than a fleet's operator.
   *
   * It decides which of two interfaces to render, and there are two because the credentials reach
   * disjoint sets of routes: a platform credential administers fleets and is refused by every route
   * that reaches a fleet's hosts or jobs, and an operator credential is the other way round.
   */
  platform: boolean;

  /**
   * The fleet this credential acts in, null for a platform administrator.
   *
   * Null rather than an empty tenant, deliberately: a client that forgot to read `platform` fails on
   * the field it needs rather than rendering a fleet called "".
   */
  tenant: Tenant | null;

  /**
   * The control plane's version.
   *
   * It arrives here rather than from `/healthz` because that endpoint is unauthenticated, and an exact
   * build is the first thing somebody matching a deployment against a published advisory looks for.
   */
  version: string;

  /** The commit the control plane was built from. */
  commit: string;
}

/** The response of `GET /api/v1/tenants`. */
export interface TenantsResponse {
  /** Every fleet on this installation, oldest first. */
  tenants: Tenant[];
}

/** The body of `POST /api/v1/tenants`. */
export interface CreateTenantRequest {
  /** The short stable handle. Lower-case letters, digits and hyphens; it cannot be changed later. */
  slug: string;

  /** What the fleet is called in the interface, defaulting to the slug. */
  displayName?: string;

  /** How this fleet releases a destructive job: "none", "self" or "second_person". */
  approvalMode?: string;

  /** Where this fleet's events are posted, empty for nowhere. */
  webhookUrl?: string;
}

/**
 * The body of `PATCH /api/v1/tenants/{id}`.
 *
 * Every field is optional and one that is not sent is left alone, which is what makes this a patch: an
 * administrator changing an approval mode must not silently erase a webhook they never mentioned. The
 * slug is absent because it cannot be changed — it is what logs and support tickets refer to.
 */
export interface UpdateTenantRequest {
  /** What the fleet is called in the interface. */
  displayName?: string;

  /** How this fleet releases a destructive job. */
  approvalMode?: string;

  /** Where this fleet's events are posted, empty for nowhere. */
  webhookUrl?: string;
}

/** The body of `POST /api/v1/session`. */
export interface SignInRequest {
  /** The address the operator signs in with, matched without regard to case or surrounding space. */
  email: string;

  /** What they typed. It is sent once, over TLS, and is never stored by this application. */
  password: string;
}

/**
 * The response of `POST /api/v1/session`.
 *
 * There is deliberately no token in it. The credential is an HttpOnly cookie the browser keeps and
 * this application cannot read, which is the point of signing in this way rather than pasting a bearer
 * token into `localStorage`. What comes back is who signed in, so the shell can render a name without
 * a second round trip.
 */
export interface SignedIn {
  /** The identifier the provider knows this operator by, which for an account is their address. */
  subject: string;

  /** A human-readable name. */
  display: string;

  /** Which provider authenticated them. */
  provider: string;

  /** The provider-qualified string recorded as the author of anything they do. */
  principal: string;
}

/**
 * One event as the inbox and the live stream render it.
 *
 * The same shape from both sources on purpose: a page that reconciles a live stream against the
 * durable inbox must not have to translate between two spellings of the same event.
 */
export interface FleetEvent {
  /** The event identifier, which is what de-duplicates a streamed event against a fetched one. */
  id: string;

  /** A member of the control plane's closed vocabulary, such as `service.failed`. */
  kind: string;

  /** The host it concerns, absent for fleet-wide events such as a digest. */
  hostId?: string;

  /** The hostname, carried for display because an opaque identifier helps nobody. */
  hostname?: string;

  /** One line of human-readable text. */
  summary: string;

  /** When it happened, by the control plane's clock. */
  at: string;

  /** Event-specific fields, rendered only where a page knows what to do with them. */
  detail?: Record<string, unknown>;
}

/** The response of `GET /api/v1/events`. */
export interface EventsResponse {
  /** The inbox, newest first. */
  events: FleetEvent[];

  /** The control plane's clock, so ages are rendered against it rather than the browser's. */
  serverTime: string;
}

/** One systemd unit as a host reported it. */
export interface UnitState {
  /** The unit name, such as `nginx.service`. */
  name: string;

  /** Whether the unit is loaded, masked or absent. A masked unit is a different problem from a crash. */
  loadState: string;

  /** The active state, which is what `failed` is read from. */
  activeState: string;

  /** The finer-grained state, carried for display. */
  subState: string;
}

/** One host's failed units, as the fleet-wide service view renders them. */
export interface FailedServiceHost {
  /** The host. */
  hostId: string;

  /** What it calls itself. */
  hostname: string;

  /** Whether it has been heard from recently. */
  online: boolean;

  /** Its units in the failed state, each carrying the load state that says what kind of failure. */
  failed: UnitState[];

  /**
   * Whether this host's unit list was cut at the protocol's cap.
   *
   * Rendered rather than swallowed: "no failed units here" and "the failed unit sorts after the cap"
   * must not look the same, which is the same rule the needrestart scan already follows.
   */
  servicesTruncated: boolean;

  /**
   * Whether the control plane could read this host's facts at all.
   *
   * True for a host that has never reported, or whose stored facts will not parse. It is a third
   * answer beside "clean" and "failing" and has to render as one: a host nothing is known about is
   * not a host with no failed units, which is the same distinction `servicesTruncated` exists to
   * make one level down.
   */
  factsUnknown: boolean;
}

/** The response of `GET /api/v1/services/failed`. */
export interface FailedServicesResponse {
  /** Only the hosts with something failed, with a truncated list, or with no readable facts. */
  hosts: FailedServiceHost[];

  /**
   * How many hosts were examined, so "3 of 300" is renderable.
   *
   * Revoked hosts are not in it. They are not part of the fleet this page is about, and counting
   * them made the denominator include machines somebody had deliberately removed.
   */
  total: number;

  /** The control plane's clock. */
  serverTime: string;
}

/** One recorded change of a unit's active state. */
export interface UnitTransition {
  /** The unit that changed. */
  unit: string;

  /** The state it was in. */
  from: string;

  /** The state it moved to. */
  to: string;

  /** When the control plane observed the change. */
  at: string;
}

/** The response of `GET /api/v1/hosts/{id}/services/history`. */
export interface ServiceHistoryResponse {
  /** The transitions, newest first. */
  transitions: UnitTransition[];

  /**
   * The heartbeat interval, which is this history's resolution.
   *
   * Stated by the server rather than assumed by the page: a unit that failed and recovered between
   * two beats is not in here, and an operator reading the history during an incident needs to know
   * that before they conclude nothing happened.
   */
  resolutionSeconds: number;

  /** The control plane's clock. */
  serverTime: string;
}

/** One alerting rule as the control plane holds it. */
export interface AlertRule {
  /** The rule identifier. */
  id: string;

  /** What it watches: `host_silent`, `security_updates`, `reboot_required`, `unit_failed`, `job_failed`. */
  condition: string;

  /** Parameterises the condition: minutes silent, pending updates, or days a reboot has been due. */
  threshold: number;

  /** How long before one firing pair may notify again, zero for the server's default. */
  cooldownSeconds: number;

  /** Who gets mailed. Everything else — the inbox, the stream, the webhook — happens regardless. */
  emailTo: string[];

  /** Whether the rule is live. */
  enabled: boolean;

  /** When it was created. */
  createdAt: string;

  /** Which operator created it. */
  createdBy: string;

  /** When it last tried to mail somebody, absent for never. */
  lastDeliveryAt?: string;

  /**
   * Why that attempt failed, absent when it succeeded.
   *
   * Shown on the rule rather than left in a server log, because an alert that never went out and an
   * alert that never fired are indistinguishable from an inbox.
   */
  lastDeliveryError?: string;
}

/** The response of `GET /api/v1/alerts`. */
export interface AlertRulesResponse {
  /** The rules, oldest first. */
  rules: AlertRule[];

  /** What a zero cooldown means, reported so the page does not hard-code the server's number. */
  defaultCooldownSeconds: number;

  /**
   * Whether this control plane has a mail relay at all.
   *
   * Rendered as a warning beside any rule with recipients when it is false: adding an address to a
   * rule on an installation that was never given `--smtp-host` is the commonest version of the
   * mistake, and it fails silently everywhere except here.
   */
  mailConfigured: boolean;
}

/** The body of `POST /api/v1/alerts` and `PATCH /api/v1/alerts/{id}`. */
export interface AlertRuleRequest {
  /** What to watch. Required on create and refused on update: a rule's condition is its identity. */
  condition?: string;

  /** Parameterises the condition. */
  threshold: number;

  /** Re-notification bound in seconds, zero for the server's default. */
  cooldownSeconds: number;

  /** Mail recipients, empty for none. */
  emailTo: string[];

  /** Whether the rule is live. */
  enabled?: boolean;
}

/** One provisioning template, as the list renders it. */
export interface TemplateSummary {
  /** The template's name, which is what an enrolment token names to request it. */
  name: string;

  /** The highest version stored. Every save is a new version; there is no update path. */
  latestVersion: number;

  /** When the latest version was stored. */
  createdAt: string;

  /** Which operator stored it. */
  createdBy: string;

  /**
   * Whether the latest version carries an offline signature.
   *
   * An unsigned template can be rendered and pasted into a provisioner; only a signed one may be
   * handed to an enrolling agent, because the agent verifies it against its own trusted-signers and
   * this control plane cannot produce that signature.
   */
  signed: boolean;
}

/** The response of `GET /api/v1/templates`. */
export interface TemplatesResponse {
  /** One summary per template, newest first. */
  templates: TemplateSummary[];
}

/** One immutable version of a template, body included. */
export interface TemplateVersion {
  /** The template's name. */
  name: string;

  /** This version's number. */
  version: number;

  /** The cloud-config body, verbatim. */
  body: string;

  /** Whether an offline signature is attached. */
  signed: boolean;

  /** The key that signed it, absent for an unsigned version. */
  signerKeyId?: string;

  /** When it was stored. */
  createdAt: string;

  /** Which operator stored it. */
  createdBy: string;

  /** The placeholder names the body substitutes, so a render form can be built without parsing it. */
  placeholders: string[];

  /**
   * Secret shapes found in the body, with the consequence spelled out.
   *
   * Warnings and never refusals: user-data is readable from inside the instance and from the metadata
   * service, so a secret in a template is a secret in plaintext on every host it provisions — and a
   * control that blocked the save would only teach operators to route around it.
   */
  warnings: string[];
}

/**
 * What a save answers with.
 *
 * Narrower than `TemplateVersion` on purpose, and the narrowness is the server's rather than this
 * file's: the create response confirms what was stored and deliberately does not echo the body back,
 * because a body is where operators put the things the warnings are about. A client that wants the
 * whole version reads it, which is also the only way to be sure it is looking at what was stored
 * rather than at what it sent.
 */
export interface StoredTemplateVersion {
  /** The template's name. */
  name: string;

  /** The version just written. */
  version: number;

  /** Whether it carries an offline signature. */
  signed: boolean;

  /** The placeholder names the body substitutes. */
  placeholders: string[];

  /** Secret shapes found in the body, with the consequence spelled out. */
  warnings: string[];
}

/**
 * One stored revision as the version listing renders it, without its body.
 *
 * No body, because the listing is about the shape of a template's history rather than its contents:
 * bodies are sealed, potentially large, and the one a caller actually wants is fetched by naming its
 * version — which is also the request that is marked non-cacheable, because that is the one carrying
 * something worth keeping out of a cache.
 */
export interface TemplateRevision {
  /** This revision's number. */
  version: number;

  /** Whether it carries an offline signature, and so may be issued to an enrolling host. */
  signed: boolean;

  /** The key that signed it, absent for an unsigned revision. */
  signerKeyId?: string;

  /** When it was stored. */
  createdAt: string;

  /** Which operator stored it. */
  createdBy: string;
}

/** The response of `GET /api/v1/templates/{name}/versions`. */
export interface TemplateVersionsResponse {
  /** The template these revisions belong to. */
  name: string;

  /** Every stored revision, newest first. */
  versions: TemplateRevision[];
}

/** The body of `POST /api/v1/templates`. */
export interface CreateTemplateRequest {
  /** The template's name; an existing name stores the next version of it. */
  name: string;

  /** The cloud-config body. */
  body: string;

  /** A detached signature made offline by `hostseal sign-template`, absent for an unsigned version. */
  signature?: string;

  /** The signing key's identity, required with a signature. */
  signerKeyId?: string;

  /** The signature algorithm, required with a signature. */
  signerAlgorithm?: string;
}

/** The body of `POST /api/v1/templates/{name}/render`. */
export interface RenderTemplateRequest {
  /** Which version to render, omitted for the latest. */
  version?: number;

  /** The values substituted into the template's placeholders. */
  params: Record<string, string>;

  /** How to configure the enrolment token, when the body substitutes one. */
  token?: {
    /** A human-readable name for the token, defaulted to naming the template. */
    label?: string;
    /** The fleet group hosts enrolled with it join. */
    group?: string;
    /** The token's lifetime, defaulted to the server's. */
    ttlSeconds?: number;
    /** The template this token may request at enrolment, which is how a Tier 2 bootstrap is armed. */
    bootstrap?: string;
  };
}

/**
 * The response of a render.
 *
 * It is a credential and is treated as one: nothing stores it, it is not cacheable, and an operator
 * who loses it renders again — which mints a fresh token and costs nothing.
 */
export interface RenderedTemplate {
  /** The template rendered. */
  name: string;

  /** The version rendered. */
  version: number;

  /** The user-data, ready to paste into a provisioner. */
  userData: string;

  /** Secret shapes found in the *rendered* output, which includes what substitution introduced. */
  warnings: string[];

  /** When the minted enrolment token expires, absent when the template mints none. */
  tokenExpiresAt?: string | null;

  /** The control plane's own sentence about the output being shown once. */
  note: string;
}

/** The signed-in account, as `GET /api/v1/account` describes it. */
export interface Account {
  /** The address this account signs in with. */
  email: string;

  /** What to call this person, empty for the address. */
  displayName: string;

  /** When the account was made. */
  createdAt: string;

  /** When it last signed in, null for never. */
  lastSignedIn: string | null;

  /** Whether this administers the installation rather than a fleet. */
  platform: boolean;

  /** The provider-qualified string recorded as the author of anything this account does. */
  principal: string;
}

/** The body of `POST /api/v1/account/password`. */
export interface ChangePasswordRequest {
  /** What the operator signs in with today, verified even though the session already authenticated. */
  currentPassword: string;

  /** What they want instead. */
  newPassword: string;
}

/**
 * One browser this account is signed in on.
 *
 * There is no token and no token hash here, which is why `current` is a flag the server computed
 * rather than an identifier this application compares. Nothing in this shape authenticates anybody.
 */
export interface OperatorSession {
  /** When the sign-in happened. */
  createdAt: string;

  /** When the session stops authenticating, as it stands — it moves forward while it is used. */
  expiresAt: string;

  /** When a request last presented it, null for never. */
  lastUsed: string | null;

  /** What the browser called itself. Advisory: a client chooses this string. */
  userAgent: string;

  /** Where it was last used from. Advisory: behind a proxy this is the proxy. */
  source: string;

  /** Whether it has run out, in which case it is a row waiting to be swept rather than a credential. */
  expired: boolean;

  /** Whether this is the session asking. */
  current: boolean;
}

/** The response of `GET /api/v1/account/sessions`. */
export interface SessionsResponse {
  /** Every session this account holds, newest first. */
  sessions: OperatorSession[];
}

/** The response of `POST /api/v1/account/sessions/revoke`. */
export interface SessionsRevoked {
  /** How many sessions were ended, including the one that asked. */
  ended: number;
}

/**
 * One API token this account holds.
 *
 * The id is the token's SHA-256, which is what the store keys on. It is not a credential — a hash of
 * 256 bits of randomness cannot be turned back into one — and returning it is what lets revoking a
 * token need no second identifier kept in step with the first.
 */
export interface ApiToken {
  /** What names this token in a request to revoke it. */
  id: string;

  /** What the operator called it. */
  label: string;

  /** When it was issued. */
  createdAt: string;

  /** When it stops working, null for never. */
  expiresAt: string | null;

  /** When a request last presented it, null for never. */
  lastUsed: string | null;

  /** Whether it would still be accepted. */
  usable: boolean;
}

/** The response of `GET /api/v1/account/tokens`. */
export interface ApiTokensResponse {
  /** Every token this account holds, newest first. */
  tokens: ApiToken[];
}

/** The body of `POST /api/v1/account/tokens`. */
export interface CreateApiTokenRequest {
  /** What to call it, so that revoking the right one is possible later. Required. */
  label: string;

  /** How long it lasts; zero or absent means it does not expire. */
  expiresInDays?: number;
}

/**
 * A token just issued.
 *
 * The `token` field is the only time the value exists anywhere but in whoever copied it: only the
 * SHA-256 is stored, so the page that renders this has to say so.
 */
export interface IssuedApiToken {
  /** What names this token in a request to revoke it. */
  id: string;

  /** What the operator called it. */
  label: string;

  /** When it was issued. */
  createdAt: string;

  /** When it stops working, null for never. */
  expiresAt: string | null;

  /** The token itself, returned exactly once. */
  token: string;
}

/**
 * The body of `GET /api/v1/enrolment`.
 *
 * One response for all three steps, because the steps are one document. An operator who took the agent
 * URL from this control plane and the CA certificate from another has a host that cannot enrol and a
 * mistake nothing on either machine names.
 */
export interface EnrolmentInstructions {
  /** The base URL to pass to `hostseal enroll --server`. */
  agentUrl: string;

  /**
   * Whether the address above is the browser's own rather than one somebody configured.
   *
   * Shown to the operator rather than hidden. The documented Traefik deployment serves this page on a
   * hostname that refuses the agent API by design, so a guess is wrong there in a way that stays
   * invisible until an agent has been installed and cannot enrol.
   */
  agentUrlIsAGuess: boolean;

  /** Where the CA certificate can be fetched, for the second step. */
  caCertificatePath: string;

  /**
   * The CA certificate's SHA-256, formatted as `openssl x509 -fingerprint -sha256` prints it.
   *
   * Shown so that a host which can only fetch the certificate over an unverified connection has
   * something to check the result against. This session is that independent channel: the operator is
   * already authenticated here, so a digest read on this page and compared on the host closes the one
   * window an unverified fetch would otherwise leave open.
   */
  caFingerprint: string;

  /** The APT repository the agent package is installed from. */
  aptUrl: string;

  /**
   * Where the Windows agent's release archive is downloaded from.
   *
   * Separate from `aptUrl` because the two platforms are not served the same way. A Debian or Ubuntu
   * host subscribes to a signed repository and is upgraded from it; a Windows host fetches one archive
   * and is upgraded by fetching it again. Collapsing the two into one field would have the panel print
   * a repository URL to a platform that has none.
   */
  windowsArchiveUrl: string;
}

/**
 * The body of `POST /api/v1/tokens`.
 *
 * `token` is the only time the value exists anywhere but in whoever copied it: only its SHA-256 is
 * stored, so the page that renders this has to say so rather than offering to show it again.
 */
export interface MintedEnrolmentToken {
  /** The token itself, returned exactly once. */
  token: string;

  /** What the operator called it. */
  label: string;

  /** The fleet group hosts enrolled with it join. */
  group: string;

  /** When it stops being usable. */
  expiresAt: string;
}

/**
 * The body of `POST /api/v1/tokens`, as the enrolment instructions send it.
 *
 * The server takes more than this — a lifetime, and a bootstrap template — and the enrolment panel
 * sends neither. A token minted from that panel is for the plain case the panel documents, and arming
 * a Tier 2 bootstrap is a decision made where templates are, not beside a copy button.
 */
export interface CreateEnrolmentTokenRequest {
  /** A human-readable name, so the token list says what each one was for. */
  label: string;

  /** The fleet group hosts enrolled with it join. */
  group: string;
}

/**
 * The three-valued count of a fleet's health, which is the whole argument of the wallboard payload.
 *
 * `ok + bad + unknown === total`, always, and the server holds itself to it. The third value is the
 * one that costs something to leave out: a host that has never reported and a host that is fine are
 * the same colour on any board that counts two ways, and the board is then most confident about
 * exactly the fleet it knows least about.
 */
export interface WallboardCounts {
  /** How many hosts are enrolled, revoked ones excluded. */
  total: number;

  /** How many are reachable with nothing definitely wrong. */
  ok: number;

  /** How many were heard from and are broken, or were not heard from inside the grace window. */
  bad: number;

  /** How many cannot be judged: never seen, paused, or with no readable facts. */
  unknown: number;
}

/**
 * One host the board names, as an example of what the counters already counted.
 *
 * The tiles are examples and the counters are the truth — see `attentionOmitted`. Everything here is
 * composed by the control plane, including `detail`, so that two screens showing one fleet say the
 * same words and no client has to know the grace window or the skew threshold to phrase them.
 */
export interface WallboardAttention {
  /**
   * What the host calls itself, empty for a machine that has never said.
   *
   * The only name on the board, and deliberately not backed by the host id: an id is unreadable from
   * three metres and is the value three write routes name, so an empty string is what a machine that
   * has never reported gets. The board renders that as a phrase rather than as a blank tile.
   */
  hostname: string;

  /** Whether this is definitely wrong or merely unjudgeable. Never "ok": a well host is not a tile. */
  status: 'bad' | 'unknown';

  /**
   * Why, from a closed vocabulary, so the board can render a word and an icon rather than a colour.
   *
   * Closed because it is a rendering key as well as a label. An unrecognised member must still draw
   * something, which is why the board falls back rather than switching exhaustively: a control plane
   * one version ahead should add a reason, not blank a tile.
   */
  reason: 'offline' | 'unit_failed' | 'clock_skewed' | 'never_seen' | 'paused' | 'facts_unknown';

  /** One phrase, composed and bounded by the server, such as "no heartbeat for 14 minutes". */
  detail: string;
}

/**
 * One screen of a fleet's state, as both wallboard routes answer it.
 *
 * The authenticated and the public route return the same bytes but for `title`, which is a property
 * rather than an accident: were the public payload a redaction of a richer one, the redaction would
 * be a rule somebody has to remember on every future field. Nothing a host reported is in here — no
 * facts document, no host ids, no unit, package or kernel names — because a leaked link discloses
 * roughly what somebody standing in the room already sees, and that is what makes it acceptable at
 * all.
 */
export interface WallboardView {
  /**
   * The control plane's clock, for display beside the fleet's name and for nothing else.
   *
   * Emphatically not what the board ages itself against: it arrives inside the response and freezes
   * with it, so a board that measured staleness with it would report "updated one second ago" for
   * ever after the control plane stopped answering. The browser's own clock is what ticks.
   */
  serverTime: string;

  /** How often to poll, in seconds. Server-set, so changing the pacing does not mean reissuing links. */
  pollSeconds: number;

  /** What this fleet is called, and the only place a fleet is named on a public screen. */
  title: string;

  /** Host health, three-valued and summing to the fleet. */
  hosts: WallboardCounts;

  /** The security backlog. A backlog is a counter and never makes a host `bad`. */
  security: {
    /** How many hosts have at least one pending security update. */
    hosts: number;

    /**
     * How many security updates are pending across the fleet.
     *
     * Optional because the server omits it when it is zero — the three measures share one Go struct
     * and only this one has a package count — so a fully patched fleet sends no field at all. Every
     * reader has to coalesce it to zero rather than render the absence, which on a wallboard would
     * be a blank space where the reassuring number belongs.
     */
    packages?: number;

    /** How many hosts could not be asked, so the two numbers above are known to be understatements. */
    unknown: number;
  };

  /** Hosts awaiting a reboot, with the hosts that cannot answer the question counted separately. */
  reboots: {
    /** How many hosts require a reboot. */
    hosts: number;

    /** How many could not tell — the Debian case `HostFacts.reboot.conclusive` names. */
    unknown: number;
  };

  /** Hosts with a failed systemd unit, and hosts whose unit list could not be read. */
  units: {
    /** How many hosts have at least one failed unit. */
    hosts: number;

    /** How many have no readable unit list, including one cut at the protocol's cap. */
    unknown: number;
  };

  /** At most twelve hosts worth naming, ordered by the server so the grid does not shuffle. */
  attention: WallboardAttention[];

  /**
   * How many bad-or-unknown hosts did not fit.
   *
   * The number is what turns a bounded grid from "hidden" into "counted": a board that clipped its
   * thirteenth failing host would hide precisely the thing it exists to surface, using the mechanism
   * that was meant to make it readable.
   */
  attentionOmitted: number;
}

/**
 * One published link, as the share list renders it.
 *
 * The secret is not here and never will be: only its digest is stored, so the link exists exactly
 * once, in the create response. What this carries is enough to recognise a share and decide to
 * withdraw it — what it was called, who published it, when it dies, and whether anything is still
 * polling it.
 */
export interface WallboardShare {
  /** What names this share in the request that withdraws it. Not the secret, which is unrecoverable. */
  id: string;

  /** What the operator called it, and the heading the published screen shows. */
  label: string;

  /** When it was published. */
  createdAt: string;

  /** Who published it. The one name a share can carry: it names no reader and never will. */
  createdBy: string;

  /** When it stops answering. Never absent — a share that never expires is the credential §4.5 removed. */
  expiresAt: string;

  /**
   * When a screen last polled it, null for never.
   *
   * The closest thing to an access record and not one: it says something polled, not which television
   * or from where. It exists so that "which of these four links is still on a wall" is answerable
   * before somebody revokes one and waits to see who complains.
   */
  lastSeenAt: string | null;

  /** Whether a passphrase is required before a screen may poll it. */
  passphrase: boolean;

  /** Whether it has already run out, in which case it is a row to tidy rather than a credential. */
  expired: boolean;
}

/** The response of `GET /api/v1/wallboard/shares`. */
export interface WallboardSharesResponse {
  /** Every share this fleet has published, newest first, expired ones included. */
  shares: WallboardShare[];

  /** The control plane's clock, so ages in the list are rendered against it rather than the browser's. */
  serverTime: string;
}

/** The body of `POST /api/v1/wallboard/shares`. */
export interface CreateWallboardShareRequest {
  /** What to call it. Required: a list of four shares called "share" is a list nobody revokes from. */
  label: string;

  /** How long it lives, in days. Absent means the server's ninety; the server refuses more than 365. */
  days?: number;

  /** An optional passphrase a screen proves once and then exchanges for a cookie. Absent for none. */
  passphrase?: string;
}

/**
 * The response of `POST /api/v1/wallboard/shares`.
 *
 * `link` is the one moment the secret exists anywhere but in whoever copies it, so whatever renders
 * this has to say so where it is shown rather than in a footnote. Losing it costs one more share.
 */
export interface CreateWallboardShareResponse {
  /** The share as the list will show it from now on. */
  share: WallboardShare;

  /** The whole address, key in the fragment, returned exactly once. */
  link: string;
}
