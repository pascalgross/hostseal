import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

import {
  Account,
  AlertRuleRequest,
  AlertRulesResponse,
  ApiTokensResponse,
  CatalogueResponse,
  ChangePasswordRequest,
  CreateApiTokenRequest,
  CreateReadJobRequest,
  CreateTemplateRequest,
  CreateEnrolmentTokenRequest,
  EnrolmentTokensResponse,
  CreateTenantRequest,
  CreateWallboardShareRequest,
  CreateWallboardShareResponse,
  EnrolmentInstructions,
  EventsResponse,
  FailedServicesResponse,
  FleetResponse,
  Host,
  IssuedApiToken,
  Job,
  JobsResponse,
  RenderTemplateRequest,
  RenderedTemplate,
  ServiceHistoryResponse,
  SessionsResponse,
  SessionsRevoked,
  SignInRequest,
  SignedIn,
  SignedJob,
  StoredTemplateVersion,
  TemplateArchivalResult,
  TemplateVersion,
  TemplateVersionsResponse,
  TemplatesResponse,
  MintedEnrolmentToken,
  Tenant,
  TenantsResponse,
  UpdateTenantRequest,
  WallboardSharesResponse,
  WallboardView,
  Whoami,
} from './api.models';

/**
 * The header every request to the administrative API carries.
 *
 * It is the cross-site request forgery defence for the session cookie, and it works because of what a
 * browser will not do: a cross-site form post cannot set a header at all, and a cross-site fetch that
 * sets one triggers a CORS preflight the control plane does not answer. The server refuses a
 * cookie-authenticated request without it — see `internal/auth`, which is where the rule lives.
 *
 * It is exported because the live event feed reads its stream with `fetch` rather than through this
 * service, and a header written twice is a header that will one day be written differently.
 */
export const SESSION_HEADER = 'X-HostSeal-Session';

/**
 * Talks to the HostSeal control plane's administrative API.
 *
 * It is the only place in the application that knows a URL or a header. Components take an
 * `Observable` and render it, which means a change to how operators authenticate — a session cookie, an
 * OIDC flow — is one file rather than a search through the components.
 */
@Injectable({ providedIn: 'root' })
export class ApiService {
  /** Angular's HTTP client, injected rather than constructed so tests can supply a fake. */
  private readonly http = inject(HttpClient);

  /**
   * Builds the headers for an authenticated request.
   *
   * One header, and no credential in it. The credential is an HttpOnly session cookie the browser
   * sends on its own and this application cannot read — which is the whole point: there is nothing here
   * for a script on this page to steal, and nothing in `localStorage` for the next tab to inherit.
   * `SESSION_HEADER` is what proves the request came from this origin rather than from a page that
   * merely caused a browser to make it.
   *
   * A script authenticates with `Authorization: Bearer hsl_…`, minted from the account page. That path
   * deliberately does not exist in this file: a browser that could send one would be a browser that
   * had a bearer token somewhere a script could reach.
   */
  private headers(): HttpHeaders {
    return new HttpHeaders({ [SESSION_HEADER]: '1' });
  }

  /**
   * Exchanges an address and a password for a session.
   *
   * Nothing useful comes back for a client to store: the credential is an HttpOnly cookie the browser
   * keeps and this application cannot read, which is the whole point of the change. The response says
   * who signed in so that the shell can render a name without a second round trip.
   */
  signIn(request: SignInRequest): Observable<SignedIn> {
    return this.http.post<SignedIn>('/api/v1/session', request, { headers: this.headers() });
  }

  /**
   * Ends the session this browser holds.
   *
   * It deletes the row as well as the cookie, which is what makes "sign out" mean the credential stops
   * working rather than merely stops being sent. It is safe to call with no session — an operator whose
   * session expired in another tab still has a cookie to be rid of.
   */
  signOut(): Observable<unknown> {
    return this.http.delete('/api/v1/session', { headers: this.headers() });
  }

  /**
   * Fetches the signed-in account's own record.
   *
   * Separate from whoami, which answers "who does this credential authenticate as" and is what the
   * shell needs before it renders. This is the account behind that answer, and the two differ for one
   * caller: an API token authenticates as an account and cannot reach this at all.
   */
  account(): Observable<Account> {
    return this.http.get<Account>('/api/v1/account', { headers: this.headers() });
  }

  /**
   * Changes the signed-in account's own password.
   *
   * The current one goes with it and is verified server-side, even though the request already carries
   * a session that authenticated: a session is a credential somebody else may be holding, and a
   * password change is the one operation that locks the owner out of their own account.
   */
  changePassword(request: ChangePasswordRequest): Observable<unknown> {
    return this.http.post('/api/v1/account/password', request, { headers: this.headers() });
  }

  /** Lists the browsers this account is signed in on. */
  sessions(): Observable<SessionsResponse> {
    return this.http.get<SessionsResponse>('/api/v1/account/sessions', { headers: this.headers() });
  }

  /**
   * Ends every session this account holds, including the one asking.
   *
   * Including it, deliberately — see the handler. The caller's next move is to forget who it was,
   * because the credential it is holding has just stopped working.
   */
  revokeSessions(): Observable<SessionsRevoked> {
    return this.http.post<SessionsRevoked>('/api/v1/account/sessions/revoke', {}, {
      headers: this.headers(),
    });
  }

  /** Lists this account's API tokens. */
  apiTokens(): Observable<ApiTokensResponse> {
    return this.http.get<ApiTokensResponse>('/api/v1/account/tokens', { headers: this.headers() });
  }

  /**
   * Mints a token acting as this account, returned exactly once.
   *
   * Only its SHA-256 is stored, so the value in the response is the only copy that will ever exist
   * outside whoever wrote it down. The page renders it accordingly.
   */
  createApiToken(request: CreateApiTokenRequest): Observable<IssuedApiToken> {
    return this.http.post<IssuedApiToken>('/api/v1/account/tokens', request, {
      headers: this.headers(),
    });
  }

  /** Revokes one of this account's tokens, which stops it working immediately. */
  revokeApiToken(id: string): Observable<unknown> {
    return this.http.delete(`/api/v1/account/tokens/${encodeURIComponent(id)}`, {
      headers: this.headers(),
    });
  }

  /**
   * Fetches who this credential is and which fleet it acts in.
   *
   * There is no tenant selector to go with it, and that is the design rather than a gap: a credential
   * reaches exactly one fleet, so there is nothing in a request an operator could change to reach
   * another one. This call reports the answer; it does not choose it.
   */
  whoami(): Observable<Whoami> {
    return this.http.get<Whoami>('/api/v1/whoami', { headers: this.headers() });
  }

  /**
   * Fetches every fleet on this installation.
   *
   * Behind the platform credential and refused to an operator, which is the same separation from the
   * other side: a customer's operator must not be able to learn that other customers exist. There is
   * therefore no method here that takes a tenant id from a fleet page — these four are the whole of
   * what the platform interface does, and none of them reaches a fleet's hosts, jobs or results.
   */
  tenants(): Observable<TenantsResponse> {
    return this.http.get<TenantsResponse>('/api/v1/tenants', { headers: this.headers() });
  }

  /**
   * Creates a fleet.
   *
   * It does not also create a credential for it, and cannot: issuing one belongs to whatever
   * authenticates operators, and a route that handed out credentials would make whoever runs the
   * installation able to sign in as any customer. The page says what to run instead.
   */
  createTenant(request: CreateTenantRequest): Observable<Tenant> {
    return this.http.post<Tenant>('/api/v1/tenants', request, { headers: this.headers() });
  }

  /** Changes a fleet's name, approval mode or webhook. Never its slug, which is immutable. */
  updateTenant(id: string, request: UpdateTenantRequest): Observable<Tenant> {
    return this.http.patch<Tenant>(`/api/v1/tenants/${encodeURIComponent(id)}`, request, {
      headers: this.headers(),
    });
  }

  /**
   * Deletes a fleet and everything belonging to it.
   *
   * Hosts, certificates, enrolment tokens, jobs, results and accounts. It does not reach the machines
   * — nothing in HostSeal does — so their agents keep running on their own local policy and are refused
   * at the next request as an unknown certificate.
   */
  deleteTenant(id: string): Observable<unknown> {
    return this.http.delete(`/api/v1/tenants/${encodeURIComponent(id)}`, { headers: this.headers() });
  }

  /** Fetches the fleet. */
  fleet(): Observable<FleetResponse> {
    return this.http.get<FleetResponse>('/api/v1/hosts', { headers: this.headers() });
  }

  /** Fetches one host in full, including its last reported facts, policy and signers. */
  host(id: string): Observable<Host> {
    return this.http.get<Host>(`/api/v1/hosts/${encodeURIComponent(id)}`, {
      headers: this.headers(),
    });
  }

  /**
   * Revokes a host, which is how a machine is released rather than deleted.
   *
   * The control plane authenticates an agent by looking its client certificate's fingerprint up on
   * every request, so removing that certificate *is* the revocation — there is no CRL and nothing to
   * distribute. Two consequences the page has to say out loud: the host stops being able to report,
   * and its machine id stops matching, which is what lets the same machine enrol again. It does not
   * stop the agent, and it does not stop the machine being patched: a revoked host must not silently
   * become an unpatched one.
   */
  revokeHost(id: string): Observable<unknown> {
    return this.http.post(
      `/api/v1/hosts/${encodeURIComponent(id)}/revoke`,
      {},
      { headers: this.headers() },
    );
  }

  /**
   * Fetches the complete intent catalogue this control plane knows.
   *
   * The UI shows it in full, including the permanently refused list, because the claim HostSeal makes is
   * about that set being small and closed — and a claim an operator can check from the running system
   * in one screen is worth more than the same claim in a README.
   */
  catalogue(): Observable<CatalogueResponse> {
    return this.http.get<CatalogueResponse>('/api/v1/catalogue', { headers: this.headers() });
  }

  /**
   * Fetches what an operator needs to enrol a host: the agent URL, the CA path and the APT repository.
   *
   * Read from the control plane rather than assembled in the browser, because the one value that
   * matters — the address an agent connects to — is not the address this page was served from whenever
   * the interface has a hostname of its own. Guessing it would produce instructions that look right
   * and point at the one hostname the agent API is refused on.
   */
  enrolment(): Observable<EnrolmentInstructions> {
    return this.http.get<EnrolmentInstructions>('/api/v1/enrolment', { headers: this.headers() });
  }

  /**
   * Lists every enrolment token minted in this fleet, newest first, without the secrets.
   *
   * The secrets are not withheld by this client; they do not exist to be sent. Only each token's hash
   * is stored, so the listing can say what a token was for and whether it is spent, and nothing more.
   */
  enrolmentTokens(): Observable<EnrolmentTokensResponse> {
    return this.http.get<EnrolmentTokensResponse>('/api/v1/tokens', { headers: this.headers() });
  }

  /**
   * Mints one single-use enrolment token.
   *
   * The token comes back once and is not recoverable: only its SHA-256 is stored, so a database dump
   * does not let its holder enrol hosts. Whatever renders it has to say so at the moment it is shown.
   */
  createEnrolmentToken(request: CreateEnrolmentTokenRequest): Observable<MintedEnrolmentToken> {
    return this.http.post<MintedEnrolmentToken>('/api/v1/tokens', request, {
      headers: this.headers(),
    });
  }

  /** Fetches recent jobs, newest first, optionally narrowed to one host. */
  jobs(hostId?: string): Observable<JobsResponse> {
    const query = hostId ? `?host=${encodeURIComponent(hostId)}` : '';
    return this.http.get<JobsResponse>(`/api/v1/jobs${query}`, { headers: this.headers() });
  }

  /**
   * Fetches the jobs waiting for a second operator, at the largest bound the control plane accepts.
   *
   * It is a separate request rather than a filter over the list above, and that is the point: the list
   * is bounded, so on a busy fleet a destructive job leaves the newest page within a working day. The
   * second operator the approval model depends on would then have no way to find the one thing they
   * exist to look at.
   *
   * The explicit limit is `store.MaxJobLimit`, asked for rather than defaulted because the default is a
   * fifth of it and the ordering is newest first — so a defaulted request past a hundred waiting jobs
   * would drop the oldest, which for an approval queue are exactly the wrong rows to lose. Callers must
   * still read `truncated`: past five hundred the queue no longer fits any request, and that is a fact
   * the operator has to be shown rather than one this client can absorb.
   */
  jobsAwaitingApproval(): Observable<JobsResponse> {
    return this.http.get<JobsResponse>('/api/v1/jobs?awaiting=true&limit=500', {
      headers: this.headers(),
    });
  }

  /**
   * Queues a job the control plane can authorise by itself.
   *
   * That is a read intent, which needs no signature, or the routine one, which the control plane signs
   * with its own key. There is deliberately no method here for a destructive one: such a job carries a
   * signature made offline by a key the control plane does not hold, and a browser is the last place
   * that key should ever be — so the API accepts one and this client cannot produce one, which is the
   * right way round.
   */
  createReadJob(request: CreateReadJobRequest): Observable<Job> {
    return this.http.post<Job>('/api/v1/jobs', request, { headers: this.headers() });
  }

  /**
   * Queues a job that was signed somewhere this control plane cannot reach.
   *
   * The same endpoint as above, and that is the point: what makes a job destructive is not how it was
   * posted but that it carries a signature from a key in the target host's own `trusted-signers`. This
   * method forwards a document produced by `hostseal sign` or by the operator's local signer, field
   * for field — the signature covers the identifier, the host, the intent, the parameters, the window
   * and the nonce, so anything this browser changed on the way through would simply stop verifying on
   * the host.
   *
   * The control plane stores it, applies the fleet's release rule to it, and hands it over. It cannot
   * produce one, which is the whole of docs/SECURITY.md §1's first paragraph.
   */
  createSignedJob(request: SignedJob): Observable<Job> {
    return this.http.post<Job>('/api/v1/jobs', request, { headers: this.headers() });
  }

  /**
   * Records this operator's release of a destructive job.
   *
   * Whether the releaser may be the job's creator depends on the fleet's approval mode, and on the mode
   * as it stood when the job was created rather than now. Under `second_person` this fails for the
   * operator who queued it, and the message the server returns says which setting to change.
   */
  approveJob(id: string): Observable<Job> {
    return this.http.post<Job>(`/api/v1/jobs/${encodeURIComponent(id)}/approve`, null, {
      headers: this.headers(),
    });
  }

  /**
   * Fetches the event inbox, newest first, optionally narrowed to one kind.
   *
   * This is the durable half of the notification design. The live stream tells a tab that happens to
   * be open; this tells the operator asking what they missed overnight, which is the question the
   * whole feature exists for.
   *
   * The kind is filtered here rather than in the browser, and the difference is not efficiency: the
   * in-memory feed holds the newest two hundred events, so sieving it for a kind could only ever
   * answer about the newest two hundred — and reported "nothing of this kind has happened" about
   * kinds that had simply been pushed off the end.
   *
   * The limit is the caller's for the same reason `jobsAwaitingApproval` names one: the server's
   * default is a tenth of the inbox and is right for "what is new", while a narrowed read is the
   * request that wants depth. `store.MaxEventLimit` is the ceiling the control plane enforces.
   */
  events(kind?: string, limit?: number): Observable<EventsResponse> {
    const query = new URLSearchParams();
    if (kind) {
      query.set('kind', kind);
    }
    if (limit) {
      query.set('limit', String(limit));
    }
    const suffix = query.toString();
    return this.http.get<EventsResponse>(`/api/v1/events${suffix ? `?${suffix}` : ''}`, {
      headers: this.headers(),
    });
  }

  /** Fetches every host with a failed unit, without opening hosts one at a time. */
  failedServices(): Observable<FailedServicesResponse> {
    return this.http.get<FailedServicesResponse>('/api/v1/services/failed', {
      headers: this.headers(),
    });
  }

  /** Fetches one host's unit-state history, which is what makes "flapping since Tuesday" visible. */
  serviceHistory(hostId: string): Observable<ServiceHistoryResponse> {
    return this.http.get<ServiceHistoryResponse>(
      `/api/v1/hosts/${encodeURIComponent(hostId)}/services/history`,
      { headers: this.headers() },
    );
  }

  /** Fetches this fleet's alerting rules. */
  alertRules(): Observable<AlertRulesResponse> {
    return this.http.get<AlertRulesResponse>('/api/v1/alerts', { headers: this.headers() });
  }

  /** Creates an alerting rule. */
  createAlertRule(request: AlertRuleRequest): Observable<unknown> {
    return this.http.post('/api/v1/alerts', request, { headers: this.headers() });
  }

  /** Changes a rule's threshold, cooldown, recipients or enabled flag. Never its condition. */
  updateAlertRule(id: string, request: AlertRuleRequest): Observable<unknown> {
    return this.http.patch(`/api/v1/alerts/${encodeURIComponent(id)}`, request, {
      headers: this.headers(),
    });
  }

  /** Deletes a rule and the firing state it accumulated. */
  deleteAlertRule(id: string): Observable<unknown> {
    return this.http.delete(`/api/v1/alerts/${encodeURIComponent(id)}`, { headers: this.headers() });
  }

  /**
   * Fetches one summary per provisioning template.
   *
   * Archived templates are left out unless asked for. Hidden by default because that is what
   * retiring one was for; askable because a name nobody can list is a name nobody can restore.
   */
  templates(includeArchived = false): Observable<TemplatesResponse> {
    const query = includeArchived ? '?include=archived' : '';
    return this.http.get<TemplatesResponse>(`/api/v1/templates${query}`, {
      headers: this.headers(),
    });
  }

  /**
   * Withdraws a template name from use, leaving every stored version readable.
   *
   * This is the page's delete button, and the difference from a delete is the reason it can exist at
   * all: nothing is destroyed, so a host's bootstrap record still resolves to the bytes that ran.
   * What changes is what the name may still be used for — new versions, renders, enrolment tokens
   * and enrolments are refused until it is restored.
   */
  archiveTemplate(name: string): Observable<TemplateArchivalResult> {
    return this.http.post<TemplateArchivalResult>(
      `/api/v1/templates/${encodeURIComponent(name)}/archive`,
      {},
      { headers: this.headers() },
    );
  }

  /**
   * Puts an archived template name back into use.
   *
   * It grants nothing the name did not already have: a restored template is issuable at enrolment
   * only under the conditions that governed it before, signature included.
   */
  restoreTemplate(name: string): Observable<TemplateArchivalResult> {
    return this.http.post<TemplateArchivalResult>(
      `/api/v1/templates/${encodeURIComponent(name)}/restore`,
      {},
      { headers: this.headers() },
    );
  }

  /** Fetches one version of a template in full, defaulting to the latest. */
  template(name: string, version?: number): Observable<TemplateVersion> {
    const query = version ? `?version=${version}` : '';
    return this.http.get<TemplateVersion>(
      `/api/v1/templates/${encodeURIComponent(name)}${query}`,
      { headers: this.headers() },
    );
  }

  /**
   * Fetches every stored revision of one template, newest first.
   *
   * Separate from reading a version because the two differ in what they carry: this one is a history
   * with no bodies in it, which is what lets a page show that version 3 exists and who stored it
   * without pulling three sealed documents a reader did not ask for.
   */
  templateVersions(name: string): Observable<TemplateVersionsResponse> {
    return this.http.get<TemplateVersionsResponse>(
      `/api/v1/templates/${encodeURIComponent(name)}/versions`,
      { headers: this.headers() },
    );
  }

  /**
   * Stores the next version of a template.
   *
   * There is no update method and no delete, which is the storage model rather than an omission: a
   * host's bootstrap record names a version and must resolve to the bytes that actually ran. What a
   * retirement looks like instead is `archiveTemplate` above.
   */
  createTemplate(request: CreateTemplateRequest): Observable<StoredTemplateVersion> {
    return this.http.post<StoredTemplateVersion>('/api/v1/templates', request, {
      headers: this.headers(),
    });
  }

  /**
   * Renders a template to user-data.
   *
   * The response is a credential — it usually carries a freshly minted enrolment token — so it is
   * shown once and nothing stores it, here or on the server. There is deliberately no method that
   * would *deliver* the result to a host: HostSeal is not in the delivery path, and a control that
   * implied otherwise would be Tier 3, which is never built.
   */
  renderTemplate(name: string, request: RenderTemplateRequest): Observable<RenderedTemplate> {
    return this.http.post<RenderedTemplate>(
      `/api/v1/templates/${encodeURIComponent(name)}/render`,
      request,
      { headers: this.headers() },
    );
  }

  /**
   * Fetches one screen of this fleet's state, for an operator.
   *
   * The same builder answers the public route, so what an operator sees here is exactly what a
   * television shows — which is what makes it possible to check a share without holding one.
   */
  wallboard(): Observable<WallboardView> {
    return this.http.get<WallboardView>('/api/v1/wallboard', { headers: this.headers() });
  }

  /** Lists the links this fleet has published, expired ones included so a dark screen is explicable. */
  wallboardShares(): Observable<WallboardSharesResponse> {
    return this.http.get<WallboardSharesResponse>('/api/v1/wallboard/shares', {
      headers: this.headers(),
    });
  }

  /**
   * Publishes a link, returned exactly once.
   *
   * Only the key's SHA-256 is stored, so the `link` in the response is the one copy that will ever
   * exist outside whoever writes it down. Whatever renders it says so at the moment it is shown.
   */
  createWallboardShare(
    request: CreateWallboardShareRequest,
  ): Observable<CreateWallboardShareResponse> {
    return this.http.post<CreateWallboardShareResponse>('/api/v1/wallboard/shares', request, {
      headers: this.headers(),
    });
  }

  /** Withdraws a link. Every screen holding it goes dark at its next poll, because the row is read. */
  deleteWallboardShare(id: string): Observable<unknown> {
    return this.http.delete(`/api/v1/wallboard/shares/${encodeURIComponent(id)}`, {
      headers: this.headers(),
    });
  }

  /**
   * Fetches the same screen with a share key rather than a session.
   *
   * `SESSION_HEADER` is deliberately absent, and that is the whole point of these two methods rather
   * than a saving. The control plane refuses a cookie-authenticated request without that header, so
   * omitting it means the session cookie a signed-in operator's browser sends anyway cannot
   * authenticate this request: the share key is the only credential that can, and `/board` therefore
   * shows an operator precisely what it shows a television. A page that answered differently
   * depending on who opened it would be a page nobody could check before hanging it on a wall.
   *
   * The key goes in a header rather than the URL because it lives in the address's fragment, which is
   * never transmitted — so it is absent from the control plane's access log, from any proxy's, and
   * from `Referer`. Putting it back into a path would undo that in one line.
   */
  publicWallboard(key: string): Observable<WallboardView> {
    return this.http.get<WallboardView>('/api/v1/wallboard/public', {
      headers: this.bearer(key),
    });
  }

  /**
   * Proves a share's passphrase once, in exchange for a cookie the poll can carry cheaply.
   *
   * Once, because a wallboard cannot re-derive Argon2id every fifteen seconds — one derivation
   * allocates 64 MiB and at most four run at once, so a handful of screens would be the whole sign-in
   * path's memory budget. What comes back is a `Set-Cookie` this application never reads: it is
   * HttpOnly, and the browser attaches it to the poll on its own.
   */
  unlockWallboard(key: string, passphrase: string): Observable<unknown> {
    return this.http.post(
      '/api/v1/wallboard/public/unlock',
      { passphrase },
      { headers: this.bearer(key) },
    );
  }

  /**
   * Builds the headers for a request authenticated by a share key.
   *
   * Its own builder rather than an argument to `headers()`, so that the absence of `SESSION_HEADER`
   * on the two public routes is visible in one place and cannot be restored by somebody tidying a
   * call site. See `publicWallboard` for why its absence is load-bearing.
   */
  private bearer(key: string): HttpHeaders {
    return new HttpHeaders({ Authorization: `Bearer ${key}` });
  }
}
