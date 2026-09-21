import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

import { SignedJob } from './api.models';

/**
 * Where a HostSeal signer listens on the operator's own machine.
 *
 * Loopback and a fixed port, because the whole arrangement depends on this page being able to find
 * the signer without the control plane holding any configuration about anybody's laptop. The number is
 * `internal/localsign`'s `DefaultAddr` — 18515 is 0x4853, the bytes "HS" — and the two are documented
 * together in docs/INSTALL.md. An operator who moves it with `--addr` has to say so in both places,
 * which is why the default exists at all.
 *
 * `127.0.0.1` rather than `localhost`: a browser resolving `localhost` may reach ::1, and a signer
 * bound to the IPv4 loopback would then be unreachable from a page that looks correct.
 */
export const LOCAL_SIGNER_URL = 'http://127.0.0.1:18515';

/** What a running signer says about itself. */
export interface LocalSignerStatus {
  /** A fixed marker, so this page can tell a HostSeal signer from anything else on the port. */
  signer: string;

  /** The signer's build. */
  version: string;

  /** The identity a host's `trusted-signers` must list for this key. */
  keyId: string;

  /** `ed25519` or `ecdsa-p256`. */
  algorithm: string;

  /** How the key is held — `pkcs11` for a token, `file` for a key file. */
  backend: string;

  /** The line to paste into `/etc/hostseal/trusted-signers` on the hosts this key may act on. */
  trustedSignerLine: string;
}

/**
 * A detached signature over one template, as the signer hands it back.
 *
 * The three fields are exactly what `POST /api/v1/templates` takes beside the name and the body, so
 * this page forwards what it was given rather than rearranging it — there is nothing here to get
 * subtly wrong, which is the point.
 */
export interface LocalSignature {
  /** The template that was signed, echoed so a caller can check it is about what it asked. */
  name: string;

  /** The detached signature, base64. */
  signature: string;

  /** The key that made it. */
  signerKeyId: string;

  /** The algorithm it was made with. */
  signerAlgorithm: string;
}

/**
 * What a browser asks to have signed as a job.
 *
 * Three fields that describe an operation and one that bounds it, and deliberately nothing else. The
 * job's identifier, its nonce and both edges of its validity window are chosen by the signer: a caller
 * that could choose a nonce could replay a signature a host had already spent, and one that could
 * choose a window could ask for a reboot that stays valid for a year.
 */
export interface SignJobRequest {
  /** The host to act on. The signature covers it, so it binds the job to one machine. */
  hostId: string;

  /** The catalogue member, such as `host.reboot`. */
  intent: string;

  /** The parameter object, as the catalogue's own decoder will read it. */
  params: Record<string, unknown>;

  /** How long the signature stays valid, omitted for the signer's default of an hour. */
  validForSeconds?: number;
}

/**
 * Talks to the HostSeal signer running on the operator's own machine.
 *
 * It is a separate service from `ApiService` and deliberately so: everything that class talks to is
 * the control plane, and this is the one thing in the application that talks to something the control
 * plane does not run, cannot reach and must never be able to impersonate.
 *
 * What crosses this boundary is worth being explicit about, because the value of the whole arrangement
 * is in what does not. Out goes a template's name and body — the two fields the signature covers, in
 * plaintext, from this page. Back comes a detached signature, a key id and an algorithm. The private
 * key stays on the token: this page never sees it, the control plane never sees it, and a browser is
 * the last place it should ever be.
 *
 * The signer builds the signed payload itself out of the name and the body, and there is no way to ask
 * it to sign anything else. That is the property that lets a page in a browser be part of this at all:
 * even a control plane that served a malicious version of this application could only ask for a
 * signature over a template whose full text is printed in a terminal on the operator's machine, where
 * a human answers yes or no before the token is touched.
 */
@Injectable({ providedIn: 'root' })
export class LocalSignerService {
  /** Angular's HTTP client, injected rather than constructed so tests can supply a fake. */
  private readonly http = inject(HttpClient);

  /**
   * Asks whether a signer is running here, and whose key it holds.
   *
   * Called when an operator asks to sign rather than on every page load. A page that probed a loopback
   * port unprompted would put a failed request in the console of every operator who does not use a
   * token, which is how people learn to ignore console errors.
   */
  status(): Observable<LocalSignerStatus> {
    return this.http.get<LocalSignerStatus>(`${LOCAL_SIGNER_URL}/v1/signer`);
  }

  /**
   * Asks for a signature over one template.
   *
   * The request blocks for as long as the operator takes to read the body in their signer's terminal,
   * answer it, and touch their token — which is a long time by the standards of everything else this
   * application does, and is the feature rather than a cost.
   */
  signTemplate(name: string, body: string): Observable<LocalSignature> {
    return this.http.post<LocalSignature>(`${LOCAL_SIGNER_URL}/v1/sign-template`, { name, body });
  }

  /**
   * Asks for a signature over one destructive job.
   *
   * What goes out is which host, which operation and which parameters. What comes back is a complete
   * signed job request, with an identifier, a nonce and a validity window the signer chose — the
   * browser cannot choose any of those, and the signer refuses a request that tries to.
   *
   * The signer decodes the parameters against its own compiled-in catalogue and prints what the
   * operation *means* in its terminal — "reboot 01J… in 60 seconds", not a JSON object — before
   * anybody is asked. That is what makes this safe to drive from a page a compromised control plane
   * could have served.
   */
  signJob(request: SignJobRequest): Observable<SignedJob> {
    return this.http.post<SignedJob>(`${LOCAL_SIGNER_URL}/v1/sign-job`, request);
  }
}

/**
 * The shape of a refusal from the signer, which is the control plane's own problem-document shape.
 *
 * Deliberately the same: the signer writes its refusals in the shape `internal/protocol` defines, so
 * that one kind of failure in this application does not need two kinds of reader. It is declared here
 * rather than shared with `errors.ts` because the two describe different machines, and a type used by
 * both would be an invitation to write one function for both — which is exactly what the wording
 * below exists not to be.
 */
interface SignerFailure {
  /** The HTTP status, or 0 when the request never reached anything. */
  status?: number;

  /** The refusal the signer wrote, when it got far enough to write one. */
  error?: SignerProblem;
}

/** A refusal from the signer. */
interface SignerProblem {
  /** A stable machine-readable code, such as `declined`. */
  error?: string;

  /** Human-readable text, written for whoever is reading it during a task. */
  message?: string;
}

/**
 * Turns a failure from the local signer into something an operator can act on.
 *
 * Separate from `describeError`, which speaks for the control plane, because every sentence here is
 * about a different machine: "could not be reached" means the operator's own laptop is not running the
 * command, and the useful response is the command rather than an apology. The `origin` is threaded
 * through because it is the one part of that command nobody can guess — it is the address of the
 * control plane this page was served from, and the signer refuses to sign for any origin it was not
 * told about.
 */
export function describeSignerError(err: unknown, origin: string): string {
  const carrier = err as SignerFailure | null;
  const status = carrier?.status;
  if (status === 0 || status === undefined) {
    return (
      `No HostSeal signer answered on ${LOCAL_SIGNER_URL}. Start one on the machine your token is ` +
      `plugged into, and tell it this address:\n\n` +
      `  hostseal signer --key "pkcs11:token=ops;object=ops-yubikey-1?module-path=<your PKCS#11 module>" \\\n` +
      `      --origin ${origin}\n\n` +
      `On Windows the module is Yubico's libykcs11.dll, installed with the YubiKey Manager or the ` +
      `PIV Tool; on Linux it is your token's PKCS#11 library. Adding --install to that command on ` +
      `Windows registers it to start at your next logon, in your own session. If the signer is ` +
      `running, check that ` +
      `it was started with --origin ${origin} — it signs only for the addresses it was told about.`
    );
  }
  if (status === 403 && carrier?.error?.error === 'declined') {
    return 'The signature was declined at the signer\'s own terminal. Nothing was stored.';
  }
  const message = carrier?.error?.message;
  return message ? message : `The local signer returned ${status}.`;
}
