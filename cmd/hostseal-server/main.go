// Command hostseal-server is the HostSeal control plane.
//
// It is a single binary with the Angular application embedded, plus PostgreSQL. That is a deliberate
// packaging decision rather than a limitation: open-source software is installed by strangers who close
// the tab on friction, and a four-service Compose stack is friction. Sharing Go with the agent also
// means the intent catalogue and the signature verifier are literally the same code on both sides,
// rather than two implementations that agree until they do not.
//
// The server can ask a host for work. It cannot make a host do anything that host's own
// /etc/hostseal/policy.toml forbids, and it holds no key that authorises a destructive operation. See
// docs/SECURITY.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pascalgross/hostseal/internal/auth"
	"github.com/pascalgross/hostseal/internal/buildinfo"
	"github.com/pascalgross/hostseal/internal/ca"
	"github.com/pascalgross/hostseal/internal/intent"
	"github.com/pascalgross/hostseal/internal/notify"
	"github.com/pascalgross/hostseal/internal/onlinekey"
	"github.com/pascalgross/hostseal/internal/seal"
	"github.com/pascalgross/hostseal/internal/server"
	"github.com/pascalgross/hostseal/internal/store"
)

// usage prints the command list.
func usage() {
	fmt.Fprintf(os.Stderr, `hostseal-server %s

usage:
  hostseal-server serve       run the control plane
  hostseal-server ca init     create the private CA that issues agent certificates
  hostseal-server accounts    create and manage the accounts operators sign in with
  hostseal-server catalogue   print the intent catalogue this build knows
  hostseal-server version     print the version

Run "hostseal-server serve --help" for its options.
`, buildinfo.String())
}

// main dispatches to a subcommand.
func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "serve":
		os.Exit(serve(args[1:]))
	case "ca":
		os.Exit(caCommand(args[1:]))
	case "accounts":
		os.Exit(accountsCommand(args[1:]))
	case "catalogue":
		printCatalogue()
	case "version":
		fmt.Println("hostseal-server " + buildinfo.String())
	default:
		fmt.Fprintf(os.Stderr, "hostseal-server: unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
}

// setupLogging configures structured logging to stderr, which systemd routes to the journal.
func setupLogging() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "server", "version", buildinfo.Version))
}

// serve runs the control plane until it is signalled to stop.
func serve(argv []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8443", "listen address")
	caDir := fs.String("ca-dir", "/var/lib/hostseal-server/ca", "directory holding the agent CA")
	dsn := fs.String("database", envOr("HOSTSEAL_DATABASE_URL", ""),
		"PostgreSQL connection URL, or the literal \"memory\" for a throwaway in-process store")
	tlsCert := fs.String("tls-cert", "", "PEM certificate for this server's own HTTPS identity")
	tlsKey := fs.String("tls-key", "", "PEM key for this server's own HTTPS identity")
	tlsServerName := fs.String("tls-server-name", envOr("HOSTSEAL_TLS_SERVER_NAME", ""),
		"additional DNS name for the automatically issued server certificate")
	agentURL := fs.String("agent-url", envOr("HOSTSEAL_AGENT_URL", ""),
		"the base URL agents reach this control plane at, shown in the enrolment instructions. "+
			"It is not derived from the request, because the interface may be served on a second "+
			"hostname that deliberately refuses the agent API; unset means the instructions show the "+
			"address the browser is using and say it may be the wrong one")
	tenantSlug := fs.String("tenant", envOr("HOSTSEAL_TENANT", "default"),
		"the fleet this control plane serves; created on first start if it does not exist")
	bootstrapEmail := fs.String("bootstrap-email", envOr("HOSTSEAL_BOOTSTRAP_EMAIL", "admin@localhost"),
		"address of the account created when the database holds none; change it afterwards with "+
			"`hostseal-server accounts`")
	bootstrapPasswordFile := fs.String("bootstrap-password-file", "",
		"file holding the first account's password; a file rather than a flag, because argv is "+
			"world-readable in ps. HOSTSEAL_BOOTSTRAP_PASSWORD is read when this is unset, and one is "+
			"generated and printed once when neither is given")
	webhook := fs.String("webhook", "",
		"URL to POST this tenant's events to; sinks send data out and nothing sends code in")
	heartbeat := fs.Int("heartbeat-seconds", 60, "pacing handed to agents, which they clamp to 15..3600")
	smtpHost := fs.String("smtp-host", envOr("HOSTSEAL_SMTP_HOST", ""),
		"mail relay for alert rules; unset means alert mail is off and every other delivery still works")
	smtpPort := fs.Int("smtp-port", 587, "465 for implicit TLS, anything else upgrades with STARTTLS")
	smtpFrom := fs.String("smtp-from", envOr("HOSTSEAL_SMTP_FROM", ""),
		"sender address for alert mail")
	smtpUser := fs.String("smtp-username", envOr("HOSTSEAL_SMTP_USERNAME", ""),
		"relay credential, empty for an open relay on a trusted network")
	smtpPasswordFile := fs.String("smtp-password-file", "",
		"file holding the relay password; a file rather than a flag, because argv is world-readable "+
			"in ps. HOSTSEAL_SMTP_PASSWORD is read when this is unset")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	setupLogging()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	authority, err := ca.Load(*caDir)
	if errors.Is(err, ca.ErrNotInitialised) {
		fmt.Fprintf(os.Stderr, "hostseal-server: no certificate authority in %s.\n"+
			"Run: hostseal-server ca init --ca-dir %s\n", *caDir, *caDir)
		return 1
	}
	if err != nil {
		slog.Error("could not load the certificate authority", "error", err)
		return 1
	}

	backing, err := openStore(ctx, *dsn)
	if err != nil {
		slog.Error("could not open the store", "error", err)
		return 1
	}
	defer func() { _ = backing.Close() }()

	if err := backing.Migrate(ctx); err != nil {
		slog.Error("could not migrate the database", "error", err)
		return 1
	}

	// Whether the boundary this installation claims is actually there.
	//
	// Tenant isolation is PostgreSQL row-level security, and a connection made as a superuser or as a
	// role with BYPASSRLS ignores every policy in the schema. That is not a degraded mode, it is no
	// isolation at all, and nothing about the running system would look different — so this refuses to
	// start rather than serving many customers out of one database with the wall switched off.
	if err := requireRowLevelSecurity(ctx, backing, *dsn); err != nil {
		slog.Error("refusing to start", "error", err)
		return 1
	}

	tenant, err := ensureTenant(ctx, backing, *tenantSlug, *webhook)
	if err != nil {
		slog.Error("could not prepare the tenant", "error", err)
		return 1
	}

	// Somebody to sign in as, if the database holds nobody.
	//
	// A control plane that came up with no way in is one that gets abandoned or made reachable in a
	// hurry, and the second is much worse than the first. So the first start creates an account, in the
	// fleet this process serves, and says what its password is exactly once.
	if err := bootstrapAccount(ctx, backing, tenant, *bootstrapEmail, *bootstrapPasswordFile); err != nil {
		slog.Error("could not create the first account", "error", err)
		return 1
	}

	// Two providers, and between them everything that authenticates a person.
	//
	// There used to be a third and a fourth: one shared bearer token per fleet and one for the
	// installation, both held in a flag. They are gone, and nothing replaces them in that shape — a
	// credential that names nobody in the audit trail, makes second-person approval a comparison of a
	// string with itself, never expires, and is withdrawn by restarting the control plane is not
	// something an installation should have to be careful with. What a script needs instead is an API
	// token belonging to an account, which is revoked from a page in a second.
	//
	// Both are always configured, because there is nothing to configure: the credentials are rows. An
	// installation with no accounts simply has two providers that recognise nobody, which is not the
	// same as a feature being off — somebody who runs `hostseal-server accounts add` must not also have
	// to restart the control plane before the account works.
	//
	// auth.Chain asks every member, so the order is readability and nothing else: a cookie cannot be
	// shadowed by the provider that looks at headers, or the other way round.
	accounts := auth.NewAccounts(backing, auth.DefaultSessionTTL, auth.DefaultSessionMaxAge)
	provider := auth.Chain(accounts, auth.NewAPITokens(backing))

	// The key that signs routine jobs. Beside the CA, generated on first start, and its public half is
	// handed to every agent at enrolment and on every heartbeat. It authorises one tier and cannot
	// authorise the destructive one: an agent verifies those against its own trusted-signers, which
	// this process cannot write. See docs/SECURITY.md §3.
	online, err := onlinekey.Ensure(*caDir)
	if err != nil {
		slog.Error("could not prepare the online signing key", "error", err)
		return 1
	}
	slog.Info("routine jobs will be signed by this control plane", "key", online.KeyID())

	// The key that seals template bodies at rest. Beside the CA for the same reason the online key is:
	// both are things a database backup must not yield, and both are backed up by the same operator
	// with the same care. Losing it makes every stored template unreadable, which docs/INSTALL.md says
	// in the section on backing up the CA directory.
	templateKey, err := seal.Ensure(*caDir)
	if err != nil {
		slog.Error("could not prepare the template sealing key", "error", err)
		return 1
	}

	// Client certificates require TLS, so a control plane with no certificate cannot serve the agent
	// protocol at all. Rather than starting something that refuses every agent with a 401, one is
	// issued from the same private CA — which means an enrolled agent, holding the CA bundle it was
	// given, verifies the control plane with no further configuration.
	if *tlsCert == "" || *tlsKey == "" {
		dnsNames := tlsNames(*addr)
		if name := strings.TrimSpace(*tlsServerName); name != "" {
			dnsNames = append(dnsNames, name)
		}
		issuedCert, issuedKey, certErr := authority.EnsureServerCertificate(*caDir, dnsNames, nil)
		if certErr != nil {
			slog.Error("could not issue a server certificate", "error", certErr)
			return 1
		}
		*tlsCert, *tlsKey = issuedCert, issuedKey
		slog.Warn("serving with a certificate issued by HostSeal's own CA. Enrolled agents trust it "+
			"automatically; browsers will not. Pass --tls-cert and --tls-key from whatever issues your "+
			"public certificates before operators use this in earnest.",
			"certificate", issuedCert,
			"enrol_with", "hostseal enroll --ca "+filepath.Join(*caDir, "ca.crt"))
	}

	smtp, err := smtpConfig(*smtpHost, *smtpPort, *smtpFrom, *smtpUser, *smtpPasswordFile)
	if err != nil {
		slog.Error("could not configure alert mail", "error", err)
		return 1
	}

	srv, err := server.New(server.Config{
		Addr:             *addr,
		TLSCert:          *tlsCert,
		TLSKey:           *tlsKey,
		Authority:        authority,
		Store:            backing,
		Auth:             provider,
		Accounts:         accounts,
		OnlineKey:        online,
		TemplateKey:      templateKey,
		HeartbeatSeconds: *heartbeat,
		TokenTTL:         24 * time.Hour,
		SMTP:             smtp,
		AgentURL:         *agentURL,
	})
	if err != nil {
		slog.Error("could not build the server", "error", err)
		return 1
	}

	// The evaluator shares the process for the same reason the UI does: one binary plus PostgreSQL is
	// the entire deployment. It stops with the same context the listener stops with.
	go srv.RunAlertEvaluator(ctx)

	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("the server stopped with an error", "error", err)
		return 1
	}
	return 0
}

// smtpConfig assembles the relay configuration for alert mail.
//
// The password comes from a file or from the environment and never from a flag, because argv is
// world-readable in ps and shows up in shell history — the same reasoning as the admin token, applied
// to a credential that reaches somebody else's infrastructure.
func smtpConfig(host string, port int, from, username, passwordFile string) (notify.SMTPConfig, error) {
	cfg := notify.SMTPConfig{Host: host, Port: port, From: from, Username: username}
	if host == "" {
		return notify.SMTPConfig{}, nil
	}
	if from == "" {
		return notify.SMTPConfig{}, errors.New("--smtp-host is set and --smtp-from is not; alert " +
			"mail needs a sender address")
	}
	switch {
	case passwordFile != "":
		raw, err := os.ReadFile(passwordFile)
		if err != nil {
			return notify.SMTPConfig{}, fmt.Errorf("reading %s: %w", passwordFile, err)
		}
		cfg.Password = strings.TrimSpace(string(raw))
	default:
		cfg.Password = os.Getenv("HOSTSEAL_SMTP_PASSWORD")
	}
	slog.Info("alert mail is configured", "relay", host, "port", port, "from", from)
	return cfg, nil
}

// bootstrapAccount creates the first account when the installation has none, and says so once.
//
// It runs on every start and does nothing on all but the first, and the condition is "this fleet has no
// accounts" rather than a marker file or a flag. That is deliberate: a marker is state that can be lost
// or copied, and an installation restored from a database backup would either be locked out or handed a
// second administrator depending on which way the marker went. The accounts table is the truth.
//
// The account belongs to the fleet this process serves rather than to the installation, because the
// first thing anybody does with a new control plane is enrol a host — and a platform administrator,
// who by construction cannot read any fleet's hosts, would have nothing to look at. Whoever needs to
// create further fleets adds one with `hostseal-server accounts add --platform`, which is the same shape
// the optional platform token had.
//
// The password comes from a file, or from the environment, or is generated. Never from a flag: argv is
// world-readable in ps, which is the same reason --smtp-password-file is a file.
func bootstrapAccount(ctx context.Context, backing store.Store, tenant store.Tenant, email, passwordFile string) error {
	scope := backing.In(tenant.ID)
	existing, err := scope.ListAccounts(ctx)
	if err != nil {
		return fmt.Errorf("reading the account list: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}

	password, generated, err := bootstrapPassword(passwordFile)
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hashing the first password: %w", err)
	}
	id, err := server.NewID()
	if err != nil {
		return fmt.Errorf("allocating an account id: %w", err)
	}

	address := auth.NormaliseEmail(email)
	err = scope.CreateAccount(ctx, store.Account{
		ID:           id,
		Email:        address,
		EmailKey:     auth.EmailKey(address),
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	})
	if errors.Is(err, store.ErrConflict) {
		// The address belongs to an account somewhere else on this installation — most likely a
		// platform administrator created before the first fleet. Not a failure to start: this fleet
		// still has nobody, and saying which flag fixes it is more use than refusing to serve.
		slog.Warn("no account in this fleet, and the bootstrap address is taken elsewhere",
			"email", address, "fix", "hostseal-server accounts add --tenant "+tenant.Slug+" --email …")
		return nil
	}
	if err != nil {
		return fmt.Errorf("creating the first account: %w", err)
	}

	if !generated {
		slog.Info("created the first account", "email", address, "tenant", tenant.Slug)
		return nil
	}
	// Printed to stderr rather than logged, and printed exactly once. A password in a structured log
	// line is a password in whatever collects them, and this one is meant to be read by the person
	// watching the first start and then changed.
	fmt.Fprintf(os.Stderr, "\nThis control plane had no accounts, so one has been created.\n\n"+
		"  address:  %s\n  password: %s\n\n"+
		"It is stored only as an Argon2id hash and will not be printed again. Change it from the\n"+
		"account page after signing in, or with `hostseal-server accounts passwd`.\n\n", address, password)
	return nil
}

// bootstrapPassword returns the first account's password and whether it had to be invented.
//
// Three sources, in the order somebody would expect: a file named on the command line, the environment
// — which is what a Compose file sets — and failing both, thirty-two bytes of randomness. The last is
// the case that has to print, which is why the caller is told which happened.
func bootstrapPassword(passwordFile string) (string, bool, error) {
	if passwordFile != "" {
		raw, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", false, fmt.Errorf("reading %s: %w", passwordFile, err)
		}
		if password := strings.TrimSpace(string(raw)); password != "" {
			return password, false, nil
		}
		return "", false, fmt.Errorf("%s is empty", passwordFile)
	}
	if password := strings.TrimSpace(os.Getenv("HOSTSEAL_BOOTSTRAP_PASSWORD")); password != "" {
		return password, false, nil
	}
	password, err := auth.GeneratePassword()
	if err != nil {
		return "", false, fmt.Errorf("generating a password: %w", err)
	}
	return password, true, nil
}

// requireRowLevelSecurity refuses to start when the database role can see through the tenant boundary.
//
// Isolation between tenants is row-level security, and PostgreSQL exempts two kinds of role from every
// policy: a superuser, and a role with BYPASSRLS. Connecting as either does not weaken the boundary,
// it removes it — every query returns every tenant's rows — and nothing about the running system would
// look wrong. A control plane that served several customers from one database in that state would be
// discovered by a customer, so this is a refusal rather than a warning.
//
// The in-memory store has no roles and enforces the same scoping in Go, so it is exempt from the check
// rather than from the rule.
func requireRowLevelSecurity(ctx context.Context, backing store.Store, dsn string) error {
	pg, ok := backing.(*store.Postgres)
	if !ok {
		return nil
	}
	role, superuser, bypass, err := pg.ConnectionRole(ctx)
	if err != nil {
		return fmt.Errorf("could not check the database role's privileges: %w", err)
	}
	if !superuser && !bypass {
		slog.Info("tenant isolation is enforced by the database", "role", role)
		return nil
	}

	why := "is a superuser"
	if !superuser {
		why = "has BYPASSRLS"
	}
	return fmt.Errorf(
		"the database role %q %s, so PostgreSQL applies no row-level security policy to it and "+
			"tenants are not isolated from one another. Connect as an ordinary role that owns the "+
			"schema: CREATE ROLE hostseal LOGIN PASSWORD '…'; GRANT ALL ON DATABASE … TO hostseal; "+
			"and point --database at it (currently %s)",
		role, why, redactDSN(dsn))
}

// redactDSN removes the password from a connection URL so it can go in an error message.
//
// The message this appears in is one somebody will paste into an issue, and a connection string is the
// single most likely secret in a control plane's configuration.
func redactDSN(dsn string) string {
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.User == nil {
		return dsn
	}
	if _, hasPassword := parsed.User.Password(); hasPassword {
		parsed.User = url.UserPassword(parsed.User.Username(), "…")
	}
	return parsed.String()
}

// ensureTenant finds the tenant this server's operator credential acts in, creating it if it is new.
//
// A single-fleet installation should not have to know that tenants exist: it starts the binary, gets a
// token, and has a fleet. So the named tenant is created on first start and found on every start after
// that, and an installation that never passes --tenant simply always uses "default" — which is also the
// tenant migration 0004 assigns every pre-existing row to, so upgrading changes nothing.
func ensureTenant(ctx context.Context, backing store.Store, slug, webhook string) (store.Tenant, error) {
	tenants, err := backing.ListTenants(ctx)
	if err != nil {
		return store.Tenant{}, fmt.Errorf("reading the tenant list: %w", err)
	}
	for _, t := range tenants {
		if t.Slug != slug {
			continue
		}
		// The webhook flag is applied on every start, because it is how a single-fleet installation
		// configures one at all. On a hosted installation the flag is left unset and the platform API
		// is where a tenant's endpoint is set, so an unset flag must not clear what is stored.
		if webhook != "" && webhook != t.WebhookURL {
			// The webhook and nothing else. On a hosted installation this runs at every start while a
			// platform operator may be editing the same row, and writing back the whole tenant would
			// undo their change with values this process read at boot.
			updated, err := backing.UpdateTenant(ctx, t.ID, store.TenantPatch{WebhookURL: &webhook})
			if err != nil {
				return store.Tenant{}, fmt.Errorf("recording the tenant's webhook: %w", err)
			}
			return updated, nil
		}
		return t, nil
	}

	id, err := server.NewID()
	if err != nil {
		return store.Tenant{}, fmt.Errorf("allocating a tenant id: %w", err)
	}
	tenant := store.Tenant{
		ID:          store.TenantID(id),
		Slug:        slug,
		DisplayName: slug,
		CreatedAt:   time.Now().UTC(),
		// A new fleet releases destructive jobs on the strength of their offline signature alone. That
		// signature is what docs/SECURITY.md §1 rests on; approval is a control-plane control on top of
		// it, and defaulting to one that a single operator cannot satisfy would ship a tier nobody
		// could reach. Turn it on per tenant when there is a second person to turn it on for.
		ApprovalMode: store.ApprovalNone,
		WebhookURL:   webhook,
	}
	if err := backing.CreateTenant(ctx, tenant); err != nil {
		return store.Tenant{}, fmt.Errorf("creating tenant %q: %w", slug, err)
	}
	slog.Info("created a tenant", "tenant", tenant.ID, "slug", slug)
	return tenant, nil
}

// openStore connects to the configured backing store.
//
// PostgreSQL is the only supported backend. The memory option exists for a demonstration and for the
// integration harness, and it says so loudly every time, because a control plane that silently lost its
// fleet on restart would be discovered at the worst possible moment.
func openStore(ctx context.Context, dsn string) (store.Store, error) {
	switch dsn {
	case "":
		return nil, errors.New("a database URL is required: pass --database or set HOSTSEAL_DATABASE_URL")
	case "memory":
		slog.Warn("using the in-memory store. This is for demonstrations and tests only: " +
			"every host, token and job result is lost when this process exits, nothing is shared " +
			"between replicas, and none of the PostgreSQL behaviour the real store depends on is " +
			"being exercised.")
		return store.NewMemory(), nil
	default:
		return store.OpenPostgres(ctx, dsn)
	}
}

// caCommand implements `hostseal-server ca init`.
func caCommand(argv []string) int {
	if len(argv) == 0 || argv[0] != "init" {
		fmt.Fprintln(os.Stderr, "usage: hostseal-server ca init [--ca-dir DIR] [--common-name NAME]")
		return 2
	}
	fs := flag.NewFlagSet("ca init", flag.ExitOnError)
	dir := fs.String("ca-dir", "/var/lib/hostseal-server/ca", "directory to create the CA in")
	commonName := fs.String("common-name", "HostSeal Agent CA", "subject common name")
	if err := fs.Parse(argv[1:]); err != nil {
		return 2
	}
	setupLogging()

	authority, err := ca.Init(*dir, *commonName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal-server: %v\n", err)
		return 1
	}
	fmt.Printf("Created a certificate authority in %s.\n", *dir)
	fmt.Printf("It expires %s.\n\n", authority.NotAfter().Format("2006-01-02"))
	fmt.Println("Back up ca.key separately from the database. An attacker with both can impersonate")
	fmt.Println("hosts to this control plane; an attacker with the database alone cannot. Neither")
	fmt.Println("lets them run code on a host: an agent authorises a job by its class and its")
	fmt.Println("signature, not by who asked.")
	return 0
}

// printCatalogue writes the complete intent catalogue to stdout.
//
// It exists so that an operator evaluating HostSeal can see the entire set of things the control plane
// is able to ask for, from the binary they are about to run, without reading the source or trusting a
// web page. The claim this project makes is about that set being small and closed, so it should be
// possible to check it in one command.
func printCatalogue() {
	fmt.Printf("%-26s %-12s %-6s %-8s %s\n", "INTENT", "CLASS", "EXEC", "SIGNED", "SUMMARY")
	for _, s := range intent.All() {
		executor := "no"
		if s.Implemented {
			executor = "yes"
		}
		signed := "-"
		switch {
		case s.Class.RequiresOfflineSignature():
			signed = "offline"
		case s.Class.Privileged():
			signed = "online"
		}
		fmt.Printf("%-26s %-12s %-6s %-8s %s\n", s.Name, s.Class, executor, signed, s.Summary)
	}
	fmt.Printf("\n%d intents. This set is closed: a compile-time map with no registry and no\n",
		len(intent.Names()))
	fmt.Println("configuration that adds to it. Permanently refused, with reasons in docs/SECURITY.md:")
	for _, n := range intent.Refused {
		fmt.Printf("  %s\n", n)
	}
}

// tlsNames returns the DNS names a self-issued server certificate should carry.
//
// The listen address is parsed for a hostname because "--addr hostseal.internal:8443" is a reasonable
// thing to write and a certificate that omitted it would fail verification for exactly the name the
// operator chose. A bare port yields nothing extra, and the caller always adds localhost.
func tlsNames(addr string) []string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" || net.ParseIP(host) != nil {
		return nil
	}
	return []string{host}
}

// envOr returns an environment variable, or a fallback.
//
// Credentials come from the environment as well as from flags because a flag value is visible in the
// process list to every user on the machine, and a database URL usually contains a password.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
