// Command hostseal is the operator's command-line tool.
//
// Its most important job is `hostseal sign`: decoding and rendering a job request offline, without
// contacting the server, and signing it with a key the control plane does not hold. That the rendering
// happens locally from the full signed payload is a requirement on the wire format rather than a nicety
// of this program — if the tool signed an opaque digest handed to it by the server, a compromised
// control plane could show one operation in the browser and have a different one signed.
//
// The rest of the path was built first and this closed it: the control plane accepts a signed job on
// POST /api/v1/jobs, holds a destructive one for release if the fleet asks for that, an agent verifies
// the signature against the host's own trusted-signers, and a root helper acts on it. What it adds is
// the end an operator stands at. The other commands are what made that end reachable: enrolling a host,
// and generating and inspecting signing keys so a trust anchor can be established in advance.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pascalgross/hostseal/internal/agent"
	"github.com/pascalgross/hostseal/internal/buildinfo"
	"github.com/pascalgross/hostseal/internal/intent"
	"github.com/pascalgross/hostseal/internal/prompt"
	"github.com/pascalgross/hostseal/internal/signing"
	"github.com/pascalgross/hostseal/internal/signing/backend"
	"github.com/pascalgross/hostseal/internal/signing/backend/file"

	// The backends this build ships, registered by their own init functions.
	//
	// Blank imports, in the shape database/sql uses, and they are the whole of what `hostseal` knows
	// about any of them: the registry resolves a reference and this command never names a backend
	// again. They are imported here rather than in internal/signing because the agent and the control
	// plane import that package for the verifier and must link no backend at all — a property
	// TestGuaranteeNoManagedHostBinaryLoadsASigningBackend asserts rather than assumes.
	_ "github.com/pascalgross/hostseal/internal/signing/backend/kms"
)

// usage prints the command list.
func usage() {
	fmt.Fprintf(os.Stderr, `hostseal %s

usage:
  hostseal enroll        enrol this host with a control plane
  hostseal key generate  create a signing key and print its trusted-signers line
  hostseal key show      print the trusted-signers line for an existing key
  hostseal sign          render a job request offline and sign it
  hostseal signer        serve signatures to the web interface from a token on this machine
  hostseal catalogue     print the intent catalogue this build knows
  hostseal version       print the version

Run "hostseal <command> --help" for a command's options.
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
	case "enroll", "enrol":
		os.Exit(enroll(args[1:]))
	case "key":
		os.Exit(keyCommand(args[1:]))
	case "catalogue":
		for _, s := range intent.All() {
			fmt.Printf("%-26s %-12s %s\n", s.Name, s.Class, s.Summary)
		}
	case "sign":
		os.Exit(signCommand(args[1:]))
	case "signer":
		os.Exit(signerCommand(args[1:]))
	case "version":
		fmt.Println("hostseal " + buildinfo.String())
	default:
		fmt.Fprintf(os.Stderr, "hostseal: unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
}

// enroll registers this host with a control plane.
func enroll(argv []string) int {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "control plane base URL, for example https://hostseal.example.org")
	token := fs.String("token", "", "single-use bootstrap token")
	stateDir := fs.String("state-dir", agent.DefaultStateDir, "directory to keep enrolment state in")
	caBundle := fs.String("ca", "",
		"PEM file to verify the control plane's own certificate against (default "+
			agent.DefaultServerCABundle+" when it exists)")
	signers := fs.String("signers", "",
		"local trusted-signers file to install before anything is fetched")
	policyFile := fs.String("policy", "", "local policy.toml to install")
	hostname := fs.String("hostname", "", "override the reported hostname")
	if err := fs.Parse(argv); err != nil {
		return 2
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	bundle, err := resolveCABundle(*caBundle, agent.DefaultServerCABundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	state, err := agent.Enroll(ctx, agent.EnrollOptions{
		ServerURL:   *server,
		Token:       *token,
		StateDir:    *stateDir,
		CABundle:    bundle,
		SignersFile: *signers,
		PolicyFile:  *policyFile,
		Hostname:    *hostname,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}

	fmt.Printf("Enrolled as %s with %s.\n", state.HostID, state.ServerURL)
	fmt.Printf("Restart the agent so it reads this: %s\n", agent.RestartCommand)
	return 0
}

// resolveCABundle decides which CA bundle enrolment verifies the control plane against.
//
// Enrolment is the one request made with nothing on disk to verify against, so the authority for it is
// chosen locally and in advance. The two cases are deliberately not symmetric.
//
// A path the operator typed must exist. Falling back to the system roots because --ca named a file that
// is not there would verify a chain they did not ask for, and the failure it replaces — a typo — is one
// they can fix in a second if they are told about it.
//
// The default path is different: it is a convention rather than a request, so its absence simply means
// the system roots, which is correct for a control plane with a publicly trusted certificate. Its
// presence is what makes the documented ordering real — an administrator who installed the certificate
// before enrolling gets it used, without having to name it a second time on the command line.
//
// The default arrives as an argument rather than being read from the package constant, so that a test
// can exercise both halves without an absolute path only root can create.
func resolveCABundle(flagValue, defaultPath string) (string, error) {
	if flagValue != "" {
		if _, err := os.Stat(flagValue); err != nil {
			return "", fmt.Errorf("the CA bundle %s cannot be read: %w", flagValue, err)
		}
		return flagValue, nil
	}
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath, nil
	}
	return "", nil
}

// keyCommand implements `hostseal key generate` and `hostseal key show`.
func keyCommand(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: hostseal key generate|show [options]")
		return 2
	}
	switch argv[0] {
	case "generate":
		return keyGenerate(argv[1:])
	case "show":
		return keyShow(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "hostseal: unknown key command %q\n", argv[0])
		return 2
	}
}

// keyGenerate creates a signing key and prints the line to add to trusted-signers.
//
// The output is a line to paste rather than a file to copy, because trusted-signers is edited by hand
// on each host by an administrator who has decided that key should be able to reboot that machine.
// Making that a deliberate edit is the point; automating it would make the trust anchor something the
// tooling manages rather than something a person chose.
func keyGenerate(argv []string) int {
	fs := flag.NewFlagSet("key generate", flag.ExitOnError)
	out := fs.String("out", "", "path to write the encrypted key file to")
	keyID := fs.String("id", "", "identity recorded in the audit log, for example ops-laptop")
	algorithm := fs.String("algorithm", string(signing.Ed25519),
		"ed25519, or ecdsa-p256 where something in your chain cannot do Ed25519")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *out == "" || *keyID == "" {
		fmt.Fprintln(os.Stderr, "hostseal: --out and --id are both required")
		return 2
	}

	passphrase, err := readPassphrase("Passphrase for the new key: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}
	confirm, err := readPassphrase("Confirm: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}
	if string(passphrase) != string(confirm) {
		fmt.Fprintln(os.Stderr, "hostseal: the passphrases do not match")
		return 1
	}

	signer, err := file.Generate(*out, *keyID, signing.Algorithm(*algorithm), passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}
	defer func() { _ = signer.Close() }()

	line, err := signing.TrustedSignerLine(signer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}

	fmt.Printf("\nWrote %s.\n\nAdd this line to /etc/hostseal/trusted-signers on every host this key\n"+
		"should be able to authorise destructive operations on:\n\n%s\n\n", *out, line)
	fmt.Println("The file is empty by default and the control plane cannot write it, so a host will")
	fmt.Println("execute nothing destructive until somebody makes that edit deliberately.")
	return 0
}

// keyShow prints the trusted-signers line for an existing key.
//
// A file backend answers this without the passphrase, which is the situation somebody is in while
// setting up a host with the token at the office. A token or a key store may need its PIN or its cloud
// credential first, and says so rather than returning nothing.
func keyShow(argv []string) int {
	fs := flag.NewFlagSet("key show", flag.ExitOnError)
	in := fs.String("in", "", "path to the key file, or a backend reference: "+
		strings.Join(referenceExamples(), ", "))
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *in == "" {
		fmt.Fprintln(os.Stderr, "hostseal: --in is required")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	showCtx, done := context.WithTimeout(ctx, DefaultSigningTimeout)
	defer done()

	pub, err := backend.Inspect(showCtx, *in, readPassphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostseal: %v\n", err)
		return 1
	}
	fmt.Printf("%s %s %s %s\n", pub.Algorithm, pub.Encoded, pub.KeyID, pub.Backend)
	return 0
}

// referenceExamples renders one example per registered backend, for the help text.
//
// Generated from the registry rather than written out, so a build without a backend does not advertise
// it and a build with a new one does not need this list edited. The examples themselves are the
// shortest reference each backend accepts.
func referenceExamples() []string {
	examples := map[string]string{
		"file":     "~/.config/hostseal/ops.key",
		"pkcs11":   "pkcs11:token=ops;object=ops-yubikey-1?module-path=/usr/lib/opensc-pkcs11.so",
		"awskms":   "awskms:arn:aws:kms:eu-central-1:123456789012:key/abcd#ops-kms-1",
		"gcpkms":   "gcpkms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1#ops-kms-1",
		"azurekms": "azurekms:ops.vault.azure.net/keys/hostseal-signing/9885aa55#ops-kms-1",
	}
	var out []string
	for _, scheme := range backend.Schemes() {
		if example, ok := examples[scheme]; ok {
			out = append(out, example)
		}
	}
	return out
}

// readPassphrase reads a passphrase without echoing it.
//
// A thin wrapper over internal/prompt so that it can be handed to the signing-backend registry as a
// backend.PassphraseFunc, which is the shape that keeps the rule travelling with the value: a
// passphrase or a PIN is never a command-line argument, where every user on the machine can read it
// from the process list.
func readPassphrase(message string) ([]byte, error) { return prompt.Secret(message) }
