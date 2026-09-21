# HostSeal build entry points.
#
# Everything a contributor or CI runs lives here, so that "what does CI do" is answerable by reading one
# file rather than by reading five workflow YAMLs. The workflows in .github/workflows call these targets
# rather than duplicating the commands.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DIST    := dist

# The instant every reproducible artefact is pinned to: whatever the environment set, or this commit's
# own time. The release workflow exports it for the Go builds, and the archives below need it just as
# much — a zip entry carries a modification time that -X does not touch, so without this the same commit
# packed twice produces two different checksums and the SHA256SUMS published beside a release is a
# number nobody can reproduce.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)

# -s -w strip the symbol table and DWARF; the agent ships to other people's servers and there is no
# reason for it to be larger than it needs to be. The version is stamped rather than compiled in from a
# constant so that a build from a tag and a build from a branch are distinguishable in a heartbeat.
# -buildid= is here rather than only in the release workflow so that `make windows` produces the same
# bytes the release does. Without it a maintainer checking a published archive against a local build
# gets a different checksum and has no way to tell a real difference from a build-id.
LDFLAGS := -s -w -buildid= \
	-X github.com/pascalgross/hostseal/internal/buildinfo.Version=$(VERSION) \
	-X github.com/pascalgross/hostseal/internal/buildinfo.Commit=$(COMMIT)

GO_PACKAGES := ./...

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: $(DIST)/hostseal-agent $(DIST)/hostseal-server $(DIST)/hostseal helpers ## Build every binary

$(DIST):
	mkdir -p $(DIST)

$(DIST)/hostseal-agent: $(DIST)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/hostseal-agent

$(DIST)/hostseal-server: $(DIST)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/hostseal-server

$(DIST)/hostseal: $(DIST)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/hostseal

.PHONY: helpers
helpers: $(DIST) ## Build the three root helpers
	@for h in apply-updates restart-unit reboot-host; do \
	  CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/$$h ./helpers/$$h; \
	done

# The Windows agent, and the archive it ships in.
#
# A zip with two binaries, the installer and the default policy, rather than an MSI. MSI has no
# equivalent of dpkg's conffile handling, and WiX's default major-upgrade schedule uninstalls before it
# installs — which deletes an edited trusted-signers and reinstalls it empty, re-opening every
# destructive operation an administrator had closed with no symptom until a signature that should verify
# does not. The installer keeps both files by hand instead, which is a promise a script can actually make.
WINDOWS_DIST := $(DIST)/windows

.PHONY: windows
windows: $(DIST) ## Build the Windows agent and assemble its release archive
	mkdir -p $(WINDOWS_DIST)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	  go build -trimpath -ldflags '$(LDFLAGS)' -o $(WINDOWS_DIST)/hostseal-agent.exe ./cmd/hostseal-agent
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	  go build -trimpath -ldflags '$(LDFLAGS)' -o $(WINDOWS_DIST)/hostseal-update-scan.exe ./cmd/hostseal-update-scan
	@# The operator's CLI ships in the archive for the same reason it is in the .deb rather than a
	@# package of its own: `hostseal enroll` runs ON the host, writing the private key and agent.json into
	@# the local state directory, so a host that has only the agent can never enrol and idles for ever.
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	  go build -trimpath -ldflags '$(LDFLAGS)' -o $(WINDOWS_DIST)/hostseal.exe ./cmd/hostseal
	cp packaging/windows/Install-HostSealAgent.ps1 $(WINDOWS_DIST)/
	cp packaging/policy.toml $(WINDOWS_DIST)/
	@# Reproducible to the byte, which -X alone does not manage. It drops the extra fields that carry
	@# uids and high-resolution times, but every entry still keeps a DOS timestamp taken from the staged
	@# file's mtime and recorded in local time — so an archive packed from one commit differed by when
	@# and where it was packed, against a SHA256SUMS published as though it could not. Three things fix
	@# it and all three are needed: the mtimes are pinned to SOURCE_DATE_EPOCH, the archive is written
	@# with TZ=UTC, and the entries come from a sorted list rather than from whatever order the
	@# directory happens to be walked in.
	find $(WINDOWS_DIST) -exec touch -h -d @$(SOURCE_DATE_EPOCH) {} +
	cd $(WINDOWS_DIST) && find . -type f | LC_ALL=C sort \
	  | TZ=UTC zip -q -X -@ ../hostseal-agent-windows-amd64.zip && cd -
	@echo "wrote $(DIST)/hostseal-agent-windows-amd64.zip"

# The operator's CLI on its own, for the machine that holds the signing key.
#
# hostseal.exe is in the agent archive as well, because `hostseal enroll` runs on the host — but an
# operator who only wants to sign is not installing a host. Telling them to download an agent's
# installer, unpack it and use one file out of five is how a workstation ends up running a service
# nobody meant to install, and the .ps1 sitting next to it is an invitation to run exactly that.
WINDOWS_CLI_DIST := $(DIST)/windows-cli

.PHONY: windows-cli
windows-cli: $(DIST) ## Build the operator's CLI archive for Windows
	mkdir -p $(WINDOWS_CLI_DIST)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	  go build -trimpath -ldflags '$(LDFLAGS)' -o $(WINDOWS_CLI_DIST)/hostseal.exe ./cmd/hostseal
	@# Pinned, UTC and sorted, for the reason the agent archive above spells out.
	find $(WINDOWS_CLI_DIST) -exec touch -h -d @$(SOURCE_DATE_EPOCH) {} +
	cd $(WINDOWS_CLI_DIST) && find . -type f | LC_ALL=C sort \
	  | TZ=UTC zip -q -X -@ ../hostseal-windows-amd64.zip && cd -
	@echo "wrote $(DIST)/hostseal-windows-amd64.zip"

# The Windows agent must keep cross-compiling, and `make ci` runs on Linux. Compiling it is not a test —
# nothing here can exercise COM, the SCM or the registry — but a build failure is the one Windows defect
# this project can catch without a Windows machine, and catching it costs seconds.
.PHONY: windows-build
windows-build: ## Check that the Windows agent still cross-compiles
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /dev/null ./cmd/hostseal-agent
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /dev/null ./cmd/hostseal-update-scan
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /dev/null ./cmd/hostseal
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./cmd/hostseal-agent ./cmd/hostseal-update-scan \
	  ./internal/winapi ./internal/updatescan ./internal/collect/platform \
	  ./internal/signing/backend/pkcs11 ./internal/localsign ./internal/autostart
	@# internal/wua is vetted by golangci-lint, which can scope the unsafeptr exclusion to the one
	@# file that earns it. Raw `go vet` has no such setting, and excluding the whole package here
	@# would stop checking the two files that do no unsafe work at all.
	@echo "the Windows agent cross-compiles and vets clean"

.PHONY: test
test: ## Run unit tests
	go test -race -count=1 $(GO_PACKAGES)

# The module the signing-backend tests drive. libsofthsm2, not softhsm2: the tests build their own
# token through the module's own C_InitToken, C_InitPIN and C_GenerateKeyPair, so the tools package is
# not needed.
.PHONY: test-pkcs11
test-pkcs11: ## Run the PKCS#11 backend against a real module, in the build that ships
	# Twice, deliberately. `make test` runs with cgo because -race requires it, so the path the
	# released binary actually takes — purego's own dlopen, with no cgo — is otherwise never
	# exercised by anything.
	go test -race -count=1 -v ./internal/signing/backend/pkcs11/
	CGO_ENABLED=0 go test -count=1 ./internal/signing/backend/pkcs11/

.PHONY: cover
cover: ## Run unit tests with a coverage profile
	go test -race -count=1 -coverprofile=coverage.txt -covermode=atomic $(GO_PACKAGES)

.PHONY: guarantee
guarantee: guarantee-tests guarantee-fuzz ## Run the tests that enforce docs/SECURITY.md section 1

# Split so that the guarantee workflow can call the two halves as two named steps — which is what puts
# the right failure message at the top of a red run — without restating the commands. The required
# check and `make guarantee` must be the same thing; a workflow that copied the commands could be
# weakened by an edit here that nobody noticed, or strengthened here and never run in CI.
.PHONY: guarantee-tests
guarantee-tests: ## The catalogue is the expected set, and nothing reaches a shell
	# ./... rather than ./internal/...: three guarantee-named tests live under helpers/ and were
	# silently outside the required check, which nothing about their names said.
	go test -count=1 -run '^(TestGuarantee|TestClassPredicates)' -v ./...

.PHONY: guarantee-fuzz
guarantee-fuzz: ## Fuzz the parameter decoders and the canonical encoder, as CI does
	go test -count=1 -run '^$$' -fuzz 'FuzzGuarantee' -fuzztime 60s ./internal/intent/
	go test -count=1 -run '^$$' -fuzz 'FuzzNormalize' -fuzztime 60s ./internal/canonical/

.PHONY: fuzz
fuzz: ## Fuzz both guarantee targets for longer than CI does
	go test -run '^$$' -fuzz 'FuzzGuarantee' -fuzztime 10m ./internal/intent/
	go test -run '^$$' -fuzz 'FuzzNormalize' -fuzztime 10m ./internal/canonical/

.PHONY: site
site: ## Render the documentation site into public/
	go run ./tools/docsite -root . -out public

# Generated and committed rather than built, so that a checkout has the mark without running anything
# and so that a change to it shows up as a diff somebody looks at. tools/brandmark's own test fails when
# a committed copy stops matching, which is what makes that safe.
.PHONY: brand
brand: ## Regenerate the mark: the SVGs and the favicon
	go run ./tools/brandmark -root .

.PHONY: lint
lint: vet doccheck golangci ## Run every Go linter

.PHONY: vet
vet: ## go vet
	go vet $(GO_PACKAGES)

.PHONY: doccheck
doccheck: ## Enforce a doc comment on every type and function, exported or not
	go run ./tools/doccheck ./cmd ./internal ./helpers ./tools

# The linter version, used by the golangci target and by CI. Pinned rather than @latest: a new linter
# release must be something somebody adopts deliberately, not something that turns every open pull
# request red overnight on a tree nobody touched.
GOLANGCI_VERSION := v2.13.1

.PHONY: golangci-install
golangci-install: ## Install the pinned golangci-lint
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

.PHONY: golangci
golangci: ## golangci-lint, for this platform and for Windows
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
	  echo "golangci-lint not installed; see https://golangci-lint.run/welcome/install/"; \
	  exit 1; \
	fi
	golangci-lint run
	@# And again for Windows, because a linter only ever analyses one platform. Every file behind
	@# //go:build windows — the whole agent's platform layer, the COM chokepoint and the update scan —
	@# is invisible to the pass above, so without this second one several thousand lines would ship
	@# having been linted by nothing at all. It caught six real findings the first time it was run.
	@#
	@# The package list is explicit rather than ./... because a Windows pass over every package would
	@# lint a great deal of code that no Windows binary links, and slowly. It names the operator's CLI
	@# and the signing packages as well as the agent's: an operator's workstation is very often a
	@# Windows one, and since the PKCS#11 backend learned LoadLibraryEx that is where its token signing
	@# happens — an FFI path linted by nothing would be the worst of the set to leave unlinted.
	GOOS=windows GOARCH=amd64 golangci-lint run $(WINDOWS_PACKAGES)

# The packages a Windows agent is built from, for the linter and the cross-compile check.
#
# Listed once and used twice so the two cannot drift apart — a package added to one and forgotten in the
# other would be one that compiles and is never linted, which is the state this list exists to end.
WINDOWS_PACKAGES := ./cmd/hostseal/... ./cmd/hostseal-agent/... ./cmd/hostseal-update-scan/... \
  ./internal/winapi/... ./internal/wua/... ./internal/updatescan/... \
  ./internal/collect/... ./internal/agent/... ./internal/policy/... ./internal/run/... \
  ./internal/signing/... ./internal/localsign/... ./internal/autostart/...

.PHONY: fmt
fmt: ## Format Go source
	gofmt -w $(shell git ls-files '*.go')

.PHONY: fmt-check
fmt-check: ## Fail if any Go source is unformatted
	@unformatted="$$(gofmt -l $$(git ls-files '*.go'))"; \
	if [ -n "$$unformatted" ]; then \
	  echo "these files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: web
web: ## Build the Angular application into the location hostseal-server embeds
	cd web && pnpm install --frozen-lockfile && pnpm run build
	find internal/server/assets -mindepth 1 -maxdepth 1 \
	  ! -name .gitignore ! -name PLACEHOLDER.md -exec rm -rf {} +
	cp -r web/dist/. internal/server/assets/

.PHONY: web-lint
web-lint: ## Lint the web application, including the doc-comment rule on private members
	cd web && pnpm install --frozen-lockfile && pnpm exec eslint .

# Every systemd unit the package ships. systemd silently ignores a directive it does not understand, so
# a typo in one of these is a hardening line that is simply absent on every host — which is why the deb
# target verifies them and CI verifies them again with the binaries in place.
UNITS := packaging/hostseal-agent.service \
	packaging/hostseal-apply-updates.socket packaging/hostseal-apply-updates@.service \
	packaging/hostseal-restart-unit.socket packaging/hostseal-restart-unit@.service \
	packaging/hostseal-reboot-host.socket packaging/hostseal-reboot-host@.service

.PHONY: units
units: ## Check every packaged systemd unit with systemd-analyze
	systemd-analyze verify $(UNITS)

ARCH ?= $(shell go env GOARCH)
# nfpm insists on a semver version, and `git describe` yields v0.1.0-3-gabc1234 between tags.
DEB_VERSION ?= $(patsubst v%,%,$(VERSION))

# Debian's version ordering has no notion of a prerelease, so nfpm's semver schema encodes the hyphen
# as a tilde — 0.1.0-rc1 becomes 0.1.0~rc1, which sorts *before* 0.1.0 exactly as a prerelease should.
# Anything that needs to name the resulting file has to do the same substitution, and forgetting is a
# glob that silently matches nothing.
DEB_FILE_VERSION = $(subst -,~,$(DEB_VERSION))

.PHONY: deb-path
deb-path: ## Print the .deb path `make deb` would produce, for scripts that need to name it
	@echo "$(DIST)/packages/hostseal-agent_$(DEB_FILE_VERSION)_$(ARCH).deb"

# The packager version, used by the nfpm-install target and by every workflow that builds a .deb. Pinned
# for a sharper reason than the linter above is. nfpm is the program that assembles the package every
# enrolled host installs and runs maintainer scripts from as root, so whoever controls the nfpm build
# controls root on the whole fleet through the one channel it trusts. `@latest` made that a decision
# taken by whoever published a release most recently; an exact version makes it one somebody adopts, and
# `go install module@version` verifies the download against the checksum database on the way in.
NFPM_VERSION := v2.47.0

.PHONY: nfpm-install
nfpm-install: ## Install the pinned packager
	go install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)

.PHONY: deb
deb: build ## Build the hostseal-agent .deb
	@command -v nfpm >/dev/null 2>&1 || { echo "nfpm not installed; see https://nfpm.goreleaser.com/install/"; exit 1; }
	@command -v systemd-analyze >/dev/null 2>&1 && systemd-analyze verify $(UNITS) >/dev/null 2>&1 || true
	mkdir -p $(DIST)/packages
	cd packaging && \
	  VERSION="$(DEB_VERSION)" ARCH="$(ARCH)" \
	  nfpm package --packager deb --target "../$(DIST)/packages"

# The control plane's container image, and the Compose stack in deploy/. The agent is packaged as a .deb
# above and is deliberately not containerised: it manages a host, and a host it managed from inside a
# container on the control plane would be the control plane.
IMAGE ?= hostseal-server
IMAGE_TAG ?= $(VERSION)

.PHONY: image
image: ## Build the hostseal-server container image
	docker build -t $(IMAGE):$(IMAGE_TAG) \
	  --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) .

# Values for the variables the Compose files require, so that the files can be parsed without a .env.
# They are visibly fake: this target checks that the stack is well-formed, and starting anything with
# them would be a control plane whose every password is the word "check". A real value in the
# environment wins, because Compose prefers the environment over .env — so this never validates the file
# it is checking against somebody's actual secrets.
COMPOSE_CHECK_ENV := POSTGRES_SUPERUSER_PASSWORD=check HOSTSEAL_DB_PASSWORD=check \
	HOSTSEAL_REPLICATION_PASSWORD=check \
	HOSTSEAL_AGENT_HOSTNAME=agents.example.invalid HOSTSEAL_UI_HOSTNAME=hostseal.example.invalid

.PHONY: compose-check
compose-check: ## Parse every Compose file, including the optional overlays
	# Each overlay separately, because a merge error only shows up in the combination that produces
	# it — and the Traefik one is where a mistake is expensive: an overlay that failed to remove the
	# published port would leave the control plane reachable beside the proxy rather than behind it.
	@cd deploy && env $(COMPOSE_CHECK_ENV) docker compose -f compose.yaml config -q
	@cd deploy && env $(COMPOSE_CHECK_ENV) docker compose -f compose.yaml -f compose.traefik.yaml config -q
	@cd deploy && env $(COMPOSE_CHECK_ENV) docker compose -f compose.yaml -f compose.traefik.yaml \
	  -f compose.traefik-ui.yaml config -q
	@cd deploy && env $(COMPOSE_CHECK_ENV) docker compose -f compose.yaml -f compose.standby.yaml config -q
	@echo "compose: every file parses"

.PHONY: clean
clean: ## Remove build output
	rm -rf $(DIST) coverage.txt

.PHONY: actions-pinned
actions-pinned: ## Every third-party action names a commit rather than a movable tag
	@.github/scripts/actions-pinned.sh .

.PHONY: ci
ci: fmt-check vet doccheck actions-pinned windows-build test guarantee ## What CI runs, minus the pieces that need extra tooling
