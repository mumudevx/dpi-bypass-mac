BINARY  := dpb
MODULE  := github.com/mumudevx/dpi-bypass-mac
CMD     := ./cmd/dpb
DIST    := dist

# No --dirty here: buildinfo reports a dirty tree from the VCS stamp, and
# having it in both places prints it twice.
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(MODULE)/internal/buildinfo.Date=$(DATE)

COVER_PROFILE := coverage.out

# Packages whose functions may never sit at 0.0%. This is the list from the
# plan's test strategy: every confirmed defect in the previous tree lived in a
# 0.0%-covered function, so 0% is a build failure rather than a warning.
COVER_GATED := \
	internal/cliapp \
	internal/flow \
	internal/strategy \
	internal/ops \
	internal/emit \
	internal/tlsmsg \
	internal/front/proxyfe \
	internal/front/tunfe \
	internal/netstate \
	internal/netwatch \
	internal/policy \
	internal/resolve \
	internal/probe

# A regex matching a file inside any gated package.
COVER_GATED_RE := $(MODULE)/(internal/(cliapp|flow|strategy|ops|emit|tlsmsg|front/proxyfe|front/tunfe|netstate|netwatch|policy|resolve|probe))/

# Statement-coverage floor.
COVER_MIN := 85

# Per-package floors that differ from COVER_MIN. These are exceptions with a
# reason, never a knob to turn when the gate goes red:
#
#   internal/front/tunfe, internal/netstate  their syscall leaves are only
#     reachable from root-gated integration tests.
#   internal/cliapp  the command tree is the largest package in the tree and
#     most of it is wiring that only a whole `dpb run` exercises; it entered
#     the gate at the floor it met on the day it was added. It is here rather
#     than outside the gate because it is where most of the code now lives,
#     and a gate that skips the largest package has stopped being a gate.
#
# A floor may be RAISED as coverage improves. Lowering one to make a red build
# pass defeats the entire mechanism, so don't.
COVER_FLOORS := \
	internal/front/tunfe=70 \
	internal/netstate=70 \
	internal/cliapp=83

.PHONY: all build install test race cover cover-gate fuzz vet fmt lint tidy clean deps

all: lint test build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) $(CMD)

install:
	go install -trimpath -ldflags '$(LDFLAGS)' $(CMD)

test:
	go test ./...

race:
	go test ./... -race

# deps compiles the dependency-pin package. It is the only thing that builds
# with the `tools` tag; running it proves every pinned module still resolves.
deps:
	go build -tags tools ./tools/

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal tools

lint:
	@bad=$$(gofmt -l cmd internal tools 2>/dev/null); \
	if [ -n "$$bad" ]; then echo "gofmt needed:"; echo "$$bad"; exit 1; fi
	go vet ./...

tidy:
	go mod tidy

cover: $(COVER_PROFILE)
	go tool cover -func=$(COVER_PROFILE) | tail -1

$(COVER_PROFILE): FORCE
	go test ./... -covermode=atomic -coverpkg=./internal/... -coverprofile=$(COVER_PROFILE)

FORCE:

# cover-gate fails the build when any function in a gated package is at 0.0%,
# or when a gated package's statement coverage is below its floor. A gated
# package that does not exist yet is skipped, so the gate passes vacuously
# early in the build-out and tightens on its own as packages land.
cover-gate: $(COVER_PROFILE)
	@echo "cover-gate: functions at 0.0% in gated packages"
	@go tool cover -func=$(COVER_PROFILE) \
		| awk -v gate='$(COVER_GATED_RE)' \
			'$$1 ~ gate && $$3 == "0.0%" { printf "  ZERO  %s  %s\n", $$1, $$2; bad++ } \
			 END { if (bad) { printf "cover-gate: %d function(s) at 0.0%%\n", bad; exit 1 } \
			       else print "  none" }'
	@echo "cover-gate: statement coverage per gated package"
	@awk -v mod='$(MODULE)/' \
		-v gated='$(COVER_GATED)' \
		-v floors='$(COVER_FLOORS)' \
		-v min=$(COVER_MIN) \
		'NR > 1 { \
			stm[$$1] = $$2; if ($$3 + 0 > cnt[$$1]) cnt[$$1] = $$3 + 0 } \
		 END { \
			for (k in stm) { \
				split(k, a, ":"); f = a[1]; sub(mod, "", f); d = f; sub(/\/[^\/]*$$/, "", d); \
				s[d] += stm[k]; if (cnt[k] > 0) c[d] += stm[k] } \
			m = split(floors, fo, " "); \
			for (j = 1; j <= m; j++) { split(fo[j], kv, "="); fl[kv[1]] = kv[2] + 0 } \
			n = split(gated, g, " "); \
			for (i = 1; i <= n; i++) { \
				d = g[i]; \
				if (!(d in s) || s[d] == 0) { printf "  SKIP  %-24s (no code yet)\n", d; continue } \
				floor = (d in fl) ? fl[d] : min; \
				p = 100 * c[d] / s[d]; \
				status = (p + 0.05 < floor) ? "LOW " : "ok  "; \
				printf "  %s  %-24s %5.1f%% (min %d%%, %d stmts)\n", status, d, p, floor, s[d]; \
				if (p + 0.05 < floor) bad++ } \
			if (bad) { printf "cover-gate: %d package(s) below the coverage floor\n", bad; exit 1 } }' \
		$(COVER_PROFILE)
	@echo "cover-gate: pass"

# 60 s per fuzz target, matching what CI runs. Targets are discovered, so this
# needs no edit as milestones add them.
FUZZTIME ?= 60s
fuzz:
	@set -e; \
	found=0; \
	for pkg in $$(go list ./...); do \
		dir=$$(go list -f '{{.Dir}}' $$pkg); \
		for fn in $$(grep -rhoE '^func (Fuzz[A-Za-z0-9_]+)' $$dir/*_test.go 2>/dev/null | awk '{print $$2}'); do \
			found=1; \
			echo "==> $$pkg $$fn ($(FUZZTIME))"; \
			go test $$pkg -run '^$$' -fuzz "^$$fn$$" -fuzztime=$(FUZZTIME); \
		done; \
	done; \
	if [ $$found -eq 0 ]; then echo "no fuzz targets yet"; fi

clean:
	rm -f $(BINARY) $(COVER_PROFILE)
	rm -rf $(DIST)
