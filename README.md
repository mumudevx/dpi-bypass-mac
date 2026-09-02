# dpb — macOS DPI bypass

A macOS-first tool for getting past the two censorship techniques actually
measured on a Türk Telekom line: passive SNI inspection of the TLS ClientHello,
and DNS poisoning. It runs a local proxy (and, later, a TUN device), reframes
the first ClientHello record so the hostname is not visible to the middlebox in
the record it inspects, and resolves names over its own encrypted DNS chain.

> **Status: rebuilding.** The v2 tree is being implemented milestone by
> milestone against [`docs/PLAN.md`](docs/PLAN.md). There is no released binary
> and no Homebrew tap yet, so this README deliberately has no install section.
> Build from source with `make build`.

## Honesty

- This is **not a VPN**. It changes how packets are framed; it adds no
  encryption and no anonymity beyond what HTTPS already gives you.
- Whether a strategy defeats a specific ISP's DPI can only be established on
  that network. The shipped profiles are starting points derived from
  first-hand measurement, not guarantees; `dpb tune` measures your own line.
- The in-repo censor models (`internal/testcensor`) are hypotheses about how
  the DPI works. They test our model, not the DPI.
- No emitter is both a bypass and universally safe. Ten of the 41 hosts
  measured — every Turkish bank and `.gov.tr` site tested — *regressed* under
  the winning emitter, which is why the default connection policy is to connect
  plain and escalate only on evidence.

## Evidence

- [`docs/MEASUREMENTS.md`](docs/MEASUREMENTS.md) — the first-hand measurements
  everything here is derived from. Where any other document disagrees with it,
  it wins.
- [`docs/measurements/`](docs/measurements) — the standalone probe programs that
  produced those numbers. Each is its own Go module and is not part of the main
  build.
- [`docs/PLAN.md`](docs/PLAN.md) — the implementation contract.
- [`docs/DOSSIER.md`](docs/DOSSIER.md) — background research.

## Development

Requires Go 1.26.4 on darwin/arm64.

```sh
make build       # -> ./dpb
make test        # go test ./...
make race        # go test ./... -race
make lint        # gofmt check + go vet
make cover-gate  # fails on any 0.0%-covered function in a gated package
make fuzz        # 60s per discovered fuzz target
make deps        # compile the dependency-pin package (tools/tools.go)
```

Two build gates run inside the normal test invocation and fail the build rather
than warn:

- **no bare goroutine** in `internal/front`, `internal/flow` or
  `internal/resolve` — Go runs only the panicking goroutine's deferred
  functions, so every per-connection goroutine goes through `flow.Safe`.
- **no hostname dial** outside `internal/resolve` — the first run of the
  measured compatibility matrix scored every emitter 0/6 because Go's own
  resolver returned the sinkhole address. Every outbound dial resolves through
  the tool's chain.

`go.mod` pins the whole tree's dependency set up front, including modules that
milestones still to come will need; `tools/tools.go` is what stops `go mod tidy`
from pruning them.

## License

MIT — see [LICENSE](LICENSE).
