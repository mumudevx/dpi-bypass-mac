# Measurement programs

Each directory is a self-contained Go module that reproduces one row of
`../MEASUREMENTS.md`. They are nested modules, deliberately excluded from the
main `dpb` module, so `go build ./...` at the repository root ignores them.

| program | what it establishes |
|---|---|
| `chunkprobe` | the chunk-size efficacy curve is non-monotonic |
| `emitprobe` | which emitters get through; TCP splitting and disorder do not |
| `mechprobe` | the mechanism is the TLS record layer, not TCP framing |
| `ruleprobe` | the exact rule: the cut must land before `sniEnd` |
| `compatprobe` | record splitting breaks 10 of 41 sites, all Turkish banks and `.gov.tr` |
| `matrixprobe` | no emitter is both a bypass and universally safe |
| `retryprobe` | plain-first then desync-retry works, costs ~23 ms, provokes no escalation |

Run one against a censored line:

```sh
cd ruleprobe && go run .
```

Every program interleaves a benign-SNI control against the same destination IP.
If the control fails, the run is meaningless — the network is down, not the DPI.
