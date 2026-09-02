// This file owns tuned.toml: what `dpb tune` writes and what a later `dpb run`
// reads back. It is deliberately a plain data record with no behaviour beyond
// decoding, freshness and network matching — the prober owns the measurement,
// this owns the file.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// TunedVersion is the schema version written into every file. A reader that
// meets a higher one refuses rather than guessing: the record decides which
// packets a user's browser emits, and a field silently reinterpreted between
// releases is the sni_match trap in a different costume.
const TunedVersion = 1

// TunedTTL is how long a measurement is believed.
//
// Seven days, matching the learned-desync verdict TTL. DOSSIER GT21 records
// Turkish DPI configurations rotting on a months-scale cadence and GT20
// records a block being lifted after 680 days, so a week is well inside the
// window where a stale profile would still be right, and short enough that a
// lifted block is rediscovered without the user knowing to ask.
const TunedTTL = 7 * 24 * time.Hour

// Confidence labels, mirrored from internal/probe so a reader of this file does
// not have to import the prober to know what the string may be.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

var (
	// ErrTunedUnknownKey is what an unrecognised key produces. Rejecting rather
	// than ignoring is the whole reason this decodes by hand: a user who
	// mistypes `strategy` gets told, instead of silently running the default
	// and believing they configured something.
	ErrTunedUnknownKey = errors.New("config: tuned.toml has an unknown key")
	// ErrTunedVersion is a schema this build cannot read.
	ErrTunedVersion = errors.New("config: tuned.toml schema version is not supported")
	// ErrTunedInvalid is a structurally impossible record.
	ErrTunedInvalid = errors.New("config: tuned.toml is not a usable profile")
)

// TunedClassification is the mechanism section.
type TunedClassification struct {
	Shape            string `toml:"shape"`
	FirstRecordLimit int    `toml:"first_record_limit"`
	SNIEnd           int    `toml:"sni_end"`
	// InspectBytes is 0 when the inspection window was not measured, which is
	// the only value this build can produce. See internal/probe/classify.go.
	InspectBytes  int    `toml:"inspect_bytes"`
	RSTLatencyMS  int64  `toml:"rst_latency_ms"`
	RecordFrag    bool   `toml:"record_frag"`
	TCPSplit      bool   `toml:"tcp_split"`
	Chunking      bool   `toml:"chunking"`
	InspectSource string `toml:"inspect_bytes_note,omitempty"`
}

// TunedCandidate is one ranked row of the sweep, kept so that a user who does
// not trust the winner can read the evidence instead of re-running the tune.
type TunedCandidate struct {
	Spec         string  `toml:"spec"`
	BypassPass   int     `toml:"bypass_pass"`
	BypassTotal  int     `toml:"bypass_total"`
	WilsonLo     float64 `toml:"wilson_lo"`
	AllTargets   bool    `toml:"all_targets"`
	ControlPass  int     `toml:"control_pass"`
	ControlTotal int     `toml:"control_total"`
	FragilePass  int     `toml:"fragile_pass"`
	FragileTotal int     `toml:"fragile_total"`
	Determinism  string  `toml:"determinism"`
	Segments     int     `toml:"segments"`
	MedianRTTMS  int64   `toml:"median_rtt_ms"`
	Discarded    int     `toml:"discarded"`
	Unmeasurable bool    `toml:"unmeasurable"`
}

// Tuned is the whole record.
type Tuned struct {
	Version     int       `toml:"version"`
	CreatedAt   time.Time `toml:"created_at"`
	ToolVersion string    `toml:"tool_version"`
	// NetworkKey namespaces the measurement. Replaying "discord.com needs
	// tlsfrag" onto a different network would desync a flow with no evidence at
	// all, which is exactly what MEASUREMENTS.md §5.2 forbids.
	NetworkKey string   `toml:"network_key"`
	Caps       string   `toml:"caps"`
	Confidence string   `toml:"confidence"`
	NoiseRate  float64  `toml:"noise_rate"`
	ElapsedMS  int64    `toml:"elapsed_ms"`
	Strategy   string   `toml:"strategy"`
	Ladder     []string `toml:"ladder"`
	Resolvers  []string `toml:"resolvers"`
	Blocked    []string `toml:"blocked"`
	NotBlocked []string `toml:"not_blocked"`
	Warnings   []string `toml:"warnings"`

	Classification TunedClassification `toml:"classification"`
	Candidates     []TunedCandidate    `toml:"candidate"`
}

// Fresh reports whether the profile is young enough to act on.
func (t Tuned) Fresh(now time.Time, ttl time.Duration) bool {
	if ttl <= 0 {
		ttl = TunedTTL
	}
	if t.CreatedAt.IsZero() {
		return false
	}
	return now.Sub(t.CreatedAt) < ttl
}

// Age is how long ago the profile was measured.
func (t Tuned) Age(now time.Time) time.Duration {
	if t.CreatedAt.IsZero() {
		return 0
	}
	return now.Sub(t.CreatedAt)
}

// MatchesNetwork reports whether the profile was measured on this network.
//
// An empty key on either side does NOT match. A profile with no recorded
// network was measured somewhere unknown, and applying it anywhere is the
// failure mode the namespace exists to prevent.
func (t Tuned) MatchesNetwork(key string) bool {
	return t.NetworkKey != "" && key != "" && t.NetworkKey == key
}

// Usable reports whether the profile should be acted on now: fresh, on this
// network, and carrying a confidence the caller is willing to accept.
func (t Tuned) Usable(now time.Time, networkKey string, minConfidence string) bool {
	if !t.Fresh(now, TunedTTL) || !t.MatchesNetwork(networkKey) {
		return false
	}
	return confidenceRank(t.Confidence) >= confidenceRank(minConfidence)
}

func confidenceRank(c string) int {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// Validate rejects a record that cannot be acted on.
func (t Tuned) Validate() error {
	switch {
	case t.Version == 0:
		return fmt.Errorf("%w: no version key", ErrTunedInvalid)
	case t.Version > TunedVersion:
		return fmt.Errorf("%w: file is version %d, this build reads %d; upgrade dpb or delete the file",
			ErrTunedVersion, t.Version, TunedVersion)
	case confidenceRank(t.Confidence) == 0:
		return fmt.Errorf("%w: confidence is %q, want one of %s, %s, %s",
			ErrTunedInvalid, t.Confidence, ConfidenceHigh, ConfidenceMedium, ConfidenceLow)
	case len(t.Ladder) == 0:
		return fmt.Errorf("%w: the ladder is empty, so there is nothing to run", ErrTunedInvalid)
	case t.Ladder[0] != "":
		// Rung 1 must be plain. MEASUREMENTS.md §5.1 measures every bypassing
		// emitter breaking Turkish banking, so a profile whose first rung
		// desyncs would desync a bank on its first visit — the one outcome the
		// whole architecture exists to prevent.
		return fmt.Errorf("%w: rung 1 of the ladder is %q, but it must be plain (MEASUREMENTS.md §5.2)",
			ErrTunedInvalid, t.Ladder[0])
	}
	return nil
}

// LoadTuned reads and validates a profile.
//
// A missing file returns fs.ErrNotExist wrapped, which the caller distinguishes
// with errors.Is: "you have not tuned this network yet" is a different thing
// from "your profile is corrupt".
func LoadTuned(path string) (Tuned, error) {
	var t Tuned
	b, err := os.ReadFile(path)
	if err != nil {
		return t, fmt.Errorf("config: read tuned profile: %w", err)
	}
	md, err := toml.Decode(string(b), &t)
	if err != nil {
		return t, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if keys := md.Undecoded(); len(keys) > 0 {
		names := make([]string, 0, len(keys))
		for _, k := range keys {
			names = append(names, k.String())
		}
		sort.Strings(names)
		return t, fmt.Errorf("%w: %s in %s", ErrTunedUnknownKey, strings.Join(names, ", "), path)
	}
	if err := t.Validate(); err != nil {
		return t, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

// Save writes the profile atomically.
//
// A fully written temp file is renamed over the target, so a crash at any
// instant leaves either the previous profile or the new one and never a
// half-written record that the next run would refuse to parse.
func (t Tuned) Save(path string) error {
	if t.Version == 0 {
		t.Version = TunedVersion
	}
	if err := t.Validate(); err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("config: create %s: %w", dir, err)
		}
	}

	var sb strings.Builder
	sb.WriteString("# dpb tuned profile — written by `dpb tune`, read by `dpb run`.\n")
	sb.WriteString("# It records what was MEASURED on one network, not what is believed in general.\n")
	sb.WriteString("# Delete it to go back to the shipped profile; re-run `dpb tune` to replace it.\n\n")
	enc := toml.NewEncoder(&sb)
	enc.Indent = ""
	if err := enc.Encode(t); err != nil {
		return fmt.Errorf("config: encode tuned profile: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".tuned-*.toml")
	if err != nil {
		return fmt.Errorf("config: create temp profile: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("config: chmod temp profile: %w", err)
	}
	if _, err := tmp.WriteString(sb.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("config: write temp profile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("config: sync temp profile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close temp profile: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("config: install tuned profile: %w", err)
	}
	return nil
}
