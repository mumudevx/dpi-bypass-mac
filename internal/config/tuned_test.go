package config_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
)

func good() config.Tuned {
	return config.Tuned{
		Version:     config.TunedVersion,
		CreatedAt:   time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
		ToolVersion: "v0.1.0",
		NetworkKey:  "wifi:abc123",
		Caps:        "stream|nodelay",
		Confidence:  config.ConfidenceHigh,
		NoiseRate:   0.01,
		ElapsedMS:   184000,
		Strategy:    "tlsfrag:pos=snimid",
		Ladder:      []string{"", "tlsfrag:pos=snimid", "chunk:size=12"},
		Resolvers:   []string{"udp-yandex-1253", "doh-cloudflare"},
		Blocked:     []string{"discord.com:443[162.159.128.233]"},
		NotBlocked:  []string{"media.discordapp.net:443"},
		Classification: config.TunedClassification{
			Shape:            "sni-reset",
			FirstRecordLimit: 121,
			SNIEnd:           122,
			RSTLatencyMS:     22,
			RecordFrag:       true,
		},
		Candidates: []config.TunedCandidate{{
			Spec: "tlsfrag:pos=snimid", BypassPass: 9, BypassTotal: 9,
			WilsonLo: 0.7026, AllTargets: true, ControlPass: 8, ControlTotal: 8,
			Determinism: "rule-based", Segments: 1, MedianRTTMS: 23,
		}},
	}
}

func TestTunedRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tuned.toml")
	want := good()
	if err := want.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := config.LoadTuned(path)
	if err != nil {
		t.Fatalf("LoadTuned: %v", err)
	}
	if got.Strategy != want.Strategy || got.Confidence != want.Confidence ||
		got.NetworkKey != want.NetworkKey || len(got.Ladder) != len(want.Ladder) {
		t.Errorf("round trip lost data:\n got %+v\nwant %+v", got, want)
	}
	if got.Classification.FirstRecordLimit != 121 || got.Classification.SNIEnd != 122 {
		t.Errorf("classification round trip = %+v", got.Classification)
	}
	if len(got.Candidates) != 1 || got.Candidates[0].BypassPass != 9 {
		t.Errorf("candidate table round trip = %+v", got.Candidates)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, want.CreatedAt)
	}
}

func TestTunedWriteIsPrivateAndAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tuned.toml")
	if err := good().Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600: the profile names the sites this user reaches for", perm)
	}
	// A second write must replace it and leave no temp file behind.
	if err := good().Save(path); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(ents) != 1 {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only tuned.toml", names)
	}
}

// TestTunedRejectsAnUnknownKey is the sni_match trap made impossible: a user
// who mistypes a key is told, rather than silently running the default and
// believing they configured something.
func TestTunedRejectsAnUnknownKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tuned.toml")
	body := "version = 1\nconfidence = \"high\"\nladder = [\"\"]\nstratagem = \"tlsfrag:pos=snimid\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.LoadTuned(path)
	if !errors.Is(err, config.ErrTunedUnknownKey) {
		t.Fatalf("error = %v, want ErrTunedUnknownKey", err)
	}
	if !strings.Contains(err.Error(), "stratagem") {
		t.Errorf("the error does not name the offending key: %v", err)
	}
}

func TestTunedValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*config.Tuned)
		want error
	}{
		{"future version", func(c *config.Tuned) { c.Version = config.TunedVersion + 1 }, config.ErrTunedVersion},
		{"bad confidence", func(c *config.Tuned) { c.Confidence = "excellent" }, config.ErrTunedInvalid},
		{"empty ladder", func(c *config.Tuned) { c.Ladder = nil }, config.ErrTunedInvalid},
		// The one that matters: MEASUREMENTS.md §5.1 measures every bypassing
		// emitter breaking Turkish banking, so a profile whose first rung
		// desyncs would desync a bank on its first visit.
		{"rung 1 desyncs", func(c *config.Tuned) {
			c.Ladder = []string{"tlsfrag:pos=snimid", ""}
		}, config.ErrTunedInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mut(&c)
			if err := c.Validate(); !errors.Is(err, tc.want) {
				t.Errorf("Validate = %v, want %v", err, tc.want)
			}
			if err := c.Save(filepath.Join(t.TempDir(), "t.toml")); !errors.Is(err, tc.want) {
				t.Errorf("Save wrote an invalid profile: %v", err)
			}
		})
	}
	// A record with no version is not invalid, it is unversioned: Save stamps
	// the current version onto it, and only a version this build cannot READ is
	// refused. Asserted here so the two cases are not confused later.
	unversioned := good()
	unversioned.Version = 0
	if err := unversioned.Validate(); !errors.Is(err, config.ErrTunedInvalid) {
		t.Errorf("Validate of an unversioned record = %v, want ErrTunedInvalid", err)
	}
	if err := unversioned.Save(filepath.Join(t.TempDir(), "t.toml")); err != nil {
		t.Errorf("Save of an unversioned record = %v, want it stamped and written", err)
	}
}

func TestTunedMissingFileIsDistinguishable(t *testing.T) {
	_, err := config.LoadTuned(filepath.Join(t.TempDir(), "absent.toml"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error = %v, want fs.ErrNotExist: 'not tuned yet' is not 'profile corrupt'", err)
	}
}

func TestTunedFreshnessAndNetwork(t *testing.T) {
	c := good()
	now := c.CreatedAt.Add(24 * time.Hour)

	if !c.Fresh(now, config.TunedTTL) {
		t.Error("a one-day-old profile is not fresh")
	}
	if c.Fresh(c.CreatedAt.Add(config.TunedTTL+time.Hour), config.TunedTTL) {
		t.Error("a profile older than the TTL is still fresh")
	}
	if (config.Tuned{}).Fresh(now, config.TunedTTL) {
		t.Error("a profile with no timestamp is fresh")
	}
	if got := c.Age(now); got != 24*time.Hour {
		t.Errorf("Age = %v, want 24h", got)
	}

	if !c.MatchesNetwork("wifi:abc123") {
		t.Error("the profile does not match the network it was measured on")
	}
	if c.MatchesNetwork("wifi:other") {
		t.Error("the profile matched a different network")
	}
	// An unknown network on either side must NOT match: replaying a
	// measurement onto an unknown network is what the namespace prevents.
	if c.MatchesNetwork("") {
		t.Error("the profile matched an empty network key")
	}
	blank := c
	blank.NetworkKey = ""
	if blank.MatchesNetwork("wifi:abc123") {
		t.Error("a profile with no recorded network matched one")
	}
}

func TestTunedUsable(t *testing.T) {
	c := good()
	now := c.CreatedAt.Add(time.Hour)
	if !c.Usable(now, "wifi:abc123", config.ConfidenceMedium) {
		t.Error("a fresh high-confidence profile on the right network is not usable")
	}
	low := c
	low.Confidence = config.ConfidenceLow
	if low.Usable(now, "wifi:abc123", config.ConfidenceMedium) {
		t.Error("a low-confidence profile satisfied a medium bar")
	}
	if c.Usable(c.CreatedAt.Add(config.TunedTTL+time.Hour), "wifi:abc123", config.ConfidenceLow) {
		t.Error("a stale profile is usable")
	}
	if c.Usable(now, "wifi:elsewhere", config.ConfidenceLow) {
		t.Error("a profile from another network is usable")
	}
}

func TestTunedSaveCreatesTheDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dpb", "tuned.toml")
	if err := good().Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := config.LoadTuned(path); err != nil {
		t.Fatalf("LoadTuned: %v", err)
	}
}

func TestTunedSaveFillsTheVersion(t *testing.T) {
	c := good()
	c.Version = 0
	path := filepath.Join(t.TempDir(), "tuned.toml")
	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := config.LoadTuned(path)
	if err != nil {
		t.Fatalf("LoadTuned: %v", err)
	}
	if got.Version != config.TunedVersion {
		t.Errorf("version = %d, want %d", got.Version, config.TunedVersion)
	}
}

func TestTunedFileIsSelfExplaining(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tuned.toml")
	if err := good().Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{"dpb tune", "Delete it"} {
		if !strings.Contains(body, want) {
			t.Errorf("the written file does not tell the reader %q:\n%s", want, body)
		}
	}
}
