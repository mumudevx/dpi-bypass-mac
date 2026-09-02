package netstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func init() { reviveByKind[OpPACFile] = revivePACFile }

type pacFileRevert struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	PrevExisted bool   `json:"prev_existed"`
	Prev        []byte `json:"prev,omitempty"`
	PrevMode    uint32 `json:"prev_mode,omitempty"`
}

// pacFileOp writes the PAC file the system proxy points at. The write goes
// through os.WriteFile; verification re-reads the file and compares a SHA-256,
// which catches the case a plain "did WriteFile return nil" check cannot: a
// partial write, or another process replacing the file between write and use.
type pacFileOp struct {
	path     string
	content  []byte
	sum      string
	prev     []byte
	prevOK   bool
	prevMode os.FileMode
	prepared bool
}

// NewPACFile returns an Op that writes content to path.
func NewPACFile(path string, content []byte) Op {
	sum := sha256.Sum256(content)
	return &pacFileOp{
		path:    path,
		content: append([]byte(nil), content...),
		sum:     hex.EncodeToString(sum[:]),
	}
}

// canAdopt is always false: a PAC file whose SHA-256 already matches ours was
// written by a previous run of dpb. See proxyOp.canAdopt.
func (o *pacFileOp) canAdopt() bool { return false }

func (o *pacFileOp) Kind() OpKind { return OpPACFile }
func (o *pacFileOp) ID() string   { return "proxy.pacfile:" + o.path }
func (o *pacFileOp) Describe() string {
	return fmt.Sprintf("write PAC file %s (%d bytes, sha256 %s)", o.path, len(o.content), o.sum[:12])
}

func (o *pacFileOp) prepare(_ context.Context, _ Env) error {
	if o.prepared {
		return nil
	}
	b, err := os.ReadFile(o.path)
	switch {
	case err == nil:
		// notSelf: a file that already holds exactly our content was written by a
		// previous run of dpb, not by the user. Capturing it as the "previous"
		// state would make Revert restore our own residue.
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) == o.sum {
			break
		}
		o.prev, o.prevOK = b, true
		if fi, statErr := os.Stat(o.path); statErr == nil {
			o.prevMode = fi.Mode().Perm()
		}
	case errors.Is(err, os.ErrNotExist):
		// Nothing to restore; Revert removes the file.
	default:
		return fmt.Errorf("netstate: read existing PAC file %s: %w", o.path, err)
	}
	o.prepared = true
	return nil
}

// Apply writes through a temporary file in the same directory and renames, so a
// browser fetching the PAC never sees a half-written policy.
func (o *pacFileOp) Apply(_ context.Context, _ Env) error {
	dir := filepath.Dir(o.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("netstate: create PAC directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".dpb-pac-*")
	if err != nil {
		return fmt.Errorf("netstate: create temp PAC file in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename has succeeded

	if _, err := tmp.Write(o.content); err != nil {
		tmp.Close()
		return fmt.Errorf("netstate: write temp PAC file %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("netstate: fsync temp PAC file %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("netstate: close temp PAC file %s: %w", name, err)
	}
	// The PAC is fetched by other processes, so it must be world-readable even
	// though the state directory around it is not.
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("netstate: chmod temp PAC file %s: %w", name, err)
	}
	if err := os.Rename(name, o.path); err != nil {
		return fmt.Errorf("netstate: install PAC file %s: %w", o.path, err)
	}
	return nil
}

func (o *pacFileOp) Verify(_ context.Context, _ Env) error {
	got, err := fileSum(o.path)
	if err != nil {
		return err
	}
	if got != o.sum {
		return fmt.Errorf("PAC file %s has sha256 %s, want %s", o.path, got, o.sum)
	}
	return nil
}

func (o *pacFileOp) Revert(_ context.Context, _ Env) error {
	if !o.prevOK {
		if err := os.Remove(o.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("netstate: remove PAC file %s: %w", o.path, err)
		}
		return nil
	}
	mode := o.prevMode
	if mode == 0 {
		mode = 0o644
	}
	if err := os.WriteFile(o.path, o.prev, mode); err != nil {
		return fmt.Errorf("netstate: restore PAC file %s: %w", o.path, err)
	}
	// WriteFile does not touch the mode of a file that already exists, and Apply
	// left ours at 0644, so restore the captured permissions explicitly.
	if err := os.Chmod(o.path, mode); err != nil {
		return fmt.Errorf("netstate: restore PAC file mode on %s: %w", o.path, err)
	}
	return nil
}

func (o *pacFileOp) VerifyReverted(_ context.Context, _ Env) error {
	got, err := fileSum(o.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if got == o.sum {
		return fmt.Errorf("PAC file %s still holds our content", o.path)
	}
	return nil
}

func (o *pacFileOp) Record() Record {
	raw, err := marshalRevert(pacFileRevert{
		Path:        o.path,
		SHA256:      o.sum,
		PrevExisted: o.prevOK,
		Prev:        o.prev,
		PrevMode:    uint32(o.prevMode),
	})
	rec := Record{Kind: OpPACFile, ID: o.ID(), Revert: raw}
	if err != nil {
		rec.Note = err.Error()
	}
	return rec
}

func revivePACFile(r Record) (Op, error) {
	var p pacFileRevert
	if err := unmarshalRevert(r.Revert, &p); err != nil {
		return nil, err
	}
	if p.Path == "" {
		return nil, fmt.Errorf("netstate: pacfile record carries no path")
	}
	return &pacFileOp{
		path:     p.Path,
		sum:      p.SHA256,
		prev:     p.Prev,
		prevOK:   p.PrevExisted,
		prevMode: os.FileMode(p.PrevMode),
		prepared: true,
	}, nil
}

func fileSum(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return "", fmt.Errorf("netstate: read %s: %w", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
