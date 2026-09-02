package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestEverySchemaKeyIsReadOrDeclaredDeferred is a build gate against the
// sni_match shape.
//
// MEASUREMENTS.md §3.5 records the previous implementation shipping a config
// setting that was declared, documented and recommended to users — and read
// nowhere, so a user who set it believed they had changed the tool's behaviour
// and had not. Unknown-key rejection stops a user inventing a key; this stops
// US shipping one.
//
// The scan is textual, not type-directed: the module has no x/tools dependency
// to resolve types with. It looks for the field name used as a selector in a
// file that actually deals with a Config — every file in this package, plus
// every file that imports it. That is narrow enough that a genuinely dead key
// has nowhere to hide, and wide enough that a live one is always found. It can
// still be fooled by an unrelated selector of the same name in a file that also
// imports config (`ap.Port()`, say), which is why the deferredKeys table exists
// as the explicit, reviewed alternative rather than as the fallback.
func TestEverySchemaKeyIsReadOrDeclaredDeferred(t *testing.T) {
	sources := configAwareSources(t)
	if len(sources) < 2 {
		t.Fatalf("found %d source files that deal with a Config; the scan is broken", len(sources))
	}

	for _, f := range schemaFields(reflect.TypeOf(Config{}), "") {
		if _, deferred := deferredKeys[f.field]; deferred {
			continue
		}
		re := regexp.MustCompile(`\.` + regexp.QuoteMeta(f.field) + `\b`)
		found := ""
		for path, src := range sources {
			if re.MatchString(src) {
				found = path
				break
			}
		}
		if found == "" {
			t.Errorf("key %q (field %s) is decoded and then read nowhere: "+
				"wire it up, delete it, or record it in deferredKeys with the milestone that reads it",
				f.key, f.field)
		}
	}
}

// TestDeferredKeysAreStillDeclared fails when a deferredKeys entry names a
// field that no longer exists, so the table cannot rot into a list of excuses
// for keys that were removed years ago.
func TestDeferredKeysAreStillDeclared(t *testing.T) {
	have := map[string]bool{}
	for _, f := range schemaFields(reflect.TypeOf(Config{}), "") {
		have[f.field] = true
	}
	for field, why := range deferredKeys {
		if !have[field] {
			t.Errorf("deferredKeys names %s, which is not a schema field", field)
		}
		if !strings.Contains(why, "M1") && !strings.Contains(why, "M2") {
			t.Errorf("deferredKeys[%s] = %q: name the milestone that reads it", field, why)
		}
	}
}

type schemaField struct{ field, key string }

func schemaFields(t reflect.Type, prefix string) []schemaField {
	var out []schemaField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("toml")
		if tag == "" || tag == "-" || f.PkgPath != "" {
			continue
		}
		ft := f.Type
		if ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && !isTextUnmarshaler(f.Type) {
			out = append(out, schemaFields(ft, prefix+tag+".")...)
			continue
		}
		out = append(out, schemaField{field: f.Name, key: prefix + tag})
	}
	return out
}

const configImport = `"github.com/mumudevx/dpi-bypass-mac/internal/config"`

func configAwareSources(t *testing.T) map[string]string {
	t.Helper()
	root := moduleRoot(t)
	out := map[string]string{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			src := string(b)
			rel, _ := filepath.Rel(root, path)
			if strings.Contains(src, configImport) || strings.HasPrefix(rel, filepath.Join("internal", "config")) {
				out[rel] = src
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return out
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}
