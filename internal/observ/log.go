// Package observ is dpb's observability layer: the leveled logger, the NDJSON
// event log, the in-process event bus, and hostname redaction for diagnostics
// a user can paste in public.
package observ

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log verbosity. Lower is more severe, so a message is emitted when
// its level is <= the logger's level.
type Level int8

// LevelUnset is the zero value, so a LogOptions nobody filled in gets the
// sensible default (info) rather than the quietest setting. A tool whose
// warnings carry remediations must not fall silent by omission.
const (
	LevelUnset Level = iota
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

var levelNames = [...]string{"unset", "error", "warn", "info", "debug", "trace"}

func (l Level) String() string {
	if l < LevelUnset || int(l) >= len(levelNames) {
		return "invalid"
	}
	return levelNames[l]
}

// ParseLevel accepts the long names and the single-letter forms. It is
// case-insensitive because it parses both a config value and a flag.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error", "err", "e":
		return LevelError, nil
	case "warn", "warning", "w":
		return LevelWarn, nil
	case "info", "i", "":
		return LevelInfo, nil
	case "debug", "d":
		return LevelDebug, nil
	case "trace", "t":
		return LevelTrace, nil
	default:
		return LevelInfo, fmt.Errorf("observ: unknown log level %q (want error|warn|info|debug|trace)", s)
	}
}

// VerbosityLevel maps the -v/-vv flag count onto a level.
func VerbosityLevel(v int) Level {
	switch {
	case v <= 0:
		return LevelInfo
	case v == 1:
		return LevelDebug
	default:
		return LevelTrace
	}
}

// LogOptions configures a Logger. The zero value is usable: info level, text
// format, os.Stderr.
type LogOptions struct {
	Level Level
	// JSON selects one JSON object per line instead of the human format.
	JSON bool
	// Out is the sink. nil means os.Stderr.
	Out io.Writer
	// Now is a clock seam for tests. nil means time.Now.
	Now func() time.Time
}

// logCore is the state shared by a logger and every logger derived from it with
// With, so that raising verbosity on a live process reaches per-connection
// loggers that were created before the change.
type logCore struct {
	mu    sync.Mutex
	out   io.Writer
	level Level
	json  bool
	now   func() time.Time
}

// Logger is a leveled logger safe for concurrent use.
//
// Its distinguishing rule is that Warn takes a remediation string as a
// mandatory first argument. A warning a user cannot act on is noise, and noise
// is how the one warning that mattered gets ignored; making the signature
// require it is the only enforcement that cannot be forgotten.
type Logger struct {
	core   *logCore
	fields []field
}

type field struct {
	key string
	val any
}

// NewLogger builds a logger from opts.
func NewLogger(opts LogOptions) *Logger {
	out := opts.Out
	if out == nil {
		out = os.Stderr
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	level := opts.Level
	if level == LevelUnset {
		level = LevelInfo
	}
	return &Logger{core: &logCore{out: out, level: level, json: opts.JSON, now: now}}
}

// Discard is a logger that writes nothing. Used by tests and by callers that
// must not have to nil-check.
func Discard() *Logger { return NewLogger(LogOptions{Level: LevelError, Out: io.Discard}) }

// Level reports the current threshold.
func (l *Logger) Level() Level {
	l.core.mu.Lock()
	defer l.core.mu.Unlock()
	return l.core.level
}

// SetLevel changes the threshold at runtime, for every derived logger too.
func (l *Logger) SetLevel(lv Level) {
	l.core.mu.Lock()
	l.core.level = lv
	l.core.mu.Unlock()
}

// Enabled reports whether a message at lv would be emitted. Callers use it to
// skip expensive formatting, not to decide whether to log.
func (l *Logger) Enabled(lv Level) bool { return lv <= l.Level() }

// With returns a logger that adds the given key/value pairs to every record.
// An odd trailing key is kept with a "(missing)" value rather than dropped, so
// a miscounted call still shows what the caller meant to say.
func (l *Logger) With(kv ...any) *Logger {
	if len(kv) == 0 {
		return l
	}
	merged := make([]field, 0, len(l.fields)+(len(kv)+1)/2)
	merged = append(merged, l.fields...)
	merged = append(merged, pairs(kv)...)
	return &Logger{core: l.core, fields: merged}
}

func pairs(kv []any) []field {
	out := make([]field, 0, (len(kv)+1)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			k = fmt.Sprint(kv[i])
		}
		v := any("(missing)")
		if i+1 < len(kv) {
			v = kv[i+1]
		}
		out = append(out, field{key: k, val: v})
	}
	return out
}

// Errorf logs at error level. Its signature matches flow.Safe's logf parameter.
func (l *Logger) Errorf(format string, args ...any) { l.emit(LevelError, "", format, args) }

// Warn logs at warn level. remedy states what the user should do about it and
// must not be empty; see the Logger doc comment.
func (l *Logger) Warn(remedy, format string, args ...any) {
	if strings.TrimSpace(remedy) == "" {
		// Do not drop the warning — surface the defect alongside it.
		remedy = "no remediation was provided; this is a bug in dpb, please report it"
	}
	l.emit(LevelWarn, remedy, format, args)
}

// Infof logs at info level: the handful of lines a normal run prints.
func (l *Logger) Infof(format string, args ...any) { l.emit(LevelInfo, "", format, args) }

// Debugf logs at debug level (-v).
func (l *Logger) Debugf(format string, args ...any) { l.emit(LevelDebug, "", format, args) }

// Tracef logs at trace level (-vv): per-connection detail.
func (l *Logger) Tracef(format string, args ...any) { l.emit(LevelTrace, "", format, args) }

func (l *Logger) emit(lv Level, remedy, format string, args []any) {
	if !l.Enabled(lv) {
		return
	}
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}

	l.core.mu.Lock()
	defer l.core.mu.Unlock()

	ts := l.core.now()
	var line []byte
	if l.core.json {
		line = l.jsonLine(ts, lv, remedy, msg)
	} else {
		line = l.textLine(ts, lv, remedy, msg)
	}
	// A logger that cannot write has nowhere to report that it cannot write.
	// Dropping is the only non-recursive option; the event log is the durable
	// record and it reports its write errors to the caller instead.
	_, _ = l.core.out.Write(line)
}

func (l *Logger) jsonLine(ts time.Time, lv Level, remedy, msg string) []byte {
	rec := make(map[string]any, len(l.fields)+4)
	for _, f := range l.fields {
		rec[f.key] = f.val
	}
	rec["ts"] = ts.UTC().Format(time.RFC3339Nano)
	rec["level"] = lv.String()
	rec["msg"] = msg
	if remedy != "" {
		rec["remedy"] = remedy
	}
	b, err := json.Marshal(rec)
	if err != nil {
		// An unmarshalable field value is a caller bug, not a reason to go
		// silent: keep the message, report the field failure.
		b, _ = json.Marshal(map[string]any{
			"ts":          ts.UTC().Format(time.RFC3339Nano),
			"level":       lv.String(),
			"msg":         msg,
			"field_error": err.Error(),
		})
	}
	return append(b, '\n')
}

const levelColumn = 6

func (l *Logger) textLine(ts time.Time, lv Level, remedy, msg string) []byte {
	var b strings.Builder
	b.WriteString(ts.Format("15:04:05.000"))
	b.WriteByte(' ')
	name := lv.String()
	b.WriteString(strings.ToUpper(name))
	b.WriteString(strings.Repeat(" ", levelColumn-len(name)+1))
	b.WriteString(msg)
	for _, f := range l.fields {
		fmt.Fprintf(&b, " %s=%v", f.key, f.val)
	}
	if remedy != "" {
		b.WriteString("\n         -> ")
		b.WriteString(remedy)
	}
	b.WriteByte('\n')
	return []byte(b.String())
}
