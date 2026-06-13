// Package logx is a tiny leveled logger writing to stderr.
package logx

import (
	"fmt"
	"os"
	"sync"
)

type Logger struct {
	mu        sync.Mutex
	verbosity int
}

// New returns a logger; verbosity > 0 enables debug output.
func New(verbosity int) *Logger { return &Logger{verbosity: verbosity} }

func (l *Logger) logf(prefix, format string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, prefix+format+"\n", a...)
}

func (l *Logger) Errorf(format string, a ...any) { l.logf("error: ", format, a...) }
func (l *Logger) Warnf(format string, a ...any)  { l.logf("warn: ", format, a...) }
func (l *Logger) Infof(format string, a ...any)  { l.logf("", format, a...) }
func (l *Logger) Debugf(format string, a ...any) {
	if l.verbosity > 0 {
		l.logf("debug: ", format, a...)
	}
}
