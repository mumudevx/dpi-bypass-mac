package policy

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// `dpb why HOST` is the command that makes this tool trustworthy to the person
// running it. A circumvention tool that silently decides to mangle a bank's
// TLS handshake and gives no account of why is indistinguishable from a bug,
// so every decision has to be attributable to a rule with a file and a line,
// or to a cached observation with a timestamp.

// Text renders the explanation the way `dpb why` prints it.
func (x Explanation) Text(w io.Writer) error {
	return x.textAt(w, time.Time{})
}

// TextAt renders with ages computed relative to now, so the output is
// deterministic under test.
func (x Explanation) TextAt(w io.Writer, now time.Time) error {
	return x.textAt(w, now)
}

func (x Explanation) textAt(w io.Writer, now time.Time) error {
	var b strings.Builder
	fmt.Fprintf(&b, "host:      %s\n", x.Input)
	if x.Punycode != "" && x.Punycode != x.Input {
		fmt.Fprintf(&b, "normalised: %s\n", x.Punycode)
	}

	if len(x.Matched) == 0 {
		b.WriteString("rules:     none matched\n")
	} else {
		b.WriteString("rules:\n")
		for i, r := range x.Matched {
			marker := " "
			if i == 0 {
				// The first match is the most specific one and is the rule
				// that actually decided; the rest are shown so a user can see
				// what a broader rule would have done.
				marker = "*"
			}
			fmt.Fprintf(&b, "  %s %-28s -> %-6s  (%s)\n", marker, r.Pattern, r.Class, r.Where())
		}
	}

	v := x.Effective
	fmt.Fprintf(&b, "verdict:   %s\n", v.Class)
	fmt.Fprintf(&b, "source:    %s\n", v.Source)
	if v.Reason != "" {
		fmt.Fprintf(&b, "because:   %s\n", v.Reason)
	}
	if v.Spec != "" {
		fmt.Fprintf(&b, "strategy:  %s\n", v.Spec)
	}
	if len(v.Ladder) > 0 {
		fmt.Fprintf(&b, "ladder:    %s\n", strings.Join(ladderText(v.Ladder), " -> "))
	}
	if !v.Learned.IsZero() {
		fmt.Fprintf(&b, "learned:   %s%s\n", v.Learned.Format(time.RFC3339), ageSuffix(v.Learned, now))
	}
	if v.Expires.IsZero() {
		if v.Source == SrcLearnedPlain {
			// Worth stating explicitly: a user who sees "never" should know it
			// is deliberate and self-correcting, not a missing TTL.
			b.WriteString("expires:   never (a plain flow that starts failing escalates on its own)\n")
		}
	} else {
		fmt.Fprintf(&b, "expires:   %s%s\n", v.Expires.Format(time.RFC3339), ageSuffix(v.Expires, now))
	}
	if v.Wins > 0 || v.Losses > 0 {
		fmt.Fprintf(&b, "record:    %d ok, %d failed\n", v.Wins, v.Losses)
	}

	if len(x.Recent) > 0 {
		b.WriteString("recent:\n")
		for _, c := range x.Recent {
			status := "failed"
			if c.OK {
				status = "ok"
			}
			fmt.Fprintf(&b, "  %s  %-6s  attempts=%d  %s  %s\n",
				c.At.Format(time.RFC3339), status, c.Attempts,
				c.Latency.Round(time.Millisecond), specText(c.Spec))
		}
	}

	_, err := io.WriteString(w, b.String())
	if err != nil {
		return fmt.Errorf("policy: write explanation: %w", err)
	}
	return nil
}

// ladderText spells the empty strategy as "plain" so a ladder never renders
// with a hole in it.
func ladderText(l []string) []string {
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = specText(s)
	}
	return out
}

func specText(s string) string {
	if s == "" {
		return "plain"
	}
	return s
}

func ageSuffix(t, now time.Time) string {
	if now.IsZero() {
		return ""
	}
	d := now.Sub(t)
	if d < 0 {
		return fmt.Sprintf(" (in %s)", (-d).Round(time.Second))
	}
	return fmt.Sprintf(" (%s ago)", d.Round(time.Second))
}
