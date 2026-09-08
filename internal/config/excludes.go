package config

import (
	"strings"

	"github.com/mumudevx/dpb/internal/policy"
)

// The compiled-in bypass list: names this build will never desync, whatever a
// config file says.
//
// It is extendable and NOT removable. `bypass` in a config file adds to it;
// there is no key that takes anything out, because the entries here are not
// preferences — each one is a host MEASUREMENTS.md §5.1 watched break under the
// emitter that defeats the DPI, and every one of the ten is a bank or a .gov.tr
// site on a machine its owner also banks on.
//
// Under default-direct this list is belt-and-braces rather than the primary
// defence. §5.2 is explicit that "a shipped exclusion list cannot be the answer
// — 24% of the tested hosts are fragile, and no hand-maintained list covers the
// Turkish long tail": the real protection is that attempt one is always plain,
// so a fragile host that nobody listed still succeeds undesynced. The list is
// here so that the ten hosts we have first-hand evidence about are not even
// buffered.
//
// Address rules are deliberately absent. policy.NewEngine applies the bogon
// table (RFC1918, loopback, link-local, CGNAT, ULA, multicast, 198.18/15) on
// its own and re-applies it on every Reload, so restating it here would create
// a second copy that can drift from the one actually enforced.
type exclude struct {
	pattern string
	// why cites the measurement or dossier item the entry comes from. `dpb why`
	// prints it, and an entry that cannot cite anything does not belong here.
	why string
	// fragile marks the ten hosts measured regressing under desync. `dpb tune`
	// uses exactly this set as its compatibility axis, which is why it is a flag
	// here rather than a second list that could disagree with this one.
	fragile bool
}

var mandatory = []exclude{
	// The ten measured regressors, MEASUREMENTS.md §5.1. Every one of them
	// completes a handshake plain and fails under tlsfrag, chunk or oob.
	{"akbank.com", "MEASUREMENTS.md 5.1: breaks under desync", true},
	{"isbank.com.tr", "MEASUREMENTS.md 5.1: breaks under desync", true},
	{"yapikredi.com.tr", "MEASUREMENTS.md 5.1: 2/2 plain, 0/2 under tlsfrag (tls: illegal parameter)", true},
	{"ziraatbank.com.tr", "MEASUREMENTS.md 5.1: breaks under desync", true},
	{"vakifbank.com.tr", "MEASUREMENTS.md 5.1: breaks under desync", true},
	{"denizbank.com", "MEASUREMENTS.md 5.1: breaks under desync", true},
	{"turkiye.gov.tr", "MEASUREMENTS.md 5.1: breaks under desync", true},
	{"gib.gov.tr", "MEASUREMENTS.md 5.1: breaks under desync", true},
	{"mhrs.gov.tr", "MEASUREMENTS.md 5.1: breaks under desync", true},
	{"btk.gov.tr", "MEASUREMENTS.md 5.1: breaks under desync", true},

	// The suffix rules. GT22 records zapret-win-turkey shipping .gov.tr, .com.tr,
	// google.com and googleapis.com in excludelist.txt verbatim; the four
	// measured .gov.tr and four measured .com.tr regressors above are the
	// evidence that the suffix generalises rather than the exception.
	{".gov.tr", "GT22 + MEASUREMENTS.md 5.1: four of the ten measured regressors are .gov.tr", false},
	{".com.tr", "GT22 + MEASUREMENTS.md 5.1: four of the ten measured regressors are .com.tr", false},
	{"google.com", "GT22: zapret-win-turkey excludelist.txt", false},
	{"googleapis.com", "GT22: zapret-win-turkey excludelist.txt", false},
	{"discordapp.net", "GT22: desync corrupts large CDN transfers; MEASUREMENTS.md 1 records media.discordapp.net reaching the origin unblocked", false},
}

// Mandatory returns the compiled-in bypass rules, in declaration order.
//
// Line is the entry's position in the list so policy.Rule.Where() renders
// "compiled-in:7", which is a thing a user can grep this file for.
func Mandatory() []policy.Rule {
	out := make([]policy.Rule, 0, len(mandatory))
	for i, e := range mandatory {
		out = append(out, policy.Rule{
			Pattern: e.pattern,
			Class:   policy.ScopeBypass,
			From:    policy.FromCompiledIn,
			Line:    i + 1,
		})
	}
	return out
}

// MandatoryReason returns the citation recorded for a compiled-in pattern.
// Matching is on the pattern as written, so ".gov.tr" and "gov.tr" are the same
// entry — the leading dot is a spelling convenience in policy's matcher and
// must not become two different rules here.
func MandatoryReason(pattern string) (string, bool) {
	want := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	for _, e := range mandatory {
		if strings.TrimPrefix(e.pattern, ".") == want {
			return e.why, true
		}
	}
	return "", false
}

// FragileHosts is the compatibility axis: the hosts measured breaking under
// desync. `dpb tune` scores every candidate against these, and the prober's
// default --fragile list is this one, so the two can never disagree.
func FragileHosts() []string {
	out := make([]string, 0, len(mandatory))
	for _, e := range mandatory {
		if e.fragile {
			out = append(out, e.pattern)
		}
	}
	return out
}
